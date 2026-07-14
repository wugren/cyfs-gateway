//! SN seed config（`sn_seed.yaml`）：格式真值 + 幂等导入。
//!
//! 设计边界（见 cyfs-gateway/doc/SN/SN-seed-config-TODO.md 与 doc/SN/SN-Seed-Config.md）：
//!
//! - 内容**仅限 C 类**数据——无合理默认值、必须显式创建的 SN-local 数据：
//!   激活码、sn_user 账号（密码 / owner 公钥 / bns_name 绑定）、user_domain 绑定。
//!   不含 zone/boot/device_mini_doc（A 类，权威在 BNS，经 bns_dv seed 上链）、
//!   不含在线态 / relay 分配。`self_cert` 通常仍是 B 类运行态，
//!   但允许可信 dev seed 显式声明已预置测试证书（ACME 不可用的离线环境）。
//! - **幂等契约 = ensure-exists**：种子只保证"存在"。已存在 → no-op；
//!   已存在且内容不一致 → `warn!` 并跳过（绝不覆盖运行中的账号/密码）；
//!   带相同 seed 二次启动零写入、无副作用。
//! - 与 bns_dv 的 `BnsDvInitConfig` 同风格：snake_case YAML。本结构体是格式
//!   真值；src/make_sn_config.ts 中的 TS interface 只是镜像，勿漂移。
//!
//! 失败策略：seed 文件不存在 → 跳过（`Ok(None)`）；文件存在但解析/校验失败 →
//! 返回错误，调用方（`SnServerFactory::create`）应让启动失败（坏种子不能静默）。

use std::path::{Path, PathBuf};

use log::*;
use serde::{Deserialize, Serialize};

use crate::sn_auth::{canonical_email, SnAuthDB, SqliteSnAuthDB, ZoneInfoPatch};
use crate::sn_auth_manager::{hash_password, PASSWORD_ALGO};
use crate::{sn_err, SnErrorCode, SnResult};

/// `sn_seed.yaml` 顶层结构（格式真值）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnSeedConfig {
    /// 未使用的激活码（Web2 新用户注册流程测试用）。
    #[serde(default)]
    pub activation_codes: Vec<String>,
    /// sn_user 账号种子（仅 snAccount=true 的用户）。
    #[serde(default)]
    pub users: Vec<SnSeedUser>,
    /// did:web 型 zone 的 user_domain 绑定种子。
    #[serde(default)]
    pub user_domains: Vec<SnSeedUserDomain>,
}

/// 词汇沿用 devenv_config.ts（username / zone_id / user_domain）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnSeedUser {
    pub username: String,
    /// 规范化后全局唯一的 SN 账号邮箱。
    pub email: String,
    /// dev 明文测试密码；导入时走现有 PBKDF2 哈希路径（即登录时客户端提交的
    /// pwd_hash 值——dev 约定直接用明文）。
    pub password: String,
    /// ed25519 owner 公钥。canonical 形式是 JWK 的 x 分量（base64url）；也接受
    /// 完整 JWK JSON（以 `{` 开头时原样存储）。
    pub owner_public_key: String,
    /// sn_user <-> BNS name 绑定（仅绑定关系，非权威文档）。缺省 = username。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_name: Option<String>,
    /// 可信 dev seed 的证书状态。未声明时保持生产安全默认值 false；
    /// 显式声明时导入器会幂等对齐 users/zone_info 两处投影。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_cert: Option<bool>,
}

/// did:web 型 zone：ZoneDocument 走 SN 的 user_domain 机制保存（did:bns 的
/// zone/boot 权威在 BNS，不在此列）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnSeedUserDomain {
    /// 自有域名，如 `charlie.me`。
    pub domain: String,
    /// 关联 sn_user 的 username（须在 `users` 列表中，或已存在于 DB）。
    pub owner: String,
    /// owner 的 ed25519 公钥 JWK x 分量，与 owner 用户的 owner_public_key 一致。
    pub pkx: String,
    /// owner key 签名的 ZoneDocument(boot) JWT；SN 保存后用于 did:web 解析。
    pub zone_document_jwt: String,
}

/// 导入结果统计（`Display` 输出用于启动日志）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnSeedImportReport {
    pub activation_codes_added: u64,
    pub activation_codes_existing: u64,
    pub users_added: u64,
    pub users_existing: u64,
    /// 已存在的 seed 用户其显式运行态被对齐的数量。
    pub users_updated: u64,
    pub user_domains_added: u64,
    pub user_domains_existing: u64,
    /// 已存在但内容与种子不一致而跳过的条目数（每条已 `warn!`）。
    pub conflicts_skipped: u64,
}

impl SnSeedImportReport {
    /// 本次导入是否零写入（幂等重放的期望结果）。
    pub fn is_noop(&self) -> bool {
        self.activation_codes_added == 0
            && self.users_added == 0
            && self.users_updated == 0
            && self.user_domains_added == 0
    }
}

impl std::fmt::Display for SnSeedImportReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "codes +{}/{} users +{}/{} updated {} domains +{}/{} conflicts {}",
            self.activation_codes_added,
            self.activation_codes_added + self.activation_codes_existing,
            self.users_added,
            self.users_added + self.users_existing,
            self.users_updated,
            self.user_domains_added,
            self.user_domains_added + self.user_domains_existing,
            self.conflicts_skipped,
        )
    }
}

/// 相对路径按网关主配置目录解析（与 local_dns 的 `file_path` 同语义）。
pub fn resolve_sn_seed_path(seed_path: &str) -> PathBuf {
    let path = Path::new(seed_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cyfs_gateway_lib::get_gateway_main_config_dir().join(path)
    }
}

/// 从 YAML 文本解析并做结构校验（格式坏 → Err，调用方 fail fast）。
pub fn parse_sn_seed_config(text: &str) -> SnResult<SnSeedConfig> {
    let seed: SnSeedConfig = serde_yaml_ng::from_str(text)
        .map_err(|e| sn_err!(SnErrorCode::InvalidInput, "parse sn seed config failed: {}", e))?;
    validate_sn_seed_config(&seed)?;
    Ok(seed)
}

fn validate_sn_seed_config(seed: &SnSeedConfig) -> SnResult<()> {
    let mut seen_codes = std::collections::HashSet::new();
    for code in &seed.activation_codes {
        if code.trim().is_empty() {
            return Err(sn_err!(SnErrorCode::InvalidInput, "seed activation code is empty"));
        }
        if !seen_codes.insert(code.trim()) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "duplicated seed activation code: {}",
                code
            ));
        }
    }

    let mut seen_users = std::collections::HashSet::new();
    let mut seen_emails = std::collections::HashSet::new();
    for user in &seed.users {
        if user.username.trim().is_empty() {
            return Err(sn_err!(SnErrorCode::InvalidInput, "seed user username is empty"));
        }
        if user.password.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "seed user {} password is empty",
                user.username
            ));
        }
        let email = canonical_email(user.email.as_str()).map_err(|e| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "seed user {} has invalid email: {}",
                user.username,
                e
            )
        })?;
        if !seen_emails.insert(email.clone()) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "duplicated seed user email: {}",
                email
            ));
        }
        if user.owner_public_key.trim().is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "seed user {} owner_public_key is empty",
                user.username
            ));
        }
        if !seen_users.insert(user.username.trim()) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "duplicated seed user: {}",
                user.username
            ));
        }
    }

    let mut seen_domains = std::collections::HashSet::new();
    for entry in &seed.user_domains {
        for (field, value) in [
            ("domain", entry.domain.as_str()),
            ("owner", entry.owner.as_str()),
            ("pkx", entry.pkx.as_str()),
            ("zone_document_jwt", entry.zone_document_jwt.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "seed user_domain {} field {} is empty",
                    entry.domain,
                    field
                ));
            }
        }
        if !seen_domains.insert(entry.domain.trim().to_ascii_lowercase()) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "duplicated seed user_domain: {}",
                entry.domain
            ));
        }
        // 域名 owner 在 users 列表内时，pkx 必须与该用户的 owner 公钥一致；
        // 不在列表内的 owner 允许（要求导入时 DB 已有该用户）。
        if let Some(user) = seed.users.iter().find(|u| u.username == entry.owner) {
            let expected_x = jwk_x_of(&user.owner_public_key);
            if expected_x.as_deref() != Some(entry.pkx.trim()) {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "seed user_domain {} pkx mismatches owner {} owner_public_key",
                    entry.domain,
                    entry.owner
                ));
            }
        }
    }
    Ok(())
}

/// 把种子里的 owner_public_key 规格化成 users.public_key 的存储形式：
/// 完整 JWK 的 sorted-compact JSON（与 websdk provision 写库格式一致）。
fn canonical_public_key(owner_public_key: &str) -> String {
    let trimmed = owner_public_key.trim();
    if trimmed.starts_with('{') {
        trimmed.to_string()
    } else {
        format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, trimmed)
    }
}

/// 从 canonical/原始 owner_public_key 值中提取 JWK x 分量。
fn jwk_x_of(owner_public_key: &str) -> Option<String> {
    let trimmed = owner_public_key.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()?
            .get("x")?
            .as_str()
            .map(ToString::to_string)
    } else {
        Some(trimmed.to_string())
    }
}

/// 每个种子用户注册时使用的专属激活码（可追溯 provenance；不占用
/// `activation_codes` 里留给注册流程测试的码）。
fn seed_user_activation_code(username: &str) -> String {
    format!("seed-user-{}", username)
}

/// 从文件导入。文件不存在 → `Ok(None)`（调用方记日志后跳过）；
/// 读取/解析/导入失败 → `Err`（调用方 fail fast）。
pub async fn import_sn_seed_from_path(
    auth_db: &SqliteSnAuthDB,
    seed_path: &Path,
) -> SnResult<Option<SnSeedImportReport>> {
    if !seed_path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(seed_path).map_err(|e| {
        sn_err!(
            SnErrorCode::InvalidInput,
            "read sn seed config {} failed: {}",
            seed_path.display(),
            e
        )
    })?;
    let seed = parse_sn_seed_config(text.as_str())?;
    let report = import_sn_seed(auth_db, &seed).await?;
    Ok(Some(report))
}

/// 幂等导入（ensure-exists）。语义见模块注释；逐条处理，冲突仅告警不中断。
pub async fn import_sn_seed(
    auth_db: &SqliteSnAuthDB,
    seed: &SnSeedConfig,
) -> SnResult<SnSeedImportReport> {
    validate_sn_seed_config(seed)?;
    let mut report = SnSeedImportReport::default();

    // 1. 激活码：存在（含已用）→ no-op；不存在 → 插入。
    for code in &seed.activation_codes {
        let code = code.trim();
        if auth_db.has_activation_code(code).await? {
            report.activation_codes_existing += 1;
        } else {
            auth_db.insert_activation_code(code).await?;
            report.activation_codes_added += 1;
        }
    }

    // 2. sn_user 账号。
    for user in &seed.users {
        let username = user.username.trim();
        let email = canonical_email(user.email.as_str())?;
        let domain_entry = seed
            .user_domains
            .iter()
            .find(|entry| entry.owner == username);
        let public_key = canonical_public_key(user.owner_public_key.as_str());
        let zone_document_jwt = domain_entry.map(|entry| entry.zone_document_jwt.as_str());

        if auth_db.is_user_exist(username).await? {
            let existing = auth_db.get_user_info(username).await?.ok_or_else(|| {
                sn_err!(SnErrorCode::DBError, "user {} exists but unreadable", username)
            })?;
            let mut mismatches: Vec<&str> = Vec::new();
            if existing.public_key != public_key {
                mismatches.push("owner_public_key");
            }
            if existing.email.as_deref() != Some(email.as_str()) {
                mismatches.push("email");
            }
            if let Some(entry) = domain_entry {
                if existing.user_domain.as_deref() != Some(entry.domain.trim()) {
                    mismatches.push("user_domain");
                }
                if existing.zone_config != entry.zone_document_jwt {
                    mismatches.push("zone_document_jwt");
                }
            }
            if mismatches.is_empty() {
                if let Some(self_cert) = user.self_cert {
                    if existing.self_cert != self_cert {
                        auth_db.update_user_self_cert(username, self_cert).await?;
                        report.users_updated += 1;
                    }
                }
                report.users_existing += 1;
            } else {
                // ensure-exists：绝不覆盖运行中的账号/密码，只告警。
                warn!(
                    "sn seed user {} already exists with different {:?}; keep existing data, seed entry skipped",
                    username, mismatches
                );
                report.conflicts_skipped += 1;
            }
            continue;
        }

        if let Some(existing) = auth_db.get_user_by_email(email.as_str()).await? {
            warn!(
                "sn seed user {} email {} already belongs to {}; seed entry skipped",
                username,
                email,
                existing.username.as_deref().unwrap_or("<unknown>")
            );
            report.conflicts_skipped += 1;
            continue;
        }

        // 先建 auth（user_auth 与 users 都要求"用户不存在"，且 create_auth
        // 的守卫更严；若上次导入中途失败留下孤儿 auth 行，这里返回 false，
        // 继续走注册即可自愈）。
        let (password_hash, password_salt) = hash_password(user.password.as_str())
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash seed password failed: {}", e))?;
        let auth_created = auth_db
            .create_auth(
                username,
                password_hash.as_str(),
                password_salt.as_str(),
                PASSWORD_ALGO,
            )
            .await?;
        if !auth_created {
            warn!(
                "sn seed user {}: auth row already exists (previous partial import?); keep it",
                username
            );
        }

        let code = seed_user_activation_code(username);
        if !auth_db.has_activation_code(code.as_str()).await? {
            auth_db.insert_activation_code(code.as_str()).await?;
        }
        // user_domain 种子是开发捷径：register_user_with_owner_key 会把域名
        // 绑定直接置 verified/active（绕过 domain proof 流程）——仅 seed 路径
        // 允许这么做，线上绑定必须走 domain.bind 的服务端外部 DNS PKX proof。
        let registered = auth_db
            .register_user_with_owner_key(
                code.as_str(),
                username,
                email.as_str(),
                public_key.as_str(),
                zone_document_jwt.unwrap_or(""),
                domain_entry.map(|entry| entry.domain.trim().to_string()),
                None,
            )
            .await?;
        if !registered {
            warn!(
                "sn seed user {}: register_user_with_owner_key returned false; seed entry skipped",
                username
            );
            report.conflicts_skipped += 1;
            continue;
        }
        // bns_name 缺省即 username（register 已写入）；显式给出且不同时补投影。
        if let Some(bns_name) = user.bns_name.as_deref() {
            let bns_name = bns_name.trim();
            if !bns_name.is_empty() && bns_name != username {
                auth_db
                    .update_zone_info(
                        username,
                        ZoneInfoPatch {
                            bns_name: Some(bns_name.to_string()),
                            ..ZoneInfoPatch::default()
                        },
                    )
                    .await?;
            }
        }
        if let Some(self_cert) = user.self_cert {
            if self_cert {
                auth_db.update_user_self_cert(username, true).await?;
            }
        }
        report.users_added += 1;
    }

    // 3. user_domain 绑定（owner 不在本次 users 列表里的存量用户补绑定；
    //    在列表里的已随注册完成，这里核对后计入 existing）。
    for entry in &seed.user_domains {
        let domain = entry.domain.trim();
        let owner = entry.owner.trim();
        match auth_db.get_user_by_domain(domain).await? {
            Some(bound) => {
                let bound_user = bound.username.as_deref().unwrap_or_default();
                if bound_user != owner {
                    warn!(
                        "sn seed user_domain {} already bound to {} (seed owner {}); seed entry skipped",
                        domain, bound_user, owner
                    );
                    report.conflicts_skipped += 1;
                } else if bound.zone_config != entry.zone_document_jwt
                    || jwk_x_of(bound.public_key.as_str()).as_deref() != Some(entry.pkx.trim())
                {
                    warn!(
                        "sn seed user_domain {} exists with different zone document/pkx; keep existing data, seed entry skipped",
                        domain
                    );
                    report.conflicts_skipped += 1;
                } else {
                    report.user_domains_existing += 1;
                }
            }
            None => {
                if !auth_db.is_user_exist(owner).await? {
                    return Err(sn_err!(
                        SnErrorCode::InvalidInput,
                        "seed user_domain {} owner {} is neither in seed users nor in database",
                        domain,
                        owner
                    ));
                }
                // 开发捷径：直接写 ZoneDocument 并置 verified 绑定（绕过
                // domain proof），仅 seed 路径允许。
                auth_db
                    .update_user_zone_config(owner, entry.zone_document_jwt.as_str())
                    .await?;
                auth_db
                    .update_user_domain(owner, Some(domain.to_string()))
                    .await?;
                report.user_domains_added += 1;
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn_auth_manager::verify_password;

    const ALICE_X: &str = "uh7RD37tflN65CrcJSUQ3vGnyU4vmC7_M8IkEEOHnds";
    const BOB_X: &str = "iSMKakFEGzGAxLTlaB5TkqZ6d4wurObr-BpaQleoE2M";
    const CHARLIE_X: &str = "PY9uu16H74QYVRjstVxdWdAsgkoy10-74fvQhx4ddek";
    const CHARLIE_ZONE_JWT: &str = "eyJhbGciOiJFZERTQSJ9.charlie-zone-doc.sig";
    const SAMPLE_ACTIVATION_CODE_COUNT: u64 = 16;

    fn sample_seed_yaml() -> String {
        let activation_codes = (1..=SAMPLE_ACTIVATION_CODE_COUNT)
            .map(|i| format!("\"dev-code-{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
activation_codes: [{activation_codes}]
users:
  - username: alice
    email: "alice@buckyos.org"
    password: "devtest-pwd"
    owner_public_key: "{ALICE_X}"
    bns_name: alice
    self_cert: true
  - username: bob
    email: "bob@buckyos.org"
    password: "devtest-pwd"
    owner_public_key: "{BOB_X}"
    self_cert: true
  - username: charlie
    email: "charlie@buckyos.org"
    password: "devtest-pwd"
    owner_public_key: "{CHARLIE_X}"
    self_cert: true
user_domains:
  - domain: charlie.me
    owner: charlie
    pkx: "{CHARLIE_X}"
    zone_document_jwt: "{CHARLIE_ZONE_JWT}"
"#
        )
    }

    async fn new_test_db() -> (tempfile::TempDir, SqliteSnAuthDB, PathBuf) {
        let tmp_dir = tempfile::tempdir().expect("create temp dir");
        let db_path = tmp_dir.path().join("sn_seed_test.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref())
            .await
            .expect("open db");
        db.initialize_database().await.expect("init db");
        (tmp_dir, db, db_path)
    }

    /// 与导入路径无关的独立连接，用于对底层行数/时间戳做快照断言。
    async fn table_snapshot(db_path: &Path) -> Vec<(String, i64, i64)> {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(format!("sqlite://{}", db_path.display()).as_str())
            .await
            .expect("open snapshot connection");
        let mut result = Vec::new();
        for (table, stamp_expr) in [
            ("activation_codes", "COALESCE(SUM(used), 0)"),
            ("users", "COALESCE(SUM(created_at + updated_at), 0)"),
            ("user_auth", "COALESCE(SUM(created_at + updated_at), 0)"),
            ("zone_info", "COALESCE(SUM(updated_at), 0)"),
            (
                "user_domain_bindings",
                "COALESCE(SUM(created_at + updated_at), 0)",
            ),
        ] {
            let sql = format!("SELECT COUNT(*), {} FROM {}", stamp_expr, table);
            let row: (i64, i64) = sqlx::query_as(sql.as_str())
                .fetch_one(&pool)
                .await
                .expect("snapshot query");
            result.push((table.to_string(), row.0, row.1));
        }
        pool.close().await;
        result
    }

    #[tokio::test]
    async fn test_sn_seed_fresh_import() {
        let (_tmp, db, _db_path) = new_test_db().await;
        let seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        let report = import_sn_seed(&db, &seed).await.expect("import seed");

        assert_eq!(report.activation_codes_added, SAMPLE_ACTIVATION_CODE_COUNT);
        assert_eq!(report.users_added, 3);
        // charlie 的绑定随注册完成，域名循环里应计入 existing 而非重复添加。
        assert_eq!(report.user_domains_added, 0);
        assert_eq!(report.user_domains_existing, 1);
        assert_eq!(report.conflicts_skipped, 0);

        // 账号可查、公钥为 canonical JWK JSON。
        let alice = db.get_user_info("alice").await.unwrap().expect("alice");
        assert_eq!(alice.email.as_deref(), Some("alice@buckyos.org"));
        assert_eq!(
            alice.public_key,
            format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, ALICE_X)
        );
        assert!(alice.user_domain.is_none());
        assert_eq!(alice.zone_config, "");
        assert!(alice.self_cert);
        assert!(
            db.get_zone_info("alice")
                .await
                .unwrap()
                .expect("alice zone_info")
                .self_cert
        );

        // 测试密码可登录（走现有 PBKDF2 校验路径）。
        let auth = db.get_auth("alice").await.unwrap().expect("alice auth");
        assert_eq!(auth.password_algo, PASSWORD_ALGO);
        assert!(verify_password("devtest-pwd", &auth).expect("verify"));
        assert!(!verify_password("wrong-pwd", &auth).expect("verify"));

        // 种子激活码可用（未被种子用户注册消耗）。
        for i in 1..=SAMPLE_ACTIVATION_CODE_COUNT {
            let code = format!("dev-code-{i}");
            assert!(
                db.check_active_code(&code).await.unwrap(),
                "{code} should be available"
            );
        }

        // user_domain 绑定存在且 ZoneDocument 就位。
        let charlie = db
            .get_user_by_domain("charlie.me")
            .await
            .unwrap()
            .expect("charlie.me binding");
        assert_eq!(charlie.username.as_deref(), Some("charlie"));
        assert_eq!(charlie.zone_config, CHARLIE_ZONE_JWT);
        assert_eq!(charlie.user_domain.as_deref(), Some("charlie.me"));
    }

    #[tokio::test]
    async fn test_sn_seed_reimport_zero_changes() {
        let (_tmp, db, db_path) = new_test_db().await;
        let seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        import_sn_seed(&db, &seed).await.expect("first import");

        let before = table_snapshot(db_path.as_path()).await;
        let report = import_sn_seed(&db, &seed).await.expect("second import");
        let after = table_snapshot(db_path.as_path()).await;

        assert!(report.is_noop(), "second import must be a no-op: {report}");
        assert_eq!(report.users_existing, 3);
        assert_eq!(
            report.activation_codes_existing,
            SAMPLE_ACTIVATION_CODE_COUNT
        );
        assert_eq!(report.conflicts_skipped, 0);
        // 行数与 created_at/updated_at 快照完全不变（零写入）。
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_sn_seed_omitted_self_cert_keeps_safe_default() {
        let (_tmp, db, _db_path) = new_test_db().await;
        let mut seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        seed.users.truncate(1);
        seed.users[0].self_cert = None;
        seed.user_domains.clear();

        import_sn_seed(&db, &seed).await.expect("import seed");

        assert!(!db
            .get_user_info("alice")
            .await
            .unwrap()
            .expect("alice")
            .self_cert);
        assert!(!db
            .get_zone_info("alice")
            .await
            .unwrap()
            .expect("alice zone_info")
            .self_cert);
    }

    #[tokio::test]
    async fn test_sn_seed_explicit_self_cert_repairs_seed_user_projection() {
        let (_tmp, db, _db_path) = new_test_db().await;
        let seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        import_sn_seed(&db, &seed).await.expect("first import");

        db.update_user_self_cert("alice", false)
            .await
            .expect("clear self_cert");
        let report = import_sn_seed(&db, &seed).await.expect("repair import");

        assert_eq!(report.users_updated, 1);
        assert!(!report.is_noop());
        assert!(
            db.get_user_info("alice")
                .await
                .unwrap()
                .expect("alice")
                .self_cert
        );
        assert!(
            db.get_zone_info("alice")
                .await
                .unwrap()
                .expect("alice zone_info")
                .self_cert
        );
    }

    #[tokio::test]
    async fn test_sn_seed_conflict_keeps_existing_data() {
        let (_tmp, db, _db_path) = new_test_db().await;

        // 预置一个同名但公钥不同的 alice（模拟运行中的真实账号）。
        db.insert_activation_code("pre-code").await.unwrap();
        let (hash, salt) = hash_password("real-user-pwd").unwrap();
        assert!(db
            .create_auth("alice", hash.as_str(), salt.as_str(), PASSWORD_ALGO)
            .await
            .unwrap());
        assert!(db
            .register_user_with_owner_key(
                "pre-code",
                "alice",
                "alice@buckyos.org",
                r#"{"crv":"Ed25519","kty":"OKP","x":"existing-different-key"}"#,
                "existing-zone-cfg",
                None,
                None,
            )
            .await
            .unwrap());

        let seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        let report = import_sn_seed(&db, &seed).await.expect("import seed");

        // alice 冲突跳过，其余照常导入。
        assert_eq!(report.conflicts_skipped, 1);
        assert_eq!(report.users_added, 2);

        // 原数据（公钥/密码/zone_config）一律不动。
        let alice = db.get_user_info("alice").await.unwrap().expect("alice");
        assert_eq!(
            alice.public_key,
            r#"{"crv":"Ed25519","kty":"OKP","x":"existing-different-key"}"#
        );
        assert_eq!(alice.zone_config, "existing-zone-cfg");
        let auth = db.get_auth("alice").await.unwrap().expect("alice auth");
        assert!(verify_password("real-user-pwd", &auth).expect("verify"));
        assert!(!verify_password("devtest-pwd", &auth).expect("verify"));
    }

    #[tokio::test]
    async fn test_sn_seed_missing_file_skips_and_bad_file_fails() {
        let (_tmp, db, _db_path) = new_test_db().await;
        let dir = tempfile::tempdir().expect("create temp dir");

        // 文件缺失 → Ok(None)，正常启动。
        let missing = dir.path().join("sn_seed.yaml");
        let result = import_sn_seed_from_path(&db, missing.as_path())
            .await
            .expect("missing file is not an error");
        assert!(result.is_none());

        // 格式坏 → Err，启动失败。
        let bad = dir.path().join("bad_seed.yaml");
        std::fs::write(bad.as_path(), "users: {not: [a, list}").expect("write bad seed");
        assert!(import_sn_seed_from_path(&db, bad.as_path()).await.is_err());

        // 语义坏（domain owner 缺失）→ Err。
        let orphan = dir.path().join("orphan_seed.yaml");
        std::fs::write(
            orphan.as_path(),
            "user_domains:\n  - domain: nobody.me\n    owner: nobody\n    pkx: x\n    zone_document_jwt: jwt\n",
        )
        .expect("write orphan seed");
        assert!(import_sn_seed_from_path(&db, orphan.as_path())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_sn_seed_domain_backfill_for_existing_user() {
        let (_tmp, db, _db_path) = new_test_db().await;

        // 先只导入用户（无 user_domains 的种子），再用带域名的种子补绑定，
        // 覆盖"存量用户补 user_domain"的路径。
        let mut seed = parse_sn_seed_config(sample_seed_yaml().as_str()).expect("parse seed");
        let domains = std::mem::take(&mut seed.user_domains);
        import_sn_seed(&db, &seed).await.expect("import users only");

        seed.user_domains = domains;
        seed.users.clear();
        let report = import_sn_seed(&db, &seed).await.expect("import domains");
        assert_eq!(report.user_domains_added, 1);

        let charlie = db
            .get_user_by_domain("charlie.me")
            .await
            .unwrap()
            .expect("charlie.me binding");
        assert_eq!(charlie.username.as_deref(), Some("charlie"));
        assert_eq!(charlie.zone_config, CHARLIE_ZONE_JWT);
    }
}
