use crate::{sn_err, SnError, SnErrorCode, SnResult};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVATION_CODE_LEN: usize = 32;
const ACTIVATION_CODE_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const DOMAIN_BINDING_ACTIVE: &str = "active";
const DOMAIN_BINDING_REVOKED: &str = "revoked";
const DOMAIN_BINDING_SUPERSEDED: &str = "superseded";
const SESSION_ACTIVE: &str = "active";
const SESSION_REVOKED: &str = "revoked";

pub type SnAuthDBRef = Arc<dyn SnAuthDB>;

/// 注册邮箱规范化与基本格式校验。
///
/// SN 把邮箱作为本地账号找回标识，不写入 BNS。当前产品规则是 trim 后将
/// ASCII 地址整体转成小写；不接受 quoted local-part、非 ASCII 地址或非法的
/// DNS label。所有唯一性查询和持久化都必须使用本函数的返回值。
pub fn canonical_email(email: &str) -> SnResult<String> {
    let email = email.trim();
    if email.is_empty() || email.len() > 254 || !email.is_ascii() {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email must be a non-empty ASCII address no longer than 254 bytes"
        ));
    }

    let (local, domain) = email.split_once('@').ok_or_else(|| {
        sn_err!(
            SnErrorCode::InvalidInput,
            "email must contain exactly one @ separator"
        )
    })?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.contains('@')
    {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email local part or domain is invalid"
        ));
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
    {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email local part has invalid syntax"
        ));
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email domain has invalid syntax"
        ));
    }

    Ok(email.to_ascii_lowercase())
}

/// user_domain 规范化：trim、去尾部 `.`、小写、去可选 `*.` 前缀。
/// 空结果（空串、仅点、仅通配）返回 None。
pub fn canonical_user_domain(domain: &str) -> Option<String> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let canonical = normalized
        .strip_prefix("*.")
        .unwrap_or(normalized.as_str())
        .to_string();
    if canonical.is_empty() || canonical == "*" {
        None
    } else {
        Some(canonical)
    }
}

/// PKX proof TXT 的固定 DNS name：`_pkx.<canonical-domain>`。
pub fn pkx_record_name(canonical_domain: &str) -> String {
    format!("_pkx.{}", canonical_domain)
}

/// 从 owner key 材料中提取 `sn_user.pkx`（公开身份）：
/// - JWK JSON（`{`开头）→ `x` 分量；
/// - `PKX=<x>[:...][;]` 形式 → `<x>`；
/// - 其余原样 trim（兼容已是裸 x 或测试占位串的输入）。
///
/// 空输入返回 None。
pub fn pkx_source_of(key_material: &str) -> Option<String> {
    let trimmed = key_material.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(x) = value.get("x").and_then(|v| v.as_str()) {
                let x = x.trim();
                if !x.is_empty() {
                    return Some(x.to_string());
                }
            }
        }
        return Some(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("PKX=") {
        let x = rest.split([':', ';']).next().unwrap_or("").trim();
        return if x.is_empty() {
            None
        } else {
            Some(x.to_string())
        };
    }
    Some(trimmed.trim_end_matches(';').to_string())
}

/// PKX 记录值的唯一生成 helper：`PKX(<sn_user.pkx>)`。
/// 稳定状态、无 nonce/exp；SN 接管 DNS 后继续发布同一值。
pub fn pkx_value(key_material: &str) -> SnResult<String> {
    let source = pkx_source_of(key_material).ok_or_else(|| {
        sn_err!(
            SnErrorCode::InvalidInput,
            "owner key ref or public key is required before creating PKX binding"
        )
    })?;
    Ok(format!("PKX({})", source))
}

/// TXT 值与期望 PKX 的比对：容忍首尾空白与包裹引号。
/// 多条 TXT / 多段拼接由外部 DNS 查询层归一后逐条传入。
pub fn txt_matches_pkx(txt: &str, expected_pkx: &str) -> bool {
    txt.trim().trim_matches('"').trim() == expected_pkx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    Active,
    Suspended,
    Deleted,
    Banned,
}

impl ToString for UserState {
    fn to_string(&self) -> String {
        match self {
            UserState::Active => "active".to_string(),
            UserState::Suspended => "suspended".to_string(),
            UserState::Deleted => "deleted".to_string(),
            UserState::Banned => "banned".to_string(),
        }
    }
}

impl UserState {
    pub fn from_str(s: Option<&str>) -> Self {
        match s {
            Some("suspended") => UserState::Suspended,
            Some("deleted") => UserState::Deleted,
            Some("banned") => UserState::Banned,
            _ => UserState::Active,
        }
    }

    fn is_active(&self) -> bool {
        matches!(self, UserState::Active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNUserInfo {
    pub username: Option<String>,
    /// 存量/seed 账号在补录前为 None；所有 `auth.register` 新账号必有值。
    #[serde(default)]
    pub email: Option<String>,
    pub state: UserState,
    pub public_key: String,
    pub activation_code: Option<String>,
    pub zone_config: String,
    pub self_cert: bool,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnClearStateResult {
    pub deleted_users: u64,
    pub deleted_devices: u64,
    pub deleted_domain_records: u64,
    pub deleted_did_documents: u64,
    pub activation_code_reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthInfo {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBinding {
    pub username: String,
    pub domain: String,
    pub pkx: String,
    pub pkx_record_name: String,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInfo {
    pub username: String,
    pub bns_name: String,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
    pub updated_at: u64,
}

impl ZoneInfo {
    pub fn default_for(username: &str) -> Self {
        Self {
            username: username.to_string(),
            bns_name: username.to_string(),
            zone: None,
            relay_sn: None,
            self_cert: false,
            cert_checked_at: None,
            cert_expires_at: None,
            sn_ips: None,
            source_version: None,
            updated_at: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneInfoPatch {
    pub bns_name: Option<String>,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: Option<bool>,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSession {
    pub session_id: String,
    pub username: String,
    pub token_aud: String,
    pub state: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[async_trait::async_trait]
pub trait SnAuthDB: Send + Sync + 'static {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>>;
    async fn insert_activation_code(&self, code: &str) -> SnResult<()>;
    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>>;
    async fn check_active_code(&self, active_code: &str) -> SnResult<bool>;
    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult>;
    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn is_user_exist(&self, username: &str) -> SnResult<bool>;
    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>>;
    /// trusted 路径（seed/import）专用：不经 DNS PKX proof 直接注册并激活
    /// `user_domain` 绑定。不得从对外 RPC 直接暴露。
    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool>;
    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>>;
    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>>;
    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()>;
    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()>;
    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()>;
    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()>;
    /// trusted 路径（seed/import）专用：不经 DNS PKX proof 直接把 `user_domain`
    /// 置 active（或传 None 撤销全部 active 绑定）。不得从对外 RPC 直接暴露；
    /// 线上绑定必须走 `domain.bind` 的服务端 DNS proof + `activate_user_domain_binding`。
    async fn update_user_domain(&self, username: &str, user_domain: Option<String>)
        -> SnResult<()>;
    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>>;
    async fn get_user_sn_ips_as_vec(&self, username: &str) -> SnResult<Option<Vec<String>>> {
        let Some(sn_ips) = self.get_user_sn_ips(username).await? else {
            return Ok(None);
        };
        if sn_ips.trim().is_empty() {
            return Ok(Some(Vec::new()));
        }
        match serde_json::from_str::<Vec<String>>(sn_ips.as_str()) {
            Ok(ips) => Ok(Some(ips)),
            Err(_) => Ok(Some(
                sn_ips
                    .split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(ToString::to_string)
                    .collect(),
            )),
        }
    }
    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>>;
    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()>;

    /// 外部 DNS PKX proof 成功后的激活入口。信任边界：调用方（SN 服务端
    /// `domain.bind`）必须已完成服务端侧 DNS TXT 校验，本方法不做 proof。
    ///
    /// 同一事务内：supersede 同一 canonical domain 的旧 active binding（并清理
    /// 旧 owner 的 `users.user_domain` 兼容缓存）、写入当前 active binding、
    /// 更新本用户 `users.user_domain`、追加 `user_domain_history` 审计记录。
    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding>;
    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()>;

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>>;
    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()>;
    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        let _ = (zone, relay_sn, source_version);
        Ok(false)
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()>;
    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()>;
    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64>;
    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>>;
}

/// Remote SnAuthDB backed by the sn_auth_db S2S KRPC API.
#[derive(Clone)]
pub struct RemoteSnAuthDB {
    client: crate::s2s_api::SnAuthDbClient,
}

impl RemoteSnAuthDB {
    pub fn new(client: crate::s2s_api::SnAuthDbClient) -> Self {
        Self { client }
    }

    pub fn new_krpc(client: std::sync::Arc<::kRPC::kRPC>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc(client))
    }

    pub fn new_krpc_url(auth_db_url: &str, session_token: Option<String>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc_url(
            auth_db_url,
            session_token,
        ))
    }

    pub fn client(&self) -> &crate::s2s_api::SnAuthDbClient {
        &self.client
    }
}

#[async_trait::async_trait]
impl SnAuthDB for RemoteSnAuthDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        self.client.get_activation_codes().await
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        self.client.insert_activation_code(code).await
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        self.client.generate_activation_codes(count).await
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        self.client.check_active_code(active_code).await
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        self.client.clear_state_by_active_code(active_code).await
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .register_user(
                active_code,
                username,
                email,
                password_hash,
                password_salt,
                password_algo,
            )
            .await
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .create_auth(username, password_hash, password_salt, password_algo)
            .await
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        self.client.is_user_exist(username).await
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_by_email(email).await
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        self.client
            .register_user_with_owner_key(
                active_code,
                username,
                email,
                public_key,
                zone_config,
                user_domain,
                sn_ips,
            )
            .await
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        self.client.get_user_by_public_key(public_key).await
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_info(username).await
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_by_domain(domain).await
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        self.client.set_user_state(username, state).await
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        self.client
            .update_user_public_key(username, public_key)
            .await
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.client
            .update_user_zone_config(username, zone_config)
            .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.client.update_user_self_cert(username, self_cert).await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        self.client.update_user_domain(username, user_domain).await
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        self.client.get_user_sn_ips(username).await
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        self.client.get_auth(username).await
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        self.client.update_last_login(username, last_login_at).await
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        self.client
            .activate_user_domain_binding(username, domain, pkx)
            .await
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        self.client.unbind_user_domain(username, domain).await
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        self.client.get_zone_info(username).await
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        self.client.update_zone_info(username, patch).await
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        self.client
            .update_zone_relay_sn(zone, relay_sn, source_version)
            .await
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        self.client
            .create_account_session(session_id, username, token_aud, issued_at, expires_at)
            .await
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        self.client
            .revoke_account_session(session_id, revoked_at)
            .await
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        self.client.revoke_user_sessions(username, revoked_at).await
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        self.client.get_account_session(session_id).await
    }
}

pub struct SqliteSnAuthDB {
    pool: SqlitePool,
}

impl SqliteSnAuthDB {
    const USER_DOMAIN_BINDING_LOCK: &'static str = "sn_user_domain_binding";

    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_auth.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().as_ref()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let db_url = if path.starts_with("sqlite:") {
            path.to_string()
        } else {
            format!("sqlite://{}", path)
        };
        let options = SqliteConnectOptions::from_str(db_url.as_str())
            .map_err(|e| Self::db_err("parse sqlite url failed", e))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(300)
            .connect_with(options)
            .await
            .map_err(|e| Self::db_err(format!("open file: {:?}", path), e))?;

        Ok(Self { pool })
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS activation_codes (
                code TEXT PRIMARY KEY,
                used INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create activation_codes table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT NULL,
                state TEXT NOT NULL DEFAULT 'active',
                bns_name TEXT,
                public_key TEXT NOT NULL DEFAULT '',
                activation_code TEXT,
                owner_key_ref TEXT,
                zone_config TEXT NOT NULL DEFAULT '',
                self_cert INTEGER NOT NULL DEFAULT 0,
                user_domain TEXT,
                sn_ips TEXT,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                last_login_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create users table failed", e))?;
        self.ensure_user_columns().await?;
        // SQLite 允许 UNIQUE 索引中存在多行 NULL：存量/seed 账号可以先不补录，
        // 但所有带邮箱的新注册都由数据库保证全局一对一。
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
             ON users (email) WHERE email IS NOT NULL",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create users email unique index failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_auth (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_algo TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_auth table failed", e))?;

        // 审计事件表：每次绑定获得（新建/接管）追加一行；历史仅审计，
        // 不参与冲突判定。旧 schema（domain 主键）会被迁移重建。
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_domain_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                owner TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_history table failed", e))?;
        self.migrate_legacy_user_domain_table(
            "user_domain_history",
            "id INTEGER PRIMARY KEY AUTOINCREMENT,
             domain TEXT NOT NULL,
             owner TEXT NOT NULL,
             created_at INTEGER NOT NULL",
            "domain, owner, created_at",
            None,
        )
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_user_domain_history_domain
             ON user_domain_history (domain)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_history index failed", e))?;

        // 绑定状态表：state ∈ active|revoked|superseded；同一 canonical domain
        // 至多一行 active（部分唯一索引），revoked/superseded 行保留作状态审计。
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_domain_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                owner TEXT NOT NULL,
                state TEXT NOT NULL,
                pkx TEXT NOT NULL,
                pkx_record_name TEXT NOT NULL,
                verified_at INTEGER NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_bindings table failed", e))?;
        // 旧 schema（domain 主键、含 pending_pkx 挑战态）迁移重建；
        // pending_pkx 是已移除的中间态，直接丢弃。
        self.migrate_legacy_user_domain_table(
            "user_domain_bindings",
            "id INTEGER PRIMARY KEY AUTOINCREMENT,
             domain TEXT NOT NULL,
             owner TEXT NOT NULL,
             state TEXT NOT NULL,
             pkx TEXT NOT NULL,
             pkx_record_name TEXT NOT NULL,
             verified_at INTEGER NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL",
            "domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at",
            Some("state != 'pending_pkx'"),
        )
        .await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_domain_bindings_domain_active
             ON user_domain_bindings (domain) WHERE state = 'active'",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_bindings active index failed", e))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_user_domain_bindings_owner_state
             ON user_domain_bindings (owner, state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create user_domain_bindings index failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS zone_info (
                username TEXT PRIMARY KEY,
                bns_name TEXT NOT NULL,
                zone TEXT NULL,
                relay_sn TEXT NULL,
                self_cert INTEGER NOT NULL DEFAULT 0,
                cert_checked_at INTEGER NULL,
                cert_expires_at INTEGER NULL,
                sn_ips TEXT NULL,
                source_version TEXT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create zone_info table failed", e))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS account_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                token_aud TEXT NOT NULL,
                state TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create account_sessions table failed", e))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_account_sessions_username_state
             ON account_sessions (username, state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("create account_sessions index failed", e))?;

        Ok(())
    }

    /// seed 导入用：激活码是否存在（含已使用的码；`get_activation_codes`
    /// 只返回未使用的）。
    pub async fn has_activation_code(&self, code: &str) -> SnResult<bool> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activation_codes WHERE code = ?1",
        )
        .bind(code)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::db_err("query activation code failed", e))?;
        Ok(count > 0)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn generate_activation_code() -> String {
        let mut rng = rand::rng();
        (0..ACTIVATION_CODE_LEN)
            .map(|_| {
                let index = rng.random_range(0..ACTIVATION_CODE_CHARS.len());
                ACTIVATION_CODE_CHARS[index] as char
            })
            .collect()
    }

    fn db_err(context: impl AsRef<str>, err: impl std::fmt::Display) -> SnError {
        sn_err!(SnErrorCode::DBError, "{}: {}", context.as_ref(), err)
    }

    fn invalid_input(context: impl AsRef<str>) -> SnError {
        sn_err!(SnErrorCode::InvalidInput, "{}", context.as_ref())
    }

    fn email_already_bound(email: &str) -> SnError {
        sn_err!(
            SnErrorCode::Conflict,
            "email already bound: {}",
            email
        )
    }

    fn insert_user_err(email: &str, error: sqlx::Error) -> SnError {
        let is_email_unique_violation = error
            .as_database_error()
            .is_some_and(|db_error| {
                db_error.is_unique_violation()
                    && db_error.message().to_ascii_lowercase().contains("users.email")
            });
        if is_email_unique_violation {
            Self::email_already_bound(email)
        } else {
            Self::db_err("insert user failed", error)
        }
    }

    fn check_non_empty(value: &str, field: &str) -> SnResult<()> {
        if value.trim().is_empty() {
            return Err(Self::invalid_input(format!("{} is empty", field)));
        }

        Ok(())
    }

    fn i64_to_u64(value: i64) -> u64 {
        value.max(0) as u64
    }

    fn opt_i64_to_u64(value: Option<i64>) -> Option<u64> {
        value.map(Self::i64_to_u64)
    }

    async fn ensure_user_columns(&self) -> SnResult<()> {
        // Breaking-change migration policy: legacy rows keep NULL until a separate,
        // authenticated backfill flow is introduced. Public auth.register never writes NULL.
        self.ensure_column("users", "email", "TEXT NULL").await?;
        self.ensure_column("users", "bns_name", "TEXT").await?;
        self.ensure_column("users", "owner_key_ref", "TEXT").await?;
        self.ensure_column("users", "created_at", "INTEGER NOT NULL DEFAULT 0")
            .await?;
        self.ensure_column("users", "updated_at", "INTEGER NOT NULL DEFAULT 0")
            .await?;
        self.ensure_column("users", "last_login_at", "INTEGER NULL")
            .await?;
        Ok(())
    }

    async fn ensure_column(&self, table: &str, column: &str, definition: &str) -> SnResult<()> {
        let pragma = format!("PRAGMA table_info({})", table);
        let rows = sqlx::query(pragma.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err(format!("query {} columns failed", table), e))?;
        let exists = rows.iter().any(|row| {
            row.try_get::<String, _>("name")
                .map(|name| name == column)
                .unwrap_or(false)
        });
        if !exists {
            let alter = format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, definition);
            sqlx::query(alter.as_str())
                .execute(&self.pool)
                .await
                .map_err(|e| Self::db_err(format!("add {}.{} failed", table, column), e))?;
        }
        Ok(())
    }

    /// 旧 user_domain 表（domain 主键、无 `id` 列）→ 新 id 主键 schema 的重建
    /// 迁移。以 `id` 列缺失作为旧 schema 判据；`copy_filter` 用于丢弃已移除的
    /// 状态（如 `pending_pkx`）。
    async fn migrate_legacy_user_domain_table(
        &self,
        table: &str,
        columns_def: &str,
        copy_columns: &str,
        copy_filter: Option<&str>,
    ) -> SnResult<()> {
        let pragma = format!("PRAGMA table_info({})", table);
        let rows = sqlx::query(pragma.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err(format!("query {} columns failed", table), e))?;
        let has_id = rows.iter().any(|row| {
            row.try_get::<String, _>("name")
                .map(|name| name == "id")
                .unwrap_or(false)
        });
        if has_id {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let legacy = format!("{}_legacy", table);
        sqlx::query(format!("ALTER TABLE {} RENAME TO {}", table, legacy).as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err(format!("rename legacy {} failed", table), e))?;
        sqlx::query(format!("CREATE TABLE {} ({})", table, columns_def).as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err(format!("recreate {} failed", table), e))?;
        let filter = copy_filter
            .map(|clause| format!(" WHERE {}", clause))
            .unwrap_or_default();
        sqlx::query(
            format!(
                "INSERT INTO {} ({}) SELECT {} FROM {}{}",
                table, copy_columns, copy_columns, legacy, filter
            )
            .as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err(format!("copy legacy {} rows failed", table), e))?;
        sqlx::query(format!("DROP TABLE {}", legacy).as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err(format!("drop legacy {} failed", table), e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        log::info!("migrated legacy {} table to id-keyed schema", table);
        Ok(())
    }

    async fn table_exists_tx(tx: &mut Transaction<'_, Sqlite>, table_name: &str) -> SnResult<bool> {
        let row = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(table_name)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Self::db_err("query sqlite_master failed", e))?;
        Ok(row.is_some())
    }

    async fn count_optional_related_rows(
        tx: &mut Transaction<'_, Sqlite>,
        table_name: &str,
        active_code: &str,
    ) -> SnResult<i64> {
        if !Self::table_exists_tx(tx, table_name).await? {
            return Ok(0);
        }

        let sql = match table_name {
            "devices" => {
                "SELECT COUNT(*) FROM devices
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            "user_dns_records" => {
                "SELECT COUNT(*) FROM user_dns_records
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            "did_documents" => {
                "SELECT COUNT(*) FROM did_documents
                 WHERE owner_user IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            }
            _ => return Ok(0),
        };

        sqlx::query_scalar::<_, i64>(sql)
            .bind(active_code)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| Self::db_err(format!("count {} failed", table_name), e))
    }

    async fn delete_optional_related_rows(
        tx: &mut Transaction<'_, Sqlite>,
        active_code: &str,
    ) -> SnResult<()> {
        if Self::table_exists_tx(tx, "devices").await? {
            sqlx::query(
                "DELETE FROM devices
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete devices failed", e))?;
        }

        if Self::table_exists_tx(tx, "user_dns_records").await? {
            sqlx::query(
                "DELETE FROM user_dns_records
                 WHERE owner IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete user dns records failed", e))?;
        }

        if Self::table_exists_tx(tx, "did_documents").await? {
            sqlx::query(
                "DELETE FROM did_documents
                 WHERE owner_user IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )",
            )
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("delete did documents failed", e))?;
        }

        Ok(())
    }

    /// 激活绑定的共享事务逻辑（调用方保证已完成 proof 或走 trusted 路径）。
    ///
    /// 冲突规则（Beta2.2）：`user_domain_history` 仅审计、不阻止绑定；同一
    /// canonical domain 的旧 active binding 被 supersede（旧 owner 的
    /// `users.user_domain` 兼容缓存同步清空）；父/子域名互不排斥，解析按最长
    /// active binding 匹配。同 owner 重复激活仅刷新 pkx/verified_at，不追加审计。
    async fn activate_binding_tx(
        tx: &mut Transaction<'_, Sqlite>,
        username: &str,
        canonical_domain: &str,
        pkx: &str,
        now: i64,
    ) -> SnResult<()> {
        let record_name = pkx_record_name(canonical_domain);
        let existing = sqlx::query(
            "SELECT id, owner FROM user_domain_bindings
             WHERE domain = ?1 AND state = ?2",
        )
        .bind(canonical_domain)
        .bind(DOMAIN_BINDING_ACTIVE)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query active user_domain binding failed", e))?;

        let mut refreshed = false;
        if let Some(row) = existing {
            let binding_id: i64 = row
                .try_get("id")
                .map_err(|e| Self::db_err("read binding id failed", e))?;
            let owner: String = row
                .try_get("owner")
                .map_err(|e| Self::db_err("read binding owner failed", e))?;
            if owner == username {
                sqlx::query(
                    "UPDATE user_domain_bindings
                     SET pkx = ?1, pkx_record_name = ?2, verified_at = ?3, updated_at = ?3
                     WHERE id = ?4",
                )
                .bind(pkx)
                .bind(record_name.as_str())
                .bind(now)
                .bind(binding_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("refresh user_domain binding failed", e))?;
                refreshed = true;
            } else {
                sqlx::query(
                    "UPDATE user_domain_bindings
                     SET state = ?1, updated_at = ?2
                     WHERE id = ?3",
                )
                .bind(DOMAIN_BINDING_SUPERSEDED)
                .bind(now)
                .bind(binding_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("supersede user_domain binding failed", e))?;
                sqlx::query(
                    "UPDATE users
                     SET user_domain = NULL, updated_at = ?1
                     WHERE username = ?2 AND user_domain = ?3",
                )
                .bind(now)
                .bind(owner.as_str())
                .bind(canonical_domain)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("clear superseded user_domain cache failed", e))?;
            }
        }

        if !refreshed {
            sqlx::query(
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)",
            )
            .bind(canonical_domain)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .bind(pkx)
            .bind(record_name.as_str())
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain binding failed", e))?;
            sqlx::query(
                "INSERT INTO user_domain_history (domain, owner, created_at)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(canonical_domain)
            .bind(username)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain history failed", e))?;
        }

        sqlx::query("UPDATE users SET user_domain = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(canonical_domain)
            .bind(now)
            .bind(username)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("update user_domain failed", e))?;

        Ok(())
    }

    fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<SNUserInfo> {
        let state_str: Option<String> = row
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        let self_cert: Option<i64> = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        Ok(SNUserInfo {
            username: Some(
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
            ),
            email: row
                .try_get("email")
                .map_err(|e| Self::db_err("read email failed", e))?,
            state: UserState::from_str(state_str.as_deref()),
            public_key: row
                .try_get::<Option<String>, _>("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?
                .unwrap_or_default(),
            activation_code: row
                .try_get("activation_code")
                .map_err(|e| Self::db_err("read activation_code failed", e))?,
            zone_config: row
                .try_get::<Option<String>, _>("zone_config")
                .map_err(|e| Self::db_err("read zone_config failed", e))?
                .unwrap_or_default(),
            self_cert: self_cert.unwrap_or(0) != 0,
            user_domain: row
                .try_get("user_domain")
                .map_err(|e| Self::db_err("read user_domain failed", e))?,
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
        })
    }

    fn zone_info_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<ZoneInfo> {
        let self_cert: i64 = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        let updated_at: i64 = row
            .try_get("updated_at")
            .map_err(|e| Self::db_err("read updated_at failed", e))?;
        Ok(ZoneInfo {
            username: row
                .try_get("username")
                .map_err(|e| Self::db_err("read username failed", e))?,
            bns_name: row
                .try_get("bns_name")
                .map_err(|e| Self::db_err("read bns_name failed", e))?,
            zone: row
                .try_get("zone")
                .map_err(|e| Self::db_err("read zone failed", e))?,
            relay_sn: row
                .try_get("relay_sn")
                .map_err(|e| Self::db_err("read relay_sn failed", e))?,
            self_cert: self_cert != 0,
            cert_checked_at: Self::opt_i64_to_u64(
                row.try_get("cert_checked_at")
                    .map_err(|e| Self::db_err("read cert_checked_at failed", e))?,
            ),
            cert_expires_at: Self::opt_i64_to_u64(
                row.try_get("cert_expires_at")
                    .map_err(|e| Self::db_err("read cert_expires_at failed", e))?,
            ),
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            source_version: row
                .try_get("source_version")
                .map_err(|e| Self::db_err("read source_version failed", e))?,
            updated_at: Self::i64_to_u64(updated_at),
        })
    }
}

#[async_trait::async_trait]
impl SnAuthDB for SqliteSnAuthDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        let rows = sqlx::query("SELECT code FROM activation_codes WHERE used = 0")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("query activation_codes failed", e))?;
        rows.into_iter()
            .map(|row| {
                row.try_get(0)
                    .map_err(|e| Self::db_err("read activation code failed", e))
            })
            .collect()
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        sqlx::query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("insert activation_codes failed", e))?;
        Ok(())
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        let mut codes = Vec::with_capacity(count);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        while codes.len() < count {
            let code = Self::generate_activation_code();
            let result =
                sqlx::query("INSERT OR IGNORE INTO activation_codes (code, used) VALUES (?1, 0)")
                    .bind(code.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("insert activation_codes failed", e))?;

            if result.rows_affected() > 0 {
                codes.push(code);
            }
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(codes)
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        let used =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?;
        Ok(used == Some(0))
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE activation_code = ?1")
                .bind(active_code)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("count users failed", e))?;
        let device_count =
            Self::count_optional_related_rows(&mut tx, "devices", active_code).await?;
        let domain_record_count =
            Self::count_optional_related_rows(&mut tx, "user_dns_records", active_code).await?;
        let did_doc_count =
            Self::count_optional_related_rows(&mut tx, "did_documents", active_code).await?;

        Self::delete_optional_related_rows(&mut tx, active_code).await?;

        sqlx::query(
            "DELETE FROM account_sessions
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete account sessions failed", e))?;

        sqlx::query(
            "DELETE FROM user_domain_bindings
             WHERE owner IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete user domain bindings failed", e))?;

        sqlx::query(
            "DELETE FROM zone_info
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete zone info failed", e))?;

        sqlx::query(
            "DELETE FROM user_auth
             WHERE username IN (
                SELECT username FROM users WHERE activation_code = ?1
             )",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete user auth failed", e))?;

        sqlx::query("DELETE FROM users WHERE activation_code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("delete users failed", e))?;

        sqlx::query(
            "INSERT INTO activation_codes (code, used) VALUES (?1, 0)
             ON CONFLICT(code) DO UPDATE SET used = 0",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("reset activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(SnClearStateResult {
            deleted_users: user_count.max(0) as u64,
            deleted_devices: device_count.max(0) as u64,
            deleted_domain_records: domain_record_count.max(0) as u64,
            deleted_did_documents: did_doc_count.max(0) as u64,
            activation_code_reset: true,
        })
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let email = canonical_email(email)?;
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        // 同进程内尽早串行化同邮箱注册，数据库 UNIQUE 索引仍是跨进程/竞态兜底。
        let _email_locker =
            async_named_locker::Locker::get_locker(format!("sn_email_{}", email)).await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let email_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind(email.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query email count failed", e))?;
        if email_count > 0 {
            return Err(Self::email_already_bound(email.as_str()));
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, email, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, '', ?5, NULL, '', NULL, 0, NULL, ?6, ?6, NULL)",
        )
        .bind(username)
        .bind(email.as_str())
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(active_code)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::insert_user_err(email.as_str(), e))?;

        sqlx::query(
            "INSERT INTO user_auth
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert auth failed", e))?;

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(true)
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("username_{}", username)).await;
        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO user_auth
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert auth failed", e))?;

        Ok(true)
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user failed", e))?;
        Ok(count > 0)
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        let email = canonical_email(email)?;
        let row = sqlx::query(
            "SELECT username, email, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips
             FROM users WHERE email = ?1",
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user by email failed", e))?;

        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        let email = canonical_email(email)?;
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let _email_locker =
            async_named_locker::Locker::get_locker(format!("sn_email_{}", email)).await;
        let _domain_locker = if user_domain.is_some() {
            Some(
                async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                    .await,
            )
        } else {
            None
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let email_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind(email.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query email count failed", e))?;
        if email_count > 0 {
            return Err(Self::email_already_bound(email.as_str()));
        }

        let canonical_domain = user_domain.as_deref().and_then(canonical_user_domain);

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, email, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, 0, ?9, ?10, ?10, NULL)",
        )
        .bind(username)
        .bind(email.as_str())
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(public_key)
        .bind(active_code)
        .bind(zone_config)
        .bind(canonical_domain.as_deref())
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::insert_user_err(email.as_str(), e))?;

        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, NULL, 0, NULL, NULL, ?4, NULL, ?5)",
        )
        .bind(username)
        .bind(username)
        .bind(if zone_config.trim().is_empty() {
            None
        } else {
            Some(zone_config)
        })
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert zone info failed", e))?;

        if let Some(domain) = canonical_domain.as_deref() {
            // seed/import 捷径：不经 DNS proof 直接激活（含 supersede 语义）。
            let pkx = pkx_value(public_key)?;
            Self::activate_binding_tx(&mut tx, username, domain, pkx.as_str(), now).await?;
        }

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(true)
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let row =
            sqlx::query("SELECT username, zone_config, sn_ips FROM users WHERE public_key = ?1")
                .bind(public_key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user by public_key failed", e))?;

        row.map(|row| {
            Ok((
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                row.try_get::<Option<String>, _>("zone_config")
                    .map_err(|e| Self::db_err("read zone_config failed", e))?
                    .unwrap_or_default(),
                row.try_get("sn_ips")
                    .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            ))
        })
        .transpose()
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        let row = sqlx::query(
            "SELECT username, email, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips
             FROM users WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user failed", e))?;

        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        let canonical_domain = match canonical_user_domain(domain) {
            Some(domain) => domain,
            None => return Ok(None),
        };
        let row = sqlx::query(
            "SELECT u.username, u.email, u.state, u.public_key, u.activation_code, u.zone_config,
                    u.self_cert, u.user_domain, u.sn_ips
             FROM user_domain_bindings b
             JOIN users u ON u.username = b.owner
             WHERE b.state = 'active'
               AND (?1 = b.domain OR ?1 LIKE '%.' || b.domain)
             ORDER BY length(b.domain) DESC
             LIMIT 1",
        )
        .bind(canonical_domain.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user by domain failed", e))?;

        row.as_ref().map(Self::user_from_row).transpose()
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query("UPDATE users SET state = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(state.to_string())
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("update user state failed", e))?;
        if !state.is_active() {
            self.revoke_user_sessions(username, now as u64).await?;
        }
        Ok(())
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query("UPDATE users SET public_key = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(public_key)
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("update user public_key failed", e))?;
        Ok(())
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                zone: Some(zone_config.to_string()),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                self_cert: Some(self_cert),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;

        let canonical_domain = user_domain.as_deref().and_then(canonical_user_domain);

        if let Some(domain) = canonical_domain.as_deref() {
            let user =
                sqlx::query("SELECT public_key, owner_key_ref FROM users WHERE username = ?1")
                    .bind(username)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("query user failed", e))?
                    .ok_or_else(|| {
                        sn_err!(SnErrorCode::NotFound, "user not found: {}", username)
                    })?;
            let owner_key_ref: Option<String> = user
                .try_get("owner_key_ref")
                .map_err(|e| Self::db_err("read owner_key_ref failed", e))?;
            let public_key: Option<String> = user
                .try_get("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?;
            let pkx_source = owner_key_ref
                .filter(|value| !value.trim().is_empty())
                .or_else(|| public_key.filter(|value| !value.trim().is_empty()))
                .unwrap_or_default();
            // trusted import 特例：允许无 owner key 的空 pkx 绑定。
            let pkx = if pkx_source.trim().is_empty() {
                String::new()
            } else {
                pkx_value(pkx_source.as_str())?
            };
            Self::activate_binding_tx(&mut tx, username, domain, pkx.as_str(), now).await?;
        } else {
            sqlx::query(
                "UPDATE user_domain_bindings
                 SET state = ?1, updated_at = ?2
                 WHERE owner = ?3 AND state = ?4",
            )
            .bind(DOMAIN_BINDING_REVOKED)
            .bind(now)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("revoke user_domain bindings failed", e))?;
            sqlx::query("UPDATE users SET user_domain = NULL, updated_at = ?1 WHERE username = ?2")
                .bind(now)
                .bind(username)
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("update user_domain failed", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        if let Some(zone_info) = self.get_zone_info(username).await? {
            if zone_info.sn_ips.is_some() {
                return Ok(zone_info.sn_ips);
            }
        }

        let row = sqlx::query("SELECT sn_ips FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user sn_ips failed", e))?;
        row.map(|row| {
            row.try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))
        })
        .transpose()
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        let row = sqlx::query(
            "SELECT username, password_hash, password_salt, password_algo,
                    created_at, updated_at, last_login_at
             FROM user_auth WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query auth failed", e))?;

        row.map(|row| {
            let created_at: i64 = row
                .try_get("created_at")
                .map_err(|e| Self::db_err("read created_at failed", e))?;
            let updated_at: i64 = row
                .try_get("updated_at")
                .map_err(|e| Self::db_err("read updated_at failed", e))?;
            let last_login_at: Option<i64> = row
                .try_get("last_login_at")
                .map_err(|e| Self::db_err("read last_login_at failed", e))?;
            Ok(SnAuthInfo {
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                password_hash: row
                    .try_get("password_hash")
                    .map_err(|e| Self::db_err("read password_hash failed", e))?,
                password_salt: row
                    .try_get("password_salt")
                    .map_err(|e| Self::db_err("read password_salt failed", e))?,
                password_algo: row
                    .try_get("password_algo")
                    .map_err(|e| Self::db_err("read password_algo failed", e))?,
                created_at: Self::i64_to_u64(created_at),
                updated_at: Self::i64_to_u64(updated_at),
                last_login_at: Self::opt_i64_to_u64(last_login_at),
            })
        })
        .transpose()
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        let last_login_at = last_login_at as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "UPDATE user_auth
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update last login failed", e))?;
        sqlx::query(
            "UPDATE users
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user last login failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        let canonical_domain = canonical_user_domain(domain)
            .ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let pkx = pkx.trim();
        Self::check_non_empty(pkx, "pkx")?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user = sqlx::query("SELECT state FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| Self::db_err("query user failed", e))?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "user not found: {}", username))?;
        let state: Option<String> = user
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        if !UserState::from_str(state.as_deref()).is_active() {
            return Err(sn_err!(
                SnErrorCode::Blocked,
                "user is not active: {}",
                username
            ));
        }

        let now = Self::now_secs() as i64;
        Self::activate_binding_tx(&mut tx, username, canonical_domain.as_str(), pkx, now).await?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(DomainBinding {
            username: username.to_string(),
            pkx_record_name: pkx_record_name(canonical_domain.as_str()),
            domain: canonical_domain,
            pkx: pkx.to_string(),
            verified_at: now as u64,
        })
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        let canonical_domain = canonical_user_domain(domain)
            .ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;
        sqlx::query(
            "UPDATE user_domain_bindings
             SET state = ?1, updated_at = ?2
             WHERE domain = ?3 AND owner = ?4 AND state = ?5",
        )
        .bind(DOMAIN_BINDING_REVOKED)
        .bind(now)
        .bind(canonical_domain.as_str())
        .bind(username)
        .bind(DOMAIN_BINDING_ACTIVE)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("revoke user_domain binding failed", e))?;
        sqlx::query(
            "UPDATE users
             SET user_domain = NULL, updated_at = ?1
             WHERE username = ?2 AND user_domain = ?3",
        )
        .bind(now)
        .bind(username)
        .bind(canonical_domain.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("clear user_domain failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        let row = sqlx::query(
            "SELECT username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                    cert_expires_at, sn_ips, source_version, updated_at
             FROM zone_info WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query zone_info failed", e))?;
        if let Some(row) = row.as_ref() {
            return Self::zone_info_from_row(row).map(Some);
        }

        Ok(Some(ZoneInfo::default_for(username)))
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        let mut current = self
            .get_zone_info(username)
            .await?
            .unwrap_or_else(|| ZoneInfo::default_for(username));
        if let Some(value) = patch.bns_name {
            current.bns_name = value;
        }
        if let Some(value) = patch.zone {
            current.zone = Some(value);
        }
        if let Some(value) = patch.relay_sn {
            current.relay_sn = Some(value);
        }
        if let Some(value) = patch.self_cert {
            current.self_cert = value;
        }
        if let Some(value) = patch.cert_checked_at {
            current.cert_checked_at = Some(value);
        }
        if let Some(value) = patch.cert_expires_at {
            current.cert_expires_at = Some(value);
        }
        if let Some(value) = patch.sn_ips {
            current.sn_ips = Some(value);
        }
        if let Some(value) = patch.source_version {
            current.source_version = Some(value);
        }
        current.updated_at = Self::now_secs();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(username) DO UPDATE SET
                bns_name = excluded.bns_name,
                zone = excluded.zone,
                relay_sn = excluded.relay_sn,
                self_cert = excluded.self_cert,
                cert_checked_at = excluded.cert_checked_at,
                cert_expires_at = excluded.cert_expires_at,
                sn_ips = excluded.sn_ips,
                source_version = excluded.source_version,
                updated_at = excluded.updated_at",
        )
        .bind(username)
        .bind(current.bns_name.as_str())
        .bind(current.zone.as_deref())
        .bind(current.relay_sn.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.cert_checked_at.map(|v| v as i64))
        .bind(current.cert_expires_at.map(|v| v as i64))
        .bind(current.sn_ips.as_deref())
        .bind(current.source_version.as_deref())
        .bind(current.updated_at as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert zone_info failed", e))?;

        sqlx::query(
            "UPDATE users
             SET zone_config = COALESCE(?1, zone_config),
                 self_cert = ?2,
                 sn_ips = ?3,
                 updated_at = ?4
             WHERE username = ?5",
        )
        .bind(current.zone.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.sn_ips.as_deref())
        .bind(current.updated_at as i64)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user zone cache failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        Self::check_non_empty(zone, "zone")?;
        Self::check_non_empty(relay_sn, "relay_sn")?;
        let now = Self::now_secs();
        let result = sqlx::query(
            "UPDATE zone_info
             SET relay_sn = ?1,
                 source_version = COALESCE(?2, source_version),
                 updated_at = ?3
             WHERE zone = ?4 OR bns_name = ?4 OR username = ?4",
        )
        .bind(relay_sn)
        .bind(source_version)
        .bind(now as i64)
        .bind(zone)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("update zone relay_sn failed", e))?;

        if result.rows_affected() > 0 {
            return Ok(true);
        }

        let result = sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?1, NULL, ?2, 0, NULL, NULL, NULL, ?3, ?4)
             ON CONFLICT(username) DO UPDATE SET
                relay_sn = excluded.relay_sn,
                source_version = COALESCE(excluded.source_version, zone_info.source_version),
                updated_at = excluded.updated_at",
        )
        .bind(zone)
        .bind(relay_sn)
        .bind(source_version)
        .bind(now as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert zone relay_sn cache failed", e))?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO account_sessions
                (session_id, username, token_aud, state, issued_at, expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        )
        .bind(session_id)
        .bind(username)
        .bind(token_aud)
        .bind(SESSION_ACTIVE)
        .bind(issued_at as i64)
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert account session failed", e))?;
        Ok(())
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE session_id = ?3",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke account session failed", e))?;
        Ok(())
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        let result = sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE username = ?3 AND state != ?1",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke user sessions failed", e))?;
        Ok(result.rows_affected())
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        let row = sqlx::query(
            "SELECT session_id, username, token_aud, state, issued_at, expires_at, revoked_at
             FROM account_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query account session failed", e))?;
        row.map(|row| {
            let issued_at: i64 = row
                .try_get("issued_at")
                .map_err(|e| Self::db_err("read issued_at failed", e))?;
            let expires_at: i64 = row
                .try_get("expires_at")
                .map_err(|e| Self::db_err("read expires_at failed", e))?;
            let revoked_at: Option<i64> = row
                .try_get("revoked_at")
                .map_err(|e| Self::db_err("read revoked_at failed", e))?;
            Ok(AccountSession {
                session_id: row
                    .try_get("session_id")
                    .map_err(|e| Self::db_err("read session_id failed", e))?,
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                token_aud: row
                    .try_get("token_aud")
                    .map_err(|e| Self::db_err("read token_aud failed", e))?,
                state: row
                    .try_get("state")
                    .map_err(|e| Self::db_err("read state failed", e))?,
                issued_at: Self::i64_to_u64(issued_at),
                expires_at: Self::i64_to_u64(expires_at),
                revoked_at: Self::opt_i64_to_u64(revoked_at),
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_test_db() -> SnResult<(tempfile::TempDir, SqliteSnAuthDB)> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        db.initialize_database().await?;
        Ok((tmp_dir, db))
    }

    #[test]
    fn test_canonical_email_validation() {
        assert_eq!(
            canonical_email("  Alice.Recovery+SN@Example.COM  ").unwrap(),
            "alice.recovery+sn@example.com"
        );
        for invalid in [
            "",
            "missing-at.example.com",
            "two@@example.com",
            ".alice@example.com",
            "alice..sn@example.com",
            "alice@-example.com",
            "alice@example..com",
            "爱丽丝@example.com",
        ] {
            assert!(canonical_email(invalid).is_err(), "must reject {invalid:?}");
        }
    }

    #[tokio::test]
    async fn test_register_email_is_normalized_queryable_and_unique() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("email-code-1").await?;
        db.insert_activation_code("email-code-2").await?;

        assert!(
            db.register_user(
                "email-code-1",
                "alice",
                "  Alice.Recovery@Example.COM  ",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );
        let by_name = db.get_user_info("alice").await?.unwrap();
        assert_eq!(by_name.email.as_deref(), Some("alice.recovery@example.com"));
        let by_email = db
            .get_user_by_email("ALICE.RECOVERY@EXAMPLE.COM")
            .await?
            .unwrap();
        assert_eq!(by_email.username.as_deref(), Some("alice"));

        let duplicate = db
            .register_user(
                "email-code-2",
                "bob",
                "alice.recovery@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await
            .unwrap_err();
        assert_eq!(duplicate.code(), SnErrorCode::Conflict);
        assert!(duplicate.msg().starts_with("email already bound:"));
        assert!(db.check_active_code("email-code-2").await?);
        assert!(!db.is_user_exist("bob").await?);

        // 应用层预查之外，SQLite 唯一索引也必须独立拒绝重复绑定。
        let raw_duplicate = sqlx::query(
            "INSERT INTO users (username, email, state) VALUES (?1, ?2, 'active')",
        )
        .bind("raw-duplicate")
        .bind("alice.recovery@example.com")
        .execute(&db.pool)
        .await
        .unwrap_err();
        assert!(raw_duplicate
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation()));

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_registration_rejects_same_normalized_email() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("email-race-code-1").await?;
        db.insert_activation_code("email-race-code-2").await?;
        let db = Arc::new(db);

        let alice = {
            let db = db.clone();
            tokio::spawn(async move {
                db.register_user(
                    "email-race-code-1",
                    "alice",
                    "Recovery@Example.COM",
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            })
        };
        let bob = {
            let db = db.clone();
            tokio::spawn(async move {
                db.register_user(
                    "email-race-code-2",
                    "bob",
                    " recovery@example.com ",
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            })
        };

        let outcomes = [
            alice.await.expect("alice registration task panicked"),
            bob.await.expect("bob registration task panicked"),
        ];
        let mut successes = 0;
        let mut conflicts = 0;
        for outcome in outcomes {
            match outcome {
                Ok(true) => successes += 1,
                Err(error) if error.code() == SnErrorCode::Conflict => conflicts += 1,
                other => panic!("unexpected concurrent registration outcome: {other:?}"),
            }
        }
        assert_eq!(successes, 1);
        assert_eq!(conflicts, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind("recovery@example.com")
                .fetch_one(&db.pool)
                .await
                .map_err(|e| SqliteSnAuthDB::db_err("count registered email failed", e))?,
            1
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_legacy_users_migration_keeps_account_without_email() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("legacy-sn-auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        sqlx::query(
            "CREATE TABLE users (
                username TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'active',
                public_key TEXT NOT NULL DEFAULT '',
                activation_code TEXT,
                zone_config TEXT NOT NULL DEFAULT '',
                self_cert INTEGER NOT NULL DEFAULT 0,
                user_domain TEXT,
                sn_ips TEXT
            )",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("create legacy users table failed", e))?;
        sqlx::query("INSERT INTO users (username) VALUES ('legacy-user')")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert legacy user failed", e))?;

        db.initialize_database().await?;

        let legacy = db.get_user_info("legacy-user").await?.unwrap();
        assert!(legacy.email.is_none());
        let email_column_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'email'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("query migrated email column failed", e))?;
        assert_eq!(email_column_count, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_activation_code_and_auth_flow() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        let codes = db.generate_activation_codes(3).await?;
        assert_eq!(codes.len(), 3);
        assert!(codes.iter().all(|code| code.len() == ACTIVATION_CODE_LEN));

        let active_code = codes[0].as_str();
        assert!(db.check_active_code(active_code).await?);
        assert!(
            db.register_user(
                active_code,
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );
        assert!(!db.check_active_code(active_code).await?);
        assert!(
            !db.register_user(
                active_code,
                "bob",
                "bob@example.com",
                "hash2",
                "salt2",
                "pbkdf2",
            )
                .await?
        );
        assert!(db.is_user_exist("alice").await?);

        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
        assert_eq!(user.activation_code.as_deref(), Some(active_code));
        assert_eq!(user.public_key, "");
        assert!(!user.self_cert);

        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");
        assert!(auth.last_login_at.is_none());

        db.update_last_login("alice", 12345).await?;
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.last_login_at, Some(12345));
        assert_eq!(auth.updated_at, 12345);

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);

        Ok(())
    }

    #[tokio::test]
    async fn test_activate_binding_flow_and_supersede() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );
        assert!(
            db.register_user(
                "bob-code",
                "bob",
                "bob@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );

        let binding = db
            .activate_user_domain_binding("alice", "*.Example.COM.", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(binding.pkx_record_name, "_pkx.example.com");
        assert_eq!(binding.pkx, "PKX(alice-owner-key)");
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            db.get_user_info("alice").await?.unwrap().user_domain.as_deref(),
            Some("example.com")
        );

        // 域名转让：bob 完成自己的 DNS proof（由服务端校验后调用），无需
        // alice 先手工 unbind；旧 active binding 被 supersede、旧缓存清空。
        let takeover = db
            .activate_user_domain_binding("bob", "example.com", "PKX(bob-owner-key)")
            .await?;
        assert_eq!(takeover.domain, "example.com");
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_SUPERSEDED
        );
        assert!(db
            .get_user_info("alice")
            .await?
            .unwrap()
            .user_domain
            .is_none());

        db.unbind_user_domain("bob", "example.com").await?;
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());
        // unbind 只影响 bob 的 active 行，alice 的 superseded 审计态保持不变。
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_SUPERSEDED
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_zone_info_patch_and_session_revocation() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );

        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                relay_sn: Some("relay-a".to_string()),
                self_cert: Some(true),
                cert_checked_at: Some(10),
                cert_expires_at: Some(20),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                source_version: Some("v1".to_string()),
                ..Default::default()
            },
        )
        .await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        assert_eq!(db.get_user_info("alice").await?.unwrap().self_cert, true);

        db.create_account_session("refresh-1", "alice", "sn-refresh", 1, 100)
            .await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_ACTIVE);
        db.revoke_account_session("refresh-1", 50).await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);
        assert_eq!(session.revoked_at, Some(50));

        db.create_account_session("refresh-2", "alice", "sn-refresh", 51, 100)
            .await?;
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        let session = db.get_account_session("refresh-2").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);

        Ok(())
    }

    #[tokio::test]
    async fn test_clear_state_by_active_code_resets_auth_and_legacy_related_rows() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("clear-me").await?;
        assert!(
            db.register_user(
                "clear-me",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );

        sqlx::query("CREATE TABLE devices (owner TEXT, device_name TEXT, did TEXT PRIMARY KEY, ip TEXT, description TEXT, mini_config_jwt TEXT, created_at INTEGER, updated_at INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create devices failed", e))?;
        sqlx::query("CREATE TABLE user_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, domain TEXT, record_type TEXT, record TEXT, ttl INTEGER, created_at INTEGER, updated_at INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create user_dns_records failed", e))?;
        sqlx::query("CREATE TABLE did_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, obj_id TEXT, owner_user TEXT, obj_name TEXT, did_document TEXT, doc_type TEXT, update_time INTEGER)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("create did_documents failed", e))?;
        sqlx::query("INSERT INTO devices (owner, device_name, did, ip, description, mini_config_jwt, created_at, updated_at) VALUES ('alice', 'ood1', 'did:dev:1', '', '', '', 1, 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert device failed", e))?;
        sqlx::query("INSERT INTO user_dns_records (owner, domain, record_type, record, ttl, created_at, updated_at) VALUES ('alice', 'alice.example.com', 'A', '127.0.0.1', 60, 1, 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert dns record failed", e))?;
        sqlx::query("INSERT INTO did_documents (obj_id, owner_user, obj_name, did_document, doc_type, update_time) VALUES ('obj1', 'alice', 'zone', '{}', 'zone', 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert did document failed", e))?;

        let result = db.clear_state_by_active_code("clear-me").await?;
        assert_eq!(result.deleted_users, 1);
        assert_eq!(result.deleted_devices, 1);
        assert_eq!(result.deleted_domain_records, 1);
        assert_eq!(result.deleted_did_documents, 1);
        assert!(result.activation_code_reset);
        assert!(db.check_active_code("clear-me").await?);
        assert!(!db.is_user_exist("alice").await?);
        assert!(db.get_auth("alice").await?.is_none());
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);
        assert!(zone.zone.is_none());

        Ok(())
    }

    // ---- §3.1 账号与凭证（DB 层）----

    /// 激活码：生成 32 位、charset 受限、唯一；`check_active_code` 区分存在/已用/未知；
    /// 注册后事务内置 `used=1`，二次使用被拒。
    #[tokio::test]
    async fn test_activation_code_generation_and_single_use() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        let codes = db.generate_activation_codes(8).await?;
        assert_eq!(codes.len(), 8);
        for code in &codes {
            assert_eq!(code.len(), ACTIVATION_CODE_LEN);
            assert!(code.bytes().all(|b| ACTIVATION_CODE_CHARS.contains(&b)));
        }
        let unique: std::collections::HashSet<_> = codes.iter().cloned().collect();
        assert_eq!(unique.len(), codes.len(), "generated codes must be unique");

        // 未知激活码 → false（既非存在也非未用）。
        assert!(!db.check_active_code("does-not-exist").await?);

        let code = codes[0].as_str();
        assert!(db.check_active_code(code).await?);
        assert!(
            db.register_user(code, "alice", "alice@example.com", "h", "s", "pbkdf2")
                .await?
        );

        // 注册后事务内 used=1。
        let used: i64 = sqlx::query_scalar("SELECT used FROM activation_codes WHERE code = ?1")
            .bind(code)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read used flag failed", e))?;
        assert_eq!(used, 1);
        assert!(!db.check_active_code(code).await?);

        // 二次使用被拒（既不创建用户，也不报错，按契约返回 false）。
        assert!(
            !db.register_user(code, "bob", "bob@example.com", "h", "s", "pbkdf2")
                .await?
        );
        assert!(!db.is_user_exist("bob").await?);

        Ok(())
    }

    /// `register_user` 事务性：`users` + `user_auth` + `zone_info` 一致写入，激活码标记 used。
    #[tokio::test]
    async fn test_register_user_writes_consistent_rows() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("code-1").await?;
        assert!(
            db.register_user(
                "code-1",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
                .await?
        );

        // users 行。
        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.activation_code.as_deref(), Some("code-1"));
        assert!(matches!(user.state, UserState::Active));

        // user_auth 行。
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");

        // zone_info 行（bns_name 默认为 username）。
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");

        // 同名二次注册（换激活码）被拒，且不破坏已有行。
        db.insert_activation_code("code-2").await?;
        assert!(
            !db.register_user(
                "code-2",
                "alice",
                "alice2@example.com",
                "h2",
                "s2",
                "pbkdf2",
            )
                .await?
        );
        // code-2 未被消费。
        assert!(db.check_active_code("code-2").await?);
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(
            auth.password_hash, "hash",
            "existing auth must be untouched"
        );

        Ok(())
    }

    /// 命名锁下并发注册：N 个任务用同一激活码注册不同用户名，只允许一个成功。
    #[tokio::test]
    async fn test_register_user_concurrent_single_success() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("shared-code").await?;
        let db = Arc::new(db);

        let mut handles = Vec::new();
        for i in 0..8 {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                db.register_user(
                    "shared-code",
                    &format!("user-{i}"),
                    &format!("user-{i}@example.com"),
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            }));
        }

        let mut success = 0;
        for handle in handles {
            if handle.await.expect("task panicked")? {
                success += 1;
            }
        }
        assert_eq!(success, 1, "exactly one concurrent registration may win");

        // 激活码已消费，且只创建了一个用户。
        assert!(!db.check_active_code("shared-code").await?);
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("count users failed", e))?;
        assert_eq!(user_count, 1);

        Ok(())
    }

    /// 密码：PBKDF2-sha256-100000、16B salt(hex)、32B hash(hex)；`verify_password` 正确/错误；
    /// 服务端不存明文；不支持的算法被拒。
    #[tokio::test]
    async fn test_password_pbkdf2_hash_and_verify() -> SnResult<()> {
        use crate::sn_auth_manager::{hash_password, verify_password, PASSWORD_ALGO};

        let (hash, salt) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        // 16 字节 salt → 32 hex 字符；32 字节 hash → 64 hex 字符。
        assert_eq!(salt.len(), 32);
        assert_eq!(hash.len(), 64);
        assert_eq!(hex::decode(&salt).unwrap().len(), 16);
        assert_eq!(hex::decode(&hash).unwrap().len(), 32);
        // 不存明文。
        assert_ne!(hash, "hunter2");

        // 同一密码 + 不同随机 salt → 不同 hash。
        let (hash2, salt2) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        assert_ne!(salt, salt2);
        assert_ne!(hash, hash2);

        let auth = SnAuthInfo {
            username: "alice".to_string(),
            password_hash: hash,
            password_salt: salt,
            password_algo: PASSWORD_ALGO.to_string(),
            created_at: 0,
            updated_at: 0,
            last_login_at: None,
        };
        assert!(verify_password("hunter2", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);
        assert!(!verify_password("wrong-pass", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);

        // 不支持的算法 → 错误，而非 false。
        let mut bad = auth.clone();
        bad.password_algo = "plaintext".to_string();
        assert!(verify_password("hunter2", &bad).is_err());

        Ok(())
    }

    /// 用户状态机：`set_user_state` 写入 active/suspended/deleted/banned；
    /// 置非 active 时自动撤销该用户 session；active 不撤销。
    #[tokio::test]
    async fn test_set_user_state_revokes_sessions() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("state-code").await?;
        assert!(
            db.register_user(
                "state-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // active → active：session 保留。
        db.create_account_session("sess-keep", "alice", "sn-refresh", 1, 100)
            .await?;
        db.set_user_state("alice", UserState::Active).await?;
        assert_eq!(
            db.get_account_session("sess-keep").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 逐个非 active 状态：写库 + 撤销 session。
        for (state, label) in [
            (UserState::Suspended, "suspended"),
            (UserState::Deleted, "deleted"),
            (UserState::Banned, "banned"),
        ] {
            // 重新发一个活跃 session。
            let sid = format!("sess-{label}");
            db.create_account_session(&sid, "alice", "sn-refresh", 1, 100)
                .await?;
            db.set_user_state("alice", state).await?;

            let stored: String =
                sqlx::query_scalar("SELECT state FROM users WHERE username = 'alice'")
                    .fetch_one(&db.pool)
                    .await
                    .map_err(|e| SqliteSnAuthDB::db_err("read user state failed", e))?;
            assert_eq!(stored, label);

            let session = db.get_account_session(&sid).await?.unwrap();
            assert_eq!(
                session.state, SESSION_REVOKED,
                "{label} must revoke session"
            );
            assert!(session.revoked_at.is_some());
        }

        Ok(())
    }

    // ---- §3.2 session（account_sessions）----

    /// session 生命周期：create/get/revoke/revoke_user_sessions 语义与计数。
    #[tokio::test]
    async fn test_account_session_lifecycle_and_counts() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        // 未知 session → None。
        assert!(db.get_account_session("missing").await?.is_none());

        db.create_account_session("a1", "alice", "sn-refresh", 1, 100)
            .await?;
        db.create_account_session("a2", "alice", "sn-refresh", 2, 100)
            .await?;
        db.create_account_session("b1", "bob", "sn-refresh", 3, 100)
            .await?;

        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.username, "alice");
        assert_eq!(s.token_aud, "sn-refresh");
        assert_eq!(s.state, SESSION_ACTIVE);
        assert_eq!(s.issued_at, 1);
        assert_eq!(s.expires_at, 100);
        assert!(s.revoked_at.is_none());

        // 单条撤销。
        db.revoke_account_session("a1", 50).await?;
        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.state, SESSION_REVOKED);
        assert_eq!(s.revoked_at, Some(50));

        // 批量撤销只命中 alice 的活跃 session（a1 已撤销，仅 a2 计入）。
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        assert_eq!(
            db.get_account_session("a2").await?.unwrap().state,
            SESSION_REVOKED
        );
        // bob 不受影响。
        assert_eq!(
            db.get_account_session("b1").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 再次批量撤销 alice：已无活跃 session → 0。
        assert_eq!(db.revoke_user_sessions("alice", 70).await?, 0);

        Ok(())
    }

    // ---- §3.3 user_domain + PKX proof ----

    /// `canonical_user_domain` / `pkx_record_name` / `pkx_value` / `txt_matches_pkx` helper 稳定性。
    #[test]
    fn test_user_domain_helpers_are_stable() {
        // 去 `*.` 前缀、小写、去尾点。
        assert_eq!(
            canonical_user_domain("*.Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            canonical_user_domain("  API.Example.com  "),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            canonical_user_domain("example.com"),
            Some("example.com".to_string())
        );
        // 空 / 仅点 / 仅通配 → None。
        assert_eq!(canonical_user_domain("   "), None);
        assert_eq!(canonical_user_domain("."), None);
        assert_eq!(canonical_user_domain("*."), None);

        // 派生 helper 同输入恒等（无 nonce / exp）。
        assert_eq!(pkx_record_name("example.com"), "_pkx.example.com");
        assert_eq!(pkx_value("owner-key").unwrap(), pkx_value("owner-key").unwrap());
        assert_eq!(pkx_value("  owner-key  ").unwrap(), "PKX(owner-key)");
        assert!(pkx_value("   ").is_err());

        // `sn_user.pkx` 归一：JWK JSON → x 分量；`PKX=<x>[:...];` → <x>。
        assert_eq!(
            pkx_value(r#"{"crv":"Ed25519","kty":"OKP","x":"alice-x-component"}"#).unwrap(),
            "PKX(alice-x-component)"
        );
        assert_eq!(
            pkx_source_of("PKX=alice-x-component:bns:alice;").as_deref(),
            Some("alice-x-component")
        );
        assert_eq!(pkx_source_of("raw-x;").as_deref(), Some("raw-x"));
        assert_eq!(pkx_source_of("  "), None);

        // TXT 比较容忍包裹引号与首尾空白。
        assert!(txt_matches_pkx("  \"PKX(owner-key)\"  ", "PKX(owner-key)"));
        assert!(!txt_matches_pkx("PKX(other)", "PKX(owner-key)"));
    }

    /// 状态机：activate → active + history；同 owner 重复激活仅刷新（无重复
    /// 审计行）；unbind → revoked；重新激活 → 新 active 行 + 新审计行。
    #[tokio::test]
    async fn test_activate_binding_state_transitions_and_history() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        let binding = db
            .activate_user_domain_binding("alice", "Example.com.", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(binding.pkx_record_name, "_pkx.example.com");
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_ACTIVE
        );
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);

        // 同 owner 重复激活：幂等刷新（pkx 可轮换），不追加审计行、不新增绑定行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-rotated-key)")
            .await?;
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);
        let active_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_bindings WHERE domain = 'example.com'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count binding rows failed", e))?;
        assert_eq!(active_rows, 1);
        assert_eq!(
            db.get_user_by_domain("example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        // unbind → revoked，history 保留；SN-DNS 侧 get_user_by_domain 不再命中
        // 该域名及其子域名。
        db.unbind_user_domain("alice", "example.com").await?;
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_REVOKED
        );
        assert!(db.get_user_by_domain("example.com").await?.is_none());
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);
        assert!(db
            .get_user_info("alice")
            .await?
            .unwrap()
            .user_domain
            .is_none());

        // 重新完成 proof 后再次激活：新 active 行 + 新审计行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_ACTIVE
        );
        assert_eq!(history_count(&db, "example.com", "alice").await?, 2);

        Ok(())
    }

    /// Beta2.2 冲突规则：history 仅审计，不阻止接管；同域名旧 active binding
    /// 被新 DNS owner supersede；父/子域名不互斥。非 active 用户不能激活。
    #[tokio::test]
    async fn test_history_is_audit_only_and_domains_are_not_exclusive() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        for (code, user) in [("a-code", "alice"), ("b-code", "bob")] {
            db.insert_activation_code(code).await?;
            assert!(
                db.register_user(
                    code,
                    user,
                    &format!("{user}@example.com"),
                    "h",
                    "s",
                    "pbkdf2",
                )
                .await?
            );
        }

        // alice 激活 example.com 后 unbind：留下 history 与 revoked 行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-key)")
            .await?;
        db.unbind_user_domain("alice", "example.com").await?;

        // history 不构成硬冲突：bob 能通过自己的 DNS proof 接管同一域名。
        db.activate_user_domain_binding("bob", "example.com", "PKX(bob-key)")
            .await?;
        assert_eq!(
            db.get_user_by_domain("example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );

        // 祖先/子域名不再互斥：alice 可绑定 bob 域名的子域，反向亦然。
        db.activate_user_domain_binding("alice", "api.example.com", "PKX(alice-key)")
            .await?;
        db.activate_user_domain_binding("alice", "com", "PKX(alice-key)")
            .await?;

        // 解析按最长 active binding 匹配。
        assert_eq!(
            db.get_user_by_domain("host.api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            db.get_user_by_domain("www.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );
        assert_eq!(
            db.get_user_by_domain("other.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        // 非 active 用户不能激活绑定。
        db.set_user_state("bob", UserState::Suspended).await?;
        let err = db
            .activate_user_domain_binding("bob", "blocked.example.org", "PKX(bob-key)")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Blocked);

        // 空 pkx 不能激活（proof 值必须由服务端算出）。
        let err = db
            .activate_user_domain_binding("alice", "empty.example.org", "  ")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::InvalidInput);

        Ok(())
    }

    /// `get_user_by_domain`：只查询 active binding，旧 `users.user_domain` 不再作为回退。
    #[tokio::test]
    async fn test_get_user_by_domain_longest_match_without_legacy_fallback() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // alice 同时激活 example.com 与更具体的 sub.example.com。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-key)")
            .await?;
        db.activate_user_domain_binding("alice", "sub.example.com", "PKX(alice-key)")
            .await?;

        // host.sub.example.com → 命中最长的 sub.example.com binding（同样属 alice）。
        assert_eq!(
            db.get_user_by_domain("host.sub.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert!(db.get_user_by_domain("unrelated.org").await?.is_none());

        // breaking change：bob 仅在 users.user_domain 留有遗留域名、无 binding 行，不再命中。
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user(
                "bob-code",
                "bob",
                "bob@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );
        sqlx::query("UPDATE users SET user_domain = 'legacy.test' WHERE username = 'bob'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("set legacy domain failed", e))?;
        assert!(db.get_user_by_domain("host.legacy.test").await?.is_none());

        Ok(())
    }

    /// 旧 schema（domain 主键 + pending_pkx 行）迁移：active/revoked 行保留，
    /// pending_pkx 行丢弃，迁移后 supersede/多行审计可用。
    #[tokio::test]
    async fn test_legacy_user_domain_schema_migration() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_auth.sqlite3");
        let db_path_str = db_path.to_string_lossy().to_string();

        {
            // 手工构造旧 schema。
            let db = SqliteSnAuthDB::new_by_path(db_path_str.as_str()).await?;
            for sql in [
                "CREATE TABLE user_domain_history (
                    domain TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )",
                "CREATE TABLE user_domain_bindings (
                    domain TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    state TEXT NOT NULL,
                    pkx TEXT NOT NULL,
                    pkx_record_name TEXT NOT NULL,
                    verified_at INTEGER NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )",
                "INSERT INTO user_domain_history (domain, owner, created_at)
                 VALUES ('active.test', 'alice', 1)",
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES ('active.test', 'alice', 'active', 'PKX(alice-key)', '_pkx.active.test', 1, 1, 1)",
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES ('pending.test', 'alice', 'pending_pkx', 'PKX(alice-key)', '_pkx.pending.test', NULL, 1, 1)",
            ] {
                sqlx::query(sql)
                    .execute(&db.pool)
                    .await
                    .map_err(|e| SqliteSnAuthDB::db_err("seed legacy schema failed", e))?;
            }
        }

        let db = SqliteSnAuthDB::new_by_path(db_path_str.as_str()).await?;
        db.initialize_database().await?;

        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user(
                "bob-code",
                "bob",
                "bob@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // 旧 active 行仍可解析；pending_pkx 行被丢弃。
        assert_eq!(
            db.get_user_by_domain("active.test")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        let pending_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_bindings WHERE domain = 'pending.test'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count pending rows failed", e))?;
        assert_eq!(pending_rows, 0);

        // 迁移后的表支持 supersede（多行同域名）。
        db.activate_user_domain_binding("bob", "active.test", "PKX(bob-key)")
            .await?;
        assert_eq!(
            binding_state(&db, "active.test", "alice").await?,
            DOMAIN_BINDING_SUPERSEDED
        );
        assert_eq!(
            db.get_user_by_domain("active.test")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );

        Ok(())
    }

    // ---- §3.4 zone_info ----

    /// `update_zone_info` patch 语义：只改传入字段，其余保留；users 缓存同步。
    #[tokio::test]
    async fn test_zone_info_patch_only_changes_given_fields() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // 初始整体写入。
        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                self_cert: Some(true),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                ..Default::default()
            },
        )
        .await?;

        // 仅 patch relay_sn，其余字段保留。
        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                relay_sn: Some("relay-a".to_string()),
                ..Default::default()
            },
        )
        .await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        // users 缓存同步。
        assert!(db.get_user_info("alice").await?.unwrap().self_cert);

        Ok(())
    }

    /// `get_zone_info` 缺 zone_info 行时返回默认值，不再从 `users.zone_config` 派生。
    #[tokio::test]
    async fn test_get_zone_info_without_legacy_user_cache_fallback() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // 删 zone_info 行，并在 users 上留下旧 zone_config / self_cert。
        sqlx::query("DELETE FROM zone_info WHERE username = 'alice'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("delete zone_info failed", e))?;
        sqlx::query(
            "UPDATE users SET zone_config = 'did:zone:legacy', self_cert = 1 WHERE username = 'alice'",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("update user cache failed", e))?;

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(zone.zone.is_none());
        assert!(!zone.self_cert);

        // 完全未知用户 → 默认值（不报错）。
        let zone = db.get_zone_info("ghost").await?.unwrap();
        assert_eq!(zone.username, "ghost");
        assert!(zone.zone.is_none());
        assert!(!zone.self_cert);

        Ok(())
    }

    /// `update_zone_relay_sn`：按 zone/bns_name/username 命中写 relay_sn；缺行则插入；空参数被拒。
    #[tokio::test]
    async fn test_update_zone_relay_sn_paths() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
                .await?
        );

        // 按 username/bns_name 命中既有行。
        assert!(
            db.update_zone_relay_sn("alice", "relay-a", Some("v2"))
                .await?
        );
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a"));
        assert_eq!(zone.source_version.as_deref(), Some("v2"));

        // 空 zone / 空 relay_sn → InvalidInput。
        assert_eq!(
            db.update_zone_relay_sn("", "relay-a", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assert_eq!(
            db.update_zone_relay_sn("alice", "  ", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );

        // 缺行 → 插入新 zone_info 行。
        assert!(
            db.update_zone_relay_sn("ghost-zone", "relay-b", None)
                .await?
        );
        let zone = db.get_zone_info("ghost-zone").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-b"));

        Ok(())
    }

    /// 指定 (domain, owner) 最新一行绑定的状态。
    async fn binding_state(db: &SqliteSnAuthDB, domain: &str, owner: &str) -> SnResult<String> {
        sqlx::query_scalar(
            "SELECT state FROM user_domain_bindings
             WHERE domain = ?1 AND owner = ?2
             ORDER BY id DESC LIMIT 1",
        )
        .bind(domain)
        .bind(owner)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("read binding state failed", e))
    }

    async fn history_count(db: &SqliteSnAuthDB, domain: &str, owner: &str) -> SnResult<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_history WHERE domain = ?1 AND owner = ?2",
        )
        .bind(domain)
        .bind(owner)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count history failed", e))
    }
}
