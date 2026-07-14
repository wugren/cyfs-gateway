//! e2e_sn_seed —— 本机（非 VM）拉起 + seed 生效的真集成测试
//! （doc/SN/SN-seed-config-TODO.md §3.3；仿 bns-client e2e_anvil 的
//! ignored 真集成模式）。
//!
//! 运行：
//!   cargo test -p cyfs_gateway --test e2e_sn_seed -- --ignored --test-threads=1
//!
//! 依赖本机工具：anvil / forge / cast / cargo / deno / curl / dig
//! （sn-dev-up.sh 会做工具检查）。内部拉起 3.2 的 sn-dev 三件套环境到独立
//! VAR 目录（临时 rootfs / 临时 sqlite / 独立 env_root），结束后 --purge。
//! 网关端口来自 make_sn_config --dev-local profile（15353/18081/...），
//! anvil/bns 端口在此用与手工 sn-dev 不同的值，避免互扰。
//!
//! 用例映射（单个测试函数内顺序执行，避免重复拉环境）：
//!   T1 账号种子：alice 用测试密码 auth.login 拿到 token；种子激活码走通
//!      auth.register 新用户注册。
//!   T2 DNS 种子：dev DNS 端口查 bns.devtests.org 和
//!      alice.web3.devtests.org A -> sn_ip；用户域 TXT 含 BOOT=/PKX=/DEV=
//!      （zone/boot 内容）。
//!   T3 链上种子：GET /1.0/identifiers/did:bns:alice 经 indexer 投影解析
//!      成功（bns_dv_seed.yaml 的 on_init_txs 已生效）。
//!   T4 user_domain 种子：charlie.me 绑定可查询、did:web:charlie.me 解析生效。
//!   T5 幂等：不动 seed 重启（--resume）后 sqlite 行数与 updated_at 快照
//!      不变、接口行为一致；重跑 make_sn_config 产物稳定（seed 文件哈希不变）。
//!   T6 纯 Web3 位：dave 无 sn_user 行，仍可经 BNS 路径解析。

use cyfs_sn::SnAuthDB;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web3-gateway/scripts")
        .canonicalize()
        .expect("web3-gateway/scripts dir")
}

fn run_script(name: &str, args: &[&str], var_dir: &Path) -> std::process::Output {
    let script = scripts_dir().join(name);
    let output = Command::new("bash")
        .arg(script.as_path())
        .args(args)
        .env("SN_DEV_VAR_DIR", var_dir)
        // 与手工 sn-dev 环境（18545/18082）区分的独立端口。
        .env("SN_DEV_ANVIL_PORT", "18645")
        .env("SN_DEV_BNS_PORT", "18182")
        .output()
        .unwrap_or_else(|e| panic!("spawn {} failed: {e}", name));
    if !output.status.success() {
        panic!(
            "{} {:?} failed with {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            name,
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    output
}

struct SnDevEnv {
    var_dir: PathBuf,
    env: Value,
}

impl SnDevEnv {
    fn up(var_dir: &Path, mode: &str) -> Self {
        run_script("sn-dev-up.sh", &[mode], var_dir);
        let env_json = var_dir.join("sn-dev-env.json");
        let env: Value =
            serde_json::from_str(&std::fs::read_to_string(&env_json).expect("sn-dev-env.json"))
                .expect("parse sn-dev-env.json");
        Self {
            var_dir: var_dir.to_path_buf(),
            env,
        }
    }

    fn down_purge(&self) {
        let _ = run_script("sn-dev-down.sh", &["--purge"], self.var_dir.as_path());
    }

    fn sn_host(&self) -> String {
        self.env["sn_host"].as_str().expect("sn_host").to_string()
    }

    fn http_port(&self) -> u16 {
        self.env["gw_http_port"].as_u64().expect("gw_http_port") as u16
    }

    fn dns_port(&self) -> u16 {
        self.env["gw_dns_port"].as_u64().expect("gw_dns_port") as u16
    }

    fn sn_db_path(&self) -> PathBuf {
        PathBuf::from(self.env["sn_db"].as_str().expect("sn_db"))
    }

    fn rootfs(&self) -> PathBuf {
        PathBuf::from(self.env["rootfs"].as_str().expect("rootfs"))
    }

    /// 走网关 HTTP 面（Host 头路由到 web3_sn）。
    fn http_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build http client")
    }

    async fn get_identifier(&self, did: &str) -> (u16, Value) {
        let url = format!(
            "http://127.0.0.1:{}/1.0/identifiers/{}",
            self.http_port(),
            did
        );
        let resp = self
            .http_client()
            .get(url)
            .header("Host", format!("sn.{}", self.sn_host()))
            .send()
            .await
            .expect("identifiers request");
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// kRPC 线格式（{"method","params","sys":[seq]}）。auth.* 方法必须发到
    /// /kapi/sn/auth（is_method_allowed_on_path 按命名空间限定 path）。
    async fn sn_rpc(&self, path: &str, method: &str, params: Value) -> Value {
        let url = format!("http://127.0.0.1:{}{}", self.http_port(), path);
        let resp = self
            .http_client()
            .post(url)
            .header("Host", format!("sn.{}", self.sn_host()))
            .json(&json!({ "method": method, "params": params, "sys": [1u64] }))
            .send()
            .await
            .expect("sn rpc request");
        assert!(
            resp.status().is_success(),
            "sn rpc {} http status {}",
            method,
            resp.status()
        );
        resp.json().await.expect("sn rpc response json")
    }

    async fn dns_lookup(
        &self,
        name: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Vec<String> {
        use hickory_resolver::config::{
            NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
        };
        use hickory_resolver::TokioAsyncResolver;
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], self.dns_port())),
            Protocol::Udp,
        ));
        let mut opts = ResolverOpts::default();
        opts.recursion_desired = false;
        // TXT 应答（BOOT/DEV JWT）超过 512 字节，必须带 EDNS0 声明大缓冲，
        // 否则服务端置 TC 位、hickory 回退 TCP——dev DNS 栈只监听 UDP。
        opts.edns0 = true;
        let resolver = TokioAsyncResolver::tokio(config, opts);
        match resolver.lookup(name, record_type).await {
            Ok(lookup) => lookup.iter().map(|r| r.to_string()).collect(),
            Err(e) => panic!("dns lookup {} {:?} failed: {e}", name, record_type),
        }
    }
}

/// sn.sqlite3 的行数 + 时间戳快照（T5 幂等断言：完全相等 = 零写入）。
async fn sn_db_snapshot(db_path: &Path) -> BTreeMap<String, (i64, i64)> {
    use sqlx::sqlite::SqlitePoolOptions;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(format!("sqlite://{}", db_path.display()).as_str())
        .await
        .expect("open sn.sqlite3 snapshot connection");
    let mut result = BTreeMap::new();
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
        result.insert(table.to_string(), row);
    }
    pool.close().await;
    result
}

fn seed_products_digest(rootfs: &Path) -> BTreeMap<String, u64> {
    // 产物稳定性（确定性密钥，diff 干净）：内容指纹逐文件比较即可。
    fn digest(bytes: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }
    let mut result = BTreeMap::new();
    for name in ["bns_dv_seed.yaml", "sn_seed.yaml"] {
        let path = rootfs.join(name);
        result.insert(
            name.to_string(),
            digest(&std::fs::read(path).expect("read seed product")),
        );
    }
    let docs_root = rootfs.join("bns_seed_docs");
    let mut stack = vec![docs_root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read bns_seed_docs") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(rootfs)
                    .expect("strip rootfs prefix")
                    .to_string_lossy()
                    .to_string();
                result.insert(rel, digest(&std::fs::read(&path).expect("read seed doc")));
            }
        }
    }
    result
}

fn rpc_result(resp: &Value) -> &Value {
    resp.get("result")
        .unwrap_or_else(|| panic!("rpc response has no result: {resp}"))
}

#[tokio::test]
#[ignore = "real integration: brings up anvil + bns_dv + web3_gateway locally (sn-dev-up.sh)"]
async fn e2e_sn_seed_full_stack() {
    use hickory_resolver::proto::rr::RecordType;

    let tmp = tempfile::TempDir::new().unwrap();
    let var_dir = tmp.path().join("sn-dev");
    let env = SnDevEnv::up(var_dir.as_path(), "--fresh");

    // 用 guard 确保断言失败也能清理环境。
    struct DownGuard(PathBuf);
    impl Drop for DownGuard {
        fn drop(&mut self) {
            let script = scripts_dir().join("sn-dev-down.sh");
            let _ = Command::new("bash")
                .arg(script.as_path())
                .arg("--purge")
                .env("SN_DEV_VAR_DIR", self.0.as_path())
                .output();
        }
    }
    let _guard = DownGuard(env.var_dir.clone());

    // ---- T1 账号种子：alice 测试密码登录成功、拿到 token ----
    let login = env
        .sn_rpc("/kapi/sn/auth", "auth.login", json!({ "name": "alice", "pwd_hash": "devtest-pwd" }))
        .await;
    let login_result = rpc_result(&login);
    let token = login_result
        .get("access_token")
        .or_else(|| login_result.get("session_token"))
        .or_else(|| login_result.get("token"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("T1: login result has no token: {login_result}"));
    assert!(!token.is_empty(), "T1: empty login token");

    // 错误密码必须失败（种子密码不是形同虚设）。
    let bad_login = env
        .sn_rpc("/kapi/sn/auth", "auth.login", json!({ "name": "alice", "pwd_hash": "wrong-pwd" }))
        .await;
    assert!(
        bad_login.get("result").is_none() || bad_login.get("error").is_some(),
        "T1: wrong password unexpectedly succeeded: {bad_login}"
    );

    // 种子激活码走通新用户注册。
    let register = env
        .sn_rpc(
            "/kapi/sn/auth",
            "auth.register",
            json!({
                "name": "erindevtest",
                "email": "erindevtest@example.com",
                "pwd_hash": "erin-pwd",
                "active_code": "dev-code-1",
                "asset_owner": "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
            }),
        )
        .await;
    assert!(
        register.get("result").is_some(),
        "T1: register with seed activation code failed: {register}"
    );
    let relogin = env
        .sn_rpc("/kapi/sn/auth", "auth.login", json!({ "name": "erindevtest", "pwd_hash": "erin-pwd" }))
        .await;
    assert!(
        relogin.get("result").is_some(),
        "T1: freshly registered user cannot login: {relogin}"
    );

    // ---- T2 DNS 种子：A 记录 -> sn_ip；TXT 含 zone/boot 内容 ----
    let host = format!("alice.web3.{}", env.sn_host());
    let a_records = env.dns_lookup(host.as_str(), RecordType::A).await;
    assert!(
        a_records.iter().any(|r| r == "127.0.0.1"),
        "T2: A records of {host} = {a_records:?}, expected sn_ip 127.0.0.1"
    );
    let bns_host = format!("bns.{}", env.sn_host());
    let bns_a_records = env.dns_lookup(bns_host.as_str(), RecordType::A).await;
    assert!(
        bns_a_records.iter().any(|r| r == "127.0.0.1"),
        "T2: A records of {bns_host} = {bns_a_records:?}, expected sn_ip 127.0.0.1"
    );
    let txt_records = env.dns_lookup(host.as_str(), RecordType::TXT).await;
    let txt_joined = txt_records.join(" ");
    for marker in ["PKX=", "BOOT=", "DEV="] {
        assert!(
            txt_joined.contains(marker),
            "T2: TXT of {host} misses {marker}: {txt_records:?}"
        );
    }

    // ---- T3 链上种子：did:bns:alice 经 indexer 投影解析成功 ----
    let (status, alice_doc) = env.get_identifier("did:bns:alice").await;
    assert_eq!(status, 200, "T3: identifiers did:bns:alice -> {alice_doc}");
    // did:bns 缺省返回 zone 文档（oods/sn），did:web 返回带 id 的 boot 文档，
    // 两种形状都算经 indexer 投影解析成功。
    assert!(
        alice_doc.get("id").is_some() || alice_doc.get("oods").is_some(),
        "T3: unexpected identifiers payload: {alice_doc}"
    );

    // ---- T4 user_domain 种子：charlie.me 绑定可查询、解析生效 ----
    let (status, charlie_doc) = env.get_identifier("did:web:charlie.me").await;
    assert_eq!(status, 200, "T4: identifiers did:web:charlie.me -> {charlie_doc}");
    {
        // 绑定行确实在 SN DB（owner=charlie、verified 状态由 seed 直接置位）。
        let db = cyfs_sn::SqliteSnAuthDB::new_by_path(
            env.sn_db_path().to_string_lossy().as_ref(),
        )
        .await
        .expect("open sn db");
        let bound = db
            .get_user_by_domain("charlie.me")
            .await
            .expect("query binding")
            .expect("charlie.me binding exists");
        assert_eq!(bound.username.as_deref(), Some("charlie"));
        assert!(
            !bound.zone_config.trim().is_empty(),
            "T4: charlie.me zone document jwt missing in sn db"
        );
        for username in ["alice", "bob", "charlie"] {
            let user = db
                .get_user_info(username)
                .await
                .expect("query seed user")
                .expect("seed user exists");
            assert!(
                user.self_cert,
                "T4: {username} must have self_cert=true from the trusted dev seed"
            );
            assert!(
                db.get_zone_info(username)
                    .await
                    .expect("query seed zone_info")
                    .expect("seed zone_info exists")
                    .self_cert,
                "T4: {username} zone_info must project self_cert=true"
            );
        }
    }

    // ---- T6 纯 Web3 位：dave 无 sn_user 行，仍可经 BNS 路径解析 ----
    {
        let db = cyfs_sn::SqliteSnAuthDB::new_by_path(
            env.sn_db_path().to_string_lossy().as_ref(),
        )
        .await
        .expect("open sn db");
        assert!(
            !db.is_user_exist("dave").await.expect("query dave"),
            "T6: dave must NOT have an sn_user row (pure Web3 seed slot)"
        );
    }
    let (status, dave_doc) = env.get_identifier("did:bns:dave").await;
    assert_eq!(status, 200, "T6: identifiers did:bns:dave -> {dave_doc}");

    // ---- T5 幂等：不动 seed 重启 -> 快照不变、行为一致、产物稳定 ----
    let db_before = sn_db_snapshot(env.sn_db_path().as_path()).await;
    let products_before = seed_products_digest(env.rootfs().as_path());

    // --resume 只重启服务：bns_dv 种子在链上幂等重放（apply_mutations 路径
    // 判定 already up-to-date），cyfs-sn 对已种子化 DB 做 ensure-exists 重放。
    drop(env);
    let env = SnDevEnv::up(var_dir.as_path(), "--resume");

    let db_after = sn_db_snapshot(env.sn_db_path().as_path()).await;
    assert_eq!(
        db_before, db_after,
        "T5: sn.sqlite3 row counts / updated_at changed after seed replay"
    );

    // 重跑 make_sn_config（独立 scratch rootfs，同一 env_root）→ 产物稳定。
    {
        let rootfs2 = tmp.path().join("rootfs2");
        std::fs::create_dir_all(&rootfs2).unwrap();
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("src dir");
        let env_root = var_dir.join("env_root");
        let output = Command::new("deno")
            .current_dir(src_dir.as_path())
            .args([
                "run",
                "-A",
                "./make_sn_config.ts",
                "--rootfs",
                rootfs2.to_string_lossy().as_ref(),
                "--seed-v2",
                "--dev-local",
                "--env_root",
                env_root.to_string_lossy().as_ref(),
                "--ca",
                env_root.join("ca").to_string_lossy().as_ref(),
            ])
            .output()
            .expect("rerun make_sn_config");
        assert!(
            output.status.success(),
            "T5: make_sn_config rerun failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let products_rerun = seed_products_digest(rootfs2.as_path());
        assert_eq!(
            products_before, products_rerun,
            "T5: make_sn_config seed products not deterministic across reruns"
        );
    }

    // 重启后接口行为一致。
    let login = env
        .sn_rpc("/kapi/sn/auth", "auth.login", json!({ "name": "alice", "pwd_hash": "devtest-pwd" }))
        .await;
    assert!(login.get("result").is_some(), "T5: login broken after resume");
    let (status, _) = env.get_identifier("did:bns:alice").await;
    assert_eq!(status, 200, "T5: did:bns:alice broken after resume");
    let (status, _) = env.get_identifier("did:web:charlie.me").await;
    assert_eq!(status, 200, "T5: did:web:charlie.me broken after resume");

    env.down_purge();
}
