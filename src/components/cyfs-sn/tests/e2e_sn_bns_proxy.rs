//! SN BNS proxy 真链 e2e（doc/SN/sn-bns-proxy-todo.md §测试）。
//!
//! 在测试进程内拉起 anvil + `forge create` 部署 `Bns.sol`（与
//! bns-client/tests/e2e_anvil.rs 同一套自包含 harness），验证完整验收链路：
//!
//! 注册（SN 代付 gas，assetOwner=用户地址）
//!   -> wait receipt -> indexer sync
//!   -> 链上 assetOwner 是用户地址
//!   -> 独立 publish_document 发布 zone，indexer 投影可见
//!   -> controller 不能替换 owner 文档中已存在的身份字段
//!   -> 绑定 controller 可写 dns_txt
//!   -> 用户用自己的 owner key `setControllerPolicy` 清空 SN controller 权限
//!   -> controller 再写 dns_txt：TX 可投递但链上 revert（status 0x0），投影不变。
//!
//! - `#[ignore]`：默认跳过；`cargo test -p cyfs-sn --test e2e_sn_bns_proxy -- --ignored` 运行。
//! - 缺 Foundry（anvil/forge 不在 PATH）时优雅跳过。

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bns_client::{
    BnsEvmClientConfig, BnsEvmControllerClient, BnsIndexerApi, BnsIndexerClient,
    BnsSetControllerPolicyReq, DnsTxtUpdate, MemorySnBnsWriteRequestStore, SnBnsController,
    SnBnsControllerConfig,
};
use bns_evm::{Address, EthRpcClient};
use bns_indexer::{
    policy_hash_from_rules, sync_bns_contract_once, BnsBlockSyncSourceConfig,
    BnsIndexerSyncConfig, BnsRegistryStore, CallAuthority, CentralizedBnsIndexerHandler,
    CentralizedBnsRegistry, DocumentStatus, MutationGuard, NameStatus, Principal,
    SqliteBnsRegistryStore,
};
use cyfs_sn::{
    BoundControllerKeyManager, MemorySnBnsControllerBindingStore, SnBnsControllerKeySpec,
    SnBnsDnsTxtRecord, SnBnsProxy, SnBnsProxyController, SnBnsProxyInitialDocuments,
    SnBnsProxyOperation, SnBnsProxyRegisterParams, SnBnsProxyStatus, SnBnsTxSigner,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::sleep;

const CHAIN_ID: u64 = 31_337;

// anvil 确定性助记词 "test test ... junk" 账户。
// account[1]：仅部署（nonce 与写账户隔离）。
const DEPLOYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// account[2] / account[4]：SN 的两把 controller key。
const CONTROLLER_A_KEY: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const CONTROLLER_A_ADDR: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
const CONTROLLER_B_KEY: &str =
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";
const CONTROLLER_B_ADDR: &str = "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65";
// account[3]：用户 owner EVM 地址（有 gas，可自己发 setControllerPolicy 退出托管）。
const USER_OWNER_KEY: &str =
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const USER_OWNER_ADDR: &str = "0x90f79bf6eb2c4f870365e785982e1f101e93b906";

const USER_NAME: &str = "alice";

fn foundry_available() -> bool {
    fn has(bin: &str) -> bool {
        std::process::Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    has("anvil") && has("forge")
}

fn bns_app_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../src/components/cyfs-sn
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/bns")
        .canonicalize()
        .expect("bns foundry project should exist")
}

struct AnvilNode {
    _child: Child,
    endpoint: String,
}

impl AnvilNode {
    async fn start() -> Self {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let child = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                &CHAIN_ID.to_string(),
                "--mnemonic",
                "test test test test test test test test test test test junk",
                "--disable-code-size-limit",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn anvil");

        let endpoint = format!("http://127.0.0.1:{port}");
        let rpc = EthRpcClient::new(endpoint.clone());
        for _ in 0..100 {
            if let Ok(chain_id) = rpc.chain_id().await {
                assert_eq!(chain_id, CHAIN_ID, "anvil chain id mismatch");
                return Self {
                    _child: child,
                    endpoint,
                };
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("anvil did not become ready at {endpoint}");
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn rpc(&self) -> EthRpcClient {
        EthRpcClient::new(self.endpoint.clone())
    }
}

async fn deploy_bns(endpoint: &str, deployer_key: &str) -> Address {
    let output = Command::new("forge")
        .current_dir(bns_app_dir())
        .args([
            "create",
            "src/Bns.sol:Bns",
            "--rpc-url",
            endpoint,
            "--private-key",
            deployer_key,
            "--broadcast",
            "--json",
        ])
        .output()
        .await
        .expect("failed to run forge create");
    assert!(
        output.status.success(),
        "forge create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("forge create produced no JSON: {stdout}"));
    let end = stdout
        .rfind('}')
        .unwrap_or_else(|| panic!("forge create produced no JSON object: {stdout}"));
    let parsed: serde_json::Value = serde_json::from_str(&stdout[start..=end]).unwrap();
    parsed["deployedTo"]
        .as_str()
        .expect("forge create JSON missing deployedTo")
        .parse()
        .expect("invalid deployed contract address")
}

async fn wait_receipt(rpc: &EthRpcClient, tx_hash: &str) -> serde_json::Value {
    for _ in 0..100 {
        if let Ok(receipt) = rpc
            .call::<serde_json::Value>("eth_getTransactionReceipt", json!([tx_hash]))
            .await
        {
            if !receipt.is_null() {
                return receipt;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("receipt for {tx_hash} not available");
}

fn receipt_status(receipt: &serde_json::Value) -> &str {
    receipt["status"].as_str().unwrap_or_default()
}

fn sync_config(endpoint: &str, contract: Address) -> BnsIndexerSyncConfig {
    BnsIndexerSyncConfig::new(BnsBlockSyncSourceConfig::anvil(
        endpoint,
        format!("{contract:#x}"),
        0,
    ))
}

/// 组装真链版 SnBnsProxy：SnBnsTxSigner 保管两把 controller key，
/// 每把 key 一个 BnsEvmControllerClient（真链 RPC）+ SnBnsController，
/// 读侧走同一份 indexer 投影（sqlite 文件 store）。
fn build_proxy(
    evm_config: &BnsEvmClientConfig,
    registry: &Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
) -> SnBnsProxy {
    let vault = Arc::new(
        SnBnsTxSigner::new(
            evm_config,
            SnBnsProxyOperation::all().into_iter().collect(),
            vec![
                SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: Some(CONTROLLER_A_ADDR.to_string()),
                    private_key: CONTROLLER_A_KEY.to_string(),
                    weight: 1,
                },
                SnBnsControllerKeySpec {
                    id: "controller-b".to_string(),
                    declared_address: Some(CONTROLLER_B_ADDR.to_string()),
                    private_key: CONTROLLER_B_KEY.to_string(),
                    weight: 1,
                },
            ],
        )
        .unwrap(),
    );

    let write_request_store = Arc::new(MemorySnBnsWriteRequestStore::new());
    let mut controllers = Vec::new();
    for info in vault.controller_infos() {
        let key_manager = BoundControllerKeyManager::new(vault.clone(), info.id.as_str()).unwrap();
        let evm_controller = Arc::new(BnsEvmControllerClient::new_with_key_manager(
            evm_config.clone(),
            Arc::new(key_manager),
        ));
        let handler: Arc<dyn BnsIndexerApi> =
            Arc::new(CentralizedBnsIndexerHandler::new(registry.clone()));
        let controller = SnBnsController::new_evm(
            Arc::new(BnsIndexerClient::new_in_process(handler)),
            write_request_store.clone(),
            SnBnsControllerConfig::new(
                Principal::chain_account(info.address_hex.clone()),
                "",
            ),
            evm_controller,
        )
        .unwrap();
        controllers.push(SnBnsProxyController {
            id: info.id.clone(),
            address: info.address_hex.clone(),
            principal: Principal::chain_account(info.address_hex.clone()),
            weight: info.weight,
            controller: Arc::new(controller),
        });
    }

    SnBnsProxy::new(
        controllers,
        Arc::new(MemorySnBnsControllerBindingStore::new()),
        SnBnsProxyOperation::all().into_iter().collect(),
        true,
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_register_publish_document_then_owner_exits_sn_custody() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();
    let evm_config =
        BnsEvmClientConfig::anvil(node.endpoint(), format!("{contract:#x}"), CHAIN_ID);

    // indexer 投影：文件 sqlite store；sync 与读共用同一 registry。
    let projection_db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
    let registry = Arc::new(CentralizedBnsRegistry::new(
        SqliteBnsRegistryStore::open(projection_db.path()).unwrap(),
    ));
    let sync_once = || async {
        sync_bns_contract_once(registry.store(), sync_config(node.endpoint(), contract))
            .await
            .unwrap()
    };

    let proxy = build_proxy(&evm_config, &registry);

    // --- 1. 注册：用户只出 owner 地址，gas 由 SN controller 代付 ---
    let register_outcome = proxy
        .register_bootstrap(SnBnsProxyRegisterParams {
            request_id: format!("sn:register:{USER_NAME}"),
            name: USER_NAME.to_string(),
            asset_owner: USER_OWNER_ADDR.to_string(),
            owner_config: json!({
                "name": USER_NAME,
                "created_by": "cyfs-sn",
                "public_key": {"kty":"OKP","crv":"Ed25519","x":"alice-key"}
            }),
            initial_documents: SnBnsProxyInitialDocuments {
                zone: None,
                boot: None,
                dns_txt: Some(vec![SnBnsDnsTxtRecord {
                    ttl: 600,
                    value: "pkx=seed".to_string(),
                }]),
            },
        })
        .await
        .unwrap();
    assert_eq!(register_outcome.status, SnBnsProxyStatus::Submitted);
    let register_tx = register_outcome.tx_hash.clone().unwrap();
    let bound_controller = register_outcome.controller_address.clone();

    // proxy 只返回 submitted；上链成败由客户端按 tx_hash 自查。
    let receipt = wait_receipt(&rpc, register_tx.as_str()).await;
    assert_eq!(receipt_status(&receipt), "0x1", "register must succeed on-chain");

    // --- 2. indexer sync -> 链上 assetOwner 是用户地址 ---
    sync_once().await;
    let (name_state, initial_dns) = registry
        .store()
        .transact(|tx| {
            Ok((
                tx.get_name(USER_NAME)?.expect("name projected"),
                tx.get_current_document(USER_NAME, "dns_txt")?
                    .expect("initial dns_txt projected"),
            ))
        })
        .unwrap();
    assert_eq!(name_state.status, NameStatus::Active);
    assert_eq!(
        name_state.asset_owner.to_lowercase(),
        USER_OWNER_ADDR,
        "NameState.assetOwner must be the user's EVM address"
    );
    assert_eq!(initial_dns.status, DocumentStatus::Active);
    assert!(String::from_utf8_lossy(&initial_dns.document.inline_document).contains("pkx=seed"));

    // --- 3. 注册后独立发布 zone，indexer 投影可见 ---
    let zone_outcome = proxy
        .publish_document(
            USER_NAME,
            "sn:document:alice:zone:1".to_string(),
            "zone".to_string(),
            json!({"oods":["ood1"]}),
        )
        .await
        .unwrap();
    assert_eq!(zone_outcome.status, SnBnsProxyStatus::Submitted);
    assert_eq!(zone_outcome.controller_address, bound_controller);
    let zone_tx = zone_outcome.tx_hash.clone().unwrap();
    assert_eq!(receipt_status(&wait_receipt(&rpc, zone_tx.as_str()).await), "0x1");
    sync_once().await;
    let zone_doc = registry
        .store()
        .transact(|tx| Ok(tx.get_current_document(USER_NAME, "zone")?.unwrap()))
        .unwrap();
    assert_eq!(zone_doc.version, 1);
    let zone_body: serde_json::Value =
        serde_json::from_slice(&zone_doc.document.inline_document).unwrap();
    assert_eq!(zone_body["oods"], json!(["ood1"]));

    // owner 文档已有身份字段时，替换 key 在构造/签名前即被拒绝，不落 TX。
    let owner_change_error = proxy
        .publish_document(
            USER_NAME,
            "sn:document:alice:owner:change".to_string(),
            "owner".to_string(),
            json!({
                "name": USER_NAME,
                "public_key": {"kty":"OKP","crv":"Ed25519","x":"evil-key"}
            }),
        )
        .await
        .unwrap_err();
    assert!(owner_change_error.to_string().contains("cannot be changed"));

    // --- 4. 绑定 controller 可写 dns_txt ---
    let publish_outcome = proxy
        .publish_dns_txt(
            USER_NAME,
            "sn:dns:alice:1".to_string(),
            DnsTxtUpdate::Add {
                ttl: 300,
                value: "pkx=live".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(publish_outcome.status, SnBnsProxyStatus::Submitted);
    assert_eq!(publish_outcome.controller_address, bound_controller);
    // 同一 controller 的 register -> zone -> dns_txt nonce 连续递增。
    assert_eq!(
        publish_outcome.nonce.unwrap(),
        register_outcome.nonce.unwrap() + 2
    );
    let publish_tx = publish_outcome.tx_hash.clone().unwrap();
    assert_eq!(receipt_status(&wait_receipt(&rpc, publish_tx.as_str()).await), "0x1");

    sync_once().await;
    let dns_doc = registry
        .store()
        .transact(|tx| Ok(tx.get_current_document(USER_NAME, "dns_txt")?.unwrap()))
        .unwrap();
    assert_eq!(dns_doc.version, 2);
    let dns_body = String::from_utf8_lossy(&dns_doc.document.inline_document).to_string();
    assert!(dns_body.contains("pkx=seed") && dns_body.contains("pkx=live"), "{dns_body}");

    // --- 5. 用户用自己的 owner key 清空 controller policy，退出 SN 托管 ---
    // guard 用投影里的最新 name_seq（上一步 sync 已含 publish 后状态）。
    let fresh_seq = registry
        .store()
        .transact(|tx| Ok(tx.get_name(USER_NAME)?.unwrap().name_seq))
        .unwrap();
    let user_client = BnsEvmControllerClient::new(evm_config.clone(), USER_OWNER_KEY).unwrap();
    let empty_rules = Vec::new();
    let clear_submission = user_client
        .set_controller_policy(&BnsSetControllerPolicyReq {
            name: USER_NAME.to_string(),
            rules: empty_rules.clone(),
            policy_hash: policy_hash_from_rules(&empty_rules).unwrap(),
            authority: CallAuthority::owner(Principal::chain_account(USER_OWNER_ADDR), ""),
            guard: MutationGuard {
                expected_name_seq: fresh_seq,
                expected_parent_name_seq: 0,
            },
        })
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, clear_submission.tx_hash.as_str()).await),
        "0x1",
        "owner setControllerPolicy(clear) must succeed"
    );
    sync_once().await;

    // --- 6. controller 再写：TX 可投递但链上 revert，投影不变 ---
    let denied_outcome = proxy
        .publish_dns_txt(
            USER_NAME,
            "sn:dns:alice:2".to_string(),
            DnsTxtUpdate::Add {
                ttl: 300,
                value: "pkx=denied".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(denied_outcome.status, SnBnsProxyStatus::Submitted);
    let denied_tx = denied_outcome.tx_hash.clone().unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, denied_tx.as_str()).await),
        "0x0",
        "controller write after policy clear must revert on-chain"
    );

    sync_once().await;
    let final_dns = registry
        .store()
        .transact(|tx| Ok(tx.get_current_document(USER_NAME, "dns_txt")?.unwrap()))
        .unwrap();
    assert_eq!(final_dns.version, 2, "projection must be unchanged after revert");
    assert!(
        !String::from_utf8_lossy(&final_dns.document.inline_document).contains("pkx=denied")
    );
}
