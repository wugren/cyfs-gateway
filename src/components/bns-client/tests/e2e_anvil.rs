//! §5.2(A) DV 集成测试（端到端，真 anvil 私链）。
//!
//! 覆盖测试计划 doc/SN/SN-测试计划.md §5.2(A)：在测试进程内拉起 anvil + 用 `forge create`
//! 部署 `Bns.sol`（自包含，不依赖 §5.1 脚本），跑通真链路
//! `BNS(合约) <-> BNS-Indexer <-> BNS-Server(读投影/写转发) <-> BNS-Client <-> Controller`。
//!
//! 这些用例只验证"跨层拼接 + 真 EVM 暴露的问题"（selector/packing/revert/event topic/nonce/
//! confirmations/重部署 source 隔离），不重复 §1–§4 的分支覆盖。
//!
//! - 全部 `#[ignore]`：默认 `cargo test` 跳过，`cargo test -p bns-client --test e2e_anvil -- --ignored`
//!   显式运行。
//! - 缺 Foundry（`anvil`/`forge` 不在 PATH）时优雅跳过而非失败。
//!
//! 覆盖项：
//! - [x] 写读闭环：Controller 注册 name → publishDocument(inline) → sync_once → 读投影命中，
//!       且投影 == 链上 eth_call 权威态。
//! - [x] 签名边界（真 EVM）：托管私钥签名时 msg.sender == 私钥地址 → 通过；
//!       构造 `CallAuthority.actor` != signer 的 TX → 链上 revert（receipt status 0 +
//!       eth_call 模拟回传错误码），投影不变。
//! - [x] selector / packing / event topic：真 EVM 接受 client 编码的 calldata 并 emit 事件，
//!       indexer 解码后投影一致（隐式钉死 §1.7/§2.1 契约）。
//! - [x] nonce / 重放：连续两笔写 nonce 递增；重放同一 raw TX → 链上拒绝；chainId 不匹配 → 拒绝。
//! - [x] confirmations / 同步推进：未达 confirmations 不投影，达到后投影命中；游标单调推进。
//! - [x] 重部署从 0 重放：换合约地址（新 source）→ indexer 从 start_block 重放 → 投影等价。
//! - [x] controller 策略真链路：controller 只能 publish 授权 docType，越权 docType → 链上 revert。

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use bns_client::{
    register_name_call, BnsEvmClientConfig, BnsEvmControllerClient, BnsEvmStandardClient,
    BnsPublishDocumentReq, BnsRegisterNameReq, BnsSetControllerPolicyReq,
};
use bns_evm::{
    decode_signed_eip1559, sign_eip1559_tx, signer_from_private_key, Address, Bns, EthRpcClient,
    SolCall,
};
use bns_indexer::{
    controller_rule, default_document_update, policy_hash_from_rules, sync_bns_contract_once,
    BnsBlockSyncSourceConfig, BnsIndexerSyncConfig, BnsRegistryStore, CallAuthority, DocumentRef,
    DocumentStatus, MutationGuard, NameStatus, Principal, RegisterOptions, SqliteBnsRegistryStore,
    PERMISSION_PUBLISH_DOCUMENT,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::sleep;

const CHAIN_ID: u64 = 31_337;

// anvil 确定性助记词 "test test ... junk" 的前几个账户。
// account[0]：Controller/owner 写账户（msg.sender）。
const WRITER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const WRITER_ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
// account[1]：仅用于 `forge create` 部署，nonce 与写账户独立，避免交错冲突。
const DEPLOYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// account[2]：controller-policy 用例里的受托 controller。
const CONTROLLER_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const CONTROLLER_ADDR: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

// `forge create` 会触发增量编译并读写 out/、cache/；并发跑会破坏 build 缓存，串行化。
fn forge_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

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
    // CARGO_MANIFEST_DIR = .../src/components/bns-client
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/bns")
        .canonicalize()
        .expect("bns foundry project should exist")
}

/// 进程内托管的 anvil 私链；Drop 时 kill。
struct AnvilNode {
    _child: Child,
    endpoint: String,
}

impl AnvilNode {
    async fn start() -> Self {
        // 选一个空闲端口（绑定后立即释放，留给 anvil）。
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
        // 健康门控：轮询 eth_chainId 就绪。
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

/// 用 `forge create` 部署 `Bns.sol`（与 scripts/deploy.sh 同路径），返回合约地址。
async fn deploy_bns(endpoint: &str, deployer_key: &str) -> Address {
    let _guard = forge_lock().lock().await;
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
    // forge create --json 输出（可能多行 pretty-print）的 JSON 对象；编译日志走 stderr。
    // 截取首个 '{' 到末个 '}' 的片段整体解析。
    let start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("forge create produced no JSON: {stdout}"));
    let end = stdout
        .rfind('}')
        .unwrap_or_else(|| panic!("forge create produced no JSON object: {stdout}"));
    let parsed: serde_json::Value = serde_json::from_str(&stdout[start..=end]).unwrap();
    let address = parsed["deployedTo"]
        .as_str()
        .expect("forge create JSON missing deployedTo");
    address.parse().expect("invalid deployed contract address")
}

fn writer_config(endpoint: &str, contract: Address) -> BnsEvmClientConfig {
    BnsEvmClientConfig::anvil(endpoint, format!("{contract:#x}"), CHAIN_ID)
}

fn controller_client(endpoint: &str, contract: Address, key: &str) -> BnsEvmControllerClient {
    BnsEvmControllerClient::new(writer_config(endpoint, contract), key).unwrap()
}

fn register_alice_req() -> BnsRegisterNameReq {
    BnsRegisterNameReq {
        name: "alice".to_string(),
        asset_owner: WRITER_ADDR.to_string(),
        options: RegisterOptions::default(),
        authority_key_updates: vec![],
        semantic_owner_after_authority: None,
        controller_policy: vec![],
        controller_policy_hash: String::new(),
        initial_documents: vec![],
        // registerName 走 msg.sender 准入；CallAuthority 仅作提示，用 public()。
        authority: CallAuthority::public(),
        guard: MutationGuard::default(),
    }
}

fn owner_authority() -> CallAuthority {
    CallAuthority::owner(Principal::chain_account(WRITER_ADDR), "")
}

fn publish_owner_doc_req(expected_name_seq: u64, body: &str) -> BnsPublishDocumentReq {
    BnsPublishDocumentReq {
        name: "alice".to_string(),
        update: default_document_update("owner", 0, DocumentRef::inline(body.as_bytes())).unwrap(),
        authority: owner_authority(),
        guard: MutationGuard {
            expected_name_seq,
            expected_parent_name_seq: 0,
        },
    }
}

/// 轮询 receipt（anvil 即时出块，通常立刻可得；容忍短暂未上链）。
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

async fn mine_blocks(rpc: &EthRpcClient, count: u64) {
    for _ in 0..count {
        rpc.call::<serde_json::Value>("evm_mine", json!([]))
            .await
            .expect("evm_mine failed");
    }
}

fn sync_config(endpoint: &str, contract: Address, confirmations: u64) -> BnsIndexerSyncConfig {
    let mut config = BnsIndexerSyncConfig::new(BnsBlockSyncSourceConfig::anvil(
        endpoint,
        format!("{contract:#x}"),
        0,
    ));
    config.confirmations = confirmations;
    config
}

// =====================================================================================
// 用例 1：写读闭环 + selector/packing/event topic + 投影==链上权威态
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_write_read_closed_loop_matches_onchain_truth() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();

    let controller = controller_client(node.endpoint(), contract, WRITER_KEY);

    // 写：注册 alice（nonce 自动）→ publishDocument(owner, inline)。
    let registered = controller
        .register_name(&register_alice_req())
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &registered.tx_hash).await),
        "0x1"
    );
    assert_eq!(registered.from.to_lowercase(), WRITER_ADDR);

    let body = r#"{"id":"did:bns:alice","v":1}"#;
    let published = controller
        .publish_document(&publish_owner_doc_req(1, body))
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &published.tx_hash).await),
        "0x1"
    );
    // 连续两笔写 nonce 递增（注册 nonce N、发布 nonce N+1）。
    assert_eq!(published.nonce, registered.nonce + 1);

    // 同步：sync_once 把链上事件投影进 SQLite。
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let outcome = sync_bns_contract_once(&store, sync_config(node.endpoint(), contract, 0))
        .await
        .unwrap();
    assert!(
        outcome.registry_events_stored >= 2,
        "expected name+document events"
    );

    // 读投影：name Active、owner 文档 version 1、inline 内容一致。
    let (name_state, doc_state) = store
        .transact(|tx| {
            let name = tx.get_name("alice")?.expect("alice projected");
            let doc = tx
                .get_current_document("alice", "owner")?
                .expect("owner doc projected");
            Ok((name, doc))
        })
        .unwrap();
    assert_eq!(name_state.status, NameStatus::Active);
    assert_eq!(doc_state.status, DocumentStatus::Active);
    assert_eq!(doc_state.version, 1);
    assert_eq!(doc_state.document.inline_document, body.as_bytes());

    // 投影 == 链上 eth_call 权威态（nameSeq / status 由 eth_call 取得，而非事件回放）。
    let onchain = rpc
        .call_contract(
            contract,
            &Bns::queryNameStateCall {
                name: "alice".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(onchain.nameSeq, name_state.name_seq);
    let onchain_doc = rpc
        .call_contract(
            contract,
            &Bns::getDocumentVersionCall {
                name: "alice".to_string(),
                docType: "owner".to_string(),
                version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(onchain_doc.document.contentHash.to_vec(), {
        // 链上 contentHash == sha256(body)，与投影 content_hash 一致。
        hex::decode(doc_state.document.content_hash.trim_start_matches("0x")).unwrap()
    });
}

// =====================================================================================
// 用例 2：签名边界（真 EVM）—— actor != msg.sender 链上 revert，投影不变
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_signing_boundary_actor_mismatch_reverts_onchain() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();

    let controller = controller_client(node.endpoint(), contract, WRITER_KEY);
    let registered = controller
        .register_name(&register_alice_req())
        .await
        .unwrap();
    wait_receipt(&rpc, &registered.tx_hash).await;

    // 正常路径：actor == signer == msg.sender → 通过。
    let ok = controller
        .publish_document(&publish_owner_doc_req(1, r#"{"v":"ok"}"#))
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &ok.tx_hash).await),
        "0x1"
    );

    // 越权路径：用 WRITER_KEY 签名（msg.sender = writer），但把 CallAuthority.actor
    // 改成另一个地址 → 合约只信 msg.sender 与有效 owner 的关系，actor 提示对不上 → revert。
    let mut bad = publish_owner_doc_req(2, r#"{"v":"evil"}"#);
    bad.authority = CallAuthority::owner(Principal::chain_account(CONTROLLER_ADDR), "");
    let bad_submission = controller.publish_document(&bad).await.unwrap();
    // raw TX 上链被打包但执行 revert（receipt status 0）。
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &bad_submission.tx_hash).await),
        "0x0",
        "actor != msg.sender must revert on-chain"
    );

    // 错误码透传演示：用 eth_call（from = writer）模拟同一调用 → JSON-RPC 回传 revert 错误。
    let bad_calldata = bns_client::publish_document_call(&bad)
        .unwrap()
        .abi_encode();
    let simulated: Result<String, _> = rpc
        .call(
            "eth_call",
            json!([{
                "from": WRITER_ADDR,
                "to": format!("{contract:#x}"),
                "data": format!("0x{}", hex::encode(&bad_calldata)),
            }, "latest"]),
        )
        .await;
    assert!(
        simulated.is_err(),
        "eth_call simulation should surface the revert"
    );

    // 投影不变：越权写没有改变链上权威态，sync 后 owner 文档仍是上一笔合法版本。
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    sync_bns_contract_once(&store, sync_config(node.endpoint(), contract, 0))
        .await
        .unwrap();
    let doc = store
        .transact(|tx| tx.get_current_document("alice", "owner"))
        .unwrap()
        .expect("owner doc projected");
    assert_eq!(doc.document.inline_document, br#"{"v":"ok"}"#);
}

// =====================================================================================
// 用例 3：nonce / 重放 / chainId 不匹配
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_nonce_replay_and_chain_id_rejection() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();

    let controller = controller_client(node.endpoint(), contract, WRITER_KEY);
    let first = controller
        .register_name(&register_alice_req())
        .await
        .unwrap();
    let receipt = wait_receipt(&rpc, &first.tx_hash).await;
    assert_eq!(receipt_status(&receipt), "0x1");

    // 重放同一条已上链的 raw TX → 链上拒绝（nonce 已用）。
    let standard = BnsEvmStandardClient::new(writer_config(node.endpoint(), contract));
    let raw = hex::decode(first.raw_tx.trim_start_matches("0x")).unwrap();
    let replay = standard.submit_raw_tx(&raw).await;
    assert!(replay.is_err(), "replaying a mined raw TX must be rejected");

    // chainId 不匹配的 TX → 链上拒绝。手工用错误 chainId 配置构造并签名一笔 register。
    let wrong_chain = BnsEvmStandardClient::new(BnsEvmClientConfig::anvil(
        node.endpoint(),
        format!("{contract:#x}"),
        CHAIN_ID + 1,
    ));
    let signer = signer_from_private_key(WRITER_KEY).unwrap();
    let nonce = rpc.transaction_count(signer.address()).await.unwrap();
    let tx = wrong_chain
        .build_unsigned_tx(&register_name_call(&register_alice_req()).unwrap(), nonce)
        .unwrap();
    let signed = sign_eip1559_tx(tx, &signer).unwrap();
    let wrong = standard.submit_raw_tx(&signed.raw_tx).await;
    assert!(
        wrong.is_err(),
        "TX with mismatched chainId must be rejected"
    );

    // 自检：重放/错链都没有意外改变链状态，alice 仍只注册过一次（nameSeq == 1）。
    let onchain = rpc
        .call_contract(
            contract,
            &Bns::queryNameStateCall {
                name: "alice".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(onchain.nameSeq, 1);
}

// =====================================================================================
// 用例 4：confirmations 门控 + 游标单调推进
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_confirmations_gate_and_cursor_advance() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();

    let controller = controller_client(node.endpoint(), contract, WRITER_KEY);
    let registered = controller
        .register_name(&register_alice_req())
        .await
        .unwrap();
    wait_receipt(&rpc, &registered.tx_hash).await;
    let write_block = rpc.block_number().await.unwrap();

    // confirmations 设得高于当前链高，确保注册块尚未达确认数。
    let confirmations = 5;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();

    let first = sync_bns_contract_once(
        &store,
        sync_config(node.endpoint(), contract, confirmations),
    )
    .await
    .unwrap();
    let cursor_after_first = first.cursor.as_ref().map(|c| c.block_number).unwrap_or(0);
    assert!(
        cursor_after_first < write_block,
        "unconfirmed write block must not be synced yet"
    );
    assert!(
        store.transact(|tx| tx.get_name("alice")).unwrap().is_none(),
        "name must not be projected before confirmations are met"
    );

    // 推进足够多的块满足 confirmations，再同步 → 投影命中。
    mine_blocks(&rpc, confirmations + 1).await;
    let second = sync_bns_contract_once(
        &store,
        sync_config(node.endpoint(), contract, confirmations),
    )
    .await
    .unwrap();
    let cursor_after_second = second.cursor.as_ref().map(|c| c.block_number).unwrap_or(0);
    assert!(
        cursor_after_second > cursor_after_first,
        "cursor must advance monotonically"
    );
    assert!(
        cursor_after_second >= write_block,
        "cursor must reach the confirmed write block"
    );
    assert!(
        store.transact(|tx| tx.get_name("alice")).unwrap().is_some(),
        "name must be projected once confirmations are met"
    );
}

// =====================================================================================
// 用例 5：重部署从 0 重放（新合约地址 == 新 source，游标不串扰）
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_redeploy_uses_isolated_source_and_replays_from_zero() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let rpc = node.rpc();

    // 第一份合约 + 写入 + 同步。
    let contract_a = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let controller_a = controller_client(node.endpoint(), contract_a, WRITER_KEY);
    let reg_a = controller_a
        .register_name(&register_alice_req())
        .await
        .unwrap();
    wait_receipt(&rpc, &reg_a.tx_hash).await;

    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config_a = sync_config(node.endpoint(), contract_a, 0);
    let source_a = config_a.source.source_id().unwrap();
    sync_bns_contract_once(&store, config_a.clone())
        .await
        .unwrap();
    assert!(store.transact(|tx| tx.get_name("alice")).unwrap().is_some());

    // 重部署：新合约地址 → 新 source；注册同名 alice。
    let contract_b = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    assert_ne!(contract_a, contract_b, "redeploy must yield a new address");
    let controller_b = controller_client(node.endpoint(), contract_b, WRITER_KEY);
    let reg_b = controller_b
        .register_name(&register_alice_req())
        .await
        .unwrap();
    wait_receipt(&rpc, &reg_b.tx_hash).await;

    let config_b = sync_config(node.endpoint(), contract_b, 0);
    let source_b = config_b.source.source_id().unwrap();
    assert_ne!(
        source_a, source_b,
        "new contract address must be a new source"
    );

    // 新 source 从 start_block(0) 重放（旧游标不串扰），投影命中且语义等价。
    let outcome_b = sync_bns_contract_once(&store, config_b).await.unwrap();
    assert_eq!(outcome_b.source, source_b);
    assert_eq!(
        outcome_b.from_block, 0,
        "new source replays from start_block 0"
    );
    assert!(outcome_b.registry_events_stored >= 1);

    let onchain_b = rpc
        .call_contract(
            contract_b,
            &Bns::queryNameStateCall {
                name: "alice".to_string(),
            },
        )
        .await
        .unwrap();
    let projected = store
        .transact(|tx| tx.get_name("alice"))
        .unwrap()
        .expect("alice projected from new source");
    assert_eq!(projected.name_seq, onchain_b.nameSeq);
    assert_eq!(projected.status, NameStatus::Active);
}

// =====================================================================================
// 用例 6：controller 策略真链路 —— 授权 docType 通过，越权 docType 链上 revert
// =====================================================================================

#[tokio::test]
#[ignore = "requires Foundry (anvil/forge); run with --ignored"]
async fn e2e_controller_policy_scopes_doc_types_on_chain() {
    if !foundry_available() {
        eprintln!("skipping: anvil/forge not on PATH");
        return;
    }
    let node = AnvilNode::start().await;
    let contract = deploy_bns(node.endpoint(), DEPLOYER_KEY).await;
    let rpc = node.rpc();

    // owner（writer）注册并安装 controller policy：CONTROLLER 仅可 publish "service" 文档。
    let owner = controller_client(node.endpoint(), contract, WRITER_KEY);
    let reg = owner.register_name(&register_alice_req()).await.unwrap();
    wait_receipt(&rpc, &reg.tx_hash).await;

    let rules = vec![controller_rule(
        Principal::chain_account(CONTROLLER_ADDR),
        "service",
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    let set_policy = owner
        .set_controller_policy(&BnsSetControllerPolicyReq {
            name: "alice".to_string(),
            rules,
            policy_hash,
            authority: owner_authority(),
            guard: MutationGuard {
                expected_name_seq: 1,
                expected_parent_name_seq: 0,
            },
        })
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &set_policy.tx_hash).await),
        "0x1"
    );
    let name_seq_after_policy = rpc
        .call_contract(
            contract,
            &Bns::queryNameStateCall {
                name: "alice".to_string(),
            },
        )
        .await
        .unwrap()
        .nameSeq;

    // controller（CONTROLLER_KEY）publish 授权 docType "service" → 通过。
    let controller = controller_client(node.endpoint(), contract, CONTROLLER_KEY);
    let controller_authority =
        CallAuthority::controller(Principal::chain_account(CONTROLLER_ADDR), "");
    let allowed = controller
        .publish_document(&BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: default_document_update("service", 0, DocumentRef::inline(br#"{"svc":"ok"}"#))
                .unwrap(),
            authority: controller_authority.clone(),
            guard: MutationGuard {
                expected_name_seq: name_seq_after_policy,
                expected_parent_name_seq: 0,
            },
        })
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &allowed.tx_hash).await),
        "0x1",
        "controller must publish its authorized docType"
    );
    let name_seq_after_allowed = rpc
        .call_contract(
            contract,
            &Bns::queryNameStateCall {
                name: "alice".to_string(),
            },
        )
        .await
        .unwrap()
        .nameSeq;

    // controller publish 越权 docType "owner"（owner 级文档）→ 链上 revert。
    let denied = controller
        .publish_document(&BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: default_document_update("owner", 0, DocumentRef::inline(br#"{"v":"x"}"#))
                .unwrap(),
            authority: controller_authority,
            guard: MutationGuard {
                expected_name_seq: name_seq_after_allowed,
                expected_parent_name_seq: 0,
            },
        })
        .await
        .unwrap();
    assert_eq!(
        receipt_status(&wait_receipt(&rpc, &denied.tx_hash).await),
        "0x0",
        "controller must not publish an out-of-scope docType"
    );

    // 同步后投影：service 文档落库，owner 文档（越权）未落库。
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    sync_bns_contract_once(&store, sync_config(node.endpoint(), contract, 0))
        .await
        .unwrap();
    assert!(
        store
            .transact(|tx| tx.get_current_document("alice", "service"))
            .unwrap()
            .is_some(),
        "authorized service doc must be projected"
    );
    assert!(
        store
            .transact(|tx| tx.get_current_document("alice", "owner"))
            .unwrap()
            .is_none(),
        "out-of-scope owner doc must not exist"
    );
}

/// 静默未使用导入：`decode_signed_eip1559` 仅在调试 raw TX 时用到，这里钉住编译期可用性。
#[allow(dead_code)]
fn _anchor_decode(raw: &[u8]) {
    let _ = decode_signed_eip1559(raw);
}
