//! §2.4 BNS Rust 组件独立测试补全 —— `bns-client` EVM 提交链路（无活节点）。
//!
//! 覆盖测试计划 doc/SN/SN-测试计划.md §2.4：
//! - Standard Client：外部已签 raw TX → 经 server `submit_raw` 提交（mock server）。
//! - Standard Client：`submit_raw_tx` 直接转发 `eth_sendRawTransaction`（原样 raw 字节）。
//! - Controller Client：自动 nonce → chainId/to/gas → ABI 编码 → 签名 → 提交全链。
//! - nonce 管理：连续两笔写 nonce 递增；提交失败回退重查。
//!
//! 既有 tests/rpc_and_controller.rs 已覆盖控制策略边界/DNS TXT 幂等/stale guard/多步 zone bind。

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bns_client::{
    BnsClientError, BnsClientResult, BnsEvmClientConfig, BnsEvmControllerClient,
    BnsEvmRawTxSubmitter, BnsEvmReceiptWaitConfig, BnsEvmStandardClient, BnsIndexerApi,
    BnsPrepareTxReq, BnsPrepareTxResp, BnsRegisterNameReq, BnsSubmitRawTxReq, BnsSubmitRawTxResp,
    BnsTxExecutionState, BnsTxState,
};
use bns_evm::{decode_signed_eip1559, Address};
use bns_indexer::{
    AuthorityKey, AuthoritySetState, CallAuthority, DocumentState, EventLogRecord, LogCheckpoint,
    MutationGuard, NameState, OwnerResolution, RegisterOptions, ResolveResult,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDRESS: Address = bns_evm::address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const SERVER_TX_HASH: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";

// ===== 捕获型 mock BNS Server（仅实现 submit_raw_tx，其余方法不会被调用）=====

struct CapturingBnsServer {
    received_raw_txs: Arc<Mutex<Vec<Vec<u8>>>>,
    next_nonce: Mutex<u64>,
}

impl CapturingBnsServer {
    fn new() -> Self {
        Self {
            received_raw_txs: Arc::new(Mutex::new(Vec::new())),
            next_nonce: Mutex::new(5),
        }
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.received_raw_txs.lock().unwrap().clone()
    }
}

fn unused<T>(method: &str) -> BnsClientResult<T> {
    Err(BnsClientError::unsupported(format!(
        "CapturingBnsServer.{method} should not be called in this test"
    )))
}

#[async_trait]
impl BnsIndexerApi for CapturingBnsServer {
    async fn query_name_state(&self, _name: &str) -> BnsClientResult<Option<NameState>> {
        unused("query_name_state")
    }
    async fn resolve_owner(&self, _name: &str) -> BnsClientResult<OwnerResolution> {
        unused("resolve_owner")
    }
    async fn get_authority_set(&self, _name: &str) -> BnsClientResult<AuthoritySetState> {
        unused("get_authority_set")
    }
    async fn get_authority_key(
        &self,
        _name: &str,
        _kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        unused("get_authority_key")
    }
    async fn resolve_document(
        &self,
        _name: &str,
        _doc_type: &str,
    ) -> BnsClientResult<ResolveResult> {
        unused("resolve_document")
    }
    async fn get_document_version(
        &self,
        _name: &str,
        _doc_type: &str,
        _version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        unused("get_document_version")
    }

    async fn submit_raw_tx(&self, req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        let raw = req.raw_tx_bytes()?;
        self.received_raw_txs.lock().unwrap().push(raw);
        Ok(BnsSubmitRawTxResp {
            tx_hash: SERVER_TX_HASH.to_string(),
        })
    }

    async fn prepare_tx(&self, _req: BnsPrepareTxReq) -> BnsClientResult<BnsPrepareTxResp> {
        let mut next_nonce = self.next_nonce.lock().unwrap();
        let nonce = *next_nonce;
        *next_nonce += 1;
        Ok(BnsPrepareTxResp {
            nonce,
            chain_id: 31_337,
            contract_address: OWNER.to_string(),
            estimated_gas: 100_000,
            gas_limit: 120_000,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        })
    }

    async fn query_tx_state(&self, tx_hash: &str) -> BnsClientResult<BnsTxState> {
        Ok(BnsTxState {
            tx_hash: tx_hash.to_string(),
            state: BnsTxExecutionState::Succeeded,
            block_number: Some(8),
            confirmations: 3,
        })
    }

    async fn list_events(
        &self,
        _from_seq: u64,
        _limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        unused("list_events")
    }
    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        unused("latest_checkpoint")
    }
}

// ===== mock eth JSON-RPC：回应 nonce 查询（eth_getTransactionCount）+ 捕获 sendRawTransaction =====

struct MockEthRpc {
    endpoint: String,
    sent_raw_txs: Arc<Mutex<Vec<String>>>,
}

impl MockEthRpc {
    async fn start(initial_nonce: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let nonce = Arc::new(Mutex::new(initial_nonce));
        let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let nonce_c = nonce.clone();
        let sent_c = sent.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let nonce_c = nonce_c.clone();
                let sent_c = sent_c.clone();
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    let body = request
                        .split_once("\r\n\r\n")
                        .map(|(_, b)| b.to_string())
                        .unwrap_or_default();
                    let req: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let id = req["id"].clone();
                    let result = match req["method"].as_str().unwrap_or("") {
                        "eth_getTransactionCount" => {
                            serde_json::Value::String(format!("0x{:x}", *nonce_c.lock().unwrap()))
                        }
                        "eth_sendRawTransaction" => {
                            if let Some(raw) = req["params"][0].as_str() {
                                sent_c.lock().unwrap().push(raw.to_string());
                            }
                            serde_json::Value::String(SERVER_TX_HASH.to_string())
                        }
                        "eth_getTransactionReceipt" => serde_json::json!({
                            "transactionHash": SERVER_TX_HASH,
                            "blockHash": "0x5555555555555555555555555555555555555555555555555555555555555555",
                            "blockNumber": "0x8",
                            "transactionIndex": "0x0",
                            "status": "0x1",
                            "gasUsed": "0x5208"
                        }),
                        "eth_blockNumber" => serde_json::Value::String("0xa".to_string()),
                        "eth_estimateGas" => serde_json::Value::String("0x186a0".to_string()),
                        "eth_gasPrice" => serde_json::Value::String("0x3b9aca00".to_string()),
                        "eth_maxPriorityFeePerGas" => {
                            serde_json::Value::String("0x3b9aca00".to_string())
                        }
                        _ => serde_json::Value::Null,
                    };
                    let payload = serde_json::json!({"jsonrpc":"2.0","id":id,"result":result});
                    let body = serde_json::to_string(&payload).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            endpoint,
            sent_raw_txs: sent,
        }
    }

    fn sent(&self) -> Vec<String> {
        self.sent_raw_txs.lock().unwrap().clone()
    }
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if http_request_is_complete(&buf) {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn http_request_is_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);
    buf.len() >= header_end + 4 + content_length
}

fn config(endpoint: &str) -> BnsEvmClientConfig {
    BnsEvmClientConfig::anvil(
        endpoint,
        "0x2222222222222222222222222222222222222222",
        31_337,
    )
}

fn register_req(name: &str) -> BnsRegisterNameReq {
    BnsRegisterNameReq {
        name: name.to_string(),
        asset_owner: OWNER.to_string(),
        options: RegisterOptions::default(),
        authority_key_updates: vec![],
        semantic_owner_after_authority: None,
        controller_policy: vec![],
        controller_policy_hash: String::new(),
        initial_documents: vec![],
        authority: CallAuthority::public(),
        guard: MutationGuard::default(),
    }
}

#[tokio::test]
async fn standard_client_builds_tx_from_live_gas_and_fee_suggestions() {
    let eth = MockEthRpc::start(5).await;
    let client = BnsEvmStandardClient::new(config(&eth.endpoint));
    let call = bns_client::register_name_call(&register_req("alice")).unwrap();

    let (tx, suggestion) = client
        .build_unsigned_tx_with_suggestion(&call, ANVIL_ADDRESS, 7)
        .await
        .unwrap();

    assert_eq!(suggestion.estimated_gas, 100_000);
    assert_eq!(suggestion.gas_limit, 120_000);
    assert_eq!(suggestion.max_priority_fee_per_gas, 1_000_000_000);
    assert_eq!(suggestion.max_fee_per_gas, 3_000_000_000);
    assert_eq!(tx.gas_limit, suggestion.gas_limit);
    assert_eq!(tx.max_fee_per_gas, suggestion.max_fee_per_gas);
    assert_eq!(
        tx.max_priority_fee_per_gas,
        suggestion.max_priority_fee_per_gas
    );
}

// ===== 测试 =====

#[tokio::test]
async fn controller_auto_nonce_signs_and_submits_via_bns_server() {
    // 自动 nonce（从链上 eth_getTransactionCount=5）→ 构造 → 签名 → 经 server submit_raw 提交全链。
    let eth = MockEthRpc::start(5).await;
    let server = Arc::new(CapturingBnsServer::new());
    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        config(&eth.endpoint),
        Arc::new(bns_client::StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap()),
        server.clone(),
    );

    let submission = controller
        .register_name(&register_req("alice"))
        .await
        .unwrap();

    // 返回的提交回执：from = 托管私钥地址，nonce = 链上 5，chainId = 31337，tx hash 来自 server。
    assert_eq!(
        submission.from.to_lowercase(),
        format!("{ANVIL_ADDRESS:#x}")
    );
    assert_eq!(submission.nonce, 5);
    assert_eq!(submission.chain_id, 31_337);
    assert_eq!(submission.tx_hash, SERVER_TX_HASH);

    // raw TX 经 server 转发；独立解码后恢复出的 signer == 托管私钥地址（链上 msg.sender 一致）。
    let received = server.received();
    assert_eq!(received.len(), 1);
    let decoded = decode_signed_eip1559(&received[0]).unwrap();
    assert_eq!(decoded.recover_signer().unwrap(), ANVIL_ADDRESS);
    assert_eq!(decoded.tx().nonce, 5);
    assert_eq!(decoded.tx().chain_id, 31_337);
    // 没有走 eth_sendRawTransaction（提交目标是 server，不是链 RPC）。
    assert!(eth.sent().is_empty());
}

#[tokio::test]
async fn controller_increments_nonce_across_consecutive_writes() {
    let eth = MockEthRpc::start(5).await;
    let server = Arc::new(CapturingBnsServer::new());
    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        config(&eth.endpoint),
        Arc::new(bns_client::StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap()),
        server.clone(),
    );

    let first = controller
        .register_name(&register_req("alice"))
        .await
        .unwrap();
    let second = controller
        .register_name(&register_req("bob"))
        .await
        .unwrap();
    assert_eq!(first.nonce, 5);
    assert_eq!(second.nonce, 6, "nonce must increment for the next write");

    let received = server.received();
    assert_eq!(received.len(), 2);
    assert_eq!(decode_signed_eip1559(&received[0]).unwrap().tx().nonce, 5);
    assert_eq!(decode_signed_eip1559(&received[1]).unwrap().tx().nonce, 6);
}

#[tokio::test]
async fn controller_serializes_concurrent_writes_for_nonce_allocation() {
    let eth = MockEthRpc::start(5).await;
    let server = Arc::new(CapturingBnsServer::new());
    let controller = Arc::new(BnsEvmControllerClient::new_with_bns_server_submitter(
        config(&eth.endpoint),
        Arc::new(bns_client::StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap()),
        server.clone(),
    ));

    let alice_controller = controller.clone();
    let bob_controller = controller.clone();
    let (alice, bob) = tokio::join!(
        async move { alice_controller.register_name(&register_req("alice")).await },
        async move { bob_controller.register_name(&register_req("bob")).await },
    );
    let mut nonces = vec![alice.unwrap().nonce, bob.unwrap().nonce];
    nonces.sort_unstable();

    assert_eq!(nonces, vec![5, 6]);
    assert_eq!(server.received().len(), 2);
}

#[tokio::test]
async fn controller_can_wait_for_receipt_confirmations() {
    let eth = MockEthRpc::start(5).await;
    let server = Arc::new(CapturingBnsServer::new());
    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        config(&eth.endpoint),
        Arc::new(bns_client::StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap()),
        server,
    )
    .with_receipt_wait(Some(BnsEvmReceiptWaitConfig {
        timeout_ms: 1_000,
        poll_interval_ms: 1,
        confirmations: 3,
        require_success: true,
    }));

    let submission = controller
        .register_name(&register_req("alice"))
        .await
        .unwrap();

    assert_eq!(submission.receipt_status, Some(1));
    assert_eq!(submission.receipt_block_number, Some(8));
    assert_eq!(submission.receipt_confirmations, Some(3));
}

#[tokio::test]
async fn controller_resets_cached_nonce_after_submission_failure() {
    // 提交失败应回退缓存 nonce，下一笔重新查链（仍取回 5，而非误用 6）。
    let eth = MockEthRpc::start(5).await;
    // 用一个总是失败的 server submitter。
    struct FailingServer;
    #[async_trait]
    impl BnsIndexerApi for FailingServer {
        async fn query_name_state(&self, _n: &str) -> BnsClientResult<Option<NameState>> {
            unused("query_name_state")
        }
        async fn resolve_owner(&self, _n: &str) -> BnsClientResult<OwnerResolution> {
            unused("resolve_owner")
        }
        async fn get_authority_set(&self, _n: &str) -> BnsClientResult<AuthoritySetState> {
            unused("get_authority_set")
        }
        async fn get_authority_key(
            &self,
            _n: &str,
            _k: &str,
        ) -> BnsClientResult<Option<AuthorityKey>> {
            unused("get_authority_key")
        }
        async fn resolve_document(&self, _n: &str, _d: &str) -> BnsClientResult<ResolveResult> {
            unused("resolve_document")
        }
        async fn get_document_version(
            &self,
            _n: &str,
            _d: &str,
            _v: u64,
        ) -> BnsClientResult<Option<DocumentState>> {
            unused("get_document_version")
        }
        async fn submit_raw_tx(
            &self,
            _req: BnsSubmitRawTxReq,
        ) -> BnsClientResult<BnsSubmitRawTxResp> {
            Err(BnsClientError::Transport("chain rejected".to_string()))
        }
        async fn prepare_tx(&self, _req: BnsPrepareTxReq) -> BnsClientResult<BnsPrepareTxResp> {
            Ok(BnsPrepareTxResp {
                nonce: 5,
                chain_id: 31_337,
                contract_address: OWNER.to_string(),
                estimated_gas: 100_000,
                gas_limit: 120_000,
                max_fee_per_gas: 3_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            })
        }
        async fn list_events(&self, _f: u64, _l: usize) -> BnsClientResult<Vec<EventLogRecord>> {
            unused("list_events")
        }
        async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
            unused("latest_checkpoint")
        }
    }

    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        config(&eth.endpoint),
        Arc::new(bns_client::StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap()),
        Arc::new(FailingServer),
    );

    let err = controller
        .register_name(&register_req("alice"))
        .await
        .unwrap_err();
    assert!(matches!(err, BnsClientError::Transport(_)));

    // 缓存已回退：下一笔重新从链上取 nonce（仍是 5）。
    let err2 = controller
        .register_name(&register_req("bob"))
        .await
        .unwrap_err();
    assert!(matches!(err2, BnsClientError::Transport(_)));
}

#[tokio::test]
async fn standard_client_submit_raw_tx_forwards_to_chain_rpc() {
    // Standard client 把外部已签 raw TX 原样转发到 eth_sendRawTransaction。
    let eth = MockEthRpc::start(0).await;
    let client = BnsEvmStandardClient::new(config(&eth.endpoint));

    let raw = vec![0x02u8, 0xaa, 0xbb, 0xcc];
    let tx_hash = client.submit_raw_tx(&raw).await.unwrap();
    assert_eq!(tx_hash, SERVER_TX_HASH);

    let sent = eth.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0], format!("0x{}", hex::encode(&raw)));
}

#[tokio::test]
async fn controller_with_explicit_chain_rpc_submitter_uses_chain() {
    // 显式 ChainRpc submitter：签名后直接走 eth_sendRawTransaction（不经 server）。
    let eth = MockEthRpc::start(2).await;
    let controller = BnsEvmControllerClient::new(config(&eth.endpoint), ANVIL_PRIVATE_KEY)
        .unwrap()
        .with_raw_tx_submitter(BnsEvmRawTxSubmitter::ChainRpc);

    let submission = controller
        .register_name(&register_req("alice"))
        .await
        .unwrap();
    assert_eq!(submission.nonce, 2);
    assert_eq!(submission.tx_hash, SERVER_TX_HASH);

    let sent = eth.sent();
    assert_eq!(sent.len(), 1);
    // 链上收到的 raw 与回执里的 raw 一致。
    assert_eq!(sent[0].to_lowercase(), submission.raw_tx.to_lowercase());
    let raw_bytes = hex::decode(sent[0].trim_start_matches("0x")).unwrap();
    assert_eq!(
        decode_signed_eip1559(&raw_bytes)
            .unwrap()
            .recover_signer()
            .unwrap(),
        ANVIL_ADDRESS
    );
}
