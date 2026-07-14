//! §2.3 BNS Rust 组件独立测试 —— `bns-server`（标准智能合约处理器）。
//!
//! 覆盖测试计划 doc/SN/SN-测试计划.md §2.3：
//! - 写路径 `tx.submit_raw`：合法 raw TX → 转发 `eth_sendRawTransaction`（断言收到的 raw 字节一致），返回 tx hash；非法 hex / 空 → 明确错误。
//! - 不解释 payload / 不鉴权：构造签名无效的 raw TX，server 仍原样转发（拒绝在链上发生）。
//! - 旧写 RPC 已移除：旧 method 返回 `UnknownMethod`。
//! - 读路径：投影查询经 envelope 包装正确。
//! - RPC 路由：`METHOD_SUBMIT_RAW_TX` 与别名 `submit_raw_tx` 都命中；未知 method → 错误。
//!
//! 用内存 SQLite 投影 + mock eth RPC（不需活节点）。

use std::sync::{Arc, Mutex};

use bns_client::{
    BnsIndexerApi, BnsNameReq, BnsPrepareTxReq, BnsRpcEnvelope, BnsSubmitRawTxReq,
    BnsTxExecutionState, METHOD_QUERY_NAME_STATE, METHOD_SUBMIT_RAW_TX,
};
use bns_indexer::{
    BnsRegistryStore, DocumentRef, DocumentState, DocumentStatus, NameState, NameStatus,
    OwnerSource, Principal, SqliteBnsRegistryStore, ZERO_HASH,
};
use bns_server::{BnsContractServerHandler, BnsContractServerRpcHandler};
use kRPC::{RPCErrors, RPCHandler, RPCRequest, RPCResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TX_HASH: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

/// 复用型 mock eth JSON-RPC：记录每次 `eth_sendRawTransaction` 收到的 raw-tx 参数，
/// 对所有请求返回固定 tx hash。建议作为 indexer/server 共用夹具的简化版。
#[derive(Clone)]
struct MockEthRpc {
    endpoint: String,
    received_raw_txs: Arc<Mutex<Vec<String>>>,
}

impl MockEthRpc {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let received = received_clone.clone();
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    // 抓取 jsonrpc body 中的 params[0]（raw tx hex）。
                    if let Some(body_start) = request.find("\r\n\r\n") {
                        let body = &request[body_start + 4..];
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
                            if value["method"] == "eth_sendRawTransaction" {
                                if let Some(raw) = value["params"][0].as_str() {
                                    received.lock().unwrap().push(raw.to_string());
                                }
                            }
                        }
                    }
                    let result = request
                        .find("\r\n\r\n")
                        .and_then(|start| {
                            serde_json::from_str::<serde_json::Value>(&request[start + 4..]).ok()
                        })
                        .and_then(
                            |request| match request["method"].as_str().unwrap_or_default() {
                                "eth_chainId" => Some(serde_json::json!("0x7a69")),
                                "eth_getTransactionCount" => Some(serde_json::json!("0x5")),
                                "eth_estimateGas" => Some(serde_json::json!("0x186a0")),
                                "eth_gasPrice" => Some(serde_json::json!("0x3b9aca00")),
                                "eth_maxPriorityFeePerGas" => Some(serde_json::json!("0x3b9aca00")),
                                _ => Some(serde_json::json!(TX_HASH)),
                            },
                        )
                        .unwrap();
                    let body = serde_json::to_string(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": result,
                    }))
                    .unwrap();
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
            received_raw_txs: received,
        }
    }

    fn received(&self) -> Vec<String> {
        self.received_raw_txs.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn system_info_and_tx_prepare_validate_chain_and_projection() {
    let mock = MockEthRpc::start().await;
    let handler = BnsContractServerHandler::new_with_chain_config(
        seeded_store(),
        &mock.endpoint,
        OWNER,
        31_337,
    );

    let info = handler.system_info().await.unwrap();
    assert!(info.ready);
    assert_eq!(info.chain_id, 31_337);
    assert_eq!(info.contract_address, OWNER);

    let prepared = handler
        .prepare_tx(BnsPrepareTxReq::new(OWNER, &[0x12, 0x34]))
        .await
        .unwrap();
    assert_eq!(prepared.nonce, 5);
    assert_eq!(prepared.chain_id, 31_337);
    assert_eq!(prepared.contract_address, OWNER);
    assert_eq!(prepared.estimated_gas, 100_000);
    assert_eq!(prepared.gas_limit, 120_000);
    assert_eq!(prepared.max_priority_fee_per_gas, 1_000_000_000);
    assert_eq!(prepared.max_fee_per_gas, 3_000_000_000);
}

struct MockTxStateRpc;

impl MockTxStateRpc {
    async fn start(receipt: serde_json::Value, transaction: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let receipt = receipt.clone();
                let transaction = transaction.clone();
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    let body = request
                        .split_once("\r\n\r\n")
                        .map(|(_, body)| body)
                        .unwrap_or_default();
                    let request: serde_json::Value = serde_json::from_str(body).unwrap();
                    let result = match request["method"].as_str().unwrap_or_default() {
                        "eth_getTransactionReceipt" => receipt,
                        "eth_getTransactionByHash" => transaction,
                        "eth_blockNumber" => serde_json::json!("0xa"),
                        method => panic!("unexpected EVM RPC method {method}"),
                    };
                    let body = serde_json::to_string(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": result,
                    }))
                    .unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        endpoint
    }
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before sending a complete request");
        buf.extend_from_slice(&chunk[..n]);
        if http_request_is_complete(&buf) {
            return String::from_utf8(buf).unwrap();
        }
    }
}

fn http_request_is_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
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

fn seeded_store() -> SqliteBnsRegistryStore {
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    store
        .transact(|tx| {
            tx.put_name(&NameState {
                name: "alice".to_string(),
                asset_owner: OWNER.to_string(),
                semantic_owner: Principal::unset(),
                effective_owner: Principal::chain_account(OWNER),
                owner_source: OwnerSource::AssetOwnerFallback,
                standard_transfer_enabled: true,
                status: NameStatus::Active,
                registered_at: 1,
                expire_at: 100,
                grace_until: 200,
                updated_at: 2,
                name_seq: 1,
                owner_document_version: 0,
                min_document_iat: 0,
                owner_policy_seq: 0,
                lineage_epoch: 0,
                renewable: true,
                transferable: true,
                allow_delegated_subnames: false,
                namespace_policy_hash: ZERO_HASH.to_string(),
                payment_policy_hash: ZERO_HASH.to_string(),
                alias_state_hash: ZERO_HASH.to_string(),
            })?;
            tx.put_document(&DocumentState {
                name: "alice".to_string(),
                doc_type: "owner".to_string(),
                version: 1,
                previous_version: 0,
                status: DocumentStatus::Active,
                document: DocumentRef::inline(br#"{"id":"did:bns:alice"}"#),
                controller: Principal::unset(),
                beneficiary: Principal::unset(),
                payment_target: String::new(),
                valid_from: 0,
                expire_at: 0,
                revoked_at: 0,
                controller_policy_hash: ZERO_HASH.to_string(),
                payment_policy_hash: ZERO_HASH.to_string(),
                split_policy_hash: ZERO_HASH.to_string(),
                price_policy_hash: ZERO_HASH.to_string(),
                rights_policy_hash: ZERO_HASH.to_string(),
                document_state_hash: ZERO_HASH.to_string(),
            })?;
            Ok(())
        })
        .unwrap();
    store
}

// ---- 写路径：tx.submit_raw 转发 eth_sendRawTransaction ----

#[tokio::test]
async fn submit_raw_tx_forwards_exact_bytes_and_returns_hash() {
    let mock = MockEthRpc::start().await;
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        &mock.endpoint,
    );

    let raw_hex = "0x02f86a8205";
    let resp = handler
        .submit_raw_tx(BnsSubmitRawTxReq::from_hex(raw_hex))
        .await
        .unwrap();

    assert_eq!(resp.tx_hash, TX_HASH);
    // server 转发的 raw 字节必须与提交的一致（不增删/不重新编码）。
    let received = mock.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].to_lowercase(), raw_hex.to_lowercase());
}

#[tokio::test]
async fn submit_raw_tx_does_not_parse_or_authenticate_payload() {
    // 不解释 payload / 不鉴权：一段不是合法签名 TX 的"垃圾"字节，server 仍原样转发；
    // 拒绝应发生在链上（mock 这里代表链，简单回 hash）。
    let mock = MockEthRpc::start().await;
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        &mock.endpoint,
    );

    let garbage = "0xdeadbeefcafe";
    let resp = handler
        .submit_raw_tx(BnsSubmitRawTxReq::from_hex(garbage))
        .await
        .unwrap();

    assert_eq!(resp.tx_hash, TX_HASH);
    assert_eq!(mock.received()[0].to_lowercase(), garbage.to_lowercase());
}

#[tokio::test]
async fn submit_raw_tx_rejects_invalid_hex() {
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        "http://127.0.0.1:1",
    );
    // 非 hex 输入：在到达 eth RPC 前就报错（不会触达 127.0.0.1:1）。
    let err = handler
        .submit_raw_tx(BnsSubmitRawTxReq::from_hex("0xnothex"))
        .await
        .unwrap_err();
    assert!(
        !err.code().is_empty(),
        "invalid hex must yield a structured error"
    );
}

#[tokio::test]
async fn submit_raw_tx_rejects_empty() {
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        "http://127.0.0.1:1",
    );
    let err = handler
        .submit_raw_tx(BnsSubmitRawTxReq::from_hex(""))
        .await
        .unwrap_err();
    assert!(!err.code().is_empty());
}

#[tokio::test]
async fn legacy_write_methods_are_not_routed_by_rpc() {
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        "http://127.0.0.1:1",
    );
    let rpc = BnsContractServerRpcHandler::new(handler);
    for method in ["name.register", "document.publish", "controller.set_policy"] {
        let req = RPCRequest::new(method, serde_json::json!({}));
        let err = rpc
            .handle_rpc_call(req, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(err, RPCErrors::UnknownMethod(m) if m == method),
            "method {method} should be unknown"
        );
    }
}

// ---- 读路径 + envelope 包装 ----

#[tokio::test]
async fn read_path_query_name_state_wraps_in_success_envelope() {
    let handler = BnsContractServerHandler::new(seeded_store(), "http://127.0.0.1:1");
    let rpc = BnsContractServerRpcHandler::new(handler);
    let req = RPCRequest::new(
        METHOD_QUERY_NAME_STATE,
        serde_json::to_value(BnsNameReq::new("alice")).unwrap(),
    );
    let resp = rpc
        .handle_rpc_call(req, "127.0.0.1".parse().unwrap())
        .await
        .unwrap();
    let value = match resp.result {
        RPCResult::Success(value) => value,
        RPCResult::Failed(error) => panic!("unexpected rpc failure: {error}"),
    };
    let envelope: BnsRpcEnvelope<Option<NameState>> = serde_json::from_value(value).unwrap();
    assert!(envelope.ok);
    let state = envelope.result.unwrap().unwrap();
    assert_eq!(state.name, "alice");
    assert_eq!(state.effective_owner, Principal::chain_account(OWNER));
}

#[tokio::test]
async fn read_path_resolve_document_returns_seeded_projection() {
    let handler = BnsContractServerHandler::new(seeded_store(), "http://127.0.0.1:1");
    let resolved = handler.resolve_document("alice", "owner").await.unwrap();
    assert_eq!(resolved.document_state.version, 1);
    assert_eq!(
        resolved.owner.effective_owner,
        Principal::chain_account(OWNER)
    );
}

#[tokio::test]
async fn query_names_by_address_uses_asset_owner_index() {
    let handler = BnsContractServerHandler::new(seeded_store(), "http://127.0.0.1:1");
    let page = handler
        .query_names_by_address(OWNER, None, 100)
        .await
        .unwrap();
    assert_eq!(page.names, ["alice"]);
    assert_eq!(page.next_cursor, None);
}

#[tokio::test]
async fn query_tx_state_reports_receipt_pending_and_not_found_states() {
    let succeeded_rpc = MockTxStateRpc::start(
        serde_json::json!({
            "transactionHash": TX_HASH,
            "blockNumber": "0x8",
            "status": "0x1"
        }),
        serde_json::Value::Null,
    )
    .await;
    let succeeded = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        succeeded_rpc,
    )
    .query_tx_state(TX_HASH)
    .await
    .unwrap();
    assert_eq!(succeeded.state, BnsTxExecutionState::Succeeded);
    assert_eq!(succeeded.block_number, Some(8));
    assert_eq!(succeeded.confirmations, 3);

    let reverted_rpc = MockTxStateRpc::start(
        serde_json::json!({
            "transactionHash": TX_HASH,
            "blockNumber": "0xa",
            "status": "0x0"
        }),
        serde_json::Value::Null,
    )
    .await;
    let reverted =
        BnsContractServerHandler::new(SqliteBnsRegistryStore::open_memory().unwrap(), reverted_rpc)
            .query_tx_state(TX_HASH)
            .await
            .unwrap();
    assert_eq!(reverted.state, BnsTxExecutionState::Reverted);
    assert_eq!(reverted.confirmations, 1);

    let pending_rpc = MockTxStateRpc::start(
        serde_json::Value::Null,
        serde_json::json!({"hash": TX_HASH}),
    )
    .await;
    let pending =
        BnsContractServerHandler::new(SqliteBnsRegistryStore::open_memory().unwrap(), pending_rpc)
            .query_tx_state(TX_HASH)
            .await
            .unwrap();
    assert_eq!(pending.state, BnsTxExecutionState::Pending);
    assert_eq!(pending.confirmations, 0);

    let missing_rpc = MockTxStateRpc::start(serde_json::Value::Null, serde_json::Value::Null).await;
    let missing =
        BnsContractServerHandler::new(SqliteBnsRegistryStore::open_memory().unwrap(), missing_rpc)
            .query_tx_state(TX_HASH)
            .await
            .unwrap();
    assert_eq!(missing.state, BnsTxExecutionState::NotFound);
    assert_eq!(missing.block_number, None);
}

// ---- RPC 路由：别名 + 未知 method ----

#[tokio::test]
async fn submit_raw_method_and_alias_both_route() {
    let mock = MockEthRpc::start().await;
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        &mock.endpoint,
    );
    let rpc = BnsContractServerRpcHandler::new(handler);

    for method in [METHOD_SUBMIT_RAW_TX, "submit_raw_tx"] {
        let req = RPCRequest::new(
            method,
            serde_json::to_value(BnsSubmitRawTxReq::from_hex("0x02aa")).unwrap(),
        );
        let resp = rpc
            .handle_rpc_call(req, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let value = match resp.result {
            RPCResult::Success(value) => value,
            RPCResult::Failed(error) => panic!("unexpected failure for {method}: {error}"),
        };
        let envelope: BnsRpcEnvelope<bns_client::BnsSubmitRawTxResp> =
            serde_json::from_value(value).unwrap();
        assert!(envelope.ok, "method {method} should succeed");
        assert_eq!(envelope.result.unwrap().tx_hash, TX_HASH);
    }
    assert_eq!(mock.received().len(), 2);
}

#[tokio::test]
async fn unknown_method_returns_unknown_method_error() {
    let handler = BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
        "http://127.0.0.1:1",
    );
    let rpc = BnsContractServerRpcHandler::new(handler);
    let req = RPCRequest::new("does.not.exist", serde_json::json!({}));
    let err = rpc
        .handle_rpc_call(req, "127.0.0.1".parse().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RPCErrors::UnknownMethod(m) if m == "does.not.exist"));
}
