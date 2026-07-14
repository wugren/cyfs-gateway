//! §2.2 BNS Rust 组件独立测试 —— `bns-indexer` 同步器（`sync_once`）+ 混合投影策略。
//!
//! 覆盖测试计划 doc/SN/SN-测试计划.md §2.2 中需要 mock JSON-RPC 的项：
//! - chain_id 校验：链上 chainId 与配置不符 → 拒绝同步。
//! - confirmations 回退：太新的块（未达 confirmations）不被同步。
//! - max_block_span 分片：大区间被切成多次 `eth_getLogs`，游标按 span 推进。
//! - 游标推进 + 幂等：重复调用不重投影已处理日志。
//! - 混合投影：事件定位 name/doc，随后 `eth_call` 拉权威态写投影（投影=最新快照）。
//! - source 隔离 / 合约重部署：换合约地址即换 source，新游标从 start_block。
//! - 原子落库：事件+投影同一 `transact`，中途失败整批回滚。
//!
//! 全部用进程内 mock JSON-RPC HTTP 服务，无需活节点。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_sol_types::{SolCall, SolEvent};
use bns_evm::{address, Address, Bns, B256};
use bns_indexer::{
    sync_bns_contract_once, BnsBlockSyncSourceConfig, BnsContractEventIndexer,
    BnsIndexerSyncConfig, BnsRegistryError, BnsRegistryStore, DocumentStatus, NameStatus,
    SqliteBnsRegistryStore,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CONTRACT: &str = "0x2222222222222222222222222222222222222222";
const ACTOR: Address = address!("1000000000000000000000000000000000000001");
const OWNER: Address = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

// ===== Mock JSON-RPC 服务 =====

#[derive(Default, Clone)]
struct MockConfig {
    chain_id: u64,
    block_number: u64,
    logs_json: Vec<serde_json::Value>,
    // selector(hex, no 0x) -> eth_call 返回 hex（含 0x）。
    eth_call_returns: HashMap<String, String>,
    // tx hash(lowercase, 含 0x) -> input calldata hex（含 0x），供 decode_bns_call 补全入参。
    txs: HashMap<String, String>,
    // block number -> block hash（含 0x），用于游标 reorg 检测。
    block_hashes: HashMap<u64, String>,
}

struct MockEthRpc {
    endpoint: String,
    config: Arc<Mutex<MockConfig>>,
    get_logs_calls: Arc<Mutex<u64>>,
}

impl MockEthRpc {
    async fn start(config: MockConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let config = Arc::new(Mutex::new(config));
        let get_logs_calls = Arc::new(Mutex::new(0u64));
        let cfg = config.clone();
        let calls = get_logs_calls.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let cfg = cfg.clone();
                let calls = calls.clone();
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    let body = request
                        .split_once("\r\n\r\n")
                        .map(|(_, b)| b.to_string())
                        .unwrap_or_default();
                    let req: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let id = req["id"].clone();
                    let method = req["method"].as_str().unwrap_or("");
                    let result = handle_method(method, &req, &cfg, &calls);
                    let payload = serde_json::json!({"jsonrpc":"2.0","id":id,"result":result});
                    let body = serde_json::to_string(&payload).unwrap();
                    // 每个连接只服务一次请求即关闭；用 `Connection: close` 显式告知客户端
                    // 不要复用该 keep-alive 连接，避免在已关闭 socket 上发请求的竞态。
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            endpoint,
            config,
            get_logs_calls,
        }
    }

    fn update(&self, op: impl FnOnce(&mut MockConfig)) {
        op(&mut self.config.lock().unwrap());
    }

    fn get_logs_calls(&self) -> u64 {
        *self.get_logs_calls.lock().unwrap()
    }
}

fn handle_method(
    method: &str,
    req: &serde_json::Value,
    cfg: &Arc<Mutex<MockConfig>>,
    calls: &Arc<Mutex<u64>>,
) -> serde_json::Value {
    let cfg = cfg.lock().unwrap();
    match method {
        "eth_chainId" => serde_json::Value::String(format!("0x{:x}", cfg.chain_id)),
        "eth_blockNumber" => serde_json::Value::String(format!("0x{:x}", cfg.block_number)),
        "eth_getLogs" => {
            *calls.lock().unwrap() += 1;
            serde_json::Value::Array(cfg.logs_json.clone())
        }
        "eth_getBlockByNumber" => {
            let block_number =
                parse_rpc_quantity(req["params"][0].as_str().unwrap_or("0x0")).unwrap();
            serde_json::json!({
                "number": format!("0x{block_number:x}"),
                "hash": cfg
                    .block_hashes
                    .get(&block_number)
                    .cloned()
                    .unwrap_or_else(|| block_hash_hex(block_number)),
                "parentHash": block_hash_hex(block_number.saturating_sub(1)),
            })
        }
        "eth_getTransactionByHash" => {
            let hash = req["params"][0].as_str().unwrap_or("").to_lowercase();
            match cfg.txs.get(&hash) {
                Some(input) => serde_json::json!({ "hash": hash, "input": input }),
                None => serde_json::Value::Null,
            }
        }
        "eth_call" => {
            let data = req["params"][0]["data"].as_str().unwrap_or("");
            let selector = data.trim_start_matches("0x").get(0..8).unwrap_or("");
            cfg.eth_call_returns
                .get(selector)
                .cloned()
                .map(serde_json::Value::String)
                .unwrap_or_else(|| serde_json::Value::String("0x".to_string()))
        }
        _ => serde_json::Value::Null,
    }
}

fn parse_rpc_quantity(value: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
}

fn block_hash_hex(block_number: u64) -> String {
    format!("0x{:064x}", block_number + 1)
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

// ===== 构造 mock 日志/返回值的辅助 =====

fn selector_hex<C: SolCall>() -> String {
    hex::encode(C::SELECTOR)
}

/// 把 ASCII 标签左对齐打包成 bytes32（合约里 storageType 这类短标签的编码方式）。
fn bytes32_label(label: &str) -> B256 {
    let mut out = [0u8; 32];
    let bytes = label.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    B256::from(out)
}

/// 把一个 BNS 事件结构编码为 eth_getLogs 返回的 JSON log 对象（topics + data）。
fn event_log_json<E: SolEvent>(event: &E, block_number: u64) -> serde_json::Value {
    let log_data = event.encode_log_data();
    let topics: Vec<String> = log_data
        .topics()
        .iter()
        .map(|t| format!("{t:#x}"))
        .collect();
    serde_json::json!({
        "address": format!("{CONTRACT}"),
        "topics": topics,
        "data": format!("0x{}", hex::encode(log_data.data.as_ref())),
        "blockNumber": format!("0x{block_number:x}"),
        "removed": false,
    })
}

/// 同 event_log_json，但带 transactionHash，使 indexer 触发 eth_getTransactionByHash + decode_bns_call。
fn event_log_json_with_tx<E: SolEvent>(
    event: &E,
    block_number: u64,
    tx_hash: B256,
) -> serde_json::Value {
    let mut log = event_log_json(event, block_number);
    log["transactionHash"] = serde_json::Value::String(format!("{tx_hash:#x}"));
    log
}

fn evm_name_state(name: &str, seq: u64) -> bns_evm::NameState {
    bns_evm::NameState {
        name: name.to_string(),
        assetOwner: OWNER,
        semanticOwner: bns_evm::Principal {
            kind: bns_evm::PrincipalKind::Unset,
            value: bns_evm::Bytes::new(),
        },
        effectiveOwner: bns_evm::Principal {
            kind: bns_evm::PrincipalKind::ChainAccount,
            value: bns_evm::Bytes::copy_from_slice(OWNER.as_slice()),
        },
        ownerSource: bns_evm::OwnerSource::AssetOwnerFallback,
        standardTransferEnabled: true,
        status: bns_evm::NameStatus::Active,
        registeredAt: 1,
        expireAt: 1_000,
        graceUntil: 2_000,
        updatedAt: 2,
        nameSeq: seq,
        ownerDocumentVersion: 0,
        minDocumentIat: 0,
        ownerPolicySeq: 0,
        lineageEpoch: 0,
        renewable: true,
        transferable: true,
        allowDelegatedSubnames: false,
        namespacePolicyHash: B256::ZERO,
        paymentPolicyHash: B256::ZERO,
        aliasStateHash: B256::ZERO,
    }
}

fn sha256_b256(bytes: &[u8]) -> B256 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    B256::from_slice(&digest)
}

const INLINE_DOC: &[u8] = b"{\"id\":\"did:bns:alice\"}";

fn evm_document_state(name: &str, doc_type: &str, version: u64) -> bns_evm::DocumentState {
    bns_evm::DocumentState {
        name: name.to_string(),
        docType: doc_type.to_string(),
        version,
        previousVersion: version.saturating_sub(1),
        status: bns_evm::DocumentStatus::Active,
        document: bns_evm::DocumentRef {
            storageType: bytes32_label("inline"),
            uri: String::new(),
            inlineDocument: bns_evm::Bytes::from_static(INLINE_DOC),
            contentHash: sha256_b256(INLINE_DOC),
            schema: B256::ZERO,
            codec: B256::ZERO,
            extraHash: B256::ZERO,
        },
        controller: bns_evm::Principal {
            kind: bns_evm::PrincipalKind::Unset,
            value: bns_evm::Bytes::new(),
        },
        beneficiary: bns_evm::Principal {
            kind: bns_evm::PrincipalKind::Unset,
            value: bns_evm::Bytes::new(),
        },
        paymentTarget: Address::ZERO,
        validFrom: 0,
        expireAt: 0,
        revokedAt: 0,
        controllerPolicyHash: B256::ZERO,
        paymentPolicyHash: B256::ZERO,
        splitPolicyHash: B256::ZERO,
        pricePolicyHash: B256::ZERO,
        rightsPolicyHash: B256::ZERO,
        documentStateHash: B256::repeat_byte(0x33),
    }
}

fn protocol_event_log(seq: u64, log_root: u8, block_number: u64) -> serde_json::Value {
    event_log_json(
        &Bns::ProtocolEvent {
            seq,
            eventType: B256::repeat_byte(0xE1),
            actor: ACTOR,
            previousLogRoot: B256::ZERO,
            logRoot: B256::repeat_byte(log_root),
        },
        block_number,
    )
}

fn config_for_chain(chain_id: u64) -> BnsIndexerSyncConfig {
    BnsIndexerSyncConfig::new(BnsBlockSyncSourceConfig {
        network: "anvil-local".to_string(),
        chain_id,
        rpc_endpoint: String::new(), // 由 with_endpoint 替换
        contract_address: CONTRACT.to_string(),
        start_block: 0,
    })
}

fn with_endpoint(mut config: BnsIndexerSyncConfig, endpoint: &str) -> BnsIndexerSyncConfig {
    config.source.rpc_endpoint = endpoint.to_string();
    config
}

// ===== 测试 =====

#[tokio::test]
async fn sync_rejects_chain_id_mismatch() {
    // 链上 chainId=1，配置 chainId=31337 → 拒绝同步。
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 1,
        block_number: 10,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config = with_endpoint(config_for_chain(31_337), &mock.endpoint);
    let err = sync_bns_contract_once(&store, config).await.unwrap_err();
    assert!(matches!(err, BnsRegistryError::InvalidConfig(_)));
}

#[tokio::test]
async fn sync_respects_confirmations_rollback() {
    // latest=10，confirmations=5 → target=5；start_block=8 > 5 → 不同步（块未确认）。
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 10,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let mut config = config_for_chain(31_337);
    config.confirmations = 5;
    config.source.start_block = 8;
    let outcome = sync_bns_contract_once(&store, with_endpoint(config, &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(outcome.latest_block, 10);
    assert_eq!(outcome.from_block, 8);
    assert_eq!(
        outcome.to_block, None,
        "block within confirmation window must not sync"
    );
    assert_eq!(
        mock.get_logs_calls(),
        0,
        "no getLogs when nothing confirmed"
    );
    // 游标未建立。
    assert!(outcome.cursor.is_none());
}

#[tokio::test]
async fn sync_shards_large_range_by_max_block_span_and_advances_cursor() {
    // latest=25, confirmations=0, span=10, start=0：每次 sync_once 推进一个分片。
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 25,
        logs_json: Vec::new(), // 空日志，仅验证游标/分片推进
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let mut config = config_for_chain(31_337);
    config.max_block_span = 10;

    // 第 1 片：[0,9]
    let o1 = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(o1.from_block, 0);
    assert_eq!(o1.to_block, Some(9));
    assert_eq!(o1.cursor.as_ref().unwrap().block_number, 9);

    // 第 2 片：[10,19]
    let o2 = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(o2.from_block, 10);
    assert_eq!(o2.to_block, Some(19));

    // 第 3 片：[20,25]（被 target=25 截断，不足一个 span）
    let o3 = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(o3.from_block, 20);
    assert_eq!(o3.to_block, Some(25));

    assert_eq!(
        mock.get_logs_calls(),
        3,
        "large range split into 3 eth_getLogs"
    );
}

#[tokio::test]
async fn sync_is_idempotent_when_already_caught_up() {
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 5,
        logs_json: Vec::new(),
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config = config_for_chain(31_337);

    let first = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(first.to_block, Some(5));
    let calls_after_first = mock.get_logs_calls();

    // 链上没有新块 → 第二次调用 from > target，提前返回，不再 getLogs。
    let second = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(second.from_block, 6);
    assert_eq!(second.to_block, None);
    assert_eq!(
        mock.get_logs_calls(),
        calls_after_first,
        "no extra getLogs when caught up (idempotent)"
    );
    // 游标停在 5。
    let cursor = second.cursor.unwrap();
    assert_eq!(cursor.block_number, 5);
    assert_eq!(
        cursor.block_hash.as_deref(),
        Some(block_hash_hex(5).as_str())
    );
}

#[tokio::test]
async fn sync_detects_reorg_by_cursor_block_hash_and_replays_projection() {
    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::queryNameStateCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::queryNameStateCall::abi_encode_returns(
                &evm_name_state("alice", 1)
            ))
        ),
    );
    let alice_logs = vec![
        protocol_event_log(1, 0x11, 1),
        event_log_json(
            &Bns::NameRegistered {
                nameHash: B256::repeat_byte(0xA1),
                name: "alice".to_string(),
                assetOwner: OWNER,
                actor: ACTOR,
                expireAt: 1_000,
                lineageEpoch: 0,
                nameSeq: 1,
            },
            1,
        ),
    ];
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: alice_logs,
        eth_call_returns,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config = config_for_chain(31_337);

    let first = sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert!(!first.reorg_detected);
    assert_eq!(
        first.cursor.as_ref().unwrap().block_hash.as_deref(),
        Some(block_hash_hex(1).as_str())
    );
    let names = store.transact(|tx| tx.list_names()).unwrap();
    assert_eq!(
        names.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["alice"]
    );

    let mut bob_eth_call_returns = HashMap::new();
    bob_eth_call_returns.insert(
        selector_hex::<Bns::queryNameStateCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::queryNameStateCall::abi_encode_returns(
                &evm_name_state("bob", 1)
            ))
        ),
    );
    let bob_logs = vec![
        protocol_event_log(1, 0x22, 1),
        event_log_json(
            &Bns::NameRegistered {
                nameHash: B256::repeat_byte(0xB2),
                name: "bob".to_string(),
                assetOwner: OWNER,
                actor: ACTOR,
                expireAt: 1_000,
                lineageEpoch: 0,
                nameSeq: 1,
            },
            1,
        ),
    ];
    mock.update(|cfg| {
        cfg.block_hashes
            .insert(1, B256::repeat_byte(0x99).to_string());
        cfg.logs_json = bob_logs;
        cfg.eth_call_returns = bob_eth_call_returns;
    });

    let replay = sync_bns_contract_once(&store, with_endpoint(config, &mock.endpoint))
        .await
        .unwrap();
    assert!(replay.reorg_detected);
    assert_eq!(replay.from_block, 0);
    assert_eq!(replay.to_block, Some(1));
    assert_eq!(
        replay.cursor.as_ref().unwrap().block_hash.as_deref(),
        Some(B256::repeat_byte(0x99).to_string().as_str())
    );

    let (names, events) = store
        .transact(|tx| Ok((tx.list_names()?, tx.list_events(1, 10)?)))
        .unwrap();
    assert_eq!(
        names.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["bob"]
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "name_registered");
    assert_eq!(events[0].log_root, B256::repeat_byte(0x22).to_string());
}

#[tokio::test]
async fn polling_loop_runs_sync_once_repeatedly() {
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 0,
        logs_json: Vec::new(),
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let indexer = BnsContractEventIndexer::new(
        &store,
        with_endpoint(config_for_chain(31_337), &mock.endpoint),
    )
    .unwrap();
    let outcomes = Arc::new(AtomicUsize::new(0));
    let observed = outcomes.clone();

    tokio::select! {
        _ = indexer.run_polling_loop(Duration::from_millis(1), move |outcome| {
            outcome.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
        }) => panic!("polling loop should not return"),
        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
    }

    assert!(
        outcomes.load(Ordering::SeqCst) >= 2,
        "polling loop should call sync_once more than once"
    );
}

#[tokio::test]
async fn sync_projects_document_published_via_mixed_eth_call_strategy() {
    // 混合投影：DocumentPublished 事件只定位 name/doc，随后 eth_call 拉权威态写投影。
    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::queryNameStateCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::queryNameStateCall::abi_encode_returns(
                &evm_name_state("alice", 2)
            ))
        ),
    );
    eth_call_returns.insert(
        selector_hex::<Bns::getDocumentVersionCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::getDocumentVersionCall::abi_encode_returns(
                &evm_document_state("alice", "dns_txt", 3)
            ))
        ),
    );

    // 日志：ProtocolEvent（携带 seq/logRoot）+ DocumentPublished（具体事件）。
    let logs = vec![
        protocol_event_log(7, 0x44, 1),
        event_log_json(
            &Bns::DocumentPublished {
                nameHash: B256::repeat_byte(0x09),
                name: "alice".to_string(),
                docType: "dns_txt".to_string(),
                version: 3,
                actor: ACTOR,
                contentHash: B256::repeat_byte(0x22),
                documentStateHash: B256::repeat_byte(0x33),
            },
            1,
        ),
    ];

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: logs,
        eth_call_returns,
        txs: HashMap::new(),
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config = config_for_chain(31_337);

    let outcome = sync_bns_contract_once(&store, with_endpoint(config, &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(outcome.protocol_events_seen, 1);
    assert_eq!(outcome.registry_events_stored, 1);

    // 投影 = eth_call 拉回的最新快照（而非事件字段回放）。
    let (name_state, doc_state, events) = store
        .transact(|tx| {
            let name = tx.get_name("alice")?;
            let doc = tx.get_current_document("alice", "dns_txt")?;
            let events = tx.list_events(0, 10)?;
            Ok((name, doc, events))
        })
        .unwrap();

    let name_state = name_state.expect("name projected");
    assert_eq!(name_state.name, "alice");
    assert_eq!(name_state.name_seq, 2); // 来自 eth_call 的权威 nameSeq
    assert_eq!(name_state.status, NameStatus::Active);

    let doc_state = doc_state.expect("document projected");
    assert_eq!(doc_state.version, 3);
    assert_eq!(doc_state.status, DocumentStatus::Active);
    assert_eq!(
        doc_state.document.inline_document,
        b"{\"id\":\"did:bns:alice\"}"
    );

    // EventLog：ProtocolEvent 的 seq/logRoot 派生写入 bns_events。
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 7);
    assert_eq!(events[0].event_type, "document_published");
    assert_eq!(
        events[0].log_root,
        format!("{:#x}", B256::repeat_byte(0x44))
    );
}

#[tokio::test]
async fn sync_backfills_controller_rules_from_decoded_call() {
    // ControllerPolicyUpdated 事件不携带 rules：indexer 用 decode_bns_call（按 tx hash）补全入参。
    let tx_hash = B256::repeat_byte(0xCA);
    let calldata = Bns::setControllerPolicyCall {
        name: "alice".to_string(),
        rules: vec![bns_evm::ControllerRule {
            controller: bns_evm::Principal {
                kind: bns_evm::PrincipalKind::ChainAccount,
                value: bns_evm::Bytes::copy_from_slice(ACTOR.as_slice()),
            },
            docType: "device".to_string(),
            permissions: 0b0000_0011,
            namespaceScopeHash: B256::ZERO,
            validFrom: 10,
            validUntil: 20,
            constraintHash: B256::ZERO,
        }],
        policyHash: B256::repeat_byte(0x7F),
        authority: bns_evm::CallAuthority {
            role: bns_evm::AuthorityRole::Owner,
            actor: bns_evm::Principal {
                kind: bns_evm::PrincipalKind::ChainAccount,
                value: bns_evm::Bytes::copy_from_slice(OWNER.as_slice()),
            },
            kid: B256::ZERO,
        },
        guard: bns_evm::MutationGuard {
            expectedNameSeq: 0,
            expectedParentNameSeq: 0,
        },
    }
    .abi_encode();

    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::queryNameStateCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::queryNameStateCall::abi_encode_returns(
                &evm_name_state("alice", 3)
            ))
        ),
    );
    let mut txs = HashMap::new();
    txs.insert(
        format!("{tx_hash:#x}").to_lowercase(),
        format!("0x{}", hex::encode(&calldata)),
    );

    let logs = vec![
        protocol_event_log(11, 0x55, 1),
        event_log_json_with_tx(
            &Bns::ControllerPolicyUpdated {
                nameHash: B256::repeat_byte(0x09),
                name: "alice".to_string(),
                actor: ACTOR,
                policyHash: B256::repeat_byte(0x7F),
                nameSeq: 3,
            },
            1,
            tx_hash,
        ),
    ];

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: logs,
        eth_call_returns,
        txs,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let outcome = sync_bns_contract_once(
        &store,
        with_endpoint(config_for_chain(31_337), &mock.endpoint),
    )
    .await
    .unwrap();
    assert_eq!(outcome.registry_events_stored, 1);

    let rules = store
        .transact(|tx| tx.get_controller_policy("alice"))
        .unwrap();
    assert_eq!(
        rules.len(),
        1,
        "controller rule backfilled from decoded call"
    );
    assert_eq!(rules[0].doc_type, "device");
    assert_eq!(rules[0].permissions, 0b0000_0011);
    assert_eq!(rules[0].valid_from, 10);
    assert_eq!(rules[0].valid_until, 20);
}

#[tokio::test]
async fn redeploy_to_new_contract_uses_isolated_source_cursor() {
    // 合约重部署 = 换合约地址 → 换 source；旧 source 游标不串扰，新 source 从 start_block 重放。
    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 10,
        logs_json: Vec::new(),
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();

    // 旧合约推进游标到 10。
    let old_config = config_for_chain(31_337);
    let old = sync_bns_contract_once(&store, with_endpoint(old_config.clone(), &mock.endpoint))
        .await
        .unwrap();
    assert_eq!(old.to_block, Some(10));
    let old_source = old.source.clone();

    // 新合约地址（重部署）+ start_block=0。
    let mut new_config = config_for_chain(31_337);
    new_config.source.contract_address = "0x3333333333333333333333333333333333333333".to_string();
    let new = sync_bns_contract_once(&store, with_endpoint(new_config, &mock.endpoint))
        .await
        .unwrap();

    assert_ne!(new.source, old_source, "new contract => new source id");
    // 新 source 从 0 重放（不继承旧 source 的游标 10）。
    assert_eq!(new.from_block, 0);
    assert_eq!(new.to_block, Some(10));

    // 两个 source 的游标各自独立存在。
    let (old_cursor, new_cursor) = store
        .transact(|tx| {
            Ok((
                tx.get_indexer_cursor(&old_source)?,
                tx.get_indexer_cursor(&new.source)?,
            ))
        })
        .unwrap();
    assert_eq!(old_cursor.unwrap().block_number, 10);
    assert_eq!(new_cursor.unwrap().block_number, 10);
}

#[tokio::test]
async fn event_and_projection_share_atomic_transaction_rollback() {
    // 事件+投影同一 store.transact：中段失败 → 整批回滚，不残留半截状态。
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let result: Result<(), BnsRegistryError> = store.transact(|tx| {
        // 先写一条名字投影，再人为失败。
        let mut state = sample_name_state();
        tx.put_name(&state)?;
        state.name = "second".to_string();
        tx.put_name(&state)?;
        Err(BnsRegistryError::InvalidMutation(
            "injected mid-batch failure".to_string(),
        ))
    });
    assert!(result.is_err());

    // 回滚后两条 put_name 都不应落库。
    let names = store.transact(|tx| tx.list_names()).unwrap();
    assert!(names.is_empty(), "failed batch must roll back atomically");
}

#[tokio::test]
async fn sync_projects_authority_set_and_keys_via_mixed_strategy() {
    // AuthorityKeysUpdated 事件只带 authoritySeq/authorityRoot：indexer eth_call getAuthoritySet
    // 拉权威 set，并用 decode updateAuthorityKeys（按 tx hash）补全逐 key（同混合投影策略）。
    let tx_hash = B256::repeat_byte(0xAA);
    let key = bns_evm::AuthorityKey {
        kid: B256::repeat_byte(0x0A),
        verificationMethod: bytes32_label("ed25519"),
        keyData: bns_evm::Bytes::from_static(b"pubkey-bytes"),
        purposes: 0b0000_0001,
        validFrom: 0,
        validUntil: 0,
        status: bns_evm::AuthorityKeyStatus::Active,
        metadataHash: B256::ZERO,
    };
    let calldata = Bns::updateAuthorityKeysCall {
        name: "alice".to_string(),
        updates: vec![bns_evm::AuthorityKeyUpdate { key, active: true }],
        authority: bns_evm::CallAuthority {
            role: bns_evm::AuthorityRole::Owner,
            actor: bns_evm::Principal {
                kind: bns_evm::PrincipalKind::ChainAccount,
                value: bns_evm::Bytes::copy_from_slice(OWNER.as_slice()),
            },
            kid: B256::ZERO,
        },
        guard: bns_evm::MutationGuard {
            expectedNameSeq: 0,
            expectedParentNameSeq: 0,
        },
    }
    .abi_encode();

    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::getAuthoritySetCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::getAuthoritySetCall::abi_encode_returns(
                &bns_evm::AuthoritySetState {
                    name: "alice".to_string(),
                    authoritySeq: 4,
                    authorityRoot: B256::repeat_byte(0x77),
                    activeKeyCount: 1,
                }
            ))
        ),
    );
    let mut txs = HashMap::new();
    txs.insert(
        format!("{tx_hash:#x}").to_lowercase(),
        format!("0x{}", hex::encode(&calldata)),
    );

    let logs = vec![
        protocol_event_log(13, 0x66, 1),
        event_log_json_with_tx(
            &Bns::AuthorityKeysUpdated {
                nameHash: B256::repeat_byte(0x09),
                name: "alice".to_string(),
                actor: ACTOR,
                authoritySeq: 4,
                authorityRoot: B256::repeat_byte(0x77),
            },
            1,
            tx_hash,
        ),
    ];

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: logs,
        eth_call_returns,
        txs,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let outcome = sync_bns_contract_once(
        &store,
        with_endpoint(config_for_chain(31_337), &mock.endpoint),
    )
    .await
    .unwrap();
    assert_eq!(outcome.registry_events_stored, 1);

    let (set, keys) = store
        .transact(|tx| {
            Ok((
                tx.get_authority_set("alice")?,
                tx.list_authority_keys("alice")?,
            ))
        })
        .unwrap();

    // authority set 取自 eth_call getAuthoritySet 权威态。
    let set = set.expect("authority set projected");
    assert_eq!(set.authority_seq, 4);
    assert_eq!(set.active_key_count, 1);
    assert_eq!(
        set.authority_root,
        format!("{:#x}", B256::repeat_byte(0x77))
    );

    // 逐 key 经 decode_bns_call(updateAuthorityKeys) 补全（事件不带 key 明细）。
    assert_eq!(keys.len(), 1, "key backfilled from decoded call");
    assert_eq!(keys[0].kid, format!("{:#x}", B256::repeat_byte(0x0A)));
    assert_eq!(keys[0].status, bns_indexer::AuthorityKeyStatus::Active);
    assert_eq!(keys[0].key_data, b"pubkey-bytes");
    assert_eq!(keys[0].purposes, 0b0000_0001);
}

#[tokio::test]
async fn sync_backfills_authority_keys_from_apply_mutations_call() {
    let tx_hash = B256::repeat_byte(0xAB);
    let key = bns_evm::AuthorityKey {
        kid: B256::repeat_byte(0x0B),
        verificationMethod: bytes32_label("ed25519"),
        keyData: bns_evm::Bytes::from_static(b"batch-pubkey"),
        purposes: 0b0000_0011,
        validFrom: 0,
        validUntil: 0,
        status: bns_evm::AuthorityKeyStatus::Active,
        metadataHash: B256::ZERO,
    };
    let calldata = Bns::applyMutationsCall {
        name: "alice".to_string(),
        authorityUpdates: vec![bns_evm::AuthorityKeyUpdate { key, active: true }],
        documents: vec![],
        ownerPolicy: bns_evm::OwnerPolicyUpdate {
            updateMinDocumentIat: false,
            minDocumentIat: 0,
            reasonHash: B256::ZERO,
        },
        authority: bns_evm::CallAuthority {
            role: bns_evm::AuthorityRole::Owner,
            actor: bns_evm::Principal {
                kind: bns_evm::PrincipalKind::ChainAccount,
                value: bns_evm::Bytes::copy_from_slice(OWNER.as_slice()),
            },
            kid: B256::ZERO,
        },
        guard: bns_evm::MutationGuard {
            expectedNameSeq: 1,
            expectedParentNameSeq: 0,
        },
    }
    .abi_encode();

    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::getAuthoritySetCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::getAuthoritySetCall::abi_encode_returns(
                &bns_evm::AuthoritySetState {
                    name: "alice".to_string(),
                    authoritySeq: 5,
                    authorityRoot: B256::repeat_byte(0x78),
                    activeKeyCount: 1,
                }
            ))
        ),
    );
    let mut txs = HashMap::new();
    txs.insert(
        format!("{tx_hash:#x}").to_lowercase(),
        format!("0x{}", hex::encode(&calldata)),
    );

    let logs = vec![
        protocol_event_log(14, 0x67, 1),
        event_log_json_with_tx(
            &Bns::AuthorityKeysUpdated {
                nameHash: B256::repeat_byte(0x09),
                name: "alice".to_string(),
                actor: ACTOR,
                authoritySeq: 5,
                authorityRoot: B256::repeat_byte(0x78),
            },
            1,
            tx_hash,
        ),
    ];

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: logs,
        eth_call_returns,
        txs,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let outcome = sync_bns_contract_once(
        &store,
        with_endpoint(config_for_chain(31_337), &mock.endpoint),
    )
    .await
    .unwrap();
    assert_eq!(outcome.registry_events_stored, 1);

    let keys = store
        .transact(|tx| tx.list_authority_keys("alice"))
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, format!("{:#x}", B256::repeat_byte(0x0B)));
    assert_eq!(keys[0].key_data, b"batch-pubkey");
    assert_eq!(keys[0].purposes, 0b0000_0011);
}

#[tokio::test]
async fn sync_projects_did_alias_via_eth_call() {
    // DidAliasSet → push_name_state + eth_call getAlias 拉权威 alias 态写投影。
    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::queryNameStateCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::queryNameStateCall::abi_encode_returns(
                &evm_name_state("alice", 5)
            ))
        ),
    );
    eth_call_returns.insert(
        selector_hex::<Bns::getAliasCall>(),
        format!(
            "0x{}",
            hex::encode(Bns::getAliasCall::abi_encode_returns(
                &bns_evm::AliasState {
                    name: "alice".to_string(),
                    kind: bns_evm::AliasKind::Alias,
                    targetDid: "did:bns:alice".to_string(),
                    proofHash: B256::repeat_byte(0x88),
                    setAt: 42,
                    nameSeq: 5,
                }
            ))
        ),
    );

    let logs = vec![
        protocol_event_log(17, 0x77, 1),
        event_log_json(
            &Bns::DidAliasSet {
                nameHash: B256::repeat_byte(0x09),
                name: "alice".to_string(),
                actor: ACTOR,
                targetDid: "did:bns:alice".to_string(),
                kind: bns_evm::AliasKind::Alias,
                proofHash: B256::repeat_byte(0x88),
                nameSeq: 5,
            },
            1,
        ),
    ];

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: logs,
        eth_call_returns,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    sync_bns_contract_once(
        &store,
        with_endpoint(config_for_chain(31_337), &mock.endpoint),
    )
    .await
    .unwrap();

    let alias = store
        .transact(|tx| tx.get_alias("alice"))
        .unwrap()
        .expect("alias projected");
    assert_eq!(alias.kind, bns_indexer::AliasKind::Alias);
    assert_eq!(alias.target_did, "did:bns:alice");
    assert_eq!(alias.name_seq, 5);
    assert_eq!(alias.set_at, 42);
    assert_eq!(alias.proof_hash, format!("{:#x}", B256::repeat_byte(0x88)));
}

#[tokio::test]
async fn sync_projects_log_checkpoint_and_overwrites_on_last_seq_conflict() {
    // LogCheckpointPublished → eth_call latestCheckpoint → put_checkpoint。
    // 第二个 checkpoint 同 lastSeq、新 logRoot → ON CONFLICT(last_seq) 覆盖（而非新增行）。
    let issuer = bns_evm::Principal {
        kind: bns_evm::PrincipalKind::ChainAccount,
        value: bns_evm::Bytes::copy_from_slice(OWNER.as_slice()),
    };
    let checkpoint_return = |log_root: u8, last_seq: u64, issued_at: u64| {
        format!(
            "0x{}",
            hex::encode(Bns::latestCheckpointCall::abi_encode_returns(
                &bns_evm::LogCheckpoint {
                    logRoot: B256::repeat_byte(log_root),
                    lastSeq: last_seq,
                    issuedAt: issued_at,
                    issuer: issuer.clone(),
                    externalAnchor: B256::ZERO,
                }
            ))
        )
    };
    let checkpoint_log = |log_root: u8, block_number: u64, seq: u64| {
        vec![
            protocol_event_log(seq, log_root, block_number),
            event_log_json(
                &Bns::LogCheckpointPublished {
                    logRoot: B256::repeat_byte(log_root),
                    actor: ACTOR,
                    lastSeq: 9,
                    issuedAt: 100,
                    externalAnchor: B256::ZERO,
                },
                block_number,
            ),
        ]
    };

    let mut eth_call_returns = HashMap::new();
    eth_call_returns.insert(
        selector_hex::<Bns::latestCheckpointCall>(),
        checkpoint_return(0xC1, 9, 100),
    );

    let mock = MockEthRpc::start(MockConfig {
        chain_id: 31_337,
        block_number: 1,
        logs_json: checkpoint_log(0xC1, 1, 9),
        eth_call_returns,
        ..Default::default()
    })
    .await;
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let config = config_for_chain(31_337);

    sync_bns_contract_once(&store, with_endpoint(config.clone(), &mock.endpoint))
        .await
        .unwrap();
    let first = store
        .transact(|tx| tx.latest_checkpoint())
        .unwrap()
        .expect("checkpoint projected");
    assert_eq!(first.last_seq, 9);
    assert_eq!(first.issued_at, 100);
    assert_eq!(first.log_root, format!("{:#x}", B256::repeat_byte(0xC1)));

    // 第二个 checkpoint：同 lastSeq=9、新 logRoot/issuedAt → 覆盖。
    let second_return = checkpoint_return(0xC2, 9, 200);
    mock.update(|cfg| {
        cfg.block_number = 2;
        cfg.logs_json = checkpoint_log(0xC2, 2, 10);
        cfg.eth_call_returns
            .insert(selector_hex::<Bns::latestCheckpointCall>(), second_return);
    });

    sync_bns_contract_once(&store, with_endpoint(config, &mock.endpoint))
        .await
        .unwrap();
    let second = store
        .transact(|tx| tx.latest_checkpoint())
        .unwrap()
        .expect("checkpoint still present after overwrite");
    // 同 last_seq 行被 UPDATE 覆盖：log_root/issued_at 更新为第二个 checkpoint。
    assert_eq!(second.last_seq, 9);
    assert_eq!(second.issued_at, 200);
    assert_eq!(second.log_root, format!("{:#x}", B256::repeat_byte(0xC2)));
}

fn sample_name_state() -> bns_indexer::NameState {
    bns_indexer::NameState {
        name: "alice".to_string(),
        asset_owner: format!("{OWNER:#x}"),
        semantic_owner: bns_indexer::Principal::unset(),
        effective_owner: bns_indexer::Principal::chain_account(format!("{OWNER:#x}")),
        owner_source: bns_indexer::OwnerSource::AssetOwnerFallback,
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
        namespace_policy_hash: bns_indexer::ZERO_HASH.to_string(),
        payment_policy_hash: bns_indexer::ZERO_HASH.to_string(),
        alias_state_hash: bns_indexer::ZERO_HASH.to_string(),
    }
}
