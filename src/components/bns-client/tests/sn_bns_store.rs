//! §2.4 幂等元数据：`SnBnsWriteRequestStore` 对 `evm_chain_id`/`evm_nonce`/`evm_tx_hash`/
//! `evm_raw_tx` 的写入与按 `request_id` 去重（同 request_id 不重复插入，而是原地 upsert）。
//!
//! 用进程内 SQLite（`:memory:`），无活节点。

use bns_client::{
    BnsWriteOperation, BnsWriteRequestState, SnBnsWriteRequestRecord, SnBnsWriteRequestStore,
    SqliteSnBnsWriteRequestStore,
};
use serde_json::json;

fn record(
    request_id: &str,
    state: BnsWriteRequestState,
    created_at: u64,
) -> SnBnsWriteRequestRecord {
    SnBnsWriteRequestRecord {
        request_id: request_id.to_string(),
        operation: BnsWriteOperation::PublishDocument,
        name: "alice".to_string(),
        doc_type: Some("dns_txt".to_string()),
        payload_hash: "0xabc".to_string(),
        state,
        result_json: None,
        error_code: None,
        error_message: None,
        evm_chain_id: None,
        evm_nonce: None,
        evm_tx_hash: None,
        evm_raw_tx: None,
        created_at,
        updated_at: created_at,
    }
}

#[test]
fn evm_metadata_round_trips_through_store() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();

    let mut rec = record("req-1", BnsWriteRequestState::Succeeded, 100);
    rec.evm_chain_id = Some(31_337);
    rec.evm_nonce = Some(7);
    rec.evm_tx_hash = Some("0xdeadbeef".to_string());
    rec.evm_raw_tx = Some("0x02f8...raw".to_string());
    rec.result_json = Some(json!({ "name_seq": 3 }));
    store.put(rec).unwrap();

    let got = store.get("req-1").unwrap().expect("record persisted");
    assert_eq!(got.evm_chain_id, Some(31_337));
    assert_eq!(got.evm_nonce, Some(7));
    assert_eq!(got.evm_tx_hash.as_deref(), Some("0xdeadbeef"));
    assert_eq!(got.evm_raw_tx.as_deref(), Some("0x02f8...raw"));
    assert_eq!(got.state, BnsWriteRequestState::Succeeded);
    assert_eq!(got.result_json, Some(json!({ "name_seq": 3 })));

    assert!(store.get("missing").unwrap().is_none());
}

#[test]
fn same_request_id_upserts_in_place_without_duplicate() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();

    // 首次：pending、无 evm 元数据、created_at=100。
    store
        .put(record("req-dup", BnsWriteRequestState::Pending, 100))
        .unwrap();

    // 同 request_id 再写：succeeded + evm 元数据、created_at/updated_at 取新值。
    let mut second = record("req-dup", BnsWriteRequestState::Succeeded, 999);
    second.updated_at = 1_000;
    second.evm_chain_id = Some(31_337);
    second.evm_nonce = Some(42);
    second.evm_tx_hash = Some("0xfeed".to_string());
    second.evm_raw_tx = Some("0x02raw".to_string());
    // 第二次 put 不应因 PRIMARY KEY 冲突而失败（ON CONFLICT(request_id) DO UPDATE）。
    store.put(second).unwrap();

    let got = store.get("req-dup").unwrap().expect("record present");
    // 状态/元数据被更新。
    assert_eq!(got.state, BnsWriteRequestState::Succeeded);
    assert_eq!(got.evm_chain_id, Some(31_337));
    assert_eq!(got.evm_nonce, Some(42));
    assert_eq!(got.evm_tx_hash.as_deref(), Some("0xfeed"));
    assert_eq!(got.updated_at, 1_000);
    // created_at 不在 ON CONFLICT 的 SET 列表里：保留首次插入值，证明是原地 upsert（同一行），
    // 而非新增第二行。
    assert_eq!(
        got.created_at, 100,
        "created_at must be preserved on upsert"
    );
}
