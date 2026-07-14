use bns_indexer::{
    BnsBlockSyncSourceConfig, BnsIndexerSyncConfig, BnsRegistryStore, IndexerCursor,
    SqliteBnsRegistryStore,
};

const CONTRACT: &str = "0x2222222222222222222222222222222222222222";

#[test]
fn sync_source_id_includes_network_chain_and_contract() {
    let mut testnet = BnsBlockSyncSourceConfig::anvil("http://127.0.0.1:8545", CONTRACT, 12);
    let mut production = testnet.clone();
    production.network = "bns-production-private".to_string();
    production.chain_id = 70_001;

    assert_eq!(
        testnet.source_id().unwrap(),
        "evm:anvil-local:31337:0x2222222222222222222222222222222222222222"
    );
    assert_ne!(
        testnet.source_id().unwrap(),
        production.source_id().unwrap()
    );

    testnet.network.clear();
    assert!(BnsIndexerSyncConfig::new(testnet).validate().is_err());
}

#[test]
fn sqlite_cursors_are_scoped_by_sync_source() {
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let first = IndexerCursor {
        source: "evm:test:31337:0x1111111111111111111111111111111111111111".to_string(),
        block_number: 10,
        block_hash: Some(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        log_index: 3,
        updated_at: 100,
    };
    let second = IndexerCursor {
        source: "evm:prod:70001:0x1111111111111111111111111111111111111111".to_string(),
        block_number: 20,
        block_hash: Some(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        log_index: 7,
        updated_at: 200,
    };

    store
        .transact(|tx| {
            tx.put_indexer_cursor(&first)?;
            tx.put_indexer_cursor(&second)?;
            Ok(())
        })
        .unwrap();

    let loaded_first = store
        .transact(|tx| tx.get_indexer_cursor(&first.source))
        .unwrap()
        .unwrap();
    let loaded_second = store
        .transact(|tx| tx.get_indexer_cursor(&second.source))
        .unwrap()
        .unwrap();

    assert_eq!(loaded_first.block_number, 10);
    assert_eq!(loaded_first.log_index, 3);
    assert_eq!(loaded_second.block_number, 20);
    assert_eq!(loaded_second.log_index, 7);
}
