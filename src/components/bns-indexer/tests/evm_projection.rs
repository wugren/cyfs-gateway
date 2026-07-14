use bns_evm::{address, Bns, BnsEvent, B256};
use bns_indexer::{
    store_event_record, BnsRegistryStore, ContractEventProjector, ProjectedContractEvent,
    SqliteBnsRegistryStore,
};

#[test]
fn projector_pairs_protocol_event_with_registry_event() {
    let mut projector = ContractEventProjector::new();
    let previous = B256::from([1u8; 32]);
    let current = B256::from([2u8; 32]);
    let event_type = B256::from([3u8; 32]);

    let first = projector
        .project_event(
            BnsEvent::ProtocolEvent(Bns::ProtocolEvent {
                seq: 42,
                eventType: event_type,
                actor: address!("1000000000000000000000000000000000000001"),
                previousLogRoot: previous,
                logRoot: current,
            }),
            1234,
        )
        .unwrap();
    assert!(matches!(first, ProjectedContractEvent::Protocol(_)));
    assert_eq!(projector.pending_protocol_len(), 1);

    let second = projector
        .project_event(
            BnsEvent::NameRegistered(Bns::NameRegistered {
                nameHash: B256::from([9u8; 32]),
                name: "alice".to_string(),
                assetOwner: address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                actor: address!("1000000000000000000000000000000000000001"),
                expireAt: 100,
                lineageEpoch: 1,
                nameSeq: 1,
            }),
            1235,
        )
        .unwrap();

    let record = match second {
        ProjectedContractEvent::Registry(record) => record,
        other => panic!("unexpected projected event: {other:?}"),
    };
    assert_eq!(record.seq, 42);
    assert_eq!(record.event_type, "name_registered");
    assert_eq!(record.previous_log_root, format!("{previous:#x}"));
    assert_eq!(record.log_root, format!("{current:#x}"));
    assert_eq!(projector.pending_protocol_len(), 0);
}

#[test]
fn projected_event_records_can_be_stored_with_chain_seq() {
    let store = SqliteBnsRegistryStore::open_memory().unwrap();
    let mut projector = ContractEventProjector::new();
    projector
        .project_event(
            BnsEvent::ProtocolEvent(Bns::ProtocolEvent {
                seq: 7,
                eventType: B256::from([3u8; 32]),
                actor: address!("1000000000000000000000000000000000000001"),
                previousLogRoot: B256::ZERO,
                logRoot: B256::from([4u8; 32]),
            }),
            1,
        )
        .unwrap();
    let projected = projector
        .project_event(
            BnsEvent::DocumentPublished(Bns::DocumentPublished {
                nameHash: B256::from([9u8; 32]),
                name: "alice".to_string(),
                docType: "dns_txt".to_string(),
                version: 3,
                actor: address!("1000000000000000000000000000000000000001"),
                contentHash: B256::from([5u8; 32]),
                documentStateHash: B256::from([6u8; 32]),
            }),
            2,
        )
        .unwrap();
    let record = match projected {
        ProjectedContractEvent::Registry(record) => record,
        other => panic!("unexpected projected event: {other:?}"),
    };

    store_event_record(&store, &record).unwrap();
    let events = store.transact(|tx| tx.list_events(1, 10)).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 7);
    assert_eq!(events[0].event_type, "document_published");
}
