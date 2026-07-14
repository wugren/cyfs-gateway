use bns_indexer::{
    controller_rule, default_document_update,
    dns_document::{self, DnsTxtRecord, DNS_TXT_DOC_TYPE},
    sha256_hex, AliasKind, AuthorityKey, AuthorityKeyUpdate, BnsRegistryError, CallAuthority,
    CentralizedBnsRegistry, DocumentRef, DocumentStatus, MutationGuard, NameStatus, OwnerSource,
    Principal, PrincipalKind, RegisterOptions, ReleaseMode, SqliteBnsRegistryStore,
    PERMISSION_PUBLISH_DOCUMENT, PERMISSION_SET_ALIAS, ZERO_HASH,
};
use ndn_lib::{FileObject, NamedObject, ObjId};

const OWNER_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OWNER_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTROLLER: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

fn registry() -> CentralizedBnsRegistry<SqliteBnsRegistryStore> {
    CentralizedBnsRegistry::new_legacy_state_machine(SqliteBnsRegistryStore::open_memory().unwrap())
}

#[test]
fn centralized_registry_default_constructor_is_read_only_projection() {
    let registry = CentralizedBnsRegistry::new(SqliteBnsRegistryStore::open_memory().unwrap());
    let err = registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap_err();

    assert_eq!(err.code(), "UNSUPPORTED_OPERATION");
}

fn guard(seq: u64) -> MutationGuard {
    MutationGuard {
        expected_name_seq: seq,
        expected_parent_name_seq: 0,
    }
}

fn child_guard(parent_seq: u64) -> MutationGuard {
    MutationGuard {
        expected_name_seq: 0,
        expected_parent_name_seq: parent_seq,
    }
}

fn chain_owner(seq: u64, account: &str) -> (CallAuthority, MutationGuard) {
    (
        CallAuthority::owner(Principal::chain_account(account), ""),
        guard(seq),
    )
}

fn bns_owner(seq: u64, name: &str, kid: &str) -> (CallAuthority, MutationGuard) {
    (
        CallAuthority::owner(Principal::bns_name(name).unwrap(), kid),
        guard(seq),
    )
}

fn key(kid_seed: &[u8]) -> AuthorityKey {
    AuthorityKey::authentication_key(sha256_hex(kid_seed), kid_seed.to_vec())
}

fn doc_update(doc_type: &str, expected_version: u64, body: &str) -> bns_indexer::DocumentUpdate {
    default_document_update(
        doc_type,
        expected_version,
        DocumentRef::inline(body.as_bytes()),
    )
    .unwrap()
}

fn payment_doc_update(
    doc_type: &str,
    expected_version: u64,
    body: &str,
    beneficiary: Principal,
    payment_target: &str,
    payment_policy_hash: &str,
) -> bns_indexer::DocumentUpdate {
    let mut update = doc_update(doc_type, expected_version, body);
    update.beneficiary = beneficiary;
    update.payment_target = payment_target.to_string();
    update.payment_policy_hash = payment_policy_hash.to_string();
    update
}

fn inline_body(result: &bns_indexer::ResolveResult) -> String {
    String::from_utf8(result.document_state.document.inline_document.clone()).unwrap()
}

#[test]
fn dns_document_helper_adds_txt_records_for_publish_document() {
    let registry = registry();
    let seq = registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    assert_eq!(seq, 1);

    let update =
        dns_document::add_txt_record(None, 600, "v=spf1 include:_spf.example.net -all").unwrap();
    assert_eq!(update.doc_type, DNS_TXT_DOC_TYPE);
    assert_eq!(update.expected_version, 0);

    let (authority, guard) = chain_owner(1, OWNER_A);
    let version = registry
        .publish_document("alice", update, authority, guard)
        .unwrap();
    assert_eq!(version, 1);

    let current = registry
        .resolve_document("alice", DNS_TXT_DOC_TYPE)
        .unwrap();
    let update = dns_document::add_txt_record(
        Some(&current.document_state),
        600,
        "google-site-verification=abc",
    )
    .unwrap();
    assert_eq!(update.expected_version, 1);

    let (authority, guard) = chain_owner(2, OWNER_A);
    let version = registry
        .publish_document("alice", update, authority, guard)
        .unwrap();
    assert_eq!(version, 2);

    let resolved = registry
        .resolve_document("alice", DNS_TXT_DOC_TYPE)
        .unwrap();
    let records = dns_document::txt_records_from_document(&resolved.document_state).unwrap();
    assert_eq!(
        records,
        vec![
            DnsTxtRecord {
                ttl: 600,
                value: "v=spf1 include:_spf.example.net -all".to_string(),
            },
            DnsTxtRecord {
                ttl: 600,
                value: "google-site-verification=abc".to_string(),
            },
        ]
    );
}

#[test]
fn root_name_uses_asset_owner_until_semantic_owner_is_set() {
    let registry = registry();
    let seq = registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    assert_eq!(seq, 1);

    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.owner_source, OwnerSource::AssetOwnerFallback);
    assert_eq!(state.effective_owner, Principal::chain_account(OWNER_A));
    assert!(state.standard_transfer_enabled);

    let seq = registry.standard_transfer_name("alice", OWNER_B).unwrap();
    assert_eq!(seq, 2);

    let alice_key = key(b"alice-key");
    registry
        .update_authority_keys(
            "alice",
            vec![AuthorityKeyUpdate {
                key: alice_key.clone(),
                active: true,
            }],
            chain_owner(2, OWNER_B).0,
            chain_owner(2, OWNER_B).1,
        )
        .unwrap();

    let seq = registry
        .set_name_owner(
            "alice",
            Principal::bns_name("alice").unwrap(),
            chain_owner(2, OWNER_B).0,
            chain_owner(2, OWNER_B).1,
        )
        .unwrap();
    assert_eq!(seq, 3);

    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.owner_source, OwnerSource::ExplicitSemanticOwner);
    assert_eq!(state.effective_owner, Principal::bns_name("alice").unwrap());
    assert!(!state.standard_transfer_enabled);
    assert!(matches!(
        registry.standard_transfer_name("alice", OWNER_A),
        Err(BnsRegistryError::StandardTransferDisabled { .. })
    ));

    let update = doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#);
    assert!(matches!(
        registry.publish_document(
            "alice",
            update.clone(),
            chain_owner(3, OWNER_B).0,
            chain_owner(3, OWNER_B).1,
        ),
        Err(BnsRegistryError::NotEffectiveOwner { .. })
    ));

    let version = registry
        .publish_document(
            "alice",
            update,
            bns_owner(3, "alice", &alice_key.kid).0,
            bns_owner(3, "alice", &alice_key.kid).1,
        )
        .unwrap();
    assert_eq!(version, 1);
}

#[test]
fn controller_policy_scopes_document_operations() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    registry
        .publish_document(
            "alice",
            doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();

    let service_rule = controller_rule(
        Principal::chain_account(CONTROLLER),
        "service",
        PERMISSION_PUBLISH_DOCUMENT,
    );
    let alias_rule = controller_rule(
        Principal::chain_account(CONTROLLER),
        "",
        PERMISSION_SET_ALIAS,
    );
    registry
        .set_controller_policy(
            "alice",
            vec![service_rule, alias_rule],
            ZERO_HASH,
            chain_owner(2, OWNER_A).0,
            chain_owner(2, OWNER_A).1,
        )
        .unwrap();

    let version = registry
        .publish_document(
            "alice",
            doc_update("service", 0, r#"{"service":[]}"#),
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(3),
        )
        .unwrap();
    assert_eq!(version, 1);

    assert!(matches!(
        registry.revoke_document(
            "alice",
            "owner",
            1,
            ZERO_HASH,
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(4),
        ),
        Err(BnsRegistryError::ControllerScopeDenied { .. })
    ));

    let seq = registry
        .set_did_alias(
            "alice",
            "did:bns:alice2",
            AliasKind::Alias,
            ZERO_HASH,
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(4),
        )
        .unwrap();
    assert_eq!(seq, 5);
}

#[test]
fn revoke_current_document_keeps_current_pointer_revoked() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .publish_document(
            "alice",
            doc_update("owner", 0, r#"{"version":1}"#),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();
    registry
        .publish_document(
            "alice",
            doc_update("owner", 1, r#"{"version":2}"#),
            chain_owner(2, OWNER_A).0,
            chain_owner(2, OWNER_A).1,
        )
        .unwrap();

    registry
        .revoke_document(
            "alice",
            "owner",
            2,
            ZERO_HASH,
            chain_owner(3, OWNER_A).0,
            chain_owner(3, OWNER_A).1,
        )
        .unwrap();

    let resolved = registry.resolve_document("alice", "owner").unwrap();
    assert_eq!(resolved.document_state.version, 3);
    assert_eq!(
        registry
            .get_document_version("alice", "owner", 2)
            .unwrap()
            .unwrap()
            .status,
        DocumentStatus::Active
    );
    assert_eq!(resolved.status, DocumentStatus::Revoked);
}

#[test]
fn resolve_document_rejects_inconsistent_owner_assertion() {
    let registry = registry();
    let body = format!(r#"{{"owner":"{}"}}"#, OWNER_B);
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, &body)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let err = registry.resolve_document("alice", "owner").unwrap_err();
    assert_eq!(err.code(), "DOCUMENT_INCONSISTENT");
    match err {
        BnsRegistryError::DocumentInconsistent {
            name,
            doc_type,
            reason,
        } => {
            assert_eq!(name, "alice");
            assert_eq!(doc_type, "owner");
            assert!(reason.contains("owner document declares owner"));
            assert!(reason.contains(OWNER_B));
            assert!(reason.contains(OWNER_A));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn document_consistency_is_checked_against_current_owner() {
    let registry = registry();
    let body = format!(r#"{{"owner":"{}"}}"#, OWNER_A);
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, &body)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    assert_eq!(
        registry
            .resolve_did("did:bns:alice", "owner")
            .unwrap()
            .document_state
            .version,
        1
    );

    registry.standard_transfer_name("alice", OWNER_B).unwrap();

    assert!(matches!(
        registry.resolve_document("alice", "owner"),
        Err(BnsRegistryError::DocumentInconsistent { .. })
    ));
    assert!(matches!(
        registry.resolve_did("did:bns:alice", "owner"),
        Err(BnsRegistryError::DocumentInconsistent { .. })
    ));
    assert!(matches!(
        registry.get_document_version("alice", "owner", 1),
        Err(BnsRegistryError::DocumentInconsistent { .. })
    ));
    assert!(matches!(
        registry.get_purchase_context("alice", "owner"),
        Err(BnsRegistryError::DocumentInconsistent { .. })
    ));
}

#[test]
fn semantic_owner_requires_active_authority_set() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "bob",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    assert!(matches!(
        registry.set_name_owner(
            "bob",
            Principal::bns_name("alice").unwrap(),
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        ),
        Err(BnsRegistryError::NoConcreteSigner)
    ));
}

#[test]
fn released_and_tombstoned_names_reject_state_writes() {
    let registry = registry();

    for (name, mode, expected_status) in [
        (
            "released",
            ReleaseMode::ReleaseAfterGrace,
            NameStatus::Released,
        ),
        (
            "tombstoned",
            ReleaseMode::TombstoneForever,
            NameStatus::Tombstoned,
        ),
    ] {
        registry
            .register_name(
                name,
                OWNER_A,
                RegisterOptions::default(),
                vec![doc_update("owner", 0, r#"{"id":"did:bns:inactive"}"#)],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();
        registry
            .release_name(name, mode, ZERO_HASH, chain_owner(1, OWNER_A).0, guard(1))
            .unwrap();

        let state = registry.query_name_state(name).unwrap().unwrap();
        assert_eq!(state.status, expected_status);

        assert!(matches!(
            registry.publish_document(
                name,
                doc_update("owner", 1, r#"{"id":"did:bns:inactive-v2"}"#),
                chain_owner(2, OWNER_A).0,
                guard(2),
            ),
            Err(BnsRegistryError::InvalidMutation(_))
        ));
        assert!(matches!(
            registry.transfer_name(
                name,
                OWNER_B,
                Principal::unset(),
                vec![],
                chain_owner(2, OWNER_A).0,
                guard(2),
            ),
            Err(BnsRegistryError::InvalidMutation(_))
        ));
        assert!(matches!(
            registry.set_did_alias(
                name,
                "did:bns:canonical",
                AliasKind::Alias,
                ZERO_HASH,
                chain_owner(2, OWNER_A).0,
                guard(2),
            ),
            Err(BnsRegistryError::InvalidMutation(_))
        ));
        assert!(matches!(
            registry.revoke_document(
                name,
                "owner",
                1,
                ZERO_HASH,
                chain_owner(2, OWNER_A).0,
                guard(2),
            ),
            Err(BnsRegistryError::InvalidMutation(_))
        ));
        assert!(matches!(
            registry.renew_name(name, 60),
            Err(BnsRegistryError::InvalidMutation(_))
        ));
    }
}

#[test]
fn release_name_rejects_breaking_active_semantic_owner_graph() {
    let registry = registry();
    registry
        .register_name(
            "org",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let org_key = key(b"org-key");
    registry
        .update_authority_keys(
            "org",
            vec![AuthorityKeyUpdate {
                key: org_key,
                active: true,
            }],
            chain_owner(1, OWNER_A).0,
            guard(1),
        )
        .unwrap();
    registry
        .register_name(
            "alice",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .set_name_owner(
            "alice",
            Principal::bns_name("org").unwrap(),
            chain_owner(1, OWNER_B).0,
            guard(1),
        )
        .unwrap();

    assert!(matches!(
        registry.release_name(
            "org",
            ReleaseMode::ReleaseAfterGrace,
            ZERO_HASH,
            chain_owner(1, OWNER_A).0,
            guard(1),
        ),
        Err(BnsRegistryError::NoConcreteSigner)
    ));
    assert_eq!(
        registry.query_name_state("org").unwrap().unwrap().status,
        NameStatus::Active
    );
    assert_eq!(
        registry.resolve_owner("alice").unwrap().effective_owner,
        Principal::bns_name("org").unwrap()
    );
}

#[test]
fn semantic_owner_graph_rejects_cross_name_cycle() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "bob",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let alice_key = key(b"alice-key");
    let bob_key = key(b"bob-key");
    registry
        .update_authority_keys(
            "alice",
            vec![AuthorityKeyUpdate {
                key: alice_key,
                active: true,
            }],
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();
    registry
        .update_authority_keys(
            "bob",
            vec![AuthorityKeyUpdate {
                key: bob_key,
                active: true,
            }],
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        )
        .unwrap();

    registry
        .set_name_owner(
            "alice",
            Principal::bns_name("bob").unwrap(),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();

    assert!(matches!(
        registry.set_name_owner(
            "bob",
            Principal::bns_name("alice").unwrap(),
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        ),
        Err(BnsRegistryError::OwnerGraphCycle)
    ));
}

#[test]
fn checkpoint_covers_published_log_prefix() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let checkpoint = registry
        .publish_log_checkpoint(Principal::chain_account(OWNER_A), ZERO_HASH)
        .unwrap();
    assert_eq!(checkpoint.last_seq, 1);
    assert_ne!(checkpoint.log_root, ZERO_HASH);

    let events = registry.list_events(1, 10).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_type, "log_checkpoint_published");
    assert_eq!(
        registry.latest_checkpoint().unwrap().unwrap().last_seq,
        checkpoint.last_seq
    );
}

#[test]
fn sqlite_backend_persists_registry_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bns.sqlite3");
    {
        let registry = CentralizedBnsRegistry::new_legacy_state_machine(
            SqliteBnsRegistryStore::open(&path).unwrap(),
        );
        registry
            .register_name(
                "alice",
                OWNER_A,
                RegisterOptions::default(),
                vec![doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#)],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();
    }

    let registry = CentralizedBnsRegistry::new(SqliteBnsRegistryStore::open(&path).unwrap());
    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.effective_owner.kind, PrincipalKind::ChainAccount);
    assert_eq!(
        registry
            .resolve_document("alice", "owner")
            .unwrap()
            .document_state
            .version,
        1
    );
}

#[test]
fn did_and_doc_type_resolve_distinct_zone_device_agent_and_app_documents() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![
                doc_update(
                    "owner",
                    0,
                    r#"{"id":"did:bns:alice","default_zone_did":"did:bns:alice"}"#,
                ),
                doc_update("boot", 0, r#"{"id":"did:bns:alice","oods":["ood1.alice"]}"#),
                doc_update(
                    "zone",
                    0,
                    r#"{"id":"did:bns:alice","verify_hub_info":{"public_key":"vh-pk"}}"#,
                ),
            ],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    registry
        .register_name(
            "ood1.alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![
                doc_update(
                    "doc",
                    0,
                    r#"{"id":"did:dev:gateway-pkx","owner":"did:bns:alice","zone_did":"did:bns:alice","rtcp_port":5314}"#,
                ),
                doc_update(
                    "info",
                    0,
                    r#"{"id":"did:dev:gateway-pkx","all_ip":["10.0.0.2"],"status":"online"}"#,
                ),
            ],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    registry
        .register_name(
            "jarvis.alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update(
                "agent",
                0,
                r#"{"id":"did:bns:jarvis.alice","owner":"did:bns:alice","message_endpoint":"/agent/msg"}"#,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    registry
        .register_name(
            "buckyos",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "filebrowser.buckyos",
            OWNER_B,
            RegisterOptions::default(),
            vec![doc_update(
                "app",
                0,
                r#"{"id":"did:bns:filebrowser.buckyos","package":"obj:filebrowser-v1"}"#,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_B), ""),
            child_guard(1),
        )
        .unwrap();

    let boot = registry.resolve_did("did:bns:alice", "boot").unwrap();
    let zone = registry.resolve_did("did:bns:alice", "zone").unwrap();
    assert_eq!(boot.document_state.doc_type, "boot");
    assert_eq!(zone.document_state.doc_type, "zone");
    assert_ne!(
        boot.document_state.document.content_hash,
        zone.document_state.document.content_hash
    );

    let device_doc = registry.resolve_did("did:bns:ood1.alice", "doc").unwrap();
    let device_info = registry.resolve_did("did:bns:ood1.alice", "info").unwrap();
    assert!(inline_body(&device_doc).contains(r#""rtcp_port":5314"#));
    assert!(inline_body(&device_info).contains(r#""status":"online""#));

    let agent = registry
        .resolve_did("did:bns:jarvis.alice", "agent")
        .unwrap();
    assert!(inline_body(&agent).contains(r#""message_endpoint":"/agent/msg""#));

    let app = registry
        .resolve_did("did:bns:filebrowser.buckyos", "app")
        .unwrap();
    assert!(inline_body(&app).contains(r#""package":"obj:filebrowser-v1""#));

    let missing = registry.resolve_did("did:bns:ood1.alice", "zone").unwrap();
    assert_eq!(missing.status, DocumentStatus::Missing);
    assert_eq!(missing.document_state.version, 0);
}

#[test]
fn content_name_transfer_updates_current_rights_without_rewriting_history() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let payment_v1 = sha256_hex(b"alice-payment-policy");
    registry
        .register_name(
            "book1.alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![payment_doc_update(
                "content",
                0,
                r#"{"id":"did:bns:book1.alice","owner":"did:bns:alice","current_content_id":"obj:v1"}"#,
                Principal::bns_name("alice").unwrap(),
                "wallet:alice",
                &payment_v1,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    registry
        .register_name(
            "publisher-team",
            OWNER_B,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, r#"{"id":"did:bns:publisher-team"}"#)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let publisher_key = key(b"publisher-team-key");
    registry
        .update_authority_keys(
            "publisher-team",
            vec![AuthorityKeyUpdate {
                key: publisher_key.clone(),
                active: true,
            }],
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        )
        .unwrap();

    let payment_v2 = sha256_hex(b"publisher-payment-policy");
    let seq = registry
        .transfer_name(
            "book1.alice",
            OWNER_B,
            Principal::bns_name("publisher-team").unwrap(),
            vec![payment_doc_update(
                "content",
                1,
                r#"{"id":"did:bns:book1.alice","owner":"did:bns:publisher-team","current_content_id":"obj:v2"}"#,
                Principal::bns_name("publisher-team").unwrap(),
                "wallet:publisher-team",
                &payment_v2,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            guard(1),
        )
        .unwrap();
    assert_eq!(seq, 2);

    let current = registry
        .resolve_did("did:bns:book1.alice", "content")
        .unwrap();
    assert_eq!(current.document_state.version, 2);
    assert_eq!(
        current.owner.effective_owner,
        Principal::bns_name("publisher-team").unwrap()
    );
    assert_eq!(current.owner.source, OwnerSource::ExplicitSemanticOwner);
    assert!(inline_body(&current).contains(r#""current_content_id":"obj:v2""#));

    let purchase = registry
        .get_purchase_context("book1.alice", "content")
        .unwrap();
    assert_eq!(purchase.document_version, 2);
    assert_eq!(
        purchase.beneficiary,
        Principal::bns_name("publisher-team").unwrap()
    );
    assert_eq!(purchase.payment_target, "wallet:publisher-team");

    let before_transfer = registry
        .resolve_payment_target("book1.alice", "content", 1)
        .unwrap();
    assert_eq!(
        before_transfer.beneficiary,
        Principal::bns_name("alice").unwrap()
    );
    assert_eq!(before_transfer.payment_target, "wallet:alice");
    assert_eq!(before_transfer.payment_policy_hash, payment_v1);

    let after_transfer = registry
        .resolve_payment_target("book1.alice", "content", 2)
        .unwrap();
    assert_eq!(
        after_transfer.beneficiary,
        Principal::bns_name("publisher-team").unwrap()
    );
    assert_eq!(after_transfer.payment_policy_hash, payment_v2);

    let historical_doc = registry
        .get_document_version("book1.alice", "content", 1)
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(historical_doc.document.inline_document)
        .unwrap()
        .contains(r#""current_content_id":"obj:v1""#));
}

#[test]
fn migrated_alias_keeps_old_name_resolvable_without_silent_rewrite() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "jarvis.alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update(
                "agent",
                0,
                r#"{"id":"did:bns:jarvis.alice","profile":"old-agent"}"#,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();
    registry
        .register_name(
            "jarvis",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update(
                "agent",
                0,
                r#"{"id":"did:bns:jarvis","profile":"canonical-agent"}"#,
            )],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let proof_hash = sha256_hex(b"jarvis migration proof");
    registry
        .set_did_alias(
            "jarvis.alice",
            "did:bns:jarvis",
            AliasKind::MigratedTo,
            &proof_hash,
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            guard(1),
        )
        .unwrap();

    let old = registry
        .resolve_did("did:bns:jarvis.alice", "agent")
        .unwrap();
    assert_eq!(old.alias_kind, AliasKind::MigratedTo);
    assert_eq!(old.alias_target_did, "did:bns:jarvis");
    assert_eq!(old.document_state.name, "jarvis.alice");
    assert!(inline_body(&old).contains(r#""profile":"old-agent""#));

    let canonical = registry.resolve_did("did:bns:jarvis", "agent").unwrap();
    assert_eq!(canonical.alias_kind, AliasKind::None);
    assert_eq!(canonical.document_state.name, "jarvis");
    assert!(inline_body(&canonical).contains(r#""profile":"canonical-agent""#));

    let alias = registry.get_alias("jarvis.alice").unwrap().unwrap();
    assert_eq!(alias.kind, AliasKind::MigratedTo);
    assert_eq!(alias.proof_hash, proof_hash);
}

#[test]
fn agent_identity_and_service_capability_use_separate_document_types() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#)],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "jarvis.alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update(
                "agent",
                0,
                r#"{"id":"did:bns:jarvis.alice","public_key":"agent-key"}"#,
            )],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    let service_controller = Principal::chain_account(CONTROLLER);
    registry
        .set_controller_policy(
            "jarvis.alice",
            vec![controller_rule(
                service_controller.clone(),
                "service",
                PERMISSION_PUBLISH_DOCUMENT,
            )],
            ZERO_HASH,
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            guard(1),
        )
        .unwrap();

    let service_version = registry
        .publish_document(
            "jarvis.alice",
            doc_update(
                "service",
                0,
                r#"{"service":"agent-message","endpoint":"/agents/jarvis/msg"}"#,
            ),
            CallAuthority::controller(service_controller.clone(), ""),
            guard(2),
        )
        .unwrap();
    assert_eq!(service_version, 1);

    assert!(matches!(
        registry.publish_document(
            "jarvis.alice",
            doc_update(
                "agent",
                1,
                r#"{"id":"did:bns:jarvis.alice","public_key":"rewritten"}"#,
            ),
            CallAuthority::controller(service_controller, ""),
            guard(3),
        ),
        Err(BnsRegistryError::ControllerScopeDenied { .. })
    ));

    let agent = registry
        .resolve_did("did:bns:jarvis.alice", "agent")
        .unwrap();
    assert_eq!(agent.document_state.version, 1);
    assert!(inline_body(&agent).contains(r#""public_key":"agent-key""#));

    let service = registry
        .resolve_did("did:bns:jarvis.alice", "service")
        .unwrap();
    assert_eq!(service.document_state.version, 1);
    assert!(inline_body(&service).contains(r#""service":"agent-message""#));
}

#[test]
fn name_labels_allow_full_two_level_name_budget() {
    let registry = registry();
    let parent = "a".repeat(126);
    let child_label = "b".repeat(126);
    let child = format!("{}.{}", child_label, parent);
    assert_eq!(child.len(), 253);

    registry
        .register_name(
            &parent,
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    registry
        .register_name(
            &child,
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, r#"{"id":"did:bns:long-name"}"#)],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    let state = registry.query_name_state(&child).unwrap().unwrap();
    assert_eq!(state.name, child);

    let too_long_label = "c".repeat(127);
    assert!(matches!(
        bns_indexer::canonical_bns_name(&too_long_label),
        Err(BnsRegistryError::InvalidName { .. })
    ));
}

#[test]
fn real_base32_named_objid_can_be_registered_as_second_level_name() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let content_id =
        ObjId::new("sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
    let file = FileObject::new("readme.txt".to_string(), 32, content_id.to_string());
    let (file_obj_id, _) = file.gen_obj_id();
    let label = file_obj_id.to_base32();
    assert_eq!(file_obj_id.obj_type, "cyfile");
    assert_eq!(label.len(), 63);
    assert!(label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));

    let name = format!("{}.alice", label);
    let doc = format!(r#"{{"id":"did:bns:{}"}}"#, name);
    registry
        .register_name(
            &name,
            OWNER_A,
            RegisterOptions::default(),
            vec![doc_update("owner", 0, &doc)],
            CallAuthority::owner(Principal::chain_account(OWNER_A), ""),
            child_guard(1),
        )
        .unwrap();

    let did = format!("did:bns:{}", name);
    let resolved = registry.resolve_did(&did, "owner").unwrap();
    assert_eq!(resolved.document_state.name, name);
    assert!(inline_body(&resolved).contains(&did));
}

#[test]
fn query_names_by_address_is_stable_and_paginated_by_asset_owner() {
    let registry = registry();
    for (name, owner) in [
        ("charlie", OWNER_A),
        ("alice", OWNER_A),
        ("bob", OWNER_A),
        ("other", OWNER_B),
    ] {
        registry
            .register_name(
                name,
                owner,
                RegisterOptions::default(),
                vec![],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();
    }

    let first = registry.query_names_by_address(OWNER_A, None, 2).unwrap();
    assert_eq!(first.names, ["alice", "bob"]);
    assert_eq!(first.next_cursor.as_deref(), Some("bob"));

    let second = registry
        .query_names_by_address(OWNER_A, first.next_cursor.as_deref(), 2)
        .unwrap();
    assert_eq!(second.names, ["charlie"]);
    assert_eq!(second.next_cursor, None);

    let other = registry.query_names_by_address(OWNER_B, None, 10).unwrap();
    assert_eq!(other.names, ["other"]);

    assert_eq!(
        registry
            .query_names_by_address("not-an-address", None, 10)
            .unwrap_err()
            .code(),
        "INVALID_ADDRESS"
    );
    assert_eq!(
        registry
            .query_names_by_address(OWNER_A, None, 0)
            .unwrap_err()
            .code(),
        "INVALID_LIMIT"
    );
}
