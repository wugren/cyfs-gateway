use ::kRPC::{RPCErrors, RPCHandler, RPCRequest};
use async_trait::async_trait;
use bns_client::{
    publish_document_call, register_name_call, BindZoneDocumentsParams, BnsApplyMutationsReq,
    BnsClientError, BnsClientResult, BnsEvmClientConfig, BnsEvmKeyManager, BnsEvmSignRequest,
    BnsEvmStandardClient, BnsEvmTxSubmission, BnsEvmWriteOperation, BnsIndexerApi,
    BnsIndexerClient, BnsIndexerRpcHandler, BnsPublishDocumentReq, BnsRegisterNameReq,
    BnsWriteReceiptStatus, BootstrapNameParams, DnsTxtUpdate, MemorySnBnsWriteRequestStore,
    PublishDeviceMiniDocParams, PublishDocumentParams, PublishRelayAssignmentParams,
    SnBnsController, SnBnsControllerConfig, SnBnsControllerError, SnBnsEvmSubmitter,
    StaticBnsEvmKeyManager, UpsertDnsTxtParams, BOOT_DOC_TYPE, DEVICE_MINI_DOC_TYPE,
    OWNER_DOC_TYPE, RELAY_ASSIGNMENT_DOC_TYPE, ZONE_DOC_TYPE,
};
use bns_evm::{AuthorityRole as EvmAuthorityRole, PrincipalKind as EvmPrincipalKind, SolCall};
use bns_indexer::dns_document::{self, DNS_TXT_DOC_TYPE};
use bns_indexer::{
    controller_rule, default_document_update, policy_hash_from_rules, CallAuthority,
    CentralizedBnsIndexerHandler, CentralizedBnsRegistry, DocumentRef, DocumentStatus,
    MutationGuard, Principal, RegisterOptions, SqliteBnsRegistryStore, PERMISSION_PUBLISH_DOCUMENT,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SN_CONTROLLER: &str = "0xcccccccccccccccccccccccccccccccccccccccc";
const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

fn registry() -> Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>> {
    Arc::new(CentralizedBnsRegistry::new_legacy_state_machine(
        SqliteBnsRegistryStore::open_memory().unwrap(),
    ))
}

fn guard(seq: u64) -> MutationGuard {
    MutationGuard {
        expected_name_seq: seq,
        expected_parent_name_seq: 0,
    }
}

fn owner_authority() -> CallAuthority {
    CallAuthority::owner(Principal::chain_account(OWNER), "")
}

fn sn_controller_authority() -> CallAuthority {
    CallAuthority::controller(Principal::chain_account(SN_CONTROLLER), "")
}

fn in_process_client(
    registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
) -> Arc<BnsIndexerClient> {
    let handler: Arc<dyn BnsIndexerApi> = Arc::new(CentralizedBnsIndexerHandler::new(registry));
    Arc::new(BnsIndexerClient::new_in_process(handler))
}

#[derive(Default)]
struct RecordingEvmSubmitter {
    registrations: Mutex<Vec<BnsRegisterNameReq>>,
    mutations: Mutex<Vec<BnsApplyMutationsReq>>,
    published: Mutex<Vec<BnsPublishDocumentReq>>,
    next_nonce: Mutex<u64>,
}

impl RecordingEvmSubmitter {
    fn registrations(&self) -> Vec<BnsRegisterNameReq> {
        self.registrations.lock().unwrap().clone()
    }

    fn mutations(&self) -> Vec<BnsApplyMutationsReq> {
        self.mutations.lock().unwrap().clone()
    }

    fn published(&self) -> Vec<BnsPublishDocumentReq> {
        self.published.lock().unwrap().clone()
    }

    fn submission(&self) -> BnsEvmTxSubmission {
        let mut next_nonce = self.next_nonce.lock().unwrap();
        let nonce = *next_nonce;
        *next_nonce += 1;
        BnsEvmTxSubmission {
            tx_hash: format!("0x{nonce:064x}"),
            raw_tx: format!("0x{nonce:02x}"),
            from: ANVIL_ADDRESS.to_string(),
            nonce,
            chain_id: 31_337,
            receipt_status: None,
            receipt_block_number: None,
            receipt_confirmations: None,
        }
    }
}

#[async_trait]
impl SnBnsEvmSubmitter for RecordingEvmSubmitter {
    async fn register_name(&self, req: &BnsRegisterNameReq) -> BnsClientResult<BnsEvmTxSubmission> {
        self.registrations.lock().unwrap().push(req.clone());
        Ok(self.submission())
    }

    async fn apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.mutations.lock().unwrap().push(req.clone());
        Ok(self.submission())
    }

    async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.published.lock().unwrap().push(req.clone());
        Ok(self.submission())
    }
}

struct ApplyingEvmSubmitter {
    registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
    next_nonce: Mutex<u64>,
}

impl ApplyingEvmSubmitter {
    fn new(registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>) -> Self {
        Self {
            registry,
            next_nonce: Mutex::new(0),
        }
    }

    fn submission(&self) -> BnsEvmTxSubmission {
        let mut next_nonce = self.next_nonce.lock().unwrap();
        let nonce = *next_nonce;
        *next_nonce += 1;
        BnsEvmTxSubmission {
            tx_hash: format!("0x{nonce:064x}"),
            raw_tx: format!("0x{nonce:02x}"),
            from: ANVIL_ADDRESS.to_string(),
            nonce,
            chain_id: 31_337,
            receipt_status: None,
            receipt_block_number: None,
            receipt_confirmations: None,
        }
    }
}

#[async_trait]
impl SnBnsEvmSubmitter for ApplyingEvmSubmitter {
    async fn register_name(&self, req: &BnsRegisterNameReq) -> BnsClientResult<BnsEvmTxSubmission> {
        if req.authority_key_updates.is_empty()
            && req.semantic_owner_after_authority.is_none()
            && req.controller_policy.is_empty()
        {
            self.registry
                .register_name(
                    req.name.as_str(),
                    req.asset_owner.as_str(),
                    req.options.clone(),
                    req.initial_documents.clone(),
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(BnsClientError::from)?;
        } else {
            self.registry
                .bootstrap_name(
                    req.name.as_str(),
                    req.asset_owner.as_str(),
                    req.options.clone(),
                    req.initial_documents.clone(),
                    req.authority_key_updates.clone(),
                    req.semantic_owner_after_authority.clone(),
                    req.controller_policy.clone(),
                    req.controller_policy_hash.as_str(),
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(BnsClientError::from)?;
        }
        Ok(self.submission())
    }

    async fn apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.registry
            .apply_mutations(
                req.name.as_str(),
                req.authority_key_updates.clone(),
                req.documents.clone(),
                req.owner_policy.clone(),
                req.authority.clone(),
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(self.submission())
    }

    async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.registry
            .publish_document(
                req.name.as_str(),
                req.update.clone(),
                req.authority.clone(),
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(self.submission())
    }
}

fn sn_controller_with_submitter(
    registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
) -> (SnBnsController, Arc<RecordingEvmSubmitter>) {
    let submitter = Arc::new(RecordingEvmSubmitter::default());
    let controller = SnBnsController::new_with_evm_submitter(
        in_process_client(registry),
        Arc::new(MemorySnBnsWriteRequestStore::new()),
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
        submitter.clone(),
    )
    .unwrap();
    (controller, submitter)
}

fn sn_controller(registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>) -> SnBnsController {
    sn_controller_with_submitter(registry).0
}

fn sn_controller_with_applying_submitter(
    registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
) -> SnBnsController {
    let submitter = Arc::new(ApplyingEvmSubmitter::new(registry.clone()));
    SnBnsController::new_with_evm_submitter(
        in_process_client(registry),
        Arc::new(MemorySnBnsWriteRequestStore::new()),
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
        submitter,
    )
    .unwrap()
}

fn inline_update(doc_type: &str, expected_version: u64, body: &str) -> bns_indexer::DocumentUpdate {
    default_document_update(
        doc_type,
        expected_version,
        DocumentRef::inline(body.as_bytes()),
    )
    .unwrap()
}

#[test]
fn evm_register_call_encodes_chain_account_principal_as_address_bytes() {
    let req = BnsRegisterNameReq {
        name: "alice".to_string(),
        asset_owner: OWNER.to_string(),
        options: RegisterOptions::default(),
        authority_key_updates: vec![],
        semantic_owner_after_authority: None,
        controller_policy: vec![],
        controller_policy_hash: String::new(),
        initial_documents: vec![],
        authority: owner_authority(),
        guard: guard(3),
    };

    let call = register_name_call(&req).unwrap();
    assert_eq!(call.assetOwner.to_string().to_lowercase(), OWNER);
    assert!(matches!(call.authority.role, EvmAuthorityRole::Owner));
    assert!(matches!(
        call.authority.actor.kind,
        EvmPrincipalKind::ChainAccount
    ));
    assert_eq!(call.authority.actor.value.len(), 20);
    assert_eq!(call.guard.expectedNameSeq, 3);
    assert_eq!(
        call.abi_encode()[..4],
        bns_evm::Bns::registerNameCall::SELECTOR
    );
}

#[test]
fn evm_publish_call_preserves_document_ref_and_authority_boundary() {
    let update = inline_update(DNS_TXT_DOC_TYPE, 0, r#"[{"ttl":60,"value":"x"}]"#);
    let req = BnsPublishDocumentReq {
        name: "alice".to_string(),
        update,
        authority: sn_controller_authority(),
        guard: guard(1),
    };

    let call = publish_document_call(&req).unwrap();
    assert_eq!(call.docType, DNS_TXT_DOC_TYPE);
    assert_eq!(call.document.storageType.as_slice()[..6], *b"inline");
    assert!(!call.document.inlineDocument.is_empty());
    assert!(matches!(call.authority.role, EvmAuthorityRole::Controller));
    assert_eq!(call.authority.actor.value.len(), 20);
    assert_eq!(call.guard.expectedNameSeq, 1);
}

#[test]
fn evm_standard_client_builds_unsigned_contract_tx() {
    let client = BnsEvmStandardClient::new(BnsEvmClientConfig::anvil(
        "http://127.0.0.1:8545",
        "0x2222222222222222222222222222222222222222",
        31_337,
    ));
    let req = BnsRegisterNameReq {
        name: "alice".to_string(),
        asset_owner: OWNER.to_string(),
        options: RegisterOptions::default(),
        authority_key_updates: vec![],
        semantic_owner_after_authority: None,
        controller_policy: vec![],
        controller_policy_hash: String::new(),
        initial_documents: vec![],
        authority: CallAuthority::public(),
        guard: MutationGuard::default(),
    };
    let call = register_name_call(&req).unwrap();
    let tx = client.build_unsigned_tx(&call, 9).unwrap();

    assert_eq!(tx.chain_id, 31_337);
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.input, client.build_calldata(&call));
}

#[tokio::test]
async fn static_evm_key_manager_signs_tx_for_authority_context() {
    let key_manager = StaticBnsEvmKeyManager::new(ANVIL_PRIVATE_KEY).unwrap();
    let request = BnsEvmSignRequest::new(
        BnsEvmWriteOperation::RegisterName,
        "alice",
        CallAuthority::public(),
    );
    let signer_address = BnsEvmKeyManager::signer_address(&key_manager, &request)
        .await
        .unwrap();
    assert_eq!(format!("{signer_address:#x}"), ANVIL_ADDRESS);

    let client = BnsEvmStandardClient::new(BnsEvmClientConfig::anvil(
        "http://127.0.0.1:8545",
        "0x2222222222222222222222222222222222222222",
        31_337,
    ));
    let req = BnsRegisterNameReq {
        name: "alice".to_string(),
        asset_owner: ANVIL_ADDRESS.to_string(),
        options: RegisterOptions::default(),
        authority_key_updates: vec![],
        semantic_owner_after_authority: None,
        controller_policy: vec![],
        controller_policy_hash: String::new(),
        initial_documents: vec![],
        authority: CallAuthority::public(),
        guard: MutationGuard::default(),
    };
    let call = register_name_call(&req).unwrap();
    let tx = client.build_unsigned_tx(&call, 7).unwrap();
    let signed = key_manager.sign_transaction(&request, tx).await.unwrap();

    assert_eq!(signed.signer, signer_address);
    assert_eq!(signed.nonce, 7);
    assert_eq!(signed.chain_id, 31_337);
    assert!(!signed.raw_tx.is_empty());
}

#[tokio::test]
async fn legacy_write_rpc_is_not_registered() {
    let handler = BnsIndexerRpcHandler::new(CentralizedBnsIndexerHandler::new(registry()));
    let error = handler
        .handle_rpc_call(
            RPCRequest::new("name.register", json!({})),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RPCErrors::UnknownMethod(method) if method == "name.register"));
}

#[test]
fn sn_controller_config_accepts_wildcard_and_content_doc_types_but_rejects_explicit_owner() {
    let mut config = SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), "");
    config.allowed_controller_doc_types = vec![DEVICE_MINI_DOC_TYPE.to_string()];
    config.validate().unwrap();

    config.allowed_controller_doc_types = vec![String::new()];
    config.validate().unwrap();

    config.allowed_controller_doc_types = vec![OWNER_DOC_TYPE.to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(error.code(), "INVALID_INPUT");
    assert!(error.to_string().contains("owner doc_type"));
}

#[tokio::test]
async fn sn_controller_register_name_submits_controller_policy() {
    let registry = registry();
    let (controller, submitter) = sn_controller_with_submitter(registry.clone());

    let output = controller
        .register_name(BootstrapNameParams {
            request_id: "bootstrap-1".to_string(),
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            register_options: RegisterOptions::default(),
            owner_config: json!({"id":"did:bns:alice"}),
            owner_authority_keys: vec![],
            semantic_owner_after_authority: None,
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await
        .unwrap();
    assert_eq!(output.receipt.status, BnsWriteReceiptStatus::Submitted);
    assert_eq!(output.receipt.name_seq, 0);
    assert_eq!(output.initial_documents.len(), 0);

    let registrations = submitter.registrations();
    assert_eq!(registrations.len(), 1);
    assert_eq!(registrations[0].initial_documents.len(), 1);
    assert_eq!(registrations[0].initial_documents[0].doc_type, "owner");
    assert_eq!(registrations[0].controller_policy.len(), 1);
    assert_eq!(registrations[0].controller_policy[0].doc_type, "");
}

#[tokio::test]
async fn sn_controller_publishes_arbitrary_content_document_with_wildcard_policy() {
    let registry = registry();
    let controller = sn_controller_with_applying_submitter(registry.clone());
    controller
        .register_name(BootstrapNameParams {
            request_id: "bootstrap-content".to_string(),
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            register_options: RegisterOptions::default(),
            owner_config: json!({"name":"alice"}),
            owner_authority_keys: vec![],
            semantic_owner_after_authority: None,
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await
        .unwrap();

    let receipt = controller
        .publish_content_document(PublishDocumentParams {
            request_id: "publish-zone".to_string(),
            name: "alice".to_string(),
            doc_type: ZONE_DOC_TYPE.to_string(),
            document: json!({"oods":["ood1"]}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(receipt.doc_type.as_deref(), Some(ZONE_DOC_TYPE));
    assert_eq!(receipt.document_version, Some(1));

    let resolved = registry.resolve_document("alice", ZONE_DOC_TYPE).unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&resolved.document_state.document.inline_document).unwrap();
    assert_eq!(body["oods"], json!(["ood1"]));

    let owner_error = controller
        .publish_content_document(PublishDocumentParams {
            request_id: "publish-owner-unguarded".to_string(),
            name: "alice".to_string(),
            doc_type: OWNER_DOC_TYPE.to_string(),
            document: json!({"public_key":"replacement"}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();
    assert!(owner_error
        .to_string()
        .contains("must use guarded owner publishing"));
}

#[tokio::test]
async fn guarded_owner_publish_allows_first_identity_and_content_updates_but_locks_identity() {
    let registry = registry();
    let controller = sn_controller_with_applying_submitter(registry.clone());
    controller
        .register_name(BootstrapNameParams {
            request_id: "bootstrap-owner".to_string(),
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            register_options: RegisterOptions::default(),
            owner_config: json!({"name":"alice","created_by":"cyfs-sn"}),
            owner_authority_keys: vec![],
            semantic_owner_after_authority: None,
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await
        .unwrap();

    let public_key = json!({"kty":"OKP","crv":"Ed25519","x":"alice-key"});
    let first = controller
        .publish_guarded_owner_document(PublishDocumentParams {
            request_id: "owner-first-key".to_string(),
            name: "alice".to_string(),
            doc_type: OWNER_DOC_TYPE.to_string(),
            document: json!({"name":"alice","public_key":public_key.clone()}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(first.document_version, Some(2));

    let content_update = controller
        .publish_guarded_owner_document(PublishDocumentParams {
            request_id: "owner-content-update".to_string(),
            name: "alice".to_string(),
            doc_type: OWNER_DOC_TYPE.to_string(),
            document: json!({
                "name":"alice",
                "public_key":public_key,
                "display_name":"Alice"
            }),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(content_update.document_version, Some(3));

    let changed_identity = controller
        .publish_guarded_owner_document(PublishDocumentParams {
            request_id: "owner-change-key".to_string(),
            name: "alice".to_string(),
            doc_type: OWNER_DOC_TYPE.to_string(),
            document: json!({
                "name":"alice",
                "public_key":{"kty":"OKP","crv":"Ed25519","x":"mallory-key"},
                "display_name":"Mallory"
            }),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();
    assert_eq!(changed_identity.code(), "INVALID_INPUT");
    assert!(changed_identity
        .to_string()
        .contains("owner identity field `public_key` cannot be changed"));

    let resolved = registry.resolve_document("alice", OWNER_DOC_TYPE).unwrap();
    assert_eq!(resolved.document_state.version, 3);
    let body: serde_json::Value =
        serde_json::from_slice(&resolved.document_state.document.inline_document).unwrap();
    assert_eq!(body["display_name"], "Alice");
    assert_eq!(body["public_key"]["x"], "alice-key");
}

#[tokio::test]
async fn sn_controller_bind_zone_documents_submits_atomic_zone_and_boot_documents() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let (controller, submitter) = sn_controller_with_submitter(registry);

    let receipt = controller
        .bind_zone_documents(BindZoneDocumentsParams {
            request_id: "zone-evm-submit".to_string(),
            name: "alice".to_string(),
            zone_config: json!({"gateway":{"device_name":"ood1"}}),
            boot_config: json!({"boot_config_jwt":"boot-token"}),
            authority: owner_authority(),
        })
        .await
        .unwrap();

    assert_eq!(receipt.status, BnsWriteReceiptStatus::Submitted);
    assert_eq!(receipt.receipts.len(), 2);
    assert_eq!(receipt.receipts[0].doc_type.as_deref(), Some(ZONE_DOC_TYPE));
    assert_eq!(receipt.receipts[1].doc_type.as_deref(), Some(BOOT_DOC_TYPE));

    let mutations = submitter.mutations();
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].documents.len(), 2);
    assert_eq!(mutations[0].documents[0].doc_type, ZONE_DOC_TYPE);
    assert_eq!(mutations[0].documents[1].doc_type, BOOT_DOC_TYPE);
    let document: serde_json::Value =
        serde_json::from_slice(&mutations[0].documents[0].document.inline_document).unwrap();
    assert_eq!(document["gateway"]["device_name"], "ood1");
    assert!(document.get("boot_jwt").is_none());
    let boot_document: serde_json::Value =
        serde_json::from_slice(&mutations[0].documents[1].document.inline_document).unwrap();
    assert_eq!(boot_document["boot_config_jwt"], "boot-token");
}

#[tokio::test]
async fn sn_controller_upserts_dns_txt_with_idempotency() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let rules = vec![controller_rule(
        Principal::chain_account(SN_CONTROLLER),
        DNS_TXT_DOC_TYPE,
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    registry
        .set_controller_policy("alice", rules, &policy_hash, owner_authority(), guard(1))
        .unwrap();

    let (controller, submitter) = sn_controller_with_submitter(registry.clone());

    let add = UpsertDnsTxtParams {
        request_id: "dns-1".to_string(),
        name: "alice".to_string(),
        update: DnsTxtUpdate::Add {
            ttl: 60,
            value: "_acme-challenge=token-a".to_string(),
        },
        authority: sn_controller_authority(),
    };
    let receipt = controller.upsert_dns_txt(add.clone()).await.unwrap();
    assert_eq!(receipt.status, BnsWriteReceiptStatus::Submitted);
    assert_eq!(receipt.document_version, Some(1));
    assert!(!receipt.created_or_reused);

    let replay = controller.upsert_dns_txt(add).await.unwrap();
    assert_eq!(replay.document_version, Some(1));
    assert!(replay.created_or_reused);

    let published = submitter.published();
    assert_eq!(published.len(), 1);
    let records: Vec<dns_document::DnsTxtRecord> =
        serde_json::from_slice(&published[0].update.document.inline_document).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value, "_acme-challenge=token-a");

    let conflict = controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "dns-1".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Add {
                ttl: 60,
                value: "_acme-challenge=token-b".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        conflict,
        SnBnsControllerError::IdempotencyConflict { .. }
    ));
}

#[tokio::test]
async fn owner_can_publish_device_mini_doc_and_resolve_it() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let controller = sn_controller_with_applying_submitter(registry.clone());

    let receipt = controller
        .publish_device_mini_doc(PublishDeviceMiniDocParams {
            request_id: "device-owner-publish".to_string(),
            name: "alice".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:ood1".to_string(),
            device_mini_doc: json!({
                "did": "did:dev:ood1",
                "mini_config_jwt": "jwt"
            }),
            authority: owner_authority(),
        })
        .await
        .unwrap();
    assert_eq!(receipt.status, BnsWriteReceiptStatus::Submitted);
    assert_eq!(receipt.document_version, Some(1));

    let resolved = registry
        .resolve_document("alice", DEVICE_MINI_DOC_TYPE)
        .unwrap();
    let document: serde_json::Value =
        serde_json::from_slice(&resolved.document_state.document.inline_document).unwrap();

    assert_eq!(document["version"], 1);
    assert_eq!(document["devices"]["ood1"]["did"], "did:dev:ood1");
    assert_eq!(document["devices"]["ood1"]["mini_config_jwt"], "jwt");
}

#[tokio::test]
async fn sn_controller_can_publish_relay_assignment_and_resolve_it() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let rules = vec![controller_rule(
        Principal::chain_account(SN_CONTROLLER),
        RELAY_ASSIGNMENT_DOC_TYPE,
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    registry
        .set_controller_policy("alice", rules, &policy_hash, owner_authority(), guard(1))
        .unwrap();
    let controller = sn_controller_with_applying_submitter(registry.clone());

    let receipt = controller
        .publish_relay_assignment(PublishRelayAssignmentParams {
            request_id: "relay-controller-publish".to_string(),
            name: "alice".to_string(),
            relay_assignment: json!({
                "relay": "relay-a",
                "generation": 1
            }),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(receipt.status, BnsWriteReceiptStatus::Submitted);
    assert_eq!(receipt.document_version, Some(1));

    let resolved = registry
        .resolve_document("alice", RELAY_ASSIGNMENT_DOC_TYPE)
        .unwrap();
    let document: serde_json::Value =
        serde_json::from_slice(&resolved.document_state.document.inline_document).unwrap();

    assert_eq!(document["relay"], "relay-a");
    assert_eq!(document["generation"], 1);
}

#[tokio::test]
async fn sn_controller_cannot_publish_owner_scoped_device_doc() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let controller = sn_controller(registry.clone());

    let error = controller
        .publish_device_mini_doc(PublishDeviceMiniDocParams {
            request_id: "device-controller-denied".to_string(),
            name: "alice".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:ood1".to_string(),
            device_mini_doc: json!({"did":"did:dev:ood1"}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), "INVALID_INPUT");
    assert!(error.to_string().contains("requires owner authority"));
    assert_eq!(
        registry
            .resolve_document("alice", DEVICE_MINI_DOC_TYPE)
            .unwrap()
            .status,
        DocumentStatus::Missing
    );
}

#[tokio::test]
async fn sn_controller_rejects_controller_doc_type_outside_configured_scope() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let submitter = Arc::new(RecordingEvmSubmitter::default());
    let mut config = SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), "");
    config.allowed_controller_doc_types = vec![DNS_TXT_DOC_TYPE.to_string()];
    let controller = SnBnsController::new_with_evm_submitter(
        in_process_client(registry.clone()),
        Arc::new(MemorySnBnsWriteRequestStore::new()),
        config,
        submitter,
    )
    .unwrap();

    let error = controller
        .publish_relay_assignment(PublishRelayAssignmentParams {
            request_id: "relay-denied".to_string(),
            name: "alice".to_string(),
            relay_assignment: json!({"relay":"relay-a"}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), "INVALID_INPUT");
    assert!(error
        .to_string()
        .contains("not allowed to publish doc_type"));
    assert_eq!(
        registry
            .resolve_document("alice", RELAY_ASSIGNMENT_DOC_TYPE)
            .unwrap()
            .status,
        DocumentStatus::Missing
    );
}

#[tokio::test]
async fn bns_client_preserves_stale_guard_error_codes() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let stale_name_seq = BnsClientError::from(
        registry
            .publish_document(
                "alice",
                inline_update("zone", 0, r#"{"version":1}"#),
                owner_authority(),
                guard(0),
            )
            .unwrap_err(),
    );
    assert_eq!(stale_name_seq.code(), "STALE_NAME_SEQ");
    match stale_name_seq {
        BnsClientError::Registry(info) => {
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.expected, Some(0));
            assert_eq!(info.actual, Some(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let published = registry
        .publish_document(
            "alice",
            inline_update("zone", 0, r#"{"version":1}"#),
            owner_authority(),
            guard(1),
        )
        .unwrap();
    assert_eq!(published, 1);

    let stale_document_version = BnsClientError::from(
        registry
            .publish_document(
                "alice",
                inline_update("zone", 0, r#"{"version":2}"#),
                owner_authority(),
                guard(2),
            )
            .unwrap_err(),
    );
    assert_eq!(stale_document_version.code(), "STALE_DOCUMENT_VERSION");
    match stale_document_version {
        BnsClientError::Registry(info) => {
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.doc_type.as_deref(), Some("zone"));
            assert_eq!(info.expected, Some(0));
            assert_eq!(info.actual, Some(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn sn_controller_removes_last_dns_txt_record_by_publishing_empty_rrset() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let rules = vec![controller_rule(
        Principal::chain_account(SN_CONTROLLER),
        DNS_TXT_DOC_TYPE,
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    registry
        .set_controller_policy("alice", rules, &policy_hash, owner_authority(), guard(1))
        .unwrap();

    registry
        .publish_document(
            "alice",
            inline_update(
                DNS_TXT_DOC_TYPE,
                0,
                r#"[{"ttl":60,"value":"google-site-verification=abc"}]"#,
            ),
            owner_authority(),
            guard(2),
        )
        .unwrap();

    let (controller, submitter) = sn_controller_with_submitter(registry.clone());

    let remove = controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "dns-remove".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Remove {
                value: "google-site-verification=abc".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(remove.document_version, Some(2));

    let published = submitter.published();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].update.expected_version, 1);
    assert_eq!(published[0].update.document.inline_document, b"[]");
    let records: Vec<dns_document::DnsTxtRecord> =
        serde_json::from_slice(&published[0].update.document.inline_document).unwrap();
    assert!(records.is_empty());
}
