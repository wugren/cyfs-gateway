use crate::dns_document::{self, DnsTxtRecord, DNS_TXT_DOC_TYPE};
use crate::{
    canonical_bns_name, canonical_doc_type, controller_rule, default_document_update, hash_json,
    policy_hash_from_rules, AuthorityKeyUpdate, AuthorityRole, AuthoritySetState, BnsRegistryError,
    CallAuthority, DocumentRef, DocumentState, DocumentStatus, DocumentUpdate, MutationGuard,
    NameState, OwnerPolicyUpdate, Principal, PrincipalKind, RegisterOptions,
    PERMISSION_PUBLISH_DOCUMENT, ZERO_HASH,
};
use crate::{
    BnsApplyMutationsReq, BnsClientError, BnsDocumentVersion, BnsEvmControllerClient,
    BnsEvmReceiptWaitConfig, BnsEvmTxReceipt, BnsEvmTxSubmission, BnsIndexerApi,
    BnsPublishDocumentReq, BnsRegisterNameReq, BnsRpcErrorInfo,
};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const OWNER_DOC_TYPE: &str = "owner";
pub const ZONE_DOC_TYPE: &str = "zone";
pub const BOOT_DOC_TYPE: &str = "boot";
pub const DEVICE_MINI_DOC_TYPE: &str = "device_mini_doc";
pub const RELAY_ASSIGNMENT_DOC_TYPE: &str = "relay_assignment";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteOperation {
    RegisterName,
    BootstrapName,
    PublishDocument,
    RevokeDocument,
    SetControllerPolicy,
    UpdateAuthorityKeys,
    BindZoneDocuments,
    PublishDeviceMiniDoc,
    UpsertDnsTxt,
    PublishRelayAssignment,
}

impl BnsWriteOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterName => "register_name",
            Self::BootstrapName => "bootstrap_name",
            Self::PublishDocument => "publish_document",
            Self::RevokeDocument => "revoke_document",
            Self::SetControllerPolicy => "set_controller_policy",
            Self::UpdateAuthorityKeys => "update_authority_keys",
            Self::BindZoneDocuments => "bind_zone_documents",
            Self::PublishDeviceMiniDoc => "publish_device_mini_doc",
            Self::UpsertDnsTxt => "upsert_dns_txt",
            Self::PublishRelayAssignment => "publish_relay_assignment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteReceiptStatus {
    Submitted,
}

impl Default for BnsWriteReceiptStatus {
    fn default() -> Self {
        Self::Submitted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsWriteReceipt {
    pub request_id: String,
    pub name: String,
    pub operation: BnsWriteOperation,
    #[serde(default)]
    pub status: BnsWriteReceiptStatus,
    pub name_seq: u64,
    pub doc_type: Option<String>,
    pub document_version: Option<u64>,
    pub content_hash: Option<String>,
    pub document_state_hash: Option<String>,
    pub authority_seq: u64,
    pub authority_root: String,
    pub controller_policy_hash: Option<String>,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub created_or_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsMultiWriteReceipt {
    pub request_id: String,
    pub name: String,
    pub operation: BnsWriteOperation,
    #[serde(default)]
    pub status: BnsWriteReceiptStatus,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub receipts: Vec<BnsWriteReceipt>,
    pub created_or_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNameOutput {
    pub receipt: BnsWriteReceipt,
    pub initial_documents: Vec<BnsDocumentVersion>,
}

pub type BootstrapNameOutput = RegisterNameOutput;

trait MarkIdempotentReuse {
    fn mark_reused(&mut self);
}

trait BnsWriteMetadata {
    fn evm_submission(&self) -> Option<BnsEvmTxSubmission>;
}

impl MarkIdempotentReuse for BnsWriteReceipt {
    fn mark_reused(&mut self) {
        self.created_or_reused = true;
    }
}

impl BnsWriteMetadata for BnsWriteReceipt {
    fn evm_submission(&self) -> Option<BnsEvmTxSubmission> {
        Some(BnsEvmTxSubmission {
            tx_hash: self.evm_tx_hash.clone()?,
            raw_tx: self.evm_raw_tx.clone()?,
            from: String::new(),
            nonce: self.evm_nonce?,
            chain_id: self.evm_chain_id?,
            receipt_status: None,
            receipt_block_number: None,
            receipt_confirmations: None,
        })
    }
}

impl MarkIdempotentReuse for BnsMultiWriteReceipt {
    fn mark_reused(&mut self) {
        self.created_or_reused = true;
        for receipt in &mut self.receipts {
            receipt.mark_reused();
        }
    }
}

impl BnsWriteMetadata for BnsMultiWriteReceipt {
    fn evm_submission(&self) -> Option<BnsEvmTxSubmission> {
        self.receipts
            .iter()
            .find_map(BnsWriteMetadata::evm_submission)
            .or_else(|| {
                Some(BnsEvmTxSubmission {
                    tx_hash: self.evm_tx_hash.clone()?,
                    raw_tx: self.evm_raw_tx.clone()?,
                    from: String::new(),
                    nonce: self.evm_nonce?,
                    chain_id: self.evm_chain_id?,
                    receipt_status: None,
                    receipt_block_number: None,
                    receipt_confirmations: None,
                })
            })
    }
}

impl MarkIdempotentReuse for RegisterNameOutput {
    fn mark_reused(&mut self) {
        self.receipt.mark_reused();
    }
}

impl BnsWriteMetadata for RegisterNameOutput {
    fn evm_submission(&self) -> Option<BnsEvmTxSubmission> {
        self.receipt.evm_submission()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteRequestState {
    Pending,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnBnsWriteRequestRecord {
    pub request_id: String,
    pub operation: BnsWriteOperation,
    pub name: String,
    pub doc_type: Option<String>,
    pub payload_hash: String,
    pub state: BnsWriteRequestState,
    pub result_json: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Error)]
pub enum SnBnsControllerError {
    #[error("BNS client error: {0}")]
    Bns(#[from] BnsClientError),

    #[error("invalid SN-BNS controller input: {0}")]
    InvalidInput(String),

    #[error("idempotency conflict for request `{request_id}`")]
    IdempotencyConflict { request_id: String },

    #[error("request `{request_id}` is still pending")]
    IdempotencyPending { request_id: String },

    #[error("request `{request_id}` failed previously: {message}")]
    IdempotencyPreviousFailure { request_id: String, message: String },

    #[error("idempotency store error: {0}")]
    Store(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl SnBnsControllerError {
    pub fn code(&self) -> &str {
        match self {
            Self::Bns(error) => error.code(),
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::IdempotencyConflict { .. } => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyPending { .. } => "IDEMPOTENCY_PENDING",
            Self::IdempotencyPreviousFailure { .. } => "IDEMPOTENCY_PREVIOUS_FAILURE",
            Self::Store(_) => "IDEMPOTENCY_STORE_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
        }
    }

    fn is_stale_guard(&self) -> bool {
        matches!(
            self,
            Self::Bns(error)
                if error.is_registry_code("STALE_DOCUMENT_VERSION")
                    || error.is_registry_code("STALE_NAME_SEQ")
        )
    }
}

impl From<BnsRegistryError> for SnBnsControllerError {
    fn from(value: BnsRegistryError) -> Self {
        Self::Bns(BnsClientError::from(value))
    }
}

impl From<serde_json::Error> for SnBnsControllerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type SnBnsControllerResult<T> = Result<T, SnBnsControllerError>;

pub trait SnBnsWriteRequestStore: Send + Sync {
    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>>;

    fn put(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<()>;
}

#[derive(Default)]
pub struct MemorySnBnsWriteRequestStore {
    records: Mutex<HashMap<String, SnBnsWriteRequestRecord>>,
}

impl MemorySnBnsWriteRequestStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SnBnsWriteRequestStore for MemorySnBnsWriteRequestStore {
    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>> {
        let records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        Ok(records.get(request_id).cloned())
    }

    fn put(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        records.insert(record.request_id.clone(), record);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SnBnsControllerConfig {
    pub sn_controller_principal: Principal,
    pub sn_controller_kid: String,
    pub allowed_controller_doc_types: Vec<String>,
    pub max_inline_document_size: usize,
    pub write_retry_limit: usize,
}

impl SnBnsControllerConfig {
    pub fn new(sn_controller_principal: Principal, sn_controller_kid: impl Into<String>) -> Self {
        Self {
            sn_controller_principal,
            sn_controller_kid: sn_controller_kid.into(),
            // SN proxy 的应用层入口会继续隔离 owner / relay_assignment；链上
            // policy 使用 doc_type 通配，才能支持注册后补发 zone、boot、
            // device_mini_doc 以及未来的自定义内容文档。
            allowed_controller_doc_types: vec![String::new()],
            max_inline_document_size: crate::MAX_INLINE_DOCUMENT,
            write_retry_limit: 2,
        }
    }

    pub fn validate(&self) -> SnBnsControllerResult<()> {
        self.sn_controller_principal
            .validate()
            .map_err(SnBnsControllerError::from)?;
        if self.sn_controller_principal.kind == PrincipalKind::Unset {
            return Err(SnBnsControllerError::InvalidInput(
                "SN controller principal cannot be unset".to_string(),
            ));
        }

        for doc_type in &self.allowed_controller_doc_types {
            if doc_type.is_empty() {
                continue;
            }
            canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
            if doc_type == OWNER_DOC_TYPE {
                return Err(SnBnsControllerError::InvalidInput(format!(
                    "SN controller cannot be explicitly allowed to write owner doc_type `{}`",
                    doc_type
                )));
            }
        }

        Ok(())
    }

    pub fn sn_controller_authority(&self) -> CallAuthority {
        CallAuthority::controller(
            self.sn_controller_principal.clone(),
            self.sn_controller_kid.clone(),
        )
    }

    pub fn sn_managed_owner_authority(&self) -> CallAuthority {
        CallAuthority::owner(
            self.sn_controller_principal.clone(),
            self.sn_controller_kid.clone(),
        )
    }

    pub fn sn_controller_policy(&self) -> SnBnsControllerResult<Vec<crate::ControllerRule>> {
        self.validate()?;
        Ok(self
            .allowed_controller_doc_types
            .iter()
            .map(|doc_type| {
                controller_rule(
                    self.sn_controller_principal.clone(),
                    doc_type.clone(),
                    PERMISSION_PUBLISH_DOCUMENT,
                )
            })
            .collect())
    }
}

#[async_trait]
pub trait SnBnsEvmSubmitter: Send + Sync {
    async fn register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission>;

    async fn apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission>;

    async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission>;

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> crate::BnsClientResult<BnsEvmTxReceipt> {
        let _ = (tx_hash, config);
        Err(BnsClientError::Transport(
            "EVM receipt waiting is not supported by this submitter".to_string(),
        ))
    }
}

#[async_trait]
impl SnBnsEvmSubmitter for BnsEvmControllerClient {
    async fn register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        BnsEvmControllerClient::register_name(self, req).await
    }

    async fn apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        BnsEvmControllerClient::apply_mutations(self, req).await
    }

    async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        BnsEvmControllerClient::publish_document(self, req).await
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> crate::BnsClientResult<BnsEvmTxReceipt> {
        BnsEvmControllerClient::wait_for_receipt(self, tx_hash, config).await
    }
}

#[async_trait]
trait SnBnsWriteBackend: Send + Sync {
    async fn register_name(
        &self,
        req: BnsRegisterNameReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission>;

    async fn apply_mutations(
        &self,
        req: BnsApplyMutationsReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission>;

    async fn publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission>;

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt>;
}

struct EvmSnBnsWriteBackend {
    submitter: Arc<dyn SnBnsEvmSubmitter>,
}

impl EvmSnBnsWriteBackend {
    fn new(submitter: Arc<dyn SnBnsEvmSubmitter>) -> Self {
        Self { submitter }
    }
}

#[async_trait]
impl SnBnsWriteBackend for EvmSnBnsWriteBackend {
    async fn register_name(
        &self,
        req: BnsRegisterNameReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        self.submitter.register_name(&req).await.map_err(Into::into)
    }

    async fn apply_mutations(
        &self,
        req: BnsApplyMutationsReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        self.submitter
            .apply_mutations(&req)
            .await
            .map_err(Into::into)
    }

    async fn publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        self.submitter
            .publish_document(&req)
            .await
            .map_err(Into::into)
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt> {
        self.submitter
            .wait_for_receipt(tx_hash, config)
            .await
            .map_err(Into::into)
    }
}

pub struct SnBnsController {
    client: Arc<dyn BnsIndexerApi>,
    write_backend: Arc<dyn SnBnsWriteBackend>,
    idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
    config: SnBnsControllerConfig,
}

impl SnBnsController {
    pub fn new_evm(
        client: Arc<dyn BnsIndexerApi>,
        idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
        config: SnBnsControllerConfig,
        evm_controller: Arc<BnsEvmControllerClient>,
    ) -> SnBnsControllerResult<Self> {
        let submitter: Arc<dyn SnBnsEvmSubmitter> = evm_controller;
        Self::new_with_evm_submitter(client, idempotency_store, config, submitter)
    }

    pub fn new_with_evm_submitter(
        client: Arc<dyn BnsIndexerApi>,
        idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
        config: SnBnsControllerConfig,
        evm_submitter: Arc<dyn SnBnsEvmSubmitter>,
    ) -> SnBnsControllerResult<Self> {
        config.validate()?;
        Ok(Self {
            client,
            write_backend: Arc::new(EvmSnBnsWriteBackend::new(evm_submitter)),
            idempotency_store,
            config,
        })
    }

    pub fn config(&self) -> &SnBnsControllerConfig {
        &self.config
    }

    pub fn sn_controller_authority(&self) -> CallAuthority {
        self.config.sn_controller_authority()
    }

    pub fn sn_controller_policy(&self) -> SnBnsControllerResult<Vec<crate::ControllerRule>> {
        self.config.sn_controller_policy()
    }

    pub async fn wait_for_evm_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt> {
        self.write_backend.wait_for_receipt(tx_hash, config).await
    }

    pub async fn bootstrap_name(
        &self,
        params: RegisterNameParams,
    ) -> SnBnsControllerResult<RegisterNameOutput> {
        self.register_name(params).await
    }

    pub async fn register_name(
        &self,
        params: RegisterNameParams,
    ) -> SnBnsControllerResult<RegisterNameOutput> {
        self.ensure_owner_authority_or_public_registration(&params.authority)?;
        let controller_policy = self.sn_controller_policy()?;
        let controller_policy_hash =
            policy_hash_from_rules(&controller_policy).map_err(SnBnsControllerError::from)?;

        let mut initial_documents = Vec::with_capacity(params.initial_documents.len() + 1);
        if params
            .initial_documents
            .iter()
            .any(|update| update.doc_type == OWNER_DOC_TYPE)
        {
            return Err(SnBnsControllerError::InvalidInput(
                "initial_documents must not contain owner; pass owner_config instead".to_string(),
            ));
        }
        initial_documents.push(self.inline_json_update(OWNER_DOC_TYPE, 0, &params.owner_config)?);
        initial_documents.extend(params.initial_documents.clone());

        let req = BnsRegisterNameReq {
            name: canonical_bns_name(&params.name).map_err(SnBnsControllerError::from)?,
            asset_owner: params.asset_owner.clone(),
            options: params.register_options.clone(),
            authority_key_updates: params.owner_authority_keys.clone(),
            semantic_owner_after_authority: params.semantic_owner_after_authority.clone(),
            controller_policy,
            controller_policy_hash: controller_policy_hash.clone(),
            initial_documents,
            authority: params.authority.clone(),
            guard: params.guard,
        };

        let request_id = params.request_id.clone();
        let name = params.name.clone();
        let payload = req.clone();
        let response_request_id = request_id.clone();
        let response_name = name.clone();
        self.run_idempotent(
            &request_id,
            BnsWriteOperation::RegisterName,
            &name,
            None,
            &payload,
            || async move {
                let submission = self.write_backend.register_name(req).await?;
                Ok(self.register_output_from_submission(
                    &response_request_id,
                    &response_name,
                    &controller_policy_hash,
                    submission,
                ))
            },
        )
        .await
    }

    pub async fn publish_owner_document(
        &self,
        params: PublishOwnerDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, OWNER_DOC_TYPE)?;
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(OWNER_DOC_TYPE),
            &params,
            || async {
                self.publish_json_document_once(
                    &params.request_id,
                    BnsWriteOperation::PublishDocument,
                    &params.name,
                    OWNER_DOC_TYPE,
                    &params.owner_config,
                    params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    pub async fn publish_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, &params.doc_type)?;
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(&params.doc_type),
            &params,
            || async {
                self.publish_json_document_once(
                    &params.request_id,
                    BnsWriteOperation::PublishDocument,
                    &params.name,
                    &params.doc_type,
                    &params.document,
                    params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    /// 以 controller authority 发布普通内容文档。
    ///
    /// `owner` 必须走 [`Self::publish_guarded_owner_document`]，
    /// `relay_assignment` 必须走 [`Self::publish_relay_assignment`]；把保留类型
    /// 在这一层硬编码排除，避免其它调用方绕过上层 RPC 的产品边界。
    pub async fn publish_content_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        if params.doc_type == OWNER_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(
                "owner document must use guarded owner publishing".to_string(),
            ));
        }
        if params.doc_type == RELAY_ASSIGNMENT_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(
                "relay_assignment must use publish_relay_assignment".to_string(),
            ));
        }
        if !params.document.is_object()
            && !params
                .document
                .as_str()
                .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(SnBnsControllerError::InvalidInput(
                "document must be a JSON object or non-empty text string".to_string(),
            ));
        }
        self.ensure_authority_can_publish(&params.authority, &params.doc_type)?;

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(&params.doc_type),
            &params,
            || async {
                let mut attempt = 0;
                loop {
                    let result = self
                        .publish_inline_document_once(
                            &params.request_id,
                            BnsWriteOperation::PublishDocument,
                            &params.name,
                            &params.doc_type,
                            &params.document,
                            params.authority.clone(),
                        )
                        .await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    /// 以 controller authority 更新 owner 文档，同时锁定已经存在的身份字段。
    /// 缺失的身份字段可以首次补齐；一旦存在就不能删除或改值。
    pub async fn publish_guarded_owner_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        if params.doc_type != OWNER_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "guarded owner publishing requires doc_type `{OWNER_DOC_TYPE}`"
            )));
        }
        if !params.document.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "owner document must be a JSON object".to_string(),
            ));
        }
        self.ensure_authority_can_publish(&params.authority, OWNER_DOC_TYPE)?;

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(OWNER_DOC_TYPE),
            &params,
            || async {
                let mut attempt = 0;
                loop {
                    let result = self.publish_guarded_owner_document_once(&params).await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    pub async fn bind_zone_documents(
        &self,
        params: BindZoneDocumentsParams,
    ) -> SnBnsControllerResult<BnsMultiWriteReceipt> {
        self.ensure_owner_authority(&params.authority, ZONE_DOC_TYPE)?;
        if !params.zone_config.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "zone_config must be a JSON object".to_string(),
            ));
        }
        if !params.boot_config.is_null() && !params.boot_config.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "boot_config must be a JSON object when present".to_string(),
            ));
        }
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::BindZoneDocuments,
            &params.name,
            Some(ZONE_DOC_TYPE),
            &params,
            || async {
                let name_state = self.required_name_state(&params.name).await?;
                let zone_current = self
                    .current_document_state(&params.name, ZONE_DOC_TYPE)
                    .await?;
                let zone_expected = zone_current.as_ref().map_or(0, |state| state.version);
                let mut updates = vec![self.inline_json_update(
                    ZONE_DOC_TYPE,
                    zone_expected,
                    &params.zone_config,
                )?];
                if !params.boot_config.is_null() {
                    let boot_current = self
                        .current_document_state(&params.name, BOOT_DOC_TYPE)
                        .await?;
                    let boot_expected = boot_current.as_ref().map_or(0, |state| state.version);
                    updates.push(self.inline_json_update(
                        BOOT_DOC_TYPE,
                        boot_expected,
                        &params.boot_config,
                    )?);
                }
                let guard = MutationGuard {
                    expected_name_seq: name_state.name_seq,
                    expected_parent_name_seq: 0,
                };
                let submission = self
                    .write_backend
                    .apply_mutations(BnsApplyMutationsReq {
                        name: params.name.clone(),
                        authority_key_updates: Vec::new(),
                        documents: updates.clone(),
                        owner_policy: OwnerPolicyUpdate::none(),
                        authority: params.authority.clone(),
                        guard,
                    })
                    .await?;
                let authority_set = self.client.get_authority_set(&params.name).await?;
                let receipts = updates
                    .iter()
                    .map(|update| {
                        receipt_from_submitted_document(
                            &params.request_id,
                            BnsWriteOperation::BindZoneDocuments,
                            &name_state,
                            update,
                            &authority_set,
                            submission.clone(),
                        )
                    })
                    .collect();
                Ok(BnsMultiWriteReceipt {
                    request_id: params.request_id.clone(),
                    name: params.name.clone(),
                    operation: BnsWriteOperation::BindZoneDocuments,
                    status: BnsWriteReceiptStatus::Submitted,
                    evm_chain_id: Some(submission.chain_id),
                    evm_nonce: Some(submission.nonce),
                    evm_tx_hash: Some(submission.tx_hash),
                    evm_raw_tx: Some(submission.raw_tx),
                    receipts,
                    created_or_reused: false,
                })
            },
        )
        .await
    }

    pub async fn publish_device_mini_doc(
        &self,
        params: PublishDeviceMiniDocParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, DEVICE_MINI_DOC_TYPE)?;
        self.validate_device_name(&params.device_name)?;
        crate::validate_did(&params.did).map_err(SnBnsControllerError::from)?;

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDeviceMiniDoc,
            &params.name,
            Some(DEVICE_MINI_DOC_TYPE),
            &params,
            || async {
                let current = self
                    .current_document_state(&params.name, DEVICE_MINI_DOC_TYPE)
                    .await?;
                let expected_version = current.as_ref().map_or(0, |state| state.version);
                let mut collection = match current.as_ref() {
                    Some(state) => self.parse_inline_document::<DeviceMiniDocCollection>(state)?,
                    None => DeviceMiniDocCollection::default(),
                };

                let entry =
                    normalize_device_mini_doc_entry(&params.did, params.device_mini_doc.clone())?;
                collection.devices.insert(params.device_name.clone(), entry);
                let document = serde_json::to_value(collection)?;

                self.publish_json_document_with_expected_once(
                    &params.request_id,
                    BnsWriteOperation::PublishDeviceMiniDoc,
                    &params.name,
                    DEVICE_MINI_DOC_TYPE,
                    expected_version,
                    &document,
                    params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    pub async fn upsert_dns_txt(
        &self,
        params: UpsertDnsTxtParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_authority_can_publish(&params.authority, DNS_TXT_DOC_TYPE)?;
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::UpsertDnsTxt,
            &params.name,
            Some(DNS_TXT_DOC_TYPE),
            &params,
            || async {
                let mut attempt = 0;
                loop {
                    let result = self.upsert_dns_txt_once(&params).await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    pub async fn publish_relay_assignment(
        &self,
        params: PublishRelayAssignmentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_authority_can_publish(&params.authority, RELAY_ASSIGNMENT_DOC_TYPE)?;
        if !params.relay_assignment.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "relay_assignment must be a JSON object".to_string(),
            ));
        }

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishRelayAssignment,
            &params.name,
            Some(RELAY_ASSIGNMENT_DOC_TYPE),
            &params,
            || async {
                self.publish_inline_document_once(
                    &params.request_id,
                    BnsWriteOperation::PublishRelayAssignment,
                    &params.name,
                    RELAY_ASSIGNMENT_DOC_TYPE,
                    &params.relay_assignment,
                    params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    async fn upsert_dns_txt_once(
        &self,
        params: &UpsertDnsTxtParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self
            .current_document_state(&params.name, DNS_TXT_DOC_TYPE)
            .await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        let mut records = match current.as_ref() {
            Some(state) => dns_document::txt_records_from_document(state)
                .map_err(SnBnsControllerError::from)?,
            None => Vec::new(),
        };

        match &params.update {
            DnsTxtUpdate::Add { ttl, value } => {
                DnsTxtRecord::new(*ttl, value.clone()).map_err(SnBnsControllerError::from)?;
                if !records.iter().any(|record| record.value == *value) {
                    records.push(DnsTxtRecord {
                        ttl: *ttl,
                        value: value.clone(),
                    });
                }
            }
            DnsTxtUpdate::Remove { value } => {
                records.retain(|record| record.value != *value);
            }
            DnsTxtUpdate::Replace { records: next } => {
                for record in next {
                    DnsTxtRecord::new(record.ttl, record.value.clone())
                        .map_err(SnBnsControllerError::from)?;
                }
                records = next.clone();
            }
        }

        let update = self.dns_txt_update(expected_version, &records)?;
        self.publish_document_update_once(
            &params.request_id,
            BnsWriteOperation::UpsertDnsTxt,
            &params.name,
            update,
            params.authority.clone(),
        )
        .await
    }

    async fn publish_json_document_once(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self.current_document_state(name, doc_type).await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        self.publish_json_document_with_expected_once(
            request_id,
            operation,
            name,
            doc_type,
            expected_version,
            document,
            authority,
        )
        .await
    }

    async fn publish_inline_document_once(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self.current_document_state(name, doc_type).await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        let update = self.inline_content_update(doc_type, expected_version, document)?;
        self.publish_document_update_once(request_id, operation, name, update, authority)
            .await
    }

    async fn publish_guarded_owner_document_once(
        &self,
        params: &PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self
            .current_document_state(&params.name, OWNER_DOC_TYPE)
            .await?;
        if let Some(state) = current.as_ref() {
            let current_document = self.parse_inline_document::<Value>(state)?;
            ensure_owner_identity_fields_unchanged(&current_document, &params.document)?;
        }
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        self.publish_json_document_with_expected_once(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            OWNER_DOC_TYPE,
            expected_version,
            &params.document,
            params.authority.clone(),
        )
        .await
    }

    async fn publish_json_document_with_expected_once(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let update = self.inline_json_update(doc_type, expected_version, document)?;
        self.publish_document_update_once(request_id, operation, name, update, authority)
            .await
    }

    async fn publish_document_update_once(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        update: DocumentUpdate,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let name_state = self.required_name_state(name).await?;
        let guard = MutationGuard {
            expected_name_seq: name_state.name_seq,
            expected_parent_name_seq: 0,
        };
        let submission = self
            .write_backend
            .publish_document(BnsPublishDocumentReq {
                name: name.to_string(),
                update: update.clone(),
                authority,
                guard,
            })
            .await?;
        let authority_set = self.client.get_authority_set(name).await?;

        Ok(receipt_from_submitted_document(
            request_id,
            operation,
            &name_state,
            &update,
            &authority_set,
            submission,
        ))
    }

    async fn current_document_state(
        &self,
        name: &str,
        doc_type: &str,
    ) -> SnBnsControllerResult<Option<DocumentState>> {
        match self.client.resolve_document(name, doc_type).await {
            Ok(result) if result.status == DocumentStatus::Missing => Ok(None),
            Ok(result) => Ok(Some(result.document_state)),
            Err(error) if error.is_registry_code("DOCUMENT_NOT_FOUND") => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn required_name_state(&self, name: &str) -> SnBnsControllerResult<NameState> {
        self.client
            .query_name_state(name)
            .await?
            .ok_or_else(|| {
                BnsClientError::Registry(BnsRpcErrorInfo {
                    code: "NAME_NOT_FOUND".to_string(),
                    message: format!("name `{}` was not found", name),
                    name: Some(name.to_string()),
                    doc_type: None,
                    expected: None,
                    actual: None,
                })
            })
            .map_err(SnBnsControllerError::from)
    }

    fn inline_json_update(
        &self,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
    ) -> SnBnsControllerResult<DocumentUpdate> {
        canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        let bytes = serde_json::to_vec(document)?;
        if bytes.is_empty() || bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "inline document `{}` is {} bytes, max {}",
                doc_type,
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(doc_type, expected_version, DocumentRef::inline(bytes))
            .map_err(SnBnsControllerError::from)
    }

    fn inline_content_update(
        &self,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
    ) -> SnBnsControllerResult<DocumentUpdate> {
        canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        let bytes = match document {
            Value::Object(_) => serde_json::to_vec(document)?,
            Value::String(text) if !text.trim().is_empty() => text.as_bytes().to_vec(),
            _ => {
                return Err(SnBnsControllerError::InvalidInput(
                    "document must be a JSON object or non-empty text string".to_string(),
                ));
            }
        };
        if bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "inline document `{}` is {} bytes, max {}",
                doc_type,
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(doc_type, expected_version, DocumentRef::inline(bytes))
            .map_err(SnBnsControllerError::from)
    }

    fn dns_txt_update(
        &self,
        expected_version: u64,
        records: &[DnsTxtRecord],
    ) -> SnBnsControllerResult<DocumentUpdate> {
        let bytes = serde_json::to_vec(records)?;
        if bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "dns_txt inline document is {} bytes, max {}",
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(
            DNS_TXT_DOC_TYPE,
            expected_version,
            DocumentRef::inline(bytes),
        )
        .map_err(SnBnsControllerError::from)
    }

    fn parse_inline_document<T: DeserializeOwned>(
        &self,
        state: &DocumentState,
    ) -> SnBnsControllerResult<T> {
        if state.document.storage_type != crate::STORAGE_TYPE_INLINE {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "document `{}/{}` is not inline",
                state.name, state.doc_type
            )));
        }
        serde_json::from_slice(&state.document.inline_document).map_err(Into::into)
    }

    fn ensure_owner_authority(
        &self,
        authority: &CallAuthority,
        doc_type: &str,
    ) -> SnBnsControllerResult<()> {
        if authority.role == AuthorityRole::Owner {
            Ok(())
        } else {
            Err(SnBnsControllerError::InvalidInput(format!(
                "doc_type `{}` requires owner authority",
                doc_type
            )))
        }
    }

    fn ensure_owner_authority_or_public_registration(
        &self,
        authority: &CallAuthority,
    ) -> SnBnsControllerResult<()> {
        if matches!(authority.role, AuthorityRole::Owner | AuthorityRole::None) {
            Ok(())
        } else {
            Err(SnBnsControllerError::InvalidInput(
                "register_name requires owner authority for subnames or public authority for root registration"
                    .to_string(),
            ))
        }
    }

    fn ensure_authority_can_publish(
        &self,
        authority: &CallAuthority,
        doc_type: &str,
    ) -> SnBnsControllerResult<()> {
        match authority.role {
            AuthorityRole::Owner => Ok(()),
            AuthorityRole::Controller => {
                if !self
                    .config
                    .allowed_controller_doc_types
                    .iter()
                    .any(|allowed| allowed.is_empty() || allowed == doc_type)
                {
                    return Err(SnBnsControllerError::InvalidInput(format!(
                        "SN controller is not allowed to publish doc_type `{}`",
                        doc_type
                    )));
                }
                if authority.actor != self.config.sn_controller_principal {
                    return Err(SnBnsControllerError::InvalidInput(
                        "controller authority actor does not match configured SN controller"
                            .to_string(),
                    ));
                }
                if authority.actor.kind == PrincipalKind::BnsName
                    && authority.kid != self.config.sn_controller_kid
                {
                    return Err(SnBnsControllerError::InvalidInput(
                        "controller authority kid does not match configured SN controller key"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            AuthorityRole::None => Err(SnBnsControllerError::InvalidInput(format!(
                "doc_type `{}` requires owner or controller authority",
                doc_type
            ))),
        }
    }

    fn validate_device_name(&self, device_name: &str) -> SnBnsControllerResult<()> {
        if device_name.is_empty() || device_name.len() > 64 {
            return Err(SnBnsControllerError::InvalidInput(
                "device_name must be 1..64 bytes".to_string(),
            ));
        }
        if !device_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(SnBnsControllerError::InvalidInput(
                "device_name only supports lower-case ASCII letters, digits, '-' and '_'"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn register_output_from_submission(
        &self,
        request_id: &str,
        name: &str,
        controller_policy_hash: &str,
        submission: BnsEvmTxSubmission,
    ) -> RegisterNameOutput {
        RegisterNameOutput {
            receipt: BnsWriteReceipt {
                request_id: request_id.to_string(),
                name: name.to_string(),
                operation: BnsWriteOperation::RegisterName,
                status: BnsWriteReceiptStatus::Submitted,
                name_seq: 0,
                doc_type: None,
                document_version: None,
                content_hash: None,
                document_state_hash: None,
                authority_seq: 0,
                authority_root: ZERO_HASH.to_string(),
                controller_policy_hash: Some(controller_policy_hash.to_string()),
                evm_chain_id: Some(submission.chain_id),
                evm_nonce: Some(submission.nonce),
                evm_tx_hash: Some(submission.tx_hash),
                evm_raw_tx: Some(submission.raw_tx),
                created_or_reused: false,
            },
            initial_documents: Vec::new(),
        }
    }

    async fn run_idempotent<T, P, F, Fut>(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: Option<&str>,
        payload: &P,
        execute: F,
    ) -> SnBnsControllerResult<T>
    where
        T: Serialize + DeserializeOwned + MarkIdempotentReuse + BnsWriteMetadata,
        P: Serialize + ?Sized,
        F: FnOnce() -> Fut,
        Fut: Future<Output = SnBnsControllerResult<T>>,
    {
        if request_id.is_empty() {
            return Err(SnBnsControllerError::InvalidInput(
                "request_id is required".to_string(),
            ));
        }
        canonical_bns_name(name).map_err(SnBnsControllerError::from)?;
        if let Some(doc_type) = doc_type {
            canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        }

        let payload_hash = hash_json(payload).map_err(SnBnsControllerError::from)?;
        if let Some(record) = self.idempotency_store.get(request_id)? {
            if record.payload_hash != payload_hash {
                return Err(SnBnsControllerError::IdempotencyConflict {
                    request_id: request_id.to_string(),
                });
            }

            return match record.state {
                BnsWriteRequestState::Succeeded => {
                    let value = record.result_json.ok_or_else(|| {
                        SnBnsControllerError::Store(format!(
                            "succeeded request `{}` has no result_json",
                            request_id
                        ))
                    })?;
                    let mut result: T = serde_json::from_value(value)?;
                    result.mark_reused();
                    Ok(result)
                }
                BnsWriteRequestState::Pending => Err(SnBnsControllerError::IdempotencyPending {
                    request_id: request_id.to_string(),
                }),
                BnsWriteRequestState::Failed => {
                    Err(SnBnsControllerError::IdempotencyPreviousFailure {
                        request_id: request_id.to_string(),
                        message: record
                            .error_message
                            .unwrap_or_else(|| "previous request failed".to_string()),
                    })
                }
            };
        }

        let now = crate::now_timestamp();
        self.idempotency_store.put(SnBnsWriteRequestRecord {
            request_id: request_id.to_string(),
            operation,
            name: name.to_string(),
            doc_type: doc_type.map(str::to_string),
            payload_hash: payload_hash.clone(),
            state: BnsWriteRequestState::Pending,
            result_json: None,
            error_code: None,
            error_message: None,
            evm_chain_id: None,
            evm_nonce: None,
            evm_tx_hash: None,
            evm_raw_tx: None,
            created_at: now,
            updated_at: now,
        })?;

        let result = execute().await;
        match result {
            Ok(value) => {
                let evm_submission = value.evm_submission();
                let result_json = serde_json::to_value(&value)?;
                self.idempotency_store.put(SnBnsWriteRequestRecord {
                    request_id: request_id.to_string(),
                    operation,
                    name: name.to_string(),
                    doc_type: doc_type.map(str::to_string),
                    payload_hash,
                    state: BnsWriteRequestState::Succeeded,
                    result_json: Some(result_json),
                    error_code: None,
                    error_message: None,
                    evm_chain_id: evm_submission.as_ref().map(|tx| tx.chain_id),
                    evm_nonce: evm_submission.as_ref().map(|tx| tx.nonce),
                    evm_tx_hash: evm_submission.as_ref().map(|tx| tx.tx_hash.clone()),
                    evm_raw_tx: evm_submission.as_ref().map(|tx| tx.raw_tx.clone()),
                    created_at: now,
                    updated_at: crate::now_timestamp(),
                })?;
                Ok(value)
            }
            Err(error) => {
                self.idempotency_store.put(SnBnsWriteRequestRecord {
                    request_id: request_id.to_string(),
                    operation,
                    name: name.to_string(),
                    doc_type: doc_type.map(str::to_string),
                    payload_hash,
                    state: BnsWriteRequestState::Failed,
                    result_json: None,
                    error_code: Some(error.code().to_string()),
                    error_message: Some(error.to_string()),
                    evm_chain_id: None,
                    evm_nonce: None,
                    evm_tx_hash: None,
                    evm_raw_tx: None,
                    created_at: now,
                    updated_at: crate::now_timestamp(),
                })?;
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNameParams {
    pub request_id: String,
    pub name: String,
    pub asset_owner: String,
    pub register_options: RegisterOptions,
    pub owner_config: Value,
    pub owner_authority_keys: Vec<AuthorityKeyUpdate>,
    pub semantic_owner_after_authority: Option<Principal>,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

pub type BootstrapNameParams = RegisterNameParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishOwnerDocumentParams {
    pub request_id: String,
    pub name: String,
    pub owner_config: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDocumentParams {
    pub request_id: String,
    pub name: String,
    pub doc_type: String,
    pub document: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindZoneDocumentsParams {
    pub request_id: String,
    pub name: String,
    pub zone_config: Value,
    pub boot_config: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDeviceMiniDocParams {
    pub request_id: String,
    pub name: String,
    pub device_name: String,
    pub did: String,
    pub device_mini_doc: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DnsTxtUpdate {
    Add { ttl: u32, value: String },
    Remove { value: String },
    Replace { records: Vec<DnsTxtRecord> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertDnsTxtParams {
    pub request_id: String,
    pub name: String,
    pub update: DnsTxtUpdate,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRelayAssignmentParams {
    pub request_id: String,
    pub name: String,
    pub relay_assignment: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceMiniDocCollection {
    version: u32,
    devices: BTreeMap<String, Value>,
}

impl Default for DeviceMiniDocCollection {
    fn default() -> Self {
        Self {
            version: 1,
            devices: BTreeMap::new(),
        }
    }
}

const OWNER_IDENTITY_PATHS: [(&str, &[&str]); 5] = [
    ("public_key", &["public_key"]),
    ("owner_key", &["owner_key"]),
    ("default_key", &["default_key"]),
    ("key", &["key"]),
    (
        "verificationMethod[0].publicKeyJwk",
        &["verificationMethod", "0", "publicKeyJwk"],
    ),
];

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        if let Ok(index) = segment.parse::<usize>() {
            current = current.as_array()?.get(index)?;
        } else {
            current = current.get(*segment)?;
        }
    }
    Some(current)
}

fn ensure_owner_identity_fields_unchanged(
    current: &Value,
    next: &Value,
) -> SnBnsControllerResult<()> {
    for (label, path) in OWNER_IDENTITY_PATHS {
        let Some(existing) = value_at_path(current, path) else {
            continue;
        };
        if value_at_path(next, path) != Some(existing) {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "owner identity field `{label}` cannot be changed or removed"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod owner_identity_field_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_identity_fields_can_be_filled_for_the_first_time() {
        ensure_owner_identity_fields_unchanged(
            &json!({"name":"alice","created_by":"cyfs-sn"}),
            &json!({
                "name":"alice",
                "public_key":{"kty":"OKP","crv":"Ed25519","x":"alice-key"}
            }),
        )
        .unwrap();
    }

    #[test]
    fn nested_verification_method_identity_cannot_change_or_disappear() {
        let current = json!({
            "verificationMethod":[{
                "id":"did:bns:alice#default",
                "publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"alice-key"}
            }]
        });
        let changed = json!({
            "verificationMethod":[{
                "id":"did:bns:alice#default",
                "publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"other-key"}
            }]
        });
        let error = ensure_owner_identity_fields_unchanged(&current, &changed).unwrap_err();
        assert!(error
            .to_string()
            .contains("verificationMethod[0].publicKeyJwk"));

        let removed = json!({"verificationMethod":[{"id":"did:bns:alice#default"}]});
        assert!(ensure_owner_identity_fields_unchanged(&current, &removed).is_err());
    }
}

fn normalize_device_mini_doc_entry(
    did: &str,
    device_mini_doc: Value,
) -> SnBnsControllerResult<Value> {
    let mut object = match device_mini_doc {
        Value::Object(object) => object,
        _ => {
            return Err(SnBnsControllerError::InvalidInput(
                "device_mini_doc must be a JSON object".to_string(),
            ));
        }
    };

    match object.get("did") {
        Some(Value::String(existing)) if existing == did => {}
        Some(Value::String(existing)) => {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "device_mini_doc did `{}` does not match `{}`",
                existing, did
            )));
        }
        Some(_) => {
            return Err(SnBnsControllerError::InvalidInput(
                "device_mini_doc did must be a string".to_string(),
            ));
        }
        None => {
            object.insert("did".to_string(), Value::String(did.to_string()));
        }
    }

    Ok(Value::Object(object))
}

fn receipt_from_submitted_document(
    request_id: &str,
    operation: BnsWriteOperation,
    name_state: &NameState,
    update: &DocumentUpdate,
    authority_set: &AuthoritySetState,
    submission: BnsEvmTxSubmission,
) -> BnsWriteReceipt {
    BnsWriteReceipt {
        request_id: request_id.to_string(),
        name: name_state.name.clone(),
        operation,
        status: BnsWriteReceiptStatus::Submitted,
        name_seq: name_state.name_seq,
        doc_type: Some(update.doc_type.clone()),
        document_version: Some(update.expected_version + 1),
        content_hash: Some(update.document.content_hash.clone()),
        document_state_hash: None,
        authority_seq: authority_set.authority_seq,
        authority_root: authority_set.authority_root.clone(),
        controller_policy_hash: Some(update.controller_policy_hash.clone()),
        evm_chain_id: Some(submission.chain_id),
        evm_nonce: Some(submission.nonce),
        evm_tx_hash: Some(submission.tx_hash),
        evm_raw_tx: Some(submission.raw_tx),
        created_or_reused: false,
    }
}
