use crate::{
    AuthorityKey, AuthorityKeyUpdate, AuthoritySetState, BnsRegistryError, BnsRegistryResult,
    CallAuthority, ControllerRule, DocumentState, DocumentUpdate, EventLogRecord, LogCheckpoint,
    MutationGuard, NameState, OwnerPolicyUpdate, OwnerResolution, Principal, RegisterOptions,
    ResolveResult,
};
use ::kRPC::{kRPC, RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;

pub const BNS_INDEXER_RPC_PATH: &str = "/kapi/bns-indexer";
pub const BNS_SERVER_RPC_PATH: &str = "/kapi/bns";
pub const MAX_BNS_NAMES_PAGE_SIZE: usize = 1_000;

pub const METHOD_QUERY_NAME_STATE: &str = "name.query_state";
pub const METHOD_RESOLVE_OWNER: &str = "name.resolve_owner";
pub const METHOD_GET_AUTHORITY_SET: &str = "authority.get_set";
pub const METHOD_GET_AUTHORITY_KEY: &str = "authority.get_key";
pub const METHOD_RESOLVE_DOCUMENT: &str = "document.resolve";
pub const METHOD_GET_DOCUMENT_VERSION: &str = "document.get_version";
pub const METHOD_QUERY_NAMES_BY_ADDRESS: &str = "name.query_by_addr";
pub const METHOD_QUERY_TX_STATE: &str = "tx.query_state";
pub const METHOD_SUBMIT_RAW_TX: &str = "tx.submit_raw";
pub const METHOD_PREPARE_TX: &str = "tx.prepare";
pub const METHOD_SYSTEM_INFO: &str = "system.info";
pub const METHOD_LIST_EVENTS: &str = "events.list";
pub const METHOD_LATEST_CHECKPOINT: &str = "checkpoint.latest";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsRpcErrorInfo {
    pub code: String,
    pub message: String,
    pub name: Option<String>,
    pub doc_type: Option<String>,
    pub expected: Option<u64>,
    pub actual: Option<u64>,
}

impl BnsRpcErrorInfo {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            name: None,
            doc_type: None,
            expected: None,
            actual: None,
        }
    }

    pub fn from_registry_error(error: &BnsRegistryError) -> Self {
        let mut info = Self::new(error.code(), error.to_string());
        match error {
            BnsRegistryError::InvalidName { name, .. }
            | BnsRegistryError::NameAlreadyExists { name }
            | BnsRegistryError::NameNotFound { name }
            | BnsRegistryError::NotEffectiveOwner { name }
            | BnsRegistryError::StandardTransferDisabled { name } => {
                info.name = Some(name.clone());
            }
            BnsRegistryError::InvalidDocType { doc_type, .. } => {
                info.doc_type = Some(doc_type.clone());
            }
            BnsRegistryError::DocumentNotFound { name, doc_type }
            | BnsRegistryError::DocumentInconsistent { name, doc_type, .. }
            | BnsRegistryError::ControllerScopeDenied { name, doc_type, .. } => {
                info.name = Some(name.clone());
                info.doc_type = Some(doc_type.clone());
            }
            BnsRegistryError::StaleNameSeq {
                name,
                expected,
                actual,
            }
            | BnsRegistryError::StaleParentNameSeq {
                name,
                expected,
                actual,
            } => {
                info.name = Some(name.clone());
                info.expected = Some(*expected);
                info.actual = Some(*actual);
            }
            BnsRegistryError::StaleDocumentVersion {
                name,
                doc_type,
                expected,
                actual,
            } => {
                info.name = Some(name.clone());
                info.doc_type = Some(doc_type.clone());
                info.expected = Some(*expected);
                info.actual = Some(*actual);
            }
            _ => {}
        }
        info
    }
}

#[derive(Debug, Error)]
pub enum BnsClientError {
    #[error("BNS registry error: {0:?}")]
    Registry(BnsRpcErrorInfo),

    #[error("BNS RPC transport error: {0}")]
    Transport(String),

    #[error("BNS RPC serialization error: {0}")]
    Serialization(String),

    #[error("BNS RPC response error: {0}")]
    InvalidResponse(String),
}

impl BnsClientError {
    pub fn registry(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Registry(BnsRpcErrorInfo::new(code, message))
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::registry("UNSUPPORTED_OPERATION", message)
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Registry(info) => &info.code,
            Self::Transport(_) => "RPC_TRANSPORT_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
            Self::InvalidResponse(_) => "INVALID_RESPONSE",
        }
    }

    pub fn is_registry_code(&self, code: &str) -> bool {
        matches!(self, Self::Registry(info) if info.code == code)
    }
}

impl From<BnsRegistryError> for BnsClientError {
    fn from(value: BnsRegistryError) -> Self {
        Self::Registry(BnsRpcErrorInfo::from_registry_error(&value))
    }
}

impl From<serde_json::Error> for BnsClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type BnsClientResult<T> = Result<T, BnsClientError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRpcEnvelope<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<BnsRpcErrorInfo>,
}

impl<T> BnsRpcEnvelope<T> {
    pub fn success(result: T) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(error: BnsClientError) -> Self {
        let error = match error {
            BnsClientError::Registry(info) => info,
            other => BnsRpcErrorInfo::new(other.code(), other.to_string()),
        };
        Self {
            ok: false,
            result: None,
            error: Some(error),
        }
    }

    pub fn into_result(self) -> BnsClientResult<T> {
        if self.ok {
            self.result.ok_or_else(|| {
                BnsClientError::InvalidResponse("BNS RPC envelope missing result".to_string())
            })
        } else {
            Err(BnsClientError::Registry(self.error.unwrap_or_else(|| {
                BnsRpcErrorInfo::new("UNKNOWN_BNS_ERROR", "BNS RPC envelope missing error")
            })))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsNameReq {
    pub name: String,
}

impl BnsNameReq {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsAuthorityKeyReq {
    pub name: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentReq {
    pub name: String,
    pub doc_type: String,
}

impl BnsDocumentReq {
    pub fn new(name: impl Into<String>, doc_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentVersionReq {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsAddressReq {
    pub address: String,
    #[serde(default)]
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsNamePage {
    pub names: Vec<String>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsTxHashReq {
    pub tx_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsTxExecutionState {
    NotFound,
    Pending,
    Succeeded,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsTxState {
    pub tx_hash: String,
    pub state: BnsTxExecutionState,
    pub block_number: Option<u64>,
    pub confirmations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsSubmitRawTxReq {
    pub raw_tx: String,
}

impl BnsSubmitRawTxReq {
    pub fn from_hex(raw_tx: impl Into<String>) -> Self {
        Self {
            raw_tx: raw_tx.into(),
        }
    }

    pub fn from_bytes(raw_tx: &[u8]) -> Self {
        Self {
            raw_tx: format!("0x{}", hex::encode(raw_tx)),
        }
    }

    pub fn raw_tx_bytes(&self) -> BnsClientResult<Vec<u8>> {
        let raw = self.raw_tx.trim();
        if raw.is_empty() {
            return Err(BnsClientError::Serialization(
                "raw_tx must not be empty".to_string(),
            ));
        }
        let hex = raw.strip_prefix("0x").unwrap_or(raw);
        if hex.is_empty() || hex.len() % 2 != 0 {
            return Err(BnsClientError::Serialization(format!(
                "raw_tx must be even-length hex, got `{}`",
                self.raw_tx
            )));
        }
        hex::decode(hex).map_err(|e| {
            BnsClientError::Serialization(format!("invalid raw_tx hex `{}`: {}", self.raw_tx, e))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsSubmitRawTxResp {
    pub tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsSystemInfo {
    pub ready: bool,
    pub chain_id: u64,
    pub contract_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsPrepareTxReq {
    pub from: String,
    pub calldata: String,
}

impl BnsPrepareTxReq {
    pub fn new(from: impl Into<String>, calldata: &[u8]) -> Self {
        Self {
            from: from.into(),
            calldata: format!("0x{}", hex::encode(calldata)),
        }
    }

    pub fn calldata_bytes(&self) -> BnsClientResult<Vec<u8>> {
        let value = self.calldata.trim();
        let value = value.strip_prefix("0x").unwrap_or(value);
        if value.is_empty() || value.len() % 2 != 0 {
            return Err(BnsClientError::Serialization(
                "calldata must be non-empty even-length hex".to_string(),
            ));
        }
        hex::decode(value)
            .map_err(|error| BnsClientError::Serialization(format!("invalid calldata: {error}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsPrepareTxResp {
    pub nonce: u64,
    pub chain_id: u64,
    pub contract_address: String,
    pub estimated_gas: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegisterNameReq {
    pub name: String,
    pub asset_owner: String,
    pub options: RegisterOptions,
    pub authority_key_updates: Vec<AuthorityKeyUpdate>,
    pub semantic_owner_after_authority: Option<Principal>,
    pub controller_policy: Vec<ControllerRule>,
    pub controller_policy_hash: String,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentVersion {
    pub doc_type: String,
    pub version: u64,
    pub content_hash: String,
    pub document_state_hash: String,
}

impl From<&DocumentState> for BnsDocumentVersion {
    fn from(value: &DocumentState) -> Self {
        Self {
            doc_type: value.doc_type.clone(),
            version: value.version,
            content_hash: value.document.content_hash.clone(),
            document_state_hash: value.document_state_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsBootstrapNameReq {
    pub request_id: String,
    pub name: String,
    pub asset_owner: String,
    pub options: RegisterOptions,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority_key_updates: Vec<AuthorityKeyUpdate>,
    pub semantic_owner_after_authority: Option<Principal>,
    pub controller_policy: Vec<ControllerRule>,
    pub controller_policy_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsPublishDocumentReq {
    pub name: String,
    pub update: DocumentUpdate,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsApplyMutationsReq {
    pub name: String,
    pub authority_key_updates: Vec<AuthorityKeyUpdate>,
    pub documents: Vec<DocumentUpdate>,
    #[serde(default)]
    pub owner_policy: OwnerPolicyUpdate,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRevokeDocumentReq {
    pub name: String,
    pub doc_type: String,
    pub expected_version: u64,
    pub reason_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsSetMinDocumentIatReq {
    pub name: String,
    pub min_document_iat: u64,
    pub reason_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsSetControllerPolicyReq {
    pub name: String,
    pub rules: Vec<ControllerRule>,
    pub policy_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsUpdateAuthorityKeysReq {
    pub name: String,
    pub updates: Vec<AuthorityKeyUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsListEventsReq {
    pub from_seq: u64,
    pub limit: usize,
}

#[async_trait]
pub trait BnsIndexerApi: Send + Sync {
    async fn system_info(&self) -> BnsClientResult<BnsSystemInfo> {
        Err(BnsClientError::unsupported(
            "BNS system readiness is not configured",
        ))
    }

    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>>;

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution>;

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState>;

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>>;

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult>;

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>>;

    async fn query_names_by_address(
        &self,
        _address: &str,
        _cursor: Option<&str>,
        _limit: usize,
    ) -> BnsClientResult<BnsNamePage> {
        Err(BnsClientError::unsupported(
            "BNS address lookup is not configured",
        ))
    }

    async fn query_tx_state(&self, _tx_hash: &str) -> BnsClientResult<BnsTxState> {
        Err(BnsClientError::unsupported(
            "BNS transaction state lookup is not configured",
        ))
    }

    async fn submit_raw_tx(&self, _req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        Err(BnsClientError::unsupported(
            "BNS raw TX submission is not configured",
        ))
    }

    async fn prepare_tx(&self, _req: BnsPrepareTxReq) -> BnsClientResult<BnsPrepareTxResp> {
        Err(BnsClientError::unsupported(
            "BNS transaction preparation is not configured",
        ))
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>>;

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>>;
}

#[derive(Clone)]
pub enum BnsRpcClient {
    InProcess(Arc<dyn BnsIndexerApi>),
    KRPC(Arc<kRPC>),
}

impl BnsRpcClient {
    pub fn new_in_process(handler: Arc<dyn BnsIndexerApi>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(client: Arc<kRPC>) -> Self {
        Self::KRPC(client)
    }

    pub fn new_krpc_url(indexer_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_bns_indexer_url(indexer_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    pub fn new_bns_server_url(server_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_bns_server_url(server_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    async fn call<Req, Resp>(&self, method: &str, req: &Req) -> BnsClientResult<Resp>
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        match self {
            Self::InProcess(_) => Err(BnsClientError::unsupported(
                "generic call is only available for KRPC clients",
            )),
            Self::KRPC(client) => {
                let req_json = serde_json::to_value(req)
                    .map_err(|e| BnsClientError::Serialization(e.to_string()))?;
                let result = client
                    .call(method, req_json)
                    .await
                    .map_err(|e| BnsClientError::Transport(e.to_string()))?;
                let envelope: BnsRpcEnvelope<Resp> = serde_json::from_value(result)
                    .map_err(|e| BnsClientError::InvalidResponse(e.to_string()))?;
                envelope.into_result()
            }
        }
    }
}

/// Compatibility name for callers that still target the legacy indexer path.
pub type BnsIndexerClient = BnsRpcClient;

/// Preferred trait name at the unified BNS RPC boundary.
pub use BnsIndexerApi as BnsRpcApi;

#[async_trait]
impl BnsIndexerApi for BnsRpcClient {
    async fn system_info(&self) -> BnsClientResult<BnsSystemInfo> {
        match self {
            Self::InProcess(handler) => handler.system_info().await,
            Self::KRPC(_) => self.call(METHOD_SYSTEM_INFO, &json!({})).await,
        }
    }

    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        match self {
            Self::InProcess(handler) => handler.query_name_state(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_QUERY_NAME_STATE, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        match self {
            Self::InProcess(handler) => handler.resolve_owner(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_RESOLVE_OWNER, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        match self {
            Self::InProcess(handler) => handler.get_authority_set(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_AUTHORITY_SET, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        match self {
            Self::InProcess(handler) => handler.get_authority_key(name, kid).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_AUTHORITY_KEY,
                    &BnsAuthorityKeyReq {
                        name: name.to_string(),
                        kid: kid.to_string(),
                    },
                )
                .await
            }
        }
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        match self {
            Self::InProcess(handler) => handler.resolve_document(name, doc_type).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_RESOLVE_DOCUMENT,
                    &BnsDocumentReq::new(name, doc_type),
                )
                .await
            }
        }
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        match self {
            Self::InProcess(handler) => handler.get_document_version(name, doc_type, version).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_DOCUMENT_VERSION,
                    &BnsDocumentVersionReq {
                        name: name.to_string(),
                        doc_type: doc_type.to_string(),
                        version,
                    },
                )
                .await
            }
        }
    }

    async fn query_names_by_address(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> BnsClientResult<BnsNamePage> {
        match self {
            Self::InProcess(handler) => {
                handler.query_names_by_address(address, cursor, limit).await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_QUERY_NAMES_BY_ADDRESS,
                    &BnsAddressReq {
                        address: address.to_string(),
                        cursor: cursor.map(str::to_string),
                        limit,
                    },
                )
                .await
            }
        }
    }

    async fn query_tx_state(&self, tx_hash: &str) -> BnsClientResult<BnsTxState> {
        match self {
            Self::InProcess(handler) => handler.query_tx_state(tx_hash).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_QUERY_TX_STATE,
                    &BnsTxHashReq {
                        tx_hash: tx_hash.to_string(),
                    },
                )
                .await
            }
        }
    }

    async fn submit_raw_tx(&self, req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        match self {
            Self::InProcess(handler) => handler.submit_raw_tx(req).await,
            Self::KRPC(_) => self.call(METHOD_SUBMIT_RAW_TX, &req).await,
        }
    }

    async fn prepare_tx(&self, req: BnsPrepareTxReq) -> BnsClientResult<BnsPrepareTxResp> {
        match self {
            Self::InProcess(handler) => handler.prepare_tx(req).await,
            Self::KRPC(_) => self.call(METHOD_PREPARE_TX, &req).await,
        }
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        match self {
            Self::InProcess(handler) => handler.list_events(from_seq, limit).await,
            Self::KRPC(_) => {
                self.call(METHOD_LIST_EVENTS, &BnsListEventsReq { from_seq, limit })
                    .await
            }
        }
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        match self {
            Self::InProcess(handler) => handler.latest_checkpoint().await,
            Self::KRPC(_) => self.call(METHOD_LATEST_CHECKPOINT, &json!({})).await,
        }
    }
}

pub struct BnsIndexerRpcHandler<T: BnsIndexerApi>(pub T);

impl<T: BnsIndexerApi> BnsIndexerRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for BnsIndexerRpcHandler<T>
where
    T: BnsIndexerApi,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        match req.method.as_str() {
            METHOD_SYSTEM_INFO => rpc_envelope_response(self.0.system_info().await, &req),
            METHOD_QUERY_NAME_STATE | "query_name_state" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.query_name_state(&parsed.name).await, &req)
            }
            METHOD_RESOLVE_OWNER | "resolve_owner" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.resolve_owner(&parsed.name).await, &req)
            }
            METHOD_GET_AUTHORITY_SET | "get_authority_set" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.get_authority_set(&parsed.name).await, &req)
            }
            METHOD_GET_AUTHORITY_KEY | "get_authority_key" => {
                let parsed: BnsAuthorityKeyReq =
                    parse_req(req.params.clone(), "BnsAuthorityKeyReq")?;
                rpc_envelope_response(
                    self.0.get_authority_key(&parsed.name, &parsed.kid).await,
                    &req,
                )
            }
            METHOD_RESOLVE_DOCUMENT | "resolve_document" => {
                let parsed: BnsDocumentReq = parse_req(req.params.clone(), "BnsDocumentReq")?;
                rpc_envelope_response(
                    self.0
                        .resolve_document(&parsed.name, &parsed.doc_type)
                        .await,
                    &req,
                )
            }
            METHOD_GET_DOCUMENT_VERSION | "get_document_version" => {
                let parsed: BnsDocumentVersionReq =
                    parse_req(req.params.clone(), "BnsDocumentVersionReq")?;
                rpc_envelope_response(
                    self.0
                        .get_document_version(&parsed.name, &parsed.doc_type, parsed.version)
                        .await,
                    &req,
                )
            }
            METHOD_QUERY_NAMES_BY_ADDRESS | "query_names_by_address" | "query_by_addr" => {
                let parsed: BnsAddressReq = parse_req(req.params.clone(), "BnsAddressReq")?;
                rpc_envelope_response(
                    self.0
                        .query_names_by_address(
                            &parsed.address,
                            parsed.cursor.as_deref(),
                            parsed.limit,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_QUERY_TX_STATE | "query_tx_state" => {
                let parsed: BnsTxHashReq = parse_req(req.params.clone(), "BnsTxHashReq")?;
                rpc_envelope_response(self.0.query_tx_state(&parsed.tx_hash).await, &req)
            }
            METHOD_SUBMIT_RAW_TX | "submit_raw_tx" => {
                let parsed: BnsSubmitRawTxReq = parse_req(req.params.clone(), "BnsSubmitRawTxReq")?;
                rpc_envelope_response(self.0.submit_raw_tx(parsed).await, &req)
            }
            METHOD_PREPARE_TX | "prepare_tx" => {
                let parsed: BnsPrepareTxReq = parse_req(req.params.clone(), "BnsPrepareTxReq")?;
                rpc_envelope_response(self.0.prepare_tx(parsed).await, &req)
            }
            METHOD_LIST_EVENTS | "list_events" => {
                let parsed: BnsListEventsReq = parse_req(req.params.clone(), "BnsListEventsReq")?;
                rpc_envelope_response(
                    self.0.list_events(parsed.from_seq, parsed.limit).await,
                    &req,
                )
            }
            METHOD_LATEST_CHECKPOINT | "latest_checkpoint" => {
                rpc_envelope_response(self.0.latest_checkpoint().await, &req)
            }
            _ => Err(RPCErrors::UnknownMethod(req.method.clone())),
        }
    }
}

// URL 已带显式路径时原样使用:允许把 client 指到非默认挂载点,例如
// bns_dv 这类 server/indexer 合体服务只暴露 /kapi/bns,indexer client
// 配置成 http://host:port/kapi/bns 即可。裸 host(或仅根路径)才补默认路径。
fn has_explicit_path(url: &str) -> bool {
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    match rest.split_once('/') {
        Some((_, path)) => !path.trim_end_matches('/').is_empty(),
        None => false,
    }
}

pub fn normalize_bns_indexer_url(indexer_url: &str) -> String {
    let trimmed = indexer_url.trim_end_matches('/');
    if has_explicit_path(trimmed) {
        return trimmed.to_string();
    }
    format!("{}{}", trimmed, BNS_INDEXER_RPC_PATH)
}

pub fn normalize_bns_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim_end_matches('/');
    if has_explicit_path(trimmed) {
        return trimmed.to_string();
    }
    format!("{}{}", trimmed, BNS_SERVER_RPC_PATH)
}

fn parse_req<T: DeserializeOwned>(value: Value, type_name: &str) -> Result<T, RPCErrors> {
    serde_json::from_value(value)
        .map_err(|e| RPCErrors::ParseRequestError(format!("Failed to parse {}: {}", type_name, e)))
}

fn rpc_envelope_response<T: Serialize>(
    result: BnsClientResult<T>,
    req: &RPCRequest,
) -> Result<RPCResponse, RPCErrors> {
    let envelope = match result {
        Ok(value) => BnsRpcEnvelope::success(value),
        Err(error) => BnsRpcEnvelope::failure(error),
    };
    let value = serde_json::to_value(envelope).map_err(|e| {
        RPCErrors::ParserResponseError(format!("Failed to serialize BNS RPC envelope: {}", e))
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

pub fn registry_result<T>(result: BnsRegistryResult<T>) -> BnsClientResult<T> {
    result.map_err(BnsClientError::from)
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn test_normalize_bns_urls() {
        // 裸 host 补默认路径
        assert_eq!(
            normalize_bns_indexer_url("http://127.0.0.1:18080"),
            "http://127.0.0.1:18080/kapi/bns-indexer"
        );
        assert_eq!(
            normalize_bns_indexer_url("http://127.0.0.1:18080/"),
            "http://127.0.0.1:18080/kapi/bns-indexer"
        );
        assert_eq!(
            normalize_bns_server_url("https://bns.example.com"),
            "https://bns.example.com/kapi/bns"
        );
        // 显式路径原样保留(bns_dv 只暴露 /kapi/bns)
        assert_eq!(
            normalize_bns_indexer_url("http://127.0.0.1:18080/kapi/bns"),
            "http://127.0.0.1:18080/kapi/bns"
        );
        assert_eq!(
            normalize_bns_indexer_url("http://127.0.0.1:18080/kapi/bns-indexer"),
            "http://127.0.0.1:18080/kapi/bns-indexer"
        );
        assert_eq!(
            normalize_bns_server_url("http://127.0.0.1:18080/custom/rpc/"),
            "http://127.0.0.1:18080/custom/rpc"
        );
    }
}
