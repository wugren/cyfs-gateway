//! HTTP/kRPC server adapter for BNS contract processing.
//!
//! The upgraded BNS Server is a standard smart-contract processor: writes are
//! already-signed raw EVM transactions forwarded with `eth_sendRawTransaction`,
//! while reads come from the `bns-indexer` read projection. The legacy
//! centralized registry adapter is still available for old in-process tests
//! during migration.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bns_client::{
    BnsAddressReq, BnsAuthorityKeyReq, BnsClientError, BnsClientResult, BnsDocumentReq,
    BnsDocumentVersionReq, BnsIndexerApi, BnsIndexerRpcHandler, BnsListEventsReq, BnsNamePage,
    BnsNameReq, BnsPrepareTxReq, BnsPrepareTxResp, BnsRpcEnvelope, BnsSubmitRawTxReq,
    BnsSubmitRawTxResp, BnsSystemInfo, BnsTxExecutionState, BnsTxHashReq, BnsTxState,
    BNS_INDEXER_RPC_PATH, BNS_SERVER_RPC_PATH, MAX_BNS_NAMES_PAGE_SIZE, METHOD_GET_AUTHORITY_KEY,
    METHOD_GET_AUTHORITY_SET, METHOD_GET_DOCUMENT_VERSION, METHOD_LATEST_CHECKPOINT,
    METHOD_LIST_EVENTS, METHOD_PREPARE_TX, METHOD_QUERY_NAMES_BY_ADDRESS, METHOD_QUERY_NAME_STATE,
    METHOD_QUERY_TX_STATE, METHOD_RESOLVE_DOCUMENT, METHOD_RESOLVE_OWNER, METHOD_SUBMIT_RAW_TX,
    METHOD_SYSTEM_INFO,
};
use bns_evm::{Address, EthRpcClient, B256};
use bns_indexer::{
    canonical_bns_name, canonical_doc_type, did_bns_from_name, is_top_level_name,
    name_from_did_bns, now_timestamp, parent_name, AliasKind, AuthorityKey, AuthoritySetState,
    BnsRegistryError, BnsRegistryResult, BnsRegistryStore, BnsRegistryStoreTx,
    CentralizedBnsIndexerHandler, CentralizedBnsRegistry, DocumentState, DocumentStatus,
    EventLogRecord, LogCheckpoint, NameState, NameStatus, OwnerResolution, OwnerSource, Principal,
    PrincipalKind, ResolveResult, SqliteBnsRegistryStore, DID_BNS_PREFIX, ZERO_HASH,
};
use bytes::Bytes;
use cyfs_gateway_lib::{
    hyper_serve_http, serve_http_by_rpc_handler, server_err, HttpServer, ServerError,
    ServerErrorCode, ServerResult, StreamInfo,
};
use http::{HeaderValue, Method, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use kRPC::{RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use log::warn;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::task::JoinHandle;

pub type SqliteBnsIndexerHttpServer =
    BnsIndexerHttpServer<CentralizedBnsIndexerHandler<SqliteBnsRegistryStore>>;
pub type BnsServerHttpServer<T> = BnsContractHttpServer<T>;
pub type SqliteBnsServerHttpServer =
    BnsContractHttpServer<BnsContractServerHandler<SqliteBnsRegistryStore>>;

pub struct BnsContractServerHandler<S>
where
    S: BnsRegistryStore,
{
    store: S,
    eth_rpc: EthRpcClient,
    contract_address: Option<String>,
    expected_chain_id: Option<u64>,
}

impl<S> BnsContractServerHandler<S>
where
    S: BnsRegistryStore,
{
    pub fn new(store: S, evm_rpc_endpoint: impl Into<String>) -> Self {
        Self {
            store,
            eth_rpc: EthRpcClient::new(evm_rpc_endpoint),
            contract_address: None,
            expected_chain_id: None,
        }
    }

    pub fn new_with_chain_config(
        store: S,
        evm_rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        chain_id: u64,
    ) -> Self {
        Self {
            store,
            eth_rpc: EthRpcClient::new(evm_rpc_endpoint),
            contract_address: Some(contract_address.into()),
            expected_chain_id: Some(chain_id),
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn evm_rpc(&self) -> &EthRpcClient {
        &self.eth_rpc
    }
}

#[async_trait]
impl<S> BnsIndexerApi for BnsContractServerHandler<S>
where
    S: BnsRegistryStore + 'static,
{
    async fn system_info(&self) -> BnsClientResult<BnsSystemInfo> {
        let expected_chain_id = self
            .expected_chain_id
            .ok_or_else(|| BnsClientError::unsupported("BNS server chain_id is not configured"))?;
        let contract = self.contract_address.as_deref().ok_or_else(|| {
            BnsClientError::unsupported("BNS server contract_address is not configured")
        })?;
        let contract = Address::from_str(contract).map_err(|error| {
            BnsClientError::Serialization(format!("invalid BNS contract_address: {error}"))
        })?;
        let actual_chain_id = self
            .eth_rpc
            .chain_id()
            .await
            .map_err(BnsClientError::from)?;
        if actual_chain_id != expected_chain_id {
            return Err(BnsClientError::Transport(format!(
                "BNS chain id mismatch: configured {expected_chain_id}, RPC returned {actual_chain_id}"
            )));
        }
        // Touch the projection store as part of readiness. An empty checkpoint is
        // valid for a fresh deployment; a store error is not.
        self.store
            .transact(|tx| tx.latest_checkpoint())
            .map_err(BnsClientError::from)?;
        Ok(BnsSystemInfo {
            ready: true,
            chain_id: actual_chain_id,
            contract_address: format!("{contract:#x}"),
        })
    }

    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        self.store
            .transact(|tx| projection_query_name_state(tx, name))
            .map_err(Into::into)
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        self.store
            .transact(|tx| projection_resolve_owner(tx, name))
            .map_err(Into::into)
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        self.store
            .transact(|tx| {
                let name = canonical_bns_name(name)?;
                projection_authority_set(tx, &name)
            })
            .map_err(Into::into)
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        self.store
            .transact(|tx| {
                let name = canonical_bns_name(name)?;
                tx.get_authority_key(&name, kid)
            })
            .map_err(Into::into)
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        self.store
            .transact(|tx| projection_resolve_document(tx, name, doc_type))
            .map_err(Into::into)
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        self.store
            .transact(|tx| {
                let name = canonical_bns_name(name)?;
                let doc_type = canonical_doc_type(doc_type)?;
                tx.get_document(&name, &doc_type, version)
            })
            .map_err(Into::into)
    }

    async fn query_names_by_address(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> BnsClientResult<BnsNamePage> {
        if limit == 0 || limit > MAX_BNS_NAMES_PAGE_SIZE {
            return Err(BnsRegistryError::InvalidLimit {
                limit,
                max: MAX_BNS_NAMES_PAGE_SIZE,
            }
            .into());
        }
        let address = Address::from_str(address.trim()).map_err(|error| {
            BnsClientError::from(BnsRegistryError::InvalidAddress {
                address: address.to_string(),
                reason: error.to_string(),
            })
        })?;
        let address = format!("{address:#x}");
        self.store
            .transact(|tx| {
                let mut names =
                    tx.list_names_by_asset_owner(&address, cursor, limit.saturating_add(1))?;
                let has_more = names.len() > limit;
                if has_more {
                    names.truncate(limit);
                }
                let next_cursor = if has_more {
                    names.last().cloned()
                } else {
                    None
                };
                Ok(BnsNamePage { names, next_cursor })
            })
            .map_err(Into::into)
    }

    async fn query_tx_state(&self, tx_hash: &str) -> BnsClientResult<BnsTxState> {
        let hash = B256::from_str(tx_hash.trim()).map_err(|error| {
            BnsClientError::Serialization(format!("invalid tx_hash `{tx_hash}`: {error}"))
        })?;
        let canonical_hash = format!("{hash:#x}");
        if let Some(receipt) = self
            .eth_rpc
            .transaction_receipt(hash)
            .await
            .map_err(BnsClientError::from)?
        {
            let block_number = receipt.block_number;
            let confirmations = match block_number {
                Some(block_number) => self
                    .eth_rpc
                    .block_number()
                    .await
                    .map_err(BnsClientError::from)?
                    .checked_sub(block_number)
                    .map_or(0, |depth| depth.saturating_add(1)),
                None => 0,
            };
            return Ok(BnsTxState {
                tx_hash: canonical_hash,
                state: if receipt.status == Some(0) {
                    BnsTxExecutionState::Reverted
                } else {
                    BnsTxExecutionState::Succeeded
                },
                block_number,
                confirmations,
            });
        }

        let state = if self
            .eth_rpc
            .transaction_by_hash(hash)
            .await
            .map_err(BnsClientError::from)?
            .is_some()
        {
            BnsTxExecutionState::Pending
        } else {
            BnsTxExecutionState::NotFound
        };
        Ok(BnsTxState {
            tx_hash: canonical_hash,
            state,
            block_number: None,
            confirmations: 0,
        })
    }

    async fn submit_raw_tx(&self, req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        let raw_tx = req.raw_tx_bytes()?;
        let tx_hash = self
            .eth_rpc
            .send_raw_transaction(&raw_tx)
            .await
            .map_err(BnsClientError::from)?;
        Ok(BnsSubmitRawTxResp {
            tx_hash: format!("{tx_hash:#x}"),
        })
    }

    async fn prepare_tx(&self, req: BnsPrepareTxReq) -> BnsClientResult<BnsPrepareTxResp> {
        let info = self.system_info().await?;
        let from = Address::from_str(req.from.trim()).map_err(|error| {
            BnsClientError::Serialization(format!("invalid transaction sender: {error}"))
        })?;
        let contract = Address::from_str(info.contract_address.as_str()).map_err(|error| {
            BnsClientError::Serialization(format!("invalid BNS contract_address: {error}"))
        })?;
        let calldata = req.calldata_bytes()?;
        let nonce = self
            .eth_rpc
            .transaction_count(from)
            .await
            .map_err(BnsClientError::from)?;
        let estimated_gas = self
            .eth_rpc
            .estimate_gas(from, contract, calldata.as_slice())
            .await
            .map_err(BnsClientError::from)?;
        let gas_buffer = estimated_gas / 5 + u64::from(estimated_gas % 5 != 0);
        let fees = self
            .eth_rpc
            .suggest_eip1559_fees()
            .await
            .map_err(BnsClientError::from)?;
        Ok(BnsPrepareTxResp {
            nonce,
            chain_id: info.chain_id,
            contract_address: info.contract_address,
            estimated_gas,
            gas_limit: estimated_gas.saturating_add(gas_buffer),
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        })
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        self.store
            .transact(|tx| tx.list_events(from_seq, limit))
            .map_err(Into::into)
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        self.store
            .transact(|tx| tx.latest_checkpoint())
            .map_err(Into::into)
    }
}

pub struct BnsContractServerRpcHandler<T: BnsIndexerApi>(pub T);

impl<T: BnsIndexerApi> BnsContractServerRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for BnsContractServerRpcHandler<T>
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

#[derive(Debug, Clone)]
pub struct BnsIndexerHttpServerConfig {
    pub id: String,
    pub rpc_path: String,
    pub http_version: Version,
    pub http3_port: Option<u16>,
}

impl Default for BnsIndexerHttpServerConfig {
    fn default() -> Self {
        Self {
            id: "bns-indexer".to_string(),
            rpc_path: BNS_INDEXER_RPC_PATH.to_string(),
            http_version: Version::HTTP_11,
            http3_port: None,
        }
    }
}

impl BnsIndexerHttpServerConfig {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }

    pub fn with_rpc_path(mut self, rpc_path: impl Into<String>) -> Self {
        self.rpc_path = normalize_rpc_path(rpc_path.into());
        self
    }

    pub fn with_http_version(mut self, http_version: Version) -> Self {
        self.http_version = http_version;
        self
    }

    pub fn with_http3_port(mut self, http3_port: Option<u16>) -> Self {
        self.http3_port = http3_port;
        self
    }
}

pub struct BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi,
{
    config: BnsIndexerHttpServerConfig,
    rpc_handler: BnsIndexerRpcHandler<T>,
}

impl<T> BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi,
{
    pub fn new(handler: T) -> Self {
        Self::with_config(handler, BnsIndexerHttpServerConfig::default())
    }

    pub fn with_config(handler: T, mut config: BnsIndexerHttpServerConfig) -> Self {
        config.rpc_path = normalize_rpc_path(config.rpc_path);
        Self {
            config,
            rpc_handler: BnsIndexerRpcHandler::new(handler),
        }
    }

    pub fn config(&self) -> &BnsIndexerHttpServerConfig {
        &self.config
    }

    pub fn rpc_path(&self) -> &str {
        &self.config.rpc_path
    }

    pub fn rpc_handler(&self) -> &BnsIndexerRpcHandler<T> {
        &self.rpc_handler
    }
}

pub struct BnsContractHttpServer<T>
where
    T: BnsIndexerApi,
{
    config: BnsIndexerHttpServerConfig,
    rpc_handler: BnsContractServerRpcHandler<T>,
}

impl<T> BnsContractHttpServer<T>
where
    T: BnsIndexerApi,
{
    pub fn new(handler: T) -> Self {
        Self::with_config(
            handler,
            BnsIndexerHttpServerConfig::default().with_rpc_path(BNS_SERVER_RPC_PATH),
        )
    }

    pub fn with_config(handler: T, mut config: BnsIndexerHttpServerConfig) -> Self {
        if config.rpc_path == BNS_INDEXER_RPC_PATH {
            config.rpc_path = BNS_SERVER_RPC_PATH.to_string();
        }
        config.rpc_path = normalize_rpc_path(config.rpc_path);
        Self {
            config,
            rpc_handler: BnsContractServerRpcHandler::new(handler),
        }
    }

    pub fn config(&self) -> &BnsIndexerHttpServerConfig {
        &self.config
    }

    pub fn rpc_path(&self) -> &str {
        &self.config.rpc_path
    }

    pub fn rpc_handler(&self) -> &BnsContractServerRpcHandler<T> {
        &self.rpc_handler
    }
}

impl<S> BnsIndexerHttpServer<CentralizedBnsIndexerHandler<S>>
where
    S: BnsRegistryStore + 'static,
{
    pub fn from_registry(registry: Arc<CentralizedBnsRegistry<S>>) -> Self {
        Self::new(CentralizedBnsIndexerHandler::new(registry))
    }

    pub fn from_registry_with_config(
        registry: Arc<CentralizedBnsRegistry<S>>,
        config: BnsIndexerHttpServerConfig,
    ) -> Self {
        Self::with_config(CentralizedBnsIndexerHandler::new(registry), config)
    }
}

impl<S> BnsContractHttpServer<BnsContractServerHandler<S>>
where
    S: BnsRegistryStore + 'static,
{
    pub fn from_contract_store(store: S, evm_rpc_endpoint: impl Into<String>) -> Self {
        Self::from_contract_store_with_config(
            store,
            evm_rpc_endpoint,
            BnsIndexerHttpServerConfig::default().with_rpc_path(BNS_SERVER_RPC_PATH),
        )
    }

    pub fn from_contract_store_with_config(
        store: S,
        evm_rpc_endpoint: impl Into<String>,
        config: BnsIndexerHttpServerConfig,
    ) -> Self {
        Self::with_config(
            BnsContractServerHandler::new(store, evm_rpc_endpoint),
            config,
        )
    }

    pub fn from_contract_store_with_chain_config(
        store: S,
        evm_rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        chain_id: u64,
    ) -> Self {
        Self::with_config(
            BnsContractServerHandler::new_with_chain_config(
                store,
                evm_rpc_endpoint,
                contract_address,
                chain_id,
            ),
            BnsIndexerHttpServerConfig::default().with_rpc_path(BNS_SERVER_RPC_PATH),
        )
    }
}

impl SqliteBnsIndexerHttpServer {
    pub fn open_sqlite(path: impl AsRef<Path>) -> BnsRegistryResult<Self> {
        let registry = open_sqlite_registry(path)?;
        Ok(Self::from_registry(registry))
    }

    pub fn open_sqlite_with_config(
        path: impl AsRef<Path>,
        config: BnsIndexerHttpServerConfig,
    ) -> BnsRegistryResult<Self> {
        let registry = open_sqlite_registry(path)?;
        Ok(Self::from_registry_with_config(registry, config))
    }

    pub fn open_memory() -> BnsRegistryResult<Self> {
        let registry = Arc::new(CentralizedBnsRegistry::new(
            SqliteBnsRegistryStore::open_memory()?,
        ));
        Ok(Self::from_registry(registry))
    }
}

impl SqliteBnsServerHttpServer {
    pub fn open_sqlite_contract(
        path: impl AsRef<Path>,
        evm_rpc_endpoint: impl Into<String>,
    ) -> BnsRegistryResult<Self> {
        Ok(Self::from_contract_store(
            SqliteBnsRegistryStore::open(path)?,
            evm_rpc_endpoint,
        ))
    }

    pub fn open_sqlite_contract_with_config(
        path: impl AsRef<Path>,
        evm_rpc_endpoint: impl Into<String>,
        config: BnsIndexerHttpServerConfig,
    ) -> BnsRegistryResult<Self> {
        Ok(Self::from_contract_store_with_config(
            SqliteBnsRegistryStore::open(path)?,
            evm_rpc_endpoint,
            config,
        ))
    }

    pub fn open_memory_contract(evm_rpc_endpoint: impl Into<String>) -> BnsRegistryResult<Self> {
        Ok(Self::from_contract_store(
            SqliteBnsRegistryStore::open_memory()?,
            evm_rpc_endpoint,
        ))
    }
}

pub fn open_sqlite_registry(
    path: impl AsRef<Path>,
) -> BnsRegistryResult<Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>> {
    Ok(Arc::new(CentralizedBnsRegistry::new(
        SqliteBnsRegistryStore::open(path)?,
    )))
}

#[async_trait]
impl<T> RPCHandler for BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        self.rpc_handler.handle_rpc_call(req, ip_from).await
    }
}

#[async_trait(?Send)]
impl<T> HttpServer for BnsIndexerHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let path = req.uri().path().to_string();

        // The DID resolver binding is dispatched before the rpc_path check,
        // otherwise `/1.0/identifiers/...` would fall into the 404 below.
        if let Some(identifier) = path.strip_prefix(DID_RESOLVER_PATH_PREFIX) {
            return serve_did_resolver_request(
                &self.rpc_handler.0,
                req.method(),
                identifier,
                req.uri().query(),
            )
            .await;
        }

        if req.method() == Method::OPTIONS && path == self.config.rpc_path {
            return response_with_cors(StatusCode::NO_CONTENT, "");
        }

        if req.method() == Method::GET && path == "/health" {
            return response_with_cors(StatusCode::OK, "ok");
        }

        if path != self.config.rpc_path {
            return response_with_cors(StatusCode::NOT_FOUND, "Not Found");
        }

        let mut response = serve_http_by_rpc_handler(req, info, self).await?;
        add_cors_headers(response.headers_mut());
        Ok(response)
    }

    fn id(&self) -> String {
        self.config.id.clone()
    }

    fn http_version(&self) -> Version {
        self.config.http_version
    }

    fn http3_port(&self) -> Option<u16> {
        self.config.http3_port
    }
}

#[async_trait]
impl<T> RPCHandler for BnsContractHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        self.rpc_handler.handle_rpc_call(req, ip_from).await
    }
}

#[async_trait(?Send)]
impl<T> HttpServer for BnsContractHttpServer<T>
where
    T: BnsIndexerApi + 'static,
{
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let path = req.uri().path().to_string();

        // The DID resolver binding is dispatched before the rpc_path check,
        // otherwise `/1.0/identifiers/...` would fall into the 404 below.
        if let Some(identifier) = path.strip_prefix(DID_RESOLVER_PATH_PREFIX) {
            return serve_did_resolver_request(
                &self.rpc_handler.0,
                req.method(),
                identifier,
                req.uri().query(),
            )
            .await;
        }

        if req.method() == Method::OPTIONS && path == self.config.rpc_path {
            return response_with_cors(StatusCode::NO_CONTENT, "");
        }

        if req.method() == Method::GET && path == "/health" {
            return response_with_cors(StatusCode::OK, "ok");
        }

        if path != self.config.rpc_path {
            return response_with_cors(StatusCode::NOT_FOUND, "Not Found");
        }

        let mut response = serve_http_by_rpc_handler(req, info, self).await?;
        add_cors_headers(response.headers_mut());
        Ok(response)
    }

    fn id(&self) -> String {
        self.config.id.clone()
    }

    fn http_version(&self) -> Version {
        self.config.http_version
    }

    fn http3_port(&self) -> Option<u16> {
        self.config.http3_port
    }
}

pub async fn bind_and_serve<A>(bind: A, server: Arc<dyn HttpServer>) -> ServerResult<()>
where
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(bind).await.map_err(|e| {
        server_err!(
            ServerErrorCode::BindFailed,
            "failed to bind bns-indexer server: {}",
            e
        )
    })?;
    serve_listener(listener, server).await
}

pub async fn serve_listener(
    listener: TcpListener,
    server: Arc<dyn HttpServer>,
) -> ServerResult<()> {
    loop {
        let (stream, remote_addr) = listener.accept().await.map_err(|e| {
            server_err!(
                ServerErrorCode::StreamError,
                "failed to accept bns-indexer connection: {}",
                e
            )
        })?;
        let server = server.clone();
        tokio::task::spawn_local(async move {
            let info = StreamInfo::new(remote_addr.to_string());
            if let Err(e) = hyper_serve_http(Box::new(stream), server, info).await {
                warn!("bns-indexer http connection failed: {}", e);
            }
        });
    }
}

pub struct BnsIndexerServerHandle {
    local_addr: SocketAddr,
    task: JoinHandle<ServerResult<()>>,
}

impl BnsIndexerServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

pub fn spawn_listener(
    listener: TcpListener,
    server: Arc<dyn HttpServer>,
) -> ServerResult<BnsIndexerServerHandle> {
    let local_addr = listener.local_addr().map_err(|e| {
        server_err!(
            ServerErrorCode::InvalidConfig,
            "failed to read bns-indexer listener address: {}",
            e
        )
    })?;
    let task = tokio::task::spawn_local(serve_listener(listener, server));
    Ok(BnsIndexerServerHandle { local_addr, task })
}

// ---------------------------------------------------------------------------
// BuckyOS DID Resolver HTTP binding (buckyos-base doc/http_did_resolver_api.md)
//
// `GET /1.0/identifiers/{did}?type={doc_type}[&iat={unix_ts}]` answers with a
// W3C DID Resolution Result envelope carrying the `didDocumentMetadata.buckyos`
// extension block that `name-client`'s `BaseHttpProvider::resolve_published_state`
// parses. This resolver is only authoritative for `did:bns:*`.
// ---------------------------------------------------------------------------

/// Path prefix of the DID resolver binding: `GET /1.0/identifiers/{did}`.
pub const DID_RESOLVER_PATH_PREFIX: &str = "/1.0/identifiers/";

/// Default doc_type when the `type` query parameter is omitted (protocol §2).
const DID_RESOLVER_DEFAULT_DOC_TYPE: &str = "zone";

const DID_RESOLUTION_CONTENT_TYPE: &str = "application/did-resolution+json";
const DID_DOCUMENT_CONTENT_TYPE_JSON: &str = "application/did+ld+json";
const DID_DOCUMENT_CONTENT_TYPE_JWT: &str = "application/did+jwt";

async fn serve_did_resolver_request<T: BnsIndexerApi>(
    api: &T,
    method: &Method,
    did: &str,
    query: Option<&str>,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    if method == Method::OPTIONS {
        return response_with_cors(StatusCode::NO_CONTENT, "");
    }
    if method != Method::GET {
        return response_with_cors(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    }

    if !did.starts_with("did:") {
        return did_resolution_error_response(
            StatusCode::BAD_REQUEST,
            "invalidDid",
            &format!("`{did}` is not a DID"),
        );
    }

    // Only did:bns is answered authoritatively; any other method gets the
    // NotApplicable envelope (404 without `buckyos.documentStatus`,
    // protocol §5) so clients treat it as "no opinion", not as Missing.
    if !did.starts_with(DID_BNS_PREFIX) {
        return did_resolution_not_applicable_response();
    }

    let name = match name_from_did_bns(did) {
        Ok(name) => name,
        Err(error) => {
            return did_resolution_error_response(
                StatusCode::BAD_REQUEST,
                "invalidDid",
                &error.to_string(),
            )
        }
    };

    let (doc_type, iat) = match parse_did_resolver_query(query) {
        Ok(parsed) => parsed,
        Err(reason) => {
            return did_resolution_error_response(
                StatusCode::BAD_REQUEST,
                "invalidRequest",
                &reason,
            )
        }
    };
    let doc_type = match canonical_doc_type(&doc_type) {
        Ok(doc_type) => doc_type,
        Err(error) => {
            return did_resolution_error_response(
                StatusCode::BAD_REQUEST,
                "invalidDocType",
                &error.to_string(),
            )
        }
    };

    // Historical `iat` queries need the full event-log index which the read
    // projection does not keep yet. Protocol §7: report the capability gap
    // with 501 + historicalQuerySupported=false — neither an error nor a
    // negative state, so clients can fall back to the current state.
    if iat.is_some() {
        return did_resolution_json_response(
            StatusCode::NOT_IMPLEMENTED,
            &json!({
                "didResolutionMetadata": {
                    "contentType": Value::Null,
                    "error": "historicalQueryNotSupported",
                },
                "didDocument": Value::Null,
                "didDocumentMetadata": {
                    "buckyos": { "historicalQuerySupported": false },
                },
            }),
        );
    }

    match api.resolve_document(&name, &doc_type).await {
        Ok(result) => {
            let status = did_resolver_document_status(&result, now_timestamp());
            did_resolution_state_response(&doc_type, status, Some(&result))
        }
        // The projection reports "this (did, doc_type) was never published"
        // as an error; that is the authoritative Missing verdict of the
        // protocol (strong negative evidence), not a server failure. A
        // tombstoned name still overrides it: every doc_type under a
        // destroyed name must keep answering 410 tombstoned (protocol §4),
        // never flip back to a 404 that a later publish could overturn.
        Err(error) if error.is_registry_code("DOCUMENT_NOT_FOUND") => {
            match api.query_name_state(&name).await {
                Ok(Some(state)) if state.status == NameStatus::Tombstoned => {
                    did_resolution_state_response(&doc_type, DocumentStatus::Tombstoned, None)
                }
                Ok(_) => did_resolution_state_response(&doc_type, DocumentStatus::Missing, None),
                Err(error) => did_resolution_failure_response(did, &doc_type, &error),
            }
        }
        Err(error) if error.is_registry_code("NAME_NOT_FOUND") => {
            did_resolution_state_response(&doc_type, DocumentStatus::Missing, None)
        }
        Err(error)
            if error.is_registry_code("INVALID_NAME")
                || error.is_registry_code("INVALID_DOC_TYPE") =>
        {
            did_resolution_error_response(StatusCode::BAD_REQUEST, "invalidDid", &error.to_string())
        }
        // Anything else is a resolver/dependency failure and must surface as
        // 5xx — never as Missing/Revoked (protocol §5).
        Err(error) => did_resolution_failure_response(did, &doc_type, &error),
    }
}

fn did_resolution_failure_response(
    did: &str,
    doc_type: &str,
    error: &BnsClientError,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    warn!("did resolver dependency failure for {did}#{doc_type}: {error}");
    let status = match error {
        BnsClientError::Transport(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    did_resolution_error_response(status, "internalError", &error.to_string())
}

fn parse_did_resolver_query(query: Option<&str>) -> Result<(String, Option<u64>), String> {
    let mut doc_type = DID_RESOLVER_DEFAULT_DOC_TYPE.to_string();
    let mut iat = None;
    for pair in query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "type" => doc_type = value.to_string(),
            "iat" => {
                iat = Some(value.parse::<u64>().map_err(|_| {
                    format!("query parameter `iat` must be a unix timestamp, got `{value}`")
                })?);
            }
            _ => {}
        }
    }
    Ok((doc_type, iat))
}

/// Map the projection result onto the protocol's `documentStatus` state
/// machine (protocol §4).
fn did_resolver_document_status(result: &ResolveResult, now: u64) -> DocumentStatus {
    // A tombstoned name takes every document down with it, regardless of the
    // per-document status stored before the name was destroyed.
    if result.name_state.status == NameStatus::Tombstoned {
        return DocumentStatus::Tombstoned;
    }
    if result.status != DocumentStatus::Active {
        return result.status;
    }
    if result.alias_kind == AliasKind::MigratedTo {
        // A migrated answer must always carry its migrationTarget (protocol
        // §4), so an alias row whose target is not a DID cannot be served as
        // migrated; it degrades to the underlying document status instead.
        if result.alias_target_did.starts_with("did:") {
            return DocumentStatus::Migrated;
        }
        warn!(
            "MigratedTo alias on `{}` has non-DID target `{}`; ignoring the alias",
            result.name_state.name, result.alias_target_did
        );
    }
    if matches!(
        result.name_state.status,
        NameStatus::Expired | NameStatus::Released
    ) || (result.document_state.expire_at != 0 && now >= result.document_state.expire_at)
    {
        // Registration lapsed or the document outlived its own validity
        // window. The chain has no timers, so this must be derived at read
        // time; expired stays 200 + last known content and the fallback
        // decision belongs to client policy.
        return DocumentStatus::Expired;
    }
    DocumentStatus::Active
}

/// Build the DID Resolution Result envelope for an authoritative BNS answer.
/// `result` is `None` when the verdict came from a NameNotFound /
/// DocumentNotFound error, i.e. an authoritative Missing (or Tombstoned, for
/// unpublished doc_types under a destroyed name) without projection state to
/// describe.
fn did_resolution_state_response(
    doc_type: &str,
    status: DocumentStatus,
    result: Option<&ResolveResult>,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    let http_status = match status {
        DocumentStatus::Active | DocumentStatus::Expired | DocumentStatus::Migrated => {
            StatusCode::OK
        }
        DocumentStatus::Missing => StatusCode::NOT_FOUND,
        DocumentStatus::Revoked | DocumentStatus::Tombstoned => StatusCode::GONE,
    };
    let deactivated = matches!(status, DocumentStatus::Revoked | DocumentStatus::Tombstoned);

    // Only readable states expose the document content; revoked/tombstoned
    // answers keep `didDocument` null so stale content cannot outlive a 410.
    let (did_document, document_content_type) = match (status, result) {
        (
            DocumentStatus::Active | DocumentStatus::Expired | DocumentStatus::Migrated,
            Some(result),
        ) => decode_inline_document(&result.document_state.document.inline_document),
        _ => (None, None),
    };

    // Only the fields of the trimmed protocol table are emitted; the old
    // draft's previousVersion / lineageEpoch / ownerSource / authorityRoot /
    // nextVersionId / canonicalId / equivalentId are no longer consumed by
    // any client and stay off the wire.
    let mut buckyos = Map::new();
    buckyos.insert("docType".to_string(), json!(doc_type));
    buckyos.insert("documentStatus".to_string(), json!(status.as_str()));
    if let Some(result) = result {
        // Version 0 is the "never published" placeholder, not a real version.
        if result.document_state.version != 0 {
            buckyos.insert(
                "documentVersion".to_string(),
                json!(result.document_state.version),
            );
        }
        buckyos.insert(
            "authoritySeq".to_string(),
            json!(result.owner.authority_seq),
        );
        if let Some(owner_did) = principal_did_string(&result.owner.effective_owner) {
            buckyos.insert("effectiveOwner".to_string(), json!(owner_did));
        }
        // `did_resolver_document_status` only reports Migrated when the alias
        // target is a DID, so the mandatory migrationTarget is always usable.
        if status == DocumentStatus::Migrated {
            buckyos.insert(
                "migrationTarget".to_string(),
                json!(result.alias_target_did),
            );
        }
        // `docHash` is deliberately not emitted: the store anchors the raw
        // stored bytes while protocol §6 anchors the encoded document string
        // clients re-serialize from `didDocument`; for re-encoded JSON bodies
        // the two disagree and a wrong anchor would make clients discard
        // valid documents. Inline answers need no anchor.
    }

    let mut metadata = Map::new();
    if let Some(result) = result {
        if result.document_state.version != 0 {
            metadata.insert(
                "versionId".to_string(),
                json!(result.document_state.version.to_string()),
            );
        }
    }
    metadata.insert("deactivated".to_string(), json!(deactivated));
    metadata.insert("buckyos".to_string(), Value::Object(buckyos));

    let envelope = json!({
        "didResolutionMetadata": {
            "contentType": document_content_type,
            "error": if http_status == StatusCode::NOT_FOUND {
                json!("notFound")
            } else {
                Value::Null
            },
        },
        "didDocument": did_document,
        "didDocumentMetadata": Value::Object(metadata),
    });
    did_resolution_json_response(http_status, &envelope)
}

/// `DocumentRef.inline_document` is raw bytes: JSON documents come out as a
/// JSON value (`application/did+ld+json`), anything else that is valid UTF-8
/// is assumed to be a JWT string (`application/did+jwt`). v1 of the protocol
/// only supports inline documents — no external content-hash fetching.
fn decode_inline_document(inline_document: &[u8]) -> (Option<Value>, Option<&'static str>) {
    if inline_document.is_empty() {
        return (None, None);
    }
    if let Ok(value) = serde_json::from_slice::<Value>(inline_document) {
        let content_type = if value.is_string() {
            DID_DOCUMENT_CONTENT_TYPE_JWT
        } else {
            DID_DOCUMENT_CONTENT_TYPE_JSON
        };
        return (Some(value), Some(content_type));
    }
    match std::str::from_utf8(inline_document) {
        Ok(text) => (
            Some(Value::String(text.trim().to_string())),
            Some(DID_DOCUMENT_CONTENT_TYPE_JWT),
        ),
        Err(_) => (None, None),
    }
}

/// Map an internal principal to the public DID string of
/// `buckyos.effectiveOwner`. Chain accounts have no agreed-upon DID form yet
/// (did:pkh is not wired through name-client), so they are omitted rather
/// than leaking the internal principal encoding.
/// TODO: define a DID form for chain-account owners.
fn principal_did_string(principal: &Principal) -> Option<String> {
    match principal.kind {
        PrincipalKind::BnsName => did_bns_from_name(&principal.value).ok(),
        PrincipalKind::ChainAccount | PrincipalKind::Unset => None,
    }
}

/// Protocol §5 NotApplicable: reuse 404 but omit `buckyos.documentStatus`,
/// so clients map the answer to "no opinion" instead of the strong Missing.
fn did_resolution_not_applicable_response() -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    did_resolution_json_response(
        StatusCode::NOT_FOUND,
        &json!({
            "didResolutionMetadata": { "contentType": Value::Null, "error": "notApplicable" },
            "didDocument": Value::Null,
            "didDocumentMetadata": {},
        }),
    )
}

fn did_resolution_error_response(
    status: StatusCode,
    error: &str,
    message: &str,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    did_resolution_json_response(
        status,
        &json!({
            "didResolutionMetadata": {
                "contentType": Value::Null,
                "error": error,
                "errorMessage": message,
            },
            "didDocument": Value::Null,
            "didDocumentMetadata": {},
        }),
    )
}

fn did_resolution_json_response(
    status: StatusCode,
    envelope: &Value,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    let body = serde_json::to_vec(envelope).map_err(|e| {
        server_err!(
            ServerErrorCode::EncodeError,
            "failed to encode DID resolution result: {}",
            e
        )
    })?;
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, DID_RESOLUTION_CONTENT_TYPE)
        // Protocol §2: the resolver controls cache TTL so a stale 200/404 can
        // never outlive a later Revoked/Tombstoned verdict. 200/404/410 are
        // all heuristically cacheable by default (RFC 9111), so opt out
        // entirely until a validator-based story exists.
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full_body(body.into()))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::EncodeError,
                "failed to build DID resolution response: {}",
                e
            )
        })?;
    add_cors_headers(response.headers_mut());
    Ok(response)
}

fn normalize_rpc_path(path: String) -> String {
    let trimmed = path.trim_end_matches('/');
    let normalized = if trimmed.is_empty() {
        BNS_INDEXER_RPC_PATH.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    if normalized == "/" {
        BNS_INDEXER_RPC_PATH.to_string()
    } else {
        normalized
    }
}

fn response_with_cors(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    let mut response = Response::builder()
        .status(status)
        .body(full_body(body.into()))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::EncodeError,
                "failed to build bns-indexer response: {}",
                e
            )
        })?;
    add_cors_headers(response.headers_mut());
    Ok(response)
}

fn full_body(body: Bytes) -> UnsyncBoxBody<Bytes, ServerError> {
    Full::new(body).map_err(|never| match never {}).boxed_unsync()
}

fn add_cors_headers(headers: &mut http::HeaderMap) {
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
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

fn projection_query_name_state(
    tx: &mut dyn BnsRegistryStoreTx,
    name: &str,
) -> BnsRegistryResult<Option<NameState>> {
    let name = canonical_bns_name(name)?;
    tx.get_name(&name)?
        .map(|state| projection_materialize_name_state(tx, state))
        .transpose()
}

fn projection_resolve_owner(
    tx: &mut dyn BnsRegistryStoreTx,
    name: &str,
) -> BnsRegistryResult<OwnerResolution> {
    let name = canonical_bns_name(name)?;
    let state = tx
        .get_name(&name)?
        .ok_or_else(|| BnsRegistryError::NameNotFound { name })?;
    projection_resolve_owner_from_state(tx, &state)
}

fn projection_resolve_document(
    tx: &mut dyn BnsRegistryStoreTx,
    name: &str,
    doc_type: &str,
) -> BnsRegistryResult<ResolveResult> {
    let name = canonical_bns_name(name)?;
    let doc_type = canonical_doc_type(doc_type)?;
    let raw_name_state = tx
        .get_name(&name)?
        .ok_or_else(|| BnsRegistryError::NameNotFound { name: name.clone() })?;
    let name_state = projection_materialize_name_state(tx, raw_name_state)?;
    let document_state = tx.get_current_document(&name, &doc_type)?.ok_or_else(|| {
        BnsRegistryError::DocumentNotFound {
            name: name.clone(),
            doc_type: doc_type.clone(),
        }
    })?;
    let owner = projection_resolve_owner_from_state(tx, &name_state)?;
    let alias = tx.get_alias(&name)?;
    let proof_root = projection_current_proof_root(tx)?;
    let effective_controller = if document_state.controller.is_unset() {
        owner.effective_owner.clone()
    } else {
        document_state.controller.clone()
    };

    Ok(ResolveResult {
        status: document_state.status,
        alias_kind: alias.as_ref().map_or(AliasKind::None, |state| state.kind),
        alias_target_did: alias.map_or_else(String::new, |state| state.target_did),
        name_state,
        document_state,
        owner,
        effective_controller,
        proof_root,
    })
}

fn projection_materialize_name_state(
    tx: &mut dyn BnsRegistryStoreTx,
    mut state: NameState,
) -> BnsRegistryResult<NameState> {
    let owner = projection_resolve_owner_from_state(tx, &state)?;
    state.effective_owner = owner.effective_owner;
    state.owner_source = owner.source;
    state.standard_transfer_enabled = state.transferable
        && state.status == NameStatus::Active
        && owner.source == OwnerSource::AssetOwnerFallback;
    Ok(state)
}

fn projection_resolve_owner_from_state(
    tx: &mut dyn BnsRegistryStoreTx,
    state: &NameState,
) -> BnsRegistryResult<OwnerResolution> {
    if state.semantic_owner.kind == PrincipalKind::BnsName {
        let authority = projection_authority_set(tx, &state.semantic_owner.value)?;
        return Ok(OwnerResolution {
            effective_owner: state.semantic_owner.clone(),
            source: OwnerSource::ExplicitSemanticOwner,
            authority_root: authority.authority_root,
            authority_seq: authority.authority_seq,
        });
    }

    if is_top_level_name(&state.name) {
        let authority = projection_authority_set(tx, &state.name)?;
        return Ok(OwnerResolution {
            effective_owner: Principal::chain_account(state.asset_owner.clone()),
            source: OwnerSource::AssetOwnerFallback,
            authority_root: authority.authority_root,
            authority_seq: authority.authority_seq,
        });
    }

    let parent = parent_name(&state.name).ok_or_else(|| {
        BnsRegistryError::InvalidMutation("second-level name has no parent".to_string())
    })?;
    let parent_state = tx
        .get_name(parent)?
        .ok_or_else(|| BnsRegistryError::NameNotFound {
            name: parent.to_string(),
        })?;
    let mut owner = projection_resolve_owner_from_state(tx, &parent_state)?;
    owner.source = OwnerSource::ParentInherited;
    Ok(owner)
}

fn projection_authority_set(
    tx: &mut dyn BnsRegistryStoreTx,
    name: &str,
) -> BnsRegistryResult<AuthoritySetState> {
    Ok(tx
        .get_authority_set(name)?
        .unwrap_or_else(|| AuthoritySetState::empty(name)))
}

fn projection_current_proof_root(tx: &mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<String> {
    Ok(tx
        .latest_event()?
        .map_or_else(|| ZERO_HASH.to_string(), |record| record.log_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bns_client::{
        BnsIndexerApi, BnsNameReq, BnsRpcEnvelope, BnsSubmitRawTxReq, METHOD_QUERY_NAME_STATE,
    };
    use bns_indexer::{
        CallAuthority, DocumentRef, DocumentStatus, MutationGuard, NameStatus, RegisterOptions,
    };
    use http::{Request, StatusCode};
    use kRPC::{RPCErrors, RPCRequest, RPCResult};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TX_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[tokio::test]
    async fn normalizes_configured_rpc_path() {
        let server = SqliteBnsIndexerHttpServer::open_memory()
            .unwrap()
            .config()
            .clone()
            .with_rpc_path("kapi/custom/");
        assert_eq!(server.rpc_path, "/kapi/custom");
    }

    #[tokio::test]
    async fn rejects_non_bns_indexer_paths() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/wrong")
            .body(full_body(Bytes::new()))
            .unwrap();

        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:1".to_string()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bns_indexer_rpc_rejects_legacy_writes() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let error = server
            .handle_rpc_call(
                RPCRequest::new("name.register", serde_json::json!({})),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, RPCErrors::UnknownMethod(method) if method == "name.register"));
    }

    #[tokio::test]
    async fn wraps_registry_errors_in_successful_rpc_envelope() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let rpc_req = RPCRequest::new(
            METHOD_QUERY_NAME_STATE,
            serde_json::to_value(BnsNameReq::new("not..valid")).unwrap(),
        );

        let response = server
            .handle_rpc_call(rpc_req, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let value = match response.result {
            RPCResult::Success(value) => value,
            RPCResult::Failed(error) => panic!("unexpected rpc failure: {error}"),
        };
        let envelope: BnsRpcEnvelope<Option<serde_json::Value>> =
            serde_json::from_value(value).unwrap();

        assert!(!envelope.ok);
        assert_eq!(
            envelope.error.unwrap().code,
            bns_indexer::BnsRegistryError::InvalidName {
                name: "not..valid".to_string(),
                reason: String::new(),
            }
            .code()
        );
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let server = SqliteBnsIndexerHttpServer::open_memory().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(full_body(Bytes::new()))
            .unwrap();

        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:1".to_string()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn contract_server_defaults_to_bns_rpc_path() {
        let server =
            SqliteBnsServerHttpServer::open_memory_contract("http://127.0.0.1:8545").unwrap();
        assert_eq!(server.rpc_path(), BNS_SERVER_RPC_PATH);
    }

    #[tokio::test]
    async fn contract_server_reads_projection() {
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

        let handler = BnsContractServerHandler::new(store, "http://127.0.0.1:8545");
        let state = handler.query_name_state("alice").await.unwrap().unwrap();
        assert_eq!(state.name, "alice");
        assert_eq!(state.effective_owner, Principal::chain_account(OWNER));

        let resolved = handler.resolve_document("alice", "owner").await.unwrap();
        assert_eq!(
            resolved.owner.effective_owner,
            Principal::chain_account(OWNER)
        );
        assert_eq!(resolved.document_state.version, 1);
        assert_eq!(resolved.proof_root, ZERO_HASH);
    }

    #[tokio::test]
    async fn contract_server_forwards_signed_raw_tx() {
        let endpoint = spawn_eth_rpc_stub("0x02abcd").await;
        let handler =
            BnsContractServerHandler::new(SqliteBnsRegistryStore::open_memory().unwrap(), endpoint);

        let response = handler
            .submit_raw_tx(BnsSubmitRawTxReq::from_hex("0x02abcd"))
            .await
            .unwrap();

        assert_eq!(response.tx_hash, TX_HASH);
    }

    #[tokio::test]
    async fn contract_server_rpc_does_not_dispatch_legacy_write_methods() {
        let server =
            SqliteBnsServerHttpServer::open_memory_contract("http://127.0.0.1:8545").unwrap();
        let rpc_req = RPCRequest::new("name.register", serde_json::json!({}));

        let error = server
            .handle_rpc_call(rpc_req, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(error, RPCErrors::UnknownMethod(method) if method == "name.register"));
    }

    #[test]
    fn constructs_server_from_existing_registry() {
        let registry = Arc::new(CentralizedBnsRegistry::new_legacy_state_machine(
            SqliteBnsRegistryStore::open_memory().unwrap(),
        ));
        registry
            .register_name(
                "bob",
                OWNER,
                RegisterOptions::default(),
                vec![],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();

        let server = SqliteBnsIndexerHttpServer::from_registry(registry.clone());
        assert_eq!(server.id(), "bns-indexer");
        assert_eq!(
            registry.resolve_owner("bob").unwrap().effective_owner,
            Principal::chain_account(OWNER)
        );
    }

    async fn spawn_eth_rpc_stub(expected_raw_tx: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.contains("eth_sendRawTransaction"));
            assert!(request.contains(expected_raw_tx));

            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{TX_HASH}"}}"#);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{}", addr)
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

    // ---- DID resolver HTTP binding (doc/http_did_resolver_api.md) ----

    const FAR_FUTURE: u64 = 4102444800; // 2100-01-01

    fn resolver_name_state(name: &str, status: NameStatus) -> NameState {
        NameState {
            name: name.to_string(),
            asset_owner: OWNER.to_string(),
            semantic_owner: Principal::unset(),
            effective_owner: Principal::chain_account(OWNER),
            owner_source: OwnerSource::AssetOwnerFallback,
            standard_transfer_enabled: true,
            status,
            registered_at: 1,
            expire_at: FAR_FUTURE,
            grace_until: FAR_FUTURE + 100,
            updated_at: 2,
            name_seq: 1,
            owner_document_version: 0,
            min_document_iat: 0,
            owner_policy_seq: 0,
            lineage_epoch: 1,
            renewable: true,
            transferable: true,
            allow_delegated_subnames: false,
            namespace_policy_hash: ZERO_HASH.to_string(),
            payment_policy_hash: ZERO_HASH.to_string(),
            alias_state_hash: ZERO_HASH.to_string(),
        }
    }

    fn resolver_document_state(
        name: &str,
        doc_type: &str,
        version: u64,
        status: DocumentStatus,
        content: &[u8],
    ) -> DocumentState {
        DocumentState {
            name: name.to_string(),
            doc_type: doc_type.to_string(),
            version,
            previous_version: 0,
            status,
            document: DocumentRef::inline(content),
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
        }
    }

    fn resolver_seeded_store() -> SqliteBnsRegistryStore {
        let store = SqliteBnsRegistryStore::open_memory().unwrap();
        store
            .transact(|tx| {
                // alice: active name with several document states.
                tx.put_name(&resolver_name_state("alice", NameStatus::Active))?;
                let mut owner_doc = resolver_document_state(
                    "alice",
                    "owner",
                    3,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:alice"}"#,
                );
                owner_doc.previous_version = 2;
                tx.put_document(&owner_doc)?;
                tx.put_document(&resolver_document_state(
                    "alice",
                    "zone",
                    7,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:alice","oods":["ood1"]}"#,
                ))?;
                tx.put_document(&resolver_document_state(
                    "alice",
                    "profile",
                    1,
                    DocumentStatus::Revoked,
                    br#"{"id":"did:bns:alice"}"#,
                ))?;
                let mut lapsed_doc = resolver_document_state(
                    "alice",
                    "old",
                    2,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:alice"}"#,
                );
                lapsed_doc.expire_at = 1;
                tx.put_document(&lapsed_doc)?;
                tx.put_document(&resolver_document_state(
                    "alice",
                    "jwt-doc",
                    1,
                    DocumentStatus::Active,
                    b"eyJhbGciOiJFZERTQSJ9.eyJpZCI6ImRpZDpibnM6YWxpY2UifQ.c2ln",
                ))?;

                // team: semantic owner points at the alice BNS name.
                let mut team = resolver_name_state("team", NameStatus::Active);
                team.semantic_owner = Principal::bns_name("alice")?;
                tx.put_name(&team)?;
                tx.put_document(&resolver_document_state(
                    "team",
                    "zone",
                    1,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:team"}"#,
                ))?;

                // gone: tombstoned name whose documents must report tombstoned.
                tx.put_name(&resolver_name_state("gone", NameStatus::Tombstoned))?;
                tx.put_document(&resolver_document_state(
                    "gone",
                    "zone",
                    1,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:gone"}"#,
                ))?;

                // moved: active documents behind a MigratedTo alias.
                tx.put_name(&resolver_name_state("moved", NameStatus::Active))?;
                tx.put_document(&resolver_document_state(
                    "moved",
                    "zone",
                    1,
                    DocumentStatus::Active,
                    br#"{"id":"did:bns:moved"}"#,
                ))?;
                tx.put_alias(&bns_indexer::AliasState {
                    name: "moved".to_string(),
                    kind: AliasKind::MigratedTo,
                    target_did: "did:bns:alice".to_string(),
                    proof_hash: ZERO_HASH.to_string(),
                    set_at: 1,
                    name_seq: 1,
                })?;
                Ok(())
            })
            .unwrap();
        store
    }

    fn resolver_contract_server() -> SqliteBnsServerHttpServer {
        BnsContractHttpServer::from_contract_store(resolver_seeded_store(), "http://127.0.0.1:1")
    }

    fn resolver_indexer_server() -> SqliteBnsIndexerHttpServer {
        let registry = Arc::new(CentralizedBnsRegistry::new(resolver_seeded_store()));
        SqliteBnsIndexerHttpServer::from_registry(registry)
    }

    async fn resolver_request<S: HttpServer>(
        server: &S,
        method: Method,
        uri: &str,
    ) -> (StatusCode, Value, http::HeaderMap) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(full_body(Bytes::new()))
            .unwrap();
        let response = server
            .serve_request(request, StreamInfo::new("127.0.0.1:1".to_string()))
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (parts.status, value, parts.headers)
    }

    #[tokio::test]
    async fn did_resolver_returns_active_owner_document() {
        let server = resolver_contract_server();
        let (status, body, headers) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=owner",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/did-resolution+json"
        );
        // Protocol §2: stale answers must not survive in caches past a
        // revocation, so every resolver response opts out of caching.
        assert_eq!(
            headers.get(http::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(headers.contains_key(http::header::ACCESS_CONTROL_ALLOW_ORIGIN));

        assert_eq!(
            body["didResolutionMetadata"]["contentType"],
            "application/did+ld+json"
        );
        assert_eq!(body["didDocument"]["id"], "did:bns:alice");
        let metadata = &body["didDocumentMetadata"];
        assert_eq!(metadata["versionId"], "3");
        assert_eq!(metadata["deactivated"], false);
        let buckyos = &metadata["buckyos"];
        assert_eq!(buckyos["docType"], "owner");
        assert_eq!(buckyos["documentStatus"], "active");
        assert_eq!(buckyos["documentVersion"], 3);
        assert_eq!(buckyos["authoritySeq"], 0);
        // Chain-account owners have no DID form yet: the field must be
        // omitted, never serialized as the internal principal JSON.
        assert!(buckyos.get("effectiveOwner").is_none());
        // Old-draft fields were dropped from the trimmed protocol and must
        // stay off the wire.
        for legacy in [
            "previousVersion",
            "lineageEpoch",
            "ownerSource",
            "authorityRoot",
        ] {
            assert!(buckyos.get(legacy).is_none(), "legacy field {legacy}");
        }
        for legacy in ["nextVersionId", "canonicalId", "equivalentId"] {
            assert!(metadata.get(legacy).is_none(), "legacy field {legacy}");
        }
    }

    #[tokio::test]
    async fn did_resolver_defaults_to_zone_doc_type() {
        let server = resolver_contract_server();
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:alice").await;

        assert_eq!(status, StatusCode::OK);
        let buckyos = &body["didDocumentMetadata"]["buckyos"];
        assert_eq!(buckyos["docType"], "zone");
        assert_eq!(buckyos["documentVersion"], 7);
        assert_eq!(body["didDocument"]["oods"][0], "ood1");
    }

    #[tokio::test]
    async fn did_resolver_missing_document_is_authoritative_missing() {
        let server = resolver_contract_server();

        // Name exists but the doc_type was never published (DocumentNotFound).
        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=boot",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "missing"
        );
        assert_eq!(body["didDocumentMetadata"]["deactivated"], false);

        // Name never registered at all (NameNotFound) is also authoritative.
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:ghost").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "missing"
        );
    }

    #[tokio::test]
    async fn did_resolver_revoked_and_tombstoned_return_410_deactivated() {
        let server = resolver_contract_server();

        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=profile",
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "revoked"
        );
        assert_eq!(body["didDocumentMetadata"]["deactivated"], true);
        assert!(body["didDocument"].is_null());

        // Tombstoned name overrides the stored per-document status.
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:gone").await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "tombstoned"
        );
        assert_eq!(body["didDocumentMetadata"]["deactivated"], true);

        // ...including doc_types that were never published under it: the
        // DocumentNotFound projection error must not downgrade the destroyed
        // name to a 404 Missing that a later publish could overturn.
        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:gone?type=boot",
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "tombstoned"
        );
        assert_eq!(body["didDocumentMetadata"]["deactivated"], true);
    }

    #[tokio::test]
    async fn did_resolver_non_bns_did_is_not_applicable() {
        let server = resolver_contract_server();
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:web:example.com").await;

        // Protocol §5 NotApplicable: 404 without `buckyos.documentStatus`,
        // which `BaseHttpProvider::parse_published_state_body` maps to Ok(None).
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_object());
        assert!(body["didDocumentMetadata"].get("buckyos").is_none());
    }

    #[tokio::test]
    async fn did_resolver_historical_owner_query_returns_501() {
        let server = resolver_contract_server();
        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=owner&iat=1750000000",
        )
        .await;

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["historicalQuerySupported"],
            false
        );
        assert!(body["didDocumentMetadata"]["buckyos"]
            .get("documentStatus")
            .is_none());
    }

    #[tokio::test]
    async fn did_resolver_maps_bns_semantic_owner_to_did() {
        let server = resolver_contract_server();
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:team").await;

        assert_eq!(status, StatusCode::OK);
        let buckyos = &body["didDocumentMetadata"]["buckyos"];
        assert_eq!(buckyos["effectiveOwner"], "did:bns:alice");
    }

    #[tokio::test]
    async fn did_resolver_reports_migrated_with_target() {
        let server = resolver_contract_server();
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:moved").await;

        assert_eq!(status, StatusCode::OK);
        let buckyos = &body["didDocumentMetadata"]["buckyos"];
        assert_eq!(buckyos["documentStatus"], "migrated");
        assert_eq!(buckyos["migrationTarget"], "did:bns:alice");
    }

    #[tokio::test]
    async fn did_resolver_reports_expired_document() {
        let server = resolver_contract_server();
        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=old",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "expired"
        );
        // Expired still returns the last known content for policy fallback.
        assert_eq!(body["didDocument"]["id"], "did:bns:alice");
    }

    #[tokio::test]
    async fn did_resolver_serves_jwt_documents_as_string() {
        let server = resolver_contract_server();
        let (status, body, _) = resolver_request(
            &server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=jwt-doc",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["didResolutionMetadata"]["contentType"],
            "application/did+jwt"
        );
        assert!(body["didDocument"].is_string());
    }

    #[tokio::test]
    async fn did_resolver_rejects_malformed_did_and_query() {
        let server = resolver_contract_server();

        for uri in [
            "/1.0/identifiers/not-a-did",
            "/1.0/identifiers/did:bns:INVALID",
            "/1.0/identifiers/did:bns:alice?type=NotAType",
            "/1.0/identifiers/did:bns:alice?type=owner&iat=abc",
        ] {
            let (status, body, _) = resolver_request(&server, Method::GET, uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "uri {uri}");
            // Malformed requests must not carry an authoritative negative state.
            assert!(body["didDocumentMetadata"].get("buckyos").is_none());
        }
    }

    /// Stub API whose read path fails like a broken upstream dependency.
    struct FailingResolverApi;

    #[async_trait]
    impl BnsIndexerApi for FailingResolverApi {
        async fn query_name_state(&self, _name: &str) -> BnsClientResult<Option<NameState>> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn resolve_owner(&self, _name: &str) -> BnsClientResult<OwnerResolution> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn get_authority_set(&self, _name: &str) -> BnsClientResult<AuthoritySetState> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn get_authority_key(
            &self,
            _name: &str,
            _kid: &str,
        ) -> BnsClientResult<Option<AuthorityKey>> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn resolve_document(
            &self,
            _name: &str,
            _doc_type: &str,
        ) -> BnsClientResult<ResolveResult> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn get_document_version(
            &self,
            _name: &str,
            _doc_type: &str,
            _version: u64,
        ) -> BnsClientResult<Option<DocumentState>> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn list_events(
            &self,
            _from_seq: u64,
            _limit: usize,
        ) -> BnsClientResult<Vec<EventLogRecord>> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
        async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
            Err(BnsClientError::Transport("indexer down".to_string()))
        }
    }

    #[tokio::test]
    async fn did_resolver_dependency_failure_is_5xx_not_missing() {
        // Protocol §5's hardest rule: an unavailable upstream must never be
        // presented as an authoritative negative state (missing/revoked).
        let server = BnsContractHttpServer::new(FailingResolverApi);
        let (status, body, _) =
            resolver_request(&server, Method::GET, "/1.0/identifiers/did:bns:alice").await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["didDocumentMetadata"].get("buckyos").is_none());
    }

    #[tokio::test]
    async fn did_resolver_options_and_indexer_server_route() {
        // OPTIONS preflight mirrors the RPC endpoints (CORS + 204).
        let contract_server = resolver_contract_server();
        let (status, _, headers) = resolver_request(
            &contract_server,
            Method::OPTIONS,
            "/1.0/identifiers/did:bns:alice",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(headers.contains_key(http::header::ACCESS_CONTROL_ALLOW_ORIGIN));

        // The indexer flavour of the server exposes the same binding.
        let indexer_server = resolver_indexer_server();
        let (status, body, _) = resolver_request(
            &indexer_server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=owner",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "active"
        );

        // The registry path reports never-published docs as status=Missing
        // instead of an error; both must surface the same 404 verdict.
        let (status, body, _) = resolver_request(
            &indexer_server,
            Method::GET,
            "/1.0/identifiers/did:bns:alice?type=boot",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "missing"
        );

        // ...and both flavours answer tombstoned for unpublished doc_types
        // under a destroyed name (the contract flavour reaches it through the
        // DocumentNotFound error path, the registry flavour through the
        // Missing placeholder + name-status override).
        let (status, body, _) = resolver_request(
            &indexer_server,
            Method::GET,
            "/1.0/identifiers/did:bns:gone?type=boot",
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "tombstoned"
        );
    }
}
