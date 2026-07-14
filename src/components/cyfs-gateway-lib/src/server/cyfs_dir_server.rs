//! `CyfsDirServer` — a cyfs-gateway server that serves `cyfs://` (R-Link /
//! O-Link) requests against a [`NamedDataMgr`] store.
//!
//! Differences vs. the plain `dir` server:
//! - The store is a `NamedDataMgr` (not a filesystem). Chunks and named
//!   objects are addressed by `ObjId`.
//! - A process-chain runs **before** the request is dispatched to the inner
//!   serving pipeline. The chain's job is to produce the `.cyobj` *meta* for
//!   the requested semantic path — i.e. resolve a path → `ObjId` mapping
//!   without ever touching the filesystem. Once the meta is known, downstream
//!   serving (chunk streaming, inner-path walking, cyfs-* response headers)
//!   is delegated to an inner [`NdnDirServer`].
//! - With a fully-populated chain rule set, no on-disk semantic root is
//!   required: all routing comes from the chain.
//!
//! # Process-chain contract
//!
//! The chain is given the standard HTTP `REQ` map (path, method, headers,
//! …). It can resolve the path in two equivalent ways:
//!
//! 1. **Set the env variable `RESP_cyobj_meta`** to a JSON string
//!    representing a `SidecarRecord` (the on-disk shape of a `<name>.cyobj`
//!    file). The named object inside the meta is `put_object`'d into the
//!    store on the fly so that the obj_id resolves on the inner pipeline.
//! 2. **Set `RESP_cyobj_id`** to a bare `ObjId` string. The object must
//!    already be present in the store.
//!
//! When neither variable is set, the server falls back to filesystem-based
//! resolution against `semantic_root` (if configured) — exactly the
//! behavior of `NdnDirServer` on its own.
//!
//! Standard control flow (`drop`, `reject`, `error`, `redirect`) works the
//! same way as in `ProcessChainHttpServer`.
//!
//! Future work: `.cyobj` is expected to grow permission/ACL fields. Those
//! land in `ndn-toolkit` first; this server picks them up automatically once
//! `NdnDirServer` honors them.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use buckyos_http_server as bucky_http;
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainLibExecutor};
use http::{Request, Response, StatusCode};
use http_body_util::{
    BodyExt, Full,
    combinators::{BoxBody, UnsyncBoxBody},
};
use hyper::body::Bytes;
use jsonwebtoken::EncodingKey;
use log::{debug, warn};
use named_store::NamedDataMgr;
use ndn_lib::ObjId;
use ndn_toolkit::{NdnDirServer, NdnDirServerConfig, NdnDirServerMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::global_process_chains::{GlobalProcessChainsRef, create_process_chain_executor};
use crate::{
    GlobalCollectionManagerRef, HttpRequestHeaderMap, JsExternalsManagerRef, ProcessChainConfigs,
    HttpServer, Server, ServerConfig, ServerContext, ServerContextRef, ServerError,
    ServerErrorCode, ServerFactory, ServerManagerWeakRef, ServerResult, StreamInfo,
    RequestSourceInfo, get_external_commands, into_server_err, server_err,
};

const ENV_KEY_CYOBJ_META: &str = "RESP_cyobj_meta";
const ENV_KEY_CYOBJ_ID: &str = "RESP_cyobj_id";
const INNER_PATH_DELIMITER: &str = "/@/";

// =====================================================================
// Config
// =====================================================================

/// Mirrors the on-disk `<name>.cyobj` sidecar produced by `NdnDirServer`.
/// Only the fields the chain needs to populate are accepted; the rest are
/// optional so chains can omit fields like `source_qcid`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct SidecarRecord {
    pub obj_type: String,
    pub obj_id: String,
    pub obj_json: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_obj_jwt: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsDirServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,

    /// Path to the `NamedDataMgr` store layout config file.
    pub named_store_config_path: String,

    /// HTTP proxy/backend URL for each remote storage node. Keys are the
    /// store entry's `device_did`; values are the HTTP base URL of that
    /// node (e.g. `http://10.0.0.5:8080/ndn`). Stores whose `device_did`
    /// is absent from this map are treated as local; stores listed here
    /// are routed through `NamedStoreHttpBackend` so reads *and* writes
    /// hit the remote node over HTTP. Passed through verbatim to
    /// `NamedDataMgr::get_store_mgr`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub http_backend_links: HashMap<String, String>,

    /// PEM-encoded ed25519 private key used to mint `PathObject` JWTs for
    /// auto-objectified files. When absent the server still works but
    /// R-Link responses in filesystem mode lack `cyfs-path-obj`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_kid: Option<String>,

    /// Filesystem semantic root for fallback R-Link resolution. When
    /// omitted, the server is purely process-chain-driven and no on-disk
    /// content is served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_root: Option<String>,

    /// URL prefix to strip before resolving (e.g. `"/ndn"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url_prefix: String,

    /// Recognize an `ObjId` in the leading hostname label.
    #[serde(default)]
    pub obj_id_in_host: bool,

    /// Persistence mode for the inner scanner — only relevant when
    /// `semantic_root` is set. Values: `local-link` (default), `in-store`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Auto-objectification scan interval in seconds. `0` disables the
    /// scanner. Default `60`.
    #[serde(default = "default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// Optional process-chain configs. When present, the chain runs before
    /// every request and may resolve the semantic path → `.cyobj` meta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_point: Option<ProcessChainConfigs>,
}

fn default_scan_interval_secs() -> u64 {
    60
}

impl ServerConfig for CyfsDirServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn server_type(&self) -> String {
        "cyfs-dir".to_string()
    }
    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// =====================================================================
// Context (shared per gateway instance, like HttpServerContext)
// =====================================================================

#[derive(Clone)]
pub struct CyfsDirServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub global_collection_manager: GlobalCollectionManagerRef,
}

impl CyfsDirServerContext {
    pub fn new(
        server_mgr: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        global_collection_manager: GlobalCollectionManagerRef,
    ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            js_externals,
            global_collection_manager,
        }
    }
}

impl ServerContext for CyfsDirServerContext {
    fn get_server_type(&self) -> String {
        "cyfs-dir".to_string()
    }
}

// =====================================================================
// Server
// =====================================================================

pub struct CyfsDirServer {
    id: String,
    store_mgr: Arc<NamedDataMgr>,
    inner: Arc<NdnDirServer>,
    /// Process-chain executor. Forked per request (same pattern as
    /// [`ProcessChainHttpServer`]).
    executor: Option<Arc<Mutex<ProcessChainLibExecutor>>>,
    url_prefix: String,
}

impl CyfsDirServer {
    pub fn store_mgr(&self) -> &Arc<NamedDataMgr> {
        &self.store_mgr
    }

    pub fn inner(&self) -> &Arc<NdnDirServer> {
        &self.inner
    }

    /// Run the process chain against the request. Returns either a resolved
    /// `.cyobj` meta (if the chain populated `RESP_cyobj_meta` /
    /// `RESP_cyobj_id`), an early HTTP response (drop/reject/error), or
    /// `None` to indicate the server should fall through to the inner
    /// filesystem-backed pipeline.
    async fn run_chain(
        &self,
        req: Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: &StreamInfo,
    ) -> ServerResult<ChainOutcome> {
        let executor = match self.executor.as_ref() {
            Some(e) => e,
            None => return Ok(ChainOutcome::PassThrough(req)),
        };

        let executor = { executor.lock().unwrap().fork() };
        // Clone the env Arc so it survives `execute_lib`, which consumes
        // the executor. We need to read response variables out of it after
        // the chain runs.
        let global_env = executor.global_env().clone();

        let req_map =
            HttpRequestHeaderMap::new_with_sources(req, RequestSourceInfo::from_stream_info(info));
        req_map
            .register_visitors(&global_env)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = executor
            .execute_lib()
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        if ret.is_control() {
            if ret.is_drop() {
                debug!("cyfs-dir-server {}: chain dropped request", self.id);
                return Ok(ChainOutcome::Response(empty_response(StatusCode::OK)));
            }
            if ret.is_reject() {
                return Ok(ChainOutcome::Response(empty_response(
                    StatusCode::FORBIDDEN,
                )));
            }
            if let Some(CommandControl::Error(e)) = ret.as_control() {
                let msg = e.value.to_string();
                let mut resp = Response::new(full_body(Bytes::from(msg)));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(ChainOutcome::Response(resp));
            }
            if let Some(CommandControl::Return(_)) = ret.as_control() {
                // Return values aren't used as routing directives here; the
                // chain communicates resolution via env variables instead.
            }
        }

        // Pull `RESP_cyobj_meta` / `RESP_cyobj_id` out before unwrapping
        // the request map, so we can drop the env reference cleanly.
        let meta_value = global_env
            .get(ENV_KEY_CYOBJ_META)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        let id_value = global_env
            .get(ENV_KEY_CYOBJ_ID)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        // Release our env handle so the visitor entries inside it drop
        // their request-map clones; otherwise `into_request`'s
        // `Arc::try_unwrap` would fail.
        drop(global_env);

        let req = req_map
            .into_request()
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        if let Some(CollectionValue::String(meta_json)) = meta_value {
            let record: SidecarRecord = serde_json::from_str(&meta_json).map_err(|e| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "RESP_cyobj_meta is not a valid SidecarRecord JSON: {}",
                    e
                )
            })?;

            // Make sure the object is present in the store before delegating
            // to the inner O-Link pipeline. `put_object` is idempotent for a
            // matching obj_id.
            let obj_id = ObjId::new(&record.obj_id).map_err(|e| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "RESP_cyobj_meta has invalid obj_id {}: {}",
                    record.obj_id,
                    e
                )
            })?;
            let obj_str = serde_json::to_string(&record.obj_json).map_err(|e| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "serialize obj_json failed: {}",
                    e
                )
            })?;
            if let Err(e) = self.store_mgr.put_object(&obj_id, &obj_str).await {
                // Log and continue — the object may already be present, in
                // which case `get_object` on the inner pipeline still works.
                debug!(
                    "cyfs-dir-server {}: put_object {} returned {} (likely already present)",
                    self.id, obj_id, e
                );
            }

            return Ok(ChainOutcome::Resolved(rewrite_to_o_link(
                req,
                &record.obj_id,
                &self.url_prefix,
            )));
        }

        if let Some(CollectionValue::String(obj_id)) = id_value {
            return Ok(ChainOutcome::Resolved(rewrite_to_o_link(
                req,
                &obj_id,
                &self.url_prefix,
            )));
        }

        Ok(ChainOutcome::PassThrough(req))
    }
}

#[async_trait::async_trait(?Send)]
impl HttpServer for CyfsDirServer {
    async fn serve_request(
        &self,
        req: Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> Result<Response<UnsyncBoxBody<Bytes, ServerError>>, ServerError> {
        let req = match self.run_chain(req, &info).await {
            Ok(ChainOutcome::Response(resp)) => return Ok(resp),
            Ok(ChainOutcome::Resolved(req)) | Ok(ChainOutcome::PassThrough(req)) => req,
            Err(e) => {
                warn!("cyfs-dir-server {}: chain failed: {}", self.id, e);
                let mut resp = Response::new(full_body(Bytes::from(e.to_string())));
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp);
            }
        };

        // NdnDirServer is provided by ndn-toolkit and still implements the
        // upstream buckyos_http_server::HttpServer trait. Keep the gateway
        // public surface on the local trait and adapt only at this boundary.
        let (parts, body) = req.into_parts();
        let body = body.collect().await?.to_bytes();
        let req: Request<BoxBody<Bytes, bucky_http::ServerError>> = Request::from_parts(
            parts,
            Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        );
        let resp = bucky_http::HttpServer::serve_request(
            self.inner.as_ref(),
            req,
            to_bucky_stream_info(info),
        )
        .await
        .map_err(from_bucky_server_error)?;

        Ok(resp.map(|body| body.map_err(from_bucky_server_error).boxed_unsync()))
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> http::Version {
        bucky_http::HttpServer::http_version(self.inner.as_ref())
    }

    fn http3_port(&self) -> Option<u16> {
        bucky_http::HttpServer::http3_port(self.inner.as_ref())
    }
}

fn to_bucky_stream_info(info: StreamInfo) -> bucky_http::StreamInfo {
    bucky_http::StreamInfo {
        src_addr: info.src_addr,
        dst_addr: info.dst_addr,
        conn_src_addr: info.conn_src_addr,
        real_src_addr: info.real_src_addr,
        source_mac: info.source_mac,
        source_hostname: info.source_hostname,
        source_online_secs: info.source_online_secs,
    }
}

fn to_bucky_server_error(err: ServerError) -> bucky_http::ServerError {
    bucky_http::ServerError::new(to_bucky_error_code(err.code()), err.msg().to_string())
}

fn from_bucky_server_error(err: bucky_http::ServerError) -> ServerError {
    ServerError::new(from_bucky_error_code(err.code()), err.msg().to_string())
}

fn to_bucky_error_code(code: ServerErrorCode) -> bucky_http::ServerErrorCode {
    match code {
        ServerErrorCode::BindFailed => bucky_http::ServerErrorCode::BindFailed,
        ServerErrorCode::NotFound => bucky_http::ServerErrorCode::NotFound,
        ServerErrorCode::InvalidConfig => bucky_http::ServerErrorCode::InvalidConfig,
        ServerErrorCode::InvalidParam => bucky_http::ServerErrorCode::InvalidParam,
        ServerErrorCode::ProcessChainError => bucky_http::ServerErrorCode::ProcessChainError,
        ServerErrorCode::StreamError => bucky_http::ServerErrorCode::StreamError,
        ServerErrorCode::TunnelError => bucky_http::ServerErrorCode::TunnelError,
        ServerErrorCode::InvalidTlsKey => bucky_http::ServerErrorCode::InvalidTlsKey,
        ServerErrorCode::InvalidTlsCert => bucky_http::ServerErrorCode::InvalidTlsCert,
        ServerErrorCode::InvalidData => bucky_http::ServerErrorCode::InvalidData,
        ServerErrorCode::IOError => bucky_http::ServerErrorCode::IOError,
        ServerErrorCode::BadRequest => bucky_http::ServerErrorCode::BadRequest,
        ServerErrorCode::UnknownServerType => bucky_http::ServerErrorCode::UnknownServerType,
        ServerErrorCode::EncodeError => bucky_http::ServerErrorCode::EncodeError,
        ServerErrorCode::DnsQueryError => bucky_http::ServerErrorCode::DnsQueryError,
        ServerErrorCode::InvalidDnsOpType => bucky_http::ServerErrorCode::InvalidDnsOpType,
        ServerErrorCode::InvalidDnsMessageType => bucky_http::ServerErrorCode::InvalidDnsMessageType,
        ServerErrorCode::InvalidDnsRecordType => bucky_http::ServerErrorCode::InvalidDnsRecordType,
        ServerErrorCode::Rejected => bucky_http::ServerErrorCode::Rejected,
        ServerErrorCode::AlreadyExists => bucky_http::ServerErrorCode::AlreadyExists,
    }
}

fn from_bucky_error_code(code: bucky_http::ServerErrorCode) -> ServerErrorCode {
    match code {
        bucky_http::ServerErrorCode::BindFailed => ServerErrorCode::BindFailed,
        bucky_http::ServerErrorCode::NotFound => ServerErrorCode::NotFound,
        bucky_http::ServerErrorCode::InvalidConfig => ServerErrorCode::InvalidConfig,
        bucky_http::ServerErrorCode::InvalidParam => ServerErrorCode::InvalidParam,
        bucky_http::ServerErrorCode::ProcessChainError => ServerErrorCode::ProcessChainError,
        bucky_http::ServerErrorCode::StreamError => ServerErrorCode::StreamError,
        bucky_http::ServerErrorCode::TunnelError => ServerErrorCode::TunnelError,
        bucky_http::ServerErrorCode::InvalidTlsKey => ServerErrorCode::InvalidTlsKey,
        bucky_http::ServerErrorCode::InvalidTlsCert => ServerErrorCode::InvalidTlsCert,
        bucky_http::ServerErrorCode::InvalidData => ServerErrorCode::InvalidData,
        bucky_http::ServerErrorCode::IOError => ServerErrorCode::IOError,
        bucky_http::ServerErrorCode::BadRequest => ServerErrorCode::BadRequest,
        bucky_http::ServerErrorCode::UnknownServerType => ServerErrorCode::UnknownServerType,
        bucky_http::ServerErrorCode::EncodeError => ServerErrorCode::EncodeError,
        bucky_http::ServerErrorCode::DnsQueryError => ServerErrorCode::DnsQueryError,
        bucky_http::ServerErrorCode::InvalidDnsOpType => ServerErrorCode::InvalidDnsOpType,
        bucky_http::ServerErrorCode::InvalidDnsMessageType => ServerErrorCode::InvalidDnsMessageType,
        bucky_http::ServerErrorCode::InvalidDnsRecordType => ServerErrorCode::InvalidDnsRecordType,
        bucky_http::ServerErrorCode::Rejected => ServerErrorCode::Rejected,
        bucky_http::ServerErrorCode::AlreadyExists => ServerErrorCode::AlreadyExists,
    }
}

enum ChainOutcome {
    /// Chain produced no resolution; pass the (possibly mutated) request
    /// through to the inner server.
    PassThrough(Request<UnsyncBoxBody<Bytes, ServerError>>),
    /// Chain resolved the path to an obj_id; the request URI has been
    /// rewritten into O-Link form.
    Resolved(Request<UnsyncBoxBody<Bytes, ServerError>>),
    /// Chain produced a terminal HTTP response (drop/reject/error).
    Response(Response<UnsyncBoxBody<Bytes, ServerError>>),
}

// =====================================================================
// Factory
// =====================================================================

pub struct CyfsDirServerFactory;

impl CyfsDirServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for CyfsDirServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let cfg = config
            .as_any()
            .downcast_ref::<CyfsDirServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid cyfs-dir server config"
            ))?;

        // 1. NamedDataMgr.
        let store_mgr = NamedDataMgr::get_store_mgr(
            std::path::Path::new(&cfg.named_store_config_path),
            &cfg.http_backend_links,
        )
        .await
        .map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "load named_store from {} failed: {}",
                cfg.named_store_config_path,
                e
            )
        })?;
        let store_mgr = Arc::new(store_mgr);

        // 2. Optional signing key.
        let (signing_key, signing_kid) = match cfg.signing_key_path.as_deref() {
            Some(path) => {
                let pem = std::fs::read(path).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "read signing key {} failed: {}",
                        path,
                        e
                    )
                })?;
                let key = EncodingKey::from_ed_pem(&pem).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "parse ed25519 PEM key {} failed: {}",
                        path,
                        e
                    )
                })?;
                (Some(key), cfg.signing_kid.clone())
            }
            None => (None, None),
        };

        // 3. Inner NdnDirServer. Uses semantic_root if configured, else a
        // dummy path (filesystem fallback will simply 404).
        let semantic_root = cfg
            .semantic_root
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);

        let mode = match cfg.mode.as_deref().unwrap_or("local-link") {
            "in-store" | "InStore" => NdnDirServerMode::InStore,
            "local-link" | "LocalLink" => NdnDirServerMode::LocalLink,
            other => {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid cyfs-dir mode '{}': expected 'local-link' or 'in-store'",
                    other
                ));
            }
        };

        let mut inner_cfg = NdnDirServerConfig::new(semantic_root, store_mgr.clone(), mode)
            .url_prefix(cfg.url_prefix.clone())
            .obj_id_in_host(cfg.obj_id_in_host)
            .scan_interval(Duration::from_secs(cfg.scan_interval_secs.max(1)));
        if let Some(key) = signing_key {
            inner_cfg = inner_cfg.signing_key(key, signing_kid);
        }

        let inner = NdnDirServer::new(inner_cfg);
        // Spawn the auto-objectification scanner only when the user opted
        // into a real semantic_root and a non-zero interval.
        if cfg.semantic_root.is_some() && cfg.scan_interval_secs > 0 {
            let _ = inner.spawn_scanner();
        }
        let inner = Arc::new(inner);

        // 4. Optional process-chain executor.
        let executor = if let Some(hook_point) = cfg.hook_point.as_ref() {
            let context = context.ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "cyfs-dir server context is required when hook_point is set"
            ))?;
            let context = context
                .as_ref()
                .as_any()
                .downcast_ref::<CyfsDirServerContext>()
                .ok_or(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid cyfs-dir server context"
                ))?;

            let server_mgr_strong = context.server_mgr.upgrade();
            let external_commands = server_mgr_strong
                .as_ref()
                .map(|m| get_external_commands(Arc::downgrade(m)));

            let (exec, _) = create_process_chain_executor(
                hook_point,
                Some(context.global_process_chains.clone()),
                Some(context.global_collection_manager.clone()),
                external_commands,
                Some(context.js_externals.clone()),
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
            Some(Arc::new(Mutex::new(exec)))
        } else {
            None
        };

        let server = CyfsDirServer {
            id: cfg.id.clone(),
            store_mgr,
            inner,
            executor,
            url_prefix: cfg.url_prefix.clone(),
        };

        Ok(vec![Server::Http(Arc::new(server))])
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn empty_response(status: StatusCode) -> Response<UnsyncBoxBody<Bytes, ServerError>> {
    let mut resp = Response::new(full_body(Bytes::new()));
    *resp.status_mut() = status;
    resp
}

fn full_body(data: Bytes) -> UnsyncBoxBody<Bytes, ServerError> {
    Full::new(data).map_err(|never| match never {}).boxed_unsync()
}

/// Rewrite the request URI so the inner [`NdnDirServer`] sees an O-Link:
/// `<url_prefix>/<obj_id>{inner_path?}{?query}`. The URL prefix and any
/// `/@/` inner-path tail are preserved.
fn rewrite_to_o_link(
    mut req: Request<UnsyncBoxBody<Bytes, ServerError>>,
    obj_id: &str,
    url_prefix: &str,
) -> Request<UnsyncBoxBody<Bytes, ServerError>> {
    let uri = req.uri().clone();
    let original_path = uri.path();
    let inner_tail = match original_path.find(INNER_PATH_DELIMITER) {
        Some(idx) => &original_path[idx..],
        None => "",
    };
    let prefix = url_prefix.trim_matches('/');
    let new_path = if prefix.is_empty() {
        format!("/{}{}", obj_id, inner_tail)
    } else {
        format!("/{}/{}{}", prefix, obj_id, inner_tail)
    };
    let new_uri = match uri.query() {
        Some(q) => format!("{}?{}", new_path, q),
        None => new_path,
    };
    if let Ok(parsed) = new_uri.parse::<http::Uri>() {
        *req.uri_mut() = parsed;
    } else {
        warn!(
            "cyfs-dir-server: failed to rewrite URI '{}' → '{}', keeping original",
            uri, new_uri
        );
    }
    req
}
