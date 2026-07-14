use crate::server::dns_server::NameServer;
use crate::QAServer;
use ::kRPC::{RPCHandler, RPCRequest, RPCResponse, RPCResult};
use as_any::AsAny;
use buckyos_kit::AsyncStream;
use cyfs_process_chain::{
    CollectionValue, EnvRef, HTTP_REQUEST_HEADER_VARS, MapCollection,
    MapCollectionTraverseCallBackRef, TraverseGuard, VariableVisitor,
    VariableVisitorWrapperForMapCollection,
};
use http::uri::{Parts, PathAndQuery};
use http::{HeaderName, Method, Response, StatusCode, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::rt::Executor;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, RwLock as StdRwLock, Weak};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, Debug)]
struct LocalExecutor;

impl<Fut> Executor<Fut> for LocalExecutor
where
    Fut: Future + 'static,
    Fut::Output: 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn_local(fut);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerErrorCode {
    BindFailed,
    NotFound,
    InvalidConfig,
    InvalidParam,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
    InvalidData,
    IOError,
    BadRequest,
    UnknownServerType,
    EncodeError,
    DnsQueryError,
    InvalidDnsOpType,
    InvalidDnsMessageType,
    InvalidDnsRecordType,
    Rejected,
    AlreadyExists,
}

pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
pub use sfo_result::err as server_err;
pub use sfo_result::into_err as into_server_err;

#[derive(Default, Debug, Clone)]
pub struct StreamInfo {
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub conn_src_addr: Option<String>,
    pub real_src_addr: Option<String>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_online_secs: Option<String>,
}

impl StreamInfo {
    pub fn new(src_addr: String) -> Self {
        Self {
            src_addr: Some(src_addr.clone()),
            dst_addr: None,
            conn_src_addr: Some(src_addr),
            real_src_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_addrs(conn_src_addr: Option<String>, real_src_addr: Option<String>) -> Self {
        let src_addr = real_src_addr.clone().or_else(|| conn_src_addr.clone());
        Self {
            src_addr,
            dst_addr: None,
            conn_src_addr,
            real_src_addr,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_device_info(
        mut self,
        source_mac: Option<String>,
        source_hostname: Option<String>,
        source_online_secs: Option<String>,
    ) -> Self {
        self.source_mac = source_mac;
        self.source_hostname = source_hostname;
        self.source_online_secs = source_online_secs;
        self
    }

    pub fn with_dst_addr(mut self, dst_addr: Option<String>) -> Self {
        self.dst_addr = dst_addr;
        self
    }
}

#[async_trait::async_trait(?Send)]
pub trait HttpServer: Send + Sync + 'static {
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>>;

    fn id(&self) -> String;
    fn http_version(&self) -> http::Version;
    fn http3_port(&self) -> Option<u16>;
}

pub async fn serve_http_server_request(
    server: Arc<dyn HttpServer>,
    req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
    info: StreamInfo,
) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
    server.serve_request(req, info).await
}

pub async fn serve_http_by_rpc_handler<T: RPCHandler + Send + Sync + 'static>(
    req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
    if req.method() != hyper::Method::POST {
        return Ok(text_response(
            hyper::StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        )?);
    }

    let client_ip = match client_ip(&info) {
        Ok(client_ip) => client_ip,
        Err(resp) => return Ok(resp),
    };

    let body_bytes = match req.collect().await {
        Ok(data) => data.to_bytes(),
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to read body: {:?}", e),
            )?);
        }
    };

    let body_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to convert body to string: {}", e),
            )?);
        }
    };

    log::debug!("|==>recv kRPC req: {}", body_str);

    let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
        Ok(rpc_request) => rpc_request,
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to parse request body to RPCRequest: {}", e),
            )?);
        }
    };

    let rpc_seq = rpc_request.seq;
    let rpc_trace_id = rpc_request.trace_id.clone();
    let resp: RPCResponse = match rpc_handler.handle_rpc_call(rpc_request, client_ip).await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("Failed to handle rpc call: {}", e);
            RPCResponse {
                result: RPCResult::Failed(e.to_string()),
                seq: rpc_seq,
                trace_id: rpc_trace_id,
            }
        }
    };

    let body_json = serde_json::to_string(&resp).map_err(|e| {
        server_err!(
            ServerErrorCode::EncodeError,
            "Failed to convert response to string: {}",
            e
        )
    })?;

    Response::builder()
        .body(full_body(body_json))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidData,
                "Failed to build response: {}",
                e
            )
        })
}

pub async fn hyper_serve_http(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
) -> ServerResult<()> {
    if server.http_version() <= http::Version::HTTP_11 {
        hyper_serve_http1(stream, server, info).await
    } else if server.http_version() == http::Version::HTTP_3 && server.http3_port().is_some() {
        serve_auto_http(stream, server, info, true).await
    } else {
        serve_auto_http(stream, server, info, false).await
    }
}

pub async fn hyper_serve_http1(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
) -> ServerResult<()> {
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move { handle_request(req, server, info, false).await }
            }),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;

    Ok(())
}

async fn serve_auto_http(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
    add_http3_alt_svc: bool,
) -> ServerResult<()> {
    hyper_util::server::conn::auto::Builder::new(LocalExecutor)
        .serve_connection(
            TokioIo::new(stream),
            hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move { handle_request(req, server, info, add_http3_alt_svc).await }
            }),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;

    Ok(())
}

async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
    add_http3_alt_svc: bool,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    let (parts, body) = req.into_parts();
    let req = http::Request::new(UnsyncBoxBody::new(body))
        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e))
        .boxed_unsync();
    let req = http::Request::from_parts(parts, req);

    let remote = info
        .src_addr
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let method_is_options = req.method() == Method::OPTIONS;
    let method = req.method().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("none")
        .to_string();
    let uri = req.uri().to_string();

    log::debug!(
        "recv http request:remote {} method {} host {} path {}",
        remote,
        method,
        host,
        uri,
    );

    match serve_http_server_request(server.clone(), req, info).await {
        Ok(mut resp) => {
            if add_http3_alt_svc {
                if let Some(http3_port) = server.http3_port() {
                    let value = format!("h3=\":{http3_port}\"; ma=86400");
                    resp.headers_mut().insert(
                        http::header::ALT_SVC,
                        http::HeaderValue::from_str(value.as_str())
                            .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{:?}", e))?,
                    );
                }
            }

            log_forbidden(
                &server,
                resp.status(),
                method_is_options,
                remote,
                method,
                host,
                uri,
            );
            Ok(resp)
        }
        Err(e) => {
            log::error!("http error {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(Bytes::from(e.msg().to_string()))
                        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e))
                        .boxed_unsync(),
                )
                .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
        }
    }
}

fn log_forbidden(
    server: &Arc<dyn HttpServer>,
    status: StatusCode,
    method_is_options: bool,
    remote: String,
    method: String,
    host: String,
    uri: String,
) {
    if status != StatusCode::FORBIDDEN {
        return;
    }

    if method_is_options {
        log::warn!(
            "http_forbidden server={} remote={} method={} host={} uri={}",
            server.id(),
            remote,
            method,
            host,
            uri,
        );
    } else {
        log::debug!(
            "http_forbidden server={} remote={} method={} host={} uri={}",
            server.id(),
            remote,
            method,
            host,
            uri,
        );
    }
}

fn client_ip(info: &StreamInfo) -> Result<IpAddr, http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
    match info.src_addr.as_ref() {
        Some(addr) => match addr.parse::<std::net::SocketAddr>() {
            Ok(sa) => Ok(sa.ip()),
            Err(e) => {
                log::error!("parse client ip {} err {}", addr, e);
                Err(text_response(hyper::StatusCode::BAD_REQUEST, "Bad Request")
                    .expect("static bad request response should build"))
            }
        },
        None => {
            log::error!("Failed to get client ip");
            Err(text_response(hyper::StatusCode::BAD_REQUEST, "Bad Request")
                .expect("static bad request response should build"))
        }
    }
}

fn text_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> ServerResult<Response<UnsyncBoxBody<Bytes, ServerError>>> {
    Response::builder()
        .status(status)
        .body(full_body(body))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::BadRequest,
                "Failed to build response: {}",
                e
            )
        })
}

fn full_body(body: impl Into<Bytes>) -> UnsyncBoxBody<Bytes, ServerError> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

#[derive(Clone)]
struct Router {
    routes: Arc<StdRwLock<Vec<(String, Arc<dyn HttpServer>)>>>,
}

impl Router {
    fn new() -> Self {
        Self {
            routes: Arc::new(StdRwLock::new(Vec::new())),
        }
    }

    fn add_route(&self, path: String, server: Arc<dyn HttpServer>) {
        let mut routes = self.routes.write().unwrap();
        routes.push((normalize_route(path), server));
        routes.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
    }
}

#[async_trait::async_trait(?Send)]
impl HttpServer for Router {
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let path = req.uri().path().to_string();
        let routes = self.routes.read().unwrap().clone();
        let src_addr = info.src_addr.as_deref().unwrap_or("unknown");
        info!("{}=>{} {}", src_addr, req.method(), path);

        for (prefix, server) in routes {
            debug!("try match router: {}", prefix);
            if route_matches(&path, &prefix) {
                debug!(" {} match router: {}", path, prefix);
                return server.serve_request(req, info).await;
            }
        }

        http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(
                http_body_util::Full::new(Bytes::from("No Router Found"))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{}", e))
    }

    fn id(&self) -> String {
        "router".to_string()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

#[derive(Clone)]
pub struct Runner {
    bind_addr: SocketAddr,
    router: Router,
}

#[derive(Clone, Default)]
pub struct DirHandlerOptions {
    pub index_file: Option<String>,
    pub fallback_file: Option<String>,
}

impl Runner {
    pub fn new(port: u16) -> Self {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        Self::with_addr(addr)
    }

    pub fn with_addr(addr: SocketAddr) -> Self {
        Self {
            bind_addr: addr,
            router: Router::new(),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn add_http_server(
        &self,
        router_url: String,
        server: Arc<dyn HttpServer>,
    ) -> ServerResult<()> {
        self.router.add_route(router_url, server);
        Ok(())
    }

    pub async fn add_dir_handler(&self, router_url: String, dir: PathBuf) -> ServerResult<()> {
        self.add_dir_handler_with_options(router_url, dir, DirHandlerOptions::default())
            .await
    }

    pub async fn add_dir_handler_with_options(
        &self,
        router_url: String,
        dir: PathBuf,
        options: DirHandlerOptions,
    ) -> ServerResult<()> {
        let mut builder = crate::DirServer::builder()
            .id(router_url.clone())
            .root_path(dir)
            .base_url(router_url.clone());

        if let Some(index_file) = options.index_file {
            builder = builder.index_file(index_file);
        }

        if let Some(fallback_file) = options.fallback_file {
            builder = builder.fallback_file(fallback_file);
        }

        let dir_server = builder.build().await?;
        self.router.add_route(router_url, Arc::new(dir_server));
        Ok(())
    }

    pub fn start(self) -> ServerResult<()> {
        tokio::task::spawn_local(async move {
            let _ = self.run().await;
        });
        Ok(())
    }

    pub async fn run(&self) -> ServerResult<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| server_err!(ServerErrorCode::BindFailed, "{}", e))?;

        let local_addr = listener.local_addr().unwrap_or(self.bind_addr);
        info!("cyfs-gateway-lib runner listening on {}", local_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(ret) => ret,
                Err(e) => {
                    error!("failed to accept tcp connection: {}", e);
                    continue;
                }
            };

            let server = Arc::new(self.router.clone());
            tokio::task::spawn_local(async move {
                if let Err(err) = serve_tcp_stream(stream, server, peer_addr).await {
                    error!("failed to serve {}: {:?}", peer_addr, err);
                }
            });
        }
    }
}

async fn serve_tcp_stream(
    stream: TcpStream,
    server: Arc<dyn HttpServer>,
    peer_addr: SocketAddr,
) -> ServerResult<()> {
    let info = StreamInfo::new(peer_addr.to_string());
    let stream: Box<dyn AsyncStream> = Box::new(stream);
    hyper_serve_http(stream, server, info).await
}

fn normalize_route(route: String) -> String {
    if route.is_empty() {
        return "/".to_string();
    }

    if route.starts_with('/') {
        route
    } else {
        format!("/{route}")
    }
}

fn route_matches(path: &str, route: &str) -> bool {
    if route == "/" {
        return path.starts_with('/');
    }

    path == route.trim_end_matches('/') || path.starts_with(route)
}

pub trait ServerConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn server_type(&self) -> String;
    fn get_config_json(&self) -> String;
}

pub trait ServerContext: AsAny + Send + Sync {
    fn get_server_type(&self) -> String;
}
pub type ServerContextRef = Arc<dyn ServerContext>;

#[async_trait::async_trait]
pub trait ServerFactory: Send + Sync {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>>;
}

pub struct CyfsServerFactory {
    server_factory: Mutex<HashMap<String, Arc<dyn ServerFactory>>>,
}
pub type CyfsServerFactoryRef = Arc<CyfsServerFactory>;

impl Default for CyfsServerFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsServerFactory {
    pub fn new() -> Self {
        Self {
            server_factory: Mutex::new(HashMap::new()),
        }
    }
    pub fn register(&self, server_type: String, factory: Arc<dyn ServerFactory>) {
        self.server_factory
            .lock()
            .unwrap()
            .insert(server_type, factory);
    }
}

#[async_trait::async_trait]
impl ServerFactory for CyfsServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let factory = {
            self.server_factory
                .lock()
                .unwrap()
                .get(config.server_type().as_str())
                .cloned()
        };
        match factory {
            Some(factory) => factory.create(config, context).await,
            None => Err(server_err!(
                ServerErrorCode::UnknownServerType,
                "unknown server type {}",
                config.server_type()
            )),
        }
    }
}

#[derive(Clone)]
pub enum Server {
    Stream(Arc<dyn StreamServer>),
    Datagram(Arc<dyn DatagramServer>),

    QA(Arc<dyn QAServer>),
    NameServer(Arc<dyn NameServer>),
    Http(Arc<dyn HttpServer>),
}

impl Server {
    /// 获取 server 的基础 id（不含类型后缀）
    pub fn id(&self) -> String {
        match self {
            Server::Http(server) => server.id(),
            Server::Stream(server) => server.id(),
            Server::Datagram(server) => server.id(),
            Server::QA(server) => server.id(),
            Server::NameServer(server) => server.id(),
        }
    }

    /// 获取 server 的 trait 类型名称
    pub fn trait_type(&self) -> &'static str {
        match self {
            Server::Http(_) => "http",
            Server::Stream(_) => "stream",
            Server::Datagram(_) => "datagram",
            Server::QA(_) => "qa",
            Server::NameServer(_) => "ns",
        }
    }

    /// 获取完整的 server key: $id.$trait_type
    /// 例如: "my-server.http", "my-server.stream"
    pub fn full_key(&self) -> String {
        format!("{}.{}", self.id(), self.trait_type())
    }

    /// 根据 trait 类型构建完整 key
    pub fn build_key(id: &str, trait_type: &str) -> String {
        format!("{}.{}", id, trait_type)
    }
}

#[derive(Default, Debug, Clone)]
pub struct HttpRequestProcessChainVars {
    pub req_remote_ip: Option<String>,
    pub req_remote_port: Option<String>,
    pub req_conn_remote_ip: Option<String>,
    pub req_conn_remote_port: Option<String>,
    pub req_real_remote_ip: Option<String>,
    pub req_real_remote_port: Option<String>,
}

/// Source variables resolved from a [`StreamInfo`] (and optionally from
/// trusted forwarded headers) for one HTTP request.
///
/// - `source_*`: effective source seen by this hook point (real source when a
///   trusted restore exists, otherwise the connection source)
/// - `conn_source_*`: connection-layer direct previous hop
/// - `real_source_*`: source restored through a trusted mechanism only; never
///   fabricated when no trusted mechanism applies
///
/// `*_addr` keeps the raw address string (usually `IP:PORT`, may be a bare IP
/// when restored from forwarded headers); `*_ip` / `*_port` are only present
/// when they can be derived.
#[derive(Default, Debug, Clone)]
pub struct RequestSourceInfo {
    pub source_addr: Option<String>,
    pub source_ip: Option<String>,
    pub source_port: Option<String>,
    pub conn_source_addr: Option<String>,
    pub conn_source_ip: Option<String>,
    pub conn_source_port: Option<String>,
    pub real_source_addr: Option<String>,
    pub real_source_ip: Option<String>,
    pub real_source_port: Option<String>,
}

/// Reserved source keys exposed through the HTTP `REQ` map. These keys always
/// resolve from the connection's [`RequestSourceInfo`] and never fall back to
/// same-named HTTP headers, so clients cannot forge them.
pub const HTTP_REQ_SOURCE_KEYS: [&str; 9] = [
    "source_addr",
    "source_ip",
    "source_port",
    "conn_source_addr",
    "conn_source_ip",
    "conn_source_port",
    "real_source_addr",
    "real_source_ip",
    "real_source_port",
];

fn addr_group_from_str(addr: &str) -> (Option<String>, Option<String>, Option<String>) {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        (
            Some(addr.to_string()),
            Some(socket_addr.ip().to_string()),
            Some(socket_addr.port().to_string()),
        )
    } else if addr.parse::<std::net::IpAddr>().is_ok() {
        (Some(addr.to_string()), Some(addr.to_string()), None)
    } else {
        (Some(addr.to_string()), None, None)
    }
}

impl RequestSourceInfo {
    pub fn is_reserved_key(key: &str) -> bool {
        HTTP_REQ_SOURCE_KEYS.contains(&key)
    }

    pub fn from_stream_info(info: &StreamInfo) -> Self {
        let mut this = Self::default();
        if let Some(addr) = info.src_addr.as_deref() {
            (this.source_addr, this.source_ip, this.source_port) = addr_group_from_str(addr);
        }
        if let Some(addr) = info.conn_src_addr.as_deref() {
            (
                this.conn_source_addr,
                this.conn_source_ip,
                this.conn_source_port,
            ) = addr_group_from_str(addr);
        }
        if let Some(addr) = info.real_src_addr.as_deref() {
            (
                this.real_source_addr,
                this.real_source_ip,
                this.real_source_port,
            ) = addr_group_from_str(addr);
        }
        this
    }

    /// Install `addr` as the trusted restored source and make it the
    /// effective source as well.
    pub fn set_real_source(&mut self, addr: &str) {
        (
            self.real_source_addr,
            self.real_source_ip,
            self.real_source_port,
        ) = addr_group_from_str(addr);
        (self.source_addr, self.source_ip, self.source_port) = addr_group_from_str(addr);
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let value = match key {
            "source_addr" => &self.source_addr,
            "source_ip" => &self.source_ip,
            "source_port" => &self.source_port,
            "conn_source_addr" => &self.conn_source_addr,
            "conn_source_ip" => &self.conn_source_ip,
            "conn_source_port" => &self.conn_source_port,
            "real_source_addr" => &self.real_source_addr,
            "real_source_ip" => &self.real_source_ip,
            "real_source_port" => &self.real_source_port,
            _ => &None,
        };
        value.as_deref()
    }

    fn present_entries(&self) -> Vec<(&'static str, String)> {
        HTTP_REQ_SOURCE_KEYS
            .iter()
            .filter_map(|key| self.get(key).map(|value| (*key, value.to_string())))
            .collect()
    }
}

// 流处理服务
#[async_trait::async_trait(?Send)]
pub trait StreamServer: Send + Sync {
    async fn serve_connection(
        &self,
        stream: Box<dyn AsyncStream>,
        info: StreamInfo,
    ) -> ServerResult<()>;
    fn id(&self) -> String;
}

pub fn str_to_http_version(version: &str) -> Option<http::Version> {
    match version.to_lowercase().as_str() {
        "http/0.9" => Some(http::Version::HTTP_09),
        "http/1.0" => Some(http::Version::HTTP_10),
        "http/1.1" => Some(http::Version::HTTP_11),
        "http/2" => Some(http::Version::HTTP_2),
        "http/3" => Some(http::Version::HTTP_3),
        _ => None,
    }
}

#[derive(Clone)]
pub struct HttpRequestHeaderMap {
    request: Arc<Mutex<http::Request<UnsyncBoxBody<Bytes, ServerError>>>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
    sources: Arc<RequestSourceInfo>,
}

impl HttpRequestHeaderMap {
    pub fn new(request: http::Request<UnsyncBoxBody<Bytes, ServerError>>) -> Self {
        Self {
            request: Arc::new(Mutex::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)), // Initialize counter to 0
            sources: Arc::new(RequestSourceInfo::default()),
        }
    }

    pub fn new_with_sources(
        request: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        sources: RequestSourceInfo,
    ) -> Self {
        Self {
            request: Arc::new(Mutex::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
            sources: Arc::new(sources),
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_request(self) -> Result<http::Request<UnsyncBoxBody<Bytes, ServerError>>, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| {
                let msg = "Failed to unwrap HyperHttpRequestHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?
            .into_inner()
            .map_err(|_| {
                let msg = "Failed to unwrap poisoned HyperHttpRequestHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?;

        Ok(req)
    }

    pub async fn register_visitors(&self, env: &EnvRef) -> Result<(), String> {
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        let mut wrapper = VariableVisitorWrapperForMapCollection::new(coll.clone());

        for item in HTTP_REQUEST_HEADER_VARS {
            wrapper.add_variable(item.0, item.1, item.2);
        }

        let visitor = Arc::new(Box::new(wrapper) as Box<dyn VariableVisitor>);
        for (id, _, _) in HTTP_REQUEST_HEADER_VARS {
            env.create(*id, CollectionValue::Visitor(visitor.clone()))
                .await?;
        }

        // Url visitor
        let url_visitor = HttpRequestUrlVisitor::new(self.request.clone(), false);
        let visitor = Arc::new(Box::new(url_visitor) as Box<dyn VariableVisitor>);
        env.create("REQ_url", CollectionValue::Visitor(visitor))
            .await?;

        env.create("REQ", CollectionValue::Map(coll)).await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpRequestHeaderMap {
    async fn len(&self) -> Result<usize, String> {
        let request = self.request.lock().unwrap();
        Ok(request.headers().len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert new header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        if key == "path" || key == "method" || key == "uri" || key == "version" {
            let msg = format!("Cannot insert new value '{}'", key);
            warn!("{}", msg);
            return Err(msg);
        }

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot insert read-only source variable '{}'", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.lock().unwrap();
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        if request.headers().contains_key(&name) {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        request.headers_mut().insert(name, header);
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot set read-only source variable '{}'", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.lock().unwrap();
        if key == "uri" {
            let old_value = CollectionValue::String(request.uri().to_string());
            *request.uri_mut() = Uri::try_from(value.try_as_str()?).map_err(|e| {
                let msg = format!("Invalid URI '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "method" {
            let old_value = CollectionValue::String(request.method().to_string());
            *request.method_mut() = Method::from_str(value.try_as_str()?).map_err(|e| {
                let msg = format!("Invalid method '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "version" {
            let old_value = CollectionValue::String(format!("{:?}", request.version()));
            *request.version_mut() = str_to_http_version(value.try_as_str()?).ok_or({
                let msg = format!("Invalid HTTP version '{}'", value);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else if key == "path" {
            let old_value = CollectionValue::String(request.uri().path().to_string());
            let mut parts = Parts::from(request.uri().clone());
            parts.path_and_query = if parts.path_and_query.is_none() {
                Some(PathAndQuery::from_str(value.try_as_str()?).map_err(|e| {
                    let msg = format!("Invalid path '{}': {}", value, e);
                    warn!("{}", msg);
                    msg.to_string()
                })?)
            } else {
                let query = parts.path_and_query.as_ref().unwrap().query();
                if let Some(query) = query {
                    Some(
                        PathAndQuery::from_str(
                            format!("{}?{}", value.try_as_str()?, query).as_str(),
                        )
                        .map_err(|e| {
                            let msg = format!("Invalid path '{}': {}", value, e);
                            warn!("{}", msg);
                            msg.to_string()
                        })?,
                    )
                } else {
                    Some(PathAndQuery::from_str(value.try_as_str()?).map_err(|e| {
                        let msg = format!("Invalid path '{}': {}", value, e);
                        warn!("{}", msg);
                        msg.to_string()
                    })?)
                }
            };
            *request.uri_mut() = Uri::from_parts(parts).map_err(|e| {
                let msg = format!("Invalid path '{}': {}", value, e);
                warn!("{}", msg);
                msg.to_string()
            })?;
            Ok(Some(old_value))
        } else {
            let header = value.try_as_str()?.parse().map_err(|e| {
                let msg = format!("Invalid header value '{}': {}", value, e);
                warn!("{}", msg);
                msg
            })?;

            let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                let msg = format!("Invalid header name '{}': {}", key, e);
                warn!("{}", msg);
                msg.to_string()
            })?;

            let prev = request.headers_mut().insert(name, header);
            if let Some(prev_value) = prev {
                let prev = match prev_value.to_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        let msg = format!("Header value for '{}' is not valid UTF-8", key);
                        warn!("{}", msg);
                        "".to_string()
                    }
                };
                Ok(Some(CollectionValue::String(prev)))
            } else {
                Ok(None)
            }
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if RequestSourceInfo::is_reserved_key(key) {
            // Reserved source keys resolve from stream info only; a
            // same-named HTTP header must never shadow them.
            return Ok(self
                .sources
                .get(key)
                .map(|value| CollectionValue::String(value.to_string())));
        }

        let request = self.request.lock().unwrap();
        if key == "path" {
            Ok(Some(CollectionValue::String(
                request.uri().path().to_string(),
            )))
        } else if key == "method" {
            Ok(Some(CollectionValue::String(request.method().to_string())))
        } else if key == "uri" {
            Ok(Some(CollectionValue::String(request.uri().to_string())))
        } else if key == "version" {
            Ok(Some(CollectionValue::String(format!(
                "{:?}",
                request.version()
            ))))
        } else {
            let ret = request.headers().get(key);
            if let Some(value) = ret {
                if let Ok(value_str) = value.to_str() {
                    Ok(Some(CollectionValue::String(value_str.to_string())))
                } else {
                    warn!("Header value for '{}' is not valid UTF-8", key);
                    Ok(Some(CollectionValue::String("".to_string())))
                }
            } else {
                warn!("Header '{}' not found", key);
                Ok(None)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        if RequestSourceInfo::is_reserved_key(key) {
            return Ok(self.sources.get(key).is_some());
        }
        let request = self.request.lock().unwrap();
        if key == "path" || key == "method" || key == "uri" || key == "version" {
            return Ok(true);
        }
        Ok(request.headers().get(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        if RequestSourceInfo::is_reserved_key(key) {
            let msg = format!("Cannot remove read-only source variable '{}'", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.lock().unwrap();
        let prev = request.headers_mut().remove(key);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let entries = {
            let request = self.request.lock().unwrap();
            let mut entries = vec![
                (
                    "path".to_string(),
                    CollectionValue::String(request.uri().path().to_string()),
                ),
                (
                    "method".to_string(),
                    CollectionValue::String(request.method().to_string()),
                ),
                (
                    "uri".to_string(),
                    CollectionValue::String(request.uri().to_string()),
                ),
                (
                    "version".to_string(),
                    CollectionValue::String(format!("{:?}", request.version())),
                ),
            ];
            for (key, value) in self.sources.present_entries() {
                entries.push((key.to_string(), CollectionValue::String(value)));
            }
            for (key, value) in request.headers().iter() {
                if RequestSourceInfo::is_reserved_key(key.as_str()) {
                    continue;
                }
                if let Ok(value_str) = value.to_str() {
                    entries.push((
                        key.as_str().to_string(),
                        CollectionValue::String(value_str.to_owned()),
                    ));
                } else {
                    warn!("Header value for '{}' is not valid UTF-8", key);
                }
            }
            entries
        };

        for (key, value) in entries {
            if !callback.call(&key, &value).await? {
                break;
            }
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.lock().unwrap();
        let mut result = Vec::new();
        result.push((
            "path".to_string(),
            CollectionValue::String(request.uri().path().to_string()),
        ));
        result.push((
            "method".to_string(),
            CollectionValue::String(request.method().to_string()),
        ));
        result.push((
            "uri".to_string(),
            CollectionValue::String(request.uri().to_string()),
        ));
        result.push((
            "version".to_string(),
            CollectionValue::String(format!("{:?}", request.version())),
        ));
        for (key, value) in self.sources.present_entries() {
            result.push((key.to_string(), CollectionValue::String(value)));
        }
        for (key, value) in request.headers().iter() {
            if RequestSourceInfo::is_reserved_key(key.as_str()) {
                continue;
            }
            if let Ok(value_str) = value.to_str() {
                result.push((
                    key.as_str().to_string(),
                    CollectionValue::String(value_str.to_string()),
                ));
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(result)
    }
}

#[derive(Clone)]
pub struct HttpResponseHeaderMap {
    response: Arc<Mutex<http::Response<UnsyncBoxBody<Bytes, ServerError>>>>,
    transverse_counter: Arc<AtomicU32>,
}

impl HttpResponseHeaderMap {
    pub fn new(response: http::Response<UnsyncBoxBody<Bytes, ServerError>>) -> Self {
        Self {
            response: Arc::new(Mutex::new(response)),
            transverse_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_response(self) -> Result<http::Response<UnsyncBoxBody<Bytes, ServerError>>, String> {
        let resp = Arc::try_unwrap(self.response)
            .map_err(|_| {
                let msg = "Failed to unwrap HttpResponseHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?
            .into_inner()
            .map_err(|_| {
                let msg = "Failed to unwrap poisoned HttpResponseHeaderMap".to_string();
                error!("{}", msg);
                msg
            })?;

        Ok(resp)
    }

    pub async fn register_visitors(&self, env: &EnvRef) -> Result<(), String> {
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        env.create("RESP", CollectionValue::Map(coll)).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl MapCollection for HttpResponseHeaderMap {
    async fn len(&self) -> Result<usize, String> {
        let response = self.response.lock().unwrap();
        Ok(response.headers().len())
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert new header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut response = self.response.lock().unwrap();
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        if response.headers().contains_key(&name) {
            let msg = format!("Header '{}' already exists", key);
            warn!("{}", msg);
            return Ok(false);
        }

        response.headers_mut().insert(name, header);
        Ok(true)
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot insert header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut response = self.response.lock().unwrap();
        let header = value.try_as_str()?.parse().map_err(|e| {
            let msg = format!("Invalid header value '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
            let msg = format!("Invalid header name '{}': {}", key, e);
            warn!("{}", msg);
            msg.to_string()
        })?;

        let prev = response.headers_mut().insert(name, header);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let response = self.response.lock().unwrap();
        let ret = response.headers().get(key);
        if let Some(value) = ret {
            if let Ok(value_str) = value.to_str() {
                Ok(Some(CollectionValue::String(value_str.to_string())))
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
                Ok(Some(CollectionValue::String("".to_string())))
            }
        } else {
            warn!("Header '{}' not found", key);
            Ok(None)
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let response = self.response.lock().unwrap();
        Ok(response.headers().get(key).is_some())
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = format!("Cannot remove header '{}' during traversal", key);
            warn!("{}", msg);
            return Err(msg);
        }

        let mut response = self.response.lock().unwrap();
        let prev = response.headers_mut().remove(key);
        if let Some(prev_value) = prev {
            let prev = match prev_value.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let msg = format!("Header value for '{}' is not valid UTF-8", key);
                    warn!("{}", msg);
                    "".to_string()
                }
            };
            Ok(Some(CollectionValue::String(prev)))
        } else {
            Ok(None)
        }
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let entries = {
            let response = self.response.lock().unwrap();
            let mut entries = Vec::new();
            for (key, value) in response.headers().iter() {
                if let Ok(value_str) = value.to_str() {
                    entries.push((
                        key.as_str().to_string(),
                        CollectionValue::String(value_str.to_owned()),
                    ));
                } else {
                    warn!("Header value for '{}' is not valid UTF-8", key);
                }
            }
            entries
        };

        for (key, value) in entries {
            if !callback.call(&key, &value).await? {
                break;
            }
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let response = self.response.lock().unwrap();
        let mut result = Vec::new();
        for (key, value) in response.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                result.push((
                    key.as_str().to_string(),
                    CollectionValue::String(value_str.to_string()),
                ));
            } else {
                warn!("Header value for '{}' is not valid UTF-8", key);
            }
        }
        Ok(result)
    }
}

// Url visitor for HTTP requests
#[derive(Clone)]
pub struct HttpRequestUrlVisitor {
    request: Arc<Mutex<http::Request<UnsyncBoxBody<Bytes, ServerError>>>>,
    read_only: bool,
}

impl HttpRequestUrlVisitor {
    pub fn new(
        request: Arc<Mutex<http::Request<UnsyncBoxBody<Bytes, ServerError>>>>,
        read_only: bool,
    ) -> Self {
        Self { request, read_only }
    }
}

#[async_trait::async_trait]
impl VariableVisitor for HttpRequestUrlVisitor {
    async fn get(&self, _id: &str) -> Result<CollectionValue, String> {
        let request = self.request.lock().unwrap();
        let ret = request.uri().to_string();

        Ok(CollectionValue::String(ret))
    }

    async fn set(
        &self,
        id: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.read_only {
            let msg = format!("Cannot set read-only variable '{}'", id);
            warn!("{}", msg);
            return Err(msg);
        }

        let new_url = value.try_as_str()?.parse::<Uri>().map_err(|e| {
            let msg = format!("Invalid URL '{}': {}", value, e);
            warn!("{}", msg);
            msg
        })?;

        let mut request = self.request.lock().unwrap();
        let old_value = request.uri().to_string();
        *request.uri_mut() = new_url;

        debug!("Set request url variable '{}' to '{}'", id, value);
        Ok(Some(CollectionValue::String(old_value)))
    }
}

pub struct DatagramInfo {
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_online_secs: Option<String>,
}

impl DatagramInfo {
    pub fn new(src_addr: Option<String>) -> Self {
        DatagramInfo {
            src_addr,
            dst_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_dst_addr(mut self, dst_addr: Option<String>) -> Self {
        self.dst_addr = dst_addr;
        self
    }

    pub fn with_device_info(
        mut self,
        source_mac: Option<String>,
        source_hostname: Option<String>,
        source_online_secs: Option<String>,
    ) -> Self {
        self.source_mac = source_mac;
        self.source_hostname = source_hostname;
        self.source_online_secs = source_online_secs;
        self
    }
}

#[async_trait::async_trait(?Send)]
pub trait DatagramServer: Send + Sync + 'static {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>>;
    fn id(&self) -> String;
}

pub struct ServerManager {
    // key 格式: "$id.$trait_type", 例如 "my-server.http", "my-server.stream"
    servers: Mutex<HashMap<String, Server>>,
}

impl Drop for ServerManager {
    fn drop(&mut self) {
        log::debug!("ServerManager dropped");
    }
}

impl ServerManager {
    pub fn new() -> Self {
        ServerManager {
            servers: Mutex::new(HashMap::new()),
        }
    }

    pub fn clone_manager(&self) -> ServerManager {
        let new = ServerManager {
            servers: Mutex::new(HashMap::new()),
        };

        for (key, server) in self.servers.lock().unwrap().iter() {
            new.servers
                .lock()
                .unwrap()
                .insert(key.clone(), server.clone());
        }
        new
    }
    /// 添加 server，使用 full_key 作为存储键
    /// 同一个 id 的 server 可以注册多个不同的 trait 类型
    pub fn add_server(&self, server: Server) -> ServerResult<()> {
        let full_key = server.full_key();

        if self.get_server_by_key(&full_key).is_some() {
            return Err(server_err!(
                ServerErrorCode::AlreadyExists,
                "Server {} already exists",
                full_key
            ));
        }

        self.servers.lock().unwrap().insert(full_key, server);
        Ok(())
    }

    /// 通过完整 key 获取 server: "$id.$trait_type"
    pub fn get_server_by_key(&self, key: &str) -> Option<Server> {
        self.servers.lock().unwrap().get(key).cloned()
    }

    /// 通过 id 和 trait_type 获取 server
    pub fn get_server_by_type(&self, id: &str, trait_type: &str) -> Option<Server> {
        let key = if id.contains(".") {
            id.to_string()
        } else {
            Server::build_key(id, trait_type)
        };

        let result = self.get_server_by_key(&key);
        if result.is_none() {
            return None;
        }
        let result = result.unwrap();
        if result.trait_type() == trait_type {
            return Some(result);
        }

        None
    }

    pub fn get_http_server(&self, id: &str) -> Option<Arc<dyn HttpServer>> {
        let server = self.get_server_by_type(id, "http");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Http(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_stream_server(&self, id: &str) -> Option<Arc<dyn StreamServer>> {
        let server = self.get_server_by_type(id, "stream");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Stream(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_datagram_server(&self, id: &str) -> Option<Arc<dyn DatagramServer>> {
        let server = self.get_server_by_type(id, "datagram");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::Datagram(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_qa_server(&self, id: &str) -> Option<Arc<dyn QAServer>> {
        let server = self.get_server_by_type(id, "qa");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::QA(server) => Some(server.clone()),
            _ => None,
        }
    }

    pub fn get_name_server(&self, id: &str) -> Option<Arc<dyn NameServer>> {
        let server = self.get_server_by_type(id, "ns");
        if server.is_none() {
            return None;
        }
        let server = server.unwrap();
        match server {
            Server::NameServer(server) => Some(server.clone()),
            _ => None,
        }
    }
    /// 兼容旧接口：通过 id 获取第一个匹配的 server
    /// 如果一个 id 注册了多个 trait，返回任意一个
    pub fn get_server(&self, id: &str) -> Option<Server> {
        let servers = self.servers.lock().unwrap();
        let prefix = format!("{}.", id);

        // 先尝试精确匹配（向后兼容没有使用 full_key 的旧代码）
        if let Some(server) = servers.get(id) {
            return Some(server.clone());
        }

        // 再尝试前缀匹配
        servers
            .iter()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, server)| server.clone())
    }

    /// 获取某个 id 的所有 trait 实现
    pub fn get_all_servers_by_id(&self, id: &str) -> Vec<Server> {
        let servers = self.servers.lock().unwrap();
        let prefix = format!("{}.", id);

        servers
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix) || key.as_str() == id)
            .map(|(_, server)| server.clone())
            .collect()
    }

    /// 获取所有 server 的完整列表
    pub fn get_all_servers(&self) -> Vec<Server> {
        self.servers.lock().unwrap().values().cloned().collect()
    }

    /// 替换 server（使用 full_key）
    pub fn replace_server(&self, server: Server) {
        let full_key = server.full_key();
        self.servers.lock().unwrap().insert(full_key, server);
    }

    /// 删除指定的 server
    pub fn remove_server(&self, key: &str) -> Option<Server> {
        self.servers.lock().unwrap().remove(key)
    }

    /// 删除某个 id 的所有 server
    pub fn remove_servers_by_id(&self, id: &str) {
        let prefix = format!("{}.", id);
        self.servers
            .lock()
            .unwrap()
            .retain(|key, _| !key.starts_with(&prefix) && key.as_str() != id);
    }

    /// 保留满足条件的 server (key 为完整的 full_key)
    pub fn retain(&self, f: impl Fn(&str) -> bool) {
        self.servers
            .lock()
            .unwrap()
            .retain(|key, _| f(key.as_str()));
    }
}

pub type ServerManagerRef = Arc<ServerManager>;
pub type ServerManagerWeakRef = Weak<ServerManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    fn test_request(headers: &[(&str, &str)]) -> http::Request<UnsyncBoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder().method("GET").uri("/test");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap()
    }

    #[test]
    fn test_request_source_info_from_stream_info() {
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:9000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let sources = RequestSourceInfo::from_stream_info(&info);
        assert_eq!(sources.source_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(sources.source_port.as_deref(), Some("6001"));
        assert_eq!(sources.conn_source_addr.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(sources.real_source_ip.as_deref(), Some("198.51.100.7"));

        // Bare-IP real source (e.g. restored from X-Forwarded-For): the ip is
        // derivable but the port is not.
        let mut sources =
            RequestSourceInfo::from_stream_info(&StreamInfo::new("192.168.1.9:5555".to_string()));
        assert_eq!(sources.real_source_addr, None);
        sources.set_real_source("203.0.113.7");
        assert_eq!(sources.real_source_addr.as_deref(), Some("203.0.113.7"));
        assert_eq!(sources.real_source_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(sources.real_source_port, None);
        // Effective source follows the restored value.
        assert_eq!(sources.source_ip.as_deref(), Some("203.0.113.7"));
    }

    #[tokio::test]
    async fn test_http_req_map_reserved_source_keys() {
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:9000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let sources = RequestSourceInfo::from_stream_info(&info);
        // Forged same-named headers must never shadow the reserved keys.
        let req = test_request(&[("source_ip", "6.6.6.6"), ("x-plain", "1")]);
        let map = HttpRequestHeaderMap::new_with_sources(req, sources);

        let get = |key: &str| {
            let map = map.clone();
            let key = key.to_string();
            async move {
                map.get(&key)
                    .await
                    .unwrap()
                    .map(|v| v.try_as_str().unwrap().to_string())
            }
        };

        assert_eq!(get("source_ip").await.as_deref(), Some("198.51.100.7"));
        assert_eq!(
            get("source_addr").await.as_deref(),
            Some("198.51.100.7:6001")
        );
        assert_eq!(get("conn_source_ip").await.as_deref(), Some("127.0.0.1"));
        assert_eq!(get("conn_source_port").await.as_deref(), Some("9000"));
        assert_eq!(get("real_source_ip").await.as_deref(), Some("198.51.100.7"));
        // Normal headers still resolve.
        assert_eq!(get("x-plain").await.as_deref(), Some("1"));

        assert!(map.contains_key("real_source_addr").await.unwrap());

        // Reserved keys are read-only.
        assert!(
            map.insert("source_ip", CollectionValue::String("9.9.9.9".to_string()))
                .await
                .is_err()
        );
        assert!(
            map.insert_new(
                "real_source_ip",
                CollectionValue::String("9.9.9.9".to_string())
            )
            .await
            .is_err()
        );
        assert!(map.remove("conn_source_addr").await.is_err());

        // dump: reserved keys come from stream info; the forged header is
        // dropped so the view stays consistent with get().
        let dumped = map.dump().await.unwrap();
        let dumped: std::collections::HashMap<String, String> = dumped
            .into_iter()
            .map(|(k, v)| (k, v.try_as_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            dumped.get("source_ip").map(String::as_str),
            Some("198.51.100.7")
        );
        assert_eq!(dumped.get("x-plain").map(String::as_str), Some("1"));
    }

    #[tokio::test]
    async fn test_http_req_map_absent_source_keys() {
        // No stream info at all: reserved keys resolve to None instead of
        // falling back to forged headers.
        let req = test_request(&[("real_source_ip", "7.7.7.7")]);
        let map = HttpRequestHeaderMap::new(req);
        assert!(map.get("real_source_ip").await.unwrap().is_none());
        assert!(!map.contains_key("real_source_ip").await.unwrap());
        assert!(map.get("source_addr").await.unwrap().is_none());
    }
}
