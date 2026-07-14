use super::http_compression::{
    CompressionRequestInfo, HttpCompressionSettings, apply_request_decompression,
    apply_response_compression,
};
use super::{into_server_err, server_err};
use crate::forward::{
    BalanceMethod, ForwardFailureRegistry, ForwardPlan, HttpMethodClass, NextUpstreamCondition,
    apply_least_time_via_tunnel_mgr,
};
use crate::global_process_chains::{GlobalProcessChainsRef, create_process_chain_executor};
use crate::tunnel_url_status::TunnelFailureReason;
use crate::{
    GlobalCollectionManagerRef, HttpRequestHeaderMap, HttpRequestProcessChainVars,
    HttpResponseHeaderMap, HttpServer, JsExternalsManagerRef, ProcessChainConfigs,
    RequestSourceInfo, Server, ServerConfig, ServerContext, ServerContextRef, ServerError,
    ServerErrorCode, ServerFactory, ServerManagerWeakRef, ServerResult, StreamInfo, TunnelManager,
    get_external_commands,
};
use cyfs_process_chain::{CollectionValue, CommandControl, EnvRef, ProcessChainLibExecutor};
use http::Version;
use http::header::HeaderName;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame};
use hyper::{Request, StatusCode, http};
use hyper_util::rt::TokioIo;
use regex::Regex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::fmt::Debug as FmtDebug;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Sleep, timeout};
use tokio_rustls::TlsConnector;
use url::Url;

/// A trusted upstream entry: a single IP (`10.0.0.1`) or a CIDR block
/// (`10.0.0.0/8`, `fd00::/8`).
#[derive(Debug, Clone)]
pub struct TrustedUpstreamMatcher {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedUpstreamMatcher {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let pattern = pattern.trim();
        let (addr_str, prefix) = match pattern.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| format!("invalid CIDR prefix in '{}'", pattern))?;
                (addr, Some(prefix))
            }
            None => (pattern, None),
        };
        let network: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid IP address in '{}'", pattern))?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = prefix.unwrap_or(max_prefix);
        if prefix_len > max_prefix {
            return Err(format!("CIDR prefix out of range in '{}'", pattern));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        fn prefix_eq(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
            let full = (prefix_len / 8) as usize;
            let rem = prefix_len % 8;
            if a[..full] != b[..full] {
                return false;
            }
            if rem == 0 {
                return true;
            }
            let mask = 0xffu8 << (8 - rem);
            (a[full] & mask) == (b[full] & mask)
        }
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

pub fn parse_trusted_upstreams(patterns: &[String]) -> ServerResult<Vec<TrustedUpstreamMatcher>> {
    patterns
        .iter()
        .map(|pattern| {
            TrustedUpstreamMatcher::parse(pattern)
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))
        })
        .collect()
}

fn parse_forwarded_entry(entry: &str) -> Option<(String, IpAddr)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some((entry.to_string(), addr.ip()));
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some((entry.to_string(), ip));
    }
    None
}

/// Derive the original client address from forwarded headers sent by a
/// trusted upstream. Walks `X-Forwarded-For` right-to-left, skipping trusted
/// hops; the first untrusted entry is the client (if every entry is trusted,
/// the leftmost one is used). A malformed entry poisons the whole header.
/// Falls back to `X-Real-IP` (+ optional `X-Real-Port`).
fn resolve_trusted_forwarded_source(
    headers: &http::HeaderMap,
    trusted: &[TrustedUpstreamMatcher],
) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        if let Ok(value) = value.to_str() {
            entries.extend(
                value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
    }

    let mut candidate: Option<String> = None;
    for entry in entries.iter().rev() {
        match parse_forwarded_entry(entry) {
            Some((addr, ip)) => {
                candidate = Some(addr);
                if !trusted.iter().any(|m| m.matches(&ip)) {
                    break;
                }
            }
            None => {
                candidate = None;
                break;
            }
        }
    }
    if candidate.is_some() {
        return candidate;
    }

    let real_ip = headers.get("x-real-ip")?.to_str().ok()?.trim().to_string();
    if let Ok(addr) = real_ip.parse::<SocketAddr>() {
        return Some(addr.to_string());
    }
    let ip = real_ip.parse::<IpAddr>().ok()?;
    if let Some(port) = headers
        .get("x-real-port")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        return Some(SocketAddr::new(ip, port).to_string());
    }
    Some(ip.to_string())
}

pub struct ProcessChainHttpServerBuilder {
    id: Option<String>,
    version: Option<String>,
    h3_port: Option<u16>,
    hook_point: Option<ProcessChainConfigs>,
    post_hook_point: Option<ProcessChainConfigs>,
    global_process_chains: Option<GlobalProcessChainsRef>,
    js_externals: Option<JsExternalsManagerRef>,
    server_mgr: Option<ServerManagerWeakRef>,
    tunnel_manager: Option<TunnelManager>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    compression: HttpCompressionSettings,
    forward_timeouts: ForwardUpstreamTimeouts,
    trusted_upstreams: Vec<String>,
}

// Add setter methods for HttpServerBuilder
impl ProcessChainHttpServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn post_hook_point(mut self, post_hook_point: ProcessChainConfigs) -> Self {
        self.post_hook_point = Some(post_hook_point);
        self
    }

    pub fn global_process_chains(mut self, global_process_chains: GlobalProcessChainsRef) -> Self {
        self.global_process_chains = Some(global_process_chains);
        self
    }

    pub fn js_externals(mut self, js_externals: JsExternalsManagerRef) -> Self {
        self.js_externals = Some(js_externals);
        self
    }

    pub fn server_mgr(mut self, server_mgr: ServerManagerWeakRef) -> Self {
        self.server_mgr = Some(server_mgr);
        self
    }

    pub fn h3_port(mut self, h3_port: u16) -> Self {
        self.h3_port = Some(h3_port);
        self
    }

    pub fn tunnel_manager(mut self, tunnel_manager: TunnelManager) -> Self {
        self.tunnel_manager = Some(tunnel_manager);
        self
    }

    pub fn global_collection_manager(
        mut self,
        global_collection_manager: GlobalCollectionManagerRef,
    ) -> Self {
        self.global_collection_manager = Some(global_collection_manager);
        self
    }

    pub fn compression(mut self, compression: HttpCompressionSettings) -> Self {
        self.compression = compression;
        self
    }

    fn forward_timeouts(mut self, forward_timeouts: ForwardUpstreamTimeouts) -> Self {
        self.forward_timeouts = forward_timeouts;
        self
    }

    /// Upstream IPs/CIDRs whose `X-Forwarded-For` / `X-Real-IP` headers may be
    /// converted into `real_source_*`. Forwarded headers from any other peer
    /// are treated as plain input data.
    pub fn trusted_upstreams(mut self, trusted_upstreams: Vec<String>) -> Self {
        self.trusted_upstreams = trusted_upstreams;
        self
    }

    pub async fn build(self) -> ServerResult<ProcessChainHttpServer> {
        ProcessChainHttpServer::create_server(self).await
    }

    fn build_compression_settings(
        config: &ProcessChainHttpServerConfig,
    ) -> ServerResult<HttpCompressionSettings> {
        let gzip_http_version = parse_gzip_http_version(&config.gzip_http_version)?;
        let gzip_disable = match config.gzip_disable.as_ref() {
            Some(expr) => Some(Regex::new(expr).map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid gzip_disable regex: {}",
                    e
                )
            })?),
            None => None,
        };

        Ok(HttpCompressionSettings {
            gzip: config.gzip,
            gzip_request: config.gzip_request,
            gzip_types: normalize_content_types(&config.gzip_types),
            gzip_min_length: config.gzip_min_length,
            gzip_comp_level: clamp_gzip_comp_level(config.gzip_comp_level),
            gzip_http_version,
            gzip_vary: config.gzip_vary,
            gzip_disable,
            brotli: config.brotli,
            brotli_types: normalize_content_types(&config.brotli_types),
            brotli_min_length: config.brotli_min_length,
            brotli_comp_level: clamp_brotli_comp_level(config.brotli_comp_level),
        })
    }
}

pub struct ProcessChainHttpServer {
    id: String,
    version: http::Version,
    h3_port: Option<u16>,
    server_mgr: ServerManagerWeakRef,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    post_executor: Option<Arc<Mutex<ProcessChainLibExecutor>>>,
    tunnel_manager: TunnelManager,
    compression: HttpCompressionSettings,
    forward_timeouts: ForwardUpstreamTimeouts,
    trusted_upstreams: Vec<TrustedUpstreamMatcher>,
}

#[derive(Clone)]
struct ForwardUpstreamTimeouts {
    connect_timeout: Duration,
    tls_handshake_timeout: Duration,
    http_handshake_timeout: Duration,
    request_timeout: Duration,
    response_header_timeout: Duration,
    response_body_idle_timeout: Duration,
    post_chain_timeout: Duration,
    abort_upstream_on_client_close: bool,
}

impl Default for ForwardUpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(60),
            tls_handshake_timeout: Duration::from_secs(60),
            http_handshake_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(60),
            response_header_timeout: Duration::from_secs(60),
            response_body_idle_timeout: Duration::from_secs(60),
            post_chain_timeout: Duration::from_secs(60),
            abort_upstream_on_client_close: true,
        }
    }
}

impl ForwardUpstreamTimeouts {
    fn from_config(config: Option<&ForwardUpstreamTimeoutConfig>) -> Self {
        let mut timeouts = Self::default();
        if let Some(config) = config {
            if let Some(value) = config.connect_timeout {
                timeouts.connect_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.tls_handshake_timeout {
                timeouts.tls_handshake_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.http_handshake_timeout {
                timeouts.http_handshake_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.request_timeout {
                timeouts.request_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.response_header_timeout {
                timeouts.response_header_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.response_body_idle_timeout {
                timeouts.response_body_idle_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.post_chain_timeout {
                timeouts.post_chain_timeout = Duration::from_secs(value);
            }
            if let Some(value) = config.abort_upstream_on_client_close {
                timeouts.abort_upstream_on_client_close = value;
            }
        }
        timeouts
    }
}

struct UpstreamBody<B> {
    inner: Pin<Box<B>>,
    idle_timeout: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    abort_on_drop: Option<JoinHandle<()>>,
}

impl<B> UpstreamBody<B> {
    fn new(body: B, idle_timeout: Duration, abort_on_drop: Option<JoinHandle<()>>) -> Self {
        Self {
            inner: Box::pin(body),
            idle_timeout,
            sleep: None,
            abort_on_drop,
        }
    }
}

impl<B> Body for UpstreamBody<B>
where
    B: Body<Data = Bytes, Error = ServerError>,
{
    type Data = Bytes;
    type Error = ServerError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(frame) => {
                this.sleep = None;
                if frame.is_none() {
                    this.abort_on_drop = None;
                }
                Poll::Ready(frame)
            }
            Poll::Pending => {
                if this.sleep.is_none() {
                    this.sleep = Some(Box::pin(tokio::time::sleep(this.idle_timeout)));
                }

                if let Some(sleep) = this.sleep.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Some(Err(ServerError::new(
                            ServerErrorCode::StreamError,
                            "upstream response body idle timeout".to_string(),
                        ))));
                    }
                }

                Poll::Pending
            }
        }
    }
}

impl<B> Drop for UpstreamBody<B> {
    fn drop(&mut self) {
        if let Some(handle) = self.abort_on_drop.take() {
            handle.abort();
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerifier;

impl ServerCertVerifier for NoCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl Drop for ProcessChainHttpServer {
    fn drop(&mut self) {
        debug!("ProcessChainHttpServer {} drop", self.id);
    }
}

impl ProcessChainHttpServer {
    fn request_header_value<'a>(
        req: &'a http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        name: &str,
    ) -> &'a str {
        req.headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
    }

    fn request_version(version: http::Version) -> &'static str {
        match version {
            http::Version::HTTP_09 => "HTTP/0.9",
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2.0",
            http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/?",
        }
    }

    fn upstream_sni_host(request_url: &Url) -> ServerResult<String> {
        request_url
            .host_str()
            .map(|h| h.to_string())
            .ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "Missing SNI host for upstream: {}",
                    request_url
                )
            })
    }

    /// Connect outcome carrying the bucket needed for tunnel_mgr history
    /// classification (§6.7.3). Used by `connect_upstream_with_fallback`
    /// so callers can write the right `TunnelFailureReason` without
    /// re-parsing error strings.
    fn classify_connect_errors(errors: &[(String, String, bool)]) -> TunnelFailureReason {
        // errors: (addr, message, is_timeout)
        // Prefer the most specific bucket. ConnectRefused beats Timeout
        // beats anything else, since refusal is a definitive signal that
        // the host exists but isn't listening.
        let mut saw_refused = false;
        let mut saw_timeout = false;
        for (_, msg, is_timeout) in errors {
            if *is_timeout {
                saw_timeout = true;
            } else if msg.to_ascii_lowercase().contains("refused") {
                saw_refused = true;
            }
        }
        if saw_refused {
            TunnelFailureReason::ConnectRefused
        } else if saw_timeout {
            TunnelFailureReason::ConnectTimeout
        } else {
            TunnelFailureReason::PreConnectRoute
        }
    }

    async fn connect_upstream_candidates(
        candidates: Vec<SocketAddr>,
        connect_timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), (TunnelFailureReason, String)> {
        if candidates.is_empty() {
            return Err((
                TunnelFailureReason::PreConnectDns,
                "No upstream socket addresses resolved".to_string(),
            ));
        }

        let mut errors: Vec<(String, String, bool)> = Vec::new();
        for addr in candidates {
            match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok((stream, addr)),
                Ok(Err(err)) => errors.push((addr.to_string(), err.to_string(), false)),
                Err(_) => errors.push((addr.to_string(), "connect timeout".to_string(), true)),
            }
        }

        let reason = Self::classify_connect_errors(&errors);
        let msg = errors
            .into_iter()
            .map(|(a, m, _)| format!("{} ({})", a, m))
            .collect::<Vec<_>>()
            .join(", ");
        Err((reason, msg))
    }

    async fn connect_upstream_with_fallback(
        connect_host: &str,
        connect_port: u16,
        connect_timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), (TunnelFailureReason, String)> {
        let candidates: Vec<SocketAddr> = match lookup_host((connect_host, connect_port)).await {
            Ok(it) => it.collect(),
            Err(e) => {
                return Err((
                    TunnelFailureReason::PreConnectDns,
                    format!("resolve {}:{} failed: {}", connect_host, connect_port, e),
                ));
            }
        };
        Self::connect_upstream_candidates(candidates, connect_timeout).await
    }

    fn upstream_timeout(stage: &str, target: impl std::fmt::Display) -> ServerError {
        ServerError::new(
            ServerErrorCode::StreamError,
            format!("upstream {} timeout: {}", stage, target),
        )
    }

    fn wrap_upstream_body<B, E>(
        body: B,
        idle_timeout: Duration,
        abort_on_drop: Option<JoinHandle<()>>,
    ) -> UnsyncBoxBody<Bytes, ServerError>
    where
        B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
        E: FmtDebug + 'static,
    {
        UpstreamBody::new(
            body.map_err(|e| ServerError::new(ServerErrorCode::StreamError, format!("{:?}", e))),
            idle_timeout,
            abort_on_drop,
        )
        .boxed_unsync()
    }

    /// Best-effort: parse a candidate URL string into a `Url` suitable
    /// as the tunnel_mgr history key. Returns `None` if parsing fails;
    /// callers fall back to skipping history writeback in that case
    /// (we never want history bookkeeping to mask the real error).
    fn upstream_history_key(target_url: &str) -> Option<Url> {
        Url::parse(target_url).ok()
    }

    fn origin_form_uri(raw_uri: &str) -> String {
        if raw_uri.starts_with('/') {
            return raw_uri.to_string();
        }

        if let Ok(url) = Url::parse(raw_uri) {
            let mut origin = url.path().to_string();
            if origin.is_empty() {
                origin.push('/');
            }
            if let Some(query) = url.query() {
                origin.push('?');
                origin.push_str(query);
            }
            return origin;
        }

        raw_uri.to_string()
    }

    pub fn builder() -> ProcessChainHttpServerBuilder {
        ProcessChainHttpServerBuilder {
            id: None,
            version: None,
            h3_port: None,
            hook_point: None,
            post_hook_point: None,
            global_process_chains: None,
            js_externals: None,
            server_mgr: None,
            tunnel_manager: None,
            global_collection_manager: None,
            compression: HttpCompressionSettings::default(),
            forward_timeouts: ForwardUpstreamTimeouts::default(),
            trusted_upstreams: Vec::new(),
        }
    }

    async fn create_server(
        builder: ProcessChainHttpServerBuilder,
    ) -> ServerResult<ProcessChainHttpServer> {
        if builder.id.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidConfig, "id is none"));
        }

        if builder.hook_point.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "hook_point is none"
            ));
        }

        let server_mgr = builder.server_mgr.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "server_mgr is none"
        ))?;
        let server_mgr_ref = server_mgr.upgrade().ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "server_mgr is unavailable"
        ))?;

        if builder.tunnel_manager.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "tunnel_manager is none"
            ));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => match version.as_str() {
                "HTTP/0.9" => http::Version::HTTP_09,
                "HTTP/1.0" => http::Version::HTTP_10,
                "HTTP/1.1" => http::Version::HTTP_11,
                "HTTP/2" => http::Version::HTTP_2,
                "HTTP/3" => http::Version::HTTP_3,
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid http version"
                    ));
                }
            },
            None => http::Version::HTTP_11,
        };

        let global_process_chains = builder.global_process_chains.clone();
        let global_collection_manager = builder.global_collection_manager.clone();
        let external_commands = Some(get_external_commands(Arc::downgrade(&server_mgr_ref)));
        let (executor, _) = create_process_chain_executor(
            builder.hook_point.as_ref().unwrap(),
            global_process_chains.clone(),
            global_collection_manager.clone(),
            external_commands.clone(),
            builder.js_externals.clone(),
        )
        .await
        .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        let post_executor = if let Some(post_hook_point) = builder.post_hook_point.as_ref() {
            let (post_executor, _) = create_process_chain_executor(
                post_hook_point,
                global_process_chains,
                global_collection_manager,
                external_commands,
                builder.js_externals,
            )
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
            Some(Arc::new(Mutex::new(post_executor)))
        } else {
            None
        };
        let trusted_upstreams = parse_trusted_upstreams(&builder.trusted_upstreams)?;
        Ok(ProcessChainHttpServer {
            id: builder.id.unwrap(),
            version,
            h3_port: builder.h3_port,
            server_mgr,
            executor: Arc::new(Mutex::new(executor)),
            post_executor,
            tunnel_manager: builder.tunnel_manager.unwrap(),
            compression: builder.compression,
            forward_timeouts: builder.forward_timeouts,
            trusted_upstreams,
        })
    }

    fn inject_forward_headers(header: &mut http::HeaderMap, info: &StreamInfo) {
        let Some(addr) = info
            .src_addr
            .as_deref()
            .and_then(|s| s.parse::<SocketAddr>().ok())
        else {
            return;
        };
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        if !header.contains_key("X-Real-IP") {
            if let Ok(v) = http::HeaderValue::from_str(&ip) {
                header.insert("X-Real-IP", v);
            }
        }
        if !header.contains_key("X-Real-Port") {
            if let Ok(v) = http::HeaderValue::from_str(&port) {
                header.insert("X-Real-Port", v);
            }
        }
        let xff = match header.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
            Some(existing) => format!("{}, {}", existing, ip),
            None => ip,
        };
        if let Ok(v) = http::HeaderValue::from_str(&xff) {
            header.insert("X-Forwarded-For", v);
        }
    }

    fn strip_hop_by_hop_headers(header: &mut http::HeaderMap) {
        let mut connection_tokens = Vec::new();
        for value in header.get_all(http::header::CONNECTION).iter() {
            let Ok(value) = value.to_str() else {
                continue;
            };
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                    connection_tokens.push(name);
                }
            }
        }

        for name in connection_tokens {
            header.remove(name);
        }

        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            header.remove(name);
        }
    }

    fn strip_forward_response_headers<B>(mut resp: http::Response<B>) -> http::Response<B> {
        Self::strip_hop_by_hop_headers(resp.headers_mut());
        resp
    }

    async fn handle_forward_upstream(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        target_url: &str,
        info: &StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let mut slot = Some(req);
        self.forward_to_candidate(&mut slot, target_url, info).await
    }

    /// Forward the request held by `req_slot` to `target_url`.
    ///
    /// Per §6.3 of `forward机制升级需求.md` the caller must distinguish
    /// connect-stage failures (retryable on next candidate) from
    /// after-body-consumed failures (not retryable). This is signalled
    /// through `req_slot`:
    /// - `Ok(resp)`: `*req_slot == None`. The body has been sent.
    /// - `Err(_)` with `*req_slot == Some(_)`: failure occurred during
    ///   DNS / TCP / TLS / http1 handshake / tunnel open. The body is
    ///   intact and the caller may retry against another candidate.
    /// - `Err(_)` with `*req_slot == None`: failure occurred after the
    ///   body started transmitting. Not retryable.
    async fn forward_to_candidate(
        &self,
        req_slot: &mut Option<http::Request<UnsyncBoxBody<Bytes, ServerError>>>,
        target_url: &str,
        info: &StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let (org_url, mut header, method, version, host_header) = {
            let req_ref = req_slot
                .as_ref()
                .expect("forward_to_candidate: req_slot must be Some on entry");
            let mut h = req_ref.headers().clone();
            Self::inject_forward_headers(&mut h, info);
            let host = req_ref
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            (
                req_ref.uri().to_string(),
                h,
                req_ref.method().clone(),
                req_ref.version(),
                host,
            )
        };
        let timeouts = self.forward_timeouts.clone();
        Self::strip_hop_by_hop_headers(&mut header);
        let client_origin_uri = Self::origin_form_uri(org_url.as_str());
        // Trim URL boundary slashes so we don't end up with "//" when target_url ends with '/'
        // and the request path starts with '/'.
        let raw_url = if target_url.ends_with('/') || client_origin_uri.starts_with('/') {
            let base = target_url.trim_end_matches('/');
            let path = client_origin_uri.trim_start_matches('/');
            format!("{}/{}", base, path)
        } else {
            format!("{}{}", target_url, client_origin_uri)
        };
        let request_url = Url::parse(&raw_url).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "Failed to parse request upstream url {}: {}",
                raw_url,
                e
            )
        })?;
        let upstream_origin_uri = Self::origin_form_uri(request_url.as_str());
        debug!("handle_upstream url: {}", request_url);
        // Per §6.7 we report the outcome of every business attempt to
        // tunnel_mgr against the *candidate* URL (target_url), not the
        // joined request_url with the user's path. Otherwise every
        // distinct path becomes a separate history entry. Skip writeback
        // when the candidate URL fails to parse — that's a config error,
        // not a reachability signal.
        let history_key = Self::upstream_history_key(target_url);
        let scheme = request_url.scheme();
        match scheme {
            "http" => {
                let connect_host = request_url.host_str().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream host in url: {}",
                        request_url
                    )
                })?;
                let connect_port = request_url.port_or_known_default().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream port in url: {}",
                        request_url
                    )
                })?;

                // Pre-flight TCP connect to validate reachability before
                // the body is consumed. Failure here keeps `req_slot`
                // intact so the caller can retry on another candidate
                // per §6.3.
                let started = std::time::Instant::now();
                let (tcp_stream, connected_addr) =
                    match Self::connect_upstream_with_fallback(
                        connect_host,
                        connect_port,
                        timeouts.connect_timeout,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err((reason, msg)) => {
                            if let Some(key) = history_key.as_ref() {
                                self.tunnel_manager
                                    .record_business_failure(key, reason, Some(&msg))
                                    .await;
                            }
                            return Err(server_err!(
                                ServerErrorCode::InvalidConfig,
                                "Failed to connect upstream candidates: {}",
                                msg
                            ));
                        }
                    };

                let (mut sender, conn) =
                    match timeout(
                        timeouts.http_handshake_timeout,
                        hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)),
                    )
                    .await
                    {
                        Err(_) => {
                            if let Some(key) = history_key.as_ref() {
                                self.tunnel_manager
                                    .record_business_failure(
                                        key,
                                        TunnelFailureReason::TunnelOpen,
                                        Some("http handshake timeout"),
                                    )
                                    .await;
                            }
                            return Err(Self::upstream_timeout("http handshake", connected_addr));
                        }
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            if let Some(key) = history_key.as_ref() {
                                let detail = e.to_string();
                                self.tunnel_manager
                                    .record_business_failure(
                                        key,
                                        TunnelFailureReason::TunnelOpen,
                                        Some(&detail),
                                    )
                                    .await;
                            }
                            return Err(server_err!(
                                ServerErrorCode::StreamError,
                                "Failed to build http client connection to {}: {}",
                                connected_addr,
                                e
                            ));
                        }
                    };

                if let Some(key) = history_key.as_ref() {
                    self.tunnel_manager
                        .record_business_success(key, Some(started.elapsed()))
                        .await;
                }
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("http upstream connection closed with error: {}", e);
                    }
                });

                let _ = version;
                let _ = host_header;
                // Connection up — taking the body now is the
                // commitment point. Any subsequent failure is
                // post-body and non-retryable.
                let req = req_slot
                    .take()
                    .expect("forward_to_candidate: req_slot drained mid-flight");
                let body = req
                    .into_body()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed_unsync();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(upstream_origin_uri.as_str())
                    .body(body)
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::InvalidConfig,
                            "Failed to build request: {}",
                            e
                        )
                })?;
                *upstream_req.headers_mut() = std::mem::take(&mut header);

                let resp = timeout(
                    timeouts
                        .response_header_timeout
                        .min(timeouts.request_timeout),
                    sender.send_request(upstream_req),
                )
                .await
                .map_err(|_| Self::upstream_timeout("response header", &request_url))?
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Failed to request upstream {}: {}",
                        request_url,
                        e
                    )
                })?;
                let resp = Self::strip_forward_response_headers(resp);
                let resp = resp.map(|body| {
                    Self::wrap_upstream_body(body, timeouts.response_body_idle_timeout, None)
                });
                Ok(resp)
            }
            "https" => {
                let upstream_http_version = match version {
                    http::Version::HTTP_10 => http::Version::HTTP_10,
                    http::Version::HTTP_11 => http::Version::HTTP_11,
                    _ => http::Version::HTTP_11,
                };

                let connect_host = request_url.host_str().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream host in url: {}",
                        request_url
                    )
                })?;
                let connect_port = request_url.port_or_known_default().ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Missing upstream port in url: {}",
                        request_url
                    )
                })?;

                // SNI must target the upstream host, not the inbound Host header.
                let sni_host = Self::upstream_sni_host(&request_url)?;

                // Wall-clock timer for "connection establishment" — TCP
                // connect through hyper handshake. send_request /
                // upstream app processing is excluded so RTT history
                // reflects path quality, not application latency.
                let started = std::time::Instant::now();

                let (tcp_stream, connected_addr) =
                    match Self::connect_upstream_with_fallback(
                        connect_host,
                        connect_port,
                        timeouts.connect_timeout,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err((reason, msg)) => {
                            if let Some(key) = history_key.as_ref() {
                                self.tunnel_manager
                                    .record_business_failure(key, reason, Some(&msg))
                                    .await;
                            }
                            return Err(server_err!(
                                ServerErrorCode::InvalidConfig,
                                "Failed to connect upstream candidates: {}",
                                msg
                            ));
                        }
                    };

                let tls_config = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| {
                    server_err!(ServerErrorCode::InvalidConfig, "Invalid tls config: {}", e)
                })?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerifier))
                .with_no_client_auth();
                let tls_connector = TlsConnector::from(Arc::new(tls_config));
                let server_name = ServerName::try_from(sni_host.clone()).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Invalid upstream host for tls {}: {}",
                        sni_host,
                        e
                    )
                })?;
                let tls_stream = match timeout(
                    timeouts.tls_handshake_timeout,
                    tls_connector.connect(server_name, tcp_stream),
                )
                .await
                {
                    Err(_) => {
                        if let Some(key) = history_key.as_ref() {
                            self.tunnel_manager
                                .record_business_failure(
                                    key,
                                    TunnelFailureReason::TlsHandshake,
                                    Some("tls handshake timeout"),
                                )
                                .await;
                        }
                        return Err(Self::upstream_timeout("tls handshake", &sni_host));
                    }
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        if let Some(key) = history_key.as_ref() {
                            let detail = e.to_string();
                            self.tunnel_manager
                                .record_business_failure(
                                    key,
                                    TunnelFailureReason::TlsHandshake,
                                    Some(&detail),
                                )
                                .await;
                        }
                        return Err(server_err!(
                            ServerErrorCode::InvalidConfig,
                            "Failed tls handshake with upstream {} via {}: {}",
                            sni_host,
                            connected_addr,
                            e
                        ));
                    }
                };

                let (mut sender, conn) =
                    match timeout(
                        timeouts.http_handshake_timeout,
                        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
                    )
                    .await
                    {
                        Err(_) => {
                            if let Some(key) = history_key.as_ref() {
                                self.tunnel_manager
                                    .record_business_failure(
                                        key,
                                        TunnelFailureReason::TunnelOpen,
                                        Some("http handshake timeout"),
                                    )
                                    .await;
                            }
                            return Err(Self::upstream_timeout("http handshake", &sni_host));
                        }
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            if let Some(key) = history_key.as_ref() {
                                let detail = e.to_string();
                                self.tunnel_manager
                                    .record_business_failure(
                                        key,
                                        TunnelFailureReason::TunnelOpen,
                                        Some(&detail),
                                    )
                                    .await;
                            }
                            return Err(server_err!(
                                ServerErrorCode::StreamError,
                                "Failed to build https client connection: {}",
                                e
                            ));
                        }
                    };

                // Connection establishment succeeded — record reachable
                // with the elapsed RTT before we even attempt the
                // request. send_request failures from here on are
                // upstream app health, not URL reachability (§6.7.2),
                // so they are NOT mirrored back to tunnel_mgr.
                if let Some(key) = history_key.as_ref() {
                    self.tunnel_manager
                        .record_business_success(key, Some(started.elapsed()))
                        .await;
                }
                let mut connection_task = Some(tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("https upstream connection closed with error: {}", e);
                    }
                }));

                let _ = host_header;
                let req = req_slot
                    .take()
                    .expect("forward_to_candidate: req_slot drained mid-flight");
                let body = req
                    .into_body()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed_unsync();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(upstream_origin_uri.as_str())
                    .version(upstream_http_version)
                    .body(body)
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::BadRequest,
                            "Failed to build https upstream request: {}",
                            e
                        )
                })?;
                *upstream_req.headers_mut() = std::mem::take(&mut header);

                let resp = match timeout(
                    timeouts
                        .response_header_timeout
                        .min(timeouts.request_timeout),
                    sender.send_request(upstream_req),
                )
                .await
                {
                    Err(_) => {
                        if let Some(connection_task) = connection_task.take() {
                            connection_task.abort();
                        }
                        return Err(Self::upstream_timeout("response header", &sni_host));
                    }
                    Ok(Err(e)) => {
                        if let Some(connection_task) = connection_task.take() {
                            connection_task.abort();
                        }
                        return Err(server_err!(
                            ServerErrorCode::InvalidConfig,
                            "Failed to request https upstream {} via {}: {}",
                            sni_host,
                            connected_addr,
                            e
                        ));
                    }
                    Ok(Ok(resp)) => resp,
                };
                let resp = Self::strip_forward_response_headers(resp);
                let abort_on_drop = if timeouts.abort_upstream_on_client_close {
                    connection_task.take()
                } else {
                    None
                };
                let resp = resp.map(|body| {
                    Self::wrap_upstream_body(
                        body,
                        timeouts.response_body_idle_timeout,
                        abort_on_drop,
                    )
                });
                Ok(resp)
            }
            _ => {
                // Pre-flight: open the tunnel stream first so a tunnel
                // open failure leaves `req_slot` intact for the caller
                // to retry on another candidate. tunnel_manager itself
                // writes URL history on the underlying open per §6.7.
                let tunnel_url = Url::parse(target_url).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid forward url {}: {}",
                        target_url,
                        e
                    )
                })?;
                let stream = match self.tunnel_manager.open_stream_by_url(&tunnel_url).await {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(server_err!(
                            ServerErrorCode::TunnelError,
                            "Failed to open tunnel to {}: {}",
                            target_url,
                            e
                        ));
                    }
                };

                let (mut sender, conn) = match timeout(
                    timeouts.http_handshake_timeout,
                    hyper::client::conn::http1::handshake(TokioIo::new(
                        crate::tunnel_connector::TunnelStreamConnection::new(stream),
                    )),
                )
                .await
                {
                    Err(_) => {
                        return Err(Self::upstream_timeout("http handshake", target_url));
                    }
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        return Err(server_err!(
                            ServerErrorCode::StreamError,
                            "Failed to build tunnel client connection to {}: {}",
                            target_url,
                            e
                        ));
                    }
                };
                let connection_task = tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("tunnel upstream connection closed with error: {}", e);
                    }
                });

                let _ = version;
                let req = req_slot
                    .take()
                    .expect("forward_to_candidate: req_slot drained mid-flight");
                let body = req
                    .into_body()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed_unsync();
                let mut upstream_req = Request::builder()
                    .method(method)
                    .uri(client_origin_uri.as_str())
                    .body(body)
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::BadRequest,
                            "Failed to build upstream_req: {}",
                            e
                        )
                })?;
                *upstream_req.headers_mut() = std::mem::take(&mut header);

                let resp = timeout(
                    timeouts
                        .response_header_timeout
                        .min(timeouts.request_timeout),
                    sender.send_request(upstream_req),
                )
                .await
                .map_err(|_| Self::upstream_timeout("response header", target_url))?
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::TunnelError,
                        "Failed to request upstream {}: {}",
                        target_url,
                        e
                    )
                })?;
                let resp = Self::strip_forward_response_headers(resp);
                let resp = resp.map(|body| {
                    let abort_on_drop = if timeouts.abort_upstream_on_client_close {
                        Some(connection_task)
                    } else {
                        None
                    };
                    Self::wrap_upstream_body(body, timeouts.response_body_idle_timeout, abort_on_drop)
                });
                Ok(resp)
            }
        }
    }

    /// Walk the candidates of a `ForwardPlan`, performing a connection-stage
    /// probe on each (TCP connect / TLS handshake / tunnel open) and
    /// forwarding the request through the first reachable candidate.
    ///
    /// Stage 2 (§6.3): connection-stage failure → next candidate.
    /// Stage 3 (§6.3 + §8 阶段3): when the policy enables HTTP-status retry
    /// (`http_5xx`, `http_502`, etc.), the request body is buffered up to
    /// `policy.max_body_buffer_bytes` and replayed against the next
    /// candidate. Buffering is suppressed for non-idempotent methods
    /// unless the policy explicitly opts in via `non_idempotent`. If the
    /// body exceeds the buffer cap we fall back to "send once" semantics
    /// for the chosen candidate so an oversized POST doesn't quietly
    /// behave differently — the caller sees the upstream's actual
    /// response.
    /// Stage 4 (§8 阶段4): when `plan.balance == LeastTime` we ask
    /// tunnel_mgr for an RTT-sorted candidate order before iterating.
    async fn handle_forward_group_upstream(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        plan: &ForwardPlan,
        info: &StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        // Stage 4: RTT-aware reordering before iteration.
        let mut plan_local;
        let plan: &ForwardPlan = if matches!(plan.balance, BalanceMethod::LeastTime) {
            plan_local = plan.clone();
            apply_least_time_via_tunnel_mgr(&mut plan_local, &self.tunnel_manager).await;
            &plan_local
        } else {
            plan
        };

        let policy = &plan.next_upstream;

        // Stage 3: decide whether HTTP-status retry is possible for
        // this request. Conditions:
        //   - policy enables some HTTP status condition,
        //   - tries > 1,
        //   - method is idempotent OR policy explicitly opted in via
        //     `non_idempotent`,
        //   - max_body_buffer_bytes > 0.
        let method_class = HttpMethodClass::classify(req.method().as_str());
        let method_replay_allowed = method_class.is_idempotent() || policy.allow_non_idempotent();
        let http_status_retry_armed = policy.is_enabled()
            && policy.any_http_status()
            && method_replay_allowed
            && policy.max_body_buffer_bytes > 0;

        if http_status_retry_armed {
            return self
                .handle_forward_group_with_status_retry(req, plan, info)
                .await;
        }

        // Stage 2 path: connection-stage retry only, body forwarded
        // once after probing the chosen candidate.
        self.handle_forward_group_connect_only(req, plan, info)
            .await
    }

    /// Connection-stage retry only (§6.3). The body is sent only after
    /// `forward_to_candidate` confirms the connection is up; failures
    /// before that point leave `req_slot` populated so we can retry on
    /// the next candidate. Once a candidate has consumed the body we
    /// surface its result without further retry.
    async fn handle_forward_group_connect_only(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        plan: &ForwardPlan,
        info: &StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let registry = ForwardFailureRegistry::global();
        let group_key = plan.failure_state_key();
        let policy = &plan.next_upstream;
        let candidate_count = plan.candidates.len();
        let max_attempts = if !policy.is_enabled() {
            candidate_count.min(1).max(1)
        } else if policy.tries == 0 {
            candidate_count
        } else {
            (policy.tries as usize).min(candidate_count)
        };
        let deadline = policy.timeout.map(|d| std::time::Instant::now() + d);

        let mut last_err: Option<ServerError> = None;
        let mut req_slot = Some(req);

        for (idx, candidate) in plan.candidates.iter().enumerate() {
            if idx >= max_attempts {
                break;
            }
            if req_slot.is_none() {
                // Body already consumed by a prior candidate but the
                // upstream-side failure was non-retryable. Surface what
                // we have rather than loop without a request.
                break;
            }
            if let Some(d) = deadline {
                if std::time::Instant::now() >= d {
                    last_err.get_or_insert_with(|| {
                        server_err!(
                            ServerErrorCode::TunnelError,
                            "forward-group {} next_upstream timeout exceeded before idx={}",
                            group_key,
                            idx
                        )
                    });
                    break;
                }
            }

            let attempt_fut = self.forward_to_candidate(&mut req_slot, &candidate.url, info);
            let (attempt_res, attempt_cond) = match deadline {
                Some(d) => {
                    let remaining = d.saturating_duration_since(std::time::Instant::now());
                    match timeout(remaining, attempt_fut).await {
                        Ok(r) => (r, NextUpstreamCondition::Error),
                        Err(_) => (
                            Err(server_err!(
                                ServerErrorCode::TunnelError,
                                "forward-group {} forward to {} timed out (next_upstream budget {}ms)",
                                group_key,
                                candidate.url,
                                policy.timeout.unwrap_or_default().as_millis()
                            )),
                            NextUpstreamCondition::Timeout,
                        ),
                    }
                }
                None => (attempt_fut.await, NextUpstreamCondition::Error),
            };
            match attempt_res {
                Ok(resp) => {
                    registry.record_success(&group_key, &candidate.url);
                    log::debug!(
                        "forward-group {}: http selected candidate idx={} url={}",
                        group_key,
                        idx,
                        candidate.url
                    );
                    return Ok(resp);
                }
                Err(e) => {
                    log::debug!(
                        "forward-group {}: http candidate {} (idx {}) failed: {}",
                        group_key,
                        candidate.url,
                        idx,
                        e
                    );
                    registry.record_failure(
                        &group_key,
                        &candidate.url,
                        candidate.max_fails,
                        candidate.fail_timeout,
                    );
                    last_err = Some(e);
                    if req_slot.is_none() {
                        // Body was consumed before/during this attempt;
                        // we cannot replay on another candidate.
                        break;
                    }
                    if !policy.is_enabled()
                        || !policy.allows(attempt_cond)
                        || idx + 1 >= max_attempts
                    {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            server_err!(
                ServerErrorCode::TunnelError,
                "forward-group {} exhausted candidates",
                group_key
            )
        }))
    }

    /// Status-aware retry. Buffers the body up to
    /// `policy.max_body_buffer_bytes`, then walks candidates until one
    /// returns a non-retryable status. Connection-stage failures and
    /// matching upstream HTTP statuses both consume an attempt.
    async fn handle_forward_group_with_status_retry(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        plan: &ForwardPlan,
        info: &StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let registry = ForwardFailureRegistry::global();
        let group_key = plan.failure_state_key();
        let policy = &plan.next_upstream;
        let candidate_count = plan.candidates.len();
        let max_attempts = if !policy.is_enabled() {
            candidate_count.min(1).max(1)
        } else if policy.tries == 0 {
            candidate_count
        } else {
            (policy.tries as usize).min(candidate_count)
        };

        let (req_parts, body) = req.into_parts();
        let buffered_body = match Self::buffer_body(body, policy.max_body_buffer_bytes).await? {
            Some(b) => b,
            None => {
                // Body exceeded the configured cap. We can no longer
                // safely replay; degrade to the connect-only path with
                // a placeholder empty body — we already consumed the
                // original. To avoid silently dropping the body we
                // surface a 413-style error so callers notice this is a
                // configuration issue (cap too small), not a black
                // hole.
                log::warn!(
                    "forward-group {}: body exceeded max_body_buffer_bytes={}, status-retry disabled",
                    group_key,
                    policy.max_body_buffer_bytes
                );
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "request body exceeded forward group max_body_buffer_bytes={}",
                    policy.max_body_buffer_bytes
                ));
            }
        };

        let mut last_err: Option<ServerError> = None;
        let mut last_status_resp: Option<http::Response<UnsyncBoxBody<Bytes, ServerError>>> = None;
        let deadline = policy.timeout.map(|d| std::time::Instant::now() + d);

        for (idx, candidate) in plan.candidates.iter().enumerate() {
            if idx >= max_attempts {
                break;
            }
            if let Some(d) = deadline {
                if std::time::Instant::now() >= d {
                    last_err.get_or_insert_with(|| {
                        server_err!(
                            ServerErrorCode::TunnelError,
                            "forward-group {} next_upstream timeout exceeded before idx={}",
                            group_key,
                            idx
                        )
                    });
                    break;
                }
            }
            let body = Self::full_body(buffered_body.clone());
            let mut attempt_req = http::Request::from_parts(req_parts.clone(), body);
            Self::set_content_length(&mut attempt_req);
            let mut req_slot = Some(attempt_req);

            let attempt_fut = self.forward_to_candidate(&mut req_slot, &candidate.url, info);
            let (attempt_res, attempt_cond) = match deadline {
                Some(d) => {
                    let remaining = d.saturating_duration_since(std::time::Instant::now());
                    match timeout(remaining, attempt_fut).await {
                        Ok(r) => (r, NextUpstreamCondition::Error),
                        Err(_) => (
                            Err(server_err!(
                                ServerErrorCode::TunnelError,
                                "forward-group {} forward to {} timed out (next_upstream budget {}ms)",
                                group_key,
                                candidate.url,
                                policy.timeout.unwrap_or_default().as_millis()
                            )),
                            NextUpstreamCondition::Timeout,
                        ),
                    }
                }
                None => (attempt_fut.await, NextUpstreamCondition::Error),
            };
            match attempt_res {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if policy.matches_http_status(status) && idx + 1 < max_attempts {
                        log::debug!(
                            "forward-group {}: candidate {} returned {}, retrying next candidate",
                            group_key,
                            candidate.url,
                            status
                        );
                        registry.record_failure(
                            &group_key,
                            &candidate.url,
                            candidate.max_fails,
                            candidate.fail_timeout,
                        );
                        last_status_resp = Some(r);
                        continue;
                    }
                    registry.record_success(&group_key, &candidate.url);
                    log::debug!(
                        "forward-group {}: http selected candidate idx={} url={} (status-retry armed)",
                        group_key,
                        idx,
                        candidate.url
                    );
                    return Ok(r);
                }
                Err(e) => {
                    log::debug!(
                        "forward-group {}: candidate {} request failed: {}",
                        group_key,
                        candidate.url,
                        e
                    );
                    registry.record_failure(
                        &group_key,
                        &candidate.url,
                        candidate.max_fails,
                        candidate.fail_timeout,
                    );
                    last_err = Some(e);
                    if !policy.allows(attempt_cond) || idx + 1 >= max_attempts {
                        break;
                    }
                    continue;
                }
            }
        }

        if let Some(r) = last_status_resp {
            return Ok(r);
        }

        Err(last_err.unwrap_or_else(|| {
            server_err!(
                ServerErrorCode::TunnelError,
                "forward-group {} exhausted candidates",
                group_key
            )
        }))
    }

    /// Buffer at most `cap` bytes of the request body. Returns
    /// `Ok(Some(bytes))` if the body fit within the cap, `Ok(None)`
    /// if it exceeded the cap (in which case retry is no longer safe
    /// for this request).
    async fn buffer_body(
        body: UnsyncBoxBody<Bytes, ServerError>,
        cap: u64,
    ) -> ServerResult<Option<Bytes>> {
        let cap = cap as usize;
        let collected = body.collect().await.map_err(|e| {
            server_err!(
                ServerErrorCode::StreamError,
                "buffering request body failed: {:?}",
                e
            )
        })?;
        let bytes = collected.to_bytes();
        if bytes.len() > cap {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    fn full_body(bytes: Bytes) -> UnsyncBoxBody<Bytes, ServerError> {
        Full::new(bytes).map_err(|e| match e {}).boxed_unsync()
    }

    fn set_content_length(req: &mut http::Request<UnsyncBoxBody<Bytes, ServerError>>) {
        use hyper::body::Body;
        let len = req.body().size_hint().exact().unwrap_or(0);
        if let Ok(v) = http::HeaderValue::from_str(&len.to_string()) {
            req.headers_mut().insert(http::header::CONTENT_LENGTH, v);
        }
        // Replayable bodies can't keep Transfer-Encoding: chunked.
        req.headers_mut().remove(http::header::TRANSFER_ENCODING);
    }

    fn parse_redirect_status_code(status: Option<&str>) -> ServerResult<StatusCode> {
        let status_code = match status {
            Some(status) => {
                let code = status.parse::<u16>().map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid redirect status code: {}, {}",
                        status,
                        e
                    )
                })?;
                StatusCode::from_u16(code).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid redirect status code: {}, {}",
                        code,
                        e
                    )
                })?
            }
            None => StatusCode::FOUND,
        };

        match status_code {
            StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT => Ok(status_code),
            _ => Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid redirect status code: {}, supported values are 301, 302, 303, 307, 308",
                status_code.as_u16()
            )),
        }
    }

    fn build_redirect_response(
        &self,
        location: &str,
        status: StatusCode,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let response = http::Response::builder()
            .status(status)
            .header(http::header::LOCATION, location)
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "Failed to build redirect response: {}",
                    e
                )
            })?;
        Ok(response)
    }

    fn parse_error_status_code(status: &str) -> ServerResult<StatusCode> {
        let code = status.parse::<u16>().map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, {}",
                status,
                e
            )
        })?;
        if !(400..=599).contains(&code) {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, supported range is 400..=599",
                code
            ));
        }
        StatusCode::from_u16(code).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid error status code: {}, {}",
                code,
                e
            )
        })
    }

    fn build_error_response(
        &self,
        status: StatusCode,
        message: Option<&str>,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let body = message.unwrap_or("");
        let response = http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(
                Full::new(Bytes::from(body.to_string()))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "Failed to build error response: {}",
                    e
                )
            })?;
        Ok(response)
    }

    /// Resolve the source variables for one request: stream info first, then
    /// forwarded headers when (and only when) the direct previous hop is a
    /// trusted upstream and no stronger mechanism already restored a source.
    fn resolve_request_sources(
        &self,
        info: &StreamInfo,
        headers: &http::HeaderMap,
    ) -> RequestSourceInfo {
        let mut sources = RequestSourceInfo::from_stream_info(info);
        if self.trusted_upstreams.is_empty() {
            return sources;
        }
        if sources.real_source_addr.is_some() {
            // PROXY protocol / tunnel identity already restored the source;
            // that mechanism outranks forwarded headers.
            return sources;
        }
        let direct_hop = sources
            .conn_source_ip
            .as_deref()
            .or(sources.source_ip.as_deref());
        let Some(direct_hop_ip) = direct_hop.and_then(|ip| ip.parse::<IpAddr>().ok()) else {
            return sources;
        };
        if !self
            .trusted_upstreams
            .iter()
            .any(|m| m.matches(&direct_hop_ip))
        {
            return sources;
        }
        if let Some(real) = resolve_trusted_forwarded_source(headers, &self.trusted_upstreams) {
            sources.set_real_source(&real);
        }
        sources
    }

    async fn create_source_env_vars(
        global_env: &EnvRef,
        sources: &RequestSourceInfo,
    ) -> ServerResult<()> {
        for (name, value) in [
            ("REQ_remote_ip", sources.source_ip.as_ref()),
            ("REQ_remote_port", sources.source_port.as_ref()),
            ("REQ_conn_remote_ip", sources.conn_source_ip.as_ref()),
            ("REQ_conn_remote_port", sources.conn_source_port.as_ref()),
            ("REQ_real_remote_ip", sources.real_source_ip.as_ref()),
            ("REQ_real_remote_port", sources.real_source_port.as_ref()),
        ] {
            if let Some(value) = value {
                global_env
                    .create(name, CollectionValue::String(value.clone()))
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        Ok(())
    }

    // Post-hook rules:
    // - post_hook_point is optional; when absent, response is returned as-is.
    // - RESP is a header-only map (no status/version keys).
    // - Post chain control results are ignored; only header mutations are applied.
    async fn apply_post_chain(
        &self,
        resp: http::Response<UnsyncBoxBody<Bytes, ServerError>>,
        info: Option<&StreamInfo>,
        sources: Option<&RequestSourceInfo>,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let post_executor = match &self.post_executor {
            Some(executor) => executor.lock().unwrap().fork(),
            None => return Ok(resp),
        };

        let resp_map = HttpResponseHeaderMap::new(resp);
        let global_env = post_executor.global_env();
        if let Some(sources) = sources {
            Self::create_source_env_vars(global_env, sources).await?;
        }
        if let Some(info) = info {
            if let Some(dst_addr) = info.dst_addr.as_ref() {
                if let Ok(socket_addr) = dst_addr.parse::<SocketAddr>() {
                    global_env
                        .create(
                            "REQ_target_ip",
                            CollectionValue::String(socket_addr.ip().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                    global_env
                        .create(
                            "REQ_target_port",
                            CollectionValue::String(socket_addr.port().to_string()),
                        )
                        .await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                }
            }
            if let Some(source_mac) = info.source_mac.as_ref() {
                global_env
                    .create(
                        "REQ_source_mac",
                        CollectionValue::String(source_mac.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
            if let Some(source_hostname) = info.source_hostname.as_ref() {
                global_env
                    .create(
                        "REQ_source_hostname",
                        CollectionValue::String(source_hostname.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
            if let Some(source_online_secs) = info.source_online_secs.as_ref() {
                global_env
                    .create(
                        "REQ_source_online_secs",
                        CollectionValue::String(source_online_secs.to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        resp_map
            .register_visitors(&global_env)
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;

        let ret = post_executor
            .execute_lib()
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        if ret.is_control() {
            debug!(
                "post_hook_point control result ignored hook_point={} final_value={:?}",
                self.id,
                ret.value(),
            );
        }

        let resp = resp_map
            .into_response()
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        Ok(resp)
    }

    async fn apply_post_chain_result(
        &self,
        resp: ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>>,
        req_info: &CompressionRequestInfo,
        info: Option<&StreamInfo>,
        sources: Option<&RequestSourceInfo>,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        match resp {
            Ok(resp) => {
                let resp = timeout(
                    self.forward_timeouts.post_chain_timeout,
                    self.apply_post_chain(resp, info, sources),
                )
                .await
                .map_err(|_| {
                    ServerError::new(
                        ServerErrorCode::StreamError,
                        "post hook timeout".to_string(),
                    )
                })??;
                apply_response_compression(resp, req_info, &self.compression)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl HttpServer for ProcessChainHttpServer {
    async fn serve_request(
        &self,
        req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        let req_info = CompressionRequestInfo::from_request(&req);
        let sources = self.resolve_request_sources(&info, req.headers());
        let mut req = match apply_request_decompression(req, &self.compression) {
            Ok(req) => req,
            Err(err) => {
                let mut response = http::Response::new(
                    Full::new(Bytes::from(err.msg().to_string()))
                        .map_err(|e| match e {})
                        .boxed_unsync(),
                );
                *response.status_mut() = StatusCode::BAD_REQUEST;
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info), Some(&sources))
                    .await;
            }
        };

        // Capture request meta early so we can log it even if the process chain
        // decides to drop/reject without forwarding the request.
        let req_method = req.method().to_string();
        let req_host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("none")
            .to_string();
        let req_uri = req.uri().to_string();
        let req_remote = info.src_addr.as_deref().unwrap_or("unknown").to_string();
        let req_version = Self::request_version(req.version());
        let req_user_agent = Self::request_header_value(&req, "user-agent").to_string();
        let req_referer = Self::request_header_value(&req, "referer").to_string();
        let req_x_forwarded_for = Self::request_header_value(&req, "x-forwarded-for").to_string();

        info!(
            "{} - - \"{} {} {}\" host=\"{}\" ua=\"{}\" referer=\"{}\" xff=\"{}\" server=\"{}\"",
            req_remote,
            req_method,
            req_uri,
            req_version,
            req_host,
            req_user_agent,
            req_referer,
            req_x_forwarded_for,
            self.id,
        );

        let mut process_chain_vars = HttpRequestProcessChainVars::default();
        let executor = { self.executor.lock().unwrap().fork() };

        let global_env = executor.global_env();
        process_chain_vars.req_remote_ip = sources.source_ip.clone();
        process_chain_vars.req_remote_port = sources.source_port.clone();
        process_chain_vars.req_conn_remote_ip = sources.conn_source_ip.clone();
        process_chain_vars.req_conn_remote_port = sources.conn_source_port.clone();
        process_chain_vars.req_real_remote_ip = sources.real_source_ip.clone();
        process_chain_vars.req_real_remote_port = sources.real_source_port.clone();
        Self::create_source_env_vars(global_env, &sources).await?;
        req.extensions_mut().insert(process_chain_vars);
        let req_map = HttpRequestHeaderMap::new_with_sources(req, sources.clone());
        if let Some(dst_addr) = info.dst_addr.as_ref() {
            if let Ok(socket_addr) = dst_addr.parse::<SocketAddr>() {
                global_env
                    .create(
                        "REQ_target_ip",
                        CollectionValue::String(socket_addr.ip().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
                global_env
                    .create(
                        "REQ_target_port",
                        CollectionValue::String(socket_addr.port().to_string()),
                    )
                    .await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
            }
        }
        if let Some(source_mac) = info.source_mac.as_ref() {
            global_env
                .create(
                    "REQ_source_mac",
                    CollectionValue::String(source_mac.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
        if let Some(source_hostname) = info.source_hostname.as_ref() {
            global_env
                .create(
                    "REQ_source_hostname",
                    CollectionValue::String(source_hostname.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
        if let Some(source_online_secs) = info.source_online_secs.as_ref() {
            global_env
                .create(
                    "REQ_source_online_secs",
                    CollectionValue::String(source_online_secs.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{}", e))?;
        }
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
                debug!("Request dropped by the process chain");
                let response = http::Response::new(
                    Full::new(Bytes::from("Request dropped"))
                        .map_err(|e| match e {})
                        .boxed_unsync(),
                );
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info), Some(&sources))
                    .await;
            } else if ret.is_reject() {
                debug!(
                    "process_chain_reject server={} remote={} method={} host={} uri={}",
                    self.id, req_remote, req_method, req_host, req_uri,
                );
                let mut response =
                    http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info), Some(&sources))
                    .await;
            }
            if let Some(CommandControl::Error(ret)) = ret.as_control() {
                debug!(
                    "process_chain_error server={} remote={} method={} host={} uri={} message={}",
                    self.id, req_remote, req_method, req_host, req_uri, ret.value,
                );
                let mut response = http::Response::new(
                    Full::new(Bytes::from(ret.value.to_string()))
                        .map_err(|e| match e {})
                        .boxed_unsync(),
                );
                *response.status_mut() = StatusCode::BAD_GATEWAY;
                return self
                    .apply_post_chain_result(Ok(response), &req_info, Some(&info), Some(&sources))
                    .await;
            }
            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    log::error!(
                        "process chain return is not string: {}",
                        ret.value.get_type()
                    );
                    let mut response = http::Response::new(
                        Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync(),
                    );
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return self
                        .apply_post_chain_result(
                            Ok(response),
                            &req_info,
                            Some(&info),
                            Some(&sources),
                        )
                        .await;
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        log::error!("process chain return is empty");
                        let mut response = http::Response::new(
                            Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync(),
                        );
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return self
                            .apply_post_chain_result(
                                Ok(response),
                                &req_info,
                                Some(&info),
                                Some(&sources),
                            )
                            .await;
                    }

                    let cmd = list[0].as_str();
                    match cmd {
                        "server" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let server_id = list[1].as_str();
                            let post_req = req_map.into_request().map_err(|e| {
                                server_err!(ServerErrorCode::ProcessChainError, "{}", e)
                            })?;

                            if let Some(server_mgr) = self.server_mgr.upgrade() {
                                if let Some(service) = server_mgr.get_http_server(server_id) {
                                    let resp = service.serve_request(post_req, info.clone()).await;
                                    return self
                                        .apply_post_chain_result(
                                            resp,
                                            &req_info,
                                            Some(&info),
                                            Some(&sources),
                                        )
                                        .await;
                                }
                            } else {
                                log::error!("server manager is unavailable");
                            }
                        }
                        "forward" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target_url = list[1].as_str();
                            let post_req = req_map.into_request().map_err(|e| {
                                server_err!(ServerErrorCode::ProcessChainError, "{}", e)
                            })?;
                            let resp = self
                                .handle_forward_upstream(post_req, target_url, &info)
                                .await;
                            return self
                                .apply_post_chain_result(
                                    resp,
                                    &req_info,
                                    Some(&info),
                                    Some(&sources),
                                )
                                .await;
                        }
                        "forward-group" => {
                            if list.len() < 2 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward-group command"
                                ));
                            }
                            let plan = ForwardPlan::decode(list[1].as_str()).map_err(|e| {
                                server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid forward plan: {}",
                                    e
                                )
                            })?;
                            let post_req = req_map.into_request().map_err(|e| {
                                server_err!(ServerErrorCode::ProcessChainError, "{}", e)
                            })?;
                            let resp = self
                                .handle_forward_group_upstream(post_req, &plan, &info)
                                .await;
                            return self
                                .apply_post_chain_result(
                                    resp,
                                    &req_info,
                                    Some(&info),
                                    Some(&sources),
                                )
                                .await;
                        }
                        "redirect" => {
                            if list.len() < 2 || list.len() > 3 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid redirect command"
                                ));
                            }

                            let location = list[1].as_str();
                            if location.is_empty() {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid redirect command"
                                ));
                            }
                            let status =
                                Self::parse_redirect_status_code(list.get(2).map(|v| v.as_str()))?;
                            let resp = self.build_redirect_response(location, status)?;
                            return self
                                .apply_post_chain_result(
                                    Ok(resp),
                                    &req_info,
                                    Some(&info),
                                    Some(&sources),
                                )
                                .await;
                        }
                        "error" => {
                            if list.len() < 2 || list.len() > 3 {
                                return Err(server_err!(
                                    ServerErrorCode::InvalidConfig,
                                    "invalid error command"
                                ));
                            }
                            let status = Self::parse_error_status_code(list[1].as_str())?;
                            let message = list.get(2).map(|v| v.as_str());
                            let resp = self.build_error_response(status, message)?;
                            return self
                                .apply_post_chain_result(
                                    Ok(resp),
                                    &req_info,
                                    Some(&info),
                                    Some(&sources),
                                )
                                .await;
                        }
                        _ => {
                            log::error!("unknown command: {}", cmd);
                        }
                    }
                }
            }
        } else {
            // Log only the non-control (normal) outcome.
            // A normal value like "false" often means no routing rule matched.
            debug!(
                "process_chain_decision hook_point={} final_result_kind=normal final_value={:?}",
                self.id,
                ret.value(),
            );
        }
        let mut response =
            http::Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        self.apply_post_chain_result(Ok(response), &req_info, Some(&info), Some(&sources))
            .await
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        self.h3_port
    }
}

fn default_gzip_min_length() -> u64 {
    20
}

fn default_gzip_comp_level() -> u32 {
    1
}

fn default_gzip_http_version() -> String {
    "1.1".to_string()
}

fn default_brotli_min_length() -> u64 {
    20
}

fn default_brotli_comp_level() -> u32 {
    4
}

fn clamp_gzip_comp_level(level: u32) -> u32 {
    level.clamp(1, 9)
}

fn clamp_brotli_comp_level(level: u32) -> u32 {
    level.clamp(0, 11)
}

fn normalize_content_types(types: &[String]) -> Vec<String> {
    types
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn parse_gzip_http_version(value: &str) -> ServerResult<Version> {
    match value.trim().to_ascii_uppercase().as_str() {
        "1.0" | "HTTP/1.0" => Ok(Version::HTTP_10),
        "1.1" | "HTTP/1.1" => Ok(Version::HTTP_11),
        "2" | "2.0" | "HTTP/2" => Ok(Version::HTTP_2),
        "3" | "3.0" | "HTTP/3" => Ok(Version::HTTP_3),
        _ => Err(server_err!(
            ServerErrorCode::InvalidConfig,
            "invalid gzip_http_version: {}",
            value
        )),
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ForwardUpstreamTimeoutConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_handshake_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_handshake_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_header_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_idle_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_chain_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_upstream_on_client_close: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProcessChainHttpServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h3_port: Option<u16>,
    pub hook_point: ProcessChainConfigs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_hook_point: Option<ProcessChainConfigs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward: Option<ForwardUpstreamTimeoutConfig>,
    /// Upstream IPs/CIDRs whose `X-Forwarded-For` / `X-Real-IP` headers may be
    /// converted into `real_source_*`. Empty (default) means forwarded headers
    /// from any peer are treated as plain input data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_upstreams: Vec<String>,
    #[serde(default)]
    pub gzip: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gzip_types: Vec<String>,
    #[serde(default = "default_gzip_min_length")]
    pub gzip_min_length: u64,
    #[serde(default = "default_gzip_comp_level")]
    pub gzip_comp_level: u32,
    #[serde(default = "default_gzip_http_version")]
    pub gzip_http_version: String,
    #[serde(default)]
    pub gzip_vary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gzip_disable: Option<String>,
    #[serde(default)]
    pub gzip_request: bool,
    #[serde(default)]
    pub brotli: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brotli_types: Vec<String>,
    #[serde(default = "default_brotli_min_length")]
    pub brotli_min_length: u64,
    #[serde(default = "default_brotli_comp_level")]
    pub brotli_comp_level: u32,
}

impl ServerConfig for ProcessChainHttpServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "http".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone)]
pub struct HttpServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub tunnel_manager: TunnelManager,
    pub global_collection_manager: GlobalCollectionManagerRef,
}

impl HttpServerContext {
    pub fn new(
        server_mgr: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        tunnel_manager: TunnelManager,
        global_collection_manager: GlobalCollectionManagerRef,
    ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            js_externals,
            tunnel_manager,
            global_collection_manager,
        }
    }
}

impl ServerContext for HttpServerContext {
    fn get_server_type(&self) -> String {
        "http".to_string()
    }
}

pub struct ProcessChainHttpServerFactory;

impl ProcessChainHttpServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainHttpServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<ProcessChainHttpServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid process chain http server config"
            ))?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "http server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<HttpServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid http server context"
            ))?;
        let mut builder = ProcessChainHttpServer::builder()
            .hook_point(config.hook_point.clone())
            .id(config.id.clone())
            .server_mgr(context.server_mgr.clone())
            .tunnel_manager(context.tunnel_manager.clone())
            .global_process_chains(context.global_process_chains.clone())
            .js_externals(context.js_externals.clone())
            .global_collection_manager(context.global_collection_manager.clone())
            .trusted_upstreams(config.trusted_upstreams.clone());
        let compression = ProcessChainHttpServerBuilder::build_compression_settings(config)?;
        builder = builder.compression(compression);
        if config.h3_port.is_some() {
            builder = builder.h3_port(config.h3_port.clone().unwrap());
        }
        if config.version.is_some() {
            builder = builder.version(config.version.clone().unwrap());
        }
        builder = builder.forward_timeouts(ForwardUpstreamTimeouts::from_config(
            config.forward.as_ref(),
        ));
        if let Some(post_hook_point) = config.post_hook_point.as_ref() {
            builder = builder.post_hook_point(post_hook_point.clone());
        }
        let server = builder.build().await?;
        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GlobalCollectionManager, GlobalProcessChains, JsExternalsManager, ServerManager,
        StreamInfo, hyper_serve_http, hyper_serve_http1,
    };
    use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, GzipEncoder};
    use buckyos_kit::init_logging;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = ServerError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    struct DelayedFramesBody {
        frames: VecDeque<Bytes>,
        delay: Duration,
        sleep: Option<Pin<Box<Sleep>>>,
    }

    impl DelayedFramesBody {
        fn new(frames: Vec<Bytes>, delay: Duration) -> Self {
            Self {
                frames: frames.into(),
                delay,
                sleep: None,
            }
        }
    }

    impl Body for DelayedFramesBody {
        type Data = Bytes;
        type Error = ServerError;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if this.frames.is_empty() {
                return Poll::Ready(None);
            }

            if this.sleep.is_none() {
                this.sleep = Some(Box::pin(tokio::time::sleep(this.delay)));
            }

            if let Some(sleep) = this.sleep.as_mut()
                && sleep.as_mut().poll(cx).is_pending()
            {
                return Poll::Pending;
            }

            this.sleep = None;
            Poll::Ready(this.frames.pop_front().map(|frame| Ok(Frame::data(frame))))
        }
    }

    struct FixedResponseServer {
        id: String,
        body: Bytes,
        content_type: &'static str,
        status: StatusCode,
        content_encoding: Option<&'static str>,
    }

    #[async_trait::async_trait(?Send)]
    impl HttpServer for FixedResponseServer {
        async fn serve_request(
            &self,
            _req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
            let body = self.body.clone();
            let len = body.len();
            let mut builder = http::Response::builder()
                .status(self.status)
                .header("Content-Type", self.content_type)
                .header("Content-Length", len);
            if let Some(encoding) = self.content_encoding {
                builder = builder.header("Content-Encoding", encoding);
            }
            let response = builder
                .body(Full::new(body).map_err(|e| match e {}).boxed_unsync())
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::BadRequest,
                        "Failed to build response: {}",
                        e
                    )
                })?;
            Ok(response)
        }

        fn id(&self) -> String {
            self.id.clone()
        }

        fn http_version(&self) -> Version {
            Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    struct EchoBodyServer {
        id: String,
    }

    #[async_trait::async_trait(?Send)]
    impl HttpServer for EchoBodyServer {
        async fn serve_request(
            &self,
            req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
            let body_bytes = req
                .collect()
                .await
                .map_err(|e| server_err!(ServerErrorCode::StreamError, "Stream error: {}", e))?
                .to_bytes();
            let len = body_bytes.len();
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", len)
                .body(Full::new(body_bytes).map_err(|e| match e {}).boxed_unsync())
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::BadRequest,
                        "Failed to build response: {}",
                        e
                    )
                })?;
            Ok(response)
        }

        fn id(&self) -> String {
            self.id.clone()
        }

        fn http_version(&self) -> Version {
            Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    /// Reflects every `x-test-*` request header back as a response header, so
    /// process-chain `map-add REQ ...` effects become observable.
    struct EchoHeadersServer {
        id: String,
    }

    #[async_trait::async_trait(?Send)]
    impl HttpServer for EchoHeadersServer {
        async fn serve_request(
            &self,
            req: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
            let mut builder = http::Response::builder().status(StatusCode::OK);
            for (name, value) in req.headers() {
                if name.as_str().starts_with("x-test-") {
                    builder = builder.header(name, value);
                }
            }
            builder
                .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::BadRequest,
                        "Failed to build response: {}",
                        e
                    )
                })
        }

        fn id(&self) -> String {
            self.id.clone()
        }

        fn http_version(&self) -> Version {
            Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    const SOURCE_VARS_CHAIN: &str = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        map-add REQ X-Test-Source "S:${REQ.source_ip}:${REQ.source_port}";
        map-add REQ X-Test-Conn "C:${REQ.conn_source_ip}:${REQ.conn_source_port}";
        map-add REQ X-Test-Real "R:${REQ.real_source_ip}:${REQ.real_source_port}";
        map-add REQ X-Test-Remote "REM:${REQ_remote_ip}:${REQ_remote_port}";
        map-add REQ X-Test-Real-Remote "RR:${REQ_real_remote_ip}";
        return "server echo-headers";
"#;

    async fn build_source_vars_server(
        trusted_upstreams: Vec<String>,
    ) -> (ProcessChainHttpServer, Arc<ServerManager>) {
        let mock_server_mgr = Arc::new(ServerManager::new());
        mock_server_mgr
            .add_server(Server::Http(Arc::new(EchoHeadersServer {
                id: "echo-headers".to_string(),
            })))
            .unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(SOURCE_VARS_CHAIN).unwrap();
        let server = ProcessChainHttpServer::builder()
            .id("test_source_vars")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .trusted_upstreams(trusted_upstreams)
            .build()
            .await
            .unwrap();
        (server, mock_server_mgr)
    }

    fn source_vars_request(
        headers: &[(&str, &str)],
    ) -> http::Request<UnsyncBoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder()
            .method("GET")
            .uri("http://localhost/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap()
    }

    fn header_str<'a>(
        resp: &'a http::Response<UnsyncBoxBody<Bytes, ServerError>>,
        name: &str,
    ) -> &'a str {
        resp.headers()
            .get(name)
            .map(|value| value.to_str().unwrap())
            .unwrap_or("<missing>")
    }

    #[test]
    fn test_trusted_upstream_matcher() {
        let exact = TrustedUpstreamMatcher::parse("10.0.0.1").unwrap();
        assert!(exact.matches(&"10.0.0.1".parse().unwrap()));
        assert!(!exact.matches(&"10.0.0.2".parse().unwrap()));

        let net = TrustedUpstreamMatcher::parse("10.0.0.0/8").unwrap();
        assert!(net.matches(&"10.255.1.2".parse().unwrap()));
        assert!(!net.matches(&"11.0.0.1".parse().unwrap()));

        let narrow = TrustedUpstreamMatcher::parse("192.168.1.4/31").unwrap();
        assert!(narrow.matches(&"192.168.1.4".parse().unwrap()));
        assert!(narrow.matches(&"192.168.1.5".parse().unwrap()));
        assert!(!narrow.matches(&"192.168.1.6".parse().unwrap()));

        let v6 = TrustedUpstreamMatcher::parse("fd00::/8").unwrap();
        assert!(v6.matches(&"fd12::1".parse().unwrap()));
        assert!(!v6.matches(&"fe80::1".parse().unwrap()));
        // Address family mismatch never matches.
        assert!(!v6.matches(&"10.0.0.1".parse().unwrap()));

        assert!(TrustedUpstreamMatcher::parse("not-an-ip").is_err());
        assert!(TrustedUpstreamMatcher::parse("10.0.0.0/33").is_err());
        assert!(TrustedUpstreamMatcher::parse("10.0.0.0/x").is_err());
    }

    #[test]
    fn test_resolve_trusted_forwarded_source_cases() {
        let trusted = vec![
            TrustedUpstreamMatcher::parse("127.0.0.0/8").unwrap(),
            TrustedUpstreamMatcher::parse("10.0.0.0/8").unwrap(),
        ];

        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.1.2.3".parse().unwrap());
        assert_eq!(
            resolve_trusted_forwarded_source(&headers, &trusted),
            Some("203.0.113.7".to_string())
        );

        // Rightmost untrusted entry wins even if further-left entries exist.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.7, 10.1.2.3".parse().unwrap(),
        );
        assert_eq!(
            resolve_trusted_forwarded_source(&headers, &trusted),
            Some("203.0.113.7".to_string())
        );

        // All entries trusted: leftmost is used.
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.9.9.9, 10.1.2.3".parse().unwrap());
        assert_eq!(
            resolve_trusted_forwarded_source(&headers, &trusted),
            Some("10.9.9.9".to_string())
        );

        // Malformed entry poisons X-Forwarded-For; falls back to X-Real-IP.
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "garbage, 10.1.2.3".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.9".parse().unwrap());
        headers.insert("x-real-port", "7777".parse().unwrap());
        assert_eq!(
            resolve_trusted_forwarded_source(&headers, &trusted),
            Some("198.51.100.9:7777".to_string())
        );

        // No forwarded info at all.
        let headers = http::HeaderMap::new();
        assert_eq!(resolve_trusted_forwarded_source(&headers, &trusted), None);

        // Entry with a port is preserved as-is.
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7:4443".parse().unwrap());
        assert_eq!(
            resolve_trusted_forwarded_source(&headers, &trusted),
            Some("203.0.113.7:4443".to_string())
        );
    }

    #[tokio::test]
    async fn test_http_source_vars_direct_connection() {
        let (server, _mgr) = build_source_vars_server(vec![]).await;
        // Forged headers must not leak into the reserved source keys.
        let request = source_vars_request(&[
            ("source_ip", "6.6.6.6"),
            ("real_source_ip", "7.7.7.7"),
            ("X-Forwarded-For", "8.8.8.8"),
        ]);
        let resp = server
            .serve_request(request, StreamInfo::new("192.168.1.9:5555".to_string()))
            .await
            .unwrap();

        assert_eq!(header_str(&resp, "X-Test-Source"), "S:192.168.1.9:5555");
        assert_eq!(header_str(&resp, "X-Test-Conn"), "C:192.168.1.9:5555");
        assert_eq!(header_str(&resp, "X-Test-Real"), "R::");
        assert_eq!(header_str(&resp, "X-Test-Remote"), "REM:192.168.1.9:5555");
        assert_eq!(header_str(&resp, "X-Test-Real-Remote"), "RR:");
    }

    #[tokio::test]
    async fn test_http_source_vars_stream_restored_source() {
        // A stack-level trusted mechanism (e.g. PROXY protocol) filled
        // StreamInfo.real_src_addr; the HTTP layer must expose it untouched.
        let (server, _mgr) = build_source_vars_server(vec![]).await;
        let request = source_vars_request(&[]);
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:9000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let resp = server.serve_request(request, info).await.unwrap();

        assert_eq!(header_str(&resp, "X-Test-Source"), "S:198.51.100.7:6001");
        assert_eq!(header_str(&resp, "X-Test-Conn"), "C:127.0.0.1:9000");
        assert_eq!(header_str(&resp, "X-Test-Real"), "R:198.51.100.7:6001");
        assert_eq!(header_str(&resp, "X-Test-Remote"), "REM:198.51.100.7:6001");
        assert_eq!(header_str(&resp, "X-Test-Real-Remote"), "RR:198.51.100.7");
    }

    #[tokio::test]
    async fn test_http_source_vars_trusted_upstream_xff() {
        let (server, _mgr) =
            build_source_vars_server(vec!["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()])
                .await;
        let request = source_vars_request(&[("X-Forwarded-For", "203.0.113.7, 10.1.2.3")]);
        let resp = server
            .serve_request(request, StreamInfo::new("127.0.0.1:4000".to_string()))
            .await
            .unwrap();

        // Trusted hops are skipped right-to-left; the client IP becomes the
        // real (and effective) source; the conn source stays the direct hop.
        assert_eq!(header_str(&resp, "X-Test-Source"), "S:203.0.113.7:");
        assert_eq!(header_str(&resp, "X-Test-Conn"), "C:127.0.0.1:4000");
        assert_eq!(header_str(&resp, "X-Test-Real"), "R:203.0.113.7:");
        assert_eq!(header_str(&resp, "X-Test-Remote"), "REM:203.0.113.7:");
        assert_eq!(header_str(&resp, "X-Test-Real-Remote"), "RR:203.0.113.7");
    }

    #[tokio::test]
    async fn test_http_source_vars_untrusted_forwarded_headers_ignored() {
        // The direct hop is NOT in the trusted set: forwarded headers stay
        // plain input data and must not fabricate real_source_*.
        let (server, _mgr) = build_source_vars_server(vec!["10.0.0.0/8".to_string()]).await;
        let request = source_vars_request(&[
            ("X-Forwarded-For", "203.0.113.7"),
            ("X-Real-IP", "203.0.113.8"),
        ]);
        let resp = server
            .serve_request(request, StreamInfo::new("127.0.0.1:4000".to_string()))
            .await
            .unwrap();

        assert_eq!(header_str(&resp, "X-Test-Source"), "S:127.0.0.1:4000");
        assert_eq!(header_str(&resp, "X-Test-Conn"), "C:127.0.0.1:4000");
        assert_eq!(header_str(&resp, "X-Test-Real"), "R::");
        assert_eq!(header_str(&resp, "X-Test-Remote"), "REM:127.0.0.1:4000");
        assert_eq!(header_str(&resp, "X-Test-Real-Remote"), "RR:");
    }

    #[tokio::test]
    async fn test_http_source_vars_trusted_x_real_ip_fallback() {
        let (server, _mgr) = build_source_vars_server(vec!["127.0.0.0/8".to_string()]).await;
        let request =
            source_vars_request(&[("X-Real-IP", "198.51.100.9"), ("X-Real-Port", "7777")]);
        let resp = server
            .serve_request(request, StreamInfo::new("127.0.0.1:4000".to_string()))
            .await
            .unwrap();

        assert_eq!(header_str(&resp, "X-Test-Real"), "R:198.51.100.9:7777");
        assert_eq!(header_str(&resp, "X-Test-Source"), "S:198.51.100.9:7777");
        assert_eq!(header_str(&resp, "X-Test-Remote"), "REM:198.51.100.9:7777");
    }

    #[tokio::test]
    async fn test_http_source_vars_stream_mechanism_outranks_forwarded_headers() {
        let (server, _mgr) = build_source_vars_server(vec!["127.0.0.0/8".to_string()]).await;
        let request = source_vars_request(&[("X-Forwarded-For", "203.0.113.7")]);
        let info = StreamInfo::with_addrs(
            Some("127.0.0.1:4000".to_string()),
            Some("198.51.100.7:6001".to_string()),
        );
        let resp = server.serve_request(request, info).await.unwrap();

        assert_eq!(header_str(&resp, "X-Test-Real"), "R:198.51.100.7:6001");
        assert_eq!(header_str(&resp, "X-Test-Source"), "S:198.51.100.7:6001");
    }

    async fn gzip_bytes(data: &[u8]) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut encoder = GzipEncoder::new(reader);
        let mut output = Vec::new();
        encoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    async fn gunzip_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = GzipDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    async fn brotli_decode_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = BrotliDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    async fn build_timeout_test_server(
        post_hook_point: Option<ProcessChainConfigs>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> ProcessChainHttpServer {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut builder = ProcessChainHttpServer::builder()
            .id("timeout_test")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr));

        if let Some(post_hook_point) = post_hook_point {
            builder = builder.post_hook_point(post_hook_point);
        }
        if let Some(js_externals) = js_externals {
            builder = builder.js_externals(js_externals);
        }

        builder.build().await.unwrap()
    }

    #[tokio::test]
    async fn test_http_server_builder_creation() {
        let builder = ProcessChainHttpServer::builder();
        assert!(builder.version.is_none());
        assert!(builder.hook_point.is_none());
        assert!(builder.post_hook_point.is_none());
        assert!(builder.global_process_chains.is_none());
        assert!(builder.server_mgr.is_none());
    }

    #[test]
    fn test_origin_form_uri_normalizes_absolute_uri() {
        assert_eq!(
            ProcessChainHttpServer::origin_form_uri(
                "http://127.0.0.1:3180/.cluster/klog/ood2/raft/append-entries?x=1",
            ),
            "/.cluster/klog/ood2/raft/append-entries?x=1"
        );
        assert_eq!(
            ProcessChainHttpServer::origin_form_uri("/kapi/klog-service"),
            "/kapi/klog-service"
        );
    }

    #[tokio::test]
    async fn test_gzip_min_length_no_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "test".to_string(),
            body: Bytes::from_static(b"small-body"),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server test";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1024;
        compression.gzip_types = vec!["text/plain".to_string()];

        let result = ProcessChainHttpServer::builder()
            .id("test_gzip_min")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = result.unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(b"small-body"));
    }

    #[tokio::test]
    async fn test_gzip_response_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"compress-body-contents");
        let server = FixedResponseServer {
            id: "compress".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server compress";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_compress")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        assert!(resp.headers().get("content-length").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        let decoded = gunzip_bytes(body).await;
        assert_eq!(decoded, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_request_decompression() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = EchoBodyServer {
            id: "echo".to_string(),
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server echo";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip_request = true;

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_request")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let original = Bytes::from_static(b"request-body");
        let compressed = gzip_bytes(original.as_ref()).await;

        let request = http::Request::builder()
            .method("POST")
            .uri("http://localhost/")
            .header("Content-Encoding", "gzip")
            .body(Full::new(compressed).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_when_already_encoded() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"already-encoded");
        let server = FixedResponseServer {
            id: "encoded".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: Some("gzip"),
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server encoded";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_encoded")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_head() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"head-body-content");
        let server = FixedResponseServer {
            id: "head".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server head";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_head")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("HEAD")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "no_content".to_string(),
            body: Bytes::new(),
            content_type: "text/plain",
            status: StatusCode::NO_CONTENT,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server no_content";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_no_content")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
    }

    #[tokio::test]
    async fn test_gzip_response_skip_for_not_modified() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let server = FixedResponseServer {
            id: "not_modified".to_string(),
            body: Bytes::new(),
            content_type: "text/plain",
            status: StatusCode::NOT_MODIFIED,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server not_modified";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_not_modified")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
    }

    #[tokio::test]
    async fn test_brotli_response_compress() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"brotli-contents");
        let server = FixedResponseServer {
            id: "brotli".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server brotli";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.brotli = true;
        compression.gzip_vary = true;
        compression.brotli_min_length = 1;
        compression.brotli_types = vec!["text/plain".to_string()];

        let http_server = ProcessChainHttpServer::builder()
            .id("test_brotli_compress")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "br")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("br")
        );
        assert!(resp.headers().get("content-length").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));

        let body = resp.collect().await.unwrap().to_bytes();
        let decoded = brotli_decode_bytes(body).await;
        assert_eq!(decoded, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_http_version_gate() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"version-gate");
        let server = FixedResponseServer {
            id: "version".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server version";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];
        compression.gzip_http_version = Version::HTTP_2;

        let http_server = ProcessChainHttpServer::builder()
            .id("test_version_gate")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .version(Version::HTTP_11)
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_gzip_disable_user_agent() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let raw_body = Bytes::from_static(b"ua-disable");
        let server = FixedResponseServer {
            id: "ua".to_string(),
            body: raw_body.clone(),
            content_type: "text/plain",
            status: StatusCode::OK,
            content_encoding: None,
        };
        mock_server_mgr
            .add_server(Server::Http(Arc::new(server)))
            .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server ua";
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let mut compression = HttpCompressionSettings::default();
        compression.gzip = true;
        compression.gzip_vary = true;
        compression.gzip_min_length = 1;
        compression.gzip_types = vec!["text/plain".to_string()];
        compression.gzip_disable = Some(Regex::new("TestAgent").unwrap());

        let http_server = ProcessChainHttpServer::builder()
            .id("test_gzip_disable")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .compression(compression)
            .build()
            .await
            .unwrap();

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("Accept-Encoding", "gzip")
            .header("User-Agent", "TestAgent/1.0")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let resp = http_server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap();

        assert!(resp.headers().get("content-encoding").is_none());
        let vary = resp
            .headers()
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, raw_body);
    }

    #[tokio::test]
    async fn test_create_server_without_hook_point() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_inner_services() {
        let builder = ProcessChainHttpServer::builder().hook_point(vec![]);
        let result = ProcessChainHttpServer::create_server(builder).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_invalid_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .version("HTTP/1.2".to_string())
            .hook_point(vec![])
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_http11_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_server_with_http2_version() {
        let mock_server_mgr = Arc::new(ServerManager::new());

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(vec![])
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_strip_hop_by_hop_headers() {
        let mut resp = http::Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONNECTION, "close, X-Upstream-Hop")
            .header("X-Upstream-Hop", "remove")
            .header("Keep-Alive", "timeout=5")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::new()))
            .unwrap();

        ProcessChainHttpServer::strip_hop_by_hop_headers(resp.headers_mut());

        assert!(resp.headers().get(http::header::CONNECTION).is_none());
        assert!(resp.headers().get("X-Upstream-Hop").is_none());
        assert!(resp.headers().get("Keep-Alive").is_none());
        assert!(resp.headers().get(http::header::UPGRADE).is_none());
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
    }

    #[tokio::test(flavor = "local")]
    async fn test_handle_http1_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http1(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "local")]
    async fn test_post_hook_point_adds_header() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let post_chains = r#"
- id: post
  priority: 1
  blocks:
    - id: post
      block: |
        map-add RESP x-test "1";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();
        let post_chains: ProcessChainConfigs = serde_yaml_ng::from_str(post_chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .post_hook_point(post_chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http1(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("x-test").unwrap(), "1");
    }

    #[tokio::test(flavor = "local")]
    async fn test_handle_http1_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "local")]
    async fn test_handle_http2_request_http2_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/2".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            conn.await.unwrap();
        });
        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_2);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "local")]
    async fn test_handle_http2_request_http1_server() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("1")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .tunnel_manager(TunnelManager::new())
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            let ret = hyper_serve_http(Box::new(server), http_server, StreamInfo::default()).await;
            assert!(ret.is_err());
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            let ret = conn.await;
            assert!(ret.is_err());
        });
        let resp = sender.send_request(request).await;
        assert!(resp.is_err());
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_forward() {
        // 鍒涘缓涓�涓洃鍚�8090绔彛鐨凥TTP鏈嶅姟鍣ㄦ潵澶勭悊璇锋眰
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18090").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(
                    |req: http::Request<hyper::body::Incoming>| async move {
                        println!("{:?}", req.headers());
                        assert!(req.headers().get(http::header::CONNECTION).is_none());
                        assert!(req.headers().get("X-Client-Hop").is_none());
                        assert!(req.headers().get("Keep-Alive").is_none());
                        assert!(req.headers().get(http::header::UPGRADE).is_none());
                        assert_eq!(
                            req.headers()
                                .get("X-End-To-End")
                                .map(|v| v.to_str().unwrap()),
                            Some("keep")
                        );
                        assert!(req.headers().get("X-Real-IP").is_some());
                        assert_eq!(
                            req.headers().get("X-Real-IP").map(|v| v.to_str().unwrap()),
                            Some("127.0.0.1")
                        );
                        assert!(req.headers().get("X-Real-Port").is_some());
                        assert_eq!(
                            req.headers()
                                .get("X-Real-Port")
                                .map(|v| v.to_str().unwrap()),
                            Some("344")
                        );
                        let _ = req.collect().await; // 娑堣垂璇锋眰浣�
                        Ok::<_, ServerError>(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .header(http::header::CONNECTION, "close")
                                .body(
                                    Full::new(Bytes::from("forward success"))
                                        .map_err(|e| match e {})
                                        .boxed_unsync(),
                                )
                                .unwrap(),
                        )
                    },
                );

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 绛夊緟鏈嶅姟鍣ㄥ惎鍔�
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        map-add REQ X-Real-IP $REQ_remote_ip && map-add REQ X-Real-Port $REQ_remote_port && forward http://127.0.0.1:18090;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(
                Box::new(server),
                http_server,
                StreamInfo {
                    src_addr: Some("127.0.0.1:344".to_string()),
                    dst_addr: None,
                    conn_src_addr: Some("127.0.0.1:344".to_string()),
                    real_src_addr: None,
                    source_mac: None,
                    source_hostname: None,
                    source_online_secs: None,
                },
            )
            .await
            .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .header(http::header::CONNECTION, "X-Client-Hop")
            .header("X-Client-Hop", "remove")
            .header("Keep-Alive", "timeout=5")
            .header(http::header::UPGRADE, "websocket")
            .header("X-End-To-End", "keep")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::CONNECTION).is_none());

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_forward_http_base_path_keeps_origin_form_uri() {
        use http_body_util::BodyExt;
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                |req: http::Request<hyper::body::Incoming>| async move {
                    assert_eq!(req.uri().scheme_str(), None);
                    assert_eq!(req.uri().authority(), None);
                    assert_eq!(req.uri().to_string(), "/base/v1/chat?x=1");
                    let _ = req.collect().await;
                    Ok::<_, ServerError>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(
                                Full::new(Bytes::from("base path success"))
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap(),
                    )
                },
            );

            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward http://{}/base/;
        "#,
            upstream_addr
        );

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();
        let http_server = Arc::new(
            ProcessChainHttpServer::builder()
                .id("test_forward_http_base_path")
                .version("HTTP/1.1".to_string())
                .hook_point(chains)
                .server_mgr(Arc::downgrade(&mock_server_mgr))
                .tunnel_manager(TunnelManager::new())
                .build()
                .await
                .unwrap(),
        );

        let (client, server) = tokio::io::duplex(1024);
        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/v1/chat?x=1")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("base path success"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_forward_tcp() {
        tokio::spawn(async move {
            use http_body_util::BodyExt;
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:18091").await.unwrap();

            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = hyper::service::service_fn(
                    |req: http::Request<hyper::body::Incoming>| async move {
                        println!("{:?}", req.headers());
                        let _ = req.collect().await; // 娑堣垂璇锋眰浣�
                        Ok::<_, ServerError>(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .body(
                                    Full::new(Bytes::from("forward success"))
                                        .map_err(|e| match e {})
                                        .boxed_unsync(),
                                )
                                .unwrap(),
                        )
                    },
                );

                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        // 绛夊緟鏈嶅姟鍣ㄥ惎鍔�
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///127.0.0.1:18091;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward success"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_two_hop_tcp_forward_keeps_origin_form_uri() {
        use http_body_util::BodyExt;
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                |req: http::Request<hyper::body::Incoming>| async move {
                    assert_eq!(req.uri().scheme_str(), None);
                    assert_eq!(req.uri().authority(), None);
                    assert_eq!(
                        req.uri().to_string(),
                        "/.cluster/klog-it-dv/ood2/raft/append-entries"
                    );
                    let _ = req.collect().await;
                    Ok::<_, ServerError>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(
                                Full::new(Bytes::from("two-hop success"))
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap(),
                    )
                },
            );

            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let target_server_mgr = Arc::new(ServerManager::new());
        let target_chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///{};
        "#,
            upstream_addr
        );
        let target_chains: ProcessChainConfigs = serde_yaml_ng::from_str(&target_chains).unwrap();
        let target_gateway = Arc::new(
            ProcessChainHttpServer::builder()
                .id("target_gateway")
                .version("HTTP/1.1".to_string())
                .hook_point(target_chains)
                .server_mgr(Arc::downgrade(&target_server_mgr))
                .tunnel_manager(TunnelManager::new())
                .build()
                .await
                .unwrap(),
        );

        let target_gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_gateway_addr = target_gateway_listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            let (stream, _) = target_gateway_listener.accept().await.unwrap();
            hyper_serve_http(Box::new(stream), target_gateway, StreamInfo::default())
                .await
                .unwrap();
        });

        let source_server_mgr = Arc::new(ServerManager::new());
        let source_chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///{};
        "#,
            target_gateway_addr
        );
        let source_chains: ProcessChainConfigs = serde_yaml_ng::from_str(&source_chains).unwrap();
        let source_gateway = Arc::new(
            ProcessChainHttpServer::builder()
                .id("source_gateway")
                .version("HTTP/1.1".to_string())
                .hook_point(source_chains)
                .server_mgr(Arc::downgrade(&source_server_mgr))
                .tunnel_manager(TunnelManager::new())
                .build()
                .await
                .unwrap(),
        );

        let (client, server) = tokio::io::duplex(1024);
        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), source_gateway, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("POST")
            .uri("/.cluster/klog-it-dv/ood2/raft/append-entries")
            .header("host", "127.0.0.1:3180")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("two-hop success"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_uses_forward_plan_from_process_chain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let upstream_hit_count = hit_count.clone();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let service =
                hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let upstream_hit_count = upstream_hit_count.clone();
                    async move {
                        upstream_hit_count.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(req.uri().path(), "/plan");
                        let _ = req.collect().await;
                        Ok::<_, ServerError>(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .body(
                                    Full::new(Bytes::from("forward plan success"))
                                        .map_err(|e| match e {})
                                        .boxed_unsync(),
                                )
                                .unwrap(),
                        )
                    }
                });

            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward round_robin --next-upstream "error,timeout" --tries 2 http://{} http://{};
        "#,
            closed_addr, upstream_addr
        );

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward_group_plan")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(
            result.is_ok(),
            "forward group plan server should build: {:?}",
            result.err()
        );
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/plan")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("forward plan success"));
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_forward_err() {
        init_logging("test", false);
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward http://127.0.0.1:19999";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_forward_err")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        // 褰揻orward澶辫触鏃讹紝搴旇杩斿洖500閿欒
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_forward_upstream_timeouts_default() {
        let timeouts = ForwardUpstreamTimeouts::default();

        assert_eq!(timeouts.connect_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.tls_handshake_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.http_handshake_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.request_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.response_header_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.response_body_idle_timeout, Duration::from_secs(60));
        assert_eq!(timeouts.post_chain_timeout, Duration::from_secs(60));
        assert!(timeouts.abort_upstream_on_client_close);
    }

    #[test]
    fn test_forward_upstream_config_defaults_when_omitted() {
        let config: ProcessChainHttpServerConfig = serde_yaml_ng::from_str(
            r#"
id: test
type: http
hook_point: []
"#,
        )
        .unwrap();

        assert!(config.forward.is_none());
        let timeouts = ForwardUpstreamTimeouts::from_config(config.forward.as_ref());
        let defaults = ForwardUpstreamTimeouts::default();
        assert_eq!(timeouts.connect_timeout, defaults.connect_timeout);
        assert_eq!(
            timeouts.response_body_idle_timeout,
            defaults.response_body_idle_timeout
        );
        assert_eq!(
            timeouts.abort_upstream_on_client_close,
            defaults.abort_upstream_on_client_close
        );
    }

    #[test]
    fn test_forward_upstream_config_overrides_timeouts() {
        let config: ProcessChainHttpServerConfig = serde_yaml_ng::from_str(
            r#"
id: test
type: http
hook_point: []
forward:
  connect_timeout: 11
  tls_handshake_timeout: 12
  http_handshake_timeout: 13
  request_timeout: 14
  response_header_timeout: 15
  response_body_idle_timeout: 16
  post_chain_timeout: 17
  abort_upstream_on_client_close: false
"#,
        )
        .unwrap();

        let timeouts = ForwardUpstreamTimeouts::from_config(config.forward.as_ref());
        assert_eq!(timeouts.connect_timeout, Duration::from_secs(11));
        assert_eq!(timeouts.tls_handshake_timeout, Duration::from_secs(12));
        assert_eq!(timeouts.http_handshake_timeout, Duration::from_secs(13));
        assert_eq!(timeouts.request_timeout, Duration::from_secs(14));
        assert_eq!(timeouts.response_header_timeout, Duration::from_secs(15));
        assert_eq!(timeouts.response_body_idle_timeout, Duration::from_secs(16));
        assert_eq!(timeouts.post_chain_timeout, Duration::from_secs(17));
        assert!(!timeouts.abort_upstream_on_client_close);
    }

    #[test]
    fn test_forward_upstream_config_partial_preserves_defaults() {
        let config: ProcessChainHttpServerConfig = serde_yaml_ng::from_str(
            r#"
id: test
type: http
hook_point: []
forward:
  response_header_timeout: 7
"#,
        )
        .unwrap();

        let timeouts = ForwardUpstreamTimeouts::from_config(config.forward.as_ref());
        let defaults = ForwardUpstreamTimeouts::default();
        assert_eq!(timeouts.connect_timeout, defaults.connect_timeout);
        assert_eq!(timeouts.response_header_timeout, Duration::from_secs(7));
        assert_eq!(
            timeouts.response_body_idle_timeout,
            defaults.response_body_idle_timeout
        );
        assert_eq!(
            timeouts.abort_upstream_on_client_close,
            defaults.abort_upstream_on_client_close
        );
    }

    #[tokio::test]
    async fn test_upstream_body_idle_timeout_errors() {
        let mut body = UpstreamBody::new(PendingBody, Duration::from_millis(10), None);
        let err = body.frame().await.unwrap().unwrap_err();

        assert_eq!(err.code(), ServerErrorCode::StreamError, "{}", err.msg());
        assert!(err.msg().contains("upstream response body idle timeout"));
    }

    #[tokio::test]
    async fn test_upstream_body_allows_frames_before_idle_and_resets_timer() {
        let inner = DelayedFramesBody::new(
            vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")],
            Duration::from_millis(10),
        );
        let mut body = UpstreamBody::new(inner, Duration::from_millis(100), None);

        let first = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .map_err(|_| ())
            .unwrap();
        let second = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .map_err(|_| ())
            .unwrap();

        assert_eq!(first, Bytes::from_static(b"first"));
        assert_eq!(second, Bytes::from_static(b"second"));
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn test_upstream_body_abort_handle_fires_on_drop() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        struct AbortGuard(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for AbortGuard {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let connection_task = tokio::spawn(async move {
            let _guard = AbortGuard(Some(tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        let body = UpstreamBody::new(
            Full::new(Bytes::new()).map_err(|e| match e {}),
            Duration::from_secs(60),
            Some(connection_task),
        );
        drop(body);

        timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_upstream_body_does_not_abort_handle_after_eof() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        struct AbortGuard(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for AbortGuard {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let connection_task = tokio::spawn(async move {
            let _guard = AbortGuard(Some(tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        let mut body = UpstreamBody::new(
            Full::new(Bytes::from_static(b"done")).map_err(|e| match e {}),
            Duration::from_secs(60),
            Some(connection_task),
        );
        let data = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .map_err(|_| ())
            .unwrap();
        assert_eq!(data, Bytes::from_static(b"done"));
        assert!(body.frame().await.is_none());
        drop(body);

        assert!(timeout(Duration::from_millis(20), rx).await.is_err());
    }

    #[tokio::test]
    async fn test_http_forward_response_header_timeout_errors() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            std::future::pending::<()>().await;
        });

        let mut http_server = build_timeout_test_server(None, None).await;
        http_server.forward_timeouts.response_header_timeout = Duration::from_millis(10);
        http_server.forward_timeouts.request_timeout = Duration::from_secs(1);

        let request = http::Request::builder()
            .method("GET")
            .uri("/slow")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();
        let target_url = format!("http://{}", listen_addr);

        let err = http_server
            .handle_forward_upstream(request, &target_url, &StreamInfo::default())
            .await
            .unwrap_err();

        assert_eq!(err.code(), ServerErrorCode::StreamError, "{}", err.msg());
        assert!(err.msg().contains("upstream response header timeout"));
        assert!(err.msg().contains(target_url.as_str()));
    }

    #[tokio::test]
    async fn test_https_forward_tls_handshake_timeout_errors() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let mut http_server = build_timeout_test_server(None, None).await;
        http_server.forward_timeouts.connect_timeout = Duration::from_secs(1);
        http_server.forward_timeouts.tls_handshake_timeout = Duration::from_millis(10);

        let request = http::Request::builder()
            .method("GET")
            .uri("/slow")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();
        let target_url = format!("https://{}", listen_addr);

        let err = http_server
            .handle_forward_upstream(request, &target_url, &StreamInfo::default())
            .await
            .unwrap_err();

        assert_eq!(err.code(), ServerErrorCode::StreamError, "{}", err.msg());
        assert!(err.msg().contains("upstream tls handshake timeout"));
        assert!(err.msg().contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn test_post_chain_timeout_errors() {
        let js_externals = Arc::new(JsExternalsManager::new());
        js_externals
            .add_js_external(
                "slow_post",
                r#"
function slow_post(context) {
    let sum = 0;
    for (let i = 0; i < 10000000; i++) {
        sum += i;
    }
    return sum > 0;
}
"#
                .to_string(),
            )
            .await
            .unwrap();
        let post_chains = r#"
- id: post
  priority: 1
  blocks:
    - id: post
      block: |
        call slow_post;
        "#;
        let post_chains: ProcessChainConfigs = serde_yaml_ng::from_str(post_chains).unwrap();

        let mut http_server =
            build_timeout_test_server(Some(post_chains), Some(js_externals.clone())).await;
        http_server.forward_timeouts.post_chain_timeout = Duration::from_millis(5);

        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();
        let req_info = CompressionRequestInfo::from_request(&request);
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(
                Full::new(Bytes::from_static(b"ok"))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();

        let err = http_server
            .apply_post_chain_result(
                Ok(response),
                &req_info,
                Some(&StreamInfo::default()),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), ServerErrorCode::StreamError, "{}", err.msg());
        assert!(err.msg().contains("post hook timeout"));
    }

    #[test]
    fn test_upstream_sni_host_uses_upstream_host() {
        let request_url = Url::parse("https://inuy7.tbudr.top/api/v1/ai/chat/completions").unwrap();
        let sni_host = ProcessChainHttpServer::upstream_sni_host(&request_url).unwrap();
        assert_eq!(sni_host, "inuy7.tbudr.top");
    }

    #[test]
    fn test_upstream_sni_host_ignores_inbound_host_semantics() {
        let request_url = Url::parse("https://inuy7.tbudr.top/api/v1/payment/ping").unwrap();
        let sni_host = ProcessChainHttpServer::upstream_sni_host(&request_url).unwrap();
        assert_ne!(sni_host, "sn.buckyos.ai");
        assert_eq!(sni_host, "inuy7.tbudr.top");
    }

    #[tokio::test]
    async fn test_connect_upstream_candidates_falls_back_after_failed_address() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let unreachable_v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let (stream, connected_addr) = ProcessChainHttpServer::connect_upstream_candidates(
            vec![unreachable_v6, listen_addr],
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(connected_addr, listen_addr);
        assert_eq!(stream.peer_addr().unwrap(), listen_addr);
    }

    #[tokio::test]
    async fn test_connect_upstream_candidates_reports_when_all_fail() {
        let unreachable_v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let closed_v4: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let (_reason, msg) = ProcessChainHttpServer::connect_upstream_candidates(
            vec![unreachable_v6, closed_v4],
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();

        assert!(msg.contains("2001:db8::1"));
        assert!(msg.contains("127.0.0.1:9"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_redirect_default_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/path";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_default")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com/path")
        );
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_redirect_custom_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/permanent 301";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_custom")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com/permanent")
        );
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_redirect_invalid_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "redirect https://example.com/invalid 200";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_redirect_invalid")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_error_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 404";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_status")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_error_with_message() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 503 \"upstream unavailable\"";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_message")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("upstream unavailable"));
    }

    #[tokio::test(flavor = "local")]
    async fn test_process_chain_http_server_error_invalid_status() {
        let mock_server_mgr = Arc::new(ServerManager::new());
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "error 200 should fail";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = ProcessChainHttpServer::builder()
            .id("test_error_invalid")
            .version("HTTP/1.1".to_string())
            .hook_point(chains)
            .server_mgr(Arc::downgrade(&mock_server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await;

        assert!(result.is_ok());
        let http_server = Arc::new(result.unwrap());

        let (client, server) = tokio::io::duplex(128);

        tokio::task::spawn_local(async move {
            hyper_serve_http(Box::new(server), http_server, StreamInfo::default())
                .await
                .unwrap();
        });

        let request = http::Request::builder()
            .method("GET")
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed_unsync())
            .unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        let resp = sender.send_request(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_factory() {
        let config = ProcessChainHttpServerConfig {
            id: "test".to_string(),
            ty: "http".to_string(),
            version: None,
            h3_port: None,
            hook_point: ProcessChainConfigs::default(),
            post_hook_point: None,
            forward: None,
            trusted_upstreams: Vec::new(),
            gzip: false,
            gzip_types: Vec::new(),
            gzip_min_length: default_gzip_min_length(),
            gzip_comp_level: default_gzip_comp_level(),
            gzip_http_version: default_gzip_http_version(),
            gzip_vary: false,
            gzip_disable: None,
            gzip_request: false,
            brotli: false,
            brotli_types: Vec::new(),
            brotli_min_length: default_brotli_min_length(),
            brotli_comp_level: default_brotli_comp_level(),
        };
        let server_mgr = Arc::new(ServerManager::new());
        let context = HttpServerContext::new(
            Arc::downgrade(&server_mgr),
            Arc::new(GlobalProcessChains::new()),
            Arc::new(JsExternalsManager::new()),
            TunnelManager::new(),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
        );
        let factory = ProcessChainHttpServerFactory::new();
        let result = factory
            .create(Arc::new(config), Some(Arc::new(context)))
            .await;
        assert!(result.is_ok());
    }
}
