use crate::forward::ForwardPlan;
use crate::global_process_chains::{
    GlobalProcessChainsRef, create_process_chain_executor, execute_stream_chain,
};
use crate::self_cert_mgr::SelfCertMgrRef;
use crate::stack::limiter::Limiter;
use crate::stack::tls_cert_resolver::{
    IdentityCertResolver, ResolvesServerCertUsingSni, TlsIdentityCertConfig, TlsIdentityHost,
};
use crate::stack::{
    TlsCertResolver, connect_timeout_from_secs, get_limit_info, get_source_addr_from_req_env,
    probe_proxy_protocol_stream, stream_forward, stream_forward_group,
    stream_idle_timeout_from_secs,
};
use crate::{
    ConnectionController, ConnectionInfo, ConnectionManagerRef, DumpStream,
    GlobalCollectionManagerRef, IoDumpStackConfig, JsExternalsManagerRef, LimiterManagerRef,
    MutComposedSpeedStat, MutComposedSpeedStatRef, ProcessChainConfigs, Server, ServerManagerRef,
    Stack, StackConfig, StackContext, StackErrorCode, StackProtocol, StackResult, StatManagerRef,
    StreamInfo, TunnelManager, create_io_dump_stack_config, get_external_commands, get_stat_info,
    hyper_serve_http, into_stack_err, stack_err,
};
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainLibExecutor, StreamRequest};
use futures_util::future::{AbortHandle, Abortable};
use name_client::IdentityRoots;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use sfo_reuseport::{ServerRuntime, SocketOptions, TcpServer, TcpServiceConfig, TransparentMode};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

const DEFAULT_TLS_CONCURRENCY: u32 = 0;
const DEFAULT_IDENTITY_CERT_REFRESH_INTERVAL_SECS: u64 = 60;

pub async fn load_certs(path: &str) -> StackResult<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(into_stack_err!(
            StackErrorCode::InvalidTlsCert,
            "failed to parse certificate, file:{}",
            path
        ))?
        .filter(|item| item.is_ok())
        .map(|item| item.unwrap())
        .collect();
    Ok(certs)
}

pub async fn load_key(path: &str) -> StackResult<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(into_stack_err!(
        StackErrorCode::InvalidTlsKey,
        "failed to parse private key, file:{}",
        path
    ))
}
pub async fn create_server_config(
    cert_path: &str,
    key_path: &str,
) -> StackResult<Arc<ServerConfig>> {
    let certs = load_certs(cert_path).await?;
    let key = load_key(key_path).await?;
    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| stack_err!(StackErrorCode::InvalidTlsCert, "{}", e))?,
    ))
}

#[derive(Clone)]
pub struct TlsStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub self_cert_mgr: SelfCertMgrRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl TlsStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            self_cert_mgr,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for TlsStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }
}

struct TlsConnectionHandler {
    env: Arc<TlsStackContext>,
    executor: ProcessChainLibExecutor,
    connection_manager: Option<ConnectionManagerRef>,
    certs: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    server_config: Arc<ServerConfig>,
    io_dump: Option<IoDumpStackConfig>,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl TlsConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        certs: Vec<TlsDomainConfig>,
        identity_certs: Option<TlsIdentityCertConfig>,
        alpn_protocols: Vec<Vec<u8>>,
        env: Arc<TlsStackContext>,
        connection_manager: Option<ConnectionManagerRef>,
        io_dump: Option<IoDumpStackConfig>,
        stream_idle_timeout: std::time::Duration,
        connect_timeout: std::time::Duration,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
            env.js_externals.clone(),
        )
        .await
        .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let certs = Self::build_cert_resolver(certs, identity_certs, env.as_ref())?;
        let server_config = Self::build_server_config(certs.clone(), &alpn_protocols)?;
        Ok(Self {
            env,
            executor,
            connection_manager,
            certs,
            alpn_protocols,
            server_config,
            io_dump,
            stream_idle_timeout,
            connect_timeout,
        })
    }

    async fn rebuild_with_hook_point(&self, hook_point: ProcessChainConfigs) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            self.env.global_process_chains.clone(),
            self.env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&self.env.servers))),
            self.env.js_externals.clone(),
        )
        .await
        .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        Ok(Self {
            env: self.env.clone(),
            executor,
            connection_manager: self.connection_manager.clone(),
            certs: self.certs.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            server_config: self.server_config.clone(),
            io_dump: self.io_dump.clone(),
            stream_idle_timeout: self.stream_idle_timeout,
            connect_timeout: self.connect_timeout,
        })
    }

    fn build_cert_resolver(
        certs: Vec<TlsDomainConfig>,
        identity_certs: Option<TlsIdentityCertConfig>,
        env: &TlsStackContext,
    ) -> StackResult<Arc<dyn ResolvesServerCert>> {
        let crypto_provider = rustls::crypto::ring::default_provider();
        let cert_resolver = Arc::new(ResolvesServerCertUsingSni::new());
        let mut self_cert = false;
        for cert_config in certs.into_iter() {
            if cert_config.domain == "*" {
                self_cert = true;
                continue;
            }
            match (cert_config.certs, cert_config.key) {
                (Some(certs), Some(key)) => {
                    let cert_key = CertifiedKey::from_der(certs, key, &crypto_provider).map_err(
                        into_stack_err!(
                            StackErrorCode::InvalidTlsCert,
                            "parse {} cert failed",
                            cert_config.domain
                        ),
                    )?;
                    cert_resolver
                        .add(&cert_config.domain, cert_key)
                        .map_err(|e| {
                            stack_err!(
                                StackErrorCode::InvalidConfig,
                                "add {} cert failed.err {}",
                                cert_config.domain,
                                e
                            )
                        })?;
                }
                (None, None) => {}
                _ => {
                    return Err(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "cert and key must both be configured for {}",
                        cert_config.domain
                    ));
                }
            }
        }
        let mut cert: Arc<dyn ResolvesServerCert> = cert_resolver;
        if let Some(identity_certs) = identity_certs {
            cert = IdentityCertResolver::new(identity_certs, Some(cert));
        }

        let cert: Arc<dyn ResolvesServerCert> = if self_cert {
            Arc::new(TlsCertResolver::new(cert, Some(env.self_cert_mgr.clone())))
        } else {
            cert
        };
        Ok(cert)
    }

    fn build_server_config(
        certs: Arc<dyn ResolvesServerCert>,
        alpn_protocols: &[Vec<u8>],
    ) -> StackResult<Arc<ServerConfig>> {
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(certs);
        server_config.alpn_protocols = alpn_protocols.to_vec();

        Ok(Arc::new(server_config))
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        local_addr: SocketAddr,
        compose_stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let servers = self.env.servers.clone();
        let executor = self.executor.fork();
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(
            StackErrorCode::ServerError,
            "read remote addr failed"
        ))?;
        let (stream, proxy_source_addr) = probe_proxy_protocol_stream(Box::new(stream)).await?;
        let request_source_addr = proxy_source_addr.unwrap_or(remote_addr);

        let tls_acceptor = TlsAcceptor::from(self.server_config.clone());
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .map_err(into_stack_err!(StackErrorCode::StreamError))?;
        let server_name = {
            let (_, conn) = tls_stream.get_ref();
            conn.server_name().map(|s| s.to_string())
        };
        if server_name.is_none() {
            return Ok(());
        }
        if let Some(proxy_addr) = proxy_source_addr {
            log::debug!(
                "accept tls stream from {} (proxy via {}) to {} name {}",
                proxy_addr,
                remote_addr,
                local_addr,
                server_name.as_ref().unwrap_or(&"".to_string())
            );
        } else {
            log::debug!(
                "accept tls stream from {} to {} name {}",
                remote_addr,
                local_addr,
                server_name.as_ref().unwrap_or(&"".to_string())
            );
        }
        let request_stream: Box<dyn buckyos_kit::AsyncStream> =
            if let Some(io_dump) = self.io_dump.clone() {
                Box::new(DumpStream::new(
                    tls_stream,
                    io_dump,
                    remote_addr.to_string(),
                    local_addr.to_string(),
                ))
            } else {
                Box::new(tls_stream)
            };
        let mut request = StreamRequest::new(request_stream, local_addr);
        request.source_addr = Some(request_source_addr);
        request.conn_source_addr = Some(remote_addr);
        request.real_source_addr = proxy_source_addr;
        request.dest_port = local_addr.port();
        request.dest_host = server_name;
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(request_source_addr.ip()))
        {
            request.source_mac = device_info.mac().map(|v| v.to_string());
            request.source_hostname = device_info.hostname().map(|v| v.to_string());
            request.source_online_secs = Some(device_info.today_online_seconds().to_string());
        }
        let global_env = executor.global_env().clone();
        let (ret, stream) = execute_stream_chain(executor, request)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let conn_src_addr = Some(remote_addr.to_string());
        let mut real_src_addr = get_source_addr_from_req_env(&global_env)
            .await
            .and_then(|addr| addr.parse::<SocketAddr>().ok().map(|_| addr));
        if real_src_addr.is_none() {
            real_src_addr = proxy_source_addr.map(|addr| addr.to_string());
        }
        let mut stream_info = StreamInfo::with_addrs(conn_src_addr, real_src_addr)
            .with_dst_addr(Some(local_addr.to_string()));
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(request_source_addr.ip()))
        {
            stream_info = stream_info.with_device_info(
                device_info.mac().map(|v| v.to_string()),
                device_info.hostname().map(|v| v.to_string()),
                Some(device_info.today_online_seconds().to_string()),
            );
        }
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Error(ret)) = ret.as_control() {
                return Err(stack_err!(
                    StackErrorCode::ProcessChainError,
                    "process chain error: {}",
                    ret.value
                ));
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    return Ok(());
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) =
                        get_limit_info(global_env.clone()).await?;
                    let upper = if limiter_id.is_some() {
                        self.env.limiter_manager.get_limiter(limiter_id.unwrap())
                    } else {
                        None
                    };
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(
                            upper,
                            Some(1),
                            down_speed.map(|v| v as u32),
                            up_speed.map(|v| v as u32),
                        ))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self
                        .env
                        .stat_manager
                        .get_speed_stats(stat_group_ids.as_slice());
                    compose_stat.set_external_stats(speed_groups);

                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            let target = list[1].as_str();
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream =
                                    LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };
                            stream_forward(
                                stream,
                                target,
                                &self.env.tunnel_manager,
                                Some(&stream_info),
                                self.stream_idle_timeout,
                                self.connect_timeout,
                            )
                            .await?;
                        }
                        "forward-group" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward-group command"
                                ));
                            }
                            let plan = ForwardPlan::decode(list[1].as_str()).map_err(|e| {
                                stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward plan: {}",
                                    e
                                )
                            })?;
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream =
                                    LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };
                            stream_forward_group(
                                stream,
                                &plan,
                                &self.env.tunnel_manager,
                                Some(&stream_info),
                            )
                            .await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();

                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream =
                                    LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };

                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(http_server) => {
                                        if let Err(e) = hyper_serve_http(
                                            stream,
                                            http_server,
                                            stream_info.clone(),
                                        )
                                        .await
                                        {
                                            log::error!("hyper serve http failed: {}", e);
                                        }
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, stream_info.clone())
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::InvalidConfig
                                            ))?;
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type"
                                        ));
                                    }
                                }
                            }
                        }
                        v => {
                            log::error!("unknown command: {}", v);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct TlsStack {
    id: String,
    bind_addr: String,
    concurrency: u32,
    server_runtime: ServerRuntime,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<TlsConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<TlsConnectionHandler>>>>,
    reuse_address: bool,
    server: Mutex<Option<TcpServer>>,
}

impl Drop for TlsStack {
    fn drop(&mut self) {
        if let Some(server) = self.server.lock().unwrap().take() {
            if let Err(e) = server.close() {
                log::error!("close tls server failed: {}", e);
            }
        }
    }
}

impl TlsStack {
    pub fn builder() -> TlsStackBuilder {
        TlsStackBuilder::new()
    }

    async fn create(config: TlsStackBuilder) -> StackResult<Self> {
        if config.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if config.bind.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "bind is required"
            ));
        }
        if config.hook_point.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "hook_point is required"
            ));
        }
        if config.stack_context.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "stack_context is required"
            ));
        }
        if config.server_runtime.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "server_runtime is required"
            ));
        }

        let id = config.id.unwrap();
        let bind_addr = config.bind.unwrap();
        let server_runtime = config.server_runtime.unwrap();
        let env = config.stack_context.unwrap();
        let handler = TlsConnectionHandler::create(
            config.hook_point.unwrap(),
            config.certs,
            config.identity_certs,
            config.alpn_protocols,
            env,
            config.connection_manager.clone(),
            config.io_dump,
            config.stream_idle_timeout,
            config.connect_timeout,
        )
        .await?;

        Ok(Self {
            id,
            bind_addr,
            concurrency: config.concurrency,
            server_runtime,
            connection_manager: config.connection_manager,
            handler: Arc::new(RwLock::new(Arc::new(handler))),
            prepare_handler: Arc::new(Default::default()),
            reuse_address: config.reuse_address,
            server: Mutex::new(None),
        })
    }

    async fn start_listener(&self) -> StackResult<TcpServer> {
        let addr: SocketAddr = self.bind_addr.parse().map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "invalid bind address {}",
            self.bind_addr
        ))?;
        let socket_options = SocketOptions {
            reuse_address: self.reuse_address,
            ipv4_transparent: TransparentMode::Disabled,
            ipv6_transparent: TransparentMode::Disabled,
        };
        let mut service_config = TcpServiceConfig::new(addr).with_socket_options(socket_options);
        if self.concurrency != u32::MAX {
            service_config =
                service_config.with_max_concurrency_per_worker(self.concurrency as usize);
        }

        let handler = self.handler.clone();
        let connection_manager = self.connection_manager.clone();
        let server = TcpServer::serve(&self.server_runtime, service_config, move |stream| {
            let handler = handler.clone();
            let connection_manager = connection_manager.clone();
            async move {
                handle_reuseport_tls_stream(stream, handler, connection_manager).await;
                Ok(())
            }
        })
        .map_err(|e| stack_err!(StackErrorCode::BindFailed, "start tls server error: {e}"))?;
        Ok(server)
    }
}

async fn handle_reuseport_tls_stream(
    stream: TcpStream,
    handler: Arc<RwLock<Arc<TlsConnectionHandler>>>,
    connection_manager: Option<ConnectionManagerRef>,
) {
    let remote_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("read tls peer addr failed: {}", e);
            return;
        }
    };
    if let Err(e) = stream.set_nodelay(true) {
        log::warn!(
            "set TCP_NODELAY failed for tcp stream from {}: {}",
            remote_addr,
            e
        );
    }
    let local_addr = match stream.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("get local addr failed: {}", e);
            return;
        }
    };

    log::debug!("accept tls stream from {} to {}", remote_addr, local_addr);
    let compose_stat = MutComposedSpeedStat::new();
    let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
    let speed = stat_stream.get_speed_stat();
    let handler_snapshot = {
        let handler = handler.read().unwrap();
        handler.clone()
    };

    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let (controller, done_sender) = AbortableTlsConnectionController::new(abort_handle);
    if let Some(manager) = &connection_manager {
        manager.add_connection(ConnectionInfo::new(
            remote_addr.to_string(),
            local_addr.to_string(),
            StackProtocol::Tls,
            speed,
            controller.clone(),
        ));
    }

    let result = Abortable::new(
        handler_snapshot.handle_connect(stat_stream, local_addr, compose_stat),
        abort_registration,
    )
    .await;
    controller.mark_stopped();
    let _ = done_sender.send(());

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::error!("handle tls stream failed: {}", e),
        Err(_) => log::debug!("tls stream handler aborted"),
    }
}

struct AbortableTlsConnectionController {
    abort_handle: AbortHandle,
    stopped: AtomicBool,
    done_receiver: Mutex<Option<oneshot::Receiver<()>>>,
}

impl AbortableTlsConnectionController {
    fn new(abort_handle: AbortHandle) -> (Arc<Self>, oneshot::Sender<()>) {
        let (done_sender, done_receiver) = oneshot::channel();
        (
            Arc::new(Self {
                abort_handle,
                stopped: AtomicBool::new(false),
                done_receiver: Mutex::new(Some(done_receiver)),
            }),
            done_sender,
        )
    }

    fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}

#[async_trait::async_trait]
impl ConnectionController for AbortableTlsConnectionController {
    fn stop_connection(&self) {
        self.abort_handle.abort();
    }

    async fn wait_stop(&self) {
        let receiver = {
            let mut receiver = self.done_receiver.lock().unwrap();
            receiver.take()
        };
        if let Some(receiver) = receiver {
            let _ = receiver.await;
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire) || self.abort_handle.is_aborted()
    }
}

#[async_trait::async_trait]
impl Stack for TlsStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.server.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let server = self.start_listener().await?;
        *self.server.lock().unwrap() = Some(server);
        Ok(())
    }

    async fn prepare_update(
        &self,
        config: Arc<dyn StackConfig>,
        context: Option<Arc<dyn StackContext>>,
    ) -> StackResult<()> {
        let config = config
            .as_ref()
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tls stack config"
            ))?;
        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }
        if config.bind.to_string() != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if config.reuse_address.unwrap_or(false) != self.reuse_address {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "reuse_address unmatch"
            ));
        }

        if normalize_concurrency(config.concurrency.unwrap_or(DEFAULT_TLS_CONCURRENCY))
            != self.concurrency
        {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "concurrency unmatch"
            ));
        }

        let env = match context {
            Some(context) => {
                let tls_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<TlsStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid tls stack context"
                    ))?;
                Arc::new(tls_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };

        let alpn_protocols = config
            .alpn_protocols
            .clone()
            .unwrap_or_else(|| vec!["http/1.1".to_string()])
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let cert_list = build_tls_domain_configs(config).await?;

        let new_handler = TlsConnectionHandler::create(
            config.hook_point.clone(),
            cert_list,
            build_tls_identity_cert_config(&config.hosts, config.identity_manager.as_ref())?,
            alpn_protocols,
            env,
            self.connection_manager.clone(),
            create_io_dump_stack_config(
                &config.id,
                config.io_dump_file.as_deref(),
                config.io_dump_rotate_size.as_deref(),
                config.io_dump_rotate_max_files,
                config.io_dump_max_upload_bytes_per_conn.as_deref(),
                config.io_dump_max_download_bytes_per_conn.as_deref(),
            )
            .await
            .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?,
            stream_idle_timeout_from_secs(config.stream_idle_timeout),
            connect_timeout_from_secs(config.connect_timeout),
        )
        .await?;

        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct TlsDomainConfig {
    pub domain: String,
    pub certs: Option<Vec<CertificateDer<'static>>>,
    pub key: Option<PrivateKeyDer<'static>>,
}

// 为TlsDomainConfig实现Clone trait
impl Clone for TlsDomainConfig {
    fn clone(&self) -> Self {
        Self {
            domain: self.domain.clone(),
            certs: self.certs.clone(),
            key: match &self.key {
                None => None,
                Some(PrivateKeyDer::Pkcs8(key)) => Some(PrivateKeyDer::Pkcs8(key.clone_key())),
                Some(PrivateKeyDer::Pkcs1(key)) => Some(PrivateKeyDer::Pkcs1(key.clone_key())),
                Some(PrivateKeyDer::Sec1(key)) => Some(PrivateKeyDer::Sec1(key.clone_key())),
                Some(_) => panic!("Unsupported key type"),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TlsIdentityManagerConfig {
    #[serde(
        default,
        alias = "public_root",
        alias = "public_identity_root",
        alias = "public_identity_root_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_root_path: Option<String>,
    #[serde(
        default,
        alias = "security_root",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_root_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum TlsHostConfig {
    Host(String),
    Cert(TlsHostCertConfig),
}

impl TlsHostConfig {
    fn identity_host(&self) -> Option<&str> {
        match self {
            Self::Host(host) => Some(host.as_str()),
            Self::Cert(_) => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TlsHostCertConfig {
    #[serde(alias = "domain")]
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TlsStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: std::net::SocketAddr,
    pub hook_point: Vec<crate::ProcessChainConfig>,
    #[serde(default)]
    pub hosts: Vec<TlsHostConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_manager: Option<TlsIdentityManagerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn_protocols: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_max_files: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_upload_bytes_per_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_download_bytes_per_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_idle_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<u64>,
    pub reuse_address: Option<bool>,
}

async fn build_tls_domain_configs(config: &TlsStackConfig) -> StackResult<Vec<TlsDomainConfig>> {
    let mut cert_list = Vec::new();
    for host_config in config.hosts.iter() {
        let TlsHostConfig::Cert(host_config) = host_config else {
            continue;
        };
        match (
            host_config.cert_path.as_deref(),
            host_config.key_path.as_deref(),
        ) {
            (Some(cert_path), Some(key_path)) => {
                if !std::path::Path::new(cert_path).is_absolute()
                    || !std::path::Path::new(key_path).is_absolute()
                {
                    return Err(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "cert_path and key_path must be absolute paths for {}",
                        host_config.host
                    ));
                }
                let certs = load_certs(cert_path).await?;
                let key = load_key(key_path).await?;
                cert_list.push(TlsDomainConfig {
                    domain: host_config.host.clone(),
                    certs: Some(certs),
                    key: Some(key),
                });
            }
            _ => {
                return Err(stack_err!(
                    StackErrorCode::InvalidConfig,
                    "cert_path and key_path must both be configured for {}",
                    host_config.host
                ));
            }
        }
    }
    Ok(cert_list)
}

impl crate::StackConfig for TlsStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tls
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

fn normalize_concurrency(concurrency: u32) -> u32 {
    if concurrency == 0 {
        u32::MAX
    } else {
        concurrency
    }
}

pub(crate) fn build_identity_cert_config(
    hosts: &[String],
    identity_manager: Option<&TlsIdentityManagerConfig>,
) -> StackResult<Option<TlsIdentityCertConfig>> {
    let hosts = hosts
        .iter()
        .map(|host| host.trim())
        .filter(|host| !host.is_empty())
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        return Ok(None);
    }

    let mut roots = IdentityRoots::from_env_or_buckyos_root().map_err(|e| {
        stack_err!(
            StackErrorCode::InvalidConfig,
            "load identity manager roots failed: {}",
            e
        )
    })?;
    if let Some(identity_manager) = identity_manager {
        if let Some(public_root_path) = identity_manager.public_root_path.as_ref() {
            roots.public_root = public_root_path.into();
        }
        if let Some(security_root_path) = identity_manager.security_root_path.as_ref() {
            roots.security_root = security_root_path.into();
        }
    }

    let mut identity_hosts = Vec::with_capacity(hosts.len());
    for host in hosts {
        identity_hosts.push(TlsIdentityHost::new(&roots, host).map_err(|e| {
            stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid TLS identity host {}: {}",
                host,
                e
            )
        })?);
    }

    Ok(Some(TlsIdentityCertConfig {
        roots,
        hosts: identity_hosts,
        refresh_interval: Duration::from_secs(DEFAULT_IDENTITY_CERT_REFRESH_INTERVAL_SECS),
    }))
}

fn build_tls_identity_cert_config(
    hosts: &[TlsHostConfig],
    identity_manager: Option<&TlsIdentityManagerConfig>,
) -> StackResult<Option<TlsIdentityCertConfig>> {
    let hosts = hosts
        .iter()
        .filter_map(|host| host.identity_host().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    build_identity_cert_config(&hosts, identity_manager)
}

pub struct TlsStackFactory {
    connection_manager: ConnectionManagerRef,
    server_runtime: ServerRuntime,
}

impl TlsStackFactory {
    pub fn new(connection_manager: ConnectionManagerRef, server_runtime: ServerRuntime) -> Self {
        Self {
            connection_manager,
            server_runtime,
        }
    }
}

#[async_trait::async_trait]
impl crate::StackFactory for TlsStackFactory {
    async fn create(
        &self,
        config: Arc<dyn crate::StackConfig>,
        context: Arc<dyn crate::StackContext>,
    ) -> crate::StackResult<crate::StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tls stack config"
            ))?;

        let cert_list = build_tls_domain_configs(config).await?;
        let identity_certs =
            build_tls_identity_cert_config(&config.hosts, config.identity_manager.as_ref())?;

        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<TlsStackContext>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tls stack context"
            ))?;
        let stack_context = Arc::new(stack_context.clone());
        let io_dump = create_io_dump_stack_config(
            &config.id,
            config.io_dump_file.as_deref(),
            config.io_dump_rotate_size.as_deref(),
            config.io_dump_rotate_max_files,
            config.io_dump_max_upload_bytes_per_conn.as_deref(),
            config.io_dump_max_download_bytes_per_conn.as_deref(),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;

        let stack = TlsStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .server_runtime(self.server_runtime.clone())
            .connection_manager(self.connection_manager.clone())
            .hook_point(config.hook_point.clone())
            .add_certs(cert_list)
            .identity_certs(identity_certs)
            .concurrency(config.concurrency.unwrap_or(DEFAULT_TLS_CONCURRENCY))
            .alpn_protocols(
                config
                    .alpn_protocols
                    .clone()
                    .unwrap_or(vec!["http/1.1".to_string()])
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect(),
            )
            .reuse_address(config.reuse_address.unwrap_or(false))
            .stack_context(stack_context)
            .io_dump(io_dump)
            .stream_idle_timeout(stream_idle_timeout_from_secs(config.stream_idle_timeout))
            .connect_timeout(connect_timeout_from_secs(config.connect_timeout))
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

pub struct TlsStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    certs: Vec<TlsDomainConfig>,
    identity_certs: Option<TlsIdentityCertConfig>,
    concurrency: u32,
    server_runtime: Option<ServerRuntime>,
    connection_manager: Option<ConnectionManagerRef>,
    alpn_protocols: Vec<Vec<u8>>,
    stack_context: Option<Arc<TlsStackContext>>,
    io_dump: Option<IoDumpStackConfig>,
    reuse_address: bool,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl TlsStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind: None,
            hook_point: None,
            certs: vec![],
            identity_certs: None,
            concurrency: normalize_concurrency(DEFAULT_TLS_CONCURRENCY),
            server_runtime: None,
            connection_manager: None,
            alpn_protocols: vec![],
            stack_context: None,
            io_dump: None,
            reuse_address: false,
            stream_idle_timeout: stream_idle_timeout_from_secs(None),
            connect_timeout: connect_timeout_from_secs(None),
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
        self
    }

    pub fn add_certs(mut self, certs: Vec<TlsDomainConfig>) -> Self {
        self.certs.extend(certs);
        self
    }

    pub(crate) fn identity_certs(mut self, identity_certs: Option<TlsIdentityCertConfig>) -> Self {
        self.identity_certs = identity_certs;
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn server_runtime(mut self, server_runtime: ServerRuntime) -> Self {
        self.server_runtime = Some(server_runtime);
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<TlsStackContext>) -> Self {
        self.stack_context = Some(stack_context);
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = normalize_concurrency(concurrency);
        self
    }

    pub fn alpn_protocols(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    pub fn io_dump(mut self, io_dump: Option<IoDumpStackConfig>) -> Self {
        self.io_dump = io_dump;
        self
    }

    pub fn reuse_address(mut self, reuse_address: bool) -> Self {
        self.reuse_address = reuse_address;
        self
    }

    pub fn stream_idle_timeout(mut self, stream_idle_timeout: std::time::Duration) -> Self {
        self.stream_idle_timeout = stream_idle_timeout;
        self
    }

    pub fn connect_timeout(mut self, connect_timeout: std::time::Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub async fn build(self) -> StackResult<TlsStack> {
        let stack = TlsStack::create(self).await?;
        Ok(stack)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        TlsConnectionHandler, TlsHostConfig, TlsIdentityManagerConfig, build_identity_cert_config,
        build_tls_domain_configs, build_tls_identity_cert_config, load_certs, load_key,
    };
    use crate::global_process_chains::GlobalProcessChains;
    use crate::self_cert_mgr::{SelfCertConfig, SelfCertMgr, SelfCertMgrRef};
    use crate::{
        ConnectionManager, DefaultLimiterManager, GlobalCollectionManager, MutComposedSpeedStat,
        ProcessChainConfigs, ProcessChainHttpServer, Server, ServerManager, ServerResult, Stack,
        StackFactory, StackProtocol, StatManager, StreamInfo, StreamServer, TlsStackConfig,
        TlsStackFactory, TunnelManager, connect_timeout_from_secs, create_io_dump_stack_config,
        decode_io_dump_frames, stream_idle_timeout_from_secs,
    };
    use crate::{
        LimiterManagerRef, ServerManagerRef, StackContext, StatManagerRef, TlsDomainConfig,
        TlsStack, TlsStackBuilder, TlsStackContext,
    };
    use buckyos_kit::{AsyncStream, init_logging};
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use name_lib::{DeviceConfig, encode_ed25519_sk_to_pk_jwk, generate_ed25519_key};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, generate_simple_self_signed,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::server::StoresServerSessions;
    use rustls::{
        ClientConfig, DigitallySignedStruct, Error, HandshakeKind, RootCertStore, ServerConfig,
        SignatureScheme,
    };
    use sfo_io::StatStream;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn test_server_runtime() -> sfo_reuseport::ServerRuntime {
        sfo_reuseport::ServerRuntime::start(
            sfo_reuseport::ServerRuntimeConfig::new().with_workers(1),
        )
        .unwrap()
    }

    async fn wait_dump_frames(
        file: &std::path::Path,
        min_frames: usize,
    ) -> Vec<crate::DecodedIoDumpFrame> {
        for _ in 0..50 {
            if let Ok(data) = std::fs::read(file)
                && !data.is_empty()
                && let Ok(frames) = decode_io_dump_frames(&data)
                && frames.len() >= min_frames
            {
                return frames;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("dump frames not ready");
    }

    fn build_stack_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<TlsStackContext> {
        Arc::new(TlsStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            self_cert_mgr,
            global_process_chains,
            None,
            None,
        ))
    }

    fn tls_stack_builder() -> TlsStackBuilder {
        TlsStack::builder().server_runtime(test_server_runtime())
    }

    #[tokio::test]
    async fn test_tls_stack_creation() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = tls_stack_builder().build().await;
        assert!(result.is_err());
        let result = tls_stack_builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_err());
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tls_stack_reject() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9080").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_drop() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9081")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9081").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_forward() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9083";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9091")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9083").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

        {
            let stream = TcpStream::connect("127.0.0.1:9091").await.unwrap();
            let connector = TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
                .await
                .unwrap();
            let result = stream.write_all(b"test").await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            assert!(result.is_ok());
            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;
            assert!(ret.is_ok());
            assert_eq!(b"recv", &buf[..ret.unwrap()]);
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_tls_stack_forward_err() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:19083";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9093")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

        let stream = TcpStream::connect("127.0.0.1:9093").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());
        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_self_cert() {
        init_logging("test", false);
        let _subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9088";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tls_self_certs_path = tempfile::env::temp_dir()
            .join("tls_self_certs")
            .to_string_lossy()
            .to_string();
        let mut self_cert_config = SelfCertConfig::default();
        self_cert_config.store_path = tls_self_certs_path.clone();
        let connection_manager = ConnectionManager::new();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9097")
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .add_certs(vec![TlsDomainConfig {
                domain: "*".to_string(),
                certs: None,
                key: None,
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(self_cert_config).await.unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9088").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

        {
            let stream = TcpStream::connect("127.0.0.1:9097").await.unwrap();
            let connector = TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
                .await
                .unwrap();
            let result = stream.write_all(b"test").await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            assert!(result.is_ok());
            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;
            assert!(ret.is_ok());
            assert_eq!(b"recv", &buf[..ret.unwrap()]);
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);

        tokio::fs::remove_dir_all(tls_self_certs_path)
            .await
            .unwrap();
    }

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            Self { id }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl StreamServer for MockServer {
        async fn serve_connection(
            &self,
            mut stream: Box<dyn AsyncStream>,
            _info: StreamInfo,
        ) -> ServerResult<()> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all("recv".as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }
    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
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

    #[derive(Debug)]
    struct CountingServerSessionStorage {
        inner: Arc<dyn StoresServerSessions>,
        puts: AtomicUsize,
        gets: AtomicUsize,
        takes: AtomicUsize,
    }

    impl CountingServerSessionStorage {
        fn new(size: usize) -> Arc<Self> {
            Arc::new(Self {
                inner: rustls::server::ServerSessionMemoryCache::new(size),
                puts: AtomicUsize::new(0),
                gets: AtomicUsize::new(0),
                takes: AtomicUsize::new(0),
            })
        }

        fn puts(&self) -> usize {
            self.puts.load(Ordering::SeqCst)
        }

        fn takes(&self) -> usize {
            self.takes.load(Ordering::SeqCst)
        }
    }

    impl StoresServerSessions for CountingServerSessionStorage {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.inner.put(key, value)
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key)
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.takes.fetch_add(1, Ordering::SeqCst);
            self.inner.take(key)
        }

        fn can_cache(&self) -> bool {
            self.inner.can_cache()
        }
    }

    async fn connect_tls_and_exchange(connector: &TlsConnector, addr: SocketAddr) -> HandshakeKind {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        let handshake_kind = stream.get_ref().1.handshake_kind().unwrap();
        stream.shutdown().await.unwrap();
        handshake_kind
    }

    #[tokio::test]
    async fn test_tls_connection_handler_resumes_tls13_sessions() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_handle = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = upstream_listener.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, b"ping");
                    stream.write_all(b"pong").await.unwrap();
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });

        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///{upstream_addr}";
        "#
        );
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let mut handler = TlsConnectionHandler::create(
            chains,
            vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }],
            None,
            vec![b"http/1.1".to_vec()],
            stack_context,
            None,
            None,
            stream_idle_timeout_from_secs(None),
            connect_timeout_from_secs(None),
        )
        .await
        .unwrap();
        let session_storage = CountingServerSessionStorage::new(16);
        Arc::get_mut(&mut handler.server_config)
            .unwrap()
            .session_storage = session_storage.clone();

        let handler = Arc::new(handler);
        let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let server = {
            let handler = handler.clone();
            async move {
                let handle_stream = |stream: TcpStream, handler: Arc<TlsConnectionHandler>| async move {
                    let local_addr = stream.local_addr().unwrap();
                    let compose_stat = MutComposedSpeedStat::new();
                    let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
                    handler
                        .handle_connect(stat_stream, local_addr, compose_stat)
                        .await
                        .unwrap();
                };

                let (first_stream, _) = tls_listener.accept().await.unwrap();
                let first = handle_stream(first_stream, handler.clone());
                let second = async {
                    let (stream, _) = tls_listener.accept().await.unwrap();
                    handle_stream(stream, handler).await;
                };
                tokio::join!(first, second);
            }
        };

        let client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let client = async {
            let first = connect_tls_and_exchange(&connector, tls_addr).await;
            assert!(matches!(
                first,
                HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest
            ));
            for _ in 0..50 {
                if session_storage.puts() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(session_storage.puts() > 0);

            let second = connect_tls_and_exchange(&connector, tls_addr).await;
            assert_eq!(second, HandshakeKind::Resumed);
            assert!(session_storage.takes() > 0);
        };

        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
        upstream_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_stack_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9085")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9085").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_tls_http1() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await
            .unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9087")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let _device_config =
            DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9087").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_11)
            .method("GET")
            .uri("https://www.buckyos.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = send.send_request(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_11);
        let header = resp.headers().get(http::header::ALT_SVC);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "h3=\":9186\"; ma=86400");
    }

    #[tokio::test]
    async fn test_tls_http2() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9186)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await
            .unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9086")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let _device_config =
            DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9086").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method("GET")
            .uri("https://www.buckyos.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = send.send_request(request).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_2);
        let header = resp.headers().get(http::header::ALT_SVC);
        assert!(header.is_some());
        assert_eq!(header.unwrap(), "h3=\":9186\"; ma=86400");
    }

    #[tokio::test]
    async fn test_tls_io_dump_raw_single_roundtrip() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_raw.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_raw",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let stack = tls_stack_builder()
            .id("tls-raw")
            .bind("127.0.0.1:9093")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9093").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");
        drop(stream);

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"test" && f.download == b"recv")
        );
    }

    #[tokio::test]
    async fn test_tls_io_dump_raw_flush_on_upload_limit() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_raw_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_raw_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("2B"),
            None,
        )
        .await
        .unwrap();

        let stack = tls_stack_builder()
            .id("tls-raw-limit")
            .bind("127.0.0.1:9095")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9095").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"te" && f.download.is_empty())
        );
    }

    #[tokio::test]
    async fn test_tls_io_dump_http1_multi_requests_same_connection() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9196)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await
            .unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_http.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_http",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let stack = tls_stack_builder()
            .id("tls-http")
            .bind("127.0.0.1:9094")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9094").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        for path in ["/a", "/b"] {
            let req = http::Request::builder()
                .version(http::Version::HTTP_11)
                .method("GET")
                .uri(format!("https://www.buckyos.com{path}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = send.send_request(req).await.unwrap();
            assert_eq!(resp.version(), http::Version::HTTP_11);
        }

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(frames.iter().any(|f| {
            f.upload.starts_with(b"GET ")
                && f.upload.windows(2).any(|w| w == b"/a")
                && f.download.starts_with(b"HTTP/1.1")
        }));
        assert!(frames.iter().any(|f| {
            f.upload.starts_with(b"GET ")
                && f.upload.windows(2).any(|w| w == b"/b")
                && f.download.starts_with(b"HTTP/1.1")
        }));
    }

    #[tokio::test]
    async fn test_tls_io_dump_http_flush_on_upload_limit() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_mgr = Arc::new(ServerManager::new());
        let http_server = ProcessChainHttpServer::builder()
            .id("www.buckyos.com")
            .version("HTTP/3")
            .h3_port(9196)
            .hook_point(chains)
            .global_process_chains(Arc::new(GlobalProcessChains::new()))
            .server_mgr(Arc::downgrade(&server_mgr))
            .tunnel_manager(TunnelManager::new())
            .build()
            .await
            .unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Http(Arc::new(http_server)));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let dir = tempdir().unwrap();
        let dump = dir.path().join("tls_http_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tls_http_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("4B"),
            None,
        )
        .await
        .unwrap();
        let stack = tls_stack_builder()
            .id("tls-http-limit")
            .bind("127.0.0.1:9096")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9096").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .version(http::Version::HTTP_11)
            .method("GET")
            .uri("https://www.buckyos.com/a")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.version(), http::Version::HTTP_11);

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"GET " && f.download.is_empty())
        );
    }

    #[tokio::test]
    async fn test_factory() {
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default())
            .await
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let factory = TlsStackFactory::new(ConnectionManager::new(), test_server_runtime());

        let config = TlsStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tls,
            bind: "127.0.0.1:343".parse().unwrap(),
            hook_point: vec![],
            hosts: vec![],
            identity_manager: None,
            concurrency: None,
            alpn_protocols: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        };
        let stack_context: Arc<dyn StackContext> = Arc::new(TlsStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            self_cert_mgr,
            Some(global_process_chains),
            Some(collection_manager),
            None,
        ));
        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }

    #[test]
    fn test_tls_stack_config_uses_identity_hosts() {
        let config: TlsStackConfig = serde_yaml_ng::from_str(
            r#"
id: tls_test
protocol: tls
bind: 127.0.0.1:443
hosts:
  - example.com
  - "*.example.org"
identity_manager:
  public_root_path: /tmp/identity
  security_root_path: /tmp/security
hook_point: []
"#,
        )
        .unwrap();

        assert_eq!(
            config.hosts,
            vec![
                TlsHostConfig::Host("example.com".to_string()),
                TlsHostConfig::Host("*.example.org".to_string())
            ]
        );
        let identity_manager = config.identity_manager.unwrap();
        assert_eq!(
            identity_manager.public_root_path.as_deref(),
            Some("/tmp/identity")
        );
        assert_eq!(
            identity_manager.security_root_path.as_deref(),
            Some("/tmp/security")
        );
    }

    #[tokio::test]
    async fn test_tls_stack_config_loads_cert_paths() {
        let cert_key = generate_simple_self_signed(vec!["cert.example.com".to_string()]).unwrap();
        let tmp_dir = tempdir().unwrap();
        let cert_path = tmp_dir.path().join("fullchain.pem");
        let key_path = tmp_dir.path().join("leaf.key");
        fs::write(&cert_path, cert_key.cert.pem()).await.unwrap();
        fs::write(&key_path, cert_key.signing_key.serialize_pem())
            .await
            .unwrap();

        let config: TlsStackConfig = serde_yaml_ng::from_str(&format!(
            r#"
id: tls_test
protocol: tls
bind: 127.0.0.1:443
hosts:
  - example.com
  - host: cert.example.com
    cert_path: {}
    key_path: {}
hook_point: []
"#,
            cert_path.display(),
            key_path.display(),
        ))
        .unwrap();

        let identity_certs = build_tls_identity_cert_config(&config.hosts, None)
            .unwrap()
            .unwrap();
        assert_eq!(identity_certs.hosts.len(), 1);
        assert_eq!(identity_certs.hosts[0].identity, "example.com");

        let certs = build_tls_domain_configs(&config).await.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].domain, "cert.example.com");
        assert!(certs.iter().all(|item| item.certs.is_some()));
        assert!(certs.iter().all(|item| item.key.is_some()));
    }

    #[tokio::test]
    async fn test_tls_stack_config_rejects_relative_cert_paths() {
        let config: TlsStackConfig = serde_yaml_ng::from_str(
            r#"
id: tls_test
protocol: tls
bind: 127.0.0.1:443
hosts:
  - host: cert.example.com
    cert_path: ./fullchain.pem
    key_path: ./leaf.key
hook_point: []
"#,
        )
        .unwrap();

        let result = build_tls_domain_configs(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tls_stack_config_rejects_host_object_without_cert_paths() {
        let config: TlsStackConfig = serde_yaml_ng::from_str(
            r#"
id: tls_test
protocol: tls
bind: 127.0.0.1:443
hosts:
  - host: cert.example.com
hook_point: []
"#,
        )
        .unwrap();

        let identity_certs = build_tls_identity_cert_config(&config.hosts, None).unwrap();
        assert!(identity_certs.is_none());

        let result = build_tls_domain_configs(&config).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_identity_config_normalizes_supported_hosts() {
        let tmp_dir = tempdir().unwrap();
        let public_root = tmp_dir.path().join("identity");
        let security_root = tmp_dir.path().join("security");
        let identity_manager = TlsIdentityManagerConfig {
            public_root_path: Some(public_root.to_string_lossy().to_string()),
            security_root_path: Some(security_root.to_string_lossy().to_string()),
        };

        let hosts = vec![
            "*.example.com".to_string(),
            "did:web:example.org:user:alice".to_string(),
        ];
        let config = build_identity_cert_config(&hosts, Some(&identity_manager))
            .unwrap()
            .unwrap();

        assert_eq!(config.roots.public_root, public_root);
        assert_eq!(config.roots.security_root, security_root);
        assert_eq!(config.hosts[0].identity, "*.example.com");
        assert_eq!(config.hosts[0].tls_host, "*.example.com");
        assert_eq!(config.hosts[1].identity, "did:web:example.org:user:alice");
        assert_eq!(config.hosts[1].tls_host, "example.org");
    }

    #[tokio::test]
    async fn test_tls_stack_stat_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9185")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                stat_manager.clone(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9185").await.unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_limiter_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "2B/s" "2B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9186")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                stat_manager.clone(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9186").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 3000);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_group_limiter_server() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9187")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                limiter_manager,
                stat_manager.clone(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9187").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tls_stack_stat_group_limiter_server2() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test "10KB/s" "10KB/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let result = tls_stack_builder()
            .id("test")
            .bind("127.0.0.1:9188")
            .hook_point(chains)
            .add_certs(vec![TlsDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"http/1.1".to_vec(), b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(build_stack_context(
                server_manager,
                TunnelManager::new(),
                limiter_manager,
                stat_manager.clone(),
                SelfCertMgr::create(SelfCertConfig::default())
                    .await
                    .unwrap(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let stream = TcpStream::connect("127.0.0.1:9188").await.unwrap();
        let start = std::time::Instant::now();
        let connector = TlsConnector::from(Arc::new(config));
        let mut stream = connector
            .connect(ServerName::try_from("www.buckyos.com").unwrap(), stream)
            .await
            .unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert!(test_stat.get_read_sum_size() > 350);
        assert!(test_stat.get_write_sum_size() > 880);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn build_test_chain() -> (String, String, String, CertificateDer<'static>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test Root CA".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params =
            CertificateParams::new(vec!["Test Intermediate CA".to_string()]).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &ca_issuer)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["sn.buckyos.ai".to_string()]).unwrap();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, &intermediate_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();

        let intermediate_pem = intermediate_cert.pem();
        let leaf_pem = leaf_cert.pem();
        let leaf_key_pem = leaf_key.serialize_pem();
        let root_der = CertificateDer::from(ca_cert.clone());

        let fullchain_pem = format!("{leaf_pem}\n{intermediate_pem}");
        (fullchain_pem, leaf_pem, leaf_key_pem, root_der)
    }

    #[tokio::test]
    async fn test_tls_fullchain_allows_client_verify() {
        ensure_crypto_provider();
        let (fullchain_pem, _leaf_pem, leaf_key_pem, root_der) = build_test_chain();
        let tmp_dir = tempdir().unwrap();
        let cert_path = tmp_dir.path().join("fullchain.pem");
        let key_path = tmp_dir.path().join("leaf.key");
        fs::write(&cert_path, fullchain_pem).await.unwrap();
        fs::write(&key_path, leaf_key_pem).await.unwrap();

        let certs = load_certs(cert_path.to_str().unwrap()).await.unwrap();
        let key = load_key(key_path.to_str().unwrap()).await.unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let mut roots = RootCertStore::empty();
        roots.add(root_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("sn.buckyos.ai").unwrap(), stream)
            .await;
        assert!(result.is_ok());

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_missing_intermediate_fails_client_verify() {
        ensure_crypto_provider();
        let (_fullchain_pem, leaf_pem, leaf_key_pem, root_der) = build_test_chain();
        let tmp_dir = tempdir().unwrap();
        let cert_path = tmp_dir.path().join("leaf.pem");
        let key_path = tmp_dir.path().join("leaf.key");
        fs::write(&cert_path, leaf_pem).await.unwrap();
        fs::write(&key_path, leaf_key_pem).await.unwrap();

        let certs = load_certs(cert_path.to_str().unwrap()).await.unwrap();
        let key = load_key(key_path.to_str().unwrap()).await.unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let mut roots = RootCertStore::empty();
        roots.add(root_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("sn.buckyos.ai").unwrap(), stream)
            .await;
        assert!(result.is_err());

        server_handle.await.unwrap();
    }
}
