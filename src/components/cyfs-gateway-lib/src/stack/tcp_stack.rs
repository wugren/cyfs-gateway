use super::{
    Stack, connect_timeout_from_secs, get_limit_info, get_source_addr_from_req_env,
    probe_proxy_protocol_stream, stream_forward, stream_forward_group,
    stream_idle_timeout_from_secs,
};
use crate::forward::ForwardPlan;

#[cfg(target_os = "linux")]
use super::has_root_privileges;

use super::StackResult;
use crate::global_process_chains::{
    GlobalProcessChainsRef, create_process_chain_executor, execute_stream_chain,
};
use crate::stack::limiter::Limiter;
use crate::{
    ConnectionController, ConnectionInfo, ConnectionManagerRef, DumpStream,
    GlobalCollectionManagerRef, IoDumpStackConfig, JsExternalsManagerRef, LimiterManagerRef,
    MutComposedSpeedStat, MutComposedSpeedStatRef, ProcessChainConfig, ProcessChainConfigs, Server,
    ServerManagerRef, StackConfig, StackContext, StackErrorCode, StackFactory, StackProtocol,
    StackRef, StatManagerRef, StreamInfo, TunnelManager, create_io_dump_stack_config,
    get_external_commands, get_stat_info, hyper_serve_http, into_stack_err, stack_err,
};
use cyfs_process_chain::{CollectionValue, CommandControl, ProcessChainLibExecutor, StreamRequest};
use futures_util::future::{AbortHandle, Abortable};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use sfo_reuseport::{ServerRuntime, SocketOptions, TcpServer, TcpServiceConfig, TransparentMode};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::oneshot;

const DEFAULT_TCP_CONCURRENCY: u32 = 0;

#[derive(Clone)]
pub struct TcpStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl TcpStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for TcpStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }
}

struct TcpConnectionHandler {
    env: Arc<TcpStackContext>,
    executor: ProcessChainLibExecutor,
    connection_manager: Option<ConnectionManagerRef>,
    io_dump: Option<IoDumpStackConfig>,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl TcpConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<TcpStackContext>,
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
        Ok(Self {
            env,
            executor,
            connection_manager,
            io_dump,
            stream_idle_timeout,
            connect_timeout,
        })
    }

    async fn rebuild_with_hook_point(
        &self,
        hook_point: ProcessChainConfigs,
        io_dump: Option<IoDumpStackConfig>,
    ) -> StackResult<Self> {
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
            io_dump,
            stream_idle_timeout: self.stream_idle_timeout,
            connect_timeout: self.connect_timeout,
        })
    }

    async fn handle_connect(
        &self,
        mut stream: StatStream<TcpStream>,
        dest_addr: SocketAddr,
        compose_stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_addr = stream.raw_stream().peer_addr().map_err(into_stack_err!(
            StackErrorCode::ServerError,
            "read remote addr failed"
        ))?;
        let req_stream: Box<dyn buckyos_kit::AsyncStream> =
            if let Some(io_dump) = self.io_dump.clone() {
                Box::new(DumpStream::new(
                    stream,
                    io_dump,
                    remote_addr.to_string(),
                    dest_addr.to_string(),
                ))
            } else {
                Box::new(stream)
            };
        let (req_stream, proxy_source_addr) = probe_proxy_protocol_stream(req_stream).await?;
        let request_source_addr = proxy_source_addr.unwrap_or(remote_addr);
        let device_lookup_ip = request_source_addr.ip();
        let mut request = StreamRequest::new(req_stream, dest_addr);
        request.source_addr = Some(request_source_addr);
        request.conn_source_addr = Some(remote_addr);
        request.real_source_addr = proxy_source_addr;
        request.dest_port = dest_addr.port();
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(device_lookup_ip))
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
            .with_dst_addr(Some(dest_addr.to_string()));
        if let Some(device_info) = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(device_lookup_ip))
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
                            let stream = if limiter.is_some() {
                                let (read_limit, write_limit) =
                                    limiter.as_ref().unwrap().new_limit_session();
                                let limit_stream =
                                    LimitStream::new(stream, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                stream
                            };

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        hyper_serve_http(stream, server, stream_info.clone())
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(stream, stream_info.clone())
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type {server_name}"
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

fn get_dest_addr(stream: &TcpStream) -> StackResult<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let ret = crate::stack::get_socket_opt(
            stream,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut addr,
        );
        if ret.is_ok() {
            return crate::stack::sockaddr_to_socket_addr(&addr).map_err(into_stack_err!(
                StackErrorCode::InvalidData,
                "read dest addr failed"
            ));
        }

        let ret =
            crate::stack::get_socket_opt(stream, libc::SOL_IP, libc::SO_ORIGINAL_DST, &mut addr);
        if ret.is_ok() {
            return crate::stack::sockaddr_to_socket_addr(&addr).map_err(into_stack_err!(
                StackErrorCode::InvalidData,
                "read dest addr failed"
            ));
        }
    }

    stream.local_addr().map_err(into_stack_err!(
        StackErrorCode::ServerError,
        "read dest addr failed"
    ))
}

pub struct TcpStack {
    id: String,
    bind_addr: String,
    concurrency: u32,
    server_runtime: ServerRuntime,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<TcpConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<TcpConnectionHandler>>>>,
    transparent: bool,
    reuse_address: bool,
    start_lock: AsyncMutex<()>,
    server: Mutex<Option<TcpServer>>,
}

impl TcpStack {
    pub fn builder() -> TcpStackBuilder {
        TcpStackBuilder {
            id: None,
            bind: None,
            hook_point: None,
            server_runtime: None,
            connection_manager: None,
            stack_context: None,
            transparent: false,
            io_dump: None,
            reuse_address: false,
            concurrency: normalize_concurrency(DEFAULT_TCP_CONCURRENCY),
            stream_idle_timeout: stream_idle_timeout_from_secs(None),
            connect_timeout: connect_timeout_from_secs(None),
        }
    }

    async fn create(config: TcpStackBuilder) -> StackResult<Self> {
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
                "handler_env is required"
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
        let handler = TcpConnectionHandler::create(
            config.hook_point.unwrap(),
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
            transparent: config.transparent,
            reuse_address: config.reuse_address,
            start_lock: AsyncMutex::new(()),
            server: Mutex::new(None),
        })
    }

    async fn start_listener(&self) -> StackResult<TcpServer> {
        let addr: SocketAddr = self.bind_addr.parse().map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "invalid bind address {}",
            self.bind_addr
        ))?;
        #[cfg(target_os = "linux")]
        {
            if self.transparent && !has_root_privileges() {
                return Err(stack_err!(
                    StackErrorCode::PermissionDenied,
                    "transparent mode requires root privileges"
                ));
            }
        }

        let socket_options = SocketOptions {
            reuse_address: self.reuse_address || self.transparent,
            ipv4_transparent: transparent_mode(self.transparent, addr.is_ipv4()),
            ipv6_transparent: transparent_mode(self.transparent, addr.is_ipv6()),
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
                handle_reuseport_stream(stream, handler, connection_manager).await;
                Ok(())
            }
        })
        .map_err(|e| {
            stack_err!(
                StackErrorCode::BindFailed,
                "start tcp server {} on {} error: {e}",
                self.id,
                self.bind_addr
            )
        })?;
        Ok(server)
    }
}

impl Drop for TcpStack {
    fn drop(&mut self) {
        if let Some(server) = self.server.lock().unwrap().take() {
            if let Err(e) = server.close() {
                log::error!("close tcp server failed: {}", e);
            }
        }
    }
}

fn transparent_mode(transparent: bool, matches_bind_family: bool) -> TransparentMode {
    if transparent && matches_bind_family {
        #[cfg(target_os = "linux")]
        {
            TransparentMode::Required
        }
        #[cfg(not(target_os = "linux"))]
        {
            TransparentMode::Disabled
        }
    } else {
        TransparentMode::Disabled
    }
}

async fn handle_reuseport_stream(
    stream: TcpStream,
    handler: Arc<RwLock<Arc<TcpConnectionHandler>>>,
    connection_manager: Option<ConnectionManagerRef>,
) {
    let remote_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("read tcp peer addr failed: {}", e);
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
    let dest_addr = match get_dest_addr(&stream) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("get dest addr failed: {}", e);
            return;
        }
    };
    log::debug!("accept tcp stream from {} to {}", remote_addr, dest_addr);
    let compose_stat = MutComposedSpeedStat::new();
    let stat_stream = StatStream::new_with_tracker(stream, compose_stat.clone());
    let speed = stat_stream.get_speed_stat();
    let handler_snapshot = {
        let handler = handler.read().unwrap();
        handler.clone()
    };

    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let (controller, done_sender) = AbortableConnectionController::new(abort_handle);
    if let Some(manager) = &connection_manager {
        manager.add_connection(ConnectionInfo::new(
            remote_addr.to_string(),
            dest_addr.to_string(),
            StackProtocol::Tcp,
            speed,
            controller.clone(),
        ));
    }

    let result = Abortable::new(
        handler_snapshot.handle_connect(stat_stream, dest_addr, compose_stat),
        abort_registration,
    )
    .await;
    controller.mark_stopped();
    let _ = done_sender.send(());

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::error!("handle tcp stream failed: {}", e),
        Err(_) => log::debug!("tcp stream handler aborted"),
    }
}

#[async_trait::async_trait]
impl Stack for TcpStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        let _start_guard = self.start_lock.lock().await;
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
            .downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tcp stack config"
            ))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if normalize_concurrency(config.concurrency.unwrap_or(DEFAULT_TCP_CONCURRENCY))
            != self.concurrency
        {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "concurrency unmatch"
            ));
        }

        if config.transparent.unwrap_or(false) != self.transparent {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "transparent unmatch"
            ));
        }

        if config.reuse_address.unwrap_or(false) != self.reuse_address {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "reuse_address unmatch"
            ));
        }

        let env = match context {
            Some(context) => {
                let tcp_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<TcpStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid tcp stack context"
                    ))?;
                Arc::new(tcp_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };

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
        let new_handler = TcpConnectionHandler::create(
            config.hook_point.clone(),
            env,
            self.connection_manager.clone(),
            io_dump,
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

pub struct TcpStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    server_runtime: Option<ServerRuntime>,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<TcpStackContext>>,
    transparent: bool,
    io_dump: Option<IoDumpStackConfig>,
    reuse_address: bool,
    concurrency: u32,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl TcpStackBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn bind(mut self, bind: impl Into<String>) -> Self {
        self.bind = Some(bind.into());
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

    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    pub fn reuse_address(mut self, reuse_address: bool) -> Self {
        self.reuse_address = reuse_address;
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = normalize_concurrency(concurrency);
        self
    }

    pub fn stack_context(mut self, handler_env: Arc<TcpStackContext>) -> Self {
        self.stack_context = Some(handler_env);
        self
    }

    pub fn io_dump(mut self, io_dump: Option<IoDumpStackConfig>) -> Self {
        self.io_dump = io_dump;
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

    pub async fn build(self) -> StackResult<TcpStack> {
        let stack = TcpStack::create(self).await?;
        Ok(stack)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TcpStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
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
    pub hook_point: Vec<ProcessChainConfig>,
}

impl StackConfig for TcpStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Tcp
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

struct AbortableConnectionController {
    abort_handle: AbortHandle,
    done: Mutex<Option<oneshot::Receiver<()>>>,
    stopped: AtomicBool,
}

impl AbortableConnectionController {
    fn new(abort_handle: AbortHandle) -> (Arc<Self>, oneshot::Sender<()>) {
        let (done_sender, done_receiver) = oneshot::channel();
        (
            Arc::new(Self {
                abort_handle,
                done: Mutex::new(Some(done_receiver)),
                stopped: AtomicBool::new(false),
            }),
            done_sender,
        )
    }

    fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl ConnectionController for AbortableConnectionController {
    fn stop_connection(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.abort_handle.abort();
    }

    async fn wait_stop(&self) {
        let done = self.done.lock().unwrap().take();
        if let Some(done) = done {
            let _ = done.await;
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

pub struct TcpStackFactory {
    connection_manager: ConnectionManagerRef,
    server_runtime: ServerRuntime,
}

impl TcpStackFactory {
    pub fn new(connection_manager: ConnectionManagerRef, server_runtime: ServerRuntime) -> Self {
        Self {
            connection_manager,
            server_runtime,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for TcpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_ref()
            .as_any()
            .downcast_ref::<TcpStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tcp stack config"
            ))?;
        let handler_env = context
            .as_ref()
            .as_any()
            .downcast_ref::<TcpStackContext>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid tcp stack context"
            ))?;
        let handler_env = Arc::new(handler_env.clone());
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
        let stack = TcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string())
            .server_runtime(self.server_runtime.clone())
            .connection_manager(self.connection_manager.clone())
            .transparent(config.transparent.unwrap_or(false))
            .reuse_address(config.reuse_address.unwrap_or(false))
            .concurrency(config.concurrency.unwrap_or(DEFAULT_TCP_CONCURRENCY))
            .hook_point(config.hook_point.clone())
            .stack_context(handler_env)
            .io_dump(io_dump)
            .stream_idle_timeout(stream_idle_timeout_from_secs(config.stream_idle_timeout))
            .connect_timeout(connect_timeout_from_secs(config.connect_timeout))
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{
        ConnectionManager, DefaultLimiterManager, GlobalCollectionManager, LimiterManagerRef,
        ProcessChainConfigs, Server, ServerManager, ServerManagerRef, ServerResult, Stack,
        StackFactory, StackProtocol, StatManager, StatManagerRef, StreamInfo, StreamServer,
        TcpStack, TcpStackConfig, TcpStackContext, TcpStackFactory, TunnelManager,
        create_io_dump_stack_config, decode_io_dump_frames,
    };
    use buckyos_kit::AsyncStream;
    use sfo_reuseport::ServerRuntimeConfig;
    use std::net::TcpListener as StdTcpListener;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_server_runtime() -> sfo_reuseport::ServerRuntime {
        sfo_reuseport::ServerRuntime::start(ServerRuntimeConfig::new().with_workers(1)).unwrap()
    }

    fn unused_tcp_addr() -> String {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    fn build_handler_env(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<TcpStackContext> {
        Arc::new(TcpStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            None,
            None,
        ))
    }

    fn default_handler_env() -> Arc<TcpStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            None,
        )
    }

    fn handler_env_with_process_chains() -> Arc<TcpStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        )
    }

    async fn wait_dump_frames(file: &Path, min_frames: usize) -> Vec<crate::DecodedIoDumpFrame> {
        for _ in 0..50 {
            if let Ok(data) = std::fs::read(file)
                && !data.is_empty()
                && let Ok(frames) = decode_io_dump_frames(&data)
                && frames.len() >= min_frames
            {
                return frames;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("dump frames not ready");
    }

    #[tokio::test]
    async fn test_tcp_stack_creation() {
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .bind("127.0.0.1:8080")
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind("127.0.0.1:8080")
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .stack_context(default_handler_env())
            .build()
            .await;
        assert!(result.is_err());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .stack_context(default_handler_env())
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .stack_context(handler_env_with_process_chains())
            .build()
            .await;
        assert!(result.is_ok());
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind("127.0.0.1:8080")
            .hook_point(vec![])
            .connection_manager(ConnectionManager::new())
            .stack_context(handler_env_with_process_chains())
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_stack_reject() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        {
            let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
            let result = stream
                .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
                .await;
            assert!(result.is_ok());
            let ret = stream.read(&mut [0; 1024]).await;
            assert!(matches!(ret, Err(_) | Ok(0)));
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test]
    async fn test_tcp_stack_drop() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        assert!(matches!(ret, Err(_) | Ok(0)));
    }

    #[tokio::test]
    async fn test_tcp_stack_forward() {
        let target_addr = unused_tcp_addr();
        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward tcp:///{target_addr};
        "#
        );

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();

        let connection_manager = ConnectionManager::new();
        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind(target_addr.as_str()).await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        {
            let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            assert_eq!(connection_manager.get_all_connection_info().len(), 1);
            let result = stream.write_all(b"test").await;
            assert!(result.is_ok());

            let mut buf = [0u8; 4];
            let ret = stream.read_exact(&mut buf).await;

            assert!(ret.is_ok());
            assert_eq!(&buf, b"recv");
            stream.shutdown().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    async fn run_tcp_source_vars_case(bind: &str, chain_condition: &str, client_payload: &[u8]) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();

        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        {chain_condition} && forward tcp:///127.0.0.1:{echo_port};
        drop;
"#
        );
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();

        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack = TcpStack::builder()
            .id("test")
            .bind(bind)
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut client = TcpStream::connect(bind).await.unwrap();
        client.write_all(client_payload).await.unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("process chain did not forward: source vars not exposed as expected");
        let (mut conn, _) = accepted.unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn test_tcp_stack_source_vars_direct_connection() {
        // Direct connection: conn_source mirrors the effective source and no
        // real_source_* is fabricated (missing keys expand to "").
        run_tcp_source_vars_case(
            "127.0.0.1:8180",
            r#"eq ${REQ.real_source_ip} "" && eq ${REQ.conn_source_ip} "127.0.0.1" && eq ${REQ.source_ip} "127.0.0.1""#,
            b"hello",
        )
        .await;
    }

    #[tokio::test]
    async fn test_tcp_stack_source_vars_proxy_protocol() {
        // PROXY protocol restores the origin: it becomes both the trusted
        // real_source_* and the effective source_*, while conn_source_* keeps
        // the direct hop.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"PROXY TCP4 203.0.113.9 127.0.0.1 5678 80\r\n");
        payload.extend_from_slice(b"hello");
        run_tcp_source_vars_case(
            "127.0.0.1:8181",
            r#"eq ${REQ.real_source_ip} "203.0.113.9" && eq ${REQ.real_source_port} "5678" && eq ${REQ.conn_source_ip} "127.0.0.1" && eq ${REQ.source_ip} "203.0.113.9" && eq ${REQ.source_port} "5678""#,
            &payload,
        )
        .await;
    }

    #[tokio::test]
    async fn test_tcp_stack_forward_err() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:18086";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let handler_env = build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_err());
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

    #[tokio::test]
    async fn test_tcp_stack_server() {
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
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_server() {
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
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_limiter_server() {
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
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_group_limiter_server() {
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
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tcp_stack_stat_group_limiter_server2() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test 10KB/s 10KB/s;
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
        let handler_env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            limiter_manager,
            stat_manager.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let bind_addr = unused_tcp_addr();
        let result = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("test")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(handler_env)
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        let start = Instant::now();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test]
    async fn test_tcp_io_dump_raw_single_roundtrip() {
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
        let env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("tcp_raw.dump");
        let io_dump = create_io_dump_stack_config(
            "tcp_raw",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let bind_addr = unused_tcp_addr();
        let stack = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("tcp-raw")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(env)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
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
    async fn test_tcp_io_dump_raw_flush_on_upload_limit() {
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
        let env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("tcp_raw_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tcp_raw_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("2B"),
            None,
        )
        .await
        .unwrap();
        let bind_addr = unused_tcp_addr();
        let stack = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("tcp-raw-limit")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(env)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
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

    struct MockHttpKeepAliveServer {
        id: String,
    }

    #[async_trait::async_trait(?Send)]
    impl StreamServer for MockHttpKeepAliveServer {
        async fn serve_connection(
            &self,
            mut stream: Box<dyn AsyncStream>,
            _info: StreamInfo,
        ) -> ServerResult<()> {
            for _ in 0..2 {
                let mut req = Vec::new();
                let mut b = [0u8; 1];
                loop {
                    stream.read_exact(&mut b).await.unwrap();
                    req.push(b[0]);
                    if req.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let body = if req.windows(2).any(|w| w == b"/a") {
                    b"A"
                } else {
                    b"B"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                );
                stream.write_all(resp.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[tokio::test]
    async fn test_tcp_io_dump_http1_multi_requests_same_connection() {
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
                id: "www.buckyos.com".to_string(),
            })))
            .unwrap();
        let env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("tcp_http.dump");
        let io_dump = create_io_dump_stack_config(
            "tcp_http",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let bind_addr = unused_tcp_addr();
        let stack = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("tcp-http")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(env)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        stream
            .write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp_a = vec![0u8; 64];
        let n = stream.read(&mut resp_a).await.unwrap();
        assert!(n > 0);

        stream
            .write_all(b"GET /b HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp_b = vec![0u8; 64];
        let n = stream.read(&mut resp_b).await.unwrap();
        assert!(n > 0);

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(frames.iter().any(|f| {
            println!("{}", String::from_utf8_lossy(f.upload.as_slice()));
            println!("{}", String::from_utf8_lossy(f.download.as_slice()));
            f.upload.starts_with(b"GET /a HTTP/1.1") && f.download.starts_with(b"HTTP/1.1 200 OK")
        }));
        assert!(frames.iter().any(|f| {
            f.upload.starts_with(b"GET /b HTTP/1.1") && f.download.starts_with(b"HTTP/1.1 200 OK")
        }));
    }

    #[tokio::test]
    async fn test_tcp_io_dump_http_flush_on_upload_limit() {
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
                id: "www.buckyos.com".to_string(),
            })))
            .unwrap();
        let env = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("tcp_http_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "tcp_http_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("4B"),
            None,
        )
        .await
        .unwrap();
        let bind_addr = unused_tcp_addr();
        let stack = TcpStack::builder()
            .server_runtime(test_server_runtime())
            .id("tcp-http-limit")
            .bind(bind_addr.clone())
            .hook_point(chains)
            .stack_context(env)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut stream = TcpStream::connect(bind_addr.as_str()).await.unwrap();
        stream
            .write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 64];
        let n = stream.read(&mut resp).await.unwrap();
        assert!(n > 0);

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"GET " && f.download.is_empty())
        );
    }

    #[tokio::test]
    async fn test_factory() {
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let tcp_factory = TcpStackFactory::new(ConnectionManager::new(), test_server_runtime());
        let config = TcpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Tcp,
            bind: "127.0.0.1:3345".parse().unwrap(),
            transparent: None,
            concurrency: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
            hook_point: vec![],
        };

        let stack_context = Arc::new(TcpStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains),
            Some(collection_manager),
            None,
        ));
        let ret = tcp_factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }
}
