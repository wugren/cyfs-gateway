use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use buckyos_kit::AsyncStream;
use cyfs_process_chain::{
    CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor,
};
use name_client::{IdentityMaterial, IdentityRoots, IdentityUsage};
use name_lib::{
    DID, DIDDocumentTrait, DeviceConfig, EncodedDocument, encode_ed25519_pkcs8_sk_to_pk,
    get_x_from_jwk, load_raw_private_key,
};
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use sfo_reuseport::{
    ServerRuntime, SocketOptions, TaskHandle, TcpServer, TcpServiceConfig, TransparentMode,
};
use tokio::sync::Notify;
use url::Url;

use crate::forward::ForwardPlan;
use crate::global_process_chains::{
    GlobalProcessChainsRef, create_process_chain_executor, execute_chain,
};
use crate::rtcp::{
    AsyncStreamWithDatagram, RTcpTunnelDatagramClient, validate_rtcp_hostname_form_did,
};
use crate::stack::limiter::Limiter;
use crate::stack::{
    connect_timeout_from_secs, datagram_forward, datagram_forward_group, get_limit_info,
    get_source_addr_from_req_env, insert_req_source_addr_group, probe_proxy_protocol_stream,
    stream_forward, stream_forward_group, stream_idle_timeout_from_secs,
};
use crate::tunnel_url_status::{
    TunnelProbeOptions, TunnelUrlProber, TunnelUrlProberRef, TunnelUrlStatus,
    TunnelUrlStatusSource, normalize_tunnel_url, reachable_status, unreachable_status,
};
use crate::{
    ConnectionController, ConnectionInfo, ConnectionManagerRef, DatagramInfo, DumpStream,
    GlobalCollectionManagerRef, IoDumpStackConfig, JsExternalsManagerRef, LimiterManagerRef,
    MutComposedSpeedStat, MutComposedSpeedStatRef, ProcessChainConfigs, RTcp, RTcpListener, Server,
    ServerManagerRef, Stack, StackConfig, StackContext, StackErrorCode, StackFactory,
    StackProtocol, StackRef, StackResult, StatManagerRef, StreamInfo, TunnelBox, TunnelBuilder,
    TunnelEndpoint, TunnelError, TunnelManager, TunnelResult, create_io_dump_stack_config,
    get_external_commands, get_stat_info, has_scheme, hyper_serve_http, into_stack_err, stack_err,
};

#[derive(Clone)]
pub struct RtcpStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl RtcpStackContext {
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

impl StackContext for RtcpStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }
}

struct RtcpConnectionHandler {
    env: Arc<RtcpStackContext>,
    executor: ProcessChainLibExecutor,
    on_new_tunnel_executor: Option<ProcessChainLibExecutor>,
    connection_manager: Option<ConnectionManagerRef>,
    io_dump: Option<IoDumpStackConfig>,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl RtcpConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        on_new_tunnel_hook_point: Option<ProcessChainConfigs>,
        env: Arc<RtcpStackContext>,
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
        let on_new_tunnel_executor =
            if let Some(on_new_tunnel_hook_point) = on_new_tunnel_hook_point {
                let (executor, _) = create_process_chain_executor(
                    &on_new_tunnel_hook_point,
                    env.global_process_chains.clone(),
                    env.global_collection_manager.clone(),
                    Some(get_external_commands(Arc::downgrade(&env.servers))),
                    env.js_externals.clone(),
                )
                .await
                .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
                Some(executor)
            } else {
                None
            };
        Ok(Self {
            env,
            executor,
            on_new_tunnel_executor,
            connection_manager,
            io_dump,
            stream_idle_timeout,
            connect_timeout,
        })
    }

    async fn rebuild_with_hook_point(
        &self,
        hook_point: ProcessChainConfigs,
        on_new_tunnel_hook_point: Option<ProcessChainConfigs>,
        env: Arc<RtcpStackContext>,
        io_dump: Option<IoDumpStackConfig>,
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
        let on_new_tunnel_executor =
            if let Some(on_new_tunnel_hook_point) = on_new_tunnel_hook_point {
                let (executor, _) = create_process_chain_executor(
                    &on_new_tunnel_hook_point,
                    env.global_process_chains.clone(),
                    env.global_collection_manager.clone(),
                    Some(get_external_commands(Arc::downgrade(&env.servers))),
                    env.js_externals.clone(),
                )
                .await
                .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
                Some(executor)
            } else {
                None
            };
        Ok(Self {
            env,
            executor,
            on_new_tunnel_executor,
            connection_manager: self.connection_manager.clone(),
            io_dump,
            stream_idle_timeout: self.stream_idle_timeout,
            connect_timeout: self.connect_timeout,
        })
    }

    async fn handle_new_tunnel(
        &self,
        endpoint: TunnelEndpoint,
        source_addr: SocketAddr,
        source_device_info: Option<crate::RTcpSourceDeviceInfo>,
    ) -> StackResult<()> {
        let Some(executor) = self.on_new_tunnel_executor.as_ref() else {
            return Ok(());
        };

        let executor = executor.fork();
        let map = MemoryMapCollection::new_ref();
        map.insert("protocol", CollectionValue::String("rtcp".to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_addr",
            CollectionValue::String(source_addr.to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        insert_req_source_addr_group(&map, "conn_source_", source_addr).await?;
        map.insert(
            "source_device_id",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        // The RTCP handshake authenticated this DID; expose it as the trusted
        // origin identity plus the current effective identity alias.
        map.insert(
            "real_source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        if let Some(source_device_info) = source_device_info {
            if let Some(device_name) = source_device_info.name {
                map.insert("source_device_name", CollectionValue::String(device_name))
                    .await
                    .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            if let Some(device_owner) = source_device_info.owner {
                map.insert("source_device_owner", CollectionValue::String(device_owner))
                    .await
                    .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            if let Some(zone_did) = source_device_info.zone_did {
                map.insert("source_zone_did", CollectionValue::String(zone_did))
                    .await
                    .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            if let Some(device_doc_jwt) = source_device_info.device_doc_jwt {
                map.insert(
                    "source_device_doc_jwt",
                    CollectionValue::String(device_doc_jwt),
                )
                .await
                .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
        }

        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() && (ret.is_drop() || ret.is_reject()) {
            return Err(stack_err!(
                StackErrorCode::PermissionDenied,
                "rtcp tunnel rejected by process_chain, source_device_id={}, source_addr={}",
                endpoint.device_id,
                source_addr
            ));
        }

        Ok(())
    }

    async fn handle_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        protocol: String,
        dest_host: Option<String>,
        dest_port: u16,
        path: String,
        endpoint: TunnelEndpoint,
        stat: MutComposedSpeedStatRef,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let (stream, proxy_source_addr) = probe_proxy_protocol_stream(stream).await?;
        let request_source_addr = proxy_source_addr.unwrap_or(remote_addr);
        let device_lookup_ip = request_source_addr.ip();
        let device_info = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(device_lookup_ip));
        let remote_addr_str = remote_addr.to_string();
        let request_source_addr_str = request_source_addr.to_string();
        let dest_host = dest_host.unwrap_or_default();
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "source_device_id",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        // The RTCP handshake authenticated this DID; expose it as the trusted
        // origin identity plus the current effective identity alias.
        map.insert(
            "real_source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_addr",
            CollectionValue::String(request_source_addr_str.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_ip",
            CollectionValue::String(request_source_addr.ip().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_port",
            CollectionValue::String(request_source_addr.port().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        insert_req_source_addr_group(&map, "conn_source_", remote_addr).await?;
        if let Some(proxy_source_addr) = proxy_source_addr {
            insert_req_source_addr_group(&map, "real_source_", proxy_source_addr).await?;
        }
        map.insert("dest_addr", CollectionValue::String(local_addr.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "dest_ip",
            CollectionValue::String(local_addr.ip().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_port", CollectionValue::String(dest_port.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("protocol", CollectionValue::String(protocol))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("path", CollectionValue::String(path))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        if let Some(device_info) = device_info.as_ref() {
            if let Some(mac) = device_info.mac() {
                map.insert("source_mac", CollectionValue::String(mac.to_string()))
                    .await
                    .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            if let Some(host_name) = device_info.hostname() {
                map.insert(
                    "source_hostname",
                    CollectionValue::String(host_name.to_string()),
                )
                .await
                .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            map.insert(
                "source_online_secs",
                CollectionValue::String(device_info.today_online_seconds().to_string()),
            )
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        }
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let conn_src_addr = Some(remote_addr_str.clone());
        let mut real_src_addr = get_source_addr_from_req_env(&global_env)
            .await
            .and_then(|addr| addr.parse::<SocketAddr>().ok().map(|_| addr));
        if real_src_addr.is_none() {
            real_src_addr = proxy_source_addr.map(|addr| addr.to_string());
        }
        let stream_info = StreamInfo::with_addrs(conn_src_addr, real_src_addr)
            .with_dst_addr(Some(local_addr.to_string()))
            .with_device_info(
                device_info
                    .as_ref()
                    .and_then(|v| v.mac().map(|m| m.to_string())),
                device_info
                    .as_ref()
                    .and_then(|v| v.hostname().map(|h| h.to_string())),
                device_info
                    .as_ref()
                    .map(|v| v.today_online_seconds().to_string()),
            );
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
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
                    stat.set_external_stats(speed_groups);

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

    async fn handle_datagram(
        &self,
        datagram: Box<dyn AsyncStream>,
        protocol: String,
        dest_host: Option<String>,
        dest_port: u16,
        path: String,
        endpoint: TunnelEndpoint,
        stat: MutComposedSpeedStatRef,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let remote_ip = remote_addr.ip();
        let device_info = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(remote_ip));
        let dest_host = dest_host.unwrap_or_default();
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "source_device_id",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        // The RTCP handshake authenticated this DID; expose it as the trusted
        // origin identity plus the current effective identity alias.
        map.insert(
            "real_source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_did",
            CollectionValue::String(endpoint.device_id.clone()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_addr",
            CollectionValue::String(remote_addr.to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_ip",
            CollectionValue::String(remote_addr.ip().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_port",
            CollectionValue::String(remote_addr.port().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        insert_req_source_addr_group(&map, "conn_source_", remote_addr).await?;
        map.insert("dest_addr", CollectionValue::String(local_addr.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "dest_ip",
            CollectionValue::String(local_addr.ip().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_port", CollectionValue::String(dest_port.to_string()))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("dest_host", CollectionValue::String(dest_host))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("protocol", CollectionValue::String(protocol))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        map.insert("path", CollectionValue::String(path))
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        if let Some(device_info) = device_info.as_ref() {
            if let Some(mac) = device_info.mac() {
                map.insert("source_mac", CollectionValue::String(mac.to_string()))
                    .await
                    .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            if let Some(host_name) = device_info.hostname() {
                map.insert(
                    "source_hostname",
                    CollectionValue::String(host_name.to_string()),
                )
                .await
                .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
            }
            map.insert(
                "source_online_secs",
                CollectionValue::String(device_info.today_online_seconds().to_string()),
            )
            .await
            .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        }
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
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
                    stat.set_external_stats(speed_groups);

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
                                    LimitStream::new(datagram, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                datagram
                            };
                            let datagram_stream = Box::new(RTcpTunnelDatagramClient::new(stream));
                            datagram_forward(
                                datagram_stream,
                                target,
                                &self.env.tunnel_manager,
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
                                    LimitStream::new(datagram, read_limit, write_limit);
                                Box::new(limit_stream)
                            } else {
                                datagram
                            };
                            let datagram_stream = Box::new(RTcpTunnelDatagramClient::new(stream));
                            datagram_forward_group(
                                datagram_stream,
                                &plan,
                                &self.env.tunnel_manager,
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
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Datagram(server) => {
                                        let stream = if limiter.is_some() {
                                            let (read_limit, write_limit) =
                                                limiter.as_ref().unwrap().new_limit_session();
                                            let limit_stream =
                                                LimitStream::new(datagram, read_limit, write_limit);
                                            Box::new(limit_stream)
                                        } else {
                                            datagram
                                        };
                                        let datagram_stream = AsyncStreamWithDatagram::new(stream);
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            let len = datagram_stream
                                                .recv_datagram(&mut buf)
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "recv datagram error"
                                                ))?;
                                            let resp = server
                                                .serve_datagram(
                                                    &buf[..len],
                                                    DatagramInfo::new(Some(
                                                        remote_addr.to_string(),
                                                    ))
                                                    .with_dst_addr(Some(local_addr.to_string()))
                                                    .with_device_info(
                                                        device_info.as_ref().and_then(|v| {
                                                            v.mac().map(|m| m.to_string())
                                                        }),
                                                        device_info.as_ref().and_then(|v| {
                                                            v.hostname().map(|h| h.to_string())
                                                        }),
                                                        device_info.as_ref().map(|v| {
                                                            v.today_online_seconds().to_string()
                                                        }),
                                                    ),
                                                )
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::ServerError,
                                                    "serve datagram error"
                                                ))?;
                                            datagram_stream
                                                .send_datagram(resp.as_slice())
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "send datagram error"
                                                ))?;
                                        }
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

struct Listener {
    bind_addr: String,
    server_runtime: ServerRuntime,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
}

impl Listener {
    pub fn new(
        bind_addr: String,
        server_runtime: ServerRuntime,
        connection_manager: Option<ConnectionManagerRef>,
        handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
    ) -> Self {
        Self {
            bind_addr,
            server_runtime,
            connection_manager,
            handler,
        }
    }
}

struct TaskHandleConnectionController {
    handle: Mutex<Option<TaskHandle>>,
    completed: Arc<AtomicBool>,
    completion_notify: Arc<Notify>,
}

impl TaskHandleConnectionController {
    fn new(
        handle: TaskHandle,
        completed: Arc<AtomicBool>,
        completion_notify: Arc<Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            handle: Mutex::new(Some(handle)),
            completed,
            completion_notify,
        })
    }

    fn mark_completed(&self) {
        self.completed.store(true, Ordering::Release);
        self.completion_notify.notify_waiters();
    }
}

#[async_trait::async_trait]
impl ConnectionController for TaskHandleConnectionController {
    fn stop_connection(&self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.cancel();
        }
        self.mark_completed();
    }

    async fn wait_stop(&self) {
        loop {
            let notified = self.completion_notify.notified();
            if self.completed.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn is_stopped(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

struct TaskStopGuard {
    completed: Arc<AtomicBool>,
    completion_notify: Arc<Notify>,
}

impl Drop for TaskStopGuard {
    fn drop(&mut self) {
        self.completed.store(true, Ordering::Release);
        self.completion_notify.notify_waiters();
    }
}

#[async_trait::async_trait]
impl RTcpListener for Listener {
    async fn on_new_tunnel(
        &self,
        endpoint: TunnelEndpoint,
        source_addr: SocketAddr,
        source_device_info: Option<crate::RTcpSourceDeviceInfo>,
    ) -> TunnelResult<()> {
        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let handle = self
            .server_runtime
            .spawn_task(move || async move {
                let result = handler_snapshot
                    .handle_new_tunnel(endpoint, source_addr, source_device_info)
                    .await
                    .map_err(|e| {
                        TunnelError::ReasonError(format!("rtcp on_new_tunnel rejected: {}", e))
                    });
                let _ = result_tx.send(result);
            })
            .map_err(|e| {
                TunnelError::ReasonError(format!("spawn rtcp on_new_tunnel handler failed: {}", e))
            })?;
        drop(handle);
        result_rx.await.map_err(|e| {
            TunnelError::ReasonError(format!("rtcp on_new_tunnel handler dropped: {}", e))
        })?
    }

    async fn on_new_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        dest_host: Option<String>,
        dest_port: u16,
        endpoint: TunnelEndpoint,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> TunnelResult<()> {
        let (protocol, dest_host, dest_port, path) = if dest_port == 0 {
            if dest_host.is_none() {
                let msg = format!("dest_host and dest_port can not be empty {:?}", endpoint);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            }
            let dest_host = dest_host.unwrap();
            if !has_scheme(dest_host.as_str()) {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            };
            let url = Url::parse(dest_host.as_str()).map_err(|e| {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                TunnelError::UrlParseError(dest_host.clone(), format!("{}", e))
            })?;
            if url.port().is_none() {
                return Err(TunnelError::UrlParseError(
                    dest_host,
                    "The port must be include".to_string(),
                ));
            }
            let scheme = url.scheme();
            let dest_host = url.host_str().map(|s| s.to_string());
            let dest_port = url.port().unwrap();
            let path = url.path();
            let path = if path == "/" {
                String::from("")
            } else {
                path.to_string()
            };
            (scheme.to_string(), dest_host, dest_port, path)
        } else {
            ("tcp".to_string(), dest_host, dest_port, "".to_string())
        };

        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        let remote_addr_str = remote_addr.to_string();
        let local_addr_str = local_addr.to_string();
        let stream: Box<dyn AsyncStream> = if let Some(io_dump) = handler_snapshot.io_dump.clone() {
            Box::new(DumpStream::new(
                stream,
                io_dump,
                remote_addr_str.clone(),
                local_addr_str.clone(),
            ))
        } else {
            stream
        };
        let stat = MutComposedSpeedStat::new();
        let stat_stream = Box::new(StatStream::new_with_tracker(stream, stat.clone()));

        let speed = stat_stream.get_speed_stat();
        let completed = Arc::new(AtomicBool::new(false));
        let completion_notify = Arc::new(Notify::new());
        let task_completed = completed.clone();
        let task_completion_notify = completion_notify.clone();
        let handle = self
            .server_runtime
            .spawn_task(move || async move {
                let _stop_guard = TaskStopGuard {
                    completed: task_completed,
                    completion_notify: task_completion_notify,
                };
                if let Err(e) = handler_snapshot
                    .handle_stream(
                        stat_stream,
                        protocol,
                        dest_host,
                        dest_port,
                        path,
                        endpoint,
                        stat,
                        remote_addr,
                        local_addr,
                    )
                    .await
                {
                    error!("on_new_stream error: {}", e);
                }
            })
            .map_err(|e| {
                TunnelError::ReasonError(format!("spawn rtcp stream handler failed: {}", e))
            })?;
        if let Some(manager) = &self.connection_manager {
            let controller =
                TaskHandleConnectionController::new(handle, completed, completion_notify);
            manager.add_connection(ConnectionInfo::new(
                remote_addr.to_string(),
                local_addr.to_string(),
                StackProtocol::Rtcp,
                speed,
                controller,
            ))
        }
        Ok(())
    }

    async fn on_new_datagram(
        &self,
        stream: Box<dyn AsyncStream>,
        dest_host: Option<String>,
        dest_port: u16,
        endpoint: TunnelEndpoint,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> TunnelResult<()> {
        let (protocol, dest_host, dest_port, path) = if dest_port == 0 {
            if dest_host.is_none() {
                let msg = format!("dest_host and dest_port can not be empty {:?}", endpoint);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            }
            let dest_host = dest_host.unwrap();
            if !has_scheme(dest_host.as_str()) {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                return Err(TunnelError::ReasonError(msg));
            };
            let url = Url::parse(dest_host.as_str()).map_err(|e| {
                let msg = format!("invalid url {}", dest_host);
                log::error!("{}", msg);
                TunnelError::UrlParseError(dest_host.clone(), format!("{}", e))
            })?;
            if url.port().is_none() {
                return Err(TunnelError::UrlParseError(
                    dest_host,
                    "The port must be include".to_string(),
                ));
            }
            let scheme = url.scheme();
            let dest_host = url.host_str().map(|s| s.to_string());
            let dest_port = url.port().unwrap();
            let path = url.path();
            let path = if path == "/" {
                String::from("")
            } else {
                path.to_string()
            };
            (scheme.to_string(), dest_host, dest_port, path)
        } else {
            ("udp".to_string(), dest_host, dest_port, "".to_string())
        };

        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        let remote_addr_str = remote_addr.to_string();
        let local_addr_str = local_addr.to_string();
        let stream: Box<dyn AsyncStream> = if let Some(io_dump) = handler_snapshot.io_dump.clone() {
            Box::new(DumpStream::new(
                stream,
                io_dump,
                remote_addr_str.clone(),
                local_addr_str.clone(),
            ))
        } else {
            stream
        };
        let stat = MutComposedSpeedStat::new();
        let stat_stream = Box::new(StatStream::new_with_tracker(stream, stat.clone()));

        let speed = stat_stream.get_speed_stat();
        let completed = Arc::new(AtomicBool::new(false));
        let completion_notify = Arc::new(Notify::new());
        let task_completed = completed.clone();
        let task_completion_notify = completion_notify.clone();
        let handle = self
            .server_runtime
            .spawn_task(move || async move {
                let _stop_guard = TaskStopGuard {
                    completed: task_completed,
                    completion_notify: task_completion_notify,
                };
                if let Err(e) = handler_snapshot
                    .handle_datagram(
                        stat_stream,
                        protocol,
                        dest_host,
                        dest_port,
                        path,
                        endpoint,
                        stat,
                        remote_addr,
                        local_addr,
                    )
                    .await
                {
                    error!("on_new_stream error: {}", e);
                }
            })
            .map_err(|e| {
                TunnelError::ReasonError(format!("spawn rtcp datagram handler failed: {}", e))
            })?;

        if let Some(manager) = &self.connection_manager {
            let controller =
                TaskHandleConnectionController::new(handle, completed, completion_notify);
            manager.add_connection(ConnectionInfo::new(
                remote_addr.to_string(),
                local_addr.to_string(),
                StackProtocol::Rtcp,
                speed,
                controller,
            ))
        }
        Ok(())
    }
}

struct RtcpTunnelBuilder {
    rtcp: Arc<RTcp>,
    prober: Arc<RtcpUrlProber>,
}

impl RtcpTunnelBuilder {
    pub fn new(rtcp: Arc<RTcp>) -> Self {
        let prober = Arc::new(RtcpUrlProber { rtcp: rtcp.clone() });
        RtcpTunnelBuilder { rtcp, prober }
    }
}

#[async_trait::async_trait]
impl TunnelBuilder for RtcpTunnelBuilder {
    async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
    ) -> TunnelResult<Box<dyn TunnelBox>> {
        self.rtcp.create_tunnel(tunnel_stack_id).await
    }

    fn url_prober(&self) -> Option<TunnelUrlProberRef> {
        Some(self.prober.clone())
    }
}

struct RtcpUrlProber {
    rtcp: Arc<RTcp>,
}

#[async_trait::async_trait]
impl TunnelUrlProber for RtcpUrlProber {
    async fn probe_url(
        &self,
        url: &Url,
        options: &TunnelProbeOptions,
    ) -> TunnelResult<TunnelUrlStatus> {
        self.rtcp.probe_url(url, options).await
    }
}

pub struct RtcpStack {
    id: String,
    bind_addr: String,
    device_id: String,
    device_public_key: String,
    keep_tunnel: Vec<String>,
    reuse_address: bool,
    server_runtime: ServerRuntime,
    server: Mutex<Option<TcpServer>>,
    keep_tunnel_handles: Mutex<Vec<TaskHandle>>,
    rtcp: Mutex<Option<RTcp>>,
    rtcp_ref: Mutex<Option<Arc<RTcp>>>,
    connection_manager: Option<ConnectionManagerRef>,
    tunnel_manager: TunnelManager,
    handler: Arc<RwLock<Arc<RtcpConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<RtcpConnectionHandler>>>>,
}

impl Drop for RtcpStack {
    fn drop(&mut self) {
        for handle in self.keep_tunnel_handles.lock().unwrap().drain(..) {
            handle.cancel();
        }
        if let Some(server) = self.server.lock().unwrap().take() {
            if let Err(e) = server.close() {
                log::error!("close rtcp server failed: {}", e);
            }
        }
        self.tunnel_manager.remove_tunnel_builder("rtcp");
        self.tunnel_manager.remove_tunnel_builder("rudp");
    }
}

fn load_device_config_from_path(
    content: &str,
    path: &str,
    public_key: &str,
    expected_did: Option<&DID>,
) -> StackResult<(DeviceConfig, Option<String>)> {
    if let Ok(device_config) = serde_json::from_str::<DeviceConfig>(content) {
        validate_device_config_identity(&device_config, path, public_key, expected_did)?;
        return Ok((device_config, None));
    }

    let jwt = content.trim();
    let device_config = DeviceConfig::decode(&EncodedDocument::Jwt(jwt.to_string()), None)
        .map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "parse device config jwt {} failed",
            path
        ))?;
    validate_device_config_identity(&device_config, path, public_key, expected_did)?;
    Ok((device_config, Some(jwt.to_string())))
}

fn validate_device_config_identity(
    device_config: &DeviceConfig,
    source: &str,
    public_key: &str,
    expected_did: Option<&DID>,
) -> StackResult<()> {
    let auth_key = device_config
        .get_key_by_scope("authentication")
        .map(|(_, _, jwk)| jwk)
        .or_else(|| device_config.get_default_key())
        .ok_or(stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} has no authentication key",
            source
        ))?;
    let x_of_auth_key = get_x_from_jwk(&auth_key).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "device config {} has no auth key",
        source
    ))?;
    if x_of_auth_key != public_key {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} public key not match",
            source
        ));
    }

    if let Some(expected_did) = expected_did
        && &device_config.id != expected_did
    {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} id {} does not match configured identity {}",
            source,
            device_config.id.to_string(),
            expected_did.to_string()
        ));
    }

    Ok(())
}

struct RtcpIdentityMaterial {
    device_config: DeviceConfig,
    device_doc_jwt: Option<String>,
    private_key: [u8; 48],
    public_key: String,
}

fn normalize_device_doc_jwt(value: &str) -> StackResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "device_doc_jwt is empty"
        ));
    }
    Ok(value.to_string())
}

// buckyos 节点(node_daemon/make_config)落盘的设备文档 JWT 文件名;
// name-client IdentityRoots 的约定名是 device.jwt,两者都要探测。
const BUCKYOS_DEVICE_DOC_JWT_FILE_NAME: &str = "device_doc.jwt";

// 逻辑名(非 did:dev)的 rtcp stack 必须持有 owner 签名的 device doc jwt
// 才能向对端证明身份,但 boot_gateway.yaml 等 legacy 配置的
// device_config_path 指向的是未签名的 did.json。buckyos 的身份布局把
// owner 签名的 device_doc.jwt 写在同一目录,这里按约定探测并采用它,
// 避免要求所有存量配置改写。探测失败只告警不报错:did:dev 栈不需要
// jwt,逻辑名栈随后会被 require_device_doc_jwt_for_logical_did 拦下。
fn probe_sibling_device_doc_jwt(
    device_config_path: &Path,
    public_key: &str,
    expected_did: &DID,
) -> Option<(DeviceConfig, String)> {
    let dir = device_config_path.parent()?;
    for file_name in [BUCKYOS_DEVICE_DOC_JWT_FILE_NAME, "device.jwt"] {
        let candidate = dir.join(file_name);
        if !candidate.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(candidate.as_path()) {
            Ok(content) => content,
            Err(e) => {
                warn!(
                    "read sibling device doc jwt {} failed: {}",
                    candidate.display(),
                    e
                );
                continue;
            }
        };
        match load_device_config_from_path(
            content.as_str(),
            candidate.to_string_lossy().as_ref(),
            public_key,
            Some(expected_did),
        ) {
            Ok((device_config, Some(jwt))) => {
                info!(
                    "loaded device doc jwt for {} from {}",
                    expected_did.to_string(),
                    candidate.display()
                );
                return Some((device_config, jwt));
            }
            Ok((_, None)) => {
                warn!(
                    "sibling device doc {} is not a jwt, ignored",
                    candidate.display()
                );
            }
            Err(e) => {
                warn!(
                    "sibling device doc jwt {} rejected: {}",
                    candidate.display(),
                    e
                );
            }
        }
    }
    None
}

fn require_device_doc_jwt_for_logical_did(
    device_config: &DeviceConfig,
    device_doc_jwt: Option<&String>,
) -> StackResult<()> {
    if device_config.id.method == "dev" {
        return Ok(());
    }

    if device_doc_jwt
        .map(|jwt| !jwt.trim().is_empty())
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err(stack_err!(
        StackErrorCode::InvalidConfig,
        "rtcp stack did {} is not did:dev; device_doc_jwt is required",
        device_config.id.to_string()
    ))
}

fn apply_explicit_device_doc_jwt(
    mut material: RtcpIdentityMaterial,
    device_doc_jwt: Option<&str>,
) -> StackResult<RtcpIdentityMaterial> {
    if let Some(device_doc_jwt) = device_doc_jwt {
        let device_doc_jwt = normalize_device_doc_jwt(device_doc_jwt)?;
        let (device_config, loaded_device_doc_jwt) = load_device_config_from_path(
            device_doc_jwt.as_str(),
            "device_doc_jwt",
            &material.public_key,
            Some(&material.device_config.id),
        )?;
        material.device_config = device_config;
        material.device_doc_jwt = loaded_device_doc_jwt;
    }

    require_device_doc_jwt_for_logical_did(
        &material.device_config,
        material.device_doc_jwt.as_ref(),
    )?;
    Ok(material)
}

fn build_rtcp_identity_roots(
    identity_manager: Option<&RtcpIdentityManagerConfig>,
) -> StackResult<IdentityRoots> {
    let mut roots = IdentityRoots::from_env_or_buckyos_root().map_err(|e| {
        stack_err!(
            StackErrorCode::InvalidConfig,
            "load identity manager roots failed: {}",
            e
        )
    })?;
    if let Some(identity_manager) = identity_manager {
        if let Some(public_root_path) = identity_manager.public_root_path.as_ref() {
            roots.public_root = PathBuf::from(public_root_path);
        }
        if let Some(security_root_path) = identity_manager.security_root_path.as_ref() {
            roots.security_root = PathBuf::from(security_root_path);
        }
    }
    Ok(roots)
}

fn require_rtcp_hostname_form_did(did: &DID, context: &str) -> StackResult<()> {
    if let Err(e) = validate_rtcp_hostname_form_did(did, context) {
        return Err(stack_err!(StackErrorCode::InvalidConfig, "{}", e));
    }
    Ok(())
}

fn require_rtcp_identity_material_hostname_form(
    material: RtcpIdentityMaterial,
) -> StackResult<RtcpIdentityMaterial> {
    require_rtcp_hostname_form_did(&material.device_config.id, "rtcp identity")?;
    Ok(material)
}

fn has_legacy_rtcp_identity_config(config: &RtcpStackConfig) -> bool {
    config.key_path.is_some() || config.device_config_path.is_some() || config.name.is_some()
}

async fn load_rtcp_identity_material(
    config: &RtcpStackConfig,
) -> StackResult<RtcpIdentityMaterial> {
    if let Some(identity) = config.identity.as_deref() {
        if has_legacy_rtcp_identity_config(config) {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "rtcp identity cannot be mixed with key_path/device_config_path/name"
            ));
        }
        return load_rtcp_identity_from_manager(
            identity,
            config.identity_manager.as_ref(),
            config.device_doc_jwt.as_deref(),
        )
        .await;
    }

    if config.identity_manager.is_some() {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "rtcp identity is required when identity_manager is configured"
        ));
    }

    load_legacy_rtcp_identity_material(config).await
}

async fn load_legacy_rtcp_identity_material(
    config: &RtcpStackConfig,
) -> StackResult<RtcpIdentityMaterial> {
    let key_path = config.key_path.as_deref().ok_or(stack_err!(
        StackErrorCode::InvalidConfig,
        "key_path is required"
    ))?;
    let private_key = load_raw_private_key(Path::new(key_path)).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "load private key {} failed",
        key_path
    ))?;
    let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);
    let (device_config, device_doc_jwt) = if let Some(path) = config.device_config_path.as_ref() {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(into_stack_err!(
                StackErrorCode::InvalidConfig,
                "load device config {} failed",
                path
            ))?;
        let (device_config, device_doc_jwt) =
            load_device_config_from_path(content.as_str(), path, &public_key, None)?;
        // 只在逻辑名(必须有 jwt 才能启动)时探测:did:dev 的 hello 不带
        // doc_jwt 时对端零解析成本即可验证,不要平白增加 owner 解析负担。
        if device_doc_jwt.is_none()
            && config.device_doc_jwt.is_none()
            && device_config.id.method != "dev"
        {
            match probe_sibling_device_doc_jwt(Path::new(path), &public_key, &device_config.id) {
                Some((device_config, jwt)) => (device_config, Some(jwt)),
                None => (device_config, None),
            }
        } else {
            (device_config, device_doc_jwt)
        }
    } else if let Some(device_doc_jwt) = config.device_doc_jwt.as_deref() {
        let device_doc_jwt = normalize_device_doc_jwt(device_doc_jwt)?;
        load_device_config_from_path(device_doc_jwt.as_str(), "device_doc_jwt", &public_key, None)?
    } else {
        if config.name.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "name is required"
            ));
        }
        (
            DeviceConfig::new(config.name.as_ref().unwrap().as_str(), public_key.clone()),
            None,
        )
    };

    let material = RtcpIdentityMaterial {
        device_config,
        device_doc_jwt,
        private_key,
        public_key,
    };

    let material = apply_explicit_device_doc_jwt(material, config.device_doc_jwt.as_deref())?;
    require_rtcp_identity_material_hostname_form(material)
}

async fn load_rtcp_identity_from_manager(
    identity: &str,
    identity_manager: Option<&RtcpIdentityManagerConfig>,
    device_doc_jwt: Option<&str>,
) -> StackResult<RtcpIdentityMaterial> {
    let identity = identity.trim();
    if identity.is_empty() {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "rtcp identity is empty"
        ));
    }
    let expected_did = DID::from_str(identity).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "invalid rtcp identity {}",
        identity
    ))?;
    require_rtcp_hostname_form_did(&expected_did, "rtcp identity")?;
    let roots = build_rtcp_identity_roots(identity_manager)?;
    let private_key_path = roots
        .security_file(
            identity,
            IdentityUsage::Authentication,
            IdentityMaterial::PrivateKey,
        )
        .map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "resolve rtcp identity private key failed"
        ))?;
    let private_key = load_raw_private_key(private_key_path.as_path()).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "load rtcp identity private key {} failed",
        private_key_path.display()
    ))?;
    let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

    if let Some(device_doc_jwt) = device_doc_jwt {
        let device_doc_jwt = normalize_device_doc_jwt(device_doc_jwt)?;
        let (device_config, device_doc_jwt) = load_device_config_from_path(
            device_doc_jwt.as_str(),
            "device_doc_jwt",
            &public_key,
            Some(&expected_did),
        )?;
        let material = RtcpIdentityMaterial {
            device_config,
            device_doc_jwt,
            private_key,
            public_key,
        };
        require_device_doc_jwt_for_logical_did(
            &material.device_config,
            material.device_doc_jwt.as_ref(),
        )?;
        return require_rtcp_identity_material_hostname_form(material);
    }

    let public_dir = roots
        .public_dir(identity)
        .map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "resolve rtcp identity public dir failed"
        ))?;
    // device.jwt is the legacy name-client convention. Newer identity roots
    // only model did.json directly, so retain the JWT filename explicitly.
    let device_doc_jwt_path = public_dir.join("device.jwt");
    // buckyos 落盘用的是 device_doc.jwt(见 buckyos-api device_identity),
    // 与 name-client 的 device.jwt 约定并存,两个名字都探测。
    let buckyos_device_doc_jwt_path = public_dir.join(BUCKYOS_DEVICE_DOC_JWT_FILE_NAME);
    let did_json_path = roots
        .public_file(
            identity,
            IdentityUsage::Authentication,
            IdentityMaterial::DidJson,
        )
        .map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "resolve rtcp identity did.json failed"
        ))?;

    let (document_path, prefer_jwt) = if device_doc_jwt_path.exists() {
        (device_doc_jwt_path, true)
    } else if buckyos_device_doc_jwt_path.exists() {
        (buckyos_device_doc_jwt_path, true)
    } else {
        (did_json_path, false)
    };
    let content = tokio::fs::read_to_string(&document_path)
        .await
        .map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "load rtcp identity document {} failed",
            document_path.display()
        ))?;
    let (device_config, device_doc_jwt) = load_device_config_from_path(
        content.as_str(),
        document_path.to_string_lossy().as_ref(),
        &public_key,
        Some(&expected_did),
    )?;

    if prefer_jwt && device_doc_jwt.is_none() {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "rtcp identity {} must contain a device document jwt",
            document_path.display()
        ));
    }

    let material = RtcpIdentityMaterial {
        device_config,
        device_doc_jwt,
        private_key,
        public_key,
    };
    require_device_doc_jwt_for_logical_did(
        &material.device_config,
        material.device_doc_jwt.as_ref(),
    )?;
    require_rtcp_identity_material_hostname_form(material)
}

impl RtcpStack {
    pub fn builder() -> RtcpStackBuilder {
        RtcpStackBuilder::new()
    }

    fn start_keep_tunnels(&self) {
        for tunnel in self.keep_tunnel.iter().cloned() {
            self.start_keep_tunnel(tunnel);
        }
    }

    fn start_keep_tunnel(&self, tunnel: String) {
        let tunnel_url = format!("rtcp://{}", tunnel);
        info!("Will keep tunnel: {}", tunnel_url);
        let tunnel_url = match Url::parse(tunnel_url.as_str()) {
            Ok(url) => url,
            Err(err) => {
                warn!("Invalid tunnel url: {}", err);
                return;
            }
        };

        let tunnel_manager = self.tunnel_manager.clone();
        let handle = self.server_runtime.spawn_task(|| async move {
            // Pin the keep_tunnel URL so its URL history is never evicted
            // by LRU pressure -- it is a configured, long-lived URL.
            tunnel_manager.pin_tunnel_url(&tunnel_url).await;
            loop {
                let last_ok;
                let normalized = normalize_tunnel_url(&tunnel_url);
                let now = crate::tunnel_mgr::now_ms();
                match tunnel_manager.get_tunnel(&tunnel_url, None).await {
                    Err(err) => {
                        warn!("Error getting tunnel: {}", err);
                        let status = unreachable_status(
                            &tunnel_url,
                            &normalized,
                            now,
                            TunnelUrlStatusSource::KeepAlive,
                            format!("get_tunnel: {}", err),
                        );
                        tunnel_manager.record_status_observation(status).await;
                        last_ok = false;
                    }
                    Ok(tunnel) => match tunnel.ping().await {
                        Err(err) => {
                            warn!("Error pinging tunnel: {}", err);
                            let status = unreachable_status(
                                &tunnel_url,
                                &normalized,
                                now,
                                TunnelUrlStatusSource::KeepAlive,
                                format!("ping: {}", err),
                            );
                            tunnel_manager.record_status_observation(status).await;
                            last_ok = false;
                        }
                        Ok(_) => {
                            // The classic ping() does not measure RTT;
                            // record reachable without an RTT value. The
                            // prober's `force_probe` path can populate
                            // RTT explicitly when needed.
                            let status = reachable_status(
                                &tunnel_url,
                                &normalized,
                                now,
                                TunnelUrlStatusSource::KeepAlive,
                                None,
                            );
                            tunnel_manager.record_status_observation(status).await;
                            last_ok = true;
                        }
                    },
                }

                if last_ok {
                    tokio::time::sleep(std::time::Duration::from_secs(60 * 2)).await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
            }
        });
        match handle {
            Ok(handle) => self.keep_tunnel_handles.lock().unwrap().push(handle),
            Err(err) => warn!("start rtcp keep_tunnel task failed: {}", err),
        }
    }

    async fn create(mut builder: RtcpStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind_addr.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "bind is required"
            ));
        }
        if builder.device_config.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "device_config is required"
            ));
        }
        if builder.private_key.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "private_key is required"
            ));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "hook_point is required"
            ));
        }
        if builder.server_runtime.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "server_runtime is required"
            ));
        }

        let id = builder.id.take().unwrap();
        let bind_addr = builder.bind_addr.clone().unwrap();
        let keep_tunnel = sanitize_keep_tunnels(&builder.keep_tunnel);
        let device_config = builder.device_config.take().unwrap();
        let device_id = device_config.id.to_string();
        let private_key = builder.private_key.take().unwrap();
        let device_public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);
        let device_doc_jwt = builder
            .device_doc_jwt
            .take()
            .map(|jwt| normalize_device_doc_jwt(jwt.as_str()))
            .transpose()?;
        if let Some(device_doc_jwt) = device_doc_jwt.as_ref() {
            load_device_config_from_path(
                device_doc_jwt.as_str(),
                "device_doc_jwt",
                &device_public_key,
                Some(&device_config.id),
            )?;
        }
        require_device_doc_jwt_for_logical_did(&device_config, device_doc_jwt.as_ref())?;
        let connection_manager = builder.connection_manager.clone();
        let server_runtime = builder.server_runtime.take().unwrap();
        let stack_context = if let Some(stack_context) = builder.stack_context.take() {
            stack_context
        } else {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "stack_context is required"
            ));
        };
        let handler = RtcpConnectionHandler::create(
            builder.hook_point.unwrap(),
            builder.on_new_tunnel_hook_point.take(),
            stack_context.clone(),
            connection_manager.clone(),
            builder.io_dump,
            builder.stream_idle_timeout,
            builder.connect_timeout,
        )
        .await?;
        let handler = Arc::new(RwLock::new(Arc::new(handler)));
        let listener = Listener::new(
            bind_addr.clone(),
            server_runtime.clone(),
            connection_manager.clone(),
            handler.clone(),
        );
        let mut rtcp = RTcp::new(
            device_config.id.clone(),
            bind_addr.clone(),
            Some(private_key),
            device_doc_jwt,
            Arc::new(listener),
        );
        rtcp.set_reuse_address(builder.reuse_address);
        Ok(Self {
            id,
            bind_addr,
            device_id,
            device_public_key,
            keep_tunnel,
            reuse_address: builder.reuse_address,
            server_runtime,
            server: Mutex::new(None),
            keep_tunnel_handles: Mutex::new(Vec::new()),
            rtcp: Mutex::new(Some(rtcp)),
            rtcp_ref: Mutex::new(None),
            connection_manager,
            tunnel_manager: stack_context.tunnel_manager.clone(),
            handler,
            prepare_handler: Arc::new(Default::default()),
        })
    }

    async fn start_listener(&self, rtcp: Arc<RTcp>) -> StackResult<TcpServer> {
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
        let service_config = TcpServiceConfig::new(addr).with_socket_options(socket_options);
        let server = TcpServer::serve(&self.server_runtime, service_config, move |stream| {
            let rtcp = rtcp.clone();
            async move {
                let peer_addr = stream.peer_addr().map_err(|e| {
                    log::error!("read rtcp peer addr failed: {}", e);
                    e
                })?;
                log::debug!("RTcp stack accept new tcp stream from {}", peer_addr);
                rtcp.serve_connection(stream, peer_addr).await;
                Ok(())
            }
        })
        .map_err(|e| stack_err!(StackErrorCode::BindFailed, "start rtcp server error: {e}"))?;
        Ok(server)
    }
}

#[async_trait::async_trait]
impl Stack for RtcpStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
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
        let mut rtcp = { self.rtcp.lock().unwrap().take().unwrap() };
        // Provide the tunnel framework entry point so create_tunnel can build
        // bootstrap streams when the stack id carries a `params@remote` prefix.
        rtcp.set_tunnel_manager(self.tunnel_manager.clone());
        let rtcp = Arc::new(rtcp);
        let server = match self.start_listener(rtcp.clone()).await {
            Ok(server) => server,
            Err(e) => {
                if let Ok(rtcp) = Arc::try_unwrap(rtcp) {
                    *self.rtcp.lock().unwrap() = Some(rtcp);
                }
                return Err(e);
            }
        };
        let tunnel_builder = Arc::new(RtcpTunnelBuilder::new(rtcp.clone()));
        self.tunnel_manager
            .register_tunnel_builder("rtcp", tunnel_builder.clone());
        self.tunnel_manager
            .register_tunnel_builder("rudp", tunnel_builder);
        *self.server.lock().unwrap() = Some(server);
        *self.rtcp_ref.lock().unwrap() = Some(rtcp);
        self.start_keep_tunnels();
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
            .downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid rtcp stack config"
            ))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if config.reuse_address.unwrap_or(false) != self.reuse_address {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "reuse_address unmatch"
            ));
        }

        let identity_material = load_rtcp_identity_material(config).await?;
        if identity_material.device_config.id.to_string() != self.device_id {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "rtcp identity change requires stack restart"
            ));
        }
        if identity_material.public_key != self.device_public_key {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "rtcp private key change requires stack restart"
            ));
        }

        let env = match context {
            Some(context) => {
                let rtcp_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<RtcpStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid rtcp stack context"
                    ))?;
                Arc::new(rtcp_context.clone())
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
        let handler = RtcpConnectionHandler::create(
            config.hook_point.clone(),
            config.on_new_tunnel_hook_point.clone(),
            env,
            self.connection_manager.clone(),
            io_dump,
            stream_idle_timeout_from_secs(config.stream_idle_timeout),
            connect_timeout_from_secs(config.connect_timeout),
        )
        .await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(handler));
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

pub struct RtcpStackBuilder {
    id: Option<String>,
    bind_addr: Option<String>,
    keep_tunnel: Vec<String>,
    device_config: Option<DeviceConfig>,
    device_doc_jwt: Option<String>,
    private_key: Option<[u8; 48]>,
    hook_point: Option<ProcessChainConfigs>,
    on_new_tunnel_hook_point: Option<ProcessChainConfigs>,
    server_runtime: Option<ServerRuntime>,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<RtcpStackContext>>,
    io_dump: Option<IoDumpStackConfig>,
    reuse_address: bool,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl RtcpStackBuilder {
    fn new() -> Self {
        Self {
            id: None,
            bind_addr: None,
            keep_tunnel: vec![],
            device_config: None,
            device_doc_jwt: None,
            private_key: None,
            hook_point: None,
            on_new_tunnel_hook_point: None,
            server_runtime: None,
            connection_manager: None,
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

    pub fn bind(mut self, bind_addr: String) -> Self {
        self.bind_addr = Some(bind_addr);
        self
    }

    pub fn keep_tunnel(mut self, keep_tunnel: Vec<String>) -> Self {
        self.keep_tunnel = keep_tunnel;
        self
    }

    pub fn device_config(mut self, device_config: DeviceConfig) -> Self {
        self.device_config = Some(device_config);
        self
    }

    pub fn device_doc_jwt(mut self, device_doc_jwt: String) -> Self {
        self.device_doc_jwt = Some(device_doc_jwt);
        self
    }

    pub fn private_key(mut self, private_key: [u8; 48]) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn on_new_tunnel_hook_point(
        mut self,
        on_new_tunnel_hook_point: ProcessChainConfigs,
    ) -> Self {
        self.on_new_tunnel_hook_point = Some(on_new_tunnel_hook_point);
        self
    }

    pub fn server_runtime(mut self, server_runtime: ServerRuntime) -> Self {
        self.server_runtime = Some(server_runtime);
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<RtcpStackContext>) -> Self {
        self.stack_context = Some(stack_context);
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

    pub async fn build(self) -> StackResult<RtcpStack> {
        RtcpStack::create(self).await
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RtcpIdentityManagerConfig {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct RtcpStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: String,
    pub hook_point: Vec<crate::ProcessChainConfig>,
    #[serde(default, alias = "keep-tunnel", skip_serializing_if = "Vec::is_empty")]
    pub keep_tunnel: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_new_tunnel_hook_point: Option<Vec<crate::ProcessChainConfig>>,
    #[serde(
        default,
        alias = "did",
        alias = "device_did",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_manager: Option<RtcpIdentityManagerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_config_path: Option<String>,
    #[serde(
        default,
        alias = "device-doc-jwt",
        alias = "device_document_jwt",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_doc_jwt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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

impl crate::StackConfig for RtcpStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Rtcp
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct RtcpStackFactory {
    connection_manager: ConnectionManagerRef,
    server_runtime: ServerRuntime,
}

impl RtcpStackFactory {
    pub fn new(connection_manager: ConnectionManagerRef, server_runtime: ServerRuntime) -> Self {
        Self {
            connection_manager,
            server_runtime,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for RtcpStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<RtcpStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid rtcp stack config"
            ))?;

        let identity_material = load_rtcp_identity_material(config).await?;
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<RtcpStackContext>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid rtcp stack context"
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
        let stack = RtcpStack::builder()
            .id(config.id.clone())
            .bind(config.bind.clone())
            .keep_tunnel(config.keep_tunnel.clone())
            .server_runtime(self.server_runtime.clone())
            .connection_manager(self.connection_manager.clone())
            .device_config(identity_material.device_config)
            .private_key(identity_material.private_key)
            .hook_point(config.hook_point.clone());
        let stack = if let Some(on_new_tunnel_hook_point) = config.on_new_tunnel_hook_point.clone()
        {
            stack.on_new_tunnel_hook_point(on_new_tunnel_hook_point)
        } else {
            stack
        };
        let stack = if let Some(device_doc_jwt) = identity_material.device_doc_jwt {
            stack.device_doc_jwt(device_doc_jwt)
        } else {
            stack
        };
        let stack = stack
            .stack_context(stack_context.clone())
            .io_dump(io_dump)
            .stream_idle_timeout(stream_idle_timeout_from_secs(config.stream_idle_timeout))
            .connect_timeout(connect_timeout_from_secs(config.connect_timeout))
            .reuse_address(config.reuse_address.unwrap_or(false))
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

fn sanitize_keep_tunnels(keep_tunnels: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut dedup = HashSet::new();
    for keep_tunnel in keep_tunnels {
        let keep_tunnel = keep_tunnel.trim();
        if keep_tunnel.is_empty() {
            continue;
        }
        if dedup.insert(keep_tunnel.to_string()) {
            result.push(keep_tunnel.to_string());
        }
    }
    result
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RtcpConnectionHandler, RtcpIdentityManagerConfig, load_rtcp_identity_material,
        sanitize_keep_tunnels,
    };
    use crate::global_process_chains::GlobalProcessChains;
    use crate::{
        ConnectionManager, DatagramInfo, DefaultLimiterManager, GlobalCollectionManager,
        LimiterManagerRef, ProcessChainConfigs, RtcpStack, RtcpStackBuilder, RtcpStackConfig,
        RtcpStackContext, RtcpStackFactory, Server, ServerManager, ServerManagerRef, ServerResult,
        Stack, StackContext, StackFactory, StackProtocol, StatManager, StatManagerRef, StreamInfo,
        StreamServer, TunnelEndpoint, TunnelManager, create_io_dump_stack_config,
        connect_timeout_from_secs, decode_io_dump_frames, stream_idle_timeout_from_secs,
    };
    use buckyos_kit::AsyncStream;
    use jsonwebtoken::EncodingKey;
    use name_client::{
        IdentityMaterial, IdentityRoots, IdentityUsage, NameInfo, add_nameinfo_cache,
        init_name_lib_for_test, update_did_cache,
    };
    use name_lib::{
        DID, DIDDocumentTrait, DeviceConfig, EncodedDocument, encode_ed25519_sk_to_pk_jwk,
        generate_ed25519_key, generate_ed25519_key_pair,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use url::Url;

    fn test_server_runtime() -> sfo_reuseport::ServerRuntime {
        sfo_reuseport::ServerRuntime::start(
            sfo_reuseport::ServerRuntimeConfig::new().with_workers(1),
        )
        .unwrap()
    }

    fn rtcp_stack_builder() -> RtcpStackBuilder {
        RtcpStack::builder().server_runtime(test_server_runtime())
    }

    async fn wait_dump_frames(
        file: &std::path::Path,
        min_frames: usize,
    ) -> Vec<crate::DecodedIoDumpFrame> {
        for _ in 0..60 {
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
        global_process_chains: Option<Arc<GlobalProcessChains>>,
    ) -> Arc<RtcpStackContext> {
        Arc::new(RtcpStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            None,
            None,
        ))
    }

    fn build_rtcp_identity_config(
        id: &str,
        bind: &str,
        identity: &str,
        roots: &IdentityRoots,
    ) -> RtcpStackConfig {
        RtcpStackConfig {
            id: id.to_string(),
            protocol: StackProtocol::Rtcp,
            bind: bind.to_string(),
            hook_point: vec![],
            keep_tunnel: vec![],
            on_new_tunnel_hook_point: None,
            identity: Some(identity.to_string()),
            identity_manager: Some(RtcpIdentityManagerConfig {
                public_root_path: Some(roots.public_root.to_string_lossy().to_string()),
                security_root_path: Some(roots.security_root.to_string_lossy().to_string()),
            }),
            key_path: None,
            device_config_path: None,
            device_doc_jwt: None,
            name: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        }
    }

    fn write_rtcp_identity_files(
        roots: &IdentityRoots,
        identity: &str,
        private_key_pem: &str,
        did_json: Option<&DeviceConfig>,
        device_doc_jwt: Option<&str>,
    ) {
        let public_dir = roots.public_dir(identity).unwrap();
        let security_dir = roots.security_dir(identity).unwrap();
        std::fs::create_dir_all(&public_dir).unwrap();
        std::fs::create_dir_all(&security_dir).unwrap();
        let private_key_path = roots
            .security_file(
                identity,
                IdentityUsage::Authentication,
                IdentityMaterial::PrivateKey,
            )
            .unwrap();
        std::fs::write(private_key_path, private_key_pem).unwrap();
        if let Some(did_json) = did_json {
            let did_json_path = roots
                .public_file(
                    identity,
                    IdentityUsage::Authentication,
                    IdentityMaterial::DidJson,
                )
                .unwrap();
            std::fs::write(did_json_path, serde_json::to_string(did_json).unwrap()).unwrap();
        }
        if let Some(device_doc_jwt) = device_doc_jwt {
            let device_doc_jwt_path = public_dir.join("device.jwt");
            std::fs::write(device_doc_jwt_path, device_doc_jwt).unwrap();
        }
    }

    async fn build_factory_context() -> Arc<dyn StackContext> {
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        Arc::new(RtcpStackContext::new(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(collection_manager),
            None,
        ))
    }

    #[tokio::test]
    async fn test_rtcp_stack_creation() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test", serde_json::from_value(jwk).unwrap());

        let result = rtcp_stack_builder().build().await;
        assert!(result.is_err());
        let result = rtcp_stack_builder()
            .bind("127.0.0.1:2980".to_string())
            .build()
            .await;
        assert!(result.is_err());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .build()
            .await;
        assert!(result.is_err());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .build()
            .await;
        assert!(result.is_err());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());

        let tunnel_manager = TunnelManager::new();
        let result = RtcpStack::builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager.clone(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_err());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager.clone(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                None,
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager.clone(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2980".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .connection_manager(ConnectionManager::new())
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                tunnel_manager,
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rtcp_stack_builder_requires_device_doc_jwt_for_logical_did() {
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let mut device_config =
            DeviceConfig::new_by_jwk("logical-test", serde_json::from_value(jwk).unwrap());
        device_config.id = DID::new("web", "logical.example.com");

        let result = rtcp_stack_builder()
            .id("logical-test")
            .bind("127.0.0.1:0".to_string())
            .device_config(device_config)
            .private_key(pkcs8_bytes)
            .hook_point(vec![])
            .stack_context(build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ))
            .build()
            .await;

        let err = result.as_ref().err().unwrap().to_string();
        assert!(err.contains("device_doc_jwt"), "unexpected error: {}", err);
    }

    #[tokio::test]
    async fn test_rtcp_on_new_tunnel_hook_point_rejects_source_device() {
        let on_new_tunnel_hook_point = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        eq ${REQ.source_device_id} "blocked-device" && reject;
        "#;
        let on_new_tunnel_hook_point: ProcessChainConfigs =
            serde_yaml_ng::from_str(on_new_tunnel_hook_point).unwrap();

        let handler = RtcpConnectionHandler::create(
            vec![],
            Some(on_new_tunnel_hook_point),
            build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ),
            None,
            None,
            stream_idle_timeout_from_secs(None),
            connect_timeout_from_secs(None),
        )
        .await
        .unwrap();

        let rejected = handler
            .handle_new_tunnel(
                TunnelEndpoint {
                    device_id: "blocked-device".to_string(),
                    port: 2981,
                },
                "127.0.0.1:41000".parse().unwrap(),
                None,
            )
            .await;
        assert!(rejected.is_err());

        let accepted = handler
            .handle_new_tunnel(
                TunnelEndpoint {
                    device_id: "allowed-device".to_string(),
                    port: 2981,
                },
                "127.0.0.1:41001".parse().unwrap(),
                None,
            )
            .await;
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn test_rtcp_on_new_tunnel_exposes_authenticated_did_and_conn_source() {
        // The handshake-authenticated DID must be visible as the trusted
        // real_source_did, with source_did as the effective-identity alias,
        // alongside the connection-layer source group.
        let on_new_tunnel_hook_point = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        !eq ${REQ.real_source_did} "did:dev:blocked" && !eq ${REQ.conn_source_ip} "10.9.9.9" && return "ok";
        eq ${REQ.source_did} ${REQ.real_source_did} && eq ${REQ.source_device_id} ${REQ.real_source_did} && reject;
        "#;
        let on_new_tunnel_hook_point: ProcessChainConfigs =
            serde_yaml_ng::from_str(on_new_tunnel_hook_point).unwrap();

        let handler = RtcpConnectionHandler::create(
            vec![],
            Some(on_new_tunnel_hook_point),
            build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ),
            None,
            None,
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        // Matching DID: the second line proves source_did/source_device_id
        // alias the authenticated DID (reject only fires when all eq hold).
        let rejected = handler
            .handle_new_tunnel(
                TunnelEndpoint {
                    device_id: "did:dev:blocked".to_string(),
                    port: 2981,
                },
                "127.0.0.1:41002".parse().unwrap(),
                None,
            )
            .await;
        assert!(rejected.is_err());

        // Same chain keyed on conn_source_ip: proves the connection-layer
        // source group is populated.
        let rejected = handler
            .handle_new_tunnel(
                TunnelEndpoint {
                    device_id: "did:dev:other".to_string(),
                    port: 2981,
                },
                "10.9.9.9:41003".parse().unwrap(),
                None,
            )
            .await;
        assert!(rejected.is_err());

        let accepted = handler
            .handle_new_tunnel(
                TunnelEndpoint {
                    device_id: "did:dev:other".to_string(),
                    port: 2981,
                },
                "127.0.0.1:41004".parse().unwrap(),
                None,
            )
            .await;
        assert!(accepted.is_ok());
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stream_source_vars_with_proxy_protocol() {
        // Streams over an authenticated RTCP tunnel expose:
        // - real_source_did / source_did: the handshake-authenticated DID
        // - conn_source_*: the tunnel peer socket address
        // - real_source_* / source_*: the PROXY-protocol-restored origin
        // The chain only forwards to the listener when all of them match, so
        // a successful accept proves the whole set.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();

        let chains = format!(
            r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        eq ${{REQ.real_source_did}} "did:dev:peer" && eq ${{REQ.source_did}} "did:dev:peer" && eq ${{REQ.real_source_ip}} "203.0.113.9" && eq ${{REQ.real_source_port}} "5678" && eq ${{REQ.conn_source_ip}} "127.0.0.1" && eq ${{REQ.conn_source_port}} "52000" && eq ${{REQ.source_ip}} "203.0.113.9" && forward tcp:///127.0.0.1:{echo_port};
        drop;
"#
        );
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(&chains).unwrap();

        let handler = RtcpConnectionHandler::create(
            chains,
            None,
            build_stack_context(
                Arc::new(ServerManager::new()),
                TunnelManager::new(),
                Arc::new(DefaultLimiterManager::new()),
                StatManager::new(),
                Some(Arc::new(GlobalProcessChains::new())),
            ),
            None,
            None,
            stream_idle_timeout_from_secs(None),
            connect_timeout_from_secs(None),
        )
        .await
        .unwrap();

        let (near, mut far) = tokio::io::duplex(1024);
        far.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 5678 80\r\nhello")
            .await
            .unwrap();

        let handle = tokio::task::spawn_local(async move {
            handler
                .handle_stream(
                    Box::new(near),
                    "tcp".to_string(),
                    None,
                    80,
                    "".to_string(),
                    TunnelEndpoint {
                        device_id: "did:dev:peer".to_string(),
                        port: 2981,
                    },
                    crate::MutComposedSpeedStat::new(),
                    "127.0.0.1:52000".parse().unwrap(),
                    "127.0.0.1:2981".parse().unwrap(),
                )
                .await
        });

        let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("process chain did not forward: source vars not exposed as expected");
        let (mut conn, _) = accepted.unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        drop(conn);
        drop(far);
        let _ = handle.await;
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_reject() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let mut device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        device_config.iat = chrono::Utc::now().timestamp() as u64;
        device_config.exp = chrono::Utc::now().timestamp() as u64 + 1000;
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2981".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let mut device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        device_config.iat = chrono::Utc::now().timestamp() as u64;
        device_config.exp = chrono::Utc::now().timestamp() as u64 + 1000;
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2982".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2981/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        match ret {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("reject should not return application data, got {} bytes", n),
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_drop() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2983".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        // assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2984".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2983/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.read(&mut [0; 1024]).await;
        match ret {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("drop should not return application data, got {} bytes", n),
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_forward() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:2987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2985".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:2987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2986".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:2987").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2985/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;

        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        stream.shutdown().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_forward_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:12987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2988".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:12987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            Arc::new(ServerManager::new()),
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2989".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2988/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // assert_eq!(connection_manager.get_all_connection_info().len(), 1);
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

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2990".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2991".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2990/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        ret.as_ref().unwrap();
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_io_dump_raw_single_roundtrip() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (s1, k1) = generate_ed25519_key();
        let d1 = DeviceConfig::new_by_jwk(
            "test1",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s1)).unwrap(),
        );
        let id1 = d1.id.clone();
        update_did_cache(
            d1.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d1).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d1.id.to_string().as_str(),
            NameInfo::from_address(d1.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("rtcp_raw.dump");
        let io_dump = create_io_dump_stack_config(
            "rtcp_raw",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let sm1 = Arc::new(ServerManager::new());
        sm1.add_server(Server::Stream(Arc::new(MockServer::new(
            "www.buckyos.com".to_string(),
        ))))
        .unwrap();
        let tm1 = TunnelManager::new();
        let cm = ConnectionManager::new();
        let ctx1 = build_stack_context(
            sm1,
            tm1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack1 = rtcp_stack_builder()
            .id("rtcp-dump-1")
            .bind("127.0.0.1:3010".to_string())
            .device_config(d1.clone())
            .private_key(k1)
            .hook_point(chains.clone())
            .connection_manager(cm.clone())
            .stack_context(ctx1)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack1.start().await.unwrap();

        let (s2, k2) = generate_ed25519_key();
        let d2 = DeviceConfig::new_by_jwk(
            "test2",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s2)).unwrap(),
        );
        update_did_cache(
            d2.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d2).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d2.id.to_string().as_str(),
            NameInfo::from_address(d2.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let sm2 = Arc::new(ServerManager::new());
        let tm2 = TunnelManager::new();
        let ctx2 = build_stack_context(
            sm2,
            tm2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack2 = rtcp_stack_builder()
            .id("rtcp-dump-2")
            .bind("127.0.0.1:3011".to_string())
            .device_config(d2)
            .private_key(k2)
            .hook_point(chains)
            .connection_manager(cm)
            .stack_context(ctx2)
            .build()
            .await
            .unwrap();
        stack2.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let url =
            Url::parse(format!("rtcp://{}:3010/test:80", id1.to_host_name()).as_str()).unwrap();
        let mut stream = tm2.open_stream_by_url(&url).await.unwrap();
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

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_io_dump_raw_flush_on_upload_limit() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (s1, k1) = generate_ed25519_key();
        let d1 = DeviceConfig::new_by_jwk(
            "test1",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s1)).unwrap(),
        );
        let id1 = d1.id.clone();
        update_did_cache(
            d1.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d1).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d1.id.to_string().as_str(),
            NameInfo::from_address(d1.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("rtcp_raw_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "rtcp_raw_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("2B"),
            None,
        )
        .await
        .unwrap();
        let sm1 = Arc::new(ServerManager::new());
        sm1.add_server(Server::Stream(Arc::new(MockServer::new(
            "www.buckyos.com".to_string(),
        ))))
        .unwrap();
        let tm1 = TunnelManager::new();
        let cm = ConnectionManager::new();
        let ctx1 = build_stack_context(
            sm1,
            tm1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack1 = rtcp_stack_builder()
            .id("rtcp-limit-1")
            .bind("127.0.0.1:3014".to_string())
            .device_config(d1.clone())
            .private_key(k1)
            .hook_point(chains.clone())
            .connection_manager(cm.clone())
            .stack_context(ctx1)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack1.start().await.unwrap();

        let (s2, k2) = generate_ed25519_key();
        let d2 = DeviceConfig::new_by_jwk(
            "test2",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s2)).unwrap(),
        );
        update_did_cache(
            d2.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d2).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d2.id.to_string().as_str(),
            NameInfo::from_address(d2.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let sm2 = Arc::new(ServerManager::new());
        let tm2 = TunnelManager::new();
        let ctx2 = build_stack_context(
            sm2,
            tm2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack2 = rtcp_stack_builder()
            .id("rtcp-limit-2")
            .bind("127.0.0.1:3015".to_string())
            .device_config(d2)
            .private_key(k2)
            .hook_point(chains)
            .connection_manager(cm)
            .stack_context(ctx2)
            .build()
            .await
            .unwrap();
        stack2.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let url =
            Url::parse(format!("rtcp://{}:3014/test:80", id1.to_host_name()).as_str()).unwrap();
        let mut stream = tm2.open_stream_by_url(&url).await.unwrap();
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

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_io_dump_http_multi_requests_same_connection() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (s1, k1) = generate_ed25519_key();
        let d1 = DeviceConfig::new_by_jwk(
            "test1",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s1)).unwrap(),
        );
        let id1 = d1.id.clone();
        update_did_cache(
            d1.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d1).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d1.id.to_string().as_str(),
            NameInfo::from_address(d1.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("rtcp_http.dump");
        let io_dump = create_io_dump_stack_config(
            "rtcp_http",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let sm1 = Arc::new(ServerManager::new());
        sm1.add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
            id: "www.buckyos.com".to_string(),
        })))
        .unwrap();
        let tm1 = TunnelManager::new();
        let cm = ConnectionManager::new();
        let ctx1 = build_stack_context(
            sm1,
            tm1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack1 = rtcp_stack_builder()
            .id("rtcp-http-1")
            .bind("127.0.0.1:3012".to_string())
            .device_config(d1.clone())
            .private_key(k1)
            .hook_point(chains.clone())
            .connection_manager(cm.clone())
            .stack_context(ctx1)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack1.start().await.unwrap();

        let (s2, k2) = generate_ed25519_key();
        let d2 = DeviceConfig::new_by_jwk(
            "test2",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s2)).unwrap(),
        );
        update_did_cache(
            d2.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d2).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d2.id.to_string().as_str(),
            NameInfo::from_address(d2.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let sm2 = Arc::new(ServerManager::new());
        let tm2 = TunnelManager::new();
        let ctx2 = build_stack_context(
            sm2,
            tm2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack2 = rtcp_stack_builder()
            .id("rtcp-http-2")
            .bind("127.0.0.1:3013".to_string())
            .device_config(d2)
            .private_key(k2)
            .hook_point(chains)
            .connection_manager(cm)
            .stack_context(ctx2)
            .build()
            .await
            .unwrap();
        stack2.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let url =
            Url::parse(format!("rtcp://{}:3012/test:80", id1.to_host_name()).as_str()).unwrap();
        let mut stream = tm2.open_stream_by_url(&url).await.unwrap();
        stream
            .write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let _ = stream.read(&mut tmp).await.unwrap();
        stream
            .write_all(b"GET /b HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let _ = stream.read(&mut tmp).await.unwrap();

        let frames = wait_dump_frames(&dump, 2).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload.starts_with(b"GET /a HTTP/1.1")
                    && f.download.starts_with(b"HTTP/1.1 200 OK"))
        );
        assert!(
            frames
                .iter()
                .any(|f| f.upload.starts_with(b"GET /b HTTP/1.1")
                    && f.download.starts_with(b"HTTP/1.1 200 OK"))
        );
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_io_dump_http_flush_on_upload_limit() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (s1, k1) = generate_ed25519_key();
        let d1 = DeviceConfig::new_by_jwk(
            "test1",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s1)).unwrap(),
        );
        let id1 = d1.id.clone();
        update_did_cache(
            d1.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d1).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d1.id.to_string().as_str(),
            NameInfo::from_address(d1.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("rtcp_http_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "rtcp_http_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("4B"),
            None,
        )
        .await
        .unwrap();
        let sm1 = Arc::new(ServerManager::new());
        sm1.add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
            id: "www.buckyos.com".to_string(),
        })))
        .unwrap();
        let tm1 = TunnelManager::new();
        let cm = ConnectionManager::new();
        let ctx1 = build_stack_context(
            sm1,
            tm1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack1 = rtcp_stack_builder()
            .id("rtcp-http-limit-1")
            .bind("127.0.0.1:3016".to_string())
            .device_config(d1.clone())
            .private_key(k1)
            .hook_point(chains.clone())
            .connection_manager(cm.clone())
            .stack_context(ctx1)
            .io_dump(io_dump)
            .build()
            .await
            .unwrap();
        stack1.start().await.unwrap();

        let (s2, k2) = generate_ed25519_key();
        let d2 = DeviceConfig::new_by_jwk(
            "test2",
            serde_json::from_value(encode_ed25519_sk_to_pk_jwk(&s2)).unwrap(),
        );
        update_did_cache(
            d2.id.clone(),
            None,
            EncodedDocument::JsonLd(serde_json::to_value(&d2).unwrap()),
        )
        .await
        .unwrap();
        add_nameinfo_cache(
            d2.id.to_string().as_str(),
            NameInfo::from_address(d2.id.to_string().as_str(), "127.0.0.1".parse().unwrap()),
        )
        .await
        .unwrap();
        let sm2 = Arc::new(ServerManager::new());
        let tm2 = TunnelManager::new();
        let ctx2 = build_stack_context(
            sm2,
            tm2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let stack2 = rtcp_stack_builder()
            .id("rtcp-http-limit-2")
            .bind("127.0.0.1:3017".to_string())
            .device_config(d2)
            .private_key(k2)
            .hook_point(chains)
            .connection_manager(cm)
            .stack_context(ctx2)
            .build()
            .await
            .unwrap();
        stack2.start().await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let url =
            Url::parse(format!("rtcp://{}:3016/test:80", id1.to_host_name()).as_str()).unwrap();
        let mut stream = tm2.open_stream_by_url(&url).await.unwrap();
        stream
            .write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let _ = stream.read(&mut tmp).await.unwrap();

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"GET " && f.download.is_empty())
        );
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_reject() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2995".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2996".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2995/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream
            .send_datagram(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.recv_datagram(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_udp_stack_drop() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2997".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2313".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2997/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream
            .send_datagram(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = stream.recv_datagram(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_udp_stack_forward() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2998".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:2300";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2999".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("127.0.0.1:2300").await.unwrap();
            let mut buf = [0; 1024];
            let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"test");
            let _ = udp_socket.send_to(b"recv", addr).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2998/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.send_datagram(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.recv_datagram(&mut buf).await;

        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        drop(stream);

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 0);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_forward_err() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2301".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward udp:///127.0.0.1:22987";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2302".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2301/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(connection_manager.get_all_connection_info().len(), 1);
        let result = stream.send_datagram(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret =
            tokio::time::timeout(Duration::from_secs(5), stream.recv_datagram(&mut buf)).await;

        assert!(ret.is_err() || ret.unwrap().is_err());
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_stat_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = Arc::new(DefaultLimiterManager::new());
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            limiter_manager1.clone(),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2322".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2323".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2322/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_stat_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = Arc::new(DefaultLimiterManager::new());
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            limiter_manager1.clone(),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2324".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2325".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2324/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_stat_group_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2326".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2327".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2326/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rtcp_stack_stat_group_limiter_server2() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2328".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2329".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rtcp://{}:2328/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.open_stream_by_url(&url).await;
        assert!(ret.is_ok());
        let start = Instant::now();
        let mut stream = ret.unwrap();
        let result = stream.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = stream.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);
    }

    struct MockDatagramServer {
        id: String,
    }

    impl MockDatagramServer {
        pub fn new(id: String) -> Self {
            Self { id }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl crate::server::DatagramServer for MockDatagramServer {
        async fn serve_datagram(&self, buf: &[u8], _info: DatagramInfo) -> ServerResult<Vec<u8>> {
            assert_eq!(buf, b"test_server");
            Ok("datagram".as_bytes().to_vec())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager1 = TunnelManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2310".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager2 = TunnelManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2311".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2310/test2:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_stat_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager1 = TunnelManager::new();
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2332".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2333".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2332/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);

        let url = Url::parse(format!("rudp://{}:2332/udp://test:80", id1.to_host_name()).as_str())
            .unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_stat_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "4B/s" "4B/s";
        return "server www.buckyos.com";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager1 = TunnelManager::new();
        let limiter_manager1 = DefaultLimiterManager::new();
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2314".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2315".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2314/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5200);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_stat_group_limiter_server() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(4),
            Some(4),
        );
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2316".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2317".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2316/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5000);
    }

    #[tokio::test(flavor = "local")]
    async fn test_rudp_stack_stat_group_limiter_server2() {
        let _ = init_name_lib_for_test(&HashMap::new()).await;
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let id1 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager1 = TunnelManager::new();
        let mut limiter_manager1 = DefaultLimiterManager::new();
        let _ = limiter_manager1.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(4),
            Some(4),
        );
        let stat1 = StatManager::new();
        let connection_manager = ConnectionManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager1.clone(),
            Arc::new(limiter_manager1),
            stat1.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test")
            .bind("127.0.0.1:2318".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack1 = result.unwrap();
        let result = stack1.start().await;
        assert!(result.is_ok());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceConfig::new_by_jwk("test1", serde_json::from_value(jwk).unwrap());
        let _id2 = device_config.id.clone();
        let did_doc_value = serde_json::to_value(&device_config).unwrap();
        let encoded_doc = EncodedDocument::JsonLd(did_doc_value);
        update_did_cache(device_config.id.clone(), None, encoded_doc)
            .await
            .unwrap();
        add_nameinfo_cache(
            device_config.id.to_string().as_str(),
            NameInfo::from_address(
                device_config.id.to_string().as_str(),
                "127.0.0.1".parse().unwrap(),
            ),
        )
        .await
        .unwrap();

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

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let tunnel_manager2 = TunnelManager::new();
        let stat2 = StatManager::new();
        let stack_context = build_stack_context(
            server_manager,
            tunnel_manager2.clone(),
            Arc::new(DefaultLimiterManager::new()),
            stat2.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let result = rtcp_stack_builder()
            .id("test2")
            .bind("127.0.0.1:2319".to_string())
            .device_config(device_config.clone())
            .private_key(pkcs8_bytes)
            .hook_point(chains)
            .connection_manager(connection_manager.clone())
            .stack_context(stack_context)
            .build()
            .await;
        assert!(result.is_ok());

        let stack2 = result.unwrap();
        let result = stack2.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let url =
            Url::parse(format!("rudp://{}:2318/test:80", id1.to_host_name()).as_str()).unwrap();
        let ret = tunnel_manager2.create_datagram_client_by_url(&url).await;
        assert!(ret.is_ok());
        let stream = ret.unwrap();
        let start = Instant::now();
        let result = stream.send_datagram(b"test_server").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 8];
        let ret = stream.recv_datagram(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"datagram");

        let test_stat = stat1.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 15);
        assert_eq!(test_stat.get_write_sum_size(), 12);
        assert!(start.elapsed().as_millis() > 4600);
        assert!(start.elapsed().as_millis() < 5000);
    }

    #[tokio::test]
    async fn test_factory() {
        let server_manager = Arc::new(ServerManager::new());
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let factory = RtcpStackFactory::new(ConnectionManager::new(), test_server_runtime());

        let (signing_key, pkcs8_bytes) = generate_ed25519_key_pair();

        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), signing_key).unwrap();

        let device_config = DeviceConfig::new_by_jwk(
            "test",
            serde_json::from_value(pkcs8_bytes.clone()).unwrap(),
        );
        let device_doc = serde_json::to_string(&device_config).unwrap();
        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), device_doc).unwrap();

        let config = RtcpStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:394".to_string(),
            hook_point: vec![],
            keep_tunnel: vec![],
            on_new_tunnel_hook_point: None,
            identity: None,
            identity_manager: None,
            key_path: Some(key_file.path().to_string_lossy().to_string()),
            device_config_path: None,
            device_doc_jwt: None,
            name: Some("test".to_string()),
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        };

        let stack_context: Arc<dyn StackContext> = Arc::new(RtcpStackContext::new(
            server_manager,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains),
            Some(collection_manager),
            None,
        ));
        let ret = factory
            .create(Arc::new(config), stack_context.clone())
            .await;
        assert!(ret.is_ok());

        let config = RtcpStackConfig {
            id: "test1".to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:394".to_string(),
            hook_point: vec![],
            keep_tunnel: vec![],
            on_new_tunnel_hook_point: None,
            identity: None,
            identity_manager: None,
            key_path: Some(key_file.path().to_string_lossy().to_string()),
            device_config_path: Some(config_file.path().to_string_lossy().to_string()),
            device_doc_jwt: None,
            name: Some("test".to_string()),
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        };

        let ret = factory
            .create(Arc::new(config), stack_context.clone())
            .await;
        assert!(ret.is_ok());

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);
        let mut jwt_device_config =
            DeviceConfig::new_by_jwk("test-jwt", serde_json::from_value(pkcs8_bytes).unwrap());
        jwt_device_config.owner = owner_config.id.clone();
        let jwt_device_doc = match jwt_device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };
        let jwt_config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(jwt_config_file.path(), jwt_device_doc).unwrap();

        let config = RtcpStackConfig {
            id: "test2".to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:394".to_string(),
            hook_point: vec![],
            keep_tunnel: vec![],
            on_new_tunnel_hook_point: None,
            identity: None,
            identity_manager: None,
            key_path: Some(key_file.path().to_string_lossy().to_string()),
            device_config_path: Some(jwt_config_file.path().to_string_lossy().to_string()),
            device_doc_jwt: None,
            name: Some("test".to_string()),
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        };

        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_factory_loads_identity_manager_config() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();
        let device_config = DeviceConfig::new_by_jwk(
            "identity-device",
            serde_json::from_value(public_jwk).unwrap(),
        );
        let identity = device_config.id.to_string();
        write_rtcp_identity_files(
            &roots,
            &identity,
            &private_key_pem,
            Some(&device_config),
            None,
        );

        let factory = RtcpStackFactory::new(ConnectionManager::new(), test_server_runtime());
        let stack_context = build_factory_context().await;
        let config = build_rtcp_identity_config("identity-test", "127.0.0.1:0", &identity, &roots);

        let ret = factory.create(Arc::new(config), stack_context).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_logical_rtcp_identity_requires_device_doc_jwt() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();
        let mut device_config = DeviceConfig::new_by_jwk(
            "logical-device",
            serde_json::from_value(public_jwk).unwrap(),
        );
        device_config.id = DID::new("web", "logical-device.example.com");
        let identity = device_config.id.to_string();
        write_rtcp_identity_files(
            &roots,
            &identity,
            &private_key_pem,
            Some(&device_config),
            None,
        );

        let config =
            build_rtcp_identity_config("logical-missing-jwt", "127.0.0.1:0", &identity, &roots);
        let ret = load_rtcp_identity_material(&config).await;
        let err = ret.as_ref().err().unwrap().to_string();
        assert!(err.contains("device_doc_jwt"), "unexpected error: {}", err);
    }

    #[tokio::test]
    async fn test_rtcp_identity_rejects_did_url_path_form() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let identity = "did:web:logical-device.example.com:user:alice";
        let config =
            build_rtcp_identity_config("logical-path-did", "127.0.0.1:0", identity, &roots);

        let ret = load_rtcp_identity_material(&config).await;
        let err = ret.as_ref().err().unwrap().to_string();
        assert!(err.contains("hostname-form"), "unexpected error: {}", err);
    }

    #[tokio::test]
    async fn test_logical_rtcp_identity_loads_device_doc_jwt() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let mut device_config = DeviceConfig::new_by_jwk(
            "logical-device",
            serde_json::from_value(public_jwk).unwrap(),
        );
        device_config.id = DID::new("web", "logical-device.example.com");
        device_config.owner = owner_config.id.clone();
        let identity = device_config.id.to_string();
        let device_doc_jwt = match device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };
        write_rtcp_identity_files(
            &roots,
            &identity,
            &private_key_pem,
            None,
            Some(&device_doc_jwt),
        );

        let config = build_rtcp_identity_config("logical-jwt", "127.0.0.1:0", &identity, &roots);
        let material = load_rtcp_identity_material(&config).await.unwrap();
        assert_eq!(
            material.device_config.id,
            DID::new("web", "logical-device.example.com")
        );
        assert_eq!(
            material.device_doc_jwt.as_deref(),
            Some(device_doc_jwt.as_str())
        );
    }

    fn build_legacy_rtcp_identity_config(
        id: &str,
        key_path: &std::path::Path,
        device_config_path: &std::path::Path,
    ) -> RtcpStackConfig {
        RtcpStackConfig {
            id: id.to_string(),
            protocol: StackProtocol::Rtcp,
            bind: "127.0.0.1:0".to_string(),
            hook_point: vec![],
            keep_tunnel: vec![],
            on_new_tunnel_hook_point: None,
            identity: None,
            identity_manager: None,
            key_path: Some(key_path.to_string_lossy().to_string()),
            device_config_path: Some(device_config_path.to_string_lossy().to_string()),
            device_doc_jwt: None,
            name: None,
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            stream_idle_timeout: None,
            connect_timeout: None,
            reuse_address: None,
        }
    }

    // buckyos OOD 布局:did.json(未签名) 与 owner 签名的 device_doc.jwt
    // 同目录。legacy 配置只给 device_config_path 时必须能拾取 sibling jwt,
    // 否则逻辑名 stack 无法启动(boot_gateway.yaml 回归场景)。
    #[tokio::test]
    async fn test_legacy_rtcp_identity_loads_sibling_device_doc_jwt() {
        let temp = tempfile::tempdir().unwrap();
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let mut device_config =
            DeviceConfig::new_by_jwk("ood1", serde_json::from_value(public_jwk).unwrap());
        device_config.id = DID::new("bns", "ood1.alice");
        device_config.owner = owner_config.id.clone();
        let device_doc_jwt = match device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        let key_path = temp.path().join("authentication.private.pem");
        std::fs::write(&key_path, &private_key_pem).unwrap();
        let did_json_path = temp.path().join("did.json");
        std::fs::write(
            &did_json_path,
            serde_json::to_string(&device_config).unwrap(),
        )
        .unwrap();
        std::fs::write(temp.path().join("device_doc.jwt"), &device_doc_jwt).unwrap();

        let config =
            build_legacy_rtcp_identity_config("legacy-sibling-jwt", &key_path, &did_json_path);
        let material = load_rtcp_identity_material(&config).await.unwrap();
        assert_eq!(material.device_config.id, DID::new("bns", "ood1.alice"));
        assert_eq!(
            material.device_doc_jwt.as_deref(),
            Some(device_doc_jwt.as_str())
        );
    }

    // sibling jwt 的 id 与 did.json 不一致时必须被忽略,逻辑名 stack 仍然
    // 因缺少可信 jwt 而拒绝启动,不能拿错误身份顶包。
    #[tokio::test]
    async fn test_legacy_rtcp_identity_ignores_mismatched_sibling_jwt() {
        let temp = tempfile::tempdir().unwrap();
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let mut device_config =
            DeviceConfig::new_by_jwk("ood1", serde_json::from_value(public_jwk.clone()).unwrap());
        device_config.id = DID::new("bns", "ood1.alice");
        device_config.owner = owner_config.id.clone();

        let mut other_device_config =
            DeviceConfig::new_by_jwk("ood2", serde_json::from_value(public_jwk).unwrap());
        other_device_config.id = DID::new("bns", "ood2.alice");
        other_device_config.owner = owner_config.id.clone();
        let mismatched_jwt = match other_device_config
            .encode(Some(&owner_private_key))
            .unwrap()
        {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        let key_path = temp.path().join("authentication.private.pem");
        std::fs::write(&key_path, &private_key_pem).unwrap();
        let did_json_path = temp.path().join("did.json");
        std::fs::write(
            &did_json_path,
            serde_json::to_string(&device_config).unwrap(),
        )
        .unwrap();
        std::fs::write(temp.path().join("device_doc.jwt"), &mismatched_jwt).unwrap();

        let config =
            build_legacy_rtcp_identity_config("legacy-mismatch-jwt", &key_path, &did_json_path);
        let err = load_rtcp_identity_material(&config)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_doc_jwt"), "unexpected error: {}", err);
    }

    // buckyos 落盘的文件名是 device_doc.jwt(而不是 name-client 约定的
    // device.jwt),identity 配置也必须能找到它。
    #[tokio::test]
    async fn test_identity_manager_loads_buckyos_device_doc_jwt_file_name() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);

        let mut device_config = DeviceConfig::new_by_jwk(
            "logical-device",
            serde_json::from_value(public_jwk).unwrap(),
        );
        device_config.id = DID::new("web", "logical-device.example.com");
        device_config.owner = owner_config.id.clone();
        let identity = device_config.id.to_string();
        let device_doc_jwt = match device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        write_rtcp_identity_files(&roots, &identity, &private_key_pem, None, None);
        let buckyos_jwt_path = roots
            .public_dir(&identity)
            .unwrap()
            .join(super::BUCKYOS_DEVICE_DOC_JWT_FILE_NAME);
        std::fs::write(buckyos_jwt_path, &device_doc_jwt).unwrap();

        let config =
            build_rtcp_identity_config("buckyos-jwt-name", "127.0.0.1:0", &identity, &roots);
        let material = load_rtcp_identity_material(&config).await.unwrap();
        assert_eq!(
            material.device_config.id,
            DID::new("web", "logical-device.example.com")
        );
        assert_eq!(
            material.device_doc_jwt.as_deref(),
            Some(device_doc_jwt.as_str())
        );
    }

    #[tokio::test]
    async fn test_identity_manager_prefers_device_doc_jwt() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem, public_jwk) = generate_ed25519_key_pair();
        let json_device_config = DeviceConfig::new_by_jwk(
            "json-device",
            serde_json::from_value(public_jwk.clone()).unwrap(),
        );
        let identity = json_device_config.id.to_string();

        let (owner_signing_key, owner_pkcs8_bytes) = generate_ed25519_key();
        let owner_jwk = encode_ed25519_sk_to_pk_jwk(&owner_signing_key);
        let owner_config =
            DeviceConfig::new_by_jwk("owner", serde_json::from_value(owner_jwk).unwrap());
        let owner_private_key = EncodingKey::from_ed_der(&owner_pkcs8_bytes);
        let mut jwt_device_config =
            DeviceConfig::new_by_jwk("jwt-device", serde_json::from_value(public_jwk).unwrap());
        jwt_device_config.owner = owner_config.id.clone();
        let device_doc_jwt = match jwt_device_config.encode(Some(&owner_private_key)).unwrap() {
            EncodedDocument::Jwt(jwt) => jwt,
            _ => panic!("device config encode should return jwt"),
        };

        write_rtcp_identity_files(
            &roots,
            &identity,
            &private_key_pem,
            Some(&json_device_config),
            Some(&device_doc_jwt),
        );
        let config = build_rtcp_identity_config("identity-jwt", "127.0.0.1:0", &identity, &roots);

        let material = load_rtcp_identity_material(&config).await.unwrap();
        assert_eq!(material.device_config.name, "jwt-device");
        assert_eq!(
            material.device_doc_jwt.as_deref(),
            Some(device_doc_jwt.as_str())
        );
    }

    #[tokio::test]
    async fn test_prepare_update_rejects_identity_switch() {
        let temp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(temp.path().join("identity"), temp.path().join("security"));
        let (private_key_pem1, public_jwk1) = generate_ed25519_key_pair();
        let device_config1 =
            DeviceConfig::new_by_jwk("device-1", serde_json::from_value(public_jwk1).unwrap());
        let identity1 = device_config1.id.to_string();
        write_rtcp_identity_files(
            &roots,
            &identity1,
            &private_key_pem1,
            Some(&device_config1),
            None,
        );

        let (private_key_pem2, public_jwk2) = generate_ed25519_key_pair();
        let device_config2 =
            DeviceConfig::new_by_jwk("device-2", serde_json::from_value(public_jwk2).unwrap());
        let identity2 = device_config2.id.to_string();
        write_rtcp_identity_files(
            &roots,
            &identity2,
            &private_key_pem2,
            Some(&device_config2),
            None,
        );

        let factory = RtcpStackFactory::new(ConnectionManager::new(), test_server_runtime());
        let stack_context = build_factory_context().await;
        let config1 =
            build_rtcp_identity_config("identity-update", "127.0.0.1:0", &identity1, &roots);
        let stack = factory
            .create(Arc::new(config1), stack_context)
            .await
            .unwrap();

        let config2 =
            build_rtcp_identity_config("identity-update", "127.0.0.1:0", &identity2, &roots);
        let ret = stack.prepare_update(Arc::new(config2), None).await;
        assert!(ret.is_err());
    }

    #[test]
    fn test_sanitize_keep_tunnels() {
        assert_eq!(
            sanitize_keep_tunnels(&[
                "did:1".to_string(),
                " did:2 ".to_string(),
                "".to_string(),
                "did:1".to_string(),
            ]),
            vec!["did:1".to_string(), "did:2".to_string()]
        );
    }
}
