use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::forward::ForwardPlan;
use crate::global_process_chains::{
    GlobalProcessChainsRef, create_process_chain_executor, execute_chain,
};
use crate::stack::limiter::Limiter;
use crate::stack::tls_cert_resolver::{
    IdentityCertResolver, ResolvesServerCertUsingSni, TlsIdentityCertConfig,
};
use crate::stack::tls_stack::build_identity_cert_config;
use crate::stack::{
    TlsCertResolver, connect_timeout_from_secs, get_limit_info, insert_req_source_addr_group,
    probe_proxy_protocol_stream, stream_forward, stream_forward_group,
    stream_idle_timeout_from_secs,
};
use crate::{
    ComposedSpeedStat, ConnectionController, ConnectionInfo, ConnectionManagerRef, DumpStream,
    GlobalCollectionManagerRef, HandleConnectionController, IoDumpStackConfig,
    JsExternalsManagerRef, LimiterManagerRef, ProcessChainConfig, ProcessChainConfigs,
    SelfCertMgrRef, Server, ServerError, ServerErrorCode, ServerManagerRef, Stack, StackConfig,
    StackContext, StackErrorCode, StackFactory, StackProtocol, StackRef, StackResult,
    StatManagerRef, StreamInfo, TlsIdentityManagerConfig, TunnelManager,
    create_io_dump_stack_config, get_external_commands, get_stat_info, into_stack_err, server_err,
    stack_err,
};
use buckyos_kit::AsyncStream;
use cyfs_process_chain::{
    CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor,
};
use futures::Stream;
use h3::error::Code;
use h3::quic;
use h3::quic::{
    BidiStream, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream, StreamErrorIncoming,
    StreamId, WriteBuf,
};
use h3::server::RequestStream;
use http_body_util::BodyExt;
use hyper::body::{Body, Buf, Bytes, Frame};
use pin_project::pin_project;
use quinn::Incoming;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sfo_io::{
    LimitRead, LimitStream, LimitWrite, SfoSpeedStat, SimpleAsyncWrite, SimpleAsyncWriteHolder,
    SpeedTracker, StatRead, StatStream, StatWrite,
};
use sfo_reuseport::{
    Error as SfoReuseportError, QuicCidGenerator, QuicServer, ServerRuntime, SocketOptions,
    UdpServiceConfig, UdpSocket as ReuseportUdpSocket,
};
use std::future::poll_fn;
use std::io;
use std::io::IoSliceMut;
use std::io::Read;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf, Take};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};
use tokio_util::io::ReaderStream;

const DEFAULT_QUIC_CONCURRENCY: u32 = 0;

struct SfoQuicUdpSocket {
    socket: ReuseportUdpSocket,
    worker_id: usize,
    worker_count: Arc<AtomicUsize>,
}

impl SfoQuicUdpSocket {
    fn new(socket: ReuseportUdpSocket, worker_id: usize, worker_count: Arc<AtomicUsize>) -> Self {
        Self {
            socket,
            worker_id,
            worker_count,
        }
    }
}

impl std::fmt::Debug for SfoQuicUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SfoQuicUdpSocket").finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for SfoQuicUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SfoQuicUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        match transmit.segment_size {
            Some(segment_size) if segment_size > 0 => {
                for chunk in transmit.contents.chunks(segment_size) {
                    let sent = self.socket.try_send_to(chunk, transmit.destination)?;
                    if sent != chunk.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "short quic udp send",
                        ));
                    }
                }
                Ok(())
            }
            _ => {
                let sent = self
                    .socket
                    .try_send_to(transmit.contents, transmit.destination)?;
                if sent == transmit.contents.len() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short quic udp send",
                    ))
                }
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.socket.poll_recv_from_vectored(cx, bufs) {
            Poll::Ready(Ok((len, peer_addr))) => {
                if cfg!(debug_assertions) {
                    let mut packet = Vec::new();
                    let packet = quic_packet_prefix(bufs, len, &mut packet);
                    let worker_count = self.worker_count.load(Ordering::Acquire);
                    if let Some(worker_index) = quic_packet_worker_index(packet, worker_count) {
                        debug_assert_eq!(
                            worker_index, self.worker_id,
                            "quic packet dcid worker index does not match sfo worker socket"
                        );
                    }
                }
                meta[0] = quinn::udp::RecvMeta {
                    addr: peer_addr,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

struct SfoQuicUdpPoller {
    socket: Arc<SfoQuicUdpSocket>,
}

impl std::fmt::Debug for SfoQuicUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SfoQuicUdpPoller").finish()
    }
}

impl quinn::UdpPoller for SfoQuicUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.socket.poll_send_ready(cx)
    }
}

#[derive(Clone, Debug)]
struct WorkerQuicCidGenerator {
    inner: QuicCidGenerator,
}

impl WorkerQuicCidGenerator {
    fn for_worker(worker_id: usize) -> StackResult<Self> {
        let inner = QuicCidGenerator::for_worker(worker_id).map_err(|err| {
            stack_err!(
                StackErrorCode::InvalidConfig,
                "create quic cid generator failed: {}",
                err
            )
        })?;
        Ok(Self { inner })
    }
}

impl quinn::ConnectionIdGenerator for WorkerQuicCidGenerator {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let cid = self
            .inner
            .generate()
            .expect("sfo quic cid generation should not fail after validation");
        quinn::ConnectionId::new(cid.as_slice())
    }

    fn cid_len(&self) -> usize {
        self.inner.cid_len()
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

fn new_quic_endpoint_config(worker_id: usize) -> StackResult<quinn::EndpointConfig> {
    let generator = WorkerQuicCidGenerator::for_worker(worker_id)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.cid_generator(move || Box::new(generator.clone()));
    Ok(endpoint_config)
}

fn quic_packet_worker_index_prefix(packet: &[u8]) -> Option<usize> {
    if packet.is_empty() {
        return None;
    }

    let dcid = if packet[0] & 0x80 != 0 {
        if matches!(packet[0] & 0x30, 0x00 | 0x10) {
            return None;
        }
        let dcid_len = usize::from(*packet.get(5)?);
        if dcid_len == 0 {
            return None;
        }
        packet.get(6..6 + dcid_len)?
    } else {
        packet.get(1..)?
    };

    let high = *dcid.first()?;
    let low = *dcid.get(1)?;
    Some((usize::from(high) << 8) | usize::from(low))
}

fn quic_packet_worker_index(packet: &[u8], worker_count: usize) -> Option<usize> {
    if worker_count == 0 {
        return None;
    }
    quic_packet_worker_index_prefix(packet).map(|worker_index| worker_index % worker_count)
}

fn quic_packet_prefix<'a>(
    bufs: &'a [IoSliceMut<'_>],
    len: usize,
    out: &'a mut Vec<u8>,
) -> &'a [u8] {
    if let Some(first) = bufs.first()
        && first.len() >= len
    {
        return &first[..len];
    }

    out.clear();
    out.reserve(len);
    let mut remaining = len;
    for buf in bufs {
        if remaining == 0 {
            break;
        }
        let copy_len = remaining.min(buf.len());
        out.extend_from_slice(&buf[..copy_len]);
        remaining -= copy_len;
    }
    out.as_slice()
}

#[derive(Clone)]
pub struct QuicStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub self_cert_mgr: SelfCertMgrRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl QuicStackContext {
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

impl StackContext for QuicStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }
}

pub struct QuicDomainConfig {
    pub domain: String,
    pub certs: Option<Vec<CertificateDer<'static>>>,
    pub key: Option<PrivateKeyDer<'static>>,
}

impl Clone for QuicDomainConfig {
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

struct QuicConnectionHandler {
    env: Arc<QuicStackContext>,
    executor: ProcessChainLibExecutor,
    connection_manager: Option<ConnectionManagerRef>,
    io_dump: Option<IoDumpStackConfig>,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
    stream_semaphore: Arc<Semaphore>,
}

impl QuicConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        env: Arc<QuicStackContext>,
        connection_manager: Option<ConnectionManagerRef>,
        io_dump: Option<IoDumpStackConfig>,
        stream_idle_timeout: std::time::Duration,
        connect_timeout: std::time::Duration,
        stream_concurrency: u32,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
            env.js_externals.clone(),
        )
        .await
        .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
        Ok(Self {
            env,
            executor,
            connection_manager,
            io_dump,
            stream_idle_timeout,
            connect_timeout,
            stream_semaphore: Arc::new(Semaphore::new(stream_concurrency as usize)),
        })
    }

    fn build_cert_resolver(
        certs: Vec<QuicDomainConfig>,
        identity_certs: Option<TlsIdentityCertConfig>,
        env: &QuicStackContext,
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

    async fn accept(&self, conn: Incoming, local_addr: SocketAddr) -> StackResult<()> {
        let connection = conn
            .await
            .map_err(into_stack_err!(StackErrorCode::QuicError))?;
        let server_name = {
            let handshake_data = connection.handshake_data();
            if handshake_data.is_none() {
                return Err(stack_err!(
                    StackErrorCode::QuicError,
                    "handshake data is None"
                ));
            }
            let handshake_data = handshake_data
                .as_ref()
                .unwrap()
                .as_ref()
                .downcast_ref::<HandshakeData>();
            if handshake_data.is_none() {
                return Err(stack_err!(
                    StackErrorCode::QuicError,
                    "handshake data is None"
                ));
            }

            let server_name = handshake_data.unwrap().server_name.as_ref();
            if server_name.is_none() {
                return Err(stack_err!(StackErrorCode::QuicError, "server name is None"));
            }
            server_name.unwrap().to_string()
        };

        let remote_addr = connection.remote_address();
        log::debug!("quic accept: {} -> {}", remote_addr, local_addr);
        let map = MemoryMapCollection::new_ref();
        map.insert("dest_host", CollectionValue::String(server_name))
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
        map.insert(
            "dest_port",
            CollectionValue::String(local_addr.port().to_string()),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
        let device_info = self
            .connection_manager
            .as_ref()
            .and_then(|manager| manager.get_device_info_by_source(remote_addr.ip()));
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

        let executor = self.executor.fork();
        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                connection.close(0u32.into(), "".as_bytes());
                return Ok(());
            } else if ret.is_reject() {
                connection.close(0u32.into(), "".as_bytes());
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
                    let speed_stat = ComposedSpeedStat::new(speed_groups);
                    let cmd = list[0].as_str();
                    match cmd {
                        "forward" | "forward-group" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid {} command",
                                    list[0]
                                ));
                            }
                            let is_group = list[0].as_str() == "forward-group";
                            let plan: Option<ForwardPlan> = if is_group {
                                Some(ForwardPlan::decode(list[1].as_str()).map_err(|e| {
                                    stack_err!(
                                        StackErrorCode::InvalidConfig,
                                        "invalid forward plan: {}",
                                        e
                                    )
                                })?)
                            } else {
                                None
                            };
                            let speed_stat = speed_stat.clone();
                            loop {
                                let permit =
                                    match self.stream_semaphore.clone().acquire_owned().await {
                                        Ok(permit) => permit,
                                        Err(_) => break,
                                    };
                                let (send, recv) = connection
                                    .accept_bi()
                                    .await
                                    .map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                log::debug!("quic accept bi: {} -> {}", remote_addr, local_addr);
                                let stream = sfo_split::Splittable::new(recv, send);
                                let stream: Box<dyn AsyncStream> =
                                    if let Some(io_dump) = self.io_dump.clone() {
                                        Box::new(DumpStream::new(
                                            stream,
                                            io_dump,
                                            remote_addr.to_string(),
                                            local_addr.to_string(),
                                        ))
                                    } else {
                                        Box::new(stream)
                                    };
                                let (stream, proxy_source_addr) =
                                    probe_proxy_protocol_stream(stream).await?;
                                let request_source_addr = proxy_source_addr.unwrap_or(remote_addr);
                                let stream_info = StreamInfo::with_addrs(
                                    Some(remote_addr.to_string()),
                                    proxy_source_addr.map(|a| a.to_string()),
                                )
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
                                let _ = request_source_addr;
                                let stat_stream =
                                    StatStream::new_with_tracker(stream, speed_stat.clone());
                                let speed = stat_stream.get_speed_stat();
                                let target_or_plan: Result<String, ForwardPlan> = match &plan {
                                    Some(p) => Err(p.clone()),
                                    None => Ok(list[1].clone()),
                                };
                                let stream: Box<dyn AsyncStream> = if limiter.is_some() {
                                    let (read_limit, write_limit) =
                                        limiter.as_ref().unwrap().new_limit_session();
                                    let limit_stream =
                                        LimitStream::new(stat_stream, read_limit, write_limit);
                                    Box::new(limit_stream)
                                } else {
                                    Box::new(stat_stream)
                                };
                                let tunnel_manager = self.env.tunnel_manager.clone();
                                let forward_info = stream_info.clone();
                                let stream_idle_timeout = self.stream_idle_timeout;
                                let connect_timeout = self.connect_timeout;
                                let handle = tokio::spawn(async move {
                                    let _permit = permit;
                                    let result = match target_or_plan {
                                        Ok(target) => {
                                            stream_forward(
                                                stream,
                                                target.as_str(),
                                                &tunnel_manager,
                                                Some(&forward_info),
                                                stream_idle_timeout,
                                                connect_timeout,
                                            )
                                            .await
                                        }
                                        Err(plan) => {
                                            stream_forward_group(
                                                stream,
                                                &plan,
                                                &tunnel_manager,
                                                Some(&forward_info),
                                            )
                                            .await
                                        }
                                    };
                                    if let Err(e) = result {
                                        log::error!("stream forward error: {}", e);
                                    }
                                });
                                if let Some(connection_manager) = self.connection_manager.as_ref() {
                                    let controller = HandleConnectionController::new(handle);
                                    connection_manager.add_connection(ConnectionInfo::new(
                                        remote_addr.to_string(),
                                        local_addr.to_string(),
                                        StackProtocol::Quic,
                                        speed,
                                        controller,
                                    ));
                                }
                            }
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }
                            let server_name = list[1].as_str();
                            let speed_stat = speed_stat.clone();
                            if let Some(server) = self.env.servers.get_server(server_name) {
                                match server {
                                    Server::Http(server) => {
                                        let mut h3_conn =
                                            match h3::server::Connection::<_, Bytes>::new(
                                                Http3Connection::new(
                                                    h3_quinn::Connection::new(connection),
                                                    local_addr,
                                                    remote_addr,
                                                    self.connection_manager.clone(),
                                                ),
                                            )
                                            .await
                                            {
                                                Ok(h3_conn) => h3_conn,
                                                Err(e) => {
                                                    return if e.is_h3_no_error() {
                                                        Ok(())
                                                    } else {
                                                        Err(stack_err!(
                                                            StackErrorCode::QuicError,
                                                            "h3 new error: {e}"
                                                        ))
                                                    };
                                                }
                                            };
                                        loop {
                                            let resolver = match h3_conn.accept().await {
                                                Ok(resolver) => resolver,
                                                Err(e) => {
                                                    if e.is_h3_no_error() {
                                                        break;
                                                    } else {
                                                        return Err(stack_err!(
                                                            StackErrorCode::QuicError,
                                                            "h3 accept error: {e}"
                                                        ));
                                                    }
                                                }
                                            };
                                            if resolver.is_none() {
                                                break;
                                            }
                                            let speed = speed_stat.clone();
                                            let limiter = limiter.clone();
                                            let server = server.clone();
                                            let speed_stat = speed_stat.clone();
                                            let device_info = device_info.clone();
                                            let permit = match self
                                                .stream_semaphore
                                                .clone()
                                                .acquire_owned()
                                                .await
                                            {
                                                Ok(permit) => permit,
                                                Err(_) => break,
                                            };
                                            let handle = tokio::task::spawn_local(async move {
                                                let _permit = permit;
                                                let ret: StackResult<()> = async move {
                                                    let (req, stream) = resolver.unwrap().resolve_request().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 resolve request error"))?;
                                                    let (parts, _) = req.into_parts();
                                                    let (mut send, recv) = stream.split();
                                                    let recv_stream = StatRead::new_with_tracker(Http3Recv::new(recv), speed_stat.clone());
                                                    let (read_limit, write_limit) = if limiter.is_some() {
                                                        let (read_limit, write_limit) = limiter.as_ref().unwrap().new_limit_session();
                                                        (Some(read_limit), Some(write_limit))
                                                    } else {
                                                        (None, None)
                                                    };

                                                    let body = if read_limit.is_some() {
                                                        AsyncReadBody::with_capacity(LimitRead::new(recv_stream, read_limit.unwrap()), 4096)
                                                            .map_err(|e| server_err!(ServerErrorCode::IOError, "async read body error: {e}")).boxed_unsync()
                                                    } else {
                                                        AsyncReadBody::with_capacity(recv_stream, 4096)
                                                            .map_err(|e| server_err!(ServerErrorCode::IOError, "async read body error: {e}")).boxed_unsync()
                                                    };
                                                    let req = http::Request::from_parts(parts, body);
                                                    log::debug!("recv http request:remote {} method {} host {} path {}",
                                                        remote_addr,
                                                        req.method().to_string(),
                                                        req.headers().get("host").map(|h| h.to_str().unwrap_or("none")).unwrap_or("none"),
                                                        req.uri().to_string());
                                                    let resp = crate::serve_http_server_request(
                                                        server,
                                                        req,
                                                        StreamInfo::new(remote_addr.to_string()).with_dst_addr(Some(local_addr.to_string())).with_device_info(
                                                            device_info.as_ref().and_then(|v| v.mac().map(|m| m.to_string())),
                                                            device_info.as_ref().and_then(|v| v.hostname().map(|h| h.to_string())),
                                                            device_info.as_ref().map(|v| v.today_online_seconds().to_string()),
                                                        ),
                                                    )
                                                    .await
                                                    .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
                                                    let (parts, mut body) = resp.into_parts();

                                                    send.send_response(http::Response::from_parts(parts, ())).await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send response error"))?;

                                                    let send_stream = StatWrite::new_with_tracker(SimpleAsyncWriteHolder::new(Http3Send::new(send)), speed_stat.clone());
                                                    let mut send: Box<dyn AsyncWrite + Unpin + Send> = if write_limit.is_some() {
                                                        Box::new(LimitWrite::new(send_stream, write_limit.unwrap()))
                                                    } else {
                                                        Box::new(send_stream)
                                                    };
                                                    loop {
                                                        let mut pin_body = Pin::new(&mut body);
                                                        let data = poll_fn(move |cx| {
                                                            pin_body.as_mut().poll_frame(cx)
                                                        }).await;
                                                        match data {
                                                            Some(data) => {
                                                                let data = data.map_err(into_stack_err!(StackErrorCode::QuicError, "h3 map error"))?;
                                                                send.write_all(data.into_data()
                                                                    .map_err(|_e| stack_err!(StackErrorCode::QuicError, "h3 data error"))?.as_ref()).await
                                                                    .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 send data error"))?;
                                                            }
                                                            None => {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    send.shutdown().await
                                                        .map_err(into_stack_err!(StackErrorCode::QuicError, "h3 finish error"))?;
                                                    Ok(())
                                                }.await;
                                                if let Err(e) = ret {
                                                    log::error!("server error: {}", e);
                                                }
                                            });

                                            if let Some(connection_manager) =
                                                self.connection_manager.as_ref()
                                            {
                                                let controller =
                                                    HandleConnectionController::new(handle);
                                                connection_manager.add_connection(
                                                    ConnectionInfo::new(
                                                        remote_addr.to_string(),
                                                        local_addr.to_string(),
                                                        StackProtocol::Quic,
                                                        speed,
                                                        controller,
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    Server::Stream(server) => loop {
                                        let permit = match self
                                            .stream_semaphore
                                            .clone()
                                            .acquire_owned()
                                            .await
                                        {
                                            Ok(permit) => permit,
                                            Err(_) => break,
                                        };
                                        let (send, recv) = connection
                                            .accept_bi()
                                            .await
                                            .map_err(into_stack_err!(StackErrorCode::QuicError))?;
                                        log::debug!(
                                            "quic accept bi: {} -> {}",
                                            remote_addr,
                                            local_addr
                                        );
                                        let server = server.clone();
                                        let stream = sfo_split::Splittable::new(recv, send);
                                        let stream: Box<dyn AsyncStream> =
                                            if let Some(io_dump) = self.io_dump.clone() {
                                                Box::new(DumpStream::new(
                                                    stream,
                                                    io_dump,
                                                    remote_addr.to_string(),
                                                    local_addr.to_string(),
                                                ))
                                            } else {
                                                Box::new(stream)
                                            };
                                        let (stream, proxy_source_addr) =
                                            probe_proxy_protocol_stream(stream).await?;
                                        let stat_stream = StatStream::new_with_tracker(
                                            stream,
                                            speed_stat.clone(),
                                        );
                                        let speed = stat_stream.get_speed_stat();
                                        let stream: Box<dyn AsyncStream> = if limiter.is_some() {
                                            let (read_limit, write_limit) =
                                                limiter.as_ref().unwrap().new_limit_session();
                                            let limit_stream = LimitStream::new(
                                                stat_stream,
                                                read_limit,
                                                write_limit,
                                            );
                                            Box::new(limit_stream)
                                        } else {
                                            Box::new(stat_stream)
                                        };
                                        let device_info = device_info.clone();
                                        let handle = tokio::task::spawn_local(async move {
                                            let _permit = permit;
                                            let info = StreamInfo::with_addrs(
                                                Some(remote_addr.to_string()),
                                                proxy_source_addr.map(|a| a.to_string()),
                                            )
                                            .with_dst_addr(Some(local_addr.to_string()))
                                            .with_device_info(
                                                device_info
                                                    .as_ref()
                                                    .and_then(|v| v.mac().map(|m| m.to_string())),
                                                device_info.as_ref().and_then(|v| {
                                                    v.hostname().map(|h| h.to_string())
                                                }),
                                                device_info
                                                    .as_ref()
                                                    .map(|v| v.today_online_seconds().to_string()),
                                            );
                                            if let Err(e) =
                                                server.serve_connection(stream, info).await
                                            {
                                                log::error!("server error: {}", e);
                                            }
                                        });
                                        if let Some(connection_manager) =
                                            self.connection_manager.as_ref()
                                        {
                                            let controller =
                                                HandleConnectionController::new(handle);
                                            connection_manager.add_connection(ConnectionInfo::new(
                                                remote_addr.to_string(),
                                                local_addr.to_string(),
                                                StackProtocol::Quic,
                                                speed,
                                                controller,
                                            ));
                                        }
                                    },
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "Unsupport server type"
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

pub struct Http3Body<S, B> {
    stream: RequestStream<S, B>,
}

impl<S, B> Http3Body<S, B> {
    pub fn new(stream: RequestStream<S, B>) -> Self {
        Self { stream }
    }
}

impl<S, B> Body for Http3Body<S, B>
where
    S: quic::RecvStream + 'static,
    B: Buf + 'static,
{
    type Data = Bytes;
    type Error = ServerError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(ret) => match ret {
                Ok(Some(mut ret)) => {
                    Poll::Ready(Some(Ok(Frame::data(ret.copy_to_bytes(ret.remaining())))))
                }
                Ok(None) => Poll::Ready(None),
                Err(e) => Poll::Ready(Some(Err(server_err!(ServerErrorCode::IOError, "{}", e)))),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pin_project]
#[derive(Debug)]
pub struct AsyncReadBody<T> {
    #[pin]
    reader: ReaderStream<T>,
}

impl<T> AsyncReadBody<T>
where
    T: AsyncRead + Send + 'static,
{
    /// Create a new [`AsyncReadBody`] wrapping the given reader,
    /// with a specific read buffer capacity
    pub(crate) fn with_capacity(read: T, capacity: usize) -> Self {
        Self {
            reader: ReaderStream::with_capacity(read, capacity),
        }
    }

    pub(crate) fn with_capacity_limited(
        read: T,
        capacity: usize,
        max_read_bytes: u64,
    ) -> AsyncReadBody<Take<T>> {
        AsyncReadBody {
            reader: ReaderStream::with_capacity(read.take(max_read_bytes), capacity),
        }
    }

    pub fn raw_stream(&mut self) -> &mut ReaderStream<T> {
        &mut self.reader
    }
}

impl<T> Body for AsyncReadBody<T>
where
    T: AsyncRead,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match std::task::ready!(self.project().reader.poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}

pub struct Http3Recv<B: Buf + 'static + Send, R: quic::RecvStream + 'static> {
    recv: RequestStream<R, B>,
    cache: Option<Box<dyn Read + Send + Sync>>,
}

impl<B: Buf + 'static + Send, R: quic::RecvStream + 'static> Http3Recv<B, R> {
    pub fn new(recv: RequestStream<R, B>) -> Self {
        Self { recv, cache: None }
    }
}

impl<B: Buf + 'static + Send, R: quic::RecvStream + 'static> AsyncRead for Http3Recv<B, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(reader) = self.cache.as_mut() {
            let buf_ref = buf.initialize_unfilled();
            match reader.read(buf_ref) {
                Ok(n) => {
                    buf.advance(n);
                    if n == 0 {
                        self.cache = None;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
        match self.recv.poll_recv_data(cx) {
            Poll::Ready(ret) => match ret {
                Ok(Some(ret)) => {
                    let remaining = ret.remaining();
                    let mut reader = Box::new(ret.reader());
                    let buf_ref = buf.initialize_unfilled();
                    match reader.read(buf_ref) {
                        Ok(n) => {
                            buf.advance(n);
                            if n < remaining {
                                self.cache = Some(reader);
                            }
                        }
                        Err(e) => {
                            return Poll::Ready(Err(e));
                        }
                    }
                    Poll::Ready(Ok(()))
                }
                Ok(None) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct Http3Send<B: Buf + 'static + Send, S: quic::SendStream<B> + 'static> {
    send: RequestStream<S, B>,
}

impl<B: Buf + 'static + Send, S: quic::SendStream<B> + 'static> Http3Send<B, S> {
    pub fn new(send: RequestStream<S, B>) -> Self {
        Self { send }
    }

    pub fn raw_stream(&mut self) -> &mut RequestStream<S, B> {
        &mut self.send
    }
}

#[async_trait::async_trait]
impl<S: quic::SendStream<Bytes> + Send + Unpin + 'static> SimpleAsyncWrite for Http3Send<Bytes, S> {
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let static_buf = unsafe { std::mem::transmute::<&[u8], &'static [u8]>(buf) };
        match self.send.send_data(Bytes::from(static_buf)).await {
            Ok(()) => Ok(buf.len()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.send
            .finish()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

pub struct Http3RecvStream {
    recv: h3_quinn::RecvStream,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl Drop for Http3RecvStream {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

impl Http3RecvStream {
    pub fn new(
        recv: h3_quinn::RecvStream,
        speed_tracker: Arc<dyn SpeedTracker>,
        notify: Arc<Notify>,
        has_stopped: Arc<AtomicBool>,
    ) -> Self {
        Self {
            recv,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl quic::RecvStream for Http3RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if self.has_stopped.load(Ordering::Relaxed) {
            return Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "user stopped".to_string(),
                ),
            }));
        }

        match self.recv.poll_data(cx) {
            Poll::Ready(Ok(Some(ret))) => {
                self.speed_tracker.add_read_data_size(ret.len() as u64);
                Poll::Ready(Ok(Some(ret)))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

pub struct Http3SendStream<B: Buf> {
    send: h3_quinn::SendStream<B>,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl<B: Buf> Drop for Http3SendStream<B> {
    fn drop(&mut self) {
        self.notify.notify_waiters();
    }
}

impl<B: Buf> Http3SendStream<B> {
    pub fn new(
        send: h3_quinn::SendStream<B>,
        speed_tracker: Arc<dyn SpeedTracker>,
        notify: Arc<Notify>,
        has_stopped: Arc<AtomicBool>,
    ) -> Self {
        Self {
            send,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for Http3SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.has_stopped.load(Ordering::Relaxed) {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "user stopped".to_string(),
                ),
            });
        }

        let buf = data.into();
        self.speed_tracker
            .add_write_data_size(buf.remaining() as u64);
        self.send.send_data(buf)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

pub struct Http3BidiStream<B: Buf> {
    send: Http3SendStream<B>,
    recv: Http3RecvStream,
}

impl<B: Buf> Http3BidiStream<B> {
    pub fn new(
        stream: h3_quinn::BidiStream<B>,
        speed_tracker: Arc<dyn SpeedTracker>,
        notify: Arc<Notify>,
        has_stopped: Arc<AtomicBool>,
    ) -> Self {
        let (send, recv) = stream.split();
        Self {
            send: Http3SendStream::new(
                send,
                speed_tracker.clone(),
                notify.clone(),
                has_stopped.clone(),
            ),
            recv: Http3RecvStream::new(recv, speed_tracker, notify, has_stopped),
        }
    }
}

impl<B: Buf> SendStream<B> for Http3BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data.into())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> RecvStream for Http3BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::BidiStream<B> for Http3BidiStream<B> {
    type SendStream = Http3SendStream<B>;
    type RecvStream = Http3RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

pub struct Http3OpenStreams {
    streams: h3_quinn::OpenStreams,
    speed_tracker: Arc<dyn SpeedTracker>,
    notify: Arc<Notify>,
    has_stopped: Arc<AtomicBool>,
}

impl Http3OpenStreams {
    pub fn new(
        streams: h3_quinn::OpenStreams,
        speed_tracker: Arc<dyn SpeedTracker>,
        notify: Arc<Notify>,
        has_stopped: Arc<AtomicBool>,
    ) -> Self {
        Self {
            streams,
            speed_tracker,
            notify,
            has_stopped,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Http3OpenStreams {
    type BidiStream = Http3BidiStream<B>;
    type SendStream = Http3SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.streams.poll_open_bidi(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(Http3BidiStream::new(
                stream,
                self.speed_tracker.clone(),
                self.notify.clone(),
                self.has_stopped.clone(),
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.streams.poll_open_send(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(Http3SendStream::new(
                stream,
                self.speed_tracker.clone(),
                self.notify.clone(),
                self.has_stopped.clone(),
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as OpenStreams<B>>::close(&mut self.streams, code, reason);
    }
}

struct Http3ConnectionController {
    is_stopped: Arc<AtomicBool>,
    notify: Arc<Notify>,
    stopped: AtomicBool,
}

impl Http3ConnectionController {
    pub fn new(is_stopped: Arc<AtomicBool>, notify: Arc<Notify>) -> Self {
        Self {
            is_stopped,
            notify,
            stopped: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl ConnectionController for Http3ConnectionController {
    fn stop_connection(&self) {
        self.is_stopped.store(true, Ordering::Relaxed);
    }

    async fn wait_stop(&self) {
        self.notify.notified().await;
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

pub struct Http3Connection {
    conn: h3_quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    connection_manager: Option<ConnectionManagerRef>,
}

impl Http3Connection {
    pub fn new(
        conn: h3_quinn::Connection,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        connection_manager: Option<ConnectionManagerRef>,
    ) -> Self {
        Self {
            conn,
            local_addr,
            remote_addr,
            connection_manager,
        }
    }
}

impl<B: Buf> OpenStreams<B> for Http3Connection {
    type BidiStream = Http3BidiStream<B>;
    type SendStream = Http3SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.conn.poll_open_bidi(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(
                        has_stopped.clone(),
                        notify.clone(),
                    ));
                    connection_manager.add_connection(ConnectionInfo::new(
                        self.remote_addr.to_string(),
                        self.local_addr.to_string(),
                        StackProtocol::Quic,
                        speed_tracker.clone(),
                        controller,
                    ));
                }
                Poll::Ready(Ok(Http3BidiStream::new(
                    stream,
                    speed_tracker.clone(),
                    notify.clone(),
                    has_stopped.clone(),
                )))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.conn.poll_open_send(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(
                        has_stopped.clone(),
                        notify.clone(),
                    ));
                    connection_manager.add_connection(ConnectionInfo::new(
                        self.remote_addr.to_string(),
                        self.local_addr.to_string(),
                        StackProtocol::Quic,
                        speed_tracker.clone(),
                        controller,
                    ));
                }
                Poll::Ready(Ok(Http3SendStream::new(
                    stream,
                    speed_tracker.clone(),
                    notify.clone(),
                    has_stopped.clone(),
                )))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::Connection as OpenStreams<B>>::close(&mut self.conn, code, reason);
    }
}

impl<B: Buf> quic::Connection<B> for Http3Connection {
    type RecvStream = Http3RecvStream;
    type OpenStreams = Http3OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match <h3_quinn::Connection as h3::quic::Connection<B>>::poll_accept_recv(
            &mut self.conn,
            cx,
        ) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(
                        has_stopped.clone(),
                        notify.clone(),
                    ));
                    connection_manager.add_connection(ConnectionInfo::new(
                        self.remote_addr.to_string(),
                        self.local_addr.to_string(),
                        StackProtocol::Quic,
                        speed_tracker.clone(),
                        controller,
                    ));
                }
                Poll::Ready(Ok(Http3RecvStream::new(
                    stream,
                    speed_tracker.clone(),
                    notify.clone(),
                    has_stopped.clone(),
                )))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match self.conn.poll_accept_bidi(cx) {
            Poll::Ready(Ok(stream)) => {
                let speed_tracker = Arc::new(SfoSpeedStat::new());
                let notify = Arc::new(Notify::new());
                let has_stopped = Arc::new(AtomicBool::new(false));
                if let Some(connection_manager) = &self.connection_manager {
                    let controller = Arc::new(Http3ConnectionController::new(
                        has_stopped.clone(),
                        notify.clone(),
                    ));
                    connection_manager.add_connection(ConnectionInfo::new(
                        self.remote_addr.to_string(),
                        self.local_addr.to_string(),
                        StackProtocol::Quic,
                        speed_tracker.clone(),
                        controller,
                    ));
                }
                Poll::Ready(Ok(Http3BidiStream::new(
                    stream,
                    speed_tracker.clone(),
                    notify.clone(),
                    has_stopped.clone(),
                )))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        let speed_tracker = Arc::new(SfoSpeedStat::new());
        let notify = Arc::new(Notify::new());
        let has_stopped = Arc::new(AtomicBool::new(false));
        if let Some(connection_manager) = &self.connection_manager {
            let controller = Arc::new(Http3ConnectionController::new(
                has_stopped.clone(),
                notify.clone(),
            ));
            connection_manager.add_connection(ConnectionInfo::new(
                self.remote_addr.to_string(),
                self.local_addr.to_string(),
                StackProtocol::Quic,
                speed_tracker.clone(),
                controller,
            ));
        }
        Http3OpenStreams::new(
            <h3_quinn::Connection as h3::quic::Connection<B>>::opener(&self.conn),
            speed_tracker.clone(),
            notify.clone(),
            has_stopped.clone(),
        )
    }
}

struct QuicStackInner {
    id: String,
    bind_addr: String,
    concurrency: u32,
    certs: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    reuse_address: bool,
    connection_manager: Option<ConnectionManagerRef>,
    handler: Arc<RwLock<Arc<QuicConnectionHandler>>>,
    server_runtime: ServerRuntime,
    endpoints: Mutex<Vec<quinn::Endpoint>>,
    worker_count: Arc<AtomicUsize>,
}

impl QuicStackInner {
    async fn start(self: &Arc<Self>) -> StackResult<QuicServer> {
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(self.certs.clone());
        server_config.alpn_protocols = self.alpn_protocols.clone();
        server_config.max_early_data_size = u32::MAX;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_config)
                .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?,
        ));
        let addr: SocketAddr = self
            .bind_addr
            .parse()
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;

        let this = self.clone();
        let config = UdpServiceConfig::new(addr).with_socket_options(SocketOptions {
            reuse_address: self.reuse_address,
            ..SocketOptions::default()
        });
        QuicServer::serve_socket(&self.server_runtime, config, move |socket, worker_id| {
            let this = this.clone();
            let server_config = server_config.clone();
            async move {
                this.run_worker_endpoint(socket, worker_id, server_config)
                    .await
            }
        })
        .map_err(|err| {
            stack_err!(
                StackErrorCode::BindFailed,
                "bind {} error: {}",
                self.bind_addr,
                err
            )
        })
    }

    async fn run_worker_endpoint(
        self: Arc<Self>,
        socket: ReuseportUdpSocket,
        worker_id: usize,
        server_config: quinn::ServerConfig,
    ) -> Result<(), SfoReuseportError> {
        self.worker_count
            .fetch_max(worker_id.saturating_add(1), Ordering::AcqRel);
        let endpoint_config = new_quic_endpoint_config(worker_id)
            .map_err(|err| SfoReuseportError::Runtime(err.to_string()))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Arc::new(SfoQuicUdpSocket::new(
                socket,
                worker_id,
                self.worker_count.clone(),
            )),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|err| SfoReuseportError::Runtime(err.to_string()))?;
        self.endpoints.lock().unwrap().push(endpoint.clone());

        loop {
            match endpoint.accept().await {
                None => break,
                Some(conn) => {
                    if endpoint.open_connections() > self.concurrency as usize {
                        conn.refuse();
                        continue;
                    }
                    let this = self.clone();
                    tokio::task::spawn_local(async move {
                        if let Err(e) = this.accept(conn).await {
                            log::error!("quic accept error: {}", e);
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn accept(self: &Arc<Self>, conn: Incoming) -> StackResult<()> {
        let local_addr: SocketAddr = self
            .bind_addr
            .parse()
            .map_err(into_stack_err!(StackErrorCode::InvalidConfig))?;
        let handler_snapshot = {
            let handler = self.handler.read().unwrap();
            handler.clone()
        };
        handler_snapshot.accept(conn, local_addr).await
    }

    fn close_endpoints(&self) {
        let endpoints = std::mem::take(&mut *self.endpoints.lock().unwrap());
        for endpoint in endpoints {
            endpoint.close(0_u32.into(), b"close quic listener");
        }
    }
}

pub struct QuicStack {
    inner: Arc<QuicStackInner>,
    prepare_handler: Arc<RwLock<Option<Arc<QuicConnectionHandler>>>>,
    server: Mutex<Option<QuicServer>>,
}

impl Drop for QuicStack {
    fn drop(&mut self) {
        if let Some(server) = self.server.lock().unwrap().take() {
            if let Err(e) = server.close() {
                log::warn!("close quic server failed: {}", e);
            }
        }
        self.inner.close_endpoints();
    }
}

impl QuicStack {
    pub fn builder() -> QuicStackBuilder {
        QuicStackBuilder::new()
    }

    async fn create(mut builder: QuicStackBuilder) -> StackResult<Self> {
        if builder.id.is_none() {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id is required"));
        }
        if builder.bind.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "bind is required"
            ));
        }
        if builder.hook_point.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "hook_point is required"
            ));
        }
        if builder.stack_context.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "stack_context is required"
            ));
        }
        if builder.server_runtime.is_none() {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "server_runtime is required"
            ));
        }

        let stack_context = builder.stack_context.unwrap();

        let handler = QuicConnectionHandler::create(
            builder.hook_point.take().unwrap(),
            stack_context.clone(),
            builder.connection_manager.clone(),
            builder.io_dump,
            builder.stream_idle_timeout,
            builder.connect_timeout,
            builder.concurrency,
        )
        .await?;
        let handler = Arc::new(RwLock::new(Arc::new(handler)));
        let certs = QuicConnectionHandler::build_cert_resolver(
            builder.certs,
            builder.identity_certs,
            stack_context.as_ref(),
        )?;

        Ok(QuicStack {
            inner: Arc::new(QuicStackInner {
                id: builder.id.take().unwrap(),
                bind_addr: builder.bind.take().unwrap(),
                concurrency: builder.concurrency,
                certs,
                alpn_protocols: builder.alpn_protocols,
                reuse_address: builder.reuse_address,
                connection_manager: builder.connection_manager.clone(),
                handler,
                server_runtime: builder.server_runtime.take().unwrap(),
                endpoints: Mutex::new(Vec::new()),
                worker_count: Arc::new(AtomicUsize::new(0)),
            }),
            prepare_handler: Arc::new(Default::default()),
            server: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl Stack for QuicStack {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
    }

    fn get_bind_addr(&self) -> String {
        self.inner.bind_addr.clone()
    }

    async fn start(&self) -> StackResult<()> {
        {
            if self.server.lock().unwrap().is_some() {
                return Ok(());
            }
        }
        let server = self.inner.start().await?;
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
            .downcast_ref::<QuicStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid quic stack config"
            ))?;

        if config.id != self.inner.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }

        if config.bind.to_string() != self.inner.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }

        if config.reuse_address.unwrap_or(false) != self.inner.reuse_address {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "reuse_address unmatch"
            ));
        }

        if normalize_concurrency(config.concurrency.unwrap_or(DEFAULT_QUIC_CONCURRENCY))
            != self.inner.concurrency
        {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "concurrency unmatch"
            ));
        }

        let env = match context {
            Some(context) => {
                let quic_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<QuicStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid quic stack context"
                    ))?;
                Arc::new(quic_context.clone())
            }
            None => self.inner.handler.read().unwrap().env.clone(),
        };

        let new_handler = QuicConnectionHandler::create(
            config.hook_point.clone(),
            env,
            self.inner.connection_manager.clone(),
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
            self.inner.concurrency,
        )
        .await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(new_handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.inner.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct QuicStackBuilder {
    id: Option<String>,
    bind: Option<String>,
    hook_point: Option<ProcessChainConfigs>,
    certs: Vec<QuicDomainConfig>,
    identity_certs: Option<TlsIdentityCertConfig>,
    alpn_protocols: Vec<Vec<u8>>,
    concurrency: u32,
    reuse_address: bool,
    connection_manager: Option<ConnectionManagerRef>,
    stack_context: Option<Arc<QuicStackContext>>,
    io_dump: Option<IoDumpStackConfig>,
    stream_idle_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
    server_runtime: Option<ServerRuntime>,
}

impl QuicStackBuilder {
    fn new() -> Self {
        QuicStackBuilder {
            id: None,
            bind: None,
            hook_point: None,
            certs: vec![],
            identity_certs: None,
            concurrency: normalize_concurrency(DEFAULT_QUIC_CONCURRENCY),
            alpn_protocols: vec![],
            reuse_address: false,
            connection_manager: None,
            stack_context: None,
            io_dump: None,
            stream_idle_timeout: stream_idle_timeout_from_secs(None),
            connect_timeout: connect_timeout_from_secs(None),
            server_runtime: None,
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    pub fn bind(mut self, bind: &str) -> Self {
        self.bind = Some(bind.to_string());
        self
    }

    pub fn hook_point(mut self, hook_point: ProcessChainConfigs) -> Self {
        self.hook_point = Some(hook_point);
        self
    }

    pub fn add_certs(mut self, certs: Vec<QuicDomainConfig>) -> Self {
        self.certs = certs;
        self
    }

    pub(crate) fn identity_certs(mut self, identity_certs: Option<TlsIdentityCertConfig>) -> Self {
        self.identity_certs = identity_certs;
        self
    }

    pub fn concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = normalize_concurrency(concurrency);
        self
    }

    pub fn alpn_protocols(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn;
        self
    }

    pub fn connection_manager(mut self, connection_manager: ConnectionManagerRef) -> Self {
        self.connection_manager = Some(connection_manager);
        self
    }

    pub fn reuse_address(mut self, reuse_address: bool) -> Self {
        self.reuse_address = reuse_address;
        self
    }

    pub fn stack_context(mut self, stack_context: Arc<QuicStackContext>) -> Self {
        self.stack_context = Some(stack_context);
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

    pub fn server_runtime(mut self, server_runtime: ServerRuntime) -> Self {
        self.server_runtime = Some(server_runtime);
        self
    }

    pub async fn build(self) -> StackResult<QuicStack> {
        QuicStack::create(self).await
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QuicStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    pub concurrency: Option<u32>,
    pub hook_point: Vec<ProcessChainConfig>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_manager: Option<TlsIdentityManagerConfig>,
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

impl StackConfig for QuicStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Quic
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

pub struct QuicStackFactory {
    connection_manager: ConnectionManagerRef,
    server_runtime: ServerRuntime,
}

impl QuicStackFactory {
    pub fn new(connection_manager: ConnectionManagerRef, server_runtime: ServerRuntime) -> Self {
        Self {
            connection_manager,
            server_runtime,
        }
    }
}

#[async_trait::async_trait]
impl StackFactory for QuicStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<QuicStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid quic stack config"
            ))?;
        let identity_certs =
            build_identity_cert_config(&config.hosts, config.identity_manager.as_ref())?;
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<QuicStackContext>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid quic stack context"
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
        let stack = QuicStack::builder()
            .id(config.id.clone())
            .bind(config.bind.to_string().as_str())
            .connection_manager(self.connection_manager.clone())
            .hook_point(config.hook_point.clone())
            .identity_certs(identity_certs)
            .alpn_protocols(
                config
                    .alpn_protocols
                    .clone()
                    .unwrap_or(vec![])
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect(),
            )
            .concurrency(config.concurrency.unwrap_or(DEFAULT_QUIC_CONCURRENCY))
            .stack_context(stack_context.clone())
            .io_dump(io_dump)
            .stream_idle_timeout(stream_idle_timeout_from_secs(config.stream_idle_timeout))
            .connect_timeout(connect_timeout_from_secs(config.connect_timeout))
            .reuse_address(config.reuse_address.unwrap_or(false))
            .server_runtime(self.server_runtime.clone())
            .build()
            .await?;
        Ok(Arc::new(stack))
    }
}

#[cfg(test)]
mod tests {
    use crate::global_process_chains::{GlobalProcessChains, GlobalProcessChainsRef};
    use crate::{
        ConnectionManager, DefaultLimiterManager, GlobalCollectionManager,
        GlobalCollectionManagerRef, LimiterManagerRef, ProcessChainConfigs, ProcessChainHttpServer,
        QuicDomainConfig, QuicStack, QuicStackConfig, QuicStackContext, QuicStackFactory,
        SelfCertConfig, SelfCertMgr, SelfCertMgrRef, Server, ServerManager, ServerManagerRef,
        ServerErrorCode, ServerResult, Stack, StackContext, StackFactory, StackProtocol,
        StatManager, StatManagerRef, StreamInfo, StreamServer, TunnelManager,
        create_io_dump_stack_config, decode_io_dump_frames, server_err,
    };
    use buckyos_kit::AsyncStream;
    use h3::error::{ConnectionError, StreamError};
    use quinn::Endpoint;
    use quinn::crypto::rustls::QuicClientConfig;
    use rcgen::generate_simple_self_signed;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn build_quic_context(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        self_cert_mgr: SelfCertMgrRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
    ) -> Arc<QuicStackContext> {
        Arc::new(QuicStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            self_cert_mgr,
            global_process_chains,
            global_collection_manager,
            None,
        ))
    }

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

    #[tokio::test]
    async fn test_quic_stack_creation() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let result = QuicStack::builder().build().await;
        assert!(result.is_err());
        let result = QuicStack::builder().bind("127.0.0.1:9080").build().await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .build()
            .await;
        assert!(result.is_err());
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .build()
            .await;
        assert!(result.is_err());
        let servers = Arc::new(ServerManager::new());
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default())
            .await
            .unwrap();
        let stack_context = build_quic_context(
            servers.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            self_cert_mgr.clone(),
            None,
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack_context = build_quic_context(
            servers.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            self_cert_mgr.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9080")
            .hook_point(vec![])
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_stack_reject() {
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

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9180")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9180".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_quic_stack_drop() {
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

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9181")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9181".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_quic_stack_self_cert() {
        let _subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let tls_self_certs_path = tempfile::env::temp_dir()
            .join("quic_self_certs")
            .to_string_lossy()
            .to_string();
        let mut self_cert_config = SelfCertConfig::default();
        self_cert_config.store_path = tls_self_certs_path.clone();

        let stack_context = build_quic_context(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(self_cert_config).await.unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9193")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "*".to_string(),
                certs: None,
                key: None,
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9193".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send
            .write_all(b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
            .await;
        assert!(result.is_ok());
        let ret = recv.read(&mut [0; 1024]).await;
        assert!(ret.is_err());

        tokio::fs::remove_dir_all(tls_self_certs_path)
            .await
            .unwrap();
    }

    pub struct MockServer {
        id: String,
    }

    impl MockServer {
        pub fn new(id: String) -> Self {
            MockServer { id }
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

    #[tokio::test]
    async fn test_quic_stack_server() {
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

        let tunnel_manager = TunnelManager::new();

        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockServer::new(
            "www.buckyos.com".to_string(),
        ))));
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9185")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");

        let ret = endpoint
            .connect("127.0.0.1:9185".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_http3_server() {
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

        let tunnel_manager = TunnelManager::new();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9186")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .alpn_protocols(vec![b"h2".to_vec(), b"h3".to_vec()])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(
                std::future::poll_fn(|cx| driver.poll_close(cx)).await,
            );
        };

        let request = async move {
            let req = http::Request::builder()
                .uri("https://www.buckyos.com/")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, _drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());

        let ret = endpoint
            .connect("127.0.0.1:9186".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let quinn_conn = h3_quinn::Connection::new(ret);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let drive = async move {
            return Err::<(), ConnectionError>(
                std::future::poll_fn(|cx| driver.poll_close(cx)).await,
            );
        };

        let request = async move {
            let req = http::Request::builder()
                .uri("https://www.buckyos.com/")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await?;

            stream.finish().await?;
            let resp = stream.recv_response().await?;

            assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
            assert_eq!(resp.version(), http::Version::HTTP_3);

            Ok::<_, StreamError>(())
        };

        let (req_res, _drive_res) = tokio::join!(request, drive);

        assert!(req_res.is_ok());
    }

    #[tokio::test]
    async fn test_quic_io_dump_raw_single_roundtrip() {
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
        let ctx = build_quic_context(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("quic_raw.dump");
        let io_dump = create_io_dump_stack_config(
            "quic_raw",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let stack = QuicStack::builder()
            .id("quic-raw")
            .bind("127.0.0.1:9197")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(ctx)
            .io_dump(io_dump)
            .server_runtime(test_server_runtime())
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect("127.0.0.1:9197".parse().unwrap(), "www.buckyos.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");
        send.finish().unwrap();
        drop(send);
        drop(recv);
        conn.close(0u32.into(), b"done");

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"test" && f.download == b"recv")
        );
    }

    #[tokio::test]
    async fn test_quic_io_dump_raw_flush_on_upload_limit() {
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
        let ctx = build_quic_context(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("quic_raw_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "quic_raw_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("2B"),
            None,
        )
        .await
        .unwrap();
        let stack = QuicStack::builder()
            .id("quic-raw-limit")
            .bind("127.0.0.1:9199")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(ctx)
            .io_dump(io_dump)
            .server_runtime(test_server_runtime())
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect("127.0.0.1:9199".parse().unwrap(), "www.buckyos.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
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
                    if let Err(e) = stream.read_exact(&mut b).await {
                        if req.is_empty() {
                            return Ok(());
                        }
                        return Err(server_err!(
                            ServerErrorCode::StreamError,
                            "failed to read keep-alive request: {e}"
                        ));
                    }
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
                stream.write_all(resp.as_bytes()).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::StreamError,
                        "failed to write keep-alive response headers: {e}"
                    )
                })?;
                stream.write_all(body).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::StreamError,
                        "failed to write keep-alive response body: {e}"
                    )
                })?;
            }
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[tokio::test]
    async fn test_quic_io_dump_http_multi_requests_same_connection() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
            id: "www.buckyos.com".to_string(),
        })));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let ctx = build_quic_context(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("quic_http.dump");
        let io_dump = create_io_dump_stack_config(
            "quic_http",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let stack = QuicStack::builder()
            .id("quic-http")
            .bind("127.0.0.1:9198")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(ctx)
            .io_dump(io_dump)
            .server_runtime(test_server_runtime())
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect("127.0.0.1:9198".parse().unwrap(), "www.buckyos.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let n = recv.read(&mut tmp).await.unwrap();
        assert!(matches!(n, Some(v) if v > 0));
        send.write_all(b"GET /b HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let n = recv.read(&mut tmp).await.unwrap();
        assert!(matches!(n, Some(v) if v > 0));

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

    #[tokio::test]
    async fn test_quic_io_dump_http_flush_on_upload_limit() {
        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let _ = server_manager.add_server(Server::Stream(Arc::new(MockHttpKeepAliveServer {
            id: "www.buckyos.com".to_string(),
        })));

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(
            "- id: main\n  priority: 1\n  blocks:\n    - id: main\n      block: |\n        return \"server www.buckyos.com\";\n",
        )
        .unwrap();
        let ctx = build_quic_context(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let dump = dir.path().join("quic_http_limit.dump");
        let io_dump = create_io_dump_stack_config(
            "quic_http_limit",
            Some(dump.to_string_lossy().as_ref()),
            None,
            None,
            Some("4B"),
            None,
        )
        .await
        .unwrap();
        let stack = QuicStack::builder()
            .id("quic-http-limit")
            .bind("127.0.0.1:9200")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(ctx)
            .io_dump(io_dump)
            .server_runtime(test_server_runtime())
            .build()
            .await
            .unwrap();
        stack.start().await.unwrap();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect("127.0.0.1:9200".parse().unwrap(), "www.buckyos.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"GET /a HTTP/1.1\r\nHost: www.buckyos.com\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let n = recv.read(&mut tmp).await.unwrap();
        assert!(matches!(n, Some(v) if v > 0));

        let frames = wait_dump_frames(&dump, 1).await;
        assert!(
            frames
                .iter()
                .any(|f| f.upload == b"GET " && f.download.is_empty())
        );
    }

    #[tokio::test]
    async fn test_quic_server_forward() {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///127.0.0.1:9183";
        "#;

        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();

        let subject_alt_names = vec!["www.buckyos.com".to_string(), "127.0.0.1".to_string()];
        let cert_key = generate_simple_self_signed(subject_alt_names).unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let tunnel_manager = TunnelManager::new();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9188")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::spawn(async move {
            let tcp_listener = TcpListener::bind("127.0.0.1:9183").await.unwrap();
            if let Ok((mut tcp_stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 4];
                tcp_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"test");
                tcp_stream.write_all("recv".as_bytes()).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9188".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
    }

    #[tokio::test]
    async fn test_quic_stack_stat_server() {
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

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9189")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9189".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);

        let ret = endpoint
            .connect("127.0.0.1:9189".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_limit_server() {
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

        let tunnel_manager = TunnelManager::new();

        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "www.buckyos.com".to_string(),
            ))))
            .unwrap();
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            Arc::new(DefaultLimiterManager::new()),
            stat_manager.clone(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9190")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9190".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint
            .connect("127.0.0.1:9190".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_group_limit_server() {
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

        let tunnel_manager = TunnelManager::new();

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
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9191")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9191".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint
            .connect("127.0.0.1:9191".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
    }

    #[tokio::test]
    async fn test_quic_stack_stat_group_limit_server2() {
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

        let tunnel_manager = TunnelManager::new();

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
        let stack_context = build_quic_context(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager.clone(),
            SelfCertMgr::create(SelfCertConfig::default())
                .await
                .unwrap(),
            Some(Arc::new(GlobalProcessChains::new())),
            None,
        );
        let result = QuicStack::builder()
            .id("test")
            .bind("127.0.0.1:9192")
            .hook_point(chains)
            .add_certs(vec![QuicDomainConfig {
                domain: "www.buckyos.com".to_string(),
                certs: Some(vec![cert_key.cert.der().clone()]),
                key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert_key.signing_key.serialize_der(),
                ))),
            }])
            .stack_context(stack_context)
            .server_runtime(test_server_runtime())
            .build()
            .await;
        assert!(result.is_ok());
        let stack = result.unwrap();
        let result = stack.start().await;
        assert!(result.is_ok());

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        config.enable_early_data = true;
        // config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config).unwrap()));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let ret = endpoint
            .connect("127.0.0.1:9192".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let start = Instant::now();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        ret.unwrap();
        // assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        let test_stat = stat_manager.get_speed_stat("test");
        assert!(test_stat.is_some());
        let test_stat = test_stat.unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
        assert!(start.elapsed().as_millis() < 2500);

        let ret = endpoint
            .connect("127.0.0.1:9192".parse().unwrap(), "www.buckyos.com")
            .unwrap();
        let ret = ret.await.unwrap();
        let (mut send, mut recv) = ret.open_bi().await.unwrap();
        let result = send.write_all(b"test").await;
        assert!(result.is_ok());

        let mut buf = [0u8; 4];
        let ret = recv.read_exact(&mut buf).await;
        assert!(ret.is_ok());
        assert_eq!(&buf, b"recv");
        assert_eq!(test_stat.get_read_sum_size(), 8);
        assert_eq!(test_stat.get_write_sum_size(), 8);
        assert!(start.elapsed().as_millis() > 3800);
        assert!(start.elapsed().as_millis() < 4500);
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

        let factory = QuicStackFactory::new(ConnectionManager::new(), test_server_runtime());

        let config = QuicStackConfig {
            id: "test".to_string(),
            protocol: StackProtocol::Quic,
            bind: "127.0.0.1:3345".parse().unwrap(),
            concurrency: None,
            hook_point: vec![],
            hosts: vec![],
            identity_manager: None,
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
        let stack_context: Arc<dyn StackContext> = Arc::new(QuicStackContext::new(
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
    fn test_quic_stack_config_uses_identity_hosts() {
        let config: QuicStackConfig = serde_yaml_ng::from_str(
            r#"
id: quic_test
protocol: quic
bind: 127.0.0.1:4433
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

        assert_eq!(config.hosts, vec!["example.com", "*.example.org"]);
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
}
