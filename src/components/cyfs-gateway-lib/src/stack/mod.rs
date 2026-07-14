mod limiter;
mod proxy_protocol;
mod quic_stack;
mod rtcp_stack;
mod stack;
mod tcp_stack;
mod tls_cert_resolver;
mod tls_stack;
mod udp_stack;

use buckyos_kit::AsyncStream;
use cyfs_process_chain::CollectionValue;
pub use limiter::*;
pub use proxy_protocol::*;
pub use quic_stack::*;
pub use rtcp_stack::*;
pub use stack::*;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
pub use tcp_stack::*;
pub(crate) use tls_cert_resolver::*;
pub use tls_stack::*;
pub use udp_stack::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StackErrorCode {
    Failed,
    BindFailed,
    ProcessChainError,
    InvalidConfig,
    TunnelError,
    StreamError,
    InvalidTlsKey,
    InvalidTlsCert,
    ServerError,
    IoError,
    QuicError,
    UnsupportedStackProtocol,
    InvalidData,
    PermissionDenied,
    ListenFailed,
    AlreadyExists,
    BindUnmatched,
}
pub type StackResult<T> = sfo_result::Result<T, StackErrorCode>;
pub type StackError = sfo_result::Error<StackErrorCode>;
use crate::forward::{
    ForwardFailureRegistry, ForwardPlan, NextUpstreamCondition, NextUpstreamPolicy,
    apply_least_time_via_tunnel_mgr,
};
use crate::{DatagramClientBox, TunnelManager};
pub use sfo_result::err as stack_err;
pub use sfo_result::into_err as into_stack_err;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{Instant, sleep_until, timeout};
use url::Url;

pub const DEFAULT_STREAM_IDLE_TIMEOUT_SECS: u64 = 600;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 60;

pub fn stream_idle_timeout_from_secs(timeout_secs: Option<u64>) -> Duration {
    Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_STREAM_IDLE_TIMEOUT_SECS))
}

pub fn connect_timeout_from_secs(timeout_secs: Option<u64>) -> Duration {
    Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS))
}

/// Insert a `<prefix>addr` / `<prefix>ip` / `<prefix>port` group into a REQ
/// map collection. `prefix` is a source-layer prefix such as `source_`,
/// `conn_source_` or `real_source_`.
pub async fn insert_req_source_addr_group(
    map: &cyfs_process_chain::MapCollectionRef,
    prefix: &str,
    addr: std::net::SocketAddr,
) -> StackResult<()> {
    for (suffix, value) in [
        ("addr", addr.to_string()),
        ("ip", addr.ip().to_string()),
        ("port", addr.port().to_string()),
    ] {
        map.insert(
            format!("{}{}", prefix, suffix).as_str(),
            CollectionValue::String(value),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
    }
    Ok(())
}

pub async fn get_source_addr_from_req_env(
    global_env: &cyfs_process_chain::EnvRef,
) -> Option<String> {
    let req = match global_env.get("REQ").await {
        Ok(Some(req)) => req,
        _ => return None,
    };

    let req = match req.into_map() {
        Some(req) => req,
        None => return None,
    };

    let ext = match req.get("ext").await {
        Ok(Some(CollectionValue::Map(ext))) => ext,
        _ => return None,
    };
    let source = match ext.get("proxy_source_addr").await {
        Ok(Some(source)) => source,
        _ => return None,
    };

    match source {
        CollectionValue::String(addr) => Some(addr),
        _ => None,
    }
}

pub async fn stream_forward(
    mut stream: Box<dyn AsyncStream>,
    target: &str,
    tunnel_manager: &TunnelManager,
    info: Option<&crate::StreamInfo>,
    idle_timeout: Duration,
    connect_timeout: Duration,
) -> StackResult<()> {
    let url = Url::parse(target).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "invalid forward url {}",
        target
    ))?;
    // Opt-in PROXY v2: `?proxy_protocol=v2` on the forward URL.
    // Without opt-in we stay transparent to non-PROXY-aware downstreams.
    let emit_proxy_v2 = url
        .query_pairs()
        .any(|(k, v)| k == "proxy_protocol" && v.eq_ignore_ascii_case("v2"));

    let mut forward_stream =
        match timeout(connect_timeout, tunnel_manager.open_stream_by_url(&url)).await {
            Ok(result) => result.map_err(into_stack_err!(StackErrorCode::TunnelError))?,
            Err(_) => {
                return Err(stack_err!(
                    StackErrorCode::TunnelError,
                    "connect target {} timeout after {:?}",
                    target,
                    connect_timeout
                ));
            }
        };

    if emit_proxy_v2 {
        if let Some(info) = info {
            let src_addr = info.src_addr.as_deref();
            let dst_addr = info.dst_addr.as_deref();
            let _ =
                proxy_protocol::write_proxy_v2_preamble(&mut forward_stream, src_addr, dst_addr)
                    .await?;
        }
    }

    sfo_io::copy_bidirectional_with_timeout(&mut stream, forward_stream.as_mut(), idle_timeout)
        .await
        .map_err(into_stack_err!(
            StackErrorCode::StreamError,
            "target {target}"
        ))?;
    Ok(())
}

/// Walk the candidate list of a `ForwardPlan` until we successfully open a
/// stream tunnel, then run `copy_bidirectional`. Retries are connection-stage
/// only — once a candidate has been opened we never silently fail over.
///
/// Implements §6.4 of `forward机制升级需求.md`. Honors `policy.timeout`
/// as a wall-clock budget that caps the total cost of all candidate
/// attempts (§6.3 "next_upstream_tries 和 next_upstream_timeout 必须限
/// 制单次请求的最大尝试成本"). The timer starts before the first
/// attempt and any remaining slice is passed to `tokio::time::timeout`
/// per attempt, so a slow candidate cannot blow past the budget.
pub async fn stream_forward_group(
    stream: Box<dyn AsyncStream>,
    plan: &ForwardPlan,
    tunnel_manager: &TunnelManager,
    info: Option<&crate::StreamInfo>,
) -> StackResult<()> {
    // Stage 4: re-order plan candidates by RTT before iterating when
    // the plan asked for least-time selection. Best-effort: any failure
    // in tunnel_mgr leaves the original order untouched.
    let mut plan_local;
    let plan: &ForwardPlan = if matches!(plan.balance, crate::forward::BalanceMethod::LeastTime) {
        plan_local = plan.clone();
        apply_least_time_via_tunnel_mgr(&mut plan_local, tunnel_manager).await;
        &plan_local
    } else {
        plan
    };
    let registry = ForwardFailureRegistry::global();
    let group_key = plan.failure_state_key();
    let policy = &plan.next_upstream;
    let max_attempts = policy_max_attempts(policy, plan.candidates.len());
    let deadline = policy.timeout.map(|d| std::time::Instant::now() + d);

    let mut last_err: Option<StackError> = None;
    let mut last_target_url: Option<String> = None;
    let mut chosen: Option<(usize, Box<dyn AsyncStream>, String, bool)> = None;

    for (idx, candidate) in plan.candidates.iter().enumerate() {
        if idx >= max_attempts {
            break;
        }
        // Bail before issuing the next attempt if we're already out of
        // budget — even if `tries` would still allow another. This keeps
        // a long candidate list from amortizing a tight timeout into
        // many failed but cheap attempts that still over-shoot.
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                last_err.get_or_insert_with(|| {
                    stack_err!(
                        StackErrorCode::TunnelError,
                        "forward-group {} next_upstream timeout exceeded before idx={}",
                        group_key,
                        idx
                    )
                });
                break;
            }
        }

        let url = match Url::parse(&candidate.url) {
            Ok(u) => u,
            Err(e) => {
                let err = stack_err!(
                    StackErrorCode::InvalidConfig,
                    "invalid forward url {}: {}",
                    candidate.url,
                    e
                );
                last_err = Some(err);
                last_target_url = Some(candidate.url.clone());
                registry.record_failure(
                    &group_key,
                    &candidate.url,
                    candidate.max_fails,
                    candidate.fail_timeout,
                );
                if !should_continue(policy, idx, max_attempts, NextUpstreamCondition::Error) {
                    break;
                }
                continue;
            }
        };

        let emit_proxy_v2 = url
            .query_pairs()
            .any(|(k, v)| k == "proxy_protocol" && v.eq_ignore_ascii_case("v2"));

        let attempt = tunnel_manager.open_stream_by_url(&url);
        let (result, cond) = match deadline {
            Some(d) => {
                let remaining = d.saturating_duration_since(std::time::Instant::now());
                match tokio::time::timeout(remaining, attempt).await {
                    Ok(r) => (
                        r.map_err(|e| crate::TunnelError::ConnectError(e.to_string())),
                        NextUpstreamCondition::Error,
                    ),
                    Err(_) => (
                        Err(crate::TunnelError::ConnectError(format!(
                            "next_upstream timeout exceeded ({}ms budget) on {}",
                            policy.timeout.unwrap_or_default().as_millis(),
                            candidate.url,
                        ))),
                        NextUpstreamCondition::Timeout,
                    ),
                }
            }
            None => (
                attempt
                    .await
                    .map_err(|e| crate::TunnelError::ConnectError(e.to_string())),
                NextUpstreamCondition::Error,
            ),
        };

        match result {
            Ok(forward_stream) => {
                registry.record_success(&group_key, &candidate.url);
                chosen = Some((idx, forward_stream, candidate.url.clone(), emit_proxy_v2));
                break;
            }
            Err(e) => {
                let err = stack_err!(
                    StackErrorCode::TunnelError,
                    "open upstream {} failed: {}",
                    candidate.url,
                    e
                );
                log::debug!(
                    "forward-group {}: candidate {} (idx {}) failed to open: {}",
                    group_key,
                    candidate.url,
                    idx,
                    err
                );
                registry.record_failure(
                    &group_key,
                    &candidate.url,
                    candidate.max_fails,
                    candidate.fail_timeout,
                );
                last_err = Some(err);
                last_target_url = Some(candidate.url.clone());
                if !should_continue(policy, idx, max_attempts, cond) {
                    break;
                }
            }
        }
    }

    let (idx, mut forward_stream, target_url, emit_proxy_v2) = match chosen {
        Some(v) => v,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                stack_err!(
                    StackErrorCode::TunnelError,
                    "forward-group {} exhausted candidates",
                    group_key
                )
            }));
        }
    };

    log::debug!(
        "forward-group {}: selected candidate idx={} url={}",
        group_key,
        idx,
        target_url
    );

    let mut stream = stream;
    if emit_proxy_v2 {
        if let Some(info) = info {
            let src_addr = info.src_addr.as_deref();
            let dst_addr = info.dst_addr.as_deref();
            let _ =
                proxy_protocol::write_proxy_v2_preamble(&mut forward_stream, src_addr, dst_addr)
                    .await?;
        }
    }

    tokio::io::copy_bidirectional(&mut stream, forward_stream.as_mut())
        .await
        .map_err(into_stack_err!(
            StackErrorCode::StreamError,
            "target {target_url}"
        ))?;

    let _ = last_target_url; // suppress unused
    Ok(())
}

pub async fn datagram_forward(
    datagram: Box<dyn DatagramClientBox>,
    target: &str,
    tunnel_manager: &TunnelManager,
    idle_timeout: Duration,
    connect_timeout: Duration,
) -> StackResult<()> {
    let url = Url::parse(&target).map_err(into_stack_err!(
        StackErrorCode::InvalidConfig,
        "invalid forward url {}",
        target
    ))?;
    let forward_datagram = match timeout(
        connect_timeout,
        tunnel_manager.create_datagram_client_by_url(&url),
    )
    .await
    {
        Ok(result) => result.map_err(into_stack_err!(StackErrorCode::TunnelError))?,
        Err(_) => {
            return Err(stack_err!(
                StackErrorCode::TunnelError,
                "connect target {} timeout after {:?}",
                target,
                connect_timeout
            ));
        }
    };

    copy_datagram_bidirectional(datagram, forward_datagram, idle_timeout)
        .await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;
    Ok(())
}

/// Walk the candidate list of a `ForwardPlan` for datagram forwarding.
/// Connection-stage retry only: once a datagram client has been created, a
/// failure inside `copy_datagram_bidirectional` is propagated, never retried
/// transparently. Implements §6.5. Honors `policy.timeout` as a wall-clock
/// budget (see `stream_forward_group`).
pub async fn datagram_forward_group(
    datagram: Box<dyn DatagramClientBox>,
    plan: &ForwardPlan,
    tunnel_manager: &TunnelManager,
) -> StackResult<()> {
    let mut plan_local;
    let plan: &ForwardPlan = if matches!(plan.balance, crate::forward::BalanceMethod::LeastTime) {
        plan_local = plan.clone();
        apply_least_time_via_tunnel_mgr(&mut plan_local, tunnel_manager).await;
        &plan_local
    } else {
        plan
    };
    let registry = ForwardFailureRegistry::global();
    let group_key = plan.failure_state_key();
    let policy = &plan.next_upstream;
    let max_attempts = policy_max_attempts(policy, plan.candidates.len());
    let deadline = policy.timeout.map(|d| std::time::Instant::now() + d);

    let mut last_err: Option<StackError> = None;
    let mut chosen: Option<(usize, Box<dyn DatagramClientBox>, String)> = None;

    for (idx, candidate) in plan.candidates.iter().enumerate() {
        if idx >= max_attempts {
            break;
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                last_err.get_or_insert_with(|| {
                    stack_err!(
                        StackErrorCode::TunnelError,
                        "forward-group {} next_upstream timeout exceeded before idx={}",
                        group_key,
                        idx
                    )
                });
                break;
            }
        }
        let url = match Url::parse(&candidate.url) {
            Ok(u) => u,
            Err(e) => {
                let err = stack_err!(
                    StackErrorCode::InvalidConfig,
                    "invalid forward url {}: {}",
                    candidate.url,
                    e
                );
                last_err = Some(err);
                registry.record_failure(
                    &group_key,
                    &candidate.url,
                    candidate.max_fails,
                    candidate.fail_timeout,
                );
                if !should_continue(policy, idx, max_attempts, NextUpstreamCondition::Error) {
                    break;
                }
                continue;
            }
        };
        let attempt = tunnel_manager.create_datagram_client_by_url(&url);
        let (result, cond) = match deadline {
            Some(d) => {
                let remaining = d.saturating_duration_since(std::time::Instant::now());
                match tokio::time::timeout(remaining, attempt).await {
                    Ok(r) => (
                        r.map_err(|e| crate::TunnelError::ConnectError(e.to_string())),
                        NextUpstreamCondition::Error,
                    ),
                    Err(_) => (
                        Err(crate::TunnelError::ConnectError(format!(
                            "next_upstream timeout exceeded ({}ms budget) on {}",
                            policy.timeout.unwrap_or_default().as_millis(),
                            candidate.url,
                        ))),
                        NextUpstreamCondition::Timeout,
                    ),
                }
            }
            None => (
                attempt
                    .await
                    .map_err(|e| crate::TunnelError::ConnectError(e.to_string())),
                NextUpstreamCondition::Error,
            ),
        };
        match result {
            Ok(client) => {
                registry.record_success(&group_key, &candidate.url);
                chosen = Some((idx, client, candidate.url.clone()));
                break;
            }
            Err(e) => {
                let err = stack_err!(
                    StackErrorCode::TunnelError,
                    "create datagram client {} failed: {}",
                    candidate.url,
                    e
                );
                log::debug!(
                    "forward-group {}: datagram candidate {} (idx {}) failed: {}",
                    group_key,
                    candidate.url,
                    idx,
                    err
                );
                registry.record_failure(
                    &group_key,
                    &candidate.url,
                    candidate.max_fails,
                    candidate.fail_timeout,
                );
                last_err = Some(err);
                if !should_continue(policy, idx, max_attempts, cond) {
                    break;
                }
            }
        }
    }

    let (_idx, forward_datagram, _target) = match chosen {
        Some(v) => v,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                stack_err!(
                    StackErrorCode::TunnelError,
                    "forward-group {} exhausted datagram candidates",
                    group_key
                )
            }));
        }
    };

    copy_datagram_bidirectional(datagram, forward_datagram, stream_idle_timeout_from_secs(None))
        .await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;
    Ok(())
}

fn policy_max_attempts(policy: &NextUpstreamPolicy, candidate_count: usize) -> usize {
    if !policy.is_enabled() {
        return candidate_count.min(1).max(1);
    }
    let tries = policy.tries as usize;
    if tries == 0 {
        candidate_count
    } else {
        tries.min(candidate_count)
    }
}

fn should_continue(
    policy: &NextUpstreamPolicy,
    attempted_idx: usize,
    max_attempts: usize,
    cond: NextUpstreamCondition,
) -> bool {
    if !policy.is_enabled() {
        return false;
    }
    if !policy.allows(cond) {
        return false;
    }
    attempted_idx + 1 < max_attempts
}

pub async fn copy_datagram_bidirectional(
    a: Box<dyn DatagramClientBox>,
    b: Box<dyn DatagramClientBox>,
    idle_timeout: Duration,
) -> Result<(), std::io::Error> {
    async fn copy_datagram_one_way(
        recv: Box<dyn DatagramClientBox>,
        send: Box<dyn DatagramClientBox>,
        last_active: Arc<Mutex<Instant>>,
        active_notify: Arc<Notify>,
    ) -> Result<(), std::io::Error> {
        loop {
            let mut buf = [0u8; 4096];
            let n = recv.recv_datagram(&mut buf).await?;
            send.send_datagram(&buf[..n]).await?;

            *last_active.lock().unwrap() = Instant::now();
            active_notify.notify_waiters();
        }
    }

    async fn idle_timeout_guard(
        idle_timeout: Duration,
        last_active: Arc<Mutex<Instant>>,
        active_notify: Arc<Notify>,
    ) -> Result<(), std::io::Error> {
        loop {
            let deadline = *last_active.lock().unwrap() + idle_timeout;
            tokio::select! {
                _ = sleep_until(deadline) => {
                    if last_active.lock().unwrap().elapsed() >= idle_timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "datagram copy idle timeout",
                        ));
                    }
                }
                _ = active_notify.notified() => {}
            }
        }
    }

    let last_active = Arc::new(Mutex::new(Instant::now()));
    let active_notify = Arc::new(Notify::new());

    let recv = copy_datagram_one_way(
        a.clone(),
        b.clone(),
        last_active.clone(),
        active_notify.clone(),
    );
    let send = copy_datagram_one_way(b, a, last_active.clone(), active_notify.clone());
    let timeout = idle_timeout_guard(idle_timeout, last_active, active_notify);

    let ret = tokio::try_join!(recv, send, timeout);
    ret?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct PendingDatagram;

    #[async_trait::async_trait]
    impl crate::DatagramClient for PendingDatagram {
        async fn recv_datagram(&self, _buffer: &mut [u8]) -> Result<usize, std::io::Error> {
            std::future::pending::<Result<usize, std::io::Error>>().await
        }

        async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, std::io::Error> {
            Ok(buffer.len())
        }
    }

    #[tokio::test]
    async fn copy_datagram_bidirectional_times_out_when_idle() {
        let err = copy_datagram_bidirectional(
            Box::new(PendingDatagram),
            Box::new(PendingDatagram),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn sockaddr_to_socket_addr(
    addr: &libc::sockaddr_storage,
) -> std::io::Result<std::net::SocketAddr> {
    unsafe {
        match (*addr).ss_family as i32 {
            libc::AF_INET => {
                let addr_in: *const libc::sockaddr_in =
                    addr as *const _ as *const libc::sockaddr_in;
                // 转换端口：网络字节序 -> 主机字节序
                let port = u16::from_be((*addr_in).sin_port);
                // 转换 IPv4 地址：网络字节序的 u32 -> Ipv4Addr
                // Ipv4Addr::from 直接接收一个 u32，并按网络字节序解释
                let ip_addr = std::net::Ipv4Addr::from((*addr_in).sin_addr.s_addr.to_le_bytes());
                Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    ip_addr, port,
                )))
            }
            libc::AF_INET6 => {
                let addr_in6: *const libc::sockaddr_in6 =
                    addr as *const _ as *const libc::sockaddr_in6;
                // 转换端口：网络字节序 -> 主机字节序
                let port = u16::from_be((*addr_in6).sin6_port);
                // 转换 IPv6 地址：直接使用 libc::sockaddr_in6 中的 sin6_addr 字段
                // sin6_addr 是一个包含 16 个 u8 的数组，表示 IPv6 地址的 128 位
                let segments = (*addr_in6).sin6_addr.s6_addr;
                let ipv6_addr = std::net::Ipv6Addr::from(segments);
                Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    ipv6_addr,
                    port,
                    (*addr_in6).sin6_flowinfo,
                    (*addr_in6).sin6_scope_id,
                )))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "addr family must be either AF_INET or AF_INET6",
            )), // 未知地址族
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_opt<T: AsRawFd, V>(
    socket: &T,
    level: libc::c_int,
    name: libc::c_int,
    optval: V,
) -> StackResult<()> {
    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &optval as *const _ as *mut libc::c_void,
            std::mem::size_of::<V>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(stack_err!(
                StackErrorCode::IoError,
                "setsockopt error {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn get_socket_opt<T: AsRawFd, V>(
    socket: &T,
    level: libc::c_int,
    name: libc::c_int,
    optval: &mut V,
) -> StackResult<libc::socklen_t> {
    unsafe {
        let mut len = std::mem::size_of::<V>() as libc::socklen_t;
        let ret = libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            optval as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(stack_err!(
                StackErrorCode::IoError,
                "getsockopt error {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(len)
    }
}

#[cfg(target_os = "linux")]
fn get_destination_addr(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    unsafe {
        let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let rcmsg = &*cmsg;
            match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );

                    return Some(dst_addr);
                }
                (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );

                    return Some(dst_addr);
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    None
}

#[cfg(target_os = "linux")]
pub(crate) fn recv_from<T: AsRawFd>(
    socket: &T,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr, std::net::SocketAddr)> {
    unsafe {
        let mut control_buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of_val(&src_addr) as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len() as libc::size_t,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        msg.msg_control = control_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = TryFrom::try_from(control_buf.len())
            .expect("failed to convert usize to msg_controllen");

        let fd = socket.as_raw_fd();
        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let dst_addr = match get_destination_addr(&msg) {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing destination address in msghdr",
                ));
            }
            Some(d) => d,
        };

        Ok((
            ret as usize,
            sockaddr_to_socket_addr(&src_addr)?,
            sockaddr_to_socket_addr(&dst_addr)?,
        ))
    }
}

#[cfg(target_os = "linux")]
fn has_root_privileges() -> bool {
    // 获取当前进程的有效用户ID (EUID)
    let euid: libc::uid_t = unsafe { libc::geteuid() };
    // Root 用户的 UID 为 0
    euid == 0
}
