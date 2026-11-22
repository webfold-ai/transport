//! The userspace TCP plane: accept, admit, (optionally) read a trusted PROXY header, pick a
//! backend for the NEW flow, connect, pin, copy.
//!
//! ## Abuse story (the listener is public)
//!
//! * The kernel handles SYN floods (SYN cookies, the listen backlog; see `docs/tas-lb.md` for the
//!   sysctls). The accept loop does the minimum per connection and never blocks: it takes a
//!   *setup permit* (bounded by `max_pending`) or drops the connection with an RST. Everything
//!   slow (PROXY header read, backend connect) happens under the permit and under timeouts, so
//!   a slowloris costs one permit for at most `proxy_header_timeout`, not a thread or a queue slot.
//! * After setup, a connection is a tracked flow bounded globally and per source, rate limited per
//!   source, and subject to an idle timeout (activity in either direction), a write-stall timeout,
//!   and a half-close timeout.
//! * Memory per flow is two sockets and a task plus, only while bytes are actually moving, two
//!   copy buffers (`buffer_bytes`): `max_flows * 2 * buffer_bytes` bounds the buffers.
//!
//! ## Never read payload
//!
//! Bytes are moved between buffers and sockets and counted. They are never parsed (no SNI, no
//! `ClientHello`), logged or put in a metric. The single inspection is a 12-byte prefix compare on
//! the first chunk from an *untrusted* client, to refuse and count a spoofed PROXY v2 signature.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use crate::backend::Lease;
use crate::cidr::CidrSet;
use crate::config::{LimitsConfig, ListenerConfig};
use crate::director::FlowTuple;
use crate::flows::{AdmitError, FlowGuard, FlowKey, Killed, Proto};
use crate::loglimit::unix_now;
use crate::metrics::{Closed, Metrics, Reject, PROXY_IN_LABELS};
use crate::proxy_protocol::{self, ReadError, Transport};
use crate::userspace::Shared;

/// Per-listener context.
pub struct ListenerCtx {
    /// Index in the static config (part of the flow key).
    pub index: u16,
    /// Name, for logs.
    pub name: String,
    /// Port to use on backends.
    pub backend_port: u16,
    /// Senders whose PROXY v2 header is accepted.
    pub trusted: CidrSet,
}

impl ListenerCtx {
    /// Build from config.
    ///
    /// # Errors
    /// The CIDR error if the trust list is bad (validated earlier; defence in depth).
    pub fn new(index: u16, cfg: &ListenerConfig) -> Result<Self, crate::cidr::CidrError> {
        Ok(ListenerCtx {
            index,
            name: cfg.name.clone(),
            backend_port: cfg.backend_port,
            trusted: crate::config::StaticConfig::trusted(cfg)?,
        })
    }
}

/// Bind a TCP listener with an explicit backlog.
///
/// # Errors
/// I/O errors from socket, bind or listen.
pub fn bind(addr: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(addr)?;
    sock.listen(backlog)
}

/// Reset a socket: `SO_LINGER = 0` so that closing sends RST, not FIN.
pub fn reset(s: &TcpStream) {
    let _ = SockRef::from(s).set_linger(Some(Duration::ZERO));
}

fn tune(s: &TcpStream, limits: &LimitsConfig) {
    let _ = s.set_nodelay(true);
    if limits.tcp_keepalive_secs > 0 {
        let ka = TcpKeepalive::new().with_time(Duration::from_secs(limits.tcp_keepalive_secs));
        let _ = SockRef::from(s).set_tcp_keepalive(&ka);
    }
}

/// The accept loop. Returns when `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    lc: Arc<ListenerCtx>,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let pending = Arc::new(Semaphore::new(shared.limits.max_pending));
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.changed() => return,
        };
        let Ok((sock, peer)) = accepted else {
            // EMFILE / ENFILE / ECONNABORTED: count, back off briefly, never spin.
            shared.metrics.accept_errors.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        if shared.shutting_down.load(Ordering::SeqCst) {
            shared.metrics.reject(Reject::ShuttingDown);
            reset(&sock);
            continue;
        }
        if let Ok(permit) = pending.clone().try_acquire_owned() {
            tokio::spawn(handle(shared.clone(), lc.clone(), sock, peer, permit));
        } else {
            shared.metrics.reject(Reject::PendingFull);
            reset(&sock);
        }
    }
}

fn proxy_in_reject(m: &Metrics, label: &str) {
    if let Some(i) = PROXY_IN_LABELS.iter().position(|l| *l == label) {
        m.proxy_in_rejected.inc(i);
    }
}

/// Who is the client? Only a configured trusted sender may tell us; everyone else is who the
/// socket says. `None` means the connection was refused (and reset) here.
async fn resolve_client(
    shared: &Shared,
    lc: &ListenerCtx,
    sock: &mut TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<(SocketAddr, SocketAddr)> {
    if !lc.trusted.contains(peer.ip()) {
        return Some((peer, local));
    }
    let m = &shared.metrics;
    let timeout = Duration::from_millis(shared.limits.proxy_header_timeout_ms);
    let refused = match tokio::time::timeout(timeout, proxy_protocol::read_from(sock)).await {
        Ok(Ok(h)) if h.transport != Transport::Datagram => {
            m.proxy_in_accepted.fetch_add(1, Ordering::Relaxed);
            return Some(h.addrs.unwrap_or((peer, local)));
        }
        Ok(Ok(_)) => "transport_mismatch",
        Ok(Err(ReadError::Parse(e))) => {
            log_refusal(
                shared,
                "proxy header refused from trusted sender",
                lc,
                peer,
                e.label(),
            );
            e.label()
        }
        Ok(Err(ReadError::Io(_))) => "io",
        Err(_) => "timeout",
    };
    proxy_in_reject(m, refused);
    reset(sock);
    None
}

/// Connect to a backend for the NEW flow `tuple`, retrying on distinct backends. Failures are
/// passive health signals. `Err(had_candidate)` says whether any backend was eligible at all.
async fn connect_backend(
    shared: &Shared,
    lc: &ListenerCtx,
    tuple: &FlowTuple,
) -> Result<(Lease, TcpStream), bool> {
    let mut excluded: Vec<u64> = Vec::new();
    let mut had_candidate = false;
    for _ in 0..shared.limits.connect_attempts {
        let Some(lease) = shared.director.select(tuple, &excluded) else {
            break;
        };
        had_candidate = true;
        let backend = lease.backend().clone();
        let addr = SocketAddr::new(backend.ip, lc.backend_port);
        if let Ok(Ok(s)) =
            tokio::time::timeout(shared.limits.connect_timeout(), TcpStream::connect(addr)).await
        {
            if backend.take_failure_flag() {
                shared.director.report(&backend, true, true, Instant::now());
            }
            return Ok((lease, s));
        }
        backend.note_failure();
        shared
            .director
            .report(&backend, false, true, Instant::now());
        excluded.push(backend.serial);
    }
    Err(had_candidate)
}

async fn handle(
    shared: Arc<Shared>,
    lc: Arc<ListenerCtx>,
    mut sock: TcpStream,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
) {
    let m = &shared.metrics;
    let Ok(local) = sock.local_addr() else {
        reset(&sock);
        return;
    };
    tune(&sock, &shared.limits);

    // 1. Who is the client?
    let trusted = lc.trusted.contains(peer.ip());
    let Some((client, dst)) = resolve_client(&shared, &lc, &mut sock, peer, local).await else {
        return;
    };

    // 2. Rate, then capacity.
    if !shared
        .rate
        .allow(client.ip(), u32::try_from(unix_now()).unwrap_or(u32::MAX))
    {
        m.reject(Reject::RateLimited);
        reset(&sock);
        return;
    }
    let reservation = match shared.flows.admit(client.ip()) {
        Ok(r) => r,
        Err(AdmitError::MaxFlows) => {
            m.reject(Reject::MaxFlows);
            reset(&sock);
            return;
        }
        Err(AdmitError::PerSource) => {
            m.reject(Reject::PerSource);
            log_refusal(&shared, "per-source flow limit", &lc, peer, "per_source");
            reset(&sock);
            return;
        }
    };

    // 3. A backend for this NEW flow.
    let tuple = FlowTuple {
        client,
        local: dst,
        proto: Proto::Tcp,
    };
    let (lease, backend_sock) = match connect_backend(&shared, &lc, &tuple).await {
        Ok(x) => x,
        Err(had_candidate) => {
            m.reject(if had_candidate {
                Reject::ConnectFailed
            } else {
                Reject::NoBackend
            });
            reset(&sock);
            return;
        }
    };
    tune(&backend_sock, &shared.limits);

    // 4. Pin. From here the flow's backend is fixed for its whole life.
    let key = FlowKey {
        proto: Proto::Tcp,
        listener: lc.index,
        peer,
    };
    let Ok(mut guard) = reservation.pin(key, lease, None) else {
        reset(&sock);
        return;
    };
    drop(permit); // setup is over; this connection no longer counts against the setup bound
    m.flows.inc(0);

    // 5. Tell the backend who the client is.
    if guard.send_proxy() {
        let hdr = proxy_protocol::encode(client, dst, Transport::Stream);
        let stall = Duration::from_secs(shared.limits.write_stall_timeout_secs);
        let act = Activity::new();
        if write_all(&backend_sock, hdr.as_bytes(), stall, &act)
            .await
            .is_err()
        {
            reset(&sock);
            reset(&backend_sock);
            m.close(Closed::Error);
            return;
        }
        m.proxy_out.fetch_add(1, Ordering::Relaxed);
    }

    // 6. Copy.
    let end = splice(&sock, &backend_sock, &mut guard, &shared, !trusted).await;
    m.close(end);
}

fn log_refusal(shared: &Shared, what: &str, lc: &ListenerCtx, peer: SocketAddr, reason: &str) {
    if shared.logs.allow(unix_now()) {
        // Source address only (it is the abuse-response handle); never payload, never header contents.
        tracing::warn!(listener = %lc.name, peer = %peer.ip(), reason, "{what}");
    }
}

/// Idle tracking shared by both directions of a flow.
pub struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    /// Start now.
    #[must_use]
    pub fn new() -> Self {
        Activity {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Note activity.
    pub fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    /// Time since the last activity.
    #[must_use]
    pub fn idle_for(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_ms.load(Ordering::Relaxed)),
        )
    }
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

/// Why one direction of a flow ended abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpEnd {
    /// No bytes in either direction for the idle timeout.
    Idle,
    /// A socket error.
    Error,
    /// The peer stopped accepting bytes.
    WriteStall,
    /// An untrusted client opened with a PROXY v2 signature.
    Spoof,
    /// The other direction outlived the half-close grace.
    HalfClose,
}

struct PumpCfg {
    buf: usize,
    idle: Duration,
    stall: Duration,
}

async fn wait_readable(src: &TcpStream, act: &Activity, idle: Duration) -> Result<(), PumpEnd> {
    loop {
        let remaining = idle
            .saturating_sub(act.idle_for())
            .max(Duration::from_millis(1));
        match tokio::time::timeout(remaining, src.readable()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) => return Err(PumpEnd::Error),
            Err(_) => {
                if act.idle_for() >= idle {
                    return Err(PumpEnd::Idle);
                }
            }
        }
    }
}

/// Copy `src` to `dst` until EOF, then half-close `dst`.
async fn pump(
    src: &TcpStream,
    dst: &TcpStream,
    cfg: &PumpCfg,
    act: &Activity,
    bytes: &AtomicU64,
    spoof_check: bool,
) -> Result<(), PumpEnd> {
    let mut held: Option<Vec<u8>> = None;
    let mut first = spoof_check;
    let mut streak = 0u32;
    loop {
        let buf = held.get_or_insert_with(|| vec![0u8; cfg.buf]);
        match src.try_read(buf) {
            Ok(0) => {
                let _ = SockRef::from(dst).shutdown(std::net::Shutdown::Write);
                return Ok(());
            }
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or(&[]);
                if first {
                    first = false;
                    if chunk.starts_with(&proxy_protocol::SIGNATURE) {
                        return Err(PumpEnd::Spoof);
                    }
                }
                write_all(dst, chunk, cfg.stall, act).await?;
                act.touch();
                bytes.fetch_add(n as u64, Ordering::Relaxed);
                streak += 1;
                if streak % 8 == 0 {
                    tokio::task::yield_now().await; // try_read/try_write do not spend the coop budget
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                held = None; // nothing in flight: give the buffer back
                wait_readable(src, act, cfg.idle).await?;
            }
            Err(_) => return Err(PumpEnd::Error),
        }
    }
}

/// Write all of `data`, failing if the peer makes no progress for `stall`.
async fn write_all(
    dst: &TcpStream,
    mut data: &[u8],
    stall: Duration,
    act: &Activity,
) -> Result<(), PumpEnd> {
    while !data.is_empty() {
        match tokio::time::timeout(stall, dst.writable()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(PumpEnd::Error),
            Err(_) => return Err(PumpEnd::WriteStall),
        }
        match dst.try_write(data) {
            Ok(n) => {
                data = data.get(n..).unwrap_or(&[]);
                act.touch();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(PumpEnd::Error),
        }
    }
    Ok(())
}

/// Copy both directions with half-close semantics. The first direction to finish cleanly
/// half-closes its destination; the other may continue for at most `half_close`.
async fn run_both(
    client: &TcpStream,
    backend: &TcpStream,
    cfg: &PumpCfg,
    half_close: Duration,
    shared: &Shared,
    spoof_check: bool,
) -> Result<(), PumpEnd> {
    let act = Activity::new();
    act.touch();
    let up = pump(
        client,
        backend,
        cfg,
        &act,
        &shared.metrics.bytes_up,
        spoof_check,
    );
    let down = pump(
        backend,
        client,
        cfg,
        &act,
        &shared.metrics.bytes_down,
        false,
    );
    tokio::pin!(up, down);
    let up_first = tokio::select! {
        r = &mut up => { r?; true }
        r = &mut down => { r?; false }
    };
    let rest = if up_first {
        tokio::time::timeout(half_close, &mut down).await
    } else {
        tokio::time::timeout(half_close, &mut up).await
    };
    rest.map_err(|_| PumpEnd::HalfClose)?
}

async fn splice(
    client: &TcpStream,
    backend: &TcpStream,
    guard: &mut FlowGuard,
    shared: &Shared,
    spoof_check: bool,
) -> Closed {
    let l = &shared.limits;
    let cfg = PumpCfg {
        buf: l.buffer_bytes,
        idle: Duration::from_secs(l.tcp_idle_timeout_secs),
        stall: Duration::from_secs(l.write_stall_timeout_secs),
    };
    let half_close = Duration::from_secs(l.half_close_timeout_secs);
    let result = tokio::select! {
        k = guard.killed() => Err(k),
        r = run_both(client, backend, &cfg, half_close, shared, spoof_check) => Ok(r),
    };
    let reset_both = || {
        reset(client);
        reset(backend);
    };
    match result {
        Ok(Ok(())) => Closed::Clean,
        Ok(Err(end)) => {
            reset_both();
            match end {
                PumpEnd::Idle => Closed::Idle,
                PumpEnd::HalfClose => Closed::HalfCloseTimeout,
                PumpEnd::Spoof => {
                    shared.metrics.reject(Reject::ProxyUntrusted);
                    if shared.logs.allow(unix_now()) {
                        if let Ok(p) = client.peer_addr() {
                            tracing::warn!(peer = %p.ip(), "PROXY v2 signature from an untrusted sender; connection reset");
                        }
                    }
                    Closed::Error
                }
                PumpEnd::Error | PumpEnd::WriteStall => Closed::Error,
            }
        }
        Err(Killed::Reset) => {
            reset_both();
            if shared.shutting_down.load(Ordering::SeqCst) {
                Closed::ShutdownReset
            } else {
                Closed::DrainReset
            }
        }
        Err(Killed::Gone) => {
            reset_both();
            Closed::Error
        }
    }
}
