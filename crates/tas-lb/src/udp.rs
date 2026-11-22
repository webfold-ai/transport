//! The userspace UDP plane.
//!
//! One receive loop per listener. A datagram from a client with a tracked flow goes to that
//! flow's pinned backend through the flow's own connected socket (so only that backend's replies
//! are accepted). A datagram with no flow is a NEW flow: rate limit, admit, pick a backend with
//! the keyed Maglev hash, create the socket, pin, spawn the reply task.
//!
//! ## What UDP cannot give you
//!
//! There is no handshake, so a UDP "source" can be forged and a backend's reply goes wherever the
//! source claimed: UDP forwarding is a reflection vector unless the protocol above it is
//! self-validating (QUIC Retry, DTLS cookies). This plane therefore bounds what it can: per-source
//! and global flow limits and the per-source new-flow rate apply exactly as for TCP, datagrams are
//! capped at `udp_max_datagram`, idle flows expire, and a UDP listener exists only if configured.
//! It does not (and at L4 cannot) cap amplification ratio. Do not expose UDP listeners for
//! protocols with amplification potential.
//!
//! With PROXY v2 on, every datagram toward the backend is prefixed with a v2 header (UDP has no
//! connection to put it on). The header's destination is the listener's bound address, so bind a
//! UDP listener to the VIP rather than the wildcard if the backend needs the real destination.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::director::FlowTuple;
use crate::flows::{AdmitError, FlowGuard, FlowKey, Killed, Proto};
use crate::loglimit::unix_now;
use crate::metrics::Reject;
use crate::proxy_protocol::{self, Transport};
use crate::tcp::ListenerCtx;
use crate::userspace::Shared;

/// Bind a UDP listener.
///
/// # Errors
/// I/O errors from socket or bind.
pub async fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

/// The receive loop. Returns when `shutdown` fires.
pub async fn serve(
    sock: Arc<UdpSocket>,
    lc: Arc<ListenerCtx>,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let max = shared.limits.udp_max_datagram;
    // One extra byte so an oversize datagram is detected rather than silently truncated.
    let mut buf = vec![0u8; max + 1];
    let mut out: Vec<u8> = Vec::with_capacity(max + proxy_protocol::MAX_ENCODED_LEN);
    let Ok(local) = sock.local_addr() else { return };
    loop {
        let received = tokio::select! {
            r = sock.recv_from(&mut buf) => r,
            _ = shutdown.changed() => return,
        };
        let Ok((n, peer)) = received else {
            shared.metrics.accept_errors.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        if n > max {
            shared.metrics.reject(Reject::UdpTooBig);
            continue;
        }
        let Some(payload) = buf.get(..n) else {
            continue;
        };
        let key = FlowKey {
            proto: Proto::Udp,
            listener: lc.index,
            peer,
        };

        if let Some(hit) = shared.flows.lookup_udp(&key) {
            forward(
                &shared,
                &hit.socket,
                hit.send_proxy,
                peer,
                local,
                payload,
                &mut out,
            )
            .await;
            continue;
        }

        // A new flow. First, the one payload inspection: an untrusted sender opening with a PROXY
        // v2 signature is refused and counted (UDP never accepts PROXY from anyone).
        if payload.starts_with(&proxy_protocol::SIGNATURE) {
            shared.metrics.reject(Reject::ProxyUntrusted);
            if shared.logs.allow(unix_now()) {
                tracing::warn!(listener = %lc.name, peer = %peer.ip(), "PROXY v2 signature on a UDP listener; datagram dropped");
            }
            continue;
        }
        if shared.shutting_down.load(Ordering::SeqCst) {
            shared.metrics.reject(Reject::ShuttingDown);
            continue;
        }
        if !shared
            .rate
            .allow(peer.ip(), u32::try_from(unix_now()).unwrap_or(u32::MAX))
        {
            shared.metrics.reject(Reject::RateLimited);
            continue;
        }
        let reservation = match shared.flows.admit(peer.ip()) {
            Ok(r) => r,
            Err(AdmitError::MaxFlows) => {
                shared.metrics.reject(Reject::MaxFlows);
                continue;
            }
            Err(AdmitError::PerSource) => {
                shared.metrics.reject(Reject::PerSource);
                continue;
            }
        };
        let tuple = FlowTuple {
            client: peer,
            local,
            proto: Proto::Udp,
        };
        let Some(lease) = shared.director.select(&tuple, &[]) else {
            shared.metrics.reject(Reject::NoBackend);
            continue;
        };
        let target = SocketAddr::new(lease.backend().ip, lc.backend_port);
        let bind_addr: SocketAddr = if target.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let Ok(bsock) = UdpSocket::bind(bind_addr).await else {
            shared.metrics.reject(Reject::ConnectFailed);
            continue;
        };
        if bsock.connect(target).await.is_err() {
            shared.metrics.reject(Reject::ConnectFailed);
            continue;
        }
        let bsock = Arc::new(bsock);
        let Ok(guard) = reservation.pin(key, lease, Some(bsock.clone())) else {
            continue;
        };
        shared.metrics.flows.inc(1);
        let send_proxy = guard.send_proxy();
        tokio::spawn(replies(
            shared.clone(),
            sock.clone(),
            bsock.clone(),
            guard,
            key,
        ));
        forward(&shared, &bsock, send_proxy, peer, local, payload, &mut out).await;
    }
}

async fn forward(
    shared: &Shared,
    bsock: &UdpSocket,
    send_proxy: bool,
    client: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    let sent = if send_proxy {
        out.clear();
        out.extend_from_slice(
            proxy_protocol::encode(client, local, Transport::Datagram).as_bytes(),
        );
        out.extend_from_slice(payload);
        shared.metrics.proxy_out.fetch_add(1, Ordering::Relaxed);
        bsock.send(out).await
    } else {
        bsock.send(payload).await
    };
    if sent.is_ok() {
        shared
            .metrics
            .udp_datagrams_up
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Backend-to-client direction of one flow, until the flow is killed or expires.
async fn replies(
    shared: Arc<Shared>,
    listener: Arc<UdpSocket>,
    bsock: Arc<UdpSocket>,
    mut guard: FlowGuard,
    key: FlowKey,
) {
    let mut held: Option<Vec<u8>> = None;
    loop {
        tokio::select! {
            k = guard.killed() => {
                shared.metrics.close(match k {
                    Killed::Reset if shared.shutting_down.load(Ordering::SeqCst) => crate::metrics::Closed::ShutdownReset,
                    Killed::Reset => crate::metrics::Closed::DrainReset,
                    Killed::Gone => crate::metrics::Closed::Idle,
                });
                return;
            }
            r = bsock.readable() => {
                if r.is_err() {
                    shared.metrics.close(crate::metrics::Closed::Error);
                    return;
                }
                // Drain what is ready; the buffer exists only while datagrams are in flight.
                loop {
                    let buf = held.get_or_insert_with(|| vec![0u8; shared.limits.udp_max_datagram]);
                    match bsock.try_recv(buf) {
                        Ok(n) => {
                            if let Some(d) = buf.get(..n) {
                                if listener.send_to(d, key.peer).await.is_ok() {
                                    shared.metrics.udp_datagrams_down.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            shared.flows.touch(&key);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            held = None;
                            break;
                        }
                        Err(_) => {
                            shared.metrics.close(crate::metrics::Closed::Error);
                            return;
                        }
                    }
                }
            }
        }
    }
}
