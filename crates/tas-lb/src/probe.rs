//! The active health prober: one task per backend.
//!
//! A probe is a bounded TCP connect (plus a PROXY v2 `LOCAL` header when PROXY is on, so the
//! backend sees what the protocol defines for proxy-originated checks instead of a malformed
//! connection). The task ends when its backend is no longer live or at shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::backend::Backend;
use crate::proxy_protocol;
use crate::userspace::Shared;

/// One probe: true if the backend accepted a connection within `timeout`.
pub async fn probe_once(addr: SocketAddr, timeout: Duration, send_proxy_local: bool) -> bool {
    let attempt = async {
        let mut s = TcpStream::connect(addr).await?;
        if send_proxy_local {
            s.write_all(proxy_protocol::encode_local().as_bytes())
                .await?;
        }
        std::io::Result::Ok(())
    };
    matches!(tokio::time::timeout(timeout, attempt).await, Ok(Ok(())))
}

/// Run the prober for `backend` until it is retired or `shutdown` fires.
pub async fn run(shared: Arc<Shared>, backend: Arc<Backend>, mut shutdown: watch::Receiver<bool>) {
    // Spread first probes so a reload does not probe every backend in the same millisecond.
    let jitter = u64::from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()),
    ) % 50;
    tokio::time::sleep(Duration::from_millis(jitter)).await;
    loop {
        if *shutdown.borrow() || !shared.director.is_live(&backend) {
            return;
        }
        let Some(spec) = shared.director.health_spec() else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let port = spec.port.unwrap_or(shared.default_health_port);
        let ok = probe_once(
            SocketAddr::new(backend.ip, port),
            Duration::from_millis(spec.timeout_ms),
            shared.director.send_proxy(),
        )
        .await;
        shared.director.report(&backend, ok, false, Instant::now());
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(spec.interval_ms)) => {}
            _ = shutdown.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn a_listening_port_probes_ok_and_a_closed_one_fails() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        assert!(probe_once(addr, Duration::from_millis(500), false).await);
        drop(l);
        assert!(!probe_once(addr, Duration::from_millis(500), false).await);
    }

    #[tokio::test]
    async fn the_proxy_local_header_is_sent_when_asked() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let t = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });
        assert!(probe_once(addr, Duration::from_millis(500), true).await);
        let got = t.await.unwrap();
        let (h, n) = proxy_protocol::parse(&got).unwrap();
        assert_eq!((h.command, n), (proxy_protocol::Command::Local, 16));
    }
}
