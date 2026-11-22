//! The internal HTTP listener: `/metrics`, `/healthz`, `/readyz`.
//!
//! Deliberately tiny and defensive instead of pulling in an HTTP stack for three GETs: request
//! head capped at 2 KiB and read under a 3 s timeout, only `GET` of exactly those paths, one
//! response, `Connection: close`, at most 32 connections at once (excess are dropped). It is bound
//! to an internal address (enforced by [`crate::config::StaticConfig::validate`]) and serves only
//! aggregate counters and backend ids; no client addresses, no payload.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};

use crate::metrics::Gauges;
use crate::userspace::Shared;

const MAX_HEAD: usize = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

/// Serve until `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(32));
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.changed() => return,
        };
        let Ok((sock, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(IO_TIMEOUT * 2, handle(sock, &shared)).await;
        });
    }
}

/// Render the page for `path`, or `None` for an unknown path.
fn respond(path: &str, shared: &Shared) -> (u16, &'static str, String) {
    match path {
        "/metrics" => {
            let g = Gauges {
                flows_active: shared.flows.len(),
                backends: shared.director.gauges(),
                config_loaded: shared.director.is_configured(),
            };
            (200, "text/plain; version=0.0.4", shared.metrics.render(&g))
        }
        "/healthz" => (200, "text/plain", "ok\n".to_string()),
        "/readyz" => {
            if shared.director.is_ready() && !shared.shutting_down.load(Ordering::SeqCst) {
                (200, "text/plain", "ready\n".to_string())
            } else {
                (
                    503,
                    "text/plain",
                    "not ready: no verified config or no healthy backend\n".to_string(),
                )
            }
        }
        _ => (404, "text/plain", "not found\n".to_string()),
    }
}

async fn handle(mut sock: TcpStream, shared: &Shared) {
    let mut head = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let complete = loop {
        match tokio::time::timeout(IO_TIMEOUT, sock.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break false,
            Ok(Ok(n)) => {
                head.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break true;
                }
                if head.len() >= MAX_HEAD {
                    break false;
                }
            }
        }
    };
    let (status, ctype, body) = if complete {
        let line = head.split(|b| *b == b'\r').next().unwrap_or(&[]);
        let line = String::from_utf8_lossy(line);
        let mut parts = line.split(' ');
        match (parts.next(), parts.next()) {
            (Some("GET"), Some(path)) => respond(path, shared),
            _ => (405, "text/plain", "method not allowed\n".to_string()),
        }
    } else {
        (400, "text/plain", "bad request\n".to_string())
    };
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Service Unavailable",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(IO_TIMEOUT, sock.write_all(resp.as_bytes())).await;
    let _ = sock.shutdown().await;
}
