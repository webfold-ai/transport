//! A real readiness probe: the edge itself asks the staged unit whether it is up.
//!
//! Before this, `POST /control/releases/{host}/probe` flipped on the caller's word
//! (`{"ok": true}`), so the readiness gate (INV-02) was only as good as the deploy driver's
//! honesty. With `{"path": "/healthz"}` the edge dials the staged target and flips only on a
//! `2xx`.
//!
//! Plain HTTP/1.1 over TCP: rollout targets are `http://host:port` (see
//! [`crate::rollout::http_target`]). No redirects are followed and nothing is retried: a unit
//! that is not ready yet answers [`ProbeResult::NotReady`] and the driver probes again.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::rollout::{http_target, ProbeResult};

/// How much of the response head is read; the status line is all that matters.
const HEAD_BYTES: usize = 1024;

/// A request path is safe to put on the request line: absolute, no whitespace or control
/// characters (a CR/LF here would let a caller inject headers into the probe request).
#[must_use]
pub fn is_safe_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 512 && path.bytes().all(|b| b.is_ascii_graphic())
}

/// Parse the status code out of an HTTP/1.x response head.
#[must_use]
pub fn status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\r' || *b == b'\n').next()?;
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    parts.next().filter(|v| v.starts_with("HTTP/1."))?;
    parts.next()?.parse().ok()
}

/// `GET path` on `target`; `2xx` is [`ProbeResult::Ready`]. A refused connection, a timeout and
/// a non-2xx answer are all [`ProbeResult::NotReady`] (it may simply not be up yet); only a
/// target or path that can never work is a [`ProbeResult::ProbeError`].
pub async fn http_ready(target: &str, path: &str, timeout: Duration) -> ProbeResult {
    let Some((host, port)) = http_target(target) else {
        return ProbeResult::ProbeError(format!("target {target:?} is not http://host:port"));
    };
    if !is_safe_path(path) {
        return ProbeResult::ProbeError(format!("probe path {path:?} is not a safe request path"));
    }
    let attempt = async {
        let mut stream = TcpStream::connect((host.as_str(), port)).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: edge-lb-readiness\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = vec![0u8; HEAD_BYTES];
        let mut filled = 0;
        // Read until the status line is complete (or the buffer/peer ends).
        while filled < buf.len() {
            let n = stream.read(&mut buf[filled..]).await.ok()?;
            if n == 0 {
                break;
            }
            filled += n;
            if buf[..filled].contains(&b'\n') {
                break;
            }
        }
        status_code(&buf[..filled])
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Some(code)) if (200..300).contains(&code) => ProbeResult::Ready,
        _ => ProbeResult::NotReady,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use tokio::net::TcpListener;

    use super::*;

    /// A one-shot HTTP server answering every connection with `status_line`.
    async fn serve(status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(format!("{status_line}\r\ncontent-length: 0\r\n\r\n").as_bytes())
                    .await;
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    const T: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn a_2xx_is_ready_and_anything_else_is_not() {
        assert_eq!(
            http_ready(&serve("HTTP/1.1 200 OK").await, "/healthz", T).await,
            ProbeResult::Ready
        );
        assert_eq!(
            http_ready(&serve("HTTP/1.1 204 No Content").await, "/", T).await,
            ProbeResult::Ready
        );
        assert_eq!(
            http_ready(
                &serve("HTTP/1.1 503 Service Unavailable").await,
                "/healthz",
                T
            )
            .await,
            ProbeResult::NotReady
        );
        assert_eq!(
            http_ready(&serve("HTTP/1.1 301 Moved Permanently").await, "/", T).await,
            ProbeResult::NotReady,
            "redirects are not followed"
        );
        assert_eq!(
            http_ready(&serve("garbage").await, "/", T).await,
            ProbeResult::NotReady
        );
    }

    #[tokio::test]
    async fn a_unit_that_is_not_listening_is_not_ready_rather_than_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            http_ready(&format!("http://127.0.0.1:{port}"), "/", T).await,
            ProbeResult::NotReady
        );
    }

    #[tokio::test]
    async fn a_unit_that_accepts_but_never_answers_times_out_as_not_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        let r = http_ready(
            &format!("http://127.0.0.1:{port}"),
            "/",
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(r, ProbeResult::NotReady);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn unusable_targets_and_paths_are_errors_not_probes() {
        assert!(matches!(
            http_ready("dialkey://k#s", "/", T).await,
            ProbeResult::ProbeError(_)
        ));
        for bad in ["healthz", "/a b", "/x\r\nHost: evil", "/x\n", ""] {
            assert!(
                matches!(
                    http_ready("http://127.0.0.1:1", bad, T).await,
                    ProbeResult::ProbeError(_)
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(status_code(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(status_code(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(status_code(b"SPDY/3 200 OK\r\n"), None);
        assert_eq!(status_code(b"HTTP/1.1 abc\r\n"), None);
        assert_eq!(status_code(b""), None);
    }
}
