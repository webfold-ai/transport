//! The public TLS front: one listener, SNI-routed.
//!
//! `servelet_tls::serve_tls` terminates every connection with one static certificate. This
//! listener instead reads the `ClientHello` first ([`transport::tls_hello::peek_sni`] — strict,
//! capped, time-boxed) and routes on the server name:
//!
//! - **terminate** (the default): hand the bytes read so far plus the live socket to rustls, with
//!   the per-SNI certificate resolver ([`transport::edge_proxy::sni::EdgeCertResolver`]); the
//!   decrypted stream runs the normal HTTP loop with the connection's SNI attached
//!   ([`crate::ConnMeta`]) so Host/SNI disagreement is a 421, not a cross-tenant request.
//! - **passthrough**: the tenant terminates TLS themselves. The edge never holds a key or sees
//!   plaintext; it takes an idle `splice` pipe from the tenant's connector, replays the hello
//!   bytes into it, and copies bytes both ways.
//!
//! Unknown names, no-SNI clients and malformed hellos get their connection closed without a
//! reply — there is nothing safe to say, and no default certificate to present (which would
//! disclose the platform to every scanner).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use servelet_router::Router;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};
use transport::edge_proxy::{Decision, SniRoute};
use transport::tls_hello::{peek_sni, Hello, MAX_HELLO_BYTES};

use crate::{ConnMeta, EdgeLb};

/// A client gets this long to deliver its `ClientHello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Most connections the front serves at once; beyond it new connections are dropped at accept.
pub const MAX_CONNECTIONS: usize = 20_000;

/// A stream that yields `prefix` before reading from `inner` — how bytes consumed while peeking
/// the `ClientHello` are handed back to the TLS stack.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Read until the `ClientHello` names a server (or is hopeless). Returns the name and every byte
/// consumed, which the caller must replay.
///
/// # Errors
/// Timeout, EOF, a malformed hello, or a hello with no `server_name`.
pub async fn read_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(String, Vec<u8>), &'static str> {
    read_hello_within(stream, HELLO_TIMEOUT).await
}

/// [`read_hello`] with an explicit deadline.
///
/// # Errors
/// As [`read_hello`].
pub async fn read_hello_within<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> Result<(String, Vec<u8>), &'static str> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let read = async {
        loop {
            match peek_sni(&buf) {
                Hello::Sni(name) => return Ok(name),
                Hello::NoSni => return Err("client hello has no server name"),
                Hello::Invalid => return Err("not a routable TLS client hello"),
                Hello::NeedMore => {}
            }
            if buf.len() >= MAX_HELLO_BYTES {
                return Err("client hello too large");
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err("connection closed before a client hello"),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let name = tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| "timed out waiting for a client hello")??;
    Ok((name, buf))
}

/// Serve one accepted connection.
async fn handle_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    edge: Arc<EdgeLb>,
    app: Router,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    let (sni, hello) = match read_hello(&mut stream).await {
        Ok(v) => v,
        Err(why) => {
            debug!(%peer, why, "tls front: dropping connection");
            return;
        }
    };
    match edge.state.sni_route(&sni).await {
        SniRoute::Passthrough => match edge.state.decide_passthrough(&sni).await {
            Decision::Serve(_) => {
                let host = sni.to_ascii_lowercase();
                let mut pipe = match edge.tunnels.take_splice(&host).await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(%peer, %host, error = %e, "passthrough: no connector pipe");
                        return;
                    }
                };
                let outcome = pipe.run(stream, &hello).await;
                edge.tunnels.finish_splice(pipe);
                match outcome {
                    Ok((up, down)) => debug!(%peer, %host, up, down, "passthrough flow ended"),
                    Err(e) => debug!(%peer, %host, error = %e, "passthrough flow failed"),
                }
            }
            other => debug!(%peer, %sni, decision = ?other, "passthrough refused"),
        },
        SniRoute::Terminate => {
            let tls = match acceptor.accept(Prefixed::new(hello, stream)).await {
                Ok(t) => t,
                Err(e) => {
                    // Includes the "no certificate for this name" refusal: unknown names never
                    // complete a handshake.
                    debug!(%peer, %sni, error = %e, "tls handshake failed");
                    return;
                }
            };
            let app = app.with_state(ConnMeta {
                sni: Some(sni.to_ascii_lowercase()),
                tls: true,
            });
            servelet_h1::serve_connection(tls, app, Some(peer)).await;
        }
    }
}

/// Run the front on an already-bound listener until it errors.
pub async fn serve(
    listener: TcpListener,
    edge: Arc<EdgeLb>,
    app: Router,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    info!(addr = ?listener.local_addr().ok(), "tls front listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            debug!(%peer, "tls front at capacity; dropping connection");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let (edge, app, acceptor) = (edge.clone(), app.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(stream, peer, edge, app, acceptor).await;
        });
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn prefixed_replays_then_reads_through() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"world").await.unwrap();
        a.shutdown().await.unwrap();
        let mut p = Prefixed::new(b"hello ".to_vec(), b);
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    /// A real rustls `ClientHello` for `name`.
    fn client_hello(name: &'static str) -> Vec<u8> {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            transport::edge_proxy::sni::provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(cfg),
            rustls::pki_types::ServerName::try_from(name).unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn the_hello_is_read_in_pieces_and_every_byte_is_kept_for_replay() {
        let hello = client_hello("app.example.com");
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let h = hello.clone();
        tokio::spawn(async move {
            for piece in h.chunks(7) {
                client.write_all(piece).await.unwrap();
                tokio::task::yield_now().await;
            }
            client.shutdown().await.ok();
        });
        let (name, bytes) = read_hello(&mut server).await.unwrap();
        assert_eq!(name, "app.example.com");
        assert!(
            hello.starts_with(&bytes),
            "replay must be a prefix of what the client sent"
        );
        assert!(bytes.len() >= 5);
    }

    #[tokio::test]
    async fn garbage_empty_and_silent_clients_are_refused_promptly() {
        for junk in [&b"GET / HTTP/1.1\r\n\r\n"[..], &b""[..]] {
            let (mut c, mut s) = tokio::io::duplex(1024);
            c.write_all(junk).await.unwrap();
            drop(c);
            assert!(read_hello(&mut s).await.is_err());
        }
        // A peer that connects and says nothing is dropped at the deadline.
        let (_c, mut s) = tokio::io::duplex(1024);
        assert_eq!(
            read_hello_within(&mut s, Duration::from_millis(80))
                .await
                .unwrap_err(),
            "timed out waiting for a client hello"
        );
    }
}
