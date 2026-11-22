//! Overlay tunnels on the edge (RFC 0008 §8 + `tascloud-product-mapping.md`
//! § tas-overlay) — a tenant origin's `overlay-agent` dials the edge's tunnel listener, and
//! traffic for its hostname is carried over those authenticated connections. No inbound ports
//! on the tenant side, no A/AAAA record on ours.
//!
//! ## Protocol
//!
//! The agent dials the listener many times. Each connection is mutually authenticated by the
//! native Ed25519 handshake, carries **one** sealed pipe, and opens with a one-line claim:
//!
//! ```text
//! register <hostname>\n     an HTTP pipe: the edge writes one request, the agent answers once
//! splice <hostname>\n       a raw pipe: the edge hands it one whole TLS flow (passthrough)
//! ```
//!
//! The edge accepts a claim only if **the connection's authenticated peer is the connector bound
//! to that hostname** (`EdgeState`; bound at enrolment or, for a legacy unbound name, refused).
//! Before this, the claim was trusted on the strength of the shared control secret alone: any
//! holder of the secret could dial in and steal any enrolled hostname's traffic.
//!
//! ## Concurrency
//!
//! One request per pipe at a time (the sealed stream is a single logical stream), so concurrency
//! is *more pipes*: the agent keeps a pool of idle `register` connections and the edge takes one
//! per request. A slow request no longer blocks every other request to the tenant; if every pipe
//! is busy the edge waits [`ACQUIRE_TIMEOUT`] for one to free up, then answers 503.
//!
//! ## Framing and failure
//!
//! HTTP/1.1, `Content-Length` framed only — the agent re-frames whatever its origin sends
//! (chunked, close-delimited) before answering, so the edge never has to guess where a response
//! ends. The edge is strict about it: a response with `Transfer-Encoding`, conflicting
//! `Content-Length`s, or bytes beyond the declared body is a protocol error, and **a pipe that
//! errors or times out is dropped, never reused** — a late response left in a reused pipe would
//! be served to the *next* visitor, possibly another user's.
//!
//! Sealed frames: one `read` returns one frame and discards what does not fit the buffer, so every
//! write is ≤ [`FRAME`] bytes and every read buffer is [`FRAME`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{info, warn};
use transport::{BiStream, Connection, PeerId, Transport as _};

use crate::edge_state::{peer_hex, EdgeState};

/// How long one relayed request may take, whole round trip.
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a request waits for an idle pipe before the edge gives up with a 503.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);
/// Sealed-frame size both ends read and write in.
pub const FRAME: usize = 4096;
/// Largest response head accepted from a tunnel.
pub const MAX_HEAD: usize = 64 * 1024;
/// Largest response body accepted from a tunnel (the edge buffers it; streaming is not offered).
pub const MAX_RESPONSE_BODY: usize = 64 * 1024 * 1024;
/// Most pipes (HTTP + splice) one hostname may hold, so a bug or a hostile agent cannot exhaust
/// the edge's file descriptors.
pub const MAX_PIPES_PER_TUNNEL: usize = 64;
/// How long a claim may take to arrive after the handshake.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

/// The control-surface view of one tunnel (never carries the stream pipes).
#[derive(Clone, Debug)]
pub struct TunnelInfo {
    pub hostname: String,
    pub port: u16,
    pub version: Option<String>,
    pub online: bool,
    /// HTTP pipes currently held (idle + in flight).
    pub pipes: usize,
}

/// One authenticated pipe: its two halves, plus the connection that must stay alive with them.
pub struct Pipe {
    send: Box<dyn BiStream>,
    recv: Box<dyn BiStream>,
    conn: Arc<dyn Connection>,
}

impl Pipe {
    /// Close the underlying connection (best effort).
    pub fn close(self) {
        let conn = self.conn;
        tokio::spawn(async move {
            let _ = conn.close().await;
        });
    }
}

struct Tunnel {
    hostname: String,
    port: u16,
    version: Option<String>,
    /// The connector this tunnel belongs to — fixed at enrolment, checked on every claim.
    peer: PeerId,
    idle: Mutex<VecDeque<Pipe>>,
    splice: Mutex<VecDeque<Pipe>>,
    idle_notify: tokio::sync::Notify,
    splice_notify: tokio::sync::Notify,
    /// HTTP pipes alive (idle + in flight).
    live: AtomicUsize,
    /// Splice pipes alive (idle + in flight); counts toward [`MAX_PIPES_PER_TUNNEL`].
    live_splice: AtomicUsize,
}

/// What a claim was refused for.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    UnknownHostname,
    /// The authenticated peer is not the connector bound to this hostname.
    WrongPeer,
    TooManyPipes,
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ClaimError::UnknownHostname => "no tunnel is enrolled for this hostname",
            ClaimError::WrongPeer => {
                "this connection's identity is not the connector enrolled for this hostname"
            }
            ClaimError::TooManyPipes => "too many pipes for this hostname",
        })
    }
}

/// Which kind of pipe a claim opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeKind {
    Http,
    Splice,
}

/// The edge's tunnel registry — one entry per enrolled hostname.
#[derive(Clone)]
pub struct TunnelRegistry {
    tunnels: Arc<Mutex<HashMap<String, Arc<Tunnel>>>>,
    state: Arc<EdgeState>,
}

impl TunnelRegistry {
    #[must_use]
    pub fn new(state: Arc<EdgeState>) -> Self {
        TunnelRegistry {
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            state,
        }
    }

    /// Enrol `hostname` for the connector `peer`, forwarding to origin port `port`.
    ///
    /// Idempotent for the same `(peer, port)`; a different peer for an enrolled hostname is
    /// refused (revoke first) — the connector binding is the thing claims are checked against.
    ///
    /// # Errors
    /// Invalid input, or the hostname is enrolled for a different connector.
    pub fn register(
        &self,
        hostname: &str,
        port: u16,
        version: Option<String>,
        peer: PeerId,
    ) -> Result<bool, String> {
        let hostname = hostname.trim().to_ascii_lowercase();
        if hostname.is_empty() || hostname.contains('/') {
            return Err(format!("hostname '{hostname}' is invalid"));
        }
        if port == 0 {
            return Err(format!("port {port} is invalid"));
        }
        if peer == [0u8; 32] {
            return Err("peer must be the connector's Ed25519 public key".to_string());
        }
        let mut tunnels = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = tunnels.get(&hostname) {
            return if existing.peer == peer {
                Ok(false)
            } else {
                Err(format!(
                    "hostname '{hostname}' is enrolled for a different connector"
                ))
            };
        }
        tunnels.insert(
            hostname.clone(),
            Arc::new(Tunnel {
                hostname: hostname.clone(),
                port,
                version,
                peer,
                idle: Mutex::new(VecDeque::new()),
                splice: Mutex::new(VecDeque::new()),
                idle_notify: tokio::sync::Notify::new(),
                splice_notify: tokio::sync::Notify::new(),
                live: AtomicUsize::new(0),
                live_splice: AtomicUsize::new(0),
            }),
        );
        info!(%hostname, %port, peer = %peer_hex(&peer), "tunnel registered");
        Ok(true)
    }

    fn tunnel(&self, hostname: &str) -> Option<Arc<Tunnel>> {
        self.tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hostname)
            .cloned()
    }

    /// The connector bound to `hostname`'s tunnel.
    #[must_use]
    pub fn peer_of(&self, hostname: &str) -> Option<PeerId> {
        self.tunnel(hostname).map(|t| t.peer)
    }

    /// Attach a pipe the connection `conn` opened for `hostname`. `conn.peer_id()` — what the
    /// handshake proved — must be the connector the tunnel was enrolled for.
    ///
    /// # Errors
    /// See [`ClaimError`]. On error the connection is closed.
    pub fn attach(
        &self,
        hostname: &str,
        kind: PipeKind,
        conn: Arc<dyn Connection>,
        send: Box<dyn BiStream>,
        recv: Box<dyn BiStream>,
    ) -> Result<(), ClaimError> {
        let pipe = Pipe {
            send,
            recv,
            conn: conn.clone(),
        };
        let Some(tunnel) = self.tunnel(hostname) else {
            pipe.close();
            return Err(ClaimError::UnknownHostname);
        };
        if conn.peer_id() != tunnel.peer {
            pipe.close();
            return Err(ClaimError::WrongPeer);
        }
        if tunnel.live.load(Ordering::Acquire) + tunnel.live_splice.load(Ordering::Acquire)
            >= MAX_PIPES_PER_TUNNEL
        {
            pipe.close();
            return Err(ClaimError::TooManyPipes);
        }
        match kind {
            PipeKind::Http => {
                tunnel.live.fetch_add(1, Ordering::AcqRel);
                self.mark_online(&tunnel, conn);
                tunnel
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push_back(pipe);
                tunnel.idle_notify.notify_one();
            }
            PipeKind::Splice => {
                tunnel.live_splice.fetch_add(1, Ordering::AcqRel);
                tunnel
                    .splice
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push_back(pipe);
                tunnel.splice_notify.notify_one();
            }
        }
        info!(hostname = %tunnel.hostname, ?kind, "tunnel pipe attached");
        Ok(())
    }

    /// Tell the shared connector pool this peer is reachable (once per peer, not per pipe).
    fn mark_online(&self, tunnel: &Tunnel, conn: Arc<dyn Connection>) {
        let mut pool = self
            .state
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pool.is_online(tunnel.peer) {
            pool.register(tunnel.peer, conn);
        }
    }

    /// A pipe died or was discarded: account for it, and take the peer offline if that was the
    /// last HTTP pipe of every tunnel it connects.
    fn pipe_lost(&self, tunnel: &Tunnel, kind: PipeKind) {
        match kind {
            PipeKind::Splice => {
                tunnel.live_splice.fetch_sub(1, Ordering::AcqRel);
                return;
            }
            PipeKind::Http => {
                tunnel.live.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let still_alive = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|t| t.peer == tunnel.peer && t.live.load(Ordering::Acquire) > 0);
        if !still_alive {
            self.state
                .pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .evict(tunnel.peer);
        }
    }

    async fn acquire(&self, tunnel: &Tunnel, kind: PipeKind) -> Result<Pipe, String> {
        let (queue, notify) = match kind {
            PipeKind::Http => (&tunnel.idle, &tunnel.idle_notify),
            PipeKind::Splice => (&tunnel.splice, &tunnel.splice_notify),
        };
        let wait = async {
            loop {
                // Register interest *before* checking the queue so a push between the check and
                // the await cannot be missed.
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(pipe) = queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop_front()
                {
                    return pipe;
                }
                notified.await;
            }
        };
        tokio::time::timeout(ACQUIRE_TIMEOUT, wait)
            .await
            .map_err(|_| match kind {
                PipeKind::Http => {
                    "every connector pipe is busy or the connector is offline".to_string()
                }
                PipeKind::Splice => "no spare connector pipe for a new flow".to_string(),
            })
    }

    /// Relay one request over an idle pipe. `head_only` (a `HEAD` request) means the response
    /// carries headers but no body.
    ///
    /// The pipe goes back to the idle set only after a clean exchange; on any error or timeout it
    /// is closed and discarded.
    pub async fn relay(
        &self,
        hostname: &str,
        message: &[u8],
        head_only: bool,
    ) -> Result<RelayedResponse, RelayError> {
        let tunnel = self.tunnel(hostname).ok_or(RelayError::NoTunnel)?;
        let mut pipe = self
            .acquire(&tunnel, PipeKind::Http)
            .await
            .map_err(RelayError::Unavailable)?;
        let outcome = tokio::time::timeout(
            RELAY_TIMEOUT,
            relay_on(&mut *pipe.send, &mut *pipe.recv, message, head_only),
        )
        .await;
        match outcome {
            Ok(Ok(resp)) => {
                tunnel
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push_back(pipe);
                tunnel.idle_notify.notify_one();
                Ok(resp)
            }
            Ok(Err(e)) => {
                self.pipe_lost(&tunnel, PipeKind::Http);
                pipe.close();
                Err(RelayError::Failed(e))
            }
            Err(_) => {
                self.pipe_lost(&tunnel, PipeKind::Http);
                pipe.close();
                Err(RelayError::Failed("tunnel relay timed out".to_string()))
            }
        }
    }

    /// Take an idle splice pipe for one raw flow. The caller owns it until it calls
    /// [`Self::finish_splice`].
    pub async fn take_splice(&self, hostname: &str) -> Result<SplicePipe, String> {
        let tunnel = self
            .tunnel(hostname)
            .ok_or_else(|| "no tunnel registered for this hostname".to_string())?;
        let pipe = self.acquire(&tunnel, PipeKind::Splice).await?;
        Ok(SplicePipe { pipe, tunnel })
    }

    /// A splice flow ended; its pipe is spent (the agent dials a fresh one).
    pub fn finish_splice(&self, sp: SplicePipe) {
        self.pipe_lost(&sp.tunnel, PipeKind::Splice);
        sp.pipe.close();
    }

    /// Revoke a hostname's tunnel, closing every pipe.
    pub fn revoke(&self, hostname: &str) -> bool {
        let removed = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(hostname);
        let Some(tunnel) = removed else { return false };
        let drained: Vec<Pipe> = {
            let mut idle = tunnel
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut splice = tunnel
                .splice
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.drain(..).chain(splice.drain(..)).collect()
        };
        for p in drained {
            p.close();
        }
        let shared = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|t| t.peer == tunnel.peer && t.live.load(Ordering::Acquire) > 0);
        if !shared {
            self.state
                .pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .evict(tunnel.peer);
        }
        info!(%hostname, "tunnel revoked");
        true
    }

    #[must_use]
    pub fn is_registered(&self, hostname: &str) -> bool {
        self.tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(hostname)
    }

    /// Whether any HTTP pipe for `hostname` is alive.
    #[must_use]
    pub fn is_online(&self, hostname: &str) -> bool {
        self.tunnel(hostname)
            .is_some_and(|t| t.live.load(Ordering::Acquire) > 0)
    }

    /// Every registered hostname (for the control surface).
    #[must_use]
    pub fn list(&self) -> Vec<TunnelInfo> {
        let tunnels = self
            .tunnels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out: Vec<TunnelInfo> = tunnels
            .values()
            .map(|t| {
                let pipes = t.live.load(Ordering::Acquire);
                TunnelInfo {
                    hostname: t.hostname.clone(),
                    port: t.port,
                    version: t.version.clone(),
                    online: pipes > 0,
                    pipes,
                }
            })
            .collect();
        out.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        out
    }
}

/// A raw pipe checked out for one flow.
pub struct SplicePipe {
    pipe: Pipe,
    tunnel: Arc<Tunnel>,
}

impl SplicePipe {
    /// Copy `client` ⇄ the pipe until either side ends, after first writing `prefix` (the bytes
    /// already read from the client — a TLS `ClientHello` — which the origin must see first).
    ///
    /// When the client finishes first the pipe gets [`HALF_CLOSE_GRACE`] to deliver what is still
    /// in flight (TLS `close_notify` exchanges); when the pipe finishes first the flow ends at once.
    pub async fn run<C>(&mut self, client: C, prefix: &[u8]) -> std::io::Result<(u64, u64)>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        write_chunked(&mut *self.pipe.send, prefix).await?;
        let (mut cr, mut cw) = tokio::io::split(client);
        let (send, recv) = (&mut self.pipe.send, &mut self.pipe.recv);

        let up = async {
            let mut total = prefix.len() as u64;
            let mut buf = [0u8; FRAME];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<u64, std::io::Error>(total);
                }
                send.write_all(&buf[..n]).await?;
                total += n as u64;
            }
        };
        let down = async {
            let mut total = 0u64;
            let mut buf = [0u8; FRAME];
            loop {
                let n = recv.read(&mut buf).await?;
                if n == 0 {
                    let _ = cw.shutdown().await;
                    return Ok::<u64, std::io::Error>(total);
                }
                cw.write_all(&buf[..n]).await?;
                total += n as u64;
            }
        };
        tokio::pin!(up, down);
        let (mut sent, mut received) = (0u64, 0u64);
        tokio::select! {
            r = &mut down => { received = r.unwrap_or(0); }
            r = &mut up => {
                sent = r.unwrap_or(0);
                if let Ok(Ok(n)) = tokio::time::timeout(HALF_CLOSE_GRACE, &mut down).await { received = n; }
            }
        }
        Ok((sent, received))
    }
}

/// How long the pipe side may keep delivering after the client half-closes.
pub const HALF_CLOSE_GRACE: Duration = Duration::from_secs(5);

// ── the relay ──────────────────────────────────────────────────────────────

/// Why a relay failed, distinguishing "nothing to send it on" (503) from "the connector broke the
/// protocol or died" (502).
#[derive(Debug)]
pub enum RelayError {
    NoTunnel,
    Unavailable(String),
    Failed(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::NoTunnel => f.write_str("no tunnel registered for this hostname"),
            RelayError::Unavailable(m) | RelayError::Failed(m) => f.write_str(m),
        }
    }
}

/// One header line: name and raw value.
pub type HeaderLine = (String, Vec<u8>);

/// A response read off a tunnel pipe, not yet turned into an HTTP response object.
#[derive(Debug, PartialEq, Eq)]
pub struct RelayedResponse {
    pub status: u16,
    /// Every header line, in order, duplicates preserved (`Set-Cookie`).
    pub headers: Vec<HeaderLine>,
    pub body: Vec<u8>,
}

/// Send one request's bytes over a pipe and read exactly one response back.
///
/// # Errors
/// I/O failure, a malformed or ambiguously framed response, or bytes beyond the declared body.
pub async fn relay_on(
    send: &mut (dyn BiStream + '_),
    recv: &mut (dyn BiStream + '_),
    request: &[u8],
    head_only: bool,
) -> Result<RelayedResponse, String> {
    write_chunked(send, request)
        .await
        .map_err(|e| format!("write: {e}"))?;
    read_response(recv, head_only).await
}

/// Read one response: head, then a `Content-Length` body.
pub async fn read_response(
    recv: &mut (dyn BiStream + '_),
    head_only: bool,
) -> Result<RelayedResponse, String> {
    let mut buf = [0u8; FRAME];
    let mut head = Vec::new();
    let header_end = loop {
        if let Some(pos) = find_header_end(&head) {
            break pos;
        }
        if head.len() > MAX_HEAD {
            return Err("response head too large".to_string());
        }
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("tunnel closed mid-response".to_string());
        }
        head.extend_from_slice(&buf[..n]);
    };
    let (status, headers) = parse_head(&head[..header_end])?;
    let mut body = head[header_end + 4..].to_vec();

    let bodiless = head_only || (100..200).contains(&status) || status == 204 || status == 304;
    let declared = framing(&headers)?;
    let want = if bodiless {
        0
    } else {
        declared.ok_or("response is not Content-Length framed")?
    };
    if want > MAX_RESPONSE_BODY {
        return Err("response body too large".to_string());
    }
    while body.len() < want {
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("tunnel closed mid-body".to_string());
        }
        body.extend_from_slice(&buf[..n]);
        if body.len() > MAX_RESPONSE_BODY {
            return Err("response body too large".to_string());
        }
    }
    if body.len() != want {
        // The agent sent more than it declared. Whatever follows belongs to no request we made.
        return Err("tunnel sent bytes beyond the declared response".to_string());
    }
    Ok(RelayedResponse {
        status,
        headers,
        body,
    })
}

/// Chunk a write into ≤ [`FRAME`] sealed frames.
pub async fn write_chunked(send: &mut (dyn BiStream + '_), data: &[u8]) -> std::io::Result<()> {
    for piece in data.chunks(FRAME) {
        send.write_all(piece).await?;
    }
    Ok(())
}

/// Find the `\r\n\r\n` that ends the header block.
fn find_header_end(head: &[u8]) -> Option<usize> {
    head.windows(4).position(|w| w == b"\r\n\r\n")
}

/// `(status, headers)` from a response head (status line + header lines, no terminator).
fn parse_head(head: &[u8]) -> Result<(u16, Vec<HeaderLine>), String> {
    let mut lines = head
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next().ok_or("empty response")?;
    let status_line =
        std::str::from_utf8(status_line).map_err(|_| "status line is not text".to_string())?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("bad status line: {status_line}"));
    }
    let status: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .filter(|c| (100..=599).contains(c))
        .ok_or_else(|| format!("bad status line: {status_line}"))?;
    let mut headers = Vec::new();
    for line in lines {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Err("malformed header line".to_string());
        };
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| "header name is not text".to_string())?;
        if name.is_empty()
            || name
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err("malformed header name".to_string());
        }
        let value = line[colon + 1..].trim_ascii();
        headers.push((name.to_string(), value.to_vec()));
    }
    Ok((status, headers))
}

/// The body length the headers declare. `Ok(None)` = no `Content-Length`.
///
/// Rejects `Transfer-Encoding` outright and any disagreement between repeated `Content-Length`
/// headers: both are request-smuggling shapes, and the agent never needs to produce either.
fn framing(headers: &[HeaderLine]) -> Result<Option<usize>, String> {
    let mut declared: Option<usize> = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("tunnel responses must not use Transfer-Encoding".to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(value).map_err(|_| "bad content-length".to_string())?;
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err("bad content-length".to_string());
            }
            let n: usize = text.parse().map_err(|_| "bad content-length".to_string())?;
            if declared.is_some_and(|d| d != n) {
                return Err("conflicting content-length headers".to_string());
            }
            declared = Some(n);
        }
    }
    Ok(declared)
}

// ── the listener ───────────────────────────────────────────────────────────

/// The dialkey the edge's tunnel identity is derived from. The agents derive
/// the same string (`overlay_agent`'s copy) — a drift between the two is a
/// dial that never authenticates, which `tests/tunnel_identity.rs` pins.
#[must_use]
pub fn tunnel_dialkey(control_secret: &str) -> String {
    format!("tas-edge:{control_secret}")
}

/// Bind the tunnel endpoint whose identity is [`transport::dialkey::peer_id`]
/// of `dialkey` — the id a dialling agent observes in the handshake.
///
/// `bind_with_dialkey` derives the secret inside `transport`. Do NOT feed
/// `dialkey::peer_id(..)` to `bind_with_key`: since transport 0.2.0 that is
/// the PUBLIC key, so the endpoint would be keyed by it and present the
/// public key of the public key (a silent identity change).
///
/// # Errors
/// The socket could not be bound.
pub async fn bind_tunnel_endpoint(
    bind: &str,
    dialkey: &str,
) -> std::io::Result<transport::native::NativeEndpoint> {
    // MUTANT edge_old_form: the pre-0.2.0 call shape against transport 0.2.0. Compiled only by
    // `RUSTFLAGS=--cfg=mutant_edge_old_form`; tests/tunnel_identity.rs must reject it.
    #[cfg(mutant_edge_old_form)]
    {
        transport::native::NativeEndpoint::bind_with_key(bind, transport::dialkey::peer_id(dialkey))
            .await
    }
    #[cfg(not(mutant_edge_old_form))]
    {
        transport::native::NativeEndpoint::bind_with_dialkey(bind, dialkey).await
    }
}

/// Parse a claim line: `register <host>` or `splice <host>`.
fn parse_claim(line: &str) -> Option<(PipeKind, String)> {
    let line = line.trim();
    let (verb, host) = line.split_once(' ')?;
    let kind = match verb {
        "register" => PipeKind::Http,
        "splice" => PipeKind::Splice,
        _ => return None,
    };
    let host = host.trim().to_ascii_lowercase();
    (!host.is_empty() && !host.contains(char::is_whitespace)).then_some((kind, host))
}

/// Accept tunnel connections: authenticate (native handshake), read the claim, attach the pipe
/// iff the authenticated peer is the connector enrolled for the claimed hostname.
///
/// The listener's identity is DERIVED from the control secret
/// (`dialkey::peer_id(`[`tunnel_dialkey`]`(secret))`, the public key) — the
/// same derivation the agents verify, so a dial authenticates the edge
/// without any key exchange. Authorising a *hostname* is not the secret's job: that is the
/// per-connector binding made at enrolment ([`TunnelRegistry::attach`]).
pub async fn run_tunnel_listener(bind: &str, registry: TunnelRegistry, control_secret: &str) {
    let endpoint = match bind_tunnel_endpoint(bind, &tunnel_dialkey(control_secret)).await {
        Ok(e) => e,
        Err(e) => {
            warn!("tunnel listener bind failed on {bind}: {e}");
            return;
        }
    };
    serve_tunnel_endpoint(endpoint, registry).await;
}

/// The accept loop over an already-bound endpoint (split out so tests can bind port 0 and learn
/// the address).
pub async fn serve_tunnel_endpoint(
    endpoint: transport::native::NativeEndpoint,
    registry: TunnelRegistry,
) {
    loop {
        let Some(conn) = endpoint.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let peer = peer_hex(&conn.peer_id());
        let registry = registry.clone();
        tokio::spawn(async move {
            let Ok((send, mut recv)) = conn.open_bi().await else {
                warn!(%peer, "tunnel open_bi failed");
                return;
            };
            // One sealed frame carries the whole claim; read into a buffer that fits it.
            let mut chunk = [0u8; FRAME];
            let n = match tokio::time::timeout(CLAIM_TIMEOUT, recv.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let Some(newline) = chunk[..n].iter().position(|b| *b == b'\n') else {
                warn!(%peer, "tunnel claim frame has no newline");
                return;
            };
            let claim = String::from_utf8_lossy(&chunk[..newline]).to_string();
            let Some((kind, hostname)) = parse_claim(&claim) else {
                warn!(%peer, "bad tunnel claim");
                return;
            };
            let conn: Arc<dyn Connection> = Arc::new(conn);
            if let Err(e) = registry.attach(&hostname, kind, conn, send, recv) {
                warn!(%peer, %hostname, error = %e, "tunnel claim refused");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::elidable_lifetime_names,
        reason = "test code: deterministic assertions on fixtures; the BiStream impl mirrors the trait signature"
    )]
    use super::*;

    fn head(status_and_headers: &str) -> Vec<u8> {
        status_and_headers.as_bytes().to_vec()
    }

    #[test]
    fn framing_accepts_one_length_and_rejects_every_smuggling_shape() {
        let h = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(n, v)| ((*n).to_string(), v.as_bytes().to_vec()))
                .collect::<Vec<_>>()
        };
        assert_eq!(framing(&h(&[("Content-Length", "42")])).unwrap(), Some(42));
        assert_eq!(
            framing(&h(&[("content-length", "7"), ("Content-Length", "7")])).unwrap(),
            Some(7),
            "identical repeats are harmless"
        );
        assert_eq!(framing(&h(&[("X", "y")])).unwrap(), None);
        assert!(
            framing(&h(&[("content-length", "7"), ("content-length", "8")])).is_err(),
            "disagreement"
        );
        assert!(framing(&h(&[("Transfer-Encoding", "chunked")])).is_err());
        assert!(framing(&h(&[("content-length", "+7")])).is_err());
        assert!(framing(&h(&[("content-length", "7, 7")])).is_err());
        assert!(framing(&h(&[("content-length", "")])).is_err());
        assert!(framing(&h(&[("content-length", "99999999999999999999999")])).is_err());
    }

    #[test]
    fn parse_head_keeps_duplicate_headers_and_rejects_garbage() {
        let (status, headers) = parse_head(&head(
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nContent-Length: 0",
        ))
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
                .count(),
            2
        );
        assert!(parse_head(b"HTTP/2 200 OK").is_err());
        assert!(parse_head(b"HTTP/1.1 99 Low").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nno colon here").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\n bad name: x").is_err());
    }

    #[test]
    fn claims_parse_strictly() {
        assert_eq!(
            parse_claim("register App.Example.com"),
            Some((PipeKind::Http, "app.example.com".into()))
        );
        assert_eq!(
            parse_claim("splice a.b"),
            Some((PipeKind::Splice, "a.b".into()))
        );
        assert_eq!(parse_claim("register"), None);
        assert_eq!(parse_claim("steal a.b"), None);
        assert_eq!(parse_claim("register a b"), None);
    }

    // ── pipe-level tests over an in-memory duplex ────────────────────────────────────────

    /// A `BiStream` over one half of a tokio duplex, with the FRAME read discipline the sealed
    /// stream has (a read returns at most one write's worth, here approximated by a plain read).
    struct Half {
        r: Option<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        w: Option<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
    }
    impl BiStream for Half {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> transport::BoxFuture<'a, std::io::Result<usize>> {
            Box::pin(async move {
                use tokio::io::AsyncReadExt as _;
                self.r
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("write half"))?
                    .read(buf)
                    .await
            })
        }
        fn read_exact<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> transport::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async move {
                use tokio::io::AsyncReadExt as _;
                self.r
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("write half"))?
                    .read_exact(buf)
                    .await
                    .map(|_| ())
            })
        }
        fn write_all<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> transport::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async move {
                use tokio::io::AsyncWriteExt as _;
                self.w
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("read half"))?
                    .write_all(data)
                    .await
            })
        }
        fn finish<'a>(&'a mut self) -> transport::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(async move {
                use tokio::io::AsyncWriteExt as _;
                self.w
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("read half"))?
                    .shutdown()
                    .await
            })
        }
    }

    /// (edge send, edge recv, agent send, agent recv) wired back to back.
    type Pipes = (
        Box<dyn BiStream>,
        Box<dyn BiStream>,
        Box<dyn BiStream>,
        Box<dyn BiStream>,
    );

    fn pipes() -> Pipes {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        (
            Box::new(Half {
                r: None,
                w: Some(a_w),
            }), // edge send  → agent recv
            Box::new(Half {
                r: Some(a_r),
                w: None,
            }), // edge recv  ← agent send
            Box::new(Half {
                r: None,
                w: Some(b_w),
            }), // agent send → edge recv
            Box::new(Half {
                r: Some(b_r),
                w: None,
            }), // agent recv ← edge send
        )
    }

    #[tokio::test]
    async fn binary_bodies_and_multi_frame_responses_round_trip_exactly() {
        let (mut es, mut er, mut as_, mut ar) = pipes();
        // Not UTF-8, longer than one frame, includes \r\n\r\n inside the body.
        let body: Vec<u8> = (0..20_000u32)
            .map(|i| (i % 251) as u8)
            .chain(*b"\r\n\r\nHTTP/1.1 200 OK\r\n")
            .collect();
        let expected = body.clone();
        let agent = tokio::spawn(async move {
            let mut buf = [0u8; FRAME];
            let n = ar.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET / HTTP/1.1"));
            let mut resp = format!("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            resp.extend_from_slice(&body);
            write_chunked(&mut *as_, &resp).await.unwrap();
        });
        let r = relay_on(
            &mut *es,
            &mut *er,
            b"GET / HTTP/1.1\r\nhost: x\r\n\r\n",
            false,
        )
        .await
        .unwrap();
        agent.await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, expected);
        assert_eq!(
            r.headers.iter().filter(|(n, _)| n == "Set-Cookie").count(),
            2
        );
    }

    #[tokio::test]
    async fn a_head_response_has_a_length_but_no_body_and_trailing_bytes_are_a_protocol_error() {
        let (mut es, mut er, mut as_, mut ar) = pipes();
        let agent = tokio::spawn(async move {
            let mut buf = [0u8; FRAME];
            let _ = ar.read(&mut buf).await.unwrap();
            as_.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n")
                .await
                .unwrap();
        });
        let r = relay_on(&mut *es, &mut *er, b"HEAD / HTTP/1.1\r\n\r\n", true)
            .await
            .unwrap();
        agent.await.unwrap();
        assert!(r.body.is_empty());
        assert!(r
            .headers
            .iter()
            .any(|(n, v)| n == "Content-Length" && v == b"9000"));

        let (mut es, mut er, mut as_, mut ar) = pipes();
        let agent = tokio::spawn(async move {
            let mut buf = [0u8; FRAME];
            let _ = ar.read(&mut buf).await.unwrap();
            as_.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA")
                .await
                .unwrap();
        });
        let e = relay_on(&mut *es, &mut *er, b"GET / HTTP/1.1\r\n\r\n", false)
            .await
            .unwrap_err();
        agent.await.unwrap();
        assert!(e.contains("beyond"), "{e}");
    }

    #[tokio::test]
    async fn chunked_and_unframed_responses_are_refused() {
        for resp in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\nbody until close"[..],
        ] {
            let (mut es, mut er, mut as_, mut ar) = pipes();
            let resp = resp.to_vec();
            let agent = tokio::spawn(async move {
                let mut buf = [0u8; FRAME];
                let _ = ar.read(&mut buf).await.unwrap();
                as_.write_all(&resp).await.unwrap();
            });
            assert!(
                relay_on(&mut *es, &mut *er, b"GET / HTTP/1.1\r\n\r\n", false)
                    .await
                    .is_err()
            );
            agent.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_heads_and_bodies_are_refused_without_buffering_them() {
        let (mut es, mut er, mut as_, mut ar) = pipes();
        let agent = tokio::spawn(async move {
            let mut buf = [0u8; FRAME];
            let _ = ar.read(&mut buf).await.unwrap();
            as_.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_RESPONSE_BODY + 1
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });
        let e = relay_on(&mut *es, &mut *er, b"GET / HTTP/1.1\r\n\r\n", false)
            .await
            .unwrap_err();
        agent.await.unwrap();
        assert!(e.contains("too large"), "{e}");
    }

    // ── registry-level tests with a scripted connection ──────────────────────────────────

    struct FakeConn {
        peer: PeerId,
        closed: std::sync::atomic::AtomicBool,
    }
    impl Connection for FakeConn {
        fn open_bi<'a>(
            &'a self,
        ) -> transport::BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>>
        {
            Box::pin(async { Err(std::io::Error::other("fake")) })
        }
        fn accept_bi<'a>(
            &'a self,
        ) -> transport::BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>>
        {
            Box::pin(async { Err(std::io::Error::other("fake")) })
        }
        fn peer_id(&self) -> PeerId {
            self.peer
        }
        fn close<'a>(&'a self) -> transport::BoxFuture<'a, std::io::Result<()>> {
            self.closed.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    fn fake(peer: PeerId) -> Arc<FakeConn> {
        Arc::new(FakeConn {
            peer,
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[tokio::test]
    async fn only_the_enrolled_connector_may_claim_a_hostname() {
        let state = EdgeState::ephemeral();
        let reg = TunnelRegistry::new(state.clone());
        assert!(reg
            .register("app.acme.example", 8080, None, [1; 32])
            .unwrap());
        assert!(
            !reg.register("app.acme.example", 8080, None, [1; 32])
                .unwrap(),
            "idempotent for the same connector"
        );
        assert!(
            reg.register("app.acme.example", 8080, None, [2; 32])
                .is_err(),
            "no takeover by re-enrolling"
        );
        assert!(reg.register("x.example", 0, None, [1; 32]).is_err());
        assert!(reg.register("x.example", 80, None, [0; 32]).is_err());

        let (es, _er, _as, ar) = pipes();
        let thief = fake([9; 32]);
        assert_eq!(
            reg.attach("app.acme.example", PipeKind::Http, thief.clone(), es, ar),
            Err(ClaimError::WrongPeer)
        );
        assert!(!reg.is_online("app.acme.example"));
        assert!(
            !state.pool.lock().unwrap().is_online([9; 32]),
            "a refused claim must not make anyone look online"
        );

        let (es, _er, _as, ar) = pipes();
        assert_eq!(
            reg.attach("nope.example", PipeKind::Http, fake([1; 32]), es, ar),
            Err(ClaimError::UnknownHostname)
        );

        let (es, _er, _as, ar) = pipes();
        reg.attach("app.acme.example", PipeKind::Http, fake([1; 32]), es, ar)
            .unwrap();
        assert!(reg.is_online("app.acme.example"));
        assert!(state.pool.lock().unwrap().is_online([1; 32]));
        assert!(reg.revoke("app.acme.example"));
        assert!(
            !state.pool.lock().unwrap().is_online([1; 32]),
            "revocation takes the connector offline immediately"
        );
        assert!(!reg.revoke("app.acme.example"));
    }

    #[tokio::test]
    async fn a_failed_exchange_drops_the_pipe_and_a_late_response_can_never_reach_the_next_request()
    {
        let state = EdgeState::ephemeral();
        let reg = TunnelRegistry::new(state.clone());
        reg.register("a.example", 80, None, [1; 32]).unwrap();

        // Pipe 1: the agent replies with garbage (a protocol error), then would reply "late".
        let (es, er, mut as1, mut ar) = pipes();
        let c = fake([1; 32]);
        reg.attach("a.example", PipeKind::Http, c, es, er).unwrap();
        let agent = tokio::spawn(async move {
            let mut buf = [0u8; FRAME];
            let _ = ar.read(&mut buf).await.unwrap();
            as1.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            as1
        });
        let err = reg
            .relay("a.example", b"GET / HTTP/1.1\r\n\r\n", false)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::Failed(_)));
        let _late = agent.await.unwrap();
        // The pipe is gone: the peer is offline, and the next request cannot be served by it.
        assert!(!reg.is_online("a.example"));
        assert!(!state.pool.lock().unwrap().is_online([1; 32]));
        let next = reg
            .relay("a.example", b"GET /next HTTP/1.1\r\n\r\n", false)
            .await
            .unwrap_err();
        assert!(matches!(next, RelayError::Unavailable(_)));
    }

    #[tokio::test]
    async fn concurrent_requests_use_separate_pipes_and_a_slow_one_does_not_block_a_fast_one() {
        let state = EdgeState::ephemeral();
        let reg = TunnelRegistry::new(state);
        reg.register("a.example", 80, None, [1; 32]).unwrap();
        let mut agents = Vec::new();
        for slow in [true, false] {
            let (es, er, mut as_, mut ar) = pipes();
            reg.attach("a.example", PipeKind::Http, fake([1; 32]), es, er)
                .unwrap();
            agents.push(tokio::spawn(async move {
                let mut buf = [0u8; FRAME];
                let n = ar.read(&mut buf).await.unwrap();
                let who = if buf[..n].starts_with(b"GET /slow") {
                    "slow"
                } else {
                    "fast"
                };
                if who == "slow" {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                as_.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{who}",
                        who.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                let _ = slow;
            }));
        }
        let reg2 = reg.clone();
        let slow = tokio::spawn(async move {
            reg2.relay("a.example", b"GET /slow HTTP/1.1\r\n\r\n", false)
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t = std::time::Instant::now();
        let fast = reg
            .relay("a.example", b"GET /fast HTTP/1.1\r\n\r\n", false)
            .await
            .unwrap();
        assert_eq!(fast.body, b"fast");
        assert!(
            t.elapsed() < Duration::from_millis(300),
            "fast request waited behind the slow one"
        );
        assert_eq!(slow.await.unwrap().unwrap().body, b"slow");
        for a in agents {
            a.await.unwrap();
        }
    }
}
