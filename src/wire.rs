// The wire itself: the plain/TLS `Stream`, the buffered `StreamReader`, client and server
// TLS config (PEM -> DER by hand), `serve_tls`, the Pingora-style keepalive connection
// pool, and request write / response read -- buffered, streaming, and chunked.
//
// Ported from bedrock's `native_lib::wire` (originally `include!`d into `native_lib.rs`,
// sharing its flat scope); here it's a real module, paired with `crate::http_types`.

use std::borrow::Cow;
use std::io;
use hashtrinity::{Coord, CoordMap};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::http_types::*;

// -- Wire ----------------------------------------------------------------

pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Stream {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf).await,
            Stream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf).await,
            Stream::Tls(s) => s.read(buf).await,
        }
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => {
                s.read_exact(buf).await?;
            }
            Stream::Tls(s) => {
                s.read_exact(buf).await?;
            }
        }
        Ok(())
    }

    async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read_to_end(buf).await,
            Stream::Tls(s) => s.read_to_end(buf).await,
        }
    }

    fn into_reader(self) -> StreamReader {
        StreamReader {
            inner: self,
            buf: Vec::new(),
            pos: 0,
            line: Vec::new(),
        }
    }
}

struct StreamReader {
    inner: Stream,
    buf: Vec<u8>,
    pos: usize,
    line: Vec<u8>,
}

impl StreamReader {
    async fn read_line(&mut self) -> io::Result<&[u8]> {
        self.line.clear();
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|b| *b == b'\n') {
                let end = self.pos + i + 1;
                self.line.extend_from_slice(&self.buf[self.pos..end]);
                self.pos = end;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Ok(&self.line);
            }

            if self.pos < self.buf.len() {
                self.line.extend_from_slice(&self.buf[self.pos..]);
                self.buf.clear();
                self.pos = 0;
            } else {
                self.buf.clear();
                self.pos = 0;
            }

            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                return Ok(&self.line);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut copied = 0;
        let buffered = (self.buf.len() - self.pos).min(len);
        if buffered > 0 {
            buf[..buffered].copy_from_slice(&self.buf[self.pos..self.pos + buffered]);
            self.pos += buffered;
            copied = buffered;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
        }
        if copied < len {
            self.inner.read_exact_into(&mut buf[copied..]).await?;
        }
        Ok(buf)
    }

    async fn read_to_end(&mut self, out: &mut Vec<u8>) -> io::Result<usize> {
        let before = out.len();
        if self.pos < self.buf.len() {
            out.extend_from_slice(&self.buf[self.pos..]);
            self.buf.clear();
            self.pos = 0;
        }
        self.inner.read_to_end(out).await?;
        Ok(out.len() - before)
    }

    /// Read UP TO `max` bytes — whatever's already buffered first, else one read from the
    /// underlying stream (0 on EOF). Unlike `read_exact`, never blocks waiting to fill `max`;
    /// this is the "give me the next available piece" primitive `StreamingResponse`'s
    /// read-until-EOF framing needs.
    async fn read_some(&mut self, max: usize, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(max);
            buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Ok(n);
        }
        self.inner.read(&mut buf[..max]).await
    }

    /// Reclaim the underlying `Stream` (for connection pooling) plus any bytes already read off
    /// the wire but not yet consumed by the caller — losing these would corrupt whatever the
    /// NEXT request on a reused connection tries to read (they'd belong to the tail of THIS
    /// response, not the start of the next one). Only safe to call once the caller knows the
    /// current response has been read to completion (`send_request` only does this after a
    /// Content-Length or chunked-terminated body, never the "read until EOF" fallback, which by
    /// definition means the peer is closing the connection).
    fn into_inner(self) -> (Stream, Vec<u8>) {
        let leftover = self.buf[self.pos..].to_vec();
        (self.inner, leftover)
    }
}

/// The TLS client config, built once from the system's own CA trust store
/// (`rustls-native-certs` — the same "prefer OS package signatures" discipline as
/// everywhere else in this workspace) and cached: every `https://` request reuses it.
fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // `ClientConfig::builder()` (no explicit provider) reads the process-wide default
            // `CryptoProvider` — rustls 0.23 never auto-installs one even with the `ring`
            // feature enabled (that only makes it linkable). Nothing else in this crate installs
            // it, so the first real HTTPS request from ANY consumer would otherwise panic here.
            // `install_default` errors only if a provider is already installed (by this crate or
            // a consumer) — harmless, the existing one wins either way.
            // The provider is chosen explicitly: under `fips` it is the FIPS-approved one, never
            // whatever the process happens to have installed first.
            #[cfg(feature = "fips")]
            let provider = rustls::crypto::default_fips_provider();
            #[cfg(not(feature = "fips"))]
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            let _ = provider.clone().install_default();
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("the provider supports the default TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            debug_assert_eq!(config.fips(), cfg!(feature = "fips"), "client TLS must be FIPS exactly when built for it");
            std::sync::Arc::new(config)
        })
        .clone()
}

// Server-side pieces (`tls_server_config`, `serve_tls`, PEM parsing, and the
// `Router`/`serve_connection`/`httpsrv` machinery they depend on) were intentionally left
// behind in this port: this crate's `pkarr::RelayClient` is a pure HTTP *client* (it only
// ever calls a relay, never accepts connections) and doesn't reach any of it. Re-add if/when
// this crate grows a server role.

// -- Connection pool (Pingora-style keepalive reuse) ---------------------

/// A pooled, idle connection plus any bytes already pulled off the wire past the previous
/// response's end (see `StreamReader::into_inner`'s doc for why this must travel with it).
struct PooledConn {
    stream: Stream,
    leftover: Vec<u8>,
}

/// Max idle connections kept per upstream identity — mirrors Pingora's own
/// `keepalive_pool_size` (a per-identity cap, not a global one). Small and fixed rather than
/// configurable yet: an honest scope limit, not a hidden one.
const POOL_CAP_PER_IDENTITY: usize = 32;

/// Process-global keepalive pool, keyed by upstream identity (`scheme://host:port`) — mirrors
/// Pingora's own `pingora-core::connectors` pool (an `Arc<ConnectionPool>` keyed by
/// `peer.reuse_hash()`). This is the single biggest gap the architecture survey found on the
/// client side ("No connection pooling/keep-alive reuse... new TCP+TLS handshake per request").
/// `CoordMap` (not a synchronized `Table`) is fine here because the `Mutex` around it is the
/// actual synchronization — matches this file's own established convention of using
/// `identity.coord()` for a bounded, small set of distinct upstream identities (the same shape
/// `Router`'s route keys and `Proxy`'s upstream keys already use), not the opaque-hash misuse
/// `Extensions` had to move off of.
fn pool() -> &'static std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(CoordMap::coordinate()))
}

fn identity_for(uri: &Uri) -> Result<String> {
    let (host, port) = host_port(uri)?;
    let scheme = uri.scheme_str().unwrap_or("http");
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Pop the most-recently-returned idle connection for `identity`, if any (LIFO — better cache
/// locality than FIFO for the common bursty-traffic case). Takes the WHOLE per-identity `Vec`
/// out via `remove` (ownership, no clone — `PooledConn` holds a live socket and can't be cloned
/// anyway) and puts back whatever's left, rather than trying to mutate through a shared `&Vec`.
fn pool_take(identity: &str) -> Option<PooledConn> {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key)?;
    let popped = conns.pop();
    if !conns.is_empty() {
        guard.put(key, conns);
    }
    popped
}

/// Return an idle connection to the pool for reuse, capped at `POOL_CAP_PER_IDENTITY` (excess
/// connections are simply dropped/closed rather than kept, matching Pingora's own per-identity
/// cap behavior).
fn pool_put(identity: &str, conn: PooledConn) {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key).unwrap_or_default();
    if conns.len() < POOL_CAP_PER_IDENTITY {
        conns.push(conn);
    }
    guard.put(key, conns);
}

/// Connect, preferring a pooled idle connection. Returns whether the connection came from the
/// pool — the caller needs this to know whether a first-write failure warrants a transparent
/// retry on a guaranteed-fresh connection (a reused connection can always turn out to be stale:
/// the peer's own idle timeout, a network blip, or — found via this crate's own test suite — a
/// connection pooled under one tokio runtime and reused from a different one, since a socket is
/// registered with the specific runtime's I/O driver that was active when it was created. All
/// three are the same class of problem a robust pool has to handle, not paper over: never trust
/// an idle connection's first write to succeed).
pub(crate) async fn connect(uri: &Uri, resolve: &std::collections::HashMap<String, std::net::SocketAddr>) -> Result<(Stream, bool)> {
    let identity = identity_for(uri)?;
    if let Some(pooled) = pool_take(&identity) {
        tracing::debug!(target: "bedrock::client", %identity, "reusing pooled connection");
        // A pooled connection is only ever stored with an empty `leftover` (see `send_request`'s
        // pool-return step, which only pools a connection when there wasn't any) — there's no
        // plumbing here to hand leftover bytes into a fresh `send_request` call, so this
        // invariant is asserted rather than silently trusted.
        debug_assert!(pooled.leftover.is_empty(), "pooled connections are only stored with no leftover bytes");
        return Ok((pooled.stream, true));
    }
    Ok((connect_fresh(uri, resolve).await?, false))
}

/// Always open a brand new connection, bypassing the pool entirely — used for the initial
/// connect when nothing's pooled, and for the guaranteed-fresh retry after a pooled connection's
/// first write fails. `resolve` overrides the socket address a host connects to (reqwest's
/// `.resolve()`) while keeping the ORIGINAL hostname for TLS SNI — only the IP changes.
pub(crate) async fn connect_fresh(
    uri: &Uri,
    resolve: &std::collections::HashMap<String, std::net::SocketAddr>,
) -> Result<Stream> {
    let (host, port) = host_port(uri)?;
    let dial_target = resolve.get(&host).copied();
    match uri.scheme_str() {
        Some("https") => {
            let tcp = match dial_target {
                Some(addr) => nodelay(TcpStream::connect(addr).await?),
                None => nodelay(TcpStream::connect(format!("{}:{}", host, port)).await?),
            };
            let server_name = rustls_pki_types::ServerName::try_from(host.clone())
                .map_err(|e| Error::Tls(format!("invalid hostname {host:?}: {e}")))?
                .to_owned();
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Tls(format!("handshake with {host} failed: {e}")))?;
            Ok(Stream::Tls(Box::new(tls)))
        }
        _ => Ok(Stream::Plain(match dial_target {
            Some(addr) => nodelay(TcpStream::connect(addr).await?),
            None => nodelay(TcpStream::connect(format!("{}:{}", host, port)).await?),
        })),
    }
}

/// HTTP is many small writes and one wait for the answer: do not hold the small ones back.
fn nodelay(s: TcpStream) -> TcpStream {
    let _ = s.set_nodelay(true);
    s
}

/// Write the request line, headers, and body — shared by the buffered (`send_request`) and
/// streaming (`send_request_streaming`) paths; they only diverge on how the RESPONSE body gets
/// read, never on how the request itself goes out.
/// The `User-Agent` value to serialize, or `None` when the caller already supplied one.
///
/// Split out from [`write_request`] because it is the whole decision and the one
/// thing here worth a test: the wire is a live socket, so a regression in this
/// function is invisible to every other test in the crate. An empty caller value
/// falls back to the transport default rather than serializing `User-Agent: `,
/// which some servers reject and others read as a malformed request.
fn effective_user_agent(headers: &HeaderMap) -> Option<Cow<'_, str>> {
    let Some(supplied) = headers.get(crate::http_types::header::USER_AGENT) else {
        return Some(Cow::Borrowed(DEFAULT_USER_AGENT));
    };
    let text = std::str::from_utf8(supplied.as_bytes()).unwrap_or_default().trim();
    // An empty caller value falls back rather than serializing `User-Agent: `,
    // which some servers reject outright.
    if text.is_empty() {
        return Some(Cow::Borrowed(DEFAULT_USER_AGENT));
    }
    Some(Cow::Owned(text.to_owned()))
}

/// The value written when the caller names no agent.
const DEFAULT_USER_AGENT: &str = "bedrock/0.1.0";

async fn write_request(
    stream: &mut Stream,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Option<Vec<u8>>,
) -> Result<()> {
    // One request, one write. A write per header leaves the peer with dozens of tiny segments, and Nagle's
    // algorithm plus the peer's delayed ACK then hold the tail back for ~40 ms on every request.
    stream.write_all(&encode_request(method, uri, headers, body)).await?;
    Ok(())
}

/// The request line, headers, `Content-Length` and body as the bytes that go on the wire.
fn encode_request(method: &Method, uri: &Uri, headers: &HeaderMap, body: &Option<Vec<u8>>) -> Vec<u8> {
    let path = uri.path_and_query();
    let host = uri.host().unwrap_or("");
    let authority = match uri.port_u16() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    let mut out: Vec<u8> = Vec::with_capacity(256 + body.as_ref().map_or(0, Vec::len));
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, authority).as_bytes());
    // A caller-supplied User-Agent wins.
    //
    // This used to be unconditional, so `RequestBuilder::header(USER_AGENT, …)` sent
    // the transport's value AND the caller's — two `User-Agent:` lines, which a
    // server is free to read as either or both. webfold's fetch adapter responded
    // by refusing a caller User-Agent outright on the direct path, so a client
    // could not identify itself at all; the practical effect was that every
    // request left this crate claiming to be `bedrock/0.1.0`, whatever was actually
    // making it, and origins that gate on the agent string (Google's asset CDN
    // among them) served a sign-in page instead of the file.
    if let Some(agent) = effective_user_agent(headers) {
        out.extend_from_slice(format!("User-Agent: {agent}\r\n").as_bytes());
    }

    for (name, value) in headers.iter() {
        // Skip the agent: it was written above, under its canonical casing. Leaving
        // it in the loop is how the request ends up with two `User-Agent` lines —
        // the transport's spelling and the caller's — which is the defect this
        // whole change exists to remove, so it is skipped rather than duplicated.
        if name.eq_ignore_ascii_case(crate::http_types::header::USER_AGENT) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if let Some(ref body) = body {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if let Some(body) = body {
        out.extend_from_slice(body);
    }
    out
}

/// The parsed response status line + headers, before the body is touched — shared by both the
/// buffered and streaming read paths.
struct ResponseHead {
    version: Version,
    status: StatusCode,
    headers: HeaderMap,
    content_length: Option<usize>,
    chunked: bool,
}

async fn read_response_head(reader: &mut StreamReader) -> Result<ResponseHead> {
    let raw = reader.read_line().await?;
    let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
    let (version, status) = parse_status_line(line)?;

    let mut headers = HeaderMap::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let raw = reader.read_line().await?;
        if raw.is_empty() || raw == b"\r\n" || raw == b"\n" {
            break;
        }
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        if let Some((n, v)) = line.split_once(':') {
            let name = n.parse::<HeaderName>()?;
            let value = v.trim().parse::<HeaderValue>()?;
            if name.as_str() == header::CONTENT_LENGTH {
                content_length = value.to_str().ok().and_then(|s| s.parse().ok());
            }
            if name.as_str() == header::TRANSFER_ENCODING
                && value.to_str().unwrap_or("").contains("chunked")
            {
                chunked = true;
            }
            headers.insert(name, value);
        }
    }
    Ok(ResponseHead { version, status, headers, content_length, chunked })
}

pub(crate) async fn send_request(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<Response> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    // Only a DEFINITE-length body (no body at all, Content-Length, or a chunked terminator) means
    // the connection is genuinely still usable afterward — the "read to end" fallback below means
    // there was no length information at all, which in practice means the peer intends to close
    // the connection once the body is sent, so pooling that stream would just hand back a socket
    // that's already going away.
    // RFC 9110 §9.3.2: a response to HEAD never has a body, whatever Content-Length says (and
    // many servers, Go's net/http among them, send none at all). Reading "until close" here made
    // `HEAD` hang for the server's idle timeout on a keep-alive connection — ACME's `newNonce`
    // is exactly such a request.
    let (body, poolable) = if method == Method::HEAD
        || head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
    {
        (Vec::new(), true)
    } else if head.chunked {
        (read_chunked(&mut reader).await?, true)
    } else if let Some(len) = head.content_length {
        let b = if len > 0 { reader.read_exact(len).await? } else { Vec::new() };
        (b, true)
    } else {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        (buf, false)
    };

    // Return the connection to the pool if the response as a whole allows reuse: a definite-
    // length body (above), HTTP/1.1 (matches this crate's own server-side keep-alive default,
    // `serve()`'s `connection_close` check), and neither side said `Connection: close`.
    if poolable && head.version != Version::HTTP_10 && !connection_close(&head.headers) {
        let (stream, leftover) = reader.into_inner();
        if leftover.is_empty() {
            if let Ok(identity) = identity_for(uri) {
                pool_put(&identity, PooledConn { stream, leftover });
            }
        }
        // A non-empty leftover means the peer sent extra bytes we haven't consumed (unusual for
        // a non-pipelined client, but possible) — there's no plumbing to hand them to whatever
        // uses this connection next, so the connection is simply dropped/closed here instead of
        // risking a corrupted next read. Honest, not silent: this is exactly the situation
        // `into_inner`'s own doc calls out.
    }

    Ok(Response {
        status: head.status,
        version: head.version,
        headers: head.headers,
        body,
        url: uri.clone(),
        extensions: Extensions::new(),
    })
}

/// How the still-open body is framed — decided once from the response head, then consumed
/// incrementally by `StreamingResponse::chunk`.
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

/// A response whose body has NOT been read yet — `reqwest::Response::chunk`/`bytes_stream`'s
/// equivalent. Never pools its connection (a caller can stop draining partway through; pooling
/// would then hand the next request a stream mid-body), a deliberate, conservative simplicity
/// over squeezing pooling out of the streaming path too.
pub struct StreamingResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    url: Uri,
    reader: StreamReader,
    framing: BodyFraming,
}

impl StreamingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn url(&self) -> &Uri {
        &self.url
    }

    /// Read the next chunk of the body, or `None` once it's exhausted — reqwest's `chunk()`.
    /// A `Content-Length` body is read in ≤64KiB pieces; a chunked body yields exactly one
    /// wire-chunk per call (already a natural unit, no extra buffering needed); a headerless
    /// body reads whatever's available up to 64KiB until EOF.
    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>> {
        const MAX_CHUNK: usize = 64 * 1024;
        match &mut self.framing {
            BodyFraming::None => Ok(None),
            BodyFraming::ContentLength(remaining) => {
                if *remaining == 0 {
                    return Ok(None);
                }
                // `read_some`, not `read_exact` — the latter blocks until the FULL requested
                // amount arrives, which would silently coalesce however many real TCP segments
                // the body came in into one chunk for any body under `MAX_CHUNK` (the common
                // case). Returning whatever's actually available right now is the point of
                // streaming at all.
                let take = (*remaining).min(MAX_CHUNK);
                let mut buf = vec![0u8; take];
                let n = self.reader.read_some(take, &mut buf).await?;
                if n == 0 {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("connection closed with {remaining} content-length bytes still expected"),
                    )));
                }
                buf.truncate(n);
                *remaining -= n;
                Ok(Some(buf))
            }
            BodyFraming::Chunked => {
                let raw = self.reader.read_line().await?;
                let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
                let size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
                    .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
                if size == 0 {
                    self.framing = BodyFraming::None;
                    return Ok(None);
                }
                let data = self.reader.read_exact(size).await?;
                self.reader.read_line().await?; // trailing CRLF after the chunk data
                Ok(Some(data))
            }
            BodyFraming::UntilEof => {
                let mut buf = vec![0u8; MAX_CHUNK];
                let n = self.reader.read_some(MAX_CHUNK, &mut buf).await?;
                if n == 0 {
                    self.framing = BodyFraming::None;
                    Ok(None)
                } else {
                    buf.truncate(n);
                    Ok(Some(buf))
                }
            }
        }
    }

    /// Drain every remaining chunk into one buffer — for callers that started streaming but
    /// decide midway they want the whole thing after all.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

pub(crate) async fn send_request_streaming(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<StreamingResponse> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    let framing = if method == Method::HEAD
        || head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
    {
        BodyFraming::None
    } else if head.chunked {
        BodyFraming::Chunked
    } else if let Some(len) = head.content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::UntilEof
    };

    Ok(StreamingResponse {
        status: head.status,
        version: head.version,
        headers: head.headers,
        url: uri.clone(),
        reader,
        framing,
    })
}

/// Whether a response's `Connection` header says `close` — client and server both need this to
/// decide poolability, but it lived in the (not-ported) server-side `router.rs`; inlined here
/// since it's five lines and this is the only caller left.
fn connection_close(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("close"))
        .unwrap_or(false)
}

fn parse_status_line(line: &str) -> Result<(Version, StatusCode)> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::Parse(format!("bad status line: {line}")));
    }
    let version = match parts[0] {
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    };
    let code = parts[1]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("bad status code: {e}")))?;
    Ok((version, StatusCode::from_u16(code)?))
}

async fn read_chunked(reader: &mut StreamReader) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let raw = reader.read_line().await?;
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let chunk_size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
            .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
        if chunk_size == 0 {
            break;
        }
        let chunk = reader.read_exact(chunk_size).await?;
        body.extend_from_slice(&chunk);
        reader.read_line().await?;
    }
    Ok(body)
}

#[cfg(test)]
mod wire_head_tests {
    //! The request head as it reaches the socket.
    //!
    //! These are loopback tests on purpose. The decision function has unit tests,
    //! but a unit test cannot catch `write_request` failing to *use* it — and that
    //! was the entire defect: the decision existed nowhere, the wire wrote
    //! `bedrock/0.1.0` unconditionally, and every client inherited it. Only a
    //! request that actually lands on a socket proves what went out.
    //!
    //! A single `TcpListener` on an ephemeral port, one request, and the bytes the
    //! server received. No network, no fixture, no DNS.

    use crate::http_types::header::USER_AGENT;
    use crate::http_types::{HeaderMap, Method};
    use crate::http_types::Uri;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn receive_once(listener: TcpListener) -> Vec<u8> {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a client must connect")
            .expect("accept");
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
            .await
            .expect("the client must send a head")
            .expect("read");
        buf.truncate(n);
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        buf
    }

    /// Every `User-Agent:` line in a raw request, in order.
    fn user_agent_lines(raw: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(raw)
            .lines()
            .filter_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("user-agent")
                    .then(|| value.trim().to_string())
            })
            .collect()
    }

    async fn head_over_loopback(headers: HeaderMap) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move { receive_once(listener).await });
        let uri: Uri = format!("http://{addr}/x").parse().expect("uri");
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        crate::wire::send_request(crate::wire::Stream::Plain(stream), Method::GET, &uri, headers, None)
            .await
            .expect("send");
        server.await.expect("the loopback server task must not panic")
    }

    /// The whole request is one buffer: this is what keeps it in one write (see `write_request`).
    #[test]
    fn the_request_is_encoded_as_one_buffer_with_the_exact_wire_bytes() {
        let uri: Uri = "http://example.test:8080/a?b=1".parse().expect("uri");
        let mut headers = HeaderMap::new();
        headers.insert("accept", "*/*");
        headers.insert(USER_AGENT, "webfold/0.1");
        let got = super::encode_request(&Method::POST, &uri, &headers, &Some(b"xyz".to_vec()));
        let text = String::from_utf8(got).expect("ascii");
        assert!(text.starts_with("POST /a?b=1 HTTP/1.1\r\nHost: example.test:8080\r\nUser-Agent: webfold/0.1\r\n"), "{text:?}");
        assert!(text.contains("accept: */*\r\n"), "{text:?}");
        assert!(text.ends_with("Content-Length: 3\r\n\r\nxyz"), "{text:?}");
        assert_eq!(text.matches("ser-Agent").count(), 1, "one agent: {text:?}");
    }

    /// A fresh plain connection has Nagle off, so a small write is never held back waiting for an ACK.
    #[tokio::test]
    async fn a_fresh_plain_connection_has_nodelay_set() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let _server = tokio::spawn(async move { listener.accept().await });
        let uri: Uri = format!("http://{addr}/").parse().expect("uri");
        let stream = crate::wire::connect_fresh(&uri, &std::collections::HashMap::new()).await.expect("connect");
        match stream {
            crate::wire::Stream::Plain(s) => assert!(s.nodelay().expect("nodelay"), "TCP_NODELAY must be set"),
            crate::wire::Stream::Tls(_) => panic!("plain http gave a TLS stream"),
        }
    }

    #[tokio::test]
    async fn a_caller_agent_is_the_only_agent_on_the_wire() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "webfold/0.1 (+https://example.test)");
        let raw = head_over_loopback(headers).await;
        let lines = user_agent_lines(&raw);
        assert_eq!(
            lines,
            vec!["webfold/0.1 (+https://example.test)".to_string()],
            "expected exactly the caller's agent, got {lines:?} in:\n{}",
            String::from_utf8_lossy(&raw)
        );
    }

    #[tokio::test]
    async fn no_caller_agent_sends_exactly_one_default_agent() {
        let raw = head_over_loopback(HeaderMap::new()).await;
        let lines = user_agent_lines(&raw);
        assert_eq!(lines.len(), 1, "one agent, not two: {lines:?}");
        assert_eq!(lines[0], super::DEFAULT_USER_AGENT);
    }

    /// The exact shape of the original bug: two `User-Agent` lines, the
    /// transport's first and the caller's second, leaving the server to guess.
    #[tokio::test]
    async fn the_request_never_carries_two_agents() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "*/*");
        headers.insert(USER_AGENT, "webfold/0.1");
        let raw = head_over_loopback(headers).await;
        assert!(
            user_agent_lines(&raw).len() <= 1,
            "duplicate User-Agent: {}",
            String::from_utf8_lossy(&raw)
        );
    }

    /// A regression guard on the sibling headers too: the caller's headers are
    /// still serialized, so "the agent now wins" did not come from dropping them.
    #[tokio::test]
    async fn caller_headers_are_still_sent_alongside_the_agent() {
        let mut headers = HeaderMap::new();
        headers.insert("x-webfold-test", "present");
        let raw = head_over_loopback(headers).await;
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("x-webfold-test: present"), "{text}");
    }
}

#[cfg(test)]
mod user_agent_tests {
    //! The caller-supplied `User-Agent` decision.
    //!
    //! A unit test rather than an integration one because this function's whole
    //! job is to decide what goes on the wire, and the wire is a socket: a
    //! regression here is invisible to every other test in the crate, and
    //! invisible in production too — a duplicated `User-Agent` is not a crash, it
    //! is a request that identifies as something it is not.

    use super::effective_user_agent;
    use crate::http_types::header::USER_AGENT;
    use crate::http_types::HeaderMap;

    fn with_agent(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(USER_AGENT, value);
        map
    }

    #[test]
    fn a_caller_agent_is_the_one_that_goes_out() {
        assert_eq!(
            effective_user_agent(&with_agent("webfold/0.1 (+https://example.test)")).as_deref(),
            Some("webfold/0.1 (+https://example.test)")
        );
    }

    #[test]
    fn no_caller_agent_keeps_the_transport_default() {
        assert_eq!(
            effective_user_agent(&HeaderMap::new()).as_deref(),
            Some(super::DEFAULT_USER_AGENT)
        );
    }

    /// The header map is case-insensitive, so `User-Agent` set through any
    /// spelling must still win. Before this change it did not: the transport
    /// wrote its own value first and the caller's followed it, giving a server
    /// two `User-Agent` lines and no way to know which one webfold meant.
    #[test]
    fn the_caller_agent_wins_whatever_the_header_spelling() {
        let mut map = HeaderMap::new();
        map.insert("User-Agent", "spelled-camel");
        assert_eq!(effective_user_agent(&map).as_deref(), Some("spelled-camel"));

        let mut map = HeaderMap::new();
        map.insert("USER-AGENT", "spelled-upper");
        assert_eq!(effective_user_agent(&map).as_deref(), Some("spelled-upper"));
    }

    /// An empty value must not serialize as `User-Agent: `, which some servers
    /// reject and others read as a malformed request. The default stands in.
    #[test]
    fn an_empty_agent_falls_back_instead_of_sending_a_bare_header() {
        assert_eq!(
            effective_user_agent(&with_agent("")).as_deref(),
            Some(super::DEFAULT_USER_AGENT)
        );
        assert_eq!(
            effective_user_agent(&with_agent("   ")).as_deref(),
            Some(super::DEFAULT_USER_AGENT)
        );
    }

    /// An unrelated header must not be mistaken for the agent.
    #[test]
    fn other_headers_are_not_mistaken_for_the_agent() {
        let mut map = HeaderMap::new();
        map.insert("accept", "text/html");
        assert_eq!(
            effective_user_agent(&map).as_deref(),
            Some(super::DEFAULT_USER_AGENT)
        );
    }
}
