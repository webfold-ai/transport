// The wire itself: the plain/TLS `Stream`, the buffered `StreamReader`, client and server
// TLS config (PEM -> DER by hand), `serve_tls`, the Pingora-style keepalive connection
// pool, and request write / response read -- buffered, streaming, and chunked.
//
// Ported from bedrock's `native_lib::wire` (originally `include!`d into `native_lib.rs`,
// sharing its flat scope); here it's a real module, paired with `crate::http_types`.

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
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
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
                Some(addr) => TcpStream::connect(addr).await?,
                None => TcpStream::connect(format!("{}:{}", host, port)).await?,
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
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect(format!("{}:{}", host, port)).await?,
        })),
    }
}

/// Write the request line, headers, and body — shared by the buffered (`send_request`) and
/// streaming (`send_request_streaming`) paths; they only diverge on how the RESPONSE body gets
/// read, never on how the request itself goes out.
async fn write_request(
    stream: &mut Stream,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Option<Vec<u8>>,
) -> Result<()> {
    let path = uri.path_and_query();
    let host = uri.host().unwrap_or("");
    let authority = match uri.port_u16() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    stream
        .write_all(format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, authority).as_bytes())
        .await?;
    stream
        .write_all(b"User-Agent: bedrock/0.1.0\r\n")
        .await?;

    for (name, value) in headers.iter() {
        stream.write_all(name.as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    if let Some(ref body) = body {
        stream
            .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
            .await?;
    }
    stream.write_all(b"\r\n").await?;
    if let Some(body) = body {
        stream.write_all(body).await?;
    }
    Ok(())
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

/// Read response heads until the FINAL one. RFC 9110 §15.2 requires a client to accept one or
/// more interim 1xx responses (100 Continue, 103 Early Hints — nginx and CDNs send these
/// unbidden, Songsterr among them) before the final response. Treating an interim head as final
/// lost the real response entirely — and worse, the interim head looks bodyless, so the
/// still-unread final response stayed in a socket that was then returned to the keepalive pool,
/// corrupting the next pooled request. The interim count is bounded: an endless 1xx stream is a
/// parse error, not a hang.
async fn read_final_response_head(reader: &mut StreamReader) -> Result<ResponseHead> {
    const MAX_INTERIM_RESPONSES: usize = 8;
    for _ in 0..=MAX_INTERIM_RESPONSES {
        let head = read_response_head(reader).await?;
        if !head.status.is_informational() {
            return Ok(head);
        }
    }
    Err(Error::Parse(format!(
        "more than {MAX_INTERIM_RESPONSES} interim 1xx responses without a final response"
    )))
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
    let head = read_final_response_head(&mut reader).await?;

    // Only a DEFINITE-length body (no body at all, Content-Length, or a chunked terminator) means
    // the connection is genuinely still usable afterward — the "read to end" fallback below means
    // there was no length information at all, which in practice means the peer intends to close
    // the connection once the body is sent, so pooling that stream would just hand back a socket
    // that's already going away.
    // `head` is the final response — interim 1xx heads were already consumed by
    // `read_final_response_head` — so only 204/304 are bodyless here.
    let (body, poolable) = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
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
    let head = read_final_response_head(&mut reader).await?;

    let framing = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
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
mod interim_response_tests {
    //! RFC 9110 §15.2 interim 1xx responses. Loopback tests on purpose: the defect was
    //! `send_request` surfacing a 103 Early Hints head as the final response — empty body,
    //! and the still-unread real 200 left in a socket that was then pooled, corrupting the
    //! next pooled request. Only a server that actually emits the two-head sequence proves
    //! the client reads past it. Songsterr's nginx (`?pattern=` search) is the production
    //! case that motivated this fix.

    use super::{identity_for, pool_take, send_request, send_request_streaming, Stream};
    use crate::http_types::{HeaderMap, Method, StatusCode, Uri};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Accept one connection, read one request head, answer with `responses` verbatim.
    async fn serve_once(listener: TcpListener, responses: &'static [u8]) {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("client connects")
            .expect("accept");
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
            .await
            .expect("client sends a request")
            .expect("read request");
        // A client that errors early (the endless-interim test) makes these writes fail;
        // that is the client's business, not the server's.
        let _ = socket.write_all(responses).await;
    }

    async fn request_once(responses: &'static [u8]) -> (crate::http_types::Response, Uri) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(serve_once(listener, responses));
        let uri: Uri = format!("http://{addr}/x").parse().expect("uri");
        let stream = TcpStream::connect(addr).await.expect("connect");
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            send_request(Stream::Plain(stream), Method::GET, &uri, HeaderMap::new(), None),
        )
        .await
        .expect("no hang")
        .expect("a final response");
        server.await.expect("server task");
        (resp, uri)
    }

    #[tokio::test]
    async fn an_interim_103_is_read_through_to_the_final_response() {
        let (resp, _) = request_once(
            b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"hello");
    }

    #[tokio::test]
    async fn several_interim_responses_are_all_read_through() {
        let (resp, _) = request_once(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"ok");
    }

    #[tokio::test]
    async fn the_streaming_path_reads_past_interim_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(serve_once(
            listener,
            b"HTTP/1.1 103 Early Hints\r\nLink: </app.js>; rel=modulepreload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nstream",
        ));
        let uri: Uri = format!("http://{addr}/s").parse().expect("uri");
        let stream = TcpStream::connect(addr).await.expect("connect");
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            send_request_streaming(Stream::Plain(stream), Method::GET, &uri, HeaderMap::new(), None),
        )
        .await
        .expect("no hang")
        .expect("a final response");
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.bytes().await.expect("body"), b"stream");
        server.await.expect("server task");
    }

    /// The negative control: a peer that never stops sending 1xx must produce an error,
    /// quickly — not a task parked on a socket forever.
    #[tokio::test]
    async fn an_endless_interim_stream_errors_instead_of_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            for _ in 0..16 {
                if socket.write_all(b"HTTP/1.1 103 Early Hints\r\n\r\n").await.is_err() {
                    break;
                }
            }
        });
        let uri: Uri = format!("http://{addr}/loop").parse().expect("uri");
        let stream = TcpStream::connect(addr).await.expect("connect");
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            send_request(Stream::Plain(stream), Method::GET, &uri, HeaderMap::new(), None),
        )
        .await
        .expect("an endless 1xx stream must not hang the caller");
        assert!(outcome.is_err(), "endless interim responses must error");
        server.await.expect("server task");
    }

    /// The pool-corruption half of the original bug: after a 103+200 exchange the pooled
    /// connection must serve the NEXT request its own response, not the unread tail of the
    /// first. Before the fix the first exchange pooled a socket still holding the real 200.
    #[tokio::test]
    async fn a_pooled_connection_after_an_interim_response_serves_the_next_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await
                .expect("write first");
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
                .await
                .expect("write second");
        });
        let uri: Uri = format!("http://{addr}/one").parse().expect("uri");
        let stream = TcpStream::connect(addr).await.expect("connect");
        let r1 = send_request(Stream::Plain(stream), Method::GET, &uri, HeaderMap::new(), None)
            .await
            .expect("first response");
        assert_eq!(r1.status, StatusCode::OK);
        assert_eq!(r1.body, b"first");

        let identity = identity_for(&uri).expect("identity");
        let pooled = pool_take(&identity).expect("the keepalive connection was pooled");
        let uri2: Uri = format!("http://{addr}/two").parse().expect("uri");
        let r2 = tokio::time::timeout(
            Duration::from_secs(5),
            send_request(pooled.stream, Method::GET, &uri2, HeaderMap::new(), None),
        )
        .await
        .expect("no hang on the pooled connection")
        .expect("second response");
        assert_eq!(r2.status, StatusCode::OK);
        assert_eq!(
            r2.body, b"second",
            "a pooled connection must never answer a request with a previous response's tail"
        );
        server.await.expect("server task");
    }
}
