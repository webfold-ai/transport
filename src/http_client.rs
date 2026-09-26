// The reqwest face: retry policy, the RFC 6265 cookie jar, `crate::httpsrv::httpx::multipart::Form`, the
// `RequestBuilder`/`Client`/`ClientBuilder` chain, redirect following, and the free
// `get`/`post` helpers. What a caller drives; the bytes go out through `wire.rs`.
//
// Ported from bedrock's `native_lib::client` (originally `include!`d into `native_lib.rs`,
// sharing its flat scope); here it's a real module, paired with `crate::http_types` for the
// `Method`/`HeaderMap`/`Uri`/`header` types it was written against.

use crate::http_types::*;
use crate::wire::{connect, connect_fresh, send_request, send_request_streaming};
use std::sync::Arc;
use tracing::Instrument;

/// Re-export the streaming response so platform callers (e.g. ai-gateway's
/// `transport_ndjson` adapter) can construct / pass it without reaching into
/// the `wire` module's internals.
pub use crate::wire::StreamingResponse;

/// Small non-cryptographic PRNG step for the multipart boundary — same as bedrock's
/// `native_lib::splitmix64`, kept local since it's five lines and not worth a shared dep.
fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E3779B97F4A7C15);
    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

// -- Reqwest face: client -----------------------------------------------

/// A retry policy for transient (connect/IO) failures — never retried on an application-level
/// HTTP status (a 5xx is a real answer from the server, not a transport failure), matching a
/// conservative default: retrying blind on 5xx risks duplicating a non-idempotent POST's effect.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub backoff: std::time::Duration,
}

impl RetryPolicy {
    pub fn new(max_attempts: usize, backoff: std::time::Duration) -> Self {
        RetryPolicy { max_attempts: max_attempts.max(1), backoff }
    }
}

/// One stored cookie's RFC 6265 attributes (beyond name/value) — `Path` (default `/`),
/// `Expires`/`Max-Age` (collapsed to one absolute expiry point, `Max-Age` taking precedence per
/// §5.3), `Secure`, `HttpOnly`. `Domain` isn't tracked per-cookie: this jar already partitions
/// storage by domain at the outer map, an honest simplification versus full domain-matching
/// (subdomain inheritance via a `Domain=` attribute isn't modeled).
#[derive(Clone, Debug)]
struct StoredCookie {
    value: String,
    path: String,
    expires_at: Option<std::time::SystemTime>,
    secure: bool,
    // Parsed and stored for spec completeness; unread because `HttpOnly` only gates
    // JavaScript access to a cookie, which has no meaning for this Rust HTTP client (there is
    // no scripting layer here to deny) — it would matter if this jar were ever exposed to one.
    #[allow(dead_code)]
    http_only: bool,
}

impl StoredCookie {
    fn is_expired(&self) -> bool {
        self.expires_at.map(|t| std::time::SystemTime::now() > t).unwrap_or(false)
    }
}

/// RFC 6265 §5.1.4 cookie-path matching: `cookie_path` must be a prefix of `request_path`, and
/// either they're equal, `cookie_path` ends in `/`, or the next character in `request_path`
/// after the shared prefix is `/`.
fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.len() == request_path.len() || cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// Parse an RFC 7231 IMF-fixdate (`Set-Cookie`'s `Expires` format, e.g. "Wed, 21 Oct 2015
/// 07:28:00 GMT") into a `SystemTime`. The two legacy formats (RFC 850, `asctime`) aren't
/// handled — an honest reduction; IMF-fixdate is what every modern server actually sends.
fn parse_http_date(s: &str) -> Option<std::time::SystemTime> {
    let rest = s.trim().split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let day: u64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u64 = parts.next()?.parse().ok()?;
    let mut time_parts = parts.next()?.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec: u64 = time_parts.next()?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + (hour * 3600 + min * 60 + sec) as i64;
    if secs < 0 {
        return Some(std::time::SystemTime::UNIX_EPOCH);
    }
    Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

/// Parse an RFC 3339 timestamp (`2026-07-07T02:39:45+10:00`, `...Z`, or with fractional
/// seconds `...45.123+10:00`) into epoch MILLISECONDS. Reuses the same `days_from_civil`
/// civil-calendar math `parse_http_date` uses — one date primitive, two textual formats.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: u64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;

    // Split off the trailing offset (`Z`, or `+HH:MM`/`-HH:MM`) from the time-of-day. RFC 3339
    // never puts `+`/`-` anywhere else in the time-of-day, so the LAST one is always the offset.
    let (time_part, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(idx) = rest.rfind(['+', '-']) {
        let (t, off) = rest.split_at(idx);
        let sign = if off.starts_with('-') { -1i64 } else { 1i64 };
        let mut off_parts = off[1..].split(':');
        let oh: i64 = off_parts.next()?.parse().ok()?;
        let om: i64 = off_parts.next()?.parse().ok()?;
        (t, sign * (oh * 3600 + om * 60))
    } else {
        (rest, 0i64)
    };

    let mut time_parts = time_part.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec_field = time_parts.next()?;
    let (sec_str, ms) = match sec_field.split_once('.') {
        Some((s, frac)) => {
            let frac3 = format!("{:0<3}", &frac[..frac.len().min(3)]);
            (s, frac3.parse::<i64>().unwrap_or(0))
        }
        None => (sec_field, 0),
    };
    let sec: u64 = sec_str.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let local_secs = days * 86400 + (hour * 3600 + min * 60 + sec) as i64;
    let utc_secs = local_secs - offset_secs;
    Some(utc_secs * 1000 + ms)
}

/// Howard Hinnant's `days_from_civil` — days since the Unix epoch (1970-01-01) for a given
/// (year, month, day), proleptic Gregorian, valid for any year. Verified below against the
/// well-known reference "2000-01-01T00:00:00Z = 946684800".
fn days_from_civil(y: u64, m: u64, d: u64) -> i64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// A cookie jar — store-and-replay of `Set-Cookie`/`Cookie`, keyed by domain, respecting RFC
/// 6265's `Path`/`Expires`/`Max-Age`/`Secure`/`HttpOnly` attributes (not just name=value).
// The outer (per-domain) map uses `hashtrinity::Table` -- the framework's own map face, the
// same primitive `crate::runtime::cache::Cache`/`crate::runtime::metrics::Registry`/`crate::runtime::cluster::Cluster` key on elsewhere in this
// crate. The inner (per-domain cookie-name) map stays a plain `HashMap`: small (a handful of
// cookies per domain) and read-modify-write on every `Set-Cookie`, where std's
// `entry().or_default()` fits better than `Table`'s insert/overwrite-only API.
#[derive(Debug, Default)]
struct CookieJar {
    by_domain: hashtrinity::Table<String, std::collections::HashMap<String, StoredCookie>>,
}

impl CookieJar {
    /// Parse one `Set-Cookie` header value (name=value plus all its attributes) and store or
    /// delete it. An explicitly-expired cookie (`Max-Age<=0` or a past `Expires`) is REMOVED
    /// from the jar — RFC 6265's own deletion mechanism, not a silent no-op.
    fn store(&mut self, domain: &str, set_cookie: &str) {
        let mut segments = set_cookie.split(';');
        let Some(pair) = segments.next() else { return };
        let Some((name, value)) = pair.trim().split_once('=') else { return };
        let (name, value) = (name.trim().to_string(), value.trim().to_string());

        let mut path = "/".to_string();
        let mut expires_at: Option<std::time::SystemTime> = None;
        let mut max_age: Option<i64> = None;
        let mut secure = false;
        let mut http_only = false;

        for attr in segments {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            let (key, val) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (attr, None),
            };
            match key.to_ascii_lowercase().as_str() {
                "path" => {
                    if let Some(v) = val {
                        path = v.to_string();
                    }
                }
                "expires" => {
                    if let Some(v) = val {
                        expires_at = parse_http_date(v);
                    }
                }
                "max-age" => max_age = val.and_then(|v| v.parse().ok()),
                "secure" => secure = true,
                "httponly" => http_only = true,
                _ => {}
            }
        }

        // Max-Age takes precedence over Expires (RFC 6265 §5.3) once both are present.
        if let Some(secs) = max_age {
            expires_at = Some(if secs <= 0 {
                std::time::SystemTime::UNIX_EPOCH
            } else {
                std::time::SystemTime::now() + std::time::Duration::from_secs(secs as u64)
            });
        }

        let mut cookies = self.by_domain.get(&domain.to_string()).cloned().unwrap_or_default();
        if expires_at.map(|t| t <= std::time::SystemTime::now()).unwrap_or(false) {
            cookies.remove(&name);
        } else {
            cookies.insert(name, StoredCookie { value, path, expires_at, secure, http_only });
        }
        self.by_domain.put(domain.to_string(), cookies);
    }

    /// The `Cookie` header value to send for a request to `domain` at `request_path`, over a
    /// (non-)secure connection — filters out expired cookies, path-mismatched cookies (§5.1.4),
    /// and `Secure`-flagged cookies on a plain HTTP request.
    fn header_for(&self, domain: &str, request_path: &str, is_secure_request: bool) -> Option<String> {
        let map = self.by_domain.get(&domain.to_string())?;
        let mut pairs: Vec<(&String, &StoredCookie)> = map
            .iter()
            .filter(|(_, c)| !c.is_expired())
            .filter(|(_, c)| cookie_path_matches(&c.path, request_path))
            .filter(|(_, c)| !c.secure || is_secure_request)
            .collect();
        if pairs.is_empty() {
            return None;
        }
        pairs.sort_by_key(|(k, _)| k.as_str());
        Some(pairs.iter().map(|(k, c)| format!("{k}={}", c.value)).collect::<Vec<_>>().join("; "))
    }
}

struct ClientInner {
    cookies: std::sync::Mutex<CookieJar>,
    resolve_overrides: std::collections::HashMap<String, std::net::SocketAddr>,
    follow_redirects: bool,
    max_redirects: usize,
    retry: Option<RetryPolicy>,
}

impl Default for ClientInner {
    fn default() -> Self {
        ClientInner {
            cookies: std::sync::Mutex::new(CookieJar::default()),
            resolve_overrides: std::collections::HashMap::new(),
            follow_redirects: true,
            max_redirects: 10,
            retry: None,
        }
    }
}

/// One `multipart/form-data` field — reqwest's `crate::httpsrv::httpx::multipart::Part`.
pub struct Part {
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Part {
    pub fn text(value: impl Into<String>) -> Self {
        Part { filename: None, content_type: None, body: value.into().into_bytes() }
    }

    pub fn bytes(body: Vec<u8>) -> Self {
        Part { filename: None, content_type: None, body }
    }

    pub fn file_name(mut self, name: impl Into<String>) -> Self {
        self.filename = Some(name.into());
        self
    }

    pub fn mime(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

/// A `multipart/form-data` body builder — reqwest's `crate::httpsrv::httpx::multipart::Form`. Encodes to a real,
/// spec-shaped body (`--boundary`-delimited parts, `Content-Disposition`/`Content-Type` per
/// part, terminating `--boundary--`) with no external dependency for the boundary token.
pub struct Form {
    parts: Vec<(String, Part)>,
    boundary: String,
}

impl Form {
    pub fn new() -> Self {
        // A boundary just needs to be unlikely to collide with the body content -- 32 hex
        // chars from two splitmix64 draws seeded off the clock is plenty; no uuid dependency.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let a = splitmix64(now);
        let b = splitmix64(a ^ 0x5DEECE66D);
        Form { parts: Vec::new(), boundary: format!("bedrock-{a:016x}{b:016x}") }
    }

    pub fn part(mut self, name: impl Into<String>, part: Part) -> Self {
        self.parts.push((name.into(), part));
        self
    }

    pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.part(name, Part::text(value.into()))
    }

    /// Encode to `(Content-Type header value, body bytes)`.
    fn encode(&self) -> (String, Vec<u8>) {
        let mut body = Vec::new();
        for (name, part) in &self.parts {
            body.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
            let mut disposition = format!("Content-Disposition: form-data; name=\"{name}\"");
            if let Some(filename) = &part.filename {
                disposition.push_str(&format!("; filename=\"{filename}\""));
            }
            body.extend_from_slice(format!("{disposition}\r\n").as_bytes());
            if let Some(ct) = &part.content_type {
                body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(&part.body);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        (format!("multipart/form-data; boundary={}", self.boundary), body)
    }
}

impl Default for Form {
    fn default() -> Self {
        Form::new()
    }
}

pub struct RequestBuilder {
    method: Method,
    uri: Result<Uri>,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    client: Client,
    retry_override: Option<RetryPolicy>,
}

impl RequestBuilder {
    pub fn header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set headers from a `HeaderMap` — reqwest's `RequestBuilder::headers`, merging onto any
    /// already set (multi-value headers append, `HeaderMap::append` semantics).
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        for (name, value) in headers.iter() {
            self.headers.append(name, value.as_bytes().to_vec());
        }
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn body_bytes(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Set a `multipart/form-data` body from a `Form` — encodes and sets `Content-Type` with
    /// the boundary in one step, matching reqwest's `RequestBuilder::multipart`.
    pub fn multipart(mut self, form: Form) -> Self {
        let (content_type, body) = form.encode();
        self.headers.insert(header::CONTENT_TYPE, content_type);
        self.body = Some(body);
        self
    }

    /// Override this request's retry policy (defaults to the client's, if any).
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry_override = Some(policy);
        self
    }

    pub async fn send(self) -> Result<Response> {
        let uri = self.uri?;
        let span = tracing::debug_span!(target: "bedrock::client", "http.client_request", method = %self.method, uri = %uri, status = tracing::field::Empty);
        let client = self.client.clone();
        let method = self.method;
        let headers = self.headers;
        let body = self.body;
        let policy = self.retry_override.or(client.inner.retry);
        async move {
            let attempts = policy.map(|r| r.max_attempts).unwrap_or(1);
            let backoff = policy.map(|r| r.backoff).unwrap_or_default();
            let mut last_err = None;
            for attempt in 0..attempts {
                match send_with_redirects(&client, method.clone(), uri.clone(), headers.clone(), body.clone()).await {
                    Ok(resp) => {
                        tracing::Span::current().record("status", resp.status().as_u16());
                        return Ok(resp);
                    }
                    Err(e) => {
                        tracing::warn!(target: "bedrock::client", error = %e, attempt, "request attempt failed");
                        last_err = Some(e);
                        if attempt + 1 < attempts {
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }
            Err(last_err.expect("attempts >= 1, so the loop ran at least once"))
        }
        .instrument(span)
        .await
    }

    /// Send without buffering the response body — `reqwest`'s `chunk()`/`bytes_stream()`
    /// equivalent. A stated, honest scope reduction versus `send()`: no redirect-following, no
    /// retry, no cookie jar (all three exist to make ONE logical request out of several
    /// physical ones, which conflicts with handing the body stream to the caller mid-flight —
    /// the caller gets the connection directly instead, no in-between logic).
    pub async fn send_streaming(self) -> Result<StreamingResponse> {
        let uri = self.uri?;
        let (stream, _was_pooled) = connect(&uri, &self.client.inner.resolve_overrides).await?;
        send_request_streaming(stream, self.method, &uri, self.headers, self.body).await
    }
}

/// One logical request, following redirects (bounded) and threading the client's cookie jar —
/// what `RequestBuilder::send`'s retry loop calls per attempt.
async fn send_with_redirects(
    client: &Client,
    mut method: Method,
    mut uri: Uri,
    mut headers: HeaderMap,
    mut body: Option<Vec<u8>>,
) -> Result<Response> {
    for _ in 0..=client.inner.max_redirects {
        if let Some(domain) = uri.host() {
            let is_secure = uri.scheme_str() == Some("https");
            if let Some(cookie_header) = client.inner.cookies.lock().unwrap().header_for(domain, uri.path(), is_secure) {
                headers.insert(header::COOKIE, cookie_header);
            }
        }

        let (stream, was_pooled) = connect(&uri, &client.inner.resolve_overrides).await?;
        let mut result = send_request(stream, method.clone(), &uri, headers.clone(), body.clone()).await;
        if was_pooled && result.is_err() {
            // A pooled connection's first write/read failing is expected, not exceptional —
            // see `connect`'s own doc for the three real ways this happens. Retry exactly once
            // on a guaranteed-fresh connection before giving up.
            tracing::debug!(target: "bedrock::client", "pooled connection failed on first use, retrying fresh");
            let fresh = connect_fresh(&uri, &client.inner.resolve_overrides).await?;
            result = send_request(fresh, method.clone(), &uri, headers.clone(), body.clone()).await;
        }
        let resp = result?;

        if let Some(domain) = uri.host() {
            let mut jar = client.inner.cookies.lock().unwrap();
            for set_cookie in resp.headers().get_all(header::SET_COOKIE) {
                if let Ok(v) = set_cookie.to_str() {
                    jar.store(domain, v);
                }
            }
        }

        if !client.inner.follow_redirects || !resp.status().is_redirection() {
            return Ok(resp);
        }
        let Some(location) = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
            return Ok(resp);
        };
        let next_uri = resolve_redirect_uri(&uri, location)?;
        // 303 always becomes a bodyless GET; 301/302 do the same ONLY for a POST original (the
        // legacy browser behavior every HTTP client, reqwest included, still follows); 307/308
        // preserve the method and body exactly.
        let status = resp.status().as_u16();
        if status == 303 || ((status == 301 || status == 302) && method == Method::POST) {
            method = Method::GET;
            body = None;
        }
        uri = next_uri;
    }
    Err(Error::Http(format!("too many redirects (> {})", client.inner.max_redirects)))
}

fn resolve_redirect_uri(base: &Uri, location: &str) -> Result<Uri> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return parse_uri(location);
    }
    // A relative Location (path-absolute, e.g. "/next") -- rebuild against the base's own
    // scheme/host/port, since bedrock's Uri has no separate "resolve against base" op.
    let scheme = base.scheme_str().unwrap_or("http");
    let host = base.host().unwrap_or_default();
    let authority = match base.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let path = if location.starts_with('/') { location.to_string() } else { format!("/{location}") };
    parse_uri(&format!("{scheme}://{authority}{path}"))
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new() -> Self {
        Client { inner: Arc::new(ClientInner::default()) }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder(ClientInner::default())
    }

    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder {
            method,
            uri: parse_uri(url.as_ref()),
            headers: HeaderMap::new(),
            body: None,
            client: self.clone(),
            retry_override: None,
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

/// Opaque debug — `reqwest::Client`'s own `Debug` prints nothing about the pool either.
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

pub struct ClientBuilder(ClientInner);

impl ClientBuilder {
    /// Redirect the DNS resolution of `host` to a fixed address — reqwest's `.resolve()`. The
    /// TLS SNI identity still uses the ORIGINAL hostname; only the socket address changes.
    pub fn resolve(mut self, host: impl Into<String>, addr: std::net::SocketAddr) -> Self {
        self.0.resolve_overrides.insert(host.into(), addr);
        self
    }

    pub fn redirect(mut self, follow: bool) -> Self {
        self.0.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, n: usize) -> Self {
        self.0.max_redirects = n;
        self
    }

    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.0.retry = Some(policy);
        self
    }

    pub fn build(self) -> Client {
        Client { inner: Arc::new(self.0) }
    }
}

pub async fn get(url: impl AsRef<str>) -> Result<Response> {
    Client::new().get(url).send().await
}

pub async fn post(url: impl AsRef<str>) -> Result<Response> {
    Client::new().post(url).send().await
}

