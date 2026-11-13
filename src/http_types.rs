// The `http` crate face: the error type every surface below returns, the wire vocabulary
// (`Method`/`Version`/`StatusCode`/`HeaderName`/`HeaderValue`/`HeaderMap`/`Uri`), the
// `Extensions` type-map, and the `Request`/`Response` messages themselves. No I/O.
//
// Ported from bedrock's `native_lib::http_types` (originally `include!`d into `native_lib.rs`,
// sharing its flat scope); here it's a real module with its own imports.

use apeiron::map::hashtrinity::{CoordMap, PHI};
use std::io;
use std::str::FromStr;
use std::sync::Arc;

// -- Error ---------------------------------------------------------------

// `apeiron::map::hashtrinity::Error`'s derive (the thiserror-compatible `#[error("...")]`/`#[from]` subset)
// needs hashtrinity's `derive` feature, which transitively pulls in `codec` -> `apeiron`, and
// the pinned `apeiron` revision doesn't build (`apeiron::Words` missing) — a pre-existing,
// separate breakage out of scope here. Hand-written instead; it's the same boilerplate the
// derive exists to remove, just not worth a broken transitive dependency to avoid.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Http(String),
    Tls(String),
    Url(String),
    Parse(String),
    Overlay(String),
    Youki(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O: {e}"),
            Error::Http(s) => write!(f, "HTTP: {s}"),
            Error::Tls(s) => write!(f, "TLS: {s}"),
            Error::Url(s) => write!(f, "URL: {s}"),
            Error::Parse(s) => write!(f, "parse: {s}"),
            Error::Overlay(s) => write!(f, "overlay: {s}"),
            Error::Youki(s) => write!(f, "youki: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// -- Native http-crate surface ------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    Other(String),
}

/// `req.method()` returns `&Method`; real rauthy handler/middleware code (written against the
/// `http` crate's `Method`, which supports this) compares it directly against an owned value —
/// `req.method() == Method::GET`, not `req.method() == &Method::GET`. `#[derive(PartialEq)]`
/// alone only gives `Method: PartialEq<Method>`, not this cross (reference, owned) comparison.
impl PartialEq<Method> for &Method {
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::DELETE => "DELETE",
            Method::PATCH => "PATCH",
            Method::HEAD => "HEAD",
            Method::OPTIONS => "OPTIONS",
            Method::CONNECT => "CONNECT",
            Method::TRACE => "TRACE",
            Method::Other(s) => s.as_str(),
        }
    }

    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        )
    }

    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Method::GET
                | Method::HEAD
                | Method::OPTIONS
                | Method::TRACE
                | Method::PUT
                | Method::DELETE
        )
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            "CONNECT" => Method::CONNECT,
            "TRACE" => Method::TRACE,
            other if !other.is_empty() => Method::Other(other.to_string()),
            _ => return Err(Error::Parse("empty method".into())),
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    HTTP_10,
    HTTP_11,
    HTTP_2,
    HTTP_3,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const OK: StatusCode = StatusCode(200);
    pub const CREATED: StatusCode = StatusCode(201);
    pub const ACCEPTED: StatusCode = StatusCode(202);
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    pub const RESET_CONTENT: StatusCode = StatusCode(205);
    pub const PARTIAL_CONTENT: StatusCode = StatusCode(206);
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode(301);
    pub const FOUND: StatusCode = StatusCode(302);
    pub const NOT_MODIFIED: StatusCode = StatusCode(304);
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const NOT_ACCEPTABLE: StatusCode = StatusCode(406);
    pub const PRECONDITION_REQUIRED: StatusCode = StatusCode(428);
    pub const TOO_MANY_REQUESTS: StatusCode = StatusCode(429);
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode(503);

    pub fn from_u16(code: u16) -> Result<Self> {
        if (100..=999).contains(&code) {
            Ok(StatusCode(code))
        } else {
            Err(Error::Parse(format!("bad status code: {code}")))
        }
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }

    pub fn is_informational(self) -> bool {
        (100..200).contains(&self.0)
    }

    pub fn is_success(self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn is_redirection(self) -> bool {
        (300..400).contains(&self.0)
    }

    pub fn is_client_error(self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn is_server_error(self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn from_static(s: &'static str) -> Self {
        HeaderName(normalize_header_name(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HeaderName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for HeaderName {
    fn from(value: &str) -> Self {
        HeaderName(normalize_header_name(value))
    }
}

impl From<String> for HeaderName {
    fn from(value: String) -> Self {
        HeaderName(normalize_header_name(&value))
    }
}

impl FromStr for HeaderName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::Parse(format!("bad header name: {s}")));
        }
        Ok(HeaderName(normalize_header_name(s)))
    }
}

impl std::fmt::Display for HeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderValue(Vec<u8>);

impl HeaderValue {
    pub fn from_static(s: &'static str) -> Self {
        HeaderValue(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }
}

impl From<&str> for HeaderValue {
    fn from(value: &str) -> Self {
        HeaderValue(value.as_bytes().to_vec())
    }
}

impl From<String> for HeaderValue {
    fn from(value: String) -> Self {
        HeaderValue(value.into_bytes())
    }
}

impl From<Vec<u8>> for HeaderValue {
    fn from(value: Vec<u8>) -> Self {
        HeaderValue(value)
    }
}

impl From<u32> for HeaderValue {
    fn from(value: u32) -> Self {
        HeaderValue::from(value.to_string())
    }
}

impl From<i64> for HeaderValue {
    fn from(value: i64) -> Self {
        HeaderValue::from(value.to_string())
    }
}

impl FromStr for HeaderValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(HeaderValue::from(s))
    }
}

impl std::fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_str() {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

fn normalize_header_name(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

pub mod header {
    pub const ACCEPT: &str = "accept";
    pub const ACCEPT_ENCODING: &str = "accept-encoding";
    pub const AUTHORIZATION: &str = "authorization";
    pub const CONNECTION: &str = "connection";
    pub const CONTENT_LENGTH: &str = "content-length";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const HOST: &str = "host";
    pub const TRANSFER_ENCODING: &str = "transfer-encoding";
    pub const USER_AGENT: &str = "user-agent";
    pub const COOKIE: &str = "cookie";
    pub const SET_COOKIE: &str = "set-cookie";
    pub const LOCATION: &str = "location";
    pub const CACHE_CONTROL: &str = "cache-control";
    pub const ETAG: &str = "etag";
    pub const ACCEPT_LANGUAGE: &str = "accept-language";
    pub const ACCESS_CONTROL_ALLOW_CREDENTIALS: &str = "access-control-allow-credentials";
    pub const ACCESS_CONTROL_ALLOW_HEADERS: &str = "access-control-allow-headers";
    pub const ACCESS_CONTROL_ALLOW_METHODS: &str = "access-control-allow-methods";
    pub const ACCESS_CONTROL_ALLOW_ORIGIN: &str = "access-control-allow-origin";
    pub const ACCESS_CONTROL_EXPOSE_HEADERS: &str = "access-control-expose-headers";
    pub const ACCESS_CONTROL_MAX_AGE: &str = "access-control-max-age";
    pub const CONTENT_ENCODING: &str = "content-encoding";
    pub const CONTENT_SECURITY_POLICY: &str = "content-security-policy";
    pub const ORIGIN: &str = "origin";
    pub const WWW_AUTHENTICATE: &str = "www-authenticate";
    pub const IF_NONE_MATCH: &str = "if-none-match";
    pub const VARY: &str = "vary";

    /// Strip a `;q=0.8`-style quality parameter (and any other `;param=value` suffix) off one
    /// comma-separated `Accept`/`Accept-Encoding` entry, trimming whitespace either side.
    fn strip_params(entry: &str) -> &str {
        entry.split(';').next().unwrap_or(entry).trim()
    }

    /// `actix_web::http::header::Accept` — a parsed `Accept:` request header. Scope, stated
    /// honestly: quality values are parsed off (so the list order reflects the header's own
    /// order, not a quality-sorted one) since every real call site only checks *membership*
    /// (`.iter().any(|p| p.item.essence_str() == "text/html")`), never picks "the best match".
    #[derive(Debug, Clone, Default)]
    pub struct Accept(pub Vec<QualityItem<MediaType>>);

    impl Accept {
        pub fn parse(raw: &str) -> Self {
            Accept(
                raw.split(',')
                    .map(strip_params)
                    .filter(|s| !s.is_empty())
                    .map(|s| QualityItem {
                        item: MediaType(s.to_string()),
                    })
                    .collect(),
            )
        }

        pub fn iter(&self) -> impl Iterator<Item = &QualityItem<MediaType>> {
            self.0.iter()
        }
    }

    /// One `Accept`/`Accept-Encoding` entry, quality value already stripped (see [`Accept`]'s
    /// doc comment) — the real crate's `QualityItem<T>` shape, minus the quality field nothing
    /// here reads.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct QualityItem<T> {
        pub item: T,
    }

    /// A bare `type/subtype` media type — real crate's `mime::Mime`, scoped to the one method
    /// (`essence_str`) every call site actually uses.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MediaType(String);

    impl MediaType {
        pub fn essence_str(&self) -> &str {
            &self.0
        }
    }

    /// `actix_web::http::header::AcceptEncoding` — a parsed `Accept-Encoding:` request header.
    #[derive(Debug, Clone, Default)]
    pub struct AcceptEncoding(pub Vec<QualityItem<Encoding>>);

    impl AcceptEncoding {
        pub fn parse(raw: &str) -> Self {
            AcceptEncoding(
                raw.split(',')
                    .map(strip_params)
                    .filter(|s| !s.is_empty())
                    .map(|s| QualityItem {
                        item: Encoding(s.to_string()),
                    })
                    .collect(),
            )
        }

        pub fn contains(&self, enc: &Encoding) -> bool {
            self.0.iter().any(|q| &q.item == enc)
        }
    }

    /// One content-coding token (`"br"`/`"gzip"`/`"deflate"`/...) — real crate's `Encoding`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Encoding(String);

    impl std::str::FromStr for Encoding {
        type Err = std::convert::Infallible;

        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Ok(Encoding(s.trim().to_string()))
        }
    }
}

#[derive(Clone, Debug)]
struct HeaderEntry {
    name: String,
    values: Vec<HeaderValue>,
}

#[derive(Clone, Debug)]
pub struct HeaderMap {
    inner: CoordMap<u64, HeaderEntry>,
}

impl Default for HeaderMap {
    fn default() -> Self {
        HeaderMap::new()
    }
}

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap {
            inner: CoordMap::coordinate(),
        }
    }

    pub fn insert(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        let name = name.into().0;
        self.inner.put(
            header_coord(&name),
            HeaderEntry {
                name,
                values: vec![value.into()],
            },
        );
    }

    pub fn append(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        let name = name.into().0;
        self.inner.insert_with(
            header_coord(&name),
            HeaderEntry {
                name,
                values: vec![value.into()],
            },
            |mut new, mut old| {
                old.values.append(&mut new.values);
                old
            },
        );
    }

    pub fn get(&self, name: impl AsRef<str>) -> Option<&HeaderValue> {
        self.inner
            .get(&header_coord(name.as_ref()))
            .and_then(|entry| entry.values.first())
    }

    pub fn get_all(&self, name: impl AsRef<str>) -> &[HeaderValue] {
        self.inner
            .get(&header_coord(name.as_ref()))
            .map(|entry| entry.values.as_slice())
            .unwrap_or(&[])
    }

    pub fn contains_key(&self, name: impl AsRef<str>) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &HeaderValue)> {
        self.inner.iter().flat_map(|(_, entry)| {
            let name = entry.name.as_str();
            entry.values.iter().map(move |value| (name, value))
        })
    }

    pub fn len(&self) -> usize {
        self.inner.iter().map(|(_, entry)| entry.values.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// actix-web's real `HeaderMap` implements `IntoIterator` for `&HeaderMap` directly (so `for (k,
/// v) in req.headers()` works without an explicit `.iter()`) — matched here rather than making
/// every caller add `.iter()`.
impl<'a> IntoIterator for &'a HeaderMap {
    type Item = (&'a str, &'a HeaderValue);
    type IntoIter = Box<dyn Iterator<Item = (&'a str, &'a HeaderValue)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

fn header_coord(s: &str) -> u64 {
    let s = s.trim();
    let mut acc = 0u64;
    for b in s.bytes() {
        acc = acc.rotate_left(5) ^ (b.to_ascii_lowercase() as u64).wrapping_mul(PHI);
    }
    acc ^ (s.len() as u64).wrapping_mul(PHI)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uri {
    raw: String,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path_and_query: String,
}

impl Uri {
    pub fn scheme_str(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn port_u16(&self) -> Option<u16> {
        self.port
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// The path alone, query string stripped — what route matching needs. `path_and_query`
    /// stays available for handlers that want the query (`req.uri().path_and_query()`).
    pub fn path(&self) -> &str {
        self.path_and_query
            .split_once('?')
            .map_or(&self.path_and_query[..], |(p, _)| p)
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Uri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        parse_uri(s)
    }
}

pub fn parse_uri(s: &str) -> Result<Uri> {
    if s.is_empty() {
        return Err(Error::Url("empty URI".into()));
    }

    let (scheme, rest) = match s.find("://") {
        Some(i) => (Some(s[..i].to_ascii_lowercase()), &s[i + 3..]),
        None => (None, s),
    };

    let (authority, path) = if scheme.is_some() {
        match rest.find(['/', '?']) {
            Some(i) => {
                let path = if rest[i..].starts_with('?') {
                    format!("/{}", &rest[i..])
                } else {
                    rest[i..].to_string()
                };
                (&rest[..i], path)
            }
            None => (rest, "/".to_string()),
        }
    } else {
        ("", s.to_string())
    };

    let (host, port) = parse_authority(authority)?;
    let path_and_query = if path.is_empty() { "/".into() } else { path };

    Ok(Uri {
        raw: s.to_string(),
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn parse_authority(authority: &str) -> Result<(Option<String>, Option<u16>)> {
    if authority.is_empty() {
        return Ok((None, None));
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::Url("bad IPv6 authority".into()))?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .map(str::parse::<u16>)
            .transpose()
            .map_err(|e| Error::Url(format!("bad port: {e}")))?;
        return Ok((Some(host), port));
    }

    match authority.rsplit_once(':') {
        Some((host, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port = p
                .parse::<u16>()
                .map_err(|e| Error::Url(format!("bad port: {e}")))?;
            Ok((Some(host.to_string()), Some(port)))
        }
        _ => Ok((Some(authority.to_string()), None)),
    }
}

pub fn host_port(uri: &Uri) -> Result<(String, u16)> {
    let host = uri.host().ok_or_else(|| Error::Url("no host".into()))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    Ok((host.to_string(), port))
}

// -- Extensions: TypeId-keyed type-map (mirrors the real `http` crate's `Extensions`) ----

/// A type-erased value that can still be cloned — the standard "clone_box" pattern, needed
/// because `Extensions` must itself be `Clone` (both `Request` and `Response` derive `Clone`)
/// even though it stores arbitrary `dyn Any` values.
///
/// Found by a reproduced bug (downcast always failing, even for the type just inserted): calling
/// `b.as_any()` where `b: &Box<dyn CloneAny>` does NOT dispatch to the boxed value's own impl —
/// `Box<dyn CloneAny>` is itself `'static`, so it ALSO satisfies the blanket impl's own bound
/// below, and Rust's method resolution tries the receiver type (`Box<dyn CloneAny>`) before
/// auto-deref'ing into its contents, silently picking the WRONG (box-level, recursive) impl
/// instance instead of the concrete stored type's. The fix is forcing dispatch through the
/// unsized `dyn CloneAny` place directly — every call site below double-derefs (`(**b)`) rather
/// than calling `.as_any()` on the `&Box<..>` reference itself.
trait CloneAny: std::any::Any + Send + Sync {
    fn clone_box(&self) -> Box<dyn CloneAny>;
    fn as_any(&self) -> &dyn std::any::Any;
}
impl<T: std::any::Any + Clone + Send + Sync> CloneAny for T {
    fn clone_box(&self) -> Box<dyn CloneAny> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl Clone for Box<dyn CloneAny> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

fn type_id_coord(id: std::any::TypeId) -> u64 {
    // `TypeId` isn't a string/int `Coord` covers directly — hash it through its own `Hash` impl
    // into a u64, same shape as this file's own `header_coord` for `HeaderName`.
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

/// A type-map carried alongside a `Request`/`Response` — mirrors the real `http` crate's
/// `Extensions` exactly (`insert<T: Clone+Send+Sync+'static>`/`get<T>`/`remove<T>`): middleware
/// stashes arbitrary typed data (a parsed auth identity, a request id, a trace span) for
/// downstream handlers/layers to read back by type, without a bespoke field on `Request`/
/// `Response` for every such use — exactly what `axum`'s `Extension<T>` extractor and `actix-web`
/// equivalents both build on. Honest gap vs. the real crate: no `get_mut` — hashtrinity's
/// `Table` has no `get_mut` to build it on; every other operation (`get`/`insert`/`remove`, the
/// shapes `FromRequestParts`-style extractors and middleware actually use) is exact.
///
/// Uses `apeiron::map::hashtrinity::Table` (the exact-key-storing variant), NOT `CoordMap` — `CoordMap`
/// ("the address regenerates the key... stores nothing") is for keys that ARE their own
/// collision-free coordinate (small dense integers, direct addressing); a `TypeId` hashed
/// through `DefaultHasher` is an OPAQUE 64-bit value with no such guarantee, so two unrelated
/// types whose hashes happened to collide would have silently overwritten each other's slot —
/// found via a reproduced test failure (a second `insert` of a different type corrupted the
/// first), root-caused to exactly this mismatch. `Table` stores the key and resolves collisions
/// by real comparison, which is what a type-map's correctness actually depends on.
#[derive(Clone)]
pub struct Extensions {
    map: apeiron::map::hashtrinity::Table<u64, Box<dyn CloneAny>>,
}

impl Default for Extensions {
    fn default() -> Self {
        Extensions::new()
    }
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions").finish_non_exhaustive()
    }
}

impl Extensions {
    pub fn new() -> Self {
        Extensions {
            map: apeiron::map::hashtrinity::Table::new(),
        }
    }

    /// Insert a value, returning whatever was previously stored for this exact type `T`.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        let prev = self
            .map
            .remove(&key)
            .and_then(|b| (*b).as_any().downcast_ref::<T>().cloned());
        self.map.put(key, Box::new(val));
        prev
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        self.map
            .get(&key)
            .and_then(|b| (**b).as_any().downcast_ref::<T>())
    }

    pub fn remove<T: Clone + 'static>(&mut self) -> Option<T> {
        let key = type_id_coord(std::any::TypeId::of::<T>());
        self.map
            .remove(&key)
            .and_then(|b| (*b).as_any().downcast_ref::<T>().cloned())
    }
}

// -- Request / Response -------------------------------------------------

#[derive(Clone, Debug)]
pub struct Request {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
    extensions: Extensions,
    peer_addr: Option<std::net::SocketAddr>,
}

impl Request {
    pub fn new(method: Method, uri: Uri) -> Self {
        Request {
            method,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Vec::new(),
            extensions: Extensions::new(),
            peer_addr: None,
        }
    }

    /// The TCP peer's socket address — actix's `HttpRequest::connection_info().peer_addr()`
    /// equivalent, set once by `serve_connection` from the listener's `accept()` and otherwise
    /// `None` (constructed directly via `Request::new`, e.g. in a unit test). `with_peer_addr`
    /// exists for tests that need to exercise IP-derived logic without a real socket.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr
    }

    pub fn with_peer_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    /// actix's `HttpRequest::connection_info()` — bundles the raw TCP peer address with the
    /// proxy-aware "real" client address (`X-Forwarded-For`'s first hop, falling back to the
    /// peer address when absent). A fresh value per call (matching actix's own — it's a cheap,
    /// header-derived read, not cached state).
    pub fn connection_info(&self) -> ConnectionInfo {
        let peer_addr = self.peer_addr.map(|a| a.ip().to_string());
        let realip_remote_addr = self
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| peer_addr.clone());
        ConnectionInfo {
            peer_addr,
            realip_remote_addr,
        }
    }
}

/// actix's `dev::ConnectionInfo` — see [`Request::connection_info`].
pub struct ConnectionInfo {
    peer_addr: Option<String>,
    realip_remote_addr: Option<String>,
}

impl ConnectionInfo {
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    pub fn realip_remote_addr(&self) -> Option<&str> {
        self.realip_remote_addr.as_deref()
    }
}

impl Request {
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn path(&self) -> &str {
        self.uri.path()
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    // `cookies()`/`cookie()` (actix's `HttpRequest::cookies()`/`cookie(name)`, an RFC 6265
    // parse of the `Cookie:` request header) intentionally not ported: they need the
    // server-side `httpsrv::httpx::cookie` jar, which this client-only crate doesn't have, and
    // `pkarr::RelayClient` never receives a `Request` to call them on anyway.

    /// actix's `HttpRequest::app_data::<T>()` — reads back whatever `Router::with_state`
    /// injected (the same `Arc<T>`-in-`Extensions` mechanism `App::app_data`/`Data<T>` use), by
    /// reference rather than a clone.
    pub fn app_data<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<Arc<T>>().map(|arc| arc.as_ref())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub fn with_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub(crate) status: StatusCode,
    pub(crate) version: Version,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
    pub(crate) url: Uri,
    pub(crate) extensions: Extensions,
}

impl Response {
    pub fn new(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: body.into(),
            url: "/".parse().expect("static URI parses"),
            extensions: Extensions::new(),
        }
    }

    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Response::new(StatusCode::OK, body)
    }

    pub fn not_found() -> Self {
        Response::new(StatusCode::NOT_FOUND, "not found")
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn url(&self) -> &Uri {
        &self.url
    }

    pub fn with_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub async fn text(self) -> Result<String> {
        String::from_utf8(self.body).map_err(|e| Error::Parse(e.to_string()))
    }

    pub async fn bytes(self) -> Vec<u8> {
        self.body
    }

    /// Create a streaming body from a byte chunk — replaces reqwest's `bytes_stream()`.
    /// Each call returns a single-chunk stream (the full buffered body). True streaming
    /// requires an un-buffered HTTP reader (future feature).
    pub fn stream_body(&self) -> Vec<u8> {
        self.body.clone()
    }
}
