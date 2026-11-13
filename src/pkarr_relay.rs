#![cfg(feature = "native")]

//! A pkarr relay **server** — the other half of [`crate::pkarr::RelayClient`].
//!
//! `RelayClient` publishes a [`SignedPacket`] with `PUT {relay}/{z32-key}` and reads it back with
//! `GET {relay}/{z32-key}`; the body is [`SignedPacket::to_relay_bytes`] (`signature ‖ seq ‖ v`).
//! Until now the only thing on the other end was a public relay or a test fixture. This is the
//! real thing, small enough to run inside the private network so service discovery by dialkey
//! does not depend on a third party.
//!
//! ## What a relay is trusted for
//!
//! Nothing but availability. Every record carries its author's signature, so the relay cannot
//! forge one; a client verifies against the key it asked for. What the relay *does* enforce:
//!
//! - **Only valid records are stored.** The signature is verified against the key in the URL
//!   before anything is kept, so a `PUT` under key A with a record signed by key B is refused.
//! - **Sequence numbers only go up.** A record older than the one held is refused (`409`), as is
//!   a different record at the same sequence number. Re-sending the identical record is accepted
//!   and refreshes its age.
//! - **Bounded.** Request bodies are at most [`MAX_BODY`] bytes, the store holds at most
//!   [`Limits::max_keys`] keys, and a record older than [`Limits::max_age`] (when set) stops
//!   being served.
//! - **Optionally closed.** [`Limits::allow`] restricts who may *publish* (reads stay open).
//!   `RelayClient` cannot send credentials, so network placement is the other half of this:
//!   run the relay on a private interface.
//!
//! ## Persistence
//!
//! With a data directory every accepted record is written to `<dir>/<z32>.pkt` (a temp file then
//! an atomic rename) before it is acknowledged, and reloaded — re-verified — on start. A file
//! that does not verify is skipped and counted, never served.
//!
//! ## Not here
//!
//! The Mainline DHT. [`crate::pkarr`] has the same stated gap: relay (HTTP) path only.

use crate::signed_dns::{PublicKey, SignedDnsError, SignedPacket, MAX_VALUE_LEN};
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// The largest request body: `signature(64) ‖ seq(8) ‖ v`, with `v` capped at BEP44's limit.
pub const MAX_BODY: usize = 72 + MAX_VALUE_LEN;

const MAX_HEADER_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 256;

/// Seconds since the epoch, the clock the store is driven by (injected so tests control it).
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Store limits and the optional publisher allowlist.
#[derive(Debug, Clone)]
pub struct Limits {
    /// The most distinct keys held. Updating a key already held never counts against this.
    pub max_keys: usize,
    /// A record last written longer ago than this is no longer served. `None` keeps records
    /// until replaced: a publisher that announces once at boot must not vanish.
    pub max_age: Option<Duration>,
    /// When `Some`, only these keys may publish.
    pub allow: Option<HashSet<[u8; 32]>>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_keys: 100_000,
            max_age: None,
            allow: None,
        }
    }
}

/// Why a `PUT` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    /// The key is not on the publisher allowlist.
    NotAllowed,
    /// The body is not a record signed by the key it was sent under.
    Invalid(SignedDnsError),
    /// A record with a higher sequence number (or a different record at the same one) is held.
    Stale {
        /// The sequence number currently held.
        current: u64,
    },
    /// The store is at [`Limits::max_keys`] and this is a new key.
    Full,
    /// The record could not be written to disk, so it was not accepted.
    Io(String),
}

/// What an accepted `PUT` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// New key, or a higher sequence number than the one held.
    Stored,
    /// The identical record was already held; its age was refreshed.
    Unchanged,
}

/// What [`RelayStore::open`] found on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Records that verified and were loaded.
    pub loaded: usize,
    /// Files skipped: unreadable, malformed, or not verifying under their own file name.
    pub skipped: usize,
}

struct Entry {
    packet: SignedPacket,
    stored_at: u64,
}

/// The records a relay holds, keyed by public key.
pub struct RelayStore {
    limits: Limits,
    dir: Option<PathBuf>,
    map: Mutex<HashMap<[u8; 32], Entry>>,
}

impl RelayStore {
    /// A store that keeps records in memory only.
    #[must_use]
    pub fn in_memory(limits: Limits) -> Self {
        RelayStore {
            limits,
            dir: None,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// A store persisted under `dir` (created if missing), reloading what is already there.
    ///
    /// # Errors
    /// If the directory cannot be created or listed.
    pub fn open(dir: impl AsRef<Path>, limits: Limits) -> io::Result<(Self, LoadReport)> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let mut map = HashMap::new();
        let mut report = LoadReport::default();
        for item in std::fs::read_dir(&dir)? {
            let path = item?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pkt") {
                continue; // temp files and anything else that is not ours
            }
            match load_file(&path) {
                Some((key, entry)) => {
                    map.insert(*key.as_bytes(), entry);
                    report.loaded += 1;
                }
                None => report.skipped += 1,
            }
        }
        Ok((
            RelayStore {
                limits,
                dir: Some(dir),
                map: Mutex::new(map),
            },
            report,
        ))
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        // A poisoned lock means another request panicked mid-update; the map is still a valid
        // map of verified records, so keep serving rather than take the relay down with it.
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn expired(&self, entry: &Entry, now: u64) -> bool {
        self.limits
            .max_age
            .is_some_and(|age| now.saturating_sub(entry.stored_at) > age.as_secs())
    }

    /// Verify and store `body` as the record for `key`.
    ///
    /// # Errors
    /// See [`PutError`].
    pub fn put(&self, key: &PublicKey, body: &[u8], now: u64) -> Result<PutOutcome, PutError> {
        if self
            .limits
            .allow
            .as_ref()
            .is_some_and(|a| !a.contains(key.as_bytes()))
        {
            return Err(PutError::NotAllowed);
        }
        if body.len() > MAX_BODY {
            return Err(PutError::Invalid(SignedDnsError::ValueTooLong));
        }
        let packet = SignedPacket::from_relay_bytes(*key, body).map_err(PutError::Invalid)?;

        let mut map = self.lock();
        let held = map.get(key.as_bytes());
        let outcome = match held {
            Some(e) if packet.seq() < e.packet.seq() => {
                return Err(PutError::Stale {
                    current: e.packet.seq(),
                });
            }
            Some(e) if packet.seq() == e.packet.seq() => {
                if e.packet != packet {
                    return Err(PutError::Stale {
                        current: e.packet.seq(),
                    });
                }
                PutOutcome::Unchanged
            }
            Some(_) => PutOutcome::Stored,
            None => {
                if map.len() >= self.limits.max_keys {
                    let dead: Vec<[u8; 32]> = map
                        .iter()
                        .filter(|(_, e)| self.expired(e, now))
                        .map(|(k, _)| *k)
                        .collect();
                    for k in dead {
                        map.remove(&k);
                        self.remove_file(&PublicKey::from_bytes(&k).ok());
                    }
                    if map.len() >= self.limits.max_keys {
                        return Err(PutError::Full);
                    }
                }
                PutOutcome::Stored
            }
        };
        if let Some(dir) = &self.dir {
            write_file(dir, key, now, body).map_err(|e| PutError::Io(e.to_string()))?;
        }
        map.insert(
            *key.as_bytes(),
            Entry {
                packet,
                stored_at: now,
            },
        );
        Ok(outcome)
    }

    /// The relay wire bytes held for `key`, unless absent or past [`Limits::max_age`].
    #[must_use]
    pub fn get(&self, key: &PublicKey, now: u64) -> Option<Vec<u8>> {
        self.get_packet(key, now).map(|p| p.to_relay_bytes())
    }

    /// The record held for `key`, unless absent or past [`Limits::max_age`].
    #[must_use]
    pub fn get_packet(&self, key: &PublicKey, now: u64) -> Option<SignedPacket> {
        let map = self.lock();
        map.get(key.as_bytes())
            .filter(|e| !self.expired(e, now))
            .map(|e| e.packet.clone())
    }

    /// Drop every expired record (and its file). Returns how many.
    pub fn sweep(&self, now: u64) -> usize {
        let mut map = self.lock();
        let dead: Vec<[u8; 32]> = map
            .iter()
            .filter(|(_, e)| self.expired(e, now))
            .map(|(k, _)| *k)
            .collect();
        for k in &dead {
            map.remove(k);
            self.remove_file(&PublicKey::from_bytes(k).ok());
        }
        dead.len()
    }

    /// How many keys are held (expired ones included until swept).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remove_file(&self, key: &Option<PublicKey>) {
        if let (Some(dir), Some(key)) = (&self.dir, key) {
            let _ = std::fs::remove_file(dir.join(format!("{}.pkt", key.to_z32())));
        }
    }
}

/// On-disk form: `stored_at(8, big-endian) ‖ relay bytes`.
fn write_file(dir: &Path, key: &PublicKey, now: u64, body: &[u8]) -> io::Result<()> {
    let z32 = key.to_z32();
    let tmp = dir.join(format!(".{z32}.tmp"));
    let mut data = Vec::with_capacity(8 + body.len());
    data.extend_from_slice(&now.to_be_bytes());
    data.extend_from_slice(body);
    std::fs::write(&tmp, &data)?;
    std::fs::rename(&tmp, dir.join(format!("{z32}.pkt")))
}

fn load_file(path: &Path) -> Option<(PublicKey, Entry)> {
    let key = PublicKey::from_z32(path.file_stem()?.to_str()?).ok()?;
    let data = std::fs::read(path).ok()?;
    let stored_at = u64::from_be_bytes(data.get(..8)?.try_into().ok()?);
    let packet = SignedPacket::from_relay_bytes(key, data.get(8..)?).ok()?;
    Some((key, Entry { packet, stored_at }))
}

/// A response the HTTP layer will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Body bytes.
    pub body: Vec<u8>,
    /// `Content-Type` value.
    pub content_type: &'static str,
}

impl Response {
    fn text(status: u16, msg: &str) -> Self {
        Response {
            status,
            body: format!("{msg}\n").into_bytes(),
            content_type: "text/plain",
        }
    }
}

/// Route one request. Pure: no I/O, the clock is passed in.
///
/// `GET /health`, `GET /{z32}`, `PUT /{z32}`; anything else is `404`/`405`.
#[must_use]
pub fn handle(store: &RelayStore, method: &str, target: &str, body: &[u8], now: u64) -> Response {
    let path = target.split(['?', '#']).next().unwrap_or("");
    if path == "/health" {
        return match method {
            "GET" | "HEAD" => Response::text(200, &format!("ok keys={}", store.len())),
            _ => Response::text(405, "method not allowed"),
        };
    }
    let Some(label) = path
        .strip_prefix('/')
        .filter(|l| !l.is_empty() && !l.contains('/'))
    else {
        return Response::text(404, "not found");
    };
    let Ok(key) = PublicKey::from_z32(label) else {
        return Response::text(400, "not a z-base-32 public key");
    };
    match method {
        "GET" => match store.get(&key, now) {
            Some(bytes) => Response {
                status: 200,
                body: bytes,
                content_type: "application/octet-stream",
            },
            None => Response::text(404, "no record"),
        },
        "PUT" => match store.put(&key, body, now) {
            Ok(_) => Response::text(200, "ok"),
            Err(PutError::NotAllowed) => Response::text(403, "key may not publish here"),
            Err(PutError::Invalid(SignedDnsError::ValueTooLong)) => {
                Response::text(413, "record too large")
            }
            Err(PutError::Invalid(e)) => Response::text(400, &format!("invalid record: {e}")),
            Err(PutError::Stale { current }) => {
                Response::text(409, &format!("a record with seq {current} is held"))
            }
            Err(PutError::Full) => Response::text(507, "relay is full"),
            Err(PutError::Io(_)) => Response::text(500, "could not persist record"),
        },
        _ => Response::text(405, "method not allowed"),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        507 => "Insufficient Storage",
        _ => "Error",
    }
}

/// Serve the relay on `listener` until the task is dropped. Each connection carries one request
/// (`Connection: close`) under a ten-second deadline; at most 256 are in flight.
///
/// # Errors
/// Only if `accept` itself fails.
pub async fn serve(listener: tokio::net::TcpListener, store: Arc<RelayStore>) -> io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            drop(stream); // shed load rather than queue it
            continue;
        };
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(REQUEST_TIMEOUT, serve_one(stream, &store)).await;
        });
    }
}

async fn serve_one(mut stream: tokio::net::TcpStream, store: &RelayStore) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let resp = match read_request(&mut stream).await {
        Ok((method, target, body)) => handle(store, &method, &target, &body, unix_now()),
        Err(status) => Response::text(status, reason(status)),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    stream.shutdown().await?;
    // Drain so a client still sending does not see a reset instead of our status.
    let mut sink = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut sink)).await;
    Ok(())
}

/// Read one request: `(method, target, body)`, or the status to answer with.
async fn read_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, Vec<u8>), u16> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(431);
        }
        let n = stream.read(&mut chunk).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (first.next(), first.next(), first.next(), first.next())
    else {
        return Err(400);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(400);
    }
    let mut length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(400);
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(501); // a record has a known length; chunked bodies are not supported
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n: usize = value.parse().map_err(|_| 400u16)?;
            if length.is_some_and(|prev| prev != n) {
                return Err(400); // conflicting lengths are a smuggling signal, not a typo
            }
            length = Some(n);
        }
    }
    let length = match (method, length) {
        ("PUT", None) => return Err(411),
        (_, l) => l.unwrap_or(0),
    };
    if length > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    if body.len() > length {
        body.truncate(length);
    }
    while body.len() < length {
        let n = stream.read(&mut chunk).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        let take = n.min(length - body.len());
        body.extend_from_slice(&chunk[..take]);
    }
    Ok((method.to_owned(), target.to_owned(), body))
}
