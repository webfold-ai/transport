//! The certificate renewal engine — the issuance worker [`crate::edge::EdgeRegistry::required_cert_names`]
//! has always described as "the work list" and nothing implemented.
//!
//! [`crate::acme::AcmeClient`] can obtain one certificate. Operating an edge needs everything
//! around that, and getting any of it wrong is an outage on a name the browser will not let a
//! user click through (`.app`/`.dev` are HSTS-preloaded):
//!
//! - **What to issue.** The registry's required names, plus a *baseline* (every apex wildcard,
//!   so the first customer on a new apex never waits on a CA round trip).
//! - **When to renew.** At a fraction of the certificate's own lifetime ([`RenewalPolicy`]),
//!   not "30 days before expiry": lifetimes are shrinking (90 -> 45 -> 6 days) and a fixed
//!   30-day window would mean renewing a 45-day certificate after 15 days and a 6-day one
//!   immediately, forever. Sooner if the CA says so: where it publishes ACME Renewal
//!   Information (RFC 9773, [`CertIssuer::renewal_window`]) a name is also due once a
//!   deterministic per-name instant inside the CA's suggested window has passed
//!   ([`Reason::CaSuggested`], [`ari_renew_at`]). ARI is advisory and can only *advance* a
//!   renewal: a CA without it, or one whose answer fails, leaves the percentage rule in charge.
//! - **What to do when it fails.** Keep serving the last-known-good certificate (a failed
//!   *renewal* is not a failed hostname — INV-06), back off exponentially with deterministic
//!   per-name jitter, honour the CA's `Retry-After`, and never hammer a rate limit.
//! - **When to give up.** A hostname that has *never* had a certificate and keeps failing is
//!   failed with a reason the portal can show ([`EdgeRegistry::cert_failed`]); a baseline
//!   wildcard is never failed, only retried.
//! - **Surviving a restart.** [`FileCertStore`] persists every certificate (one atomically
//!   renamed file per name, 0600), so a reboot does not re-order every certificate and run
//!   into the CA's duplicate-certificate limit.
//! - **Not holding keys forever.** Certificates for names that stopped being required are
//!   pruned after a grace period.
//! - **Not leaving a live credential behind.** A dedicated certificate for a name that is
//!   released is revoked ([`CertIssuer::revoke`], reason `cessationOfOperation`) — see
//!   [`RevocationQueue`] for why that is a durable queue rather than a call — and a renewal names
//!   the certificate it replaces ([`CertIssuer::issue_replacing`], RFC 9773 `replaces`).
//!
//! The registry lock is never held across CA I/O: [`RenewalEngine::run_once`] takes it for
//! short reads and short state transitions only.
//!
//! ## What is verified
//! The planner, backoff, activation/failure transitions, persistence and pruning are unit
//! tested with a scripted issuer; the ACME protocol itself is tested against a mock CA in
//! [`crate::acme`]. Against a *real* CA (Let's Encrypt staging) this is not exercised by any
//! automated test: no outbound path to one exists in CI.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hashtrinity::crypto::sha256;
use hashtrinity::Table;

use crate::acme::{days_from_civil, der, AcmeClient, AcmeError, Dns01Responder, Http01Responder, RenewalWindow, RevocationReason};
use crate::edge::{CertMaterial, CertSource, EdgeRegistry, APEXES};
use crate::edge_proxy::MemoryCertSource;
use crate::BoxFuture;

// ── Certificate validity window ───────────────────────────────────────────────────────────

/// A certificate's validity window, unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}

impl Validity {
    #[must_use]
    pub fn lifetime(&self) -> i64 {
        self.not_after - self.not_before
    }
}

/// `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) -> unix seconds.
fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?;
    let s = s.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, s.len()) {
        (0x17, 12) => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..]) // RFC 5280 §4.1.2.5.1
        }
        (0x18, 14) => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let (month, day, hh, mm, ss) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// The leaf certificate's validity window, read from the first `CERTIFICATE` block of a PEM
/// chain. The signature is NOT verified here — this answers "when does it expire", not "is it
/// trustworthy"; trust is the CA's job and the browser's.
#[must_use]
pub fn cert_validity(chain_pem: &str) -> Option<Validity> {
    let cert_der = crate::pem::blocks(chain_pem, "CERTIFICATE").into_iter().next()?;
    let (tag, cert, _) = der::read(&cert_der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der::read(cert)?;
    if tag != 0x30 {
        return None;
    }
    // TBSCertificate: [0] version OPTIONAL, serial, signature alg, issuer, validity, ...
    let (t0, _, after) = der::read(tbs)?;
    let rest = if t0 == 0xA0 { after } else { tbs };
    let (_, _, rest) = der::read(rest)?; // serialNumber
    let (_, _, rest) = der::read(rest)?; // signature AlgorithmIdentifier
    let (_, _, rest) = der::read(rest)?; // issuer
    let (tag, validity, _) = der::read(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, nb, after) = der::read(validity)?;
    let (t2, na, _) = der::read(after)?;
    let v = Validity { not_before: parse_asn1_time(t1, nb)?, not_after: parse_asn1_time(t2, na)? };
    (v.not_after > v.not_before).then_some(v)
}

// ── Storage ───────────────────────────────────────────────────────────────────────────────

/// A writable [`CertSource`]. The renewal engine writes through this; the SNI resolver reads
/// through the [`CertSource`] half.
pub trait CertStore: CertSource {
    /// Install `material` for `name`. Must be atomic: on `Err` the previous certificate is
    /// still what [`CertSource::cert_for`] returns.
    fn put(&self, name: &str, material: CertMaterial) -> Result<(), String>;
    fn remove(&self, name: &str);
    fn names(&self) -> Vec<String>;

    /// Retry state recorded for `name` by a previous process, if this store persists it. Without
    /// it a restart forgets a CA's `Retry-After` and immediately re-orders, which is how a routine
    /// deploy defeats rate-limit backoff.
    fn load_retry(&self, _name: &str) -> Option<RetryState> {
        None
    }

    /// Record (`Some`) or clear (`None`) `name`'s retry state. Best effort: losing it costs one
    /// early retry, never correctness.
    fn save_retry(&self, _name: &str, _state: Option<&RetryState>) {}
}

/// The part of a name's renewal state that must survive a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryState {
    pub failures: u32,
    /// Unix seconds before which no new order is placed.
    pub next_attempt: i64,
    pub last_error: Option<String>,
}

impl CertStore for MemoryCertSource {
    fn put(&self, name: &str, material: CertMaterial) -> Result<(), String> {
        self.install(name, material);
        Ok(())
    }
    fn remove(&self, name: &str) {
        MemoryCertSource::remove(self, name);
    }
    fn names(&self) -> Vec<String> {
        MemoryCertSource::names(self)
    }
}

/// File name stem for a certificate name, or `None` if the name is not a plain DNS name (or
/// `*.` plus one) — the name comes from the registry, but a path built from it is a
/// path-traversal sink if anything upstream ever goes wrong.
fn file_stem(name: &str) -> Option<String> {
    let (wild, body) = match name.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, name),
    };
    let ok = !body.is_empty()
        && body.len() <= 253
        && !body.starts_with(['.', '-'])
        && !body.contains("..")
        && body.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    ok.then(|| if wild { format!("_wildcard.{body}") } else { body.to_string() })
}

fn name_from_stem(stem: &str) -> String {
    match stem.strip_prefix("_wildcard.") {
        Some(rest) => format!("*.{rest}"),
        None => stem.to_string(),
    }
}

/// Certificates on disk, served from memory. One file per name holding the chain then the key,
/// replaced by write-temp-then-rename so a crash can never leave a new key beside an old chain.
pub struct FileCertStore {
    dir: PathBuf,
    mem: MemoryCertSource,
}

const KEY_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";

impl FileCertStore {
    /// Open (creating if needed) `dir` and load every certificate already in it. Files that do
    /// not parse are skipped with a warning, never fatal: a corrupt file for one name must not
    /// stop the edge booting and serving every other name.
    ///
    /// # Errors
    /// Only if the directory cannot be created or listed.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mem = MemoryCertSource::new();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pem") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            match Self::read_file(&path) {
                Some(material) => mem.install(name_from_stem(stem), material),
                None => tracing::warn!(path = %path.display(), "skipping unreadable certificate file"),
            }
        }
        Ok(FileCertStore { dir, mem })
    }

    fn read_file(path: &Path) -> Option<CertMaterial> {
        let text = std::fs::read_to_string(path).ok()?;
        let split = text.find(KEY_BEGIN)?;
        let material = CertMaterial { chain_pem: text[..split].to_string(), key_pem: text[split..].to_string() };
        validate(&material).ok()?;
        Some(material)
    }

    fn path_for(&self, name: &str) -> Option<PathBuf> {
        Some(self.dir.join(format!("{}.pem", file_stem(name)?)))
    }

    fn retry_path_for(&self, name: &str) -> Option<PathBuf> {
        Some(self.dir.join(format!("{}.retry", file_stem(name)?)))
    }
}

/// Material is installable only if it has a chain whose leaf has a readable validity window and
/// a PKCS#8 key. This is deliberately cheap structural checking — whether the key matches the
/// leaf is established by the CA flow that produced it.
fn validate(material: &CertMaterial) -> Result<Validity, String> {
    let v = cert_validity(&material.chain_pem).ok_or("certificate chain has no readable leaf")?;
    if crate::pem::blocks(&material.key_pem, "PRIVATE KEY").is_empty() {
        return Err("missing PKCS#8 private key".to_string());
    }
    Ok(v)
}

impl CertSource for FileCertStore {
    fn cert_for(&self, cert_name: &str) -> Option<CertMaterial> {
        self.mem.cert_for(cert_name)
    }
}

impl CertStore for FileCertStore {
    fn put(&self, name: &str, material: CertMaterial) -> Result<(), String> {
        validate(&material)?;
        let path = self.path_for(name).ok_or_else(|| format!("refusing to store a certificate under {name:?}"))?;
        let tmp = path.with_extension("pem.tmp");
        let mut body = material.chain_pem.clone();
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&material.key_pem);
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.write_all(body.as_bytes()).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.sync_all().map_err(|e| format!("syncing {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| format!("installing {}: {e}", path.display()))?;
        // The rename itself must be durable too: without syncing the directory a power loss can
        // drop the new directory entry and a restart would reload the old certificate (or none)
        // and place another order.
        #[cfg(unix)]
        std::fs::File::open(&self.dir).and_then(|d| d.sync_all()).map_err(|e| format!("syncing {}: {e}", self.dir.display()))?;
        // Memory is updated only after the file is durable: what is served is never ahead of
        // what a restart would reload.
        self.mem.install(name.to_string(), material);
        Ok(())
    }

    fn remove(&self, name: &str) {
        if let Some(path) = self.path_for(name) {
            let _ = std::fs::remove_file(path);
        }
        self.mem.remove(name);
    }

    fn names(&self) -> Vec<String> {
        self.mem.names()
    }

    fn load_retry(&self, name: &str) -> Option<RetryState> {
        let text = std::fs::read_to_string(self.retry_path_for(name)?).ok()?;
        let mut lines = text.lines();
        let failures = lines.next()?.strip_prefix("failures=")?.parse().ok()?;
        let next_attempt = lines.next()?.strip_prefix("next_attempt=")?.parse().ok()?;
        let last_error = lines.next().and_then(|l| l.strip_prefix("last_error=")).map(str::to_string).filter(|e| !e.is_empty());
        Some(RetryState { failures, next_attempt, last_error })
    }

    fn save_retry(&self, name: &str, state: Option<&RetryState>) {
        let Some(path) = self.retry_path_for(name) else { return };
        let Some(state) = state else {
            let _ = std::fs::remove_file(path);
            return;
        };
        let error = state.last_error.as_deref().unwrap_or("").replace(['\n', '\r'], " ");
        let body = format!("failures={}\nnext_attempt={}\nlast_error={error}\n", state.failures, state.next_attempt);
        let tmp = path.with_extension("retry.tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

// ── Revocation ────────────────────────────────────────────────────────────────────────────

/// A certificate waiting to be revoked. The key is held (0600) beside the chain until the
/// revocation lands or the certificate expires — see [`RevocationQueue`].
#[derive(Clone)]
struct PendingRevocation {
    id: String,
    name: String,
    material: CertMaterial,
    enqueued_at: i64,
    attempts: u32,
    next_attempt: i64,
    last_error: Option<String>,
}

// Manual: `material` holds a private key.
impl std::fmt::Debug for PendingRevocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRevocation")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("attempts", &self.attempts)
            .field("material", &"<redacted>")
            .finish()
    }
}

/// What the queue shows about one pending revocation (never the key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationStatus {
    pub name: String,
    /// SHA-256 prefix of the chain: the queue's identity for this certificate.
    pub id: String,
    pub enqueued_at: i64,
    pub attempts: u32,
    pub next_attempt: i64,
    pub last_error: Option<String>,
    /// When the certificate expires on its own, ending the need to revoke it.
    pub not_after: Option<i64>,
}

/// Tunables for the revocation worker ([`process_revocations`]).
#[derive(Clone, Copy, Debug)]
pub struct RevocationPolicy {
    /// First retry delay after a failed attempt; doubles per attempt.
    pub retry_base_secs: u64,
    /// Cap on the retry delay. A revocation is never abandoned while the certificate is valid
    /// (its key is a live credential), so this bounds the polling rate, not the effort.
    pub retry_max_secs: u64,
    /// Most revocations attempted per pass.
    pub max_per_pass: usize,
}

impl Default for RevocationPolicy {
    fn default() -> Self {
        RevocationPolicy { retry_base_secs: 60, retry_max_secs: 6 * 3600, max_per_pass: 50 }
    }
}

/// The durable queue of certificates that must be revoked.
///
/// **Why a queue, and why the key stays in it.** When a customer hostname is released the
/// certificate for it is a credential for a name we no longer serve, with a private key we hold:
/// until it is revoked or expires, anyone who obtains that key can impersonate the name. So it
/// is revoked promptly — but the CA can be unreachable, rate limiting or rejecting the
/// account, and a release must not wait on any of that. The certificate is therefore *moved* out
/// of the serving store into this queue (stopping service at once), and the revocation is retried
/// with backoff until it succeeds. The key is kept, 0600 and fsynced, for exactly as long as a
/// revocation might still be needed: it lets the certificate's own key sign the revocation when
/// the account cannot (RFC 8555 §7.6), and it is destroyed (overwritten, then unlinked) only when
/// the CA has revoked the certificate or the certificate has expired. The queue entry is written
/// **before** the certificate leaves the store ([`retire_for_revocation`]), so no crash or disk
/// error between the two can lose the key of a certificate that has not been revoked.
///
/// Entries live in `dir`, one `<id>.revoke` file each (`dir` is normally `<cert dir>/revocations`,
/// which [`FileCertStore`] ignores), and are reloaded at boot.
pub struct RevocationQueue {
    dir: Option<PathBuf>,
    entries: std::sync::Mutex<Vec<PendingRevocation>>,
    wake: Arc<tokio::sync::Notify>,
}

fn revocation_id(chain_pem: &str) -> String {
    sha256(chain_pem.as_bytes()).iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Write `body` to `path` atomically (temp file, 0600, fsync, rename, fsync of the directory).
fn write_private(path: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.write_all(body.as_bytes()).and_then(|()| f.sync_all()).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("installing {}: {e}", path.display()))?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("syncing {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Overwrite then unlink: the key does not linger in a freed block more than a file system lets us
/// prevent (journalling and copy-on-write file systems can still keep old blocks; the directory is
/// 0700 and the disk is expected to be encrypted).
fn shred(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let mut f = f;
            let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0)];
            let _ = f.write_all(&zeros).and_then(|()| f.sync_all());
        }
    }
    let _ = std::fs::remove_file(path);
}

impl PendingRevocation {
    fn to_file(&self) -> String {
        let error = self.last_error.as_deref().unwrap_or("").replace(['\n', '\r'], " ");
        let mut body = format!(
            "name={}\nenqueued_at={}\nattempts={}\nnext_attempt={}\nlast_error={error}\n",
            self.name, self.enqueued_at, self.attempts, self.next_attempt
        );
        body.push_str(&self.material.chain_pem);
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&self.material.key_pem);
        body
    }

    fn from_file(text: &str) -> Option<Self> {
        let split = text.find("-----BEGIN")?;
        let (header, pems) = text.split_at(split);
        let key_at = pems.find(KEY_BEGIN)?;
        let material = CertMaterial { chain_pem: pems[..key_at].to_string(), key_pem: pems[key_at..].to_string() };
        validate(&material).ok()?;
        let mut lines = header.lines();
        let mut field = |k: &str| lines.next().and_then(|l| l.strip_prefix(k)).map(str::to_string);
        let name = field("name=")?;
        let enqueued_at = field("enqueued_at=")?.parse().ok()?;
        let attempts = field("attempts=")?.parse().ok()?;
        let next_attempt = field("next_attempt=")?.parse().ok()?;
        let last_error = field("last_error=").filter(|e| !e.is_empty());
        Some(PendingRevocation { id: revocation_id(&material.chain_pem), name, material, enqueued_at, attempts, next_attempt, last_error })
    }
}

impl RevocationQueue {
    /// A queue that lives in memory only (tests, and hosts with no durable store). A restart
    /// forgets it, so the production edge uses [`Self::open`].
    #[must_use]
    pub fn in_memory() -> Self {
        RevocationQueue { dir: None, entries: std::sync::Mutex::new(Vec::new()), wake: Arc::new(tokio::sync::Notify::new()) }
    }

    /// Open (creating, 0700) `dir` and load every pending revocation in it. A file that does not
    /// parse is left untouched on disk (it may hold the only copy of a key) and logged.
    ///
    /// # Errors
    /// Only if the directory cannot be created or listed.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("revoke") {
                continue;
            }
            match std::fs::read_to_string(&path).ok().and_then(|t| PendingRevocation::from_file(&t)) {
                Some(p) => entries.push(p),
                None => tracing::error!(path = %path.display(), "unreadable pending-revocation file; left in place"),
            }
        }
        entries.sort_by(|a, b| (a.enqueued_at, &a.id).cmp(&(b.enqueued_at, &b.id)));
        Ok(RevocationQueue { dir: Some(dir), entries: std::sync::Mutex::new(entries), wake: Arc::new(tokio::sync::Notify::new()) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<PendingRevocation>> {
        self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn path_for(&self, id: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(format!("{id}.revoke")))
    }

    /// Notified whenever something is enqueued — a worker sleeping between passes waits on this
    /// too, so a release is revoked within moments rather than at the next tick.
    #[must_use]
    pub fn wakeup(&self) -> Arc<tokio::sync::Notify> {
        self.wake.clone()
    }

    /// Queue `material` (for `name`) for revocation. **Durable before it returns**: `Err` means
    /// nothing was recorded and the caller must keep the certificate where it is. Queueing the same
    /// certificate twice is a no-op.
    ///
    /// # Errors
    /// The material is unusable or the entry could not be written to disk.
    pub fn enqueue(&self, name: &str, material: CertMaterial, now: i64) -> Result<(), String> {
        validate(&material)?;
        let id = revocation_id(&material.chain_pem);
        if self.lock().iter().any(|e| e.id == id) {
            return Ok(());
        }
        let entry = PendingRevocation { id: id.clone(), name: name.to_string(), material, enqueued_at: now, attempts: 0, next_attempt: now, last_error: None };
        if let Some(path) = self.path_for(&id) {
            write_private(&path, &entry.to_file())?;
        }
        self.lock().push(entry);
        self.wake.notify_one();
        Ok(())
    }

    /// Pending revocations, for status and metrics.
    #[must_use]
    pub fn status(&self) -> Vec<RevocationStatus> {
        self.lock()
            .iter()
            .map(|e| RevocationStatus {
                name: e.name.clone(),
                id: e.id.clone(),
                enqueued_at: e.enqueued_at,
                attempts: e.attempts,
                next_attempt: e.next_attempt,
                last_error: e.last_error.clone(),
                not_after: cert_validity(&e.material.chain_pem).map(|v| v.not_after),
            })
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn due(&self, now: i64, limit: usize) -> Vec<PendingRevocation> {
        self.lock().iter().filter(|e| e.next_attempt <= now).take(limit).cloned().collect()
    }

    /// Drop a finished entry (revoked, or expired) and destroy its key.
    fn complete(&self, id: &str) {
        self.lock().retain(|e| e.id != id);
        if let Some(path) = self.path_for(id) {
            shred(&path);
        }
    }

    fn record_failure(&self, id: &str, error: &str, next_attempt: i64) {
        let updated = {
            let mut entries = self.lock();
            entries.iter_mut().find(|e| e.id == id).map(|e| {
                e.attempts = e.attempts.saturating_add(1);
                e.next_attempt = next_attempt;
                e.last_error = Some(error.to_string());
                e.clone()
            })
        };
        // Best effort: losing the retry counters costs one early retry, never the entry.
        if let (Some(entry), Some(path)) = (updated, self.path_for(id)) {
            if let Err(e) = write_private(&path, &entry.to_file()) {
                tracing::warn!(error = %e, "could not persist revocation retry state");
            }
        }
    }
}

/// What one [`process_revocations`] pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationReport {
    /// Names whose certificate the CA has now revoked (including `alreadyRevoked`).
    pub revoked: Vec<String>,
    /// Names dropped because the certificate expired before it could be revoked: nothing is left
    /// to revoke, and the key is destroyed.
    pub expired: Vec<String>,
    /// `(name, error)` for attempts that failed and will be retried.
    pub failed: Vec<(String, String)>,
    /// Entries still waiting after the pass.
    pub pending: usize,
}

/// Try every due revocation once. A failure schedules a retry with exponential backoff
/// (honouring the CA's `Retry-After`); an entry is only ever removed when the CA revoked the
/// certificate or the certificate has expired.
pub async fn process_revocations(queue: &RevocationQueue, issuer: &dyn CertIssuer, now: i64, policy: &RevocationPolicy) -> RevocationReport {
    let mut report = RevocationReport::default();
    for entry in queue.due(now, policy.max_per_pass) {
        if cert_validity(&entry.material.chain_pem).is_some_and(|v| now >= v.not_after) {
            queue.complete(&entry.id);
            tracing::info!(cert = %entry.name, "certificate expired before it could be revoked; dropped");
            report.expired.push(entry.name);
            continue;
        }
        match issuer.revoke(&entry.material).await {
            Ok(()) => {
                queue.complete(&entry.id);
                tracing::info!(cert = %entry.name, attempts = entry.attempts + 1, "certificate revoked");
                report.revoked.push(entry.name);
            }
            Err(e) => {
                let exp = entry.attempts.min(20);
                let backoff = policy.retry_base_secs.saturating_mul(1u64 << exp).min(policy.retry_max_secs);
                let wait = backoff.max(e.retry_after_secs().unwrap_or(0).min(policy.retry_max_secs.max(3600)));
                let next = now.saturating_add(i64::try_from(wait).unwrap_or(i64::MAX / 4));
                tracing::warn!(cert = %entry.name, attempts = entry.attempts + 1, error = %e, retry_in_secs = wait, "certificate revocation failed; will retry");
                queue.record_failure(&entry.id, &e.to_string(), next);
                report.failed.push((entry.name, e.to_string()));
            }
        }
    }
    report.pending = queue.len();
    report
}

/// Why [`retire_for_revocation`] did nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retired {
    /// The certificate was queued for revocation and removed from the store.
    Queued,
    /// The store holds nothing under that name.
    NotHeld,
    /// A wildcard certificate: shared by every hostname under the apex, so it is **never**
    /// revoked because one hostname went away.
    SharedWildcard,
}

/// Stop serving `name`'s dedicated certificate and queue it for revocation, in the order that
/// cannot lose the key: the queue entry is made durable first, and only then is the certificate
/// removed from the store. If queueing fails the certificate stays where it is (and keeps being
/// served — the caller has already stopped routing the name) so the next prune retries.
///
/// # Errors
/// The revocation could not be recorded; nothing was changed.
pub fn retire_for_revocation<S: CertStore + ?Sized>(store: &S, queue: &RevocationQueue, name: &str, now: i64) -> Result<Retired, String> {
    if name.starts_with("*.") {
        return Ok(Retired::SharedWildcard);
    }
    let Some(material) = store.cert_for(name) else { return Ok(Retired::NotHeld) };
    queue.enqueue(name, material, now)?;
    store.remove(name);
    store.save_retry(name, None);
    Ok(Retired::Queued)
}

// ── Issuance ──────────────────────────────────────────────────────────────────────────────

/// Obtains a certificate for one certificate name. A trait so the engine is testable without a
/// CA; [`AcmeIssuer`] is the production implementation.
pub trait CertIssuer: Send + Sync {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>>;

    /// The CA's renewal advice for a certificate it issued (ACME Renewal Information, RFC 9773),
    /// if it gives any. Advisory: `None` — the default — means "no advice", whether the CA has
    /// no ARI, does not know the certificate or failed to answer, and the engine then renews on
    /// the percentage rule alone. An implementation should not retry or sleep here; the engine
    /// polls at most once per [`RenewalWindow::retry_after_secs`] (default 6 h) per name.
    fn renewal_window<'a>(&'a self, _material: &'a CertMaterial) -> BoxFuture<'a, Option<RenewalWindow>> {
        Box::pin(async { None })
    }

    /// As [`Self::issue`], for a renewal of `previous`: an ACME issuer names it in the order
    /// (`replaces`, RFC 9773 §5) so the CA can recognise the order as a renewal. The default
    /// forwards to [`Self::issue`], so an issuer that has no use for it need not know it exists.
    fn issue_replacing<'a>(&'a self, cert_name: &'a str, _previous: &'a CertMaterial) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        self.issue(cert_name)
    }

    /// Revoke `material` at the CA (reason `cessationOfOperation`: the name is no longer ours to
    /// serve). Must treat "already revoked" as success. The default does nothing and succeeds —
    /// right for an issuer with no CA behind it, and the reason a caller that must know a
    /// certificate is revoked has to use an issuer that implements this ([`AcmeIssuer`] does).
    fn revoke<'a>(&'a self, _material: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Lets one issuer serve the renewal engine and a separate revocation worker.
impl<T: CertIssuer + ?Sized> CertIssuer for Arc<T> {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        (**self).issue(cert_name)
    }
    fn renewal_window<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Option<RenewalWindow>> {
        (**self).renewal_window(material)
    }
    fn issue_replacing<'a>(&'a self, cert_name: &'a str, previous: &'a CertMaterial) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        (**self).issue_replacing(cert_name, previous)
    }
    fn revoke<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
        (**self).revoke(material)
    }
}

/// [`CertIssuer`] over a registered ACME account: DNS-01 for wildcards (we are the
/// authoritative server for our apexes), HTTP-01 for a customer's own hostname.
pub struct AcmeIssuer {
    client: AcmeClient,
    dns01: Arc<dyn Dns01Responder>,
    http01: Option<Arc<dyn Http01Responder>>,
}

impl AcmeIssuer {
    #[must_use]
    pub fn new(client: AcmeClient, dns01: Arc<dyn Dns01Responder>, http01: Option<Arc<dyn Http01Responder>>) -> Self {
        AcmeIssuer { client, dns01, http01 }
    }
}

impl AcmeIssuer {
    async fn order(&self, cert_name: &str, previous: Option<&CertMaterial>) -> Result<CertMaterial, AcmeError> {
        if let Some(apex) = cert_name.strip_prefix("*.") {
            // The wildcard does not cover the bare apex, which we also serve; one certificate
            // carries both names (two TXT values at the same `_acme-challenge` name).
            let names = [cert_name, apex];
            match previous {
                Some(p) => self.client.issue_dns01_replacing(&names, self.dns01.as_ref(), &p.chain_pem).await,
                None => self.client.issue_dns01(&names, self.dns01.as_ref()).await,
            }
        } else if let Some(http01) = &self.http01 {
            match previous {
                Some(p) => self.client.issue_replacing(&[cert_name], http01.as_ref(), &p.chain_pem).await,
                None => self.client.issue(&[cert_name], http01.as_ref()).await,
            }
        } else {
            // No way to prove control of a customer's name without an HTTP-01 listener.
            Err(AcmeError::ChallengeSetup)
        }
    }
}

impl CertIssuer for AcmeIssuer {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        Box::pin(self.order(cert_name, None))
    }

    fn issue_replacing<'a>(&'a self, cert_name: &'a str, previous: &'a CertMaterial) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        Box::pin(self.order(cert_name, Some(previous)))
    }

    fn renewal_window<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Option<RenewalWindow>> {
        Box::pin(async move {
            match self.client.renewal_info(&material.chain_pem).await {
                Ok(window) => window,
                Err(e) => {
                    tracing::debug!(error = %e, "ARI lookup failed; renewing on the percentage rule");
                    None
                }
            }
        })
    }

    /// Signed by the account first (it ordered the certificate). If the CA says the account has no
    /// claim to it — the account key was rotated onto a new account, or the certificate predates
    /// this one — the certificate's own key signs instead, which the CA accepts from whoever holds
    /// it. That is why the queue keeps the key until the revocation lands.
    fn revoke<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async move {
            let reason = RevocationReason::CessationOfOperation;
            let by_account = self.client.revoke_certificate(material.chain_pem.as_bytes(), reason).await;
            match by_account {
                Ok(_) => Ok(()),
                Err(e) if e.is_problem("unauthorized") || matches!(e, AcmeError::Rejected { status: 401 | 403, .. }) => {
                    tracing::info!("account not authorised to revoke; signing the revocation with the certificate's key");
                    self.client.revoke_certificate_with_key(material.chain_pem.as_bytes(), &material.key_pem, reason).await.map(|_| ())
                }
                Err(e) => Err(e),
            }
        })
    }
}

// ── Policy ────────────────────────────────────────────────────────────────────────────────

/// Tunables. Defaults are chosen for Let's Encrypt-class CAs.
#[derive(Clone, Debug)]
pub struct RenewalPolicy {
    /// Renew once this percentage of the certificate's lifetime has elapsed. 66 renews a
    /// 90-day certificate at day 59 (31 left), a 45-day one at day 30, a 6-day one at day 4.
    pub renew_after_percent: u8,
    /// First retry delay after a failure; doubles per consecutive failure.
    pub retry_base_secs: u64,
    /// Cap on the retry delay (also the cap applied to a CA's `Retry-After`: 7 days).
    pub retry_max_secs: u64,
    /// Most orders started per [`RenewalEngine::run_once`] — keeps a mass re-issue from
    /// blowing through the CA's new-orders limit.
    pub max_per_run: usize,
    /// Consecutive failures after which a name that has NEVER had a certificate fails its
    /// waiting hostnames.
    pub give_up_after: u32,
    /// How long a certificate for a no-longer-required name is kept before being deleted.
    pub prune_after_secs: i64,
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        RenewalPolicy {
            renew_after_percent: 66,
            retry_base_secs: 600,
            retry_max_secs: 24 * 3600,
            max_per_run: 10,
            give_up_after: 6,
            prune_after_secs: 7 * 24 * 3600,
        }
    }
}

/// Why a name is being (re)issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Missing,
    Unreadable,
    Expired,
    Renewal,
    /// The CA's ACME Renewal Information window (RFC 9773) has opened for this certificate,
    /// ahead of the percentage-of-lifetime rule.
    CaSuggested,
}

/// Whether, given what is held, `cert_name` needs an order now. Pure. This is the
/// percentage-of-lifetime rule only; [`due_with_window`] adds the CA's advice.
#[must_use]
pub fn due(policy: &RenewalPolicy, held: Option<&CertMaterial>, now: i64) -> Option<Reason> {
    let Some(material) = held else { return Some(Reason::Missing) };
    let Some(v) = cert_validity(&material.chain_pem) else { return Some(Reason::Unreadable) };
    if now >= v.not_after {
        return Some(Reason::Expired);
    }
    let renew_at = v.not_before + v.lifetime() * i64::from(policy.renew_after_percent.min(100)) / 100;
    (now >= renew_at).then_some(Reason::Renewal)
}

/// The instant within the CA's suggested window at which `name` renews: `start` plus a
/// deterministic, name-derived fraction of the window (SHA-256, like the retry jitter), so a
/// fleet of certificates sharing a window spreads across it instead of renewing in one burst
/// (RFC 9773 §4.2 asks clients to pick randomly), reproducibly across restarts and in logs.
/// Always within `start..=end`; a degenerate window yields `start`.
#[must_use]
pub fn ari_renew_at(name: &str, window: &RenewalWindow) -> i64 {
    let d = sha256(format!("ari:{name}").as_bytes());
    let frac = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
    let span = u128::try_from(window.end.saturating_sub(window.start)).unwrap_or(0);
    let offset = i64::try_from((span * u128::from(frac)) >> 64).unwrap_or(0);
    window.start.saturating_add(offset)
}

/// [`due`] plus the CA's renewal advice. A held, otherwise healthy certificate is
/// [`Reason::CaSuggested`] once `now` reaches [`ari_renew_at`] inside `window` (an `end` already
/// past makes that immediate); anything else is [`due`]'s answer. A `window` of `None` — no ARI,
/// or a failed lookup — changes nothing, and a window still in the future never causes an order:
/// ARI can only advance a renewal, never delay one the percentage rule already wants.
///
/// A window that starts before the held certificate's `notBefore` is advice about some other
/// certificate (or a broken CA) and is ignored. Without that, a CA answering every lookup with
/// the same long-past window would have each replacement re-ordered on the next pass, burning
/// its rate limit. Pure.
#[must_use]
pub fn due_with_window(policy: &RenewalPolicy, name: &str, held: Option<&CertMaterial>, now: i64, window: Option<&RenewalWindow>) -> Option<Reason> {
    if let Some(reason) = due(policy, held, now) {
        return Some(reason);
    }
    let (v, w) = (cert_validity(&held?.chain_pem)?, window?);
    (w.start >= v.not_before && now >= ari_renew_at(name, w)).then_some(Reason::CaSuggested)
}

// ── The engine ────────────────────────────────────────────────────────────────────────────

/// How far ahead of `now` a certificate's `notBefore` may be and still be installed (CAs
/// normally backdate; a few minutes of clock skew must not reject a fresh certificate).
const NOT_BEFORE_SKEW_SECS: i64 = 300;

/// How long to wait before asking the CA for renewal information again when it did not say
/// (RFC 9773 §4.2 suggests a few hours), and the most a `Retry-After` can defer the next ask.
const ARI_DEFAULT_POLL_SECS: u64 = 6 * 3600;
const ARI_MAX_POLL_SECS: u64 = 7 * 24 * 3600;

/// The last renewal advice fetched for a name's held certificate. In memory only: after a
/// restart the CA is asked once more.
#[derive(Clone, Debug)]
struct AriCache {
    /// SHA-256 of the chain it was fetched for; advice about a replaced certificate is dropped.
    cert: [u8; 32],
    /// `None` when the CA had no advice (or the lookup failed) — cached so a failing ARI endpoint
    /// is not hit on every pass.
    window: Option<RenewalWindow>,
    poll_after: i64,
}

#[derive(Clone, Debug, Default)]
struct NameState {
    failures: u32,
    next_attempt: i64,
    last_error: Option<String>,
    unrequired_since: Option<i64>,
    ari: Option<AriCache>,
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    pub issued: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub backing_off: usize,
    pub activated: Vec<String>,
    pub gave_up: Vec<String>,
    pub pruned: Vec<String>,
    /// Certificates the CA revoked this pass (see [`RevocationQueue`]).
    pub revoked: Vec<String>,
    /// Revocations that failed this pass and will be retried.
    pub revocation_failed: Vec<(String, String)>,
}

/// Per-name operational status, for the portal and metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertStatus {
    pub name: String,
    pub not_after: Option<i64>,
    pub seconds_left: Option<i64>,
    pub consecutive_failures: u32,
    pub next_attempt: i64,
    pub last_error: Option<String>,
}

pub struct RenewalEngine<S: CertStore, I: CertIssuer> {
    store: Arc<S>,
    issuer: I,
    policy: RenewalPolicy,
    baseline: Vec<String>,
    state: Table<String, NameState>,
    revocations: Option<Arc<RevocationQueue>>,
    revocation_policy: RevocationPolicy,
}

/// Every apex wildcard — issue these at boot so a first claim never waits on a CA.
#[must_use]
pub fn apex_wildcards() -> Vec<String> {
    APEXES.iter().map(|a| a.wildcard()).collect()
}

impl<S: CertStore, I: CertIssuer> RenewalEngine<S, I> {
    #[must_use]
    pub fn new(store: Arc<S>, issuer: I, policy: RenewalPolicy) -> Self {
        RenewalEngine { store, issuer, policy, baseline: Vec::new(), state: Table::new(), revocations: None, revocation_policy: RevocationPolicy::default() }
    }

    /// Names to hold regardless of what the registry currently needs (see [`apex_wildcards`]).
    #[must_use]
    pub fn with_baseline(mut self, names: Vec<String>) -> Self {
        self.baseline = names;
        self
    }

    /// Revoke through `queue`: a pruned dedicated certificate is queued instead of just deleted,
    /// and every pass retries what is due. Without it the engine neither revokes nor needs to.
    /// Share the queue with whatever releases names (`retire_for_revocation`) and, to revoke
    /// within moments rather than at the next pass, with a worker running [`process_revocations`].
    #[must_use]
    pub fn with_revocations(mut self, queue: Arc<RevocationQueue>) -> Self {
        self.revocations = Some(queue);
        self
    }

    /// The name's state: in memory if we have seen it this process, else what a previous process
    /// persisted (retry deadlines survive a restart), else fresh.
    fn st(&self, name: &str) -> NameState {
        if let Some(s) = self.state.get(&name.to_string()) {
            return s.clone();
        }
        self.store
            .load_retry(name)
            .map(|r| NameState { failures: r.failures, next_attempt: r.next_attempt, last_error: r.last_error, ..NameState::default() })
            .unwrap_or_default()
    }

    /// Delay before the next attempt after `failures` consecutive failures. Exponential, capped,
    /// with ±10% jitter derived from the name so a fleet of failing names does not retry in
    /// lockstep — deterministic rather than random so it is testable and reproducible in logs.
    fn backoff_secs(&self, name: &str, failures: u32, retry_after: Option<u64>) -> u64 {
        let exp = failures.saturating_sub(1).min(20);
        let base = self.policy.retry_base_secs.saturating_mul(1u64 << exp).min(self.policy.retry_max_secs);
        let d = sha256(format!("{name}:{failures}").as_bytes());
        let per_mille = i128::from(u16::from_be_bytes([d[0], d[1]]) % 201) - 100; // -100..=100
        // i128 so a very large configured `retry_max_secs` cannot overflow the multiplication.
        let base_i = i128::from(base);
        let jittered = u64::try_from(base_i + base_i * per_mille / 1000).unwrap_or(base);
        jittered.max(retry_after.unwrap_or(0).min(7 * 24 * 3600))
    }

    /// The CA's renewal window for `name`'s held `material`, from the cache in `s` or — at most
    /// once per [`RenewalWindow::retry_after_secs`] (default 6 h) — from the issuer. No I/O while
    /// the name is backing off: no order could be placed anyway.
    async fn ca_window(&self, material: &CertMaterial, s: &mut NameState, now: i64) -> Option<RenewalWindow> {
        if s.next_attempt > now {
            return None;
        }
        let cert = sha256(material.chain_pem.as_bytes());
        if !s.ari.as_ref().is_some_and(|c| c.cert == cert && now < c.poll_after) {
            let window = self.issuer.renewal_window(material).await;
            let wait = window.as_ref().and_then(|w| w.retry_after_secs).unwrap_or(ARI_DEFAULT_POLL_SECS).min(ARI_MAX_POLL_SECS);
            s.ari = Some(AriCache { cert, window, poll_after: now.saturating_add(i64::try_from(wait).unwrap_or(i64::MAX / 4)) });
        }
        s.ari.as_ref().and_then(|c| c.window.clone())
    }

    /// One pass: decide what is due, order it, install it, and tell the registry.
    pub async fn run_once(&mut self, now: i64, registry: &tokio::sync::Mutex<EdgeRegistry>) -> RunReport {
        let mut report = RunReport::default();

        // 1. The work list. Short lock, no I/O.
        let mut required = registry.lock().await.required_cert_names();
        for b in &self.baseline {
            if !required.contains(b) {
                required.push(b.clone());
            }
        }
        required.sort();

        // 2. What is due, most urgent first (nothing held, then soonest expiry).
        let mut work: Vec<(i64, String, Reason)> = Vec::new();
        for name in &required {
            let held = self.store.cert_for(name);
            let mut s = self.st(name);
            s.unrequired_since = None;
            // The percentage rule decides first and costs nothing; only a held certificate it
            // calls healthy is worth asking the CA about.
            let mut reason = due(&self.policy, held.as_ref(), now);
            if let (None, Some(material)) = (reason, &held) {
                let window = self.ca_window(material, &mut s, now).await;
                reason = due_with_window(&self.policy, name, held.as_ref(), now, window.as_ref());
            }
            self.state.put(name.clone(), s.clone());
            match reason {
                None => {
                    // Held and healthy: make sure waiting hostnames (e.g. registry rebuilt
                    // after a restart) are activated.
                    report.activated.extend(registry.lock().await.activate_cert(name));
                }
                Some(reason) => {
                    if s.next_attempt > now {
                        report.backing_off += 1;
                        continue; // while backing off we change nothing, including activation
                    }
                    let urgency = held
                        .as_ref()
                        .and_then(|m| cert_validity(&m.chain_pem))
                        .map_or(i64::MIN, |v| v.not_after);
                    work.push((urgency, name.clone(), reason));
                }
            }
        }
        work.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));

        // 3. Order them. No registry lock is held across the CA round trip.
        for (_, name, reason) in work.into_iter().take(self.policy.max_per_run) {
            // A renewal names the certificate it replaces (RFC 9773) so the CA can treat it as one;
            // a first issuance, or a replacement of something already expired or unreadable, has
            // nothing to name.
            let previous = match reason {
                Reason::Renewal | Reason::CaSuggested => self.store.cert_for(&name),
                Reason::Missing | Reason::Unreadable | Reason::Expired => None,
            };
            let ordered = match &previous {
                Some(prev) => self.issuer.issue_replacing(&name, prev).await,
                None => self.issuer.issue(&name).await,
            };
            let outcome: Result<(), (String, Option<u64>)> = match ordered {
                Ok(material) => match validate(&material) {
                    // Never replace a held certificate with something the CA mangled or that
                    // is already dead: a bad order must leave last-known-good untouched.
                    Ok(v) if v.not_after > now && v.not_before <= now.saturating_add(NOT_BEFORE_SKEW_SECS) => {
                        self.store.put(&name, material).map_err(|e| (e, None))
                    }
                    Ok(v) if v.not_before > now => Err(("CA returned a certificate that is not yet valid".to_string(), None)),
                    Ok(_) => Err(("CA returned an already-expired certificate".to_string(), None)),
                    Err(e) => Err((format!("CA returned unusable material: {e}"), None)),
                },
                Err(e) => Err((e.to_string(), e.retry_after_secs())),
            };
            match outcome {
                Ok(()) => {
                    self.state.put(name.clone(), NameState::default());
                    self.store.save_retry(&name, None);
                    report.issued.push(name.clone());
                    let activated = registry.lock().await.activate_cert(&name);
                    tracing::info!(cert = %name, ?reason, activated = activated.len(), "certificate installed");
                    report.activated.extend(activated);
                }
                Err((detail, retry_after)) => {
                    self.record_failure(&name, detail, retry_after, now, registry, &mut report).await;
                }
            }
        }

        // 4. Prune certificates nothing requires any more, after a grace period.
        let held: Vec<String> = self.store.names();
        for name in held {
            if required.contains(&name) {
                continue;
            }
            let mut s = self.st(&name);
            let since = *s.unrequired_since.get_or_insert(now);
            if now - since >= self.policy.prune_after_secs {
                // A dedicated certificate is revoked, not just deleted: its key is a live
                // credential for a name that is no longer ours until the certificate expires. The
                // queue entry is durable before the certificate leaves the store; if it cannot be
                // written the certificate stays and the next pass tries again. A shared wildcard
                // is only removed (see `Retired::SharedWildcard`).
                match &self.revocations {
                    Some(queue) => match retire_for_revocation(self.store.as_ref(), queue, &name, now) {
                        Ok(Retired::SharedWildcard) => {
                            self.store.remove(&name);
                            self.store.save_retry(&name, None);
                        }
                        Ok(Retired::Queued | Retired::NotHeld) => {}
                        Err(e) => {
                            tracing::error!(cert = %name, error = %e, "could not queue the certificate for revocation; keeping it");
                            self.state.put(name, s);
                            continue;
                        }
                    },
                    None => {
                        self.store.remove(&name);
                        self.store.save_retry(&name, None);
                    }
                }
                self.state.remove(&name);
                report.pruned.push(name);
            } else {
                self.state.put(name, s);
            }
        }

        // 5. Revocations that are due (the engine's pass is the backstop; a dedicated worker
        //    makes them prompt).
        if let Some(queue) = &self.revocations {
            let done = process_revocations(queue, &self.issuer, now, &self.revocation_policy).await;
            report.revoked = done.revoked;
            report.revocation_failed = done.failed;
        }
        report
    }

    async fn record_failure(
        &mut self,
        name: &str,
        detail: String,
        retry_after: Option<u64>,
        now: i64,
        registry: &tokio::sync::Mutex<EdgeRegistry>,
        report: &mut RunReport,
    ) {
        let mut s = self.st(name);
        s.failures += 1;
        s.last_error = Some(detail.clone());
        s.next_attempt = now.saturating_add(i64::try_from(self.backoff_secs(name, s.failures, retry_after)).unwrap_or(i64::MAX / 4));
        let never_had_one = self.store.cert_for(name).is_none();
        let is_baseline = self.baseline.iter().any(|b| b == name);
        let give_up = never_had_one && !is_baseline && s.failures >= self.policy.give_up_after;
        tracing::warn!(cert = %name, failures = s.failures, error = %detail, "certificate issuance failed");
        self.store.save_retry(name, Some(&RetryState { failures: s.failures, next_attempt: s.next_attempt, last_error: s.last_error.clone() }));
        self.state.put(name.to_string(), s);
        report.failed.push((name.to_string(), detail.clone()));
        if give_up {
            let failed = registry.lock().await.cert_failed(name, &detail);
            if !failed.is_empty() {
                report.gave_up.extend(failed);
            }
        }
    }

    /// Status of every name currently required or held, for the portal / metrics.
    pub async fn status(&self, now: i64, registry: &tokio::sync::Mutex<EdgeRegistry>) -> Vec<CertStatus> {
        let mut names = registry.lock().await.required_cert_names();
        names.extend(self.baseline.iter().cloned());
        names.extend(self.store.names());
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(|name| {
                let s = self.st(&name);
                let v = self.store.cert_for(&name).and_then(|m| cert_validity(&m.chain_pem));
                CertStatus {
                    not_after: v.map(|v| v.not_after),
                    seconds_left: v.map(|v| v.not_after - now),
                    consecutive_failures: s.failures,
                    next_attempt: s.next_attempt,
                    last_error: s.last_error,
                    name,
                }
            })
            .collect()
    }

    /// Run [`Self::run_once`] every `interval` until the future is dropped. Spawn this once at
    /// boot; it never touches the request path.
    pub async fn run_forever(self, registry: Arc<tokio::sync::Mutex<EdgeRegistry>>, interval: std::time::Duration) {
        self.run_forever_with(registry, interval, |_, _| {}).await;
    }

    /// As [`Self::run_forever`], handing each pass's report and the per-name status to
    /// `on_pass` — how a host publishes `/certs`-style status without owning the engine.
    pub async fn run_forever_with(
        mut self,
        registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
        interval: std::time::Duration,
        mut on_pass: impl FnMut(&RunReport, Vec<CertStatus>) + Send,
    ) {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let report = self.run_once(now, &registry).await;
            if !report.issued.is_empty() || !report.failed.is_empty() || !report.pruned.is_empty() {
                tracing::info!(?report, "renewal pass");
            }
            let status = self.status(now, &registry).await;
            on_pass(&report, status);
            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::{generate_cert_key, p256_key_to_pkcs8_pem, pem_wrap};
    use crate::edge::{HostnameState, Route};
    use std::sync::Mutex;

    const T0: i64 = 1_800_000_000; // 2027-01-15
    const DAY: i64 = 86_400;

    // A real self-signed EC certificate (the same OpenSSL-generated fixture edge-lb's tests embed).
    const REAL_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBvzCCAWWgAwIBAgIUDNjqZLCC8q5tnWpTuhHxnyy2ubwwCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcwNjA5NTkyNloYDzIxMjYwNjEy\n\
MDk1OTI2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAAQWzzNgEHmWExfSibB4yxRBk1XskVgjCno/DO/69cKbImX6Mesim9v5\n\
6PmqJXWVtsTxPgyjXGc9t7qFcshNGmdro4GSMIGPMB0GA1UdDgQWBBR+o7nTOCVp\n\
5N9mVXOepMnBc2oSFjAfBgNVHSMEGDAWgBR+o7nTOCVp5N9mVXOepMnBc2oSFjAa\n\
BgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8B\n\
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIh\n\
AIpKWXNFn17ZEEBKN1cs3MZYH3hEJugX5iw7AOut4zPJAiAhTcY+TtqBBinAMs6Y\n\
PfFwXFUdKr72euUqW9E4wdcMVA==\n\
-----END CERTIFICATE-----\n";

    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(m <= 2), m, d)
    }

    fn asn1_time(ts: i64) -> Vec<u8> {
        let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
        let rem = ts.rem_euclid(86_400);
        let (hh, mm, ss) = (rem / 3600, rem % 3600 / 60, rem % 60);
        if (1950..2050).contains(&y) {
            der::tlv(0x17, format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100).as_bytes())
        } else {
            der::tlv(0x18, format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z").as_bytes())
        }
    }

    /// A structurally valid (unsigned) X.509 certificate with the given validity window.
    fn fake_chain(not_before: i64, not_after: i64) -> String {
        let alg = der::seq(&[der::tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
        let tbs = der::seq(&[
            der::tlv(0xA0, &der::uint(&[2])),
            der::uint(&[1, 2, 3]),
            alg.clone(),
            der::seq(&[]),
            der::seq(&[asn1_time(not_before), asn1_time(not_after)]),
            der::seq(&[]),
            der::seq(&[]),
        ]);
        pem_wrap("CERTIFICATE", &der::seq(&[tbs, alg, der::bit_string(&[0])]))
    }

    fn material(not_before: i64, not_after: i64) -> CertMaterial {
        CertMaterial { chain_pem: fake_chain(not_before, not_after), key_pem: p256_key_to_pkcs8_pem(&generate_cert_key()) }
    }

    type IssueFn = Box<dyn Fn(&str, usize) -> Result<CertMaterial, AcmeError> + Send + Sync>;

    struct FnIssuer {
        f: IssueFn,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl CertIssuer for FnIssuer {
        fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            Box::pin(async move {
                let n = {
                    let mut calls = self.calls.lock().unwrap();
                    calls.push(cert_name.to_string());
                    calls.len()
                };
                (self.f)(cert_name, n)
            })
        }
    }

    fn issuer(f: impl Fn(&str, usize) -> Result<CertMaterial, AcmeError> + Send + Sync + 'static) -> (FnIssuer, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (FnIssuer { f: Box::new(f), calls: calls.clone() }, calls)
    }

    fn route(tenant: &str, tunnel: &str) -> Route {
        Route { tenant_id: tenant.into(), tunnel_id: tunnel.into(), peer: crate::dialkey::peer_id(tunnel), origin_port: 8080 }
    }

    /// Registry with one live managed hostname and one validated custom hostname awaiting a cert.
    fn registry() -> Arc<tokio::sync::Mutex<EdgeRegistry>> {
        let apex = APEXES.iter().find(|a| a.zone == "tascloud.app").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        reg.claim_managed_label(apex, "mine", route("acme", "t0")).unwrap();
        reg.add_custom("app.acme.com.au", "mine.tascloud.app", route("acme", "t1")).unwrap();
        reg.record_probe("app.acme.com.au", true, 5).unwrap();
        Arc::new(tokio::sync::Mutex::new(reg))
    }

    fn ninety_days(now: i64) -> CertMaterial {
        material(now, now + 90 * DAY)
    }

    fn engine<I: CertIssuer>(store: Arc<MemoryCertSource>, issuer: I) -> RenewalEngine<MemoryCertSource, I> {
        RenewalEngine::new(store, issuer, RenewalPolicy::default())
    }

    async fn state_of(reg: &tokio::sync::Mutex<EdgeRegistry>, fqdn: &str) -> HostnameState {
        reg.lock().await.lookup(fqdn).unwrap().state.clone()
    }

    // ── validity reader ───────────────────────────────────────────────────────────────────

    #[test]
    fn validity_is_read_from_a_real_openssl_certificate() {
        let v = cert_validity(REAL_CERT).expect("parses");
        assert_eq!(v.not_before, 1_783_331_966, "2026-07-06T09:59:26Z (UTCTime)");
        assert_eq!(v.not_after, 4_936_931_966, "2126-06-12T09:59:26Z (GeneralizedTime, year >= 2050)");
    }

    #[test]
    fn validity_round_trips_both_time_encodings_and_rejects_garbage() {
        for (nb, na) in [(T0, T0 + 90 * DAY), (T0, 2_600_000_000), (946_684_800, 951_782_400)] {
            assert_eq!(cert_validity(&fake_chain(nb, na)), Some(Validity { not_before: nb, not_after: na }), "{nb}..{na}");
        }
        assert!(cert_validity("").is_none());
        assert!(cert_validity("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_none());
        assert!(cert_validity(&fake_chain(T0 + 10, T0)).is_none(), "notAfter before notBefore is not a window");
    }

    // ── the planner ───────────────────────────────────────────────────────────────────────

    #[test]
    fn renewal_is_a_fraction_of_the_certificate_own_lifetime() {
        let p = RenewalPolicy::default();
        let long = material(T0, T0 + 90 * DAY);
        assert_eq!(due(&p, None, T0), Some(Reason::Missing));
        assert_eq!(due(&p, Some(&long), T0 + 58 * DAY), None);
        assert_eq!(due(&p, Some(&long), T0 + 60 * DAY), Some(Reason::Renewal));
        assert_eq!(due(&p, Some(&long), T0 + 91 * DAY), Some(Reason::Expired));
        // A 6-day certificate must not be treated like a 90-day one.
        let short = material(T0, T0 + 6 * DAY);
        assert_eq!(due(&p, Some(&short), T0 + 3 * DAY), None);
        assert_eq!(due(&p, Some(&short), T0 + 4 * DAY + 100), Some(Reason::Renewal));
        let junk = CertMaterial { chain_pem: "x".into(), key_pem: "y".into() };
        assert_eq!(due(&p, Some(&junk), T0), Some(Reason::Unreadable));
    }

    #[test]
    fn baseline_covers_every_apex() {
        let names = apex_wildcards();
        assert_eq!(names.len(), APEXES.len());
        assert!(names.contains(&"*.tascloud.app".to_string()));
    }

    // ── the engine ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn first_pass_issues_the_baseline_and_activates_waiting_hostnames_then_goes_quiet() {
        let reg = registry();
        let (iss, calls) = issuer(|_, _| Ok(ninety_days(T0)));
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss).with_baseline(apex_wildcards());

        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::PendingCert);
        let r = eng.run_once(T0, &reg).await;

        let mut issued = r.issued.clone();
        issued.sort();
        let mut expected: Vec<String> = apex_wildcards();
        expected.push("app.acme.com.au".to_string());
        expected.sort();
        assert_eq!(issued, expected, "every apex wildcard plus the validated custom name");
        assert_eq!(r.activated, vec!["app.acme.com.au".to_string()]);
        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::Active);
        assert!(store.cert_for("app.acme.com.au").is_some());

        let again = eng.run_once(T0 + DAY, &reg).await;
        assert!(again.issued.is_empty() && again.failed.is_empty(), "{again:?}");
        assert_eq!(calls.lock().unwrap().len(), APEXES.len() + 1, "nothing re-ordered when nothing is due");
    }

    #[tokio::test]
    async fn a_certificate_is_renewed_once_at_two_thirds_of_its_life() {
        let reg = registry();
        let now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(T0));
        let n = now.clone();
        let (iss, calls) = issuer(move |_, _| Ok(ninety_days(n.load(std::sync::atomic::Ordering::SeqCst))));
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let before = calls.lock().unwrap().len();

        now.store(T0 + 60 * DAY, std::sync::atomic::Ordering::SeqCst);
        let r = eng.run_once(T0 + 60 * DAY, &reg).await;
        assert_eq!(r.issued.len(), 2, "the wildcard behind the live managed host AND the custom name");
        assert_eq!(calls.lock().unwrap().len(), before + 2);
        let v = cert_validity(&store.cert_for("app.acme.com.au").unwrap().chain_pem).unwrap();
        assert_eq!(v.not_before, T0 + 60 * DAY, "the renewed certificate replaced the old one");
        // And not again the next hour.
        assert!(eng.run_once(T0 + 60 * DAY + 3600, &reg).await.issued.is_empty());
    }

    #[tokio::test]
    async fn a_failed_renewal_keeps_the_last_known_good_cert_and_backs_off() {
        let reg = registry();
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fail.clone();
        let (iss, calls) = issuer(move |_, _| {
            if f.load(std::sync::atomic::Ordering::SeqCst) {
                Err(AcmeError::Rejected { status: 500, detail: "boom".into() })
            } else {
                Ok(ninety_days(T0))
            }
        });
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let held = store.cert_for("app.acme.com.au").unwrap().chain_pem;

        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let t = T0 + 61 * DAY;
        let r = eng.run_once(t, &reg).await;
        assert_eq!(r.failed.len(), 2);
        assert_eq!(store.cert_for("app.acme.com.au").unwrap().chain_pem, held, "last-known-good untouched");
        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::Active, "a failed RENEWAL is not a failed hostname");

        let n_calls = calls.lock().unwrap().len();
        let r = eng.run_once(t + 60, &reg).await; // inside the backoff window
        assert_eq!((r.failed.len(), r.backing_off), (0, 2));
        assert_eq!(calls.lock().unwrap().len(), n_calls, "no hammering while backing off");

        let r = eng.run_once(t + 2 * 3600, &reg).await; // past the first delay
        assert_eq!(r.failed.len(), 2, "retried after the delay");
        let status = eng.status(t + 2 * 3600, &reg).await;
        let s = status.iter().find(|s| s.name == "app.acme.com.au").unwrap();
        assert_eq!(s.consecutive_failures, 2);
        assert!(s.last_error.as_deref().unwrap().contains("boom"));
        assert!(s.seconds_left.unwrap() > 0);
    }

    #[tokio::test]
    async fn backoff_grows_is_capped_and_honours_the_cas_retry_after() {
        let (iss, _) = issuer(|_, _| Ok(ninety_days(T0)));
        let eng = engine(Arc::new(MemoryCertSource::new()), iss);
        let d: Vec<u64> = (1..=8).map(|n| eng.backoff_secs("x", n, None)).collect();
        assert!(d[0] >= 540 && d[0] <= 660, "~10min +-10%: {}", d[0]);
        assert!(d.windows(2).take(5).all(|w| w[1] > w[0]), "grows: {d:?}");
        assert!(d[7] <= 24 * 3600 * 11 / 10, "capped near 24h: {}", d[7]);
        assert!(eng.backoff_secs("x", 1, Some(5 * 3600)) >= 5 * 3600, "Retry-After wins over a short backoff");
        assert!(eng.backoff_secs("x", 1, Some(90 * DAY as u64)) <= 7 * 24 * 3600, "a silly Retry-After is capped");
        assert_ne!(eng.backoff_secs("a", 3, None), eng.backoff_secs("b", 3, None), "per-name jitter de-synchronises retries");
    }

    #[tokio::test]
    async fn an_absurdly_large_retry_cap_does_not_overflow_the_jitter() {
        let (iss, _) = issuer(|_, _| Ok(ninety_days(T0)));
        let eng = RenewalEngine::new(
            Arc::new(MemoryCertSource::new()),
            iss,
            RenewalPolicy { retry_max_secs: u64::MAX, retry_base_secs: u64::MAX / 2, ..RenewalPolicy::default() },
        );
        for failures in [1, 2, 30, u32::MAX] {
            let _ = eng.backoff_secs("x", failures, None); // must not panic in debug builds
        }
    }

    #[tokio::test]
    async fn rate_limit_retry_after_is_stored_through_the_engine() {
        let reg = registry();
        let (iss, _) = issuer(|_, _| Err(AcmeError::RateLimited { retry_after_secs: Some(6 * 3600), detail: "too many".into() }));
        let mut eng = engine(Arc::new(MemoryCertSource::new()), iss);
        eng.run_once(T0, &reg).await;
        let s = eng.status(T0, &reg).await.into_iter().find(|s| s.name == "app.acme.com.au").unwrap();
        assert!(s.next_attempt >= T0 + 6 * 3600, "{s:?}");
    }

    #[tokio::test]
    async fn a_hostname_that_never_gets_a_certificate_is_failed_but_a_baseline_wildcard_never_is() {
        let reg = registry();
        let (iss, _) = issuer(|_, _| Err(AcmeError::AuthorizationFailed("authz (CAA forbids)".into())));
        let mut eng = RenewalEngine::new(Arc::new(MemoryCertSource::new()), iss, RenewalPolicy { give_up_after: 3, ..RenewalPolicy::default() })
            .with_baseline(vec!["*.tascloud.app".into()]);
        let mut t = T0;
        let mut gave_up = Vec::new();
        for _ in 0..4 {
            gave_up.extend(eng.run_once(t, &reg).await.gave_up);
            t += 2 * DAY; // always past any backoff
        }
        assert_eq!(gave_up, vec!["app.acme.com.au".to_string()]);
        match state_of(&reg, "app.acme.com.au").await {
            HostnameState::Failed(why) => assert!(why.contains("CAA forbids"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(state_of(&reg, "mine.tascloud.app").await, HostnameState::Active, "the wildcard failing does not fail live hostnames");
        // The failed name left the work list, so it stops costing CA requests.
        assert!(!reg.lock().await.required_cert_names().contains(&"app.acme.com.au".to_string()));
    }

    #[tokio::test]
    async fn unusable_material_from_the_ca_is_rejected_and_never_replaces_a_good_cert() {
        let reg = registry();
        let bad = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let b = bad.clone();
        let (iss, _) = issuer(move |_, _| match b.load(std::sync::atomic::Ordering::SeqCst) {
            0 => Ok(ninety_days(T0)),
            1 => Ok(CertMaterial { chain_pem: "not a cert".into(), key_pem: "nope".into() }),
            _ => Ok(material(T0 - 100 * DAY, T0 - 10 * DAY)), // already expired
        });
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let good = store.cert_for("app.acme.com.au").unwrap().chain_pem;

        for mode in [1, 2] {
            bad.store(mode, std::sync::atomic::Ordering::SeqCst);
            let r = eng.run_once(T0 + (60 + 3 * u64::from(mode) as i64) * DAY, &reg).await;
            assert_eq!(r.failed.len(), 2, "mode {mode}: {r:?}");
            assert_eq!(store.cert_for("app.acme.com.au").unwrap().chain_pem, good);
        }
    }

    #[tokio::test]
    async fn a_suspended_hostname_is_not_reactivated_by_its_certificate() {
        let reg = registry();
        reg.lock().await.suspend("acme", "app.acme.com.au").unwrap();
        let (iss, _) = issuer(|_, _| Ok(ninety_days(T0)));
        let mut eng = engine(Arc::new(MemoryCertSource::new()), iss);
        let r = eng.run_once(T0, &reg).await;
        assert!(r.issued.contains(&"app.acme.com.au".to_string()), "still renewed while suspended");
        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::Suspended);
    }

    #[tokio::test]
    async fn at_most_max_per_run_orders_start_per_pass_and_the_rest_wait_for_the_next() {
        let reg = registry();
        let (iss, calls) = issuer(|_, _| Ok(ninety_days(T0)));
        let mut eng = RenewalEngine::new(Arc::new(MemoryCertSource::new()), iss, RenewalPolicy { max_per_run: 2, ..RenewalPolicy::default() })
            .with_baseline(apex_wildcards());
        let total = APEXES.len() + 1; // every wildcard + the custom name
        let mut seen = 0;
        while seen < total {
            let n = eng.run_once(T0 + 60 * seen as i64, &reg).await.issued.len();
            assert!(n >= 1 && n <= 2, "never more than max_per_run per pass: {n}");
            seen += n;
        }
        assert_eq!(seen, total);
        assert_eq!(eng.run_once(T0 + 10_000, &reg).await.issued.len(), 0);
        assert_eq!(calls.lock().unwrap().len(), total);
    }

    #[tokio::test]
    async fn certificates_nothing_requires_any_more_are_pruned_after_the_grace_period() {
        let reg = registry();
        let (iss, _) = issuer(|_, _| Ok(ninety_days(T0)));
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        reg.lock().await.release("acme", "app.acme.com.au").unwrap();

        assert!(eng.run_once(T0 + DAY, &reg).await.pruned.is_empty());
        assert!(store.cert_for("app.acme.com.au").is_some(), "kept during the grace period");
        let r = eng.run_once(T0 + 9 * DAY, &reg).await;
        assert_eq!(r.pruned, vec!["app.acme.com.au".to_string()]);
        assert!(store.cert_for("app.acme.com.au").is_none());
        assert!(store.cert_for("*.tascloud.app").is_some(), "still-required names are untouched");
    }

    // ── durable store ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_ca_retry_after_survives_an_engine_restart() {
        let dir = temp_dir("retry");
        let reg = registry();
        let store = Arc::new(FileCertStore::open(&dir).unwrap());
        let (iss, calls) = issuer(|_, _| Err(AcmeError::RateLimited { retry_after_secs: Some(3 * 3600), detail: "slow down".into() }));
        let mut eng = RenewalEngine::new(store.clone(), iss, RenewalPolicy::default());
        let first = eng.run_once(T0, &reg).await;
        assert_eq!(first.failed.len(), 2);
        let ordered = calls.lock().unwrap().len();

        // "Restart": a new process opens the same directory and builds a fresh engine.
        let store2 = Arc::new(FileCertStore::open(&dir).unwrap());
        let (iss2, calls2) = issuer(|_, _| Ok(ninety_days(T0)));
        let mut eng2 = RenewalEngine::new(store2.clone(), iss2, RenewalPolicy::default());
        let r = eng2.run_once(T0 + 600, &reg).await; // inside the CA's 3 h Retry-After
        assert_eq!((r.issued.len(), r.backing_off), (0, 2), "the persisted deadline holds across the restart");
        assert!(calls2.lock().unwrap().is_empty(), "no order placed while the CA said wait ({ordered} before)");
        let st = eng2.status(T0 + 600, &reg).await;
        assert_eq!(st.iter().find(|s| s.name == "app.acme.com.au").unwrap().consecutive_failures, 1);

        let r = eng2.run_once(T0 + 4 * 3600, &reg).await;
        assert_eq!(r.issued.len(), 2, "after the deadline it orders, and success clears the persisted state");
        assert!(store2.load_retry("app.acme.com.au").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_certificate_that_is_not_yet_valid_never_displaces_the_one_we_hold() {
        let reg = registry();
        let (iss, _) = issuer(|_, n| if n <= 2 { Ok(ninety_days(T0)) } else { Ok(material(T0 + 61 * DAY + 3600, T0 + 150 * DAY)) });
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let held = store.cert_for("app.acme.com.au").unwrap().chain_pem;
        let r = eng.run_once(T0 + 61 * DAY, &reg).await; // renewal due; CA hands back a future-dated cert
        assert_eq!(r.issued.len(), 0);
        assert!(r.failed.iter().all(|(_, why)| why.contains("not yet valid")), "{:?}", r.failed);
        assert_eq!(store.cert_for("app.acme.com.au").unwrap().chain_pem, held);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let id: String = hashtrinity::crypto::rand_bytes(6).iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("transport-certstore-{tag}-{id}"))
    }

    #[tokio::test]
    async fn a_restart_reloads_certificates_from_disk_and_does_not_reorder_them() {
        let dir = temp_dir("restart");
        let reg = registry();
        {
            let (iss, calls) = issuer(|_, _| Ok(ninety_days(T0)));
            let mut eng = RenewalEngine::new(Arc::new(FileCertStore::open(&dir).unwrap()), iss, RenewalPolicy::default())
                .with_baseline(apex_wildcards());
            eng.run_once(T0, &reg).await;
            assert_eq!(calls.lock().unwrap().len(), APEXES.len() + 1);
        }
        // "Reboot": brand-new store from the same directory, brand-new engine, fresh registry
        // whose hostname is waiting on a certificate again.
        let reg = registry();
        let (iss, calls) = issuer(|_, _| Ok(ninety_days(T0)));
        let store = Arc::new(FileCertStore::open(&dir).unwrap());
        assert_eq!(store.names().len(), APEXES.len() + 1);
        let mut eng = RenewalEngine::new(store, iss, RenewalPolicy::default()).with_baseline(apex_wildcards());
        let r = eng.run_once(T0 + DAY, &reg).await;
        assert!(calls.lock().unwrap().is_empty(), "no re-issue after a restart (duplicate-cert rate limit)");
        assert_eq!(r.activated, vec!["app.acme.com.au".to_string()], "waiting hostnames are activated from disk");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stored_keys_are_private_and_wildcard_names_map_to_safe_file_names() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let store = FileCertStore::open(&dir).unwrap();
        store.put("*.tascloud.app", ninety_days(T0)).unwrap();
        let file = dir.join("_wildcard.tascloud.app.pem");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(!dir.join("_wildcard.tascloud.app.pem.tmp").exists(), "no temp file left behind");
        assert_eq!(FileCertStore::open(&dir).unwrap().names(), vec!["*.tascloud.app".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_store_refuses_names_that_could_escape_its_directory_and_junk_material() {
        let dir = temp_dir("names");
        let store = FileCertStore::open(&dir).unwrap();
        for bad in ["../etc/passwd", "a/b", "..", "", "*.", "UPPER.example.com", "a..b", "-x.com", "*.*.x.com"] {
            assert!(store.put(bad, ninety_days(T0)).is_err(), "{bad:?}");
        }
        assert!(store.put("ok.example.com", CertMaterial { chain_pem: "x".into(), key_pem: "y".into() }).is_err());
        assert!(store.names().is_empty());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "nothing written for refused names");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_file_on_disk_is_skipped_not_fatal() {
        let dir = temp_dir("corrupt");
        {
            let store = FileCertStore::open(&dir).unwrap();
            store.put("good.example.com", ninety_days(T0)).unwrap();
        }
        std::fs::write(dir.join("bad.example.com.pem"), "garbage").unwrap();
        let store = FileCertStore::open(&dir).unwrap();
        assert_eq!(store.names(), vec!["good.example.com".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── CA-suggested renewal (ACME Renewal Information) ──────────────────────────────────

    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering::SeqCst};

    fn window(start: i64, end: i64, retry_after: Option<u64>) -> RenewalWindow {
        RenewalWindow { start, end, explanation_url: None, retry_after_secs: retry_after }
    }

    /// The CA's advice as the test controls it: what to answer, and how often it was asked.
    #[derive(Clone, Default)]
    struct Ari {
        answer: Arc<Mutex<Option<RenewalWindow>>>,
        polls: Arc<AtomicUsize>,
    }

    impl Ari {
        fn set(&self, w: Option<RenewalWindow>) {
            *self.answer.lock().unwrap() = w;
        }
        fn polls(&self) -> usize {
            self.polls.load(SeqCst)
        }
    }

    struct AriIssuer {
        inner: FnIssuer,
        ari: Ari,
    }

    impl CertIssuer for AriIssuer {
        fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            self.inner.issue(cert_name)
        }
        fn renewal_window<'a>(&'a self, _material: &'a CertMaterial) -> BoxFuture<'a, Option<RenewalWindow>> {
            Box::pin(async move {
                self.ari.polls.fetch_add(1, SeqCst);
                self.ari.answer.lock().unwrap().clone()
            })
        }
    }

    /// An issuer whose certificates are 90-day ones starting at the (settable) clock, a CA whose
    /// advice is `ari`, and the log of issue calls.
    fn ari_issuer(fail: Arc<std::sync::atomic::AtomicBool>) -> (AriIssuer, Ari, Arc<AtomicI64>, Arc<Mutex<Vec<String>>>) {
        let clock = Arc::new(AtomicI64::new(T0));
        let c = clock.clone();
        let (inner, calls) = issuer(move |_, _| {
            if fail.load(SeqCst) {
                Err(AcmeError::Rejected { status: 500, detail: "boom".into() })
            } else {
                Ok(ninety_days(c.load(SeqCst)))
            }
        });
        let ari = Ari::default();
        (AriIssuer { inner, ari: ari.clone() }, ari, clock, calls)
    }

    fn no_failure() -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    #[test]
    fn the_renewal_instant_is_a_deterministic_per_name_point_inside_the_window() {
        let w = window(1_000_000, 1_000_000 + 2 * DAY, None);
        let picks: Vec<i64> = (0..64).map(|i| ari_renew_at(&format!("host{i}.example.com"), &w)).collect();
        assert!(picks.iter().all(|p| (w.start..=w.end).contains(p)), "{picks:?}");
        assert_eq!(picks[5], ari_renew_at("host5.example.com", &w), "deterministic");
        let mut distinct = picks.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(distinct.len() >= 60, "names spread across the window rather than renewing together: {} distinct", distinct.len());
        assert!(distinct[0] < w.start + DAY / 2 && distinct[distinct.len() - 1] > w.end - DAY / 2, "and across all of it");
        // Degenerate and extreme windows neither panic nor leave the window.
        assert_eq!(ari_renew_at("x", &window(500, 500, None)), 500);
        assert_eq!(ari_renew_at("x", &window(500, 400, None)), 500);
        let huge = window(i64::MIN / 2, i64::MAX / 2, None);
        assert!((huge.start..=huge.end).contains(&ari_renew_at("x", &huge)));
        let at_max = window(i64::MAX - 5, i64::MAX, None);
        assert!((at_max.start..=at_max.end).contains(&ari_renew_at("x", &at_max)));
    }

    #[test]
    fn the_cas_advice_only_ever_advances_a_renewal() {
        let p = RenewalPolicy::default();
        let cert = material(T0, T0 + 90 * DAY);
        let w = window(T0 + 10 * DAY, T0 + 11 * DAY, None);
        let pick = ari_renew_at("n", &w);
        let at = |now: i64, win: Option<&RenewalWindow>, held: Option<&CertMaterial>| due_with_window(&p, "n", held, now, win);

        assert_eq!(at(T0 + 5 * DAY, None, Some(&cert)), None, "no advice: the percentage rule alone");
        assert_eq!(at(T0 + 5 * DAY, Some(&w), Some(&cert)), None, "a window that has not opened is not a reason");
        assert_eq!(at(w.start - 1, Some(&w), Some(&cert)), None);
        assert_eq!(at(pick - 1, Some(&w), Some(&cert)), None, "inside the window but before this name's instant");
        assert_eq!(at(pick, Some(&w), Some(&cert)), Some(Reason::CaSuggested));
        assert_eq!(at(w.end + DAY, Some(&w), Some(&cert)), Some(Reason::CaSuggested), "a window already past means now");
        // Whatever the percentage rule says stays, and wins over the advice.
        assert_eq!(at(T0 + 61 * DAY, Some(&w), Some(&cert)), Some(Reason::Renewal));
        assert_eq!(at(T0 + 91 * DAY, Some(&w), Some(&cert)), Some(Reason::Expired));
        assert_eq!(at(T0, Some(&w), None), Some(Reason::Missing));
        let junk = CertMaterial { chain_pem: "x".into(), key_pem: "y".into() };
        assert_eq!(at(T0, Some(&w), Some(&junk)), Some(Reason::Unreadable));
        // Advice that predates the certificate is about some other certificate.
        let newer = material(T0 + 20 * DAY, T0 + 110 * DAY);
        assert_eq!(at(T0 + 25 * DAY, Some(&w), Some(&newer)), None);
    }

    #[tokio::test]
    async fn a_ca_suggested_window_renews_each_name_at_its_own_instant_and_not_before_it_opens() {
        let reg = registry();
        let (iss, ari, clock, calls) = ari_issuer(no_failure());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        assert_eq!((calls.lock().unwrap().len(), ari.polls()), (2, 0), "nothing held yet, so nothing to ask the CA about");

        let w = window(T0 + 10 * DAY, T0 + 11 * DAY, Some(3600));
        ari.set(Some(w.clone()));
        let r = eng.run_once(T0 + 5 * DAY, &reg).await;
        assert!(r.issued.is_empty() && r.failed.is_empty(), "far from the window nothing is ordered: {r:?}");
        assert_eq!(ari.polls(), 2, "one lookup per held name, in one pass");
        assert!(eng.run_once(T0 + 10 * DAY - 1, &reg).await.issued.is_empty(), "a second before the window opens");

        // Each name has its own instant inside the window.
        let (wild, custom) = (ari_renew_at("*.tascloud.app", &w), ari_renew_at("app.acme.com.au", &w));
        assert!(wild != custom && wild > w.start && custom > w.start, "{wild} {custom}");
        let (first, second, first_name, second_name) =
            if wild < custom { (wild, custom, "*.tascloud.app", "app.acme.com.au") } else { (custom, wild, "app.acme.com.au", "*.tascloud.app") };
        assert!(eng.run_once(first - 1, &reg).await.issued.is_empty());
        clock.store(first, SeqCst);
        assert_eq!(eng.run_once(first, &reg).await.issued, vec![first_name.to_string()], "only the name whose instant has come");
        clock.store(second, SeqCst);
        assert_eq!(eng.run_once(second, &reg).await.issued, vec![second_name.to_string()]);
        assert_eq!(calls.lock().unwrap().len(), 4);
        for name in [first_name, second_name] {
            let v = cert_validity(&store.cert_for(name).unwrap().chain_pem).unwrap();
            assert!(v.not_before >= first, "{name} was replaced, 10 days into a 90-day certificate");
        }

        // The CA keeps answering with the old, long-past window. It is not about the replacements
        // (it starts before they existed), so it must not trigger an order storm.
        for hours in 1..=6 {
            let t = second + hours * 3600 + 1;
            clock.store(t, SeqCst);
            let r = eng.run_once(t, &reg).await;
            assert!(r.issued.is_empty() && r.failed.is_empty(), "hour {hours}: {r:?}");
        }
        assert_eq!(calls.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn a_ca_suggested_renewal_installs_and_activates_like_any_other_renewal() {
        let reg = registry();
        let (iss, ari, clock, _calls) = ari_issuer(no_failure());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let before = store.cert_for("app.acme.com.au").unwrap().chain_pem;

        // Revocation-style advice: the window closed a while ago.
        ari.set(Some(window(T0 + DAY, T0 + DAY + 3600, None)));
        clock.store(T0 + 2 * DAY, SeqCst);
        let r = eng.run_once(T0 + 2 * DAY, &reg).await;
        assert_eq!(r.issued.len(), 2, "{r:?}");
        assert_ne!(store.cert_for("app.acme.com.au").unwrap().chain_pem, before);
        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::Active);
        assert!(due(&RenewalPolicy::default(), store.cert_for("app.acme.com.au").as_ref(), T0 + 2 * DAY).is_none(), "the percentage rule alone would not have renewed");
    }

    #[tokio::test]
    async fn without_usable_advice_the_percentage_rule_decides_and_the_ca_is_not_pestered() {
        let reg = registry();
        let (iss, ari, clock, calls) = ari_issuer(no_failure());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await; // ARI answers None throughout: no ARI, or a failed lookup

        for t in [T0 + DAY, T0 + DAY + 60, T0 + DAY + 3600, T0 + DAY + 5 * 3600] {
            assert!(eng.run_once(t, &reg).await.issued.is_empty());
        }
        assert_eq!(ari.polls(), 2, "an unanswered lookup is not repeated every pass: the default 6 h applies");
        assert!(eng.run_once(T0 + DAY + 7 * 3600, &reg).await.issued.is_empty());
        assert_eq!(ari.polls(), 4);
        assert!(eng.run_once(T0 + 30 * DAY, &reg).await.issued.is_empty(), "30 days into 90: no advice, no order");

        let polls = ari.polls();
        clock.store(T0 + 61 * DAY, SeqCst);
        assert_eq!(eng.run_once(T0 + 61 * DAY, &reg).await.issued.len(), 2, "the percentage rule still renews");
        assert_eq!(ari.polls(), polls, "a name already due by the percentage rule is not worth a lookup");
        assert_eq!(calls.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn the_ca_is_asked_at_most_once_per_retry_after_per_name() {
        let reg = registry();
        let (iss, ari, clock, calls) = ari_issuer(no_failure());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;

        ari.set(Some(window(T0 + 80 * DAY, T0 + 81 * DAY, Some(7200))));
        for t in [T0 + DAY, T0 + DAY + 60, T0 + DAY + 3599, T0 + DAY + 7199] {
            assert!(eng.run_once(t, &reg).await.issued.is_empty());
        }
        assert_eq!(ari.polls(), 2, "Retry-After: 7200 honoured: asked once per name");
        assert!(eng.run_once(T0 + DAY + 7200, &reg).await.issued.is_empty());
        assert_eq!(ari.polls(), 4, "and again once it has elapsed");

        // The CA changes its mind (an incident): the next permitted lookup picks it up.
        ari.set(Some(window(T0 + DAY, T0 + 2 * DAY, Some(7200))));
        clock.store(T0 + 3 * DAY, SeqCst);
        assert!(eng.run_once(T0 + DAY + 7200 + 60, &reg).await.issued.is_empty(), "cached advice is used until the lookup is due");
        assert_eq!(eng.run_once(T0 + 3 * DAY, &reg).await.issued.len(), 2);
        assert_eq!(calls.lock().unwrap().len(), 4);

        // A silly Retry-After cannot switch the lookups off for good.
        ari.set(Some(window(T0 + 80 * DAY, T0 + 81 * DAY, Some(u64::MAX))));
        let polls = ari.polls();
        eng.run_once(T0 + 4 * DAY, &reg).await;
        assert_eq!(ari.polls(), polls + 2);
        eng.run_once(T0 + 4 * DAY + 8 * 24 * 3600, &reg).await;
        assert_eq!(ari.polls(), polls + 4, "capped at 7 days");
    }

    #[tokio::test]
    async fn a_name_that_is_backing_off_is_not_looked_up_and_is_retried_on_the_backoff_schedule() {
        let reg = registry();
        let fail = no_failure();
        let (iss, ari, clock, calls) = ari_issuer(fail.clone());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        let held = store.cert_for("app.acme.com.au").unwrap().chain_pem;

        ari.set(Some(window(T0 + DAY, T0 + 2 * DAY, Some(60))));
        fail.store(true, SeqCst);
        let r = eng.run_once(T0 + 3 * DAY, &reg).await;
        assert_eq!(r.failed.len(), 2, "advised renewal attempted and failed: {r:?}");
        assert_eq!(state_of(&reg, "app.acme.com.au").await, HostnameState::Active, "a failed advised renewal keeps last-known-good");
        assert_eq!(store.cert_for("app.acme.com.au").unwrap().chain_pem, held);
        let (polls, orders) = (ari.polls(), calls.lock().unwrap().len());

        let r = eng.run_once(T0 + 3 * DAY + 120, &reg).await; // the CA's 60 s have passed, the backoff (~10 min) has not
        assert!(r.failed.is_empty() && r.issued.is_empty(), "{r:?}");
        assert_eq!((ari.polls(), calls.lock().unwrap().len()), (polls, orders), "backing off: no order and no lookup");

        fail.store(false, SeqCst);
        clock.store(T0 + 3 * DAY + 3 * 3600, SeqCst);
        assert_eq!(eng.run_once(T0 + 3 * DAY + 3 * 3600, &reg).await.issued.len(), 2, "retried once the backoff has passed");
    }

    #[tokio::test]
    async fn replacing_a_certificate_discards_the_advice_cached_for_the_old_one() {
        let reg = registry();
        let (iss, ari, _clock, _calls) = ari_issuer(no_failure());
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = engine(store.clone(), iss);
        eng.run_once(T0, &reg).await;
        ari.set(Some(window(T0 + 80 * DAY, T0 + 81 * DAY, Some(7 * 24 * 3600))));
        eng.run_once(T0 + DAY, &reg).await;
        eng.run_once(T0 + 2 * DAY, &reg).await;
        assert_eq!(ari.polls(), 2);

        store.install("app.acme.com.au", material(T0 + DAY, T0 + 91 * DAY)); // an operator drops in another certificate
        eng.run_once(T0 + 2 * DAY + 1, &reg).await;
        assert_eq!(ari.polls(), 3, "only the replaced name is asked again");
    }

    #[tokio::test]
    async fn an_issuer_without_renewal_information_gives_no_advice() {
        let (iss, _) = issuer(|_, _| Ok(ninety_days(T0)));
        assert!(iss.renewal_window(&ninety_days(T0)).await.is_none());
    }

    // ── `replaces` (RFC 9773) through the engine ─────────────────────────────────────────

    /// An issuer that records whether each order named a previous certificate, and what it
    /// was asked to revoke (answering from a script, then "revoked").
    #[derive(Default)]
    struct SpyIssuer {
        orders: Mutex<Vec<(String, Option<String>)>>,
        revoke_script: Mutex<std::collections::VecDeque<Result<(), AcmeError>>>,
        revoked: Mutex<Vec<String>>,
        clock: std::sync::atomic::AtomicI64,
    }

    impl SpyIssuer {
        fn at(now: i64) -> Arc<Self> {
            let s = SpyIssuer::default();
            s.clock.store(now, SeqCst);
            Arc::new(s)
        }
        /// A 90-day certificate whose bytes differ per name (real certificates have distinct serials).
        fn fresh(&self, cert_name: &str) -> CertMaterial {
            let nb = self.clock.load(SeqCst) + i64::try_from(cert_name.len()).unwrap();
            material(nb, nb + 90 * DAY)
        }
        fn script(&self, results: Vec<Result<(), AcmeError>>) {
            *self.revoke_script.lock().unwrap() = results.into();
        }
    }

    impl CertIssuer for SpyIssuer {
        fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            Box::pin(async move {
                self.orders.lock().unwrap().push((cert_name.to_string(), None));
                Ok(self.fresh(cert_name))
            })
        }
        fn issue_replacing<'a>(&'a self, cert_name: &'a str, previous: &'a CertMaterial) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            Box::pin(async move {
                self.orders.lock().unwrap().push((cert_name.to_string(), Some(previous.chain_pem.clone())));
                Ok(self.fresh(cert_name))
            })
        }
        fn revoke<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
            Box::pin(async move {
                let next = self.revoke_script.lock().unwrap().pop_front();
                let r = next.unwrap_or(Ok(()));
                if r.is_ok() {
                    self.revoked.lock().unwrap().push(material.chain_pem.clone());
                }
                r
            })
        }
    }

    #[tokio::test]
    async fn a_renewal_names_the_certificate_it_replaces_and_a_first_issuance_does_not() {
        let reg = registry();
        let spy = SpyIssuer::at(T0);
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = RenewalEngine::new(store.clone(), spy.clone(), RenewalPolicy::default());
        eng.run_once(T0, &reg).await;
        {
            let orders = spy.orders.lock().unwrap();
            assert_eq!(orders.len(), 2);
            assert!(orders.iter().all(|(_, prev)| prev.is_none()), "first issuance replaces nothing: {orders:?}");
        }
        let held = store.cert_for("app.acme.com.au").unwrap().chain_pem;
        spy.clock.store(T0 + 61 * DAY, SeqCst);
        eng.run_once(T0 + 61 * DAY, &reg).await;
        let orders = spy.orders.lock().unwrap().clone();
        assert_eq!(orders.len(), 4);
        let custom = orders[2..].iter().find(|(n, _)| n == "app.acme.com.au").unwrap();
        assert_eq!(custom.1.as_deref(), Some(held.as_str()), "the renewal names the chain it replaces");
        assert!(orders[2..].iter().all(|(_, prev)| prev.is_some()));
    }

    #[tokio::test]
    async fn an_expired_or_unreadable_certificate_is_not_named_as_replaced() {
        let reg = registry();
        let spy = SpyIssuer::at(T0);
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = RenewalEngine::new(store.clone(), spy.clone(), RenewalPolicy::default());
        eng.run_once(T0, &reg).await;
        spy.orders.lock().unwrap().clear();
        spy.clock.store(T0 + 100 * DAY, SeqCst);
        eng.run_once(T0 + 100 * DAY, &reg).await; // both expired
        let orders = spy.orders.lock().unwrap().clone();
        assert_eq!(orders.len(), 2);
        assert!(orders.iter().all(|(_, prev)| prev.is_none()), "{orders:?}");
    }

    #[tokio::test]
    async fn an_arc_wrapped_issuer_forwards_every_hook() {
        let spy = SpyIssuer::at(T0);
        let shared: Arc<dyn CertIssuer> = spy.clone();
        let m = ninety_days(T0);
        shared.issue("a.example").await.unwrap();
        shared.issue_replacing("a.example", &m).await.unwrap();
        shared.revoke(&m).await.unwrap();
        assert_eq!(spy.orders.lock().unwrap().len(), 2);
        assert_eq!(spy.revoked.lock().unwrap().len(), 1);
        // and the default hooks of an issuer that implements neither are harmless
        let (plain, calls) = issuer(|_, _| Ok(ninety_days(T0)));
        plain.issue_replacing("b.example", &m).await.unwrap();
        assert_eq!(calls.lock().unwrap().as_slice(), ["b.example"], "issue_replacing falls back to issue");
        plain.revoke(&m).await.expect("the default revoke is a successful no-op");
    }

    // ── revocation queue ─────────────────────────────────────────────────────────────────

    fn pending_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        v.sort();
        v
    }

    #[test]
    fn a_queued_revocation_is_durable_private_and_reloaded_with_its_key() {
        let dir = temp_dir("rq-durable");
        let q = RevocationQueue::open(&dir).unwrap();
        let m = ninety_days(T0);
        q.enqueue("app.acme.com.au", m.clone(), T0).unwrap();
        q.enqueue("app.acme.com.au", m.clone(), T0 + 5).unwrap(); // the same certificate again
        assert_eq!(q.len(), 1, "idempotent");
        let files = pending_files(&dir);
        assert_eq!(files.len(), 1, "one file, no temp file left: {files:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600, "the file holds a private key");
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let on_disk = std::fs::read_to_string(&files[0]).unwrap();
        assert!(on_disk.contains(&m.key_pem) && on_disk.contains("name=app.acme.com.au"));

        // A restart: the entry, its state and (checked via a later revoke) its key come back.
        let again = RevocationQueue::open(&dir).unwrap();
        let st = again.status();
        assert_eq!(st.len(), 1);
        assert_eq!((st[0].name.as_str(), st[0].enqueued_at, st[0].attempts), ("app.acme.com.au", T0, 0));
        assert_eq!(st[0].not_after, Some(T0 + 90 * DAY));
        assert_eq!(again.due(T0, 10)[0].material.key_pem, m.key_pem);
        assert!(!format!("{:?}", again.due(T0, 1)[0]).contains("PRIVATE"), "Debug redacts the key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_pending_file_is_left_alone_not_deleted_and_not_fatal() {
        let dir = temp_dir("rq-corrupt");
        {
            let q = RevocationQueue::open(&dir).unwrap();
            q.enqueue("good.example.com", ninety_days(T0), T0).unwrap();
        }
        std::fs::write(dir.join("broken.revoke"), "name=x\nnot a certificate").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let q = RevocationQueue::open(&dir).unwrap();
        assert_eq!(q.len(), 1);
        assert!(dir.join("broken.revoke").exists(), "it may hold the only copy of a key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn revocation_is_retried_with_backoff_keeps_the_key_and_ends_when_the_ca_revokes() {
        let dir = temp_dir("rq-retry");
        let q = RevocationQueue::open(&dir).unwrap();
        let m = ninety_days(T0);
        q.enqueue("app.acme.com.au", m.clone(), T0).unwrap();
        let spy = SpyIssuer::at(T0);
        spy.script(vec![
            Err(AcmeError::Rejected { status: 500, detail: "boom".into() }),
            Err(AcmeError::RateLimited { retry_after_secs: Some(1800), detail: "slow".into() }),
        ]);
        let policy = RevocationPolicy::default();

        let r = process_revocations(&q, spy.as_ref(), T0, &policy).await;
        assert_eq!((r.revoked.len(), r.failed.len(), r.pending), (0, 1, 1), "{r:?}");
        assert!(r.failed[0].1.contains("boom"));
        let st = &q.status()[0];
        assert_eq!((st.attempts, st.next_attempt), (1, T0 + 60), "first retry after the base delay");
        assert!(st.last_error.as_deref().unwrap().contains("boom"));
        assert_eq!(pending_files(&dir).len(), 1, "the key is still on disk");

        // Not due yet: no attempt (and the spy script is untouched).
        let r = process_revocations(&q, spy.as_ref(), T0 + 30, &policy).await;
        assert_eq!((r.revoked.len(), r.failed.len(), r.pending), (0, 0, 1));

        // Second failure: backoff doubles, but the CA's longer Retry-After wins.
        let r = process_revocations(&q, spy.as_ref(), T0 + 60, &policy).await;
        assert_eq!(r.failed.len(), 1);
        assert_eq!(q.status()[0].next_attempt, T0 + 60 + 1800, "Retry-After 1800 beats the 120 s backoff");
        // The retry state survives a restart.
        let reopened = RevocationQueue::open(&dir).unwrap();
        assert_eq!((reopened.status()[0].attempts, reopened.status()[0].next_attempt), (2, T0 + 60 + 1800));

        // Success: entry gone, file gone (shredded), CA saw the right chain.
        let r = process_revocations(&reopened, spy.as_ref(), T0 + 60 + 1800, &policy).await;
        assert_eq!((r.revoked.clone(), r.pending), (vec!["app.acme.com.au".to_string()], 0));
        assert_eq!(spy.revoked.lock().unwrap().as_slice(), std::slice::from_ref(&m.chain_pem));
        assert!(pending_files(&dir).is_empty(), "revoked: the key is destroyed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_retry_delay_is_capped_and_a_valid_certificate_is_never_given_up_on() {
        let q = RevocationQueue::in_memory();
        q.enqueue("x.example.com", ninety_days(T0), T0).unwrap();
        let spy = SpyIssuer::at(T0);
        spy.script((0..40).map(|_| Err(AcmeError::Rejected { status: 503, detail: "down".into() })).collect());
        let policy = RevocationPolicy { retry_base_secs: 60, retry_max_secs: 3600, max_per_pass: 10 };
        let mut now = T0;
        let mut delays = Vec::new();
        for _ in 0..30 {
            process_revocations(&q, spy.as_ref(), now, &policy).await;
            let next = q.status()[0].next_attempt;
            assert!(next > now && next - now <= 3600, "delay within (0, cap]: {}", next - now);
            delays.push(next - now);
            now = next;
        }
        assert_eq!(delays[..7], [60, 120, 240, 480, 960, 1920, 3600], "doubles per failure, then holds at the cap");
        assert!(delays[7..].iter().all(|d| *d == 3600));
        assert_eq!((q.len(), q.status()[0].attempts), (1, 30), "still queued after thirty failures");
    }

    #[tokio::test]
    async fn a_certificate_that_expires_before_it_is_revoked_is_dropped_without_calling_the_ca() {
        let dir = temp_dir("rq-expire");
        let q = RevocationQueue::open(&dir).unwrap();
        q.enqueue("old.example.com", material(T0, T0 + 10 * DAY), T0).unwrap();
        let spy = SpyIssuer::at(T0);
        let r = process_revocations(&q, spy.as_ref(), T0 + 11 * DAY, &RevocationPolicy::default()).await;
        assert_eq!((r.expired, r.revoked.len(), r.pending), (vec!["old.example.com".to_string()], 0, 0));
        assert!(spy.revoked.lock().unwrap().is_empty());
        assert!(pending_files(&dir).is_empty(), "nothing left to revoke, so the key goes too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retiring_stops_serving_only_after_the_revocation_is_durable_and_never_touches_a_wildcard() {
        let cdir = temp_dir("rq-retire-certs");
        let qdir = temp_dir("rq-retire-queue");
        let store = FileCertStore::open(&cdir).unwrap();
        let q = RevocationQueue::open(&qdir).unwrap();
        store.put("app.acme.com.au", ninety_days(T0)).unwrap();
        store.put("*.tascloud.app", ninety_days(T0)).unwrap();

        assert_eq!(retire_for_revocation(&store, &q, "*.tascloud.app", T0), Ok(Retired::SharedWildcard));
        assert!(store.cert_for("*.tascloud.app").is_some() && q.is_empty(), "the shared wildcard is untouched");
        assert_eq!(retire_for_revocation(&store, &q, "nothing.example.com", T0), Ok(Retired::NotHeld));

        assert_eq!(retire_for_revocation(&store, &q, "app.acme.com.au", T0), Ok(Retired::Queued));
        assert!(store.cert_for("app.acme.com.au").is_none(), "no longer served");
        assert!(!cdir.join("app.acme.com.au.pem").exists(), "nor on disk in the cert store");
        assert_eq!(q.len(), 1, "but its key lives on in the queue");

        // If the queue cannot be written, the certificate is NOT removed: the key is never dropped
        // before a revocation is on record.
        store.put("other.acme.com.au", material(T0 + 1, T0 + 91 * DAY)).unwrap();
        let _ = std::fs::remove_dir_all(&qdir); // the queue's directory vanishes underneath it
        let err = retire_for_revocation(&store, &q, "other.acme.com.au", T0).unwrap_err();
        assert!(err.contains("writing"), "{err}");
        assert!(store.cert_for("other.acme.com.au").is_some(), "still held");
        assert!(cdir.join("other.acme.com.au.pem").exists());
        assert_eq!(q.len(), 1, "and not recorded as queued");
        let _ = std::fs::remove_dir_all(&cdir);
    }

    #[tokio::test]
    async fn pruning_a_dedicated_certificate_revokes_it_but_a_wildcard_is_only_deleted() {
        let reg = registry();
        let spy = SpyIssuer::at(T0);
        let store = Arc::new(MemoryCertSource::new());
        let q = Arc::new(RevocationQueue::in_memory());
        let mut eng = RenewalEngine::new(store.clone(), spy.clone(), RenewalPolicy::default()).with_revocations(q.clone());
        eng.run_once(T0, &reg).await;
        let custom = store.cert_for("app.acme.com.au").unwrap();
        let wildcard = store.cert_for("*.tascloud.app").unwrap();
        // Release both the custom name and the last managed hostname: nothing requires either cert.
        reg.lock().await.release("acme", "app.acme.com.au").unwrap();
        reg.lock().await.release("acme", "mine.tascloud.app").unwrap();

        let r = eng.run_once(T0 + DAY, &reg).await;
        assert!(r.pruned.is_empty() && r.revoked.is_empty(), "grace period: {r:?}");
        let r = eng.run_once(T0 + 9 * DAY, &reg).await;
        let mut pruned = r.pruned.clone();
        pruned.sort();
        assert_eq!(pruned, vec!["*.tascloud.app".to_string(), "app.acme.com.au".to_string()]);
        assert_eq!(r.revoked, vec!["app.acme.com.au".to_string()], "the dedicated certificate was revoked in the same pass");
        assert_eq!(spy.revoked.lock().unwrap().as_slice(), std::slice::from_ref(&custom.chain_pem));
        assert!(!spy.revoked.lock().unwrap().contains(&wildcard.chain_pem), "the shared wildcard is never revoked");
        assert!(q.is_empty());
        assert!(store.cert_for("app.acme.com.au").is_none() && store.cert_for("*.tascloud.app").is_none());
    }

    #[tokio::test]
    async fn a_prune_that_cannot_queue_the_revocation_keeps_the_certificate_and_tries_again() {
        let dir = temp_dir("rq-prune-fail");
        let reg = registry();
        let spy = SpyIssuer::at(T0);
        let store = Arc::new(MemoryCertSource::new());
        let q = Arc::new(RevocationQueue::open(&dir).unwrap());
        let mut eng = RenewalEngine::new(store.clone(), spy.clone(), RenewalPolicy::default()).with_revocations(q.clone());
        eng.run_once(T0, &reg).await;
        reg.lock().await.release("acme", "app.acme.com.au").unwrap();
        eng.run_once(T0 + DAY, &reg).await;
        std::fs::remove_dir_all(&dir).unwrap();

        let r = eng.run_once(T0 + 9 * DAY, &reg).await;
        assert!(!r.pruned.contains(&"app.acme.com.au".to_string()), "not pruned while it cannot be recorded: {r:?}");
        assert!(store.cert_for("app.acme.com.au").is_some());
        std::fs::create_dir_all(&dir).unwrap();
        let r = eng.run_once(T0 + 9 * DAY + 3600, &reg).await;
        assert!(r.pruned.contains(&"app.acme.com.au".to_string()) && r.revoked == vec!["app.acme.com.au".to_string()], "{r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_engine_without_a_revocation_queue_prunes_exactly_as_before() {
        let reg = registry();
        let spy = SpyIssuer::at(T0);
        let store = Arc::new(MemoryCertSource::new());
        let mut eng = RenewalEngine::new(store.clone(), spy.clone(), RenewalPolicy::default());
        eng.run_once(T0, &reg).await;
        reg.lock().await.release("acme", "app.acme.com.au").unwrap();
        eng.run_once(T0 + DAY, &reg).await;
        let r = eng.run_once(T0 + 9 * DAY, &reg).await;
        assert_eq!(r.pruned, vec!["app.acme.com.au".to_string()]);
        assert!(r.revoked.is_empty() && spy.revoked.lock().unwrap().is_empty());
    }
}
