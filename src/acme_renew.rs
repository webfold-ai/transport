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
//!   immediately, forever.
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

use crate::acme::{der, AcmeClient, AcmeError, Dns01Responder, Http01Responder};
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

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
}

// ── Issuance ──────────────────────────────────────────────────────────────────────────────

/// Obtains a certificate for one certificate name. A trait so the engine is testable without a
/// CA; [`AcmeIssuer`] is the production implementation.
pub trait CertIssuer: Send + Sync {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>>;
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

impl CertIssuer for AcmeIssuer {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        Box::pin(async move {
            if cert_name.starts_with("*.") {
                self.client.issue_dns01(&[cert_name], self.dns01.as_ref()).await
            } else if let Some(http01) = &self.http01 {
                self.client.issue(&[cert_name], http01.as_ref()).await
            } else {
                // No way to prove control of a customer's name without an HTTP-01 listener.
                Err(AcmeError::ChallengeSetup)
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
}

/// Whether, given what is held, `cert_name` needs an order now. Pure.
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

// ── The engine ────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct NameState {
    failures: u32,
    next_attempt: i64,
    last_error: Option<String>,
    unrequired_since: Option<i64>,
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
}

/// Every apex wildcard — issue these at boot so a first claim never waits on a CA.
#[must_use]
pub fn apex_wildcards() -> Vec<String> {
    APEXES.iter().map(|a| a.wildcard()).collect()
}

impl<S: CertStore, I: CertIssuer> RenewalEngine<S, I> {
    #[must_use]
    pub fn new(store: Arc<S>, issuer: I, policy: RenewalPolicy) -> Self {
        RenewalEngine { store, issuer, policy, baseline: Vec::new(), state: Table::new() }
    }

    /// Names to hold regardless of what the registry currently needs (see [`apex_wildcards`]).
    #[must_use]
    pub fn with_baseline(mut self, names: Vec<String>) -> Self {
        self.baseline = names;
        self
    }

    fn st(&self, name: &str) -> NameState {
        self.state.get(&name.to_string()).cloned().unwrap_or_default()
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
            self.state.put(name.clone(), s.clone());
            match due(&self.policy, held.as_ref(), now) {
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
            let outcome: Result<(), (String, Option<u64>)> = match self.issuer.issue(&name).await {
                Ok(material) => match validate(&material) {
                    // Never replace a held certificate with something the CA mangled or that
                    // is already dead: a bad order must leave last-known-good untouched.
                    Ok(v) if v.not_after > now => self.store.put(&name, material).map_err(|e| (e, None)),
                    Ok(_) => Err(("CA returned an already-expired certificate".to_string(), None)),
                    Err(e) => Err((format!("CA returned unusable material: {e}"), None)),
                },
                Err(e) => Err((e.to_string(), e.retry_after_secs())),
            };
            match outcome {
                Ok(()) => {
                    self.state.put(name.clone(), NameState::default());
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
                self.store.remove(&name);
                self.state.remove(&name);
                report.pruned.push(name);
            } else {
                self.state.put(name, s);
            }
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
    pub async fn run_forever(mut self, registry: Arc<tokio::sync::Mutex<EdgeRegistry>>, interval: std::time::Duration) {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let report = self.run_once(now, &registry).await;
            if !report.issued.is_empty() || !report.failed.is_empty() || !report.pruned.is_empty() {
                tracing::info!(?report, "renewal pass");
            }
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
}

