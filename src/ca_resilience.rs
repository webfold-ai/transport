//! Obtaining certificates from more than one CA, and moving between them without an emergency.
//!
//! [`MultiCaIssuer`] is a [`CertIssuer`] over every CA on the [allow-list](crate::ca_policy). The
//! renewal engine talks to it exactly as it talks to a single-CA issuer; underneath:
//!
//! * **Choice.** An order goes to the first CA that is eligible (`active`, then `standby`, by
//!   *effective* status — a root-program signal can make a CA worse than configured) and not
//!   benched. A CA that is not on the list is not reachable at all ([`CaPolicy::admit`]).
//! * **Fail-over, bounded.** If that CA fails with something that could be the CA's (its server
//!   erroring, timing out, returning junk, refusing the order — [`FailureClass::CaSide`] /
//!   [`FailureClass::Refused`]), the *same order* is retried at the next eligible CA, once per CA,
//!   with an alert. A rate limit is never a reason to switch (waiting is the answer) and neither is
//!   a failure that is ours (the RNG, our challenge responder): those are returned as they are.
//! * **No flapping.** After [`Failover::fail_threshold`] consecutive failures a CA is *benched*:
//!   tried last, for a time that doubles each time it is benched again (up to a cap). A bench that
//!   expires leaves the CA one failure from being benched again, so a CA that is still broken is
//!   not re-trusted with the whole fleet. Orders that fell back at all are counted in a rolling
//!   day; past [`Failover::max_failovers_per_day`] the engine stops falling back and says so — a
//!   standby doing all the work is a decision for an operator (flip the statuses), not a flap.
//! * **Memory.** Which CA issued which certificate (a [`Ledger`], with the certificate's issuer
//!   name as a fallback) so [`CertIssuer::migration`] can tell the engine which certificates to
//!   move, `replaces` is only sent to the CA that issued the certificate being replaced, and a
//!   revocation goes to the right CA. Every decision is appended to a [`Journal`].
//! * **DNS.** [`MultiCaIssuer::caa_plan`] is what the zones publish: the union of every eligible
//!   CA with its own account, so a switch between them needs no DNS change.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::acme::{AcmeError, FailureClass, RenewalWindow};
use crate::acme_renew::{CertIssuer, Migration};
use crate::ca_policy::{CaEntry, CaPolicy, CaStatus, CaaPlan, Standings};
use crate::ca_trust::{CaTrust, TrustVerdict};
use crate::edge::CertMaterial;
use crate::BoxFuture;

/// Seconds since the unix epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    })
}

// ── Alerts ────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// An order fell back from one CA to another.
    Failover,
    /// A CA failed enough times in a row to be tried last.
    CaBenched,
    /// A benched CA issued again.
    CaRecovered,
    /// Fall-back was refused because the day's budget is spent.
    FailoverBudgetExhausted,
    /// A CA gave us an account other than the one pinned for it.
    AccountMismatch,
    /// No CA on the list may issue.
    NoEligibleCa,
    /// A CA's effective standing changed (a root-program signal, or its clearing).
    StandingChanged,
}

impl AlertKind {
    /// Every kind, for exporting a counter per kind (zero included).
    pub const ALL: [AlertKind; 7] = [
        AlertKind::Failover,
        AlertKind::CaBenched,
        AlertKind::CaRecovered,
        AlertKind::FailoverBudgetExhausted,
        AlertKind::AccountMismatch,
        AlertKind::NoEligibleCa,
        AlertKind::StandingChanged,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::Failover => "failover",
            AlertKind::CaBenched => "ca_benched",
            AlertKind::CaRecovered => "ca_recovered",
            AlertKind::FailoverBudgetExhausted => "failover_budget_exhausted",
            AlertKind::AccountMismatch => "account_mismatch",
            AlertKind::NoEligibleCa => "no_eligible_ca",
            AlertKind::StandingChanged => "standing_changed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaAlert {
    pub at: i64,
    pub kind: AlertKind,
    pub ca: String,
    pub detail: String,
}

const ALERT_RING: usize = 256;

/// Where alerts go: the `tracing` log at error/warn level, a bounded ring the control API
/// shows, and per-kind counters for metrics. (Paging is the alert rules' job, off the metrics.)
#[derive(Default)]
pub struct AlertLog {
    ring: Mutex<VecDeque<CaAlert>>,
    counts: Mutex<HashMap<AlertKind, u64>>,
}

impl AlertLog {
    pub fn raise(&self, alert: CaAlert) {
        match alert.kind {
            AlertKind::CaRecovered | AlertKind::StandingChanged => {
                tracing::warn!(kind = alert.kind.as_str(), ca = %alert.ca, detail = %alert.detail, "CA alert")
            }
            _ => {
                tracing::error!(kind = alert.kind.as_str(), ca = %alert.ca, detail = %alert.detail, "CA alert")
            }
        }
        *self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(alert.kind)
            .or_default() += 1;
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ring.len() == ALERT_RING {
            ring.pop_front();
        }
        ring.push_back(alert);
    }

    /// The most recent alerts, oldest first.
    #[must_use]
    pub fn recent(&self) -> Vec<CaAlert> {
        self.ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// How many alerts of `kind` have been raised since start.
    #[must_use]
    pub fn count(&self, kind: AlertKind) -> u64 {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&kind)
            .copied()
            .unwrap_or(0)
    }
}

// ── Journal ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEvent {
    pub at: i64,
    pub event: String,
    pub ca: String,
    pub detail: String,
}

/// An append-only record of CA decisions (JSON lines, fsynced, rotated at 2 MiB so it cannot fill
/// a disk). It is the audit trail for "why did the edge move to the standby at 03:12".
pub struct Journal {
    path: Option<PathBuf>,
    memory: Mutex<Vec<JournalEvent>>,
}

const JOURNAL_ROTATE_BYTES: u64 = 2 * 1024 * 1024;

impl Journal {
    /// Keep events in memory only (tests).
    #[must_use]
    pub fn memory() -> Self {
        Journal {
            path: None,
            memory: Mutex::new(Vec::new()),
        }
    }

    /// Append to `path` (the directory must exist).
    ///
    /// # Errors
    /// The file cannot be opened for appending.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        drop(Self::file(&path)?);
        Ok(Journal {
            path: Some(path),
            memory: Mutex::new(Vec::new()),
        })
    }

    fn file(path: &Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }

    pub fn append(&self, at: i64, event: &str, ca: &str, detail: &str) {
        let ev = JournalEvent {
            at,
            event: event.to_string(),
            ca: ca.to_string(),
            detail: detail.chars().take(500).collect(),
        };
        match &self.path {
            None => self
                .memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ev),
            Some(path) => {
                use std::io::Write;
                if std::fs::metadata(path).is_ok_and(|m| m.len() > JOURNAL_ROTATE_BYTES) {
                    let _ = std::fs::rename(path, path.with_extension("jsonl.1"));
                }
                let line = serde_json::to_string(&ev).unwrap_or_default();
                let written = Self::file(path).and_then(|mut f| {
                    f.write_all(format!("{line}\n").as_bytes())
                        .and_then(|()| f.sync_data())
                });
                if let Err(e) = written {
                    tracing::error!(error = %e, "could not write the CA journal");
                }
            }
        }
    }

    /// The last `n` events, oldest first.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<JournalEvent> {
        let all: Vec<JournalEvent> = match &self.path {
            None => self
                .memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            Some(p) => std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
        };
        let skip = all.len().saturating_sub(n);
        all.into_iter().skip(skip).collect()
    }
}

// ── Accounts ──────────────────────────────────────────────────────────────────────────────

/// The ACME account URL we hold at each CA, remembered across restarts so the CAA records stay the
/// same when a standby CA happens to be down at boot. A CA whose policy entry pins `account_uri`
/// must hand out exactly that account.
pub struct AccountBook {
    path: Option<PathBuf>,
    map: Mutex<HashMap<String, String>>,
}

impl AccountBook {
    #[must_use]
    pub fn memory() -> Self {
        AccountBook {
            path: None,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Load (or start) the book at `path`.
    ///
    /// # Errors
    /// An existing file that is not a JSON object of strings (refused: a damaged book must not be
    /// silently replaced, because the CAA records are built from it).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let map = match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(AccountBook {
            path: Some(path),
            map: Mutex::new(map),
        })
    }

    #[must_use]
    pub fn get(&self, ca: &str) -> Option<String> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(ca)
            .cloned()
    }

    #[must_use]
    pub fn all(&self) -> HashMap<String, String> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Record the account the CA gave us. `Ok(true)` if that is new information.
    ///
    /// # Errors
    /// The policy pins a different account for this CA, or the book cannot be saved.
    pub fn learn(&self, entry: &CaEntry, uri: &str) -> Result<bool, String> {
        if let Some(pinned) = &entry.account_uri {
            if pinned != uri {
                return Err(format!(
                    "CA '{}' registered us as {uri}, but the policy pins {pinned}",
                    entry.name
                ));
            }
        }
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.get(&entry.name).is_some_and(|u| u == uri) {
            return Ok(false);
        }
        map.insert(entry.name.clone(), uri.to_string());
        if let Some(path) = &self.path {
            let body = serde_json::to_vec_pretty(&*map).map_err(|e| e.to_string())?;
            crate::certkey::write_private_atomic(path, &body)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(true)
    }
}

// ── Ledger ────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LedgerLine {
    cert: String,
    ca: String,
    at: i64,
    /// The leaf's serial number (hex), so the CT monitor can tell a certificate we ordered from one
    /// we did not. Empty in lines written before this field existed.
    #[serde(default)]
    serial: String,
}

const LEDGER_MAX: usize = 8192;

/// Which CA issued which certificate (by the SHA-256 of the leaf DER), kept across restarts.
pub struct Ledger {
    path: Option<PathBuf>,
    map: Mutex<(HashMap<String, String>, VecDeque<String>)>,
    serials: Mutex<VecDeque<String>>,
}

impl Ledger {
    #[must_use]
    pub fn memory() -> Self {
        Ledger {
            path: None,
            map: Mutex::new((HashMap::new(), VecDeque::new())),
            serials: Mutex::new(VecDeque::new()),
        }
    }

    /// Load (or start) the ledger at `path`. Unreadable lines are skipped: the ledger is a hint
    /// with a fallback ([`MultiCaIssuer::attribute`]), not a source of truth.
    ///
    /// # Errors
    /// The file cannot be opened.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let mut state = (HashMap::new(), VecDeque::new());
        let mut serials = VecDeque::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text
                .lines()
                .filter_map(|l| serde_json::from_str::<LedgerLine>(l).ok())
            {
                if !line.serial.is_empty() {
                    serials.push_back(line.serial.clone());
                }
                Self::insert(&mut state, line.cert, line.ca);
            }
        }
        while serials.len() > LEDGER_MAX {
            serials.pop_front();
        }
        drop(Journal::file(&path)?);
        Ok(Ledger {
            path: Some(path),
            map: Mutex::new(state),
            serials: Mutex::new(serials),
        })
    }

    fn insert(state: &mut (HashMap<String, String>, VecDeque<String>), cert: String, ca: String) {
        if state.0.insert(cert.clone(), ca).is_none() {
            state.1.push_back(cert);
        }
        while state.1.len() > LEDGER_MAX {
            if let Some(old) = state.1.pop_front() {
                state.0.remove(&old);
            }
        }
    }

    fn id(material: &CertMaterial) -> Option<String> {
        crate::x509::leaf_der(&material.chain_pem)
            .map(|d| crate::x509::fingerprint_hex(&d))
            .or_else(|| Some(crate::x509::fingerprint_hex(material.chain_pem.as_bytes())))
    }

    pub fn record(&self, material: &CertMaterial, ca: &str, at: i64) {
        let Some(cert) = Self::id(material) else {
            return;
        };
        let serial = crate::x509::leaf_der(&material.chain_pem)
            .and_then(|d| {
                crate::x509::parse(&d).map(|c| {
                    c.serial
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                })
            })
            .unwrap_or_default();
        Self::insert(
            &mut self
                .map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            cert.clone(),
            ca.to_string(),
        );
        if !serial.is_empty() {
            let mut s = self
                .serials
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.push_back(serial.clone());
            while s.len() > LEDGER_MAX {
                s.pop_front();
            }
        }
        if let Some(path) = &self.path {
            use std::io::Write;
            let line = serde_json::to_string(&LedgerLine {
                cert,
                ca: ca.to_string(),
                at,
                serial,
            })
            .unwrap_or_default();
            if let Err(e) =
                Journal::file(path).and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()))
            {
                tracing::warn!(error = %e, "could not append to the CA ledger");
            }
        }
    }

    /// Serial numbers (hex) of every certificate recorded, most recent last.
    #[must_use]
    pub fn serials(&self) -> Vec<String> {
        self.serials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn lookup(&self, material: &CertMaterial) -> Option<String> {
        let id = Self::id(material)?;
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
            .get(&id)
            .cloned()
    }
}

// ── Health ────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CaHealth {
    consecutive: u32,
    bench_level: u32,
    benched_until: i64,
    last_error: Option<String>,
    last_ok: i64,
    issued: u64,
    failures: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HealthFile {
    cas: HashMap<String, CaHealth>,
    /// Unix seconds of each order that fell back to another CA, within the last day.
    failovers: Vec<i64>,
}

/// What an operator or a dashboard sees of one CA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaView {
    pub name: String,
    pub configured: CaStatus,
    pub effective: CaStatus,
    pub benched_until: i64,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub account_url: Option<String>,
    pub issued: u64,
    pub failures: u64,
}

// ── Connecting ────────────────────────────────────────────────────────────────────────────

/// A live connection to one CA: an issuer and the account URL it registered.
pub struct Connected {
    pub issuer: Arc<dyn CertIssuer>,
    pub account_url: Option<String>,
}

/// Opens a connection to a CA that is on the allow-list. The production implementation registers
/// an ACME account; tests substitute scripted CAs.
pub trait CaConnector: Send + Sync {
    fn connect<'a>(&'a self, ca: &'a CaEntry) -> BoxFuture<'a, Result<Connected, AcmeError>>;
}

/// The production [`CaConnector`]: registers (or finds) our ACME account at the CA with the
/// account key and External Account Binding the policy entry names, and wraps the result in an
/// [`AcmeIssuer`]. One account key per CA, created 0600 on first use; an entry with no
/// `account_key_file` cannot be connected (there is no anonymous account).
pub struct AcmeCaConnector {
    pub dns01: Arc<dyn crate::acme::Dns01Responder>,
    pub http01: Option<Arc<dyn crate::acme::Http01Responder>>,
    /// Key algorithm, key policy, generator and request deadline for every CA's client.
    pub options: crate::acme::ClientOptions,
    /// Contact used where an entry has none.
    pub default_contact: Option<String>,
}

impl CaConnector for AcmeCaConnector {
    fn connect<'a>(&'a self, ca: &'a CaEntry) -> BoxFuture<'a, Result<Connected, AcmeError>> {
        Box::pin(async move {
            let local = |m: String| AcmeError::Local(format!("CA '{}': {m}", ca.name));
            let key_file = ca
                .account_key_file
                .as_deref()
                .ok_or_else(|| local("the policy entry has no account_key_file".into()))?;
            let account = crate::acme::load_or_create_account_key_with(
                Path::new(key_file),
                self.options.keygen.as_ref(),
            )?;
            let eab = match &ca.eab {
                Some(e) => {
                    let key = std::fs::read_to_string(&e.hmac_key_file)
                        .map_err(|err| local(format!("{}: {err}", e.hmac_key_file)))?;
                    Some(crate::acme::ExternalAccountBinding::from_base64url(
                        e.kid.clone(),
                        &key,
                    )?)
                }
                None => None,
            };
            let mut options = self.options.clone();
            if ca.profile.is_some() {
                options.profile = ca.profile.clone();
            }
            let contact = ca.contact.as_deref().or(self.default_contact.as_deref());
            let client =
                crate::acme::AcmeClient::connect(&ca.directory_url, account, contact, eab, options)
                    .await?;
            let account_url = client.account_url();
            Ok(Connected {
                issuer: Arc::new(crate::acme_renew::AcmeIssuer::new(
                    client,
                    self.dns01.clone(),
                    self.http01.clone(),
                )),
                account_url,
            })
        })
    }
}

// ── The issuer ────────────────────────────────────────────────────────────────────────────

struct Inner {
    policy: RwLock<Arc<CaPolicy>>,
    standings: RwLock<Standings>,
    trust_streak: Mutex<HashMap<String, (Option<CaStatus>, u32)>>,
    connector: Arc<dyn CaConnector>,
    connected: tokio::sync::Mutex<HashMap<(String, String), Arc<Connected>>>,
    health: Mutex<HealthFile>,
    health_path: Option<PathBuf>,
    accounts: AccountBook,
    ledger: Ledger,
    journal: Journal,
    alerts: Arc<AlertLog>,
    clock: Clock,
    last_no_ca_alert: Mutex<i64>,
}

/// A [`CertIssuer`] over every CA on the allow-list. See the [module docs](self).
pub struct MultiCaIssuer {
    inner: Arc<Inner>,
}

/// Persistent state locations. Every path is optional: `None` keeps that piece in memory.
#[derive(Clone, Debug, Default)]
pub struct StatePaths {
    pub journal: Option<PathBuf>,
    pub ledger: Option<PathBuf>,
    pub accounts: Option<PathBuf>,
    pub health: Option<PathBuf>,
}

impl StatePaths {
    /// The standard layout inside one directory.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        StatePaths {
            journal: Some(dir.join("ca-journal.jsonl")),
            ledger: Some(dir.join("ca-ledger.jsonl")),
            accounts: Some(dir.join("ca-accounts.json")),
            health: Some(dir.join("ca-health.json")),
        }
    }
}

impl MultiCaIssuer {
    /// # Errors
    /// A state file exists and cannot be used.
    pub fn new(
        policy: CaPolicy,
        connector: Arc<dyn CaConnector>,
        state: &StatePaths,
    ) -> Result<Self, String> {
        Self::with_clock(policy, connector, state, system_clock())
    }

    /// As [`Self::new`], with an explicit clock (tests).
    ///
    /// # Errors
    /// A state file exists and cannot be used.
    pub fn with_clock(
        policy: CaPolicy,
        connector: Arc<dyn CaConnector>,
        state: &StatePaths,
        clock: Clock,
    ) -> Result<Self, String> {
        let journal = match &state.journal {
            Some(p) => Journal::open(p).map_err(|e| format!("{}: {e}", p.display()))?,
            None => Journal::memory(),
        };
        let ledger = match &state.ledger {
            Some(p) => Ledger::open(p).map_err(|e| format!("{}: {e}", p.display()))?,
            None => Ledger::memory(),
        };
        let accounts = match &state.accounts {
            Some(p) => AccountBook::open(p)?,
            None => AccountBook::memory(),
        };
        let health = match &state.health {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
                Err(_) => HealthFile::default(),
            },
            None => HealthFile::default(),
        };
        Ok(MultiCaIssuer {
            inner: Arc::new(Inner {
                policy: RwLock::new(Arc::new(policy)),
                standings: RwLock::new(Standings::new()),
                trust_streak: Mutex::new(HashMap::new()),
                connector,
                connected: tokio::sync::Mutex::new(HashMap::new()),
                health: Mutex::new(health),
                health_path: state.health.clone(),
                accounts,
                ledger,
                journal,
                alerts: Arc::new(AlertLog::default()),
                clock,
                last_no_ca_alert: Mutex::new(i64::MIN),
            }),
        })
    }

    #[must_use]
    pub fn policy(&self) -> Arc<CaPolicy> {
        self.inner
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replace the policy (a reloaded file). Takes effect for the next order.
    pub fn set_policy(&self, policy: CaPolicy) {
        let now = (self.inner.clock)();
        self.inner.journal.append(
            now,
            "policy_reloaded",
            "",
            &format!("{} CAs", policy.cas.len()),
        );
        *self
            .inner
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
    }

    #[must_use]
    pub fn alerts(&self) -> Arc<AlertLog> {
        self.inner.alerts.clone()
    }

    #[must_use]
    pub fn journal(&self) -> &Journal {
        &self.inner.journal
    }

    #[must_use]
    pub fn accounts(&self) -> HashMap<String, String> {
        self.inner.accounts.all()
    }

    /// Serial numbers of every certificate this issuer has obtained (for the CT monitor).
    #[must_use]
    pub fn issued_serials(&self) -> Vec<String> {
        self.inner.ledger.serials()
    }

    fn now(&self) -> i64 {
        (self.inner.clock)()
    }

    fn standings(&self) -> Standings {
        self.inner
            .standings
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn raise(&self, kind: AlertKind, ca: &str, detail: &str) {
        self.inner
            .journal
            .append(self.now(), kind.as_str(), ca, detail);
        self.inner.alerts.raise(CaAlert {
            at: self.now(),
            kind,
            ca: ca.to_string(),
            detail: detail.to_string(),
        });
    }

    fn save_health(&self, h: &HealthFile) {
        if let Some(path) = &self.inner.health_path {
            if let Ok(body) = serde_json::to_vec(h) {
                if let Err(e) = crate::certkey::write_private_atomic(path, &body) {
                    tracing::warn!(error = %e, "could not persist CA health");
                }
            }
        }
    }

    // ── standing ──

    /// Feed a root-program evaluation ([`crate::ca_trust::evaluate`]) into the CA's effective
    /// status. A `Distrusted` verdict escalates to `distrusted`, a `DistrustPending` one to
    /// `retiring` (so renewals move early and the CA leaves CAA while it still can be left in
    /// order); an escalation takes effect only after [`crate::ca_policy::TrustSettings::confirmations`]
    /// consecutive evaluations agree; `Unknown` (a failed or unparseable fetch) changes nothing,
    /// ever. Returns the CAs whose standing changed.
    pub fn apply_trust(&self, report: &[CaTrust]) -> Vec<String> {
        let policy = self.policy();
        let mut changed = Vec::new();
        for t in report {
            if policy.get(&t.ca).is_none() {
                continue;
            }
            let desired = match &t.combined {
                TrustVerdict::Unknown { .. } => continue,
                TrustVerdict::Trusted => None,
                TrustVerdict::DistrustPending { .. } => Some(CaStatus::Retiring),
                TrustVerdict::Distrusted { .. } => Some(CaStatus::Distrusted),
            };
            let streak = {
                let mut s = self
                    .inner
                    .trust_streak
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let e = s.entry(t.ca.clone()).or_insert((desired, 0));
                if e.0 == desired {
                    e.1 = e.1.saturating_add(1);
                } else {
                    *e = (desired, 1);
                }
                e.1
            };
            if streak < policy.trust.confirmations {
                continue;
            }
            let mut standings = self
                .inner
                .standings
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = standings.get(&t.ca).copied();
            match desired {
                Some(s) => {
                    standings.insert(t.ca.clone(), s);
                }
                None => {
                    standings.remove(&t.ca);
                }
            }
            if standings.get(&t.ca).copied() != before {
                drop(standings);
                changed.push(t.ca.clone());
                self.raise(
                    AlertKind::StandingChanged,
                    &t.ca,
                    &format!(
                        "root-program verdict {} -> effective standing {:?}",
                        t.combined.label(),
                        desired.map(CaStatus::as_str)
                    ),
                );
            }
        }
        changed
    }

    /// Force a CA's standing (an operator's `distrusted` override that does not wait for the file).
    pub fn set_standing(&self, ca: &str, status: Option<CaStatus>) {
        let mut s = self
            .inner
            .standings
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match status {
            Some(st) => s.insert(ca.to_string(), st),
            None => s.remove(ca),
        };
    }

    /// The status the engine acts on for `ca`.
    #[must_use]
    pub fn effective(&self, ca: &str) -> CaStatus {
        self.policy().effective(ca, &self.standings())
    }

    /// The CAA the zones should publish now.
    #[must_use]
    pub fn caa_plan(&self, validation_methods: &[String]) -> CaaPlan {
        self.policy().caa_plan(
            &self.standings(),
            &self.inner.accounts.all(),
            validation_methods,
        )
    }

    /// Findings about the policy as it stands now, including the effect of root-program signals.
    #[must_use]
    pub fn lint(&self) -> Vec<crate::ca_policy::PolicyFinding> {
        self.policy().lint_with(&self.standings())
    }

    /// Names of the CAs that may issue now, in preference order.
    #[must_use]
    pub fn eligible_names(&self) -> Vec<String> {
        self.policy()
            .eligible(&self.standings())
            .into_iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// One row per CA for status pages and metrics.
    #[must_use]
    pub fn views(&self) -> Vec<CaView> {
        let policy = self.policy();
        let standings = self.standings();
        let health = self
            .inner
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        policy
            .cas
            .iter()
            .map(|c| {
                let h = health.cas.get(&c.name).cloned().unwrap_or_default();
                CaView {
                    name: c.name.clone(),
                    configured: c.status,
                    effective: policy.effective(&c.name, &standings),
                    benched_until: h.benched_until,
                    consecutive_failures: h.consecutive,
                    last_error: h.last_error,
                    account_url: c
                        .account_uri
                        .clone()
                        .or_else(|| self.inner.accounts.get(&c.name)),
                    issued: h.issued,
                    failures: h.failures,
                }
            })
            .collect()
    }

    // ── attribution ──

    /// The CA that issued `material`: the ledger first, then the leaf's issuer name against each
    /// CA's `issuer_names`. `None` if neither says.
    #[must_use]
    pub fn attribute(&self, material: &CertMaterial) -> Option<String> {
        if let Some(ca) = self.inner.ledger.lookup(material) {
            if self.policy().get(&ca).is_some() {
                return Some(ca);
            }
        }
        let der = crate::x509::leaf_der(&material.chain_pem)?;
        let cert = crate::x509::parse(&der)?;
        let issuer: Vec<String> = [cert.issuer_cn(), cert.issuer_org()]
            .into_iter()
            .flatten()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        self.policy()
            .cas
            .iter()
            .find(|c| {
                c.issuer_names
                    .iter()
                    .any(|n| issuer.iter().any(|i| i.contains(&n.to_ascii_lowercase())))
            })
            .map(|c| c.name.clone())
    }

    // ── connecting ──

    async fn backend(&self, ca: &CaEntry, for_issuance: bool) -> Result<Arc<Connected>, AcmeError> {
        if for_issuance {
            // The gate: never talk to a CA to order from it unless it is on the list and may issue.
            self.policy()
                .admit(&ca.directory_url, &self.standings())
                .map_err(|e| AcmeError::Local(e.to_string()))?;
        }
        let key = (ca.name.clone(), ca.directory_url.clone());
        let mut connected = self.inner.connected.lock().await;
        if let Some(c) = connected.get(&key) {
            return Ok(c.clone());
        }
        let c = Arc::new(self.inner.connector.connect(ca).await?);
        if let Some(url) = &c.account_url {
            match self.inner.accounts.learn(ca, url) {
                Ok(true) => {
                    self.inner
                        .journal
                        .append(self.now(), "account_registered", &ca.name, url)
                }
                Ok(false) => {}
                Err(e) => {
                    self.raise(AlertKind::AccountMismatch, &ca.name, &e);
                    return Err(AcmeError::CaMisbehaved(e));
                }
            }
        }
        connected.insert(key, c.clone());
        Ok(c)
    }

    /// Register an account at every CA that may issue, so each one has an account URL for the CAA
    /// records *before* it is needed. Best effort: a CA that is down is retried at its first order.
    /// Returns `(ca, error)` for the ones that failed.
    pub async fn connect_all(&self) -> Vec<(String, String)> {
        let mut failed = Vec::new();
        let policy = self.policy();
        for ca in policy.eligible(&self.standings()) {
            if let Err(e) = self.backend(ca, true).await {
                tracing::warn!(ca = %ca.name, error = %e, "could not register at the CA");
                failed.push((ca.name.clone(), e.to_string()));
            }
        }
        failed
    }

    // ── choosing and recording ──

    /// The CAs to try for the next order: eligible ones in preference order, benched ones after
    /// the rest (soonest to return first).
    fn candidates(&self, now: i64) -> Vec<CaEntry> {
        let policy = self.policy();
        let eligible: Vec<CaEntry> = policy
            .eligible(&self.standings())
            .into_iter()
            .cloned()
            .collect();
        let health = self
            .inner
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let benched_until = |c: &CaEntry| health.cas.get(&c.name).map_or(0, |h| h.benched_until);
        let (mut ready, mut benched): (Vec<CaEntry>, Vec<CaEntry>) =
            eligible.into_iter().partition(|c| benched_until(c) <= now);
        benched.sort_by_key(|c| benched_until(c));
        ready.extend(benched);
        ready
    }

    fn record_success(&self, ca: &str, material: &CertMaterial, now: i64) {
        self.inner.ledger.record(material, ca, now);
        let (recovered, snapshot) = {
            let mut h = self
                .inner
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let e = h.cas.entry(ca.to_string()).or_default();
            let recovered = e.benched_until > 0 || e.bench_level > 0;
            *e = CaHealth {
                issued: e.issued + 1,
                failures: e.failures,
                last_ok: now,
                ..CaHealth::default()
            };
            (recovered, h.clone())
        };
        self.save_health(&snapshot);
        self.inner.journal.append(now, "issued", ca, "");
        if recovered {
            self.raise(
                AlertKind::CaRecovered,
                ca,
                "issued a certificate after being benched",
            );
        }
    }

    fn record_failure(&self, ca: &str, err: &AcmeError, now: i64) {
        let failover = self.policy().failover.clone();
        let (benched, snapshot) = {
            let mut h = self
                .inner
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let e = h.cas.entry(ca.to_string()).or_default();
            e.consecutive = e.consecutive.saturating_add(1);
            e.failures += 1;
            e.last_error = Some(err.to_string().chars().take(300).collect());
            let mut benched = None;
            if e.consecutive >= failover.fail_threshold {
                let secs = failover
                    .bench_secs
                    .saturating_mul(1i64 << e.bench_level.min(20))
                    .min(failover.bench_max_secs);
                e.benched_until = now.saturating_add(secs);
                e.bench_level = e.bench_level.saturating_add(1);
                // One more failure after the bench re-benches (longer); a success clears all of it.
                e.consecutive = failover.fail_threshold.saturating_sub(1);
                benched = Some(secs);
            }
            (benched, h.clone())
        };
        self.save_health(&snapshot);
        self.inner
            .journal
            .append(now, "failure", ca, &format!("{:?}: {err}", err.class()));
        if let Some(secs) = benched {
            self.raise(
                AlertKind::CaBenched,
                ca,
                &format!("failing; tried last for {secs}s ({err})"),
            );
        }
    }

    /// Whether another order may fall back to an alternative CA today.
    fn failover_budget(&self, now: i64) -> bool {
        let max = self.policy().failover.max_failovers_per_day as usize;
        let mut h = self
            .inner
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        h.failovers.retain(|t| now - *t < 24 * 3600);
        h.failovers.len() < max
    }

    fn note_failover(&self, now: i64) {
        let snapshot = {
            let mut h = self
                .inner
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            h.failovers.push(now);
            h.clone()
        };
        self.save_health(&snapshot);
    }

    async fn order(
        &self,
        cert_name: &str,
        previous: Option<&CertMaterial>,
    ) -> Result<CertMaterial, AcmeError> {
        let now = self.now();
        let candidates = self.candidates(now);
        if candidates.is_empty() {
            let mut last = self
                .inner
                .last_no_ca_alert
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if now.saturating_sub(*last) > 3600 {
                *last = now;
                drop(last);
                self.raise(
                    AlertKind::NoEligibleCa,
                    "",
                    "no CA on the allow-list may issue (all are retiring or distrusted)",
                );
            }
            return Err(AcmeError::Local(
                "no CA on the allow-list is eligible to issue; make one active or standby".into(),
            ));
        }
        let previous_ca = previous.and_then(|p| self.attribute(p));
        let mut first_error: Option<AcmeError> = None;
        let mut previous_try: Option<String> = None;
        for (i, ca) in candidates.iter().enumerate() {
            if i > 0 {
                let now = self.now();
                if !self.failover_budget(now) {
                    self.raise(AlertKind::FailoverBudgetExhausted, &ca.name, "this order will not fall back to another CA: the day's fail-over budget is spent");
                    break;
                }
                self.note_failover(now);
                self.raise(
                    AlertKind::Failover,
                    &ca.name,
                    &format!(
                        "ordering {cert_name} from '{}' after '{}' failed ({})",
                        ca.name,
                        previous_try.as_deref().unwrap_or("?"),
                        first_error
                            .as_ref()
                            .map_or_else(String::new, ToString::to_string)
                    ),
                );
            }
            // `replaces` names a certificate by the issuing CA's ARI id, so only that CA gets it.
            let replacing = previous.filter(|_| previous_ca.as_deref() == Some(ca.name.as_str()));
            let attempt = async {
                let backend = self.backend(ca, true).await?;
                match replacing {
                    Some(prev) => backend.issuer.issue_replacing(cert_name, prev).await,
                    None => backend.issuer.issue(cert_name).await,
                }
            }
            .await;
            match attempt {
                Ok(material) => {
                    self.record_success(&ca.name, &material, self.now());
                    return Ok(material);
                }
                Err(e) => match e.class() {
                    // Waiting is the answer to a rate limit, and our own failure is ours at every CA.
                    FailureClass::RateLimited | FailureClass::Local => {
                        return Err(first_error.unwrap_or(e))
                    }
                    FailureClass::CaSide | FailureClass::Refused => {
                        self.record_failure(&ca.name, &e, self.now());
                        previous_try = Some(ca.name.clone());
                        first_error.get_or_insert(e);
                    }
                },
            }
        }
        Err(first_error.unwrap_or_else(|| AcmeError::Local("no CA could be tried".into())))
    }
}

impl CertIssuer for MultiCaIssuer {
    fn issue<'a>(&'a self, cert_name: &'a str) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        Box::pin(self.order(cert_name, None))
    }

    fn issue_replacing<'a>(
        &'a self,
        cert_name: &'a str,
        previous: &'a CertMaterial,
    ) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
        Box::pin(self.order(cert_name, Some(previous)))
    }

    fn renewal_window<'a>(
        &'a self,
        material: &'a CertMaterial,
    ) -> BoxFuture<'a, Option<RenewalWindow>> {
        Box::pin(async move {
            let ca = self.attribute(material)?;
            let entry = self.policy().get(&ca)?.clone();
            let backend = self.backend(&entry, false).await.ok()?;
            backend.issuer.renewal_window(material).await
        })
    }

    fn revoke<'a>(&'a self, material: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async move {
            let ca = self.attribute(material).ok_or_else(|| {
                AcmeError::Local(
                    "cannot tell which CA issued this certificate, so cannot revoke it".into(),
                )
            })?;
            let entry = self.policy().get(&ca).cloned().ok_or_else(|| {
                AcmeError::Local(format!("CA '{ca}' is no longer on the allow-list"))
            })?;
            // Revocation talks to the issuing CA whatever its standing: a distrusted CA's
            // certificates are exactly what we most want revoked.
            let backend = self.backend(&entry, false).await?;
            backend.issuer.revoke(material).await
        })
    }

    fn migration(&self, material: &CertMaterial) -> Migration {
        match self.attribute(material) {
            Some(ca) => self.effective(&ca).migration(),
            None => Migration::None,
        }
    }

    fn ca_name(&self, material: &CertMaterial) -> Option<String> {
        self.attribute(material)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_policy::fixtures::{entry, policy};
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering::SeqCst};

    const T0: i64 = 1_800_000_000;

    /// A scripted CA: answers orders from a queue, falling back to success.
    struct ScriptedCa {
        name: String,
        script: Mutex<VecDeque<Result<(), AcmeError>>>,
        orders: Mutex<Vec<(String, bool)>>,
        revoked: Mutex<Vec<String>>,
        issued_counter: AtomicUsize,
        always: Mutex<Option<fn() -> AcmeError>>,
    }

    impl ScriptedCa {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(ScriptedCa {
                name: name.into(),
                script: Mutex::default(),
                orders: Mutex::default(),
                revoked: Mutex::default(),
                issued_counter: AtomicUsize::new(0),
                always: Mutex::new(None),
            })
        }
        fn fail_with(&self, f: fn() -> AcmeError) {
            *self.always.lock().unwrap() = Some(f);
        }
        fn heal(&self) {
            *self.always.lock().unwrap() = None;
        }
        fn orders(&self) -> usize {
            self.orders.lock().unwrap().len()
        }
        fn material(&self) -> CertMaterial {
            // A real certificate whose issuer common name is "<ca> CA" (matches the fixture's issuer_names).
            let n = self.issued_counter.fetch_add(1, SeqCst);
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, format!("{} CA", self.name));
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["x.example.test".to_string()]).unwrap();
            params.serial_number = Some(rcgen::SerialNumber::from_slice(&n.to_be_bytes()));
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            CertMaterial {
                chain_pem: cert.pem(),
                key_pem: crate::acme::pem_wrap("PRIVATE KEY", &pkcs8_of(&key)),
            }
        }
    }

    fn pkcs8_of(key: &rcgen::KeyPair) -> Vec<u8> {
        key.serialize_der()
    }

    impl CertIssuer for ScriptedCa {
        fn issue<'a>(
            &'a self,
            cert_name: &'a str,
        ) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            Box::pin(async move {
                self.orders
                    .lock()
                    .unwrap()
                    .push((cert_name.to_string(), false));
                if let Some(f) = *self.always.lock().unwrap() {
                    return Err(f());
                }
                match self.script.lock().unwrap().pop_front() {
                    Some(Err(e)) => Err(e),
                    _ => Ok(self.material()),
                }
            })
        }
        fn issue_replacing<'a>(
            &'a self,
            cert_name: &'a str,
            _p: &'a CertMaterial,
        ) -> BoxFuture<'a, Result<CertMaterial, AcmeError>> {
            Box::pin(async move {
                let r = self.issue(cert_name).await;
                if let Some(last) = self.orders.lock().unwrap().last_mut() {
                    last.1 = true;
                }
                r
            })
        }
        fn revoke<'a>(&'a self, m: &'a CertMaterial) -> BoxFuture<'a, Result<(), AcmeError>> {
            Box::pin(async move {
                self.revoked.lock().unwrap().push(m.chain_pem.clone());
                Ok(())
            })
        }
    }

    struct Connector {
        cas: HashMap<String, Arc<ScriptedCa>>,
        down: Mutex<std::collections::HashSet<String>>,
        connects: AtomicUsize,
        account_override: Mutex<HashMap<String, String>>,
    }

    impl CaConnector for Connector {
        fn connect<'a>(&'a self, ca: &'a CaEntry) -> BoxFuture<'a, Result<Connected, AcmeError>> {
            Box::pin(async move {
                self.connects.fetch_add(1, SeqCst);
                if self.down.lock().unwrap().contains(&ca.name) {
                    return Err(AcmeError::Http(crate::http_types::Error::Http(
                        "connection refused".into(),
                    )));
                }
                let scripted = self
                    .cas
                    .get(&ca.name)
                    .cloned()
                    .ok_or_else(|| AcmeError::Local("unknown".into()))?;
                let account = self
                    .account_override
                    .lock()
                    .unwrap()
                    .get(&ca.name)
                    .cloned()
                    .unwrap_or_else(|| format!("https://{}.example.test/acct/1", ca.name));
                Ok(Connected {
                    issuer: scripted,
                    account_url: Some(account),
                })
            })
        }
    }

    struct Fixture {
        issuer: Arc<MultiCaIssuer>,
        a: Arc<ScriptedCa>,
        b: Arc<ScriptedCa>,
        connector: Arc<Connector>,
        now: Arc<AtomicI64>,
    }

    fn fixture_with(policy: CaPolicy) -> Fixture {
        let (a, b) = (ScriptedCa::new("a"), ScriptedCa::new("b"));
        let mut cas = HashMap::new();
        cas.insert("a".to_string(), a.clone());
        cas.insert("b".to_string(), b.clone());
        let connector = Arc::new(Connector {
            cas,
            down: Mutex::default(),
            connects: AtomicUsize::new(0),
            account_override: Mutex::default(),
        });
        let now = Arc::new(AtomicI64::new(T0));
        let n = now.clone();
        let issuer = Arc::new(
            MultiCaIssuer::with_clock(
                policy,
                connector.clone(),
                &StatePaths::default(),
                Arc::new(move || n.load(SeqCst)),
            )
            .unwrap(),
        );
        Fixture {
            issuer,
            a,
            b,
            connector,
            now,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(policy(vec![
            entry("a", CaStatus::Active, "a.test"),
            entry("b", CaStatus::Standby, "b.test"),
        ]))
    }

    fn server_error() -> AcmeError {
        AcmeError::Rejected {
            status: 503,
            detail: "overloaded".into(),
        }
    }
    fn rate_limited() -> AcmeError {
        AcmeError::RateLimited {
            retry_after_secs: Some(3600),
            detail: "too many".into(),
        }
    }
    fn local() -> AcmeError {
        AcmeError::Local("rng".into())
    }

    #[tokio::test]
    async fn orders_go_to_the_active_ca_and_the_certificate_is_attributed_to_it() {
        let f = fixture();
        let m = f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!((f.a.orders(), f.b.orders()), (1, 0));
        assert_eq!(f.issuer.ca_name(&m).as_deref(), Some("a"));
        // With no ledger entry at all the issuer name in the certificate still says who issued it.
        let fresh = Fixture {
            issuer: Arc::new(
                MultiCaIssuer::new(
                    f.issuer.policy().as_ref().clone(),
                    f.connector.clone(),
                    &StatePaths::default(),
                )
                .unwrap(),
            ),
            ..f
        };
        assert_eq!(
            fresh.issuer.ca_name(&m).as_deref(),
            Some("a"),
            "attributed by issuer name"
        );
        assert_eq!(fresh.issuer.migration(&m), Migration::None);
    }

    #[tokio::test]
    async fn a_ca_side_failure_falls_back_to_the_standby_for_that_order_with_an_alert_and_a_journal_entry(
    ) {
        let f = fixture();
        f.a.fail_with(server_error);
        let m = f
            .issuer
            .issue("x.example.test")
            .await
            .expect("the standby issued it");
        assert_eq!((f.a.orders(), f.b.orders()), (1, 1));
        assert_eq!(f.issuer.ca_name(&m).as_deref(), Some("b"));
        let alerts = f.issuer.alerts();
        assert_eq!(alerts.count(AlertKind::Failover), 1);
        let a = alerts.recent();
        assert!(
            a.iter().any(|x| x.kind == AlertKind::Failover
                && x.ca == "b"
                && x.detail.contains("'a' failed")),
            "{a:?}"
        );
        let j = f.issuer.journal().recent(10);
        assert!(
            j.iter().any(|e| e.event == "failover" && e.ca == "b"),
            "{j:?}"
        );
        assert!(
            j.iter().any(|e| e.event == "failure" && e.ca == "a"),
            "{j:?}"
        );
    }

    #[tokio::test]
    async fn a_rate_limit_and_a_local_failure_never_cause_a_switch() {
        let f = fixture();
        f.a.fail_with(rate_limited);
        let e = f.issuer.issue("x.example.test").await.unwrap_err();
        assert!(matches!(e, AcmeError::RateLimited { .. }));
        assert_eq!(
            (f.a.orders(), f.b.orders()),
            (1, 0),
            "a rate limit is waited out, not routed around"
        );
        f.a.fail_with(local);
        let e = f.issuer.issue("x.example.test").await.unwrap_err();
        assert!(matches!(e, AcmeError::Local(_)));
        assert_eq!(f.b.orders(), 0, "our own failure fails at every CA");
        // Neither counts against the CA.
        let v = f.issuer.views();
        assert_eq!(v[0].consecutive_failures, 0);
        assert_eq!(
            f.issuer.alerts().count(AlertKind::Failover)
                + f.issuer.alerts().count(AlertKind::CaBenched),
            0
        );
    }

    #[tokio::test]
    async fn consecutive_failures_bench_the_ca_so_later_orders_go_to_the_standby_first() {
        let f = fixture();
        f.a.fail_with(server_error);
        for _ in 0..3 {
            f.issuer.issue("x.example.test").await.unwrap();
        }
        assert_eq!(f.a.orders(), 3, "three consecutive failures");
        assert_eq!(f.issuer.alerts().count(AlertKind::CaBenched), 1);
        let v = f.issuer.views();
        assert_eq!(v[0].benched_until, T0 + 3600);
        // Benched: the standby is now tried FIRST, and the primary is not touched.
        f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!((f.a.orders(), f.b.orders()), (3, 4));
        assert_eq!(
            f.issuer.alerts().count(AlertKind::Failover),
            3,
            "the fourth order did not need a fall back"
        );
    }

    #[tokio::test]
    async fn the_bench_expires_doubles_on_repeat_and_a_success_forgives_everything() {
        let f = fixture();
        f.a.fail_with(server_error);
        for _ in 0..3 {
            f.issuer.issue("x.example.test").await.unwrap();
        }
        // After the bench the primary is tried first again; still broken -> ONE failure re-benches, for twice as long.
        f.now.store(T0 + 3601, SeqCst);
        f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(f.a.orders(), 4);
        assert_eq!(
            f.issuer.views()[0].benched_until,
            T0 + 3601 + 7200,
            "second bench is twice as long"
        );
        // Heal and wait it out: the primary issues again and the bench level resets.
        f.a.heal();
        f.now.store(T0 + 3601 + 7201, SeqCst);
        let m = f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(f.issuer.ca_name(&m).as_deref(), Some("a"));
        assert_eq!(f.issuer.alerts().count(AlertKind::CaRecovered), 1);
        f.a.fail_with(server_error);
        for _ in 0..3 {
            f.issuer.issue("x.example.test").await.unwrap();
        }
        let v = f.issuer.views();
        assert_eq!(
            v[0].benched_until,
            T0 + 3601 + 7201 + 3600,
            "a recovered CA starts again from the shortest bench"
        );
    }

    #[tokio::test]
    async fn the_bench_is_capped() {
        let mut p = policy(vec![
            entry("a", CaStatus::Active, "a.test"),
            entry("b", CaStatus::Standby, "b.test"),
        ]);
        p.failover.bench_secs = 100;
        p.failover.bench_max_secs = 250;
        let f = fixture_with(p);
        f.a.fail_with(server_error);
        let mut t = T0;
        let mut lengths = Vec::new();
        for _ in 0..5 {
            for _ in 0..3 {
                f.issuer.issue("x.example.test").await.unwrap();
                if f.issuer.views()[0].benched_until > t {
                    break;
                }
            }
            let until = f.issuer.views()[0].benched_until;
            lengths.push(until - t);
            t = until + 1;
            f.now.store(t, SeqCst);
        }
        assert_eq!(lengths, [100, 200, 250, 250, 250]);
    }

    #[tokio::test]
    async fn fall_back_is_bounded_per_day_and_the_bound_is_alerted() {
        let mut p = policy(vec![
            entry("a", CaStatus::Active, "a.test"),
            entry("b", CaStatus::Standby, "b.test"),
        ]);
        p.failover.max_failovers_per_day = 2;
        p.failover.fail_threshold = 1000; // never bench in this test
        let f = fixture_with(p);
        f.a.fail_with(server_error);
        assert!(f.issuer.issue("x.example.test").await.is_ok());
        assert!(f.issuer.issue("x.example.test").await.is_ok());
        let e = f
            .issuer
            .issue("x.example.test")
            .await
            .expect_err("the third fall back in a day is refused");
        assert_eq!(
            e.class(),
            FailureClass::CaSide,
            "the primary's error is what is returned: {e}"
        );
        assert_eq!(f.b.orders(), 2, "the standby was not asked a third time");
        assert_eq!(
            f.issuer.alerts().count(AlertKind::FailoverBudgetExhausted),
            1
        );
        // A day later the budget is back.
        f.now.store(T0 + 24 * 3600 + 1, SeqCst);
        assert!(f.issuer.issue("x.example.test").await.is_ok());
    }

    #[tokio::test]
    async fn each_ca_is_tried_once_per_order_and_the_first_error_is_returned() {
        let f = fixture();
        f.a.fail_with(server_error);
        f.b.fail_with(|| AcmeError::Rejected {
            status: 403,
            detail: "no".into(),
        });
        let e = f.issuer.issue("x.example.test").await.unwrap_err();
        assert_eq!((f.a.orders(), f.b.orders()), (1, 1));
        assert!(matches!(e, AcmeError::Rejected { status: 503, .. }), "{e}");
    }

    #[tokio::test]
    async fn replaces_goes_only_to_the_ca_that_issued_the_certificate() {
        let f = fixture();
        let first = f.issuer.issue("x.example.test").await.unwrap(); // from a
        f.issuer
            .issue_replacing("x.example.test", &first)
            .await
            .unwrap();
        assert_eq!(
            f.a.orders.lock().unwrap().iter().filter(|o| o.1).count(),
            1,
            "a renewal at the issuing CA names the old certificate"
        );
        // The primary fails: the standby gets a plain order, not a `replaces` for a certificate it never issued.
        f.a.fail_with(server_error);
        f.issuer
            .issue_replacing("x.example.test", &first)
            .await
            .unwrap();
        assert_eq!(f.b.orders.lock().unwrap().iter().filter(|o| o.1).count(), 0);
        assert_eq!(f.b.orders(), 1);
    }

    #[tokio::test]
    async fn a_ca_not_on_the_list_or_not_allowed_to_issue_is_never_contacted() {
        let f = fixture();
        f.issuer.set_standing("a", Some(CaStatus::Distrusted));
        f.issuer.set_standing("b", Some(CaStatus::Distrusted)); // would remove everyone: the guard keeps one
        let _ = f.issuer.issue("x.example.test").await;
        let before = f.connector.connects.load(SeqCst);
        // Retire both for real in the file: nothing may be ordered, and no connection is even attempted.
        let mut p = f.issuer.policy().as_ref().clone();
        p.cas[0].status = CaStatus::Distrusted;
        p.cas[1].status = CaStatus::Retiring;
        f.issuer.set_policy(p);
        let e = f.issuer.issue("x.example.test").await.unwrap_err();
        assert!(
            matches!(&e, AcmeError::Local(m) if m.contains("no CA on the allow-list is eligible")),
            "{e}"
        );
        assert_eq!(f.connector.connects.load(SeqCst), before);
        assert_eq!(f.issuer.alerts().count(AlertKind::NoEligibleCa), 1);
    }

    #[tokio::test]
    async fn a_distrusted_cas_certificates_migrate_and_revocation_still_reaches_that_ca() {
        let f = fixture();
        let m = f.issuer.issue("x.example.test").await.unwrap(); // from a
        assert_eq!(f.issuer.migration(&m), Migration::None);
        let mut p = f.issuer.policy().as_ref().clone();
        p.cas[0].status = CaStatus::Distrusted;
        f.issuer.set_policy(p);
        assert_eq!(f.issuer.migration(&m), Migration::Distrusted);
        // New orders go to b; the revocation of the old certificate goes to a, which is no longer eligible.
        let replaced = f
            .issuer
            .issue_replacing("x.example.test", &m)
            .await
            .unwrap();
        assert_eq!(f.issuer.ca_name(&replaced).as_deref(), Some("b"));
        f.issuer.revoke(&m).await.unwrap();
        assert_eq!(f.a.revoked.lock().unwrap().len(), 1);
        assert_eq!(f.b.revoked.lock().unwrap().len(), 0);
        // Retiring is a migration too, not an emergency.
        let mut p = f.issuer.policy().as_ref().clone();
        p.cas[0].status = CaStatus::Retiring;
        f.issuer.set_policy(p);
        assert_eq!(f.issuer.migration(&m), Migration::Retiring);
        // A certificate nobody can attribute is not migrated, and cannot be revoked blind.
        let stranger = CertMaterial {
            chain_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
            key_pem: String::new(),
        };
        assert_eq!(f.issuer.migration(&stranger), Migration::None);
        assert!(f.issuer.revoke(&stranger).await.is_err());
    }

    fn verdict(ca: &str, v: TrustVerdict) -> CaTrust {
        CaTrust {
            ca: ca.into(),
            mozilla: v.clone(),
            chrome: v.clone(),
            combined: v,
        }
    }

    #[tokio::test]
    async fn a_confirmed_distrust_verdict_switches_the_fleet_to_the_standby_and_an_unknown_one_does_nothing(
    ) {
        let f = fixture();
        let distrusted = || {
            vec![verdict(
                "a",
                TrustVerdict::Distrusted {
                    reason: "root removed".into(),
                },
            )]
        };
        // One evaluation is not enough (confirmations = 2).
        assert!(f.issuer.apply_trust(&distrusted()).is_empty());
        assert_eq!(f.issuer.effective("a"), CaStatus::Active);
        // A failed fetch in between changes nothing and does not reset the streak.
        assert!(f
            .issuer
            .apply_trust(&[verdict(
                "a",
                TrustVerdict::Unknown {
                    reason: "fetch failed".into()
                }
            )])
            .is_empty());
        assert_eq!(f.issuer.apply_trust(&distrusted()), ["a"]);
        assert_eq!(f.issuer.effective("a"), CaStatus::Distrusted);
        let m = f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(
            f.issuer.ca_name(&m).as_deref(),
            Some("b"),
            "new certificates come from the standby"
        );
        assert_eq!(f.issuer.alerts().count(AlertKind::StandingChanged), 1);
        // The CAA plan drops a.
        let plan = f.issuer.caa_plan(&[]);
        assert_eq!(
            plan.records
                .issue
                .iter()
                .map(|i| i.domain.as_str())
                .collect::<Vec<_>>(),
            ["b.test"]
        );
        // Trusted again (twice) clears the escalation.
        let trusted = || vec![verdict("a", TrustVerdict::Trusted)];
        assert!(f.issuer.apply_trust(&trusted()).is_empty());
        assert_eq!(f.issuer.apply_trust(&trusted()), ["a"]);
        assert_eq!(f.issuer.effective("a"), CaStatus::Active);
    }

    #[tokio::test]
    async fn a_pending_distrust_makes_the_ca_retiring_so_it_stops_being_chosen_and_its_certificates_move(
    ) {
        let f = fixture();
        let pending = || {
            vec![verdict(
                "a",
                TrustVerdict::DistrustPending {
                    after: T0 + 30 * 86400,
                },
            )]
        };
        f.issuer.apply_trust(&pending());
        f.issuer.apply_trust(&pending());
        assert_eq!(f.issuer.effective("a"), CaStatus::Retiring);
        let m = f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(f.issuer.ca_name(&m).as_deref(), Some("b"));
        assert_eq!(f.a.orders(), 0);
    }

    #[tokio::test]
    async fn accounts_are_learned_remembered_pinned_and_a_mismatch_refuses_the_ca() {
        let f = fixture();
        let failed = f.issuer.connect_all().await;
        assert!(failed.is_empty());
        let accounts = f.issuer.accounts();
        assert_eq!(accounts["a"], "https://a.example.test/acct/1");
        assert_eq!(accounts["b"], "https://b.example.test/acct/1");
        let plan = f.issuer.caa_plan(&["dns-01".to_string()]);
        assert!(plan.unbound.is_empty());
        assert_eq!(
            plan.records.issue.len(),
            2,
            "both CAs are authorised in DNS before either is needed"
        );

        // A pinned account that the CA does not hand back is refused, with an alert.
        let mut p = policy(vec![
            entry("a", CaStatus::Active, "a.test"),
            entry("b", CaStatus::Standby, "b.test"),
        ]);
        p.cas[0].account_uri = Some("https://a.example.test/acct/PINNED".into());
        let g = fixture_with(p);
        let e = g.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(
            g.issuer.ca_name(&e).as_deref(),
            Some("b"),
            "the CA that handed out the wrong account was skipped"
        );
        assert_eq!(g.issuer.alerts().count(AlertKind::AccountMismatch), 1);
        assert_eq!(
            g.a.orders(),
            0,
            "no order was placed at an account we did not pin"
        );
    }

    #[tokio::test]
    async fn a_standby_that_is_down_at_boot_is_reported_and_connected_at_its_first_use() {
        let f = fixture();
        f.connector.down.lock().unwrap().insert("b".into());
        let failed = f.issuer.connect_all().await;
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, "b");
        let plan = f.issuer.caa_plan(&[]);
        assert_eq!(
            plan.unbound,
            ["b"],
            "no account yet: left out of CAA rather than published unbound"
        );
        f.connector.down.lock().unwrap().clear();
        f.a.fail_with(server_error);
        let m = f.issuer.issue("x.example.test").await.unwrap();
        assert_eq!(f.issuer.ca_name(&m).as_deref(), Some("b"));
        assert!(f.issuer.caa_plan(&[]).unbound.is_empty());
    }

    #[tokio::test]
    async fn health_ledger_and_accounts_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!(
            "ca-state-{}",
            crate::entropy::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state = StatePaths::in_dir(&dir);
        let build = |connector: Arc<Connector>, now: Arc<AtomicI64>| {
            MultiCaIssuer::with_clock(
                policy(vec![
                    entry("a", CaStatus::Active, "a.test"),
                    entry("b", CaStatus::Standby, "b.test"),
                ]),
                connector,
                &state,
                Arc::new(move || now.load(SeqCst)),
            )
            .unwrap()
        };
        let f = fixture();
        let issuer = build(f.connector.clone(), f.now.clone());
        f.a.fail_with(server_error);
        let m = {
            let mut last = None;
            for _ in 0..3 {
                last = Some(issuer.issue("x.example.test").await.unwrap());
            }
            last.unwrap()
        };
        drop(issuer);

        // "Restart": a new issuer over the same files remembers the bench, the account book and who issued what.
        let restarted = build(f.connector.clone(), f.now.clone());
        assert_eq!(
            restarted.views()[0].benched_until,
            T0 + 3600,
            "the bench survives"
        );
        assert_eq!(restarted.ca_name(&m).as_deref(), Some("b"));
        assert_eq!(restarted.accounts().len(), 2);
        assert!(
            !restarted.issued_serials().is_empty(),
            "the serials of what was issued survive too (the CT monitor needs them)"
        );
        let before = f.b.orders();
        restarted.issue("x.example.test").await.unwrap();
        assert_eq!(
            f.a.orders(),
            3,
            "the benched primary is not retried after a restart"
        );
        assert_eq!(f.b.orders(), before + 1);
        let files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(files.iter().all(|f| !f.ends_with(".tmp")), "{files:?}");
        // A damaged account book is refused, not replaced.
        std::fs::write(dir.join("ca-accounts.json"), "{broken").unwrap();
        assert!(MultiCaIssuer::new(
            f.issuer.policy().as_ref().clone(),
            f.connector.clone(),
            &state
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_journal_rotates_and_returns_the_most_recent_events() {
        let dir = std::env::temp_dir().join(format!(
            "ca-journal-{}",
            crate::entropy::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let j = Journal::open(dir.join("j.jsonl")).unwrap();
        for i in 0..5 {
            j.append(i, "e", "a", &format!("n{i}"));
        }
        let recent = j.recent(2);
        assert_eq!(
            recent.iter().map(|e| e.detail.as_str()).collect::<Vec<_>>(),
            ["n3", "n4"]
        );
        let big = "x".repeat(400);
        for i in 0..6000 {
            j.append(i, "e", "a", &big);
        }
        assert!(dir.join("j.jsonl.1").exists(), "rotated at 2 MiB");
        assert!(
            std::fs::metadata(dir.join("j.jsonl")).unwrap().len() <= JOURNAL_ROTATE_BYTES + 1000
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
