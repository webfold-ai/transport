//! The CA allow-list: which certificate authorities this platform may obtain certificates from,
//! in what standing, and what that means for DNS (CAA) and for the renewal engine.
//!
//! The platform is *structurally* resistant to a CA losing browser trust only if (a) it can never
//! obtain a certificate from a CA nobody approved, (b) a second approved CA is already
//! authorised in DNS and already has an account, so switching is a configuration change and not
//! an emergency, and (c) the engine knows which certificates came from which CA so it can move
//! them. This module is (a) and the data for (b) and (c); [`crate::ca_resilience`] is the engine
//! side and [`crate::ca_trust`] the watch that tells us when to switch.
//!
//! ## The policy file
//! A JSON document ([`CaPolicy`]; `deny_unknown_fields`, so a typo is a refused file and not a
//! silently ignored setting). Each [`CaEntry`] names a CA by its ACME directory URL, the CAA
//! issuer domain it answers to, the ACME account we hold there (optionally pinned), any External
//! Account Binding, the names it appears under in a certificate's issuer, the roots whose standing
//! we watch, and a [`CaStatus`]:
//!
//! | status | may issue | in CAA | existing certificates |
//! |---|---|---|---|
//! | `active` | yes, preferred (file order) | yes | kept |
//! | `standby` | yes, only when no `active` CA can | yes | kept |
//! | `retiring` | no | no | replaced early |
//! | `distrusted` | no | no | replaced first, then revoked |
//!
//! **Nothing issues from a CA that is not on the list.** [`CaPolicy::admit`] is the gate every
//! issuing client is created through; an unknown directory URL, or a CA that is `retiring` or
//! `distrusted`, is refused. The CA's *effective* status can be worse than its configured one
//! (see [`CaPolicy::effective`]): a root-program distrust signal escalates it, never relaxes it.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::acme_renew::Migration;
use crate::edge_dns::{CaaIssuer, CaaRecords};

/// Largest policy file read. A policy is a few KiB.
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
/// Most CAs in a policy. More than a handful is a mistake, not a feature.
pub const MAX_CAS: usize = 16;

/// A CA's standing with us.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CaStatus {
    Active,
    Standby,
    Retiring,
    Distrusted,
}

impl CaStatus {
    /// Whether new certificates may be ordered from a CA in this status.
    #[must_use]
    pub fn may_issue(self) -> bool {
        matches!(self, CaStatus::Active | CaStatus::Standby)
    }

    /// Whether the CA's issuer domain belongs in the zones' CAA records. A retiring or distrusted
    /// CA is *removed* from CAA: the record is what stops a rogue or compromised path to it.
    #[must_use]
    pub fn in_caa(self) -> bool {
        self.may_issue()
    }

    /// What this status means for certificates already held from the CA.
    #[must_use]
    pub fn migration(self) -> Migration {
        match self {
            CaStatus::Active | CaStatus::Standby => Migration::None,
            CaStatus::Retiring => Migration::Retiring,
            CaStatus::Distrusted => Migration::Distrusted,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CaStatus::Active => "active",
            CaStatus::Standby => "standby",
            CaStatus::Retiring => "retiring",
            CaStatus::Distrusted => "distrusted",
        }
    }
}

impl fmt::Display for CaStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// External Account Binding credentials for a CA that needs them: the CA-issued key id and the
/// **path** of a file holding the base64url HMAC key (the key never lives in the policy).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EabSpec {
    pub kid: String,
    pub hmac_key_file: String,
}

/// A root whose standing in the root programs we watch.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootRef {
    /// SHA-256 of the root certificate's DER, hex — how CCADB and the Chrome Root Store list it.
    /// The robust form: a removed root is detected by its absence.
    #[serde(default)]
    pub sha256: Option<String>,
    /// The root's common name as CCADB lists it ("ISRG Root X1"). Convenient, but a name can match
    /// several roots (cross-signs); all of them are evaluated.
    #[serde(default)]
    pub name: Option<String>,
}

/// One CA the platform may use.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaEntry {
    /// Our name for it: lower-case letters, digits and `-`. Appears in metrics and the journal.
    pub name: String,
    /// The ACME directory URL. `https://` only (see [`CaPolicy::allow_loopback_http`]).
    pub directory_url: String,
    /// The CAA issuer domain this CA answers to (`letsencrypt.org`, `pki.goog`).
    pub caa_domain: String,
    pub status: CaStatus,
    /// The ACME account URL we expect to hold at this CA. If set, the account the CA gives us must
    /// be exactly this one, or the CA is refused (a different account means a different key
    /// identity than the one CAA is bound to). If unset it is learned at first registration and
    /// remembered by [`crate::ca_resilience::AccountBook`].
    #[serde(default)]
    pub account_uri: Option<String>,
    /// Path of this CA's ACME account key (created 0600 on first use). One account per CA.
    #[serde(default)]
    pub account_key_file: Option<String>,
    #[serde(default)]
    pub eab: Option<EabSpec>,
    #[serde(default)]
    pub contact: Option<String>,
    /// Substrings of the issuer common name or organization that identify certificates this CA
    /// issued ("Let's Encrypt", "Google Trust Services"). Used to attribute a certificate to its
    /// CA when we have no record of ordering it, and by the CT monitor to recognise legitimate
    /// issuance. Case-insensitive.
    #[serde(default)]
    pub issuer_names: Vec<String>,
    /// The roots whose root-program standing decides this CA's [`CaPolicy::effective`] status.
    #[serde(default)]
    pub trust_roots: Vec<RootRef>,
    /// Whether this CA issues wildcard certificates (published as `issuewild`).
    #[serde(default = "yes")]
    pub wildcard: bool,
    /// The ACME profile (draft-ietf-acme-profiles) to request, if the CA's directory offers it.
    #[serde(default)]
    pub profile: Option<String>,
    /// Free text: why this status, the incident link.
    #[serde(default)]
    pub note: Option<String>,
}

fn yes() -> bool {
    true
}

/// When and how the engine moves between CAs. Defaults are conservative.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Failover {
    /// Consecutive CA-side failures after which a CA is *benched* (tried last).
    #[serde(default = "d_threshold")]
    pub fail_threshold: u32,
    /// How long the first bench lasts; each repeat doubles it up to `bench_max_secs`.
    #[serde(default = "d_bench")]
    pub bench_secs: i64,
    #[serde(default = "d_bench_max")]
    pub bench_max_secs: i64,
    /// Most orders per rolling day that may be placed at a standby because the preferred CA
    /// failed. Past it the engine stops falling back and alerts: a standby that is being used for
    /// everything is a decision (flip the statuses), not a flap.
    #[serde(default = "d_failovers")]
    pub max_failovers_per_day: u32,
}

fn d_threshold() -> u32 {
    3
}
fn d_bench() -> i64 {
    3600
}
fn d_bench_max() -> i64 {
    24 * 3600
}
fn d_failovers() -> u32 {
    24
}

impl Default for Failover {
    fn default() -> Self {
        Failover {
            fail_threshold: d_threshold(),
            bench_secs: d_bench(),
            bench_max_secs: d_bench_max(),
            max_failovers_per_day: d_failovers(),
        }
    }
}

/// How root-program signals change a CA's standing.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustSettings {
    /// Let the distrust watch escalate a CA's effective status (never relax it). Default on.
    #[serde(default = "yes")]
    pub auto_escalate: bool,
    /// Successive successful evaluations that must agree before an escalation takes effect, so one
    /// bad fetch or a transient listing glitch cannot move the fleet.
    #[serde(default = "d_confirm")]
    pub confirmations: u32,
}

fn d_confirm() -> u32 {
    2
}

impl Default for TrustSettings {
    fn default() -> Self {
        TrustSettings {
            auto_escalate: true,
            confirmations: d_confirm(),
        }
    }
}

/// The allow-list.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaPolicy {
    /// Format version; this reader understands 1.
    pub version: u32,
    /// Permit `http://127.0.0.1` / `http://localhost` directories. For a local test CA only.
    #[serde(default)]
    pub allow_loopback_http: bool,
    pub cas: Vec<CaEntry>,
    #[serde(default)]
    pub failover: Failover,
    #[serde(default)]
    pub trust: TrustSettings,
}

/// A policy problem, or something the operator should know about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFinding {
    pub severity: Severity,
    pub ca: Option<String>,
    pub message: String,
}

/// A policy file that is not acceptable, or a CA that is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CA policy: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

fn err<T>(m: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(m.into()))
}

fn valid_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && s.contains('.')
}

fn valid_ca_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
}

impl CaPolicy {
    /// Parse and validate a policy document.
    ///
    /// # Errors
    /// Anything malformed, oversized, duplicated or unsafe; the message names the CA and field.
    pub fn from_json(text: &str) -> Result<Self, PolicyError> {
        if text.len() > MAX_POLICY_BYTES {
            return err(format!("policy is larger than {MAX_POLICY_BYTES} bytes"));
        }
        let policy: CaPolicy = serde_json::from_str(text)
            .map_err(|e| PolicyError(format!("not a valid policy document: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Read, bound and parse the policy file at `path`.
    ///
    /// # Errors
    /// Unreadable, too large, or not a valid policy.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let meta =
            std::fs::metadata(path).map_err(|e| PolicyError(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_POLICY_BYTES as u64 {
            return err(format!(
                "{} is larger than {MAX_POLICY_BYTES} bytes",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| PolicyError(format!("{}: {e}", path.display())))?;
        Self::from_json(&text)
    }

    /// A one-CA policy for a deployment that has not adopted the allow-list yet: the single CA is
    /// `active`, there is no standby, and [`Self::lint`] says so.
    ///
    /// # Errors
    /// The arguments do not make a valid entry.
    pub fn single(
        name: &str,
        directory_url: &str,
        caa_domain: &str,
        issuer_names: Vec<String>,
    ) -> Result<Self, PolicyError> {
        let loopback = directory_url.starts_with("http://127.0.0.1")
            || directory_url.starts_with("http://localhost");
        let policy = CaPolicy {
            version: 1,
            allow_loopback_http: loopback,
            cas: vec![CaEntry {
                name: name.to_string(),
                directory_url: directory_url.to_string(),
                caa_domain: caa_domain.to_string(),
                status: CaStatus::Active,
                account_uri: None,
                account_key_file: None,
                eab: None,
                contact: None,
                issuer_names,
                trust_roots: Vec::new(),
                wildcard: true,
                profile: None,
                note: None,
            }],
            failover: Failover::default(),
            trust: TrustSettings::default(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Structural validation. Failing it refuses the policy.
    ///
    /// # Errors
    /// The first problem found.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return err(format!(
                "unsupported policy version {} (this reader understands 1)",
                self.version
            ));
        }
        if self.cas.is_empty() || self.cas.len() > MAX_CAS {
            return err(format!(
                "a policy lists between 1 and {MAX_CAS} CAs, not {}",
                self.cas.len()
            ));
        }
        let (mut names, mut urls) = (HashSet::new(), HashSet::new());
        for ca in &self.cas {
            let who = format!("CA '{}'", ca.name);
            if !valid_ca_name(&ca.name) {
                return err(format!(
                    "CA name {:?} must be 1-32 lower-case letters, digits or '-'",
                    ca.name
                ));
            }
            if !names.insert(ca.name.clone()) {
                return err(format!("{who} is listed twice"));
            }
            if !urls.insert(normalize_url(&ca.directory_url)) {
                return err(format!(
                    "{who}: directory_url {} is already used by another entry",
                    ca.directory_url
                ));
            }
            let https = ca.directory_url.starts_with("https://") && ca.directory_url.len() > 8;
            let loopback_http = self.allow_loopback_http
                && (ca.directory_url.starts_with("http://127.0.0.1")
                    || ca.directory_url.starts_with("http://localhost"));
            if !https && !loopback_http {
                return err(format!("{who}: directory_url must be https:// (plain http is accepted only for a loopback test CA with allow_loopback_http)"));
            }
            if ca.directory_url.contains(char::is_whitespace) || ca.directory_url.len() > 512 {
                return err(format!("{who}: directory_url is malformed"));
            }
            if !valid_dns_name(&ca.caa_domain) {
                return err(format!(
                    "{who}: caa_domain {:?} is not a lower-case DNS name",
                    ca.caa_domain
                ));
            }
            if let Some(a) = &ca.account_uri {
                if !(a.starts_with("https://")
                    || (self.allow_loopback_http && a.starts_with("http://")))
                    || a.len() > 512
                    || a.contains([' ', ';', '"'])
                {
                    return err(format!(
                        "{who}: account_uri must be an https URL without spaces or ';'"
                    ));
                }
            }
            if let Some(e) = &ca.eab {
                if e.kid.is_empty() || e.hmac_key_file.is_empty() {
                    return err(format!("{who}: eab needs a kid and an hmac_key_file"));
                }
            }
            if ca
                .issuer_names
                .iter()
                .any(|n| n.trim().is_empty() || n.len() > 128)
                || ca.issuer_names.len() > 16
            {
                return err(format!(
                    "{who}: issuer_names entries must be 1-128 characters, at most 16"
                ));
            }
            if ca.trust_roots.len() > 32 {
                return err(format!("{who}: at most 32 trust_roots"));
            }
            for r in &ca.trust_roots {
                match (&r.sha256, &r.name) {
                    (Some(h), None) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                    (None, Some(n)) if !n.trim().is_empty() && n.len() <= 128 => {}
                    _ => return err(format!("{who}: a trust_roots entry has exactly one of a 64-hex-digit sha256 or a name")),
                }
            }
            if let Some(p) = &ca.profile {
                if p.is_empty()
                    || p.len() > 64
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return err(format!(
                        "{who}: profile must be 1-64 letters, digits, '-' or '_'"
                    ));
                }
            }
        }
        if self.failover.fail_threshold == 0
            || self.failover.bench_secs <= 0
            || self.failover.bench_max_secs < self.failover.bench_secs
        {
            return err(
                "failover: fail_threshold must be >= 1 and 0 < bench_secs <= bench_max_secs",
            );
        }
        if self.trust.confirmations == 0 || self.trust.confirmations > 10 {
            return err("trust.confirmations must be between 1 and 10");
        }
        Ok(())
    }

    /// The entry named `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CaEntry> {
        self.cas.iter().find(|c| c.name == name)
    }

    /// **The gate.** The entry for `directory_url` if — and only if — the CA is on the list and
    /// its effective status permits issuing. Every client that orders certificates is created
    /// through this; there is no other way to reach an ACME server from the engine.
    ///
    /// # Errors
    /// The URL is not on the list, or the CA is retiring/distrusted.
    pub fn admit(
        &self,
        directory_url: &str,
        overrides: &Standings,
    ) -> Result<&CaEntry, PolicyError> {
        let want = normalize_url(directory_url);
        let ca = self.cas.iter().find(|c| normalize_url(&c.directory_url) == want).ok_or_else(|| PolicyError(format!("{directory_url} is not on the CA allow-list; refusing to obtain certificates from it")))?;
        let status = self.effective(&ca.name, overrides);
        if !status.may_issue() {
            return err(format!(
                "CA '{}' is {status}; certificates are not ordered from it",
                ca.name
            ));
        }
        Ok(ca)
    }

    /// A CA's status after root-program signals: the configured status, escalated (never relaxed)
    /// by `overrides`. Guarded so the platform never ends up with no CA to issue from: if every
    /// issuing-eligible CA would be escalated away, the escalation of the least-bad one (a
    /// pending distrust before an outright one, then file order) is withheld and the shortfall is
    /// reported by [`Self::lint_with`].
    #[must_use]
    pub fn effective(&self, name: &str, overrides: &Standings) -> CaStatus {
        let Some(ca) = self.get(name) else {
            return CaStatus::Distrusted;
        };
        let escalated = |c: &CaEntry| -> CaStatus {
            if !self.trust.auto_escalate {
                return c.status;
            }
            c.status
                .max(overrides.get(&c.name).copied().unwrap_or(c.status))
        };
        if self.cas.iter().any(|c| escalated(c).may_issue()) {
            return escalated(ca);
        }
        // Every CA that could issue would be escalated away. Keep the least-bad one as configured:
        // the mildest signal first (a pending distrust before an outright one), then file order.
        let keeper = self
            .cas
            .iter()
            .filter(|c| c.status.may_issue())
            .min_by_key(|c| overrides.get(&c.name).copied().unwrap_or(c.status));
        match keeper {
            Some(k) if k.name == ca.name => ca.status,
            _ => escalated(ca),
        }
    }

    /// CAs that may issue, in preference order: `active` in file order, then `standby` in file
    /// order, by effective status.
    #[must_use]
    pub fn eligible<'a>(&'a self, overrides: &Standings) -> Vec<&'a CaEntry> {
        let mut out: Vec<(&CaEntry, CaStatus)> = self
            .cas
            .iter()
            .map(|c| (c, self.effective(&c.name, overrides)))
            .filter(|(_, s)| s.may_issue())
            .collect();
        out.sort_by_key(|(_, s)| *s); // Active < Standby; stable, so file order within a status
        out.into_iter().map(|(c, _)| c).collect()
    }

    /// The CAA records the zones should publish: the union of every issuing-eligible CA's issuer
    /// domain and known account URI (so a switch between them needs no DNS change), for `issue`
    /// and `issuewild` (wildcard-capable CAs only; if there are none, `issuewild ";"` forbids
    /// wildcard issuance). A CA whose account is not yet known is left out and named in
    /// [`CaaPlan::unbound`]: publishing its domain without an `accounturi` would let *any* account
    /// at that CA issue.
    #[must_use]
    pub fn caa_plan(
        &self,
        overrides: &Standings,
        accounts: &HashMap<String, String>,
        validation_methods: &[String],
    ) -> CaaPlan {
        let mut issue = Vec::new();
        let mut issuewild = Vec::new();
        let mut unbound = Vec::new();
        for ca in self.eligible(overrides) {
            let Some(uri) = ca
                .account_uri
                .clone()
                .or_else(|| accounts.get(&ca.name).cloned())
            else {
                unbound.push(ca.name.clone());
                continue;
            };
            let entry = CaaIssuer {
                domain: ca.caa_domain.clone(),
                account_uri: Some(uri),
                validation_methods: validation_methods.to_vec(),
            };
            if ca.wildcard {
                issuewild.push(entry.clone());
            }
            issue.push(entry);
        }
        CaaPlan {
            records: CaaRecords {
                issue,
                issuewild,
                forbid_wildcard: false,
            }
            .finish(),
            unbound,
        }
    }

    /// Operator-facing findings about the policy itself, ignoring live standing.
    #[must_use]
    pub fn lint(&self) -> Vec<PolicyFinding> {
        self.lint_with(&Standings::new())
    }

    /// [`Self::lint`] with the live standing overrides.
    #[must_use]
    pub fn lint_with(&self, overrides: &Standings) -> Vec<PolicyFinding> {
        let mut out = Vec::new();
        let finding = |severity, ca: Option<&str>, message: String| PolicyFinding {
            severity,
            ca: ca.map(str::to_string),
            message,
        };
        let eligible = self.eligible(overrides);
        if eligible.is_empty() {
            out.push(finding(Severity::Critical, None, "no CA is eligible to issue: every CA is retiring or distrusted. Existing certificates keep serving; nothing new can be obtained until a CA is made active".into()));
        } else if eligible.len() == 1 {
            out.push(finding(Severity::Warning, eligible.first().map(|c| c.name.as_str()), "only one CA is eligible to issue: there is no fallback if it fails or loses trust. Add a standby CA".into()));
        }
        let distinct_domains: HashSet<&str> =
            eligible.iter().map(|c| c.caa_domain.as_str()).collect();
        if eligible.len() > 1 && distinct_domains.len() == 1 {
            out.push(finding(Severity::Warning, None, "all eligible CAs share one CAA issuer domain: they are one operator, and a loss of that operator's trust takes them all".into()));
        }
        for ca in &self.cas {
            let eff = self.effective(&ca.name, overrides);
            if eff != ca.status {
                out.push(finding(Severity::Error, Some(&ca.name), format!("configured {} but treated as {eff} because a root program has distrusted or scheduled distrust of its roots", ca.status)));
            } else if self.trust.auto_escalate
                && ca.status.may_issue()
                && overrides.get(&ca.name).is_some_and(|s| *s > ca.status)
            {
                out.push(finding(Severity::Critical, Some(&ca.name), "a root program signals distrust of this CA, but it is the last one able to issue so it stays eligible; add another CA now".into()));
            }
            if ca.status.may_issue() && ca.trust_roots.is_empty() {
                out.push(finding(Severity::Warning, Some(&ca.name), "no trust_roots configured: root-program distrust of this CA cannot be detected".into()));
            }
            if ca.status.may_issue() && ca.issuer_names.is_empty() {
                out.push(finding(Severity::Warning, Some(&ca.name), "no issuer_names configured: certificates from this CA cannot be recognised by the CT monitor".into()));
            }
            if ca.status.may_issue() && ca.account_uri.is_none() {
                out.push(finding(
                    Severity::Info,
                    Some(&ca.name),
                    "account_uri is not pinned; it is learned at first registration".into(),
                ));
            }
        }
        out
    }
}

/// What is known about a well-known CA, to fill in the watch inputs of a single-CA deployment that
/// has not adopted a policy file. **Taken from CCADB and the Chrome Root Store as fetched on
/// 2026-10-22 and not re-verified by any other means**; a policy file overrides all of it.
#[derive(Clone, Copy, Debug)]
pub struct KnownCa {
    pub caa_domain: &'static str,
    /// Substrings of the issuing intermediates' names.
    pub issuer_names: &'static [&'static str],
    /// Common names of the roots its chains lead to, as CCADB lists them.
    pub root_names: &'static [&'static str],
}

impl KnownCa {
    #[must_use]
    pub fn issuer_names(&self) -> Vec<String> {
        self.issuer_names.iter().map(|s| (*s).to_string()).collect()
    }

    #[must_use]
    pub fn trust_roots(&self) -> Vec<RootRef> {
        self.root_names
            .iter()
            .map(|n| RootRef {
                sha256: None,
                name: Some((*n).to_string()),
            })
            .collect()
    }
}

/// The well-known CA behind `directory_url`, if it is one of the production directories this
/// platform ships defaults for (Let's Encrypt, Google Trust Services).
#[must_use]
pub fn known_ca(directory_url: &str) -> Option<KnownCa> {
    match normalize_url(directory_url).as_str() {
        "https://acme-v02.api.letsencrypt.org/directory" => Some(KnownCa {
            caa_domain: "letsencrypt.org",
            issuer_names: &["Let's Encrypt"],
            root_names: &["ISRG Root X1", "ISRG Root X2"],
        }),
        "https://dv.acme-v02.api.pki.goog/directory" => Some(KnownCa {
            caa_domain: "pki.goog",
            issuer_names: &["Google Trust Services"],
            root_names: &["GTS Root R1", "GTS Root R4"],
        }),
        _ => None,
    }
}

/// What [`CaPolicy::caa_plan`] says to publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaPlan {
    pub records: CaaRecords,
    /// Eligible CAs left out of the records because their account URL is not known yet.
    pub unbound: Vec<String>,
}

impl CaaPlan {
    /// What the DNS health check should hold the published CAA to: every issuer in the plan with
    /// its own account and validation methods. `customer_method` is the method used for customers'
    /// own names (`http-01`).
    #[must_use]
    pub fn health_policy(&self, customer_method: Option<&str>) -> crate::dns_health::CaaPolicy {
        let mut issuers: Vec<crate::dns_health::IssuerExpectation> = Vec::new();
        for i in self
            .records
            .issue
            .iter()
            .chain(self.records.issuewild.iter())
        {
            let row = crate::dns_health::IssuerExpectation {
                domain: i.domain.clone(),
                account_uri: i.account_uri.clone(),
                validation_methods: i.validation_methods.clone(),
            };
            if !issuers.contains(&row) {
                issuers.push(row);
            }
        }
        crate::dns_health::CaaPolicy {
            allowed_issuers: Vec::new(),
            account_uri: None,
            validation_methods: Vec::new(),
            customer_method: customer_method.map(str::to_string),
            issuers,
        }
    }
}

/// Live standing overrides, by CA name: only ever *worse* than configured (`Retiring` for a
/// pending distrust, `Distrusted` for an effective one).
pub type Standings = HashMap<String, CaStatus>;

/// `https://Host/dir/` and `https://host/dir` are one directory.
#[must_use]
pub fn normalize_url(u: &str) -> String {
    let u = u.trim();
    let (scheme, rest) = u.split_once("://").unwrap_or(("", u));
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    format!(
        "{}://{}/{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase(),
        path.trim_end_matches('/')
    )
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn entry(name: &str, status: CaStatus, domain: &str) -> CaEntry {
        CaEntry {
            name: name.into(),
            directory_url: format!("https://{name}.example.test/directory"),
            caa_domain: domain.into(),
            status,
            account_uri: None,
            account_key_file: None,
            eab: None,
            contact: None,
            issuer_names: vec![format!("{name} CA")],
            trust_roots: vec![RootRef {
                sha256: None,
                name: Some(format!("{name} Root")),
            }],
            wildcard: true,
            profile: None,
            note: None,
        }
    }

    pub fn policy(cas: Vec<CaEntry>) -> CaPolicy {
        let p = CaPolicy {
            version: 1,
            allow_loopback_http: false,
            cas,
            failover: Failover::default(),
            trust: TrustSettings::default(),
        };
        p.validate().unwrap();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const GOOD: &str = r#"{
      "version": 1,
      "cas": [
        {"name": "le", "directory_url": "https://acme-v02.api.letsencrypt.org/directory", "caa_domain": "letsencrypt.org",
         "status": "active", "issuer_names": ["Let's Encrypt"], "trust_roots": [{"name": "ISRG Root X1"}], "profile": "tlsserver"},
        {"name": "gts", "directory_url": "https://dv.acme-v02.api.pki.goog/directory", "caa_domain": "pki.goog",
         "status": "standby", "account_key_file": "/etc/edge/gts.key",
         "eab": {"kid": "k1", "hmac_key_file": "/etc/edge/gts.eab"}, "issuer_names": ["Google Trust Services"],
         "trust_roots": [{"sha256": "d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf"}]}
      ]
    }"#;

    #[test]
    fn a_good_policy_loads_and_orders_active_before_standby() {
        let p = CaPolicy::from_json(GOOD).unwrap();
        assert_eq!(p.cas.len(), 2);
        let order: Vec<&str> = p
            .eligible(&Standings::new())
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(order, ["le", "gts"]);
        assert_eq!(p.get("gts").unwrap().eab.as_ref().unwrap().kid, "k1");
    }

    #[test]
    fn a_ca_that_is_not_on_the_list_is_refused_and_so_is_one_that_may_not_issue() {
        let p = CaPolicy::from_json(GOOD).unwrap();
        let none = Standings::new();
        assert_eq!(
            p.admit("https://acme-v02.api.letsencrypt.org/directory", &none)
                .unwrap()
                .name,
            "le"
        );
        assert_eq!(
            p.admit("HTTPS://Dv.ACME-v02.api.pki.goog/directory/", &none)
                .unwrap()
                .name,
            "gts",
            "URL spelling is normalised"
        );
        for rogue in [
            "https://acme.zerossl.com/v2/DV90",
            "https://acme-v02.api.letsencrypt.org/directory/../x",
            "http://acme-v02.api.letsencrypt.org/directory",
            "",
        ] {
            let e = p.admit(rogue, &none).unwrap_err();
            assert!(e.0.contains("not on the CA allow-list"), "{rogue}: {e}");
        }
        let mut retiring = p.clone();
        retiring.cas[0].status = CaStatus::Retiring;
        assert!(retiring
            .admit("https://acme-v02.api.letsencrypt.org/directory", &none)
            .unwrap_err()
            .0
            .contains("retiring"));
        let mut distrusted = p.clone();
        distrusted.cas[1].status = CaStatus::Distrusted;
        assert!(distrusted
            .admit("https://dv.acme-v02.api.pki.goog/directory", &none)
            .unwrap_err()
            .0
            .contains("distrusted"));
    }

    #[test]
    fn caa_is_the_union_of_active_and_standby_with_each_cas_own_account() {
        let mut p = CaPolicy::from_json(GOOD).unwrap();
        let mut accounts = HashMap::new();
        accounts.insert(
            "le".to_string(),
            "https://acme-v02.api.letsencrypt.org/acme/acct/1".to_string(),
        );
        accounts.insert(
            "gts".to_string(),
            "https://dv.acme-v02.api.pki.goog/acme/acct/ZZ".to_string(),
        );
        let methods = vec!["dns-01".to_string()];
        let plan = p.caa_plan(&Standings::new(), &accounts, &methods);
        assert!(plan.unbound.is_empty());
        let domains: Vec<(&str, Option<&str>)> = plan
            .records
            .issue
            .iter()
            .map(|i| (i.domain.as_str(), i.account_uri.as_deref()))
            .collect();
        assert_eq!(
            domains,
            [
                (
                    "letsencrypt.org",
                    Some("https://acme-v02.api.letsencrypt.org/acme/acct/1")
                ),
                (
                    "pki.goog",
                    Some("https://dv.acme-v02.api.pki.goog/acme/acct/ZZ")
                )
            ]
        );
        assert_eq!(plan.records.issuewild.len(), 2, "both issue wildcards");

        // A standby without a known account is left out (never published unbound) and reported.
        accounts.remove("gts");
        let plan = p.caa_plan(&Standings::new(), &accounts, &methods);
        assert_eq!(plan.unbound, ["gts"]);
        assert_eq!(plan.records.issue.len(), 1);

        // A CA without wildcard support is in `issue` but not `issuewild`.
        accounts.insert(
            "gts".into(),
            "https://dv.acme-v02.api.pki.goog/acme/acct/ZZ".into(),
        );
        p.cas[1].wildcard = false;
        let plan = p.caa_plan(&Standings::new(), &accounts, &methods);
        assert_eq!(
            (plan.records.issue.len(), plan.records.issuewild.len()),
            (2, 1)
        );
        // With no wildcard-capable CA at all, wildcard issuance is forbidden outright.
        p.cas[0].wildcard = false;
        let plan = p.caa_plan(&Standings::new(), &accounts, &methods);
        assert!(plan.records.issuewild.is_empty() && plan.records.forbid_wildcard);
    }

    #[test]
    fn a_retiring_or_distrusted_ca_leaves_caa_and_its_certificates_get_a_migration() {
        let mut p = CaPolicy::from_json(GOOD).unwrap();
        let mut accounts = HashMap::new();
        accounts.insert("le".to_string(), "https://x/acct/1".to_string());
        accounts.insert("gts".to_string(), "https://y/acct/2".to_string());
        p.cas[0].status = CaStatus::Distrusted;
        let plan = p.caa_plan(&Standings::new(), &accounts, &[]);
        assert_eq!(plan.records.issue.len(), 1);
        assert_eq!(
            plan.records.issue[0].domain, "pki.goog",
            "the distrusted CA is gone from DNS"
        );
        assert_eq!(CaStatus::Distrusted.migration(), Migration::Distrusted);
        assert_eq!(CaStatus::Retiring.migration(), Migration::Retiring);
        assert_eq!(CaStatus::Standby.migration(), Migration::None);
    }

    #[test]
    fn root_program_signals_escalate_but_never_relax_and_never_remove_the_last_issuer() {
        let p = CaPolicy::from_json(GOOD).unwrap();
        let mut o = Standings::new();
        o.insert("le".into(), CaStatus::Distrusted);
        assert_eq!(p.effective("le", &o), CaStatus::Distrusted);
        assert_eq!(p.effective("gts", &o), CaStatus::Standby);
        assert_eq!(
            p.eligible(&o)
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["gts"],
            "the standby takes over"
        );
        // An override cannot make a distrusted CA better.
        let mut d = p.clone();
        d.cas[0].status = CaStatus::Distrusted;
        o.insert("le".into(), CaStatus::Active);
        assert_eq!(d.effective("le", &o), CaStatus::Distrusted);
        // If both would be escalated away, the platform keeps one able to issue.
        let mut both = Standings::new();
        both.insert("le".into(), CaStatus::Distrusted);
        both.insert("gts".into(), CaStatus::Retiring);
        let eligible: Vec<&str> = p.eligible(&both).iter().map(|c| c.name.as_str()).collect();
        assert_eq!(eligible.len(), 1, "never zero: {eligible:?}");
        assert!(p
            .lint_with(&both)
            .iter()
            .any(|f| f.severity == Severity::Critical));
        // Escalation can be switched off.
        let mut off = p.clone();
        off.trust.auto_escalate = false;
        assert_eq!(off.effective("le", &both), CaStatus::Active);
    }

    #[test]
    fn invalid_policies_are_refused_with_a_message_naming_the_problem() {
        let bad = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_str(GOOD).unwrap();
            edit(&mut v);
            CaPolicy::from_json(&v.to_string()).unwrap_err().0
        };
        assert!(bad(&|v| v["version"] = 2.into()).contains("version"));
        assert!(bad(&|v| v["cas"] = serde_json::json!([])).contains("between 1 and"));
        assert!(bad(&|v| v["cas"][1]["name"] = "le".into()).contains("listed twice"));
        assert!(bad(&|v| v["cas"][1]["name"] = "Bad Name".into()).contains("lower-case"));
        assert!(
            bad(&|v| v["cas"][1]["directory_url"] = v["cas"][0]["directory_url"].clone())
                .contains("already used")
        );
        assert!(
            bad(&|v| v["cas"][0]["directory_url"] = "http://acme.example/dir".into())
                .contains("https")
        );
        assert!(
            bad(&|v| v["cas"][0]["directory_url"] = "http://127.0.0.1:14000/dir".into())
                .contains("https"),
            "loopback http needs the opt-in"
        );
        assert!(
            bad(&|v| v["cas"][0]["caa_domain"] = "Letsencrypt.org".into()).contains("caa_domain")
        );
        assert!(bad(&|v| v["cas"][0]["caa_domain"] = "nodots".into()).contains("caa_domain"));
        assert!(bad(&|v| v["cas"][0]["status"] = "trusted".into()).contains("not a valid policy"));
        assert!(bad(&|v| v["cas"][0]["typo_field"] = 1.into()).contains("unknown field"));
        assert!(
            bad(&|v| v["cas"][0]["account_uri"] = "https://x/a;b".into()).contains("account_uri")
        );
        assert!(
            bad(&|v| v["cas"][0]["trust_roots"] = serde_json::json!([{"sha256": "abc"}]))
                .contains("trust_roots")
        );
        assert!(bad(&|v| v["cas"][0]["trust_roots"] =
            serde_json::json!([{"sha256": "a".repeat(64), "name": "x"}]))
        .contains("exactly one"));
        assert!(
            bad(&|v| v["failover"] = serde_json::json!({"fail_threshold": 0}))
                .contains("fail_threshold")
        );
        assert!(
            bad(&|v| v["trust"] = serde_json::json!({"confirmations": 0}))
                .contains("confirmations")
        );
        assert!(CaPolicy::from_json("{")
            .unwrap_err()
            .0
            .contains("not a valid"));
        assert!(CaPolicy::from_json(&" ".repeat(MAX_POLICY_BYTES + 1))
            .unwrap_err()
            .0
            .contains("larger"));
        // The loopback opt-in works for the test CA and nothing else.
        let mut v: serde_json::Value = serde_json::from_str(GOOD).unwrap();
        v["allow_loopback_http"] = true.into();
        v["cas"][0]["directory_url"] = "http://127.0.0.1:14000/dir".into();
        CaPolicy::from_json(&v.to_string()).unwrap();
        v["cas"][0]["directory_url"] = "http://evil.example/dir".into();
        assert!(CaPolicy::from_json(&v.to_string()).is_err());
    }

    #[test]
    fn lint_flags_a_single_ca_a_shared_operator_and_missing_watch_inputs() {
        let single = CaPolicy::single(
            "le",
            "https://acme-v02.api.letsencrypt.org/directory",
            "letsencrypt.org",
            vec![],
        )
        .unwrap();
        let findings = single.lint();
        assert!(findings.iter().any(|f| f.message.contains("no fallback")));
        assert!(findings
            .iter()
            .any(|f| f.message.contains("no trust_roots")));
        assert!(findings
            .iter()
            .any(|f| f.message.contains("no issuer_names")));
        let same_operator = policy(vec![
            entry("a", CaStatus::Active, "ca.test"),
            entry("b", CaStatus::Standby, "ca.test"),
        ]);
        assert!(same_operator
            .lint()
            .iter()
            .any(|f| f.message.contains("one operator")));
        let healthy = policy(vec![
            entry("a", CaStatus::Active, "ca.test"),
            entry("b", CaStatus::Standby, "other.test"),
        ]);
        assert!(
            healthy.lint().iter().all(|f| f.severity <= Severity::Info),
            "{:?}",
            healthy.lint()
        );
        let none = policy(vec![entry("a", CaStatus::Retiring, "ca.test")]);
        assert!(none.lint().iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn well_known_directories_get_watch_defaults_and_others_do_not() {
        let le = known_ca("https://acme-v02.api.letsencrypt.org/directory/").unwrap();
        assert_eq!(le.caa_domain, "letsencrypt.org");
        assert_eq!(le.trust_roots().len(), 2);
        assert!(known_ca("https://dv.acme-v02.api.pki.goog/directory").is_some());
        assert!(
            known_ca("https://acme-staging-v02.api.letsencrypt.org/directory").is_none(),
            "staging is not production"
        );
        assert!(known_ca("https://localhost:14000/dir").is_none());
    }

    #[test]
    fn the_policy_loads_from_a_file_and_refuses_an_oversized_one() {
        let dir = std::env::temp_dir().join(format!(
            "ca-policy-{}",
            crate::entropy::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("ca.json");
        std::fs::write(&f, GOOD).unwrap();
        assert_eq!(CaPolicy::load(&f).unwrap().cas.len(), 2);
        std::fs::write(&f, vec![b' '; MAX_POLICY_BYTES + 1]).unwrap();
        assert!(CaPolicy::load(&f).unwrap_err().0.contains("larger"));
        assert!(CaPolicy::load(&dir.join("missing.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
