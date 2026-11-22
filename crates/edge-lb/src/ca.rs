//! The edge's side of CA resilience: telemetry, health findings, and the background loops that keep
//! the CA policy, the CAA records, the root-program watch and the CT monitor current.
//!
//! The mechanics live in `transport` ([`transport::ca_policy`], [`transport::ca_resilience`],
//! [`transport::ca_trust`], [`transport::ct_monitor`]); this module is what makes them visible and
//! alive in a running edge:
//!
//! * [`CaTelemetry`] holds the newest view of every CA, the newest root-program verdicts, the newest
//!   CT report and whether the RNG self-check passed. It is written by the loops below and read by
//!   [`crate::metrics`].
//! * [`findings`] turns that into operator-facing findings (`/control/health` and the metrics counts
//!   come from the same list, so they cannot disagree).
//! * [`render_prometheus`] is the `edge_lb_ca_*` / `edge_lb_ct_*` / `edge_lb_rng_*` exposition, among
//!   them `edge_lb_ca_distrust_pending` and `edge_lb_ca_distrusted`.
//! * The loops: [`policy_reload_loop`] (the allow-list file, polled), [`caa_sync_loop`] (CAA follows
//!   the policy and the accounts), [`trust_loop`] (CCADB + Chrome Root Store), [`ct_loop`] (CT logs).
//!
//! **Nothing here takes an outage action on a fetch failure.** An unreachable or unparseable root
//! program or CT source is recorded as an error and an `unknown` verdict; only a successfully parsed
//! document that says a CA's roots are gone can move certificates.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{json, Value};
use tracing::{info, warn};
use transport::acme_renew::{CertStatus, Migration};
use transport::ca_policy::{CaPolicy, CaStatus, PolicyFinding, Severity};
use transport::ca_resilience::{AlertKind, CaAlert, CaView, MultiCaIssuer};
use transport::ca_trust::{observe, TrustSnapshot, TrustVerdict, TrustWatch};
use transport::ct_monitor::{CtFinding, CtMonitor, CtReport, Expected};
use transport::dns_health::CaaPolicy;
use transport::edge::{CertMaterial, APEXES};
use transport::edge_dns::ZoneAuthority;

/// Validation method the zones' CAA pins for names under our own apexes.
pub const CAA_VALIDATION_METHOD: &str = "dns-01";
/// The validation method used for customers' own hostnames.
pub const CUSTOMER_VALIDATION_METHOD: &str = "http-01";

/// Customer hostnames queried per CT pass. crt.sh is a shared public service: one query per name,
/// spaced, capped.
const CT_MAX_CUSTOMER_NAMES: usize = 50;
/// Pause between CT queries.
const CT_QUERY_SPACING: Duration = Duration::from_secs(5);
/// A trust fetch older than this is stale: it is reported, never acted on.
const TRUST_STALE_AFTER_SECS: i64 = 36 * 3600;
/// Most recent CA alerts shown in `/control/health`.
const RECENT_ALERTS: usize = 20;

// ── telemetry ─────────────────────────────────────────────────────────────────────────────

/// One operator-facing finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaFinding {
    pub severity: Severity,
    pub kind: &'static str,
    pub subject: String,
    pub detail: String,
}

fn sev(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// Everything the endpoints show about CA resilience.
#[derive(Clone, Debug, Default)]
pub struct CaSnapshot {
    /// The multi-CA issuer is wired (certificate hosting is on).
    pub enabled: bool,
    pub updated_at: i64,
    pub views: Vec<CaView>,
    pub policy_findings: Vec<PolicyFinding>,
    pub alert_counts: Vec<(AlertKind, u64)>,
    pub recent_alerts: Vec<CaAlert>,
    /// Eligible CAs left out of CAA because their account is not known yet.
    pub caa_unbound: Vec<String>,
    /// Held certificates per issuing CA, and how many of them are waiting to be moved.
    pub held_by_ca: BTreeMap<String, u64>,
    pub migrating: BTreeMap<(String, &'static str), u64>,
    pub trust: Option<TrustSnapshot>,
    pub trust_enabled: bool,
    pub trust_runs: u64,
    /// Unix time the Mozilla / Chrome data was last fetched and parsed (0: never).
    pub trust_success: [i64; 2],
    pub ct: Option<CtReport>,
    pub ct_enabled: bool,
    pub ct_runs: u64,
    pub ct_success: i64,
    /// Held certificates that lack embedded SCTs or are precertificates.
    pub obtained: Vec<CtFinding>,
    pub scts_required: bool,
    pub policy_loaded_at: i64,
    pub policy_reload_errors: u64,
    pub rng_selfcheck: Option<bool>,
    pub fips_build: bool,
}

/// Shared, mutex-guarded [`CaSnapshot`]; one per [`crate::edge_state::EdgeState`].
#[derive(Default)]
pub struct CaTelemetry {
    inner: Mutex<CaSnapshot>,
}

impl CaTelemetry {
    fn with<T>(&self, f: impl FnOnce(&mut CaSnapshot) -> T) -> T {
        f(&mut self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    #[must_use]
    pub fn snapshot(&self) -> CaSnapshot {
        self.with(|s| s.clone())
    }

    pub fn set_enabled(&self, trust: bool, ct: bool, scts_required: bool, loaded_at: i64) {
        self.with(|s| {
            s.enabled = true;
            s.trust_enabled = trust;
            s.ct_enabled = ct;
            s.scts_required = scts_required;
            s.policy_loaded_at = loaded_at;
        });
    }

    pub fn record_rng_selfcheck(&self, ok: bool) {
        self.with(|s| {
            s.rng_selfcheck = Some(ok);
            s.fips_build = transport::entropy::fips_build();
        });
    }

    pub fn record_policy_reload(&self, ok: bool, now: i64) {
        self.with(|s| {
            if ok {
                s.policy_loaded_at = now;
            } else {
                s.policy_reload_errors = s.policy_reload_errors.saturating_add(1);
            }
        });
    }

    pub fn record_trust(&self, snap: TrustSnapshot) {
        self.with(|s| {
            s.trust_runs = s.trust_runs.saturating_add(1);
            if snap.mozilla_error.is_none() {
                s.trust_success[0] = snap.checked_at;
            }
            if snap.chrome_error.is_none() {
                s.trust_success[1] = snap.checked_at;
            }
            s.trust = Some(snap);
        });
    }

    pub fn record_ct(&self, report: CtReport) {
        self.with(|s| {
            s.ct_runs = s.ct_runs.saturating_add(1);
            if report.errors.is_empty() {
                s.ct_success = report.checked_at;
            }
            s.ct = Some(report);
        });
    }

    pub fn record_obtained(&self, findings: Vec<CtFinding>) {
        self.with(|s| s.obtained = findings);
    }

    /// Refresh everything derived from the issuer and the certificate status.
    pub fn refresh(&self, issuer: &MultiCaIssuer, certs: &[CertStatus], now: i64) {
        let views = issuer.views();
        let policy_findings = issuer.lint();
        let alerts = issuer.alerts();
        let alert_counts = AlertKind::ALL
            .iter()
            .map(|k| (*k, alerts.count(*k)))
            .collect();
        let mut recent = alerts.recent();
        let skip = recent.len().saturating_sub(RECENT_ALERTS);
        recent.drain(..skip);
        let unbound = issuer
            .caa_plan(&[CAA_VALIDATION_METHOD.to_string()])
            .unbound;
        let mut held: BTreeMap<String, u64> = BTreeMap::new();
        let mut migrating: BTreeMap<(String, &'static str), u64> = BTreeMap::new();
        for c in certs {
            if let Some(ca) = &c.ca {
                *held.entry(ca.clone()).or_default() += 1;
                let reason = match c.migration {
                    Migration::None => continue,
                    Migration::Retiring => "retiring",
                    Migration::Distrusted => "distrusted",
                };
                *migrating.entry((ca.clone(), reason)).or_default() += 1;
            }
        }
        self.with(|s| {
            s.enabled = true;
            s.updated_at = now;
            s.views = views;
            s.policy_findings = policy_findings;
            s.alert_counts = alert_counts;
            s.recent_alerts = recent;
            s.caa_unbound = unbound;
            s.held_by_ca = held;
            s.migrating = migrating;
        });
    }
}

// ── findings ──────────────────────────────────────────────────────────────────────────────

/// The findings behind `/control/health`'s `ca` section and the findings counts in the metrics.
#[must_use]
pub fn findings(s: &CaSnapshot, now: i64) -> Vec<CaFinding> {
    let mut out = Vec::new();
    let mut add = |severity, kind, subject: &str, detail: String| {
        out.push(CaFinding {
            severity,
            kind,
            subject: subject.to_string(),
            detail,
        })
    };
    if !s.enabled {
        return out;
    }
    if s.rng_selfcheck == Some(false) {
        add(
            Severity::Critical,
            "rng_selfcheck_failed",
            "",
            "the startup RNG self-check failed; no key was generated".into(),
        );
    }
    for f in &s.policy_findings {
        add(
            f.severity,
            "ca_policy",
            f.ca.as_deref().unwrap_or(""),
            f.message.clone(),
        );
    }
    for v in &s.views {
        if v.benched_until > now {
            add(
                Severity::Warning,
                "ca_benched",
                &v.name,
                format!(
                    "failing ({} consecutive); tried last until {}: {}",
                    v.consecutive_failures,
                    v.benched_until,
                    v.last_error.as_deref().unwrap_or("")
                ),
            );
        }
        let waiting: u64 = s
            .migrating
            .iter()
            .filter(|((ca, _), _)| *ca == v.name)
            .map(|(_, n)| *n)
            .sum();
        if waiting > 0 {
            let severity = if v.effective == CaStatus::Distrusted {
                Severity::Error
            } else {
                Severity::Warning
            };
            add(
                severity,
                "ca_certificates_awaiting_migration",
                &v.name,
                format!(
                    "{waiting} certificate(s) from this {} CA are waiting to be replaced",
                    v.effective
                ),
            );
        }
    }
    for ca in &s.caa_unbound {
        add(Severity::Warning, "ca_not_in_caa", ca, "this CA may issue but is not in the CAA records yet: its ACME account is not known (it was unreachable at registration). A switch to it would fail CAA".into());
    }
    if let Some(t) = &s.trust {
        for c in &t.cas {
            match &c.combined {
                TrustVerdict::Distrusted { reason } => add(
                    Severity::Critical,
                    "ca_distrusted",
                    &c.ca,
                    format!("a root program has distrusted this CA: {reason}"),
                ),
                TrustVerdict::DistrustPending { after } => {
                    let soon = *after != i64::MIN && *after - now < 90 * 86_400;
                    add(
                        if soon || *after == i64::MIN {
                            Severity::Error
                        } else {
                            Severity::Warning
                        },
                        "ca_distrust_pending",
                        &c.ca,
                        if *after == i64::MIN {
                            "some of this CA's roots are already gone from a root program"
                                .to_string()
                        } else {
                            format!("a root program will stop trusting new certificates from this CA after unix time {after}")
                        },
                    )
                }
                TrustVerdict::Trusted | TrustVerdict::Unknown { .. } => {}
            }
        }
        for (ca, d) in &t.unwatched {
            add(Severity::Warning, "ca_unwatched_root", ca, d.clone());
        }
        if let Some(e) = &t.mozilla_error {
            add(
                Severity::Info,
                "ca_trust_source_unavailable",
                "mozilla",
                e.clone(),
            );
        }
        if let Some(e) = &t.chrome_error {
            add(
                Severity::Info,
                "ca_trust_source_unavailable",
                "chrome",
                e.clone(),
            );
        }
    }
    if s.trust_enabled && s.trust_runs > 0 {
        for (i, program) in ["mozilla", "chrome"].iter().enumerate() {
            if s.trust_success[i] == 0 || now - s.trust_success[i] > TRUST_STALE_AFTER_SECS {
                add(Severity::Warning, "ca_trust_stale", program, format!("no successful {program} root-program fetch in the last {} hours: CA distrust cannot be detected from this source (nothing is changed because of that)", TRUST_STALE_AFTER_SECS / 3600));
            }
        }
    }
    if let Some(r) = &s.ct {
        for f in &r.findings {
            add(f.severity, f.kind.as_str(), &f.name, f.detail.clone());
        }
    }
    for f in &s.obtained {
        add(f.severity, f.kind.as_str(), &f.name, f.detail.clone());
    }
    let alert_window = now - 3600;
    let recent_failover = s
        .recent_alerts
        .iter()
        .filter(|a| {
            a.at >= alert_window
                && matches!(
                    a.kind,
                    AlertKind::Failover
                        | AlertKind::FailoverBudgetExhausted
                        | AlertKind::AccountMismatch
                )
        })
        .count();
    if recent_failover > 0 {
        add(
            Severity::Warning,
            "ca_failover_recent",
            "",
            format!("{recent_failover} CA fail-over event(s) in the last hour"),
        );
    }
    out
}

/// The worst severity among [`findings`], if any is above `Info`.
#[must_use]
pub fn worst(s: &CaSnapshot, now: i64) -> Option<Severity> {
    findings(s, now)
        .into_iter()
        .map(|f| f.severity)
        .filter(|s| *s > Severity::Info)
        .max()
}

// ── exposition ────────────────────────────────────────────────────────────────────────────

fn esc(v: &str) -> String {
    v.chars().fold(String::with_capacity(v.len()), |mut s, c| {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            c => s.push(c),
        }
        s
    })
}

struct X(String);

impl X {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: i64) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{k}=\"{}\"", esc(v));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {value}");
    }
}

fn n(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The `edge_lb_ca_*`, `edge_lb_ct_*` and `edge_lb_rng_*` families, appended to the scrape.
#[must_use]
pub fn render_prometheus(s: &CaSnapshot, now: i64) -> String {
    let mut x = X(String::new());
    x.family(
        "edge_lb_ca_enabled",
        "gauge",
        "1 when the multi-CA issuer is running.",
    );
    x.sample("edge_lb_ca_enabled", &[], i64::from(s.enabled));
    x.family(
        "edge_lb_rng_selfcheck_ok",
        "gauge",
        "1 when the startup RNG self-check passed (0: failed; absent: not run).",
    );
    if let Some(ok) = s.rng_selfcheck {
        x.sample("edge_lb_rng_selfcheck_ok", &[], i64::from(ok));
    }
    x.family(
        "edge_lb_fips_build",
        "gauge",
        "1 when this binary uses the FIPS-validated aws-lc module.",
    );
    x.sample("edge_lb_fips_build", &[], i64::from(s.fips_build));
    if !s.enabled {
        return x.0;
    }

    x.family("edge_lb_ca_status", "gauge", "Each CA's configured and effective status (value 1; effective can be worse than configured after a root-program signal).");
    for v in &s.views {
        x.sample(
            "edge_lb_ca_status",
            &[
                ("ca", &v.name),
                ("configured", v.configured.as_str()),
                ("effective", v.effective.as_str()),
            ],
            1,
        );
    }
    x.family(
        "edge_lb_ca_eligible",
        "gauge",
        "1 when new certificates may be ordered from the CA.",
    );
    x.family(
        "edge_lb_ca_benched",
        "gauge",
        "1 while the CA is tried last because it failed repeatedly.",
    );
    x.family(
        "edge_lb_ca_consecutive_failures",
        "gauge",
        "Consecutive CA-side failures of the CA.",
    );
    x.family(
        "edge_lb_ca_issued_total",
        "counter",
        "Certificates the CA has issued to this edge (since the health file began).",
    );
    x.family(
        "edge_lb_ca_failures_total",
        "counter",
        "CA-side failures of the CA (since the health file began).",
    );
    x.family(
        "edge_lb_ca_certificates",
        "gauge",
        "Held certificates issued by the CA.",
    );
    for v in &s.views {
        let l = [("ca", v.name.as_str())];
        x.sample(
            "edge_lb_ca_eligible",
            &l,
            i64::from(v.effective.may_issue()),
        );
        x.sample("edge_lb_ca_benched", &l, i64::from(v.benched_until > now));
        x.sample(
            "edge_lb_ca_consecutive_failures",
            &l,
            i64::from(v.consecutive_failures),
        );
        x.sample("edge_lb_ca_issued_total", &l, n(v.issued));
        x.sample("edge_lb_ca_failures_total", &l, n(v.failures));
        x.sample(
            "edge_lb_ca_certificates",
            &l,
            n(s.held_by_ca.get(&v.name).copied().unwrap_or(0)),
        );
    }
    x.family(
        "edge_lb_ca_migration_pending",
        "gauge",
        "Held certificates waiting to be replaced because their CA is retiring or distrusted.",
    );
    for ((ca, reason), count) in &s.migrating {
        x.sample(
            "edge_lb_ca_migration_pending",
            &[("ca", ca), ("reason", reason)],
            n(*count),
        );
    }
    x.family(
        "edge_lb_ca_alerts_total",
        "counter",
        "CA alerts raised since start, by kind.",
    );
    for (kind, count) in &s.alert_counts {
        x.sample(
            "edge_lb_ca_alerts_total",
            &[("kind", kind.as_str())],
            n(*count),
        );
    }
    x.family(
        "edge_lb_ca_caa_unbound",
        "gauge",
        "Eligible CAs left out of CAA because their account is not known.",
    );
    x.sample(
        "edge_lb_ca_caa_unbound",
        &[],
        i64::try_from(s.caa_unbound.len()).unwrap_or(0),
    );
    x.family(
        "edge_lb_ca_policy_loaded_timestamp_seconds",
        "gauge",
        "Unix time the CA allow-list was last loaded.",
    );
    x.sample(
        "edge_lb_ca_policy_loaded_timestamp_seconds",
        &[],
        s.policy_loaded_at,
    );
    x.family(
        "edge_lb_ca_policy_reload_errors_total",
        "counter",
        "Reloads of the CA allow-list file that were refused (the previous policy stays in force).",
    );
    x.sample(
        "edge_lb_ca_policy_reload_errors_total",
        &[],
        n(s.policy_reload_errors),
    );
    x.family(
        "edge_lb_ca_policy_findings",
        "gauge",
        "CA policy findings by severity.",
    );
    for severity in [
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ] {
        x.sample(
            "edge_lb_ca_policy_findings",
            &[("severity", sev(severity))],
            i64::try_from(
                s.policy_findings
                    .iter()
                    .filter(|f| f.severity == severity)
                    .count(),
            )
            .unwrap_or(0),
        );
    }

    // ── root-program standing
    x.family("edge_lb_ca_distrust_pending", "gauge", "1 when a root program has scheduled distrust of the CA's roots (or some of them are already gone): the CA is treated as retiring.");
    x.family("edge_lb_ca_distrusted", "gauge", "1 when a root program no longer trusts new certificates from the CA: the CA is treated as distrusted.");
    x.family("edge_lb_ca_distrust_after_timestamp_seconds", "gauge", "Unix time after which a root program stops trusting new certificates from the CA (series exist only for CAs with a scheduled distrust).");
    if let Some(t) = &s.trust {
        for c in &t.cas {
            if let TrustVerdict::DistrustPending { after } = &c.combined {
                if *after != i64::MIN {
                    x.sample(
                        "edge_lb_ca_distrust_after_timestamp_seconds",
                        &[("ca", &c.ca)],
                        *after,
                    );
                }
            }
        }
    }
    x.family("edge_lb_ca_trust_verdict", "gauge", "Each program's verdict per CA (value 1): trusted, distrust_pending, distrusted or unknown.");
    if let Some(t) = &s.trust {
        for c in &t.cas {
            x.sample(
                "edge_lb_ca_distrust_pending",
                &[("ca", &c.ca)],
                i64::from(matches!(c.combined, TrustVerdict::DistrustPending { .. })),
            );
            x.sample(
                "edge_lb_ca_distrusted",
                &[("ca", &c.ca)],
                i64::from(matches!(c.combined, TrustVerdict::Distrusted { .. })),
            );
            for (program, v) in [
                ("mozilla", &c.mozilla),
                ("chrome", &c.chrome),
                ("combined", &c.combined),
            ] {
                x.sample(
                    "edge_lb_ca_trust_verdict",
                    &[("ca", &c.ca), ("program", program), ("verdict", v.label())],
                    1,
                );
            }
        }
    }
    x.family(
        "edge_lb_ca_trust_last_success_timestamp_seconds",
        "gauge",
        "Unix time a root program's data was last fetched and parsed (0: never).",
    );
    x.sample(
        "edge_lb_ca_trust_last_success_timestamp_seconds",
        &[("program", "mozilla")],
        s.trust_success[0],
    );
    x.sample(
        "edge_lb_ca_trust_last_success_timestamp_seconds",
        &[("program", "chrome")],
        s.trust_success[1],
    );
    x.family(
        "edge_lb_ca_trust_runs_total",
        "counter",
        "Root-program watch passes completed.",
    );
    x.sample("edge_lb_ca_trust_runs_total", &[], n(s.trust_runs));
    x.family("edge_lb_ca_trust_source_errors", "gauge", "1 when the program's data could not be fetched or parsed in the newest pass (verdicts are then unknown, and nothing is changed).");
    x.sample(
        "edge_lb_ca_trust_source_errors",
        &[("program", "mozilla")],
        i64::from(s.trust.as_ref().is_some_and(|t| t.mozilla_error.is_some())),
    );
    x.sample(
        "edge_lb_ca_trust_source_errors",
        &[("program", "chrome")],
        i64::from(s.trust.as_ref().is_some_and(|t| t.chrome_error.is_some())),
    );
    x.family(
        "edge_lb_ca_unwatched_roots",
        "gauge",
        "Roots our certificates chain to that no CA's trust_roots covers.",
    );
    x.sample(
        "edge_lb_ca_unwatched_roots",
        &[],
        i64::try_from(s.trust.as_ref().map_or(0, |t| t.unwatched.len())).unwrap_or(0),
    );

    // ── certificate transparency
    x.family(
        "edge_lb_ct_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the last CT pass in which every query succeeded (0: never).",
    );
    x.sample(
        "edge_lb_ct_last_success_timestamp_seconds",
        &[],
        s.ct_success,
    );
    x.family(
        "edge_lb_ct_runs_total",
        "counter",
        "CT monitor passes completed.",
    );
    x.sample("edge_lb_ct_runs_total", &[], n(s.ct_runs));
    x.family(
        "edge_lb_ct_errors",
        "gauge",
        "CT queries that failed in the newest pass.",
    );
    x.sample(
        "edge_lb_ct_errors",
        &[],
        i64::try_from(s.ct.as_ref().map_or(0, |r| r.errors.len())).unwrap_or(0),
    );
    x.family(
        "edge_lb_ct_entries_seen",
        "gauge",
        "Logged certificates examined in the newest pass.",
    );
    x.sample(
        "edge_lb_ct_entries_seen",
        &[],
        i64::try_from(s.ct.as_ref().map_or(0, |r| r.entries_seen)).unwrap_or(0),
    );
    x.family(
        "edge_lb_ct_finding",
        "gauge",
        "Certificates for our names found in CT that we did not order, by kind and severity.",
    );
    let mut by: BTreeMap<(&'static str, &'static str), i64> = BTreeMap::new();
    for f in s.ct.iter().flat_map(|r| r.findings.iter()) {
        *by.entry((f.kind.as_str(), sev(f.severity))).or_default() += 1;
    }
    for ((kind, severity), count) in by {
        x.sample(
            "edge_lb_ct_finding",
            &[("kind", kind), ("severity", severity)],
            count,
        );
    }
    x.family(
        "edge_lb_cert_ct_defects",
        "gauge",
        "Held certificates lacking embedded SCTs or that are precertificates.",
    );
    x.sample(
        "edge_lb_cert_ct_defects",
        &[],
        i64::try_from(s.obtained.len()).unwrap_or(0),
    );

    x.family(
        "edge_lb_ca_findings",
        "gauge",
        "All CA-resilience findings by severity (the same list /control/health shows).",
    );
    let all = findings(s, now);
    for severity in [
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ] {
        x.sample(
            "edge_lb_ca_findings",
            &[("severity", sev(severity))],
            i64::try_from(all.iter().filter(|f| f.severity == severity).count()).unwrap_or(0),
        );
    }
    x.0
}

/// The `ca` object in `GET /control/health`.
#[must_use]
pub fn health_json(s: &CaSnapshot, now: i64) -> Value {
    if !s.enabled {
        return Value::Null;
    }
    json!({
        "updated_at": s.updated_at,
        "worst_severity": worst(s, now).map(sev),
        "cas": s.views.iter().map(|v| json!({
            "name": v.name,
            "configured": v.configured.as_str(),
            "effective": v.effective.as_str(),
            "eligible": v.effective.may_issue(),
            "benched_until": v.benched_until,
            "consecutive_failures": v.consecutive_failures,
            "last_error": v.last_error,
            "account_url": v.account_url,
            "certificates": s.held_by_ca.get(&v.name).copied().unwrap_or(0),
            "issued": v.issued,
            "failures": v.failures,
        })).collect::<Vec<_>>(),
        "caa_unbound": s.caa_unbound,
        "trust": s.trust.as_ref().map(|t| json!({
            "checked_at": t.checked_at,
            "mozilla_error": t.mozilla_error,
            "chrome_error": t.chrome_error,
            "last_success": {"mozilla": s.trust_success[0], "chrome": s.trust_success[1]},
            "verdicts": t.cas.iter().map(|c| json!({
                "ca": c.ca,
                "mozilla": verdict_json(&c.mozilla),
                "chrome": verdict_json(&c.chrome),
                "combined": verdict_json(&c.combined),
            })).collect::<Vec<_>>(),
            "unwatched": t.unwatched.iter().map(|(ca, d)| json!({"ca": ca, "detail": d})).collect::<Vec<_>>(),
        })),
        "ct": s.ct.as_ref().map(|r| json!({
            "checked_at": r.checked_at,
            "queries": r.queries,
            "entries_seen": r.entries_seen,
            "errors": r.errors,
            "last_success": s.ct_success,
        })),
        "alerts": s.recent_alerts.iter().map(|a| json!({"at": a.at, "kind": a.kind.as_str(), "ca": a.ca, "detail": a.detail})).collect::<Vec<_>>(),
        "findings": findings(s, now).iter().map(|f| json!({"severity": sev(f.severity), "kind": f.kind, "subject": f.subject, "detail": f.detail})).collect::<Vec<_>>(),
    })
}

fn verdict_json(v: &TrustVerdict) -> Value {
    match v {
        TrustVerdict::Trusted => json!({"verdict": "trusted"}),
        TrustVerdict::DistrustPending { after } => {
            json!({"verdict": "distrust_pending", "after": if *after == i64::MIN { Value::Null } else { json!(after) }})
        }
        TrustVerdict::Distrusted { reason } => json!({"verdict": "distrusted", "reason": reason}),
        TrustVerdict::Unknown { reason } => json!({"verdict": "unknown", "reason": reason}),
    }
}

// ── the loops ─────────────────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// What the loops need to see of the certificate store.
pub type HeldCerts = Arc<dyn Fn() -> Vec<(String, CertMaterial)> + Send + Sync>;

/// Poll `path` and apply it when it changes. A file that fails to load or validate is refused and
/// the policy in force stays (the failure is counted and logged): a typo cannot take the edge's
/// issuance away.
pub async fn policy_reload_loop(
    path: PathBuf,
    issuer: Arc<MultiCaIssuer>,
    telemetry: Arc<crate::edge_state::EdgeState>,
    every: Duration,
) {
    let mut last = file_stamp(&path);
    loop {
        tokio::time::sleep(every).await;
        let now_stamp = file_stamp(&path);
        if now_stamp == last {
            continue;
        }
        last = now_stamp;
        match reload_policy(&path, &issuer) {
            Ok(()) => {
                telemetry.ca.record_policy_reload(true, unix_now());
                info!(path = %path.display(), "CA policy reloaded");
            }
            Err(e) => {
                telemetry.ca.record_policy_reload(false, unix_now());
                warn!(path = %path.display(), error = %e, "CA policy reload refused; the previous policy stays in force");
            }
        }
    }
}

fn file_stamp(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    std::fs::metadata(path)
        .and_then(|m| m.modified().map(|t| (t, m.len())))
        .ok()
}

/// Load `path` and, if valid, make it the issuer's policy.
///
/// # Errors
/// The file is unreadable or not a valid policy.
pub fn reload_policy(path: &Path, issuer: &MultiCaIssuer) -> Result<(), String> {
    let policy = CaPolicy::load(path).map_err(|e| e.to_string())?;
    issuer.set_policy(policy);
    Ok(())
}

/// Keep the zones' CAA and the health check's expectation equal to what the policy and the known
/// accounts say they should be. Runs every `every`; cheap when nothing changed.
pub async fn caa_sync_loop(
    issuer: Arc<MultiCaIssuer>,
    authority: Arc<tokio::sync::Mutex<ZoneAuthority>>,
    live_caa: Arc<RwLock<CaaPolicy>>,
    every: Duration,
) {
    let mut last = None;
    loop {
        sync_caa_once(&issuer, &authority, &live_caa, &mut last).await;
        tokio::time::sleep(every).await;
    }
}

/// One CAA sync. `last` remembers what was published.
pub async fn sync_caa_once(
    issuer: &MultiCaIssuer,
    authority: &tokio::sync::Mutex<ZoneAuthority>,
    live_caa: &RwLock<CaaPolicy>,
    last: &mut Option<transport::edge_dns::CaaRecords>,
) {
    let plan = issuer.caa_plan(&[CAA_VALIDATION_METHOD.to_string()]);
    if last.as_ref() == Some(&plan.records) {
        return;
    }
    authority.lock().await.set_caa_records(&plan.records);
    *live_caa
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        plan.health_policy(Some(CUSTOMER_VALIDATION_METHOD));
    info!(issue = plan.records.issue.len(), issuewild = plan.records.issuewild.len(), unbound = ?plan.unbound, "CAA records published from the CA policy");
    *last = Some(plan.records);
}

/// One root-program pass: judge every CA, feed the verdicts to the issuer (which escalates only on
/// agreeing, successful evaluations), record the result.
pub async fn run_trust_once(
    state: &crate::edge_state::EdgeState,
    issuer: &MultiCaIssuer,
    watch: &TrustWatch,
    held: &HeldCerts,
    now: i64,
) -> TrustSnapshot {
    let chains = held()
        .into_iter()
        .filter_map(|(_, m)| issuer.attribute(&m).map(|ca| (ca, m.chain_pem)));
    let observed = observe(chains);
    let policy = issuer.policy();
    let snap = watch.check(&policy, &observed, now).await;
    for c in &snap.cas {
        if matches!(
            c.combined,
            TrustVerdict::Distrusted { .. } | TrustVerdict::DistrustPending { .. }
        ) {
            warn!(ca = %c.ca, verdict = c.combined.label(), "root-program distrust signal");
        }
    }
    issuer.apply_trust(&snap.cas);
    state.ca.record_trust(snap.clone());
    snap
}

/// [`run_trust_once`] every `every`, after a short delay so start-up is not slowed.
pub async fn trust_loop(
    state: Arc<crate::edge_state::EdgeState>,
    issuer: Arc<MultiCaIssuer>,
    watch: TrustWatch,
    held: HeldCerts,
    every: Duration,
) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        run_trust_once(&state, &issuer, &watch, &held, unix_now()).await;
        tokio::time::sleep(every).await;
    }
}

/// One CT pass over the platform apexes and the customer hostnames we hold certificates for.
pub async fn run_ct_once(
    state: &crate::edge_state::EdgeState,
    issuer: &MultiCaIssuer,
    monitor: &CtMonitor,
    held: &HeldCerts,
    now: i64,
) -> CtReport {
    let customer: Vec<String> = {
        let mut names: Vec<String> = state
            .registry
            .lock()
            .await
            .required_cert_names()
            .into_iter()
            .filter(|n| !n.starts_with("*.") && !APEXES.iter().any(|a| *n == a.zone))
            .collect();
        names.sort();
        names.dedup();
        names.truncate(CT_MAX_CUSTOMER_NAMES);
        names
    };
    let mut expected = Expected::default();
    for s in issuer.issued_serials() {
        expected.add_serial(&s);
    }
    for (_, m) in held() {
        expected.add_material(&m);
    }
    let apexes: Vec<String> = APEXES.iter().map(|a| a.zone.to_string()).collect();
    let report = monitor
        .check(&issuer.policy(), &apexes, &customer, &expected, now)
        .await;
    for f in report
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
    {
        warn!(kind = f.kind.as_str(), name = %f.name, issuer = ?f.issuer, serial = ?f.serial, "CT: {}", f.detail);
    }
    state.ca.record_ct(report.clone());
    report
}

/// [`run_ct_once`] every `every`.
pub async fn ct_loop(
    state: Arc<crate::edge_state::EdgeState>,
    issuer: Arc<MultiCaIssuer>,
    monitor: CtMonitor,
    held: HeldCerts,
    every: Duration,
) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        run_ct_once(&state, &issuer, &monitor, &held, unix_now()).await;
        tokio::time::sleep(every).await;
    }
}

/// Check every held certificate for CT defects (no embedded SCTs, or a precertificate) and record
/// them. Cheap enough to run on every renewal pass.
pub fn check_held(state: &crate::edge_state::EdgeState, monitor: &CtMonitor, held: &HeldCerts) {
    let mut out = Vec::new();
    for (name, m) in held().into_iter().take(crate::metrics::MAX_SERIES) {
        out.extend(monitor.check_obtained(&name, &m));
    }
    state.ca.record_obtained(out);
}

/// Spacing between CT queries is applied by the source; exposed for the doc table.
pub const CT_SPACING: Duration = CT_QUERY_SPACING;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use transport::ca_trust::CaTrust;
    use transport::ct_monitor::CtFindingKind;

    const NOW: i64 = 1_800_000_000;

    fn view(name: &str, configured: CaStatus, effective: CaStatus) -> CaView {
        CaView {
            name: name.into(),
            configured,
            effective,
            benched_until: 0,
            consecutive_failures: 0,
            last_error: None,
            account_url: Some(format!("https://{name}/acct/1")),
            issued: 3,
            failures: 1,
        }
    }

    fn base() -> CaSnapshot {
        CaSnapshot {
            enabled: true,
            updated_at: NOW,
            views: vec![
                view("le", CaStatus::Active, CaStatus::Active),
                view("gts", CaStatus::Standby, CaStatus::Standby),
            ],
            alert_counts: AlertKind::ALL.iter().map(|k| (*k, 0)).collect(),
            held_by_ca: [("le".to_string(), 4)].into_iter().collect(),
            trust_enabled: true,
            rng_selfcheck: Some(true),
            ..CaSnapshot::default()
        }
    }

    fn trust(ca: &str, combined: TrustVerdict) -> CaTrust {
        CaTrust {
            ca: ca.into(),
            mozilla: combined.clone(),
            chrome: combined.clone(),
            combined,
        }
    }

    fn snapshot_with(cas: Vec<CaTrust>) -> TrustSnapshot {
        TrustSnapshot {
            checked_at: NOW,
            cas,
            mozilla_error: None,
            chrome_error: None,
            unwatched: vec![],
        }
    }

    #[test]
    fn a_healthy_two_ca_edge_has_no_findings_above_info() {
        let mut s = base();
        s.trust = Some(snapshot_with(vec![
            trust("le", TrustVerdict::Trusted),
            trust("gts", TrustVerdict::Trusted),
        ]));
        s.trust_success = [NOW - 3600, NOW - 3600];
        s.trust_runs = 3;
        assert_eq!(worst(&s, NOW), None, "{:?}", findings(&s, NOW));
        let text = render_prometheus(&s, NOW);
        assert!(
            text.contains("edge_lb_ca_distrusted{ca=\"le\"} 0")
                && text.contains("edge_lb_ca_distrust_pending{ca=\"le\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("edge_lb_ca_eligible{ca=\"gts\"} 1")
                && text.contains("edge_lb_ca_certificates{ca=\"le\"} 4"),
            "{text}"
        );
        assert!(text.contains("edge_lb_rng_selfcheck_ok 1"), "{text}");
        assert!(health_json(&s, NOW)["findings"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_distrusted_ca_is_critical_in_health_and_set_in_the_metrics() {
        let mut s = base();
        s.views[0].effective = CaStatus::Distrusted;
        s.trust = Some(snapshot_with(vec![
            trust(
                "le",
                TrustVerdict::Distrusted {
                    reason: "root removed".into(),
                },
            ),
            trust("gts", TrustVerdict::Trusted),
        ]));
        s.trust_success = [NOW, NOW];
        s.trust_runs = 1;
        s.migrating.insert(("le".into(), "distrusted"), 4);
        let f = findings(&s, NOW);
        assert!(
            f.iter().any(|x| x.kind == "ca_distrusted"
                && x.severity == Severity::Critical
                && x.subject == "le"),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|x| x.kind == "ca_certificates_awaiting_migration"
                    && x.severity == Severity::Error),
            "{f:?}"
        );
        assert_eq!(worst(&s, NOW), Some(Severity::Critical));
        let text = render_prometheus(&s, NOW);
        assert!(
            text.contains("edge_lb_ca_distrusted{ca=\"le\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edge_lb_ca_distrusted{ca=\"gts\"} 0"),
            "{text}"
        );
        assert!(
            text.contains(
                "edge_lb_ca_status{ca=\"le\",configured=\"active\",effective=\"distrusted\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("edge_lb_ca_migration_pending{ca=\"le\",reason=\"distrusted\"} 4"),
            "{text}"
        );
        assert!(
            text.contains(
                "edge_lb_ca_trust_verdict{ca=\"le\",program=\"combined\",verdict=\"distrusted\"} 1"
            ),
            "{text}"
        );
        let j = health_json(&s, NOW);
        assert_eq!(j["worst_severity"], "critical");
        assert_eq!(
            j["trust"]["verdicts"][0]["combined"]["verdict"],
            "distrusted"
        );
        assert_eq!(j["cas"][0]["effective"], "distrusted");
    }

    #[test]
    fn a_pending_distrust_is_flagged_and_louder_when_it_is_close() {
        let mut s = base();
        s.trust_success = [NOW, NOW];
        s.trust_runs = 1;
        s.trust = Some(snapshot_with(vec![trust(
            "le",
            TrustVerdict::DistrustPending {
                after: NOW + 200 * 86_400,
            },
        )]));
        let f = findings(&s, NOW);
        let p = f.iter().find(|x| x.kind == "ca_distrust_pending").unwrap();
        assert_eq!(p.severity, Severity::Warning, "200 days out");
        s.trust = Some(snapshot_with(vec![trust(
            "le",
            TrustVerdict::DistrustPending {
                after: NOW + 30 * 86_400,
            },
        )]));
        assert_eq!(
            findings(&s, NOW)
                .iter()
                .find(|x| x.kind == "ca_distrust_pending")
                .unwrap()
                .severity,
            Severity::Error,
            "within 90 days"
        );
        let text = render_prometheus(&s, NOW);
        assert!(text.contains("edge_lb_ca_distrust_pending{ca=\"le\"} 1"));
        assert!(
            text.contains(&format!(
                "edge_lb_ca_distrust_after_timestamp_seconds{{ca=\"le\"}} {}",
                NOW + 30 * 86_400
            )),
            "{text}"
        );
    }

    #[test]
    fn an_unavailable_source_is_never_worse_than_a_warning_and_never_a_distrust() {
        let mut s = base();
        s.trust = Some(TrustSnapshot {
            checked_at: NOW,
            cas: vec![trust(
                "le",
                TrustVerdict::Unknown {
                    reason: "503".into(),
                },
            )],
            mozilla_error: Some("503".into()),
            chrome_error: Some("503".into()),
            unwatched: vec![],
        });
        s.trust_runs = 5;
        s.trust_success = [NOW - 3 * 86_400, 0];
        let f = findings(&s, NOW);
        assert!(f.iter().all(|x| x.severity <= Severity::Warning), "{f:?}");
        assert!(
            f.iter().filter(|x| x.kind == "ca_trust_stale").count() == 2,
            "{f:?}"
        );
        let text = render_prometheus(&s, NOW);
        assert!(
            text.contains("edge_lb_ca_distrusted{ca=\"le\"} 0")
                && text.contains("edge_lb_ca_trust_source_errors{program=\"mozilla\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn benching_unbound_standbys_ct_findings_and_missing_scts_all_surface() {
        let mut s = base();
        s.views[0].benched_until = NOW + 600;
        s.views[0].consecutive_failures = 2;
        s.caa_unbound = vec!["gts".into()];
        s.ct = Some(CtReport {
            checked_at: NOW,
            findings: vec![transport::ct_monitor::CtFinding {
                severity: Severity::Critical,
                kind: CtFindingKind::UnknownIssuer,
                name: "login.tascloud.app".into(),
                issuer: Some("O=Sketchy".into()),
                serial: Some("ab".into()),
                detail: "issued by Sketchy".into(),
            }],
            errors: vec!["503".into()],
            queries: 3,
            entries_seen: 9,
        });
        s.obtained = vec![transport::ct_monitor::CtFinding {
            severity: Severity::Error,
            kind: CtFindingKind::MissingEmbeddedScts,
            name: "*.tascloud.app".into(),
            issuer: None,
            serial: None,
            detail: "no SCTs".into(),
        }];
        let f = findings(&s, NOW);
        for kind in [
            "ca_benched",
            "ca_not_in_caa",
            "unknown_issuer",
            "missing_embedded_scts",
        ] {
            assert!(f.iter().any(|x| x.kind == kind), "{kind} in {f:?}");
        }
        assert_eq!(worst(&s, NOW), Some(Severity::Critical));
        let text = render_prometheus(&s, NOW);
        assert!(
            text.contains("edge_lb_ct_finding{kind=\"unknown_issuer\",severity=\"critical\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edge_lb_ca_benched{ca=\"le\"} 1")
                && text.contains("edge_lb_ca_caa_unbound 1")
                && text.contains("edge_lb_cert_ct_defects 1")
                && text.contains("edge_lb_ct_errors 1"),
            "{text}"
        );
    }

    #[test]
    fn a_disabled_edge_exports_only_the_rng_and_fips_gauges() {
        let s = CaSnapshot::default();
        let text = render_prometheus(&s, NOW);
        assert!(text.contains("edge_lb_ca_enabled 0") && text.contains("edge_lb_fips_build"));
        assert!(!text.contains("edge_lb_ca_status"));
        assert_eq!(health_json(&s, NOW), Value::Null);
        assert!(findings(&s, NOW).is_empty());
    }

    #[test]
    fn label_values_are_escaped() {
        let mut s = base();
        s.views[0].name = "we\"ird\nname".into();
        assert!(render_prometheus(&s, NOW).contains(r#"ca="we\"ird\nname""#));
    }
}
