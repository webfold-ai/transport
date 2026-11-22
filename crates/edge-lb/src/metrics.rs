//! Operational telemetry for the edge: what an on-call needs to know before a customer does.
//!
//! Two endpoints (mounted by [`crate::control`], behind the control secret like everything else
//! under `/control`):
//!
//! ```text
//! GET /control/metrics   Prometheus text exposition (version 0.0.4)
//! GET /control/health    one JSON document: overall status plus the findings behind it
//! ```
//!
//! and one background task, [`health_loop`], that runs `transport::dns_health` against the zones
//! the edge serves and the custom names it holds certificates for, and records the result here.
//!
//! ## What is exported
//!
//! | Family | Meaning |
//! |---|---|
//! | `edge_lb_cert_seconds_left{name}` | seconds to expiry (negative = expired) |
//! | `edge_lb_cert_lifetime_seconds{name}` | the certificate's whole validity (alert on a *fraction*) |
//! | `edge_lb_cert_consecutive_failures{name}` | failed renewal passes in a row |
//! | `edge_lb_cert_next_attempt_timestamp_seconds{name}` | when the engine will next try |
//! | `edge_lb_revocation_pending`, `_oldest_age_seconds`, `_max_attempts`, `_enqueue_failures_total` | the revocation backlog |
//! | `edge_lb_journal_*` | hostname-journal replay result and write failures |
//! | `edge_lb_tunnel_pipes{host}` | live tunnel pipes per hostname |
//! | `edge_lb_dns_rrsig_earliest_expiry_seconds{zone}` | earliest RRSIG expiry |
//! | `edge_lb_dns_ds_mismatch{zone}` | 1 when no DS matches a published DNSKEY |
//! | `edge_lb_dns_findings{severity}`, `edge_lb_dns_finding{kind,severity}`, `edge_lb_dns_caa_findings` | DNS health findings |
//! | `edge_lb_acme_account_key_age_seconds` | age of the ACME account key file |
//!
//! Names and zones are registry-validated hostnames, never free text, and label values are escaped
//! regardless. Per-name families are capped at [`MAX_SERIES`] so a registry that grows without
//! bound cannot grow a scrape without bound.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tracing::{info, warn};
use transport::acme_renew::{RevocationQueue, RevocationStatus};
use transport::dns_health::{
    run_checks, CaaPolicy, CaaScope, CaaTarget, DnsLookup, FindingKind, HealthConfig, HealthReport,
    RrsigThresholds, Severity,
};
use transport::edge::APEXES;

use crate::edge_state::EdgeState;
use crate::tunnel::TunnelInfo;

/// Most series any per-name family emits.
pub const MAX_SERIES: usize = 10_000;

/// The longest a single health run may take before it is abandoned (and counted).
const HEALTH_RUN_TIMEOUT: Duration = Duration::from_secs(300);

/// Hostname-journal counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JournalStats {
    /// A journal is configured (`EDGE_LB_HOSTNAME_JOURNAL`).
    pub enabled: bool,
    /// Boot replay has completed.
    pub replayed: bool,
    pub replay_ops: u64,
    /// Operations in the journal that no longer applied on replay (skipped, not fatal).
    pub replay_failed: u64,
    /// Appends that failed since boot: an accepted change that would not survive a restart.
    pub write_failures: u64,
}

/// The newest DNS health run.
#[derive(Clone, Debug)]
pub struct HealthSnapshot {
    pub report: HealthReport,
}

#[derive(Default)]
struct Inner {
    journal: JournalStats,
    health: Option<HealthSnapshot>,
    health_runs: u64,
    health_timeouts: u64,
    account_key_created: Option<i64>,
    revocation_enqueue_failures: u64,
    queue: Option<Arc<RevocationQueue>>,
    hosting: bool,
    /// Requests refused by `admission`, by rule label.
    admission_rejects: std::collections::BTreeMap<&'static str, u64>,
}

/// Everything the metrics and health endpoints report that is not derived on demand from the
/// registry, certificate store or tunnel table.
#[derive(Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub fn set_journal_enabled(&self, enabled: bool) {
        self.with(|i| i.journal.enabled = enabled);
    }

    pub fn record_replay(&self, total: u64, failed: u64) {
        self.with(|i| {
            i.journal.replayed = true;
            i.journal.replay_ops = total;
            i.journal.replay_failed = failed;
        });
    }

    pub fn record_journal_write_failure(&self) {
        self.with(|i| i.journal.write_failures = i.journal.write_failures.saturating_add(1));
    }

    #[must_use]
    pub fn journal(&self) -> JournalStats {
        self.with(|i| i.journal)
    }

    /// A request was refused by edge admission (`rule` is `admission::Rule::as_str`).
    pub fn record_admission_reject(&self, rule: &'static str) {
        self.with(|i| {
            let c = i.admission_rejects.entry(rule).or_insert(0);
            *c = c.saturating_add(1);
        });
    }

    /// Refusals so far, by rule.
    #[must_use]
    pub fn admission_rejects(&self) -> Vec<(&'static str, u64)> {
        self.with(|i| i.admission_rejects.iter().map(|(k, v)| (*k, *v)).collect())
    }

    /// Certificate hosting is on (otherwise the certificate and DNS families are empty by design).
    pub fn set_hosting(&self, on: bool) {
        self.with(|i| i.hosting = on);
    }

    pub fn set_account_key_created(&self, unix: Option<i64>) {
        self.with(|i| i.account_key_created = unix);
    }

    pub fn set_revocation_queue(&self, queue: Arc<RevocationQueue>) {
        self.with(|i| i.queue = Some(queue));
    }

    /// A release could not be recorded in the revocation queue (the certificate was kept and the
    /// engine's prune will retry).
    pub fn record_revocation_enqueue_failure(&self) {
        self.with(|i| {
            i.revocation_enqueue_failures = i.revocation_enqueue_failures.saturating_add(1)
        });
    }

    pub fn record_health(&self, report: HealthReport) {
        self.with(|i| {
            i.health_runs = i.health_runs.saturating_add(1);
            i.health = Some(HealthSnapshot { report });
        });
    }

    pub fn record_health_timeout(&self) {
        self.with(|i| i.health_timeouts = i.health_timeouts.saturating_add(1));
    }

    #[must_use]
    pub fn health(&self) -> Option<HealthSnapshot> {
        self.with(|i| i.health.clone())
    }

    fn revocations(&self) -> (Vec<RevocationStatus>, u64) {
        self.with(|i| {
            (
                i.queue.as_ref().map(|q| q.status()).unwrap_or_default(),
                i.revocation_enqueue_failures,
            )
        })
    }
}

// ── Prometheus exposition ─────────────────────────────────────────────────────────────────

/// Prometheus label-value escaping: backslash, double quote and newline.
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

struct Exposition(String);

impl Exposition {
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

fn severity_rank(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

/// The `edge_lb_dns_*` families: counters of runs, and the newest run's per-zone numbers and findings.
fn dns_section(
    x: &mut Exposition,
    health: Option<&HealthSnapshot>,
    health_runs: u64,
    health_timeouts: u64,
) {
    let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    x.family(
        "edge_lb_dns_health_runs_total",
        "counter",
        "DNS health runs completed.",
    );
    x.sample("edge_lb_dns_health_runs_total", &[], n(health_runs));
    x.family(
        "edge_lb_dns_health_timeouts_total",
        "counter",
        "DNS health runs abandoned for taking too long.",
    );
    x.sample("edge_lb_dns_health_timeouts_total", &[], n(health_timeouts));
    x.family(
        "edge_lb_dns_health_last_run_timestamp_seconds",
        "gauge",
        "Unix time of the newest completed DNS health run (0: none yet).",
    );
    x.sample(
        "edge_lb_dns_health_last_run_timestamp_seconds",
        &[],
        health.map_or(0, |h| h.report.checked_at),
    );
    if let Some(h) = health {
        x.family("edge_lb_dns_rrsig_earliest_expiry_seconds", "gauge", "Seconds until the earliest RRSIG over the zone's DNSKEY/SOA expires (negative: expired).");
        for z in h.report.zones.iter().take(MAX_SERIES) {
            if let Some(left) = z.rrsig_earliest_expiry_secs {
                x.sample(
                    "edge_lb_dns_rrsig_earliest_expiry_seconds",
                    &[("zone", &z.zone)],
                    left,
                );
            }
        }
        x.family(
            "edge_lb_dns_ds_mismatch",
            "gauge",
            "1 when the parent's DS matches none of the zone's DNSKEYs.",
        );
        for z in h.report.zones.iter().take(MAX_SERIES) {
            x.sample(
                "edge_lb_dns_ds_mismatch",
                &[("zone", &z.zone)],
                i64::from(z.ds_mismatch),
            );
        }
        x.family(
            "edge_lb_dns_zone_signed",
            "gauge",
            "1 when the zone is DNSSEC-signed.",
        );
        for z in h.report.zones.iter().take(MAX_SERIES) {
            x.sample(
                "edge_lb_dns_zone_signed",
                &[("zone", &z.zone)],
                i64::from(z.signed),
            );
        }
        x.family(
            "edge_lb_dns_servers_answering",
            "gauge",
            "Authoritative servers that answered authoritatively, per zone.",
        );
        for z in h.report.zones.iter().take(MAX_SERIES) {
            x.sample(
                "edge_lb_dns_servers_answering",
                &[("zone", &z.zone)],
                i64::try_from(z.servers_answering).unwrap_or(0),
            );
        }
        x.family(
            "edge_lb_dns_servers_total",
            "gauge",
            "Authoritative servers checked, per zone.",
        );
        for z in h.report.zones.iter().take(MAX_SERIES) {
            x.sample(
                "edge_lb_dns_servers_total",
                &[("zone", &z.zone)],
                i64::try_from(z.servers_total).unwrap_or(0),
            );
        }
        x.family(
            "edge_lb_dns_findings",
            "gauge",
            "Findings in the newest DNS health run, by severity.",
        );
        for sev in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ] {
            let count = h
                .report
                .findings
                .iter()
                .filter(|f| f.severity == sev)
                .count();
            x.sample(
                "edge_lb_dns_findings",
                &[("severity", sev.as_str())],
                i64::try_from(count).unwrap_or(0),
            );
        }
        x.family("edge_lb_dns_finding", "gauge", "Findings in the newest DNS health run, by kind and worst severity (series exist only for kinds present).");
        let mut by_kind: std::collections::BTreeMap<(&'static str, usize), (Severity, i64)> =
            std::collections::BTreeMap::new();
        for f in &h.report.findings {
            let e = by_kind
                .entry((f.kind.as_str(), severity_rank(f.severity)))
                .or_insert((f.severity, 0));
            e.1 += 1;
        }
        for ((kind, _), (sev, count)) in &by_kind {
            x.sample(
                "edge_lb_dns_finding",
                &[("kind", kind), ("severity", sev.as_str())],
                *count,
            );
        }
        x.family(
            "edge_lb_dns_caa_findings",
            "gauge",
            "CAA findings above info severity in the newest run (drift from the intended policy).",
        );
        x.sample(
            "edge_lb_dns_caa_findings",
            &[],
            i64::try_from(h.report.caa_findings()).unwrap_or(0),
        );
    }
}

/// The Prometheus text exposition of the edge's current state. `now` is unix seconds.
pub fn render_prometheus(state: &EdgeState, tunnels: &[TunnelInfo], now: i64) -> String {
    let mut x = Exposition(String::with_capacity(4096));
    let (journal, health, health_runs, health_timeouts, account_key_created, hosting) =
        state.metrics.with(|i| {
            (
                i.journal,
                i.health.clone(),
                i.health_runs,
                i.health_timeouts,
                i.account_key_created,
                i.hosting,
            )
        });

    x.family(
        "edge_lb_hosting_enabled",
        "gauge",
        "1 when certificate hosting (EDGE_LB_CERT_DIR) is on.",
    );
    x.sample("edge_lb_hosting_enabled", &[], i64::from(hosting));

    // ── certificates
    let certs = state.cert_status();
    x.family(
        "edge_lb_cert_seconds_left",
        "gauge",
        "Seconds until the certificate expires (negative: expired).",
    );
    for c in certs.iter().take(MAX_SERIES) {
        if let Some(left) = c.seconds_left {
            x.sample("edge_lb_cert_seconds_left", &[("name", &c.name)], left);
        }
    }
    x.family(
        "edge_lb_cert_lifetime_seconds",
        "gauge",
        "Total validity of the held certificate, to alert on a fraction of it.",
    );
    for c in certs.iter().take(MAX_SERIES) {
        if let Some(life) = state.cert_lifetime(&c.name) {
            x.sample("edge_lb_cert_lifetime_seconds", &[("name", &c.name)], life);
        }
    }
    x.family(
        "edge_lb_cert_consecutive_failures",
        "gauge",
        "Consecutive failed issuance/renewal attempts for the name.",
    );
    for c in certs.iter().take(MAX_SERIES) {
        x.sample(
            "edge_lb_cert_consecutive_failures",
            &[("name", &c.name)],
            i64::from(c.consecutive_failures),
        );
    }
    x.family(
        "edge_lb_cert_next_attempt_timestamp_seconds",
        "gauge",
        "Unix time before which the engine will not try the name again (0: not backing off).",
    );
    for c in certs.iter().take(MAX_SERIES) {
        x.sample(
            "edge_lb_cert_next_attempt_timestamp_seconds",
            &[("name", &c.name)],
            c.next_attempt,
        );
    }

    // ── revocation backlog
    let (pending, enqueue_failures) = state.metrics.revocations();
    x.family(
        "edge_lb_revocation_pending",
        "gauge",
        "Certificates queued for revocation that the CA has not yet revoked.",
    );
    x.sample(
        "edge_lb_revocation_pending",
        &[],
        i64::try_from(pending.len()).unwrap_or(i64::MAX),
    );
    x.family(
        "edge_lb_revocation_oldest_age_seconds",
        "gauge",
        "Age of the oldest pending revocation (0 when none).",
    );
    x.sample(
        "edge_lb_revocation_oldest_age_seconds",
        &[],
        pending
            .iter()
            .map(|p| (now - p.enqueued_at).max(0))
            .max()
            .unwrap_or(0),
    );
    x.family(
        "edge_lb_revocation_max_attempts",
        "gauge",
        "Failed attempts of the most-retried pending revocation.",
    );
    x.sample(
        "edge_lb_revocation_max_attempts",
        &[],
        pending
            .iter()
            .map(|p| i64::from(p.attempts))
            .max()
            .unwrap_or(0),
    );
    x.family(
        "edge_lb_revocation_enqueue_failures_total",
        "counter",
        "Releases whose certificate could not be queued for revocation (kept; prune retries).",
    );
    x.sample(
        "edge_lb_revocation_enqueue_failures_total",
        &[],
        i64::try_from(enqueue_failures).unwrap_or(i64::MAX),
    );

    // ── journal
    let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    x.family(
        "edge_lb_journal_enabled",
        "gauge",
        "1 when a hostname journal is configured.",
    );
    x.sample("edge_lb_journal_enabled", &[], i64::from(journal.enabled));
    x.family(
        "edge_lb_journal_replayed",
        "gauge",
        "1 once boot replay has completed.",
    );
    x.sample("edge_lb_journal_replayed", &[], i64::from(journal.replayed));
    x.family(
        "edge_lb_journal_replay_ops",
        "gauge",
        "Operations read from the journal at boot.",
    );
    x.sample("edge_lb_journal_replay_ops", &[], n(journal.replay_ops));
    x.family(
        "edge_lb_journal_replay_failed",
        "gauge",
        "Journal operations that no longer applied at boot and were skipped.",
    );
    x.sample(
        "edge_lb_journal_replay_failed",
        &[],
        n(journal.replay_failed),
    );
    x.family(
        "edge_lb_journal_write_failures_total",
        "counter",
        "Journal appends that failed: accepted changes that would not survive a restart.",
    );
    x.sample(
        "edge_lb_journal_write_failures_total",
        &[],
        n(journal.write_failures),
    );

    // ── tunnels
    x.family(
        "edge_lb_tunnel_pipes",
        "gauge",
        "Live tunnel pipes per enrolled hostname.",
    );
    for t in tunnels.iter().take(MAX_SERIES) {
        x.sample(
            "edge_lb_tunnel_pipes",
            &[("host", &t.hostname)],
            i64::try_from(t.pipes).unwrap_or(i64::MAX),
        );
    }

    dns_section(&mut x, health.as_ref(), health_runs, health_timeouts);

    // ── ACME account key
    x.family(
        "edge_lb_acme_account_key_age_seconds",
        "gauge",
        "Age of the ACME account key file (0 when unknown).",
    );
    x.sample(
        "edge_lb_acme_account_key_age_seconds",
        &[],
        account_key_created.map_or(0, |c| (now - c).max(0)),
    );

    // ── CA resilience: CA standing, root-program verdicts, CT findings, RNG self-check
    x.0.push_str(&crate::ca::render_prometheus(&state.ca.snapshot(), now));

    x.family(
        "edge_lb_admission_rejected_total",
        "counter",
        "Requests refused by edge admission (CGI argument injection, traversal, denied multipart fields, ...), by rule.",
    );
    // Every rule is exported, zero included, so `rate()` and absence alerts work from the first scrape.
    let rejects = state.metrics.admission_rejects();
    for rule in crate::admission::Rule::ALL {
        let n = rejects
            .iter()
            .find(|(k, _)| *k == rule.as_str())
            .map_or(0, |(_, v)| *v);
        x.sample(
            "edge_lb_admission_rejected_total",
            &[("rule", rule.as_str())],
            i64::try_from(n).unwrap_or(i64::MAX),
        );
    }

    x.0
}

// ── /control/health ───────────────────────────────────────────────────────────────────────

/// The overall verdict. `Critical` is "a customer is affected or will be within a day".
fn overall(
    state: &EdgeState,
    health: Option<&HealthSnapshot>,
    pending: &[RevocationStatus],
) -> &'static str {
    let certs = state.cert_status();
    let journal = state.metrics.journal();
    let dns_max = health.and_then(|h| h.report.max_severity());
    let ca_worst = crate::ca::worst(&state.ca.snapshot(), unix_now());
    if dns_max == Some(Severity::Critical)
        || ca_worst == Some(transport::ca_policy::Severity::Critical)
        || certs.iter().any(|c| c.seconds_left.is_some_and(|s| s < 0))
    {
        return "critical";
    }
    if dns_max.is_some_and(|s| s >= Severity::Warning)
        || ca_worst.is_some_and(|s| s >= transport::ca_policy::Severity::Warning)
        || certs.iter().any(|c| c.consecutive_failures > 0)
        || !pending.is_empty()
        || journal.replay_failed > 0
        || journal.write_failures > 0
    {
        return "degraded";
    }
    "ok"
}

/// The JSON for `GET /control/health`.
pub fn health_json(state: &EdgeState, tunnels: &[TunnelInfo], now: i64) -> Value {
    let health = state.metrics.health();
    let (pending, enqueue_failures) = state.metrics.revocations();
    let certs = state.cert_status();
    let journal = state.metrics.journal();
    let status = overall(state, health.as_ref(), &pending);
    let dns = match &health {
        None => Value::Null,
        Some(h) => json!({
            "checked_at": h.report.checked_at,
            "age_seconds": (now - h.report.checked_at).max(0),
            "max_severity": h.report.max_severity().map(Severity::as_str),
            "zones": h.report.zones.iter().map(|z| json!({
                "zone": z.zone,
                "signed": z.signed,
                "ds_present": z.ds_present,
                "ds_mismatch": z.ds_mismatch,
                "rrsig_earliest_expiry_seconds": z.rrsig_earliest_expiry_secs,
                "servers_answering": z.servers_answering,
                "servers_total": z.servers_total,
                "soa_serial": z.soa_serial,
            })).collect::<Vec<_>>(),
            "findings": h.report.findings.iter().map(|f| json!({
                "severity": f.severity.as_str(),
                "kind": f.kind.as_str(),
                "subject": f.subject,
                "detail": f.detail,
            })).collect::<Vec<_>>(),
        }),
    };
    json!({
        "status": status,
        "checked_at": now,
        "certificates": {
            "total": certs.len(),
            "failing": certs.iter().filter(|c| c.consecutive_failures > 0).count(),
            "min_seconds_left": certs.iter().filter_map(|c| c.seconds_left).min(),
            "names": certs.iter().take(MAX_SERIES).map(|c| json!({
                "name": c.name,
                "seconds_left": c.seconds_left,
                "consecutive_failures": c.consecutive_failures,
                "next_attempt": c.next_attempt,
                "last_error": c.last_error,
            })).collect::<Vec<_>>(),
        },
        "revocation": {
            "pending": pending.len(),
            "oldest_age_seconds": pending.iter().map(|p| (now - p.enqueued_at).max(0)).max().unwrap_or(0),
            "enqueue_failures": enqueue_failures,
            "entries": pending.iter().map(|p| json!({
                "name": p.name,
                "enqueued_at": p.enqueued_at,
                "attempts": p.attempts,
                "next_attempt": p.next_attempt,
                "last_error": p.last_error,
                "certificate_not_after": p.not_after,
            })).collect::<Vec<_>>(),
        },
        "journal": {
            "enabled": journal.enabled,
            "replayed": journal.replayed,
            "replay_ops": journal.replay_ops,
            "replay_failed": journal.replay_failed,
            "write_failures": journal.write_failures,
        },
        "tunnels": {
            "total": tunnels.len(),
            "online": tunnels.iter().filter(|t| t.online).count(),
        },
        "dns": dns,
        "ca": crate::ca::health_json(&state.ca.snapshot(), now),
    })
}

// ── the health loop ───────────────────────────────────────────────────────────────────────

/// What the health loop checks and expects, apart from which names exist right now.
#[derive(Clone, Debug, Default)]
pub struct HealthSettings {
    pub caa: CaaPolicy,
    pub rrsig: RrsigThresholds,
}

/// The [`HealthConfig`] for this moment: every apex zone (DNSSEC, NS/SOA, and its CAA as our own
/// name — wildcard and bare), plus a customer-scope CAA check for each custom hostname that
/// needs a certificate. `required_cert_names` is `EdgeRegistry::required_cert_names`; wildcard
/// names are the apexes already covered.
#[must_use]
pub fn build_config(settings: &HealthSettings, required_cert_names: &[String]) -> HealthConfig {
    let mut cfg = HealthConfig {
        caa: settings.caa.clone(),
        rrsig: settings.rrsig,
        ..HealthConfig::default()
    };
    for apex in APEXES {
        cfg.zones.push(apex.zone.to_string());
        cfg.caa_targets.push(CaaTarget {
            name: apex.zone.to_string(),
            wildcard: true,
            scope: CaaScope::Own,
        });
        cfg.caa_targets.push(CaaTarget {
            name: apex.zone.to_string(),
            wildcard: false,
            scope: CaaScope::Own,
        });
    }
    let room = cfg.max_caa_targets.saturating_sub(cfg.caa_targets.len());
    let mut customers: Vec<&String> = required_cert_names
        .iter()
        .filter(|n| !n.starts_with("*.") && !APEXES.iter().any(|a| **n == a.zone))
        .collect();
    customers.sort();
    customers.dedup();
    for name in customers.into_iter().take(room) {
        cfg.caa_targets.push(CaaTarget {
            name: name.clone(),
            wildcard: false,
            scope: CaaScope::Customer,
        });
    }
    cfg
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// One health run: snapshot the names under a short registry lock, run the checks lock-free
/// (bounded by [`HEALTH_RUN_TIMEOUT`]), record the result. Returns the report if the run finished.
pub async fn run_health_once(
    state: &EdgeState,
    lookup: &dyn DnsLookup,
    settings: &HealthSettings,
    now: i64,
) -> Option<HealthReport> {
    let required = state.registry.lock().await.required_cert_names();
    let cfg = build_config(settings, &required);
    if let Ok(report) =
        tokio::time::timeout(HEALTH_RUN_TIMEOUT, run_checks(lookup, &cfg, now)).await
    {
        for f in report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Error)
        {
            warn!(severity = f.severity.as_str(), kind = f.kind.as_str(), subject = %f.subject, detail = %f.detail, "dns health finding");
        }
        state.metrics.record_health(report.clone());
        Some(report)
    } else {
        warn!(
            "dns health run exceeded {}s and was abandoned",
            HEALTH_RUN_TIMEOUT.as_secs()
        );
        state.metrics.record_health_timeout();
        None
    }
}

/// Run [`run_health_once`] now and then every `interval`, forever.
pub async fn health_loop(
    state: Arc<EdgeState>,
    lookup: Arc<dyn DnsLookup>,
    settings: HealthSettings,
    interval: Duration,
) {
    loop {
        if let Some(report) = run_health_once(&state, lookup.as_ref(), &settings, unix_now()).await
        {
            info!(
                findings = report.findings.len(),
                worst = report.max_severity().map_or("none", Severity::as_str),
                caa = report.caa_findings(),
                "dns health run complete"
            );
        }
        tokio::time::sleep(interval).await;
    }
}

/// Whether a finding kind is one the alert rules treat as a DS/chain break (kept here so the
/// documentation and the code name the same set).
#[must_use]
pub fn is_chain_break(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::DsDnskeyMismatch
            | FindingKind::DsWithoutDnskey
            | FindingKind::DnskeyNotSignedByDsKey
    )
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use transport::acme_renew::CertStatus;
    use transport::dns_health::{Finding, ZoneHealth};

    const NOW: i64 = 1_800_000_000;

    fn status(name: &str, left: Option<i64>, failures: u32, next: i64) -> CertStatus {
        CertStatus {
            name: name.into(),
            not_after: left.map(|l| NOW + l),
            seconds_left: left,
            consecutive_failures: failures,
            next_attempt: next,
            last_error: (failures > 0).then(|| "boom".to_string()),
            ca: None,
            migration: transport::acme_renew::Migration::None,
        }
    }

    fn zone(name: &str, expiry: Option<i64>, mismatch: bool) -> ZoneHealth {
        ZoneHealth {
            zone: name.into(),
            signed: true,
            ds_present: true,
            ds_mismatch: mismatch,
            rrsig_earliest_expiry_secs: expiry,
            servers_total: 2,
            servers_answering: 2,
            soa_serial: Some(1),
        }
    }

    fn finding(sev: Severity, kind: FindingKind, subject: &str) -> Finding {
        Finding {
            severity: sev,
            kind,
            subject: subject.into(),
            detail: "d".into(),
        }
    }

    fn value(text: &str, series: &str) -> Option<i64> {
        text.lines().find_map(|l| {
            l.strip_prefix(series)
                .and_then(|r| r.strip_prefix(' '))
                .and_then(|v| v.parse().ok())
        })
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(esc(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(esc("a\nb"), "a\\nb");
        assert_eq!(esc("plain.example.com"), "plain.example.com");
    }

    #[tokio::test]
    async fn the_exposition_reports_certificates_tunnels_journal_and_revocations() {
        let state = EdgeState::ephemeral();
        state.set_cert_status(vec![
            status("*.tascloud.app", Some(40 * 86_400), 0, 0),
            status("app.acme.com.au", Some(-5), 3, NOW + 600),
            status("never.example", None, 2, NOW),
        ]);
        state.metrics.set_journal_enabled(true);
        state.metrics.record_replay(12, 2);
        state.metrics.record_journal_write_failure();
        state.metrics.set_account_key_created(Some(NOW - 1000));
        state.metrics.set_hosting(true);
        let tunnels = vec![TunnelInfo {
            hostname: "mine.tascloud.app".into(),
            port: 80,
            version: None,
            online: true,
            pipes: 4,
        }];
        let q = Arc::new(RevocationQueue::in_memory());
        state.metrics.set_revocation_queue(q.clone());
        state.metrics.record_revocation_enqueue_failure();

        let text = render_prometheus(&state, &tunnels, NOW);
        let v = |s: &str| value(&text, s);
        assert_eq!(
            v(r#"edge_lb_cert_seconds_left{name="*.tascloud.app"}"#),
            Some(40 * 86_400)
        );
        assert_eq!(
            v(r#"edge_lb_cert_seconds_left{name="app.acme.com.au"}"#),
            Some(-5),
            "expired is negative, not hidden"
        );
        assert_eq!(
            v(r#"edge_lb_cert_seconds_left{name="never.example"}"#),
            None,
            "no certificate, no expiry sample"
        );
        assert_eq!(
            v(r#"edge_lb_cert_consecutive_failures{name="never.example"}"#),
            Some(2)
        );
        assert_eq!(
            v(r#"edge_lb_cert_next_attempt_timestamp_seconds{name="app.acme.com.au"}"#),
            Some(NOW + 600)
        );
        assert_eq!(
            v(r#"edge_lb_tunnel_pipes{host="mine.tascloud.app"}"#),
            Some(4)
        );
        assert_eq!(v("edge_lb_journal_replay_ops"), Some(12));
        assert_eq!(v("edge_lb_journal_replay_failed"), Some(2));
        assert_eq!(v("edge_lb_journal_write_failures_total"), Some(1));
        assert_eq!(v("edge_lb_journal_enabled"), Some(1));
        assert_eq!(v("edge_lb_acme_account_key_age_seconds"), Some(1000));
        assert_eq!(v("edge_lb_hosting_enabled"), Some(1));
        assert_eq!(v("edge_lb_revocation_pending"), Some(0));
        assert_eq!(v("edge_lb_revocation_enqueue_failures_total"), Some(1));
        assert_eq!(v("edge_lb_dns_health_last_run_timestamp_seconds"), Some(0));
        assert!(
            !text.contains("edge_lb_dns_ds_mismatch"),
            "no DNS series before the first run"
        );
        // Exposition hygiene: every family has HELP and TYPE, and every sample line parses.
        for fam in text.lines().filter_map(|l| l.strip_prefix("# TYPE ")) {
            let name = fam.split(' ').next().unwrap();
            assert!(text.contains(&format!("# HELP {name} ")), "{name}");
        }
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (series, val) = line.rsplit_once(' ').unwrap();
            assert!(
                val.parse::<i64>().is_ok() && series.starts_with("edge_lb_"),
                "{line}"
            );
        }
    }

    #[tokio::test]
    async fn dns_health_series_follow_the_latest_run() {
        let state = EdgeState::ephemeral();
        state.metrics.record_health(HealthReport {
            checked_at: NOW - 30,
            zones: vec![
                zone("tascloud.app", Some(86_400), true),
                zone("tascloud.dev", None, false),
            ],
            findings: vec![
                finding(
                    Severity::Critical,
                    FindingKind::DsDnskeyMismatch,
                    "tascloud.app",
                ),
                finding(Severity::Warning, FindingKind::CaaAbsent, "tascloud.dev"),
                finding(
                    Severity::Error,
                    FindingKind::CaaMissingAccountUri,
                    "tascloud.dev",
                ),
                finding(Severity::Info, FindingKind::CaaAbsent, "x"),
            ],
        });
        let text = render_prometheus(&state, &[], NOW);
        let v = |s: &str| value(&text, s);
        assert_eq!(
            v(r#"edge_lb_dns_rrsig_earliest_expiry_seconds{zone="tascloud.app"}"#),
            Some(86_400)
        );
        assert_eq!(
            v(r#"edge_lb_dns_rrsig_earliest_expiry_seconds{zone="tascloud.dev"}"#),
            None,
            "no signature, no sample"
        );
        assert_eq!(
            v(r#"edge_lb_dns_ds_mismatch{zone="tascloud.app"}"#),
            Some(1)
        );
        assert_eq!(
            v(r#"edge_lb_dns_ds_mismatch{zone="tascloud.dev"}"#),
            Some(0)
        );
        assert_eq!(v(r#"edge_lb_dns_findings{severity="critical"}"#), Some(1));
        assert_eq!(v(r#"edge_lb_dns_findings{severity="warning"}"#), Some(1));
        assert_eq!(v(r#"edge_lb_dns_findings{severity="info"}"#), Some(1));
        assert_eq!(
            v(r#"edge_lb_dns_finding{kind="ds_dnskey_mismatch",severity="critical"}"#),
            Some(1)
        );
        assert_eq!(
            v("edge_lb_dns_caa_findings"),
            Some(2),
            "info-level CAA findings are not drift"
        );
        assert_eq!(
            v("edge_lb_dns_health_last_run_timestamp_seconds"),
            Some(NOW - 30)
        );
        assert_eq!(v("edge_lb_dns_health_runs_total"), Some(1));
        assert_eq!(
            v(r#"edge_lb_dns_servers_answering{zone="tascloud.app"}"#),
            Some(2)
        );
    }

    #[tokio::test]
    async fn the_revocation_backlog_is_visible_with_its_age_and_attempts() {
        let state = EdgeState::ephemeral();
        let q = Arc::new(RevocationQueue::in_memory());
        state.metrics.set_revocation_queue(q.clone());
        let m = test_material();
        q.enqueue("app.acme.com.au", m, NOW - 1800).unwrap();
        let text = render_prometheus(&state, &[], NOW);
        assert_eq!(value(&text, "edge_lb_revocation_pending"), Some(1));
        assert_eq!(
            value(&text, "edge_lb_revocation_oldest_age_seconds"),
            Some(1800)
        );
        assert_eq!(value(&text, "edge_lb_revocation_max_attempts"), Some(0));
        let h = health_json(&state, &[], NOW);
        assert_eq!(h["revocation"]["pending"], 1);
        assert_eq!(h["revocation"]["entries"][0]["name"], "app.acme.com.au");
        assert!(
            !h.to_string().contains("PRIVATE KEY"),
            "the health document never carries key material"
        );
        assert_eq!(
            h["status"], "degraded",
            "a revocation that is waiting is not healthy"
        );
    }

    /// A real self-signed certificate (valid 2027-01-14 .. 2027-04-15, around `NOW`) with its key.
    fn test_material() -> transport::edge::CertMaterial {
        use rcgen::{date_time_ymd, CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["app.acme.com.au".to_string()]).unwrap();
        params.not_before = date_time_ymd(2027, 1, 14);
        params.not_after = date_time_ymd(2027, 4, 15);
        let cert = params.self_signed(&key).unwrap();
        transport::edge::CertMaterial {
            chain_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    // ── status, config, loop ──

    #[tokio::test]
    async fn the_overall_status_is_ok_degraded_or_critical() {
        let state = EdgeState::ephemeral();
        let status = |v: Value| v["status"].as_str().unwrap().to_string();
        assert_eq!(status(health_json(&state, &[], NOW)), "ok");

        state.set_cert_status(vec![status_of("a.example", Some(86_400), 0)]);
        assert_eq!(status(health_json(&state, &[], NOW)), "ok");
        state.set_cert_status(vec![status_of("a.example", Some(86_400), 2)]);
        assert_eq!(
            status(health_json(&state, &[], NOW)),
            "degraded",
            "a renewal that is failing"
        );
        state.set_cert_status(vec![status_of("a.example", Some(-1), 0)]);
        assert_eq!(
            status(health_json(&state, &[], NOW)),
            "critical",
            "an expired certificate"
        );
        state.set_cert_status(vec![]);

        state.metrics.record_replay(3, 1);
        assert_eq!(
            status(health_json(&state, &[], NOW)),
            "degraded",
            "a journal operation was dropped at replay"
        );

        let state = EdgeState::ephemeral();
        state.metrics.record_journal_write_failure();
        assert_eq!(
            status(health_json(&state, &[], NOW)),
            "degraded",
            "a change that would not survive a restart"
        );

        let state = EdgeState::ephemeral();
        let run = |sev, kind| HealthReport {
            checked_at: NOW,
            zones: vec![],
            findings: vec![finding(sev, kind, "z")],
        };
        state
            .metrics
            .record_health(run(Severity::Info, FindingKind::SignedZoneWithoutDs));
        assert_eq!(
            status(health_json(&state, &[], NOW)),
            "ok",
            "info is not a degradation"
        );
        state
            .metrics
            .record_health(run(Severity::Warning, FindingKind::CaaAbsent));
        assert_eq!(status(health_json(&state, &[], NOW)), "degraded");
        state
            .metrics
            .record_health(run(Severity::Critical, FindingKind::DsDnskeyMismatch));
        let h = health_json(&state, &[], NOW);
        assert_eq!(status(h.clone()), "critical");
        assert_eq!(h["dns"]["max_severity"], "critical");
        assert_eq!(h["dns"]["findings"][0]["kind"], "ds_dnskey_mismatch");
        assert_eq!(h["dns"]["age_seconds"], 0);
    }

    fn status_of(name: &str, left: Option<i64>, failures: u32) -> CertStatus {
        status(name, left, failures, 0)
    }

    #[test]
    fn the_health_config_covers_every_apex_and_each_custom_name_once() {
        let settings = HealthSettings {
            caa: CaaPolicy {
                allowed_issuers: vec!["letsencrypt.org".into()],
                ..CaaPolicy::default()
            },
            ..HealthSettings::default()
        };
        let required: Vec<String> = [
            "*.tascloud.app",
            "b.acme.com.au",
            "a.acme.com.au",
            "b.acme.com.au",
            "*.tascloud.dev",
            "tascloud.app",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let cfg = build_config(&settings, &required);
        assert_eq!(cfg.zones.len(), APEXES.len());
        assert!(APEXES.iter().all(|a| cfg.zones.iter().any(|z| z == a.zone)));
        let own: Vec<_> = cfg
            .caa_targets
            .iter()
            .filter(|t| t.scope == CaaScope::Own)
            .collect();
        assert_eq!(
            own.len(),
            APEXES.len() * 2,
            "wildcard and bare name of each apex"
        );
        assert_eq!(own.iter().filter(|t| t.wildcard).count(), APEXES.len());
        let customers: Vec<&str> = cfg
            .caa_targets
            .iter()
            .filter(|t| t.scope == CaaScope::Customer)
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(
            customers,
            ["a.acme.com.au", "b.acme.com.au"],
            "sorted, deduplicated, wildcards and apexes excluded"
        );
        assert_eq!(cfg.caa.allowed_issuers, ["letsencrypt.org"]);

        // A registry with absurdly many custom names cannot grow the check without bound.
        let many: Vec<String> = (0..10_000).map(|i| format!("h{i}.example.org")).collect();
        let cfg = build_config(&settings, &many);
        assert_eq!(cfg.caa_targets.len(), cfg.max_caa_targets);
    }

    /// Answers nothing: every lookup fails, as with every resolver unreachable.
    struct Silent;
    impl DnsLookup for Silent {
        fn recursive<'a>(
            &'a self,
            _: &'a transport::dns::Name,
            _: transport::dns::RecordType,
        ) -> transport::BoxFuture<'a, Option<transport::dns::Message>> {
            Box::pin(async { None })
        }
        fn direct<'a>(
            &'a self,
            _: std::net::SocketAddr,
            _: &'a transport::dns::Name,
            _: transport::dns::RecordType,
        ) -> transport::BoxFuture<'a, Option<transport::dns::Message>> {
            Box::pin(async { None })
        }
        fn nameserver_addrs<'a>(
            &'a self,
            _: &'a transport::dns::Name,
        ) -> transport::BoxFuture<'a, Vec<std::net::SocketAddr>> {
            Box::pin(async { Vec::new() })
        }
    }

    #[tokio::test]
    async fn a_health_run_checks_the_registry_snapshot_and_records_into_the_metrics() {
        let state = EdgeState::ephemeral();
        state
            .apply(&crate::edge_state::Op::AdmitManaged {
                tenant_id: "acme".into(),
                tunnel_id: "t".into(),
                apex: "tascloud.app".into(),
                label: Some("mine".into()),
                dialkey: None,
                tls_mode: "terminate".into(),
                origin_port: 80,
                agent_peer: None,
            })
            .await
            .unwrap();
        state
            .apply(&crate::edge_state::Op::AdmitCustom {
                tenant_id: "acme".into(),
                tunnel_id: "t".into(),
                fqdn: "app.acme.com.au".into(),
                cname_target: "mine.tascloud.app".into(),
                tls_mode: "terminate".into(),
                origin_port: 80,
                agent_peer: None,
            })
            .await
            .unwrap();
        state
            .apply(&crate::edge_state::Op::Validated {
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();
        assert!(state.metrics.health().is_none());

        let report = run_health_once(&state, &Silent, &HealthSettings::default(), NOW)
            .await
            .expect("the run finished");
        assert_eq!(report.checked_at, NOW);
        assert_eq!(report.zones.len(), APEXES.len());
        assert!(
            report.of_kind(FindingKind::NsLookupFailed).count() >= APEXES.len(),
            "{:#?}",
            report.findings
        );
        // Our own names and the validated custom name were all looked at.
        let caa_subjects: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::CaaLookupFailed)
            .map(|f| f.subject.as_str())
            .collect();
        assert!(
            caa_subjects.contains(&"app.acme.com.au")
                && caa_subjects.contains(&"*.tascloud.app")
                && caa_subjects.contains(&"tascloud.app"),
            "{caa_subjects:?}"
        );
        // ...and the endpoints now show it.
        let snapshot = state.metrics.health().expect("recorded");
        assert_eq!(snapshot.report.findings.len(), report.findings.len());
        let text = render_prometheus(&state, &[], NOW);
        assert_eq!(value(&text, "edge_lb_dns_health_runs_total"), Some(1));
        assert_eq!(
            value(&text, "edge_lb_dns_health_last_run_timestamp_seconds"),
            Some(NOW)
        );
        assert!(value(&text, "edge_lb_dns_caa_findings").unwrap() > 0);
        assert_eq!(health_json(&state, &[], NOW)["status"], "degraded");
    }

    #[test]
    fn the_chain_break_kinds_are_the_critical_dnssec_ones() {
        assert!(
            is_chain_break(FindingKind::DsDnskeyMismatch)
                && is_chain_break(FindingKind::DsWithoutDnskey)
                && is_chain_break(FindingKind::DnskeyNotSignedByDsKey)
        );
        assert!(
            !is_chain_break(FindingKind::RrsigExpiring) && !is_chain_break(FindingKind::CaaAbsent)
        );
    }
}
