//! Certificate Transparency monitoring: is anyone getting certificates for our names that we did
//! not ask for, and is what we got actually logged?
//!
//! CAA tells honest CAs not to issue; it does nothing against a CA that is compromised, buggy or
//! dishonest, and a CA that has lost the root programs' trust is exactly the kind whose controls we
//! should not lean on. Every publicly trusted certificate has to be in a CT log, so the logs are
//! the one place all mis-issuance eventually shows up. This module polls them through a
//! [`CtSource`] (crt.sh's JSON by default, behind a trait with a fake for tests) and raises:
//!
//! * [`CtFindingKind::UnknownIssuer`] -- a certificate for one of our names from an issuer that is
//!   on **no** CA entry of the allow-list. The CAA record should have stopped it; it did not.
//! * [`CtFindingKind::UnexpectedCertificate`] -- from an issuer we do use, but not one we ordered
//!   (its serial is in none of our records): another account at the same CA, a stolen validation
//!   capability, a second deployment. `accounturi` in CAA exists to prevent exactly this.
//! * [`CtFindingKind::MissingEmbeddedScts`] / [`CtFindingKind::PrecertificateServed`] -- about what
//!   *we* obtained: a certificate without embedded SCTs will be refused by browsers that enforce CT;
//!   one carrying the precertificate poison is not a certificate at all.
//!
//! Scope. Names under our own apexes are ours: any certificate we did not obtain is critical.
//! Customers' own hostnames are not: the customer may hold certificates for them elsewhere, so
//! those are reported at `Info` for visibility and never page.
//!
//! The monitor never fails and never acts: an unreachable or malformed source is an entry in
//! [`CtReport::errors`], not a finding about a certificate.

use std::collections::HashSet;
use std::sync::Arc;

use crate::ca_policy::{CaPolicy, Severity};
use crate::ca_trust::SignalSource;
use crate::edge::CertMaterial;
use crate::BoxFuture;

/// Most entries read from one query. A wildcard apex of a busy platform can have many; more than
/// this is a flood to be summarised, not parsed.
pub const MAX_ENTRIES_PER_QUERY: usize = 5000;
/// Largest response read.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// A certificate logged this recently may be one we just ordered and have not recorded yet (the
/// precertificate reaches the log before the CA hands us the certificate).
pub const RECENT_GRACE_SECS: i64 = 30 * 60;

/// What to look for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtQuery {
    /// Certificates covering exactly this name.
    Exact(String),
    /// Certificates for this domain and anything under it.
    Subdomains(String),
}

/// One logged certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtEntry {
    pub log_id: u64,
    /// The issuer's distinguished name as the source prints it (`C=US, O=Let's Encrypt, CN=R11`).
    pub issuer: String,
    /// Serial number, lower-case hex, leading zeros stripped.
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    /// When the entry was logged, if the source says.
    pub logged_at: Option<i64>,
    /// Subject alternative names, lower-case.
    pub names: Vec<String>,
}

/// A source of CT log entries. A trait so the monitor is testable offline.
pub trait CtSource: Send + Sync {
    fn query<'a>(&'a self, q: &'a CtQuery) -> BoxFuture<'a, Result<Vec<CtEntry>, String>>;
}

fn norm_serial(s: &str) -> String {
    let t = s.trim().trim_start_matches("0x").to_ascii_lowercase();
    let t = t.trim_start_matches('0');
    if t.is_empty() { "0".to_string() } else { t.to_string() }
}

/// Parse crt.sh's `output=json` array.
///
/// # Errors
/// Not a JSON array of objects, or an entry missing a field this reader depends on. A malformed
/// document is an error, never "no certificates".
pub fn parse_crtsh(body: &[u8]) -> Result<Vec<CtEntry>, String> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("crt.sh response is larger than expected".into());
    }
    let text = std::str::from_utf8(body).map_err(|_| "crt.sh response is not UTF-8".to_string())?;
    if text.trim().is_empty() {
        return Ok(Vec::new()); // crt.sh answers an empty body for no results
    }
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("crt.sh response is not JSON: {e}"))?;
    let arr = v.as_array().ok_or("crt.sh response is not an array")?;
    if arr.len() > MAX_ENTRIES_PER_QUERY {
        return Err(format!("crt.sh returned more than {MAX_ENTRIES_PER_QUERY} entries"));
    }
    let ts = |s: &str| crate::acme::parse_rfc3339(&if s.contains(['Z', '+']) { s.to_string() } else { format!("{}Z", s.split('.').next().unwrap_or(s)) });
    arr.iter()
        .map(|e| {
            let field = |k: &str| e.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("a crt.sh entry has no '{k}'"));
            Ok(CtEntry {
                log_id: e.get("id").and_then(serde_json::Value::as_u64).ok_or("a crt.sh entry has no 'id'")?,
                issuer: field("issuer_name")?.to_string(),
                serial: norm_serial(field("serial_number")?),
                not_before: ts(field("not_before")?).ok_or("a crt.sh entry has a malformed not_before")?,
                not_after: ts(field("not_after")?).ok_or("a crt.sh entry has a malformed not_after")?,
                logged_at: e.get("entry_timestamp").and_then(|x| x.as_str()).and_then(ts),
                names: field("name_value")?.lines().map(|l| l.trim().to_ascii_lowercase()).filter(|l| !l.is_empty()).collect(),
            })
        })
        .collect()
}

/// crt.sh through a [`SignalSource`] (HTTPS, verified TLS, bounded, no redirects).
pub struct CrtSh {
    source: Arc<dyn SignalSource>,
    base: String,
}

impl CrtSh {
    #[must_use]
    pub fn new(source: Arc<dyn SignalSource>) -> Self {
        CrtSh { source, base: "https://crt.sh".to_string() }
    }

    /// The production source over [`crate::ca_trust::HttpsSource`].
    #[must_use]
    pub fn https() -> Self {
        Self::new(Arc::new(crate::ca_trust::HttpsSource::default()))
    }

    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    fn url(&self, q: &CtQuery) -> String {
        let enc = |s: &str| s.replace('%', "%25").replace('*', "%2A");
        let pattern = match q {
            CtQuery::Exact(n) => enc(n),
            CtQuery::Subdomains(d) => format!("%25.{}", enc(d)),
        };
        format!("{}/?q={pattern}&output=json&exclude=expired", self.base)
    }
}

impl CtSource for CrtSh {
    fn query<'a>(&'a self, q: &'a CtQuery) -> BoxFuture<'a, Result<Vec<CtEntry>, String>> {
        Box::pin(async move {
            let body = self.source.fetch(&self.url(q), MAX_RESPONSE_BYTES).await?;
            parse_crtsh(&body)
        })
    }
}

/// What the monitor is told about the names it watches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameScope {
    /// A platform apex (`tascloud.app`): every name under it is ours.
    Own,
    /// A customer's hostname.
    Customer,
}

/// What we know we obtained.
#[derive(Clone, Debug, Default)]
pub struct Expected {
    /// Serial numbers (hex) of every certificate we ordered: held, replaced, queued for revocation.
    pub serials: HashSet<String>,
}

impl Expected {
    /// Add the serial of `material`'s leaf.
    pub fn add_material(&mut self, material: &CertMaterial) {
        if let Some(der) = crate::x509::leaf_der(&material.chain_pem) {
            if let Some(c) = crate::x509::parse(&der) {
                self.serials.insert(norm_serial(&c.serial.iter().map(|b| format!("{b:02x}")).collect::<String>()));
            }
        }
    }

    pub fn add_serial(&mut self, hex: &str) {
        self.serials.insert(norm_serial(hex));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CtFindingKind {
    UnknownIssuer,
    UnexpectedCertificate,
    MissingEmbeddedScts,
    PrecertificateServed,
}

impl CtFindingKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CtFindingKind::UnknownIssuer => "unknown_issuer",
            CtFindingKind::UnexpectedCertificate => "unexpected_certificate",
            CtFindingKind::MissingEmbeddedScts => "missing_embedded_scts",
            CtFindingKind::PrecertificateServed => "precertificate_served",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtFinding {
    pub severity: Severity,
    pub kind: CtFindingKind,
    pub name: String,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub detail: String,
}

/// One pass's result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CtReport {
    pub checked_at: i64,
    pub findings: Vec<CtFinding>,
    /// Queries that failed (source unreachable, malformed answer), as text.
    pub errors: Vec<String>,
    pub queries: usize,
    pub entries_seen: usize,
}

impl CtReport {
    /// Findings above `Info`.
    #[must_use]
    pub fn actionable(&self) -> usize {
        self.findings.iter().filter(|f| f.severity > Severity::Info).count()
    }
}

pub struct CtMonitor {
    source: Arc<dyn CtSource>,
    /// Require embedded SCTs in what we obtained (true for any public CA; false for a test CA).
    pub scts_required: bool,
}

fn covers(entry_name: &str, ours: &str) -> bool {
    entry_name == ours || entry_name.strip_prefix("*.").is_some_and(|d| ours.strip_suffix(d).is_some_and(|label| label.ends_with('.') && !label[..label.len() - 1].contains('.') && label.len() > 1))
}

fn within(name: &str, apex: &str) -> bool {
    name == apex || name.strip_suffix(apex).is_some_and(|p| p.ends_with('.'))
}

impl CtMonitor {
    #[must_use]
    pub fn new(source: Arc<dyn CtSource>) -> Self {
        CtMonitor { source, scts_required: true }
    }

    /// Does `issuer` (a DN string) belong to any CA on the allow-list, whatever its standing?
    fn known_issuer(policy: &CaPolicy, issuer: &str) -> bool {
        let issuer = issuer.to_ascii_lowercase();
        policy.cas.iter().any(|c| c.issuer_names.iter().any(|n| issuer.contains(&n.to_ascii_lowercase())))
    }

    /// Judge one logged certificate for a watched name. Pure.
    #[must_use]
    pub fn judge(&self, policy: &CaPolicy, expected: &Expected, name: &str, scope: &NameScope, e: &CtEntry, now: i64) -> Option<CtFinding> {
        if e.not_after <= now {
            return None;
        }
        let own = *scope == NameScope::Own;
        let ours = expected.serials.contains(&e.serial);
        if ours {
            return None;
        }
        // Certificates are logged before they are delivered: give a fresh entry time to be recorded.
        if e.logged_at.unwrap_or(e.not_before) > now - RECENT_GRACE_SECS {
            return None;
        }
        let mk = |severity, kind, detail: String| CtFinding { severity, kind, name: name.to_string(), issuer: Some(e.issuer.clone()), serial: Some(e.serial.clone()), detail };
        if !Self::known_issuer(policy, &e.issuer) {
            let sev = if own { Severity::Critical } else { Severity::Info };
            return Some(mk(sev, CtFindingKind::UnknownIssuer, format!("a certificate for {name} (serial {}, valid until {}) was issued by '{}', which is on no entry of the CA allow-list", e.serial, e.not_after, e.issuer)));
        }
        let sev = if own { Severity::Critical } else { Severity::Info };
        Some(mk(sev, CtFindingKind::UnexpectedCertificate, format!("a certificate for {name} (serial {}, valid until {}) was issued by '{}' but is not one we ordered: another account at that CA, or a second deployment", e.serial, e.not_after, e.issuer)))
    }

    /// Poll the logs for every watched name and judge what comes back.
    pub async fn check(&self, policy: &CaPolicy, apexes: &[String], customer_names: &[String], expected: &Expected, now: i64) -> CtReport {
        let mut report = CtReport { checked_at: now, ..CtReport::default() };
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let queries: Vec<(CtQuery, NameScope, String)> = apexes
            .iter()
            .map(|a| (CtQuery::Subdomains(a.clone()), NameScope::Own, a.clone()))
            .chain(customer_names.iter().map(|n| (CtQuery::Exact(n.clone()), NameScope::Customer, n.clone())))
            .collect();
        for (q, scope, root) in queries {
            report.queries += 1;
            let entries = match self.source.query(&q).await {
                Ok(e) => e,
                Err(e) => {
                    report.errors.push(format!("{q:?}: {e}"));
                    continue;
                }
            };
            report.entries_seen += entries.len();
            for e in &entries {
                // Only names we actually watch: a Subdomains query for the apex also returns
                // certificates whose SANs merely include something under it among many others.
                let Some(name) = e.names.iter().find(|n| if scope == NameScope::Own { within(n.trim_start_matches("*."), &root) } else { covers(n, &root) || **n == root }) else { continue };
                if !seen.insert((root.clone(), e.log_id)) {
                    continue;
                }
                if let Some(f) = self.judge(policy, expected, name, &scope, e, now) {
                    report.findings.push(f);
                }
            }
        }
        report
    }

    /// What is wrong with a certificate **we obtained**: no embedded SCTs (browsers that enforce
    /// CT refuse it), or it is a precertificate.
    #[must_use]
    pub fn check_obtained(&self, name: &str, material: &CertMaterial) -> Vec<CtFinding> {
        let mk = |severity, kind, detail: &str| CtFinding { severity, kind, name: name.to_string(), issuer: None, serial: None, detail: detail.to_string() };
        let Some(der) = crate::x509::leaf_der(&material.chain_pem) else { return Vec::new() };
        let Some(cert) = crate::x509::parse(&der) else { return Vec::new() };
        let mut out = Vec::new();
        if cert.is_precertificate() {
            out.push(mk(Severity::Error, CtFindingKind::PrecertificateServed, "the certificate carries the CT precertificate poison: it is a precertificate, not a certificate"));
        }
        if self.scts_required && !cert.has_embedded_scts() {
            out.push(mk(Severity::Error, CtFindingKind::MissingEmbeddedScts, "the certificate has no embedded SCT list; browsers that enforce Certificate Transparency will refuse it"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_policy::fixtures::{entry, policy};
    use crate::ca_policy::CaStatus;
    use std::sync::Mutex;

    const NOW: i64 = 1_792_627_200; // 2026-10-22
    const HOUR: i64 = 3600;

    fn pol() -> CaPolicy {
        let mut a = entry("le", CaStatus::Active, "letsencrypt.org");
        a.issuer_names = vec!["Let's Encrypt".into()];
        let mut b = entry("gts", CaStatus::Standby, "pki.goog");
        b.issuer_names = vec!["Google Trust Services".into()];
        policy(vec![a, b])
    }

    fn ct(id: u64, issuer: &str, serial: &str, names: &[&str]) -> CtEntry {
        CtEntry { log_id: id, issuer: issuer.into(), serial: norm_serial(serial), not_before: NOW - 10 * HOUR, not_after: NOW + 80 * 24 * HOUR, logged_at: Some(NOW - 9 * HOUR), names: names.iter().map(|s| (*s).to_string()).collect() }
    }

    struct Fake {
        by_query: Mutex<Vec<Canned>>,
    }
    impl CtSource for Fake {
        fn query<'a>(&'a self, q: &'a CtQuery) -> BoxFuture<'a, Result<Vec<CtEntry>, String>> {
            Box::pin(async move { self.by_query.lock().unwrap().iter().find(|(k, _)| k == q).map_or_else(|| Ok(Vec::new()), |(_, v)| v.clone()) })
        }
    }

    type Canned = (CtQuery, Result<Vec<CtEntry>, String>);

    fn monitor(entries: Vec<Canned>) -> CtMonitor {
        CtMonitor::new(Arc::new(Fake { by_query: Mutex::new(entries) }))
    }

    #[tokio::test]
    async fn a_certificate_we_ordered_is_quiet_and_one_we_did_not_is_critical_for_our_own_names() {
        let mut expected = Expected::default();
        expected.add_serial("0A0B");
        let apex = CtQuery::Subdomains("tascloud.app".into());
        let m = monitor(vec![(apex, Ok(vec![
            ct(1, "C=US, O=Let's Encrypt, CN=R11", "0a0b", &["*.tascloud.app", "tascloud.app"]),
            ct(2, "C=US, O=Let's Encrypt, CN=R11", "ffee01", &["login.tascloud.app"]),
            ct(3, "C=XX, O=Sketchy CA, CN=Sketchy Issuing CA", "123", &["tascloud.app"]),
            ct(4, "C=US, O=Google Trust Services, CN=WR1", "9999", &["*.tascloud.app"]),
            ct(5, "C=US, O=Let's Encrypt, CN=R11", "77", &["unrelated.example.org"]),
        ]))]);
        let r = m.check(&pol(), &["tascloud.app".into()], &[], &expected, NOW).await;
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(r.entries_seen, 5);
        let kinds: Vec<(CtFindingKind, &str)> = r.findings.iter().map(|f| (f.kind, f.serial.as_deref().unwrap_or(""))).collect();
        assert_eq!(kinds, vec![(CtFindingKind::UnexpectedCertificate, "ffee01"), (CtFindingKind::UnknownIssuer, "123"), (CtFindingKind::UnexpectedCertificate, "9999")], "{r:?}");
        assert!(r.findings.iter().all(|f| f.severity == Severity::Critical));
        assert_eq!(r.actionable(), 3);
        assert!(r.findings[1].detail.contains("Sketchy"), "the issuer is named");
    }

    #[tokio::test]
    async fn the_issuer_is_judged_against_the_allow_list_whatever_the_cas_standing() {
        // A retired CA's certificates still exist and are still ours; a CA that was never listed is not.
        let mut p = pol();
        p.cas[0].status = CaStatus::Distrusted;
        let m = monitor(vec![(CtQuery::Subdomains("tascloud.app".into()), Ok(vec![ct(1, "O=Let's Encrypt, CN=R11", "5", &["x.tascloud.app"])]))]);
        let r = m.check(&p, &["tascloud.app".into()], &[], &Expected::default(), NOW).await;
        assert_eq!(r.findings[0].kind, CtFindingKind::UnexpectedCertificate, "known issuer, unknown serial -- not 'unknown issuer'");
    }

    #[tokio::test]
    async fn expired_and_freshly_logged_entries_do_not_alarm() {
        let mut stale = ct(1, "O=Sketchy", "1", &["a.tascloud.app"]);
        stale.not_after = NOW - 1;
        let mut fresh = ct(2, "O=Let's Encrypt", "2", &["b.tascloud.app"]);
        fresh.logged_at = Some(NOW - 60); // the precert of an order in flight
        let m = monitor(vec![(CtQuery::Subdomains("tascloud.app".into()), Ok(vec![stale, fresh]))]);
        let r = m.check(&pol(), &["tascloud.app".into()], &[], &Expected::default(), NOW).await;
        assert!(r.findings.is_empty(), "{r:?}");
        // The same fresh entry is judged on the next pass once the grace has elapsed.
        let r = m.check(&pol(), &["tascloud.app".into()], &[], &Expected::default(), NOW + RECENT_GRACE_SECS + 120).await;
        assert_eq!(r.findings.len(), 1);
    }

    #[tokio::test]
    async fn customer_names_are_informational_and_wildcards_cover_one_label() {
        let m = monitor(vec![
            (CtQuery::Exact("app.acme.com.au".into()), Ok(vec![ct(1, "O=Some Other CA", "9", &["app.acme.com.au"]), ct(2, "O=Let's Encrypt", "8", &["*.acme.com.au"])])),
            (CtQuery::Exact("deep.sub.acme.com.au".into()), Ok(vec![ct(3, "O=Some Other CA", "7", &["*.acme.com.au"])])),
        ]);
        let r = m.check(&pol(), &[], &["app.acme.com.au".into(), "deep.sub.acme.com.au".into()], &Expected::default(), NOW).await;
        assert_eq!(r.findings.len(), 2, "{r:?}");
        assert!(r.findings.iter().all(|f| f.severity == Severity::Info), "a customer's other certificates are theirs to hold: {r:?}");
        assert_eq!(r.actionable(), 0);
        assert!(covers("*.acme.com.au", "app.acme.com.au") && !covers("*.acme.com.au", "a.b.acme.com.au") && !covers("*.acme.com.au", "acme.com.au"));
    }

    #[tokio::test]
    async fn an_unreachable_or_malformed_source_is_an_error_entry_never_a_finding_and_never_a_panic() {
        let m = monitor(vec![(CtQuery::Subdomains("tascloud.app".into()), Err("HTTP 503".into()))]);
        let r = m.check(&pol(), &["tascloud.app".into(), "other.app".into()], &[], &Expected::default(), NOW).await;
        assert_eq!(r.errors.len(), 1);
        assert!(r.findings.is_empty());
        assert_eq!(r.queries, 2);
    }

    #[test]
    fn the_real_crtsh_response_format_parses() {
        let body = include_bytes!("../tests/fixtures/crtsh_ccadb_org.json");
        let entries = parse_crtsh(body).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.issuer, "C=US, O=Let's Encrypt, CN=YE2");
        assert_eq!(e.serial, "6591c662889b639d35f82ee6330ab181238", "leading zero stripped");
        assert_eq!(e.names, ["*.ccadb.org", "ccadb.org"]);
        assert_eq!(e.not_after - e.not_before, 89 * 86_400 + 86_399, "a 90-day certificate");
        assert_eq!(e.logged_at, None);
        // Malformed documents are errors, not 'no certificates'.
        assert!(parse_crtsh(b"<html>rate limited</html>").is_err());
        assert!(parse_crtsh(b"{\"a\":1}").is_err());
        assert!(parse_crtsh(br#"[{"id":1}]"#).is_err());
        assert!(parse_crtsh(br#"[{"id":1,"issuer_name":"x","name_value":"a","serial_number":"1","not_before":"yesterday","not_after":"2026-01-01T00:00:00"}]"#).is_err());
        assert_eq!(parse_crtsh(b"").unwrap(), vec![]);
        assert_eq!(parse_crtsh(b"[]").unwrap(), vec![]);
    }

    #[tokio::test]
    async fn crtsh_queries_are_built_and_parsed_through_the_bounded_source() {
        struct Canned(Mutex<Vec<String>>);
        impl SignalSource for Canned {
            fn fetch<'a>(&'a self, url: &'a str, _max: usize) -> BoxFuture<'a, Result<Vec<u8>, String>> {
                Box::pin(async move {
                    self.0.lock().unwrap().push(url.to_string());
                    Ok(include_bytes!("../tests/fixtures/crtsh_ccadb_org.json").to_vec())
                })
            }
        }
        let src = Arc::new(Canned(Mutex::default()));
        let crt = CrtSh::new(src.clone());
        let got = crt.query(&CtQuery::Subdomains("ccadb.org".into())).await.unwrap();
        assert_eq!(got.len(), 1);
        crt.query(&CtQuery::Exact("*.ccadb.org".into())).await.unwrap();
        let urls = src.0.lock().unwrap().clone();
        assert_eq!(urls[0], "https://crt.sh/?q=%25.ccadb.org&output=json&exclude=expired");
        assert_eq!(urls[1], "https://crt.sh/?q=%2A.ccadb.org&output=json&exclude=expired");
    }

    fn cert_with(scts: bool, poison: bool) -> CertMaterial {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["x.tascloud.app".to_string()]).unwrap();
        if scts {
            params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2], vec![0x04, 0x02, 0x00, 0x00]));
        }
        if poison {
            let mut p = rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 3], vec![0x05, 0x00]);
            p.set_criticality(true);
            params.custom_extensions.push(p);
        }
        let cert = params.self_signed(&key).unwrap();
        CertMaterial { chain_pem: cert.pem(), key_pem: String::new() }
    }

    #[test]
    fn what_we_obtained_must_carry_scts_and_must_not_be_a_precertificate() {
        let m = monitor(vec![]);
        assert!(m.check_obtained("x", &cert_with(true, false)).is_empty());
        let f = m.check_obtained("x", &cert_with(false, false));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, CtFindingKind::MissingEmbeddedScts);
        assert_eq!(f[0].severity, Severity::Error);
        let f = m.check_obtained("x", &cert_with(true, true));
        assert_eq!(f.iter().map(|x| x.kind).collect::<Vec<_>>(), [CtFindingKind::PrecertificateServed]);
        // A test CA that does not log can be exempted explicitly.
        let mut lax = monitor(vec![]);
        lax.scts_required = false;
        assert!(lax.check_obtained("x", &cert_with(false, false)).is_empty());
        // Garbage is not a finding about a certificate.
        assert!(m.check_obtained("x", &CertMaterial { chain_pem: "nope".into(), key_pem: String::new() }).is_empty());
    }

    #[test]
    fn serials_are_compared_without_leading_zeros_or_case() {
        let mut e = Expected::default();
        e.add_serial("0x00AbCd");
        assert!(e.serials.contains("abcd"));
        let cert = cert_with(true, false);
        e.add_material(&cert);
        assert_eq!(e.serials.len(), 2);
    }
}
