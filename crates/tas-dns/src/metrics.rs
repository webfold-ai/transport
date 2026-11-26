//! Counters and the Prometheus text exposition, served from a small internal-only listener.
//!
//! Counters are plain atomics (no allocation on the query path). Per-zone gauges (version,
//! seconds until the first signature expires) are read from the serving set at scrape time and
//! capped at [`MAX_ZONE_SERIES`] zones so tenant count cannot blow up the exposition; label
//! values are validated names, escaped again for the exposition format.

use crate::authority::Serving;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Most zones that get their own series.
pub const MAX_ZONE_SERIES: usize = 5000;

/// One monotonically increasing counter.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Add one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A gauge that can go up and down.
#[derive(Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    /// Increase.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrease (saturating at zero).
    pub fn dec(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Every process-wide counter.
#[derive(Default)]
pub struct Metrics {
    /// Queries received over UDP (after the budget check).
    pub queries_udp: Counter,
    /// Queries received over TCP.
    pub queries_tcp: Counter,
    /// Responses by rcode (index = rcode, 16 = other).
    pub rcode: [Counter; 17],
    /// Responses truncated (TC set by size).
    pub truncated: Counter,
    /// UDP responses withheld by RRL.
    pub rrl_dropped: Counter,
    /// UDP responses replaced by an empty TC response by RRL.
    pub rrl_slipped: Counter,
    /// Queries dropped by the per-source budget.
    pub budget_dropped: Counter,
    /// Datagrams/frames that did not parse.
    pub malformed: Counter,
    /// Datagrams/frames over the size bound.
    pub oversize: Counter,
    /// Queries dropped because too many were already in flight.
    pub overload_dropped: Counter,
    /// TCP connections refused (global or per-source cap).
    pub tcp_refused: Counter,
    /// Open TCP connections.
    pub tcp_open: Gauge,
    /// AXFR/IXFR attempts refused.
    pub transfers_refused: Counter,
    /// Zone updates by outcome: applied, duplicate, stale, fork, invalid, unauthorized, quota.
    pub updates: [Counter; 7],
    /// Registrations by outcome (same order).
    pub registrations: [Counter; 7],
    /// Challenge-label updates by outcome (same order).
    pub challenges: [Counter; 7],
    /// Mesh pulls completed.
    pub sync_pulls: Counter,
    /// Mesh pulls that failed.
    pub sync_errors: Counter,
    /// Zone rebuilds (signing) performed.
    pub rebuilds: Counter,
    /// Zones that could not be built (served SERVFAIL).
    pub rebuild_failures: Counter,
}

/// Index into the outcome counter arrays.
#[must_use]
pub fn outcome_index(o: transport::zone_sync::ApplyOutcome) -> usize {
    use transport::zone_sync::ApplyOutcome as O;
    match o {
        O::Applied => 0,
        O::Duplicate => 1,
        O::Stale => 2,
        O::Fork => 3,
        O::Invalid => 4,
        O::Unauthorized => 5,
        O::Quota => 6,
    }
}

const OUTCOMES: [&str; 7] = [
    "applied",
    "duplicate",
    "stale",
    "fork",
    "invalid",
    "unauthorized",
    "quota",
];

fn label_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c if c.is_ascii_graphic() => o.push(c),
            _ => o.push('?'),
        }
    }
    o
}

impl Metrics {
    /// Record one response by rcode value.
    pub fn count_rcode(&self, code: u16) {
        let idx = usize::from(code.min(16));
        if let Some(c) = self.rcode.get(idx) {
            c.inc();
        }
    }

    /// Render the Prometheus text format, including per-zone gauges from `serving` at `now`.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one linear sequence; splitting it would obscure the order of the steps"
    )]
    pub fn render(&self, serving: &Serving, now: u64) -> String {
        let mut o = String::with_capacity(4096);
        let mut c = |name: &str, help: &str, v: u64| {
            let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}");
        };
        c(
            "tas_dns_queries_udp_total",
            "Queries received over UDP.",
            self.queries_udp.get(),
        );
        c(
            "tas_dns_queries_tcp_total",
            "Queries received over TCP.",
            self.queries_tcp.get(),
        );
        c(
            "tas_dns_truncated_total",
            "Responses truncated by size.",
            self.truncated.get(),
        );
        c(
            "tas_dns_rrl_dropped_total",
            "Responses dropped by response rate limiting.",
            self.rrl_dropped.get(),
        );
        c(
            "tas_dns_rrl_slipped_total",
            "Responses replaced by an empty truncated response by RRL.",
            self.rrl_slipped.get(),
        );
        c(
            "tas_dns_budget_dropped_total",
            "Queries dropped by the per-source budget.",
            self.budget_dropped.get(),
        );
        c(
            "tas_dns_malformed_total",
            "Packets that did not parse.",
            self.malformed.get(),
        );
        c(
            "tas_dns_oversize_total",
            "Packets over the size bound.",
            self.oversize.get(),
        );
        c(
            "tas_dns_overload_dropped_total",
            "Queries dropped under overload.",
            self.overload_dropped.get(),
        );
        c(
            "tas_dns_tcp_refused_total",
            "TCP connections refused by caps.",
            self.tcp_refused.get(),
        );
        c(
            "tas_dns_transfers_refused_total",
            "AXFR/IXFR requests refused.",
            self.transfers_refused.get(),
        );
        c(
            "tas_dns_sync_pulls_total",
            "Mesh anti-entropy pulls completed.",
            self.sync_pulls.get(),
        );
        c(
            "tas_dns_sync_errors_total",
            "Mesh anti-entropy pulls failed.",
            self.sync_errors.get(),
        );
        c(
            "tas_dns_rebuilds_total",
            "Zone rebuilds (re-sign) performed.",
            self.rebuilds.get(),
        );
        c(
            "tas_dns_rebuild_failures_total",
            "Zone rebuilds that failed (zone served SERVFAIL).",
            self.rebuild_failures.get(),
        );
        let _ = writeln!(o, "# HELP tas_dns_tcp_open Open TCP connections.\n# TYPE tas_dns_tcp_open gauge\ntas_dns_tcp_open {}", self.tcp_open.get());
        let _ = writeln!(o, "# HELP tas_dns_responses_total Responses by rcode.\n# TYPE tas_dns_responses_total counter");
        for (i, ctr) in self.rcode.iter().enumerate() {
            let label = if i == 16 {
                "other".to_string()
            } else {
                i.to_string()
            };
            let _ = writeln!(
                o,
                "tas_dns_responses_total{{rcode=\"{label}\"}} {}",
                ctr.get()
            );
        }
        for (name, arr) in [
            ("tas_dns_zone_updates_total", &self.updates),
            ("tas_dns_registrations_total", &self.registrations),
            ("tas_dns_challenge_updates_total", &self.challenges),
        ] {
            let _ = writeln!(
                o,
                "# HELP {name} Replicated objects by outcome.\n# TYPE {name} counter"
            );
            for (i, ctr) in arr.iter().enumerate() {
                let _ = writeln!(
                    o,
                    "{name}{{outcome=\"{}\"}} {}",
                    OUTCOMES.get(i).copied().unwrap_or("?"),
                    ctr.get()
                );
            }
        }
        let mut zones = serving.snapshot();
        zones.sort_by_key(|(n, _)| n.to_ascii());
        let _ = writeln!(
            o,
            "# HELP tas_dns_zones Zones served.\n# TYPE tas_dns_zones gauge\ntas_dns_zones {}",
            zones.len()
        );
        let _ = writeln!(o, "# HELP tas_dns_zone_version Zone version (SOA serial).\n# TYPE tas_dns_zone_version gauge");
        for (n, i) in zones.iter().take(MAX_ZONE_SERIES) {
            let _ = writeln!(
                o,
                "tas_dns_zone_version{{zone=\"{}\"}} {}",
                label_escape(&n.to_ascii()),
                i.version
            );
        }
        let _ = writeln!(
            o,
            "# HELP tas_dns_zone_signature_expiry_seconds Seconds until the first RRSIG of a signed zone expires (negative: expired).\n# TYPE tas_dns_zone_signature_expiry_seconds gauge"
        );
        for (n, i) in zones
            .iter()
            .filter(|(_, i)| i.signed && !i.failed)
            .take(MAX_ZONE_SERIES)
        {
            let left = i64::try_from(i.earliest_expiry).unwrap_or(i64::MAX)
                - i64::try_from(now).unwrap_or(0);
            let _ = writeln!(
                o,
                "tas_dns_zone_signature_expiry_seconds{{zone=\"{}\"}} {left}",
                label_escape(&n.to_ascii())
            );
        }
        let _ = writeln!(o, "# HELP tas_dns_zone_failed Zones that cannot be served (1).\n# TYPE tas_dns_zone_failed gauge");
        for (n, _) in zones.iter().filter(|(_, i)| i.failed).take(MAX_ZONE_SERIES) {
            let _ = writeln!(
                o,
                "tas_dns_zone_failed{{zone=\"{}\"}} 1",
                label_escape(&n.to_ascii())
            );
        }
        o
    }
}

/// `<apex>. IN DS ...` lines for a signed zone, or `None` if it is not served signed.
fn ds_lines(serving: &Serving, name: &str) -> Option<String> {
    let apex = crate::names::parse_fqdn_no_wildcard(name).ok()?;
    let info = serving.info(&apex)?;
    if !info.signed || info.failed || info.ds.is_empty() {
        return None;
    }
    let mut out = String::new();
    for d in &info.ds {
        let _ = writeln!(out, "{} IN DS {d}", apex.to_ascii());
    }
    Some(out)
}

/// Serve `GET /metrics`, `GET /healthz` and `GET /ds/<apex>` and `GET /healthz` on `listener` until `shutdown`. This listener is for
/// the internal network only: it never reads more than 4 KiB of request, answers three paths, and
/// closes after one response.
pub async fn serve_metrics(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
    serving: Arc<Serving>,
    clock: impl Fn() -> u64 + Send + Sync + 'static,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let clock = Arc::new(clock);
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let accepted = tokio::select! {
            () = crate::server::wait_shutdown(&mut shutdown) => return,
            r = listener.accept() => r,
        };
        let Ok((mut stream, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (m, s, clock) = (metrics.clone(), serving.clone(), clock.clone());
        tokio::spawn(async move {
            let _permit = permit;
            // read until the end of the request head (or the 4 KiB bound / 3 s timeout)
            let mut buf = [0u8; 4096];
            let mut n = 0usize;
            let read_head = async {
                while n < buf.len() {
                    let Some(rest) = buf.get_mut(n..) else { break };
                    match stream.read(rest).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => n += k,
                    }
                    let head = buf.get(..n).unwrap_or(&[]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n")
                        || head.windows(2).any(|w| w == b"\n\n")
                    {
                        break;
                    }
                }
            };
            if tokio::time::timeout(Duration::from_secs(3), read_head)
                .await
                .is_err()
            {
                return;
            }
            let req = buf.get(..n).unwrap_or(&[]);
            let first = req
                .split(|b| *b == b'\r' || *b == b'\n')
                .next()
                .unwrap_or(&[]);
            let (status, body) =
                if first.starts_with(b"GET /metrics ") || first.starts_with(b"GET /metrics?") {
                    ("200 OK", m.render(&s, clock()))
                } else if first.starts_with(b"GET /healthz ") {
                    ("200 OK", "ok\n".to_string())
                } else if let Some(rest) = first.strip_prefix(b"GET /ds/") {
                    // the DS records a parent should hold for a signed zone (public data)
                    let name = rest
                        .split(|b| *b == b' ')
                        .next()
                        .and_then(|n| std::str::from_utf8(n).ok())
                        .unwrap_or("");
                    match ds_lines(&s, name) {
                        Some(body) => ("200 OK", body),
                        None => ("404 Not Found", "not found\n".to_string()),
                    }
                } else {
                    ("404 Not Found", "not found\n".to_string())
                };
            let resp = format!("HTTP/1.0 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.write_all(resp.as_bytes()))
                .await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped_for_the_exposition_format() {
        assert_eq!(label_escape("a\"b\\c\nd\u{e9}"), "a\\\"b\\\\c\\nd?");
    }

    #[test]
    fn counters_and_gauges_behave() {
        let c = Counter::default();
        c.inc();
        c.inc();
        assert_eq!(c.get(), 2);
        let g = Gauge::default();
        g.dec();
        assert_eq!(g.get(), 0, "never underflows");
        g.inc();
        g.inc();
        g.dec();
        assert_eq!(g.get(), 1);
        let m = Metrics::default();
        m.count_rcode(3);
        m.count_rcode(999);
        assert_eq!((m.rcode[3].get(), m.rcode[16].get()), (1, 1));
    }

    #[test]
    fn the_exposition_has_the_required_series_even_when_empty() {
        let text = Metrics::default().render(&Serving::new(), 0);
        for series in [
            "tas_dns_queries_udp_total",
            "tas_dns_rrl_dropped_total",
            "tas_dns_responses_total{rcode=\"0\"}",
            "tas_dns_zone_updates_total{outcome=\"fork\"}",
            "tas_dns_zones 0",
        ] {
            assert!(text.contains(series), "{series}");
        }
    }
}
