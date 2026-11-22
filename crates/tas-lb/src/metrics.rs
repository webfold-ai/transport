//! Counters and the Prometheus text exposition.
//!
//! Every label value comes from a fixed enum, so cardinality is bounded by construction (the one
//! exception, per-backend gauges, is bounded by the validated backend count and charset-checked
//! ids). Nothing here ever holds, formats or logs payload bytes or PROXY TLV contents; client
//! addresses are not labels.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// A counter family with a fixed label set.
pub struct Family<const N: usize> {
    labels: [&'static str; N],
    values: [AtomicU64; N],
}

impl<const N: usize> Family<N> {
    fn new(labels: [&'static str; N]) -> Self {
        Family {
            labels,
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Increment the counter for label index `i` (out-of-range is ignored).
    pub fn inc(&self, i: usize) {
        if let Some(v) = self.values.get(i) {
            v.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Current value for label index `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> u64 {
        self.values.get(i).map_or(0, |v| v.load(Ordering::Relaxed))
    }

    fn render(&self, out: &mut String, name: &str, label: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        for (l, v) in self.labels.iter().zip(&self.values) {
            let _ = writeln!(
                out,
                "{name}{{{label}=\"{l}\"}} {}",
                v.load(Ordering::Relaxed)
            );
        }
    }
}

/// Why a connection or datagram was refused before it became a flow.
#[derive(Debug, Clone, Copy)]
pub enum Reject {
    /// Global flow bound.
    MaxFlows = 0,
    /// Per-source flow bound.
    PerSource,
    /// Per-source new-flow rate.
    RateLimited,
    /// Too many connections in setup.
    PendingFull,
    /// No eligible backend.
    NoBackend,
    /// Every backend attempt failed to connect.
    ConnectFailed,
    /// A PROXY v2 signature from a sender not in the trust list.
    ProxyUntrusted,
    /// Oversize UDP datagram.
    UdpTooBig,
    /// The LB is shutting down.
    ShuttingDown,
}

const REJECT_LABELS: [&str; 9] = [
    "max_flows",
    "per_source",
    "rate_limited",
    "pending_full",
    "no_backend",
    "connect_failed",
    "proxy_untrusted",
    "udp_too_big",
    "shutting_down",
];

/// Why a PROXY header from a trusted sender was refused (parse labels, then I/O outcomes).
pub const PROXY_IN_LABELS: [&str; 12] = [
    "bad_signature",
    "bad_version",
    "bad_command",
    "bad_family",
    "too_long",
    "truncated",
    "bad_length",
    "bad_tlv",
    "bad_address",
    "timeout",
    "io",
    "transport_mismatch",
];

/// Why a flow ended.
#[derive(Debug, Clone, Copy)]
pub enum Closed {
    /// Both directions finished.
    Clean = 0,
    /// Idle timeout.
    Idle,
    /// I/O error.
    Error,
    /// Reset by drain expiry.
    DrainReset,
    /// Reset at shutdown.
    ShutdownReset,
    /// Half-close grace expired.
    HalfCloseTimeout,
}

const CLOSED_LABELS: [&str; 6] = [
    "clean",
    "idle",
    "error",
    "drain_reset",
    "shutdown_reset",
    "half_close_timeout",
];

/// Outcome of a config push or load.
#[derive(Debug, Clone, Copy)]
pub enum ConfigResult {
    /// Verified and applied.
    Applied = 0,
    /// Signature did not verify.
    BadSignature,
    /// Sequence number not greater than the last accepted.
    Rollback,
    /// Signed for another cluster.
    WrongCluster,
    /// Verified but the contents are invalid.
    Invalid,
    /// Too large or structurally malformed.
    Malformed,
    /// Could not persist the new floor; refused.
    PersistFailed,
    /// Connection was not from the control plane.
    PeerRejected,
}

const CONFIG_LABELS: [&str; 8] = [
    "applied",
    "bad_signature",
    "rollback",
    "wrong_cluster",
    "invalid",
    "malformed",
    "persist_failed",
    "peer_rejected",
];

/// All counters.
pub struct Metrics {
    /// Connections / flows accepted into the table, by protocol (`tcp`, `udp`).
    pub flows: Family<2>,
    /// Refusals before a flow existed.
    pub rejected: Family<9>,
    /// PROXY v2 headers refused from trusted senders.
    pub proxy_in_rejected: Family<12>,
    /// PROXY v2 headers accepted from trusted senders.
    pub proxy_in_accepted: AtomicU64,
    /// PROXY v2 headers emitted to backends.
    pub proxy_out: AtomicU64,
    /// Flow endings.
    pub closed: Family<6>,
    /// Config applications / refusals.
    pub config: Family<8>,
    /// Health transitions, by new state.
    pub health_transitions: Family<3>,
    /// Bytes client to backend.
    pub bytes_up: AtomicU64,
    /// Bytes backend to client.
    pub bytes_down: AtomicU64,
    /// UDP datagrams forwarded to backends.
    pub udp_datagrams_up: AtomicU64,
    /// UDP datagrams forwarded to clients.
    pub udp_datagrams_down: AtomicU64,
    /// Accept errors (EMFILE and friends).
    pub accept_errors: AtomicU64,
    /// Sequence number of the config in force.
    pub config_seq: AtomicU64,
    /// Unix time the current config was applied.
    pub config_applied_unix: AtomicU64,
    /// Unix time of the last refused config (0 = never): alert on it moving.
    pub config_rejected_unix: AtomicU64,
    /// Table generation number.
    pub generation: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            flows: Family::new(["tcp", "udp"]),
            rejected: Family::new(REJECT_LABELS),
            proxy_in_rejected: Family::new(PROXY_IN_LABELS),
            proxy_in_accepted: AtomicU64::new(0),
            proxy_out: AtomicU64::new(0),
            closed: Family::new(CLOSED_LABELS),
            config: Family::new(CONFIG_LABELS),
            health_transitions: Family::new(["unknown", "up", "down"]),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            udp_datagrams_up: AtomicU64::new(0),
            udp_datagrams_down: AtomicU64::new(0),
            accept_errors: AtomicU64::new(0),
            config_seq: AtomicU64::new(0),
            config_applied_unix: AtomicU64::new(0),
            config_rejected_unix: AtomicU64::new(0),
            generation: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    /// Count a refusal.
    pub fn reject(&self, r: Reject) {
        self.rejected.inc(r as usize);
    }

    /// Count a flow ending.
    pub fn close(&self, c: Closed) {
        self.closed.inc(c as usize);
    }

    /// Count a config outcome.
    pub fn config_result(&self, r: ConfigResult) {
        self.config.inc(r as usize);
    }

    /// Add `n` to a plain counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

/// Point-in-time values the Director and flow table contribute at render time.
#[derive(Debug, Default)]
pub struct Gauges {
    /// Tracked flows.
    pub flows_active: usize,
    /// One entry per live backend.
    pub backends: Vec<BackendGauge>,
    /// Whether a config is in force.
    pub config_loaded: bool,
}

/// One backend's gauges.
#[derive(Debug)]
pub struct BackendGauge {
    /// Backend id (charset-validated).
    pub id: String,
    /// 1 if Up, 0 otherwise.
    pub up: bool,
    /// `unknown`, `up`, `down`.
    pub health: &'static str,
    /// `active`, `draining` (admin or unhealthy with flows) or `removed`.
    pub admin: &'static str,
    /// Pinned flows.
    pub flows: u64,
    /// Weight.
    pub weight: u32,
}

fn esc(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            '\n' => vec!['\\', 'n'],
            c => vec![c],
        })
        .collect()
}

impl Metrics {
    /// Render the Prometheus text format.
    #[must_use]
    pub fn render(&self, g: &Gauges) -> String {
        let mut o = String::with_capacity(4096);
        self.flows
            .render(&mut o, "tas_lb_flows_total", "proto", "Flows admitted.");
        self.rejected.render(
            &mut o,
            "tas_lb_rejected_total",
            "reason",
            "Connections or datagrams refused before becoming a flow.",
        );
        self.proxy_in_rejected.render(
            &mut o,
            "tas_lb_proxy_in_rejected_total",
            "reason",
            "PROXY v2 headers refused from trusted senders.",
        );
        self.closed.render(
            &mut o,
            "tas_lb_flows_closed_total",
            "reason",
            "Flow endings.",
        );
        self.config.render(
            &mut o,
            "tas_lb_config_total",
            "result",
            "Signed config applications and refusals.",
        );
        self.health_transitions.render(
            &mut o,
            "tas_lb_health_transitions_total",
            "to",
            "Backend health transitions.",
        );
        let plain = |o: &mut String, name: &str, kind: &str, help: &str, v: u64| {
            let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {v}");
        };
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        plain(
            &mut o,
            "tas_lb_proxy_in_accepted_total",
            "counter",
            "PROXY v2 headers accepted from trusted senders.",
            ld(&self.proxy_in_accepted),
        );
        plain(
            &mut o,
            "tas_lb_proxy_out_total",
            "counter",
            "PROXY v2 headers sent to backends.",
            ld(&self.proxy_out),
        );
        plain(
            &mut o,
            "tas_lb_bytes_up_total",
            "counter",
            "Bytes client to backend.",
            ld(&self.bytes_up),
        );
        plain(
            &mut o,
            "tas_lb_bytes_down_total",
            "counter",
            "Bytes backend to client.",
            ld(&self.bytes_down),
        );
        plain(
            &mut o,
            "tas_lb_udp_datagrams_up_total",
            "counter",
            "UDP datagrams to backends.",
            ld(&self.udp_datagrams_up),
        );
        plain(
            &mut o,
            "tas_lb_udp_datagrams_down_total",
            "counter",
            "UDP datagrams to clients.",
            ld(&self.udp_datagrams_down),
        );
        plain(
            &mut o,
            "tas_lb_accept_errors_total",
            "counter",
            "accept(2) errors.",
            ld(&self.accept_errors),
        );
        plain(
            &mut o,
            "tas_lb_config_seq",
            "gauge",
            "Sequence number of the config in force.",
            ld(&self.config_seq),
        );
        plain(
            &mut o,
            "tas_lb_config_applied_unixtime",
            "gauge",
            "Unix time the config in force was applied.",
            ld(&self.config_applied_unix),
        );
        plain(
            &mut o,
            "tas_lb_config_rejected_unixtime",
            "gauge",
            "Unix time of the most recent refused config (0 = never). Alert when it moves.",
            ld(&self.config_rejected_unix),
        );
        plain(
            &mut o,
            "tas_lb_table_generation",
            "gauge",
            "Maglev table generation.",
            ld(&self.generation),
        );
        plain(
            &mut o,
            "tas_lb_flows_active",
            "gauge",
            "Tracked flows.",
            g.flows_active as u64,
        );
        plain(
            &mut o,
            "tas_lb_config_loaded",
            "gauge",
            "1 if a verified config is in force.",
            u64::from(g.config_loaded),
        );
        let _ = writeln!(o, "# HELP tas_lb_backend_up 1 if the backend takes new flows.\n# TYPE tas_lb_backend_up gauge");
        for b in &g.backends {
            let _ = writeln!(
                o,
                "tas_lb_backend_up{{backend=\"{}\",health=\"{}\",admin=\"{}\"}} {}",
                esc(&b.id),
                b.health,
                b.admin,
                u8::from(b.up)
            );
        }
        let _ = writeln!(o, "# HELP tas_lb_backend_flows Flows pinned to the backend.\n# TYPE tas_lb_backend_flows gauge");
        for b in &g.backends {
            let _ = writeln!(
                o,
                "tas_lb_backend_flows{{backend=\"{}\"}} {}",
                esc(&b.id),
                b.flows
            );
        }
        let _ = writeln!(
            o,
            "# HELP tas_lb_backend_weight Configured weight.\n# TYPE tas_lb_backend_weight gauge"
        );
        for b in &g.backends {
            let _ = writeln!(
                o,
                "tas_lb_backend_weight{{backend=\"{}\"}} {}",
                esc(&b.id),
                b.weight
            );
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_with_their_labels() {
        let m = Metrics::default();
        m.reject(Reject::PerSource);
        m.reject(Reject::PerSource);
        m.config_result(ConfigResult::Rollback);
        let text = m.render(&Gauges::default());
        assert!(
            text.contains("tas_lb_rejected_total{reason=\"per_source\"} 2"),
            "{text}"
        );
        assert!(text.contains("tas_lb_config_total{result=\"rollback\"} 1"));
        assert!(text.contains("tas_lb_proxy_in_rejected_total{reason=\"bad_signature\"} 0"));
    }

    #[test]
    fn label_arrays_match_their_enums() {
        // The last variant's index must be the last label.
        assert_eq!(Reject::ShuttingDown as usize, REJECT_LABELS.len() - 1);
        assert_eq!(Closed::HalfCloseTimeout as usize, CLOSED_LABELS.len() - 1);
        assert_eq!(ConfigResult::PeerRejected as usize, CONFIG_LABELS.len() - 1);
    }

    #[test]
    fn backend_gauges_escape_ids() {
        let m = Metrics::default();
        let g = Gauges {
            flows_active: 3,
            config_loaded: true,
            backends: vec![BackendGauge {
                id: "a\"b".into(),
                up: true,
                health: "up",
                admin: "active",
                flows: 2,
                weight: 100,
            }],
        };
        let t = m.render(&g);
        assert!(t.contains("backend=\"a\\\"b\""));
        assert!(t.contains("tas_lb_flows_active 3"));
    }

    #[test]
    fn out_of_range_increments_are_ignored() {
        let m = Metrics::default();
        m.flows.inc(99);
        assert_eq!(m.flows.get(99), 0);
    }
}
