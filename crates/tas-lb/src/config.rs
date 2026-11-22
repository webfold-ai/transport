//! Static (local, restart-to-change) configuration.
//!
//! Split from the signed [`crate::backend::BackendSet`] on purpose: what binds sockets, what
//! limits bound memory, and *who may sign the backend set* are properties of the node and its
//! operator, not something the control plane (or whoever compromises it) may rewrite remotely.
//! The signed document can only move traffic between backends the operator-configured listeners
//! already forward to.
//!
//! The control and metrics listeners must bind internal addresses (loopback, RFC 1918, CGNAT
//! 100.64/10 for the Netbird mesh, ULA, link-local). A wildcard or globally routable bind is a
//! configuration error, not a warning: RFC 0031 / CLAUDE.md rule 5 allow only the customer
//! listeners on the public VIP.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use transport::signed_dns::PublicKey;

use crate::cidr::{CidrError, CidrSet};
use crate::flows::Proto;

/// Listener transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProto {
    /// TCP stream forwarding.
    Tcp,
    /// UDP datagram forwarding.
    Udp,
}

impl From<ListenerProto> for Proto {
    fn from(p: ListenerProto) -> Self {
        match p {
            ListenerProto::Tcp => Proto::Tcp,
            ListenerProto::Udp => Proto::Udp,
        }
    }
}

/// One customer-facing listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Unique name (`[a-z0-9-]`, up to 32).
    pub name: String,
    /// TCP or UDP.
    pub proto: ListenerProto,
    /// Address to bind.
    pub bind: SocketAddr,
    /// Port to use on the backends for flows from this listener.
    pub backend_port: u16,
    /// Senders (CIDRs) whose PROXY protocol v2 header is accepted. Empty means nobody; TCP only.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

/// The mesh endpoint the control plane pushes signed configs to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Internal address to listen on.
    pub bind: SocketAddr,
}

/// Bounds. Every default is a deliberate ceiling; see `docs/tas-lb.md` for the memory arithmetic.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Concurrent flows, all listeners.
    pub max_flows: usize,
    /// Concurrent flows per source (IPv4 address / IPv6 /64); 0 disables.
    pub max_flows_per_source: usize,
    /// New flows per second per source; 0 disables.
    pub new_flows_per_source_per_sec: u32,
    /// Connections in setup (PROXY header read + backend connect) at once.
    pub max_pending: usize,
    /// Kernel listen backlog.
    pub accept_backlog: u32,
    /// Backend connect timeout.
    pub connect_timeout_ms: u64,
    /// Time a trusted sender has to deliver its PROXY header.
    pub proxy_header_timeout_ms: u64,
    /// Idle time (no bytes either way) after which a TCP flow is reset.
    pub tcp_idle_timeout_secs: u64,
    /// After one side half-closes, how long the other direction may keep going.
    pub half_close_timeout_secs: u64,
    /// How long a write may make no progress before the flow is reset.
    pub write_stall_timeout_secs: u64,
    /// Idle time after which a UDP flow is dropped.
    pub udp_idle_timeout_secs: u64,
    /// Per-direction copy buffer (held only while data is in flight).
    pub buffer_bytes: usize,
    /// Largest UDP datagram forwarded (larger are dropped and counted).
    pub udp_max_datagram: usize,
    /// How long graceful shutdown waits for flows before resetting them.
    pub shutdown_grace_secs: u64,
    /// TCP keepalive idle time on both legs (dead-peer detection); 0 disables.
    pub tcp_keepalive_secs: u64,
    /// Connect attempts per new flow across distinct backends (>= 1).
    pub connect_attempts: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_flows: 16_384,
            max_flows_per_source: 256,
            new_flows_per_source_per_sec: 200,
            max_pending: 1024,
            accept_backlog: 1024,
            connect_timeout_ms: 3000,
            proxy_header_timeout_ms: 3000,
            tcp_idle_timeout_secs: 350,
            half_close_timeout_secs: 60,
            write_stall_timeout_secs: 30,
            udp_idle_timeout_secs: 30,
            buffer_bytes: 16 * 1024,
            udp_max_datagram: 2048,
            shutdown_grace_secs: 30,
            tcp_keepalive_secs: 60,
            connect_attempts: 2,
        }
    }
}

impl LimitsConfig {
    /// Worst-case buffer memory: every flow with data in flight in both directions.
    #[must_use]
    pub fn worst_case_buffer_bytes(&self) -> usize {
        self.max_flows
            .saturating_mul(self.buffer_bytes)
            .saturating_mul(2)
    }

    /// Backend connect timeout.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }
}

/// The whole static configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    /// Cluster (`PoP`) name; a signed set for any other cluster is refused.
    pub cluster: String,
    /// Directory for the identity key and the persisted last good config (0700 recommended).
    pub state_dir: PathBuf,
    /// The control plane's PUBLIC key, z-base32 (52 chars) or 64 hex. Configs must be signed by
    /// it, and (when `control` is set) the pushing peer's transport identity must be it too.
    pub signer_key: String,
    /// Where the control plane pushes signed configs. Without it only a persisted config applies.
    pub control: Option<ControlConfig>,
    /// Internal bind for `/metrics`, `/healthz`, `/readyz`.
    pub metrics_bind: SocketAddr,
    /// Customer listeners.
    pub listeners: Vec<ListenerConfig>,
    /// Bounds.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Allow signed sets to name loopback backends (dev and tests only).
    #[serde(default)]
    pub allow_loopback_backends: bool,
    /// Operator floor: signed configs must have `seq` strictly greater than this.
    #[serde(default)]
    pub min_config_seq: u64,
}

/// Why a static configuration was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum StaticConfigError {
    /// JSON did not parse.
    Parse(String),
    /// A field is out of range; the text names it.
    Invalid(String),
}

impl core::fmt::Display for StaticConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StaticConfigError::Parse(e) => write!(f, "config parse: {e}"),
            StaticConfigError::Invalid(e) => write!(f, "config invalid: {e}"),
        }
    }
}

impl std::error::Error for StaticConfigError {}

/// Addresses that may carry control or metrics traffic.
#[must_use]
pub fn is_internal(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xC0) == 0x40)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback() || (seg0 & 0xFE00) == 0xFC00 || (seg0 & 0xFFC0) == 0xFE80
        }
    }
}

/// Parse a control-plane public key given as z-base32 or hex.
///
/// # Errors
/// [`StaticConfigError::Invalid`] if it is neither.
pub fn parse_signer_key(s: &str) -> Result<PublicKey, StaticConfigError> {
    let s = s.trim();
    if let Some(raw) = crate::backend::decode_key(s) {
        return PublicKey::from_bytes(&raw)
            .map_err(|_| StaticConfigError::Invalid("signer_key".into()));
    }
    PublicKey::from_z32(s).map_err(|_| StaticConfigError::Invalid("signer_key".into()))
}

impl StaticConfig {
    /// Parse and validate.
    ///
    /// # Errors
    /// [`StaticConfigError`].
    pub fn from_json(text: &str) -> Result<Self, StaticConfigError> {
        let cfg: StaticConfig =
            serde_json::from_str(text).map_err(|e| StaticConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The parsed trust list for listener `l`.
    ///
    /// # Errors
    /// [`CidrError`] for a bad entry.
    pub fn trusted(l: &ListenerConfig) -> Result<CidrSet, CidrError> {
        CidrSet::parse_all(&l.trusted_proxy_cidrs)
    }

    /// Check every field and cross-field rule.
    ///
    /// # Errors
    /// [`StaticConfigError::Invalid`] naming the first problem.
    pub fn validate(&self) -> Result<(), StaticConfigError> {
        let bad = |s: &str| Err(StaticConfigError::Invalid(s.to_string()));
        let name_ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 32
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if !crate::backend::id_ok(&self.cluster) {
            return bad("cluster");
        }
        if !is_internal(self.metrics_bind.ip()) {
            return bad("metrics_bind must be an internal address (not wildcard, not public)");
        }
        if let Some(c) = &self.control {
            if !is_internal(c.bind.ip()) {
                return bad("control.bind must be an internal address (not wildcard, not public)");
            }
        }
        parse_signer_key(&self.signer_key)?;
        if self.listeners.is_empty() || self.listeners.len() > 16 {
            return bad("listeners (1..=16)");
        }
        let mut names = std::collections::HashSet::new();
        for l in &self.listeners {
            if !name_ok(&l.name) || !names.insert(l.name.as_str()) {
                return bad("listeners[].name");
            }
            if l.backend_port == 0 {
                return bad("listeners[].backend_port");
            }
            if l.bind.port() != 0
                && (Some(l.bind) == Some(self.metrics_bind)
                    || self.control.as_ref().is_some_and(|c| c.bind == l.bind))
            {
                return bad("listener collides with the metrics or control bind");
            }
            if Self::trusted(l).is_err() {
                return bad("listeners[].trusted_proxy_cidrs");
            }
            if l.proto == ListenerProto::Udp && !l.trusted_proxy_cidrs.is_empty() {
                return bad("trusted_proxy_cidrs is TCP only (PROXY v2 is not accepted on UDP)");
            }
        }
        let l = &self.limits;
        let checks: [(&str, bool); 14] = [
            ("limits.max_flows", (1..=1_000_000).contains(&l.max_flows)),
            (
                "limits.max_flows_per_source",
                l.max_flows_per_source <= l.max_flows,
            ),
            ("limits.max_pending", (1..=100_000).contains(&l.max_pending)),
            (
                "limits.accept_backlog",
                (1..=65_535).contains(&l.accept_backlog),
            ),
            (
                "limits.connect_timeout_ms",
                (10..=60_000).contains(&l.connect_timeout_ms),
            ),
            (
                "limits.proxy_header_timeout_ms",
                (10..=60_000).contains(&l.proxy_header_timeout_ms),
            ),
            (
                "limits.tcp_idle_timeout_secs",
                (1..=86_400).contains(&l.tcp_idle_timeout_secs),
            ),
            (
                "limits.half_close_timeout_secs",
                (1..=86_400).contains(&l.half_close_timeout_secs),
            ),
            (
                "limits.write_stall_timeout_secs",
                (1..=3600).contains(&l.write_stall_timeout_secs),
            ),
            (
                "limits.udp_idle_timeout_secs",
                (1..=3600).contains(&l.udp_idle_timeout_secs),
            ),
            (
                "limits.buffer_bytes",
                (1024..=262_144).contains(&l.buffer_bytes),
            ),
            (
                "limits.udp_max_datagram",
                (512..=65_507).contains(&l.udp_max_datagram),
            ),
            (
                "limits.connect_attempts",
                (1..=4).contains(&l.connect_attempts),
            ),
            ("limits.shutdown_grace_secs", l.shutdown_grace_secs <= 3600),
        ];
        for (name, ok) in checks {
            if !ok {
                return bad(name);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    const GOOD: &str = r#"{
        "cluster": "pop-syd1",
        "state_dir": "/var/lib/tas-lb",
        "signer_key": "abababababababababababababababababababababababababababababababab",
        "control": {"bind": "100.64.1.2:7443"},
        "metrics_bind": "127.0.0.1:9180",
        "listeners": [
            {"name": "https", "proto": "tcp", "bind": "0.0.0.0:443", "backend_port": 8443, "trusted_proxy_cidrs": ["10.0.0.0/8"]},
            {"name": "quic", "proto": "udp", "bind": "0.0.0.0:443", "backend_port": 8443}
        ]
    }"#;

    #[test]
    fn a_good_config_parses_with_default_limits() {
        let c = StaticConfig::from_json(GOOD).unwrap();
        assert_eq!(c.listeners.len(), 2);
        assert_eq!(c.limits.max_flows, 16_384);
        assert_eq!(c.limits.worst_case_buffer_bytes(), 16_384 * 16 * 1024 * 2);
    }

    fn with(edit: impl Fn(&mut serde_json::Value)) -> Result<StaticConfig, StaticConfigError> {
        let mut v: serde_json::Value = serde_json::from_str(GOOD).unwrap();
        edit(&mut v);
        StaticConfig::from_json(&v.to_string())
    }

    #[test]
    fn public_or_wildcard_internal_listeners_are_refused() {
        for bad in [
            "0.0.0.0:9180",
            "203.0.113.5:9180",
            "[::]:9180",
            "8.8.8.8:9180",
        ] {
            assert!(with(|v| v["metrics_bind"] = bad.into()).is_err(), "{bad}");
            assert!(
                with(|v| v["control"]["bind"] = bad.into()).is_err(),
                "{bad}"
            );
        }
        for good in [
            "127.0.0.1:1",
            "10.1.2.3:1",
            "192.168.0.1:1",
            "172.16.0.1:1",
            "100.64.9.9:1",
            "[fd00::1]:1",
            "[::1]:1",
            "[fe80::1]:1",
        ] {
            assert!(with(|v| v["metrics_bind"] = good.into()).is_ok(), "{good}");
        }
    }

    #[test]
    fn field_errors_are_refused() {
        assert!(with(|v| v["listeners"] = serde_json::json!([])).is_err());
        assert!(with(|v| v["listeners"][0]["name"] = "Bad Name".into()).is_err());
        assert!(
            with(|v| v["listeners"][1]["name"] = "https".into()).is_err(),
            "duplicate name"
        );
        assert!(with(|v| v["listeners"][0]["backend_port"] = 0.into()).is_err());
        assert!(
            with(|v| v["listeners"][0]["trusted_proxy_cidrs"] = serde_json::json!(["nope"]))
                .is_err()
        );
        assert!(
            with(|v| v["listeners"][1]["trusted_proxy_cidrs"] = serde_json::json!(["10.0.0.0/8"]))
                .is_err(),
            "udp has no PROXY accept"
        );
        assert!(with(|v| v["signer_key"] = "not a key".into()).is_err());
        assert!(with(|v| v["limits"] = serde_json::json!({"max_flows": 0})).is_err());
        assert!(with(
            |v| v["limits"] = serde_json::json!({"max_flows": 10, "max_flows_per_source": 11})
        )
        .is_err());
        assert!(with(|v| v["limits"] = serde_json::json!({"buffer_bytes": 1})).is_err());
        assert!(with(|v| v["surprise"] = 1.into()).is_err());
    }

    #[test]
    fn signer_keys_parse_as_hex_or_z32() {
        let pk = transport::signed_dns::Keypair::from_secret_key(&[3; 32]).public_key();
        let hex = crate::backend::hex_encode(pk.as_bytes());
        assert_eq!(parse_signer_key(&hex).unwrap(), pk);
        assert_eq!(parse_signer_key(&pk.to_z32()).unwrap(), pk);
        assert!(parse_signer_key("zzzz").is_err());
    }
}
