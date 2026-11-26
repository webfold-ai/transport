//! The backend set: what the control plane signs and the LB enforces.
//!
//! A [`BackendSet`] is the *whole* desired state for the backend side of this LB (members,
//! weights, drain flags, health parameters, the flow-hash key). It is replaced atomically, never
//! patched, so a half-applied update cannot exist and a verified set is self-describing.
//!
//! Everything arriving here is attacker-influenced until its signature has been checked, and is
//! validated after as well: the signature proves *who* wrote it, not that it is sane.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Most backends one set may carry. Maglev's table is 65 537 slots; the original paper wants at
/// least 100 slots per backend for ~1% imbalance, so 256 backends (256 slots each) is well inside.
pub const MAX_BACKENDS: usize = 256;
/// Largest accepted weight; weights are relative.
pub const MAX_WEIGHT: u16 = 1000;
/// Longest cluster / backend id.
pub const MAX_ID_LEN: usize = 64;

/// One member of the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSpec {
    /// Stable identity, unique within the set (`[A-Za-z0-9._-]`, 1..=64).
    pub id: String,
    /// Address of the backend (the port comes from each listener's `backend_port`).
    pub ip: IpAddr,
    /// Relative share of *new* flows (1..=1000).
    #[serde(default = "default_weight")]
    pub weight: u16,
    /// Administratively draining: takes no new flows, existing flows finish or are reset after
    /// the drain timeout.
    #[serde(default)]
    pub drain: bool,
}

fn default_weight() -> u16 {
    100
}

/// Active health-check parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSpec {
    /// Time between probes of one backend.
    #[serde(default = "default_interval")]
    pub interval_ms: u64,
    /// Per-probe connect timeout (must not exceed the interval).
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Consecutive successes for a Down backend to become Up.
    #[serde(default = "default_rise")]
    pub rise: u32,
    /// Consecutive failures for Up/Unknown to become Down.
    #[serde(default = "default_fall")]
    pub fall: u32,
    /// Count connect failures seen by real traffic as probe failures (passive checking).
    #[serde(default = "default_true")]
    pub passive: bool,
    /// Probe port; unset means the first TCP listener's `backend_port`.
    #[serde(default)]
    pub port: Option<u16>,
}

fn default_interval() -> u64 {
    2000
}
fn default_timeout() -> u64 {
    1000
}
fn default_rise() -> u32 {
    2
}
fn default_fall() -> u32 {
    3
}
fn default_true() -> bool {
    true
}

impl Default for HealthSpec {
    fn default() -> Self {
        HealthSpec {
            interval_ms: default_interval(),
            timeout_ms: default_timeout(),
            rise: default_rise(),
            fall: default_fall(),
            passive: true,
            port: None,
        }
    }
}

/// The signed document body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSet {
    /// Which LB cluster (`PoP`) this is for. A set for another cluster is refused even when its
    /// signature is valid, so one `PoP`'s config cannot be replayed into another.
    pub cluster: String,
    /// 32-byte key (hex) of the flow hash that picks a backend for a new flow. Secret: it is what
    /// stops a client from steering its flows onto one backend. All nodes of a cluster share it.
    pub hash_key: String,
    /// Emit a PROXY protocol v2 header to backends (TCP: once at connection start; UDP: on every
    /// datagram).
    #[serde(default = "default_true")]
    pub send_proxy_v2: bool,
    /// How long a removed / unhealthy / draining backend keeps its existing flows before they are
    /// reset.
    pub drain_timeout_ms: u64,
    /// Health checking.
    #[serde(default)]
    pub health: HealthSpec,
    /// Members.
    pub backends: Vec<BackendSpec>,
}

impl core::fmt::Debug for BackendSet {
    /// The hash key is a secret; it is never rendered.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackendSet")
            .field("cluster", &self.cluster)
            .field("hash_key", &"<redacted>")
            .field("send_proxy_v2", &self.send_proxy_v2)
            .field("drain_timeout_ms", &self.drain_timeout_ms)
            .field("health", &self.health)
            .field("backends", &self.backends)
            .finish()
    }
}

/// Why a set was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    /// A field is out of range or malformed; the text names the field, never a value that could be secret.
    Invalid(&'static str),
}

impl core::fmt::Display for SetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SetError::Invalid(what) => write!(f, "backend set invalid: {what}"),
        }
    }
}

impl std::error::Error for SetError {}

pub(crate) fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Lowercase hex.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Decode a 64-hex-character key.
pub(crate) fn decode_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        *out.get_mut(i)? = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

impl BackendSet {
    /// Check every field. `allow_loopback` is the operator's static opt-in for backends on
    /// loopback (tests, single-host dev): otherwise a signed set may not aim the LB at itself.
    ///
    /// # Errors
    /// [`SetError::Invalid`] naming the first offending field.
    pub fn validate(&self, allow_loopback: bool) -> Result<(), SetError> {
        if !id_ok(&self.cluster) {
            return Err(SetError::Invalid("cluster"));
        }
        if decode_key(&self.hash_key).is_none() {
            return Err(SetError::Invalid("hash_key"));
        }
        if !(1..=86_400_000).contains(&self.drain_timeout_ms) {
            return Err(SetError::Invalid("drain_timeout_ms"));
        }
        let h = &self.health;
        if !(20..=60_000).contains(&h.interval_ms) {
            return Err(SetError::Invalid("health.interval_ms"));
        }
        if h.timeout_ms < 10 || h.timeout_ms > h.interval_ms {
            return Err(SetError::Invalid("health.timeout_ms"));
        }
        if !(1..=20).contains(&h.rise) || !(1..=20).contains(&h.fall) {
            return Err(SetError::Invalid("health.rise/fall"));
        }
        if h.port == Some(0) {
            return Err(SetError::Invalid("health.port"));
        }
        if self.backends.is_empty() || self.backends.len() > MAX_BACKENDS {
            return Err(SetError::Invalid("backends (count)"));
        }
        let mut seen = std::collections::HashSet::new();
        for b in &self.backends {
            if !id_ok(&b.id) || !seen.insert(b.id.as_str()) {
                return Err(SetError::Invalid("backends[].id"));
            }
            if b.weight == 0 || b.weight > MAX_WEIGHT {
                return Err(SetError::Invalid("backends[].weight"));
            }
            let ip = b.ip.to_canonical();
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(SetError::Invalid("backends[].ip"));
            }
            if ip.is_loopback() && !allow_loopback {
                return Err(SetError::Invalid("backends[].ip (loopback not allowed)"));
            }
        }
        Ok(())
    }

    /// The decoded flow-hash key (valid after [`Self::validate`]).
    #[must_use]
    pub fn hash_key_bytes(&self) -> Option<[u8; 32]> {
        decode_key(&self.hash_key)
    }
}

/// A live backend as the data plane sees it. Identity is fixed at creation (`serial` is unique
/// for the process lifetime), so a flow holding an `Arc<Backend>` cannot be re-pointed at another
/// backend by any later change to the set: that immutability *is* the pinning guarantee for the
/// userspace plane.
pub struct Backend {
    /// Id from the signed set.
    pub id: String,
    /// Address.
    pub ip: IpAddr,
    /// Process-unique, never reused.
    pub serial: u64,
    /// Flows pinned (plus connects in flight) on this backend.
    flows: AtomicU64,
    /// Set (under the director's lock, only when `flows == 0`) when the backend is deleted.
    retired: AtomicBool,
    /// Whether a health-prober task has been started for it.
    prober_started: AtomicBool,
    /// A passive failure has been reported and not yet cleared by a success.
    recent_failure: AtomicBool,
}

impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Backend")
            .field("id", &self.id)
            .field("ip", &self.ip)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}

impl Backend {
    pub(crate) fn new(id: String, ip: IpAddr, serial: u64) -> Self {
        Backend {
            id,
            ip,
            serial,
            flows: AtomicU64::new(0),
            retired: AtomicBool::new(false),
            prober_started: AtomicBool::new(false),
            recent_failure: AtomicBool::new(false),
        }
    }

    /// Flows currently pinned here (including connects in flight).
    #[must_use]
    pub fn flows(&self) -> u64 {
        self.flows.load(Ordering::SeqCst)
    }

    /// Whether the director has deleted this backend.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
    }

    /// Undo [`Backend::retire`] when a lease raced in (see [`Lease::acquire`]).
    pub(crate) fn unretire(&self) {
        self.retired.store(false, Ordering::SeqCst);
    }

    /// Record a passive failure.
    pub(crate) fn note_failure(&self) {
        self.recent_failure.store(true, Ordering::Relaxed);
    }

    /// Whether a success needs reporting to clear a failure streak (true once per failure run);
    /// keeps the director's lock off the connect fast path.
    pub(crate) fn take_failure_flag(&self) -> bool {
        self.recent_failure.swap(false, Ordering::Relaxed)
    }

    /// Claim the right to start this backend's prober (true exactly once).
    pub(crate) fn claim_prober(&self) -> bool {
        !self.prober_started.swap(true, Ordering::SeqCst)
    }
}

/// A hold on a backend: counts one flow (or connect in flight) against it so the drain logic can
/// see it. Dropping releases the count.
pub struct Lease {
    backend: Arc<Backend>,
    /// Whether the generation that chose this backend asked for PROXY v2 to be sent.
    pub send_proxy: bool,
}

impl Lease {
    /// Take a lease, or `None` if the backend was retired concurrently. The increment happens
    /// before the retired check and the director sets `retired` only after seeing `flows == 0`
    /// (all `SeqCst`), so either the director sees this lease or this lease sees the retirement.
    pub(crate) fn acquire(backend: &Arc<Backend>, send_proxy: bool) -> Option<Lease> {
        backend.flows.fetch_add(1, Ordering::SeqCst);
        if backend.retired.load(Ordering::SeqCst) {
            backend.flows.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Lease {
            backend: backend.clone(),
            send_proxy,
        })
    }

    /// The backend this lease pins.
    #[must_use]
    pub fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.backend.flows.fetch_sub(1, Ordering::SeqCst);
    }
}

impl core::fmt::Debug for Lease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lease")
            .field("backend", &self.backend.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    pub(crate) fn key() -> String {
        "ab".repeat(32)
    }

    pub(crate) fn set(n: usize) -> BackendSet {
        BackendSet {
            cluster: "pop-test".into(),
            hash_key: key(),
            send_proxy_v2: true,
            drain_timeout_ms: 5000,
            health: HealthSpec::default(),
            backends: (0..n)
                .map(|i| BackendSpec {
                    id: format!("edge-{i}"),
                    ip: format!("10.0.0.{}", i + 1).parse().unwrap(),
                    weight: 100,
                    drain: false,
                })
                .collect(),
        }
    }

    #[test]
    fn a_sane_set_validates() {
        set(3).validate(false).unwrap();
    }

    #[test]
    fn each_bad_field_is_refused() {
        type Edit = Box<dyn Fn(&mut BackendSet)>;
        let bad: Vec<(&str, Edit)> = vec![
            ("cluster", Box::new(|s| s.cluster = "has space".into())),
            ("cluster empty", Box::new(|s| s.cluster.clear())),
            ("hash_key short", Box::new(|s| s.hash_key = "ab".into())),
            (
                "hash_key non-hex",
                Box::new(|s| s.hash_key = "zz".repeat(32)),
            ),
            ("drain 0", Box::new(|s| s.drain_timeout_ms = 0)),
            ("drain huge", Box::new(|s| s.drain_timeout_ms = 86_400_001)),
            ("interval", Box::new(|s| s.health.interval_ms = 1)),
            (
                "timeout>interval",
                Box::new(|s| s.health.timeout_ms = s.health.interval_ms + 1),
            ),
            ("rise 0", Box::new(|s| s.health.rise = 0)),
            ("fall 0", Box::new(|s| s.health.fall = 0)),
            ("port 0", Box::new(|s| s.health.port = Some(0))),
            ("no backends", Box::new(|s| s.backends.clear())),
            (
                "dup id",
                Box::new(|s| s.backends[1].id = s.backends[0].id.clone()),
            ),
            ("bad id", Box::new(|s| s.backends[0].id = "a/b".into())),
            ("weight 0", Box::new(|s| s.backends[0].weight = 0)),
            (
                "weight big",
                Box::new(|s| s.backends[0].weight = MAX_WEIGHT + 1),
            ),
            (
                "unspecified",
                Box::new(|s| s.backends[0].ip = "0.0.0.0".parse().unwrap()),
            ),
            (
                "multicast",
                Box::new(|s| s.backends[0].ip = "224.0.0.1".parse().unwrap()),
            ),
            (
                "loopback",
                Box::new(|s| s.backends[0].ip = "127.0.0.1".parse().unwrap()),
            ),
            (
                "mapped loopback",
                Box::new(|s| s.backends[0].ip = "::ffff:127.0.0.1".parse().unwrap()),
            ),
        ];
        for (name, f) in bad {
            let mut s = set(3);
            f(&mut s);
            assert!(s.validate(false).is_err(), "{name} must be refused");
        }
    }

    #[test]
    fn too_many_backends_are_refused() {
        let mut s = set(2);
        s.backends = (0..=MAX_BACKENDS)
            .map(|i| BackendSpec {
                id: format!("e{i}"),
                ip: "10.1.0.1".parse().unwrap(),
                weight: 1,
                drain: false,
            })
            .collect();
        assert!(s.validate(false).is_err());
    }

    #[test]
    fn loopback_is_allowed_only_by_static_opt_in() {
        let mut s = set(1);
        s.backends[0].ip = "127.0.0.1".parse().unwrap();
        assert!(s.validate(false).is_err());
        s.validate(true).unwrap();
    }

    #[test]
    fn unknown_json_fields_are_refused() {
        let j = r#"{"cluster":"c","hash_key":"","drain_timeout_ms":1,"backends":[],"surprise":1}"#;
        assert!(serde_json::from_str::<BackendSet>(j).is_err());
    }

    #[test]
    fn debug_never_shows_the_hash_key() {
        let s = set(1);
        assert!(!format!("{s:?}").contains(&key()));
    }

    #[test]
    fn a_lease_counts_and_a_retired_backend_refuses_new_leases() {
        let b = Arc::new(Backend::new("x".into(), "10.0.0.1".parse().unwrap(), 1));
        let l = Lease::acquire(&b, true).unwrap();
        assert_eq!(b.flows(), 1);
        drop(l);
        assert_eq!(b.flows(), 0);
        b.retire();
        assert!(Lease::acquire(&b, true).is_none());
        assert_eq!(b.flows(), 0, "a refused lease leaves no count behind");
    }

    #[test]
    fn decode_key_round_trips() {
        assert_eq!(decode_key(&key()), Some([0xab; 32]));
        assert_eq!(decode_key("é".repeat(32).as_str()), None);
    }
}
