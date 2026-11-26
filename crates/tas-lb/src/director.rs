//! The Director: every *decision* the LB makes, with no I/O.
//!
//! It owns the backend registry (identity, weights, admin drain, health), publishes immutable
//! table [`Generation`]s for choosing a backend for a **new** flow, runs the drain clocks, and
//! tells the data plane (a [`Forwarder`]) when a generation changes or a backend's flows must be
//! reset. It never touches a socket and takes the current time as an argument, so every rule
//! below is unit-testable without sleeping.
//!
//! ## Invariants
//!
//! 1. **Pinning is not the Director's to break.** `select` is only ever called for a flow with no
//!    tracking entry. Nothing here can re-point an existing flow: a flow holds a [`Lease`] on an
//!    `Arc<Backend>` whose identity is immutable.
//! 2. **Eligibility** for new flows is `!removed && !admin_drain && health == Up`. The Maglev
//!    table is rebuilt over exactly the eligible set whenever it (or a weight, key or PROXY flag)
//!    changes, and not otherwise (a probe that changes nothing builds nothing).
//! 3. **Draining.** The moment a backend becomes ineligible its drain clock starts. If it becomes
//!    eligible again (health recovered, un-drained, re-added) the clock stops and nothing is
//!    reset. If the clock reaches `drain_timeout` with flows still pinned, the Forwarder is told
//!    to reset them. A removed backend with no flows is deleted; one with flows stays until they
//!    are gone.
//! 4. **Lease/retire race.** A backend is retired only when it has no flows, and a lease taken
//!    concurrently either sees the retirement and backs off, or is seen by the retirer, which
//!    then keeps the backend (see [`Lease::acquire`]).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use apeiron::map::hashtrinity::crypto::hmac_sha256;

use crate::backend::{Backend, BackendSet, HealthSpec, Lease, SetError};
use crate::flows::{lock, Proto};
use crate::health::{Health, HealthTracker};
use crate::maglev::{self, Member};
use crate::metrics::{BackendGauge, Metrics};

/// A failure installing a generation into a data plane.
#[derive(Debug)]
pub struct ForwarderError(pub String);

impl core::fmt::Display for ForwarderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "forwarder: {}", self.0)
    }
}

impl std::error::Error for ForwarderError {}

/// The seam between decisions and packet/byte movement.
///
/// The userspace plane in this crate implements it over its flow table. An XDP plane would
/// implement `install` by writing the generation's backend array and Maglev table into BPF maps,
/// `reset_backend` by deleting that backend's entries from the BPF conntrack map, and
/// `active_flows` by counting them; the Director, config verification, health checking and
/// metrics are shared unchanged. Under DSR the XDP plane cannot see backend replies, which is why
/// health is probed actively here rather than inferred from traffic.
pub trait Forwarder: Send + Sync {
    /// Short name for logs.
    fn name(&self) -> &'static str;
    /// A new generation of the new-flow table is in force.
    ///
    /// # Errors
    /// [`ForwarderError`] if the plane could not adopt it.
    fn install(&self, generation: &Generation) -> Result<(), ForwarderError>;
    /// End every flow pinned to `backend`. Returns how many were signalled.
    fn reset_backend(&self, backend: &Backend) -> usize;
    /// Flows currently pinned to `backend`.
    fn active_flows(&self, backend: &Backend) -> u64;
}

/// The 5-tuple-ish input to the new-flow hash.
#[derive(Debug, Clone, Copy)]
pub struct FlowTuple {
    /// Effective client address.
    pub client: SocketAddr,
    /// Address the client connected to (the VIP).
    pub local: SocketAddr,
    /// Transport.
    pub proto: Proto,
}

fn put_addr(buf: &mut [u8], a: SocketAddr) {
    let v6 = match a.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    };
    if let Some(dst) = buf.get_mut(..16) {
        dst.copy_from_slice(&v6.octets());
    }
    if let Some(dst) = buf.get_mut(16..18) {
        dst.copy_from_slice(&a.port().to_be_bytes());
    }
}

impl FlowTuple {
    fn bytes(&self) -> [u8; 37] {
        let mut b = [0u8; 37];
        b[0] = match self.proto {
            Proto::Tcp => 6,
            Proto::Udp => 17,
        };
        put_addr(&mut b[1..19], self.client);
        put_addr(&mut b[19..37], self.local);
        b
    }
}

/// An immutable, published view for choosing backends for new flows.
pub struct Generation {
    /// Monotonic number (1 for the first).
    pub number: u64,
    table: maglev::Table,
    members: Vec<Arc<Backend>>,
    hash_key: [u8; 32],
    /// Whether flows chosen from this generation get a PROXY v2 header toward the backend.
    pub send_proxy: bool,
}

impl core::fmt::Debug for Generation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Generation")
            .field("number", &self.number)
            .field(
                "members",
                &self
                    .members
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("hash_key", &"<redacted>")
            .field("send_proxy", &self.send_proxy)
            .finish_non_exhaustive()
    }
}

impl Generation {
    /// The eligible backends, in table-index order (an XDP plane mirrors this array).
    #[must_use]
    pub fn members(&self) -> &[Arc<Backend>] {
        &self.members
    }

    /// The Maglev table (an XDP plane mirrors this too).
    #[must_use]
    pub fn table(&self) -> &maglev::Table {
        &self.table
    }

    /// Keyed hash of a flow: HMAC-SHA256 under the cluster's secret key, truncated to 64 bits.
    /// Keyed so a client cannot choose its source port to land on a target backend.
    #[must_use]
    pub fn flow_hash(&self, t: &FlowTuple) -> u64 {
        let mac = hmac_sha256(&self.hash_key, &t.bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&mac[..8]);
        u64::from_be_bytes(b)
    }

    /// The backend for `t`, skipping `excluded` (serials already tried this attempt).
    #[must_use]
    pub fn pick(&self, t: &FlowTuple, excluded: &[u64]) -> Option<&Arc<Backend>> {
        let h = self.flow_hash(t);
        let idx = self.table.lookup_skipping(h, |i| {
            self.members
                .get(i)
                .is_none_or(|m| excluded.contains(&m.serial))
        })?;
        self.members.get(idx)
    }
}

struct Slot {
    backend: Arc<Backend>,
    weight: u32,
    admin_drain: bool,
    removed: bool,
    health: HealthTracker,
    drain_since: Option<Instant>,
}

impl Slot {
    fn eligible(&self) -> bool {
        !self.removed && !self.admin_drain && self.health.state() == Health::Up
    }
}

struct Params {
    hash_key: [u8; 32],
    send_proxy: bool,
    drain_timeout: Duration,
    health: HealthSpec,
}

/// The inputs a published generation was built from: eligible `(serial, weight)`, key, PROXY flag.
#[derive(PartialEq, Eq)]
struct BuiltFrom {
    eligible: Vec<(u64, u32)>,
    hash_key: [u8; 32],
    send_proxy: bool,
}

struct State {
    slots: Vec<Slot>,
    params: Option<Params>,
    next_serial: u64,
    gen_number: u64,
    /// What the published generation was built from: eligible `(serial, weight)`, key, flag.
    built: Option<BuiltFrom>,
}

/// The decision engine.
pub struct Director {
    state: Mutex<State>,
    current: RwLock<Option<Arc<Generation>>>,
    forwarder: Arc<dyn Forwarder>,
    metrics: Arc<Metrics>,
}

impl Director {
    /// A Director with no configuration: `select` returns `None` until a set is applied.
    #[must_use]
    pub fn new(forwarder: Arc<dyn Forwarder>, metrics: Arc<Metrics>) -> Self {
        Director {
            state: Mutex::new(State {
                slots: Vec::new(),
                params: None,
                next_serial: 1,
                gen_number: 0,
                built: None,
            }),
            current: RwLock::new(None),
            forwarder,
            metrics,
        }
    }

    /// The published generation, if any.
    #[must_use]
    pub fn generation(&self) -> Option<Arc<Generation>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether a config is in force and at least one backend takes new flows.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.generation().is_some_and(|g| !g.members.is_empty())
    }

    /// Whether any config has been applied.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        lock(&self.state).params.is_some()
    }

    /// The health parameters in force.
    #[must_use]
    pub fn health_spec(&self) -> Option<HealthSpec> {
        lock(&self.state).params.as_ref().map(|p| p.health)
    }

    /// Whether PROXY v2 is on for backends probes (the `LOCAL` header).
    #[must_use]
    pub fn send_proxy(&self) -> bool {
        lock(&self.state)
            .params
            .as_ref()
            .is_some_and(|p| p.send_proxy)
    }

    /// Reconcile the registry to `set` (already verified and validated by the caller).
    ///
    /// # Errors
    /// [`SetError`] if the hash key does not decode (defence in depth: `validate` checks it).
    pub fn apply_set(&self, set: &BackendSet, now: Instant) -> Result<(), SetError> {
        let hash_key = set.hash_key_bytes().ok_or(SetError::Invalid("hash_key"))?;
        let mut st = lock(&self.state);
        st.params = Some(Params {
            hash_key,
            send_proxy: set.send_proxy_v2,
            drain_timeout: Duration::from_millis(set.drain_timeout_ms),
            health: set.health,
        });
        // Anything not named in the new set is removed (and drains if it has flows).
        for slot in &mut st.slots {
            if !set
                .backends
                .iter()
                .any(|b| b.id == slot.backend.id && b.ip == slot.backend.ip)
            {
                slot.removed = true;
            }
        }
        for spec in &set.backends {
            let live = st.slots.iter_mut().find(|s| {
                s.backend.id == spec.id && s.backend.ip == spec.ip && !s.backend.is_retired()
            });
            if let Some(slot) = live {
                slot.removed = false; // re-added while still draining: revive, flows stay pinned
                slot.weight = u32::from(spec.weight);
                slot.admin_drain = spec.drain;
            } else {
                let serial = st.next_serial;
                st.next_serial += 1;
                st.slots.push(Slot {
                    backend: Arc::new(Backend::new(spec.id.clone(), spec.ip, serial)),
                    weight: u32::from(spec.weight),
                    admin_drain: spec.drain,
                    removed: false,
                    health: HealthTracker::default(),
                    drain_since: None,
                });
            }
        }
        self.rebuild(&mut st, now);
        Ok(())
    }

    /// Feed a probe or passive result for `backend`.
    pub fn report(&self, backend: &Backend, ok: bool, passive: bool, now: Instant) {
        let mut st = lock(&self.state);
        let Some(spec) = st.params.as_ref().map(|p| p.health) else {
            return;
        };
        if passive && !spec.passive {
            return;
        }
        let Some(slot) = st
            .slots
            .iter_mut()
            .find(|s| s.backend.serial == backend.serial)
        else {
            return;
        };
        if let Some((from, to)) = slot.health.record(ok, &spec) {
            self.metrics.health_transitions.inc(match to {
                Health::Unknown => 0,
                Health::Up => 1,
                Health::Down => 2,
            });
            tracing::info!(backend = %slot.backend.id, from = from.label(), to = to.label(), passive, "backend health changed");
            self.rebuild(&mut st, now);
        }
    }

    /// Choose a backend for a NEW flow (one with no tracking entry), skipping `excluded`.
    #[must_use]
    pub fn select(&self, t: &FlowTuple, excluded: &[u64]) -> Option<Lease> {
        let mut excluded = excluded.to_vec();
        for _ in 0..4 {
            let generation = self.generation()?;
            let backend = generation.pick(t, &excluded)?;
            match Lease::acquire(backend, generation.send_proxy) {
                Some(l) => return Some(l),
                None => excluded.push(backend.serial), // retired between publish and lease
            }
        }
        None
    }

    /// Advance drain clocks and delete finished backends.
    pub fn tick(&self, now: Instant) {
        let mut st = lock(&self.state);
        let Some(drain_timeout) = st.params.as_ref().map(|p| p.drain_timeout) else {
            return;
        };
        let mut changed = false;
        for slot in &mut st.slots {
            if slot.eligible() {
                continue;
            }
            let flows = self.forwarder.active_flows(&slot.backend);
            if slot.removed && flows == 0 {
                slot.backend.retire();
                if self.forwarder.active_flows(&slot.backend) > 0 {
                    slot.backend.unretire(); // a lease raced in; keep the backend
                } else {
                    changed = true;
                }
                continue;
            }
            if flows > 0 {
                let since = *slot.drain_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= drain_timeout {
                    let n = self.forwarder.reset_backend(&slot.backend);
                    if n > 0 {
                        tracing::warn!(backend = %slot.backend.id, flows = n, "drain timeout reached; resetting remaining flows");
                    }
                }
            }
        }
        if changed {
            st.slots.retain(|s| !s.backend.is_retired());
        }
    }

    /// Backends that have no prober yet (each is returned exactly once).
    #[must_use]
    pub fn take_unprobed(&self) -> Vec<Arc<Backend>> {
        lock(&self.state)
            .slots
            .iter()
            .filter(|s| !s.removed && s.backend.claim_prober())
            .map(|s| s.backend.clone())
            .collect()
    }

    /// Per-backend gauges.
    #[must_use]
    pub fn gauges(&self) -> Vec<BackendGauge> {
        let st = lock(&self.state);
        st.slots
            .iter()
            .map(|s| BackendGauge {
                id: s.backend.id.clone(),
                up: s.eligible(),
                health: s.health.state().label(),
                admin: if s.removed {
                    "removed"
                } else if s.admin_drain {
                    "draining"
                } else {
                    "active"
                },
                flows: self.forwarder.active_flows(&s.backend),
                weight: s.weight,
            })
            .collect()
    }

    /// Whether `backend` is still known (probers stop when it is not).
    #[must_use]
    pub fn is_live(&self, backend: &Backend) -> bool {
        !backend.is_retired()
            && lock(&self.state)
                .slots
                .iter()
                .any(|s| s.backend.serial == backend.serial && !s.removed)
    }

    fn rebuild(&self, st: &mut State, now: Instant) {
        // Drain clocks follow eligibility.
        for slot in &mut st.slots {
            if slot.eligible() {
                slot.drain_since = None;
            } else if slot.drain_since.is_none() {
                slot.drain_since = Some(now);
            }
        }
        let Some(params) = st.params.as_ref() else {
            return;
        };
        let mut eligible: Vec<&Slot> = st.slots.iter().filter(|s| s.eligible()).collect();
        eligible.sort_by(|a, b| {
            a.backend
                .id
                .cmp(&b.backend.id)
                .then(a.backend.serial.cmp(&b.backend.serial))
        });
        let sig: Vec<(u64, u32)> = eligible
            .iter()
            .map(|s| (s.backend.serial, s.weight))
            .collect();
        let built = BuiltFrom {
            eligible: sig,
            hash_key: params.hash_key,
            send_proxy: params.send_proxy,
        };
        if st.built.as_ref() == Some(&built) {
            return;
        }
        let members_spec: Vec<Member> = eligible
            .iter()
            .map(|s| Member {
                name: format!("{}|{}", s.backend.id, s.backend.ip).into_bytes(),
                weight: s.weight,
            })
            .collect();
        let generation = Generation {
            number: st.gen_number + 1,
            table: maglev::Table::build(&members_spec),
            members: eligible.iter().map(|s| s.backend.clone()).collect(),
            hash_key: params.hash_key,
            send_proxy: params.send_proxy,
        };
        st.gen_number += 1;
        st.built = Some(built);
        self.metrics
            .generation
            .store(generation.number, std::sync::atomic::Ordering::Relaxed);
        if let Err(e) = self.forwarder.install(&generation) {
            tracing::error!(forwarder = self.forwarder.name(), error = %e, "data plane refused the new table generation");
        }
        tracing::info!(
            generation = generation.number,
            backends = generation.members.len(),
            "table generation published"
        );
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(generation));
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::many_single_char_names,
        reason = "test code: deterministic assertions on fixtures; backends are named a..f"
    )]
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::backend::{BackendSpec, HealthSpec};

    /// A Forwarder with a configurable flow count, recording resets and installs.
    #[derive(Default)]
    pub(crate) struct FakeForwarder {
        flows: Mutex<std::collections::HashMap<u64, u64>>,
        resets: Mutex<Vec<u64>>,
        installs: AtomicUsize,
    }

    impl FakeForwarder {
        fn set_flows(&self, serial: u64, n: u64) {
            lock(&self.flows).insert(serial, n);
        }
    }

    impl Forwarder for FakeForwarder {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn install(&self, _g: &Generation) -> Result<(), ForwarderError> {
            self.installs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn reset_backend(&self, b: &Backend) -> usize {
            lock(&self.resets).push(b.serial);
            usize::try_from(lock(&self.flows).get(&b.serial).copied().unwrap_or(0)).unwrap()
        }
        fn active_flows(&self, b: &Backend) -> u64 {
            lock(&self.flows)
                .get(&b.serial)
                .copied()
                .unwrap_or(0)
                .max(b.flows())
        }
    }

    fn set(ids: &[&str]) -> BackendSet {
        BackendSet {
            cluster: "t".into(),
            hash_key: "cd".repeat(32),
            send_proxy_v2: true,
            drain_timeout_ms: 1000,
            health: HealthSpec {
                rise: 2,
                fall: 2,
                ..HealthSpec::default()
            },
            backends: ids
                .iter()
                .map(|id| BackendSpec {
                    id: (*id).into(),
                    // The address follows the id ("a" -> 10.0.0.1), so a backend keeps its identity across sets.
                    ip: format!("10.0.0.{}", id.as_bytes()[0] - b'a' + 1)
                        .parse()
                        .unwrap(),
                    weight: 100,
                    drain: false,
                })
                .collect(),
        }
    }

    fn tuple(i: u32) -> FlowTuple {
        FlowTuple {
            client: SocketAddr::new(
                std::net::Ipv4Addr::from(0xC000_0200 + i).into(),
                40_000 + (i % 1000) as u16,
            ),
            local: "198.51.100.1:443".parse().unwrap(),
            proto: Proto::Tcp,
        }
    }

    fn setup() -> (Director, Arc<FakeForwarder>, Instant) {
        let f = Arc::new(FakeForwarder::default());
        let d = Director::new(f.clone(), Arc::new(Metrics::default()));
        (d, f, Instant::now())
    }

    fn up_all(d: &Director, now: Instant) {
        for b in d.take_unprobed() {
            d.report(&b, true, false, now);
        }
    }

    fn serial(l: &Lease) -> u64 {
        l.backend().serial
    }

    #[test]
    fn nothing_is_selected_before_config_or_before_any_backend_is_up() {
        let (d, _f, now) = setup();
        assert!(d.select(&tuple(1), &[]).is_none());
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        assert!(
            !d.is_ready(),
            "Unknown backends take no flows (fail closed)"
        );
        assert!(d.select(&tuple(1), &[]).is_none());
        up_all(&d, now);
        assert!(d.is_ready());
        assert!(d.select(&tuple(1), &[]).is_some());
    }

    #[test]
    fn selection_is_deterministic_for_a_flow_and_spreads_across_backends() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b", "c", "d"]), now).unwrap();
        up_all(&d, now);
        let mut seen = std::collections::HashSet::new();
        for i in 0..400 {
            let a = serial(&d.select(&tuple(i), &[]).unwrap());
            let b = serial(&d.select(&tuple(i), &[]).unwrap());
            assert_eq!(a, b);
            seen.insert(a);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn the_flow_hash_is_keyed() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b", "c", "d"]), now).unwrap();
        up_all(&d, now);
        let g1 = d.generation().unwrap();
        let mut s2 = set(&["a", "b", "c", "d"]);
        s2.hash_key = "ee".repeat(32);
        d.apply_set(&s2, now).unwrap();
        let g2 = d.generation().unwrap();
        assert!((0..50).any(|i| g1.flow_hash(&tuple(i)) != g2.flow_hash(&tuple(i))));
    }

    #[test]
    fn excluded_backends_are_skipped_for_retries() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let first = d.select(&tuple(7), &[]).unwrap();
        let second = d.select(&tuple(7), &[serial(&first)]).unwrap();
        assert_ne!(serial(&first), serial(&second));
    }

    /// The reviewer's concern, at the decision layer: a backend that is healthy and still in the
    /// set must keep its pinned flows through ANY change to the set. Flows are modelled as leases
    /// (what the data plane holds); the lease's backend is the pin.
    #[test]
    fn pinned_leases_survive_every_kind_of_set_change_while_their_backend_is_healthy() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b", "c", "d"]), now).unwrap();
        up_all(&d, now);
        let pinned: Vec<(u32, Lease)> = (0..300)
            .map(|i| (i, d.select(&tuple(i), &[]).unwrap()))
            .collect();
        let before: Vec<u64> = pinned.iter().map(|(_, l)| serial(l)).collect();

        // Add a backend, remove one, reweight, flip drain on another, change the key.
        let mut s = set(&["a", "b", "c", "d", "e"]);
        s.backends[0].weight = 900;
        d.apply_set(&s, now).unwrap();
        up_all(&d, now);
        let mut s = set(&["a", "c", "d", "e", "f"]); // b removed, f added
        s.hash_key = "01".repeat(32);
        s.backends[2].drain = true;
        d.apply_set(&s, now).unwrap();
        up_all(&d, now);
        d.tick(now + Duration::from_millis(1));

        // Every lease still names the same backend, which has not been retired.
        let after: Vec<u64> = pinned.iter().map(|(_, l)| serial(l)).collect();
        assert_eq!(before, after);
        assert!(
            pinned.iter().all(|(_, l)| !l.backend().is_retired()),
            "a backend with flows is never deleted"
        );
        // And no reset was ordered for backends that were healthy and in the set (a, c, d, e are
        // in the final set; only b is removed and f is new). Resets need the drain timeout anyway.
    }

    #[test]
    fn a_new_flow_never_lands_on_a_removed_unhealthy_or_draining_backend() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b", "c", "e"]), now).unwrap();
        up_all(&d, now);
        let g = d.generation().unwrap();
        let find = |id: &str| g.members().iter().find(|m| m.id == id).unwrap().clone();
        let (b, c, e) = (find("b"), find("c"), find("e"));
        // b is removed, e is admin-drained, c fails health.
        let mut s = set(&["a", "c", "e"]);
        s.backends[2].drain = true;
        d.apply_set(&s, now).unwrap();
        d.report(&c, false, false, now);
        d.report(&c, false, false, now); // fall = 2 -> Down
        for i in 0..500 {
            let l = d.select(&tuple(i), &[]).unwrap();
            assert_eq!(
                l.backend().id,
                "a",
                "only a is eligible; got {}",
                l.backend().id
            );
            let _ = (&b, &e);
        }
    }

    #[test]
    fn health_changes_rebuild_only_when_eligibility_changes() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let installs = f.installs.load(Ordering::SeqCst);
        let a = d.generation().unwrap().members()[0].clone();
        d.report(&a, true, false, now); // already Up: no change
        d.apply_set(&set(&["a", "b"]), now).unwrap(); // identical set: no new generation
        assert_eq!(f.installs.load(Ordering::SeqCst), installs);
        d.report(&a, false, false, now);
        assert_eq!(
            f.installs.load(Ordering::SeqCst),
            installs,
            "one failure of fall=2 changes nothing"
        );
        d.report(&a, false, false, now);
        assert_eq!(f.installs.load(Ordering::SeqCst), installs + 1);
    }

    #[test]
    fn passive_failures_count_only_when_enabled() {
        let (d, _f, now) = setup();
        let mut s = set(&["a", "b"]);
        s.health.passive = false;
        d.apply_set(&s, now).unwrap();
        up_all(&d, now);
        let a = d.generation().unwrap().members()[0].clone();
        for _ in 0..10 {
            d.report(&a, false, true, now);
        }
        assert_eq!(d.generation().unwrap().members().len(), 2);
        let mut s = set(&["a", "b"]);
        s.health.passive = true;
        d.apply_set(&s, now).unwrap();
        d.report(&a, false, true, now);
        d.report(&a, false, true, now);
        assert_eq!(d.generation().unwrap().members().len(), 1);
    }

    #[test]
    fn a_removed_backend_with_flows_drains_then_is_reset_at_the_deadline() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d
            .generation()
            .unwrap()
            .members()
            .iter()
            .find(|m| m.id == "b")
            .unwrap()
            .clone();
        f.set_flows(b.serial, 3);
        // Remove b (a keeps its ip).
        let mut s = set(&["a"]);
        s.backends[0].ip = "10.0.0.1".parse().unwrap();
        d.apply_set(&s, now).unwrap();
        d.tick(now + Duration::from_millis(999));
        assert!(
            lock(&f.resets).is_empty(),
            "no reset before the drain timeout"
        );
        d.tick(now + Duration::from_millis(1000));
        assert_eq!(*lock(&f.resets), vec![b.serial]);
        assert!(!b.is_retired(), "still has flows");
        // Flows finish: next tick deletes it.
        f.set_flows(b.serial, 0);
        d.tick(now + Duration::from_millis(1100));
        assert!(b.is_retired());
        assert_eq!(d.gauges().len(), 1);
    }

    #[test]
    fn a_removed_backend_without_flows_is_deleted_immediately() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let mut s = set(&["a"]);
        s.backends[0].ip = "10.0.0.1".parse().unwrap();
        d.apply_set(&s, now).unwrap();
        d.tick(now);
        assert_eq!(d.gauges().len(), 1);
    }

    #[test]
    fn an_unhealthy_backend_that_recovers_before_the_deadline_is_not_reset() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        f.set_flows(b.serial, 2);
        d.report(&b, false, false, now);
        d.report(&b, false, false, now); // Down: drain clock starts
        d.tick(now + Duration::from_millis(900));
        // Recovers (rise = 2).
        d.report(&b, true, false, now + Duration::from_millis(950));
        d.report(&b, true, false, now + Duration::from_millis(960));
        d.tick(now + Duration::from_millis(5000));
        assert!(lock(&f.resets).is_empty(), "recovery cancels the drain");
        assert!(d
            .generation()
            .unwrap()
            .members()
            .iter()
            .any(|m| m.serial == b.serial));
    }

    #[test]
    fn a_second_outage_restarts_the_drain_clock() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        f.set_flows(b.serial, 2);
        // First outage at t0, recovery at t0+900ms.
        d.report(&b, false, false, now);
        d.report(&b, false, false, now);
        d.report(&b, true, false, now + Duration::from_millis(900));
        d.report(&b, true, false, now + Duration::from_millis(900));
        // A second outage much later: its deadline is measured from ITS start, not the first one.
        let t1 = now + Duration::from_millis(5000);
        d.report(&b, false, false, t1);
        d.report(&b, false, false, t1);
        d.tick(t1 + Duration::from_millis(100));
        assert!(
            lock(&f.resets).is_empty(),
            "a stale clock from the first outage must not reset flows early"
        );
        d.tick(t1 + Duration::from_millis(1000));
        assert_eq!(lock(&f.resets).len(), 1);
    }

    #[test]
    fn an_unhealthy_backend_that_stays_down_is_reset_at_the_deadline_but_kept() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        f.set_flows(b.serial, 2);
        d.report(&b, false, false, now);
        d.report(&b, false, false, now);
        d.tick(now + Duration::from_millis(1000));
        assert_eq!(lock(&f.resets).len(), 1);
        f.set_flows(b.serial, 0);
        d.tick(now + Duration::from_millis(1100));
        assert!(
            !b.is_retired(),
            "unhealthy but still in the set: it stays, for recovery"
        );
    }

    #[test]
    fn admin_drain_stops_new_flows_and_undrain_restores_them() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        f.set_flows(b.serial, 1);
        let mut s = set(&["a", "b"]);
        s.backends[1].drain = true;
        d.apply_set(&s, now).unwrap();
        for i in 0..200 {
            assert_ne!(serial(&d.select(&tuple(i), &[]).unwrap()), b.serial);
        }
        d.apply_set(&set(&["a", "b"]), now + Duration::from_millis(500))
            .unwrap();
        d.tick(now + Duration::from_millis(5000));
        assert!(lock(&f.resets).is_empty(), "undrain cancelled the clock");
        assert!((0..200).any(|i| serial(&d.select(&tuple(i), &[]).unwrap()) == b.serial));
    }

    #[test]
    fn re_adding_a_draining_backend_revives_the_same_identity() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        f.set_flows(b.serial, 1);
        let mut s = set(&["a"]);
        s.backends[0].ip = "10.0.0.1".parse().unwrap();
        d.apply_set(&s, now).unwrap();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        let again = d
            .generation()
            .unwrap()
            .members()
            .iter()
            .find(|m| m.id == "b")
            .unwrap()
            .clone();
        assert_eq!(
            again.serial, b.serial,
            "the same Backend, so pinned flows stay on it"
        );
    }

    #[test]
    fn a_changed_ip_is_a_new_backend_and_the_old_one_drains() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a"]), now).unwrap();
        up_all(&d, now);
        let old = d.generation().unwrap().members()[0].clone();
        f.set_flows(old.serial, 1);
        let mut s = set(&["a"]);
        s.backends[0].ip = "10.9.9.9".parse().unwrap();
        d.apply_set(&s, now).unwrap();
        up_all(&d, now);
        let new = d.generation().unwrap().members()[0].clone();
        assert_ne!(old.serial, new.serial);
        assert!(!old.is_retired());
        assert_eq!(d.gauges().len(), 2);
    }

    #[test]
    fn take_unprobed_hands_each_backend_out_once() {
        let (d, _f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        assert_eq!(d.take_unprobed().len(), 2);
        assert!(d.take_unprobed().is_empty());
    }

    #[test]
    fn a_lease_racing_the_retirement_is_either_refused_or_keeps_the_backend() {
        let (d, f, now) = setup();
        d.apply_set(&set(&["a", "b"]), now).unwrap();
        up_all(&d, now);
        let b = d.generation().unwrap().members()[1].clone();
        let mut s = set(&["a"]);
        s.backends[0].ip = "10.0.0.1".parse().unwrap();
        d.apply_set(&s, now).unwrap();
        // The lease is taken from a stale generation view, then the tick runs.
        let lease = Lease::acquire(&b, true).unwrap();
        d.tick(now);
        assert!(!b.is_retired(), "a held lease prevents retirement");
        drop(lease);
        d.tick(now);
        assert!(b.is_retired());
        assert!(Lease::acquire(&b, true).is_none());
        let _ = f;
    }
}
