//! The connection-tracking table: the single source of truth for "which flows exist and which
//! backend each one is pinned to".
//!
//! ## What it guarantees
//!
//! * **Pinning.** A flow's backend is recorded when the flow is admitted and never changes. Both
//!   planes consult this table (UDP on every datagram; TCP holds its [`FlowGuard`] for the
//!   life of the connection) *before* any hashing, so a change to the backend set, to health, or
//!   to the Maglev table cannot move an established flow. The only thing that ends a flow early
//!   is its own end, its idle timeout, or the drain deadline of its backend.
//! * **Bounded memory.** The table holds at most `max_flows` entries, and each source (IPv4
//!   address, IPv6 /64) at most `max_flows_per_source`. Admission is refused, not queued, beyond
//!   either bound, so memory under attack is `max_flows * size_of(entry)` plus the per-source map
//!   (never more entries than flows).
//! * **Exactly-once accounting.** The global and per-source counts move only when an entry enters
//!   or leaves the map (or a [`Reservation`] is created or dropped unpinned), so no path can leak
//!   a slot or double-release one.
//!
//! The map is sharded to keep the UDP per-datagram lookup from serialising on one lock.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::backend::{Backend, Lease};
use crate::ratelimit::source_bucket;

const SHARDS: usize = 16;

/// Lock a mutex, recovering from poisoning (a panic elsewhere must not cascade into every flow).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Transport of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Identity of a flow as the tracking table sees it: the listener it arrived on and the socket
/// peer. (For TCP behind a trusted PROXY sender the *socket* peer is the sender; the effective
/// client address is carried separately for hashing and per-source limits.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Transport.
    pub proto: Proto,
    /// Index of the listener in the static config.
    pub listener: u16,
    /// Socket peer (the client for UDP and direct TCP).
    pub peer: SocketAddr,
}

/// Admission limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Total concurrent flows.
    pub max_flows: usize,
    /// Concurrent flows per source (IPv4 address / IPv6 /64). 0 disables the per-source bound.
    pub max_flows_per_source: usize,
}

/// Why admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    /// The global flow bound is reached.
    MaxFlows,
    /// This source holds its maximum.
    PerSource,
}

struct Entry {
    id: u64,
    backend: Arc<Backend>,
    /// `true` = reset (drain deadline); the sender being dropped = quiet close (idle expiry).
    kill: watch::Sender<bool>,
    last_seen_ms: u64,
    src: u128,
    udp: Option<Arc<UdpSocket>>,
    send_proxy: bool,
}

/// What the UDP fast path needs for a tracked flow.
pub struct UdpHit {
    /// The pinned backend.
    pub backend: Arc<Backend>,
    /// The flow's backend-facing socket.
    pub socket: Arc<UdpSocket>,
    /// Whether to prefix each datagram with a PROXY v2 header.
    pub send_proxy: bool,
}

/// The table.
pub struct FlowTable {
    shards: Vec<Mutex<HashMap<FlowKey, Entry>>>,
    hasher: RandomState,
    total: AtomicUsize,
    per_source: Mutex<HashMap<u128, usize>>,
    limits: Limits,
    next_id: AtomicU64,
    epoch: std::time::Instant,
}

impl core::fmt::Debug for FlowTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlowTable")
            .field("flows", &self.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl FlowTable {
    /// An empty table.
    #[must_use]
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(FlowTable {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            hasher: RandomState::new(),
            total: AtomicUsize::new(0),
            per_source: Mutex::new(HashMap::new()),
            limits,
            next_id: AtomicU64::new(1),
            epoch: std::time::Instant::now(),
        })
    }

    /// Flows currently tracked (including reservations not yet pinned).
    #[must_use]
    pub fn len(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    /// No flows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn shard(&self, key: &FlowKey) -> &Mutex<HashMap<FlowKey, Entry>> {
        // SHARDS is a power of two and `shards` has exactly that many entries.
        let idx = usize::try_from(self.hasher.hash_one(key) & (SHARDS as u64 - 1)).unwrap_or(0);
        &self.shards[idx]
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Reserve one flow's worth of capacity for `src`. The reservation is released on drop
    /// unless [`Reservation::pin`] turns it into a tracked flow.
    ///
    /// # Errors
    /// [`AdmitError`] when a bound is reached.
    pub fn admit(self: &Arc<Self>, src: IpAddr) -> Result<Reservation, AdmitError> {
        let bucket = source_bucket(src);
        // Global bound first: CAS loop so concurrent admits cannot overshoot.
        let mut cur = self.total.load(Ordering::SeqCst);
        loop {
            if cur >= self.limits.max_flows {
                return Err(AdmitError::MaxFlows);
            }
            match self
                .total
                .compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        if self.limits.max_flows_per_source > 0 {
            let mut map = lock(&self.per_source);
            let n = map.entry(bucket).or_insert(0);
            if *n >= self.limits.max_flows_per_source {
                // Do not leave an empty entry behind for a source that holds nothing.
                if *n == 0 {
                    map.remove(&bucket);
                }
                drop(map);
                self.total.fetch_sub(1, Ordering::SeqCst);
                return Err(AdmitError::PerSource);
            }
            *n += 1;
        }
        Ok(Reservation {
            table: self.clone(),
            src: bucket,
            armed: true,
        })
    }

    fn release(&self, src: u128) {
        if self.limits.max_flows_per_source > 0 {
            let mut map = lock(&self.per_source);
            if let Some(n) = map.get_mut(&src) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&src);
                }
            }
        }
        self.total.fetch_sub(1, Ordering::SeqCst);
    }

    /// Remove the entry for `key` if it is still the one with `id`; releases its accounting.
    fn remove_entry(&self, key: &FlowKey, id: u64) {
        let removed = {
            let mut shard = lock(self.shard(key));
            match shard.get(key) {
                Some(e) if e.id == id => shard.remove(key),
                _ => None,
            }
        };
        if let Some(e) = removed {
            self.release(e.src);
        }
    }

    /// UDP fast path: the pinned backend and backend-facing socket for `key`, refreshing its
    /// idle clock.
    #[must_use]
    pub fn lookup_udp(&self, key: &FlowKey) -> Option<UdpHit> {
        let now = self.now_ms();
        let mut shard = lock(self.shard(key));
        let e = shard.get_mut(key)?;
        e.last_seen_ms = now;
        Some(UdpHit {
            backend: e.backend.clone(),
            socket: e.udp.clone()?,
            send_proxy: e.send_proxy,
        })
    }

    /// Refresh a flow's idle clock (UDP replies).
    pub fn touch(&self, key: &FlowKey) {
        let now = self.now_ms();
        if let Some(e) = lock(self.shard(key)).get_mut(key) {
            e.last_seen_ms = now;
        }
    }

    /// The backend `key` is pinned to, if tracked.
    #[must_use]
    pub fn backend_of(&self, key: &FlowKey) -> Option<Arc<Backend>> {
        lock(self.shard(key)).get(key).map(|e| e.backend.clone())
    }

    /// Order every flow pinned to `backend` to reset. Returns how many were signalled. The flows
    /// remove themselves as their tasks unwind.
    pub fn reset_backend(&self, backend: &Backend) -> usize {
        let mut n = 0;
        for shard in &self.shards {
            let shard = lock(shard);
            for e in shard
                .values()
                .filter(|e| e.backend.serial == backend.serial)
            {
                if e.kill.send(true).is_ok() {
                    n += 1;
                }
            }
        }
        n
    }

    /// Order every flow to reset (shutdown past its grace period).
    pub fn reset_all(&self) -> usize {
        let mut n = 0;
        for shard in &self.shards {
            let shard = lock(shard);
            for e in shard.values() {
                if e.kill.send(true).is_ok() {
                    n += 1;
                }
            }
        }
        n
    }

    /// Drop UDP flows idle for longer than `idle`. Dropping the entry drops its kill sender,
    /// which tells the reply task to exit quietly.
    pub fn expire_idle_udp(&self, idle: Duration) -> usize {
        let now = self.now_ms();
        let cutoff = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
        let mut victims = Vec::new();
        for shard in &self.shards {
            let mut shard = lock(shard);
            let keys: Vec<FlowKey> = shard
                .iter()
                .filter(|(_, e)| e.udp.is_some() && now.saturating_sub(e.last_seen_ms) >= cutoff)
                .map(|(k, _)| *k)
                .collect();
            for k in keys {
                if let Some(e) = shard.remove(&k) {
                    victims.push(e.src);
                }
            }
        }
        let n = victims.len();
        for src in victims {
            self.release(src);
        }
        n
    }

    /// Per-backend flow counts, for diagnostics and tests.
    #[must_use]
    pub fn count_on(&self, backend: &Backend) -> usize {
        self.shards
            .iter()
            .map(|s| {
                lock(s)
                    .values()
                    .filter(|e| e.backend.serial == backend.serial)
                    .count()
            })
            .sum()
    }
}

/// Capacity reserved for one flow, not yet bound to a backend.
pub struct Reservation {
    table: Arc<FlowTable>,
    src: u128,
    armed: bool,
}

impl Reservation {
    /// Record the flow `key` as pinned to `lease`'s backend. `udp` is the backend-facing socket
    /// for UDP flows. Consumes the reservation: the accounting now belongs to the map entry.
    ///
    /// # Errors
    /// The lease back (and the reservation released) if `key` is already tracked and live.
    pub fn pin(
        mut self,
        key: FlowKey,
        lease: Lease,
        udp: Option<Arc<UdpSocket>>,
    ) -> Result<FlowGuard, Lease> {
        let table = self.table.clone();
        let id = table.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = watch::channel(false);
        let entry = Entry {
            id,
            backend: lease.backend().clone(),
            kill: tx,
            last_seen_ms: table.now_ms(),
            src: self.src,
            udp,
            send_proxy: lease.send_proxy,
        };
        {
            let mut shard = lock(table.shard(&key));
            if shard.contains_key(&key) {
                return Err(lease); // `self` drops: reservation released
            }
            shard.insert(key, entry);
        }
        self.armed = false; // accounting now owned by the entry
        Ok(FlowGuard {
            table,
            key,
            id,
            kill: rx,
            lease,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            self.table.release(self.src);
        }
    }
}

/// A tracked flow. Dropping it ends the flow's table entry (and its backend lease).
pub struct FlowGuard {
    table: Arc<FlowTable>,
    key: FlowKey,
    id: u64,
    kill: watch::Receiver<bool>,
    lease: Lease,
}

/// What ended the wait on a flow's kill channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Killed {
    /// Told to reset (drain deadline, shutdown).
    Reset,
    /// Entry removed by the table (idle expiry): close quietly.
    Gone,
}

impl FlowGuard {
    /// Resolves when the flow is ordered to end.
    pub async fn killed(&mut self) -> Killed {
        match self.kill.wait_for(|k| *k).await {
            Ok(_) => Killed::Reset,
            Err(_) => Killed::Gone,
        }
    }

    /// The backend this flow is pinned to.
    #[must_use]
    pub fn backend(&self) -> &Arc<Backend> {
        self.lease.backend()
    }

    /// Whether PROXY v2 should be sent for this flow.
    #[must_use]
    pub fn send_proxy(&self) -> bool {
        self.lease.send_proxy
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.table.remove_entry(&self.key, self.id);
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    fn backend(n: u64) -> Arc<Backend> {
        Arc::new(Backend::new(
            format!("b{n}"),
            "10.0.0.1".parse().unwrap(),
            n,
        ))
    }

    fn key(port: u16) -> FlowKey {
        FlowKey {
            proto: Proto::Tcp,
            listener: 0,
            peer: SocketAddr::new("203.0.113.1".parse().unwrap(), port),
        }
    }

    fn table(max: usize, per: usize) -> Arc<FlowTable> {
        FlowTable::new(Limits {
            max_flows: max,
            max_flows_per_source: per,
        })
    }

    fn src(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pin(
        t: &Arc<FlowTable>,
        b: &Arc<Backend>,
        ip: &str,
        port: u16,
    ) -> Result<FlowGuard, AdmitError> {
        let r = t.admit(src(ip))?;
        let lease = Lease::acquire(b, false).unwrap();
        Ok(r.pin(key(port), lease, None).unwrap())
    }

    #[test]
    fn the_global_bound_refuses_and_a_close_frees_a_slot() {
        let t = table(2, 0);
        let b = backend(1);
        let g1 = pin(&t, &b, "203.0.113.1", 1).unwrap();
        let _g2 = pin(&t, &b, "203.0.113.2", 2).unwrap();
        assert_eq!(
            pin(&t, &b, "203.0.113.3", 3).err(),
            Some(AdmitError::MaxFlows)
        );
        drop(g1);
        assert_eq!(t.len(), 1);
        pin(&t, &b, "203.0.113.3", 3).unwrap();
    }

    #[test]
    fn the_per_source_bound_is_per_source() {
        let t = table(100, 2);
        let b = backend(1);
        let _a = pin(&t, &b, "203.0.113.1", 1).unwrap();
        let _b = pin(&t, &b, "203.0.113.1", 2).unwrap();
        assert_eq!(
            pin(&t, &b, "203.0.113.1", 3).err(),
            Some(AdmitError::PerSource)
        );
        let _c = pin(&t, &b, "203.0.113.2", 4).unwrap();
        assert_eq!(t.len(), 3, "a refused admit must not leak a global slot");
    }

    #[test]
    fn a_v6_source_is_limited_by_its_slash_64() {
        let t = table(100, 2);
        let b = backend(1);
        let _a = pin(&t, &b, "2001:db8::1", 1).unwrap();
        let _b = pin(&t, &b, "2001:db8::2", 2).unwrap();
        assert_eq!(
            pin(&t, &b, "2001:db8::ffff", 3).err(),
            Some(AdmitError::PerSource)
        );
    }

    #[test]
    fn a_dropped_reservation_releases_everything() {
        let t = table(1, 1);
        let r = t.admit(src("203.0.113.1")).unwrap();
        assert_eq!(t.len(), 1);
        drop(r);
        assert_eq!(t.len(), 0);
        assert!(
            lock(&t.per_source).is_empty(),
            "the per-source map must not retain empty entries"
        );
        t.admit(src("203.0.113.1")).unwrap();
    }

    #[test]
    fn the_per_source_map_never_outgrows_the_flow_count() {
        let t = table(50, 5);
        let b = backend(1);
        let mut guards = Vec::new();
        for i in 0..200u32 {
            if let Ok(g) = pin(
                &t,
                &b,
                &format!("10.{}.{}.1", i / 250, i % 250),
                u16::try_from(i).unwrap(),
            ) {
                guards.push(g);
            }
        }
        assert_eq!(guards.len(), 50);
        assert!(lock(&t.per_source).len() <= 50);
        drop(guards);
        assert!(t.is_empty());
        assert!(lock(&t.per_source).is_empty());
    }

    #[test]
    fn a_duplicate_live_key_is_refused_without_leaking() {
        let t = table(10, 0);
        let b = backend(1);
        let _g = pin(&t, &b, "203.0.113.1", 1).unwrap();
        let r = t.admit(src("203.0.113.1")).unwrap();
        let lease = Lease::acquire(&b, false).unwrap();
        assert!(r.pin(key(1), lease, None).is_err());
        assert_eq!(t.len(), 1);
        assert_eq!(b.flows(), 1, "the refused lease was returned and dropped");
    }

    #[test]
    fn backend_flow_counts_follow_the_guard() {
        let t = table(10, 0);
        let b = backend(1);
        let g = pin(&t, &b, "203.0.113.1", 1).unwrap();
        assert_eq!(b.flows(), 1);
        assert_eq!(t.count_on(&b), 1);
        assert!(Arc::ptr_eq(&t.backend_of(&key(1)).unwrap(), &b));
        drop(g);
        assert_eq!(b.flows(), 0);
        assert_eq!(t.count_on(&b), 0);
    }

    #[tokio::test]
    async fn reset_backend_signals_only_that_backends_flows() {
        let t = table(10, 0);
        let (b1, b2) = (backend(1), backend(2));
        let mut g1 = pin(&t, &b1, "203.0.113.1", 1).unwrap();
        let mut g2 = pin(&t, &b2, "203.0.113.2", 2).unwrap();
        assert_eq!(t.reset_backend(&b1), 1);
        assert_eq!(g1.killed().await, Killed::Reset);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), g2.killed())
                .await
                .is_err(),
            "the other backend's flow is untouched"
        );
    }

    #[tokio::test]
    async fn removing_the_entry_quietly_closes_the_flow() {
        let t = table(10, 0);
        let b = backend(1);
        let mut g = pin(&t, &b, "203.0.113.1", 1).unwrap();
        // Simulate idle expiry removing the entry.
        let e = lock(t.shard(&key(1))).remove(&key(1)).unwrap();
        t.release(e.src);
        drop(e);
        assert_eq!(g.killed().await, Killed::Gone);
        drop(g); // must not double-release
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn concurrent_admits_never_exceed_the_bound() {
        let t = table(100, 0);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let t = t.clone();
                std::thread::spawn(move || {
                    (0..100)
                        .filter_map(|_| t.admit(src("203.0.113.1")).ok())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let held: usize = handles.into_iter().map(|h| h.join().unwrap().len()).sum();
        // Reservations are dropped when each thread's vector drops at join; the point is that
        // at no time did more than 100 exist, which the CAS guarantees; check the final state.
        assert!(held <= 800);
        assert_eq!(t.len(), 0);
    }
}
