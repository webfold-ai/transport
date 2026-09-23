//! Shared load-balancing primitives — the algorithm set `biota-http-server`'s `kernel::Proxy`
//! implements over HTTP `Upstream`s, and this crate's own [`crate::edge_proxy::ConnectorPool`]
//! needs over tunnelled `PeerId` connections. Neither type knows about the other, so the shared
//! part is exactly the pure selection logic: given N candidates (identified only by a
//! `hashtrinity::Coord` and a weight) plus per-candidate health state, pick one index. Extracted
//! out of `kernel::Backends::pick` (a behavior-preserving move — same constants, same mixing,
//! same rules) rather than reimplemented, so the two proxies can never quietly drift onto two
//! different notions of "healthiest" or "consistent."

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use hashtrinity::Coord;

/// Which algorithm to use. `#[default]` matches every existing caller's prior default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LoadBalance {
    #[default]
    RoundRobin,
    Random,
    Weighted,
    Consistent,
    /// Pick the candidate with the lowest estimated latency — a real, continuously-fused
    /// measurement ([`HealthEstimator`]), not a static config value like `Weighted`'s weight.
    /// A candidate with no observations yet is treated as best (untested candidates get a fair
    /// first try, the standard load-balancer convention).
    Healthiest,
}

/// Passive per-candidate latency estimator: `HashTrinity.fuse (η,τ) (latency,1)` /
/// `HashTrinity.mean = η/τ`. `None` before any observation (`τ = 0`, the untested prior — not a
/// false zero-latency claim).
#[derive(Debug)]
pub struct HealthEstimator {
    state: std::sync::Mutex<(f64, f64)>,
}

impl Default for HealthEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthEstimator {
    #[must_use]
    pub fn new() -> Self {
        // `(0, 0)` — `HashTrinity.fuse`'s own uninformative-prior unit.
        HealthEstimator { state: std::sync::Mutex::new((0.0, 0.0)) }
    }

    /// Fuse in one latency observation (seconds).
    pub fn observe(&self, latency_secs: f64) {
        let mut s = self.state.lock().unwrap();
        *s = (s.0 + latency_secs, s.1 + 1.0);
    }

    /// The current estimate `μ = η/τ`.
    #[must_use]
    pub fn estimate(&self) -> Option<f64> {
        let s = *self.state.lock().unwrap();
        if s.1 == 0.0 { None } else { Some(s.0 / s.1) }
    }
}

/// splitmix64 — the same tiny, dependency-free, well-known mixing step used in tokio-xor's
/// scheduler for randomized steal-victim selection. Not cryptographic; fine for load-balancing
/// spread, which is all it's used for here.
#[must_use]
pub const fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E3779B97F4A7C15);
    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// VNODES for the Ketama-style ring [`consistent_ring_index`] builds — each node gets this many
/// virtual points, spreading placement evenly even across a handful of real nodes.
pub const CONSISTENT_HASH_VNODES: u32 = 40;

/// Ketama-style consistent-hash ring lookup. Build a ring of `vnodes` virtual points per node
/// (`splitmix64(node_coord ^ v)`), then route `key_coord` to the first ring point at-or-after
/// its own `splitmix64` hash, wrapping to the ring's first point past the end.
#[must_use]
pub fn consistent_ring_index(key_coord: u64, node_coords: &[u64], vnodes: u32) -> usize {
    if node_coords.is_empty() {
        return 0;
    }
    let key_hash = splitmix64(key_coord);
    let mut ring: Vec<(u64, usize)> = Vec::with_capacity(node_coords.len() * vnodes as usize);
    for (i, &coord) in node_coords.iter().enumerate() {
        for v in 0..vnodes {
            ring.push((splitmix64(coord ^ (v as u64)), i));
        }
    }
    ring.sort_unstable_by_key(|(h, _)| *h);
    ring.iter()
        .find(|(h, _)| *h >= key_hash)
        .or_else(|| ring.first())
        .map(|(_, i)| *i)
        .unwrap_or(0)
}

/// Pick one candidate index by `algo`. `node_coords`/`weights`/`health`/`active_health` are all
/// the same length (one entry per candidate) — callers own building that from their own
/// candidate list (an `Upstream`, a tunnelled peer connection, whatever). `hash_key_coord` only
/// matters for [`LoadBalance::Consistent`]. `rr_counter` is the caller's own shared cursor (one
/// per candidate *set*, not per candidate) so `RoundRobin`/`Random`/`Weighted` spread correctly
/// across repeated calls.
///
/// Fails OPEN: if every candidate is marked down by `active_health`, the algorithm's own pick
/// still goes through rather than refusing outright — a stale/wrong health-checker must not turn
/// a real outage into a guaranteed refusal on every request.
///
/// # Panics
/// Never on mismatched slice lengths from a well-behaved caller; returns `None` only when
/// `node_coords` is empty.
#[must_use]
pub fn pick_index(
    algo: LoadBalance,
    node_coords: &[u64],
    weights: &[u32],
    health: &[Arc<HealthEstimator>],
    active_health: &[Arc<AtomicBool>],
    hash_key_coord: u64,
    rr_counter: &AtomicUsize,
) -> Option<usize> {
    if node_coords.is_empty() {
        return None;
    }
    if node_coords.len() == 1 {
        return Some(0);
    }
    let idx = match algo {
        LoadBalance::RoundRobin => rr_counter.fetch_add(1, Ordering::Relaxed) % node_coords.len(),
        LoadBalance::Random => {
            let seed = rr_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            (splitmix64(seed ^ now) as usize) % node_coords.len()
        }
        LoadBalance::Weighted => {
            let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
            let seed = rr_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let mut r = splitmix64(seed ^ now) % total.max(1);
            let mut chosen = 0;
            for (i, &w) in weights.iter().enumerate() {
                if r < u64::from(w) {
                    chosen = i;
                    break;
                }
                r -= u64::from(w);
            }
            chosen
        }
        LoadBalance::Consistent => consistent_ring_index(hash_key_coord, node_coords, CONSISTENT_HASH_VNODES),
        LoadBalance::Healthiest => health
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                let av = a.estimate().unwrap_or(f64::MIN);
                let bv = b.estimate().unwrap_or(f64::MIN);
                av.partial_cmp(&bv).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
            .unwrap_or(0),
    };

    let idx = if active_health.get(idx).map(|h| h.load(Ordering::Relaxed)).unwrap_or(true) {
        idx
    } else {
        active_health.iter().position(|h| h.load(Ordering::Relaxed)).unwrap_or(idx)
    };
    Some(idx)
}

/// Convenience: coordinate a hashable identity the same way every caller here already does
/// (`hashtrinity::Coord::coord`), so nobody has to import the trait just to call [`pick_index`].
#[must_use]
pub fn coord_of<T: Coord>(value: &T) -> u64 {
    value.coord()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health_set(n: usize) -> Vec<Arc<HealthEstimator>> {
        (0..n).map(|_| Arc::new(HealthEstimator::new())).collect()
    }

    fn all_up(n: usize) -> Vec<Arc<AtomicBool>> {
        (0..n).map(|_| Arc::new(AtomicBool::new(true))).collect()
    }

    #[test]
    fn single_candidate_always_wins() {
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1],
            &[1],
            &health_set(1),
            &all_up(1),
            0,
            &AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn round_robin_cycles_through_every_candidate() {
        let counter = AtomicUsize::new(0);
        let coords = [1, 2, 3];
        let picks: Vec<usize> = (0..6)
            .map(|_| {
                pick_index(LoadBalance::RoundRobin, &coords, &[1, 1, 1], &health_set(3), &all_up(3), 0, &counter)
                    .unwrap()
            })
            .collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn healthiest_prefers_the_lower_estimate() {
        let health = health_set(2);
        health[0].observe(0.5);
        health[1].observe(0.05);
        let idx = pick_index(
            LoadBalance::Healthiest,
            &[1, 2],
            &[1, 1],
            &health,
            &all_up(2),
            0,
            &AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn untested_candidate_is_treated_as_best() {
        let health = health_set(2);
        health[0].observe(0.1);
        // health[1] never observed -> None -> f64::MIN -> wins.
        let idx = pick_index(
            LoadBalance::Healthiest,
            &[1, 2],
            &[1, 1],
            &health,
            &all_up(2),
            0,
            &AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn down_candidate_is_skipped() {
        let active = all_up(2);
        active[0].store(false, Ordering::Relaxed);
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1, 2],
            &[1, 1],
            &health_set(2),
            &active,
            0,
            &AtomicUsize::new(0), // first pick would be index 0, which is down
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn all_down_fails_open_rather_than_returning_none() {
        let active = all_up(2);
        active[0].store(false, Ordering::Relaxed);
        active[1].store(false, Ordering::Relaxed);
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1, 2],
            &[1, 1],
            &health_set(2),
            &active,
            0,
            &AtomicUsize::new(0),
        );
        assert!(idx.is_some(), "must fail open, not refuse every request");
    }

    #[test]
    fn consistent_is_stable_and_spreads() {
        let node_coords: Vec<u64> = (0..5).collect();
        // Same key always maps to the same node.
        let a = consistent_ring_index(42, &node_coords, CONSISTENT_HASH_VNODES);
        let b = consistent_ring_index(42, &node_coords, CONSISTENT_HASH_VNODES);
        assert_eq!(a, b);
        // Different keys spread across more than one node.
        let picks: std::collections::HashSet<usize> =
            (0..200u64).map(|k| consistent_ring_index(k, &node_coords, CONSISTENT_HASH_VNODES)).collect();
        assert!(picks.len() > 1, "200 distinct keys landed on only one node");
    }
}
