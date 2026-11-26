//! Load-balancing primitives: the algorithm set a reverse proxy applies over a route's upstreams,
//! and that this crate's own [`crate::edge_proxy::ConnectorPool`] applies over tunnelled peer
//! connections. Neither type knows about the other, so the shared part is exactly the pure
//! selection logic: given N candidates (identified only by a coordinate and a weight) plus
//! per-candidate health state, pick one index.
//!
//! This module is the one home of that logic. `relayfold` (the HTTP proxy library) re-exports it
//! instead of carrying a second copy, so the dependency runs one way: relayfold depends on
//! transport, never the reverse.

/// Weighted Maglev selection for new L4 flows. One canonical implementation;
/// flow pinning stays in tas-lb and relayfold keeps using this module's existing
/// consistent-ring selector for its different request-selection contract.
pub mod maglev;

use apeiron::map::hashtrinity::Coord;
use std::sync::Arc;

/// Load-balancing algorithm across a route's upstreams — mirrors Pingora's own
/// `pingora-load-balancing::selection` algorithm set (`RoundRobin`/`Random`/`Weighted`/
/// `Consistent`). `Consistent` uses the request path as its hash key (session/cache affinity by
/// path) — a reasonable default, though real deployments may want client-IP-based affinity
/// instead; not yet configurable, an honest scope limit rather than a hidden one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LoadBalance {
    #[default]
    RoundRobin,
    Random,
    Weighted,
    Consistent,
    /// Pick the upstream with the lowest estimated response latency — the estimate is a real,
    /// continuously-fused measurement (`HealthEstimator`), not a static config value like
    /// `Weighted`'s weight. An upstream with no observations yet is treated as best (untested
    /// backends get a fair first try, the standard load-balancer convention).
    Healthiest,
}

/// A Kalman/information-form latency estimator for one upstream: carry `(η, τ)` (information,
/// precision), the estimate is `μ = η/τ`, and folding in a new observation is the commutative-
/// monoid merge — componentwise addition, order-free, so concurrent requests updating this from
/// different tasks never need to coordinate on ordering. Each observation here is unit-precision
/// (`τ_obs = 1`), so `μ` recovers a plain running mean — the simplest faithful instance, not the
/// full weighted-precision Kalman gain (an honest scope limit, inherited from the original).
#[derive(Debug)]
pub struct HealthEstimator {
    state: std::sync::Mutex<(f64, f64)>,
}

impl HealthEstimator {
    #[must_use]
    pub fn new() -> Self {
        // `(0, 0)` — the uninformative-prior unit.
        HealthEstimator {
            state: std::sync::Mutex::new((0.0, 0.0)),
        }
    }

    /// Fuse in one latency observation (seconds).
    pub fn observe(&self, latency_secs: f64) {
        let mut s = self.state.lock().unwrap();
        *s = (s.0 + latency_secs, s.1 + 1.0);
    }

    /// The current estimate `μ = η/τ`. `None` before any observation (`τ = 0`, the untested
    /// prior — not a false zero-latency claim).
    #[must_use]
    pub fn estimate(&self) -> Option<f64> {
        let s = *self.state.lock().unwrap();
        if s.1 == 0.0 {
            None
        } else {
            Some(s.0 / s.1)
        }
    }
}

impl Default for HealthEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// splitmix64 — a tiny, dependency-free, well-known mixing step. Not cryptographic; fine for
/// load-balancing spread, which is all it's used for here. It is `pub` because a session-ID
/// generator in the same family reuses this exact function rather than carrying a second copy
/// of the same four lines.
pub fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// VNODES for the Ketama-style ring `consistent_ring_index` builds — each node gets this many
/// virtual points, spreading placement evenly even across a handful of real nodes.
pub const CONSISTENT_HASH_VNODES: u32 = 40;

/// Ketama-style consistent-hash ring lookup — proven stable + spreading by
/// `load_balance_consistent_is_stable_and_spreads` below. Build a ring of `vnodes` virtual
/// points per node (`splitmix64(node_coord ^ v)`), then route `key_coord` to the first ring
/// point at-or-after its own `splitmix64` hash, wrapping to the ring's first point past the end.
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

/// Pick one candidate index by `algo`, decoupled from `Upstream`/`Backends` — for a caller whose
/// candidates aren't HTTP upstreams at all (e.g. a set of tunnelled peer connections), just N
/// coordinate-identified candidates with weights and health state. `Registry::pick` above is the
/// `Upstream`-shaped convenience over this same algorithm; this is the shape a second, unrelated
/// candidate type reuses instead of forking the match arms a second time.
///
/// `node_coords`/`weights`/`health`/`active_health` are all the same length (one entry per
/// candidate) — the caller builds that from its own candidate list. `hash_key_coord` only
/// matters for [`LoadBalance::Consistent`]. `rr_counter` is the caller's own shared cursor (one
/// per candidate *set*, not per candidate) so `RoundRobin`/`Random`/`Weighted` spread correctly
/// across repeated calls.
///
/// Fails OPEN: if every candidate is marked down by `active_health`, the algorithm's own pick
/// still goes through rather than refusing outright — a stale/wrong health-checker must not turn
/// a real outage into a guaranteed refusal on every request.
///
/// Returns `None` only when `node_coords` is empty.
#[must_use]
pub fn pick_index(
    algo: LoadBalance,
    node_coords: &[u64],
    weights: &[u32],
    health: &[Arc<HealthEstimator>],
    active_health: &[Arc<std::sync::atomic::AtomicBool>],
    hash_key_coord: u64,
    rr_counter: &std::sync::atomic::AtomicUsize,
) -> Option<usize> {
    if node_coords.is_empty() {
        return None;
    }
    if node_coords.len() == 1 {
        return Some(0);
    }
    let idx = match algo {
        LoadBalance::RoundRobin => {
            rr_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % node_coords.len()
        }
        LoadBalance::Random => {
            let seed = rr_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            (splitmix64(seed ^ now) as usize) % node_coords.len()
        }
        LoadBalance::Weighted => {
            let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
            let seed = rr_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64;
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
        LoadBalance::Consistent => {
            consistent_ring_index(hash_key_coord, node_coords, CONSISTENT_HASH_VNODES)
        }
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

    let idx = if active_health
        .get(idx)
        .map(|h| h.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(true)
    {
        idx
    } else {
        active_health
            .iter()
            .position(|h| h.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(idx)
    };
    Some(idx)
}

/// Convenience: coordinate a hashable identity the same way every caller here already does
/// (`wirefold::Coord::coord`), so nobody has to import the trait just to call [`pick_index`].
#[must_use]
pub fn coord_of<T: Coord>(value: &T) -> u64 {
    value.coord()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── `pick_index`: the non-`Upstream`-shaped algorithm, for candidates like tunnelled peer
    //    connections that aren't HTTP upstreams at all. ──────────────────────────────────────

    fn health_set(n: usize) -> Vec<Arc<HealthEstimator>> {
        (0..n).map(|_| Arc::new(HealthEstimator::new())).collect()
    }

    fn all_up(n: usize) -> Vec<Arc<std::sync::atomic::AtomicBool>> {
        (0..n)
            .map(|_| Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .collect()
    }

    #[test]
    fn pick_index_single_candidate_always_wins() {
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1],
            &[1],
            &health_set(1),
            &all_up(1),
            0,
            &std::sync::atomic::AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn pick_index_round_robin_cycles_through_every_candidate() {
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let coords = [1, 2, 3];
        let picks: Vec<usize> = (0..6)
            .map(|_| {
                pick_index(
                    LoadBalance::RoundRobin,
                    &coords,
                    &[1, 1, 1],
                    &health_set(3),
                    &all_up(3),
                    0,
                    &counter,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn pick_index_healthiest_prefers_the_lower_estimate() {
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
            &std::sync::atomic::AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn pick_index_untested_candidate_is_treated_as_best() {
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
            &std::sync::atomic::AtomicUsize::new(0),
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn pick_index_down_candidate_is_skipped() {
        let active = all_up(2);
        active[0].store(false, std::sync::atomic::Ordering::Relaxed);
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1, 2],
            &[1, 1],
            &health_set(2),
            &active,
            0,
            &std::sync::atomic::AtomicUsize::new(0), // first pick would be index 0, which is down
        );
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn pick_index_all_down_fails_open_rather_than_returning_none() {
        let active = all_up(2);
        active[0].store(false, std::sync::atomic::Ordering::Relaxed);
        active[1].store(false, std::sync::atomic::Ordering::Relaxed);
        let idx = pick_index(
            LoadBalance::RoundRobin,
            &[1, 2],
            &[1, 1],
            &health_set(2),
            &active,
            0,
            &std::sync::atomic::AtomicUsize::new(0),
        );
        assert!(idx.is_some(), "must fail open, not refuse every request");
    }

    #[test]
    fn coord_of_matches_the_coord_trait_directly() {
        let s = "route:/api".to_string();
        assert_eq!(coord_of(&s), s.coord());
    }
}
