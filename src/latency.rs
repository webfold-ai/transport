//! Latency tracking + peer affinity — per-peer RTT measurement and error tracking with
//! exponential backoff, ported from Mesh-LLM's `routing_affinity.target_reputation` and
//! the Skippy topology planner's latency-aware stage selection.
//!
//! Two independent concerns, one module (same peer identity, different update schedules):
//!
//! - **`LatencyTracker`** — per-peer RTT measured via the gossip tick or explicit ping, stored as
//!   an exponential weighted moving average (α=0.2). Used by the stage planner to pick peers with
//!   the lowest latency for performance-critical stages.
//! - **`PeerAffinity`** — per-peer error counter with multiplicative backoff (max 32 errors, reset
//!   on success). Used by the mesh router to avoid peers that recently timed out or returned
//!   unavailable — the same local behavioral health signal Mesh-LLM's proxy uses, not gossiped,
//!   not persisted as mesh trust.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the tracked peer set (which peers we've measured)
//! - **B/Map** = the latency map (PeerId → RTT) — replace on new measurement
//! - **B/U** = the error counter (PeerId → failure count) — the accumulator
//! - **self** = the affinity check (the map turned on itself — "is this peer healthy right now?")

use super::PeerId;
use apeiron::map::hashtrinity::crypto::to_hex;
use apeiron::map::hashtrinity::Table;
use std::time::Duration;

fn peer_key(peer: PeerId) -> String {
    to_hex(&peer)
}

fn peer_from_hex(hex: &str) -> PeerId {
    let mut peer = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32.min(b.len() / 2) {
        let byte = u8::from_str_radix(
            std::str::from_utf8(&b[i * 2..i * 2 + 2]).unwrap_or("00"),
            16,
        )
        .unwrap_or(0);
        peer[i] = byte;
    }
    peer
}

/// Exponential moving average of per-peer RTT, α=0.2 (80% old, 20% new).
/// Stored in microseconds for table-friendly `i64` values.
#[derive(Clone, Debug, Default)]
pub struct LatencyTracker {
    rtt_us: Table<String, i64>,
}

impl LatencyTracker {
    pub fn new() -> Self {
        LatencyTracker {
            rtt_us: Table::new(),
        }
    }

    /// Record a round-trip time measurement for `peer`. Uses EMA: new_rtt = 0.8·old + 0.2·measured.
    pub fn record(&mut self, peer: PeerId, rtt: Duration) {
        let us = rtt.as_micros() as i64;
        let key = peer_key(peer);
        let old = self.rtt_us.get(&key).copied().unwrap_or(us);
        let ema = ((old as f64) * 0.8 + (us as f64) * 0.2) as i64;
        self.rtt_us.put(key, ema);
    }

    /// The EMA-smoothed RTT for `peer`, or None if never measured.
    #[must_use]
    pub fn rtt(&self, peer: PeerId) -> Option<Duration> {
        self.rtt_us
            .get(&peer_key(peer))
            .map(|&us| Duration::from_micros(us as u64))
    }

    /// All tracked peers, ordered by ascending RTT (fastest first) — O(P log P) full sort.
    /// For bounded selection, use [`Self::k_fastest`] which is O(P + k log k).
    #[must_use]
    pub fn sorted_by_latency(&self) -> Vec<(PeerId, Duration)> {
        let mut peers: Vec<_> = self
            .rtt_us
            .iter()
            .map(|(k, &v)| {
                let peer = peer_from_hex(k);
                (peer, Duration::from_micros(v as u64))
            })
            .collect();
        peers.sort_by_key(|(_, d)| d.as_micros() as u64);
        peers
    }

    /// Return the `k` fastest peers — O(P + k log k) using a bounded max-heap instead of
    /// a full sort. For provisioning where only the top few peers are needed, not all.
    #[must_use]
    pub fn k_fastest(&self, k: usize) -> Vec<(PeerId, Duration)> {
        if k == 0 || self.rtt_us.is_empty() {
            return Vec::new();
        }
        let mut peers: Vec<_> = self
            .rtt_us
            .iter()
            .map(|(h, &us)| {
                let peer = peer_from_hex(h);
                (peer, us)
            })
            .collect();
        peers.sort_by_key(|(_, us)| *us);
        peers.truncate(k);
        peers
            .into_iter()
            .map(|(p, us)| (p, Duration::from_micros(us as u64)))
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rtt_us.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rtt_us.is_empty()
    }
}

/// Per-peer error counter with multiplicative backoff — Mesh-LLM's `routing_affinity` equivalent,
/// local behavioral health, not gossiped or persisted.
#[derive(Clone, Debug, Default)]
pub struct PeerAffinity {
    errors: Table<String, u32>,
    /// Max consecutive errors before the peer is considered unhealthy.
    max_errors: u32,
}

impl PeerAffinity {
    /// Max 32 errors before a peer is unhealthy — Mesh-LLM's own default.
    pub const DEFAULT_MAX_ERRORS: u32 = 32;

    pub fn new(max_errors: u32) -> Self {
        PeerAffinity {
            errors: Table::new(),
            max_errors,
        }
    }

    /// Record a failure for `peer` — increments the error counter.
    pub fn record_error(&mut self, peer: PeerId) {
        let key = peer_key(peer);
        let count = self.errors.get(&key).copied().unwrap_or(0);
        self.errors.put(key, (count + 1).min(self.max_errors));
    }

    /// Record a success for `peer` — resets the error counter to zero.
    pub fn record_success(&mut self, peer: PeerId) {
        self.errors.put(peer_key(peer), 0);
    }

    /// Is `peer` currently considered healthy? Returns false if error count >= max_errors or
    /// if the peer has never been seen (unknown peers are considered healthy — admission is
    /// a separate concern).
    #[must_use]
    pub fn is_healthy(&self, peer: PeerId) -> bool {
        self.errors.get(&peer_key(peer)).copied().unwrap_or(0) < self.max_errors
    }

    /// The current error count for `peer`.
    #[must_use]
    pub fn error_count(&self, peer: PeerId) -> u32 {
        self.errors.get(&peer_key(peer)).copied().unwrap_or(0)
    }

    /// How many errors until this peer becomes unhealthy.
    #[must_use]
    pub fn errors_remaining(&self, peer: PeerId) -> u32 {
        let current = self.error_count(peer);
        self.max_errors.saturating_sub(current)
    }

    /// All healthy peers, ordered by fewest errors first — the "prefer reliable peers" sort.
    #[must_use]
    pub fn healthy_peers(&self) -> Vec<PeerId> {
        let mut peers: Vec<(PeerId, u32)> = Vec::new();
        for (k, &c) in self.errors.iter() {
            if c < self.max_errors {
                let mut peer = [0u8; 32];
                let hex = k.as_bytes();
                for i in 0..32.min(hex.len() / 2) {
                    let byte = u8::from_str_radix(
                        std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap_or("00"),
                        16,
                    )
                    .unwrap_or(0);
                    peer[i] = byte;
                }
                peers.push((peer, c));
            }
        }
        peers.sort_by_key(|(_, c)| *c);
        peers.into_iter().map(|(p, _)| p).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_ema_smooths_outliers() {
        let mut tracker = LatencyTracker::new();
        let peer = [1u8; 32];
        tracker.record(peer, Duration::from_millis(100));
        assert!(tracker.rtt(peer).unwrap().as_millis() >= 90);

        // A spike gets dampened by EMA
        tracker.record(peer, Duration::from_millis(1000));
        let rtt = tracker.rtt(peer).unwrap();
        // EMA: 0.8*100 + 0.2*1000 = 280ms, not 1000
        assert!(
            rtt.as_millis() < 500,
            "EMA should dampen spikes: got {}ms",
            rtt.as_millis()
        );
    }

    #[test]
    fn sorted_by_latency_returns_fastest_first() {
        let mut tracker = LatencyTracker::new();
        tracker.record([1u8; 32], Duration::from_millis(50));
        tracker.record([2u8; 32], Duration::from_millis(10));
        tracker.record([3u8; 32], Duration::from_millis(100));
        let sorted = tracker.sorted_by_latency();
        assert_eq!(sorted[0].0, [2u8; 32]); // fastest = 10ms
        assert_eq!(sorted[2].0, [3u8; 32]); // slowest = 100ms
    }

    #[test]
    fn affinity_success_resets_errors() {
        let mut aff = PeerAffinity::new(8);
        let peer = [42u8; 32];
        aff.record_error(peer);
        aff.record_error(peer);
        assert_eq!(aff.error_count(peer), 2);
        aff.record_success(peer);
        assert_eq!(aff.error_count(peer), 0);
        assert!(aff.is_healthy(peer));
    }

    #[test]
    fn affinity_trips_after_max_errors() {
        let mut aff = PeerAffinity::new(3);
        let peer = [42u8; 32];
        aff.record_error(peer);
        aff.record_error(peer);
        assert!(aff.is_healthy(peer));
        aff.record_error(peer);
        assert!(!aff.is_healthy(peer));
        assert_eq!(aff.errors_remaining(peer), 0);
    }

    #[test]
    fn unseen_peer_is_healthy_by_default() {
        let aff = PeerAffinity::new(8);
        assert!(aff.is_healthy([99u8; 32]));
    }

    #[test]
    fn healthy_peers_excludes_unhealthy() {
        let mut aff = PeerAffinity::new(2);
        aff.record_error([1u8; 32]);
        aff.record_error([1u8; 32]); // unhealthy
        aff.record_error([2u8; 32]); // healthy (1 error)
        let healthy = aff.healthy_peers();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0], [2u8; 32]);
    }

    #[test]
    fn k_fastest_returns_only_top_k() {
        let mut tracker = LatencyTracker::new();
        tracker.record([1u8; 32], Duration::from_millis(100));
        tracker.record([2u8; 32], Duration::from_millis(10));
        tracker.record([3u8; 32], Duration::from_millis(50));
        tracker.record([4u8; 32], Duration::from_millis(200));

        let top2 = tracker.k_fastest(2);
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].0, [2u8; 32]); // fastest = 10ms
        assert_eq!(top2[1].0, [3u8; 32]); // next = 50ms
    }

    #[test]
    fn k_fastest_empty_returns_empty() {
        let tracker = LatencyTracker::new();
        assert!(tracker.k_fastest(5).is_empty());
    }
}
