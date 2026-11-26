//! Response rate limiting (RRL) and the per-source query budget, in fixed memory.
//!
//! Both are token buckets in a [`BucketTable`]: a fixed number of slots (memory is
//! `slots * 32 bytes` however many sources exist), indexed by a keyed hash (the key is random per
//! process, so an attacker cannot aim collisions), with the full 64-bit hash stored as a tag so
//! two keys never *share* a bucket — a colliding key evicts and starts with a full bucket. Eviction
//! therefore errs towards allowing, never towards punishing an innocent source.
//!
//! * **Budget** (`Limiter` keyed by the source network): every query from a /24 (v4) or /56 (v6)
//!   spends one token, whatever it asks, over UDP or TCP. Out of tokens, the query is dropped
//!   before it is parsed — a flood costs a hash and a lock.
//! * **RRL** (keyed by source network and *response class*): identical responses to one network
//!   are limited. NXDOMAIN/NODATA are classed by the zone they came from rather than the query
//!   name, which defeats random-subdomain floods; errors are classed by rcode. Over the limit
//!   the response is dropped, except every `slip`-th, which is sent truncated (TC=1, empty) so a
//!   real client behind a spoofed-flood victim network can retry over TCP while the reflected
//!   traffic stays small (RFC 8482 spirit, BIND "slip").

use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::Mutex;

const SHARDS: usize = 64;

#[derive(Clone, Copy, Default)]
struct Slot {
    tag: u64,
    milli_tokens: u64,
    last_ms: u64,
    drops: u32,
}

/// A fixed-size, sharded table of token buckets.
pub struct BucketTable {
    shards: Vec<Mutex<Vec<Slot>>>,
    per_shard: usize,
    hasher: std::collections::hash_map::RandomState,
    rate: u64,
    burst_milli: u64,
}

/// Outcome of taking a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    /// A token was available.
    Allowed,
    /// Out of tokens; `drops` counts consecutive denials for this bucket (1 for the first).
    Denied {
        /// Denials since the bucket last had a token.
        drops: u32,
    },
}

impl BucketTable {
    /// `slots` total buckets (rounded up to a multiple of the shard count), refilling at
    /// `rate_per_sec` tokens per second up to `burst`.
    #[must_use]
    pub fn new(slots: usize, rate_per_sec: u32, burst: u32) -> Self {
        let per_shard = slots.div_ceil(SHARDS).max(1);
        BucketTable {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(vec![Slot::default(); per_shard]))
                .collect(),
            per_shard,
            hasher: std::collections::hash_map::RandomState::new(),
            rate: u64::from(rate_per_sec),
            burst_milli: u64::from(burst.max(1)) * 1000,
        }
    }

    /// Total slots (constant for the life of the table: the memory bound).
    #[must_use]
    pub fn slots(&self) -> usize {
        self.per_shard * SHARDS
    }

    /// Take one token for `key` at `now_ms` (monotonic milliseconds).
    pub fn take<K: Hash>(&self, key: &K, now_ms: u64) -> Take {
        let h = self.hasher.hash_one(key);
        let shard = usize::try_from(h % SHARDS as u64).unwrap_or(0);
        let idx = usize::try_from((h >> 8) % self.per_shard as u64).unwrap_or(0);
        let mut guard = match self.shards.get(shard) {
            Some(m) => m.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            None => return Take::Allowed,
        };
        let Some(slot) = guard.get_mut(idx) else {
            return Take::Allowed;
        };
        if slot.tag != h || slot.last_ms == 0 && slot.milli_tokens == 0 {
            *slot = Slot {
                tag: h,
                milli_tokens: self.burst_milli,
                last_ms: now_ms.max(1),
                drops: 0,
            };
        } else {
            let elapsed = now_ms.saturating_sub(slot.last_ms);
            slot.milli_tokens = slot
                .milli_tokens
                .saturating_add(elapsed.saturating_mul(self.rate))
                .min(self.burst_milli);
            slot.last_ms = now_ms.max(slot.last_ms);
        }
        if slot.milli_tokens >= 1000 {
            slot.milli_tokens -= 1000;
            slot.drops = 0;
            Take::Allowed
        } else {
            slot.drops = slot.drops.saturating_add(1);
            Take::Denied { drops: slot.drops }
        }
    }
}

/// The aggregation prefix of a source address: /24 for IPv4, /56 for IPv6 (IPv4-mapped IPv6
/// addresses are treated as the IPv4 they carry).
#[must_use]
pub fn network_of(ip: IpAddr) -> (u8, [u8; 8]) {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    let mut out = [0u8; 8];
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            out[..3].copy_from_slice(&o[..3]);
            (4, out)
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            out[..7].copy_from_slice(&o[..7]);
            (6, out)
        }
    }
}

/// Per-source query budget.
pub struct Limiter {
    table: BucketTable,
}

impl Limiter {
    /// A budget of `rate` queries/second per network with `burst` headroom.
    #[must_use]
    pub fn new(slots: usize, rate: u32, burst: u32) -> Self {
        Limiter {
            table: BucketTable::new(slots, rate, burst),
        }
    }

    /// Whether a query from `ip` may proceed.
    pub fn allow(&self, ip: IpAddr, now_ms: u64) -> bool {
        self.table.take(&network_of(ip), now_ms) == Take::Allowed
    }

    /// Slots (memory bound).
    #[must_use]
    pub fn slots(&self) -> usize {
        self.table.slots()
    }
}

/// What to do with a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlDecision {
    /// Send it as built.
    Send,
    /// Do not send it.
    Drop,
    /// Send an empty truncated response instead.
    Slip,
}

/// The class under which identical responses are counted.
#[derive(Hash)]
pub enum ResponseClass<'a> {
    /// A positive answer: the question itself.
    Answer {
        /// Lower-cased query name.
        qname: &'a str,
        /// Query type code.
        qtype: u16,
    },
    /// NXDOMAIN / NODATA: counted per zone, not per name.
    Negative {
        /// The enclosing zone, or empty when none.
        zone: &'a str,
        /// Response code value.
        rcode: u16,
    },
    /// REFUSED, FORMERR and other errors: counted per code.
    Error {
        /// Response code value.
        rcode: u16,
    },
}

/// Response rate limiter.
pub struct Rrl {
    table: BucketTable,
    slip: u32,
}

impl Rrl {
    /// `rate`/`burst` identical responses per network; every `slip`-th denied response is sent
    /// truncated (0 disables slipping).
    #[must_use]
    pub fn new(slots: usize, rate: u32, burst: u32, slip: u32) -> Self {
        Rrl {
            table: BucketTable::new(slots, rate, burst),
            slip,
        }
    }

    /// Decide the fate of one response to `ip`.
    pub fn check(&self, ip: IpAddr, class: &ResponseClass<'_>, now_ms: u64) -> RrlDecision {
        match self.table.take(&(network_of(ip), class), now_ms) {
            Take::Allowed => RrlDecision::Send,
            Take::Denied { drops } => {
                if self.slip > 0 && drops % self.slip == 0 {
                    RrlDecision::Slip
                } else {
                    RrlDecision::Drop
                }
            }
        }
    }

    /// Slots (memory bound).
    #[must_use]
    pub fn slots(&self) -> usize {
        self.table.slots()
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_burst_is_allowed_then_the_rate_holds() {
        let l = Limiter::new(1024, 10, 20);
        let src = ip("192.0.2.7");
        let allowed = (0..100).filter(|_| l.allow(src, 1_000)).count();
        assert_eq!(allowed, 20, "burst only");
        // one second later: 10 more tokens
        let allowed = (0..100).filter(|_| l.allow(src, 2_000)).count();
        assert_eq!(allowed, 10);
        // a long quiet period refills to the burst, not beyond
        let allowed = (0..100).filter(|_| l.allow(src, 100_000)).count();
        assert_eq!(allowed, 20);
    }

    #[test]
    fn sources_in_one_network_share_a_budget_and_other_networks_do_not() {
        let l = Limiter::new(1024, 1, 5);
        for i in 0..5 {
            assert!(l.allow(ip(&format!("192.0.2.{i}")), 10));
        }
        assert!(!l.allow(ip("192.0.2.200"), 10), "same /24");
        assert!(l.allow(ip("192.0.3.1"), 10), "different /24");
        assert!(l.allow(ip("2001:db8:0:1::1"), 10));
        for _ in 0..4 {
            assert!(l.allow(ip("2001:db8:0:1:ffff::9"), 10), "same /56");
        }
        assert!(!l.allow(ip("2001:db8:0:1:aaaa::1"), 10));
        assert!(l.allow(ip("2001:db8:0:100::1"), 10), "different /56");
        // v4-mapped v6 is the v4 network
        assert!(!l.allow(ip("::ffff:192.0.2.9"), 10));
    }

    #[test]
    fn rrl_limits_identical_responses_and_slips_every_nth_denial() {
        let r = Rrl::new(1024, 5, 5, 3);
        let src = ip("198.51.100.4");
        let class = ResponseClass::Answer {
            qname: "victim.example",
            qtype: 1,
        };
        let mut sent = 0;
        let (mut dropped, mut slipped) = (0, 0);
        for _ in 0..50 {
            match r.check(src, &class, 1_000) {
                RrlDecision::Send => sent += 1,
                RrlDecision::Drop => dropped += 1,
                RrlDecision::Slip => slipped += 1,
            }
        }
        assert_eq!(sent, 5);
        assert_eq!(slipped, 15, "every third of the 45 denials");
        assert_eq!(dropped, 30);
        // a different question from the same network has its own bucket
        assert_eq!(
            r.check(
                src,
                &ResponseClass::Answer {
                    qname: "other.example",
                    qtype: 1
                },
                1_000
            ),
            RrlDecision::Send
        );
        // slip disabled: only drops
        let r0 = Rrl::new(1024, 1, 1, 0);
        assert_eq!(r0.check(src, &class, 1), RrlDecision::Send);
        assert!((0..20).all(|_| r0.check(src, &class, 1) == RrlDecision::Drop));
    }

    #[test]
    fn negative_answers_are_classed_by_zone_so_random_subdomains_share_a_bucket() {
        let r = Rrl::new(1024, 2, 3, 0);
        let src = ip("203.0.113.1");
        let mut sent = 0;
        for i in 0..100 {
            let _name = format!("random{i}.victim.example"); // the query name does not enter the class
            if r.check(
                src,
                &ResponseClass::Negative {
                    zone: "victim.example",
                    rcode: 3,
                },
                5,
            ) == RrlDecision::Send
            {
                sent += 1;
            }
        }
        assert_eq!(sent, 3);
    }

    #[test]
    fn memory_is_fixed_under_a_flood_of_distinct_sources_and_no_innocent_is_penalised_by_collisions(
    ) {
        let l = Limiter::new(256, 1, 2);
        let before = l.slots();
        let mut denied = 0;
        for a in 0..200u32 {
            for b in 0..50u32 {
                let src = IpAddr::from([10, (a % 250) as u8, (b % 250) as u8, 1]);
                if !l.allow(src, 7) {
                    denied += 1;
                }
            }
        }
        assert_eq!(l.slots(), before);
        // every distinct /24 is seen once or twice with burst 2: nothing should ever be denied
        // because of OTHER networks (a collision evicts to a full bucket, never shares one)
        assert_eq!(denied, 0);
    }

    #[test]
    fn a_non_monotonic_clock_never_panics_or_overflows() {
        let l = Limiter::new(64, u32::MAX, u32::MAX);
        let src = ip("192.0.2.1");
        for t in [u64::MAX, 0, 5, u64::MAX / 2, 1, u64::MAX] {
            let _ = l.allow(src, t);
        }
    }
}
