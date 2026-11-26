//! Per-source new-flow rate limiting in fixed memory.
//!
//! A map keyed by source address would grow with the number of distinct sources, which an
//! attacker with a /48 controls. This is a fixed array of `(second, count)` cells indexed by a
//! keyed hash of the source: memory is constant whatever the attacker does, the key is random per
//! process so collisions cannot be engineered to rate-limit a chosen victim, and the worst case
//! of a collision is that two sources share a budget (a false positive, never a bypass).
//!
//! Window semantics are fixed one-second windows, which allows up to 2x the limit across a window
//! boundary. That is acceptable for an abuse limiter whose job is to bound the order of
//! magnitude, not to meter.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cells in the array (power of two). 64 Ki cells is 512 KiB.
const CELLS: usize = 1 << 16;

/// Fixed-memory rate limiter.
pub struct SourceRateLimiter {
    cells: Vec<AtomicU64>,
    hasher: RandomState,
    limit_per_sec: u32,
}

impl core::fmt::Debug for SourceRateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceRateLimiter")
            .field("limit_per_sec", &self.limit_per_sec)
            .finish_non_exhaustive()
    }
}

/// Aggregate IPv6 sources to their /64 (a single subscriber commonly holds a whole /64, so
/// per-address accounting is bypassed by rotating addresses); IPv4 stays per-address.
#[must_use]
pub fn source_bucket(ip: IpAddr) -> u128 {
    match ip.to_canonical() {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        // Tag bit 127 so no v6 /64 collides with a v4 value.
        IpAddr::V6(v6) => (u128::from(v6) >> 64) | (1u128 << 127),
    }
}

impl SourceRateLimiter {
    /// `limit_per_sec == 0` disables limiting.
    #[must_use]
    pub fn new(limit_per_sec: u32) -> Self {
        SourceRateLimiter {
            cells: (0..CELLS).map(|_| AtomicU64::new(0)).collect(),
            hasher: RandomState::new(),
            limit_per_sec,
        }
    }

    /// Account one new flow from `ip` at wall-clock second `now_sec`; false means over limit.
    pub fn allow(&self, ip: IpAddr, now_sec: u32) -> bool {
        if self.limit_per_sec == 0 {
            return true;
        }
        let idx = usize::try_from(self.hasher.hash_one(source_bucket(ip)) & (CELLS as u64 - 1))
            .unwrap_or(0);
        let Some(cell) = self.cells.get(idx) else {
            return false;
        };
        let mut cur = cell.load(Ordering::Relaxed);
        loop {
            let (sec, count) = (
                u32::try_from(cur >> 32).unwrap_or(u32::MAX),
                u32::try_from(cur & 0xFFFF_FFFF).unwrap_or(u32::MAX),
            );
            let next = if sec == now_sec {
                if count >= self.limit_per_sec {
                    return false;
                }
                (u64::from(sec) << 32) | u64::from(count + 1)
            } else {
                (u64::from(now_sec) << 32) | 1
            };
            match cell.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_up_to_the_limit_then_refuses_within_a_second() {
        let r = SourceRateLimiter::new(3);
        let a = ip("203.0.113.1");
        assert!(r.allow(a, 100) && r.allow(a, 100) && r.allow(a, 100));
        assert!(!r.allow(a, 100));
        assert!(!r.allow(a, 100));
    }

    #[test]
    fn the_budget_returns_in_the_next_second() {
        let r = SourceRateLimiter::new(1);
        let a = ip("203.0.113.1");
        assert!(r.allow(a, 5));
        assert!(!r.allow(a, 5));
        assert!(r.allow(a, 6));
    }

    #[test]
    fn sources_are_independent() {
        let r = SourceRateLimiter::new(1);
        assert!(r.allow(ip("203.0.113.1"), 1));
        assert!(r.allow(ip("203.0.113.2"), 1));
    }

    #[test]
    fn a_v6_slash_64_shares_one_budget() {
        let r = SourceRateLimiter::new(2);
        assert!(r.allow(ip("2001:db8:1:2::1"), 1));
        assert!(r.allow(ip("2001:db8:1:2:ffff::9"), 1));
        assert!(
            !r.allow(ip("2001:db8:1:2::77"), 1),
            "rotating addresses inside a /64 must not reset the budget"
        );
        assert!(
            r.allow(ip("2001:db8:1:3::1"), 1),
            "a different /64 is a different source"
        );
    }

    #[test]
    fn v4_mapped_v6_is_the_same_source_as_v4() {
        assert_eq!(
            source_bucket(ip("::ffff:192.0.2.5")),
            source_bucket(ip("192.0.2.5"))
        );
    }

    #[test]
    fn zero_disables_limiting() {
        let r = SourceRateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(r.allow(ip("203.0.113.1"), 1));
        }
    }

    #[test]
    fn memory_is_fixed_regardless_of_distinct_sources() {
        let r = SourceRateLimiter::new(5);
        let before = r.cells.len();
        for i in 0..200_000u32 {
            let _ = r.allow(IpAddr::V4(i.into()), 1);
        }
        assert_eq!(r.cells.len(), before);
    }
}
