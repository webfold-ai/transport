//! Maglev consistent hashing (Eisenbud et al., NSDI 2016), weighted.
//!
//! ## Why Maglev, and what it is for
//!
//! RFC 0031 recommends Maglev for choosing a backend for a **new** flow. Alternatives
//! considered: rendezvous (highest-random-weight) hashing is simpler and disrupts exactly
//! `1/n`, but costs O(n) hashes per new flow and gives no O(1) table that an XDP plane can
//! mirror into a BPF array; a plain `hash % n` remaps almost everything on any change. Maglev
//! gives an O(1) lookup in a flat table (which is also the shape the future XDP plane needs) and
//! near-minimal disruption, at the price of a few milliseconds to rebuild the table when the
//! eligible set changes.
//!
//! **Maglev does not pin flows and this crate does not rely on it to.** It minimises, but does
//! not eliminate, remapping when the set changes; established flows are pinned by the connection
//! tracking table in [`crate::flows`] and never consult this table again. Everything here only
//! answers "where does a flow that has no entry go".
//!
//! ## Construction
//!
//! The table has [`TABLE_SIZE`] slots (65 537, prime). Each backend `i` owns a permutation of the
//! slots, `perm_i(j) = (offset_i + j * skip_i) mod M`, with `offset_i` and `skip_i` taken from a
//! SHA-256 of the backend's name, so any two nodes with the same members compute the same table.
//! Backends take turns claiming their next unclaimed slot until the table is full.
//!
//! Weights: in round `r` (1-based) backend `i` takes a turn iff
//! `floor(r * w_i / w_max) > floor((r - 1) * w_i / w_max)`, so it takes `w_i / w_max` turns per
//! round on average, and a backend with the maximum weight takes one every round.

use apeiron::map::hashtrinity::crypto::sha256;

/// Number of slots. Prime, so every `skip` in `1..M` generates a full permutation. With at most
/// [`crate::backend::MAX_BACKENDS`] backends that is at least 256 slots per backend.
pub const TABLE_SIZE: usize = 65_537;
const TABLE_SIZE_U64: u64 = 65_537;

/// One participant: a stable name (hashed into the permutation) and a weight.
#[derive(Debug, Clone)]
pub struct Member {
    /// Bytes hashed to derive the permutation; must be stable across nodes.
    pub name: Vec<u8>,
    /// Relative weight, `>= 1`.
    pub weight: u32,
}

/// A built lookup table. Entries index into the member slice it was built from.
#[derive(Debug, Clone)]
pub struct Table {
    slots: Vec<u16>,
    members: usize,
}

const EMPTY: u16 = u16::MAX;

fn permutation_params(name: &[u8]) -> (u64, u64) {
    let mut input = Vec::with_capacity(name.len() + 16);
    input.extend_from_slice(b"tas-lb/maglev/v1\0");
    input.extend_from_slice(name);
    let h = sha256(&input);
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    a.copy_from_slice(&h[0..8]);
    b.copy_from_slice(&h[8..16]);
    (
        u64::from_be_bytes(a) % TABLE_SIZE_U64,
        u64::from_be_bytes(b) % (TABLE_SIZE_U64 - 1) + 1,
    )
}

impl Table {
    /// Build the table for `members`. No members (or more than `u16::MAX - 1`) gives an empty
    /// table whose lookups return `None`.
    #[must_use]
    pub fn build(members: &[Member]) -> Table {
        let n = members.len();
        if n == 0 || n >= usize::from(EMPTY) {
            return Table {
                slots: Vec::new(),
                members: 0,
            };
        }
        let m = TABLE_SIZE_U64;
        let ids: Vec<u16> = (0..n).filter_map(|i| u16::try_from(i).ok()).collect();
        if ids.len() != n {
            return Table {
                slots: Vec::new(),
                members: 0,
            };
        }
        let params: Vec<(u64, u64)> = members
            .iter()
            .map(|x| permutation_params(&x.name))
            .collect();
        let weights: Vec<u64> = members.iter().map(|x| u64::from(x.weight.max(1))).collect();
        let w_max = weights.iter().copied().max().unwrap_or(1);
        let mut next = vec![0u64; n];
        let mut slots = vec![EMPTY; TABLE_SIZE];
        let mut filled = 0usize;
        let mut round: u64 = 0;
        while filled < TABLE_SIZE {
            round += 1;
            for i in 0..n {
                let w = weights[i];
                // Takes a turn this round?
                if round * w / w_max <= (round - 1) * w / w_max {
                    continue;
                }
                let (offset, skip) = params[i];
                // Claim this backend's next unclaimed slot. `next[i]` only grows, and the
                // permutation covers all slots, so this terminates while any slot is free.
                loop {
                    let c = usize::try_from((offset + next[i] * skip) % m).unwrap_or(0);
                    next[i] += 1;
                    if slots[c] == EMPTY {
                        slots[c] = ids[i];
                        filled += 1;
                        break;
                    }
                }
                if filled == TABLE_SIZE {
                    break;
                }
            }
        }
        Table { slots, members: n }
    }

    /// The member index for `hash`, or `None` for an empty table.
    #[must_use]
    pub fn lookup(&self, hash: u64) -> Option<usize> {
        self.lookup_skipping(hash, |_| false)
    }

    /// Like [`Table::lookup`], but walks forward from the hashed slot past members for which
    /// `skip` returns true (a retry after a failed connect). Bounded by one lap of the table.
    #[must_use]
    pub fn lookup_skipping(&self, hash: u64, skip: impl Fn(usize) -> bool) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let start = usize::try_from(hash % TABLE_SIZE_U64).unwrap_or(0);
        for step in 0..TABLE_SIZE {
            let idx = (start + step) % TABLE_SIZE;
            let member = usize::from(*self.slots.get(idx)?);
            if !skip(member) {
                return Some(member);
            }
        }
        None
    }

    /// Slots owned by each member (for balance tests and diagnostics).
    #[must_use]
    pub fn share(&self) -> Vec<usize> {
        let mut out = vec![0usize; self.members];
        for s in &self.slots {
            if let Some(c) = out.get_mut(usize::from(*s)) {
                *c += 1;
            }
        }
        out
    }

    /// Number of members the table was built for.
    #[must_use]
    pub fn members(&self) -> usize {
        self.members
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::cast_precision_loss,
        reason = "test code: deterministic assertions on fixtures; ratios of small counts"
    )]
    use super::*;

    fn members(n: usize, weight: u32) -> Vec<Member> {
        (0..n)
            .map(|i| Member {
                name: format!("edge-{i}|10.0.0.{i}").into_bytes(),
                weight,
            })
            .collect()
    }

    fn key_hash(i: u64) -> u64 {
        // Any well-mixed function of i will do for these tests.
        let h = sha256(&i.to_be_bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&h[..8]);
        u64::from_be_bytes(b)
    }

    #[test]
    fn every_slot_is_filled_and_shares_are_balanced() {
        let t = Table::build(&members(8, 100));
        let share = t.share();
        assert_eq!(share.iter().sum::<usize>(), TABLE_SIZE);
        let ideal = TABLE_SIZE / 8;
        for s in share {
            // Maglev guarantees near-equal shares (within a couple of slots for equal weights).
            assert!(s.abs_diff(ideal) <= 3, "share {s} vs ideal {ideal}");
        }
    }

    #[test]
    fn the_table_is_a_pure_function_of_the_members() {
        let a = Table::build(&members(5, 100));
        let b = Table::build(&members(5, 100));
        for i in 0..2000 {
            assert_eq!(a.lookup(key_hash(i)), b.lookup(key_hash(i)));
        }
    }

    #[test]
    fn weights_scale_shares() {
        let mut m = members(3, 100);
        m[0].weight = 300;
        m[1].weight = 100;
        m[2].weight = 100;
        let share = Table::build(&m).share();
        let total: usize = share.iter().sum();
        let frac0 = share[0] as f64 / total as f64;
        assert!(
            (frac0 - 0.6).abs() < 0.01,
            "weight 300 of 500 should own ~60%, got {frac0}"
        );
        assert!((share[1] as f64 / total as f64 - 0.2).abs() < 0.01);
    }

    #[test]
    fn a_tiny_weight_still_gets_its_proportional_sliver() {
        let mut m = members(2, 1000);
        m[1].weight = 10;
        let share = Table::build(&m).share();
        let frac1 = share[1] as f64 / TABLE_SIZE as f64;
        assert!(frac1 > 0.005 && frac1 < 0.02, "got {frac1}");
    }

    #[test]
    fn removing_a_member_remaps_little_beyond_the_removed_members_share() {
        let before = Table::build(&members(8, 100));
        let mut after_members = members(8, 100);
        let removed = after_members.remove(3); // original index 3
        let after = Table::build(&after_members);
        let _ = removed;
        let mut moved_unaffected = 0usize;
        let mut unaffected = 0usize;
        for i in 0..20_000u64 {
            let h = key_hash(i);
            let b = before.lookup(h).unwrap();
            let a = after.lookup(h).unwrap();
            // Map the new index back to the original index space.
            let a_orig = if a >= 3 { a + 1 } else { a };
            if b != 3 {
                unaffected += 1;
                if a_orig != b {
                    moved_unaffected += 1;
                }
            }
        }
        let frac = moved_unaffected as f64 / unaffected as f64;
        // Maglev is "near-minimal", not zero: this is exactly why flows are pinned elsewhere.
        assert!(frac < 0.10, "{frac} of flows on surviving members moved");
    }

    #[test]
    fn lookup_skipping_finds_another_member() {
        let t = Table::build(&members(4, 100));
        for i in 0..500u64 {
            let h = key_hash(i);
            let first = t.lookup(h).unwrap();
            let second = t.lookup_skipping(h, |m| m == first).unwrap();
            assert_ne!(first, second);
        }
        // Skipping everyone yields nothing, after one bounded lap.
        assert_eq!(t.lookup_skipping(1, |_| true), None);
    }

    #[test]
    fn empty_and_single_member_tables() {
        assert_eq!(Table::build(&[]).lookup(5), None);
        let t = Table::build(&members(1, 7));
        assert_eq!(t.lookup(123), Some(0));
        assert_eq!(t.share(), vec![TABLE_SIZE]);
    }

    #[test]
    fn two_hundred_fifty_six_members_still_fill_the_table() {
        let t = Table::build(&members(256, 100));
        let share = t.share();
        assert_eq!(share.iter().sum::<usize>(), TABLE_SIZE);
        assert!(
            share.iter().all(|s| *s >= 250 && *s <= 262),
            "{:?}",
            (share.iter().min(), share.iter().max())
        );
    }
}
