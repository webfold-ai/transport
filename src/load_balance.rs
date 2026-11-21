//! Shared load-balancing primitives — the algorithm set `biota-http-server`'s `kernel::Proxy`
//! implements over HTTP `Upstream`s, and this crate's own [`crate::edge_proxy::ConnectorPool`]
//! needs over tunnelled `PeerId` connections. Neither type knows about the other, so the shared
//! part is exactly the pure selection logic: given N candidates (identified only by a
//! `apeiron::map::hashtrinity::Coord` and a weight) plus per-candidate health state, pick one index.
//!
//! The load-balancing set lives in `relayfold`, which is the canonical home for it: this module
//! is a thin re-export rather than a second copy of the same algorithm, so a fix lands in one
//! place and every consumer of it gets the fix.
pub use relayfold::{
    consistent_ring_index, coord_of, pick_index, splitmix64, HealthEstimator, LoadBalance,
    CONSISTENT_HASH_VNODES,
};
