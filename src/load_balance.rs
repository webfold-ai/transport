//! Shared load-balancing primitives — the algorithm set `biota-http-server`'s `kernel::Proxy`
//! implements over HTTP `Upstream`s, and this crate's own [`crate::edge_proxy::ConnectorPool`]
//! needs over tunnelled `PeerId` connections. Neither type knows about the other, so the shared
//! part is exactly the pure selection logic: given N candidates (identified only by a
//! `apeiron::map::hashtrinity::Coord` and a weight) plus per-candidate health state, pick one index.
//!
//! This module used to define `LoadBalance`/`HealthEstimator`/`splitmix64`/`consistent_ring_index`
//! /`pick_index`/`coord_of` directly — its own independent extraction out of `kernel::Backends`,
//! done without knowing `relayfold` (github.com/Ptyktos/relayfold) already existed as the same
//! extraction out of `bedrock::native_lib`. Reconciled 2026-09-23: `relayfold` is the superset (it
//! also carries `Tuple`/`Relationships`/`Upstream`/`Backends`, which this module's version
//! didn't) and is already what `bedrock` itself re-exports on both remotes, so it's canonical —
//! this module is now a thin re-export rather than a second fork of the same algorithm.
pub use relayfold::{
    consistent_ring_index, coord_of, pick_index, splitmix64, HealthEstimator, LoadBalance,
    CONSISTENT_HASH_VNODES,
};
