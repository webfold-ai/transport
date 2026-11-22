//! Per-mesh ACL adapter implementations.
//!
//! Each adapter implements `MeshAclAdapter` for a specific mesh control
//! plane. After the Warpgate ADR
//! (`docs/decisions/2026-05-06-warpgate-as-operator-bastion.md`, umbrella),
//! the adapters split into two role buckets:
//!
//! | Adapter | Role bucket | Status |
//! |---|---|---|
//! | `netbird` (managed + customer) | Overlay membership | LIVE |
//! | `tailscale` | Overlay membership | LIVE |
//! | `cloudflare_access` | Customer-facing ZTNA | LIVE |
//! | `warpgate` | Operator → managed-service ACLs | TYPED SHELL (wire impl pending) |
//!
//! Adapter selection: `mode` field on the integration row →
//! `AdapterRegistry`. Adapters are stateless; per-call config comes from
//! the `IntegrationRow` + injected resolvers.
//!
//! In other words: `NetBird` / Tailscale / Cloudflare Access answer *"is
//! this peer/user allowed on this mesh / Access App?"*. Warpgate (when
//! its wire impl lands in Phase 1 of `Tasmanian-Cloud/warpgate-deploy`)
//! answers *"can this operator open a session to this specific
//! managed-service instance?"*. Two distinct questions, two distinct
//! adapter targets.

pub mod cloudflare_access;
pub mod netbird;
pub mod tailscale;
pub mod warpgate;

pub use cloudflare_access::{
    CloudflareAccessAdapter, CloudflareAccessSecret, CloudflareAccessSecretResolver, UserResolver,
};
pub use netbird::NetBirdAdapter;
pub use tailscale::TailscaleAdapter;
pub use warpgate::{WarpgateAdapter, WarpgateConfig, WarpgateConfigResolver};
