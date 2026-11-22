//! Warpgate ACL adapter — operator → managed-service per-target ACLs.
//!
//! This adapter is the **authoritative writer** for the bucket of ACLs the
//! Warpgate ADR (`docs/decisions/2026-05-06-warpgate-as-operator-bastion.md`,
//! umbrella) carved out: "can operator X open a session to managed-service
//! instance Y?". The other adapters (`netbird`, `tailscale`,
//! `cloudflare_access`) handle a different bucket — overlay membership and
//! customer-facing ZTNA — and stay in their lane.
//!
//! # Naming convention (mirrors the netbird / tailscale adapters)
//!
//! Warpgate primitives we use, with the convention names this adapter mints:
//!
//! | Warpgate primitive | tas-cloud convention name | Source field |
//! |---|---|---|
//! | User      | `tas-cloud:user:<user_id>`           | `MeshAclRule.user_id` |
//! | Target    | `tas-cloud:dep:<deployment_id>`      | `MeshAclRule.deployment_id` |
//! | Role      | `tas-cloud:role:<role>`              | `MeshAclRule.role` (e.g. `member` / `admin`) |
//! | Grant     | (user, target) via shared role       | derived |
//!
//! Reverse lookup at `list_rules` time: enumerate Warpgate users + targets,
//! parse the convention prefixes back into `(user_id, deployment_id, role)`.
//!
//! # Wire-protocol status
//!
//! **TYPED SHELL.** The trait + config + resolver shapes are locked. The
//! actual REST calls (`POST /api/users`, `POST /api/targets`,
//! `POST /api/users/{id}/role/{role_id}`, etc.) land in a follow-up PR after
//! Phase 1 of `Tasmanian-Cloud/warpgate-deploy` validates the live admin-API
//! endpoints against a running instance.
//!
//! Until that lands, [`WarpgateAdapter`] returns a clearly-marked
//! `not-yet-implemented` error from `push_add` / `push_remove`, and an
//! empty list from `list_rules`. The reconciler treats this the same as
//! any other empty mesh — drift is computed but no-ops are pushed.
//!
//! # Why typed shell now (vs wait for the real impl)
//!
//! 1. Locks the trait surface so downstream code (msp-portal admin UI,
//!    upgrade scripts, tests) can already depend on `WarpgateAdapter`.
//! 2. Locks the resolver / config split so warpgate-deploy Phase 1 doesn't
//!    have to re-litigate where the API URL + token live.
//! 3. Replaces the generic `StubAdapter` registration in `main.rs` with a
//!    Warpgate-specific shell whose error message tells the operator
//!    *which* service they're missing the impl for.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use crate::adapter::{MeshAclAdapter, MeshAclRule};
use crate::IntegrationRow;

/// Static config for a Warpgate integration.
///
/// `api_url` and `target_prefix` come from the integration row (or the
/// resolver — see below); `api_token` is fetched from Vault per call so the
/// adapter never holds long-lived credentials in memory.
#[derive(Clone, Debug)]
pub struct WarpgateConfig {
    /// e.g. `https://warpgate-a.tas.twn.network:8888` — Warpgate's admin
    /// REST API base. Netbird-only; never a public-internet endpoint.
    pub api_url: String,
    /// Prefix for naming Warpgate users / targets / roles. Defaults to
    /// `"tas-cloud"` so collisions with operator-created entities are
    /// impossible — the prefix is search-and-replace-grepable for ops.
    pub target_prefix: String,
    /// Bearer token for the Warpgate admin REST API. **Always** fetched
    /// fresh from Vault per call — never persisted in this struct beyond
    /// the duration of one reconcile cycle.
    pub api_token: String,
}

/// Resolves the live [`WarpgateConfig`] for a given integration. Production
/// wires this to Vault + the integration row; tests use a static closure.
#[async_trait]
pub trait WarpgateConfigResolver: Send + Sync {
    async fn resolve(&self, integration: &IntegrationRow) -> Result<WarpgateConfig>;
}

/// Warpgate ACL adapter — see module-level docs for the role split and the
/// "TYPED SHELL" status note.
pub struct WarpgateAdapter {
    resolver: Arc<dyn WarpgateConfigResolver>,
}

impl WarpgateAdapter {
    #[must_use]
    pub fn new(resolver: Arc<dyn WarpgateConfigResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl MeshAclAdapter for WarpgateAdapter {
    /// Enumerate (user, target) grants currently in Warpgate, decoded from
    /// the convention naming.
    ///
    /// **TYPED SHELL** — full impl awaits Phase-1 verification of Warpgate's
    /// admin REST API shape. Currently returns an empty list, which the
    /// reconciler treats as "Warpgate has no rules" → all desired rules
    /// become drift (and are then refused by `push_add` below until the
    /// real impl lands). That makes the gap loud rather than silent.
    async fn list_rules(&self, integration: &IntegrationRow) -> Result<Vec<MeshAclRule>> {
        // Resolve to validate the resolver pipeline — even in shell mode this
        // shakes out config / Vault / network plumbing problems early.
        let _config = self.resolver.resolve(integration).await?;
        Ok(Vec::new())
    }

    /// Grant a (user → target) ACL on Warpgate.
    ///
    /// **TYPED SHELL** — see module docs.
    async fn push_add(&self, integration: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let config = self.resolver.resolve(integration).await?;
        Err(anyhow::anyhow!(
            "WarpgateAdapter::push_add not yet implemented (rule {} → {} on {}); \
             waiting on warpgate-deploy Phase 1 to verify live admin-API shape",
            rule.user_id,
            rule.deployment_id,
            config.api_url,
        ))
    }

    /// Revoke a (user → target) ACL on Warpgate.
    ///
    /// **TYPED SHELL** — see module docs.
    async fn push_remove(&self, integration: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let config = self.resolver.resolve(integration).await?;
        Err(anyhow::anyhow!(
            "WarpgateAdapter::push_remove not yet implemented (rule {} → {} on {}); \
             waiting on warpgate-deploy Phase 1 to verify live admin-API shape",
            rule.user_id,
            rule.deployment_id,
            config.api_url,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: Result-unwrap assertions on deterministic fixtures"
    )]
    use super::*;
    use uuid::Uuid;

    struct StaticResolver(WarpgateConfig);

    #[async_trait]
    impl WarpgateConfigResolver for StaticResolver {
        async fn resolve(&self, _: &IntegrationRow) -> Result<WarpgateConfig> {
            Ok(self.0.clone())
        }
    }

    fn integration() -> IntegrationRow {
        IntegrationRow {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            mode: "warpgate-gateway".into(),
            netbird_api_url: None,
            netbird_group_id: None,
            tailscale_tailnet: None,
            credentials_secret_id: Some(Uuid::new_v4()),
        }
    }

    fn rule() -> MeshAclRule {
        MeshAclRule {
            user_id: Uuid::new_v4(),
            deployment_id: Uuid::new_v4(),
            deployment_name: "tas-cloud:dep:test".into(),
            role: "member".into(),
        }
    }

    fn config() -> WarpgateConfig {
        WarpgateConfig {
            api_url: "https://warpgate-test.tas.twn.network:8888".into(),
            target_prefix: "tas-cloud".into(),
            api_token: "test-token".into(),
        }
    }

    #[tokio::test]
    async fn list_rules_returns_empty_in_shell_mode() {
        let adapter = WarpgateAdapter::new(Arc::new(StaticResolver(config())));
        let result = adapter.list_rules(&integration()).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn push_add_returns_explicit_not_implemented_error() {
        let adapter = WarpgateAdapter::new(Arc::new(StaticResolver(config())));
        let err = adapter.push_add(&integration(), &rule()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not yet implemented"), "got: {msg}");
        assert!(msg.contains("warpgate-deploy Phase 1"), "got: {msg}");
        // The error must include identifying info so an operator can grep
        // logs for which rule failed.
        assert!(msg.contains("warpgate-test.tas.twn.network"), "got: {msg}");
    }

    #[tokio::test]
    async fn push_remove_returns_explicit_not_implemented_error() {
        let adapter = WarpgateAdapter::new(Arc::new(StaticResolver(config())));
        let err = adapter
            .push_remove(&integration(), &rule())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not yet implemented"), "got: {msg}");
    }

    #[tokio::test]
    async fn resolver_failure_propagates_through_list_rules() {
        struct FailingResolver;
        #[async_trait]
        impl WarpgateConfigResolver for FailingResolver {
            async fn resolve(&self, _: &IntegrationRow) -> Result<WarpgateConfig> {
                Err(anyhow::anyhow!("vault unreachable"))
            }
        }
        let adapter = WarpgateAdapter::new(Arc::new(FailingResolver));
        let err = adapter.list_rules(&integration()).await.unwrap_err();
        assert!(err.to_string().contains("vault unreachable"));
    }
}
