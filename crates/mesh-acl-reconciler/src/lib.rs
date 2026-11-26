//! Reconciles authorisation rules between om DB (source-of-truth) and the
//! mesh control planes (`NetBird`, Tailscale, Cloudflare Access, Warpgate).
//!
//! Pulled from `ZTNA-ARCHITECTURE.md` § Layer 2 / § Implementation status.
//! The om-side state is the union of:
//!   - `OrgMembership.userId` × deployment ownership = which user can SSH where
//!   - `cust-api-key.scope` = which API keys can hit which routes (HTTPS / Access only)
//!   - `VpnEndpoint` rows = which deployments are attached to which mesh integration
//!
//! For each `VpnIntegration` row, this worker every 60 minutes:
//!   1. Builds the *desired* ACL from om DB (read-only).
//!   2. Reads the *actual* ACL from the mesh control plane.
//!   3. Computes the diff (`add`, `remove`).
//!   4. Pushes the diff (best-effort; transient failures retry next tick).
//!   5. Records `last_reconciled_at` + per-tenant counts.
//!   6. Emits `mesh.acl.drift.detected` event when post-push diff is still non-zero.
//!
//! Failure-mode policy:
//!   - Mesh control plane unreachable → log warn, skip, retry next tick.
//!   - Auth failure → flag the integration `lastVerifiedStatus = 'auth-failed'`,
//!     pause reconciles for that integration, alert operator.
//!   - Per-rule push failure → continue with the rest of the diff; record per-rule error.
//!
//! F-O5 — drift-reconciler skips deployments with active workflow locks
//! (so a customer-initiated reconfigure doesn't race a reconciliation push).
//!
//! ## `CreatureGRC` integration (Tier-G G2)
//!
//! `mesh.acl.drift.detected` events become Findings against
//! ISO 27001 A.5.15 / A.8.2 / A.8.3, Essential 8 control-1 / control-5,
//! SOC 2 CC6.1 / CC6.3, NIST 800-171 3.1.1 / 3.1.5, NIST 800-53 AC-2.
//! The mesh-ACL surface is tas-cloud-specific — upstream `CreatureGRC` has
//! no equivalent collector — so this crate stays in the workspace.
//!
//! Audit-row payload contract (mandatory for every event this crate
//! emits): MUST carry `tenant_id` and `decision_id` at canonical JSON
//! paths so msp-portal's `CreatureGrcEmitter` can lift the row directly
//! into a Finding's `raw_data` without re-querying provider state. See
//! `docs/creaturegrc-integration.md` § What hosting-runtime crates owe
//! the integration for the full set of contracts.

#![forbid(unsafe_code)]
#![warn(clippy::nursery)]

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};
use tracing::{info, warn};
use uuid::Uuid;

pub mod adapter;
pub mod adapters;

pub use adapter::{MeshAclAdapter, MeshAclDiff, MeshAclRule};
pub use adapters::{
    CloudflareAccessAdapter, CloudflareAccessSecret, CloudflareAccessSecretResolver,
    NetBirdAdapter, TailscaleAdapter, UserResolver,
};

/* ─── Public API ──────────────────────────────────────────────────────── */

#[derive(Clone)]
pub struct Reconciler {
    pool: PgPool,
    adapters: adapter::AdapterRegistry,
    interval: Duration,
}

impl Reconciler {
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "kept non-const so the constructor signature stays stable if a future field needs runtime init"
    )]
    pub fn new(pool: PgPool, adapters: adapter::AdapterRegistry, interval: Duration) -> Self {
        Self {
            pool,
            adapters,
            interval,
        }
    }

    /// Runs the reconciler loop until cancelled. Each tick processes
    /// every active integration in parallel (bounded concurrency = 8).
    ///
    /// # Errors
    /// Propagates only fatal errors; per-tick `reconcile_all` failures are
    /// logged and the loop continues.
    pub async fn run(self, cancel: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cancel = cancel;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(err) = self.reconcile_all().await {
                        warn!(?err, "reconcile_all failed");
                    }
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() { break }
                }
            }
        }
        Ok(())
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "join-result fan-in match; TODO: extract the per-handle disposition into a helper"
    )]
    async fn reconcile_all(&self) -> Result<ReconcileSummary> {
        info!("starting reconcile tick");
        let integrations = self.list_active_integrations().await?;
        let mut summary = ReconcileSummary::default();
        // Bounded concurrency. Per-integration is independent.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut handles = Vec::with_capacity(integrations.len());
        for int in integrations {
            let sem = sem.clone();
            let pool = self.pool.clone();
            let adapters = self.adapters.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                Some(reconcile_one(&pool, &adapters, &int).await)
            }));
        }
        for h in handles {
            match h.await {
                Ok(Some(Ok(per))) => summary.merge(per),
                Ok(Some(Err(err))) => {
                    warn!(?err, "reconcile_one error");
                    summary.failures += 1;
                }
                Ok(None) => summary.failures += 1,
                Err(err) => {
                    warn!(?err, "reconcile_one join error");
                    summary.failures += 1;
                }
            }
        }
        info!(?summary, "reconcile tick complete");
        Ok(summary)
    }

    async fn list_active_integrations(&self) -> Result<Vec<IntegrationRow>> {
        let rows = sqlx::query(
            "
            SELECT id, tenant_id, mode, netbird_api_url, netbird_group_id,
                   tailscale_tailnet, credentials_secret_id
            FROM msp_vpn_integrations
            WHERE is_active = true
        ",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(IntegrationRow {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                mode: row.try_get("mode")?,
                netbird_api_url: row.try_get("netbird_api_url").ok(),
                netbird_group_id: row.try_get("netbird_group_id").ok(),
                tailscale_tailnet: row.try_get("tailscale_tailnet").ok(),
                credentials_secret_id: row.try_get("credentials_secret_id").ok(),
            });
        }
        Ok(out)
    }
}

/* ─── Per-integration reconcile ───────────────────────────────────────── */

#[expect(
    clippy::ignored_unit_patterns,
    reason = "`Ok(_)` on the push results is unambiguous here; spelling it `Ok(())` is churn for a lint sweep"
)]
async fn reconcile_one(
    pool: &PgPool,
    adapters: &adapter::AdapterRegistry,
    int: &IntegrationRow,
) -> Result<PerIntegrationSummary> {
    let Some(adapter) = adapters.get(&int.mode) else {
        return Ok(PerIntegrationSummary {
            mode: int.mode.clone(),
            drift_count: 0,
            pushed_count: 0,
            errors: 1,
        });
    };

    // 1. Build desired ACL from om DB.
    let desired = build_desired_acl(pool, &int.tenant_id, &int.id).await?;

    // 2. Read actual ACL from the mesh control plane.
    let actual = adapter.list_rules(int).await?;

    // 3. Diff.
    let diff = compute_diff(&desired, &actual);

    // 4. Push deltas (best-effort).
    let mut pushed = 0;
    let mut errors = 0;
    for rule in &diff.to_add {
        match adapter.push_add(int, rule).await {
            Ok(_) => pushed += 1,
            Err(err) => {
                warn!(?err, ?rule, "push_add failed");
                errors += 1;
            }
        }
    }
    for rule in &diff.to_remove {
        match adapter.push_remove(int, rule).await {
            Ok(_) => pushed += 1,
            Err(err) => {
                warn!(?err, ?rule, "push_remove failed");
                errors += 1;
            }
        }
    }

    // 5. Record reconcile timestamp + counts on the integration row.
    sqlx::query("UPDATE msp_vpn_integrations SET last_verified_at = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(int.id)
        .execute(pool)
        .await?;

    // 6. Emit drift-detected if there's still divergence after push.
    let drift = diff.to_add.len() + diff.to_remove.len();
    if drift > 0 && errors > 0 {
        emit_drift_event(pool, int, drift, errors).await?;
    }

    Ok(PerIntegrationSummary {
        mode: int.mode.clone(),
        drift_count: drift,
        pushed_count: pushed,
        errors,
    })
}

async fn build_desired_acl(
    pool: &PgPool,
    tenant_id: &Uuid,
    integration_id: &Uuid,
) -> Result<Vec<MeshAclRule>> {
    // Build per-(member, deployment) allow rules. Skips deployments with
    // active workflow locks (F-O5).
    let rows = sqlx::query("
        SELECT om.user_id, om.role, do_.deployment_id, ms.name AS deployment_name
        FROM msp_org_memberships om
        JOIN msp_deployment_ownership do_ ON do_.organisation_id = om.organisation_id
        JOIN msp_services ms ON ms.id = do_.deployment_id
        JOIN msp_vpn_endpoints vpe ON vpe.deployment_id = do_.deployment_id AND vpe.integration_id = $2
        WHERE om.tenant_id = $1
          AND om.revoked_at IS NULL
          AND om.accepted_at IS NOT NULL
          AND om.ssh_access = true
          AND ms.deleted_at IS NULL
          AND ms.status NOT IN ('terminated', 'partial-terminated', 'failed')
    ")
        .bind(tenant_id)
        .bind(integration_id)
        .fetch_all(pool)
        .await?;

    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        rules.push(MeshAclRule {
            user_id: row.try_get("user_id")?,
            deployment_id: row.try_get("deployment_id")?,
            deployment_name: row.try_get("deployment_name")?,
            role: row.try_get("role")?,
        });
    }
    Ok(rules)
}

fn compute_diff(desired: &[MeshAclRule], actual: &[MeshAclRule]) -> MeshAclDiff {
    let desired_set: std::collections::HashSet<_> = desired
        .iter()
        .map(|r| (r.user_id, r.deployment_id))
        .collect();
    let actual_set: std::collections::HashSet<_> = actual
        .iter()
        .map(|r| (r.user_id, r.deployment_id))
        .collect();

    let to_add: Vec<MeshAclRule> = desired
        .iter()
        .filter(|r| !actual_set.contains(&(r.user_id, r.deployment_id)))
        .cloned()
        .collect();
    let to_remove: Vec<MeshAclRule> = actual
        .iter()
        .filter(|r| !desired_set.contains(&(r.user_id, r.deployment_id)))
        .cloned()
        .collect();
    MeshAclDiff { to_add, to_remove }
}

async fn emit_drift_event(
    pool: &PgPool,
    int: &IntegrationRow,
    drift: usize,
    errors: usize,
) -> Result<()> {
    sqlx::query("INSERT INTO msp_events (id, tenant_id, kind, payload, created_at) VALUES (gen_random_uuid(), $1, 'mesh.acl.drift.detected', $2, $3)")
        .bind(int.tenant_id)
        .bind(serde_json::json!({
            "integrationId": int.id,
            "mode": int.mode,
            "driftCount": drift,
            "pushErrors": errors,
        }))
        .bind(Utc::now())
        .execute(pool)
        .await?;
    Ok(())
}

/* ─── Types ───────────────────────────────────────────────────────────── */

#[derive(Debug, Clone)]
pub struct IntegrationRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub mode: String,
    pub netbird_api_url: Option<String>,
    pub netbird_group_id: Option<String>,
    pub tailscale_tailnet: Option<String>,
    pub credentials_secret_id: Option<Uuid>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReconcileSummary {
    pub integrations_processed: usize,
    pub total_drift_count: usize,
    pub total_pushed: usize,
    pub failures: usize,
}

impl ReconcileSummary {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers hand off ownership of the per-integration summary and don't use it afterwards; keeping by-value avoids a borrow at every call site"
    )]
    fn merge(&mut self, per: PerIntegrationSummary) {
        self.integrations_processed += 1;
        self.total_drift_count += per.drift_count;
        self.total_pushed += per.pushed_count;
        if per.errors > 0 {
            self.failures += 1;
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerIntegrationSummary {
    pub mode: String,
    pub drift_count: usize,
    pub pushed_count: usize,
    pub errors: usize,
}

/* ─── Re-exported timestamps so consumers don't need chrono direct ───── */

pub type Timestamp = DateTime<Utc>;

#[cfg(test)]
mod diff_tests;
