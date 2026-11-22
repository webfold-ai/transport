//! Mesh adapter trait — per-mesh implementation of `list / push_add / push_remove`.
//!
//! Adapters live in their own modules; this trait keeps the reconciler
//! mesh-agnostic. `NetBird` + Tailscale + Cloudflare Access + Warpgate
//! each implement it. The TS-side counterparts (msp-module/lib/vpn/*)
//! handle the per-deployment attach; this trait handles the *ACL push*
//! that follows attach.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use super::IntegrationRow;

/* ─── Types ───────────────────────────────────────────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MeshAclRule {
    pub user_id: Uuid,
    pub deployment_id: Uuid,
    pub deployment_name: String,
    /// `owner` / `admin` / `member` — informational; some meshes encode
    /// this as a tag (Tailscale `tag:tas-cloud-admin`).
    pub role: String,
}

#[derive(Debug, Clone, Default)]
pub struct MeshAclDiff {
    pub to_add: Vec<MeshAclRule>,
    pub to_remove: Vec<MeshAclRule>,
}

/* ─── Trait ───────────────────────────────────────────────────────────── */

#[async_trait]
pub trait MeshAclAdapter: Send + Sync {
    /// Returns every (user, deployment) rule the control plane currently
    /// has for this integration.
    async fn list_rules(&self, int: &IntegrationRow) -> Result<Vec<MeshAclRule>>;

    /// Push a new rule. Idempotent — must not error if the rule already exists.
    async fn push_add(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()>;

    /// Remove a rule. Idempotent — must not error if the rule is already gone.
    async fn push_remove(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()>;
}

/* ─── Registry ─────────────────────────────────────────────────────────── */

#[derive(Clone, Default)]
pub struct AdapterRegistry {
    inner: HashMap<String, Arc<dyn MeshAclAdapter>>,
}

impl AdapterRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, mode: impl Into<String>, adapter: Arc<dyn MeshAclAdapter>) {
        self.inner.insert(mode.into(), adapter);
    }

    #[must_use]
    pub fn get(&self, mode: &str) -> Option<&Arc<dyn MeshAclAdapter>> {
        self.inner.get(mode)
    }
}

/* ─── Stub implementation — returns empty ACL.
 *     Real impls land per-mesh in their own files. ─────────────────── */

pub struct StubAdapter;

#[async_trait]
impl MeshAclAdapter for StubAdapter {
    async fn list_rules(&self, _int: &IntegrationRow) -> Result<Vec<MeshAclRule>> {
        Ok(Vec::new())
    }
    async fn push_add(&self, _int: &IntegrationRow, _rule: &MeshAclRule) -> Result<()> {
        Err(anyhow::anyhow!(
            "MeshAclAdapter not implemented for this mode"
        ))
    }
    async fn push_remove(&self, _int: &IntegrationRow, _rule: &MeshAclRule) -> Result<()> {
        Err(anyhow::anyhow!(
            "MeshAclAdapter not implemented for this mode"
        ))
    }
}
