//! `NetBird` ACL adapter — works for both `tas-cloud-managed-netbird` and
//! `customer-netbird` modes.
//!
//! Difference is the API URL + token source:
//! managed = our ops token from `OpenBao`; customer = the tenant's M2M
//! token (also `OpenBao`-resolved per
//! `docs/decisions/2026-05-06-m2m-internal-auth-coverage.md` umbrella —
//! the resolver bridges `IntegrationRow::credentials_secret_id` to the
//! tenant's secret namespace).
//!
//! # Role after the Warpgate ADR (2026-05-06)
//!
//! `NetBird`'s job here is **overlay membership only** — who is *on* the
//! tas-cloud-managed (or customer-managed) mesh. Per-service operator
//! ACLs (e.g. "operator alice can `psql` to customer-acme's Postgres
//! primary") move to the future Warpgate adapter when
//! `Tasmanian-Cloud/warpgate-deploy` reaches Phase 1.
//!
//! Concretely: keep emitting (peer, group) memberships and group-to-group
//! rules that describe *the mesh*. Stop using `NetBird` ACL rules to encode
//! "operator X can talk to managed-service Y" — those become Warpgate-side
//! per-target ACLs.
//!
//! See `docs/decisions/2026-05-06-warpgate-as-operator-bastion.md`
//! (umbrella) and the role-split table in `adapters/mod.rs`.
//!
//! `NetBird` ACL model:
//!   - **Groups** = sets of peers (we use one group per (tenant, deployment)
//!     plus per-user groups).
//!   - **ACL rules** = (source-group, destination-group, port, protocol).
//!
//! For msp-portal's purposes we encode every (user, deployment) pair as an
//! ACL rule from the user's group to the deployment's group on TCP/22 +
//! TCP/management-ports. The reconciler computes the desired set, queries
//! the live set, and pushes the diff.
//!
//! Outbound via reqwest with rustls (F-C1 — no openssl). Per-request
//! timeout 5s; retries handled at the reconciler layer (not here).

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::adapter::{MeshAclAdapter, MeshAclRule};
use crate::IntegrationRow;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves the bearer token for a given integration. Production wires
/// this to the Vault client + tenant-scope check; tests use a static
/// closure.
pub trait NetBirdTokenResolver: Send + Sync {
    fn resolve_token<'a>(
        &'a self,
        integration: &'a IntegrationRow,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;
}

pub struct NetBirdAdapter {
    client: Client,
    resolver: std::sync::Arc<dyn NetBirdTokenResolver>,
}

impl NetBirdAdapter {
    /// # Errors
    /// Returns an error if the HTTPS-only reqwest client cannot be built.
    pub fn new(resolver: std::sync::Arc<dyn NetBirdTokenResolver>) -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .timeout(TIMEOUT)
            .build()
            .context("reqwest build")?;
        Ok(Self { client, resolver })
    }

    fn api_base(int: &IntegrationRow) -> Result<&str> {
        int.netbird_api_url
            .as_deref()
            .filter(|u| u.starts_with("https://"))
            .context("integration.netbird_api_url missing or not https")
    }

    async fn auth_headers(&self, int: &IntegrationRow) -> Result<HeaderMap> {
        let token = self.resolver.resolve_token(int).await?;
        // managed-netbird = `Token <ops>`, customer-netbird = `Bearer <m2m>`.
        let scheme = if int.mode == "tas-cloud-managed-netbird" {
            "Token"
        } else {
            "Bearer"
        };
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("{scheme} {token}"))?,
        );
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(h)
    }
}

#[async_trait]
impl MeshAclAdapter for NetBirdAdapter {
    async fn list_rules(&self, int: &IntegrationRow) -> Result<Vec<MeshAclRule>> {
        let base = Self::api_base(int)?;
        let headers = self.auth_headers(int).await?;

        // 1. Fetch all peers. NetBird returns peer records with a `name` we
        //    encode as `tas-cloud:{tenantSlug}:{deploymentName}` at attach time.
        let peers: Vec<NetBirdPeer> = self
            .client
            .get(format!("{base}/peers"))
            .headers(headers.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // 2. Fetch ACL rules. NetBird models ACLs as policies → rules.
        let policies: Vec<NetBirdPolicy> = self
            .client
            .get(format!("{base}/policies"))
            .headers(headers)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // 3. Decode our convention: a policy whose `name` starts with
        //    `tas-cloud-acl:` carries (userId, deploymentId, role) in its
        //    `description` field as a JSON-encoded blob.
        let mut rules = Vec::with_capacity(policies.len());
        for p in policies
            .iter()
            .filter(|p| p.name.starts_with("tas-cloud-acl:"))
        {
            if let Some(metadata) = p
                .description
                .as_deref()
                .and_then(|d| serde_json::from_str::<RuleMetadata>(d).ok())
            {
                // Find the matching peer by deployment_id label so we get
                // the deployment-name surface.
                #[expect(
                    clippy::map_unwrap_or,
                    reason = "the map/unwrap_or_else chain reads more clearly here than map_or_else; behaviour-neutral idiom"
                )]
                let deployment_name = peers
                    .iter()
                    .find(|peer| peer.name.ends_with(&format!(":{}", metadata.deployment_id)))
                    .map(|peer| peer.name.clone())
                    .unwrap_or_else(|| metadata.deployment_id.to_string());

                rules.push(MeshAclRule {
                    user_id: metadata.user_id,
                    deployment_id: metadata.deployment_id,
                    deployment_name,
                    role: metadata.role,
                });
            }
        }
        Ok(rules)
    }

    async fn push_add(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let base = Self::api_base(int)?;
        let headers = self.auth_headers(int).await?;

        // 1. Ensure the user-side group exists.
        let user_group_name = format!("tas-cloud-user:{}", rule.user_id);
        let user_group_id = upsert_group(&self.client, base, &headers, &user_group_name).await?;

        // 2. Ensure the deployment-side group exists.
        let deployment_group_name = format!("tas-cloud-dep:{}", rule.deployment_id);
        let deployment_group_id =
            upsert_group(&self.client, base, &headers, &deployment_group_name).await?;

        // 3. Create the policy with our convention metadata.
        let policy_name = format!("tas-cloud-acl:{}:{}", rule.user_id, rule.deployment_id);
        let metadata = RuleMetadata {
            user_id: rule.user_id,
            deployment_id: rule.deployment_id,
            role: rule.role.clone(),
        };
        let policy_body = serde_json::json!({
            "name": policy_name,
            "description": serde_json::to_string(&metadata).unwrap_or_default(),
            "enabled": true,
            "rules": [{
                "name": format!("ssh+mgmt"),
                "enabled": true,
                "action": "accept",
                "bidirectional": false,
                "protocol": "tcp",
                "ports": ["22", "8080", "8443"],
                "sources": [user_group_id],
                "destinations": [deployment_group_id],
            }],
        });

        let resp = self
            .client
            .post(format!("{base}/policies"))
            .headers(headers)
            .json(&policy_body)
            .send()
            .await?;
        // 409 = already exists (our convention has unique-per-name); treat as idempotent success.
        if resp.status() == 409 || resp.status().is_success() {
            return Ok(());
        }
        Err(anyhow::anyhow!(
            "netbird policy create returned {}",
            resp.status()
        ))
    }

    async fn push_remove(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let base = Self::api_base(int)?;
        let headers = self.auth_headers(int).await?;
        let policy_name = format!("tas-cloud-acl:{}:{}", rule.user_id, rule.deployment_id);

        // Look up by name → delete by id. NetBird's API requires the id;
        // there's no DELETE-by-name shortcut.
        let policies: Vec<NetBirdPolicy> = self
            .client
            .get(format!("{base}/policies"))
            .headers(headers.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if let Some(target) = policies.iter().find(|p| p.name == policy_name) {
            let resp = self
                .client
                .delete(format!("{base}/policies/{}", target.id))
                .headers(headers)
                .send()
                .await?;
            if !resp.status().is_success() && resp.status() != 404 {
                return Err(anyhow::anyhow!(
                    "netbird policy delete returned {}",
                    resp.status()
                ));
            }
        }
        Ok(())
    }
}

async fn upsert_group(
    client: &Client,
    base: &str,
    headers: &HeaderMap,
    name: &str,
) -> Result<String> {
    // Look for an existing group by name first.
    let groups: Vec<NetBirdGroup> = client
        .get(format!("{base}/groups"))
        .headers(headers.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(g) = groups.iter().find(|g| g.name == name) {
        return Ok(g.id.clone());
    }

    // Create.
    let resp: NetBirdGroup = client
        .post(format!("{base}/groups"))
        .headers(headers.clone())
        .json(&serde_json::json!({ "name": name, "peers": [] }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp.id)
}

/* ─── NetBird API DTOs (only the fields we care about) ───────────────── */

#[derive(Debug, Deserialize)]
struct NetBirdPeer {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct NetBirdGroup {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct NetBirdPolicy {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleMetadata {
    user_id: Uuid,
    deployment_id: Uuid,
    role: String,
}
