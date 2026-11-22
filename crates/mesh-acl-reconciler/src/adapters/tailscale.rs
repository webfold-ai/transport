//! Tailscale ACL adapter.
//!
//! Tailscale's ACL is a *single JSON document* per tailnet, pushed via
//! `PUT /api/v2/tailnet/{tailnet}/acl`. Unlike `NetBird`, there's no
//! per-rule API — we read the whole doc, splice in the (user, device)
//! tag pair the reconciler wants, and push back.
//!
//! # Role after the Warpgate ADR (2026-05-06)
//!
//! Tailscale's job here is **overlay membership only** — same role as
//! `NetBird`, just with a different control plane the customer chose.
//! Per-service operator ACLs (operator alice → customer-acme's Postgres)
//! move to the future Warpgate adapter when
//! `Tasmanian-Cloud/warpgate-deploy` reaches Phase 1.
//!
//! Concretely: keep emitting `tag:tas-cloud-dep-*` and `tag:tas-cloud-user-*`
//! tags + the user-to-deployment grants that describe *the mesh*. Stop using
//! the Tailscale ACL doc to encode operator-to-managed-service access — that
//! becomes Warpgate-side.
//!
//! See `docs/decisions/2026-05-06-warpgate-as-operator-bastion.md`
//! (umbrella) and the role-split table in `adapters/mod.rs`.
//!
//! Convention: we tag each tas-cloud-managed device with
//! `tag:tas-cloud-dep-<deploymentId>` and each authorised user with
//! `tag:tas-cloud-user-<userId>`. ACL grants are encoded as a list of
//! `{src: tag:tas-cloud-user-XXX, dst: tag:tas-cloud-dep-YYY:22,8080,8443}`.
//!
//! Because the ACL is a single doc, concurrent reconciles last-writer-wins.
//! That's acceptable: we re-converge on the next tick. Tailscale's
//! version etag (`If-Match`) lets us refuse stale writes; we prefer
//! last-writer-wins over hard fail since the reconciler is idempotent.

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::adapter::{MeshAclAdapter, MeshAclRule};
use crate::IntegrationRow;

const TAILSCALE_API: &str = "https://api.tailscale.com/api/v2";
const TIMEOUT: Duration = Duration::from_secs(8);

/// Resolves the Tailscale auth-key for a given integration. Production
/// wires this to `OpenBao` (per
/// `docs/decisions/2026-05-06-m2m-internal-auth-coverage.md`, umbrella);
/// tests inject a static closure.
pub trait TailscaleTokenResolver: Send + Sync {
    fn resolve_token<'a>(
        &'a self,
        integration: &'a IntegrationRow,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;
}

pub struct TailscaleAdapter {
    client: Client,
    resolver: std::sync::Arc<dyn TailscaleTokenResolver>,
}

impl TailscaleAdapter {
    /// # Errors
    /// Returns an error if the HTTPS-only reqwest client cannot be built.
    pub fn new(resolver: std::sync::Arc<dyn TailscaleTokenResolver>) -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .timeout(TIMEOUT)
            .build()
            .context("reqwest build")?;
        Ok(Self { client, resolver })
    }

    fn tailnet(int: &IntegrationRow) -> Result<&str> {
        int.tailscale_tailnet
            .as_deref()
            .filter(|s| !s.is_empty())
            .context("integration.tailscale_tailnet missing")
    }

    async fn auth_headers(&self, int: &IntegrationRow) -> Result<HeaderMap> {
        let token = self.resolver.resolve_token(int).await?;
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/hujson"));
        Ok(h)
    }

    /// Fetches the current ACL doc + its etag.
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the explicit closure mirrors the surrounding chain's style; behaviour-neutral"
    )]
    async fn fetch_acl(&self, int: &IntegrationRow) -> Result<(TailscaleAcl, Option<String>)> {
        let tailnet = Self::tailnet(int)?;
        let resp = self
            .client
            .get(format!(
                "{TAILSCALE_API}/tailnet/{}/acl",
                urlencoding::encode(tailnet)
            ))
            .headers(self.auth_headers(int).await?)
            .send()
            .await?
            .error_for_status()?;
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
        let body: TailscaleAcl = resp.json().await?;
        Ok((body, etag))
    }
}

#[async_trait]
impl MeshAclAdapter for TailscaleAdapter {
    #[expect(
        clippy::explicit_iter_loop,
        reason = "`.iter()` is explicit about the borrow here; behaviour-neutral"
    )]
    async fn list_rules(&self, int: &IntegrationRow) -> Result<Vec<MeshAclRule>> {
        let (acl, _etag) = self.fetch_acl(int).await?;
        let mut rules = Vec::new();
        for entry in acl.acls.iter() {
            // Convention: src = "tag:tas-cloud-user-<userId>"; dst = "tag:tas-cloud-dep-<depId>:..."
            for src in &entry.src {
                if let Some(user_id) = parse_user_tag(src) {
                    for dst in &entry.dst {
                        if let Some((dep_id, _)) = parse_dep_target(dst) {
                            rules.push(MeshAclRule {
                                user_id,
                                deployment_id: dep_id,
                                deployment_name: dep_id.to_string(),
                                role: "member".to_string(), // Tailscale doesn't carry our role
                            });
                        }
                    }
                }
            }
        }
        Ok(rules)
    }

    async fn push_add(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let tailnet = Self::tailnet(int)?;
        let (mut acl, etag) = self.fetch_acl(int).await?;

        let user_tag = format!("tag:tas-cloud-user-{}", rule.user_id);
        let dep_tag = format!("tag:tas-cloud-dep-{}:22,8080,8443", rule.deployment_id);

        let already = acl
            .acls
            .iter()
            .any(|a| a.src.iter().any(|s| s == &user_tag) && a.dst.iter().any(|d| d == &dep_tag));
        if already {
            return Ok(()); // idempotent
        }

        acl.acls.push(TailscaleAclEntry {
            action: "accept".to_string(),
            src: vec![user_tag],
            dst: vec![dep_tag],
        });

        self.put_acl(int, tailnet, &acl, etag.as_deref()).await
    }

    #[expect(
        clippy::map_unwrap_or,
        reason = "the map(...).unwrap_or(false) chain reads clearly inside the retain predicate; behaviour-neutral idiom"
    )]
    async fn push_remove(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let tailnet = Self::tailnet(int)?;
        let (mut acl, etag) = self.fetch_acl(int).await?;

        let user_tag = format!("tag:tas-cloud-user-{}", rule.user_id);
        let dep_id = rule.deployment_id;

        let before = acl.acls.len();
        acl.acls.retain(|a| {
            let matches_pair = a.src.iter().any(|s| s == &user_tag)
                && a.dst.iter().any(|d| {
                    parse_dep_target(d)
                        .map(|(d, _)| d == dep_id)
                        .unwrap_or(false)
                });
            !matches_pair
        });
        if acl.acls.len() == before {
            return Ok(()); // already gone — idempotent
        }
        self.put_acl(int, tailnet, &acl, etag.as_deref()).await
    }
}

impl TailscaleAdapter {
    async fn put_acl(
        &self,
        int: &IntegrationRow,
        tailnet: &str,
        acl: &TailscaleAcl,
        etag: Option<&str>,
    ) -> Result<()> {
        let mut headers = self.auth_headers(int).await?;
        if let Some(tag) = etag {
            // Tailscale supports `If-Match` for optimistic concurrency.
            // If we lose the race, the reconciler simply re-runs next tick.
            if let Ok(v) = HeaderValue::from_str(tag) {
                headers.insert(IF_MATCH, v);
            }
        }
        let resp = self
            .client
            .put(format!(
                "{TAILSCALE_API}/tailnet/{}/acl",
                urlencoding::encode(tailnet)
            ))
            .headers(headers)
            .json(acl)
            .send()
            .await?;

        if resp.status() == 412 {
            // Stale etag — accept the loss; next reconcile picks up.
            return Ok(());
        }
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "tailscale ACL put returned {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

/* ─── Tailscale ACL doc shape (the bits we touch) ─────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TailscaleAcl {
    #[serde(rename = "acls", default)]
    acls: Vec<TailscaleAclEntry>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TailscaleAclEntry {
    action: String,
    src: Vec<String>,
    dst: Vec<String>,
}

/* ─── Tag parsers ─────────────────────────────────────────────────────── */

fn parse_user_tag(s: &str) -> Option<uuid::Uuid> {
    s.strip_prefix("tag:tas-cloud-user-")
        .and_then(|raw| uuid::Uuid::parse_str(raw).ok())
}

fn parse_dep_target(s: &str) -> Option<(uuid::Uuid, &str)> {
    // Form: `tag:tas-cloud-dep-<uuid>:<ports>`
    let stripped = s.strip_prefix("tag:tas-cloud-dep-")?;
    let (id_part, ports) = stripped.split_once(':').unwrap_or((stripped, ""));
    Some((uuid::Uuid::parse_str(id_part).ok()?, ports))
}
