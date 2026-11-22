//! Cloudflare Access ACL adapter.
//!
//! Cloudflare Access protects per-deployment HTTPS endpoints (e.g.
//! `nextcloud-prod.example.com`). Each deployment maps to one Access
//! Application; the App carries a single tas-cloud-managed Policy whose
//! `include` rule lists the authorized emails.
//!
//! # Role after the Warpgate ADR (2026-05-06)
//!
//! Cloudflare Access's role here is **customer-facing ZTNA** — gating
//! customer access to *customer-facing* HTTPS apps (the customer's own
//! Nextcloud, Immich, Ghost, etc., with their own end-users). It is
//! **not** an operator-bastion path; operators reach managed services
//! through Warpgate (see ADR), not through CF Access.
//!
//! This adapter is therefore **unchanged** by the Warpgate ADR. Keep the
//! per-App email allow list aligned with org membership × deployment
//! ownership; the bastion question lives elsewhere.
//!
//! See `docs/decisions/2026-05-06-warpgate-as-operator-bastion.md`
//! (umbrella) and the role-split table in `adapters/mod.rs`.
//!
//! Convention (set by the TS-side `CloudflareAdapter.configureAccessApp`):
//!   - App `name`     = `tas-cloud:<deploymentId>` — drives reverse lookup
//!   - Policy `name`  = `tas-cloud-allowed`
//!   - Policy include = `[{ email: { email: "alice@example.com" } }, ...]`
//!
//! The reconciler-side responsibility is to keep the Policy's email set
//! aligned with the org membership × deployment ownership matrix in om.
//! Per-App pushes happen at deploy-time; this adapter only re-syncs the
//! email list for org-membership churn (departures, role changes).
//!
//! The `MeshAclRule` schema is uuid-keyed (`user_id` × `deployment_id`) for
//! consistency with NetBird/Tailscale. Bridging to CF Access's email-keyed
//! model is this adapter's job: an injected `UserResolver` translates
//! email ↔ `user_id`.
//!
//! Outbound via reqwest with rustls (F-C1 — no openssl). Per-request
//! timeout 8s; retries handled at the reconciler layer.

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

use crate::adapter::{MeshAclAdapter, MeshAclRule};
use crate::IntegrationRow;

const CF_API: &str = "https://api.cloudflare.com/client/v4";
const TIMEOUT: Duration = Duration::from_secs(8);
const APP_NAME_PREFIX: &str = "tas-cloud:";
const POLICY_NAME: &str = "tas-cloud-allowed";

/* ─── Resolver traits ─────────────────────────────────────────────────── */

#[derive(Debug, Clone)]
pub struct CloudflareAccessSecret {
    /// CF account id (32-hex). The bearer token must have
    /// `Access: Apps and Policies — Edit` scope on this account.
    pub account_id: String,
    /// `Authorization: Bearer <token>` value.
    pub bearer_token: String,
}

/// Resolves the CF `account_id` + bearer token for an integration.
///
/// Production wires this to `OpenBao` (per
/// `docs/decisions/2026-05-06-m2m-internal-auth-coverage.md`, umbrella) +
/// the per-tenant `CloudflareIntegration` row; tests inject a static
/// closure.
pub trait CloudflareAccessSecretResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        integration: &'a IntegrationRow,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<CloudflareAccessSecret>> + Send + 'a>>;
}

/// Bridges between om's user-id keyed model and CF Access's email-keyed model.
/// Production wires this to a `SELECT email FROM users WHERE id = $1` query
/// (and its inverse). Tests use a static `HashMap`-backed impl.
#[async_trait]
pub trait UserResolver: Send + Sync {
    /// Returns the email for a user. Errors if the user is unknown — pushes
    /// for unresolvable users will surface as per-rule errors at the
    /// reconciler.
    async fn email_for(&self, tenant_id: Uuid, user_id: Uuid) -> Result<String>;

    /// Returns the user-id for an email. `Ok(None)` for emails that don't
    /// belong to any user in this tenant — those are CF-side drift
    /// (emails added manually outside om's control); the reconciler will
    /// push_remove them on the next tick.
    async fn user_for(&self, tenant_id: Uuid, email: &str) -> Result<Option<Uuid>>;
}

/* ─── Adapter ─────────────────────────────────────────────────────────── */

pub struct CloudflareAccessAdapter {
    client: Client,
    secret_resolver: Arc<dyn CloudflareAccessSecretResolver>,
    user_resolver: Arc<dyn UserResolver>,
}

impl CloudflareAccessAdapter {
    /// # Errors
    /// Returns an error if the HTTPS-only reqwest client cannot be built.
    pub fn new(
        secret_resolver: Arc<dyn CloudflareAccessSecretResolver>,
        user_resolver: Arc<dyn UserResolver>,
    ) -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .timeout(TIMEOUT)
            .build()
            .context("reqwest build")?;
        Ok(Self {
            client,
            secret_resolver,
            user_resolver,
        })
    }

    #[expect(
        clippy::unused_async,
        reason = "header assembly is sync today but kept async to match the call sites that .await it alongside genuinely-async resolver calls"
    )]
    async fn auth_headers(&self, secret: &CloudflareAccessSecret) -> Result<HeaderMap> {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", secret.bearer_token))?,
        );
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(h)
    }

    /// Lists every tas-cloud-managed Access App in the account. Returns
    /// `(app_id, deployment_id, app_name)` triples for any app whose name
    /// matches `tas-cloud:<uuid>`.
    async fn list_managed_apps(
        &self,
        secret: &CloudflareAccessSecret,
        headers: &HeaderMap,
    ) -> Result<Vec<ManagedApp>> {
        // CF lists up to 50 per page by default; bump to 1000 (CF's max).
        let url = format!(
            "{CF_API}/accounts/{}/access/apps?per_page=1000",
            secret.account_id,
        );
        let resp: CfEnvelope<Vec<CfApp>> = self
            .client
            .get(&url)
            .headers(headers.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(anyhow::anyhow!("cf list apps failed: {:?}", resp.errors));
        }
        let mut out = Vec::new();
        for a in resp.result {
            if let Some(rest) = a.name.strip_prefix(APP_NAME_PREFIX) {
                if let Ok(deployment_id) = Uuid::parse_str(rest) {
                    out.push(ManagedApp {
                        app_id: a.id,
                        deployment_id,
                        name: a.name,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Fetches the `tas-cloud-allowed` policy for an app, if present.
    async fn fetch_policy(
        &self,
        secret: &CloudflareAccessSecret,
        headers: &HeaderMap,
        app_id: &str,
    ) -> Result<Option<CfPolicy>> {
        let url = format!(
            "{CF_API}/accounts/{}/access/apps/{}/policies",
            secret.account_id, app_id,
        );
        let resp: CfEnvelope<Vec<CfPolicy>> = self
            .client
            .get(&url)
            .headers(headers.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(anyhow::anyhow!(
                "cf list policies failed: {:?}",
                resp.errors
            ));
        }
        Ok(resp.result.into_iter().find(|p| p.name == POLICY_NAME))
    }

    async fn put_policy(
        &self,
        secret: &CloudflareAccessSecret,
        headers: &HeaderMap,
        app_id: &str,
        policy: &CfPolicy,
    ) -> Result<()> {
        let url = format!(
            "{CF_API}/accounts/{}/access/apps/{}/policies/{}",
            secret.account_id, app_id, policy.id,
        );
        let body = serde_json::json!({
            "name": policy.name,
            "decision": policy.decision,
            "include": policy.include,
            "exclude": policy.exclude,
            "require": policy.require,
        });
        let resp = self
            .client
            .put(&url)
            .headers(headers.clone())
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("cf put policy returned {}", resp.status()));
        }
        Ok(())
    }
}

#[async_trait]
impl MeshAclAdapter for CloudflareAccessAdapter {
    async fn list_rules(&self, int: &IntegrationRow) -> Result<Vec<MeshAclRule>> {
        let secret = self.secret_resolver.resolve(int).await?;
        let headers = self.auth_headers(&secret).await?;
        let apps = self.list_managed_apps(&secret, &headers).await?;

        let mut rules = Vec::new();
        for app in apps {
            let Some(policy) = self.fetch_policy(&secret, &headers, &app.app_id).await? else {
                continue;
            };
            for rule in &policy.include {
                let Some(email) = rule.email_address() else {
                    continue;
                };
                match self.user_resolver.user_for(int.tenant_id, email).await? {
                    Some(user_id) => {
                        rules.push(MeshAclRule {
                            user_id,
                            deployment_id: app.deployment_id,
                            deployment_name: app.name.clone(),
                            role: "member".to_string(),
                        });
                    }
                    None => {
                        // CF-side drift: email not in our user table.
                        // Surfaced via the next push_remove on this tick.
                        warn!(email, deployment_id = %app.deployment_id, "cf access: unknown email in policy");
                    }
                }
            }
        }
        Ok(rules)
    }

    async fn push_add(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let secret = self.secret_resolver.resolve(int).await?;
        let headers = self.auth_headers(&secret).await?;
        let email = self
            .user_resolver
            .email_for(int.tenant_id, rule.user_id)
            .await?;

        let app_id = self
            .find_app_id(&secret, &headers, rule.deployment_id)
            .await?
            .with_context(|| format!("no cf access app for deployment {}", rule.deployment_id))?;

        let mut policy = self
            .fetch_policy(&secret, &headers, &app_id)
            .await?
            .with_context(|| format!("policy {POLICY_NAME} missing on app {app_id}"))?;

        if policy
            .include
            .iter()
            .any(|r| r.email_address() == Some(&email))
        {
            return Ok(()); // idempotent
        }
        policy.include.push(CfPolicyRule::email(email));
        self.put_policy(&secret, &headers, &app_id, &policy).await
    }

    async fn push_remove(&self, int: &IntegrationRow, rule: &MeshAclRule) -> Result<()> {
        let secret = self.secret_resolver.resolve(int).await?;
        let headers = self.auth_headers(&secret).await?;
        let email = self
            .user_resolver
            .email_for(int.tenant_id, rule.user_id)
            .await?;

        let Some(app_id) = self
            .find_app_id(&secret, &headers, rule.deployment_id)
            .await?
        else {
            return Ok(()); // app already gone — idempotent
        };
        let Some(mut policy) = self.fetch_policy(&secret, &headers, &app_id).await? else {
            return Ok(()); // policy already gone — idempotent
        };

        let before = policy.include.len();
        policy.include.retain(|r| r.email_address() != Some(&email));
        if policy.include.len() == before {
            return Ok(()); // already absent — idempotent
        }
        self.put_policy(&secret, &headers, &app_id, &policy).await
    }
}

impl CloudflareAccessAdapter {
    async fn find_app_id(
        &self,
        secret: &CloudflareAccessSecret,
        headers: &HeaderMap,
        deployment_id: Uuid,
    ) -> Result<Option<String>> {
        let apps = self.list_managed_apps(secret, headers).await?;
        Ok(apps
            .into_iter()
            .find(|a| a.deployment_id == deployment_id)
            .map(|a| a.app_id))
    }
}

/* ─── Internal types ──────────────────────────────────────────────────── */

#[derive(Debug, Clone)]
struct ManagedApp {
    app_id: String,
    deployment_id: Uuid,
    name: String,
}

/* ─── CF API DTOs (only the fields we touch) ──────────────────────────── */

#[derive(Debug, Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    result: T,
}

#[derive(Debug, Deserialize)]
struct CfApp {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CfPolicy {
    id: String,
    name: String,
    decision: String, // "allow" | "deny" | "non_identity" | "bypass"
    #[serde(default)]
    include: Vec<CfPolicyRule>,
    #[serde(default)]
    exclude: Vec<CfPolicyRule>,
    #[serde(default)]
    require: Vec<CfPolicyRule>,
}

/// CF policy rule. We use the `email` shape for our managed include list,
/// but the type stays loose so we round-trip non-managed rules unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CfPolicyRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<EmailRule>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailRule {
    email: String,
}

impl CfPolicyRule {
    fn email(addr: String) -> Self {
        Self {
            email: Some(EmailRule { email: addr }),
            other: serde_json::Map::new(),
        }
    }
    fn email_address(&self) -> Option<&str> {
        self.email.as_ref().map(|e| e.email.as_str())
    }
}

/* ─── Tests ───────────────────────────────────────────────────────────── */

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: Result-unwrap assertions on deterministic fixtures"
    )]
    use super::*;
    use std::collections::HashMap;

    struct StaticResolver {
        map_email_for: HashMap<Uuid, String>,
        map_user_for: HashMap<String, Uuid>,
    }

    #[async_trait]
    impl UserResolver for StaticResolver {
        async fn email_for(&self, _tenant: Uuid, user_id: Uuid) -> Result<String> {
            self.map_email_for
                .get(&user_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("user not found: {user_id}"))
        }
        async fn user_for(&self, _tenant: Uuid, email: &str) -> Result<Option<Uuid>> {
            Ok(self.map_user_for.get(email).copied())
        }
    }

    #[test]
    fn email_rule_round_trips_through_serde() {
        let rule = CfPolicyRule::email("alice@example.com".to_string());
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("alice@example.com"));
        let back: CfPolicyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.email_address(), Some("alice@example.com"));
    }

    #[test]
    fn non_managed_rule_round_trips_through_other_field() {
        // CF policies can carry other rule kinds (everyone, ip, group, …);
        // round-tripping must preserve them so PUT doesn't drop unrelated rules.
        let json = r#"{"everyone":{}}"#;
        let rule: CfPolicyRule = serde_json::from_str(json).unwrap();
        assert!(rule.email_address().is_none());
        let back = serde_json::to_string(&rule).unwrap();
        assert!(back.contains("everyone"));
    }

    #[tokio::test]
    async fn user_resolver_static_impl() {
        let user = Uuid::new_v4();
        let r = StaticResolver {
            map_email_for: HashMap::from([(user, "bob@example.com".to_string())]),
            map_user_for: HashMap::from([("bob@example.com".to_string(), user)]),
        };
        let tenant = Uuid::new_v4();
        assert_eq!(r.email_for(tenant, user).await.unwrap(), "bob@example.com");
        assert_eq!(
            r.user_for(tenant, "bob@example.com").await.unwrap(),
            Some(user)
        );
        assert_eq!(r.user_for(tenant, "carol@example.com").await.unwrap(), None);
    }
}
