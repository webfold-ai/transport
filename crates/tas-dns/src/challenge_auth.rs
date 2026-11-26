//! The issuance side of the challenge zone: label allocation, permanent binding, token
//! publication, and the `transport::acme::Dns01Responder` adapter the renewal engine uses.
//!
//! The authority holds the challenge authority's signing key and a local [`ZoneDb`] replica
//! (persistent, kept in step with the nameservers by the mesh pull loop). Every mutation is
//! applied to that replica first — so it passes exactly the validation a nameserver will apply,
//! including the permanent-binding rules — and then pushed to the nameservers; a publish is
//! reported successful only when every required nameserver has acknowledged holding it.

use crate::challenge::{
    label_id, ChallengeDoc, TokenDoc, LABEL_LEN, MAX_TOKENS, MAX_TOKEN_LIFETIME,
};
use crate::db::ZoneDb;
use crate::escape::esc;
use crate::names;
use crate::zone::TenantId;
use async_trait::async_trait;
use std::sync::Arc;
use transport::signed_dns::Keypair;
use transport::zone_sync::{ApplyOutcome, ObjectKind, SignedObject, SyncClient};
use transport::PeerAddr;

/// Delivers signed objects to the nameservers.
#[async_trait]
pub trait ObjectPublisher: Send + Sync {
    /// Push `objects`; `Ok` only if the required nameservers all hold every one.
    async fn publish(&self, objects: &[SignedObject]) -> Result<(), String>;
}

/// Publishes into a local database (single-node deployments and tests).
pub struct LocalPublisher(pub Arc<ZoneDb>);

#[async_trait]
impl ObjectPublisher for LocalPublisher {
    async fn publish(&self, objects: &[SignedObject]) -> Result<(), String> {
        for o in objects {
            let out = self.0.apply_object(o.clone());
            if !out.is_held() {
                return Err(format!("local node refused the object: {out:?}"));
            }
        }
        Ok(())
    }
}

/// Pushes to every configured nameserver over the mesh and requires all of them to acknowledge.
pub struct MeshPublisher {
    client: SyncClient,
    nodes: Vec<PeerAddr>,
    required: usize,
}

impl MeshPublisher {
    /// Require `required` of `nodes` to acknowledge (use `nodes.len()` for all: the CA may query any).
    #[must_use]
    pub fn new(client: SyncClient, nodes: Vec<PeerAddr>, required: usize) -> Self {
        MeshPublisher {
            client,
            nodes,
            required,
        }
    }
}

#[async_trait]
impl ObjectPublisher for MeshPublisher {
    async fn publish(&self, objects: &[SignedObject]) -> Result<(), String> {
        let mut set = tokio::task::JoinSet::new();
        for n in self.nodes.clone() {
            let (c, objs) = (self.client.clone(), objects.to_vec());
            set.spawn(async move {
                c.push(&n, &objs)
                    .await
                    .is_ok_and(|v| v.iter().all(|o| o.is_held()))
            });
        }
        let mut ok = 0usize;
        while let Some(r) = set.join_next().await {
            if r.unwrap_or(false) {
                ok += 1;
            }
        }
        if ok >= self.required {
            Ok(())
        } else {
            Err(format!(
                "only {ok} of {} required nameservers acknowledged",
                self.required
            ))
        }
    }
}

/// Why a challenge operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeError {
    /// The name was not a valid domain name.
    InvalidName,
    /// No label is bound to this (tenant, name): the customer has not been onboarded for it.
    NotBound,
    /// A quota would be exceeded.
    Quota,
    /// The local replica refused the object.
    Refused(ApplyOutcome),
    /// The nameservers did not all acknowledge.
    Publish(String),
    /// Randomness was unavailable.
    Entropy,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::InvalidName => f.write_str("invalid challenge name"),
            ChallengeError::NotBound => {
                f.write_str("no challenge label is bound to this tenant and name")
            }
            ChallengeError::Quota => f.write_str("challenge label quota exceeded"),
            ChallengeError::Refused(o) => write!(f, "challenge state refused: {o:?}"),
            ChallengeError::Publish(e) => write!(f, "challenge publish failed: {}", esc(e)),
            ChallengeError::Entropy => f.write_str("random source unavailable"),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// What the customer must publish at their own DNS provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The permanent label.
    pub label: String,
    /// `<label>.<challenge-zone>` (no trailing dot).
    pub target: String,
    /// The record to create: `_acme-challenge.<name> CNAME <target>.`
    pub cname: String,
}

/// The challenge authority.
pub struct ChallengeAuthority {
    key: Keypair,
    zone: hickory_proto::rr::Name,
    db: Arc<ZoneDb>,
    publisher: Arc<dyn ObjectPublisher>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    token_ttl: u64,
    lock: tokio::sync::Mutex<()>,
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn random_label() -> Result<String, ChallengeError> {
    use aws_lc_rs::rand::SecureRandom;
    let mut raw = [0u8; 20];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| ChallengeError::Entropy)?;
    let mut out = String::with_capacity(LABEL_LEN);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in raw {
        acc = acc << 8 | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::try_from((acc >> bits) & 31).unwrap_or(0);
            out.push(char::from(B32[idx]));
        }
    }
    Ok(out)
}

impl ChallengeAuthority {
    /// An authority signing with `key` for `zone`, over the local replica `db`.
    #[must_use]
    pub fn new(
        key: Keypair,
        zone: hickory_proto::rr::Name,
        db: Arc<ZoneDb>,
        publisher: Arc<dyn ObjectPublisher>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        ChallengeAuthority {
            key,
            zone,
            db,
            publisher,
            clock,
            token_ttl: 600,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    fn doc_object(
        &self,
        label: &str,
        version: u64,
        doc: &ChallengeDoc,
    ) -> Result<SignedObject, ChallengeError> {
        let id = label_id(label, &self.zone).map_err(|_| ChallengeError::InvalidName)?;
        let body = serde_json::to_vec(doc).map_err(|_| ChallengeError::InvalidName)?;
        SignedObject::sign(&self.key, ObjectKind::Challenge, id, 1, version, body)
            .map_err(|_| ChallengeError::InvalidName)
    }

    async fn commit(&self, obj: SignedObject) -> Result<(), ChallengeError> {
        match self.db.apply_object(obj.clone()) {
            ApplyOutcome::Applied | ApplyOutcome::Duplicate => {}
            ApplyOutcome::Quota => return Err(ChallengeError::Quota),
            o => return Err(ChallengeError::Refused(o)),
        }
        self.publisher
            .publish(&[obj])
            .await
            .map_err(ChallengeError::Publish)
    }

    fn target_of(&self, label: &str, name: &str) -> Binding {
        let zone = self.zone.to_ascii();
        let zone = zone.trim_end_matches('.');
        Binding {
            label: label.to_string(),
            target: format!("{label}.{zone}"),
            cname: format!("_acme-challenge.{name} CNAME {label}.{zone}."),
        }
    }

    /// Bind (or look up) the permanent label for `(tenant, name)`. Idempotent: the same pair
    /// always yields the same label, and a label is never issued to a different pair.
    pub async fn bind(&self, tenant: &TenantId, name: &str) -> Result<Binding, ChallengeError> {
        let name = names::canonical(name).map_err(|_| ChallengeError::InvalidName)?;
        let name = name.strip_prefix("*.").map_or(name.clone(), str::to_string);
        names::parse_fqdn_no_wildcard(&name).map_err(|_| ChallengeError::InvalidName)?;
        let _g = self.lock.lock().await;
        if let Some(label) = self.db.label_for(tenant, &name) {
            // heal: make sure the nameservers hold the current state of an existing binding
            if let Some(obj) = self.db.object(
                ObjectKind::Challenge,
                &label_id(&label, &self.zone).map_err(|_| ChallengeError::InvalidName)?,
            ) {
                let _ = self.publisher.publish(&[obj]).await;
            }
            return Ok(self.target_of(&label, &name));
        }
        let mut label = random_label()?;
        let mut tries = 0;
        while self.db.label_exists(&label) {
            tries += 1;
            if tries > 8 {
                return Err(ChallengeError::Entropy);
            }
            label = random_label()?;
        }
        let doc = ChallengeDoc {
            tenant: tenant.as_str().to_string(),
            name: name.clone(),
            tokens: Vec::new(),
            released: false,
        };
        self.commit(self.doc_object(&label, 1, &doc)?).await?;
        Ok(self.target_of(&label, &name))
    }

    async fn mutate(
        &self,
        tenant: &TenantId,
        name: &str,
        f: impl FnOnce(&mut Vec<TokenDoc>, &mut bool, u64),
    ) -> Result<(), ChallengeError> {
        let name = names::canonical(name).map_err(|_| ChallengeError::InvalidName)?;
        let name = name.strip_prefix("*.").map_or(name.clone(), str::to_string);
        let _g = self.lock.lock().await;
        let label = self
            .db
            .label_for(tenant, &name)
            .ok_or(ChallengeError::NotBound)?;
        let cur = self.db.challenge(&label).ok_or(ChallengeError::NotBound)?;
        let now = (self.clock)();
        let mut tokens: Vec<TokenDoc> = cur
            .tokens
            .iter()
            .filter(|(_, exp)| *exp > now)
            .map(|(v, e)| TokenDoc {
                v: v.clone(),
                exp: *e,
            })
            .collect();
        let mut released = cur.released;
        f(&mut tokens, &mut released, now);
        let doc = ChallengeDoc {
            tenant: tenant.as_str().to_string(),
            name,
            tokens,
            released,
        };
        self.commit(self.doc_object(&label, cur.version + 1, &doc)?)
            .await
    }

    /// Publish a TXT token for `(tenant, name)`. Returns only when the nameservers hold it.
    pub async fn publish_token(
        &self,
        tenant: &TenantId,
        name: &str,
        token: &str,
    ) -> Result<(), ChallengeError> {
        let ttl = self.token_ttl.min(MAX_TOKEN_LIFETIME);
        let token = token.to_string();
        self.mutate(tenant, name, move |tokens, released, now| {
            *released = false;
            tokens.retain(|t| t.v != token);
            if tokens.len() >= MAX_TOKENS {
                tokens.remove(0);
            }
            tokens.push(TokenDoc {
                v: token,
                exp: now + ttl,
            });
        })
        .await
    }

    /// Remove one token (other concurrent tokens at the label are kept).
    pub async fn clear_token(
        &self,
        tenant: &TenantId,
        name: &str,
        token: &str,
    ) -> Result<(), ChallengeError> {
        let token = token.to_string();
        self.mutate(tenant, name, move |tokens, _, _| {
            tokens.retain(|t| t.v != token);
        })
        .await
    }

    /// Release a binding: tokens cleared, label kept reserved forever.
    pub async fn release(&self, tenant: &TenantId, name: &str) -> Result<(), ChallengeError> {
        self.mutate(tenant, name, |tokens, released, _| {
            tokens.clear();
            *released = true;
        })
        .await
    }

    /// A [`transport::acme::Dns01Responder`] scoped to one tenant, for the renewal engine.
    #[must_use]
    pub fn responder_for(self: &Arc<Self>, tenant: TenantId) -> TenantDns01Responder {
        TenantDns01Responder {
            authority: self.clone(),
            tenant,
        }
    }
}

/// The ACME issuance worker's handle: every call is scoped to one tenant, so a worker acting for
/// tenant A can only ever touch labels bound to A.
pub struct TenantDns01Responder {
    authority: Arc<ChallengeAuthority>,
    tenant: TenantId,
}

impl transport::acme::Dns01Responder for TenantDns01Responder {
    fn publish_txt<'a>(
        &'a self,
        name: &'a str,
        value: &'a str,
    ) -> transport::BoxFuture<'a, Result<(), transport::acme::AcmeError>> {
        Box::pin(async move {
            self.authority.publish_token(&self.tenant, name, value).await.map_err(|e| {
                tracing::warn!(target: "tas_dns::challenge", error = %e, "dns-01 publish failed");
                transport::acme::AcmeError::ChallengeSetup
            })
        })
    }

    fn remove_txt<'a>(&'a self, name: &'a str, value: &'a str) -> transport::BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Err(e) = self.authority.clear_token(&self.tenant, name, value).await {
                tracing::warn!(target: "tas_dns::challenge", error = %e, "dns-01 clear failed (the token expires on its own)");
            }
        })
    }
}
