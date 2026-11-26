//! Console WebSocket forwarder — proxies a customer browser's VNC / serial /
//! xterm.js connection to a Proxmox node's console endpoint **without ever
//! revealing the Proxmox node IP** to the browser.
//!
//! ```text
//!   browser ───wss──► console-ws-proxy ───wss──► proxmox-node:8006/.../vncwebsocket
//!                  (public surface          (Netbird-only / private network;
//!                   gated by ticket)         PVEAPIToken from OpenBao)
//! ```
//!
//! Per `docs/decisions/2026-05-06-m2m-internal-auth-coverage.md` (umbrella):
//! the Proxmox API token is provisioning-bucket M2M material — fetched at
//! runner spawn from `OpenBao`, never from `std::env::var`. The HMAC ticket
//! key (`TicketSigner`) is long-lived material — also `OpenBao` (transit
//! engine). The runtime doesn't see either in cleartext at rest.
//!
//! Port of `recovered-source/src/server.mjs` upgrade handler with hardenings
//! encoded in the type system:
//!
//! - **Origin header missing → REFUSED** (Tainer F9 lesson). [`OriginPolicy::Production`]
//!   refuses any request whose `Origin` is absent or not in the allow-list.
//! - **Console ticket** is a typed [`ConsoleTicket`] payload signed with HMAC-SHA256
//!   by [`TicketSigner`]. Wire form: `payload_b64.signature_b64`. Every field in
//!   the verified payload is what the signer minted — none are caller-trusted.
//! - **One-shot redemption** via [`TicketStore`]. The store removes the ticket
//!   atomically before the WebSocket forward begins, so even if the request is
//!   replayed, the second redemption fails. Production uses [`ValkeyTicketStore`]
//!   (shared across replicas, `GETDEL`-atomic redemption); [`InMemoryTicketStore`]
//!   stays for single-replica deployments and tests.
//! - **Bidirectional forwarding** via [`pump`]. The caller's HTTP framework
//!   handles the WS upgrade; we take the resulting `WebSocketStream` and pump
//!   frames in both directions until either side closes.
//!
//! # Layering
//!
//! Framework-agnostic. The caller (axum / poem / actix) is responsible for:
//!   1. Parsing the inbound HTTP upgrade
//!   2. Calling [`validate_request`] with the `Origin` header + the wire ticket
//!   3. Performing the WebSocket upgrade with their framework
//!   4. Resolving `(deployment_id) → ProxmoxConsoleTarget` from the deployment
//!      registry (via the [`DeploymentResolver`] trait)
//!   5. Calling [`upstream::proxmox::connect_vnc`] to open the Proxmox-side WS
//!   6. Calling [`pump`] with the two streams

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use apeiron::map::hashtrinity::crypto::{ct_eq, hmac_sha256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use http::header::HeaderMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

pub mod upstream;

mod ticket_store;
pub use ticket_store::ValkeyTicketStore;

pub mod kleis_wiring;

/// Minimum HMAC key length — SHA-256 block size.
const HMAC_KEY_MIN: usize = 32;

/// Default ticket TTL — short enough that a leaked ticket has small blast
/// radius, long enough that the customer's UI can establish the WebSocket
/// without rushing.
pub const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(60);

/// Default forward stall timeout — disconnect a forward that produces no
/// traffic in either direction for this long. Defends against half-open
/// zombie sessions.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("origin header required in production")]
    OriginRequired,
    #[error("origin {0} not in allow-list")]
    OriginRejected(String),
    #[error("console ticket malformed")]
    TicketMalformed,
    #[error("console ticket signature invalid")]
    TicketSignatureInvalid,
    #[error("console ticket expired at {0}")]
    TicketExpired(DateTime<Utc>),
    #[error("console ticket binding mismatch")]
    BindingMismatch,
    #[error("console ticket already redeemed (replay refused)")]
    TicketAlreadyRedeemed,
    #[error("console ticket not in store (revoked or never issued)")]
    TicketNotInStore,
    #[error("HMAC key too short ({0} bytes; need ≥{HMAC_KEY_MIN})")]
    HmacKeyTooShort(usize),
    #[error("deployment {0} not found in registry")]
    DeploymentNotFound(Uuid),
    #[error("Proxmox API: {0}")]
    Proxmox(String),
    #[error("upstream WebSocket connect failed: {0}")]
    UpstreamConnect(String),
    #[error("WebSocket transport: {0}")]
    Transport(String),
    #[error("idle timeout — no frames in either direction for {0:?}")]
    IdleTimeout(Duration),
    #[error("rate limited for tenant {tenant_id} (retry after {retry_after:?})")]
    RateLimited {
        tenant_id: Uuid,
        retry_after: Duration,
    },
}

/// What the ticket attests. Every field is verified at sign time and frozen
/// at the verifier; no caller-supplied path can mutate them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleTicket {
    /// Unique ticket id — used as the redemption key in [`TicketStore`].
    pub ticket_id: Uuid,
    /// The deployment whose console is being accessed.
    pub deployment_id: Uuid,
    /// The tenant the deployment belongs to.
    pub tenant_id: Uuid,
    /// The session that requested this ticket. Defends against ticket theft
    /// across sessions: stolen ticket + different session = reject.
    pub session_id: String,
    /// Issued-at timestamp.
    pub issued_at: DateTime<Utc>,
    /// Hard expiry. Validators check `now < expires_at`.
    pub expires_at: DateTime<Utc>,
    /// Console kind — informational. Routing happens via the resolved
    /// upstream URL, not from this field.
    pub kind: ConsoleKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsoleKind {
    /// Proxmox QEMU VNC console.
    Vnc,
    /// Proxmox QEMU serial console (xterm.js compatible).
    Serial,
    /// Proxmox LXC pct-exec console (xterm.js compatible).
    LxcExec,
}

impl ConsoleTicket {
    #[must_use]
    pub fn new(
        deployment_id: Uuid,
        tenant_id: Uuid,
        session_id: impl Into<String>,
        kind: ConsoleKind,
        ttl: Duration,
    ) -> Self {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::from_std(ttl).unwrap_or_default();
        Self {
            ticket_id: Uuid::new_v4(),
            deployment_id,
            tenant_id,
            session_id: session_id.into(),
            issued_at,
            expires_at,
            kind,
        }
    }
}

/// HMAC-SHA256 signer for [`ConsoleTicket`]s.
///
/// Wire format: `base64url(json_payload).base64url(hmac_sig)`.
/// HMAC is computed over the raw JSON bytes, not the base64 form.
pub struct TicketSigner {
    key: Vec<u8>,
}

impl TicketSigner {
    pub fn new(key: impl Into<Vec<u8>>) -> Result<Self, ProxyError> {
        let key = key.into();
        if key.len() < HMAC_KEY_MIN {
            return Err(ProxyError::HmacKeyTooShort(key.len()));
        }
        Ok(Self { key })
    }

    pub fn sign(&self, ticket: &ConsoleTicket) -> Result<String, ProxyError> {
        let payload =
            serde_json::to_vec(ticket).map_err(|e| ProxyError::Transport(e.to_string()))?;
        let sig = hmac_sha256(&self.key, &payload);
        Ok(format!(
            "{}.{}",
            B64_URL.encode(&payload),
            B64_URL.encode(sig)
        ))
    }

    pub fn verify(&self, wire: &str) -> Result<ConsoleTicket, ProxyError> {
        let (payload_b64, sig_b64) = wire.split_once('.').ok_or(ProxyError::TicketMalformed)?;
        let payload = B64_URL
            .decode(payload_b64)
            .map_err(|_| ProxyError::TicketMalformed)?;
        let sig = B64_URL
            .decode(sig_b64)
            .map_err(|_| ProxyError::TicketMalformed)?;

        let expected = hmac_sha256(&self.key, &payload);
        if !ct_eq(&expected, &sig) {
            return Err(ProxyError::TicketSignatureInvalid);
        }

        let ticket: ConsoleTicket =
            serde_json::from_slice(&payload).map_err(|_| ProxyError::TicketMalformed)?;
        Ok(ticket)
    }
}

/// One-shot ticket store. `take(id)` returns the stored ticket and removes it
/// atomically. Trait is async so the Valkey-backed prod impl
/// ([`ValkeyTicketStore`]) drops in transparently behind it.
#[async_trait::async_trait]
pub trait TicketStore: Send + Sync {
    async fn put(&self, ticket: &ConsoleTicket) -> Result<(), ProxyError>;
    async fn take(&self, ticket_id: Uuid) -> Result<Option<ConsoleTicket>, ProxyError>;
}

/// In-memory ticket store — single-replica + tests.
#[derive(Default)]
pub struct InMemoryTicketStore {
    inner: Mutex<HashMap<Uuid, ConsoleTicket>>,
}

#[async_trait::async_trait]
impl TicketStore for InMemoryTicketStore {
    async fn put(&self, ticket: &ConsoleTicket) -> Result<(), ProxyError> {
        let mut g = self.inner.lock().await;
        g.insert(ticket.ticket_id, ticket.clone());
        Ok(())
    }

    async fn take(&self, ticket_id: Uuid) -> Result<Option<ConsoleTicket>, ProxyError> {
        let mut g = self.inner.lock().await;
        Ok(g.remove(&ticket_id))
    }
}

/// What the caller binds the ticket against — must match the session the
/// ticket was minted for.
#[derive(Clone, Debug)]
pub struct RequestBinding<'a> {
    pub session_id: &'a str,
    pub tenant_id: Uuid,
}

/// Per-tenant rate limiter (M2M ADR action #5 — DDoS-prevention bucket).
///
/// Wraps `governor` with a `Uuid`-keyed quota: each tenant gets its own
/// bucket sized to `permits_per_minute` with a `burst` allowance. Cheap
/// to construct (no I/O); cheap to check (no async).
///
/// Use one instance per console-ws-proxy process. Thread-safe; share via
/// `Arc<TenantRateLimiter>`.
pub struct TenantRateLimiter {
    inner: governor::RateLimiter<
        Uuid,
        governor::state::keyed::DashMapStateStore<Uuid>,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
}

impl TenantRateLimiter {
    /// `permits_per_minute` is the steady-state allowance; `burst` is the
    /// short-term peak before throttling kicks in. Typical defaults for
    /// console reconnects: 60/min, burst 10.
    pub fn new(permits_per_minute: u32, burst: u32) -> Result<Self, ProxyError> {
        use std::num::NonZeroU32;
        let per_min = NonZeroU32::new(permits_per_minute).ok_or_else(|| {
            ProxyError::Transport("rate-limit permits_per_minute must be > 0".into())
        })?;
        let burst_nz = NonZeroU32::new(burst)
            .ok_or_else(|| ProxyError::Transport("rate-limit burst must be > 0".into()))?;
        let quota = governor::Quota::per_minute(per_min).allow_burst(burst_nz);
        Ok(Self {
            inner: governor::RateLimiter::keyed(quota),
        })
    }

    /// Consume one permit for `tenant_id`. Returns `Ok(())` if the bucket
    /// has capacity, `Err(ProxyError::RateLimited{..})` otherwise (with
    /// `retry_after` populated from governor's negative-decision time).
    pub fn check(&self, tenant_id: Uuid) -> Result<(), ProxyError> {
        match self.inner.check_key(&tenant_id) {
            Ok(()) => Ok(()),
            Err(neg) => Err(ProxyError::RateLimited {
                tenant_id,
                retry_after: neg.wait_time_from(governor::clock::Clock::now(
                    &governor::clock::DefaultClock::default(),
                )),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub enum OriginPolicy<'a> {
    Production { allow_list: &'a [String] },
    Development,
}

impl OriginPolicy<'_> {
    fn check(&self, headers: &HeaderMap) -> Result<(), ProxyError> {
        match self {
            OriginPolicy::Development => Ok(()),
            OriginPolicy::Production { allow_list } => {
                let raw = headers
                    .get(http::header::ORIGIN)
                    .ok_or(ProxyError::OriginRequired)?;
                let s = raw.to_str().map_err(|_| ProxyError::OriginRequired)?;
                if allow_list.iter().any(|allowed| allowed == s) {
                    Ok(())
                } else {
                    Err(ProxyError::OriginRejected(s.to_string()))
                }
            }
        }
    }
}

/// Validate an incoming console-WS upgrade *before* performing the upgrade.
///
/// Order of checks (each is a separate error variant so audit logs record
/// exactly which invariant tripped):
///   1. Origin policy
///   2. Ticket structural form (base64 + JSON)
///   3. HMAC signature
///   4. Expiry
///   5. Binding (`session_id` + `tenant_id` match)
///   6. Per-tenant rate-limit (only when `rate_limiter` is `Some`)
///   7. Single-use redemption against the store
///
/// The rate-limit check sits between the binding check and the store
/// redemption so even *successful* tickets count against the tenant's
/// bucket — defends against a customer hammering reconnects. tas-edge
/// handles the broader pre-decode flood; this is the post-decode
/// per-tenant gate per the M2M ADR (action #5, DDoS-prevention bucket).
pub async fn validate_request(
    headers: &HeaderMap,
    wire_ticket: &str,
    binding: &RequestBinding<'_>,
    origin_policy: &OriginPolicy<'_>,
    signer: &TicketSigner,
    store: &Arc<dyn TicketStore>,
    rate_limiter: Option<&TenantRateLimiter>,
) -> Result<ConsoleTicket, ProxyError> {
    origin_policy.check(headers)?;

    let ticket = signer.verify(wire_ticket)?;

    if Utc::now() >= ticket.expires_at {
        return Err(ProxyError::TicketExpired(ticket.expires_at));
    }

    if ticket.session_id != binding.session_id || ticket.tenant_id != binding.tenant_id {
        return Err(ProxyError::BindingMismatch);
    }

    if let Some(limiter) = rate_limiter {
        limiter.check(ticket.tenant_id)?;
    }

    let stored = store
        .take(ticket.ticket_id)
        .await?
        .ok_or(ProxyError::TicketNotInStore)?;

    if stored != ticket {
        return Err(ProxyError::BindingMismatch);
    }

    Ok(ticket)
}

/// Bidirectional pump between two `WebSocketStream`s. Stops on either side's
/// close, transport error, or idle timeout.
pub async fn pump<D, U>(
    downstream: WebSocketStream<D>,
    upstream: WebSocketStream<U>,
    idle_timeout: Duration,
) -> Result<(), ProxyError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut d_tx, mut d_rx) = downstream.split();
    let (mut u_tx, mut u_rx) = upstream.split();

    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep(idle_timeout) => return Err(ProxyError::IdleTimeout(idle_timeout)),

            frame = d_rx.next() => match frame {
                None => return Ok(()),
                Some(Err(e)) => return Err(ProxyError::Transport(e.to_string())),
                Some(Ok(Message::Close(c))) => {
                    let _ = u_tx.send(Message::Close(c)).await;
                    return Ok(());
                }
                Some(Ok(msg)) => {
                    if u_tx.send(msg).await.is_err() {
                        return Ok(());
                    }
                }
            },

            frame = u_rx.next() => match frame {
                None => return Ok(()),
                Some(Err(e)) => return Err(ProxyError::Transport(e.to_string())),
                Some(Ok(Message::Close(c))) => {
                    let _ = d_tx.send(Message::Close(c)).await;
                    return Ok(());
                }
                Some(Ok(msg)) => {
                    if d_tx.send(msg).await.is_err() {
                        return Ok(());
                    }
                }
            },
        }
    }
}

/// Type alias for the upstream stream type returned by [`upstream::proxmox::connect_vnc`].
pub type UpstreamStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    // Test bodies assert on `Result`s with `.unwrap()`/`.expect()` and use
    // `panic!` in match arms — the workspace's `unwrap_used`/`expect_used`/
    // `panic` lints are for production paths, not test fixtures (same posture
    // as `cache-client`'s test mods).
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions and fixtures"
    )]

    use super::*;
    use http::HeaderValue;

    fn key32() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn make_ticket() -> ConsoleTicket {
        ConsoleTicket::new(
            Uuid::nil(),
            Uuid::nil(),
            "session-abc",
            ConsoleKind::Vnc,
            DEFAULT_TICKET_TTL,
        )
    }

    fn allow_origin() -> Vec<String> {
        vec!["https://portal.tasmanian.cloud".to_string()]
    }

    fn good_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::ORIGIN,
            HeaderValue::from_static("https://portal.tasmanian.cloud"),
        );
        h
    }

    #[test]
    fn signer_round_trip() {
        let signer = TicketSigner::new(key32()).unwrap();
        let t = make_ticket();
        let wire = signer.sign(&t).unwrap();
        assert_eq!(t, signer.verify(&wire).unwrap());
    }

    #[test]
    fn signer_rejects_short_key() {
        // Don't `unwrap_err()` — TicketSigner intentionally has no Debug
        // impl (the HMAC key is a secret).
        match TicketSigner::new(vec![0u8; 8]) {
            Err(ProxyError::HmacKeyTooShort(8)) => {}
            other => panic!(
                "expected HmacKeyTooShort(8), got {other:?}",
                other = other.err()
            ),
        }
    }

    #[test]
    fn signer_rejects_tampered_signature() {
        let signer = TicketSigner::new(key32()).unwrap();
        let wire = signer.sign(&make_ticket()).unwrap();
        let mut chars: Vec<char> = wire.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        let err = signer.verify(&tampered).unwrap_err();
        assert!(
            matches!(
                err,
                ProxyError::TicketSignatureInvalid | ProxyError::TicketMalformed
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn signer_rejects_malformed_form() {
        let signer = TicketSigner::new(key32()).unwrap();
        for s in ["", "no-dot-here", ".", "abc.def", "abc.!!!"] {
            let err = signer.verify(s).unwrap_err();
            assert!(
                matches!(
                    err,
                    ProxyError::TicketMalformed | ProxyError::TicketSignatureInvalid
                ),
                "{s} → {err:?}"
            );
        }
    }

    #[test]
    fn origin_policy_production_requires_header() {
        let policy = OriginPolicy::Production {
            allow_list: &allow_origin(),
        };
        assert!(matches!(
            policy.check(&HeaderMap::new()),
            Err(ProxyError::OriginRequired)
        ));
    }

    #[test]
    fn origin_policy_production_rejects_unknown_origin() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        let policy = OriginPolicy::Production {
            allow_list: &allow_origin(),
        };
        assert!(matches!(
            policy.check(&h),
            Err(ProxyError::OriginRejected(_))
        ));
    }

    #[test]
    fn origin_policy_production_accepts_known_origin() {
        let policy = OriginPolicy::Production {
            allow_list: &allow_origin(),
        };
        assert!(policy.check(&good_headers()).is_ok());
    }

    #[test]
    fn origin_policy_development_skips_check() {
        assert!(OriginPolicy::Development.check(&HeaderMap::new()).is_ok());
    }

    #[tokio::test]
    async fn validate_request_happy_path() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();

        let result = validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .expect("should validate");
        assert_eq!(result.ticket_id, t.ticket_id);
    }

    #[tokio::test]
    async fn validate_request_rejects_replay() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let binding = RequestBinding {
            session_id: "session-abc",
            tenant_id: t.tenant_id,
        };
        let policy = OriginPolicy::Production { allow_list: &allow };

        validate_request(
            &good_headers(),
            &wire,
            &binding,
            &policy,
            &signer,
            &store,
            None,
        )
        .await
        .unwrap();
        let err = validate_request(
            &good_headers(),
            &wire,
            &binding,
            &policy,
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::TicketNotInStore), "got {err:?}");
    }

    #[tokio::test]
    async fn validate_request_rejects_session_mismatch() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let err = validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "WRONG",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::BindingMismatch), "got {err:?}");
    }

    #[tokio::test]
    async fn validate_request_rejects_tenant_mismatch() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let err = validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: Uuid::new_v4(),
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::BindingMismatch), "got {err:?}");
    }

    #[tokio::test]
    async fn validate_request_rejects_expired() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let mut t = make_ticket();
        t.expires_at = Utc::now() - chrono::Duration::seconds(1);
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let err = validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::TicketExpired(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn validate_request_rejects_missing_origin() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let err = validate_request(
            &HeaderMap::new(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::OriginRequired), "got {err:?}");
    }

    #[tokio::test]
    async fn validate_request_rejects_unknown_ticket() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        // deliberately not store.put(&t)
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();
        let err = validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::TicketNotInStore), "got {err:?}");
    }

    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn ws_pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        (server, client)
    }

    #[tokio::test]
    async fn pump_forwards_text_frames_both_directions() {
        let (pump_downstream, mut test_client) = ws_pair().await;
        let (pump_upstream, mut test_upstream) = ws_pair().await;

        let pump_handle = tokio::spawn(async move {
            pump(pump_downstream, pump_upstream, Duration::from_secs(5)).await
        });

        test_client
            .send(Message::Text("hello-up".to_string()))
            .await
            .unwrap();
        let got = test_upstream.next().await.unwrap().unwrap();
        assert_eq!(got, Message::Text("hello-up".to_string()));

        test_upstream
            .send(Message::Text("hello-down".to_string()))
            .await
            .unwrap();
        let got = test_client.next().await.unwrap().unwrap();
        assert_eq!(got, Message::Text("hello-down".to_string()));

        test_client.close(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), pump_handle)
            .await
            .expect("pump should exit after close")
            .expect("join")
            .expect("pump returned err");
    }

    #[tokio::test]
    async fn pump_idle_timeout_fires() {
        let (pump_downstream, _kept_client) = ws_pair().await;
        let (pump_upstream, _kept_upstream) = ws_pair().await;
        let result = pump(pump_downstream, pump_upstream, Duration::from_millis(50)).await;
        assert!(
            matches!(result, Err(ProxyError::IdleTimeout(_))),
            "got {result:?}"
        );
    }

    // ── TenantRateLimiter ─────────────────────────────────────────────────

    #[test]
    fn ratelimiter_below_burst_passes() {
        let limiter = TenantRateLimiter::new(60, 5).unwrap();
        let tenant = Uuid::new_v4();
        // Burst = 5 → first 5 calls within the same instant should pass.
        for i in 0..5 {
            assert!(limiter.check(tenant).is_ok(), "call {i} should pass");
        }
    }

    #[test]
    fn ratelimiter_at_burst_blocks_with_retry_after() {
        let limiter = TenantRateLimiter::new(60, 3).unwrap();
        let tenant = Uuid::new_v4();
        for _ in 0..3 {
            limiter.check(tenant).unwrap();
        }
        // 4th call exceeds burst.
        match limiter.check(tenant) {
            Err(ProxyError::RateLimited {
                tenant_id,
                retry_after,
            }) => {
                assert_eq!(tenant_id, tenant);
                assert!(retry_after > Duration::ZERO, "retry_after should be > 0");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn ratelimiter_separate_tenants_have_separate_buckets() {
        let limiter = TenantRateLimiter::new(60, 2).unwrap();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        // Exhaust tenant A's bucket.
        limiter.check(tenant_a).unwrap();
        limiter.check(tenant_a).unwrap();
        assert!(matches!(
            limiter.check(tenant_a),
            Err(ProxyError::RateLimited { .. })
        ));
        // Tenant B is unaffected.
        limiter.check(tenant_b).unwrap();
        limiter.check(tenant_b).unwrap();
        assert!(matches!(
            limiter.check(tenant_b),
            Err(ProxyError::RateLimited { .. })
        ));
    }

    #[test]
    fn ratelimiter_rejects_zero_permits_or_burst() {
        // TenantRateLimiter intentionally has no Debug impl (governor's
        // internal state is verbose + not safe to log). Match the Result
        // explicitly rather than `unwrap_err()`-style.
        match TenantRateLimiter::new(0, 5) {
            Err(ProxyError::Transport(msg)) => assert!(msg.contains("permits_per_minute")),
            Err(other) => panic!("expected Transport err, got {other:?}"),
            Ok(_) => panic!("expected Err for zero permits, got Ok"),
        }
        match TenantRateLimiter::new(60, 0) {
            Err(ProxyError::Transport(msg)) => assert!(msg.contains("burst")),
            Err(other) => panic!("expected Transport err, got {other:?}"),
            Ok(_) => panic!("expected Err for zero burst, got Ok"),
        }
    }

    #[tokio::test]
    async fn validate_request_with_rate_limiter_blocks_after_burst() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let allow = allow_origin();
        let limiter = TenantRateLimiter::new(60, 1).unwrap();

        // Issue 2 tickets for the SAME tenant (so they share the ratelimit bucket).
        let t1 = make_ticket();
        let mut t2 = make_ticket();
        t2.session_id = t1.session_id.clone();
        t2.tenant_id = t1.tenant_id;
        store.put(&t1).await.unwrap();
        store.put(&t2).await.unwrap();
        let wire1 = signer.sign(&t1).unwrap();
        let wire2 = signer.sign(&t2).unwrap();

        let binding = RequestBinding {
            session_id: t1.session_id.as_str(),
            tenant_id: t1.tenant_id,
        };
        let policy = OriginPolicy::Production { allow_list: &allow };

        // First call within burst (=1) → succeeds.
        validate_request(
            &good_headers(),
            &wire1,
            &binding,
            &policy,
            &signer,
            &store,
            Some(&limiter),
        )
        .await
        .expect("first call should succeed");

        // Second call exceeds burst → RateLimited; ticket should NOT be
        // consumed (still in store).
        let err = validate_request(
            &good_headers(),
            &wire2,
            &binding,
            &policy,
            &signer,
            &store,
            Some(&limiter),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::RateLimited { .. }), "got {err:?}");

        // Confirm: ticket 2 still in the store (not redeemed because we
        // bailed at the ratelimit step before take()).
        let still_there = store.take(t2.ticket_id).await.unwrap();
        assert!(
            still_there.is_some(),
            "ticket should not have been consumed by the rate-limited call"
        );
    }

    #[tokio::test]
    async fn validate_request_without_rate_limiter_passes_normally() {
        let signer = TicketSigner::new(key32()).unwrap();
        let store: Arc<dyn TicketStore> = Arc::new(InMemoryTicketStore::default());
        let t = make_ticket();
        store.put(&t).await.unwrap();
        let wire = signer.sign(&t).unwrap();
        let allow = allow_origin();

        validate_request(
            &good_headers(),
            &wire,
            &RequestBinding {
                session_id: "session-abc",
                tenant_id: t.tenant_id,
            },
            &OriginPolicy::Production { allow_list: &allow },
            &signer,
            &store,
            None,
        )
        .await
        .expect("None ratelimiter → no rate-limit enforcement");
    }
}
