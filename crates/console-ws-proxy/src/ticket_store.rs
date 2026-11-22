//! Production [`TicketStore`] backed by `cache-client` (Valkey/Redis).
//!
//! The in-memory [`crate::InMemoryTicketStore`] keeps state per-process, so a
//! multi-replica deployment would let a ticket minted (and `put`) on replica A
//! be redeemed on replica A only — and worse, a *replayed* request that lands
//! on replica B (which never saw the `put`) would be rejected, while a replay
//! that lands back on replica A after the first redemption is correctly
//! refused. With many replicas the store has to be shared.
//!
//! [`ValkeyTicketStore`] puts the JSON-serialised [`ConsoleTicket`] under a
//! TTL'd key and redeems it with [`cache_client::Cache::get_del`] — Redis
//! `GETDEL`, a single atomic op. That's the load-bearing property: two
//! concurrent `take`s for the same `ticket_id` (across replicas, racing) can't
//! both get `Some` — exactly one wins the value, the other gets `None`, so
//! one-shot redemption stays race-free regardless of how many replicas are in
//! flight.
//!
//! ## Why no per-pod `redb` shadow (yet)
//!
//! `docs/topology.md` lists a `local-store` `validated_tokens` table — a
//! per-pod `redb` shadow of "already-validated tokens to survive Valkey
//! blips". Deferred for v1, deliberately:
//!
//! - Console tickets are **one-shot**. The first `take` consumes the ticket;
//!   there is no "validate this token again" path. A read-through shadow's
//!   value is *speeding up repeated reads of the same key* — but there are no
//!   repeated reads here.
//! - The blip-survival angle is also marginal for one-shot tickets: if Valkey
//!   is down at redemption time the request fails, the customer's UI retries,
//!   and a fresh ticket gets minted (tickets are cheap, ~60s TTL). A shadow
//!   would let an *already-validated-but-not-yet-redeemed* ticket be honoured
//!   during the blip — a vanishingly small window for a 60s credential, and it
//!   pulls a `local-store` dependency into this crate for that one edge.
//!
//! If a future design adds **re-validatable** console credentials — e.g. a
//! reconnect flow that re-presents the same ticket within its TTL rather than
//! minting a new one — revisit: a `redb` read-through shadow keyed on
//! `ticket_id` then earns its keep. Until then, `console-ws-proxy` has no
//! `local-store` dep.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use uuid::Uuid;

use crate::{ConsoleTicket, ProxyError, TicketStore};

/// Default key namespace for stored tickets — `console:ticket:{ticket_id}`.
const DEFAULT_KEY_PREFIX: &str = "console:ticket:";

/// Floor for the per-ticket TTL. [`cache_client::Cache::set_ex`] rejects a
/// zero TTL ([`cache_client::CacheError::InvalidTtl`]), and Redis `PX` is a
/// positive integer of milliseconds — so an already-expired (or about-to-
/// expire-this-instant) ticket still goes in under a 1-second lease. That's
/// harmless: [`crate::validate_request`] checks `now < expires_at`
/// independently of the store, so an expired ticket is rejected at the expiry
/// check (which runs *before* `take`) and never reaches redemption. The 1s
/// floor just keeps the `put` itself from erroring.
const MIN_TTL: Duration = Duration::from_secs(1);

/// Valkey/Redis-backed [`TicketStore`].
///
/// Construct with [`ValkeyTicketStore::new`] (default `console:ticket:`
/// prefix) or [`ValkeyTicketStore::with_prefix`]. Holds an
/// `Arc<dyn cache_client::Cache>` — the same trait every shared-state crate in
/// the runtime depends on, so the Valkey ↔ `KeyDB` swap is wiring-only.
pub struct ValkeyTicketStore {
    cache: Arc<dyn cache_client::Cache>,
    key_prefix: String,
}

impl ValkeyTicketStore {
    /// Build a store over the given cache with the default
    /// `console:ticket:` key prefix.
    #[must_use]
    pub fn new(cache: Arc<dyn cache_client::Cache>) -> Self {
        Self {
            cache,
            key_prefix: DEFAULT_KEY_PREFIX.to_string(),
        }
    }

    /// Build a store with a custom key prefix (e.g. an environment
    /// namespace layered on top of the `cache-client`'s own prefix).
    pub fn with_prefix(cache: Arc<dyn cache_client::Cache>, prefix: impl Into<String>) -> Self {
        Self {
            cache,
            key_prefix: prefix.into(),
        }
    }

    fn key(&self, ticket_id: Uuid) -> String {
        format!("{}{}", self.key_prefix, ticket_id)
    }
}

/// Map a cache-backend failure (dropped connection, protocol error, …) onto
/// the proxy's transport error variant — reusing `Transport` keeps the error
/// surface minimal and matches how `TicketSigner` already maps incidental
/// failures.
fn map_cache_err(e: &cache_client::CacheError) -> ProxyError {
    ProxyError::Transport(format!("ticket store: {e}"))
}

#[async_trait::async_trait]
impl TicketStore for ValkeyTicketStore {
    async fn put(&self, ticket: &ConsoleTicket) -> Result<(), ProxyError> {
        // TTL = remaining lifetime, floored at MIN_TTL (see its doc). Even an
        // already-expired ticket is stored (under the 1s floor): the
        // independent expiry check in `validate_request` rejects it before
        // `take` is ever called, so this is correct and avoids a
        // put-time `InvalidTtl` error.
        let remaining = ticket
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        let ttl = remaining.max(MIN_TTL);

        let json = serde_json::to_vec(ticket)
            .map_err(|e| ProxyError::Transport(format!("ticket store: serialize ticket: {e}")))?;
        self.cache
            .set_ex(&self.key(ticket.ticket_id), Bytes::from(json), ttl)
            .await
            .map_err(|e| map_cache_err(&e))
    }

    async fn take(&self, ticket_id: Uuid) -> Result<Option<ConsoleTicket>, ProxyError> {
        // GETDEL — single atomic op. Two callers racing `take(ticket_id)`
        // (different replicas, same ticket): exactly one gets `Some`, the
        // other `None`. That's the one-shot guarantee.
        let raw = self
            .cache
            .get_del(&self.key(ticket_id))
            .await
            .map_err(|e| map_cache_err(&e))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let ticket: ConsoleTicket = serde_json::from_slice(&bytes)
                    // Corrupt stored bytes — treat as a malformed ticket. The
                    // key has already been consumed by GETDEL, which is fine:
                    // a garbage value can never be redeemed anyway.
                    .map_err(|_| ProxyError::TicketMalformed)?;
                Ok(Some(ticket))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Test bodies assert on `Result`s with `.unwrap()` / `.expect()` — the
    // workspace's `unwrap_used`/`expect_used` lints are for production paths,
    // not test fixtures (same posture as `cache-client`'s test mods).
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test assertions on Results"
    )]

    use super::*;
    use crate::{ConsoleKind, DEFAULT_TICKET_TTL};
    use cache_client::{Cache, InMemoryCache};

    fn store() -> ValkeyTicketStore {
        ValkeyTicketStore::new(Arc::new(InMemoryCache::new()))
    }

    fn ticket(ttl: Duration) -> ConsoleTicket {
        ConsoleTicket::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "session-abc",
            ConsoleKind::Vnc,
            ttl,
        )
    }

    #[test]
    fn key_format() {
        let s = ValkeyTicketStore::new(Arc::new(InMemoryCache::new()));
        let id = Uuid::nil();
        assert_eq!(s.key(id), format!("console:ticket:{id}"));
        let s2 = ValkeyTicketStore::with_prefix(Arc::new(InMemoryCache::new()), "prod:ws:");
        assert_eq!(s2.key(id), format!("prod:ws:{id}"));
    }

    #[tokio::test]
    async fn put_then_take_round_trips_then_consumes() {
        let s = store();
        let t = ticket(DEFAULT_TICKET_TTL);
        s.put(&t).await.unwrap();
        let got = s.take(t.ticket_id).await.unwrap().expect("ticket present");
        assert_eq!(got, t);
        // Consumed atomically — a second take of the same id → None.
        assert!(s.take(t.ticket_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn take_of_unknown_id_is_none() {
        let s = store();
        assert!(s.take(Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_then_take_works_for_30s_ticket() {
        let s = store();
        let t = ticket(Duration::from_secs(30));
        s.put(&t).await.unwrap();
        assert_eq!(s.take(t.ticket_id).await.unwrap(), Some(t));
    }

    #[tokio::test]
    async fn already_expired_ticket_is_stored_under_floor_ttl() {
        // We store it (under the 1s floor) — `take` immediately after still
        // returns it; the independent expiry check in `validate_request`
        // rejects an expired ticket *before* it ever calls `take`, so this is
        // correct. (This test exercises the store in isolation.)
        let s = store();
        let mut t = ticket(DEFAULT_TICKET_TTL);
        t.expires_at = Utc::now() - chrono::Duration::seconds(5);
        s.put(&t).await.unwrap();
        assert_eq!(s.take(t.ticket_id).await.unwrap(), Some(t));
    }

    #[tokio::test]
    async fn corrupt_stored_value_surfaces_ticket_malformed() {
        // Drop a garbage value at the ticket key, then `take` it.
        let cache = Arc::new(InMemoryCache::new());
        let id = Uuid::new_v4();
        let key = format!("{DEFAULT_KEY_PREFIX}{id}");
        cache
            .set_ex(
                &key,
                Bytes::from_static(b"not-json"),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        let s = ValkeyTicketStore::new(cache);
        let err = s.take(id).await.unwrap_err();
        assert!(matches!(err, ProxyError::TicketMalformed), "got {err:?}");
    }

    #[tokio::test]
    async fn get_del_is_reachable_through_the_cache_trait_object() {
        // Sanity: the new trait method is on the object-safe `Cache` trait
        // and works through `Arc<dyn Cache>` (the shape the store holds).
        let cache: Arc<dyn Cache> = Arc::new(InMemoryCache::new());
        cache
            .set_ex("k", Bytes::from_static(b"v"), Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(
            cache.get_del("k").await.unwrap().as_deref(),
            Some(&b"v"[..])
        );
        assert!(cache.get_del("k").await.unwrap().is_none());
    }

    /// Real-Valkey round-trip — gated. Requires `VALKEY_URL` pointing at a
    /// running Valkey/Redis. Same gating as `cache-client`'s integration
    /// tests; won't run under a plain `cargo test`.
    #[cfg(feature = "integration-valkey")]
    #[tokio::test]
    async fn integration_valkey_ticket_round_trip() {
        use cache_client::{ValkeyCache, ValkeyConfig};

        let cache = Arc::new(ValkeyCache::new(ValkeyConfig {
            url: std::env::var("VALKEY_URL").expect("VALKEY_URL"),
            key_prefix: Some(format!("test-{}", Uuid::new_v4().simple())),
        }));
        let s = ValkeyTicketStore::new(cache);
        let t = ticket(Duration::from_secs(30));
        s.put(&t).await.unwrap();
        assert_eq!(s.take(t.ticket_id).await.unwrap(), Some(t.clone()));
        // Consumed.
        assert!(s.take(t.ticket_id).await.unwrap().is_none());
    }
}
