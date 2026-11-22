//! kleis + sangdb wiring — replaces the OpenBao dependency this crate's own module doc
//! named for the Proxmox API token and the HMAC ticket-signing key, and Valkey for the
//! `TicketStore` backend. Neither was ever a hard requirement of the *code* — the module
//! doc's "fetched from OpenBao" was a production-sourcing note, not a type constraint:
//! [`ProxmoxConsoleTarget::api_token`] is a plain `String`, [`TicketSigner::new`] takes
//! raw key bytes, and [`ValkeyTicketStore`] holds an `Arc<dyn cache_client::Cache>` — the
//! exact trait `cache_client::SangDbCache` already implements (including `get_del`, the
//! one op the one-shot-redemption guarantee rests on). All three fit `kleis` directly,
//! mirroring `deploy-api`'s own `KleisLookup`/`KleisAuthzCheck` pattern exactly rather
//! than inventing a new one.
//!
//! **What this does NOT do**: provision real secret values. The Proxmox API token is
//! real production credential material this module has no business fabricating — an
//! operator writes it in via [`kleis::CredentialStore::put_secret`] (see the doc on
//! [`kleis_proxmox_token`] for the exact tenant/path) before this can do anything live.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cache_client::SangDbCache;
use kleis::CredentialStore;

use crate::ValkeyTicketStore;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Open (or create) a sangdb-backed [`ValkeyTicketStore`] at `dir` — the same primitive
/// `deploy-api`'s own queue already stands on (`cache_client::SangDbCache`), not a new
/// storage engine. No Valkey process, no network hop: the store is a local `.kvlog`.
pub fn sangdb_ticket_store(dir: &Path) -> std::io::Result<ValkeyTicketStore> {
    let cache: Arc<dyn cache_client::Cache> = Arc::new(SangDbCache::open(dir)?);
    Ok(ValkeyTicketStore::new(cache))
}

/// Read a Proxmox node's API token from kleis — `tenant="platform"` (provider credentials
/// are platform-level infrastructure, not a customer's, matching `deploy-api`'s own
/// `KleisLookup` scope exactly), `path="provider/proxmox/{node}"`.
///
/// **Provisioning** (an operator does this once, out of band, never this crate):
/// ```ignore
/// let mut store = CredentialStore::open(&kleis_dir)?;
/// store.unseal(&unseal_seed);
/// store.put_secret("platform", "provider/proxmox/twnhost2", token.as_bytes(), None, now)?;
/// ```
pub fn kleis_proxmox_token(creds: &Mutex<CredentialStore>, node: &str) -> Option<String> {
    let now = now_secs();
    creds
        .lock()
        .ok()?
        .get_secret("platform", &format!("provider/proxmox/{node}"), now)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Read the HMAC ticket-signing key from kleis — `tenant="platform"`,
/// `path="console-ws-proxy/ticket-signing-key"`. Feed the result straight to
/// [`crate::TicketSigner::new`] (it takes raw bytes, `impl Into<Vec<u8>>`).
///
/// **Provisioning**: `put_secret("platform", "console-ws-proxy/ticket-signing-key",
/// &random_32_bytes, None, now)` — generate once, keep stable (rotating it invalidates
/// every outstanding ticket, which at a 60s TTL is a non-event).
pub fn kleis_ticket_signing_key(creds: &Mutex<CredentialStore>) -> Option<Vec<u8>> {
    let now = now_secs();
    creds
        .lock()
        .ok()?
        .get_secret("platform", "console-ws-proxy/ticket-signing-key", now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn store_with_secret(dir: &Path, path: &str, value: &[u8]) -> Mutex<CredentialStore> {
        let mut store = CredentialStore::open(dir).expect("open credential store");
        // A store with no unseal seed refuses put_secret (`is_sealed`); tests use a
        // fixed seed since this is throwaway test-fixture state, not production key
        // material.
        store.unseal(b"test-only-unseal-seed-not-production");
        store
            .put_secret("platform", path, value, None, 0)
            .expect("put_secret should not I/O-fail on a fresh temp dir");
        Mutex::new(store)
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "console-ws-proxy-kleis-test-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn kleis_proxmox_token_round_trips() {
        let dir = tmp_dir("token");
        let creds = store_with_secret(&dir, "provider/proxmox/twnhost2", b"ops@pam!cws=deadbeef");
        assert_eq!(
            kleis_proxmox_token(&creds, "twnhost2").as_deref(),
            Some("ops@pam!cws=deadbeef")
        );
        // A node with no provisioned token is None, not an error.
        assert_eq!(kleis_proxmox_token(&creds, "twnhost99"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kleis_ticket_signing_key_round_trips() {
        let dir = tmp_dir("key");
        let key = vec![7u8; 32];
        let creds = store_with_secret(&dir, "console-ws-proxy/ticket-signing-key", &key);
        assert_eq!(kleis_ticket_signing_key(&creds), Some(key));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sangdb_ticket_store_put_then_take_round_trips() {
        let dir = tmp_dir("sangdb");
        let store = sangdb_ticket_store(&dir).expect("open sangdb ticket store");
        // Exercised at the `Cache` level directly (constructing a real `ConsoleTicket`
        // needs types private to lib.rs) -- what's under test here is that
        // `SangDbCache` satisfies the same `Cache` trait `ValkeyTicketStore` was built
        // against, including the `get_del` atomicity `ticket_store.rs`'s own tests
        // already prove against `InMemoryCache`; this proves it against the real
        // sangdb-backed implementation instead.
        let cache: Arc<dyn cache_client::Cache> =
            Arc::new(SangDbCache::open(&dir.join("direct")).expect("open"));
        cache
            .set_ex(
                "k",
                bytes::Bytes::from_static(b"v"),
                Duration::from_secs(30),
            )
            .await
            .expect("set_ex");
        assert_eq!(
            cache.get_del("k").await.expect("get_del").as_deref(),
            Some(&b"v"[..])
        );
        assert!(cache.get_del("k").await.expect("get_del").is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
