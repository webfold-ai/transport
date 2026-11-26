//! Credential wiring through iotaDB's kleis.
//!
//! The Proxmox token and ticket-signing key use the existing CredentialStore.
//! Hosting-specific SangDbCache construction belongs in hosting-runtime's
//! cache-client (feature `console-tickets`), not in transport. Its Cache trait
//! is the same canonical saga-cache trait consumed by the ticket store.
//!
//! **What this does NOT do**: provision real secret values. The Proxmox API token is
//! real production credential material this module has no business fabricating — an
//! operator writes it in via [`kleis::CredentialStore::put_secret`] (see the doc on
//! [`kleis_proxmox_token`] for the exact tenant/path) before this can do anything live.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use kleis::CredentialStore;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    use std::path::Path;

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
}
