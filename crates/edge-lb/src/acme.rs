//! acme — the last-known-good certificate manager (INV-06).
//!
//! INV-06 is the load-bearing law here: certificate issuance and rotation
//! MUST NOT block the request path, and a missing or expiring certificate
//! MUST NOT cause a proxy outage. Traffic MUST continue on the
//! last-known-good certificate until a replacement is ready.
//!
//! This module is the STORE half of that law — the half that holds the
//! invariant. The full ACME client (HTTP-01 challenge, Let's Encrypt-style
//! issuance) is the DEFERRED half: no ACME client exists in this
//! workspace, so issuance is out of scope here. What this module provides
//! is the last-known-good store and reloader: certs are loaded from disk
//! paths, the manager tracks the last-known-good pair ([`CertRecord`]), and
//! a failed reload keeps serving the previous certificate. Whoever writes
//! the new PEM files — the ACME client, the deploy driver, or `certbot` —
//! this module makes the swap safe.
//!
//! The store is a `hashtrinity::Table` keyed by cert name (the trinity
//! rule: any map is a Table, no `std::collections`). Rotation runs
//! off-path from the proxy request lifecycle, exactly as the existing
//! dialkey refresh loop runs off-path: [`CertManager::reload_if_changed`]
//! is called from a background task, never from the request path.

use apeiron::map::hashtrinity::{self, Table};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::ServerConfig;
use servelet_tls::tls_server_config;

/// One last-known-good certificate record: the disk paths the pair was
/// loaded from, the fingerprint of what built, and when it was loaded.
#[derive(Clone, Debug, PartialEq)]
pub struct CertRecord {
    /// Path to the PEM certificate chain.
    pub cert_path: PathBuf,
    /// Path to the PEM private key (PKCS8).
    pub key_path: PathBuf,
    /// SHA-256 of the loaded pair (cert bytes then key bytes) — the change
    /// detector [`CertManager::reload_if_changed`] compares against.
    pub sha256: [u8; 32],
    /// When this record was loaded (the swap time).
    pub loaded_at: SystemTime,
}

/// The last-known-good certificate store (INV-06).
///
/// One entry per cert name; a failed load or reload MUST NOT evict a
/// serving config — the previous config keeps serving until a replacement
/// actually builds.
pub struct CertManager {
    /// name → last-known-good record (the pair that built successfully).
    certs: Table<String, CertRecord>,
    /// name → last-known-good config — what `serve_tls` is actually serving.
    configs: Table<String, Arc<ServerConfig>>,
    /// the active cert name; [`CertManager::current`] serves its config.
    active: Option<String>,
}

impl Default for CertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CertManager {
    /// A fresh, empty manager: no certs registered, nothing serving.
    pub fn new() -> Self {
        CertManager {
            certs: Table::new(),
            configs: Table::new(),
            active: None,
        }
    }

    /// Load a cert pair from disk paths and activate it ATOMICALLY: the
    /// swap happens only when the pair builds (INV-06).
    ///
    /// On any error — missing file, unreadable file, bad PEM — nothing
    /// changes: the previous config for this name (and the active config)
    /// keeps serving, and the error is returned. The record is written
    /// only after the config builds, so the store always describes what is
    /// actually servable.
    pub fn load(
        &mut self,
        name: &str,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<Arc<ServerConfig>, String> {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("reading {}: {e}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("reading {}: {e}", key_path.display()))?;
        let config = tls_server_config(&cert_pem, &key_pem)
            .map_err(|e| format!("building tls config: {e}"))?;
        let mut blob = cert_pem.into_bytes();
        blob.extend_from_slice(key_pem.as_bytes());
        let record = CertRecord {
            cert_path,
            key_path,
            sha256: hashtrinity::crypto::sha256(&blob),
            loaded_at: SystemTime::now(),
        };
        let key = name.to_string();
        self.certs.put(key.clone(), record);
        self.configs.put(key.clone(), config.clone());
        self.active = Some(key);
        Ok(config)
    }

    /// Re-read every registered cert's disk paths and swap in anything
    /// that changed AND builds (INV-06: only the new pair, only when it
    /// builds). Returns the number of certs swapped.
    ///
    /// On the first error — a changed file that is missing, unreadable, or
    /// fails to build — the last-known-good record and config stay put and
    /// the error is returned; nothing already serving is disturbed.
    pub fn reload_if_changed(&mut self) -> Result<usize, String> {
        let mut swapped = 0;
        let known = self
            .certs
            .iter()
            .map(|(name, record)| (name.clone(), record.clone()))
            .collect::<Vec<_>>();
        for (name, record) in known {
            let cert_pem = std::fs::read_to_string(&record.cert_path)
                .map_err(|e| format!("reading {}: {e}", record.cert_path.display()))?;
            let key_pem = std::fs::read_to_string(&record.key_path)
                .map_err(|e| format!("reading {}: {e}", record.key_path.display()))?;
            let mut blob = cert_pem.clone().into_bytes();
            blob.extend_from_slice(key_pem.as_bytes());
            let digest = hashtrinity::crypto::sha256(&blob);
            if digest == record.sha256 {
                continue;
            }
            let config = tls_server_config(&cert_pem, &key_pem)
                .map_err(|e| format!("rebuilding tls config for {name}: {e}"))?;
            let new_record = CertRecord {
                cert_path: record.cert_path,
                key_path: record.key_path,
                sha256: digest,
                loaded_at: SystemTime::now(),
            };
            self.certs.put(name.clone(), new_record);
            self.configs.put(name.clone(), config);
            swapped += 1;
        }
        Ok(swapped)
    }

    /// The last-known-good config for the active cert, if any — what
    /// `serve_tls` should be handed today.
    pub fn current(&self) -> Option<Arc<ServerConfig>> {
        self.active
            .as_ref()
            .and_then(|name| self.configs.get(name).cloned())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use std::fs;

    // A real self-signed EC pair (the same fixture bedrock's own
    // tls_server_config tests embed) — the "good" pair for every test.
    const GOOD_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBvzCCAWWgAwIBAgIUDNjqZLCC8q5tnWpTuhHxnyy2ubwwCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcwNjA5NTkyNloYDzIxMjYwNjEy\n\
MDk1OTI2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAAQWzzNgEHmWExfSibB4yxRBk1XskVgjCno/DO/69cKbImX6Mesim9v5\n\
6PmqJXWVtsTxPgyjXGc9t7qFcshNGmdro4GSMIGPMB0GA1UdDgQWBBR+o7nTOCVp\n\
5N9mVXOepMnBc2oSFjAfBgNVHSMEGDAWgBR+o7nTOCVp5N9mVXOepMnBc2oSFjAa\n\
BgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8B\n\
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIh\n\
AIpKWXNFn17ZEEBKN1cs3MZYH3hEJugX5iw7AOut4zPJAiAhTcY+TtqBBinAMs6Y\n\
PfFwXFUdKr72euUqW9E4wdcMVA==\n\
-----END CERTIFICATE-----\n";

    const GOOD_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVWtnGXHnzG6FQVVq\n\
i8YHRSNBOrNNqCa29hrqX758vMihRANCAAQWzzNgEHmWExfSibB4yxRBk1XskVgj\n\
Cno/DO/69cKbImX6Mesim9v56PmqJXWVtsTxPgyjXGc9t7qFcshNGmdr\n\
-----END PRIVATE KEY-----\n";

    fn fixture(dir: &tempfile::TempDir, cert: &str, key: &str) -> (PathBuf, PathBuf) {
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert).unwrap();
        fs::write(&key_path, key).unwrap();
        (cert_path, key_path)
    }

    fn blob_of(cert: &str, key: &str) -> Vec<u8> {
        let mut blob = cert.as_bytes().to_vec();
        blob.extend_from_slice(key.as_bytes());
        blob
    }

    #[test]
    fn current_is_none_before_any_load() {
        let manager = CertManager::new();
        assert!(manager.current().is_none());
    }

    #[test]
    fn good_pair_loads_and_serves() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let config = manager
            .load("default", cert_path.clone(), key_path.clone())
            .unwrap();
        assert!(Arc::ptr_eq(&config, &manager.current().unwrap()));
        let record = manager.certs.get(&"default".to_string()).unwrap();
        assert_eq!(record.cert_path, cert_path);
        assert_eq!(record.key_path, key_path);
        assert_eq!(
            record.sha256,
            hashtrinity::crypto::sha256(&blob_of(GOOD_CERT_PEM, GOOD_KEY_PEM))
        );
    }

    #[test]
    fn bad_pem_after_good_pem_keeps_serving_good_config() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let good = manager
            .load("default", cert_path.clone(), key_path.clone())
            .unwrap();
        // The files are replaced with garbage — a broken rotation.
        fs::write(&cert_path, "not a certificate").unwrap();
        fs::write(&key_path, "not a key").unwrap();
        assert!(manager.reload_if_changed().is_err());
        // The previous config is STILL what current() serves, same Arc.
        assert!(Arc::ptr_eq(&good, &manager.current().unwrap()));
        // And the record still describes the last-known-good pair.
        let record = manager.certs.get(&"default".to_string()).unwrap();
        assert_eq!(
            record.sha256,
            hashtrinity::crypto::sha256(&blob_of(GOOD_CERT_PEM, GOOD_KEY_PEM))
        );
    }

    #[test]
    fn load_with_bad_files_keeps_previous() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let good = manager
            .load("default", cert_path.clone(), key_path.clone())
            .unwrap();
        assert!(manager
            .load(
                "default",
                PathBuf::from("/nonexistent/cert.pem"),
                key_path.clone()
            )
            .is_err());
        assert!(manager
            .load(
                "default",
                cert_path.clone(),
                PathBuf::from("/nonexistent/key.pem")
            )
            .is_err());
        assert!(Arc::ptr_eq(&good, &manager.current().unwrap()));
    }

    #[test]
    fn changed_file_triggers_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let first = manager
            .load("default", cert_path.clone(), key_path.clone())
            .unwrap();
        // A renewed pair: same cert, a comment banner prepended — different
        // bytes (new fingerprint) but still a valid PEM stream.
        let renewed = format!("# rotated by the deploy driver\n{GOOD_CERT_PEM}");
        fs::write(&cert_path, &renewed).unwrap();
        let swapped = manager.reload_if_changed().unwrap();
        assert_eq!(swapped, 1);
        // current() now serves the NEW config — a different Arc.
        let second = manager.current().unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        let record = manager.certs.get(&"default".to_string()).unwrap();
        assert_eq!(
            record.sha256,
            hashtrinity::crypto::sha256(&blob_of(&renewed, GOOD_KEY_PEM))
        );
    }

    #[test]
    fn unchanged_files_do_not_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let first = manager.load("default", cert_path, key_path).unwrap();
        assert_eq!(manager.reload_if_changed().unwrap(), 0);
        assert!(Arc::ptr_eq(&first, &manager.current().unwrap()));
    }

    #[test]
    fn missing_file_is_error_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = fixture(&dir, GOOD_CERT_PEM, GOOD_KEY_PEM);
        let mut manager = CertManager::new();
        let good = manager
            .load("default", cert_path.clone(), key_path.clone())
            .unwrap();
        // The key vanishes after the initial load — a failed rotation.
        fs::remove_file(&key_path).unwrap();
        assert!(manager.reload_if_changed().is_err());
        // Traffic keeps the last-known-good cert; no panic anywhere.
        assert!(Arc::ptr_eq(&good, &manager.current().unwrap()));
    }
}
