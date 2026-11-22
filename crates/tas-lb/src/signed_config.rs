//! The signed backend-set document and the store that decides whether to believe it.
//!
//! ## Authenticity: the control plane is the only writer
//!
//! A config is `MAGIC ‖ seq ‖ body_len ‖ body ‖ signature`, signed with the control plane's
//! Ed25519 key. The LB holds only the **public** key ([`transport::signed_dns::PublicKey`], the
//! same key type and z-base32 name a dialkey publishes under; the control plane derives its
//! signing key with `transport::dialkey::native_keypair`, and the LB is configured with the
//! public half, never the dialkey, which is a shared secret).
//!
//! The signature covers `DOMAIN ‖ signer_public_key ‖ seq ‖ body_len ‖ body`:
//!
//! * `DOMAIN` separates this use of the key from every other (the sealed-transport handshake signs
//!   a bare 32-byte ephemeral key, BEP44 records sign `3:seqi…`; neither can be mistaken for this).
//! * Length-prefixing `body` inside the signed bytes means no choice of `seq` can shift bytes
//!   between the fields, the same property `signed_dns`'s preimage has.
//! * The cluster name lives inside the signed body, so a perfectly valid config for another `PoP`
//!   is refused here ([`ConfigError::WrongCluster`]).
//!
//! ## Why not a `signed_dns::SignedPacket` outright
//!
//! `SignedPacket` is capped at BEP44's 1000-byte value, which is about fifteen backends once the
//! DNS framing is paid for, and the LB's set also carries health parameters and a key. This
//! envelope keeps `signed_dns`'s *semantics* (Ed25519 under a z32-named key, a monotonic `seq`,
//! length-prefixed preimage, verify-before-parse, no unverified constructor) with a 64 KiB bound.
//!
//! ## Sequence numbers and rollback refusal
//!
//! `seq` is a strictly increasing `u64` (the control plane uses a microsecond timestamp, like
//! BEP44). A document with `seq <= last accepted` is refused ([`ConfigError::Rollback`]), which
//! also refuses an exact replay. The floor is persisted with the accepted document, so a
//! restart does not reopen the window, and the operator can raise it statically
//! (`min_config_seq`) to revoke a leaked-but-valid old document.
//!
//! ## Fail closed
//!
//! Every failure leaves the last good configuration serving and untouched. The order of checks is
//! cheap-and-structural first, signature before any parse of the body, sequence before applying,
//! persistence before commit (if the floor cannot be persisted the document is refused: accepting
//! it would let a restart roll back).

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use transport::signed_dns::{Keypair, PublicKey};

use crate::backend::{BackendSet, SetError};
use crate::flows::lock;
use crate::metrics::ConfigResult;

/// Envelope magic and version.
pub const MAGIC: &[u8; 8] = b"TASLBCF1";
/// Largest body accepted.
pub const MAX_BODY: usize = 64 * 1024;
/// Largest whole envelope.
pub const MAX_ENVELOPE: usize = 8 + 8 + 4 + MAX_BODY + 64;
const DOMAIN: &[u8] = b"tas-lb/config/v1\0";
const PERSIST_NAME: &str = "config.signed";

/// Why a document was refused.
#[derive(Debug)]
pub enum ConfigError {
    /// Larger than the bounds above.
    TooLarge,
    /// Wrong magic, truncated, or length fields inconsistent.
    Malformed,
    /// The signature does not verify under the configured control-plane key.
    BadSignature,
    /// `seq` is not greater than the last accepted one.
    Rollback {
        /// Last accepted.
        have: u64,
        /// Offered.
        got: u64,
    },
    /// Signed for a different cluster.
    WrongCluster,
    /// Body is not valid JSON for a [`BackendSet`], or fails validation.
    Invalid(String),
    /// The new floor could not be persisted.
    Persist(String),
}

impl ConfigError {
    /// Metric label.
    #[must_use]
    pub fn result(&self) -> ConfigResult {
        match self {
            ConfigError::TooLarge | ConfigError::Malformed => ConfigResult::Malformed,
            ConfigError::BadSignature => ConfigResult::BadSignature,
            ConfigError::Rollback { .. } => ConfigResult::Rollback,
            ConfigError::WrongCluster => ConfigResult::WrongCluster,
            ConfigError::Invalid(_) => ConfigResult::Invalid,
            ConfigError::Persist(_) => ConfigResult::PersistFailed,
        }
    }

    /// Stable short code sent back to the pusher (no body contents).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::TooLarge => "too_large",
            ConfigError::Malformed => "malformed",
            ConfigError::BadSignature => "bad_signature",
            ConfigError::Rollback { .. } => "rollback",
            ConfigError::WrongCluster => "wrong_cluster",
            ConfigError::Invalid(_) => "invalid",
            ConfigError::Persist(_) => "persist_failed",
        }
    }
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Rollback { have, got } => {
                write!(f, "config refused: seq {got} is not greater than {have}")
            }
            ConfigError::Invalid(why) => write!(f, "config refused: invalid ({why})"),
            ConfigError::Persist(why) => write!(f, "config refused: could not persist ({why})"),
            other => write!(f, "config refused: {}", other.code()),
        }
    }
}

impl std::error::Error for ConfigError {}

fn preimage(signer: &[u8; 32], seq: u64, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(DOMAIN.len() + 32 + 12 + body.len());
    p.extend_from_slice(DOMAIN);
    p.extend_from_slice(signer);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(body.len() as u64).to_be_bytes());
    p.extend_from_slice(body);
    p
}

/// Build a signed envelope around `body` (the control plane's side; the LB never signs).
///
/// # Errors
/// [`ConfigError::TooLarge`] if `body` exceeds [`MAX_BODY`].
pub fn sign_body(kp: &Keypair, seq: u64, body: &[u8]) -> Result<Vec<u8>, ConfigError> {
    if body.len() > MAX_BODY {
        return Err(ConfigError::TooLarge);
    }
    let sig = kp.sign(&preimage(kp.public_key().as_bytes(), seq, body));
    let mut out = Vec::with_capacity(8 + 8 + 4 + body.len() + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| ConfigError::TooLarge)?
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Serialise and sign a [`BackendSet`].
///
/// # Errors
/// [`ConfigError::Invalid`] if it cannot be serialised, [`ConfigError::TooLarge`] if oversize.
pub fn sign_set(kp: &Keypair, seq: u64, set: &BackendSet) -> Result<Vec<u8>, ConfigError> {
    let body = serde_json::to_vec(set).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    sign_body(kp, seq, &body)
}

/// Check structure and signature; returns `(seq, body)` only for a document `signer` signed.
///
/// # Errors
/// [`ConfigError`] for oversize, malformed, or unsigned/forged input.
pub fn verify<'a>(signer: &PublicKey, bytes: &'a [u8]) -> Result<(u64, &'a [u8]), ConfigError> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(ConfigError::TooLarge);
    }
    let head = bytes.get(..20).ok_or(ConfigError::Malformed)?;
    if head.get(..8) != Some(&MAGIC[..]) {
        return Err(ConfigError::Malformed);
    }
    let seq = u64::from_be_bytes(
        head.get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or(ConfigError::Malformed)?,
    );
    let body_len = u32::from_be_bytes(
        head.get(16..20)
            .and_then(|s| s.try_into().ok())
            .ok_or(ConfigError::Malformed)?,
    ) as usize;
    if body_len > MAX_BODY {
        return Err(ConfigError::TooLarge);
    }
    if bytes.len() != 20 + body_len + 64 {
        return Err(ConfigError::Malformed);
    }
    let body = bytes.get(20..20 + body_len).ok_or(ConfigError::Malformed)?;
    let sig: [u8; 64] = bytes
        .get(20 + body_len..)
        .and_then(|s| s.try_into().ok())
        .ok_or(ConfigError::Malformed)?;
    if !signer.verify(&preimage(signer.as_bytes(), seq, body), &sig) {
        return Err(ConfigError::BadSignature);
    }
    Ok((seq, body))
}

/// A verified, validated, committed set.
#[derive(Debug)]
pub struct Accepted {
    /// Its sequence number.
    pub seq: u64,
    /// The set.
    pub set: BackendSet,
}

/// Decides whether to believe a document, and remembers the answer across restarts.
pub struct ConfigStore {
    signer: PublicKey,
    cluster: String,
    allow_loopback: bool,
    dir: Option<PathBuf>,
    last_seq: Mutex<u64>,
}

impl core::fmt::Debug for ConfigStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigStore")
            .field("signer", &self.signer.to_z32())
            .field("cluster", &self.cluster)
            .finish_non_exhaustive()
    }
}

impl ConfigStore {
    /// `min_seq` is the operator's static floor: only documents with `seq > min_seq` are ever
    /// accepted. `dir`, if set, holds the persisted last good document.
    #[must_use]
    pub fn new(
        signer: PublicKey,
        cluster: String,
        allow_loopback: bool,
        dir: Option<PathBuf>,
        min_seq: u64,
    ) -> Self {
        ConfigStore {
            signer,
            cluster,
            allow_loopback,
            dir,
            last_seq: Mutex::new(min_seq),
        }
    }

    /// Sequence number of the last accepted document (or the static floor).
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        *lock(&self.last_seq)
    }

    fn check(&self, bytes: &[u8], last: u64) -> Result<Accepted, ConfigError> {
        let (seq, body) = verify(&self.signer, bytes)?;
        if seq <= last {
            return Err(ConfigError::Rollback {
                have: last,
                got: seq,
            });
        }
        let set: BackendSet = serde_json::from_slice(body)
            .map_err(|e| ConfigError::Invalid(format!("json: {}", e.classify_str())))?;
        if set.cluster != self.cluster {
            return Err(ConfigError::WrongCluster);
        }
        set.validate(self.allow_loopback)
            .map_err(|e: SetError| ConfigError::Invalid(e.to_string()))?;
        Ok(Accepted { seq, set })
    }

    /// Verify and, if good, persist and commit a pushed document. On any error nothing changes.
    ///
    /// # Errors
    /// [`ConfigError`] describing why the document was refused.
    pub fn apply(&self, bytes: &[u8]) -> Result<Accepted, ConfigError> {
        let mut last = lock(&self.last_seq);
        let accepted = self.check(bytes, *last)?;
        if let Some(dir) = &self.dir {
            persist(dir, bytes).map_err(|e| ConfigError::Persist(e.to_string()))?;
        }
        *last = accepted.seq;
        Ok(accepted)
    }

    /// Load the persisted last good document at startup, applying exactly the checks a push gets.
    /// A persisted document that fails them is moved aside (so it is not retried every boot and
    /// is kept for forensics) and reported.
    ///
    /// # Errors
    /// [`ConfigError`] if a persisted file exists but is not acceptable.
    pub fn load_persisted(&self) -> Result<Option<Accepted>, ConfigError> {
        let Some(dir) = &self.dir else {
            return Ok(None);
        };
        let path = dir.join(PERSIST_NAME);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ConfigError::Persist(e.to_string())),
        };
        let mut last = lock(&self.last_seq);
        match self.check(&bytes, *last) {
            Ok(a) => {
                *last = a.seq;
                Ok(Some(a))
            }
            Err(e) => {
                let _ = std::fs::rename(&path, dir.join(format!("{PERSIST_NAME}.rejected")));
                Err(e)
            }
        }
    }
}

trait ClassifyStr {
    fn classify_str(&self) -> &'static str;
}

impl ClassifyStr for serde_json::Error {
    /// The error category only: serde messages can quote input, and a rejected document may
    /// contain the hash key.
    fn classify_str(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        }
    }
}

fn persist(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{PERSIST_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(PERSIST_NAME))?;
    // Make the rename durable.
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use crate::backend::{BackendSpec, HealthSpec};

    fn kp(tag: u8) -> Keypair {
        Keypair::from_secret_key(&[tag; 32])
    }

    pub(crate) fn set(cluster: &str, n: usize) -> BackendSet {
        BackendSet {
            cluster: cluster.into(),
            hash_key: "ab".repeat(32),
            send_proxy_v2: true,
            drain_timeout_ms: 1000,
            health: HealthSpec::default(),
            backends: (0..n)
                .map(|i| BackendSpec {
                    id: format!("e{i}"),
                    ip: format!("10.0.0.{}", i + 1).parse().unwrap(),
                    weight: 100,
                    drain: false,
                })
                .collect(),
        }
    }

    fn store(dir: Option<&Path>) -> ConfigStore {
        ConfigStore::new(
            kp(1).public_key(),
            "pop".into(),
            false,
            dir.map(Path::to_path_buf),
            0,
        )
    }

    #[test]
    fn a_good_document_is_applied_and_advances_the_floor() {
        let s = store(None);
        let doc = sign_set(&kp(1), 10, &set("pop", 2)).unwrap();
        let a = s.apply(&doc).unwrap();
        assert_eq!((a.seq, a.set.backends.len()), (10, 2));
        assert_eq!(s.last_seq(), 10);
    }

    #[test]
    fn rollback_and_replay_are_refused_and_change_nothing() {
        let s = store(None);
        s.apply(&sign_set(&kp(1), 10, &set("pop", 2)).unwrap())
            .unwrap();
        for seq in [9, 10, 1, 0] {
            let doc = sign_set(&kp(1), seq, &set("pop", 3)).unwrap();
            assert!(
                matches!(s.apply(&doc), Err(ConfigError::Rollback { have: 10, .. })),
                "seq {seq}"
            );
        }
        assert_eq!(s.last_seq(), 10);
        s.apply(&sign_set(&kp(1), 11, &set("pop", 3)).unwrap())
            .unwrap();
    }

    #[test]
    fn a_document_signed_by_anyone_else_is_refused() {
        let s = store(None);
        let doc = sign_set(&kp(2), 10, &set("pop", 2)).unwrap();
        assert!(matches!(s.apply(&doc), Err(ConfigError::BadSignature)));
        assert_eq!(s.last_seq(), 0);
    }

    #[test]
    fn every_altered_byte_breaks_the_document() {
        let s = store(None);
        let doc = sign_set(&kp(1), 10, &set("pop", 1)).unwrap();
        for i in 0..doc.len() {
            let mut bad = doc.clone();
            bad[i] ^= 0x01;
            assert!(s.apply(&bad).is_err(), "flipping byte {i} must be refused");
        }
        assert_eq!(s.last_seq(), 0);
        s.apply(&doc).unwrap();
    }

    #[test]
    fn the_sequence_number_is_inside_the_signature() {
        let s = store(None);
        s.apply(&sign_set(&kp(1), 10, &set("pop", 1)).unwrap())
            .unwrap();
        // Take an old document and bump its seq field to beat the floor.
        let mut old = sign_set(&kp(1), 5, &set("pop", 1)).unwrap();
        old[8..16].copy_from_slice(&99u64.to_be_bytes());
        assert!(matches!(s.apply(&old), Err(ConfigError::BadSignature)));
    }

    #[test]
    fn a_validly_signed_document_for_another_cluster_is_refused() {
        let s = store(None);
        let doc = sign_set(&kp(1), 10, &set("other-pop", 2)).unwrap();
        assert!(matches!(s.apply(&doc), Err(ConfigError::WrongCluster)));
        assert_eq!(
            s.last_seq(),
            0,
            "a refused document must not raise the floor"
        );
    }

    #[test]
    fn a_signed_but_invalid_set_is_refused_without_raising_the_floor() {
        let s = store(None);
        let mut bad = set("pop", 2);
        bad.backends[0].weight = 0;
        assert!(matches!(
            s.apply(&sign_set(&kp(1), 10, &bad).unwrap()),
            Err(ConfigError::Invalid(_))
        ));
        let doc = sign_body(&kp(1), 11, b"{not json").unwrap();
        assert!(matches!(s.apply(&doc), Err(ConfigError::Invalid(_))));
        assert_eq!(s.last_seq(), 0);
    }

    #[test]
    fn structural_garbage_never_panics_and_is_malformed() {
        let s = store(None);
        for junk in [
            &b""[..],
            b"TASLBCF1",
            &[0u8; 100],
            &vec![0xFF; MAX_ENVELOPE + 1],
        ] {
            assert!(s.apply(junk).is_err());
        }
        let mut doc = sign_set(&kp(1), 10, &set("pop", 1)).unwrap();
        doc.push(0);
        assert!(matches!(s.apply(&doc), Err(ConfigError::Malformed)));
        let mut doc = sign_set(&kp(1), 10, &set("pop", 1)).unwrap();
        doc[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(s.apply(&doc), Err(ConfigError::TooLarge)));
        assert!(matches!(
            sign_body(&kp(1), 1, &vec![0; MAX_BODY + 1]),
            Err(ConfigError::TooLarge)
        ));
    }

    #[test]
    fn the_static_floor_revokes_old_documents() {
        let s = ConfigStore::new(kp(1).public_key(), "pop".into(), false, None, 100);
        assert!(matches!(
            s.apply(&sign_set(&kp(1), 100, &set("pop", 1)).unwrap()),
            Err(ConfigError::Rollback { .. })
        ));
        s.apply(&sign_set(&kp(1), 101, &set("pop", 1)).unwrap())
            .unwrap();
    }

    #[test]
    fn the_floor_survives_a_restart_through_the_persisted_document() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(Some(dir.path()));
        s.apply(&sign_set(&kp(1), 50, &set("pop", 2)).unwrap())
            .unwrap();
        let meta = std::fs::metadata(dir.path().join(PERSIST_NAME)).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
            0o600
        );

        let s2 = store(Some(dir.path()));
        let loaded = s2.load_persisted().unwrap().unwrap();
        assert_eq!(loaded.seq, 50);
        assert!(matches!(
            s2.apply(&sign_set(&kp(1), 49, &set("pop", 2)).unwrap()),
            Err(ConfigError::Rollback { .. })
        ));
        s2.apply(&sign_set(&kp(1), 51, &set("pop", 2)).unwrap())
            .unwrap();
    }

    #[test]
    fn a_refused_push_does_not_overwrite_the_persisted_good_document() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(Some(dir.path()));
        s.apply(&sign_set(&kp(1), 50, &set("pop", 2)).unwrap())
            .unwrap();
        let good = std::fs::read(dir.path().join(PERSIST_NAME)).unwrap();
        let _ = s.apply(&sign_set(&kp(2), 60, &set("pop", 3)).unwrap());
        let _ = s.apply(&sign_set(&kp(1), 40, &set("pop", 3)).unwrap());
        assert_eq!(std::fs::read(dir.path().join(PERSIST_NAME)).unwrap(), good);
    }

    #[test]
    fn a_tampered_persisted_document_is_refused_and_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(Some(dir.path()));
        s.apply(&sign_set(&kp(1), 50, &set("pop", 2)).unwrap())
            .unwrap();
        let path = dir.path().join(PERSIST_NAME);
        let mut b = std::fs::read(&path).unwrap();
        b[30] ^= 1;
        std::fs::write(&path, b).unwrap();
        let s2 = store(Some(dir.path()));
        assert!(matches!(
            s2.load_persisted(),
            Err(ConfigError::BadSignature)
        ));
        assert!(dir.path().join("config.signed.rejected").exists());
        assert!(s2.load_persisted().unwrap().is_none());
        assert_eq!(s2.last_seq(), 0);
    }

    #[test]
    fn a_failed_persist_refuses_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("does-not-exist");
        let s = store(Some(&gone));
        let r = s.apply(&sign_set(&kp(1), 50, &set("pop", 2)).unwrap());
        assert!(matches!(r, Err(ConfigError::Persist(_))));
        assert_eq!(
            s.last_seq(),
            0,
            "accepting without persisting would let a restart roll back"
        );
    }

    #[test]
    fn error_text_never_quotes_the_document() {
        let s = store(None);
        let body = br#"{"cluster":"pop","hash_key":"SECRET-MATERIAL","drain_timeout_ms":"x"}"#;
        let err = s.apply(&sign_body(&kp(1), 5, body).unwrap()).unwrap_err();
        assert!(!err.to_string().contains("SECRET-MATERIAL"), "{err}");
    }
}
