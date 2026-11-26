//! The LB's own transport identity (the key the control plane pins when it dials in).
//!
//! A 32-byte Ed25519 seed kept hex-encoded in a file created atomically with mode 0600
//! (`create_new`, so two starters cannot both write one, and the file never exists with wider
//! permissions). An existing file whose mode lets group or others read it is refused rather than
//! silently used: a key that has been world-readable is no longer a secret.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// Why the identity could not be loaded or created.
#[derive(Debug)]
pub enum IdentityError {
    /// File too permissive.
    Permissions,
    /// Contents are not 64 hex characters.
    Malformed,
    /// I/O.
    Io(std::io::Error),
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityError::Permissions => {
                f.write_str("identity file is readable by group/others; refusing to use it")
            }
            IdentityError::Malformed => f.write_str("identity file is not 64 hex characters"),
            IdentityError::Io(e) => write!(f, "identity file: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

/// The identity seed: 32 bytes from the system CSPRNG through aws-lc-rs (`transport::entropy`),
/// never a fallback: if the RNG fails the identity is not created.
fn random_seed() -> std::io::Result<[u8; 32]> {
    transport::entropy::random_array::<32>().map_err(std::io::Error::other)
}

fn read_existing(path: &Path) -> Result<[u8; 32], IdentityError> {
    let meta = std::fs::metadata(path)?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(IdentityError::Permissions);
    }
    let text = std::fs::read_to_string(path)?;
    crate::backend::decode_key(text.trim()).ok_or(IdentityError::Malformed)
}

/// Load the seed at `path`, creating it (0600, atomically) if absent.
///
/// # Errors
/// [`IdentityError`] on a permissive, malformed or unreadable file, or if creation fails.
pub fn load_or_create(path: &Path) -> Result<[u8; 32], IdentityError> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut f) => {
            let seed = random_seed()?;
            let hex = crate::backend::hex_encode(&seed);
            f.write_all(hex.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            Ok(seed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_existing(path),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    #[test]
    fn created_with_0600_and_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("identity.key");
        let a = load_or_create(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_create(&p).unwrap(), a);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn a_world_readable_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("identity.key");
        load_or_create(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_or_create(&p),
            Err(IdentityError::Permissions)
        ));
    }

    #[test]
    fn a_malformed_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("identity.key");
        std::fs::write(&p, "nope").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load_or_create(&p), Err(IdentityError::Malformed)));
    }
}
