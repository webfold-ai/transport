//! DNSSEC key custody: the [`KeyProvider`] seam, the P-256 signing key on aws-lc-rs, and the
//! master-derived provider used in tests and by the file provider.
//!
//! **Why derived keys.** Every nameserver of a zone must publish the same DNSKEY set, or a
//! resolver that reaches two of them sees two key sets and fails validation. Generating random
//! keys per node (or lazily on first use) makes that divergence the default. Instead a zone's
//! key for `(role, generation)` is a pure function of one sealed master secret and the zone
//! name (HKDF-SHA256 to a P-256 scalar), so nodes that hold the same master agree without any
//! key-distribution protocol, a rollover is "advance the generation number", and nothing about
//! a key schedule needs replicating. An HSM / `tas-keys` provider implements the same trait and
//! simply returns handles whose `sign` calls out.

use hickory_proto::dnssec::{Algorithm, DnsSecError, DnsSecResult, PublicKeyBuf, SigningKey, TBS};
use hickory_proto::rr::Name;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::hkdf::{self, Salt, HKDF_SHA256};
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// Which job a key does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Key-signing key: in the parent DS set, signs the DNSKEY (and `CDS`/`CDNSKEY`) `RRsets` only.
    Ksk,
    /// Zone-signing key: signs everything else.
    Zsk,
}

impl KeyRole {
    fn tag(self) -> u8 {
        match self {
            KeyRole::Ksk => b'k',
            KeyRole::Zsk => b'z',
        }
    }
}

/// Why a key could not be produced. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The provider has no such key.
    Unavailable,
    /// The key material was unusable.
    Invalid,
    /// The master file or its permissions were unacceptable.
    Storage(&'static str),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Unavailable => f.write_str("signing key unavailable"),
            KeyError::Invalid => f.write_str("signing key material invalid"),
            KeyError::Storage(w) => write!(f, "key storage: {w}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Supplies signing keys. Implementations must return the *same* key for the same arguments on
/// every node of a deployment.
pub trait KeyProvider: Send + Sync {
    /// The key for `(zone, role, generation)`.
    fn key(
        &self,
        zone: &Name,
        role: KeyRole,
        generation: u32,
    ) -> Result<Arc<dyn SigningKey>, KeyError>;
}

/// An ECDSA P-256 / SHA-256 signing key (DNSSEC algorithm 13) on aws-lc-rs.
pub struct P256Key {
    pair: EcdsaKeyPair,
}

impl fmt::Debug for P256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("P256Key(..)")
    }
}

impl P256Key {
    /// From a 32-byte private scalar. Fails if the scalar is not in `[1, n-1]`.
    pub fn from_scalar(scalar: &[u8; 32]) -> Result<Self, KeyError> {
        // SEC 1 ECPrivateKey { version 1, privateKey, parameters [0] prime256v1 }; the public
        // point is derived by aws-lc.
        let mut der = Vec::with_capacity(51);
        der.extend_from_slice(&[0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20]);
        der.extend_from_slice(scalar);
        der.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        let pair = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| KeyError::Invalid)?;
        zeroize_vec(&mut der);
        Ok(P256Key { pair })
    }
}

fn zeroize_vec(v: &mut [u8]) {
    for b in v.iter_mut() {
        // volatile-ish: black_box keeps the stores from being elided
        *b = std::hint::black_box(0);
    }
}

impl SigningKey for P256Key {
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.pair
            .sign(&rng, tbs.as_ref())
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| DnsSecError::Message("ecdsa signing failed"))
    }

    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf> {
        // uncompressed point 0x04 || X || Y -> DNSKEY wire form X || Y
        let pk = self.pair.public_key().as_ref();
        let xy = pk.get(1..).ok_or(DnsSecError::Message("public key"))?;
        Ok(PublicKeyBuf::new(xy.to_vec(), Algorithm::ECDSAP256SHA256))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::ECDSAP256SHA256
    }
}

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// Keys derived from one 32-byte master secret.
pub struct DerivedKeyProvider {
    master: [u8; 32],
}

impl fmt::Debug for DerivedKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKeyProvider(..)")
    }
}

impl Drop for DerivedKeyProvider {
    fn drop(&mut self) {
        zeroize_vec(&mut self.master);
    }
}

impl DerivedKeyProvider {
    /// From a master secret.
    #[must_use]
    pub fn from_master(master: [u8; 32]) -> Self {
        DerivedKeyProvider { master }
    }

    /// A provider with a fresh random master: the in-memory / test provider. Nothing persists.
    pub fn random() -> Result<Self, KeyError> {
        Ok(Self::from_master(random32()?))
    }

    /// Load the master from `path`. The file must be a regular file with no group/other
    /// permission bits and hold 64 hex digits.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path)
            .map_err(|_| KeyError::Storage("cannot stat master file"))?;
        if !meta.is_file() {
            return Err(KeyError::Storage("master file is not a regular file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(KeyError::Storage(
                "master file is accessible to group/other (must be 0600)",
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|_| KeyError::Storage("cannot read master file"))?;
        let master = parse_hex32(text.trim())
            .ok_or(KeyError::Storage("master file is not 64 hex digits"))?;
        // Every DNSSEC key of every zone is derived from this one value: refuse a placeholder
        // (all zeros, a repeated byte, a short pattern) that someone typed in instead of running
        // `init-master`. A random 256-bit master fails this with probability below 2^-100.
        check_master_is_random(&master)?;
        Ok(Self::from_master(master))
    }

    /// Create a new random master at `path` (mode 0600, written to a temp file, fsynced, then
    /// linked into place so it never exists half-written or readable). Refuses to overwrite.
    pub fn create(path: &Path) -> Result<Self, KeyError> {
        use std::os::unix::fs::OpenOptionsExt;
        let master = random32()?;
        let dir = path
            .parent()
            .ok_or(KeyError::Storage("master path has no parent"))?;
        let tmp = dir.join(format!(".master.{}.tmp", hex_of(&random32()?[..8])));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| KeyError::Storage("cannot create temp master file"))?;
        let mut text = hex_of(&master);
        text.push('\n');
        let r = f.write_all(text.as_bytes()).and_then(|()| f.sync_all());
        drop(f);
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeyError::Storage("cannot write master file"));
        }
        // hard_link fails if the target exists: never overwrite an existing master
        let linked = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        linked.map_err(|_| KeyError::Storage("master file already exists or cannot be linked"))?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(Self::from_master(master))
    }

    fn scalar(
        &self,
        zone: &Name,
        role: KeyRole,
        generation: u32,
        counter: u8,
    ) -> Result<[u8; 32], KeyError> {
        let prk = Salt::new(HKDF_SHA256, b"tas-dns/v1/zone-key").extract(&self.master);
        let wire = crate::names::wire_id(zone);
        let mut info_head = Vec::with_capacity(8 + wire.len());
        info_head.push(role.tag());
        info_head.extend_from_slice(&generation.to_be_bytes());
        info_head.push(counter);
        info_head.extend_from_slice(&wire);
        let info = [info_head.as_slice()];
        let okm = prk.expand(&info, Len32).map_err(|_| KeyError::Invalid)?;
        let mut out = [0u8; 32];
        okm.fill(&mut out).map_err(|_| KeyError::Invalid)?;
        Ok(out)
    }
}

impl KeyProvider for DerivedKeyProvider {
    fn key(
        &self,
        zone: &Name,
        role: KeyRole,
        generation: u32,
    ) -> Result<Arc<dyn SigningKey>, KeyError> {
        // Probability ~2^-32 that a scalar is out of range; step the counter until valid.
        for counter in 0..=255u8 {
            let mut s = self.scalar(zone, role, generation, counter)?;
            let k = P256Key::from_scalar(&s);
            zeroize_vec(&mut s);
            if let Ok(k) = k {
                return Ok(Arc::new(k));
            }
        }
        Err(KeyError::Invalid)
    }
}

/// Reject a master that cannot have come from a CSPRNG: fewer than 12 distinct byte values (32
/// random bytes have about 30), a bit count far from half (64..=192 of 256), or a repeating
/// pattern of up to 8 bytes, or a constant-step sequence.
fn check_master_is_random(master: &[u8; 32]) -> Result<(), KeyError> {
    let mut seen = [false; 256];
    for b in master {
        seen[usize::from(*b)] = true;
    }
    let distinct = seen.iter().filter(|s| **s).count();
    let ones: u32 = master.iter().map(|b| b.count_ones()).sum();
    let periodic = (1..=8usize).any(|p| {
        master
            .iter()
            .enumerate()
            .all(|(i, b)| master.get(i % p) == Some(b))
    });
    // 00 01 02 03 ... (or any constant step): a typed-in sequence, not a random value.
    let step = master[1].wrapping_sub(master[0]);
    let sequential = master.windows(2).all(|w| w[1].wrapping_sub(w[0]) == step);
    if distinct < 12 || !(64..=192).contains(&ones) || periodic || sequential {
        return Err(KeyError::Storage(
            "master secret is not random (repeating or low-entropy); create one with `tas-dns init-master`",
        ));
    }
    Ok(())
}

fn random32() -> Result<[u8; 32], KeyError> {
    let mut out = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| KeyError::Storage("random source failed"))?;
    Ok(out)
}

fn hex_of(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from(HEX[usize::from(x >> 4)]));
        s.push(char::from(HEX[usize::from(x & 15)]));
    }
    s
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let v = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        *out.get_mut(i)? = v(*pair.first()?)? << 4 | v(*pair.get(1)?)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]

    use super::*;
    use crate::names::parse_fqdn;
    use hickory_proto::dnssec::PublicKey;

    fn pubkey(k: &Arc<dyn SigningKey>) -> Vec<u8> {
        k.to_public_key().unwrap().public_bytes().to_vec()
    }

    #[test]
    fn same_master_same_key_everywhere_and_roles_generations_zones_differ() {
        let a = DerivedKeyProvider::from_master([5; 32]);
        let b = DerivedKeyProvider::from_master([5; 32]);
        let z = parse_fqdn("acme.example").unwrap();
        let k1 = pubkey(&a.key(&z, KeyRole::Zsk, 0).unwrap());
        assert_eq!(k1.len(), 64);
        assert_eq!(
            k1,
            pubkey(&b.key(&z, KeyRole::Zsk, 0).unwrap()),
            "two nodes agree"
        );
        assert_ne!(k1, pubkey(&a.key(&z, KeyRole::Ksk, 0).unwrap()));
        assert_ne!(k1, pubkey(&a.key(&z, KeyRole::Zsk, 1).unwrap()));
        assert_ne!(
            k1,
            pubkey(
                &a.key(&parse_fqdn("other.example").unwrap(), KeyRole::Zsk, 0)
                    .unwrap()
            )
        );
        let c = DerivedKeyProvider::from_master([6; 32]);
        assert_ne!(k1, pubkey(&c.key(&z, KeyRole::Zsk, 0).unwrap()));
    }

    #[test]
    fn a_derived_key_signs_and_its_public_half_verifies() {
        let p = DerivedKeyProvider::random().unwrap();
        let z = parse_fqdn("acme.example").unwrap();
        let k = p.key(&z, KeyRole::Zsk, 3).unwrap();
        let tbs = TBS::from(&b"to be signed"[..]);
        let sig = k.sign(&tbs).unwrap();
        assert_eq!(sig.len(), 64);
        k.to_public_key()
            .unwrap()
            .verify(b"to be signed", &sig)
            .unwrap();
        assert!(k
            .to_public_key()
            .unwrap()
            .verify(b"tampered", &sig)
            .is_err());
    }

    #[test]
    fn debug_never_shows_key_material() {
        let p = DerivedKeyProvider::from_master([0xab; 32]);
        assert!(!format!("{p:?}").contains("ab"));
        let k = P256Key::from_scalar(&[1; 32]).unwrap();
        assert_eq!(format!("{k:?}"), "P256Key(..)");
    }

    #[test]
    fn master_file_is_created_0600_never_overwritten_and_loaded_only_if_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.hex");
        let created = DerivedKeyProvider::create(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(DerivedKeyProvider::create(&path).is_err(), "no overwrite");
        let z = parse_fqdn("acme.example").unwrap();
        let loaded = DerivedKeyProvider::load(&path).unwrap();
        assert_eq!(
            pubkey(&created.key(&z, KeyRole::Ksk, 0).unwrap()),
            pubkey(&loaded.key(&z, KeyRole::Ksk, 0).unwrap())
        );
        // leaves no temp files behind
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(DerivedKeyProvider::load(&path), Err(KeyError::Storage(_))),
            "world-readable master refused"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "not hex\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DerivedKeyProvider::load(&path).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        // (the weak-master checks have their own test below)
        assert!(
            DerivedKeyProvider::load(&link).is_err(),
            "symlinked master refused"
        );
    }

    #[test]
    fn a_placeholder_master_is_refused_at_load_but_a_created_one_always_loads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, hex: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, format!("{hex}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        for (name, hex) in [
            ("zeros", "00".repeat(32)),
            ("ones", "ff".repeat(32)),
            ("byte", "ab".repeat(32)),
            ("pair", "0123".repeat(16)),
            (
                "counting",
                (0..32u8).map(|b| format!("{b:02x}")).collect::<String>(),
            ),
            (
                "few",
                "0102030401020304050607080102030405060708010203040506070801020304".to_string(),
            ),
        ] {
            let p = write(name, &hex);
            assert!(
                matches!(DerivedKeyProvider::load(&p), Err(KeyError::Storage(m)) if m.contains("not random")),
                "{name} must be refused"
            );
        }
        for i in 0..20 {
            let p = dir.path().join(format!("created{i}"));
            let created = DerivedKeyProvider::create(&p).unwrap();
            let loaded = DerivedKeyProvider::load(&p).unwrap();
            let z = parse_fqdn("acme.example").unwrap();
            assert_eq!(
                pubkey(&created.key(&z, KeyRole::Zsk, 0).unwrap()),
                pubkey(&loaded.key(&z, KeyRole::Zsk, 0).unwrap())
            );
        }
    }

    #[test]
    fn derivation_is_domain_separated_by_role_generation_and_zone_and_never_collides_across_many_inputs(
    ) {
        let p = DerivedKeyProvider::random().unwrap();
        let mut seen = std::collections::HashSet::new();
        for zone in ["a.example", "b.example", "a.example.b", "example"] {
            let z = parse_fqdn(zone).unwrap();
            for role in [KeyRole::Ksk, KeyRole::Zsk] {
                for generation in 0..4u32 {
                    let k = pubkey(&p.key(&z, role, generation).unwrap());
                    assert!(seen.insert(k), "{zone} {role:?} {generation} collided");
                }
            }
        }
        assert_eq!(seen.len(), 32);
    }
}
