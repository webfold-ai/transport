//! Where the platform's certificate-related randomness comes from, and the checks that stop it
//! being quietly weak.
//!
//! **One source.** Every key, nonce, serial, token and secret this crate generates for
//! certificates, ACME or DNSSEC comes from the operating system's CSPRNG through `aws-lc-rs`
//! (`aws_lc_rs::rand`; the FIPS-validated DRBG with the `fips` feature). Not `rand::thread_rng`,
//! not a clock or a counter, not a seed written in source. The only deterministic derivation
//! allowed anywhere near a signing key is the documented master-derived DNSSEC key provider in
//! `tas-dns`, whose *master* comes from here.
//!
//! **Fail closed.** [`EntropySource::fill`] returns an error; callers propagate it and do not
//! fall back to another source, retry with a weaker one, or substitute zeros. A failing RNG
//! therefore stops issuance (see `acme::AcmeClient` and the `CertKeyGen` seam in
//! [`crate::certkey`]) instead of producing a certificate whose key is predictable.
//!
//! **A startup self-check** ([`startup_self_check`]) catches the failure the error path cannot:
//! a source that *succeeds* and returns garbage (all zero, a stuck pattern, the same block
//! twice) — a broken seccomp filter that fakes `getrandom`, a container with a mocked
//! `/dev/urandom`, a virtualised guest cloned from a snapshot with identical RNG state. It is a
//! sanity test, not a statistical battery: bounded (96 bytes), thresholds far from anything a
//! working CSPRNG produces, and run before the first certificate key is generated.

use std::fmt;
use std::sync::mpsc;
use std::time::Duration;

use aws_lc_rs::rand::SecureRandom;

/// The entropy source failed, or returned something no working CSPRNG would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntropyError(pub &'static str);

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy source: {}", self.0)
    }
}

impl std::error::Error for EntropyError {}

/// A source of cryptographically secure random bytes. The production implementation is
/// [`OsEntropy`]; the trait exists so tests can inject a failing or degenerate source and prove
/// the callers fail closed.
pub trait EntropySource: Send + Sync + fmt::Debug {
    /// Fill `dest` with random bytes.
    ///
    /// # Errors
    /// The source could not deliver. The caller must not substitute another source.
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// The operating system's CSPRNG through `aws-lc-rs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        aws_lc_rs::rand::SystemRandom::new().fill(dest).map_err(|_| EntropyError("the system RNG failed"))
    }
}

/// `N` random bytes from [`OsEntropy`].
///
/// # Errors
/// If the system RNG fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], EntropyError> {
    random_array_from(&OsEntropy)
}

/// `N` random bytes from `src`.
///
/// # Errors
/// If `src` fails.
pub fn random_array_from<const N: usize>(src: &dyn EntropySource) -> Result<[u8; N], EntropyError> {
    let mut out = [0u8; N];
    src.fill(&mut out)?;
    Ok(out)
}

/// Largest buffer [`random_vec`] will fill. Keys, nonces and tokens are a few dozen bytes.
pub const MAX_RANDOM_VEC: usize = 1024 * 1024;

/// `n` random bytes from [`OsEntropy`], at most [`MAX_RANDOM_VEC`].
///
/// # Errors
/// If the system RNG fails or `n` is implausibly large.
pub fn random_vec(n: usize) -> Result<Vec<u8>, EntropyError> {
    if n > MAX_RANDOM_VEC {
        return Err(EntropyError("refusing to draw an implausibly large buffer"));
    }
    let mut buf = vec![0u8; n];
    OsEntropy.fill(&mut buf)?;
    Ok(buf)
}

/// Lower-case hex of `n` random bytes (an opaque token or identifier).
///
/// # Errors
/// If the system RNG fails.
pub fn random_hex(n: usize) -> Result<String, EntropyError> {
    let mut buf = vec![0u8; n];
    OsEntropy.fill(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

const SAMPLE: usize = 32;
const DRAWS: usize = 3;

/// Sanity-test `src`: three 32-byte draws must each be non-zero, have plenty of distinct byte
/// values and a bit count near half, and be pairwise different.
///
/// The thresholds are deliberately loose — a working CSPRNG fails them with probability below
/// 1e-12 per call — so this never turns a healthy host away, while a stuck, zeroed, repeating or
/// cloned source fails every time.
///
/// # Errors
/// The source failed or produced a degenerate sample.
pub fn self_check_with(src: &dyn EntropySource) -> Result<(), EntropyError> {
    let mut draws = [[0u8; SAMPLE]; DRAWS];
    for d in &mut draws {
        src.fill(d)?;
        if d.iter().all(|b| *b == 0) {
            return Err(EntropyError("returned an all-zero block"));
        }
        let mut seen = [false; 256];
        for b in d.iter() {
            seen[usize::from(*b)] = true;
        }
        // 32 random bytes have ~30 distinct values; fewer than 12 is a pattern, not chance.
        if seen.iter().filter(|s| **s).count() < 12 {
            return Err(EntropyError("returned a block with too few distinct bytes"));
        }
        let ones: u32 = d.iter().map(|b| b.count_ones()).sum();
        // Mean 128, sd 8 over 256 bits; 64..=192 is eight standard deviations.
        if !(64..=192).contains(&ones) {
            return Err(EntropyError("returned a block whose bit balance is implausible"));
        }
    }
    for i in 0..DRAWS {
        for j in (i + 1)..DRAWS {
            if draws[i] == draws[j] {
                return Err(EntropyError("returned the same block twice"));
            }
        }
    }
    Ok(())
}

/// [`self_check_with`] on the system RNG.
///
/// # Errors
/// See [`self_check_with`].
pub fn self_check() -> Result<(), EntropyError> {
    self_check_with(&OsEntropy)
}

/// [`self_check`] with a deadline. `getrandom` can block on a host that has not yet gathered
/// entropy (early boot of a minimal VM); a hung self-check must fail the start, not hang it.
/// The check runs on its own thread and the caller waits at most `timeout`.
///
/// # Errors
/// The check failed, or did not finish in time.
pub fn startup_self_check(timeout: Duration) -> Result<(), EntropyError> {
    startup_self_check_with(std::sync::Arc::new(OsEntropy), timeout)
}

/// [`startup_self_check`] over an arbitrary source (tests).
///
/// # Errors
/// The check failed, or did not finish in time.
pub fn startup_self_check_with(src: std::sync::Arc<dyn EntropySource>, timeout: Duration) -> Result<(), EntropyError> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("rng-self-check".into())
        .spawn(move || {
            let _ = tx.send(self_check_with(src.as_ref()));
        })
        .map_err(|_| EntropyError("could not start the self-check thread"))?;
    rx.recv_timeout(timeout).map_err(|_| EntropyError("the self-check did not finish in time"))?
}

/// Whether this build uses the FIPS-validated `aws-lc` module (the `fips` feature).
#[must_use]
pub const fn fips_build() -> bool {
    cfg!(feature = "fips")
}

/// Why a configured secret is too weak to key anything with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeakSecret(pub String);

impl fmt::Display for WeakSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WeakSecret {}

/// Refuse an operator-supplied secret that cannot be a random one: shorter than `min_len`
/// bytes, a single repeated byte, a short repeating pattern, or too few distinct bytes. This
/// cannot prove a secret is *good* (a long English phrase passes); it rejects the placeholders
/// and defaults that end up in production (`changeme`, `0000…`, `unset`).
///
/// # Errors
/// [`WeakSecret`] naming the rule broken (never the secret).
pub fn check_secret_strength(label: &str, secret: &[u8], min_len: usize) -> Result<(), WeakSecret> {
    let weak = |why: &str| WeakSecret(format!("{label} is too weak to use: {why}"));
    if secret.len() < min_len {
        return Err(weak(&format!("it must be at least {min_len} bytes")));
    }
    let mut seen = [false; 256];
    for b in secret {
        seen[usize::from(*b)] = true;
    }
    let distinct = seen.iter().filter(|s| **s).count();
    if distinct < 10.min(min_len / 2) {
        return Err(weak("it uses too few distinct characters"));
    }
    for period in 1..=4usize {
        if secret.len() > period * 2 && secret.chunks(period).skip(1).all(|c| secret.starts_with(&c[..c.len().min(period)])) {
            return Err(weak("it is a short repeating pattern"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct Failing;
    impl EntropySource for Failing {
        fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError("injected failure"))
        }
    }

    /// Succeeds but returns degenerate output.
    #[derive(Debug)]
    struct Constant(u8);
    impl EntropySource for Constant {
        fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.fill(self.0);
            Ok(())
        }
    }

    /// A repeating counter: distinct bytes, but the second draw repeats the first.
    #[derive(Debug, Default)]
    struct Cloned(AtomicUsize);
    impl EntropySource for Cloned {
        fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            // The same non-trivial block every call (a VM snapshot clone).
            let block = os_block();
            for (d, b) in dest.iter_mut().zip(block.iter().cycle()) {
                *d = *b;
            }
            Ok(())
        }
    }

    fn os_block() -> [u8; 32] {
        // Fixed, balanced, many-distinct-bytes block.
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        b
    }

    #[test]
    fn the_os_source_passes_its_own_self_check_and_returns_distinct_output() {
        self_check().unwrap();
        startup_self_check(Duration::from_secs(5)).unwrap();
        let (a, b) = (random_array::<32>().unwrap(), random_array::<32>().unwrap());
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        assert_eq!(random_hex(16).unwrap().len(), 32);
        assert_eq!(random_vec(48).unwrap().len(), 48);
        assert!(random_vec(MAX_RANDOM_VEC + 1).is_err());
    }

    #[test]
    fn a_failing_source_fails_the_check_and_the_helpers() {
        assert_eq!(self_check_with(&Failing).unwrap_err().0, "injected failure");
        assert!(random_array_from::<16>(&Failing).is_err());
        assert!(startup_self_check_with(Arc::new(Failing), Duration::from_secs(5)).is_err());
    }

    #[test]
    fn a_source_that_succeeds_with_garbage_is_refused() {
        for fill in [0x00u8, 0xff, 0x55] {
            assert!(self_check_with(&Constant(fill)).is_err(), "constant {fill:#x}");
        }
        assert_eq!(self_check_with(&Cloned::default()).unwrap_err().0, "returned the same block twice");
    }

    #[test]
    fn a_hung_source_times_out_instead_of_hanging_the_start() {
        #[derive(Debug)]
        struct Hangs;
        impl EntropySource for Hangs {
            fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
                std::thread::sleep(Duration::from_secs(3));
                Ok(())
            }
        }
        let started = std::time::Instant::now();
        let err = startup_self_check_with(Arc::new(Hangs), Duration::from_millis(100)).unwrap_err();
        assert!(err.0.contains("in time"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn weak_secrets_are_refused_and_the_error_never_echoes_them() {
        for weak in ["", "short", "unsetunsetunsetunsetunsetunsetunsetunset", "00000000000000000000000000000000", "abababababababababababababababab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
            let err = check_secret_strength("EDGE_LB_REGISTRY_SECRET", weak.as_bytes(), 32).unwrap_err();
            assert!(!weak.is_empty() && !err.0.contains(weak) || weak.is_empty(), "the error must not echo the secret: {err}");
            assert!(err.0.starts_with("EDGE_LB_REGISTRY_SECRET is too weak"), "{err}");
        }
        // Long enough to look random but under the minimum length: refused on length alone.
        let err = check_secret_strength("S", b"Zq8vK2mXp4Ld9RtYw3Hn", 32).unwrap_err();
        assert!(err.0.contains("at least 32 bytes"), "{err}");
        let good = random_hex(24).unwrap();
        check_secret_strength("x", good.as_bytes(), 32).unwrap();
        check_secret_strength("x", b"correct horse battery staple, with a salt of 9QJ4", 32).unwrap();
    }
}
