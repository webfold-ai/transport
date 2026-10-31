//! The cryptographic primitives the transport's secure channel and signed records use.
//!
//! One facade, two backends, one behaviour:
//!
//! - With the `native` feature (the default) every primitive is **`aws-lc-rs`** — FIPS-validated
//!   with the `fips` feature, assembly-optimised, constant-time scalar arithmetic, and
//!   continuously fuzzed/verified upstream.
//! - Without it (the wire-format-only `--no-default-features` core) the same functions fall back
//!   to `hashtrinity::crypto`, so the zero-dependency core still builds.
//!
//! All five algorithms are standardised and deterministic (RFC 8439 ChaCha20-Poly1305, RFC 8032
//! Ed25519 — deterministic signatures —, RFC 7748 X25519), so switching backend changes **no
//! byte on the wire**: the differential tests below assert byte-for-byte equality with
//! `hashtrinity` on random inputs, plus the RFC test vectors, so a regression in either backend
//! is caught here.
//!
//! Measured on one core of a 2.8 GHz Xeon (`cargo run --release --example crypto_bench`), the
//! hand-written implementations were: Ed25519 sign 1.3 ms / verify 4.8 ms (aws-lc: 12 / 46 µs),
//! ChaCha20-Poly1305 4 KiB 266 MB/s (aws-lc 1.7 GB/s), X25519 63 µs (aws-lc 29 µs). The secure
//! channel's per-connection handshake and every sealed frame sit on exactly these.
//!
//! X25519 has one deliberate difference: [`x25519_shared`] returns `None` for a low-order peer
//! point (an all-zero shared secret), which a handshake must treat as failure. The legacy
//! `hashtrinity::crypto::x25519` silently returned zeros.

#[cfg(feature = "native")]
mod imp {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey as SigPublicKey, ED25519};

    fn ed25519_pair(seed: &[u8; 32]) -> Ed25519KeyPair {
        // A 32-byte seed is always a valid Ed25519 private key.
        Ed25519KeyPair::from_seed_unchecked(seed).expect("32-byte Ed25519 seed")
    }

    /// `n` bytes from the system CSPRNG through aws-lc-rs (the FIPS-validated DRBG with the `fips`
    /// feature). A failing RNG panics rather than returning predictable bytes: every caller is a
    /// key, nonce or identifier whose predictability would void the security of the handshake.
    #[must_use]
    pub fn random_bytes(n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        if aws_lc_rs::rand::fill(&mut out).is_err() {
            panic!("the system RNG failed; refusing to continue with predictable key material");
        }
        out
    }

    /// The Ed25519 public key for a 32-byte seed.
    #[must_use]
    pub fn ed25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(ed25519_pair(seed).public_key().as_ref());
        out
    }

    /// Deterministic Ed25519 signature (RFC 8032).
    #[must_use]
    pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(ed25519_pair(seed).sign(msg).as_ref());
        out
    }

    /// Verify an Ed25519 signature. Rejects non-canonical `S` (malleable signatures).
    #[must_use]
    pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        SigPublicKey::new(&ED25519, pubkey).verify(msg, sig).is_ok()
    }

    /// The X25519 public key (`scalar · 9`) for a 32-byte secret.
    #[must_use]
    pub fn x25519_pubkey(secret: &[u8; 32]) -> [u8; 32] {
        let private = PrivateKey::from_private_key(&X25519, secret).expect("32-byte X25519 secret");
        let public = private.compute_public_key().expect("X25519 public key");
        let mut out = [0u8; 32];
        out.copy_from_slice(public.as_ref());
        out
    }

    /// X25519 Diffie-Hellman. `None` if the peer point is of low order (all-zero output).
    #[must_use]
    pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        let private = PrivateKey::from_private_key(&X25519, secret).ok()?;
        let peer = UnparsedPublicKey::new(&X25519, peer_public);
        agreement::agree(&private, peer, (), |shared| {
            let mut out = [0u8; 32];
            out.copy_from_slice(shared);
            Ok(out)
        })
        .ok()
    }

    fn chacha_key(key: &[u8; 32]) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte ChaCha20 key"))
    }

    /// ChaCha20-Poly1305 seal (RFC 8439): ciphertext and detached 16-byte tag.
    #[must_use]
    pub fn chacha20poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = pt.to_vec();
        let tag = chacha_key(key)
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), &mut buf)
            .expect("ChaCha20-Poly1305 seal");
        let mut t = [0u8; 16];
        t.copy_from_slice(tag.as_ref());
        (buf, t)
    }

    /// ChaCha20-Poly1305 open: verifies the tag first, `None` on any tampering.
    #[must_use]
    pub fn chacha20poly1305_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], tag: &[u8; 16], aad: &[u8]) -> Option<Vec<u8>> {
        let mut buf = Vec::with_capacity(ct.len() + 16);
        buf.extend_from_slice(ct);
        buf.extend_from_slice(tag);
        let plain = chacha_key(key).open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), &mut buf).ok()?;
        Some(plain.to_vec())
    }
}

#[cfg(not(feature = "native"))]
mod imp {
    use hashtrinity::crypto as ht;

    /// `n` bytes from the kernel CSPRNG (the zero-dependency core has no aws-lc-rs); panics on
    /// failure, never returning predictable bytes.
    #[must_use]
    pub fn random_bytes(n: usize) -> Vec<u8> {
        ht::rand_bytes(n)
    }

    #[must_use]
    pub fn ed25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
        ht::ed25519_pubkey(seed)
    }
    #[must_use]
    pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        ht::ed25519_sign(seed, msg)
    }
    #[must_use]
    pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        ht::ed25519_verify(pubkey, msg, sig)
    }
    #[must_use]
    pub fn x25519_pubkey(secret: &[u8; 32]) -> [u8; 32] {
        let mut base = [0u8; 32];
        base[0] = 9;
        ht::x25519(secret, &base)
    }
    #[must_use]
    pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        let out = ht::x25519(secret, peer_public);
        out.iter().any(|b| *b != 0).then_some(out)
    }
    #[must_use]
    pub fn chacha20poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        ht::chacha_poly::chacha20poly1305_encrypt(key, nonce, pt, aad)
    }
    #[must_use]
    pub fn chacha20poly1305_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], tag: &[u8; 16], aad: &[u8]) -> Option<Vec<u8>> {
        ht::chacha_poly::chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
    }
}

pub use imp::*;

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use hashtrinity::crypto as ht;

    #[test]
    fn random_bytes_come_from_the_system_rng_and_differ() {
        let (a, b) = (random_bytes(32), random_bytes(32));
        assert_eq!((a.len(), b.len()), (32, 32));
        assert_ne!(a, b);
        assert_ne!(a, vec![0u8; 32]);
    }

    fn rnd<const N: usize>() -> [u8; N] {
        let mut a = [0u8; N];
        a.copy_from_slice(&ht::rand_bytes(N));
        a
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    // ── RFC known-answer tests (independent of either backend) ────────────────────────────

    #[test]
    fn rfc8032_ed25519_test_vectors() {
        // RFC 8032 §7.1 TEST 1 (empty message) and TEST 2 (one byte 0x72).
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (seed, pk, msg, sig) in cases {
            let seed: [u8; 32] = unhex(seed).try_into().unwrap();
            let pk: [u8; 32] = unhex(pk).try_into().unwrap();
            let sig: [u8; 64] = unhex(sig).try_into().unwrap();
            let msg = unhex(msg);
            assert_eq!(ed25519_pubkey(&seed), pk);
            assert_eq!(ed25519_sign(&seed, &msg), sig);
            assert!(ed25519_verify(&pk, &msg, &sig));
            let mut bad = sig;
            bad[10] ^= 1;
            assert!(!ed25519_verify(&pk, &msg, &bad));
        }
    }

    #[test]
    fn rfc7748_x25519_vector() {
        // RFC 7748 §5.2, first vector.
        let k: [u8; 32] = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").try_into().unwrap();
        let u: [u8; 32] = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").try_into().unwrap();
        let want: [u8; 32] = unhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").try_into().unwrap();
        assert_eq!(x25519_shared(&k, &u), Some(want));
    }

    #[test]
    fn rfc8439_chacha20_poly1305_aead_vector() {
        // RFC 8439 §2.8.2.
        let key: [u8; 32] = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").try_into().unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let (ct, tag) = chacha20poly1305_encrypt(&key, &nonce, pt, &aad);
        assert_eq!(&ct[..16], &unhex("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(tag.to_vec(), unhex("1ae10b594f09e26a7e902ecbd0600691"));
        assert_eq!(chacha20poly1305_decrypt(&key, &nonce, &ct, &tag, &aad).as_deref(), Some(&pt[..]));
    }

    // ── differential: aws-lc-rs must equal hashtrinity byte for byte ──────────────────────

    #[test]
    fn ed25519_matches_hashtrinity_on_random_inputs() {
        for len in [0usize, 1, 31, 32, 33, 255, 1024, 4097] {
            let seed = rnd::<32>();
            let msg = ht::rand_bytes(len);
            assert_eq!(ed25519_pubkey(&seed), ht::ed25519_pubkey(&seed));
            let sig = ed25519_sign(&seed, &msg);
            assert_eq!(sig, ht::ed25519_sign(&seed, &msg), "deterministic signatures must agree (len {len})");
            let pk = ed25519_pubkey(&seed);
            assert!(ed25519_verify(&pk, &msg, &sig));
            assert!(ht::ed25519_verify(&pk, &msg, &sig), "hashtrinity accepts aws-lc signatures");
        }
    }

    #[test]
    fn ed25519_rejects_what_it_must() {
        let seed = rnd::<32>();
        let pk = ed25519_pubkey(&seed);
        let sig = ed25519_sign(&seed, b"msg");
        assert!(!ed25519_verify(&pk, b"other", &sig));
        assert!(!ed25519_verify(&ed25519_pubkey(&rnd::<32>()), b"msg", &sig));
        // Malleability: S + L is the same point equation but a non-canonical S; must be refused.
        let l: [u8; 32] = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").try_into().unwrap();
        let mut s_plus_l = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
            s_plus_l[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert!(!ed25519_verify(&pk, b"msg", &s_plus_l), "non-canonical S must not verify");
    }

    #[test]
    fn x25519_matches_hashtrinity_on_random_inputs() {
        let mut base = [0u8; 32];
        base[0] = 9;
        for _ in 0..64 {
            let a = rnd::<32>();
            let b = rnd::<32>();
            assert_eq!(x25519_pubkey(&a), ht::x25519(&a, &base));
            let pb = x25519_pubkey(&b);
            assert_eq!(x25519_shared(&a, &pb), Some(ht::x25519(&a, &pb)));
            // Both sides of a DH agree.
            assert_eq!(x25519_shared(&a, &x25519_pubkey(&b)), x25519_shared(&b, &x25519_pubkey(&a)));
        }
    }

    #[test]
    fn x25519_refuses_low_order_peer_points() {
        let secret = rnd::<32>();
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(x25519_shared(&secret, &zero), None, "the identity point yields an all-zero secret");
        assert_eq!(x25519_shared(&secret, &one), None, "the order-1/order-4 point is refused too");
    }

    #[test]
    fn chacha_matches_hashtrinity_and_authenticates_every_input() {
        for len in [0usize, 1, 15, 16, 63, 64, 65, 1000, 4096, 16384] {
            let key = rnd::<32>();
            let nonce = rnd::<12>();
            let pt = ht::rand_bytes(len);
            let aad = ht::rand_bytes(len % 37);
            let (ct, tag) = chacha20poly1305_encrypt(&key, &nonce, &pt, &aad);
            let (ht_ct, ht_tag) = ht::chacha_poly::chacha20poly1305_encrypt(&key, &nonce, &pt, &aad);
            assert_eq!((&ct, tag), (&ht_ct, ht_tag), "len {len}");
            assert_eq!(chacha20poly1305_decrypt(&key, &nonce, &ht_ct, &ht_tag, &aad).as_deref(), Some(&pt[..]));
            assert_eq!(ht::chacha_poly::chacha20poly1305_decrypt(&key, &nonce, &ct, &tag, &aad).as_deref(), Some(&pt[..]));

            // Any single-bit change in ciphertext, tag, aad or nonce must fail.
            if !ct.is_empty() {
                let mut bad = ct.clone();
                bad[len / 2] ^= 1;
                assert!(chacha20poly1305_decrypt(&key, &nonce, &bad, &tag, &aad).is_none());
            }
            let mut bad_tag = tag;
            bad_tag[0] ^= 1;
            assert!(chacha20poly1305_decrypt(&key, &nonce, &ct, &bad_tag, &aad).is_none());
            let mut bad_aad = aad.clone();
            bad_aad.push(0);
            assert!(chacha20poly1305_decrypt(&key, &nonce, &ct, &tag, &bad_aad).is_none());
            let mut bad_nonce = nonce;
            bad_nonce[11] ^= 1;
            assert!(chacha20poly1305_decrypt(&key, &bad_nonce, &ct, &tag, &aad).is_none());
        }
    }
}
