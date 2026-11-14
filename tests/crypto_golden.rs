//! Golden cross-checks for the primitives behind the transport's wire format and identities.
//!
//! Every expected value here is either (a) an RFC / FIPS published test vector, or (b) a value
//! produced by the previous in-house implementation (`apeiron::map::hashtrinity::crypto`) on fixed inputs and
//! independently re-derived with Python 3 `cryptography` (`python3 -I`). The migration to
//! aws-lc-rs must reproduce every byte: existing peers interoperate only if the wire bytes do not
//! change.
//!
//! Provenance of the non-RFC goldens:
//! - `QUIC_SEALED` (tests/fixtures/quic_seal_1200.hex): quic_seal over a 1200-byte payload, key
//!   `(7i+3)`, iv `0xa0+i`, pn `0x1_0000_0042`, 20-byte header `0xc0|i`. Old code and pyca agree.
//! - `HP_MASK`, `X25519_*`, `SHA256_PAYLOAD`, `HMAC_PAYLOAD`: same fixed inputs, old code == pyca.
//! - `ECDSA_*`: signed by pyca with a fixed P-256 key, verified here (independent signer).
//!
//! The `#[ignore]`d `packet_seal_open_timing` is a release-mode bench, not a correctness check:
//! `cargo test --release --test crypto_golden -- --ignored --nocapture`.

use transport::prim as p;
// The previous in-house implementation: used only as the reference in the timing bench below.
use apeiron::map::hashtrinity::crypto as ht;

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    let v = hex(s);
    assert_eq!(v.len(), N, "expected {N} bytes");
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    a
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The fixed QUIC packet inputs shared with the Python differential (see module docs).
fn quic_inputs() -> ([u8; 32], [u8; 12], u64, Vec<u8>, Vec<u8>) {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let iv: [u8; 12] = core::array::from_fn(|i| 0xa0 + i as u8);
    let pn: u64 = 0x0000_0001_0000_0042;
    let header: Vec<u8> = (0..20u8).map(|i| 0xc0 | i).collect();
    let payload: Vec<u8> = (0..1200usize).map(|i| ((i * 31 + 7) % 256) as u8).collect();
    (key, iv, pn, header, payload)
}

const QUIC_SEALED: &str = include_str!("fixtures/quic_seal_1200.hex");

// ── RFC / FIPS published vectors ────────────────────────────────────────────────────────────

#[test]
fn rfc8439_2_8_2_chacha20poly1305_aead_vector() {
    // RFC 8439 §2.8.2.
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce: [u8; 12] = arr("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let (ct, tag) = p::chacha20poly1305_encrypt(&key, &nonce, pt, &aad);
    assert_eq!(to_hex(&ct), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
    assert_eq!(to_hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
    assert_eq!(
        p::chacha20poly1305_decrypt(&key, &nonce, &ct, &tag, &aad).as_deref(),
        Some(&pt[..])
    );
}

#[test]
fn rfc7748_x25519_function_vector_and_diffie_hellman() {
    // RFC 7748 §5.2 first vector (raw u-coordinate ladder).
    let scalar: [u8; 32] = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u: [u8; 32] = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    assert_eq!(
        to_hex(&p::x25519_shared(&scalar, &u).unwrap()),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    );
    // RFC 7748 §6.1 Alice / Bob.
    let alice: [u8; 32] = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob: [u8; 32] = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    assert_eq!(
        to_hex(&p::x25519_pubkey(&alice)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        to_hex(&p::x25519_pubkey(&bob)),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(
        to_hex(
            &p::x25519_shared(
                &alice,
                &arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            )
            .unwrap()
        ),
        shared
    );
    assert_eq!(
        to_hex(
            &p::x25519_shared(
                &bob,
                &arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
            )
            .unwrap()
        ),
        shared
    );
}

#[test]
fn rfc4231_hmac_sha256_test_case_2() {
    let mac = p::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        to_hex(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn fips180_sha256_abc() {
    assert_eq!(
        to_hex(&p::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rfc8032_ed25519_public_key_test_1() {
    let seed: [u8; 32] = arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    assert_eq!(
        to_hex(&p::ed25519_pubkey(&seed)),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
}

#[test]
fn rfc9001_a5_header_protection_mask() {
    // RFC 9001 Appendix A.5 (ChaCha20 header protection).
    let hp: [u8; 32] = arr("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    let sample: [u8; 16] = arr("5e5cd55c41f69080575d7999c25a5bfb");
    assert_eq!(to_hex(&p::quic_hp_mask(&hp, &sample)), "aefefe7d03");
}

// ── Pinned old-implementation outputs on fixed inputs (+ Python re-derivation) ─────────────

#[test]
fn quic_packet_seal_golden_1200_bytes_and_open_round_trip() {
    let (key, iv, pn, header, payload) = quic_inputs();
    let sealed = p::quic_seal(&key, &iv, pn, &header, &payload);
    assert_eq!(sealed.len(), 1216);
    assert_eq!(to_hex(&sealed), QUIC_SEALED.trim());
    assert_eq!(
        p::quic_open(&key, &iv, pn, &header, &sealed).as_deref(),
        Some(&payload[..])
    );
    // Wrong packet number, wrong AAD, flipped tag bit: all rejected.
    assert!(p::quic_open(&key, &iv, pn + 1, &header, &sealed).is_none());
    assert!(p::quic_open(&key, &iv, pn, &header[..19], &sealed).is_none());
    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(p::quic_open(&key, &iv, pn, &header, &bad).is_none());
}

#[test]
fn quic_header_protection_mask_golden() {
    let hp: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
    let sample: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(9));
    assert_eq!(to_hex(&p::quic_hp_mask(&hp, &sample)), "66da7d9c15");
}

#[test]
fn x25519_golden_on_fixed_scalar_and_peer() {
    let (key, _, _, _, _) = quic_inputs();
    assert_eq!(
        to_hex(&p::x25519_pubkey(&key)),
        "bb50ff9e82a574cfbf820e97f60fb9c143ec7415cf514f8cfd98eff59e059614"
    );
    let peer: [u8; 32] = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    assert_eq!(
        to_hex(&p::x25519_shared(&key, &peer).unwrap()),
        "264f646c3f7363b622cbe69dec58773217af6e07623a3c92bc6132e5eb36f570"
    );
}

#[test]
fn sha256_and_hmac_golden_on_1200_byte_payload() {
    let (_, _, _, header, payload) = quic_inputs();
    assert_eq!(
        to_hex(&p::sha256(&payload)),
        "a952ade4894b1a37001ff320a7ddc6c2ad5cf943748e407fb770787f8420a39a"
    );
    assert_eq!(
        to_hex(&p::hmac_sha256(&header, &payload)),
        "ac59b57949eea014851dfc26fc649bf369b7aa9a4c934b3b38da3f66b7157f1d"
    );
}

// ── ECDSA P-256 over SHA-256, signed by pyca (independent signer) ─────────────────────────

const ECDSA_PUB: &str = "c9da820ca7099163fa70eddaf5a2c88a70c29feb1617e6977dfedf9cf7546ac3c5a96aa290a7ffccce4b84afacda743a3322721068aa9c8b1770874d560950b8";
const ECDSA_MSG: &str = "7b2270726f746563746564223a2265794a68624763694f694a46557a49314e694a39222c227061796c6f6164223a225a476c6d5a6d56795a57353061574673227d2e0726456483a2c1e0ff1e3d5c7b9ab9d8f71635547392b1d0ef0e2d4c6b8aa9c8e70625446382a1c0dffe1d3c5b7a99b8d7f61534537291b0cfee0d2c4b6a89a8";
const ECDSA_SIG: &str = "65954323286c810957d92ee5fd5615f2fba984a7f4953a73b87827bb3279634cfe415a41f271fc1bc11db1b1aaff7e4357872cc4610d77125a7909571b298a9a";

#[test]
fn ecdsa_p256_verifies_pyca_signature_and_rejects_tampering() {
    let pk: [u8; 64] = arr(ECDSA_PUB);
    let msg = hex(ECDSA_MSG);
    let sig: [u8; 64] = arr(ECDSA_SIG);
    assert!(p::ecdsa_p256_sha256_verify(&pk, &msg, &sig));
    let mut other = msg.clone();
    other[0] ^= 1;
    assert!(!p::ecdsa_p256_sha256_verify(&pk, &other, &sig));
    let mut bad_sig = sig;
    bad_sig[40] ^= 1;
    assert!(!p::ecdsa_p256_sha256_verify(&pk, &msg, &bad_sig));
}

// ── Timing (release only, ignored): per-packet seal/open cost on a 1200-byte payload ───────

#[test]
#[ignore = "timing bench: cargo test --release --test crypto_golden -- --ignored --nocapture"]
fn packet_seal_open_timing() {
    use std::hint::black_box;
    use std::time::Instant;
    const N: u32 = 20_000;
    let (key, iv, pn, header, payload) = quic_inputs();
    let sealed = p::quic_seal(&key, &iv, pn, &header, &payload);
    assert_eq!(
        sealed,
        ht::quic::quic_seal(&key, &iv, pn, &header, &payload),
        "same bytes before timing"
    );

    fn per_op(mut f: impl FnMut()) -> f64 {
        let t = Instant::now();
        for _ in 0..N {
            f();
        }
        t.elapsed().as_secs_f64() * 1e6 / f64::from(N)
    }
    let (mut old_seal, mut old_open, mut new_seal, mut new_open) =
        (f64::MAX, f64::MAX, f64::MAX, f64::MAX);
    for _ in 0..3 {
        old_seal = old_seal.min(per_op(|| {
            black_box(ht::quic::quic_seal(
                &key,
                &iv,
                black_box(pn),
                &header,
                black_box(&payload),
            ));
        }));
        old_open = old_open.min(per_op(|| {
            black_box(ht::quic::quic_open(
                &key,
                &iv,
                black_box(pn),
                &header,
                black_box(&sealed),
            ));
        }));
        new_seal = new_seal.min(per_op(|| {
            black_box(p::quic_seal(
                &key,
                &iv,
                black_box(pn),
                &header,
                black_box(&payload),
            ));
        }));
        new_open = new_open.min(per_op(|| {
            black_box(p::quic_open(
                &key,
                &iv,
                black_box(pn),
                &header,
                black_box(&sealed),
            ));
        }));
    }
    println!("1200 B packet, best of 3 x {N}:");
    println!("  hashtrinity (old): seal {old_seal:.2} us/op, open {old_open:.2} us/op");
    println!("  prim / aws-lc-rs:  seal {new_seal:.2} us/op, open {new_open:.2} us/op");
}
