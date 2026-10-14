//! hashtrinity (hand-written) vs aws-lc-rs on the primitives this stack uses on its hot paths.
//!
//! `cargo run --release --example crypto_bench --features native`
//!
//! Wall-clock micro-benchmarks, single thread, best of several rounds: they compare the two
//! implementations on THIS machine; they are not a substitute for load testing the data plane.
//! `black_box` keeps the optimiser from deleting the work.

use std::hint::black_box;
use std::time::{Duration, Instant};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519};
use hashtrinity::crypto as ht;

/// Run `f` repeatedly for ~`budget`, in 5 rounds; return the best ns/op.
fn bench(budget: Duration, mut f: impl FnMut()) -> f64 {
    // calibrate
    let t = Instant::now();
    let mut n = 0u64;
    while t.elapsed() < Duration::from_millis(20) {
        f();
        n += 1;
    }
    let per_round = ((n as f64) * (budget.as_secs_f64() / 5.0) / 0.020).max(1.0) as u64;
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..per_round {
            f();
        }
        best = best.min(t.elapsed().as_nanos() as f64 / per_round as f64);
    }
    best
}

fn row(name: &str, ht_ns: f64, lc_ns: f64, bytes: Option<usize>) {
    let tp = |ns: f64| bytes.map_or(String::new(), |b| format!("{:>9.1} MB/s", b as f64 / ns * 1000.0));
    println!(
        "{name:<34} hashtrinity {:>12.0} ns {:>14}   aws-lc-rs {:>12.0} ns {:>14}   speedup {:>8.1}x",
        ht_ns, tp(ht_ns), lc_ns, tp(lc_ns), ht_ns / lc_ns
    );
}

fn main() {
    let budget = Duration::from_millis(1500);
    let rng = SystemRandom::new();
    println!("# hashtrinity vs aws-lc-rs ({} {})", std::env::consts::ARCH, std::env::consts::OS);

    // ── hashes ──
    for size in [64usize, 4096, 65536] {
        let data = vec![0xabu8; size];
        let a = bench(budget, || { black_box(ht::sha256(black_box(&data))); });
        let b = bench(budget, || { black_box(digest::digest(&digest::SHA256, black_box(&data))); });
        row(&format!("sha256 {size}B"), a, b, Some(size));
    }

    // ── AEAD (the transport's sealed frame is ChaCha20-Poly1305 over <=4KiB chunks) ──
    let key = [7u8; 32];
    let nonce_bytes = [1u8; 12];
    for size in [64usize, 1024, 4096, 16384] {
        let pt = vec![0x5au8; size];
        let a = bench(budget, || { black_box(ht::chacha_poly::chacha20poly1305_encrypt(&key, &nonce_bytes, black_box(&pt), b"aad")); });
        let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());
        let b = bench(budget, || {
            let mut buf = pt.clone();
            let tag = k.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(b"aad"), &mut buf).unwrap();
            black_box((buf, tag.as_ref().len()));
        });
        row(&format!("chacha20-poly1305 seal {size}B"), a, b, Some(size));
    }
    for size in [4096usize, 16384] {
        let pt = vec![0x5au8; size];
        let a = bench(budget, || { black_box(ht::aes_gcm::aes256_gcm_encrypt(&key, &nonce_bytes, black_box(&pt), b"aad")); });
        let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap());
        let b = bench(budget, || {
            let mut buf = pt.clone();
            let tag = k.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(b"aad"), &mut buf).unwrap();
            black_box((buf, tag.as_ref().len()));
        });
        row(&format!("aes-256-gcm seal {size}B"), a, b, Some(size));
    }

    // ── key exchange / signatures (per handshake) ──
    let sk = [9u8; 32];
    let peer_sk = [3u8; 32];
    let peer_pub = ht::x25519(&peer_sk, &{ let mut b = [0u8; 32]; b[0] = 9; b });
    let a = bench(budget, || { black_box(ht::x25519(black_box(&sk), black_box(&peer_pub))); });
    let lc_priv = aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::X25519).unwrap();
    let lc_peer = aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::X25519).unwrap().compute_public_key().unwrap();
    let b = bench(budget, || {
        let peer = aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_rs::agreement::X25519, lc_peer.as_ref());
        black_box(aws_lc_rs::agreement::agree(&lc_priv, &peer, (), |k| Ok(k.len())).unwrap());
    });
    row("x25519 agree", a, b, None);

    let msg = vec![0x42u8; 256];
    let ht_pk = ht::ed25519_pubkey(&sk);
    let ht_sig = ht::ed25519_sign(&sk, &msg);
    let a = bench(budget, || { black_box(ht::ed25519_sign(black_box(&sk), black_box(&msg))); });
    let lc_ed = Ed25519KeyPair::from_seed_unchecked(&sk).unwrap();
    let b = bench(budget, || { black_box(lc_ed.sign(black_box(&msg))); });
    row("ed25519 sign 256B", a, b, None);
    let a = bench(budget, || { black_box(ht::ed25519_verify(&ht_pk, &msg, &ht_sig)); });
    let lc_pk = UnparsedPublicKey::new(&ED25519, lc_ed.public_key().as_ref());
    let lc_sig = lc_ed.sign(&msg);
    let b = bench(budget, || { black_box(lc_pk.verify(&msg, lc_sig.as_ref()).is_ok()); });
    row("ed25519 verify 256B", a, b, None);

    let p256 = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let digest32 = ht::sha256(&msg);
    let mut ht_sk = [0u8; 32];
    {
        use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
        let bin: EcPrivateKeyBin<'static> = p256.private_key().as_be_bytes().unwrap();
        ht_sk.copy_from_slice(bin.as_ref());
    }
    let a = bench(budget, || { black_box(ht::ecdsa_p256_sign(black_box(&ht_sk), black_box(&digest32))); });
    let b = bench(budget, || { black_box(p256.sign(&rng, black_box(&msg)).unwrap()); });
    row("ecdsa p256 sign (TLS handshake)", a, b, None);
    let ht_pub: [u8; 64] = p256.public_key().as_ref()[1..].try_into().unwrap();
    let ht_s = ht::ecdsa_p256_sign(&ht_sk, &digest32);
    let a = bench(budget, || { black_box(ht::ecdsa_p256_verify(&ht_pub, &digest32, &ht_s)); });
    let lc_s = p256.sign(&rng, &msg).unwrap();
    let lc_v = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, p256.public_key().as_ref());
    let b = bench(budget, || { black_box(lc_v.verify(&msg, lc_s.as_ref()).is_ok()); });
    row("ecdsa p256 verify", a, b, None);
}
