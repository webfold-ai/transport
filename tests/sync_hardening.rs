//! Hostile-input contracts of the sync module, checked through its public surface: archive
//! restore refuses traversal and escaping symlinks, and the certificate chain validator refuses
//! a chain that runs through a certificate which is not a CA. The unit tests beside the code
//! cover more cases; these pin what a caller relies on.

use std::fs;
use std::path::{Path, PathBuf};

use transport::sync::archive;
use transport::sync::tls::x509::{self, TrustStore};

/// The SFAR magic (see `sync::archive`), followed by hand-built entries.
const MAGIC: &[u8] = b"SFAR1\n";

/// 2027-01-15: inside the validity window of every fixture certificate.
const NOW: i64 = 1_800_000_000;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sync_hardening_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn path_field(kind: u8, path: &str) -> Vec<u8> {
    let mut e = vec![kind];
    e.extend_from_slice(&(path.len() as u16).to_be_bytes());
    e.extend_from_slice(path.as_bytes());
    e
}

fn file(path: &str, data: &[u8]) -> Vec<u8> {
    let mut e = path_field(b'f', path);
    e.extend_from_slice(&0o644u32.to_be_bytes()); // mode
    e.extend_from_slice(&0u64.to_be_bytes()); // mtime seconds
    e.extend_from_slice(&0u32.to_be_bytes()); // mtime nanoseconds
    e.extend_from_slice(&(data.len() as u64).to_be_bytes());
    e.extend_from_slice(data);
    e
}

fn link(path: &str, target: &str) -> Vec<u8> {
    let mut e = path_field(b'l', path);
    e.extend_from_slice(&(target.len() as u32).to_be_bytes());
    e.extend_from_slice(target.as_bytes());
    e
}

fn dir(path: &str) -> Vec<u8> {
    path_field(b'd', path)
}

fn archive_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    for e in entries {
        b.extend_from_slice(e);
    }
    b
}

/// Both restore paths must refuse the archive.
fn both_refuse(blob: &[u8], root: &Path) {
    assert!(
        archive::unpack(blob, &root.join("a")).is_err(),
        "unpack accepted a hostile archive"
    );
    assert!(
        archive::unpack_stream(&mut &blob[..], &root.join("b")).is_err(),
        "unpack_stream accepted a hostile archive"
    );
}

#[test]
fn archive_restore_refuses_parent_and_absolute_paths() {
    let base = scratch("traversal");
    let abs = base.join("abs_escape");
    let abs_str = abs.to_str().unwrap();
    for blob in [
        archive_of(&[file("../escape", b"pwn")]),
        archive_of(&[file("a/../../escape", b"pwn")]),
        archive_of(&[dir("../escape_dir")]),
        archive_of(&[file(abs_str, b"pwn")]),
    ] {
        both_refuse(&blob, &base);
    }
    assert!(!base.join("escape").exists(), "a file escaped the root");
    assert!(
        !base.join("escape_dir").exists(),
        "a directory escaped the root"
    );
    assert!(!abs.exists(), "an absolute entry was written");
    let _ = fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn archive_restore_refuses_absolute_and_escaping_symlinks() {
    let base = scratch("symlinks");
    let outside = base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let outside_str = outside.to_str().unwrap();

    // An absolute link target is refused outright.
    both_refuse(&archive_of(&[link("abs", outside_str)]), &base);

    // A relative target that climbs out of the root is refused, and nothing is written through it.
    both_refuse(
        &archive_of(&[link("up", "../outside"), file("up/pwned", b"pwn")]),
        &base,
    );
    // The same through an absolute link followed by a file beneath it.
    both_refuse(
        &archive_of(&[link("d", outside_str), file("d/pwned", b"pwn")]),
        &base,
    );
    assert!(
        !outside.join("pwned").exists(),
        "a file was written through an escaping symlink"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn a_chain_through_a_certificate_that_is_not_a_ca_is_rejected() {
    // The root is the only trust anchor. `attacker` is an ordinary CA:false leaf; `forged` is
    // signed with its key for victim.example. `forged` presented above `attacker` makes
    // `attacker` an intermediate, and it is not allowed to sign anything.
    let trust = TrustStore::from_pem(include_str!("fixtures/tls/root.pem"));
    let der = |pem: &str| transport::pem::blocks(pem, "CERTIFICATE").remove(0);
    let attacker = der(include_str!("fixtures/tls/attacker.pem"));
    let forged = der(include_str!("fixtures/tls/forged.pem"));

    // Control: the attacker's own leaf validates for its own name.
    assert!(
        x509::validate(
            std::slice::from_ref(&attacker),
            "attacker.example",
            NOW,
            &trust
        )
        .is_ok(),
        "control chain rejected"
    );
    let err = x509::validate(&[forged, attacker], "victim.example", NOW, &trust)
        .err()
        .expect("a chain through a non-CA intermediate was accepted");
    assert!(err.contains("not a CA"), "{err}");
}
