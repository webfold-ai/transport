//! `syncfold dd`: a dry run never touches the network, a keyed server drops a version 1
//! peer without creating its destination, and a non-loopback bind needs a key.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const KEY: &[u8] = b"0123456789abcdef-test-key";

#[test]
fn dd_dry_run_to_tcp_does_not_connect() {
    let dir = std::env::temp_dir().join(format!("syncfold_dd_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.img");
    std::fs::write(&src, vec![7u8; 64 * 1024]).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = Command::new(env!("CARGO_BIN_EXE_syncfold"))
        .args([
            "dd",
            src.to_str().unwrap(),
            &format!("tcp://127.0.0.1:{port}"),
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("dry run"));
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => panic!("accept: {e}"),
        Ok(_) => panic!("a dry run connected to the destination"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("syncfold_dd_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Connect to the server the test started, retrying while it comes up.
fn connect(port: u16) -> TcpStream {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect {addr}: {e}"),
        }
    }
}

/// A server process that is killed and reaped when the test ends, even if an assertion fails.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve_cmd(dst: &Path, port: u16, extra: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_syncfold"));
    c.args([
        "dd",
        "serve",
        dst.to_str().unwrap(),
        "--port",
        &port.to_string(),
    ])
    .args(extra)
    .env_remove("SYNCFOLD_DD_KEY");
    c
}

#[test]
fn a_v1_peer_is_dropped_by_a_keyed_server_and_the_destination_is_never_created() {
    let d = scratch("v1");
    let dst = d.join("dst.img");
    let key = d.join("key");
    std::fs::write(&key, KEY).unwrap();
    let src = d.join("src.img");
    std::fs::write(&src, vec![0x5au8; 64 * 1024]).unwrap();
    let port = free_port();
    let mut server = Reaped(
        serve_cmd(&dst, port, &["--key-file", key.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    // A version 1 HELLO: the server offers no challenge to it and must drop the connection.
    let mut s = connect(port);
    let mut hello = b"SFDD".to_vec();
    hello.push(1);
    hello.extend_from_slice(&(64 * 1024u64).to_le_bytes());
    hello.extend_from_slice(&0u32.to_le_bytes());
    s.write_all(&hello).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut answer = Vec::new();
    s.read_to_end(&mut answer).unwrap();
    assert!(answer.is_empty(), "a v1 peer was answered: {answer:?}");
    assert!(
        !dst.exists(),
        "a v1 peer caused the destination to be created"
    );

    // The server keeps listening: a correctly keyed v2 push completes and is written.
    let push = Command::new(env!("CARGO_BIN_EXE_syncfold"))
        .args([
            "dd",
            src.to_str().unwrap(),
            &format!("tcp://127.0.0.1:{port}"),
            "--key-file",
            key.to_str().unwrap(),
            "-q",
        ])
        .env_remove("SYNCFOLD_DD_KEY")
        .output()
        .unwrap();
    assert!(
        push.status.success(),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );
    assert!(server.0.wait().unwrap().success());
    let mut log = String::new();
    server
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(
        log.contains("unsupported dd protocol version (need 2)"),
        "{log}"
    );
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        std::fs::read(&src).unwrap(),
        "the keyed push did not land"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_non_loopback_bind_without_a_key_exits_2_before_listening() {
    let d = scratch("bindkey");
    let dst = d.join("dst.img");
    let out = serve_cmd(&dst, free_port(), &["--bind", "0.0.0.0"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("refusing to listen on 0.0.0.0 without authentication"),
        "{err}"
    );
    assert!(!dst.exists(), "the destination was created");
    let _ = std::fs::remove_dir_all(&d);
}
