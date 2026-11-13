//! The real `meshd` binary, as a process: start, publish, resolve, DNS, SIGTERM, restart.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use transport::dialkey::{self, native_keypair, DialkeyServiceInfo};
use transport::dns::{Flags, Message, Name, Question, RData, RecordType};
use transport::pkarr::RelayClient;

const BIN: &str = env!("CARGO_BIN_EXE_meshd");

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Meshd {
    child: Child,
    http: u16,
    dns: u16,
}

impl Meshd {
    fn start(dir: &std::path::Path, extra: &[(&str, String)]) -> Meshd {
        let (http, dns) = (free_port(), free_port());
        let mut cmd = Command::new(BIN);
        cmd.env("MESHD_HTTP_BIND", format!("127.0.0.1:{http}"))
            .env("MESHD_DNS_BIND", format!("127.0.0.1:{dns}"))
            .env("MESHD_DATA_DIR", dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let child = cmd.spawn().unwrap();
        let m = Meshd { child, http, dns };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !m.healthy() {
            assert!(Instant::now() < deadline, "meshd did not become healthy");
            std::thread::sleep(Duration::from_millis(50));
        }
        m
    }

    fn healthy(&self) -> bool {
        Command::new(BIN)
            .arg("--healthcheck")
            .env("MESHD_HTTP_BIND", format!("0.0.0.0:{}", self.http))
            .status()
            .is_ok_and(|s| s.success())
    }

    fn client(&self) -> RelayClient {
        RelayClient::with_relays(vec![format!("http://127.0.0.1:{}", self.http)])
    }

    /// SIGTERM, then wait: a clean stop exits 0.
    fn stop(mut self) -> bool {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.success();
            }
            assert!(Instant::now() < deadline, "meshd ignored SIGTERM");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Meshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn svc(port: u16) -> DialkeyServiceInfo {
    DialkeyServiceInfo {
        service: "_billing._tcp".into(),
        port,
        metadata: Default::default(),
    }
}

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("meshd-bin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn publish_resolve_dns_stop_restart() {
    let dir = tmp("e2e");
    let m = Meshd::start(&dir, &[]);

    dialkey::publish(&m.client(), "plane-a", IP, &[svc(7000)])
        .await
        .unwrap();
    let got = dialkey::resolve(&m.client(), "plane-a", "_billing._tcp")
        .await
        .unwrap();
    assert_eq!(got.peer_addr.port, 7000);

    // The same record, as DNS.
    let key = native_keypair("plane-a").public_key().to_z32();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut q = Message {
        id: 9,
        ..Message::default()
    };
    q.flags = Flags {
        recursion_desired: true,
        ..Flags::default()
    };
    q.questions.push(Question::new(
        Name::from_ascii(&format!("{key}.mesh.internal")).unwrap(),
        RecordType::A,
    ));
    sock.send_to(&q.to_bytes(), format!("127.0.0.1:{}", m.dns))
        .await
        .unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("dns reply")
        .unwrap();
    let reply = Message::from_bytes(&buf[..n]).unwrap();
    assert!(
        matches!(reply.answers.as_slice(), [r] if r.data == RData::A(Ipv4Addr::new(10, 1, 2, 3))),
        "{reply:?}"
    );

    assert!(m.stop(), "SIGTERM is a clean exit");

    // A new process on the same data directory still has the record.
    let again = Meshd::start(&dir, &[]);
    let got = dialkey::resolve(&again.client(), "plane-a", "_billing._tcp")
        .await
        .expect("persisted across restart");
    assert_eq!(got.peer_addr.port, 7000);
    drop(again);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_allowlist_file_closes_publishing() {
    let dir = tmp("allow");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("allow.txt");
    std::fs::write(
        &file,
        format!(
            "# who may publish\n{}  # plane-a\n\n",
            native_keypair("plane-a").public_key().to_z32()
        ),
    )
    .unwrap();
    let m = Meshd::start(
        &dir.join("data"),
        &[("MESHD_ALLOW_KEYS_FILE", file.display().to_string())],
    );
    assert!(dialkey::publish(&m.client(), "plane-a", IP, &[svc(1)])
        .await
        .is_ok());
    assert!(dialkey::publish(&m.client(), "intruder", IP, &[svc(1)])
        .await
        .is_err());
    drop(m);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_configuration_fails_loudly_and_dns_can_be_turned_off() {
    let dir = tmp("cfg");
    let bad = |k: &str, v: &str| {
        let out = Command::new(BIN)
            .env("MESHD_DATA_DIR", "memory")
            .env("MESHD_HTTP_BIND", format!("127.0.0.1:{}", free_port()))
            .env(k, v)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for (k, v) in [
        ("MESHD_MAX_KEYS", "lots"),
        ("MESHD_MAX_AGE_SECS", "-1"),
        ("MESHD_ALLOW_KEYS_FILE", "/nonexistent"),
        ("MESHD_ZONE", "a..b"),
    ] {
        let (ok, err) = bad(k, v);
        assert!(!ok && err.contains(k), "{k}={v}: {err}");
    }
    // A key file with a bad line names the line.
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("k.txt");
    std::fs::write(&f, "good-or-not\n").unwrap();
    let (ok, err) = bad("MESHD_ALLOW_KEYS_FILE", f.to_str().unwrap());
    assert!(!ok && err.contains("k.txt:1"), "{err}");

    let relay_only = Meshd::start(&dir.join("d"), &[("MESHD_DNS_BIND", "off".into())]);
    assert!(relay_only.healthy());
    drop(relay_only);
    let _ = std::fs::remove_dir_all(&dir);
}
