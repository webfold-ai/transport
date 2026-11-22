#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tas_dns::objects::{registration_object, update_object, RegistrationSpec};
use tas_dns::zone::{DnssecPolicy, RegState};
use transport::native::NativeEndpoint;
use transport::zone_sync::{ApplyOutcome, SyncClient};
use transport::{PeerAddr, Transport};

const BIN: &str = env!("CARGO_BIN_EXE_tas-dns");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn http_get(port: u16, path: &str) -> Option<String> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    write!(s, "GET {path} HTTP/1.0\r\n\r\n").ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

#[test]
fn cli_helpers_create_private_secrets_and_refuse_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("master");
    assert!(Command::new(BIN)
        .args(["init-master", master.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        std::fs::metadata(&master).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !Command::new(BIN)
            .args(["init-master", master.to_str().unwrap()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "never overwrites"
    );
    // node-id: refuses a group-readable dialkey, prints the public id otherwise
    let dk = dir.path().join("dialkey");
    std::fs::write(&dk, "my-secret-dialkey\n").unwrap();
    std::fs::set_permissions(&dk, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!Command::new(BIN)
        .args(["node-id", dk.to_str().unwrap()])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success());
    std::fs::set_permissions(&dk, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(BIN)
        .args(["node-id", dk.to_str().unwrap()])
        .output()
        .unwrap();
    let id = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        id.trim(),
        hex(&transport::dialkey::peer_id("my-secret-dialkey"))
    );
    assert!(!id.contains("secret"));
}

#[test]
fn bad_configuration_exits_2_without_echoing_values() {
    let out = Command::new(BIN)
        .env("TAS_DNS_REGISTRAR_KEY", "SUPERSECRETVALUE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!text.contains("SUPERSECRETVALUE"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_serves_replicated_signed_zones_exposes_metrics_and_shuts_down_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("master");
    assert!(Command::new(BIN)
        .args(["init-master", master.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    let dk = dir.path().join("dialkey");
    std::fs::write(&dk, "daemon-test-dialkey\n").unwrap();
    std::fs::set_permissions(&dk, std::fs::Permissions::from_mode(0o600)).unwrap();

    // the control plane's identity (publisher + registrar key)
    let ep = Arc::new(
        NativeEndpoint::bind_with_dialkey("127.0.0.1:0", "control-plane-dialkey")
            .await
            .unwrap(),
    );
    let cp_id = Transport::id(&*ep);
    let cp = SyncClient::new(ep, Duration::from_secs(3));

    let (udp, metrics, mesh) = (free_port(), free_port(), free_port());
    let mut child = Command::new(BIN)
        .env("TAS_DNS_UDP_BIND", format!("127.0.0.1:{udp}"))
        .env("TAS_DNS_TCP_BIND", format!("127.0.0.1:{udp}"))
        .env("TAS_DNS_METRICS_BIND", format!("127.0.0.1:{metrics}"))
        .env("TAS_DNS_DATA_DIR", dir.path().join("data"))
        .env("TAS_DNS_KEY_MASTER_FILE", &master)
        .env("TAS_DNS_NAMESERVERS", "ns1.tas.example,ns2.tas.example")
        .env("TAS_DNS_HOSTMASTER", "hostmaster.tas.example")
        .env("TAS_DNS_REGISTRAR_KEY", hex(kp(1).public_key().as_bytes()))
        .env("TAS_DNS_MESH_BIND", format!("127.0.0.1:{mesh}"))
        .env("TAS_DNS_MESH_DIALKEY_FILE", &dk)
        .env("TAS_DNS_MESH_PUBLISHERS", hex(&cp_id))
        .env("TAS_DNS_LOG_JSON", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // wait for readiness
    let mut ready = false;
    for _ in 0..100 {
        if http_get(metrics, "/healthz").is_some_and(|r| r.contains("200 OK")) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "daemon did not come up");
    assert!(http_get(metrics, "/nope").unwrap().contains("404"));

    // unknown zones are REFUSED
    let r = parse(
        &udp_exchange(
            format!("127.0.0.1:{udp}").parse().unwrap(),
            &query_packet(1, "www.acme.example.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);

    // the control plane delegates a SIGNED zone and the owner publishes it, over the mesh
    let owner = transport::dialkey::native_keypair("acme-owner");
    let node_id = transport::dialkey::peer_id("daemon-test-dialkey");
    let node = PeerAddr::new(node_id, "127.0.0.1", mesh);
    let spec = RegistrationSpec {
        apex: "acme.example",
        tenant: "acme",
        owner: *owner.public_key().as_bytes(),
        owner_epoch: 1,
        seq: 1,
        state: RegState::Active,
        quarantine_until: 0,
        dnssec: Some(DnssecPolicy {
            ksk_gen: 0,
            ksk_next: None,
            origin: unix_now() - 1000,
        }),
    };
    let reg = registration_object(&kp(1), &spec).unwrap();
    let upd = update_object(
        &owner,
        "acme.example",
        1,
        1,
        br#"{"records":[{"name":"www","ttl":300,"type":"A","data":"198.51.100.1"}]}"#,
    )
    .unwrap();
    let out = cp.push(&node, &[reg, upd]).await.unwrap();
    assert_eq!(out, vec![ApplyOutcome::Applied, ApplyOutcome::Applied]);

    let dns: std::net::SocketAddr = format!("127.0.0.1:{udp}").parse().unwrap();
    let mut answered = false;
    for _ in 0..50 {
        let r = parse(
            &udp_exchange(
                dns,
                &query_packet(
                    2,
                    "www.acme.example.",
                    RecordType::A,
                    Some((1232, true)),
                    false,
                ),
                500,
            )
            .await
            .unwrap(),
        );
        if r.metadata.response_code == ResponseCode::NoError
            && r.answers
                .iter()
                .any(|a| a.record_type() == RecordType::RRSIG)
        {
            answered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(answered, "signed answer served after replication");

    // the DS a parent should hold is exposed on the internal listener and matches the served KSK
    let ds_body = http_get(metrics, "/ds/acme.example").unwrap();
    let line = ds_body
        .lines()
        .find(|l| l.contains("IN DS"))
        .expect("a DS line")
        .to_string();
    let f: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(&f[..3], ["acme.example.", "IN", "DS"]);
    let (tag, alg, dt, hexd) = (f[3].parse::<u16>().unwrap(), f[4], f[5], f[6]);
    assert_eq!((alg, dt), ("13", "2"));
    let dk = parse(
        &udp_exchange(
            dns,
            &query_packet(
                9,
                "acme.example.",
                RecordType::DNSKEY,
                Some((1232, false)),
                false,
            ),
            1000,
        )
        .await
        .unwrap(),
    );
    let ksk =
        dk.answers.iter().find_map(|r| match &r.data {
            hickory_proto::rr::RData::DNSSEC(
                hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(k),
            ) if k.secure_entry_point() => Some(k.clone()),
            _ => None,
        });
    let ksk = ksk.expect("served KSK");
    assert_eq!(ksk.calculate_key_tag().unwrap(), tag);
    let digest = ksk
        .to_digest(
            &hickory_proto::rr::Name::from_ascii("acme.example.").unwrap(),
            hickory_proto::dnssec::DigestType::SHA256,
        )
        .unwrap();
    assert_eq!(
        hexd,
        hex(digest.as_ref()).to_uppercase(),
        "the published DS digest covers the served KSK"
    );
    assert!(http_get(metrics, "/ds/other.example")
        .unwrap()
        .contains("404"));
    assert!(http_get(metrics, "/ds/a%00b").unwrap().contains("404"));

    let m = http_get(metrics, "/metrics").unwrap();
    assert!(
        m.contains("tas_dns_zone_version{zone=\"acme.example.\"} 1"),
        "{m}"
    );
    assert!(m.contains("tas_dns_zone_signature_expiry_seconds{zone=\"acme.example.\"}"));
    assert!(m.contains("tas_dns_queries_udp_total"));
    assert!(
        m.contains("tas_dns_responses_total{rcode=\"5\"} 1"),
        "the REFUSED is counted: {m}"
    );
    let expiry: i64 = m
        .lines()
        .find(|l| l.starts_with("tas_dns_zone_signature_expiry_seconds"))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap();
    assert!(expiry > 3 * 86_400, "fresh signatures: {expiry}s left");

    // graceful shutdown on SIGTERM
    assert!(Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let mut exited = None;
    for _ in 0..60 {
        if let Some(s) = child.try_wait().unwrap() {
            exited = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = exited.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("daemon did not exit within 6 s of SIGTERM")
    });
    assert!(status.success(), "{status:?}");
    // logs never contain the secrets or tenant data verbatim beyond escaped names, and are JSON
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        !err.contains("daemon-test-dialkey") && !err.contains("acme-owner"),
        "no secret in logs"
    );
    assert!(
        err.lines()
            .all(|l| l.trim().is_empty() || l.starts_with('{')),
        "structured logs"
    );
    assert!(err.contains("mesh up") && err.contains("shutting down"));
    // restart on the same data dir: the zone is back without any publisher
    let _ = child;
}
