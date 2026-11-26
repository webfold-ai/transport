#![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]
//! Nothing a tenant or the network controls may reach a log line unescaped. This binary installs
//! a process-global capturing subscriber at TRACE for every target and then feeds hostile input
//! through every path that logs: odd query names, hostile registrations/updates through the
//! replication path, hostile challenge states, and malformed packets.

mod common;
use common::*;
use hickory_proto::rr::RecordType;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tas_dns::objects::{registration_object, update_object, RegistrationSpec};
use tas_dns::server::ServerLimits;
use tas_dns::zone::RegState;
use transport::zone_sync::SignedObject;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_input_never_reaches_a_log_line_unescaped() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(cap.clone())
            .finish(),
    )
    .unwrap();

    let t = start(ServerLimits {
        budget_rate: 100_000,
        budget_burst: 100_000,
        rrl_rate: 100_000,
        rrl_burst: 100_000,
        ..ServerLimits::default()
    })
    .await;
    t.add_zone(
        "acme.example",
        "acme",
        &kp(10),
        1,
        r#"{"records":[{"name":"www","ttl":300,"type":"A","data":"198.51.100.1"}]}"#,
        None,
    );

    // hostile query names: control characters, ESC sequences, quotes, newlines, 8-bit bytes
    for raw in [
        &b"\x1b[31mred\x07\n.acme.example."[..],
        b"a\"b\\c\r\nFORGED LOG LINE level=ERROR.acme.example.",
        b"\xff\xfe\x00bad.acme.example.",
        b"x\ny.example.org.",
    ] {
        let mut pkt = query_packet(1, "x.acme.example.", RecordType::A, None, false);
        // replace the question name with raw label bytes
        let mut name = Vec::new();
        for label in raw.split(|b| *b == b'.') {
            if label.is_empty() {
                continue;
            }
            name.push(u8::try_from(label.len().min(63)).unwrap());
            name.extend_from_slice(&label[..label.len().min(63)]);
        }
        name.push(0);
        pkt.truncate(12);
        pkt.extend_from_slice(&name);
        pkt.extend_from_slice(&[0, 1, 0, 1]);
        let _ = udp_exchange(t.udp, &pkt, 300).await;
        let _ = tcp_exchange(t.tcp, &pkt).await;
    }

    // hostile objects through the replication path: bad ids, hostile apex text, invalid content,
    // wrong signers (each of these is logged as an alert)
    let evil_key = kp(66);
    let owner = kp(10);
    let hostile = [
        SignedObject::sign(&evil_key, transport::zone_sync::ObjectKind::Update, b"\x07evil\nx\x03com\x00".to_vec(), 1, 1, b"{}".to_vec()).unwrap(),
        SignedObject::sign(&evil_key, transport::zone_sync::ObjectKind::Registration, b"\x1b[2J\x00".to_vec(), 1, 1, b"{\"apex\":\"x\\ny.example\"}".to_vec()).unwrap(),
        update_object(&owner, "acme.example", 1, 9, b"{\"records\":[{\"name\":\"evil\\nname\\u001b[31m\",\"ttl\":300,\"type\":\"A\",\"data\":\"1.2.3.4\"}]}").unwrap(),
        update_object(&evil_key, "acme.example", 1, 10, b"{}").unwrap(),
        registration_object(
            &kp(1),
            &RegistrationSpec { apex: "acme.example", tenant: "other", owner: *evil_key.public_key().as_bytes(), owner_epoch: 1, seq: 50, state: RegState::Active, quarantine_until: 0, dnssec: None },
        )
        .unwrap(),
    ];
    for o in hostile {
        let _ = t.node.db.apply_object(o);
    }
    // a hostile challenge state
    let auth = tas_dns::challenge_auth::ChallengeAuthority::new(
        kp(2),
        tas_dns::names::parse_fqdn("chal.tas.example").unwrap(),
        t.node.db.clone(),
        Arc::new(tas_dns::challenge_auth::LocalPublisher(t.node.db.clone())),
        Arc::new(unix_now),
    );
    let tenant = tas_dns::zone::TenantId::new("tenant-a").unwrap();
    let _ = auth.bind(&tenant, "bad\nname.example").await;
    // malformed packets
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for len in [0usize, 1, 11, 12, 13, 40, 300] {
        let mut junk = vec![0x1bu8; len];
        if len > 4 {
            junk[2] = 0;
        }
        sock.send_to(&junk, t.udp).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let logs = cap.0.lock().unwrap().clone();
    assert!(!logs.is_empty(), "something was logged");
    let text = String::from_utf8_lossy(&logs).to_string();
    for (n, line) in text.lines().enumerate() {
        assert!(
            line.bytes()
                .all(|b| b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80),
            "line {n} has a control byte: {line:?}"
        );
    }
    assert!(!text.contains('\u{1b}'), "no ESC byte");
    // a forged "log line" cannot start a new record: no line begins the way a real record does just because a tenant said so
    assert!(
        !text.lines().any(|l| l.starts_with("FORGED LOG LINE")),
        "{text}"
    );
    // and the alerts that SHOULD fire did fire (this is not a vacuous pass)
    assert!(text.contains("replication anomaly"), "alerts were logged");
    if std::env::var_os("TAS_DNS_SHOW_LOGS").is_some() {
        let _ = writeln!(std::io::stderr(), "{text}");
    }
}
