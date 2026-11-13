//! The pkarr relay server and the internal DNS zone, end to end.
//!
//! The relay is driven by the real [`transport::pkarr::RelayClient`] and the real
//! `dialkey::publish`/`resolve`, and by raw sockets for what a well-behaved client never sends.
//! The DNS zone is queried as bytes, including over a live UDP socket.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use transport::dialkey::{self, build_packet, native_keypair, DialkeyServiceInfo};
use transport::dns::{Flags, Message, Name, Question, RData, RecordType, ResponseCode};
use transport::edge_dns::{serve_udp_with, DnsHandler};
use transport::mesh_dns::MeshZone;
use transport::pkarr::RelayClient;
use transport::pkarr_relay::{serve, Limits, PutError, RelayStore, MAX_BODY};
use transport::signed_dns::PublicKey;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

fn billing(port: u16) -> DialkeyServiceInfo {
    DialkeyServiceInfo {
        service: "_billing._tcp".into(),
        port,
        metadata: [("tenant".to_owned(), "acme".to_owned())].into(),
    }
}

async fn start(store: Arc<RelayStore>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, store));
    addr
}

fn memory() -> Arc<RelayStore> {
    Arc::new(RelayStore::in_memory(Limits::default()))
}

/// One raw HTTP exchange: the status and the body.
async fn raw(addr: SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or_else(Vec::new, |i| buf[i + 4..].to_vec());
    (status, body)
}

fn put(path: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "PUT {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes()
}

fn z32(dialkey: &str) -> String {
    native_keypair(dialkey).public_key().to_z32()
}

// ------------------------------------------------------------------ the relay

#[tokio::test]
async fn the_real_client_publishes_and_resolves_through_the_relay() {
    let addr = start(memory()).await;
    let client = RelayClient::with_relays(vec![format!("http://{addr}")]);

    dialkey::publish(&client, "billing-plane", IP, &[billing(8080)])
        .await
        .unwrap();
    let svc = dialkey::resolve(&client, "billing-plane", "_billing._tcp")
        .await
        .expect("resolves");
    assert_eq!(svc.peer_addr.port, 8080);
    assert_eq!(svc.peer_addr.peer_id, dialkey::peer_id("billing-plane"));
    assert_eq!(svc.metadata.get("tenant").map(String::as_str), Some("acme"));

    // A different dialkey is a different name: nothing resolves under it.
    assert!(
        dialkey::resolve(&client, "telemetry-plane", "_billing._tcp")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn a_republish_replaces_and_an_older_record_is_refused() {
    let addr = start(memory()).await;
    let client = RelayClient::with_relays(vec![format!("http://{addr}")]);
    dialkey::publish(&client, "svc", IP, &[billing(1000)])
        .await
        .unwrap();
    dialkey::publish(&client, "svc", IP, &[billing(2000)])
        .await
        .unwrap(); // seq is a later timestamp
    let svc = dialkey::resolve(&client, "svc", "_billing._tcp")
        .await
        .unwrap();
    assert_eq!(svc.peer_addr.port, 2000, "the newer record wins");

    // Replaying an older record (lower seq) is a 409 and changes nothing.
    let old = build_packet("svc", IP, &[billing(1)], 1).unwrap();
    let (status, _) = raw(
        addr,
        &put(&format!("/{}", z32("svc")), &old.to_relay_bytes()),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(
        dialkey::resolve(&client, "svc", "_billing._tcp")
            .await
            .unwrap()
            .peer_addr
            .port,
        2000
    );
}

#[tokio::test]
async fn only_a_record_signed_by_the_key_in_the_url_is_stored() {
    let addr = start(memory()).await;
    let theirs = build_packet("someone-else", IP, &[billing(1)], 5).unwrap();
    // Their record, filed under our key.
    let (status, _) = raw(
        addr,
        &put(&format!("/{}", z32("me")), &theirs.to_relay_bytes()),
    )
    .await;
    assert_eq!(status, 400, "a record signed by another key is refused");
    // A flipped bit anywhere in the record is refused too.
    let mut bytes = build_packet("me", IP, &[billing(1)], 5)
        .unwrap()
        .to_relay_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        raw(addr, &put(&format!("/{}", z32("me")), &bytes)).await.0,
        400
    );
    assert_eq!(
        raw(addr, &get(&format!("/{}", z32("me")))).await.0,
        404,
        "nothing was stored"
    );
}

#[tokio::test]
async fn the_same_record_again_is_accepted_but_a_different_record_at_the_same_seq_is_not() {
    let store = memory();
    let key = native_keypair("k").public_key();
    let a = build_packet("k", IP, &[billing(1)], 10)
        .unwrap()
        .to_relay_bytes();
    let b = build_packet("k", IP, &[billing(2)], 10)
        .unwrap()
        .to_relay_bytes();
    assert!(store.put(&key, &a, 0).is_ok());
    assert!(store.put(&key, &a, 1).is_ok(), "idempotent");
    assert_eq!(store.put(&key, &b, 2), Err(PutError::Stale { current: 10 }));
}

#[tokio::test]
async fn http_hygiene() {
    let addr = start(memory()).await;
    let key = z32("h");
    let ok = build_packet("h", IP, &[billing(1)], 1)
        .unwrap()
        .to_relay_bytes();

    assert_eq!(raw(addr, &get("/health")).await.0, 200);
    assert_eq!(raw(addr, &get("/")).await.0, 404);
    assert_eq!(
        raw(addr, &get(&format!("/{key}"))).await.0,
        404,
        "unknown key"
    );
    assert_eq!(raw(addr, &get("/not-a-key")).await.0, 400);
    assert_eq!(raw(addr, &get(&format!("/{key}/extra"))).await.0, 404);
    assert_eq!(raw(addr, b"DELETE /health HTTP/1.1\r\n\r\n").await.0, 405);
    assert_eq!(raw(addr, b"garbage\r\n\r\n").await.0, 400);
    assert_eq!(raw(addr, b"GET / HTTP/2.0\r\n\r\n").await.0, 400);
    // No length, a chunked body, conflicting lengths: refused, not guessed at.
    assert_eq!(
        raw(addr, format!("PUT /{key} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .0,
        411
    );
    assert_eq!(
        raw(
            addr,
            format!("PUT /{key} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .as_bytes()
        )
        .await
        .0,
        501
    );
    assert_eq!(
        raw(
            addr,
            format!("PUT /{key} HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd")
                .as_bytes()
        )
        .await
        .0,
        400
    );
    // Too large is refused before the body is read.
    assert_eq!(
        raw(
            addr,
            format!(
                "PUT /{key} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY + 1
            )
            .as_bytes()
        )
        .await
        .0,
        413
    );
    // A query string does not change the route.
    assert_eq!(raw(addr, &put(&format!("/{key}?x=1"), &ok)).await.0, 200);
    let (status, body) = raw(addr, &get(&format!("/{key}"))).await;
    assert_eq!((status, body), (200, ok));
}

#[tokio::test]
async fn a_closed_relay_only_takes_records_from_allowed_keys_but_serves_anyone() {
    let allowed = native_keypair("allowed").public_key();
    let limits = Limits {
        allow: Some([*allowed.as_bytes()].into()),
        ..Limits::default()
    };
    let addr = start(Arc::new(RelayStore::in_memory(limits))).await;
    let client = RelayClient::with_relays(vec![format!("http://{addr}")]);
    assert!(dialkey::publish(&client, "allowed", IP, &[billing(1)])
        .await
        .is_ok());
    assert!(
        dialkey::publish(&client, "stranger", IP, &[billing(1)])
            .await
            .is_err(),
        "403"
    );
    let (status, _) = raw(
        addr,
        &put(
            &format!("/{}", z32("stranger")),
            &build_packet("stranger", IP, &[billing(1)], 1)
                .unwrap()
                .to_relay_bytes(),
        ),
    )
    .await;
    assert_eq!(status, 403);
    assert!(dialkey::resolve(&client, "allowed", "_billing._tcp")
        .await
        .is_some());
}

#[test]
fn the_store_is_bounded_but_an_existing_key_can_always_update() {
    let store = RelayStore::in_memory(Limits {
        max_keys: 2,
        ..Limits::default()
    });
    let rec = |k: &str, seq| {
        build_packet(k, IP, &[billing(1)], seq)
            .unwrap()
            .to_relay_bytes()
    };
    let key = |k: &str| native_keypair(k).public_key();
    assert!(store.put(&key("a"), &rec("a", 1), 0).is_ok());
    assert!(store.put(&key("b"), &rec("b", 1), 0).is_ok());
    assert_eq!(store.put(&key("c"), &rec("c", 1), 0), Err(PutError::Full));
    assert!(
        store.put(&key("a"), &rec("a", 2), 0).is_ok(),
        "updating a held key is not growth"
    );
    assert_eq!(store.len(), 2);
}

#[test]
fn records_expire_when_a_max_age_is_set_and_never_when_it_is_not() {
    let rec = |seq| {
        build_packet("e", IP, &[billing(1)], seq)
            .unwrap()
            .to_relay_bytes()
    };
    let key = native_keypair("e").public_key();

    let aging = RelayStore::in_memory(Limits {
        max_age: Some(Duration::from_secs(100)),
        ..Limits::default()
    });
    aging.put(&key, &rec(1), 1000).unwrap();
    assert!(
        aging.get(&key, 1100).is_some(),
        "exactly at the limit is still served"
    );
    assert!(aging.get(&key, 1101).is_none());
    assert_eq!(aging.sweep(1101), 1);
    assert!(aging.is_empty());
    // Republishing the identical record refreshes its age.
    aging.put(&key, &rec(1), 2000).unwrap();
    aging.put(&key, &rec(1), 2090).unwrap();
    assert!(aging.get(&key, 2150).is_some());

    // The default keeps a publisher that announced once at boot.
    let forever = RelayStore::in_memory(Limits::default());
    forever.put(&key, &rec(1), 0).unwrap();
    assert!(forever.get(&key, u64::MAX / 2).is_some());
}

#[test]
fn records_survive_a_restart_and_a_corrupt_file_is_skipped_not_served() {
    let dir = std::env::temp_dir().join(format!("meshd-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = native_keypair("persisted").public_key();
    let rec = build_packet("persisted", IP, &[billing(4242)], 9)
        .unwrap()
        .to_relay_bytes();
    {
        let (store, report) = RelayStore::open(&dir, Limits::default()).unwrap();
        assert_eq!(report.loaded, 0);
        store.put(&key, &rec, 50).unwrap();
    }
    // A forged file under another key's name, and junk, sit beside the good one.
    let other = native_keypair("other").public_key();
    let mut forged = 50u64.to_be_bytes().to_vec();
    forged.extend_from_slice(&rec); // signed by "persisted", filed as "other"
    std::fs::write(dir.join(format!("{}.pkt", other.to_z32())), forged).unwrap();
    std::fs::write(dir.join("junk.pkt"), b"nope").unwrap();
    std::fs::write(dir.join(".leftover.tmp"), b"half a write").unwrap();

    let (store, report) = RelayStore::open(&dir, Limits::default()).unwrap();
    assert_eq!((report.loaded, report.skipped), (1, 2), "{report:?}");
    assert_eq!(store.get(&key, 60).as_deref(), Some(rec.as_slice()));
    assert!(
        store.get(&other, 60).is_none(),
        "a record is only ever served under the key that signed it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ internal DNS

fn zone_with(records: &[(&str, u16, u64)]) -> (MeshZone, Arc<RelayStore>) {
    let store = memory();
    for (dk, port, seq) in records {
        let key = native_keypair(dk).public_key();
        store
            .put(
                &key,
                &build_packet(dk, IP, &[billing(*port)], *seq)
                    .unwrap()
                    .to_relay_bytes(),
                0,
            )
            .unwrap();
    }
    let zone = MeshZone::new(
        Arc::clone(&store),
        "mesh.internal",
        "ns.mesh.internal",
        "hostmaster.mesh.internal",
    )
    .unwrap();
    (zone, store)
}

fn query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut m = Message::default();
    m.id = 7;
    m.flags = Flags {
        recursion_desired: true,
        ..Flags::default()
    };
    m.questions
        .push(Question::new(Name::from_ascii(name).unwrap(), qtype));
    m.to_bytes()
}

fn ask(zone: &MeshZone, name: &str, qtype: RecordType) -> Message {
    Message::from_bytes(&zone.answer_at(&query(name, qtype), 0).expect("answered")).unwrap()
}

#[test]
fn a_service_resolves_by_name_with_its_target_and_address() {
    let (zone, _s) = zone_with(&[("billing-plane", 8080, 1)]);
    let key = z32("billing-plane");

    let a = ask(&zone, &format!("{key}.mesh.internal"), RecordType::A);
    assert_eq!(a.flags.response_code, ResponseCode::NoError);
    assert!(a.flags.authoritative && a.flags.response && !a.flags.recursion_available);
    assert_eq!(a.id, 7);
    assert!(matches!(a.answers.as_slice(), [r] if r.data == RData::A(Ipv4Addr::new(10, 0, 0, 7))));
    assert_eq!(
        a.answers[0].name,
        Name::from_ascii(&format!("{key}.mesh.internal")).unwrap()
    );

    let srv = ask(
        &zone,
        &format!("_billing._tcp.{key}.mesh.internal"),
        RecordType::Srv,
    );
    let [r] = srv.answers.as_slice() else {
        panic!("{srv:?}")
    };
    let RData::Srv { port, target, .. } = &r.data else {
        panic!("{r:?}")
    };
    assert_eq!(*port, 8080);
    // The target is qualified under the zone so a resolver following it asks us, not the root.
    assert_eq!(
        *target,
        Name::from_ascii(&format!("{key}.mesh.internal")).unwrap()
    );
    assert!(
        srv.additionals
            .iter()
            .any(|x| x.data == RData::A(Ipv4Addr::new(10, 0, 0, 7)) && x.name == *target),
        "the SRV's address rides along"
    );

    let txt = ask(
        &zone,
        &format!("_billing._tcp.{key}.mesh.internal"),
        RecordType::Txt,
    );
    assert!(matches!(&txt.answers[0].data, RData::Txt(s) if s.iter().any(|x| x == b"tenant=acme")));

    let any = ask(
        &zone,
        &format!("_billing._tcp.{key}.mesh.internal"),
        RecordType::Unknown(255),
    );
    assert_eq!(any.answers.len(), 2, "SRV and TXT");
}

#[test]
fn negative_answers_carry_the_soa_and_say_which_kind() {
    let (zone, _s) = zone_with(&[("p", 1, 1)]);
    let key = z32("p");
    let soa = |m: &Message| {
        m.authorities
            .iter()
            .any(|r| matches!(r.data, RData::Soa { .. }))
    };

    let nodata = ask(&zone, &format!("{key}.mesh.internal"), RecordType::Aaaa);
    assert_eq!(nodata.flags.response_code, ResponseCode::NoError);
    assert!(
        nodata.answers.is_empty() && soa(&nodata),
        "the name exists, the type does not"
    );

    for name in [
        format!("{}.mesh.internal", z32("never-published")),
        format!("_other._tcp.{key}.mesh.internal"),
        "not-a-key.mesh.internal".to_owned(),
        format!("a.b.c.{key}.mesh.internal"),
    ] {
        let nx = ask(&zone, &name, RecordType::A);
        assert_eq!(nx.flags.response_code, ResponseCode::NxDomain, "{name}");
        assert!(soa(&nx), "{name}");
    }
}

#[test]
fn it_is_authoritative_only_and_never_answers_what_it_should_not() {
    let (zone, _s) = zone_with(&[]);
    assert_eq!(
        ask(&zone, "example.com", RecordType::A).flags.response_code,
        ResponseCode::Refused
    );
    assert_eq!(
        ask(&zone, "internal", RecordType::A).flags.response_code,
        ResponseCode::Refused
    );
    assert_eq!(
        ask(&zone, "notmesh.internal", RecordType::A)
            .flags
            .response_code,
        ResponseCode::Refused
    );

    let apex_soa = ask(&zone, "mesh.internal", RecordType::Soa);
    assert!(matches!(apex_soa.answers.as_slice(), [r] if matches!(r.data, RData::Soa { .. })));
    assert!(
        matches!(ask(&zone, "mesh.internal", RecordType::Ns).answers.as_slice(), [r] if matches!(r.data, RData::Ns(_)))
    );
    assert_eq!(
        ask(&zone, "MESH.Internal", RecordType::Soa).answers.len(),
        1,
        "DNS names are case-insensitive"
    );

    // Silence for unparseable input and for responses; an error for the rest.
    assert!(zone.answer_at(b"\x00\x01garbage", 0).is_none());
    assert!(zone.answer_at(&[], 0).is_none());
    let mut resp = Message::response(1);
    resp.questions.push(Question::new(
        Name::from_ascii("mesh.internal").unwrap(),
        RecordType::Soa,
    ));
    assert!(
        zone.answer_at(&resp.to_bytes(), 0).is_none(),
        "never answer an answer"
    );
    let mut two = Message::default();
    two.questions.push(Question::new(
        Name::from_ascii("mesh.internal").unwrap(),
        RecordType::Soa,
    ));
    two.questions.push(Question::new(
        Name::from_ascii("mesh.internal").unwrap(),
        RecordType::Ns,
    ));
    assert_eq!(
        Message::from_bytes(&zone.answer_at(&two.to_bytes(), 0).unwrap())
            .unwrap()
            .flags
            .response_code,
        ResponseCode::FormErr
    );
    let mut update = Message::default();
    update.flags.opcode = 5;
    update.questions.push(Question::new(
        Name::from_ascii("mesh.internal").unwrap(),
        RecordType::Soa,
    ));
    assert_eq!(
        Message::from_bytes(&zone.answer_at(&update.to_bytes(), 0).unwrap())
            .unwrap()
            .flags
            .response_code,
        ResponseCode::NotImp
    );
}

#[test]
fn a_zone_cannot_be_the_root_or_a_bad_name() {
    let s = memory();
    assert!(MeshZone::new(Arc::clone(&s), ".", "ns.x", "h.x").is_err());
    assert!(MeshZone::new(Arc::clone(&s), "a..b", "ns.x", "h.x").is_err());
}

#[test]
fn a_record_the_relay_no_longer_serves_stops_resolving() {
    let store = Arc::new(RelayStore::in_memory(Limits {
        max_age: Some(Duration::from_secs(10)),
        ..Limits::default()
    }));
    let key = native_keypair("fading").public_key();
    store
        .put(
            &key,
            &build_packet("fading", IP, &[billing(1)], 1)
                .unwrap()
                .to_relay_bytes(),
            100,
        )
        .unwrap();
    let zone = MeshZone::new(
        store,
        "mesh.internal",
        "ns.mesh.internal",
        "h.mesh.internal",
    )
    .unwrap();
    let q = query(&format!("{}.mesh.internal", key.to_z32()), RecordType::A);
    let live = Message::from_bytes(&zone.answer_at(&q, 105).unwrap()).unwrap();
    let dead = Message::from_bytes(&zone.answer_at(&q, 200).unwrap()).unwrap();
    assert_eq!(
        (live.answers.len(), dead.flags.response_code),
        (1, ResponseCode::NxDomain)
    );
}

#[tokio::test]
async fn it_answers_over_a_live_udp_socket() {
    let (zone, _s) = zone_with(&[("udp-svc", 9090, 1)]);
    let port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let handler: Arc<dyn DnsHandler> = Arc::new(zone);
    tokio::spawn(serve_udp_with(
        Box::leak(format!("127.0.0.1:{port}").into_boxed_str()),
        handler,
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let name = format!("_billing._tcp.{}.mesh.internal", z32("udp-svc"));
    sock.send_to(&query(&name, RecordType::Srv), format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("a reply")
        .unwrap();
    let reply = Message::from_bytes(&buf[..n]).unwrap();
    assert!(
        matches!(reply.answers.as_slice(), [r] if matches!(&r.data, RData::Srv { port: 9090, .. })),
        "{reply:?}"
    );
}

#[test]
fn public_keys_round_trip_through_their_names() {
    let key = native_keypair("rt").public_key();
    assert_eq!(PublicKey::from_z32(&key.to_z32()).unwrap(), key);
    assert_eq!(key.to_z32().len(), 52);
}
