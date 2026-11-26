#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_net::client::ClientHandle;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tas_dns::server::ServerLimits;

const ZONE: &str = r#"{"records":[
 {"name":"www","ttl":300,"type":"A","data":"198.51.100.10"},
 {"name":"www","ttl":300,"type":"AAAA","data":"2001:db8::10"},
 {"name":"@","ttl":300,"type":"MX","data":{"preference":10,"exchange":"mail.acme.example"}},
 {"name":"mail","ttl":300,"type":"A","data":"198.51.100.25"},
 {"name":"@","ttl":300,"type":"CAA","data":{"flags":0,"tag":"issue","value":"letsencrypt.org"}},
 {"name":"*.dev","ttl":300,"type":"A","data":"198.51.100.20"},
 {"name":"explicit.dev","ttl":300,"type":"TXT","data":["explicit"]},
 {"name":"api","ttl":300,"type":"CNAME","data":"www.acme.example"},
 {"name":"a.b.c","ttl":300,"type":"TXT","data":["empty non-terminals above"]}
]}"#;

async fn node_with_zone(limits: ServerLimits, dnssec: bool) -> TestNode {
    let t = start(limits).await;
    let p = dnssec.then(|| tas_dns::zone::DnssecPolicy {
        ksk_gen: 0,
        ksk_next: None,
        origin: unix_now() - 1000,
    });
    t.add_zone("acme.example", "acme", &kp(10), 3, ZONE, p);
    t
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

#[tokio::test]
async fn positive_answers_over_udp_and_tcp_are_authoritative_and_never_recursive() {
    let t = node_with_zone(ServerLimits::default(), false).await;
    for client in [udp_client(t.udp), tcp_client(t.tcp).await] {
        let mut c = client;
        let r = c
            .query(n("www.acme.example."), DNSClass::IN, RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.metadata.authoritative);
        assert!(
            !r.metadata.recursion_available,
            "an authoritative-only server never offers recursion"
        );
        assert_eq!(r.answers.len(), 1);
        assert!(matches!(&r.answers[0].data, RData::A(a) if a.0.to_string() == "198.51.100.10"));
        let r = c
            .query(n("acme.example."), DNSClass::IN, RecordType::SOA)
            .await
            .unwrap();
        match &r.answers[0].data {
            RData::SOA(s) => assert_eq!(s.serial, 3, "SOA serial is the zone version"),
            o => panic!("{o:?}"),
        }
        assert!(
            r.authorities
                .iter()
                .any(|a| a.record_type() == RecordType::NS),
            "SOA answers carry the NS set"
        );
        let r = c
            .query(n("acme.example."), DNSClass::IN, RecordType::CAA)
            .await
            .unwrap();
        assert_eq!(r.answers.len(), 1, "CAA is served");
    }
}

#[tokio::test]
async fn nxdomain_and_nodata_are_distinct_and_carry_the_soa() {
    let t = node_with_zone(ServerLimits::default(), false).await;
    let mut c = udp_client(t.udp);
    let r = c
        .query(n("nope.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert!(r.answers.is_empty());
    assert!(
        r.authorities
            .iter()
            .any(|a| a.record_type() == RecordType::SOA),
        "NXDOMAIN carries the SOA (negative caching)"
    );
    // the name exists, the type does not: NOERROR + SOA
    let r = c
        .query(n("www.acme.example."), DNSClass::IN, RecordType::MX)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.is_empty());
    assert!(r
        .authorities
        .iter()
        .any(|a| a.record_type() == RecordType::SOA));
    // an empty non-terminal (b.c.acme.example has only a child) is NODATA, not NXDOMAIN
    let r = c
        .query(n("b.c.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::NoError,
        "ENT is NODATA"
    );
    // the SOA minimum bounds the negative TTL
    let soa = r
        .authorities
        .iter()
        .find(|a| a.record_type() == RecordType::SOA)
        .unwrap();
    assert!(soa.ttl <= 300);
}

#[tokio::test]
async fn wildcard_and_cname_rules() {
    let t = node_with_zone(ServerLimits::default(), false).await;
    let mut c = udp_client(t.udp);
    // wildcard expansion
    let r = c
        .query(n("anything.dev.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(
        r.answers[0].name,
        n("anything.dev.acme.example."),
        "synthesised owner is the query name"
    );
    // an explicit name suppresses the wildcard for other types: NODATA, not the wildcard's data
    let r = c
        .query(n("explicit.dev.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(
        r.answers.is_empty(),
        "explicit name exists without an A: wildcard must not apply"
    );
    // the wildcard does not match its own parent
    let r = c
        .query(n("dev.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert!(r.answers.is_empty());
    // CNAME is followed to the in-zone target
    let r = c
        .query(n("api.acme.example."), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.answers.len(), 2);
    assert_eq!(r.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(r.answers[1].record_type(), RecordType::A);
    let r = c
        .query(n("api.acme.example."), DNSClass::IN, RecordType::CNAME)
        .await
        .unwrap();
    assert_eq!(r.answers.len(), 1);
}

#[tokio::test]
async fn refusals_unhosted_names_transfers_updates_and_chaos() {
    let t = node_with_zone(ServerLimits::default(), false).await;
    // not ours, with and without RD: REFUSED, never recursion
    for rd in [true, false] {
        let r = parse(
            &udp_exchange(
                t.udp,
                &query_packet(1, "www.example.org.", RecordType::A, None, rd),
                1000,
            )
            .await
            .unwrap(),
        );
        assert_eq!(r.metadata.response_code, ResponseCode::Refused);
        assert!(r.answers.is_empty() && !r.metadata.recursion_available);
    }
    // a name that merely resembles a hosted zone
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(2, "acme.example.evil.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
    // zone transfers from anyone, both transports
    for ty in [RecordType::AXFR, RecordType::IXFR] {
        let pkt = query_packet(3, "acme.example.", ty, None, false);
        let r = parse(&udp_exchange(t.udp, &pkt, 1000).await.unwrap());
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::Refused,
            "{ty} over udp"
        );
        let r = parse(&tcp_exchange(t.tcp, &pkt).await.unwrap());
        assert_eq!(
            r.metadata.response_code,
            ResponseCode::Refused,
            "{ty} over tcp"
        );
        assert!(r.answers.is_empty());
    }
    assert!(t.metrics.transfers_refused.get() >= 4);
    // UPDATE / NOTIFY / STATUS opcodes: NOTIMP
    for op in [OpCode::Update, OpCode::Notify, OpCode::Status] {
        let mut m = hickory_proto::op::Message::query();
        m.metadata.id = 9;
        m.metadata.op_code = op;
        m.add_query(hickory_proto::op::Query::query(
            n("acme.example."),
            RecordType::SOA,
        ));
        let r = parse(
            &udp_exchange(t.udp, &m.to_bytes().unwrap(), 1000)
                .await
                .unwrap(),
        );
        assert_eq!(r.metadata.response_code, ResponseCode::NotImp, "{op:?}");
    }
    // CHAOS class (version.bind): REFUSED, nothing disclosed
    let mut m = hickory_proto::op::Message::query();
    m.metadata.id = 10;
    let mut q = hickory_proto::op::Query::query(n("version.bind."), RecordType::TXT);
    q.set_query_class(DNSClass::CH);
    m.add_query(q);
    let r = parse(
        &udp_exchange(t.udp, &m.to_bytes().unwrap(), 1000)
            .await
            .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
    // zero questions: FORMERR
    let mut m = hickory_proto::op::Message::query();
    m.metadata.id = 11;
    let r = parse(
        &udp_exchange(t.udp, &m.to_bytes().unwrap(), 1000)
            .await
            .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::FormErr);
    // a response packet sent to the server is never answered (reflection)
    let mut m = hickory_proto::op::Message::query();
    m.metadata.message_type = hickory_proto::op::MessageType::Response;
    m.add_query(hickory_proto::op::Query::query(
        n("acme.example."),
        RecordType::SOA,
    ));
    assert!(udp_exchange(t.udp, &m.to_bytes().unwrap(), 300)
        .await
        .is_none());
}

#[tokio::test]
async fn any_is_minimal_and_nothing_amplifies() {
    let t = node_with_zone(ServerLimits::default(), true).await;
    // ANY at a name with several types returns ONE rrset (RFC 8482), not everything
    let q = query_packet(
        5,
        "acme.example.",
        RecordType::ANY,
        Some((4096, true)),
        false,
    );
    let resp = udp_exchange(t.udp, &q, 1000).await.unwrap();
    let r = parse(&resp);
    let types: std::collections::BTreeSet<_> = r
        .answers
        .iter()
        .map(hickory_proto::rr::Record::record_type)
        .filter(|t| *t != RecordType::RRSIG)
        .collect();
    assert_eq!(types.len(), 1, "minimal ANY: {types:?}");
    // amplification factor of any UDP response stays small and under the flag-day cap
    for (name, ty) in [
        ("acme.example.", RecordType::ANY),
        ("acme.example.", RecordType::DNSKEY),
        ("www.acme.example.", RecordType::ANY),
        ("nope.acme.example.", RecordType::A),
    ] {
        let q = query_packet(6, name, ty, Some((65535, true)), false);
        let resp = udp_exchange(t.udp, &q, 1000).await.unwrap();
        assert!(
            resp.len() <= 1232,
            "{name} {ty}: {} bytes exceeds the 1232 cap",
            resp.len()
        );
    }
}

#[tokio::test]
async fn udp_truncation_edns_cap_and_tcp_completeness() {
    let node = start(ServerLimits::default()).await;
    // 40 TXT records of 200 bytes: ~8 KB RRset
    let recs: Vec<String> = (0..40)
        .map(|i| {
            format!(
                r#"{{"name":"big","ttl":300,"type":"TXT","data":["{}{i:010}"]}}"#,
                "x".repeat(190)
            )
        })
        .collect();
    node.add_zone(
        "acme.example",
        "acme",
        &kp(10),
        1,
        &format!(r#"{{"records":[{}]}}"#, recs.join(",")),
        None,
    );
    let (zone, ty) = ("big.acme.example.", RecordType::TXT);
    // no EDNS: 512 bytes
    let resp = udp_exchange(node.udp, &query_packet(1, zone, ty, None, false), 1000)
        .await
        .unwrap();
    assert!(resp.len() <= 512, "no-EDNS reply is {}", resp.len());
    assert!(parse(&resp).metadata.truncation);
    // client advertises 4096: capped at 1232 anyway
    let resp = udp_exchange(
        node.udp,
        &query_packet(2, zone, ty, Some((4096, false)), false),
        1000,
    )
    .await
    .unwrap();
    assert!(resp.len() <= 1232, "capped reply is {}", resp.len());
    assert!(
        parse(&resp).metadata.truncation,
        "TC tells the client to retry over TCP"
    );
    // client advertises 700: honoured below the cap
    let resp = udp_exchange(
        node.udp,
        &query_packet(3, zone, ty, Some((700, false)), false),
        1000,
    )
    .await
    .unwrap();
    assert!(resp.len() <= 700);
    // TCP returns the full RRset
    let resp = tcp_exchange(
        node.tcp,
        &query_packet(4, zone, ty, Some((4096, false)), false),
    )
    .await
    .unwrap();
    let reply = parse(&resp);
    assert_eq!(reply.answers.len(), 40);
    assert!(!reply.metadata.truncation);
    // the hickory UDP client transparently falls back? at least its TCP client gets everything
    let mut client = tcp_client(node.tcp).await;
    assert_eq!(
        client
            .query(n(zone), DNSClass::IN, ty)
            .await
            .unwrap()
            .answers
            .len(),
        40
    );
    assert!(node.metrics.truncated.get() >= 3);
    // an unsupported EDNS version is BADVERS
    let mut msg = hickory_proto::op::Message::query();
    msg.metadata.id = 7;
    msg.add_query(hickory_proto::op::Query::query(
        n("acme.example."),
        RecordType::SOA,
    ));
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(1);
    msg.set_edns(edns);
    let reply = parse(
        &udp_exchange(node.udp, &msg.to_bytes().unwrap(), 1000)
            .await
            .unwrap(),
    );
    assert_eq!(
        u16::from(reply.metadata.response_code),
        16,
        "BADVERS (extended rcode 16)"
    );
}

#[tokio::test]
async fn dnssec_answers_carry_signatures_and_nsec_proofs_that_validate() {
    let t = node_with_zone(ServerLimits::default(), true).await;
    let now = t.clock.load(std::sync::atomic::Ordering::SeqCst);
    // DNSKEY over the wire, then validate a signed answer against it with hickory's verifier
    let mut c = tcp_client(t.tcp).await;
    let dk = c
        .query(n("acme.example."), DNSClass::IN, RecordType::DNSKEY)
        .await
        .unwrap();
    let keys: Vec<_> = dk
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(keys.iter().filter(|k| k.secure_entry_point()).count(), 1);
    // the DNSKEY response's own RRSIG verifies with the KSK
    let resp = parse(
        &tcp_exchange(
            t.tcp,
            &query_packet(
                1,
                "acme.example.",
                RecordType::DNSKEY,
                Some((4096, true)),
                false,
            ),
        )
        .await
        .unwrap(),
    );
    assert!(resp
        .answers
        .iter()
        .any(|r| r.record_type() == RecordType::RRSIG));
    let mut set = hickory_proto::rr::RecordSet::new(n("acme.example."), RecordType::DNSKEY, 0);
    for r in resp
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::DNSKEY)
    {
        set.insert(r.clone(), 0);
    }
    for r in resp
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
    {
        set.insert_rrsig(r.clone());
    }
    assert_eq!(validate(&set, &keys, now, Some(true)), 1);

    // a positive answer over UDP with DO: A + RRSIG, verified
    let resp = parse(
        &udp_exchange(
            t.udp,
            &query_packet(
                2,
                "www.acme.example.",
                RecordType::A,
                Some((1232, true)),
                false,
            ),
            1000,
        )
        .await
        .unwrap(),
    );
    let mut set = hickory_proto::rr::RecordSet::new(n("www.acme.example."), RecordType::A, 0);
    for r in resp
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::A)
    {
        set.insert(r.clone(), 0);
    }
    for r in resp
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
    {
        set.insert_rrsig(r.clone());
    }
    assert_eq!(validate(&set, &keys, now, Some(false)), 1);
    // without DO no signatures are sent
    let resp = parse(
        &udp_exchange(
            t.udp,
            &query_packet(
                3,
                "www.acme.example.",
                RecordType::A,
                Some((1232, false)),
                false,
            ),
            1000,
        )
        .await
        .unwrap(),
    );
    assert!(resp
        .answers
        .iter()
        .all(|r| r.record_type() != RecordType::RRSIG));
    // NXDOMAIN with DO carries a signed NSEC that covers the name, plus the signed SOA
    let resp = parse(
        &udp_exchange(
            t.udp,
            &query_packet(
                4,
                "nope.acme.example.",
                RecordType::A,
                Some((1232, true)),
                false,
            ),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    let nsec = resp
        .authorities
        .iter()
        .find(|r| r.record_type() == RecordType::NSEC)
        .expect("an NSEC proves the denial");
    let mut set = hickory_proto::rr::RecordSet::new(nsec.name.clone(), RecordType::NSEC, 0);
    set.insert(nsec.clone(), 0);
    for r in resp
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
    {
        if let RData::DNSSEC(DNSSECRData::RRSIG(s)) = &r.data {
            if s.input().type_covered == RecordType::NSEC {
                set.insert_rrsig(r.clone());
            }
        }
    }
    assert_eq!(
        validate(&set, &keys, now, Some(false)),
        1,
        "the NSEC is signed"
    );
    if let RData::DNSSEC(DNSSECRData::NSEC(x)) = &nsec.data {
        assert!(
            nsec.name < n("nope.acme.example.")
                && (n("nope.acme.example.") < *x.next_domain_name()
                    || x.next_domain_name() == &n("acme.example.")),
            "NSEC covers the queried name"
        );
    }
    assert!(resp
        .authorities
        .iter()
        .any(|r| r.record_type() == RecordType::SOA));
}

#[tokio::test]
async fn a_zone_that_must_be_signed_but_has_no_keys_is_servfail_never_unsigned() {
    let t = start_with(ServerLimits::default(), false).await;
    t.add_zone(
        "acme.example",
        "acme",
        &kp(10),
        1,
        ZONE,
        Some(tas_dns::zone::DnssecPolicy {
            ksk_gen: 0,
            ksk_next: None,
            origin: unix_now(),
        }),
    );
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(1, "www.acme.example.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(r.answers.is_empty());
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(2, "acme.example.", RecordType::SOA, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(t.metrics.rebuild_failures.get(), 1);
    // other zones are unaffected
    t.add_zone(
        "ok.example",
        "ok",
        &kp(11),
        1,
        ZONE.replace("acme.example", "ok.example").as_str(),
        None,
    );
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(3, "www.ok.example.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn unregistered_and_released_zones_are_refused_not_nxdomain() {
    let t = node_with_zone(ServerLimits::default(), false).await;
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(1, "www.unregistered.example.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::Refused,
        "RFC 0032 3.2: no tenant claim -> REFUSED"
    );
    // release it: served no more
    let spec = tas_dns::objects::RegistrationSpec {
        apex: "acme.example",
        tenant: "acme",
        owner: *kp(10).public_key().as_bytes(),
        owner_epoch: 1,
        seq: 99,
        state: tas_dns::zone::RegState::Released,
        quarantine_until: unix_now() + 86_400,
        dnssec: None,
    };
    t.node
        .db
        .apply_object(tas_dns::objects::registration_object(&t.registrar, &spec).unwrap());
    t.node.rebuild_zone(&n("acme.example."), unix_now());
    let r = parse(
        &udp_exchange(
            t.udp,
            &query_packet(2, "www.acme.example.", RecordType::A, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn tcp_is_bounded_pipelined_and_does_not_hang_on_garbage() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let limits = ServerLimits {
        tcp_per_ip: 2,
        tcp_idle: std::time::Duration::from_millis(400),
        tcp_max_queries: 3,
        ..ServerLimits::default()
    };
    let t = node_with_zone(limits, false).await;
    // pipelining: three queries on one connection, then the connection is closed (cap = 3)
    let mut s = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    for id in 0..3u16 {
        let q = query_packet(id, "www.acme.example.", RecordType::A, None, false);
        let mut f = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
        f.extend_from_slice(&q);
        s.write_all(&f).await.unwrap();
    }
    for id in 0..3u16 {
        let mut l = [0u8; 2];
        s.read_exact(&mut l).await.unwrap();
        let mut b = vec![0u8; usize::from(u16::from_be_bytes(l))];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(parse(&b).metadata.id, id);
    }
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0,
        "closed after the per-connection query cap"
    );

    // an oversized length prefix closes the connection without reading further
    let mut s = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    s.write_all(&[0xff, 0xff]).await.unwrap();
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(t.metrics.oversize.get() >= 1);

    // an idle connection is dropped by the idle timeout
    let mut s = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    // per-source connection cap: the third simultaneous connection is refused
    let _a = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    let _b = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut c = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), c.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0,
        "refused"
    );
    assert!(t.metrics.tcp_refused.get() >= 1);
}

#[tokio::test]
async fn rrl_limits_identical_responses_and_the_budget_drops_floods() {
    let limits = ServerLimits {
        rrl_rate: 1,
        rrl_burst: 3,
        rrl_slip: 2,
        budget_rate: 1000,
        budget_burst: 1000,
        ..ServerLimits::default()
    };
    let t = node_with_zone(limits, false).await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = query_packet(1, "www.acme.example.", RecordType::A, None, false);
    for _ in 0..30 {
        sock.send_to(&q, t.udp).await.unwrap();
    }
    let mut full = 0;
    let mut slipped = 0;
    let mut buf = vec![0u8; 2048];
    while let Ok(Ok((n, _))) = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        sock.recv_from(&mut buf),
    )
    .await
    {
        let m = parse(&buf[..n]);
        if m.metadata.truncation && m.answers.is_empty() {
            slipped += 1;
        } else {
            full += 1;
        }
    }
    assert!(
        (3..=4).contains(&full),
        "burst of 3 (+1 refill at most): got {full}"
    );
    assert!(
        (10..=14).contains(&slipped),
        "about every second denial slips: got {slipped}"
    );
    assert!(t.metrics.rrl_dropped.get() >= 10);
    // a different question from the same source is not penalised
    assert!(udp_exchange(
        t.udp,
        &query_packet(2, "mail.acme.example.", RecordType::A, None, false),
        1000
    )
    .await
    .is_some());
    // TCP is not subject to RRL (cannot be spoofed): the same query repeatedly succeeds
    for _ in 0..8 {
        assert!(tcp_exchange(t.tcp, &q).await.is_some());
    }

    // budget: a tiny budget drops the flood before parsing
    let limits = ServerLimits {
        budget_rate: 1,
        budget_burst: 5,
        ..ServerLimits::default()
    };
    let t = node_with_zone(limits, false).await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..200 {
        sock.send_to(&q, t.udp).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        t.metrics.budget_dropped.get() >= 150,
        "dropped {}",
        t.metrics.budget_dropped.get()
    );
    assert!(t.metrics.queries_udp.get() <= 20);
}

#[tokio::test]
async fn signed_wildcard_nodata_and_closest_encloser_semantics() {
    let t = node_with_zone(ServerLimits::default(), true).await;
    let now = t.clock.load(std::sync::atomic::Ordering::SeqCst);
    let dk = parse(
        &tcp_exchange(
            t.tcp,
            &query_packet(
                1,
                "acme.example.",
                RecordType::DNSKEY,
                Some((4096, true)),
                false,
            ),
        )
        .await
        .unwrap(),
    );
    let keys: Vec<_> = dk
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect();
    let ask = |name: &'static str, ty: RecordType| {
        let (udp, id) = (t.udp, 20u16);
        async move {
            parse(
                &udp_exchange(
                    udp,
                    &query_packet(id, name, ty, Some((1232, true)), false),
                    1000,
                )
                .await
                .unwrap(),
            )
        }
    };

    // a wildcard-synthesised answer: owner is the query name, the RRSIG's label count excludes the
    // wildcard label, the signature verifies over the WILDCARD owner, and an NSEC proves the
    // queried name does not exist
    let r = ask("anything.dev.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    let a = r
        .answers
        .iter()
        .find(|x| x.record_type() == RecordType::A)
        .unwrap();
    assert_eq!(a.name, n("anything.dev.acme.example."));
    let sig = r.answers.iter().find_map(|x| match &x.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == RecordType::A => {
            Some(x.clone())
        }
        _ => None,
    });
    let sig = sig.expect("the wildcard answer is signed");
    let RData::DNSSEC(DNSSECRData::RRSIG(s)) = &sig.data else {
        unreachable!()
    };
    assert_eq!(
        usize::from(s.input().num_labels),
        3,
        "labels excludes the wildcard label (dev.acme.example)"
    );
    let mut set = hickory_proto::rr::RecordSet::new(n("*.dev.acme.example."), RecordType::A, 0);
    set.insert(
        hickory_proto::rr::Record::from_rdata(n("*.dev.acme.example."), a.ttl, a.data.clone()),
        0,
    );
    set.insert_rrsig(sig.clone());
    assert_eq!(
        validate(&set, &keys, now, Some(false)),
        1,
        "signature verifies over the wildcard owner"
    );
    assert!(
        r.authorities
            .iter()
            .any(|x| x.record_type() == RecordType::NSEC),
        "NSEC proves the qname does not exist"
    );

    // an existing name never takes a wildcard answer; NODATA is proven by the NSEC AT the name
    let r = ask("explicit.dev.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.iter().all(|x| x.record_type() != RecordType::A));
    let nsec = r
        .authorities
        .iter()
        .find(|x| x.record_type() == RecordType::NSEC)
        .unwrap();
    assert_eq!(nsec.name, n("explicit.dev.acme.example."));
    let RData::DNSSEC(DNSSECRData::NSEC(bits)) = &nsec.data else {
        unreachable!()
    };
    let types: Vec<_> = bits.type_bit_maps().collect();
    assert!(types.contains(&RecordType::TXT) && !types.contains(&RecordType::A));

    // closest encloser: explicit.dev exists, has no wildcard, so below it is NXDOMAIN even though *.dev exists
    let r = ask("a.explicit.dev.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        r.authorities
            .iter()
            .filter(|x| x.record_type() == RecordType::NSEC)
            .count()
            >= 1
    );
    // while a name under an existing-but-recordless parent that has no wildcard is NXDOMAIN too
    let r = ask("x.b.c.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    // and the wildcard serves names below a NON-existing intermediate label (y.dev does not exist)
    let r = ask("x.y.dev.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        r.answers
            .iter()
            .filter(|x| x.record_type() == RecordType::A)
            .count(),
        1
    );
    // empty non-terminal with DO: NODATA with a covering NSEC
    let r = ask("b.c.acme.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r
        .authorities
        .iter()
        .any(|x| x.record_type() == RecordType::NSEC));
}
