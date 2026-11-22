#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test assertions on fixtures"
)]
mod common;
use hickory_proto::dnssec::rdata::{DNSSECRData, DS};
use hickory_proto::dnssec::{Algorithm, DigestType};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tas_dns::build::{expected_ds, DsData};
use tas_dns::delegation::{
    DelegationCheck, DelegationError, DsState, Expectation, ParentProbe, ParentView, ProbeError,
    StubParentProbe,
};
use tas_dns::keys::DerivedKeyProvider;
use tas_dns::names::parse_fqdn;
use tas_dns::zone::DnssecPolicy;

fn n(s: &str) -> Name {
    parse_fqdn(s).unwrap()
}

fn check() -> DelegationCheck {
    DelegationCheck {
        our_nameservers: [n("ns1.tas.example"), n("ns2.tas.example")]
            .into_iter()
            .collect(),
        min_ns: 2,
    }
}

fn view(ns: &[&str], ds: Vec<DsData>) -> ParentView {
    ParentView {
        parent_zone: n("example"),
        ns: ns.iter().map(|s| n(s)).collect(),
        ds,
    }
}

fn my_ds() -> Vec<DsData> {
    let k = DerivedKeyProvider::random().unwrap();
    expected_ds(
        &n("acme.example"),
        &DnssecPolicy {
            ksk_gen: 0,
            ksk_next: None,
            origin: 0,
        },
        &k,
    )
    .unwrap()
}

fn ds(tag: u16) -> DsData {
    DsData {
        key_tag: tag,
        algorithm: 13,
        digest_type: 2,
        digest: vec![u8::try_from(tag).unwrap(); 32],
    }
}

#[test]
fn rules_table() {
    let c = check();
    let unsigned = Expectation {
        expected_ds: vec![],
    };
    let mine = my_ds();
    let signed = Expectation {
        expected_ds: mine.clone(),
    };

    // not delegated at all
    assert_eq!(
        c.evaluate(&view(&[], vec![]), &unsigned),
        Err(DelegationError::NotDelegated)
    );
    // delegated to us, unsigned: fine
    let ok = c
        .evaluate(
            &view(&["ns1.tas.example", "ns2.tas.example"], vec![]),
            &unsigned,
        )
        .unwrap();
    assert_eq!((ok.ours, ok.ds), (2, DsState::Unsigned));
    // case-insensitive names are already folded by the parser; a third-party NS makes it lame
    match c.evaluate(
        &view(
            &["ns1.tas.example", "ns2.tas.example", "ns.other.example"],
            vec![],
        ),
        &unsigned,
    ) {
        Err(DelegationError::Lame { foreign }) => assert_eq!(foreign, vec!["ns.other.example."]),
        o => panic!("{o:?}"),
    }
    assert!(matches!(
        c.evaluate(&view(&["ns.other.example"], vec![]), &unsigned),
        Err(DelegationError::Lame { .. })
    ));
    // only one of our two nameservers: not enough redundancy
    assert_eq!(
        c.evaluate(&view(&["ns1.tas.example"], vec![]), &unsigned),
        Err(DelegationError::Insufficient { have: 1, need: 2 })
    );
    // a deployment with a single nameserver needs only that one
    let single = DelegationCheck {
        our_nameservers: [n("ns1.tas.example")].into_iter().collect(),
        min_ns: 2,
    };
    assert!(single
        .evaluate(&view(&["ns1.tas.example"], vec![]), &unsigned)
        .is_ok());

    let both = &["ns1.tas.example", "ns2.tas.example"];
    // unsigned zone under a leftover DS -> SERVFAIL for validating resolvers: refuse
    assert_eq!(
        c.evaluate(&view(both, vec![ds(1)]), &unsigned),
        Err(DelegationError::UnsignedUnderDs)
    );
    // signed zone, DS for somebody else's key: stale DS, refuse
    assert_eq!(
        c.evaluate(&view(both, vec![ds(1)]), &signed),
        Err(DelegationError::StaleDs)
    );
    // signed zone, no DS yet: accepted, and we tell the customer what to publish
    assert_eq!(
        c.evaluate(&view(both, vec![]), &signed).unwrap().ds,
        DsState::SignedAwaitingDs {
            publish: mine.clone()
        }
    );
    // signed zone, DS matches our KSK: anchored
    assert_eq!(
        c.evaluate(&view(both, mine.clone()), &signed).unwrap().ds,
        DsState::SignedAnchored { extra: vec![] }
    );
    // matching DS plus a leftover one: still valid, leftover is reported
    let mut mixed = mine.clone();
    mixed.push(ds(7));
    assert_eq!(
        c.evaluate(&view(both, mixed), &signed).unwrap().ds,
        DsState::SignedAnchored { extra: vec![ds(7)] }
    );
    // a DS with our tag but a different digest (an attacker's guess) does not match
    let mut forged = mine[0].clone();
    forged.digest[0] ^= 1;
    assert_eq!(
        c.evaluate(&view(both, vec![forged]), &signed),
        Err(DelegationError::StaleDs)
    );
    // errors never print raw foreign names unescaped
    let e = DelegationError::Lame {
        foreign: vec!["evil\n.example".into()],
    };
    assert!(!e.to_string().contains('\n'));
}

struct Fixed(Result<ParentView, ProbeError>);

#[async_trait::async_trait]
impl ParentProbe for Fixed {
    async fn parent_view(&self, _zone: &Name) -> Result<ParentView, ProbeError> {
        self.0.clone()
    }
}

#[tokio::test]
async fn a_failing_probe_fails_closed_and_the_fake_probe_is_injectable() {
    let c = check();
    let unsigned = Expectation {
        expected_ds: vec![],
    };
    let ok = Fixed(Ok(view(&["ns1.tas.example", "ns2.tas.example"], vec![])));
    assert!(c.check(&ok, &n("acme.example"), &unsigned).await.is_ok());
    for e in [
        ProbeError::NoParent,
        ProbeError::Inconsistent,
        ProbeError::Unreachable("x".into()),
    ] {
        let r = c
            .check(&Fixed(Err(e.clone())), &n("acme.example"), &unsigned)
            .await;
        assert_eq!(r, Err(DelegationError::Probe(e)));
    }
}

// ── the real probe against fake resolver / parent servers ────────────────────────────────────

async fn fake<F>(f: F) -> SocketAddr
where
    F: Fn(&Message) -> Option<Message> + Send + Sync + 'static,
{
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let f = Arc::new(f);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            if let Some(mut r) = f(&q) {
                r.metadata.id = q.metadata.id;
                let _ = sock.send_to(&r.to_bytes().unwrap(), from).await;
            }
        }
    });
    addr
}

fn answer(q: &Message, rcode: ResponseCode, answers: Vec<Record>, auth: Vec<Record>) -> Message {
    let mut r = q.clone().into_response();
    r.metadata.response_code = rcode;
    r.insert_answers(answers);
    r.insert_authorities(auth);
    r
}

fn ns_rec(owner: &str, host: &str) -> Record {
    Record::from_rdata(n(owner), 300, RData::NS(NS(n(host))))
}

fn ds_rec(owner: &str, d: &DsData) -> Record {
    let ds = DS::new(
        d.key_tag,
        Algorithm::ECDSAP256SHA256,
        DigestType::SHA256,
        d.digest.clone(),
    );
    Record::from_rdata(n(owner), 300, RData::DNSSEC(DNSSECRData::DS(ds)))
}

/// A resolver that knows `example` is served by ns.parent.example at 127.0.0.1.
async fn fake_resolver() -> SocketAddr {
    fake(|q| {
        let qq = q.queries.first()?;
        let name = qq.name().to_ascii();
        Some(match (name.as_str(), qq.query_type()) {
            ("example.", RecordType::NS) => answer(
                q,
                ResponseCode::NoError,
                vec![ns_rec("example.", "ns.parent.example.")],
                vec![],
            ),
            ("ns.parent.example.", RecordType::A) => answer(
                q,
                ResponseCode::NoError,
                vec![Record::from_rdata(
                    n("ns.parent.example"),
                    300,
                    RData::A(A("127.0.0.1".parse().unwrap())),
                )],
                vec![],
            ),
            _ => answer(q, ResponseCode::NoError, vec![], vec![]), // NODATA
        })
    })
    .await
}

fn parent_server_answering(
    ns_hosts: Vec<&'static str>,
    ds_set: Vec<DsData>,
) -> impl Fn(&Message) -> Option<Message> + Send + Sync + 'static {
    move |q| {
        let qq = q.queries.first()?;
        assert!(
            !q.metadata.recursion_desired,
            "the probe must not ask the parent to recurse"
        );
        if qq.name().to_ascii() != "acme.example." {
            return Some(answer(q, ResponseCode::NXDomain, vec![], vec![]));
        }
        Some(match qq.query_type() {
            // a referral: delegation NS in the AUTHORITY section, AA=0
            RecordType::NS => answer(
                q,
                ResponseCode::NoError,
                vec![],
                ns_hosts
                    .iter()
                    .map(|h| ns_rec("acme.example.", h))
                    .collect(),
            ),
            RecordType::DS => {
                let mut r = answer(
                    q,
                    ResponseCode::NoError,
                    ds_set.iter().map(|d| ds_rec("acme.example.", d)).collect(),
                    vec![],
                );
                r.metadata.authoritative = true;
                r
            }
            _ => answer(q, ResponseCode::NoError, vec![], vec![]),
        })
    }
}

#[tokio::test]
async fn the_stub_probe_reads_the_delegation_and_ds_from_the_parents_own_servers() {
    let resolver = fake_resolver().await;
    let d = ds(42);
    let parent = fake(parent_server_answering(
        vec!["ns1.tas.example.", "ns2.tas.example."],
        vec![d.clone()],
    ))
    .await;
    let probe = StubParentProbe::new(resolver).with_parent_port(parent.port());
    let v = probe.parent_view(&n("acme.example")).await.unwrap();
    assert_eq!(v.parent_zone, n("example"));
    assert_eq!(
        v.ns,
        [n("ns1.tas.example"), n("ns2.tas.example")]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(v.ds, vec![d.clone()]);
    // end to end through the pure check: a stale DS is caught
    let signed = Expectation {
        expected_ds: my_ds(),
    };
    assert_eq!(
        check().check(&probe, &n("acme.example"), &signed).await,
        Err(DelegationError::StaleDs)
    );
    // and a non-delegated zone (parent returns no NS)
    let parent2 = fake(parent_server_answering(vec![], vec![])).await;
    let probe2 = StubParentProbe::new(resolver).with_parent_port(parent2.port());
    let r = check()
        .check(
            &probe2,
            &n("acme.example"),
            &Expectation {
                expected_ds: vec![],
            },
        )
        .await;
    assert_eq!(r, Err(DelegationError::NotDelegated));
}

#[tokio::test]
async fn the_stub_probe_fails_closed() {
    // resolver that knows nothing: no parent
    let blank = fake(|q| Some(answer(q, ResponseCode::NoError, vec![], vec![]))).await;
    let p = StubParentProbe::new(blank);
    assert_eq!(
        p.parent_view(&n("acme.example")).await,
        Err(ProbeError::NoParent)
    );
    // unreachable resolver
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let p = StubParentProbe::new(dead);
    assert!(matches!(
        p.parent_view(&n("acme.example")).await,
        Err(ProbeError::Unreachable(_))
    ));
    // parent that SERVFAILs
    let resolver = fake_resolver().await;
    let sf = fake(|q| Some(answer(q, ResponseCode::ServFail, vec![], vec![]))).await;
    let p = StubParentProbe::new(resolver).with_parent_port(sf.port());
    assert!(matches!(
        p.parent_view(&n("acme.example")).await,
        Err(ProbeError::Unreachable(_))
    ));
    // parent nameservers that disagree with each other: refuse rather than pick one
    let r2 = fake(|q| {
        let qq = q.queries.first()?;
        let name = qq.name().to_ascii();
        Some(match (name.as_str(), qq.query_type()) {
            ("example.", RecordType::NS) => answer(
                q,
                ResponseCode::NoError,
                vec![
                    ns_rec("example.", "a.parent.example."),
                    ns_rec("example.", "b.parent.example."),
                ],
                vec![],
            ),
            ("a.parent.example.", RecordType::A) => answer(
                q,
                ResponseCode::NoError,
                vec![Record::from_rdata(
                    n("a.parent.example"),
                    300,
                    RData::A(A("127.0.0.1".parse().unwrap())),
                )],
                vec![],
            ),
            ("b.parent.example.", RecordType::A) => answer(
                q,
                ResponseCode::NoError,
                vec![Record::from_rdata(
                    n("b.parent.example"),
                    300,
                    RData::A(A("127.0.0.2".parse().unwrap())),
                )],
                vec![],
            ),
            _ => answer(q, ResponseCode::NoError, vec![], vec![]),
        })
    })
    .await;
    let pa = fake(parent_server_answering(vec!["ns1.tas.example."], vec![])).await;
    // second parent server on 127.0.0.2 same port
    let sock = tokio::net::UdpSocket::bind(format!("127.0.0.2:{}", pa.port())).await;
    if let Ok(sock) = sock {
        let h = parent_server_answering(vec!["ns.evil.example."], vec![]);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(q) = Message::from_bytes(&buf[..len]) else {
                    continue;
                };
                if let Some(mut r) = h(&q) {
                    r.metadata.id = q.metadata.id;
                    let _ = sock.send_to(&r.to_bytes().unwrap(), from).await;
                }
            }
        });
        let p = StubParentProbe::new(r2).with_parent_port(pa.port());
        assert_eq!(
            p.parent_view(&n("acme.example")).await,
            Err(ProbeError::Inconsistent)
        );
    }
    let _ = SOA::new;
}
