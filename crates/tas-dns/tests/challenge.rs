#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_net::client::ClientHandle;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tas_dns::challenge::{label_id, ChallengeDoc, TokenDoc};
use tas_dns::challenge_auth::{ChallengeAuthority, ChallengeError, LocalPublisher};
use tas_dns::server::ServerLimits;
use tas_dns::zone::TenantId;
use transport::acme::Dns01Responder;
use transport::zone_sync::{ApplyOutcome, ObjectKind, SignedObject};

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn tenant(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

struct Env {
    t: TestNode,
    auth: Arc<ChallengeAuthority>,
}

async fn env() -> Env {
    let t = start(ServerLimits::default()).await;
    let clock = t.clock.clone();
    let clk: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || clock.load(Ordering::SeqCst));
    let auth = Arc::new(ChallengeAuthority::new(
        kp(2),
        parse_fqdn("chal.tas.example").unwrap(),
        t.node.db.clone(),
        Arc::new(LocalPublisher(t.node.db.clone())),
        clk,
    ));
    Env { t, auth }
}

async fn txt(e: &Env, label_fqdn: &str) -> (ResponseCode, Vec<String>) {
    let r = parse(
        &udp_exchange(
            e.t.udp,
            &query_packet(5, label_fqdn, RecordType::TXT, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    let v = r
        .answers
        .iter()
        .filter_map(|a| match &a.data {
            RData::TXT(t) => Some(
                t.txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    (r.metadata.response_code, v)
}

use tas_dns::names::parse_fqdn;

#[tokio::test]
async fn labels_are_random_idempotent_and_distinct_per_tenant_and_name() {
    let e = env().await;
    let a1 = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    assert_eq!(a1.label.len(), 32);
    assert!(a1
        .label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
    assert_eq!(a1.target, format!("{}.chal.tas.example", a1.label));
    assert_eq!(
        a1.cname,
        format!(
            "_acme-challenge.acme.example CNAME {}.chal.tas.example.",
            a1.label
        )
    );
    // idempotent: renewals never need the customer to touch DNS again
    assert_eq!(
        e.auth
            .bind(&tenant("tenant-a"), "acme.example")
            .await
            .unwrap(),
        a1
    );
    assert_eq!(
        e.auth
            .bind(&tenant("tenant-a"), "ACME.example.")
            .await
            .unwrap(),
        a1,
        "case/dot-insensitive"
    );
    // the wildcard and the apex share the challenge name, hence the label
    assert_eq!(
        e.auth
            .bind(&tenant("tenant-a"), "*.acme.example")
            .await
            .unwrap(),
        a1
    );
    // a different name, and a different tenant for the same name, get different labels
    let a2 = e
        .auth
        .bind(&tenant("tenant-a"), "other.example")
        .await
        .unwrap();
    let b1 = e
        .auth
        .bind(&tenant("tenant-b"), "acme.example")
        .await
        .unwrap();
    assert!(a1.label != a2.label && a1.label != b1.label && a2.label != b1.label);
    // invalid names
    for bad in ["", "a b.example", "x..y", "a.*.example"] {
        assert_eq!(
            e.auth.bind(&tenant("tenant-a"), bad).await.unwrap_err(),
            ChallengeError::InvalidName,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn the_zone_serves_only_txt_at_bound_labels_with_live_tokens() {
    let e = env().await;
    let a = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    let fq = format!("{}.", a.target);
    // bound but no token yet: the name does not exist
    assert_eq!(txt(&e, &fq).await, (ResponseCode::NXDomain, vec![]));
    e.auth
        .publish_token(&tenant("tenant-a"), "acme.example", "tokenAAA")
        .await
        .unwrap();
    assert_eq!(
        txt(&e, &fq).await,
        (ResponseCode::NoError, vec!["tokenAAA".to_string()])
    );
    // another type at the label: NODATA (the name exists, only TXT is ever served)
    for ty in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SOA,
        RecordType::CAA,
    ] {
        let r = parse(
            &udp_exchange(e.t.udp, &query_packet(6, &fq, ty, None, false), 1000)
                .await
                .unwrap(),
        );
        assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{ty}");
        assert!(
            r.answers.is_empty(),
            "{ty} must not be served at a challenge label"
        );
        assert!(r
            .authorities
            .iter()
            .any(|x| x.record_type() == RecordType::SOA));
    }
    // ANY is minimal: one rrset
    let r = parse(
        &udp_exchange(
            e.t.udp,
            &query_packet(7, &fq, RecordType::ANY, None, false),
            1000,
        )
        .await
        .unwrap(),
    );
    assert!(r.answers.iter().all(|x| x.record_type() == RecordType::TXT));
    // names that are not exactly one label under the zone, wildcards, and unbound labels: NXDOMAIN
    for name in [
        format!("x.{fq}"),
        "chal.tas.example.x.".to_string(),
        format!("{}.chal.tas.example.", "a".repeat(32)),
        "_acme-challenge.chal.tas.example.".to_string(),
        "*.chal.tas.example.".to_string(),
        "www.chal.tas.example.".to_string(),
    ] {
        let r = parse(
            &udp_exchange(
                e.t.udp,
                &query_packet(8, &name, RecordType::TXT, None, false),
                1000,
            )
            .await
            .unwrap(),
        );
        assert!(
            matches!(
                r.metadata.response_code,
                ResponseCode::NXDomain | ResponseCode::Refused
            ),
            "{name}: {:?}",
            r.metadata.response_code
        );
        assert!(r.answers.is_empty(), "{name}");
    }
    // apex: SOA and NS only
    let mut c = udp_client(e.t.udp);
    let r = c
        .query(n("chal.tas.example."), DNSClass::IN, RecordType::NS)
        .await
        .unwrap();
    assert_eq!(r.answers.len(), 2);
    let r = c
        .query(n("chal.tas.example."), DNSClass::IN, RecordType::SOA)
        .await
        .unwrap();
    assert_eq!(r.answers.len(), 1);
    let r = c
        .query(n("chal.tas.example."), DNSClass::IN, RecordType::TXT)
        .await
        .unwrap();
    assert!(r.answers.is_empty());
    // no transfers of the challenge zone either
    let r = parse(
        &tcp_exchange(
            e.t.tcp,
            &query_packet(9, "chal.tas.example.", RecordType::AXFR, None, false),
        )
        .await
        .unwrap(),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn concurrent_orders_share_a_label_and_clearing_one_keeps_the_other_and_tokens_expire() {
    let e = env().await;
    let a = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    let fq = format!("{}.", a.target);
    // `example.com` and `*.example.com` in one order: two tokens at one label
    e.auth
        .publish_token(&tenant("tenant-a"), "acme.example", "tok1")
        .await
        .unwrap();
    e.auth
        .publish_token(&tenant("tenant-a"), "*.acme.example", "tok2")
        .await
        .unwrap();
    let (_, mut v) = txt(&e, &fq).await;
    v.sort();
    assert_eq!(v, vec!["tok1", "tok2"]);
    e.auth
        .clear_token(&tenant("tenant-a"), "acme.example", "tok1")
        .await
        .unwrap();
    assert_eq!(
        txt(&e, &fq).await.1,
        vec!["tok2"],
        "only the cleared value is removed"
    );
    e.auth
        .clear_token(&tenant("tenant-a"), "acme.example", "tok2")
        .await
        .unwrap();
    assert_eq!(
        txt(&e, &fq).await.0,
        ResponseCode::NXDomain,
        "tokens are cleared after validation"
    );
    // a token the worker forgot to clear expires by itself
    e.auth
        .publish_token(&tenant("tenant-a"), "acme.example", "forgotten")
        .await
        .unwrap();
    assert_eq!(txt(&e, &fq).await.1, vec!["forgotten"]);
    e.t.clock.fetch_add(601, Ordering::SeqCst);
    assert_eq!(txt(&e, &fq).await.0, ResponseCode::NXDomain);
    // the cap on live tokens per label
    for i in 0..6 {
        e.auth
            .publish_token(&tenant("tenant-a"), "acme.example", &format!("t{i}"))
            .await
            .unwrap();
    }
    assert_eq!(txt(&e, &fq).await.1.len(), 4);
}

#[tokio::test]
async fn labels_are_permanently_bound_and_never_reissued_even_after_release() {
    let e = env().await;
    let a = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    e.auth
        .publish_token(&tenant("tenant-a"), "acme.example", "tokA")
        .await
        .unwrap();
    e.auth
        .release(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    let fq = format!("{}.", a.target);
    assert_eq!(
        txt(&e, &fq).await.0,
        ResponseCode::NXDomain,
        "a released label serves nothing"
    );
    assert!(
        e.t.node.db.label_exists(&a.label),
        "the label stays reserved"
    );
    // another tenant takes the same name: gets a DIFFERENT label; the old CNAME target is dead to them
    let b = e
        .auth
        .bind(&tenant("tenant-b"), "acme.example")
        .await
        .unwrap();
    assert_ne!(a.label, b.label);
    e.auth
        .publish_token(&tenant("tenant-b"), "acme.example", "tokB")
        .await
        .unwrap();
    assert_eq!(
        txt(&e, &fq).await.0,
        ResponseCode::NXDomain,
        "B's token is not served at A's old label"
    );
    assert_eq!(txt(&e, &format!("{}.", b.target)).await.1, vec!["tokB"]);
    // tenant isolation: A can no longer publish for the name via B's label, and an unbound pair is refused
    assert_eq!(
        e.auth
            .publish_token(&tenant("tenant-c"), "acme.example", "x")
            .await
            .unwrap_err(),
        ChallengeError::NotBound
    );
    // the original tenant coming back gets its original label (its customer CNAME never changes)
    let a_again = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    assert_eq!(a_again.label, a.label);
    e.auth
        .publish_token(&tenant("tenant-a"), "acme.example", "tokA2")
        .await
        .unwrap();
    assert_eq!(txt(&e, &fq).await.1, vec!["tokA2"]);

    // even the challenge authority key cannot rebind a label (a compromised/buggy issuer): refused by nodes
    let id = label_id(&a.label, &parse_fqdn("chal.tas.example").unwrap()).unwrap();
    let cur = e.t.node.db.object(ObjectKind::Challenge, &id).unwrap();
    let hijack = ChallengeDoc {
        tenant: "tenant-b".into(),
        name: "acme.example".into(),
        tokens: vec![TokenDoc {
            v: "evil".into(),
            exp: unix_now() + 60,
        }],
        released: false,
    };
    let obj = SignedObject::sign(
        &kp(2),
        ObjectKind::Challenge,
        id.clone(),
        1,
        cur.version() + 1,
        serde_json::to_vec(&hijack).unwrap(),
    )
    .unwrap();
    assert_eq!(
        e.t.node.db.apply_object(obj),
        ApplyOutcome::Invalid,
        "binding is immutable"
    );
    // nor can it bind a second label to the same (tenant, name)
    let dup_label = "q".repeat(32).replace('q', "a");
    let id2 = label_id(&dup_label, &parse_fqdn("chal.tas.example").unwrap()).unwrap();
    let doc = ChallengeDoc {
        tenant: "tenant-a".into(),
        name: "acme.example".into(),
        tokens: vec![],
        released: false,
    };
    let obj = SignedObject::sign(
        &kp(2),
        ObjectKind::Challenge,
        id2,
        1,
        1,
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    assert_eq!(
        e.t.node.db.apply_object(obj),
        ApplyOutcome::Invalid,
        "one label per (tenant, name)"
    );
}

#[tokio::test]
async fn only_the_challenge_authority_can_write_and_content_is_validated() {
    let e = env().await;
    let a = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    let zone = parse_fqdn("chal.tas.example").unwrap();
    let id = label_id(&a.label, &zone).unwrap();
    let now = unix_now();
    let doc = |tokens: Vec<TokenDoc>| ChallengeDoc {
        tenant: "tenant-a".into(),
        name: "acme.example".into(),
        tokens,
        released: false,
    };
    let sign = |key: u8, id: Vec<u8>, ver: u64, d: &ChallengeDoc| {
        SignedObject::sign(
            &kp(key),
            ObjectKind::Challenge,
            id,
            1,
            ver,
            serde_json::to_vec(d).unwrap(),
        )
        .unwrap()
    };
    let ok_tok = TokenDoc {
        v: "fine".into(),
        exp: now + 60,
    };
    // a tenant's own (zone owner) key, the registrar key, anyone: not the authority
    for k in [10u8, 1, 99] {
        assert_eq!(
            e.t.node
                .db
                .apply_object(sign(k, id.clone(), 50, &doc(vec![ok_tok.clone()]))),
            ApplyOutcome::Unauthorized,
            "key {k}"
        );
    }
    let bad: Vec<(Vec<u8>, ChallengeDoc, &str)> = vec![
        (
            id.clone(),
            doc(vec![TokenDoc {
                v: "has space".into(),
                exp: now + 60,
            }]),
            "token charset",
        ),
        (
            id.clone(),
            doc(vec![TokenDoc {
                v: "x".repeat(200),
                exp: now + 60,
            }]),
            "token length",
        ),
        (
            id.clone(),
            doc(vec![TokenDoc {
                v: "ok".into(),
                exp: now + 86_400,
            }]),
            "token lifetime",
        ),
        (
            id.clone(),
            doc((0..9)
                .map(|i| TokenDoc {
                    v: format!("t{i}"),
                    exp: now + 60,
                })
                .collect()),
            "token count",
        ),
        (
            label_id(&"b".repeat(32), &zone)
                .map(|mut v| {
                    v.insert(0, 0);
                    v
                })
                .unwrap_or_default(),
            doc(vec![]),
            "garbage id",
        ),
    ];
    for (i, d, why) in bad {
        if i.is_empty() {
            continue;
        }
        assert_eq!(
            e.t.node.db.apply_object(sign(2, i, 60, &d)),
            ApplyOutcome::Invalid,
            "{why}"
        );
    }
    // an id outside the challenge zone or deeper than one label
    let outside =
        tas_dns::names::wire_id(&parse_fqdn(&format!("{}.other.example", a.label)).unwrap());
    assert_eq!(
        e.t.node.db.apply_object(sign(2, outside, 61, &doc(vec![]))),
        ApplyOutcome::Invalid
    );
    let deeper =
        tas_dns::names::wire_id(&parse_fqdn(&format!("x.{}.chal.tas.example", a.label)).unwrap());
    assert_eq!(
        e.t.node.db.apply_object(sign(2, deeper, 62, &doc(vec![]))),
        ApplyOutcome::Invalid
    );
    // nothing leaked into the served zone
    assert_eq!(
        txt(&e, &format!("{}.", a.target)).await.0,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn the_dns01_responder_works_through_the_transport_trait_and_is_tenant_scoped() {
    let e = env().await;
    let a = e
        .auth
        .bind(&tenant("tenant-a"), "acme.example")
        .await
        .unwrap();
    let responder: Arc<dyn Dns01Responder> = Arc::new(e.auth.responder_for(tenant("tenant-a")));
    let value = "43-chars-of-base64url-sha256-digest_of_key_auth";
    responder.publish_txt("acme.example", value).await.unwrap();
    assert_eq!(txt(&e, &format!("{}.", a.target)).await.1, vec![value]);
    responder.remove_txt("acme.example", value).await;
    assert_eq!(
        txt(&e, &format!("{}.", a.target)).await.0,
        ResponseCode::NXDomain
    );
    // a name the tenant was never onboarded for: fails closed, nothing published
    assert!(responder
        .publish_txt("never-onboarded.example", value)
        .await
        .is_err());
    // a worker acting for tenant B cannot publish at tenant A's name
    let other: Arc<dyn Dns01Responder> = Arc::new(e.auth.responder_for(tenant("tenant-b")));
    assert!(other.publish_txt("acme.example", value).await.is_err());
    assert_eq!(
        txt(&e, &format!("{}.", a.target)).await.0,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn bindings_survive_restart_and_quotas_apply() {
    use tas_dns::db::{DbConfig, ZoneDb};
    use tas_dns::store::FileObjectStore;
    let dir = tempfile::tempdir().unwrap();
    let mk = |max_labels: usize| {
        let mut cfg = DbConfig::new(*kp(1).public_key().as_bytes());
        cfg.challenge_zone = Some(parse_fqdn("chal.tas.example").unwrap());
        cfg.challenge_authority = Some(*kp(2).public_key().as_bytes());
        cfg.max_labels_per_tenant = max_labels;
        let store: Arc<dyn tas_dns::store::ObjectStore> =
            Arc::new(FileObjectStore::open(dir.path()).unwrap());
        Arc::new(
            ZoneDb::open(
                cfg,
                store,
                Arc::new(tas_dns::metrics::Metrics::default()),
                Arc::new(unix_now),
            )
            .unwrap()
            .0,
        )
    };
    let mkauth = |db: Arc<ZoneDb>| {
        ChallengeAuthority::new(
            kp(2),
            parse_fqdn("chal.tas.example").unwrap(),
            db.clone(),
            Arc::new(LocalPublisher(db)),
            Arc::new(unix_now),
        )
    };
    let db = mk(2);
    let auth = mkauth(db);
    let l1 = auth.bind(&tenant("tenant-a"), "one.example").await.unwrap();
    auth.bind(&tenant("tenant-a"), "two.example").await.unwrap();
    assert_eq!(
        auth.bind(&tenant("tenant-a"), "three.example")
            .await
            .unwrap_err(),
        ChallengeError::Quota,
        "labels are permanent, so the cap is a lifetime cap"
    );
    auth.release(&tenant("tenant-a"), "one.example")
        .await
        .unwrap();
    assert_eq!(
        auth.bind(&tenant("tenant-a"), "three.example")
            .await
            .unwrap_err(),
        ChallengeError::Quota,
        "release does not free a label"
    );
    drop(auth);
    // restart: the same label comes back
    let auth = mkauth(mk(2));
    assert_eq!(
        auth.bind(&tenant("tenant-a"), "one.example")
            .await
            .unwrap()
            .label,
        l1.label
    );
    auth.publish_token(&tenant("tenant-a"), "one.example", "afterrestart")
        .await
        .unwrap();
}
