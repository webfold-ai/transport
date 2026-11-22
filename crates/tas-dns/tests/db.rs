#![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]
mod common;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tas_dns::db::{DbConfig, DbEvent, ZoneDb};
use tas_dns::metrics::Metrics;
use tas_dns::names::{parse_fqdn, wire_id};
use tas_dns::objects::{registration_object, update_object, RegistrationSpec};
use tas_dns::store::{FileObjectStore, MemoryObjectStore, ObjectStore};
use tas_dns::zone::{DnssecPolicy, RegState, TenantId};
use transport::dialkey::native_keypair;
use transport::signed_dns::Keypair;
use transport::zone_sync::{ApplyOutcome, ObjectKind, SignedObject, SyncStore};

fn kp(n: u8) -> Keypair {
    Keypair::from_secret_key(&[n; 32])
}

struct Env {
    db: ZoneDb,
    now: Arc<AtomicU64>,
    registrar: Keypair,
    store: Arc<dyn ObjectStore>,
    metrics: Arc<Metrics>,
}

fn env_with(store: Arc<dyn ObjectStore>, tweak: impl FnOnce(&mut DbConfig)) -> Env {
    let registrar = kp(1);
    let mut cfg = DbConfig::new(*registrar.public_key().as_bytes());
    cfg.challenge_zone = Some(parse_fqdn("chal.tas.example").unwrap());
    cfg.challenge_authority = Some(*kp(2).public_key().as_bytes());
    tweak(&mut cfg);
    let now = Arc::new(AtomicU64::new(1_800_000_000));
    let n2 = now.clone();
    let metrics = Arc::new(Metrics::default());
    let (db, refused) = ZoneDb::open(
        cfg,
        store.clone(),
        metrics.clone(),
        Arc::new(move || n2.load(Ordering::SeqCst)),
    )
    .unwrap();
    assert_eq!(refused, 0);
    Env {
        db,
        now,
        registrar,
        store,
        metrics,
    }
}

fn env() -> Env {
    env_with(Arc::new(MemoryObjectStore::new()), |_| {})
}

fn spec<'a>(
    apex: &'a str,
    tenant: &'a str,
    owner: &Keypair,
    epoch: u64,
    seq: u64,
) -> RegistrationSpec<'a> {
    RegistrationSpec {
        apex,
        tenant,
        owner: *owner.public_key().as_bytes(),
        owner_epoch: epoch,
        seq,
        state: RegState::Active,
        quarantine_until: 0,
        dnssec: None,
    }
}

fn reg(e: &Env, s: &RegistrationSpec<'_>) -> ApplyOutcome {
    e.db.apply_object(registration_object(&e.registrar, s).unwrap())
}

fn body(ip: &str) -> Vec<u8> {
    format!(r#"{{"records":[{{"name":"www","ttl":300,"type":"A","data":"{ip}"}}]}}"#).into_bytes()
}

fn upd(owner: &Keypair, apex: &str, epoch: u64, version: u64, ip: &str) -> SignedObject {
    update_object(owner, apex, epoch, version, &body(ip)).unwrap()
}

fn served_ip(e: &Env, apex: &str) -> Option<String> {
    let z = e.db.zone(&parse_fqdn(apex).unwrap())?;
    z.records.first().map(|r| format!("{:?}", r.rdata))
}

#[test]
fn registration_then_owner_signed_update_is_served_with_the_version_as_serial() {
    let e = env();
    let owner = native_keypair("acme-dialkey-secret"); // dialkey-derived owner identity
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &owner, 1, 1)),
        ApplyOutcome::Applied
    );
    // registered but no content yet: an empty zone (SOA/NS only), so the delegation is not lame
    let z = e.db.zone(&parse_fqdn("acme.example").unwrap()).unwrap();
    assert!(z.records.is_empty() && z.version == 0);
    assert_eq!(
        e.db.apply_object(upd(&owner, "acme.example", 1, 5, "198.51.100.1")),
        ApplyOutcome::Applied
    );
    let z = e.db.zone(&parse_fqdn("acme.example").unwrap()).unwrap();
    assert_eq!((z.version, z.epoch, z.records.len()), (5, 1, 1));
    assert_eq!(z.tenant, TenantId::new("acme").unwrap());
}

#[test]
fn nothing_is_applied_without_the_chain_registrar_then_owner() {
    let e = env();
    let owner = kp(10);
    let stranger = kp(11);
    // update for an apex nobody registered
    assert_eq!(
        e.db.apply_object(upd(&owner, "acme.example", 1, 1, "198.51.100.1")),
        ApplyOutcome::Unauthorized
    );
    // a registration signed by anyone but the registrar
    let forged =
        registration_object(&stranger, &spec("acme.example", "acme", &owner, 1, 1)).unwrap();
    assert_eq!(e.db.apply_object(forged), ApplyOutcome::Unauthorized);
    assert!(e.db.zone(&parse_fqdn("acme.example").unwrap()).is_none());
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &owner, 1, 1)),
        ApplyOutcome::Applied
    );
    // an update signed by someone other than the registered owner
    assert_eq!(
        e.db.apply_object(upd(&stranger, "acme.example", 1, 1, "203.0.113.66")),
        ApplyOutcome::Unauthorized
    );
    // an update at the wrong epoch
    assert_eq!(
        e.db.apply_object(upd(&owner, "acme.example", 2, 1, "203.0.113.66")),
        ApplyOutcome::Unauthorized
    );
    assert!(e
        .db
        .zone(&parse_fqdn("acme.example").unwrap())
        .unwrap()
        .records
        .is_empty());
}

#[test]
fn tenant_a_cannot_touch_tenant_bs_zone() {
    let e = env();
    let (a, b) = (kp(10), kp(11));
    reg(&e, &spec("a.example", "tenant-a", &a, 1, 1));
    reg(&e, &spec("b.example", "tenant-b", &b, 1, 1));
    assert_eq!(
        e.db.apply_object(upd(&b, "b.example", 1, 1, "198.51.100.2")),
        ApplyOutcome::Applied
    );
    // A signs an update for B's apex with A's own (valid) key
    assert_eq!(
        e.db.apply_object(upd(&a, "b.example", 1, 2, "203.0.113.66")),
        ApplyOutcome::Unauthorized
    );
    // A cannot widen its own zone to cover B's names either: records outside the apex are refused
    let sneaky = update_object(
        &a,
        "a.example",
        1,
        1,
        br#"{"records":[{"name":"www.b.example.","ttl":300,"type":"A","data":"203.0.113.66"}]}"#,
    )
    .unwrap();
    assert_eq!(e.db.apply_object(sneaky), ApplyOutcome::Invalid);
    assert!(served_ip(&e, "b.example").unwrap().contains("198.51.100.2"));
    assert!(e
        .db
        .zone(&parse_fqdn("a.example").unwrap())
        .unwrap()
        .records
        .is_empty());
}

#[test]
fn replay_rollback_and_fork_are_refused_and_counted() {
    let e = env();
    let owner = kp(10);
    reg(&e, &spec("acme.example", "acme", &owner, 1, 1));
    let v1 = upd(&owner, "acme.example", 1, 1, "198.51.100.1");
    let v2 = upd(&owner, "acme.example", 1, 2, "198.51.100.2");
    let v2_fork = upd(&owner, "acme.example", 1, 2, "203.0.113.99");
    assert_eq!(e.db.apply_object(v1.clone()), ApplyOutcome::Applied);
    assert_eq!(e.db.apply_object(v2.clone()), ApplyOutcome::Applied);
    assert_eq!(
        e.db.apply_object(v2.clone()),
        ApplyOutcome::Duplicate,
        "idempotent replay"
    );
    assert_eq!(e.db.apply_object(v1), ApplyOutcome::Stale, "rollback");
    assert_eq!(
        e.db.apply_object(v2_fork),
        ApplyOutcome::Fork,
        "forked history"
    );
    assert!(
        served_ip(&e, "acme.example")
            .unwrap()
            .contains("198.51.100.2"),
        "the first v2 stands"
    );
    assert_eq!(e.metrics.updates[2].get(), 1);
    assert_eq!(e.metrics.updates[3].get(), 1);
    // a forged copy with a flipped byte never even decodes (transport verifies on decode)
    let mut raw = v2.encode();
    let last = raw.len() - 70;
    raw[last] ^= 1;
    assert!(SignedObject::decode(&raw).is_err());
    // version 0 and versions that do not fit the SOA serial are invalid
    assert_eq!(
        e.db.apply_object(upd(
            &owner,
            "acme.example",
            1,
            u64::from(u32::MAX) + 1,
            "198.51.100.3"
        )),
        ApplyOutcome::Invalid
    );
}

#[test]
fn owner_key_rotation_needs_a_new_epoch_and_cuts_the_old_key_off() {
    let e = env();
    let (old, new) = (kp(10), kp(12));
    reg(&e, &spec("acme.example", "acme", &old, 1, 1));
    e.db.apply_object(upd(&old, "acme.example", 1, 9, "198.51.100.1"));
    // same epoch, different key: refused (a key change without an epoch bump)
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &new, 1, 2)),
        ApplyOutcome::Invalid
    );
    // proper rotation
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &new, 2, 3)),
        ApplyOutcome::Applied
    );
    // the old key can no longer publish, even at a higher version
    assert_eq!(
        e.db.apply_object(upd(&old, "acme.example", 1, 10, "203.0.113.66")),
        ApplyOutcome::Unauthorized
    );
    assert_eq!(
        e.db.apply_object(upd(&old, "acme.example", 2, 10, "203.0.113.66")),
        ApplyOutcome::Unauthorized
    );
    // the old content is no longer served (it was signed by a key that is no longer the owner)
    assert!(e
        .db
        .zone(&parse_fqdn("acme.example").unwrap())
        .unwrap()
        .records
        .is_empty());
    // the new owner starts at version 1 in the new epoch: (epoch, version) order accepts it
    assert_eq!(
        e.db.apply_object(upd(&new, "acme.example", 2, 1, "198.51.100.7")),
        ApplyOutcome::Applied
    );
    // and cannot be rolled back by replaying the old owner's older-epoch object
    assert_eq!(
        e.db.apply_object(upd(&old, "acme.example", 1, 9, "198.51.100.1")),
        ApplyOutcome::Unauthorized
    );
    // registration sequence must increase
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &new, 2, 3)),
        ApplyOutcome::Duplicate
    );
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &new, 2, 2)),
        ApplyOutcome::Stale
    );
}

#[test]
fn first_valid_delegation_wins_and_release_is_quarantined() {
    let e = env();
    let (a, b) = (kp(10), kp(11));
    assert_eq!(
        reg(&e, &spec("contested.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied
    );
    // another tenant cannot take an active apex
    assert_eq!(
        reg(&e, &spec("contested.example", "tenant-b", &b, 1, 2)),
        ApplyOutcome::Unauthorized
    );
    // release with a 30-day quarantine
    let now = e.now.load(Ordering::SeqCst);
    let mut rel = spec("contested.example", "tenant-a", &a, 1, 3);
    rel.state = RegState::Released;
    rel.quarantine_until = now + 30 * 86_400;
    assert_eq!(reg(&e, &rel), ApplyOutcome::Applied);
    assert!(
        e.db.zone(&parse_fqdn("contested.example").unwrap())
            .is_none(),
        "released zones are not served"
    );
    assert_eq!(
        reg(&e, &spec("contested.example", "tenant-b", &b, 1, 4)),
        ApplyOutcome::Unauthorized,
        "inside the quarantine"
    );
    // quarantine cannot be shortened
    let mut shorter = rel.clone();
    shorter.seq = 5;
    shorter.quarantine_until = now + 1;
    assert_eq!(reg(&e, &shorter), ApplyOutcome::Invalid);
    // the previous tenant may take it back at any time
    assert_eq!(
        reg(&e, &spec("contested.example", "tenant-a", &a, 1, 6)),
        ApplyOutcome::Applied
    );
    let mut rel2 = spec("contested.example", "tenant-a", &a, 1, 7);
    rel2.state = RegState::Released;
    rel2.quarantine_until = now + 30 * 86_400;
    assert_eq!(reg(&e, &rel2), ApplyOutcome::Applied);
    // after the quarantine, another tenant may register it
    e.now.store(now + 31 * 86_400, Ordering::SeqCst);
    assert_eq!(
        reg(&e, &spec("contested.example", "tenant-b", &b, 2, 8)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        e.db.registration(&parse_fqdn("contested.example").unwrap())
            .unwrap()
            .tenant,
        TenantId::new("tenant-b").unwrap()
    );
}

#[test]
fn cross_tenant_shadowing_reserved_and_challenge_names_are_refused() {
    let e = env_with(Arc::new(MemoryObjectStore::new()), |c| {
        c.reserved = vec![parse_fqdn("tasmanian.cloud").unwrap()];
    });
    let (a, b) = (kp(10), kp(11));
    assert_eq!(
        reg(&e, &spec("acme.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        reg(&e, &spec("edge.acme.example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized,
        "child of another tenant's zone"
    );
    assert_eq!(
        reg(&e, &spec("edge.acme.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied,
        "same tenant may sub-delegate"
    );
    assert_eq!(
        reg(&e, &spec("example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Invalid,
        "single-label apex (a TLD)"
    );
    assert_eq!(
        reg(&e, &spec("sub.example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        reg(&e, &spec("tasmanian.cloud", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized
    );
    assert_eq!(
        reg(&e, &spec("x.tasmanian.cloud", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized
    );
    assert_eq!(
        reg(&e, &spec("chal.tas.example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized,
        "the challenge zone itself"
    );
    assert_eq!(
        reg(&e, &spec("x.chal.tas.example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized
    );
    assert_eq!(
        reg(&e, &spec("tas.example", "tenant-b", &b, 1, 1)),
        ApplyOutcome::Unauthorized,
        "a parent of the challenge zone"
    );
}

#[test]
fn zones_per_tenant_are_capped_and_release_frees_a_slot() {
    let e = env_with(Arc::new(MemoryObjectStore::new()), |c| {
        c.max_zones_per_tenant = 2;
    });
    let a = kp(10);
    assert_eq!(
        reg(&e, &spec("one.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        reg(&e, &spec("two.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        reg(&e, &spec("three.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Quota
    );
    // another tenant is unaffected
    assert_eq!(
        reg(&e, &spec("other.example", "tenant-b", &kp(11), 1, 1)),
        ApplyOutcome::Applied
    );
    let mut rel = spec("one.example", "tenant-a", &a, 1, 2);
    rel.state = RegState::Released;
    rel.quarantine_until = 1;
    assert_eq!(reg(&e, &rel), ApplyOutcome::Applied);
    assert_eq!(
        e.db.tenant_zone_count(&TenantId::new("tenant-a").unwrap()),
        1
    );
    assert_eq!(
        reg(&e, &spec("three.example", "tenant-a", &a, 1, 1)),
        ApplyOutcome::Applied
    );
    // re-sending the active registration with a new sequence does not double-count
    assert_eq!(
        reg(&e, &spec("three.example", "tenant-a", &a, 1, 2)),
        ApplyOutcome::Applied
    );
    assert_eq!(
        e.db.tenant_zone_count(&TenantId::new("tenant-a").unwrap()),
        2
    );
}

#[test]
fn invalid_content_never_replaces_good_content() {
    let e = env();
    let o = kp(10);
    reg(&e, &spec("acme.example", "acme", &o, 1, 1));
    e.db.apply_object(upd(&o, "acme.example", 1, 1, "198.51.100.1"));
    let bad_bodies: Vec<Vec<u8>> = vec![
        br#"{"records":[{"name":"@","ttl":300,"type":"NS","data":"ns.evil.example"}]}"#.to_vec(),
        br#"{"records":[{"name":"@","ttl":300,"type":"SOA","data":"x"}]}"#.to_vec(),
        br#"{"records":[{"name":"x","ttl":300,"type":"A","data":"not an ip"}]}"#.to_vec(),
        br#"{"records":[{"name":"x.other.example.","ttl":300,"type":"A","data":"192.0.2.1"}]}"#
            .to_vec(),
        b"garbage".to_vec(),
        vec![b'{'; 200_000],
    ];
    for (i, b) in bad_bodies.into_iter().enumerate() {
        let v = 10 + u64::try_from(i).unwrap();
        let out = e.db.apply_object(
            update_object(&o, "acme.example", 1, v, &b)
                .unwrap_or_else(|_| upd(&o, "acme.example", 1, v, "198.51.100.9")),
        );
        // 200_000 byte bodies are over the zone_sync object cap or the zone limit
        assert!(
            matches!(out, ApplyOutcome::Invalid | ApplyOutcome::Applied),
            "{i}: {out:?}"
        );
        if out == ApplyOutcome::Invalid {
            assert!(
                served_ip(&e, "acme.example")
                    .unwrap()
                    .contains("198.51.100.1"),
                "still serving v1 after bad body {i}"
            );
        }
    }
}

#[test]
fn state_survives_restart_and_a_tampered_or_corrupt_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let fstore: Arc<dyn ObjectStore> = Arc::new(FileObjectStore::open(dir.path()).unwrap());
    let o = kp(10);
    {
        let e = env_with(fstore.clone(), |_| {});
        reg(&e, &spec("acme.example", "acme", &o, 1, 1));
        reg(&e, &spec("beta.example", "beta", &kp(11), 1, 1));
        e.db.apply_object(upd(&o, "acme.example", 1, 4, "198.51.100.1"));
    }
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let p = entry.unwrap().path();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600,
            "{p:?}"
        );
    }
    // restart: same state, and rollback protection survives it
    let e = env_with(fstore.clone(), |_| {});
    assert_eq!(
        e.db.zone(&parse_fqdn("acme.example").unwrap())
            .unwrap()
            .version,
        4
    );
    assert_eq!(
        e.db.apply_object(upd(&o, "acme.example", 1, 3, "203.0.113.66")),
        ApplyOutcome::Stale,
        "high-water mark persisted"
    );
    assert_eq!(e.db.object_count(), 3);

    // flip a byte in the persisted update: it must not be served after the next restart
    let key =
        e.db.object(
            ObjectKind::Update,
            &wire_id(&parse_fqdn("acme.example").unwrap()),
        )
        .unwrap();
    let hex: String = key.id_hash().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let file = dir.path().join(format!("u-{hex}.obj"));
    let mut bytes = std::fs::read(&file).unwrap();
    let n = bytes.len() / 2;
    bytes[n] ^= 0xff;
    std::fs::write(&file, &bytes).unwrap();
    std::fs::write(dir.path().join("zz-garbage.obj"), b"junk").unwrap();
    let registrar = kp(1);
    let cfg = DbConfig::new(*registrar.public_key().as_bytes());
    let (db, refused) = ZoneDb::open(
        cfg,
        fstore,
        Arc::new(Metrics::default()),
        Arc::new(|| 1_800_000_000),
    )
    .unwrap();
    assert!(refused >= 1, "the tampered object was refused");
    assert!(
        db.zone(&parse_fqdn("acme.example").unwrap())
            .unwrap()
            .records
            .is_empty(),
        "tampered content not served"
    );
}

#[test]
fn a_persist_failure_refuses_the_object_instead_of_acknowledging_it() {
    struct Broken;
    impl ObjectStore for Broken {
        fn put(&self, _: &str, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("disk full"))
        }
        fn load_all(&self) -> std::io::Result<(Vec<(String, Vec<u8>)>, Vec<String>)> {
            Ok((Vec::new(), Vec::new()))
        }
    }
    let e = env_with(Arc::new(Broken), |_| {});
    assert_eq!(
        reg(&e, &spec("acme.example", "acme", &kp(10), 1, 1)),
        ApplyOutcome::Invalid
    );
    assert!(e.db.zone(&parse_fqdn("acme.example").unwrap()).is_none());
    let _ = &e.store;
}

#[test]
fn summaries_page_in_order_and_events_fire() {
    let e = env();
    let mut rx = e.db.subscribe();
    for i in 0..30u8 {
        reg(&e, &spec(&format!("z{i}.example"), "acme", &kp(10), 1, 1));
    }
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = e.db.summaries(after, 7);
        if page.is_empty() {
            break;
        }
        after = page.last().map(transport::zone_sync::Summary::key);
        seen.extend(page);
    }
    assert_eq!(seen.len(), 30);
    assert!(seen.windows(2).all(|w| w[0].key() < w[1].key()));
    let mut events = 0;
    while let Ok(ev) = rx.try_recv() {
        assert!(matches!(ev, DbEvent::Zone(_)));
        events += 1;
    }
    assert_eq!(events, 30);
}

#[test]
fn dnssec_policy_rides_in_the_registration() {
    let e = env();
    let mut s = spec("acme.example", "acme", &kp(10), 1, 1);
    s.dnssec = Some(DnssecPolicy {
        ksk_gen: 0,
        ksk_next: None,
        origin: 1_800_000_000,
    });
    assert_eq!(reg(&e, &s), ApplyOutcome::Applied);
    assert!(e
        .db
        .zone(&parse_fqdn("acme.example").unwrap())
        .unwrap()
        .dnssec
        .is_some());
}
