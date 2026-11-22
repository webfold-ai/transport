#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::rdata::{DNSKEY, DS};
use hickory_proto::dnssec::DigestType;
use hickory_proto::rr::{RData, RecordType};
use tas_dns::build::{expected_ds, next_schedule_event, zsk_active, zsk_published, Timings};
use tas_dns::keys::DerivedKeyProvider;
use tas_dns::names::parse_fqdn;
use tas_dns::zone::DnssecPolicy;

fn policy(origin: u64) -> DnssecPolicy {
    DnssecPolicy {
        ksk_gen: 0,
        ksk_next: None,
        origin,
    }
}

fn timings() -> Timings {
    Timings::default()
}

#[test]
fn default_timings_are_internally_consistent() {
    Timings::default().validate().unwrap();
    let mut t = Timings::default();
    t.refresh_before = t.sig_validity; // never refresh early enough
    assert!(t.validate().is_err());
    t = Timings::default();
    t.refresh_before = 10; // refresh far too late (less than a third of validity left)
    assert!(t.validate().is_err());
    t = Timings::default();
    t.retire_grace = 1; // old signatures could outlive the old key
    assert!(t.validate().is_err());
    t = Timings::default();
    t.prepublish = 10; // new key would sign before caches have it
    assert!(t.validate().is_err());
}

/// The headline test: an independent validator chain. DS (what the parent holds) covers the KSK;
/// the KSK validates the DNSKEY `RRset`; the ZSK from that `RRset` validates every other `RRset`,
/// including the NSEC chain, SOA, wildcard, CNAME and CAA; CDS/CDNSKEY are KSK-signed.
#[test]
fn the_full_chain_of_trust_validates_with_hickory_verification() {
    let keys = DerivedKeyProvider::random().unwrap();
    let t = timings();
    let z = zone("acme.example", 7, Some(policy(T0)));
    let sz = build(&z, &keys, &t, T0 + 100);
    assert!(sz.signed);
    assert_eq!(sz.serial, 7, "SOA serial is the zone version");

    let apex = parse_fqdn("acme.example").unwrap();
    let ds_set = expected_ds(&apex, &policy(T0), &keys).unwrap();
    assert_eq!(ds_set, sz.ds);
    let ds = DS::new(
        ds_set[0].key_tag,
        hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
        DigestType::SHA256,
        ds_set[0].digest.clone(),
    );

    let all_keys = dnskeys(&sz);
    let ksk: Vec<&DNSKEY> = all_keys.iter().filter(|k| k.secure_entry_point()).collect();
    let zsk: Vec<&DNSKEY> = all_keys
        .iter()
        .filter(|k| !k.secure_entry_point())
        .collect();
    assert_eq!(ksk.len(), 1);
    assert_eq!(
        zsk.len(),
        1,
        "only the active ZSK is published outside a rollover window"
    );
    assert!(
        ds.covers(&apex, ksk[0]).unwrap(),
        "DS matches the published KSK"
    );
    assert!(!ds.covers(&apex, zsk[0]).unwrap());
    assert_eq!(ksk[0].flags(), 257);
    assert_eq!(zsk[0].flags(), 256);

    let now = T0 + 100;
    // DNSKEY RRset: signed by the KSK, and ONLY by the KSK
    let dnskey_set = rrset(&sz, "acme.example", RecordType::DNSKEY);
    assert_eq!(validate(dnskey_set, &all_keys, now, Some(true)), 1);
    assert_eq!(
        validate(dnskey_set, &all_keys, now, Some(false)),
        0,
        "ZSK does not sign the key set"
    );
    // every other RRset: signed by the ZSK only
    let mut checked = 0;
    for ((name, ty), set) in all_sets(&sz) {
        if matches!(
            ty,
            RecordType::DNSKEY | RecordType::CDS | RecordType::CDNSKEY
        ) {
            assert_eq!(
                validate(set, &all_keys, now, Some(true)),
                1,
                "{name} {ty} is KSK signed"
            );
        } else {
            assert_eq!(
                validate(set, &all_keys, now, Some(false)),
                1,
                "{name} {ty} is ZSK signed"
            );
            assert_eq!(
                validate(set, &all_keys, now, Some(true)),
                0,
                "{name} {ty} is not KSK signed"
            );
        }
        checked += 1;
    }
    assert!(checked >= 12, "checked {checked} rrsets");
    // CDS / CDNSKEY mirror the DS
    match &rrset(&sz, "acme.example", RecordType::CDS)
        .records_without_rrsigs()
        .next()
        .unwrap()
        .data
    {
        RData::DNSSEC(DNSSECRData::CDS(c)) => {
            assert_eq!(c.key_tag(), ds_set[0].key_tag);
            assert_eq!(c.digest(), ds_set[0].digest.as_slice());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        rrset(&sz, "acme.example", RecordType::CDNSKEY)
            .records_without_rrsigs()
            .count(),
        1
    );
}

#[test]
fn a_tampered_rrset_or_wrong_key_or_wrong_time_does_not_validate() {
    let keys = DerivedKeyProvider::random().unwrap();
    let t = timings();
    let sz = build(&zone("acme.example", 1, Some(policy(T0))), &keys, &t, T0);
    let all_keys = dnskeys(&sz);
    let www = rrset(&sz, "www.acme.example", RecordType::A);
    assert_eq!(validate(www, &all_keys, T0, None), 1);

    // tampered data
    let mut forged = www.clone();
    forged.set_records(vec![hickory_proto::rr::Record::from_rdata(
        www.name().clone(),
        300,
        RData::A("203.0.113.66".parse::<std::net::Ipv4Addr>().unwrap().into()),
    )]);
    assert_eq!(validate(&forged, &all_keys, T0, None), 0);

    // a different zone's key
    let other = build(&zone("other.example", 1, Some(policy(T0))), &keys, &t, T0);
    assert_eq!(validate(www, &dnskeys(&other), T0, None), 0);

    // before inception (beyond the skew) and after expiry
    assert_eq!(
        validate(www, &all_keys, T0 - t.inception_skew - 10, None),
        0
    );
    assert_eq!(validate(www, &all_keys, T0 + t.sig_validity + 10, None), 0);
    // inside the skew allowance
    assert_eq!(
        validate(www, &all_keys, T0 - t.inception_skew + 10, None),
        1
    );
}

#[test]
fn signatures_are_refreshed_well_before_expiry_and_a_stale_zone_is_detectable() {
    let keys = DerivedKeyProvider::random().unwrap();
    let t = timings();
    let z = zone("acme.example", 1, Some(policy(T0)));
    let first = build(&z, &keys, &t, T0);
    assert_eq!(first.earliest_expiry, T0 + t.sig_validity);
    assert!(
        first.refresh_at <= T0 + t.sig_validity - t.refresh_before,
        "refresh is scheduled inside the validity window"
    );
    assert!(first.refresh_at > T0);
    // the margin: at refresh time at least `refresh_before` of validity remains
    assert!(first.earliest_expiry - first.refresh_at >= t.refresh_before.min(t.sig_validity / 3));

    // walk the clock: rebuild at each refresh_at and check no instant ever has an expired sig
    let mut now = T0;
    let mut cur = first;
    let mut rebuilds = 0;
    while now < T0 + 20 * 86_400 {
        let step = (cur.refresh_at.saturating_sub(now)).max(1);
        // sample just before the refresh: still valid
        let before = now + step - 1;
        let www = rrset(&cur, "www.acme.example", RecordType::A);
        assert_eq!(
            validate(www, &dnskeys(&cur), before, None),
            1,
            "valid at {step} s before refresh"
        );
        now += step;
        cur = build(&z, &keys, &t, now);
        rebuilds += 1;
        assert!(cur.earliest_expiry > now + t.sig_validity - 1);
    }
    assert!(rebuilds >= 6, "re-signed {rebuilds} times over 20 days");
    // the OLD signatures are expired by the time they would have lapsed: freshness is real
    let old = build(&z, &keys, &t, T0);
    assert_eq!(
        validate(
            rrset(&old, "www.acme.example", RecordType::A),
            &dnskeys(&old),
            T0 + t.sig_validity + 5,
            None
        ),
        0
    );
}

/// Pre-publish ZSK rollover over a synthetic clock: at EVERY sampled instant, the signatures
/// served validate against the DNSKEY `RRset` a resolver could be holding from `key_ttl` earlier
/// (pre-publish guarantee) and against the current one, and signatures made just before a
/// switch still validate against the current set during the grace period (no flash-cut).
#[test]
fn zsk_rollover_is_pre_published_and_never_breaks_validation() {
    let keys = DerivedKeyProvider::random().unwrap();
    let t = timings();
    let p = policy(T0);
    let z = zone("acme.example", 1, Some(p));
    let period = t.zsk_period;

    // schedule shape
    assert_eq!(zsk_active(&p, &t, T0), 0);
    assert_eq!(zsk_published(&p, &t, T0), vec![0]);
    assert_eq!(
        zsk_published(&p, &t, T0 + period - t.prepublish - 1),
        vec![0]
    );
    assert_eq!(
        zsk_published(&p, &t, T0 + period - t.prepublish),
        vec![0, 1],
        "next key appears `prepublish` early"
    );
    assert_eq!(zsk_active(&p, &t, T0 + period - 1), 0);
    assert_eq!(zsk_active(&p, &t, T0 + period), 1);
    assert_eq!(
        zsk_published(&p, &t, T0 + period),
        vec![0, 1],
        "old key stays published"
    );
    assert_eq!(
        zsk_published(&p, &t, T0 + period + t.retire_grace - 1),
        vec![0, 1]
    );
    assert_eq!(
        zsk_published(&p, &t, T0 + period + t.retire_grace),
        vec![1],
        "old key retired after the grace"
    );
    assert_eq!(next_schedule_event(&p, &t, T0), T0 + period - t.prepublish);

    let mut now = T0;
    let mut saw_three_keys = false;
    let mut saw_two_zsks = false;
    let mut signer_tags = std::collections::BTreeSet::new();
    while now < T0 + 3 * period {
        let cur = build(&z, &keys, &t, now);
        let www = rrset(&cur, "www.acme.example", RecordType::A);
        let current_keys = dnskeys(&cur);
        assert_eq!(
            validate(www, &current_keys, now, None),
            1,
            "valid against current set at {now}"
        );
        // a resolver holding the DNSKEY RRset from key_ttl ago can still validate today's sigs
        let cached = build(
            &z,
            &keys,
            &t,
            now.saturating_sub(u64::from(t.key_ttl)).max(T0),
        );
        assert_eq!(
            validate(www, &dnskeys(&cached), now, None),
            1,
            "pre-publish: cached keys validate new sigs at {now}"
        );
        // sigs from one validity period ago, if still inside their window, validate against today's set
        if now >= T0 + t.sig_validity {
            let older = build(&z, &keys, &t, now - t.sig_validity + 60);
            let older_www = rrset(&older, "www.acme.example", RecordType::A);
            assert_eq!(
                validate(older_www, &current_keys, now, None),
                1,
                "old sigs still verify in the grace period at {now}"
            );
        }
        let zsk_count = current_keys
            .iter()
            .filter(|k| !k.secure_entry_point())
            .count();
        saw_two_zsks |= zsk_count == 2;
        saw_three_keys |= zsk_count == 3;
        for s in common::rrsigs_of(www) {
            signer_tags.insert(s.input().key_tag);
        }
        now += 6 * 3600;
    }
    assert!(saw_two_zsks, "rollover windows were exercised");
    assert!(
        !saw_three_keys || t.retire_grace > period,
        "three ZSKs only if grace exceeds the period"
    );
    assert!(
        signer_tags.len() >= 3,
        "the signing key actually changed over three periods: {}",
        signer_tags.len()
    );
}

/// Double-DS KSK rollover: while both KSKs are published the CDS/CDNSKEY sets carry both, the
/// DNSKEY `RRset` is signed by both KSKs (so either DS validates the chain), then promotion
/// drops the old key everywhere.
#[test]
fn ksk_double_ds_rollover_publishes_both_then_retires_the_old() {
    let keys = DerivedKeyProvider::random().unwrap();
    let t = timings();
    let apex = parse_fqdn("acme.example").unwrap();
    let stable = DnssecPolicy {
        ksk_gen: 0,
        ksk_next: None,
        origin: T0,
    };
    let intro = DnssecPolicy {
        ksk_gen: 0,
        ksk_next: Some(1),
        origin: T0,
    };
    let promoted = DnssecPolicy {
        ksk_gen: 1,
        ksk_next: None,
        origin: T0,
    };

    let ds_old = expected_ds(&apex, &stable, &keys).unwrap();
    let ds_both = expected_ds(&apex, &intro, &keys).unwrap();
    let ds_new = expected_ds(&apex, &promoted, &keys).unwrap();
    assert_eq!(ds_both.len(), 2);
    assert_eq!(ds_both[0], ds_old[0]);
    assert_eq!(ds_both[1], ds_new[0]);
    assert_ne!(ds_old[0], ds_new[0]);

    let sz = build(&zone("acme.example", 1, Some(intro)), &keys, &t, T0 + 10);
    let ks = dnskeys(&sz);
    assert_eq!(ks.iter().filter(|k| k.secure_entry_point()).count(), 2);
    let dnskey_set = rrset(&sz, "acme.example", RecordType::DNSKEY);
    assert_eq!(
        validate(dnskey_set, &ks, T0 + 10, Some(true)),
        2,
        "both KSKs sign the DNSKEY set"
    );
    assert_eq!(
        rrset(&sz, "acme.example", RecordType::CDS)
            .records_without_rrsigs()
            .count(),
        2
    );
    assert_eq!(
        rrset(&sz, "acme.example", RecordType::CDNSKEY)
            .records_without_rrsigs()
            .count(),
        2
    );
    // either DS alone is enough to anchor the chain
    for d in &ds_both {
        let ds = DS::new(
            d.key_tag,
            hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
            DigestType::SHA256,
            d.digest.clone(),
        );
        let anchored: Vec<DNSKEY> = ks
            .iter()
            .filter(|k| ds.covers(&apex, k).unwrap())
            .cloned()
            .collect();
        assert_eq!(anchored.len(), 1);
        assert_eq!(validate(dnskey_set, &anchored, T0 + 10, Some(true)), 1);
    }

    let after = build(&zone("acme.example", 2, Some(promoted)), &keys, &t, T0 + 20);
    let ks2 = dnskeys(&after);
    assert_eq!(ks2.iter().filter(|k| k.secure_entry_point()).count(), 1);
    assert_eq!(
        rrset(&after, "acme.example", RecordType::CDS)
            .records_without_rrsigs()
            .count(),
        1
    );
    assert_eq!(after.ds, ds_new);
    // the retired KSK no longer validates anything
    let old_only: Vec<DNSKEY> = ks
        .iter()
        .filter(|k| k.secure_entry_point())
        .take(1)
        .cloned()
        .collect();
    assert_eq!(
        validate(
            rrset(&after, "acme.example", RecordType::DNSKEY),
            &old_only,
            T0 + 20,
            Some(true)
        ),
        0
    );
}

#[test]
fn the_nsec_chain_is_complete_ordered_and_covers_its_types() {
    let keys = DerivedKeyProvider::random().unwrap();
    let sz = build(
        &zone("acme.example", 1, Some(policy(T0))),
        &keys,
        &timings(),
        T0,
    );
    let mut names: Vec<hickory_proto::rr::Name> = sz
        .records
        .keys()
        .map(|k| hickory_proto::rr::Name::from(k.name.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    names.sort();
    for (i, n) in names.iter().enumerate() {
        let set = rrset(&sz, &n.to_ascii(), RecordType::NSEC);
        let nsec = match &set.records_without_rrsigs().next().unwrap().data {
            RData::DNSSEC(DNSSECRData::NSEC(x)) => x.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            nsec.next_domain_name(),
            &names[(i + 1) % names.len()],
            "chain from {n}"
        );
        let types: Vec<RecordType> = nsec.type_bit_maps().collect();
        assert!(types.contains(&RecordType::NSEC) && types.contains(&RecordType::RRSIG));
        for k in sz
            .records
            .keys()
            .filter(|k| hickory_proto::rr::Name::from(k.name.clone()) == *n)
        {
            assert!(
                types.contains(&k.record_type),
                "{n} bitmap lists {}",
                k.record_type
            );
        }
    }
    // the apex is first in canonical order and the last NSEC wraps to it
    assert_eq!(names[0], parse_fqdn("acme.example").unwrap());
}

#[test]
fn unsigned_zone_has_no_dnssec_records_and_signed_zone_requires_keys() {
    let keys = DerivedKeyProvider::random().unwrap();
    let un = build(&zone("acme.example", 3, None), &keys, &timings(), T0);
    assert!(!un.signed && un.earliest_expiry == 0 && un.refresh_at == u64::MAX);
    assert!(un.records.keys().all(|k| !matches!(
        k.record_type,
        RecordType::DNSKEY | RecordType::NSEC | RecordType::RRSIG
    )));
    let signed_zone = zone("acme.example", 3, Some(policy(T0)));
    assert!(
        tas_dns::build::build_zone(&signed_zone, &identity(), None, &timings(), T0).is_err(),
        "no provider -> refuse, never serve unsigned"
    );
}
