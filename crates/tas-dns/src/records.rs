//! Tenant record specs: parsing and strict validation into hickory record data.
//!
//! The representable set is deliberately small. Types the server generates itself (SOA, NS,
//! DNSKEY, `RRSIG`, NSEC, CDS, CDNSKEY), types that change delegation or synthesis (NS below the
//! apex, DS, DNAME, ANAME) and meta types (ANY, AXFR, IXFR, OPT, TSIG) are *unrepresentable*:
//! the parser has no variant for them, so no later code path can forget to forbid them.

use crate::error::ValidationError;
use crate::names::{self, owner_in_apex};
use hickory_proto::rr::rdata::sshfp::{Algorithm as SshAlg, FingerprintType};
use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, PTR, SRV, SSHFP, TLSA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecoder, Restrict};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Size and count caps for one zone body, and the TTL window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneLimits {
    /// Most records in a zone.
    pub max_records: usize,
    /// Most records in one `RRset`.
    pub max_rrset: usize,
    /// Largest encoded body in bytes (checked before parsing).
    pub max_body_bytes: usize,
    /// Lowest TTL a tenant may set.
    pub min_ttl: u32,
    /// Highest TTL a tenant may set.
    pub max_ttl: u32,
    /// Most labels below the apex in an owner name.
    pub max_depth: usize,
}

impl Default for ZoneLimits {
    fn default() -> Self {
        ZoneLimits {
            max_records: 1000,
            max_rrset: 50,
            max_body_bytes: 128 * 1024,
            min_ttl: 30,
            max_ttl: 86_400,
            max_depth: 10,
        }
    }
}

/// One validated record: absolute lower-case owner, TTL, hickory rdata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidRecord {
    /// Owner name (absolute, lower-case).
    pub name: Name,
    /// TTL in seconds.
    pub ttl: u32,
    /// The record data.
    pub rdata: RData,
}

impl ValidRecord {
    /// The record type.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        self.rdata.record_type()
    }

    /// As a hickory record (class IN).
    #[must_use]
    pub fn to_record(&self) -> Record {
        Record::from_rdata(self.name.clone(), self.ttl, self.rdata.clone())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyDoc {
    records: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDoc {
    name: String,
    ttl: u32,
    #[serde(rename = "type")]
    rtype: String,
    data: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MxDoc {
    preference: u16,
    exchange: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SrvDoc {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaaDoc {
    flags: u8,
    tag: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsaDoc {
    usage: u8,
    selector: u8,
    matching: u8,
    data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshfpDoc {
    algorithm: u8,
    fp_type: u8,
    fingerprint: String,
}

fn hex_decode(s: &str, max: usize) -> Result<Vec<u8>, ValidationError> {
    if s.len() % 2 != 0 || s.len() > max * 2 || s.is_empty() {
        return Err(ValidationError::Rdata("hex length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = hex_val(*pair.first().ok_or(ValidationError::Rdata("hex"))?)?;
        let lo = hex_val(*pair.get(1).ok_or(ValidationError::Rdata("hex"))?)?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ValidationError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ValidationError::Rdata("hex digit")),
    }
}

fn printable(s: &str, max: usize) -> Result<(), ValidationError> {
    if s.len() > max || s.chars().any(char::is_control) {
        return Err(ValidationError::Rdata("text length or control character"));
    }
    Ok(())
}

/// An rdata target: absolute, validated, or the single dot `.` meaning "none".
fn target(s: &str, allow_root: bool) -> Result<Name, ValidationError> {
    if s == "." {
        return if allow_root {
            Ok(names::root())
        } else {
            Err(ValidationError::Name("root target not allowed"))
        };
    }
    names::parse_fqdn_no_wildcard(s)
}

fn parse_txt(data: serde_json::Value) -> Result<RData, ValidationError> {
    let bad = |_e: serde_json::Error| ValidationError::Rdata("shape");
    let strings: Vec<String> = match data {
        serde_json::Value::String(s) => {
            // one string: split into 255-byte chunks on char boundaries
            let mut out = Vec::new();
            let mut cur = String::new();
            for c in s.chars() {
                if cur.len() + c.len_utf8() > 255 {
                    out.push(std::mem::take(&mut cur));
                }
                cur.push(c);
            }
            out.push(cur);
            out
        }
        other => serde_json::from_value(other).map_err(bad)?,
    };
    if strings.is_empty() || strings.len() > 16 {
        return Err(ValidationError::Rdata("txt string count"));
    }
    let mut total = 0usize;
    for s in &strings {
        printable(s, 255)?;
        total += s.len();
    }
    if total > 2048 {
        return Err(ValidationError::Rdata("txt too long"));
    }
    Ok(RData::TXT(TXT::new(strings)))
}

fn parse_caa(data: serde_json::Value) -> Result<RData, ValidationError> {
    let bad = |_e: serde_json::Error| ValidationError::Rdata("shape");
    let d: CaaDoc = serde_json::from_value(data).map_err(bad)?;
    if !matches!(d.flags, 0 | 128) {
        return Err(ValidationError::Rdata("caa flags"));
    }
    if !matches!(d.tag.as_str(), "issue" | "issuewild" | "iodef") {
        return Err(ValidationError::Rdata("caa tag"));
    }
    printable(&d.value, 255)?;
    let mut wire = Vec::with_capacity(2 + d.tag.len() + d.value.len());
    wire.push(d.flags);
    wire.push(u8::try_from(d.tag.len()).map_err(|_| ValidationError::Rdata("caa tag"))?);
    wire.extend_from_slice(d.tag.as_bytes());
    wire.extend_from_slice(d.value.as_bytes());
    let len = u16::try_from(wire.len()).map_err(|_| ValidationError::Rdata("caa length"))?;
    // Decode through hickory's own parser: an independent check of the value syntax.
    let mut dec = BinDecoder::new(&wire);
    RData::read(&mut dec, RecordType::CAA, Restrict::new(len))
        .map_err(|_| ValidationError::Rdata("caa value"))
}

fn parse_tlsa(data: serde_json::Value) -> Result<RData, ValidationError> {
    let bad = |_e: serde_json::Error| ValidationError::Rdata("shape");
    let d: TlsaDoc = serde_json::from_value(data).map_err(bad)?;
    if d.usage > 3 || d.selector > 1 || d.matching > 2 {
        return Err(ValidationError::Rdata("tlsa parameters"));
    }
    let bytes = hex_decode(&d.data, 1024)?;
    let want = match d.matching {
        1 => Some(32),
        2 => Some(64),
        _ => None,
    };
    if want.is_some_and(|w| bytes.len() != w) {
        return Err(ValidationError::Rdata("tlsa digest length"));
    }
    Ok(RData::TLSA(TLSA::new(
        CertUsage::from(d.usage),
        Selector::from(d.selector),
        Matching::from(d.matching),
        bytes,
    )))
}

fn parse_sshfp(data: serde_json::Value) -> Result<RData, ValidationError> {
    let bad = |_e: serde_json::Error| ValidationError::Rdata("shape");
    let d: SshfpDoc = serde_json::from_value(data).map_err(bad)?;
    if !matches!(d.algorithm, 1..=4 | 6) || !matches!(d.fp_type, 1 | 2) {
        return Err(ValidationError::Rdata("sshfp parameters"));
    }
    let fp = hex_decode(&d.fingerprint, 64)?;
    if fp.len() != if d.fp_type == 1 { 20 } else { 32 } {
        return Err(ValidationError::Rdata("sshfp fingerprint length"));
    }
    Ok(RData::SSHFP(SSHFP::new(
        SshAlg::from(d.algorithm),
        FingerprintType::from(d.fp_type),
        fp,
    )))
}

fn parse_rdata(rtype: &str, data: serde_json::Value) -> Result<RData, ValidationError> {
    let bad = |_e: serde_json::Error| ValidationError::Rdata("shape");
    match rtype {
        "A" => {
            let s: String = serde_json::from_value(data).map_err(bad)?;
            let ip: Ipv4Addr = s.parse().map_err(|_| ValidationError::Rdata("ipv4"))?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(ValidationError::Rdata("ipv4 not routable"));
            }
            Ok(RData::A(A(ip)))
        }
        "AAAA" => {
            let s: String = serde_json::from_value(data).map_err(bad)?;
            let ip: Ipv6Addr = s.parse().map_err(|_| ValidationError::Rdata("ipv6"))?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(ValidationError::Rdata("ipv6 not routable"));
            }
            Ok(RData::AAAA(AAAA(ip)))
        }
        "CNAME" => {
            let s: String = serde_json::from_value(data).map_err(bad)?;
            Ok(RData::CNAME(CNAME(target(&s, false)?)))
        }
        "PTR" => {
            let s: String = serde_json::from_value(data).map_err(bad)?;
            Ok(RData::PTR(PTR(target(&s, false)?)))
        }
        "MX" => {
            let d: MxDoc = serde_json::from_value(data).map_err(bad)?;
            let ex = target(&d.exchange, true)?;
            if ex.is_root() && d.preference != 0 {
                return Err(ValidationError::Rdata("null MX must have preference 0"));
            }
            Ok(RData::MX(MX::new(d.preference, ex)))
        }
        "SRV" => {
            let d: SrvDoc = serde_json::from_value(data).map_err(bad)?;
            Ok(RData::SRV(SRV::new(
                d.priority,
                d.weight,
                d.port,
                target(&d.target, true)?,
            )))
        }
        "TXT" => parse_txt(data),
        "CAA" => parse_caa(data),
        "TLSA" => parse_tlsa(data),
        "SSHFP" => parse_sshfp(data),
        _ => Err(ValidationError::Rdata("record type not allowed")),
    }
}

/// Parse and validate a zone body into records. Order of checks: body size, record count (before
/// any per-record work), then each record, then cross-record rules.
pub fn parse_body(
    body: &[u8],
    apex: &Name,
    limits: &ZoneLimits,
) -> Result<Vec<ValidRecord>, ValidationError> {
    if body.len() > limits.max_body_bytes {
        return Err(ValidationError::Limit("body bytes"));
    }
    let doc: BodyDoc = serde_json::from_slice(body).map_err(|_| ValidationError::Parse)?;
    if doc.records.len() > limits.max_records {
        return Err(ValidationError::Limit("records per zone"));
    }
    let apex_labels = usize::from(apex.num_labels());
    let mut out: Vec<ValidRecord> = Vec::with_capacity(doc.records.len());
    for v in doc.records {
        let r: RecordDoc = serde_json::from_value(v).map_err(|_| ValidationError::Parse)?;
        if r.ttl < limits.min_ttl || r.ttl > limits.max_ttl {
            return Err(ValidationError::Ttl);
        }
        let name = owner_in_apex(&r.name, apex)?;
        if usize::from(name.num_labels()).saturating_sub(apex_labels) > limits.max_depth {
            return Err(ValidationError::Limit("name depth"));
        }
        let rdata = parse_rdata(r.rtype.as_str(), r.data)?;
        out.push(ValidRecord {
            name,
            ttl: r.ttl,
            rdata,
        });
    }
    check_rules(&out, apex, limits)?;
    out.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| u16::from(a.rtype()).cmp(&u16::from(b.rtype())))
    });
    Ok(out)
}

fn check_rules(
    recs: &[ValidRecord],
    apex: &Name,
    limits: &ZoneLimits,
) -> Result<(), ValidationError> {
    let mut sets: BTreeMap<(Name, u16), Vec<&ValidRecord>> = BTreeMap::new();
    for r in recs {
        sets.entry((r.name.clone(), u16::from(r.rtype())))
            .or_default()
            .push(r);
    }
    let mut names_with_cname: Vec<&Name> = Vec::new();
    for ((name, _), set) in &sets {
        if set.len() > limits.max_rrset {
            return Err(ValidationError::Limit("records per rrset"));
        }
        let ttl = set.first().map(|r| r.ttl);
        if set.iter().any(|r| Some(r.ttl) != ttl) {
            return Err(ValidationError::Conflict("rrset ttl mismatch"));
        }
        for (i, a) in set.iter().enumerate() {
            if set.iter().skip(i + 1).any(|b| b.rdata == a.rdata) {
                return Err(ValidationError::Conflict("duplicate record"));
            }
        }
        if set.first().is_some_and(|r| r.rtype() == RecordType::CNAME) {
            if set.len() > 1 {
                return Err(ValidationError::Conflict("more than one CNAME"));
            }
            if name == apex {
                return Err(ValidationError::Conflict("CNAME at the apex"));
            }
            names_with_cname.push(name);
        }
    }
    for n in names_with_cname {
        if sets
            .keys()
            .any(|(other, t)| other == n && *t != u16::from(RecordType::CNAME))
        {
            return Err(ValidationError::Conflict("CNAME with other data"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test assertions on fixtures"
    )]

    use super::*;

    fn apex() -> Name {
        names::parse_fqdn("acme.example").unwrap()
    }

    fn body(records: &str) -> Vec<u8> {
        format!(r#"{{"records":[{records}]}}"#).into_bytes()
    }

    fn rec(name: &str, ty: &str, data: &str) -> String {
        format!(r#"{{"name":"{name}","ttl":300,"type":"{ty}","data":{data}}}"#)
    }

    fn parse(records: &str) -> Result<Vec<ValidRecord>, ValidationError> {
        parse_body(&body(records), &apex(), &ZoneLimits::default())
    }

    #[test]
    fn a_realistic_zone_parses_and_is_sorted_canonically() {
        let recs = [
            rec("www", "A", r#""198.51.100.10""#),
            rec(
                "@",
                "MX",
                r#"{"preference":10,"exchange":"mail.acme.example."}"#,
            ),
            rec("@", "TXT", r#"["v=spf1 -all"]"#),
            rec(
                "_sip._tcp",
                "SRV",
                r#"{"priority":1,"weight":2,"port":5060,"target":"sip.acme.example"}"#,
            ),
            rec(
                "@",
                "CAA",
                r#"{"flags":0,"tag":"issue","value":"letsencrypt.org"}"#,
            ),
            rec("*.dev", "AAAA", r#""2001:db8::1""#),
            rec("api", "CNAME", r#""www.acme.example""#),
            rec(
                "_443._tcp.www",
                "TLSA",
                &format!(
                    r#"{{"usage":3,"selector":1,"matching":1,"data":"{}"}}"#,
                    "ab".repeat(32)
                ),
            ),
        ]
        .join(",");
        let out = parse(&recs).unwrap();
        assert_eq!(out.len(), 8);
        let names: Vec<String> = out.iter().map(|r| r.name.to_ascii()).collect();
        let mut sorted = names.clone();
        sorted.sort_by_key(|n| names::parse_fqdn(n).unwrap());
        assert_eq!(names, sorted, "canonical DNS order");
    }

    #[test]
    fn dangerous_and_server_owned_types_are_unrepresentable() {
        for ty in [
            "SOA", "NS", "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "CDS", "CDNSKEY", "DNAME",
            "ANAME", "ANY", "AXFR", "OPT", "TSIG", "HTTPS", "NULL", "a",
        ] {
            assert!(parse(&rec("@", ty, r#""x""#)).is_err(), "{ty}");
            assert!(parse(&rec("sub", ty, r#""x""#)).is_err(), "{ty}");
        }
    }

    #[test]
    fn records_outside_the_apex_are_refused() {
        for n in [
            "other.example.",
            "acme.example.evil.",
            "evilacme.example.",
            "x.acme.example.com.",
        ] {
            assert_eq!(
                parse(&rec(n, "A", r#""192.0.2.1""#)).unwrap_err(),
                ValidationError::OutsideApex,
                "{n}"
            );
        }
        assert!(parse(&rec("../x", "A", r#""192.0.2.1""#)).is_err());
    }

    #[test]
    fn rdata_is_strictly_checked() {
        let bad = [
            ("A", r#""0.0.0.0""#),
            ("A", r#""224.0.0.1""#),
            ("A", r#""255.255.255.255""#),
            ("A", r#""999.1.1.1""#),
            ("A", "1"),
            ("AAAA", r#""::""#),
            ("AAAA", r#""ff02::1""#),
            ("CNAME", r#""*.x.example""#),
            ("CNAME", r#"".""#),
            ("MX", r#"{"preference":5,"exchange":"."}"#),
            ("MX", r#"{"preference":5,"exchange":"m.example","extra":1}"#),
            ("TXT", "[]"),
            ("TXT", r#"["bad\nnewline"]"#),
            ("CAA", r#"{"flags":1,"tag":"issue","value":"x"}"#),
            ("CAA", r#"{"flags":0,"tag":"bogus","value":"x"}"#),
            (
                "TLSA",
                r#"{"usage":4,"selector":0,"matching":0,"data":"00"}"#,
            ),
            (
                "TLSA",
                r#"{"usage":3,"selector":1,"matching":1,"data":"abcd"}"#,
            ),
            ("SSHFP", r#"{"algorithm":9,"fp_type":2,"fingerprint":"00"}"#),
        ];
        for (ty, data) in bad {
            assert!(parse(&rec("x", ty, data)).is_err(), "{ty} {data}");
        }
        assert!(
            parse(&rec("x", "MX", r#"{"preference":0,"exchange":"."}"#)).is_ok(),
            "null MX is legal"
        );
    }

    #[test]
    fn long_txt_strings_are_split_not_rejected_but_total_is_capped() {
        let long = "x".repeat(600);
        let out = parse(&rec("t", "TXT", &format!("\"{long}\""))).unwrap();
        match &out[0].rdata {
            RData::TXT(t) => assert_eq!(t.txt_data.len(), 3),
            other => panic!("{other:?}"),
        }
        let huge = "x".repeat(3000);
        assert!(parse(&rec("t", "TXT", &format!("\"{huge}\""))).is_err());
    }

    #[test]
    fn cname_rules_and_rrset_rules() {
        let c = |n: &str| rec(n, "CNAME", r#""t.example""#);
        assert!(
            parse(&format!("{},{}", c("x"), rec("x", "A", r#""192.0.2.1""#))).is_err(),
            "cname + data"
        );
        assert!(parse(&format!("{},{}", c("x"), rec("x", "TXT", r#""t""#))).is_err());
        assert!(
            parse(&format!(
                "{},{}",
                c("x"),
                rec("x", "CNAME", r#""u.example""#)
            ))
            .is_err(),
            "two cnames"
        );
        assert!(parse(&c("@")).is_err(), "cname at apex");
        assert!(
            parse(&format!(
                "{},{}",
                rec("x", "A", r#""192.0.2.1""#),
                rec("x", "A", r#""192.0.2.1""#)
            ))
            .is_err(),
            "duplicate"
        );
        let mixed_ttl = r#"{"name":"x","ttl":300,"type":"A","data":"192.0.2.1"},{"name":"x","ttl":60,"type":"A","data":"192.0.2.2"}"#.to_string();
        assert!(parse(&mixed_ttl).is_err(), "rrset ttl mismatch");
        assert!(
            parse(&format!("{},{}", c("x"), rec("y.x", "A", r#""192.0.2.1""#))).is_ok(),
            "names below a cname are fine"
        );
    }

    #[test]
    fn ttl_window_and_caps() {
        let low = r#"{"name":"x","ttl":1,"type":"A","data":"192.0.2.1"}"#;
        let high = r#"{"name":"x","ttl":9999999,"type":"A","data":"192.0.2.1"}"#;
        assert_eq!(parse(low).unwrap_err(), ValidationError::Ttl);
        assert_eq!(parse(high).unwrap_err(), ValidationError::Ttl);
        let lim = ZoneLimits {
            max_records: 3,
            max_rrset: 2,
            ..ZoneLimits::default()
        };
        let many = (0..4)
            .map(|i| rec(&format!("h{i}"), "A", r#""192.0.2.1""#))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_body(&body(&many), &apex(), &lim).unwrap_err(),
            ValidationError::Limit("records per zone")
        );
        let rr = (0..3)
            .map(|i| rec("h", "A", &format!("\"192.0.2.{}\"", i + 1)))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_body(&body(&rr), &apex(), &lim).unwrap_err(),
            ValidationError::Limit("records per rrset")
        );
        let tiny = ZoneLimits {
            max_body_bytes: 10,
            ..ZoneLimits::default()
        };
        assert_eq!(
            parse_body(&body(&many), &apex(), &tiny).unwrap_err(),
            ValidationError::Limit("body bytes")
        );
        let deep = rec(&["a"; 11].join("."), "A", r#""192.0.2.1""#);
        assert_eq!(
            parse(&deep).unwrap_err(),
            ValidationError::Limit("name depth")
        );
    }

    #[test]
    fn unknown_fields_and_garbage_are_parse_errors() {
        assert_eq!(
            parse_body(b"not json", &apex(), &ZoneLimits::default()).unwrap_err(),
            ValidationError::Parse
        );
        assert_eq!(
            parse_body(br#"{"records":[],"x":1}"#, &apex(), &ZoneLimits::default()).unwrap_err(),
            ValidationError::Parse
        );
        assert!(
            parse(r#"{"name":"x","ttl":300,"type":"A","data":"192.0.2.1","extra":1}"#).is_err()
        );
        assert!(parse_body(&[0xff; 64], &apex(), &ZoneLimits::default()).is_err());
        // deep nesting must not overflow the stack (serde_json caps recursion)
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse_body(deep.as_bytes(), &apex(), &ZoneLimits::default()).is_err());
    }
}
