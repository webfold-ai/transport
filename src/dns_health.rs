//! DNS health findings for the zones and names the edge depends on.
//!
//! The edge is only as available as the DNS in front of it: a DS record left behind after a key
//! rollover makes every validating resolver answer SERVFAIL for the whole zone; signatures that
//! quietly expire do the same a week later; a CAA record with one permissive extra `issue` entry
//! voids the account binding that is the whole point of publishing it; a nameserver that has
//! fallen behind serves stale answers to a fraction of users. None of these show up as an error
//! in the edge itself. This module finds them.
//!
//! ## Shape
//!
//! ```text
//!   DnsLookup (network)  ──collect_*──▶  observations (plain data)  ──evaluate_*──▶  Findings
//! ```
//!
//! The evaluators ([`evaluate_zone`], [`evaluate_caa`]) are **pure**: data in, findings out, no
//! I/O, no clock (`now` is a parameter). Everything that touches the network goes through the
//! [`DnsLookup`] trait, so the evaluators are tested with hand-built observations, the collectors
//! with scripted fakes, and the whole path ([`NetLookup`]) against real sockets on loopback.
//!
//! ## What is checked
//!
//! 1. **DNSSEC chain health** for a signed zone: the DS records are fetched through the
//!    recursive resolvers (which ask the parent side), the DNSKEY and RRSIG records from *each*
//!    authoritative server directly. The DS digest is recomputed over the DNSKEY (RFC 4034 §5.1.4;
//!    SHA-256 and SHA-384 via aws-lc, SHA-1 only so a legacy DS can be recognised and flagged) and
//!    compared; the earliest RRSIG expiry is reported in seconds and escalated as it nears; a
//!    missing or already-expired signature, a DNSKEY RRset not signed by the key the DS points at,
//!    and authoritative servers that disagree (different DNSKEY sets, different SOA serials, one
//!    signing and one not) are findings.
//! 2. **Effective CAA policy** per name by the RFC 8659 §3 tree-climb: the closest ancestor with
//!    any CAA record decides. For names we own it is compared with the allow-list and the account
//!    binding we publish (RFC 8657 `accounturi`, `validationmethods`); for customer names the
//!    question is only whether it lets *us* issue.
//! 3. **NS/SOA sanity**: at least two nameservers that resolve, are reachable, are authoritative
//!    (not lame) and not all in one network; the same NS set as the resolvers see; a SOA that
//!    exists with timers in a sane relationship.
//!
//! ## What is not
//!
//! **No RRSIG is cryptographically verified.** The checks are existence, timing and the DS↔DNSKEY
//! binding; a signature that is present, current, but wrong (a corrupted zone file, a signer using
//! the wrong key for the right tag) is not caught. That would need canonical RRset construction
//! and per-algorithm verification, and a validating resolver in the path is the real arbiter. The
//! DS comes from the resolvers, which are trusted not to forge it; it is not itself validated.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use aws_lc_rs::digest;

use crate::dns::{
    dnskey_key_tag, dnskey_rdata, serial_secs_until, Message, Name, RData, RecordType, ResponseCode,
};
use crate::edge_verify::{DnsClient, QueryOptions};
use crate::BoxFuture;

// ── Findings ──────────────────────────────────────────────────────────────────────────────

/// How urgent a finding is. Ordered: `Info < Warning < Error < Critical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Worth knowing; nothing is wrong.
    Info,
    /// Degraded, or will become a problem; fix in working hours.
    Warning,
    /// A real fault with partial impact, or about to have full impact.
    Error,
    /// Customers are, or within a day will be, affected.
    Critical,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }
}

/// What a finding is about. Stable names ([`FindingKind::as_str`]) — metrics and alert rules
/// match on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    // DNSSEC
    /// The parent has DS records and none of them matches any DNSKEY the zone publishes.
    DsDnskeyMismatch,
    /// Some DS records match a DNSKEY and some do not (stale DS left behind).
    DsPartialMismatch,
    /// The parent has DS records and the zone publishes no DNSKEY at all.
    DsWithoutDnskey,
    /// A DS uses a digest type this module cannot recompute.
    DsDigestUnsupported,
    /// The only matching DS uses SHA-1.
    DsWeakDigest,
    /// The zone is signed but the parent has no DS: not chained, so not validated.
    SignedZoneWithoutDs,
    /// The DS could not be fetched.
    DsLookupFailed,
    /// An authoritative server returned no RRSIG over an RRset it should have signed.
    RrsigMissing,
    RrsigExpired,
    /// Signatures expire soon (severity by remaining time).
    RrsigExpiring,
    /// A signature's inception is in the future (clock skew, or a signer ahead of time).
    RrsigNotYetValid,
    /// The DNSKEY RRset carries no signature by the key the DS names.
    DnskeyNotSignedByDsKey,
    /// Authoritative servers publish different DNSKEY sets, or only some sign.
    DnskeyDisagreement,
    // Servers / NS / SOA
    ServerUnreachable,
    /// A listed nameserver answers but is not authoritative for the zone.
    LameDelegation,
    /// Authoritative servers answer differently (SOA serial).
    ServerDisagreement,
    NsLookupFailed,
    NsMissing,
    NsTooFew,
    NsUnresolvable,
    NsSameNetwork,
    /// A server's NS RRset differs from what the resolvers see.
    NsSetMismatch,
    SoaMissing,
    SoaTimers,
    // CAA
    CaaLookupFailed,
    /// No CAA anywhere up the tree for a name we own: any CA may issue.
    CaaAbsent,
    /// An `issue`/`issuewild` entry names a CA that is not in the allow-list.
    CaaUnknownCa,
    /// An entry for an allowed CA without our account binding, next to one that has it: the extra
    /// entry makes the binding worthless.
    CaaPermissiveIssuer,
    /// An entry for an allowed CA bound to someone else's account.
    CaaForeignAccount,
    CaaMissingAccountUri,
    CaaMissingValidationMethods,
    CaaValidationMethodsMismatch,
    /// The effective policy does not let us issue.
    CaaBlocksIssuance,
    /// A CAA property the CA must understand but we do not (flags bit 7), or one that cannot be parsed.
    CaaUnknownCritical,
    CaaMalformed,
}

impl FindingKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::DsDnskeyMismatch => "ds_dnskey_mismatch",
            FindingKind::DsPartialMismatch => "ds_partial_mismatch",
            FindingKind::DsWithoutDnskey => "ds_without_dnskey",
            FindingKind::DsDigestUnsupported => "ds_digest_unsupported",
            FindingKind::DsWeakDigest => "ds_weak_digest",
            FindingKind::SignedZoneWithoutDs => "signed_zone_without_ds",
            FindingKind::DsLookupFailed => "ds_lookup_failed",
            FindingKind::RrsigMissing => "rrsig_missing",
            FindingKind::RrsigExpired => "rrsig_expired",
            FindingKind::RrsigExpiring => "rrsig_expiring",
            FindingKind::RrsigNotYetValid => "rrsig_not_yet_valid",
            FindingKind::DnskeyNotSignedByDsKey => "dnskey_not_signed_by_ds_key",
            FindingKind::DnskeyDisagreement => "dnskey_disagreement",
            FindingKind::ServerUnreachable => "server_unreachable",
            FindingKind::LameDelegation => "lame_delegation",
            FindingKind::ServerDisagreement => "server_disagreement",
            FindingKind::NsLookupFailed => "ns_lookup_failed",
            FindingKind::NsMissing => "ns_missing",
            FindingKind::NsTooFew => "ns_too_few",
            FindingKind::NsUnresolvable => "ns_unresolvable",
            FindingKind::NsSameNetwork => "ns_same_network",
            FindingKind::NsSetMismatch => "ns_set_mismatch",
            FindingKind::SoaMissing => "soa_missing",
            FindingKind::SoaTimers => "soa_timers",
            FindingKind::CaaLookupFailed => "caa_lookup_failed",
            FindingKind::CaaAbsent => "caa_absent",
            FindingKind::CaaUnknownCa => "caa_unknown_ca",
            FindingKind::CaaPermissiveIssuer => "caa_permissive_issuer",
            FindingKind::CaaForeignAccount => "caa_foreign_account",
            FindingKind::CaaMissingAccountUri => "caa_missing_accounturi",
            FindingKind::CaaMissingValidationMethods => "caa_missing_validationmethods",
            FindingKind::CaaValidationMethodsMismatch => "caa_validationmethods_mismatch",
            FindingKind::CaaBlocksIssuance => "caa_blocks_issuance",
            FindingKind::CaaUnknownCritical => "caa_unknown_critical",
            FindingKind::CaaMalformed => "caa_malformed",
        }
    }

    /// Whether this is a CAA finding (the metric counts them separately).
    #[must_use]
    pub fn is_caa(self) -> bool {
        self.as_str().starts_with("caa_")
    }
}

/// One thing found wrong (or worth noting).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub kind: FindingKind,
    /// The zone, name or server the finding is about.
    pub subject: String,
    pub detail: String,
}

fn finding(
    severity: Severity,
    kind: FindingKind,
    subject: &str,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        kind,
        subject: subject.to_string(),
        detail: detail.into(),
    }
}

// ── Observations ──────────────────────────────────────────────────────────────────────────

/// A DNSKEY as published by one server.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnskeyObs {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnskeyObs {
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        dnskey_key_tag(self.flags, self.protocol, self.algorithm, &self.public_key)
    }
}

/// A DS record as the parent publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsObs {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// An RRSIG, reduced to what the health check reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrsigObs {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub key_tag: u16,
    /// RFC 4034 §3.1.5 serial-number timestamps; compare with [`serial_secs_until`].
    pub expiration: u32,
    pub inception: u32,
    pub signer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoaObs {
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// How one authoritative server responded when asked directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerState {
    /// The NS name has no address.
    Unresolvable,
    /// No usable reply (timeout, transport error).
    Unreachable,
    /// A reply, but not an authoritative NOERROR one (REFUSED, SERVFAIL, or AA clear): a lame
    /// delegation. Holds a short description of what it said.
    Lame(String),
    Answering,
}

/// What one authoritative server (one address of one NS name) said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerObservation {
    pub ns_name: String,
    pub addr: Option<SocketAddr>,
    pub state: ServerState,
    pub soa: Option<SoaObs>,
    /// The server's own NS RRset for the zone, normalised (lower case, no trailing dot).
    pub ns_set: BTreeSet<String>,
    pub dnskeys: Vec<DnskeyObs>,
    pub dnskey_rrsigs: Vec<RrsigObs>,
    pub soa_rrsigs: Vec<RrsigObs>,
}

impl ServerObservation {
    fn new(ns_name: &str, addr: Option<SocketAddr>, state: ServerState) -> Self {
        ServerObservation {
            ns_name: ns_name.to_string(),
            addr,
            state,
            soa: None,
            ns_set: BTreeSet::new(),
            dnskeys: Vec::new(),
            dnskey_rrsigs: Vec::new(),
            soa_rrsigs: Vec::new(),
        }
    }

    fn label(&self) -> String {
        match self.addr {
            Some(a) => format!("{} ({a})", self.ns_name),
            None => self.ns_name.clone(),
        }
    }
}

/// Everything gathered about one zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneObservation {
    pub zone: String,
    /// DS records at the parent; `None` if the lookup failed (distinct from "no DS").
    pub ds: Option<Vec<DsObs>>,
    /// NS names according to the resolvers; `None` if the lookup failed.
    pub ns_names: Option<BTreeSet<String>>,
    pub servers: Vec<ServerObservation>,
}

/// One CAA record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: Vec<u8>,
}

/// The CAA lookup for one name, climbed (RFC 8659 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaObservation {
    pub name: String,
    /// A lookup on the way up failed (SERVFAIL, timeout). RFC 8659 §3: the CA must not issue,
    /// so the policy cannot be known and the answer is a finding, not "no CAA".
    pub lookup_failed: bool,
    /// Where the closest CAA RRset was found (the name itself or an ancestor); `None` = none up
    /// to the root.
    pub found_at: Option<String>,
    pub records: Vec<CaaRecord>,
}

// ── Configuration ─────────────────────────────────────────────────────────────────────────

/// Remaining-signature-lifetime thresholds, in seconds. Below `warn` is a warning, below `error`
/// an error, below `critical` critical; already expired is critical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RrsigThresholds {
    pub warn_secs: i64,
    pub error_secs: i64,
    pub critical_secs: i64,
}

impl Default for RrsigThresholds {
    fn default() -> Self {
        RrsigThresholds {
            warn_secs: 7 * 86_400,
            error_secs: 3 * 86_400,
            critical_secs: 86_400,
        }
    }
}

/// How far in the future an RRSIG's inception may be before it is flagged (clock skew allowance).
const INCEPTION_SKEW_SECS: i64 = 3600;

/// Whose names these are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaaScope {
    /// A zone we operate: its CAA is ours to get right.
    Own,
    /// A customer's name: its CAA is theirs; we only care whether it lets us issue.
    Customer,
}

/// A name whose effective CAA policy is checked. For a wildcard certificate set `wildcard`
/// and give the base name (`tascloud.app` for `*.tascloud.app`): `issuewild` then takes
/// precedence over `issue` (RFC 8659 §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaTarget {
    pub name: String,
    pub wildcard: bool,
    pub scope: CaaScope,
}

/// What the CAA policy should say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaaPolicy {
    /// CA issuer domain names we permit (`letsencrypt.org`). Anything else in an entry for a name
    /// we own is a finding.
    pub allowed_issuers: Vec<String>,
    /// Our ACME account URI (RFC 8657). When set, every entry for an allowed CA on a name we own
    /// must carry exactly this `accounturi`.
    pub account_uri: Option<String>,
    /// The `validationmethods` we expect on entries for names we own (`["dns-01"]`). Empty = not checked.
    pub validation_methods: Vec<String>,
    /// The validation method we use for customer names (`http-01`): a customer CAA whose
    /// `validationmethods` excludes it blocks us.
    pub customer_method: Option<String>,
    /// Per-CA expectations, for a platform with more than one CA. When an issuer domain appears
    /// here, entries for it are checked against *these* accounts and methods instead of
    /// `account_uri`/`validation_methods`; the domain is also allowed without being listed in
    /// `allowed_issuers`. Several rows may share a domain (two accounts at one CA).
    pub issuers: Vec<IssuerExpectation>,
}

/// What the CAA entries for one issuer domain should look like.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerExpectation {
    pub domain: String,
    /// The account URL entries for this issuer must be bound to (one of several rows if more
    /// than one account is expected at this CA).
    pub account_uri: Option<String>,
    pub validation_methods: Vec<String>,
}

impl CaaPolicy {
    fn expects(&self, issuer: &str) -> Vec<&IssuerExpectation> {
        self.issuers
            .iter()
            .filter(|i| i.domain.eq_ignore_ascii_case(issuer))
            .collect()
    }

    fn is_allowed(&self, issuer: &str) -> bool {
        self.allowed_issuers
            .iter()
            .any(|a| a.eq_ignore_ascii_case(issuer))
            || !self.expects(issuer).is_empty()
    }

    /// The account URLs an entry for `issuer` may be bound to.
    fn accounts_for(&self, issuer: &str) -> Vec<&str> {
        let per_issuer: Vec<&str> = self
            .expects(issuer)
            .into_iter()
            .filter_map(|i| i.account_uri.as_deref())
            .collect();
        if per_issuer.is_empty() {
            self.account_uri.as_deref().into_iter().collect()
        } else {
            per_issuer
        }
    }

    /// The validation methods entries for `issuer` should carry (empty = not checked).
    fn methods_for(&self, issuer: &str) -> &[String] {
        match self
            .expects(issuer)
            .into_iter()
            .find(|i| !i.validation_methods.is_empty())
        {
            Some(i) => &i.validation_methods,
            None => &self.validation_methods,
        }
    }
}

/// What to check.
#[derive(Clone, Debug)]
pub struct HealthConfig {
    /// Zones to check (DNSSEC, NS, SOA).
    pub zones: Vec<String>,
    /// Names whose CAA policy to check.
    pub caa_targets: Vec<CaaTarget>,
    pub caa: CaaPolicy,
    pub rrsig: RrsigThresholds,
    /// Per-zone nameserver cap (a hostile NS set must not turn a check into a fan-out).
    pub max_ns_per_zone: usize,
    /// Addresses tried per nameserver.
    pub max_addrs_per_ns: usize,
    pub max_zones: usize,
    pub max_caa_targets: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig {
            zones: Vec::new(),
            caa_targets: Vec::new(),
            caa: CaaPolicy::default(),
            rrsig: RrsigThresholds::default(),
            max_ns_per_zone: 8,
            max_addrs_per_ns: 2,
            max_zones: 64,
            max_caa_targets: 256,
        }
    }
}

// ── Lookup seam ───────────────────────────────────────────────────────────────────────────

/// The network side of the checks. Implemented by [`NetLookup`] for production and by fakes in tests.
pub trait DnsLookup: Send + Sync {
    /// Ask the recursive resolvers (RD and DO set). `None` when none gave a usable
    /// (NOERROR/NXDOMAIN) answer.
    fn recursive<'a>(&'a self, name: &'a Name, qtype: RecordType)
        -> BoxFuture<'a, Option<Message>>;
    /// Ask one authoritative server directly (RD clear, DO set). The reply is returned whatever its
    /// rcode — a REFUSED is the finding.
    fn direct<'a>(
        &'a self,
        server: SocketAddr,
        name: &'a Name,
        qtype: RecordType,
    ) -> BoxFuture<'a, Option<Message>>;
    /// The socket addresses to ask for the nameserver `ns`.
    fn nameserver_addrs<'a>(&'a self, ns: &'a Name) -> BoxFuture<'a, Vec<SocketAddr>>;
}

/// [`DnsLookup`] over real sockets, on [`DnsClient`].
#[derive(Clone, Debug)]
pub struct NetLookup {
    resolvers: Vec<SocketAddr>,
    client: DnsClient,
    ns_port: u16,
    ns_override: HashMap<String, Vec<SocketAddr>>,
}

impl NetLookup {
    /// Recursive queries go to `resolvers` (in order, first usable answer wins); authoritative servers
    /// are reached on port 53 at the addresses their NS names resolve to.
    #[must_use]
    pub fn new(resolvers: Vec<SocketAddr>) -> Self {
        NetLookup {
            resolvers,
            client: DnsClient::default(),
            ns_port: 53,
            ns_override: HashMap::new(),
        }
    }

    /// Public recursive resolvers from two operators, like [`crate::edge_verify::NativeProbe::public`].
    #[must_use]
    pub fn public() -> Self {
        Self::new(
            ["1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53", "8.8.4.4:53"]
                .iter()
                .filter_map(|a| a.parse().ok())
                .collect(),
        )
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = DnsClient::new(timeout);
        self
    }

    /// Reach the nameserver `ns_name` at exactly these addresses instead of resolving it (split
    /// horizon, a server not yet in DNS, or a test).
    #[must_use]
    pub fn with_ns_addrs(mut self, ns_name: &str, addrs: Vec<SocketAddr>) -> Self {
        self.ns_override.insert(norm_str(ns_name), addrs);
        self
    }
}

impl DnsLookup for NetLookup {
    fn recursive<'a>(
        &'a self,
        name: &'a Name,
        qtype: RecordType,
    ) -> BoxFuture<'a, Option<Message>> {
        Box::pin(async move {
            for resolver in &self.resolvers {
                let opts = QueryOptions {
                    recursion_desired: true,
                    dnssec_ok: true,
                };
                if let Some(m) = self.client.query(*resolver, name, qtype, opts).await {
                    if matches!(
                        m.flags.response_code,
                        ResponseCode::NoError | ResponseCode::NxDomain
                    ) {
                        return Some(m);
                    }
                }
            }
            None
        })
    }

    fn direct<'a>(
        &'a self,
        server: SocketAddr,
        name: &'a Name,
        qtype: RecordType,
    ) -> BoxFuture<'a, Option<Message>> {
        Box::pin(async move {
            self.client
                .query(
                    server,
                    name,
                    qtype,
                    QueryOptions {
                        recursion_desired: false,
                        dnssec_ok: true,
                    },
                )
                .await
        })
    }

    fn nameserver_addrs<'a>(&'a self, ns: &'a Name) -> BoxFuture<'a, Vec<SocketAddr>> {
        Box::pin(async move {
            if let Some(addrs) = self.ns_override.get(&norm(ns)) {
                return addrs.clone();
            }
            let mut out = Vec::new();
            for qtype in [RecordType::A, RecordType::Aaaa] {
                if let Some(m) = self.recursive(ns, qtype).await {
                    for r in &m.answers {
                        match r.data {
                            RData::A(a) => out.push(SocketAddr::new(IpAddr::V4(a), self.ns_port)),
                            RData::Aaaa(a) => {
                                out.push(SocketAddr::new(IpAddr::V6(a), self.ns_port))
                            }
                            _ => {}
                        }
                    }
                }
            }
            out.dedup();
            out
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────────

fn norm_str(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn norm(n: &Name) -> String {
    norm_str(&n.to_ascii())
}

/// The digest a DS of `digest_type` would carry for `key` at `owner` (RFC 4034 §5.1.4:
/// `digest(canonical owner name ‖ DNSKEY RDATA)`). `None` for a digest type this module does not
/// compute. SHA-1 (type 1) is computed only so a legacy DS can be matched and flagged.
#[must_use]
pub fn ds_digest(owner: &Name, key: &DnskeyObs, digest_type: u8) -> Option<Vec<u8>> {
    let alg = match digest_type {
        1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        2 => &digest::SHA256,
        4 => &digest::SHA384,
        _ => return None,
    };
    let mut ctx = digest::Context::new(alg);
    ctx.update(&owner.canonical_wire());
    ctx.update(&dnskey_rdata(
        key.flags,
        key.protocol,
        key.algorithm,
        &key.public_key,
    ));
    Some(ctx.finish().as_ref().to_vec())
}

/// Whether `ds` is the DS of `key` at `owner`.
#[must_use]
pub fn ds_matches(owner: &Name, ds: &DsObs, key: &DnskeyObs) -> bool {
    ds.key_tag == key.key_tag()
        && ds.algorithm == key.algorithm
        && ds_digest(owner, key, ds.digest_type).is_some_and(|d| d == ds.digest)
}

fn rrsigs_for(m: &Message, covered: RecordType) -> Vec<RrsigObs> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Rrsig {
                type_covered,
                algorithm,
                expiration,
                inception,
                key_tag,
                signer,
                ..
            } if *type_covered == covered => Some(RrsigObs {
                type_covered: *type_covered,
                algorithm: *algorithm,
                key_tag: *key_tag,
                expiration: *expiration,
                inception: *inception,
                signer: norm(signer),
            }),
            _ => None,
        })
        .collect()
}

// ── Collectors (network) ──────────────────────────────────────────────────────────────────

/// Gather everything about `zone`: DS and NS via the resolvers, then SOA, NS, DNSKEY and their
/// RRSIGs from each authoritative server directly.
pub async fn collect_zone(
    lookup: &dyn DnsLookup,
    zone: &str,
    cfg: &HealthConfig,
) -> ZoneObservation {
    let zone = norm_str(zone);
    let Ok(zname) = Name::from_ascii(&zone) else {
        return ZoneObservation {
            zone,
            ds: None,
            ns_names: None,
            servers: Vec::new(),
        };
    };

    let (ds_reply, ns_reply) = tokio::join!(
        lookup.recursive(&zname, RecordType::DS),
        lookup.recursive(&zname, RecordType::Ns)
    );
    let ds = ds_reply.map(|m| {
        m.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                } if r.name == zname => Some(DsObs {
                    key_tag: *key_tag,
                    algorithm: *algorithm,
                    digest_type: *digest_type,
                    digest: digest.clone(),
                }),
                _ => None,
            })
            .collect::<Vec<_>>()
    });
    let ns_names: Option<BTreeSet<String>> = ns_reply.map(|m| {
        m.answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Ns(n) if r.name == zname => Some(norm(n)),
                _ => None,
            })
            .collect()
    });

    let mut servers = Vec::new();
    for ns in ns_names.iter().flatten().take(cfg.max_ns_per_zone) {
        let Ok(ns_name) = Name::from_ascii(ns) else {
            servers.push(ServerObservation::new(ns, None, ServerState::Unresolvable));
            continue;
        };
        let addrs = lookup.nameserver_addrs(&ns_name).await;
        if addrs.is_empty() {
            servers.push(ServerObservation::new(ns, None, ServerState::Unresolvable));
            continue;
        }
        for addr in addrs.into_iter().take(cfg.max_addrs_per_ns) {
            servers.push(collect_server(lookup, &zname, ns, addr).await);
        }
    }
    ZoneObservation {
        zone,
        ds,
        ns_names,
        servers,
    }
}

async fn collect_server(
    lookup: &dyn DnsLookup,
    zone: &Name,
    ns: &str,
    addr: SocketAddr,
) -> ServerObservation {
    let (soa, nsr, key) = tokio::join!(
        lookup.direct(addr, zone, RecordType::Soa),
        lookup.direct(addr, zone, RecordType::Ns),
        lookup.direct(addr, zone, RecordType::DNSKEY),
    );
    let Some(soa_reply) = soa else {
        return ServerObservation::new(ns, Some(addr), ServerState::Unreachable);
    };
    if soa_reply.flags.response_code != ResponseCode::NoError || !soa_reply.flags.authoritative {
        let said = format!(
            "rcode {} aa={}",
            soa_reply.flags.response_code.code(),
            soa_reply.flags.authoritative
        );
        return ServerObservation::new(ns, Some(addr), ServerState::Lame(said));
    }
    let mut obs = ServerObservation::new(ns, Some(addr), ServerState::Answering);
    obs.soa = soa_reply.answers.iter().find_map(|r| match &r.data {
        RData::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        } if r.name == *zone => Some(SoaObs {
            serial: *serial,
            refresh: *refresh,
            retry: *retry,
            expire: *expire,
            minimum: *minimum,
        }),
        _ => None,
    });
    obs.soa_rrsigs = rrsigs_for(&soa_reply, RecordType::Soa);
    if let Some(m) = nsr {
        obs.ns_set = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Ns(n) if r.name == *zone => Some(norm(n)),
                _ => None,
            })
            .collect();
    }
    if let Some(m) = key {
        obs.dnskeys = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Dnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                } if r.name == *zone => Some(DnskeyObs {
                    flags: *flags,
                    protocol: *protocol,
                    algorithm: *algorithm,
                    public_key: public_key.clone(),
                }),
                _ => None,
            })
            .collect();
        obs.dnskey_rrsigs = rrsigs_for(&m, RecordType::DNSKEY);
    }
    obs
}

/// The deepest a CAA climb goes (a name has at most 127 labels).
const MAX_CAA_DEPTH: usize = 16;

/// Look up `name`'s CAA by climbing toward the root until a name has any CAA RRset (RFC 8659 §3).
/// A failed lookup on the way stops the climb with `lookup_failed` set: with the record set
/// unknown the policy is unknown.
pub async fn collect_caa(lookup: &dyn DnsLookup, name: &str) -> CaaObservation {
    let name = norm_str(name);
    let mut obs = CaaObservation {
        name: name.clone(),
        lookup_failed: false,
        found_at: None,
        records: Vec::new(),
    };
    let mut candidate: &str = &name;
    for _ in 0..MAX_CAA_DEPTH {
        let Ok(q) = Name::from_ascii(candidate) else {
            obs.lookup_failed = true;
            return obs;
        };
        let Some(reply) = lookup.recursive(&q, RecordType::Caa).await else {
            obs.lookup_failed = true;
            return obs;
        };
        let records: Vec<CaaRecord> = reply
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Caa { flags, tag, value } => Some(CaaRecord {
                    flags: *flags,
                    tag: tag.to_ascii_lowercase(),
                    value: value.clone(),
                }),
                _ => None,
            })
            .collect();
        if !records.is_empty() {
            obs.found_at = Some(candidate.to_string());
            obs.records = records;
            return obs;
        }
        match candidate.split_once('.') {
            Some((_, parent)) if !parent.is_empty() => candidate = parent,
            _ => return obs,
        }
    }
    obs
}

// ── Evaluators (pure) ─────────────────────────────────────────────────────────────────────

/// Numbers about one zone, for metrics and the health report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneHealth {
    pub zone: String,
    /// Any server publishes a DNSKEY, or the parent has a DS.
    pub signed: bool,
    pub ds_present: bool,
    /// The parent has DS records and none matches a published DNSKEY.
    pub ds_mismatch: bool,
    /// Seconds until the earliest RRSIG over the DNSKEY and SOA RRsets expires (negative =
    /// already expired); `None` when there was no signature to read.
    pub rrsig_earliest_expiry_secs: Option<i64>,
    pub servers_total: usize,
    pub servers_answering: usize,
    /// The SOA serial when every answering server agrees on it.
    pub soa_serial: Option<u32>,
}

/// Evaluate one zone's observation: findings plus the numbers. Pure.
#[must_use]
pub fn evaluate_zone(
    obs: &ZoneObservation,
    cfg: &HealthConfig,
    now: i64,
) -> (ZoneHealth, Vec<Finding>) {
    let zone = obs.zone.as_str();
    let mut out = Vec::new();
    let answering: Vec<&ServerObservation> = obs
        .servers
        .iter()
        .filter(|s| s.state == ServerState::Answering)
        .collect();

    ns_soa_findings(obs, &answering, &mut out);

    // ── DNSSEC ──
    let published: BTreeSet<DnskeyObs> = answering
        .iter()
        .flat_map(|s| s.dnskeys.iter().cloned())
        .collect();
    let ds_present = obs.ds.as_ref().is_some_and(|d| !d.is_empty());
    let signed = ds_present || !published.is_empty();
    let mut health = ZoneHealth {
        zone: zone.to_string(),
        signed,
        ds_present,
        ds_mismatch: false,
        rrsig_earliest_expiry_secs: None,
        servers_total: obs.servers.len(),
        servers_answering: answering.len(),
        soa_serial: soa_serial_if_agreed(&answering),
    };
    if !signed {
        if obs.ds.is_none() && !answering.is_empty() {
            out.push(finding(
                Severity::Warning,
                FindingKind::DsLookupFailed,
                zone,
                "the DS lookup failed, so the chain of trust could not be checked",
            ));
        }
        return (health, out);
    }

    let Ok(owner) = Name::from_ascii(zone) else {
        return (health, out);
    };
    let mut ds_key_tags: BTreeSet<u16> = BTreeSet::new();
    match &obs.ds {
        None => out.push(finding(Severity::Warning, FindingKind::DsLookupFailed, zone, "the DS lookup failed, so the chain of trust could not be checked")),
        Some(ds) if ds.is_empty() => out.push(finding(
            Severity::Info,
            FindingKind::SignedZoneWithoutDs,
            zone,
            "the zone publishes DNSKEY records but the parent has no DS: it is not chained, so resolvers do not validate it",
        )),
        Some(ds) if published.is_empty() => {
            if !answering.is_empty() {
                out.push(finding(
                    Severity::Critical,
                    FindingKind::DsWithoutDnskey,
                    zone,
                    format!("the parent has {} DS record(s) but no authoritative server publishes a DNSKEY: validating resolvers answer SERVFAIL", ds.len()),
                ));
                health.ds_mismatch = true;
            }
        }
        Some(ds) => {
            let (mut matched, mut unmatched, mut unverifiable) = (Vec::new(), Vec::new(), Vec::new());
            for d in ds {
                if !matches!(d.digest_type, 1 | 2 | 4) {
                    unverifiable.push(d);
                } else if published.iter().any(|k| ds_matches(&owner, d, k)) {
                    matched.push(d);
                } else {
                    unmatched.push(d);
                }
            }
            for d in &matched {
                ds_key_tags.insert(d.key_tag);
            }
            for d in &unverifiable {
                out.push(finding(
                    Severity::Warning,
                    FindingKind::DsDigestUnsupported,
                    zone,
                    format!("DS key tag {} uses digest type {}, which cannot be recomputed here", d.key_tag, d.digest_type),
                ));
            }
            if matched.is_empty() && unverifiable.is_empty() {
                health.ds_mismatch = true;
                let tags: Vec<String> = ds.iter().map(|d| d.key_tag.to_string()).collect();
                let keys: Vec<String> = published.iter().map(|k| k.key_tag().to_string()).collect();
                out.push(finding(
                    Severity::Critical,
                    FindingKind::DsDnskeyMismatch,
                    zone,
                    format!(
                        "no DS record (key tags {}) matches any published DNSKEY (key tags {}): the chain of trust is broken and validating resolvers answer SERVFAIL",
                        tags.join(","),
                        keys.join(",")
                    ),
                ));
            } else if !unmatched.is_empty() && !matched.is_empty() {
                let tags: Vec<String> = unmatched.iter().map(|d| d.key_tag.to_string()).collect();
                out.push(finding(
                    Severity::Warning,
                    FindingKind::DsPartialMismatch,
                    zone,
                    format!("DS key tag(s) {} match no published DNSKEY (stale after a rollover?); the matching DS keep the chain valid", tags.join(",")),
                ));
            }
            if !matched.is_empty() && matched.iter().all(|d| d.digest_type == 1) {
                out.push(finding(Severity::Warning, FindingKind::DsWeakDigest, zone, "the only DS records that match use a SHA-1 digest; publish a SHA-256 DS"));
            }
        }
    }

    // Servers must agree on what they publish.
    let key_sets: Vec<BTreeSet<&DnskeyObs>> = answering
        .iter()
        .map(|s| s.dnskeys.iter().collect())
        .collect();
    if key_sets.windows(2).any(|w| w[0] != w[1]) {
        let detail = answering
            .iter()
            .map(|s| format!("{}: {} key(s)", s.label(), s.dnskeys.len()))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(finding(Severity::Error, FindingKind::DnskeyDisagreement, zone, format!("authoritative servers publish different DNSKEY sets ({detail}): resolvers see intermittent failures")));
    }

    // Signatures, per server that publishes keys.
    let mut earliest: Option<i64> = None;
    for s in answering.iter().filter(|s| !s.dnskeys.is_empty()) {
        for (what, sigs) in [("DNSKEY", &s.dnskey_rrsigs), ("SOA", &s.soa_rrsigs)] {
            if sigs.is_empty() {
                out.push(finding(
                    Severity::Critical,
                    FindingKind::RrsigMissing,
                    zone,
                    format!(
                        "{} returned no RRSIG over the {what} RRset of a signed zone",
                        s.label()
                    ),
                ));
            }
            for sig in sigs {
                let left = serial_secs_until(sig.expiration, now);
                earliest = Some(earliest.map_or(left, |e| e.min(left)));
                signature_timing(
                    zone,
                    &s.label(),
                    what,
                    left,
                    serial_secs_until(sig.inception, now),
                    &cfg.rrsig,
                    &mut out,
                );
            }
        }
        if !ds_key_tags.is_empty()
            && !s.dnskey_rrsigs.is_empty()
            && !s
                .dnskey_rrsigs
                .iter()
                .any(|r| ds_key_tags.contains(&r.key_tag))
        {
            out.push(finding(
                Severity::Critical,
                FindingKind::DnskeyNotSignedByDsKey,
                zone,
                format!("{}: the DNSKEY RRset is not signed by the key the DS record names, so the chain cannot be validated", s.label()),
            ));
        }
    }
    health.rrsig_earliest_expiry_secs = earliest;
    (health, out)
}

fn signature_timing(
    zone: &str,
    server: &str,
    what: &str,
    left: i64,
    inception_in: i64,
    t: &RrsigThresholds,
    out: &mut Vec<Finding>,
) {
    let (sev, kind) = if left < 0 {
        (Severity::Critical, FindingKind::RrsigExpired)
    } else if left < t.critical_secs {
        (Severity::Critical, FindingKind::RrsigExpiring)
    } else if left < t.error_secs {
        (Severity::Error, FindingKind::RrsigExpiring)
    } else if left < t.warn_secs {
        (Severity::Warning, FindingKind::RrsigExpiring)
    } else {
        (Severity::Info, FindingKind::RrsigExpiring)
    };
    if sev > Severity::Info {
        let detail = if left < 0 {
            format!(
                "{server}: the RRSIG over the {what} RRset expired {}s ago",
                -left
            )
        } else {
            format!("{server}: the RRSIG over the {what} RRset expires in {left}s")
        };
        out.push(finding(sev, kind, zone, detail));
    }
    if inception_in > INCEPTION_SKEW_SECS {
        out.push(finding(
            Severity::Warning,
            FindingKind::RrsigNotYetValid,
            zone,
            format!("{server}: the RRSIG over the {what} RRset is not valid for another {inception_in}s"),
        ));
    }
}

fn soa_serial_if_agreed(answering: &[&ServerObservation]) -> Option<u32> {
    let serials: BTreeSet<u32> = answering
        .iter()
        .filter_map(|s| s.soa.map(|x| x.serial))
        .collect();
    (serials.len() == 1)
        .then(|| serials.into_iter().next())
        .flatten()
}

/// `/24` (IPv4) or `/48` (IPv6) prefix, as a comparable key.
fn network_of(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets()[..3].to_vec(),
        IpAddr::V6(a) => a.octets()[..6].to_vec(),
    }
}

fn ns_soa_findings(
    obs: &ZoneObservation,
    answering: &[&ServerObservation],
    out: &mut Vec<Finding>,
) {
    let zone = obs.zone.as_str();
    match &obs.ns_names {
        None => {
            out.push(finding(
                Severity::Warning,
                FindingKind::NsLookupFailed,
                zone,
                "the NS lookup through the resolvers failed; nameserver checks were skipped",
            ));
            return;
        }
        Some(names) if names.is_empty() => {
            out.push(finding(
                Severity::Critical,
                FindingKind::NsMissing,
                zone,
                "the resolvers see no NS records for the zone",
            ));
            return;
        }
        Some(names) if names.len() < 2 => {
            out.push(finding(Severity::Warning, FindingKind::NsTooFew, zone, format!("only {} nameserver ({}): a single server is a single point of failure (RFC 2182 §5)", names.len(), names.iter().next().map_or("", String::as_str))));
        }
        Some(_) => {}
    }
    for s in &obs.servers {
        match &s.state {
            ServerState::Unresolvable => out.push(finding(
                Severity::Error,
                FindingKind::NsUnresolvable,
                zone,
                format!("nameserver {} has no A/AAAA record", s.ns_name),
            )),
            ServerState::Unreachable => out.push(finding(
                Severity::Error,
                FindingKind::ServerUnreachable,
                zone,
                format!("{} did not answer", s.label()),
            )),
            ServerState::Lame(said) => out.push(finding(
                Severity::Error,
                FindingKind::LameDelegation,
                zone,
                format!(
                    "{} is listed as a nameserver but is not authoritative ({said})",
                    s.label()
                ),
            )),
            ServerState::Answering => {}
        }
    }
    // Different networks.
    let addrs: Vec<IpAddr> = obs
        .servers
        .iter()
        .filter_map(|s| s.addr.map(|a| a.ip()))
        .collect();
    let distinct_hosts: BTreeSet<IpAddr> = addrs.iter().copied().collect();
    if distinct_hosts.len() >= 2
        && addrs
            .iter()
            .map(|a| network_of(*a))
            .collect::<BTreeSet<_>>()
            .len()
            == 1
    {
        out.push(finding(Severity::Warning, FindingKind::NsSameNetwork, zone, "every nameserver address is in the same network (/24 or /48): one routing or datacentre failure takes them all"));
    }
    // NS set agreement with the resolvers' view.
    if let Some(names) = &obs.ns_names {
        for s in answering
            .iter()
            .filter(|s| !s.ns_set.is_empty() && s.ns_set != *names)
        {
            out.push(finding(
                Severity::Warning,
                FindingKind::NsSetMismatch,
                zone,
                format!(
                    "{} lists nameservers {:?} but the resolvers see {:?}",
                    s.label(),
                    s.ns_set,
                    names
                ),
            ));
        }
    }
    // SOA.
    for s in answering.iter().filter(|s| s.soa.is_none()) {
        out.push(finding(
            Severity::Error,
            FindingKind::SoaMissing,
            zone,
            format!(
                "{} is authoritative but returns no SOA for the zone apex",
                s.label()
            ),
        ));
    }
    let serials: BTreeSet<u32> = answering
        .iter()
        .filter_map(|s| s.soa.map(|x| x.serial))
        .collect();
    if serials.len() > 1 {
        let detail = answering
            .iter()
            .filter_map(|s| s.soa.map(|x| format!("{}: {}", s.label(), x.serial)))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(finding(
            Severity::Warning,
            FindingKind::ServerDisagreement,
            zone,
            format!("authoritative servers serve different SOA serials ({detail}): one is behind"),
        ));
    }
    if let Some(soa) = answering.iter().find_map(|s| s.soa) {
        let mut problems = Vec::new();
        if u64::from(soa.expire) < u64::from(soa.refresh) + u64::from(soa.retry) {
            problems.push("expire is shorter than refresh + retry".to_string());
        }
        if soa.expire < 7 * 86_400 {
            problems.push(format!("expire {}s is under a week", soa.expire));
        }
        if soa.retry > soa.refresh {
            problems.push("retry is longer than refresh".to_string());
        }
        if soa.minimum > 86_400 {
            problems.push(format!("negative-cache TTL {}s is over a day", soa.minimum));
        }
        if !problems.is_empty() {
            out.push(finding(
                Severity::Warning,
                FindingKind::SoaTimers,
                zone,
                problems.join("; "),
            ));
        }
    }
}

/// One parsed `issue`/`issuewild` value (RFC 8659 §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaaIssue {
    /// Lower-case issuer domain; empty means "no CA may issue".
    pub issuer: String,
    pub params: Vec<(String, String)>,
}

impl CaaIssue {
    fn param(&self, tag: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(tag))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse an `issue`/`issuewild` property value: `[issuer-domain] *(; tag=value)`. `None` if it is
/// not valid UTF-8 or a parameter has no `=`.
#[must_use]
pub fn parse_caa_issue(value: &[u8]) -> Option<CaaIssue> {
    let text = std::str::from_utf8(value).ok()?;
    let mut parts = text.split(';');
    let issuer = parts.next()?.trim().to_ascii_lowercase();
    if issuer.contains(char::is_whitespace) {
        return None;
    }
    let mut params = Vec::new();
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v) = p.split_once('=')?;
        params.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    Some(CaaIssue { issuer, params })
}

const KNOWN_CAA_TAGS: [&str; 7] = [
    "issue",
    "issuewild",
    "iodef",
    "contactemail",
    "contactphone",
    "issuemail",
    "issuevmc",
];

/// Evaluate the effective CAA policy of `target` against `policy`. Pure.
#[must_use]
pub fn evaluate_caa(obs: &CaaObservation, target: &CaaTarget, policy: &CaaPolicy) -> Vec<Finding> {
    let subject = if target.wildcard {
        format!("*.{}", target.name)
    } else {
        target.name.clone()
    };
    let own = target.scope == CaaScope::Own;
    let mut out = Vec::new();
    if obs.lookup_failed {
        let sev = if own {
            Severity::Error
        } else {
            Severity::Warning
        };
        out.push(finding(sev, FindingKind::CaaLookupFailed, &subject, "the CAA lookup failed, so a CA must refuse to issue (RFC 8659 §3) and the policy cannot be checked"));
        return out;
    }
    if obs.records.is_empty() {
        if own {
            out.push(finding(
                Severity::Warning,
                FindingKind::CaaAbsent,
                &subject,
                "no CAA record at the name or any ancestor: any CA may issue for it",
            ));
        }
        return out;
    }
    let at = obs.found_at.as_deref().unwrap_or(&obs.name);

    for r in &obs.records {
        if r.flags & 0x80 != 0 && !KNOWN_CAA_TAGS.contains(&r.tag.as_str()) {
            out.push(finding(
                Severity::Error,
                FindingKind::CaaUnknownCritical,
                &subject,
                format!(
                    "CAA at {at} has a critical property '{}' that CAs must refuse to issue past",
                    r.tag
                ),
            ));
        }
    }

    // The relevant property set: `issuewild` for a wildcard if any exists, else `issue`.
    let has_wild = target.wildcard && obs.records.iter().any(|r| r.tag == "issuewild");
    let tag = if has_wild { "issuewild" } else { "issue" };
    let mut entries: Vec<CaaIssue> = Vec::new();
    for r in obs.records.iter().filter(|r| r.tag == tag) {
        match parse_caa_issue(&r.value) {
            Some(e) => entries.push(e),
            None => out.push(finding(
                Severity::Error,
                FindingKind::CaaMalformed,
                &subject,
                format!(
                    "a CAA {tag} value at {at} cannot be parsed; CAs treat the policy as unusable"
                ),
            )),
        }
    }
    if entries.is_empty() {
        // CAA exists but says nothing about issuance (e.g. only iodef): unrestricted.
        if own {
            out.push(finding(
                Severity::Warning,
                FindingKind::CaaAbsent,
                &subject,
                format!("CAA at {at} has no {tag} property: any CA may issue"),
            ));
        }
        return out;
    }

    let allowed = |issuer: &str| policy.is_allowed(issuer);
    let ours: Vec<&CaaIssue> = entries.iter().filter(|e| allowed(&e.issuer)).collect();
    let blocks_sev = if own {
        Severity::Critical
    } else {
        Severity::Warning
    };

    if own {
        for e in entries
            .iter()
            .filter(|e| !e.issuer.is_empty() && !allowed(&e.issuer))
        {
            out.push(finding(
                Severity::Error,
                FindingKind::CaaUnknownCa,
                &subject,
                format!(
                    "CAA at {at} permits '{}', which is not in the allow-list {:?}",
                    e.issuer,
                    policy
                        .allowed_issuers
                        .iter()
                        .cloned()
                        .chain(policy.issuers.iter().map(|i| i.domain.clone()))
                        .collect::<Vec<_>>()
                ),
            ));
        }
    }

    // Can we issue under this policy at all?
    let usable_for_us: Vec<&&CaaIssue> = ours
        .iter()
        .filter(|e| {
            let ours = policy.accounts_for(&e.issuer);
            match e.param("accounturi") {
                Some(theirs) if !ours.is_empty() => ours.contains(&theirs),
                _ => true,
            }
        })
        .filter(
            |e| match (&policy.customer_method, e.param("validationmethods")) {
                (Some(m), Some(list)) if !own => {
                    list.split(',').any(|x| x.trim().eq_ignore_ascii_case(m))
                }
                _ => true,
            },
        )
        .collect();
    if usable_for_us.is_empty() {
        let why = if entries.iter().all(|e| e.issuer.is_empty()) {
            "the policy forbids all issuance".to_string()
        } else if ours.is_empty() {
            format!(
                "the policy does not list any of our CAs {:?}",
                policy.allowed_issuers
            )
        } else {
            "the entries for our CA are bound to another account or to validation methods we do not use".to_string()
        };
        out.push(finding(
            blocks_sev,
            FindingKind::CaaBlocksIssuance,
            &subject,
            format!("CAA at {at}: {why}, so we cannot obtain a certificate"),
        ));
    }

    if own {
        let pinned = |e: &CaaIssue| {
            e.param("accounturi")
                .is_some_and(|theirs| policy.accounts_for(&e.issuer).contains(&theirs))
        };
        for e in ours.iter().filter(|e| !pinned(e)) {
            let expected = policy.accounts_for(&e.issuer);
            let Some(uri) = expected.first() else {
                continue;
            };
            {
                // Another entry for the same issuer *is* bound to our account: this unbound one
                // makes the binding meaningless.
                let any_pinned = ours.iter().any(|o| o.issuer == e.issuer && pinned(o));
                match e.param("accounturi") {
                    _ if any_pinned => out.push(finding(
                        Severity::Critical,
                        FindingKind::CaaPermissiveIssuer,
                        &subject,
                        format!("CAA at {at} has an extra '{}' entry that is not bound to our account next to one that is: either entry permits issuance, so the account binding protects nothing", e.issuer),
                    )),
                    None => out.push(finding(Severity::Error, FindingKind::CaaMissingAccountUri, &subject, format!("CAA at {at}: the '{}' entry has no accounturi (expected {uri})", e.issuer))),
                    Some(other) => out.push(finding(Severity::Critical, FindingKind::CaaForeignAccount, &subject, format!("CAA at {at}: the '{}' entry is bound to account {other}, not ours ({uri})", e.issuer))),
                }
            }
        }
        for e in &ours {
            let expected_methods = policy.methods_for(&e.issuer);
            if expected_methods.is_empty() {
                continue;
            }
            match e.param("validationmethods") {
                None => out.push(finding(
                    Severity::Warning,
                    FindingKind::CaaMissingValidationMethods,
                    &subject,
                    format!(
                        "CAA at {at}: the '{}' entry has no validationmethods (expected {:?})",
                        e.issuer, expected_methods
                    ),
                )),
                Some(list) => {
                    let extra: Vec<&str> = list
                        .split(',')
                        .map(str::trim)
                        .filter(|m| !expected_methods.iter().any(|p| p.eq_ignore_ascii_case(m)))
                        .collect();
                    if !extra.is_empty() {
                        out.push(finding(Severity::Warning, FindingKind::CaaValidationMethodsMismatch, &subject, format!("CAA at {at}: the '{}' entry also allows {:?}, beyond the expected {:?}", e.issuer, extra, expected_methods)));
                    }
                }
            }
        }
    }
    out
}

// ── The whole check ───────────────────────────────────────────────────────────────────────

/// The result of one [`run_checks`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthReport {
    /// Unix seconds the check ran.
    pub checked_at: i64,
    pub zones: Vec<ZoneHealth>,
    pub findings: Vec<Finding>,
}

impl HealthReport {
    /// The worst severity present, if any finding.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Findings of exactly `kind`.
    pub fn of_kind(&self, kind: FindingKind) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.kind == kind)
    }

    /// How many CAA findings are present (any severity above `Info`).
    #[must_use]
    pub fn caa_findings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.kind.is_caa() && f.severity > Severity::Info)
            .count()
    }
}

/// Run every configured check: each zone, then each CAA target. Bounded by the `max_*` limits
/// (anything past them is ignored and noted in a finding rather than silently dropped).
pub async fn run_checks(lookup: &dyn DnsLookup, cfg: &HealthConfig, now: i64) -> HealthReport {
    let mut report = HealthReport {
        checked_at: now,
        zones: Vec::new(),
        findings: Vec::new(),
    };
    if cfg.zones.len() > cfg.max_zones {
        report.findings.push(finding(
            Severity::Warning,
            FindingKind::NsLookupFailed,
            "config",
            format!(
                "{} zones configured; only the first {} are checked",
                cfg.zones.len(),
                cfg.max_zones
            ),
        ));
    }
    for zone in cfg.zones.iter().take(cfg.max_zones) {
        let obs = collect_zone(lookup, zone, cfg).await;
        let (health, findings) = evaluate_zone(&obs, cfg, now);
        report.zones.push(health);
        report.findings.extend(findings);
    }
    if cfg.caa_targets.len() > cfg.max_caa_targets {
        report.findings.push(finding(
            Severity::Warning,
            FindingKind::CaaLookupFailed,
            "config",
            format!(
                "{} CAA targets configured; only the first {} are checked",
                cfg.caa_targets.len(),
                cfg.max_caa_targets
            ),
        ));
    }
    for target in cfg.caa_targets.iter().take(cfg.max_caa_targets) {
        let obs = collect_caa(lookup, &target.name).await;
        report.findings.extend(evaluate_caa(&obs, target, &cfg.caa));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Flags, Record};
    use std::sync::{Arc, Mutex};

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn key(flags: u16, seed: u8) -> DnskeyObs {
        DnskeyObs {
            flags,
            protocol: 3,
            algorithm: 13,
            public_key: (0..64).map(|i| seed.wrapping_add(i)).collect(),
        }
    }

    fn ds_of(zone: &str, k: &DnskeyObs, digest_type: u8) -> DsObs {
        DsObs {
            key_tag: k.key_tag(),
            algorithm: k.algorithm,
            digest_type,
            digest: ds_digest(&n(zone), k, digest_type).unwrap(),
        }
    }

    fn sig(covered: RecordType, key_tag: u16, expires_in: i64) -> RrsigObs {
        RrsigObs {
            type_covered: covered,
            algorithm: 13,
            key_tag,
            expiration: u32::try_from((NOW + expires_in).rem_euclid(1 << 32)).unwrap(),
            inception: u32::try_from((NOW - DAY).rem_euclid(1 << 32)).unwrap(),
            signer: "example.com".into(),
        }
    }

    const SOA: SoaObs = SoaObs {
        serial: 42,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 300,
    };

    fn server(
        ns: &str,
        ip: &str,
        ksk: &DnskeyObs,
        zsk: &DnskeyObs,
        expires_in: i64,
    ) -> ServerObservation {
        let mut s = ServerObservation::new(
            ns,
            Some(SocketAddr::new(ip.parse().unwrap(), 53)),
            ServerState::Answering,
        );
        s.soa = Some(SOA);
        s.ns_set = ["ns1.example.net", "ns2.example.org"]
            .iter()
            .map(|x| (*x).to_string())
            .collect();
        s.dnskeys = vec![ksk.clone(), zsk.clone()];
        s.dnskey_rrsigs = vec![sig(RecordType::DNSKEY, ksk.key_tag(), expires_in)];
        s.soa_rrsigs = vec![sig(RecordType::Soa, zsk.key_tag(), expires_in)];
        s
    }

    /// A healthy signed zone served by two servers in different networks.
    fn healthy() -> (ZoneObservation, DnskeyObs, DnskeyObs) {
        let (ksk, zsk) = (key(257, 1), key(256, 100));
        let obs = ZoneObservation {
            zone: "example.com".into(),
            ds: Some(vec![ds_of("example.com", &ksk, 2)]),
            ns_names: Some(
                ["ns1.example.net", "ns2.example.org"]
                    .iter()
                    .map(|x| (*x).to_string())
                    .collect(),
            ),
            servers: vec![
                server("ns1.example.net", "192.0.2.1", &ksk, &zsk, 20 * DAY),
                server("ns2.example.org", "198.51.100.1", &ksk, &zsk, 20 * DAY),
            ],
        };
        (obs, ksk, zsk)
    }

    fn eval(obs: &ZoneObservation) -> (ZoneHealth, Vec<Finding>) {
        evaluate_zone(obs, &HealthConfig::default(), NOW)
    }

    fn kinds(f: &[Finding]) -> Vec<FindingKind> {
        f.iter().map(|x| x.kind).collect()
    }

    fn worst(f: &[Finding], kind: FindingKind) -> Option<Severity> {
        f.iter()
            .filter(|x| x.kind == kind)
            .map(|x| x.severity)
            .max()
    }

    // ── DS digest ──

    /// RFC 4034 §5.4 / RFC 4509: the DS of the `dskey.example.com` key, for SHA-1, SHA-256 (digests
    /// recomputed independently with Python's hashlib) and SHA-384.
    #[test]
    fn ds_digests_match_the_rfc_vectors_for_sha1_sha256_and_sha384() {
        let pk = crate::pem::base64_decode(
            "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        )
        .unwrap();
        let k = DnskeyObs {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: pk,
        };
        let owner = n("dskey.example.com");
        let hex = |d: Vec<u8>| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(k.key_tag(), 60485);
        assert_eq!(
            hex(ds_digest(&owner, &k, 1).unwrap()),
            "2bb183af5f22588179a53b0a98631fad1a292118",
            "RFC 4034 §5.4"
        );
        assert_eq!(
            hex(ds_digest(&owner, &k, 2).unwrap()),
            "d4b7d520e7bb5f0f67674a0cceb1e3e0614b93c4f9e99b8383f6a1e4469da50a"
        );
        assert_eq!(
            hex(ds_digest(&owner, &k, 4).unwrap()),
            "ab64dbebe13c0b6bae558b78ccab93b836f8ada4cbed2d4484a8715a819de7b9e846315e70ea5d884b377394bdaf16a3"
        );
        assert!(
            ds_digest(&owner, &k, 3).is_none()
                && ds_digest(&owner, &k, 0).is_none()
                && ds_digest(&owner, &k, 255).is_none()
        );
        // The owner name is part of the digest, case-insensitively.
        assert_eq!(
            ds_digest(&n("DSKEY.Example.COM"), &k, 2),
            ds_digest(&owner, &k, 2)
        );
        assert_ne!(
            ds_digest(&n("other.example.com"), &k, 2),
            ds_digest(&owner, &k, 2)
        );
        let ds = DsObs {
            key_tag: 60485,
            algorithm: 5,
            digest_type: 2,
            digest: ds_digest(&owner, &k, 2).unwrap(),
        };
        assert!(ds_matches(&owner, &ds, &k));
        assert!(
            !ds_matches(
                &owner,
                &DsObs {
                    key_tag: 1,
                    ..ds.clone()
                },
                &k
            ),
            "tag must match"
        );
        assert!(
            !ds_matches(
                &owner,
                &DsObs {
                    algorithm: 8,
                    ..ds.clone()
                },
                &k
            ),
            "algorithm must match"
        );
        let mut bad = ds.clone();
        bad.digest[0] ^= 1;
        assert!(!ds_matches(&owner, &bad, &k), "digest must match");
    }

    // ── DNSSEC evaluation ──

    #[test]
    fn a_healthy_signed_zone_has_no_findings_and_reports_the_earliest_expiry() {
        let (obs, ..) = healthy();
        let (health, findings) = eval(&obs);
        assert!(findings.is_empty(), "{findings:#?}");
        assert!(health.signed && health.ds_present && !health.ds_mismatch);
        assert_eq!(health.rrsig_earliest_expiry_secs, Some(20 * DAY));
        assert_eq!(
            (
                health.servers_total,
                health.servers_answering,
                health.soa_serial
            ),
            (2, 2, Some(42))
        );
    }

    #[test]
    fn a_ds_that_matches_no_dnskey_is_critical_and_flagged() {
        let (mut obs, ..) = healthy();
        let stale = key(257, 77); // the KSK was rolled; the DS at the parent still names the old one
        obs.ds = Some(vec![ds_of("example.com", &stale, 2)]);
        let (health, findings) = eval(&obs);
        assert!(health.ds_mismatch);
        let f = findings
            .iter()
            .find(|f| f.kind == FindingKind::DsDnskeyMismatch)
            .expect("mismatch reported");
        assert_eq!(f.severity, Severity::Critical);
        assert!(
            f.detail.contains(&stale.key_tag().to_string()) && f.detail.contains("SERVFAIL"),
            "{}",
            f.detail
        );
        // A DS whose digest is wrong for a key that has the right tag is the same fault.
        let (mut obs, ksk, _) = healthy();
        let mut forged = ds_of("example.com", &ksk, 2);
        forged.digest[3] ^= 0x10;
        obs.ds = Some(vec![forged]);
        assert!(eval(&obs).0.ds_mismatch);
        // ...and so is the right digest under the wrong algorithm number.
        let (mut obs, ksk, _) = healthy();
        let mut wrong_alg = ds_of("example.com", &ksk, 2);
        wrong_alg.algorithm = 8;
        obs.ds = Some(vec![wrong_alg]);
        assert!(eval(&obs).0.ds_mismatch);
    }

    #[test]
    fn a_stale_extra_ds_is_a_warning_while_a_matching_one_keeps_the_chain_valid() {
        let (mut obs, ksk, _) = healthy();
        obs.ds = Some(vec![
            ds_of("example.com", &ksk, 2),
            ds_of("example.com", &key(257, 9), 2),
        ]);
        let (health, findings) = eval(&obs);
        assert!(!health.ds_mismatch);
        assert_eq!(kinds(&findings), vec![FindingKind::DsPartialMismatch]);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn ds_edge_cases_without_dnskey_unsupported_digest_sha1_unsigned_and_lookup_failure() {
        // DS at the parent, nothing published: validators SERVFAIL.
        let (mut obs, ..) = healthy();
        for s in &mut obs.servers {
            s.dnskeys.clear();
            s.dnskey_rrsigs.clear();
            s.soa_rrsigs.clear();
        }
        let (health, f) = eval(&obs);
        assert_eq!(
            worst(&f, FindingKind::DsWithoutDnskey),
            Some(Severity::Critical)
        );
        assert!(health.ds_mismatch);

        // A digest type we cannot recompute is not called a mismatch.
        let (mut obs, ksk, _) = healthy();
        obs.ds = Some(vec![DsObs {
            digest_type: 3,
            ..ds_of("example.com", &ksk, 2)
        }]);
        let (health, f) = eval(&obs);
        assert!(!health.ds_mismatch);
        assert_eq!(kinds(&f), vec![FindingKind::DsDigestUnsupported]);

        // SHA-1 only: matches, but is flagged.
        let (mut obs, ksk, _) = healthy();
        obs.ds = Some(vec![ds_of("example.com", &ksk, 1)]);
        let (health, f) = eval(&obs);
        assert!(!health.ds_mismatch);
        assert_eq!(kinds(&f), vec![FindingKind::DsWeakDigest]);
        // ...but not when a SHA-256 DS matches as well.
        obs.ds = Some(vec![
            ds_of("example.com", &ksk, 1),
            ds_of("example.com", &ksk, 2),
        ]);
        assert!(eval(&obs).1.is_empty());

        // Signed but unchained.
        let (mut obs, ..) = healthy();
        obs.ds = Some(Vec::new());
        let (health, f) = eval(&obs);
        assert!(health.signed && !health.ds_present);
        assert_eq!(
            (kinds(&f), f[0].severity),
            (vec![FindingKind::SignedZoneWithoutDs], Severity::Info)
        );

        // The DS lookup itself failed.
        let (mut obs, ..) = healthy();
        obs.ds = None;
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::DsLookupFailed),
            Some(Severity::Warning)
        );

        // Wholly unsigned zone: no DNSSEC findings, signed = false.
        let mut obs = healthy().0;
        obs.ds = Some(Vec::new());
        for s in &mut obs.servers {
            s.dnskeys.clear();
            s.dnskey_rrsigs.clear();
            s.soa_rrsigs.clear();
        }
        let (health, f) = eval(&obs);
        assert!(!health.signed && health.rrsig_earliest_expiry_secs.is_none());
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn rrsig_lifetime_escalates_at_seven_three_and_one_days_and_expired_is_critical() {
        let cases = [
            (20 * DAY, None),
            (7 * DAY + 1, None),
            (
                7 * DAY - 1,
                Some((Severity::Warning, FindingKind::RrsigExpiring)),
            ),
            (
                3 * DAY + 1,
                Some((Severity::Warning, FindingKind::RrsigExpiring)),
            ),
            (
                3 * DAY - 1,
                Some((Severity::Error, FindingKind::RrsigExpiring)),
            ),
            (DAY + 1, Some((Severity::Error, FindingKind::RrsigExpiring))),
            (
                DAY - 1,
                Some((Severity::Critical, FindingKind::RrsigExpiring)),
            ),
            (1, Some((Severity::Critical, FindingKind::RrsigExpiring))),
            (-1, Some((Severity::Critical, FindingKind::RrsigExpired))),
            (
                -30 * DAY,
                Some((Severity::Critical, FindingKind::RrsigExpired)),
            ),
        ];
        for (left, want) in cases {
            let (mut obs, ksk, zsk) = healthy();
            obs.servers = vec![
                server("ns1.example.net", "192.0.2.1", &ksk, &zsk, left),
                server("ns2.example.org", "198.51.100.1", &ksk, &zsk, 20 * DAY),
            ];
            let (health, f) = eval(&obs);
            assert_eq!(
                health.rrsig_earliest_expiry_secs,
                Some(left.min(20 * DAY)),
                "left {left}"
            );
            let got = f
                .iter()
                .filter(|x| x.kind != FindingKind::SignedZoneWithoutDs)
                .map(|x| (x.severity, x.kind))
                .max();
            assert_eq!(got, want, "{left}s left: {f:?}");
            if want.is_some() {
                assert!(
                    f.iter().all(|x| x.detail.contains("ns1.example.net")),
                    "the finding names the server: {f:?}"
                );
            }
        }
        // The thresholds are configurable.
        let (mut obs, ksk, zsk) = healthy();
        obs.servers = vec![
            server("ns1.example.net", "192.0.2.1", &ksk, &zsk, 10 * DAY),
            server("ns2.example.org", "198.51.100.1", &ksk, &zsk, 10 * DAY),
        ];
        let cfg = HealthConfig {
            rrsig: RrsigThresholds {
                warn_secs: 14 * DAY,
                error_secs: 12 * DAY,
                critical_secs: 11 * DAY,
            },
            ..HealthConfig::default()
        };
        assert_eq!(
            worst(
                &evaluate_zone(&obs, &cfg, NOW).1,
                FindingKind::RrsigExpiring
            ),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn rrsig_times_are_compared_with_serial_arithmetic_across_the_2106_wrap() {
        let (mut obs, ..) = healthy();
        let wrap_now = (1i64 << 32) - 3600;
        for s in &mut obs.servers {
            for r in s.dnskey_rrsigs.iter_mut().chain(s.soa_rrsigs.iter_mut()) {
                r.expiration = 1800; // 1h30 after the 32-bit counter wraps
                r.inception = u32::MAX - 86_400;
            }
        }
        let (health, f) = evaluate_zone(&obs, &HealthConfig::default(), wrap_now);
        assert_eq!(health.rrsig_earliest_expiry_secs, Some(5400));
        assert_eq!(
            worst(&f, FindingKind::RrsigExpiring),
            Some(Severity::Critical)
        );
        assert!(worst(&f, FindingKind::RrsigNotYetValid).is_none());
    }

    #[test]
    fn missing_signatures_future_inception_and_a_dnskey_not_signed_by_the_ds_key_are_found() {
        let (mut obs, _ksk, zsk) = healthy();
        obs.servers[0].dnskey_rrsigs.clear();
        obs.servers[1].soa_rrsigs.clear();
        let (_, f) = eval(&obs);
        let missing: Vec<&Finding> = f
            .iter()
            .filter(|x| x.kind == FindingKind::RrsigMissing)
            .collect();
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().all(|m| m.severity == Severity::Critical));
        assert!(missing[0].detail.contains("DNSKEY") && missing[1].detail.contains("SOA"));

        let (mut obs, ..) = healthy();
        obs.servers[0].soa_rrsigs[0].inception = u32::try_from(NOW + 3 * 3600).unwrap();
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::RrsigNotYetValid),
            Some(Severity::Warning)
        );
        obs.servers[0].soa_rrsigs[0].inception = u32::try_from(NOW + 600).unwrap();
        assert!(
            worst(&eval(&obs).1, FindingKind::RrsigNotYetValid).is_none(),
            "within the skew allowance"
        );

        // The DNSKEY RRset is signed, but by the ZSK only: the DS-named KSK did not sign it.
        let (mut obs, ..) = healthy();
        obs.servers[0].dnskey_rrsigs = vec![sig(RecordType::DNSKEY, zsk.key_tag(), 20 * DAY)];
        let (_, f) = eval(&obs);
        assert_eq!(
            worst(&f, FindingKind::DnskeyNotSignedByDsKey),
            Some(Severity::Critical)
        );
        assert_eq!(
            f.iter()
                .filter(|x| x.kind == FindingKind::DnskeyNotSignedByDsKey)
                .count(),
            1,
            "only the offending server"
        );
    }

    #[test]
    fn servers_that_disagree_on_keys_serials_or_signing_are_reported() {
        // Different DNSKEY sets.
        let (mut obs, ..) = healthy();
        obs.servers[1].dnskeys.push(key(256, 200));
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::DnskeyDisagreement),
            Some(Severity::Error)
        );
        // One signs, one does not.
        let (mut obs, ..) = healthy();
        obs.servers[1].dnskeys.clear();
        obs.servers[1].dnskey_rrsigs.clear();
        obs.servers[1].soa_rrsigs.clear();
        assert!(worst(&eval(&obs).1, FindingKind::DnskeyDisagreement).is_some());
        // Different SOA serials.
        let (mut obs, ..) = healthy();
        obs.servers[1].soa = Some(SoaObs { serial: 41, ..SOA });
        let (health, f) = eval(&obs);
        let d = f
            .iter()
            .find(|x| x.kind == FindingKind::ServerDisagreement)
            .unwrap();
        assert_eq!(d.severity, Severity::Warning);
        assert!(d.detail.contains("42") && d.detail.contains("41"));
        assert_eq!(health.soa_serial, None, "no agreed serial to report");
    }

    // ── NS / SOA ──

    #[test]
    fn nameserver_faults_are_each_found() {
        let (mut obs, ..) = healthy();
        obs.servers[0].state = ServerState::Unreachable;
        obs.servers[0].dnskeys.clear();
        obs.servers[0].dnskey_rrsigs.clear();
        obs.servers[0].soa_rrsigs.clear();
        obs.servers[0].soa = None;
        obs.servers[0].ns_set.clear();
        let (health, f) = eval(&obs);
        assert_eq!(
            worst(&f, FindingKind::ServerUnreachable),
            Some(Severity::Error)
        );
        assert_eq!((health.servers_total, health.servers_answering), (2, 1));

        let (mut obs, ..) = healthy();
        obs.servers[1].state = ServerState::Lame("rcode 5 aa=false".into());
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::LameDelegation),
            Some(Severity::Error)
        );
        obs.servers[1].state = ServerState::Unresolvable;
        obs.servers[1].addr = None;
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsUnresolvable),
            Some(Severity::Error)
        );

        let (mut obs, ..) = healthy();
        obs.ns_names = Some(BTreeSet::new());
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsMissing),
            Some(Severity::Critical)
        );
        obs.ns_names = Some(["ns1.example.net".to_string()].into());
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsTooFew),
            Some(Severity::Warning)
        );
        obs.ns_names = None;
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsLookupFailed),
            Some(Severity::Warning)
        );

        // All in one /24 (and one /48 for IPv6), but two different hosts.
        let (mut obs, ..) = healthy();
        obs.servers[1].addr = Some("192.0.2.77:53".parse().unwrap());
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsSameNetwork),
            Some(Severity::Warning)
        );
        obs.servers[0].addr = Some("[2001:db8:1::1]:53".parse().unwrap());
        obs.servers[1].addr = Some("[2001:db8:1:ffff::2]:53".parse().unwrap());
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::NsSameNetwork),
            Some(Severity::Warning)
        );
        obs.servers[1].addr = Some("[2001:db8:2::2]:53".parse().unwrap());
        assert!(worst(&eval(&obs).1, FindingKind::NsSameNetwork).is_none());

        // A server's own NS set differs from the resolvers' view (parent/child drift).
        let (mut obs, ..) = healthy();
        obs.servers[0].ns_set =
            ["ns1.example.net".to_string(), "ns9.example.net".to_string()].into();
        let f = eval(&obs).1;
        assert_eq!(
            worst(&f, FindingKind::NsSetMismatch),
            Some(Severity::Warning)
        );
    }

    #[test]
    fn soa_problems_are_found() {
        let (mut obs, ..) = healthy();
        obs.servers[0].soa = None;
        assert_eq!(
            worst(&eval(&obs).1, FindingKind::SoaMissing),
            Some(Severity::Error)
        );
        for (soa, expect) in [
            (
                SoaObs {
                    expire: 3600,
                    ..SOA
                },
                "expire is shorter than refresh + retry",
            ),
            (
                SoaObs {
                    expire: 5 * 86_400,
                    ..SOA
                },
                "under a week",
            ),
            (
                SoaObs { retry: 9000, ..SOA },
                "retry is longer than refresh",
            ),
            (
                SoaObs {
                    minimum: 3 * 86_400,
                    ..SOA
                },
                "negative-cache TTL",
            ),
        ] {
            let (mut obs, ..) = healthy();
            for s in &mut obs.servers {
                s.soa = Some(soa);
            }
            let f = eval(&obs).1;
            let t = f
                .iter()
                .find(|x| x.kind == FindingKind::SoaTimers)
                .unwrap_or_else(|| panic!("{soa:?}: {f:?}"));
            assert!(t.detail.contains(expect), "{}", t.detail);
        }
        // u32::MAX timers must not overflow the arithmetic.
        let (mut obs, ..) = healthy();
        for s in &mut obs.servers {
            s.soa = Some(SoaObs {
                serial: 1,
                refresh: u32::MAX,
                retry: u32::MAX,
                expire: u32::MAX,
                minimum: u32::MAX,
            });
        }
        let _ = eval(&obs);
    }

    // ── CAA ──

    fn rec(tag: &str, value: &str) -> CaaRecord {
        CaaRecord {
            flags: 0,
            tag: tag.into(),
            value: value.as_bytes().to_vec(),
        }
    }

    fn caa_obs(name: &str, found_at: Option<&str>, records: Vec<CaaRecord>) -> CaaObservation {
        CaaObservation {
            name: name.into(),
            lookup_failed: false,
            found_at: found_at.map(str::to_string),
            records,
        }
    }

    const ACCT: &str = "https://acme-v02.api.letsencrypt.org/acme/acct/42";

    fn policy() -> CaaPolicy {
        CaaPolicy {
            allowed_issuers: vec!["letsencrypt.org".into()],
            account_uri: Some(ACCT.into()),
            validation_methods: vec!["dns-01".into()],
            customer_method: Some("http-01".into()),
            issuers: Vec::new(),
        }
    }

    fn own(name: &str, wildcard: bool) -> CaaTarget {
        CaaTarget {
            name: name.into(),
            wildcard,
            scope: CaaScope::Own,
        }
    }

    fn customer(name: &str) -> CaaTarget {
        CaaTarget {
            name: name.into(),
            wildcard: false,
            scope: CaaScope::Customer,
        }
    }

    fn good_value() -> String {
        format!("letsencrypt.org; accounturi={ACCT}; validationmethods=dns-01")
    }

    #[test]
    fn caa_values_parse_per_rfc_8659() {
        let p = parse_caa_issue(
            b"  LetsEncrypt.org ; accounturi=https://x/acct/1 ;validationmethods=dns-01,http-01;;",
        )
        .unwrap();
        assert_eq!(p.issuer, "letsencrypt.org");
        assert_eq!(p.param("accounturi"), Some("https://x/acct/1"));
        assert_eq!(p.param("VALIDATIONMETHODS"), Some("dns-01,http-01"));
        assert_eq!(
            parse_caa_issue(b";").unwrap().issuer,
            "",
            "';' alone forbids issuance"
        );
        assert_eq!(parse_caa_issue(b"").unwrap().issuer, "");
        for bad in [
            &b"two words"[..],
            &b"ca.example; novalue"[..],
            &[0xff, 0xfe][..],
        ] {
            assert!(parse_caa_issue(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_correctly_pinned_policy_for_our_own_name_is_clean() {
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &good_value()),
                rec("iodef", "mailto:ops@example.test"),
            ],
        );
        assert_eq!(
            evaluate_caa(&o, &own("tascloud.app", true), &policy()),
            vec![]
        );
        // Found at an ancestor: the climb result is what counts.
        let o = caa_obs(
            "a.b.tascloud.app",
            Some("tascloud.app"),
            vec![rec("issue", &good_value())],
        );
        assert!(evaluate_caa(&o, &own("a.b.tascloud.app", false), &policy()).is_empty());
    }

    #[test]
    fn caa_faults_on_our_own_names_are_found() {
        let target = own("tascloud.app", false);
        let one = |v: &str| {
            evaluate_caa(
                &caa_obs("tascloud.app", Some("tascloud.app"), vec![rec("issue", v)]),
                &target,
                &policy(),
            )
        };

        // No CAA at all.
        let f = evaluate_caa(&caa_obs("tascloud.app", None, vec![]), &target, &policy());
        assert_eq!(
            (kinds(&f), f[0].severity),
            (vec![FindingKind::CaaAbsent], Severity::Warning)
        );

        // A CA not in the allow-list.
        let f = evaluate_caa(
            &caa_obs(
                "tascloud.app",
                Some("tascloud.app"),
                vec![rec("issue", &good_value()), rec("issue", "digicert.com")],
            ),
            &target,
            &policy(),
        );
        assert_eq!(kinds(&f), vec![FindingKind::CaaUnknownCa]);
        assert!(f[0].detail.contains("digicert.com"));

        // Missing accounturi / validationmethods.
        let f = one("letsencrypt.org");
        assert_eq!(
            worst(&f, FindingKind::CaaMissingAccountUri),
            Some(Severity::Error)
        );
        assert_eq!(
            worst(&f, FindingKind::CaaMissingValidationMethods),
            Some(Severity::Warning)
        );
        let f = one(&format!("letsencrypt.org; accounturi={ACCT}"));
        assert_eq!(kinds(&f), vec![FindingKind::CaaMissingValidationMethods]);

        // Somebody else's account.
        let f = one("letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/666; validationmethods=dns-01");
        // Someone else's account is a foreign binding AND means we cannot issue.
        assert_eq!(
            worst(&f, FindingKind::CaaForeignAccount),
            Some(Severity::Critical)
        );
        assert_eq!(
            worst(&f, FindingKind::CaaBlocksIssuance),
            Some(Severity::Critical)
        );
        assert_eq!(f.len(), 2, "{f:?}");

        // Extra methods beyond dns-01.
        let f = one(&format!(
            "letsencrypt.org; accounturi={ACCT}; validationmethods=dns-01,http-01"
        ));
        assert_eq!(kinds(&f), vec![FindingKind::CaaValidationMethodsMismatch]);
        assert!(f[0].detail.contains("http-01"));
    }

    #[test]
    fn a_permissive_extra_issue_entry_voids_the_account_binding() {
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![rec("issue", &good_value()), rec("issue", "letsencrypt.org")],
        );
        let f = evaluate_caa(&o, &own("tascloud.app", false), &policy());
        let permissive = f
            .iter()
            .find(|x| x.kind == FindingKind::CaaPermissiveIssuer)
            .expect("flagged");
        assert_eq!(permissive.severity, Severity::Critical);
        assert!(
            !f.iter()
                .any(|x| x.kind == FindingKind::CaaMissingAccountUri),
            "reported once, as the permissive entry: {f:?}"
        );
        // The same extra entry bound to a foreign account is also permissive (either entry suffices).
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &good_value()),
                rec(
                    "issue",
                    "letsencrypt.org; accounturi=https://x/acct/9; validationmethods=dns-01",
                ),
            ],
        );
        assert_eq!(
            worst(
                &evaluate_caa(&o, &own("tascloud.app", false), &policy()),
                FindingKind::CaaPermissiveIssuer
            ),
            Some(Severity::Critical)
        );
        // Without a configured account there is nothing to be permissive about.
        let loose = CaaPolicy {
            account_uri: None,
            validation_methods: vec![],
            ..policy()
        };
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![rec("issue", "letsencrypt.org")],
        );
        assert!(evaluate_caa(&o, &own("tascloud.app", false), &loose).is_empty());
    }

    #[test]
    fn issuewild_governs_wildcards_and_issue_governs_the_rest() {
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &good_value()),
                rec("issuewild", "digicert.com"),
            ],
        );
        // For the wildcard `issuewild` wins: it permits only a CA we do not allow.
        let f = evaluate_caa(&o, &own("tascloud.app", true), &policy());
        assert_eq!(
            worst(&f, FindingKind::CaaBlocksIssuance),
            Some(Severity::Critical)
        );
        assert_eq!(worst(&f, FindingKind::CaaUnknownCa), Some(Severity::Error));
        // For the bare name only `issue` counts.
        assert!(evaluate_caa(&o, &own("tascloud.app", false), &policy()).is_empty());
        // A wildcard with no issuewild falls back to issue.
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![rec("issue", &good_value())],
        );
        assert!(evaluate_caa(&o, &own("tascloud.app", true), &policy()).is_empty());
    }

    #[test]
    fn a_policy_that_forbids_us_is_critical_for_our_names_and_a_warning_for_customers() {
        for (value, why) in [
            (";", "forbids all"),
            ("digicert.com", "does not list"),
            (
                "letsencrypt.org; accounturi=https://other/acct/1",
                "another account",
            ),
        ] {
            let o = caa_obs(
                "x.example.org",
                Some("example.org"),
                vec![rec("issue", value)],
            );
            let c = evaluate_caa(&o, &customer("x.example.org"), &policy());
            assert_eq!(
                (kinds(&c), c[0].severity),
                (vec![FindingKind::CaaBlocksIssuance], Severity::Warning),
                "{value}"
            );
            assert!(c[0].detail.contains(why), "{}", c[0].detail);
            let ours = evaluate_caa(&o, &own("x.example.org", false), &policy());
            assert_eq!(
                worst(&ours, FindingKind::CaaBlocksIssuance),
                Some(Severity::Critical),
                "{value}"
            );
        }
        // A customer who pins validationmethods without http-01 blocks our HTTP-01 issuance.
        let o = caa_obs(
            "x.example.org",
            Some("example.org"),
            vec![rec("issue", "letsencrypt.org; validationmethods=dns-01")],
        );
        assert_eq!(
            kinds(&evaluate_caa(&o, &customer("x.example.org"), &policy())),
            vec![FindingKind::CaaBlocksIssuance]
        );
        // ...while one that allows our CA, or has no CAA at all, is fine and unremarkable.
        for records in [
            vec![rec("issue", "letsencrypt.org")],
            vec![
                rec("issue", "letsencrypt.org; validationmethods=http-01,dns-01"),
                rec("issue", "sectigo.com"),
            ],
            vec![],
        ] {
            let o = caa_obs(
                "x.example.org",
                records.first().map(|_| "example.org"),
                records,
            );
            assert_eq!(
                evaluate_caa(&o, &customer("x.example.org"), &policy()),
                vec![],
                "customer CAs other than ours are the customer's business"
            );
        }
    }

    #[test]
    fn caa_lookup_failure_unknown_critical_and_malformed_values_are_findings() {
        let mut o = caa_obs("tascloud.app", None, vec![]);
        o.lookup_failed = true;
        assert_eq!(
            worst(
                &evaluate_caa(&o, &own("tascloud.app", false), &policy()),
                FindingKind::CaaLookupFailed
            ),
            Some(Severity::Error)
        );
        assert_eq!(
            worst(
                &evaluate_caa(&o, &customer("tascloud.app"), &policy()),
                FindingKind::CaaLookupFailed
            ),
            Some(Severity::Warning)
        );

        let mut records = vec![rec("issue", &good_value())];
        records.push(CaaRecord {
            flags: 0x80,
            tag: "futuretag".into(),
            value: b"x".to_vec(),
        });
        let f = evaluate_caa(
            &caa_obs("tascloud.app", Some("tascloud.app"), records),
            &own("tascloud.app", false),
            &policy(),
        );
        assert_eq!(kinds(&f), vec![FindingKind::CaaUnknownCritical]);
        // A critical flag on a tag we know is fine.
        let ok = vec![CaaRecord {
            flags: 0x80,
            ..rec("issue", &good_value())
        }];
        assert!(evaluate_caa(
            &caa_obs("tascloud.app", Some("tascloud.app"), ok),
            &own("tascloud.app", false),
            &policy()
        )
        .is_empty());

        let bad = vec![
            rec("issue", &good_value()),
            CaaRecord {
                value: vec![0xff, 0xfe],
                ..rec("issue", "")
            },
        ];
        assert_eq!(
            worst(
                &evaluate_caa(
                    &caa_obs("tascloud.app", Some("tascloud.app"), bad),
                    &own("tascloud.app", false),
                    &policy()
                ),
                FindingKind::CaaMalformed
            ),
            Some(Severity::Error)
        );
        // CAA with only iodef says nothing about issuance.
        let only_iodef = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![rec("iodef", "mailto:a@b.c")],
        );
        assert_eq!(
            kinds(&evaluate_caa(
                &only_iodef,
                &own("tascloud.app", false),
                &policy()
            )),
            vec![FindingKind::CaaAbsent]
        );
    }

    // ── collectors, against a scripted lookup ──

    type Query = (String, u16, Option<SocketAddr>);

    #[derive(Default)]
    struct FakeLookup {
        /// `(name, qtype code, server)` -> reply; missing = no answer (timeout).
        replies: Mutex<HashMap<Query, Message>>,
        addrs: Mutex<HashMap<String, Vec<SocketAddr>>>,
        asked: Mutex<Vec<Query>>,
    }

    impl FakeLookup {
        fn put(
            &self,
            name: &str,
            qtype: RecordType,
            server: Option<SocketAddr>,
            answers: Vec<Record>,
            aa: bool,
            rcode: ResponseCode,
        ) {
            let mut m = Message::response(1);
            m.flags = Flags {
                response: true,
                authoritative: aa,
                response_code: rcode,
                ..Flags::default()
            };
            m.answers = answers;
            self.replies
                .lock()
                .unwrap()
                .insert((norm_str(name), qtype.code(), server), m);
        }
    }

    impl DnsLookup for FakeLookup {
        fn recursive<'a>(
            &'a self,
            name: &'a Name,
            qtype: RecordType,
        ) -> BoxFuture<'a, Option<Message>> {
            Box::pin(async move {
                let k = (norm(name), qtype.code(), None);
                self.asked.lock().unwrap().push(k.clone());
                self.replies.lock().unwrap().get(&k).cloned()
            })
        }
        fn direct<'a>(
            &'a self,
            server: SocketAddr,
            name: &'a Name,
            qtype: RecordType,
        ) -> BoxFuture<'a, Option<Message>> {
            Box::pin(async move {
                let k = (norm(name), qtype.code(), Some(server));
                self.asked.lock().unwrap().push(k.clone());
                self.replies.lock().unwrap().get(&k).cloned()
            })
        }
        fn nameserver_addrs<'a>(&'a self, ns: &'a Name) -> BoxFuture<'a, Vec<SocketAddr>> {
            Box::pin(async move {
                self.addrs
                    .lock()
                    .unwrap()
                    .get(&norm(ns))
                    .cloned()
                    .unwrap_or_default()
            })
        }
    }

    fn caa_rr(name: &str, tag: &str, value: &str) -> Record {
        Record::new(
            n(name),
            60,
            RData::Caa {
                flags: 0,
                tag: tag.into(),
                value: value.as_bytes().to_vec(),
            },
        )
    }

    #[tokio::test]
    async fn the_caa_climb_stops_at_the_first_name_with_records_and_fails_closed_on_a_lookup_error()
    {
        let l = FakeLookup::default();
        l.put(
            "a.b.example.com",
            RecordType::Caa,
            None,
            vec![],
            false,
            ResponseCode::NoError,
        );
        l.put(
            "b.example.com",
            RecordType::Caa,
            None,
            vec![],
            false,
            ResponseCode::NxDomain,
        );
        l.put(
            "example.com",
            RecordType::Caa,
            None,
            vec![caa_rr("example.com", "ISSUE", "letsencrypt.org")],
            false,
            ResponseCode::NoError,
        );
        l.put(
            "com",
            RecordType::Caa,
            None,
            vec![caa_rr("com", "issue", "evil.example")],
            false,
            ResponseCode::NoError,
        );
        let o = collect_caa(&l, "A.B.Example.COM.").await;
        assert_eq!(
            (o.lookup_failed, o.found_at.as_deref()),
            (false, Some("example.com"))
        );
        assert_eq!(
            o.records,
            vec![rec("issue", "letsencrypt.org")],
            "tags are lower-cased"
        );
        let asked: Vec<String> = l
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|k| k.0.clone())
            .collect();
        assert_eq!(
            asked,
            ["a.b.example.com", "b.example.com", "example.com"],
            "climbs one label at a time and stops at the first RRset"
        );

        // No CAA anywhere: climbs to the TLD and reports none.
        let l = FakeLookup::default();
        for name in ["x.example.org", "example.org", "org"] {
            l.put(
                name,
                RecordType::Caa,
                None,
                vec![],
                false,
                ResponseCode::NoError,
            );
        }
        let o = collect_caa(&l, "x.example.org").await;
        assert!(!o.lookup_failed && o.found_at.is_none() && o.records.is_empty());

        // A SERVFAIL/timeout half way up: the policy is unknown, and the climb does not continue
        // past it to a parent whose answer would be wrong to apply.
        let l = FakeLookup::default();
        l.put(
            "x.example.net",
            RecordType::Caa,
            None,
            vec![],
            false,
            ResponseCode::NoError,
        );
        l.put(
            "net",
            RecordType::Caa,
            None,
            vec![caa_rr("net", "issue", "letsencrypt.org")],
            false,
            ResponseCode::NoError,
        );
        let o = collect_caa(&l, "x.example.net").await;
        assert!(
            o.lookup_failed && o.records.is_empty(),
            "example.net was never answered"
        );
        assert!(collect_caa(&l, "bad name!.example").await.lookup_failed);
    }

    #[tokio::test]
    async fn collect_zone_reads_every_server_and_classifies_the_ones_that_misbehave() {
        let l = FakeLookup::default();
        let z = "example.com";
        let (ksk, zsk) = (key(257, 1), key(256, 100));
        let ok: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let lame: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let dead: SocketAddr = "192.0.2.3:53".parse().unwrap();
        let ds = ds_of(z, &ksk, 2);
        l.put(
            z,
            RecordType::DS,
            None,
            vec![Record::new(
                n(z),
                60,
                RData::Ds {
                    key_tag: ds.key_tag,
                    algorithm: ds.algorithm,
                    digest_type: 2,
                    digest: ds.digest.clone(),
                },
            )],
            false,
            ResponseCode::NoError,
        );
        let ns = |name: &str| Record::new(n(z), 60, RData::Ns(n(name)));
        l.put(
            z,
            RecordType::Ns,
            None,
            vec![
                ns("ns1.example.net"),
                ns("ns2.example.net"),
                ns("ns3.example.net"),
                ns("ns4.example.net"),
            ],
            false,
            ResponseCode::NoError,
        );
        for (name, addr) in [
            ("ns1.example.net", ok),
            ("ns2.example.net", lame),
            ("ns3.example.net", dead),
        ] {
            l.addrs.lock().unwrap().insert(name.into(), vec![addr]);
        }
        // ns4 has no address at all.
        let soa = Record::new(
            n(z),
            60,
            RData::Soa {
                mname: n("ns1.example.net"),
                rname: n("h.example.com"),
                serial: 7,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 300,
            },
        );
        let rrsig = |covered: RecordType, tag: u16, exp: u32| {
            Record::new(
                n(z),
                60,
                RData::Rrsig {
                    type_covered: covered,
                    algorithm: 13,
                    labels: 2,
                    original_ttl: 60,
                    expiration: exp,
                    inception: 1,
                    key_tag: tag,
                    signer: n(z),
                    signature: vec![1; 64],
                },
            )
        };
        let exp = u32::try_from(NOW + 5 * DAY).unwrap();
        let dnskey = |k: &DnskeyObs| {
            Record::new(
                n(z),
                60,
                RData::Dnskey {
                    flags: k.flags,
                    protocol: 3,
                    algorithm: 13,
                    public_key: k.public_key.clone(),
                },
            )
        };
        l.put(
            z,
            RecordType::Soa,
            Some(ok),
            vec![
                soa.clone(),
                rrsig(RecordType::Soa, zsk.key_tag(), exp),
                rrsig(RecordType::DNSKEY, 1, 1),
            ],
            true,
            ResponseCode::NoError,
        );
        l.put(
            z,
            RecordType::Ns,
            Some(ok),
            vec![ns("ns2.example.net"), ns("ns1.example.net")],
            true,
            ResponseCode::NoError,
        );
        l.put(
            z,
            RecordType::DNSKEY,
            Some(ok),
            vec![
                dnskey(&ksk),
                dnskey(&zsk),
                rrsig(RecordType::DNSKEY, ksk.key_tag(), exp),
            ],
            true,
            ResponseCode::NoError,
        );
        l.put(
            z,
            RecordType::Soa,
            Some(lame),
            vec![soa],
            false,
            ResponseCode::Refused,
        ); // REFUSED, and not AA
        let obs = collect_zone(&l, z, &HealthConfig::default()).await;

        assert_eq!(obs.ds, Some(vec![ds]));
        assert_eq!(obs.ns_names.as_ref().map(BTreeSet::len), Some(4));
        let by = |name: &str| obs.servers.iter().find(|s| s.ns_name == name).unwrap();
        assert_eq!(by("ns1.example.net").state, ServerState::Answering);
        assert_eq!(by("ns1.example.net").soa.map(|s| s.serial), Some(7));
        assert_eq!(by("ns1.example.net").dnskeys.len(), 2);
        assert_eq!(
            by("ns1.example.net").dnskey_rrsigs.len(),
            1,
            "only the RRSIG covering DNSKEY is attributed to it"
        );
        assert_eq!(by("ns1.example.net").soa_rrsigs.len(), 1);
        assert_eq!(by("ns1.example.net").ns_set.len(), 2);
        assert!(matches!(by("ns2.example.net").state, ServerState::Lame(_)));
        assert_eq!(by("ns3.example.net").state, ServerState::Unreachable);
        assert_eq!(by("ns4.example.net").state, ServerState::Unresolvable);

        // And the verdict on that picture.
        let (health, f) = evaluate_zone(&obs, &HealthConfig::default(), NOW);
        assert!(!health.ds_mismatch);
        assert_eq!(health.servers_answering, 1);
        for kind in [
            FindingKind::LameDelegation,
            FindingKind::ServerUnreachable,
            FindingKind::NsUnresolvable,
            FindingKind::RrsigExpiring,
        ] {
            assert!(
                f.iter().any(|x| x.kind == kind),
                "{kind:?} missing from {f:#?}"
            );
        }
    }

    #[tokio::test]
    async fn the_nameserver_fan_out_is_bounded() {
        let l = FakeLookup::default();
        let names: Vec<Record> = (0..40)
            .map(|i| {
                Record::new(
                    n("example.com"),
                    60,
                    RData::Ns(n(&format!("ns{i}.example.net"))),
                )
            })
            .collect();
        l.put(
            "example.com",
            RecordType::Ns,
            None,
            names,
            false,
            ResponseCode::NoError,
        );
        l.put(
            "example.com",
            RecordType::DS,
            None,
            vec![],
            false,
            ResponseCode::NoError,
        );
        for i in 0..40 {
            l.addrs.lock().unwrap().insert(
                format!("ns{i}.example.net"),
                (0..10)
                    .map(|j| format!("192.0.2.{j}:53").parse().unwrap())
                    .collect(),
            );
        }
        let obs = collect_zone(&l, "example.com", &HealthConfig::default()).await;
        assert_eq!(
            obs.servers.len(),
            8 * 2,
            "max_ns_per_zone x max_addrs_per_ns"
        );
        assert!(l.asked.lock().unwrap().len() < 100);
    }

    #[tokio::test]
    async fn run_checks_covers_every_zone_and_target_and_bounds_what_it_is_given() {
        let l = FakeLookup::default();
        let cfg = HealthConfig {
            zones: vec!["example.com".into()],
            caa_targets: vec![own("example.com", true), customer("x.example.org")],
            caa: policy(),
            ..HealthConfig::default()
        };
        l.put(
            "example.com",
            RecordType::DS,
            None,
            vec![],
            false,
            ResponseCode::NoError,
        );
        l.put(
            "example.com",
            RecordType::Ns,
            None,
            vec![],
            false,
            ResponseCode::NoError,
        );
        l.put(
            "example.com",
            RecordType::Caa,
            None,
            vec![caa_rr("example.com", "issue", "letsencrypt.org")],
            false,
            ResponseCode::NoError,
        );
        let r = run_checks(&l, &cfg, NOW).await;
        assert_eq!(r.checked_at, NOW);
        assert_eq!(r.zones.len(), 1);
        assert_eq!(r.max_severity(), Some(Severity::Critical), "NsMissing");
        assert!(r.of_kind(FindingKind::NsMissing).count() == 1);
        // our wildcard: unpinned entry (Error) + missing validationmethods (Warning); the customer
        // target's lookup got no answer (Warning).
        assert!(r.of_kind(FindingKind::CaaMissingAccountUri).count() == 1);
        assert!(r.of_kind(FindingKind::CaaLookupFailed).count() == 1);
        assert_eq!(r.caa_findings(), 3);

        let many = HealthConfig {
            zones: (0..100).map(|i| format!("z{i}.example")).collect(),
            max_zones: 3,
            ..HealthConfig::default()
        };
        let r = run_checks(&FakeLookup::default(), &many, NOW).await;
        assert_eq!(r.zones.len(), 3);
        assert!(r
            .findings
            .iter()
            .any(|f| f.subject == "config" && f.detail.contains("100 zones")));
    }

    // ── live: real sockets on loopback ──

    use crate::edge::EdgeRegistry;
    use crate::edge_dns::{
        serve_udp_with, AuthorityHandler, DnsHandler, ZoneAuthority, ZoneConfig,
    };

    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Serve `zone` from a real `ZoneAuthority` on a loopback UDP socket.
    async fn serve_authority(
        serial: u32,
        account_uri: Option<&str>,
        issuers: &[&str],
    ) -> SocketAddr {
        let mut zone = ZoneConfig::new(
            "tascloud.app",
            vec!["ns1.tascloud.app".into(), "ns2.tascloud.app".into()],
        )
        .with_caa_issuers(issuers.iter().map(|s| (*s).to_string()).collect());
        if let Some(uri) = account_uri {
            zone = zone.with_caa_account_uri(uri);
        }
        zone.serial = serial;
        let authority = Arc::new(tokio::sync::Mutex::new(ZoneAuthority::new(
            vec![zone],
            vec!["127.0.0.1".parse().unwrap()],
            vec![],
        )));
        let registry = Arc::new(tokio::sync::Mutex::new(EdgeRegistry::new(b"s".to_vec())));
        let handler: Arc<dyn DnsHandler> = Arc::new(AuthorityHandler {
            authority,
            registry,
        });
        let addr: SocketAddr = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
        let bind: &'static str = Box::leak(addr.to_string().into_boxed_str());
        tokio::spawn(serve_udp_with(bind, handler));
        tokio::time::sleep(Duration::from_millis(150)).await;
        addr
    }

    fn live_cfg() -> HealthConfig {
        HealthConfig {
            zones: vec!["tascloud.app".into()],
            caa_targets: vec![
                own("tascloud.app", true),
                own("anything.tascloud.app", false),
            ],
            caa: policy(),
            ..HealthConfig::default()
        }
    }

    fn live_lookup(a: SocketAddr, b: SocketAddr) -> NetLookup {
        NetLookup::new(vec![a])
            .with_timeout(Duration::from_secs(2))
            .with_ns_addrs("ns1.tascloud.app", vec![a])
            .with_ns_addrs("ns2.tascloud.app", vec![b])
    }

    /// The edge's own authority, asked over UDP exactly as an operator's monitor would: NS and SOA
    /// sanity from each server, CAA by climbing from a hostname that has none of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_health_check_against_transports_own_zone_authority() {
        let a = serve_authority(7, Some(ACCT), &["letsencrypt.org"]).await;
        let b = serve_authority(7, Some(ACCT), &["letsencrypt.org"]).await;
        let report = run_checks(&live_lookup(a, b), &live_cfg(), NOW).await;
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        let z = &report.zones[0];
        assert_eq!(
            (z.servers_total, z.servers_answering, z.soa_serial, z.signed),
            (2, 2, Some(7), false)
        );

        // One server behind on the zone serial.
        let behind = serve_authority(6, Some(ACCT), &["letsencrypt.org"]).await;
        let report = run_checks(&live_lookup(a, behind), &live_cfg(), NOW).await;
        assert_eq!(
            kinds(&report.findings),
            vec![FindingKind::ServerDisagreement],
            "{:#?}",
            report.findings
        );

        // A CAA that is not bound to our account, with an extra CA.
        let loose_a = serve_authority(7, None, &["letsencrypt.org", "digicert.com"]).await;
        let report = run_checks(&live_lookup(loose_a, loose_a), &live_cfg(), NOW).await;
        let ks: BTreeSet<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(
            ks.contains("caa_unknown_ca")
                && ks.contains("caa_missing_accounturi")
                && ks.contains("caa_missing_validationmethods"),
            "{ks:?}"
        );
        assert_eq!(
            report.caa_findings(),
            report.findings.iter().filter(|f| f.kind.is_caa()).count()
        );

        // A nameserver that is down is an unreachable server, not a hang.
        let dead: SocketAddr = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
        let cfg = HealthConfig {
            caa_targets: vec![],
            ..live_cfg()
        };
        let lookup = NetLookup::new(vec![a])
            .with_timeout(Duration::from_millis(400))
            .with_ns_addrs("ns1.tascloud.app", vec![a])
            .with_ns_addrs("ns2.tascloud.app", vec![dead]);
        let started = std::time::Instant::now();
        let report = run_checks(&lookup, &cfg, NOW).await;
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            worst(&report.findings, FindingKind::ServerUnreachable),
            Some(Severity::Error),
            "{:#?}",
            report.findings
        );
    }

    /// A signed zone on real sockets: a small authoritative server answering with DNSKEY and RRSIG
    /// records (and DS from the "parent" the recursive resolver stands for), asked with DO set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_dnssec_check_reads_ds_dnskey_and_rrsig_over_the_wire_and_catches_a_stale_ds() {
        let (ksk, zsk) = (key(257, 1), key(256, 100));
        let z = "example.com";
        let exp = u32::try_from(NOW + 2 * DAY).unwrap();
        let dnskey = |k: &DnskeyObs| {
            Record::new(
                n(z),
                60,
                RData::Dnskey {
                    flags: k.flags,
                    protocol: 3,
                    algorithm: 13,
                    public_key: k.public_key.clone(),
                },
            )
        };
        let rrsig = move |covered: RecordType, tag: u16| {
            Record::new(
                n(z),
                60,
                RData::Rrsig {
                    type_covered: covered,
                    algorithm: 13,
                    labels: 2,
                    original_ttl: 60,
                    expiration: exp,
                    inception: u32::try_from(NOW - DAY).unwrap(),
                    key_tag: tag,
                    signer: n(z),
                    signature: vec![9; 64],
                },
            )
        };
        let soa = Record::new(
            n(z),
            60,
            RData::Soa {
                mname: n("ns1.example.net"),
                rname: n("h.example.com"),
                serial: 3,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 300,
            },
        );
        let saw_do = Arc::new(Mutex::new(Vec::<bool>::new()));
        let seen = saw_do.clone();
        let (k2, z2) = (ksk.clone(), zsk.clone());
        let auth = serve_fn(move |q: &Message| {
            let wants_dnssec = q
                .additionals
                .iter()
                .any(|r| r.data.record_type() == RecordType::Unknown(41) && r.ttl & 0x8000 != 0);
            seen.lock().unwrap().push(wants_dnssec);
            let mut r = Message::response(q.id);
            r.questions = q.questions.clone();
            r.flags.authoritative = true;
            r.answers = match q.questions[0].qtype {
                RecordType::Soa if wants_dnssec => {
                    vec![soa.clone(), rrsig(RecordType::Soa, z2.key_tag())]
                }
                RecordType::Ns => vec![Record::new(n(z), 60, RData::Ns(n("ns1.example.net")))],
                t if t == RecordType::DNSKEY && wants_dnssec => vec![
                    dnskey(&k2),
                    dnskey(&z2),
                    rrsig(RecordType::DNSKEY, k2.key_tag()),
                ],
                _ => vec![],
            };
            r
        })
        .await;
        let parent_ds = |k: &DnskeyObs| {
            let d = ds_of(z, k, 2);
            Record::new(
                n(z),
                60,
                RData::Ds {
                    key_tag: d.key_tag,
                    algorithm: d.algorithm,
                    digest_type: 2,
                    digest: d.digest,
                },
            )
        };
        let (k3, ns_rec) = (
            ksk.clone(),
            Record::new(n(z), 60, RData::Ns(n("ns1.example.net"))),
        );
        let recursor_for = move |ds_key: DnskeyObs| {
            let ns_rec = ns_rec.clone();
            let ds_rec = parent_ds(&ds_key);
            move |q: &Message| {
                let mut r = Message::response(q.id);
                r.questions = q.questions.clone();
                r.answers = match q.questions[0].qtype {
                    RecordType::DS => vec![ds_rec.clone()],
                    RecordType::Ns => vec![ns_rec.clone()],
                    _ => vec![],
                };
                r
            }
        };
        let cfg = HealthConfig {
            zones: vec![z.into()],
            ..HealthConfig::default()
        };
        let lookup_via = |recursor: SocketAddr| {
            NetLookup::new(vec![recursor])
                .with_timeout(Duration::from_secs(2))
                .with_ns_addrs("ns1.example.net", vec![auth])
        };

        // Parent DS matches the KSK: chain intact; the 2-day signature is reported.
        let good = serve_fn(recursor_for(k3.clone())).await;
        let report = run_checks(&lookup_via(good), &cfg, NOW).await;
        let h = &report.zones[0];
        assert!(h.signed && h.ds_present && !h.ds_mismatch, "{h:?}");
        assert_eq!(h.rrsig_earliest_expiry_secs, Some(2 * DAY));
        // (The fixture has a single nameserver, so NsTooFew is expected and not what is under test.)
        let rest: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.kind != FindingKind::NsTooFew)
            .collect();
        assert_eq!(
            rest.iter().map(|f| f.kind).collect::<Vec<_>>(),
            vec![FindingKind::RrsigExpiring, FindingKind::RrsigExpiring],
            "DNSKEY and SOA signatures, 2 days left: {rest:#?}"
        );
        assert!(rest.iter().all(|f| f.severity == Severity::Error));
        assert!(
            saw_do.lock().unwrap().iter().any(|d| *d),
            "the authoritative server was asked with DO set"
        );

        // The parent still holds the DS of a key that was rolled away.
        let stale = serve_fn(recursor_for(key(257, 55))).await;
        let report = run_checks(&lookup_via(stale), &cfg, NOW).await;
        assert!(report.zones[0].ds_mismatch);
        assert_eq!(
            worst(&report.findings, FindingKind::DsDnskeyMismatch),
            Some(Severity::Critical)
        );
    }

    /// A UDP DNS server answering with `answer`.
    async fn serve_fn(answer: impl Fn(&Message) -> Message + Send + Sync + 'static) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(q) = Message::from_bytes(&buf[..len]) else {
                    continue;
                };
                let _ = sock.send_to(&answer(&q).to_bytes(), peer).await;
            }
        });
        addr
    }

    // ── more than one CA ──

    const GTS_ACCT: &str = "https://dv.acme-v02.api.pki.goog/acme/acct/ZZ";

    /// Two CAs, each with its own account: Let's Encrypt (active) and a standby.
    fn multi_policy() -> CaaPolicy {
        CaaPolicy {
            allowed_issuers: Vec::new(),
            account_uri: None,
            validation_methods: Vec::new(),
            customer_method: Some("http-01".into()),
            issuers: vec![
                IssuerExpectation {
                    domain: "letsencrypt.org".into(),
                    account_uri: Some(ACCT.into()),
                    validation_methods: vec!["dns-01".into()],
                },
                IssuerExpectation {
                    domain: "pki.goog".into(),
                    account_uri: Some(GTS_ACCT.into()),
                    validation_methods: vec!["dns-01".into()],
                },
            ],
        }
    }

    fn entry_for(domain: &str, acct: &str) -> String {
        format!("{domain}; accounturi={acct}; validationmethods=dns-01")
    }

    #[test]
    fn a_union_of_two_cas_each_bound_to_its_own_account_is_clean() {
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issue", &entry_for("pki.goog", GTS_ACCT)),
                rec("issuewild", &entry_for("letsencrypt.org", ACCT)),
                rec("issuewild", &entry_for("pki.goog", GTS_ACCT)),
            ],
        );
        assert_eq!(
            evaluate_caa(&o, &own("tascloud.app", true), &multi_policy()),
            vec![]
        );
        assert_eq!(
            evaluate_caa(&o, &own("tascloud.app", false), &multi_policy()),
            vec![]
        );
    }

    #[test]
    fn a_ca_bound_to_the_wrong_account_or_unbound_is_flagged_per_issuer() {
        // The standby's entry carries the *other* CA's account: foreign for pki.goog.
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issue", &entry_for("pki.goog", ACCT)),
            ],
        );
        let f = evaluate_caa(&o, &own("tascloud.app", false), &multi_policy());
        assert!(
            f.iter()
                .any(|x| x.kind == FindingKind::CaaForeignAccount && x.detail.contains("pki.goog")),
            "{f:?}"
        );
        // An unbound extra entry for an issuer that also has a bound one makes the binding pointless.
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issue", "letsencrypt.org"),
                rec("issue", &entry_for("pki.goog", GTS_ACCT)),
            ],
        );
        let f = evaluate_caa(&o, &own("tascloud.app", false), &multi_policy());
        assert!(
            f.iter()
                .any(|x| x.kind == FindingKind::CaaPermissiveIssuer
                    && x.severity == Severity::Critical),
            "{f:?}"
        );
        // A CA that is no longer ours (a distrusted one still in DNS) is unknown.
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issue", "oldca.example"),
            ],
        );
        let f = evaluate_caa(&o, &own("tascloud.app", false), &multi_policy());
        assert!(
            f.iter()
                .any(|x| x.kind == FindingKind::CaaUnknownCa && x.detail.contains("oldca.example")),
            "{f:?}"
        );
    }

    #[test]
    fn issuewild_governs_wildcards_independently_of_issue() {
        // issue lists both CAs, issuewild only the standby (which is the only wildcard-capable one).
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issue", &entry_for("pki.goog", GTS_ACCT)),
                rec("issuewild", &entry_for("pki.goog", GTS_ACCT)),
            ],
        );
        assert_eq!(
            evaluate_caa(&o, &own("tascloud.app", true), &multi_policy()),
            vec![],
            "a wildcard may still be issued by the standby"
        );
        // A wildcard-forbidding issuewild blocks the wildcard but not the bare name.
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec("issuewild", ";"),
            ],
        );
        let f = evaluate_caa(&o, &own("tascloud.app", true), &multi_policy());
        assert!(
            f.iter().any(|x| x.kind == FindingKind::CaaBlocksIssuance),
            "{f:?}"
        );
        assert!(
            !evaluate_caa(&o, &own("tascloud.app", false), &multi_policy())
                .iter()
                .any(|x| x.kind == FindingKind::CaaBlocksIssuance)
        );
    }

    #[test]
    fn two_accounts_at_one_ca_are_both_expected() {
        let mut p = multi_policy();
        p.issuers.push(IssuerExpectation {
            domain: "letsencrypt.org".into(),
            account_uri: Some("https://acme-v02.api.letsencrypt.org/acme/acct/99".into()),
            validation_methods: vec!["dns-01".into()],
        });
        let o = caa_obs(
            "tascloud.app",
            Some("tascloud.app"),
            vec![
                rec("issue", &entry_for("letsencrypt.org", ACCT)),
                rec(
                    "issue",
                    &entry_for(
                        "letsencrypt.org",
                        "https://acme-v02.api.letsencrypt.org/acme/acct/99",
                    ),
                ),
            ],
        );
        assert_eq!(evaluate_caa(&o, &own("tascloud.app", false), &p), vec![]);
    }
}
