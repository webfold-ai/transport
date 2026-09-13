//! Authoritative DNS for the edge's apex zones — the naming half of `transport::edge`.
//!
//! We are the authority for [`super::edge::APEXES`], so the zone is not a file: it is the
//! [`EdgeRegistry`] itself. A managed hostname resolves the moment it is claimed, and stops
//! resolving the moment it is released, with no zone reload in between. That is the whole
//! reason to run our own authority rather than script an external DNS provider's API.
//!
//! It also makes ACME **DNS-01** trivial for the apex wildcards (`*.twnstack.app` cannot be
//! validated any other way — there is no HTTP request you can make to a wildcard): the
//! issuance worker calls [`ZoneAuthority::set_acme_token`] and the challenge is live on the
//! next query.
//!
//! ## Dependency stance
//!
//! `hickory-proto` — the wire format — is a real dependency: DNS message parsing is
//! attacker-facing byte handling where an audited implementation beats a hand-rolled one,
//! exactly the line `bindings::overlay` draws for iroh's QUIC and `bindings::wireguard` for
//! boringtun's crypto. `hickory-server` is NOT a dependency: `Catalog`/`Authority`/handler
//! plumbing is scaffolding, and scaffolding is the thing this crate subsumes (the same call
//! `daemon.rs` makes against `daemonize`). [`ZoneAuthority::answer`] is a pure
//! bytes-in/bytes-out function; [`serve_udp`] is a twenty-line socket loop around it.
//!
//! ## Correctness details that are easy to get wrong, and are handled here
//!
//! - **NXDOMAIN carries the SOA.** Without a SOA in the authority section a resolver has no
//!   negative-cache TTL and is free to invent one. [`SOA_MINIMUM_TTL`] is deliberately short
//!   (60s) because the alternative is a customer creating a tunnel, curling it a second
//!   later, and having the NXDOMAIN they earned cached against them for an hour.
//! - **NODATA is not NXDOMAIN.** A name that exists with no record of the asked-for type
//!   answers NOERROR with an empty answer section and the SOA — answering NXDOMAIN there
//!   tells the resolver the *name* is gone, which breaks anything else under it.
//! - **Unregistered names under our apex get NXDOMAIN, not a wildcard answer.** A catch-all
//!   would make every typo resolve to the edge and destroy our own ability to tell "this
//!   hostname exists" from "this hostname does not".
//! - **Queries for zones we do not serve get REFUSED**, never a recursive lookup. An open
//!   resolver is a reflection-attack amplifier.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the zone set (which apexes we answer for at all)
//! - **B/Map** = the ACME token map (challenge name → tokens, last write wins)
//! - **B/U** = the query counter (per-qtype volume — the accumulator)
//! - **self** = the SOA (the zone's statement about itself)

use super::edge::{normalize, EdgeRegistry, HostnameKind, HostnameState};
use hashtrinity::Table;

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CAA, NS, SOA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// TTL for hostname address records. Short: the edge address set is the failover unit.
pub const ADDRESS_TTL: u32 = 60;
/// TTL for the zone's own NS records.
pub const NS_TTL: u32 = 3600;
/// TTL for ACME challenge TXT records — short, they are live for minutes.
pub const ACME_TTL: u32 = 60;
/// SOA `minimum`, which is the **negative** cache TTL (RFC 2308). See the module doc.
pub const SOA_MINIMUM_TTL: u32 = 60;
/// The label ACME challenges live under.
pub const ACME_LABEL: &str = "_acme-challenge";

/// One apex zone's authority parameters.
#[derive(Clone, Debug)]
pub struct ZoneConfig {
    /// The apex, e.g. `"twnstack.app"`.
    pub zone: String,
    /// Primary nameserver name for the SOA `mname`.
    pub primary_ns: String,
    /// Hostmaster address, in DNS form (`hostmaster.twnstack.app`).
    pub hostmaster: String,
    /// Authoritative nameservers to publish as NS records.
    pub nameservers: Vec<String>,
    /// Zone serial. Bumped by the operator on zone-level change; per-hostname changes do not
    /// need it because nothing does a zone transfer from us.
    pub serial: u32,
    /// CA domains permitted to issue for this zone, published as CAA `issue` records. Empty
    /// means no CAA is published — which permits any CA, so it should not stay empty.
    pub caa_issuers: Vec<String>,
}

impl ZoneConfig {
    /// A config for `zone` served by `nameservers`, with sane defaults.
    #[must_use]
    pub fn new(zone: impl Into<String>, nameservers: Vec<String>) -> Self {
        let zone = normalize(&zone.into());
        let primary = nameservers.first().cloned().unwrap_or_else(|| format!("ns1.{zone}"));
        ZoneConfig {
            hostmaster: format!("hostmaster.{zone}"),
            primary_ns: primary,
            nameservers,
            serial: 1,
            caa_issuers: Vec::new(),
            zone,
        }
    }

    /// Restrict issuance for this zone to `issuers` (e.g. `["letsencrypt.org"]`).
    #[must_use]
    pub fn with_caa_issuers(mut self, issuers: Vec<String>) -> Self {
        self.caa_issuers = issuers;
        self
    }
}

/// The authoritative server: zone parameters, the edge address set, and live ACME tokens.
/// The hostname data itself is read from an [`EdgeRegistry`] at answer time.
pub struct ZoneAuthority {
    zones: Table<String, ZoneConfig>,
    edge_v4: Vec<Ipv4Addr>,
    edge_v6: Vec<Ipv6Addr>,
    /// Fully-qualified challenge name → the tokens currently valid there. A `Vec` because
    /// issuing for `example.com` and `*.example.com` in one order puts two tokens at the
    /// same name, and answering with only one fails the other challenge.
    acme: Table<String, Vec<String>>,
    /// Per-`RecordType` query counts — the B/U face, for the diagnostics endpoint.
    counters: Table<String, i64>,
}

impl ZoneAuthority {
    /// An authority answering for `zones`, pointing every hostname at `edge_v4`/`edge_v6`.
    #[must_use]
    pub fn new(zones: Vec<ZoneConfig>, edge_v4: Vec<Ipv4Addr>, edge_v6: Vec<Ipv6Addr>) -> Self {
        let mut table: Table<String, ZoneConfig> = Table::new();
        for zone in zones {
            table.put(zone.zone.clone(), zone);
        }
        ZoneAuthority {
            zones: table,
            edge_v4,
            edge_v6,
            acme: Table::new(),
            counters: Table::new(),
        }
    }

    /// Publish an ACME DNS-01 token for `name` (the base domain, NOT the
    /// `_acme-challenge.` form — this adds the label).
    pub fn set_acme_token(&mut self, name: &str, token: impl Into<String>) {
        let challenge = format!("{ACME_LABEL}.{}", normalize(name));
        let mut tokens = self.acme.get(&challenge).cloned().unwrap_or_default();
        let token = token.into();
        if !tokens.contains(&token) {
            tokens.push(token);
        }
        self.acme.put(challenge, tokens);
    }

    /// Drop every token published for `name` — called once the order validates, so a spent
    /// challenge is not left answering.
    pub fn clear_acme_tokens(&mut self, name: &str) {
        self.acme.remove(&format!("{ACME_LABEL}.{}", normalize(name)));
    }

    /// The zone `fqdn` falls in — the apex itself or anything under it.
    fn zone_for(&self, fqdn: &str) -> Option<&ZoneConfig> {
        self.zones
            .iter()
            .map(|(_, z)| z)
            .filter(|z| fqdn == z.zone || fqdn.ends_with(&format!(".{}", z.zone)))
            // Longest match wins, so a zone nested inside another still resolves correctly.
            .max_by_key(|z| z.zone.len())
    }

    /// How many queries of each record type have been answered.
    #[must_use]
    pub fn query_count(&self, rtype: &str) -> i64 {
        self.counters.count(&rtype.to_string())
    }

    /// Answer a raw DNS query. Bytes in, bytes to send back — the whole server, minus the
    /// socket.
    ///
    /// Returns `None` only when the query is unparseable, where the correct behaviour is to
    /// send nothing at all: replying to garbage with a FORMERR that echoes an id we could
    /// not read makes us a reflection amplifier.
    #[must_use]
    pub fn answer(&mut self, query_bytes: &[u8], registry: &EdgeRegistry) -> Option<Vec<u8>> {
        let request = Message::from_vec(query_bytes).ok()?;
        let id = request.metadata.id;

        if request.metadata.message_type != MessageType::Query {
            return None; // a response arriving at a server port is not ours to answer
        }
        if request.metadata.op_code != OpCode::Query {
            return encode(&Message::error_msg(id, request.metadata.op_code, ResponseCode::NotImp));
        }

        let mut response = Message::response(id, OpCode::Query);
        // Copy RD so the client can see we understood it; RA stays false — we are
        // authoritative, and an authoritative server that offers recursion is an open
        // resolver.
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = false;

        let Some(query) = request.queries.first().cloned() else {
            response.metadata.response_code = ResponseCode::FormErr;
            return encode(&response);
        };
        response.add_query(query.clone());

        if query.query_class() != DNSClass::IN {
            response.metadata.response_code = ResponseCode::NotImp;
            return encode(&response);
        }

        let qname = normalize(&query.name().to_ascii());
        let qtype = query.query_type();
        self.counters.add(format!("{qtype:?}"), 1);

        let Some(zone) = self.zone_for(&qname).cloned() else {
            // Not ours. REFUSED, never a lookup on the client's behalf.
            response.metadata.response_code = ResponseCode::Refused;
            return encode(&response);
        };
        response.metadata.authoritative = true;

        let answers = self.records_for(&qname, qtype, &zone, registry);
        match answers {
            Resolution::Answers(records) if !records.is_empty() => {
                for record in records {
                    response.add_answer(record);
                }
            }
            Resolution::Answers(_) | Resolution::NoData => {
                // The name exists, this type does not. NOERROR + SOA, so the resolver caches
                // the absence of the TYPE rather than the absence of the NAME.
                if let Some(soa) = soa_record(&zone) {
                    response.add_authority(soa);
                }
            }
            Resolution::NxDomain => {
                response.metadata.response_code = ResponseCode::NXDomain;
                if let Some(soa) = soa_record(&zone) {
                    response.add_authority(soa);
                }
            }
        }
        encode(&response)
    }

    /// The records answering `(qname, qtype)`, or which flavour of empty applies.
    fn records_for(
        &self,
        qname: &str,
        qtype: RecordType,
        zone: &ZoneConfig,
        registry: &EdgeRegistry,
    ) -> Resolution {
        // ── The apex itself ───────────────────────────────────────────────────────────────
        if qname == zone.zone {
            let Ok(name) = Name::from_ascii(format!("{qname}.")) else {
                return Resolution::NxDomain;
            };
            return match qtype {
                RecordType::SOA => soa_record(zone).map_or(Resolution::NoData, |r| Resolution::Answers(vec![r])),
                RecordType::NS => Resolution::Answers(
                    zone.nameservers
                        .iter()
                        .filter_map(|ns| Name::from_ascii(format!("{}.", normalize(ns))).ok())
                        .map(|ns| Record::from_rdata(name.clone(), NS_TTL, RData::NS(NS(ns))))
                        .collect(),
                ),
                RecordType::CAA => Resolution::Answers(
                    zone.caa_issuers
                        .iter()
                        .filter_map(|issuer| Name::from_ascii(normalize(issuer)).ok())
                        .map(|issuer| {
                            Record::from_rdata(
                                name.clone(),
                                NS_TTL,
                                RData::CAA(CAA::new_issue(false, Some(issuer), Vec::new())),
                            )
                        })
                        .collect(),
                ),
                // The apex resolves to the edge too, so `https://twnstack.app` is not a dead
                // name — but it is NOT a customer hostname and routes to the platform's own
                // landing service, which is `transport::edge`'s call, not DNS's.
                RecordType::A | RecordType::AAAA => Resolution::Answers(self.address_records(&name, qtype)),
                _ => Resolution::NoData,
            };
        }

        // ── ACME challenge names ──────────────────────────────────────────────────────────
        if qname.starts_with(&format!("{ACME_LABEL}.")) {
            let Some(tokens) = self.acme.get(&qname.to_string()) else {
                return Resolution::NxDomain;
            };
            if qtype != RecordType::TXT {
                return Resolution::NoData;
            }
            let Ok(name) = Name::from_ascii(format!("{qname}.")) else {
                return Resolution::NxDomain;
            };
            return Resolution::Answers(
                tokens
                    .iter()
                    .map(|t| Record::from_rdata(name.clone(), ACME_TTL, RData::TXT(TXT::new(vec![t.clone()]))))
                    .collect(),
            );
        }

        // ── A customer hostname ───────────────────────────────────────────────────────────
        //
        // Registry membership IS zone membership: no catch-all wildcard, so an unclaimed
        // label is genuinely NXDOMAIN and "does this hostname exist" stays answerable.
        let Some(record) = registry.lookup(qname) else {
            return Resolution::NxDomain;
        };
        // Only managed hostnames live in our zones; a custom hostname in the registry is
        // served by the CUSTOMER's DNS pointing at us, and must never be answered here.
        if record.kind != HostnameKind::Managed {
            return Resolution::NxDomain;
        }
        // A failed hostname is not a hostname. Pending/suspended ones still resolve: a
        // suspended name should reach the edge and be told why, not vanish.
        if matches!(record.state, HostnameState::Failed(_)) {
            return Resolution::NxDomain;
        }
        let Ok(name) = Name::from_ascii(format!("{qname}.")) else {
            return Resolution::NxDomain;
        };
        match qtype {
            RecordType::A | RecordType::AAAA => Resolution::Answers(self.address_records(&name, qtype)),
            _ => Resolution::NoData,
        }
    }

    fn address_records(&self, name: &Name, qtype: RecordType) -> Vec<Record> {
        match qtype {
            RecordType::A => self
                .edge_v4
                .iter()
                .map(|ip| Record::from_rdata(name.clone(), ADDRESS_TTL, RData::A(A(*ip))))
                .collect(),
            RecordType::AAAA => self
                .edge_v6
                .iter()
                .map(|ip| Record::from_rdata(name.clone(), ADDRESS_TTL, RData::AAAA(AAAA(*ip))))
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// What a lookup resolved to. `NoData` and `NxDomain` are deliberately distinct — see the
/// module doc; conflating them is the classic authoritative-server bug.
enum Resolution {
    Answers(Vec<Record>),
    NoData,
    NxDomain,
}

fn soa_record(zone: &ZoneConfig) -> Option<Record> {
    let name = Name::from_ascii(format!("{}.", zone.zone)).ok()?;
    let mname = Name::from_ascii(format!("{}.", normalize(&zone.primary_ns))).ok()?;
    let rname = Name::from_ascii(format!("{}.", normalize(&zone.hostmaster))).ok()?;
    Some(Record::from_rdata(
        name,
        SOA_MINIMUM_TTL,
        RData::SOA(SOA::new(
            mname,
            rname,
            zone.serial,
            7200,  // refresh
            3600,  // retry
            604_800, // expire
            SOA_MINIMUM_TTL,
        )),
    ))
}

fn encode(message: &Message) -> Option<Vec<u8>> {
    message.to_vec().ok()
}

// ── The socket loop ───────────────────────────────────────────────────────────────────────

/// Serve DNS over UDP on `addr` until the future is dropped.
///
/// The whole server is [`ZoneAuthority::answer`]; this is the transport around it. UDP only:
/// TCP (and therefore responses over 512 bytes, and zone transfers) is not implemented — a
/// stated limit, not an oversight. Our answers are small by construction (a handful of A
/// records or one TXT), so truncation-driven TCP retry is not on the path yet.
#[cfg(feature = "native")]
pub async fn serve_udp(
    addr: &str,
    authority: std::sync::Arc<tokio::sync::Mutex<ZoneAuthority>>,
    registry: std::sync::Arc<tokio::sync::Mutex<EdgeRegistry>>,
) -> std::io::Result<()> {
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    eprintln!(target: "bedrock::edge_dns", addr = %addr, "authoritative DNS listening");
    // 4096 covers an EDNS0-advertised payload; anything larger is not a query we serve.
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("DEBUG: target: "bedrock::edge_dns", error = %e, "recv failed");
                continue;
            }
        };
        let reply = {
            let registry = registry.lock().await;
            let mut authority = authority.lock().await;
            authority.answer(&buf[..len], &registry)
        };
        if let Some(reply) = reply {
            if let Err(e) = socket.send_to(&reply, peer).await {
                eprintln!("DEBUG: target: "bedrock::edge_dns", error = %e, %peer, "send failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::edge::{Route, APEXES};
    use hickory_proto::op::Query;

    fn authority() -> ZoneAuthority {
        let zones = APEXES
            .iter()
            .map(|apex| {
                ZoneConfig::new(apex.zone, vec![format!("ns1.{}", apex.zone), format!("ns2.{}", apex.zone)])
                    .with_caa_issuers(vec!["letsencrypt.org".to_string()])
            })
            .collect();
        ZoneAuthority::new(zones, vec![Ipv4Addr::new(203, 0, 113, 10)], vec![Ipv6Addr::LOCALHOST])
    }

    fn route(tenant: &str, tunnel: &str) -> Route {
        Route {
            tenant_id: tenant.to_string(),
            tunnel_id: tunnel.to_string(),
            peer: crate::transport::dialkey::peer_id(tunnel),
            origin_port: 8080,
        }
    }

    /// Build a real query packet — the tests go through the wire format, not around it.
    fn query_bytes(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = 0x1234;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_ascii(format!("{name}.")).unwrap(), qtype));
        msg.to_vec().unwrap()
    }

    fn ask(auth: &mut ZoneAuthority, reg: &EdgeRegistry, name: &str, qtype: RecordType) -> Message {
        let bytes = auth.answer(&query_bytes(name, qtype), reg).expect("a reply");
        Message::from_vec(&bytes).expect("reply parses as a DNS message")
    }

    #[test]
    fn a_claimed_hostname_resolves_to_the_edge() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();

        let reply = ask(&mut auth, &reg, &rec.fqdn, RecordType::A);
        assert_eq!(reply.metadata.id, 0x1234, "the response must echo the query id");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative, "we are the authority for this zone");
        assert!(!reply.metadata.recursion_available, "an authoritative server is not an open resolver");
        assert_eq!(reply.answers.len(), 1);
        match &reply.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(203, 0, 113, 10)),
            other => panic!("expected an A record, got {other:?}"),
        }
        assert_eq!(reply.answers[0].ttl, ADDRESS_TTL);
    }

    #[test]
    fn an_unclaimed_label_is_nxdomain_with_a_soa_not_a_wildcard() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        let reply = ask(&mut auth, &reg, "never-claimed-abc123.twnstack.app", RecordType::A);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a catch-all wildcard would make every typo resolve to the edge"
        );
        assert!(reply.answers.is_empty());
        let soa = reply.authorities.first().expect("NXDOMAIN must carry a SOA for negative caching");
        match &soa.data {
            RData::SOA(soa) => assert_eq!(soa.minimum, SOA_MINIMUM_TTL),
            other => panic!("expected SOA in the authority section, got {other:?}"),
        }
    }

    #[test]
    fn an_existing_name_with_no_such_type_is_nodata_not_nxdomain() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();

        let reply = ask(&mut auth, &reg, &rec.fqdn, RecordType::MX);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "the NAME exists — NXDOMAIN here would tell the resolver the whole name is gone"
        );
        assert!(reply.answers.is_empty());
        assert!(!reply.authorities.is_empty(), "NODATA still carries the SOA");
    }

    #[test]
    fn a_zone_we_do_not_serve_is_refused_never_resolved() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        let reply = ask(&mut auth, &reg, "www.google.com", RecordType::A);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "answering for other zones would make this an open resolver / amplifier"
        );
        assert!(reply.answers.is_empty());
        assert!(!reply.metadata.authoritative);
    }

    #[test]
    fn custom_hostnames_are_never_answered_from_our_zones() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        reg.add_custom("app.example.com.au", "x.twnstack.app", route("acme", "tun-1")).unwrap();
        // Their own DNS points at us; we are not authoritative for their domain.
        let reply = ask(&mut auth, &reg, "app.example.com.au", RecordType::A);
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    }

    #[test]
    fn the_apex_answers_soa_ns_and_caa() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());

        let soa = ask(&mut auth, &reg, "twnstack.app", RecordType::SOA);
        assert_eq!(soa.answers.len(), 1);
        assert!(matches!(soa.answers[0].data, RData::SOA(_)));

        let ns = ask(&mut auth, &reg, "twnstack.app", RecordType::NS);
        assert_eq!(ns.answers.len(), 2, "both nameservers must be published");

        let caa = ask(&mut auth, &reg, "twnstack.app", RecordType::CAA);
        assert_eq!(caa.answers.len(), 1, "CAA pins which CA may issue for the zone");
    }

    #[test]
    fn acme_dns01_tokens_are_served_and_can_be_cleared() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        auth.set_acme_token("twnstack.app", "token-one");

        let reply = ask(&mut auth, &reg, "_acme-challenge.twnstack.app", RecordType::TXT);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        match &reply.answers[0].data {
            RData::TXT(txt) => assert_eq!(txt.to_string(), "token-one"),
            other => panic!("expected TXT, got {other:?}"),
        }

        auth.clear_acme_tokens("twnstack.app");
        let gone = ask(&mut auth, &reg, "_acme-challenge.twnstack.app", RecordType::TXT);
        assert_eq!(gone.metadata.response_code, ResponseCode::NXDomain, "a spent challenge stops answering");
    }

    #[test]
    fn two_concurrent_orders_both_get_their_token() {
        // Issuing `example.com` and `*.example.com` puts two tokens at one challenge name.
        // Answering with only the newest fails the other order.
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        auth.set_acme_token("twnbox.dev", "token-base");
        auth.set_acme_token("twnbox.dev", "token-wildcard");

        let reply = ask(&mut auth, &reg, "_acme-challenge.twnbox.dev", RecordType::TXT);
        assert_eq!(reply.answers.len(), 2, "both live tokens must be answered");
    }

    #[test]
    fn a_released_hostname_stops_resolving_with_no_zone_reload() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        assert_eq!(ask(&mut auth, &reg, &rec.fqdn, RecordType::A).answers.len(), 1);

        reg.release("acme", &rec.fqdn).unwrap();
        assert_eq!(
            ask(&mut auth, &reg, &rec.fqdn, RecordType::A).metadata.response_code,
            ResponseCode::NXDomain,
            "the registry IS the zone — no reload step exists to forget"
        );
    }

    #[test]
    fn a_suspended_hostname_still_resolves_so_the_edge_can_explain() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        reg.suspend("acme", &rec.fqdn).unwrap();
        assert_eq!(
            ask(&mut auth, &reg, &rec.fqdn, RecordType::A).answers.len(),
            1,
            "a suspended name should reach the edge and be told why, not vanish"
        );
    }

    #[test]
    fn case_and_trailing_dot_do_not_change_the_answer() {
        let mut auth = authority();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        let upper = rec.fqdn.to_uppercase();
        assert_eq!(ask(&mut auth, &reg, &upper, RecordType::A).answers.len(), 1);
    }

    #[test]
    fn garbage_gets_no_reply_at_all() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        assert!(
            auth.answer(b"not a dns packet", &reg).is_none(),
            "replying to unparseable input makes us a reflection amplifier"
        );
    }

    #[test]
    fn a_response_arriving_at_the_server_port_is_ignored() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        let mut msg = Message::response(7, OpCode::Query);
        msg.add_query(Query::query(Name::from_ascii("twnstack.app.").unwrap(), RecordType::A));
        assert!(auth.answer(&msg.to_vec().unwrap(), &reg).is_none());
    }

    #[test]
    fn a_non_query_opcode_is_notimp_not_a_crash() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        let mut msg = Message::new(9, MessageType::Query, OpCode::Update);
        msg.add_query(Query::query(Name::from_ascii("twnstack.app.").unwrap(), RecordType::SOA));
        let bytes = auth.answer(&msg.to_vec().unwrap(), &reg).expect("a reply");
        let reply = Message::from_vec(&bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(reply.metadata.id, 9);
    }

    #[test]
    fn every_apex_is_served() {
        let mut auth = authority();
        let reg = EdgeRegistry::new(b"s".to_vec());
        for apex in APEXES {
            let reply = ask(&mut auth, &reg, apex.zone, RecordType::SOA);
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{} must be served — it is in APEXES",
                apex.zone
            );
        }
    }
}
