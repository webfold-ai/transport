//! Pkarr transport support for service discovery — native, on our own stack.
//!
//! Publishes and resolves SRV/TXT/A records under a key-derived name. A sidecar publishes its
//! HTTP endpoint under a key derived from its dialkey, and consumers resolve the endpoint
//! without hardcoding an IP or port.
//!
//! ## This no longer wraps the `pkarr` crate
//!
//! It is built from [`super::dns`] (the RFC 1035 wire format) and [`super::signed_dns`] (the
//! Ed25519-signed BEP44 record), on `apeiron::map::hashtrinity::crypto` and this crate's own HTTP client —
//! the third module in the line [`super::native`] started when it replaced `iroh::Endpoint`.
//!
//! The measurement that motivated it: `pkarr` was one direct dependency reaching **82 of the
//! 165 normal crates in the graph**, half of it, through its `relays` feature — `reqwest` →
//! `hyper` → `rustls` → `ring`, and `url` → `idna` → the whole ICU tree. For a signature over a
//! DNS packet and an HTTP PUT.
//!
//! ## Wire compatibility
//!
//! The published bytes are unchanged: `signature(64) ‖ seq(8, big-endian) ‖ v`, `v` an
//! uncompressed DNS message, signed over BEP44's bencode preimage. The record layout is the same
//! too — an A/AAAA at the key's own apex label, an SRV under `<service>.<key>` pointing at that
//! apex, and a TXT beside it carrying `k=v` attributes.
//!
//! **Not implemented: the Mainline DHT.** The `pkarr` crate could publish there as well; this
//! drives the relay (HTTP) path only, which is the one this workspace configured. That is a
//! named gap, not an oversight.

use super::dns::{Name, RData, Record};
#[cfg(feature = "native")]
use super::signed_dns::PublicKey;
use super::signed_dns::{Keypair, SignedDnsError, SignedPacket};
use crate::prim::sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

const OPSFOLD_SERVICE: &str = "_opsfold._tcp";
const OPSFOLD_PATH: &str = "/v1/ops/gateway";
const BILLING_SERVICE: &str = "_billing._tcp";
const BILLING_PATH: &str = "/v1/billing";
const RECORD_TTL: u32 = 300;

/// The environment variable [`RelayClient::from_env`] reads: comma-separated relay base URLs.
pub const RELAYS_ENV: &str = "PKARR_RELAYS";

/// `"http://a:6881, http://b:6881,,"` is two relays: split on commas, trim, drop empties, keep
/// order (the client asks them in order).
#[must_use]
pub fn parse_relay_list(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The relays a [`RelayClient`] talks to when the caller names none — the same two the `pkarr`
/// crate defaults to, so an existing deployment resolves unchanged.
pub const DEFAULT_RELAYS: [&str; 2] = ["https://relay.pkarr.org", "https://pkarr.pubky.app"];

/// Discovered opsfold endpoint.
#[derive(Clone, Debug)]
pub struct OpsfoldEndpoint {
    /// Sidecar region, e.g. `prod` or `staging`.
    pub region: String,
    /// Base HTTP URL, e.g. `http://10.7.46.107:8081`.
    pub url: String,
}

/// Discovered generic service endpoint.
#[derive(Clone, Debug)]
pub struct ServiceEndpoint {
    pub service: String,
    pub url: String,
    pub metadata: HashMap<String, String>,
}

/// Why a publish failed. Resolution returns `Option` rather than this: a key that is simply not
/// published yet is an ordinary answer, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The records did not fit BEP44's value limit, or would not sign.
    Packet(SignedDnsError),
    /// Every relay refused or was unreachable. Carries the last message seen, so a failure names
    /// a cause instead of just a count.
    AllRelaysFailed(String),
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PublishError::Packet(e) => write!(f, "pkarr: {e}"),
            PublishError::AllRelaysFailed(m) => {
                write!(f, "pkarr: no relay accepted the record ({m})")
            }
        }
    }
}

impl std::error::Error for PublishError {}

fn dialkey_seed(dialkey: &str) -> [u8; 32] {
    let mut input = String::with_capacity(dialkey.len() + 7);
    input.push_str(dialkey);
    input.push_str(":pkarr");
    sha256(input.as_bytes())
}

/// Derive a deterministic Ed25519 keypair from a dialkey.
///
/// The `:pkarr` suffix and the SHA-256 are unchanged from the wrapper this replaces — the seed
/// derivation IS the identity, so altering it would silently rename every published endpoint.
#[must_use]
pub fn keypair_from_dialkey(dialkey: &str) -> Keypair {
    Keypair::from_secret_key(&dialkey_seed(dialkey))
}

fn service_name(public_key_str: &str, service: &str) -> String {
    format!("{}.{}", service, public_key_str)
}

/// Microseconds since the epoch — BEP44's sequence number, so a later publish always outranks an
/// earlier one at the relay.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// The records for one service under `keypair`'s name: A/AAAA at the apex, SRV pointing at it,
/// TXT carrying the attributes.
fn service_records(
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    service: &str,
    metadata: &[(&str, &str)],
) -> Vec<Record> {
    let apex_str = keypair.to_z32();
    let apex = Name::from_ascii(&apex_str).expect("a z-base32 key is a valid label");
    let svc =
        Name::from_ascii(&service_name(&apex_str, service)).expect("service.key is a valid name");

    let mut out = vec![
        Record::new(
            svc.clone(),
            RECORD_TTL,
            RData::Srv {
                priority: 0,
                weight: 0,
                port,
                target: apex.clone(),
            },
        ),
        Record::new(
            svc,
            RECORD_TTL,
            RData::Txt(
                metadata
                    .iter()
                    .map(|(k, v)| format!("{k}={v}").into_bytes())
                    .collect(),
            ),
        ),
    ];
    out.push(match ip {
        IpAddr::V4(a) => Record::new(apex, RECORD_TTL, RData::A(a)),
        IpAddr::V6(a) => Record::new(apex, RECORD_TTL, RData::Aaaa(a)),
    });
    out
}

fn sign(keypair: &Keypair, records: &[Record]) -> SignedPacket {
    SignedPacket::new(keypair, records, now_micros()).expect("service records fit BEP44's limit")
}

fn build_packet(
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    service: &str,
    metadata: &[(&str, &str)],
) -> SignedPacket {
    sign(
        keypair,
        &service_records(keypair, ip, port, service, metadata),
    )
}

#[cfg_attr(not(feature = "native"), allow(dead_code))] // read back only by the relay-client resolvers (and tests)
fn resolve_service_packet(packet: &SignedPacket, service: &str) -> Option<ServiceEndpoint> {
    let key_str = packet.public_key().to_z32();
    let want = Name::from_ascii(&service_name(&key_str, service)).ok()?;
    let records = packet.records();

    let mut port = None;
    let mut target = None;
    let mut metadata = HashMap::new();
    for r in &records {
        if r.name != want {
            continue;
        }
        match &r.data {
            RData::Srv {
                port: p, target: t, ..
            } => {
                port = Some(*p);
                target = Some(t.clone());
            }
            RData::Txt(strings) => {
                for s in strings {
                    let text = String::from_utf8_lossy(s);
                    if let Some((k, v)) = text.split_once('=') {
                        metadata.insert(k.to_string(), v.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let target = target?;
    let mut ip = None;
    for r in &records {
        if r.name != target {
            continue;
        }
        match &r.data {
            RData::A(a) => ip = Some(IpAddr::V4(*a)),
            RData::Aaaa(a) => ip = Some(IpAddr::V6(*a)),
            _ => {}
        }
    }

    let ip = ip?;
    let port = port?;
    Some(ServiceEndpoint {
        service: service.to_string(),
        url: format!("http://{ip}:{port}"),
        metadata,
    })
}

/// Build a signed packet advertising an opsfold HTTP endpoint.
#[must_use]
pub fn build_opsfold_packet(
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    region: &str,
) -> SignedPacket {
    build_packet(
        keypair,
        ip,
        port,
        OPSFOLD_SERVICE,
        &[("region", region), ("path", OPSFOLD_PATH)],
    )
}

/// Build a signed packet advertising a billing HTTP endpoint.
#[must_use]
pub fn build_billing_packet(
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    tenant: &str,
) -> SignedPacket {
    build_packet(
        keypair,
        ip,
        port,
        BILLING_SERVICE,
        &[("tenant", tenant), ("path", BILLING_PATH)],
    )
}

/// Build a single signed packet advertising both opsfold and billing endpoints.
///
/// One packet rather than two because a record carries ONE sequence number for all of it:
/// publishing the two services separately makes the second overwrite the first at the relay,
/// and the loser then resolves as absent.
#[must_use]
pub fn build_combined_packet(
    keypair: &Keypair,
    ip: IpAddr,
    opsfold_port: u16,
    billing_port: u16,
    region: &str,
    tenant: &str,
) -> SignedPacket {
    let mut records = service_records(
        keypair,
        ip,
        opsfold_port,
        OPSFOLD_SERVICE,
        &[("region", region), ("path", OPSFOLD_PATH)],
    );
    // the second service contributes its SRV+TXT; the apex address is already present
    let billing = service_records(
        keypair,
        ip,
        billing_port,
        BILLING_SERVICE,
        &[("tenant", tenant), ("path", BILLING_PATH)],
    );
    records.extend(
        billing
            .into_iter()
            .filter(|r| !matches!(r.data, RData::A(_) | RData::Aaaa(_))),
    );
    sign(keypair, &records)
}

/// The mesh model service name — peers publish/advertise their model-serving capabilities
/// under this SRV record via pkarr, mDNS, and dialkey.
pub const MESH_MODEL_SERVICE: &str = "_mesh-model._tcp";

/// Build a signed packet advertising a peer's model-serving capabilities.
/// `metadata` should be the output of `transport::discovery::capability_attributes`.
#[must_use]
pub fn build_mesh_model_packet(
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    metadata: &[(&str, &str)],
) -> SignedPacket {
    build_packet(keypair, ip, port, MESH_MODEL_SERVICE, metadata)
}

// ── the relay client ────────────────────────────────────────────────────────────────────────

/// Publishes and resolves signed records over the pkarr relay HTTP protocol, on this crate's own
/// [`crate::http_client::Client`].
///
/// The protocol is two calls: `PUT <relay>/<z-base32 key>` with the record as the body, and
/// `GET` the same URL to read it back. A relay is a cache, not an authority — every response is
/// verified against the key it was requested under before it is believed, so a malicious or
/// broken relay can withhold a record but cannot forge one.
#[cfg(feature = "native")]
#[derive(Clone)]
pub struct RelayClient {
    http: crate::http_client::Client,
    relays: Vec<String>,
}

#[cfg(feature = "native")]
impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "native")]
impl RelayClient {
    /// A client against [`DEFAULT_RELAYS`].
    #[must_use]
    pub fn new() -> Self {
        RelayClient {
            http: crate::http_client::Client::new(),
            relays: DEFAULT_RELAYS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// A client against the given relay base URLs.
    #[must_use]
    pub fn with_relays(relays: Vec<String>) -> Self {
        RelayClient {
            http: crate::http_client::Client::new(),
            relays,
        }
    }

    /// A client against the relays named by [`RELAYS_ENV`] (`PKARR_RELAYS`, comma-separated base
    /// URLs, e.g. `http://meshd:6881`), or against [`DEFAULT_RELAYS`] when it is unset or names
    /// none. This is how a deployment points every service at its own `meshd` without each
    /// service growing its own variable.
    #[must_use]
    pub fn from_env() -> Self {
        let relays = std::env::var(RELAYS_ENV)
            .map(|v| parse_relay_list(&v))
            .unwrap_or_default();
        if relays.is_empty() {
            Self::new()
        } else {
            Self::with_relays(relays)
        }
    }

    fn url(relay: &str, key: &PublicKey) -> String {
        format!("{}/{}", relay.trim_end_matches('/'), key.to_z32())
    }

    /// Publish `packet` to every relay. Succeeds if **any** accepts it: a record is replicated,
    /// so one reachable relay is enough to be resolvable, and failing the call because a second
    /// relay was down would take a working deployment offline.
    ///
    /// # Errors
    /// [`PublishError::AllRelaysFailed`] only when no relay accepted the record.
    pub async fn publish(&self, packet: &SignedPacket) -> Result<(), PublishError> {
        let body = packet.to_relay_bytes();
        let mut last = String::from("no relays configured");
        for relay in &self.relays {
            let url = Self::url(relay, &packet.public_key());
            match self.http.put(&url).body_bytes(body.clone()).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => last = format!("{url} -> HTTP {}", resp.status().as_u16()),
                Err(e) => last = format!("{url} -> {e}"),
            }
        }
        Err(PublishError::AllRelaysFailed(last))
    }

    /// Resolve the most recent record for `public_key`, asking every relay and keeping the
    /// highest sequence number.
    ///
    /// Returns `None` when no relay holds a record that verifies. An unverifiable response is
    /// discarded rather than surfaced — the caller cannot do anything useful with a record that
    /// is not the key's, and returning one would defeat the point of signing it.
    pub async fn resolve_most_recent(&self, public_key: &PublicKey) -> Option<SignedPacket> {
        let mut best: Option<SignedPacket> = None;
        for relay in &self.relays {
            let url = Self::url(relay, public_key);
            let Ok(resp) = self.http.get(&url).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let body = resp.bytes().await;
            let Ok(packet) = SignedPacket::from_relay_bytes(*public_key, &body) else {
                continue; // forged, corrupt, or truncated — not this key's record
            };
            if best.as_ref().is_none_or(|b| packet.seq() > b.seq()) {
                best = Some(packet);
            }
        }
        best
    }
}

/// Publish a combined opsfold + billing endpoint record.
///
/// # Errors
/// [`PublishError`] if no relay accepted the record.
#[cfg(feature = "native")]
pub async fn publish_combined(
    client: &RelayClient,
    keypair: &Keypair,
    ip: IpAddr,
    opsfold_port: u16,
    billing_port: u16,
    region: &str,
    tenant: &str,
) -> Result<(), PublishError> {
    client
        .publish(&build_combined_packet(
            keypair,
            ip,
            opsfold_port,
            billing_port,
            region,
            tenant,
        ))
        .await
}

/// Publish an opsfold endpoint record.
///
/// # Errors
/// [`PublishError`] if no relay accepted the record.
#[cfg(feature = "native")]
pub async fn publish_opsfold(
    client: &RelayClient,
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    region: &str,
) -> Result<(), PublishError> {
    client
        .publish(&build_opsfold_packet(keypair, ip, port, region))
        .await
}

/// Publish a billing endpoint record.
///
/// # Errors
/// [`PublishError`] if no relay accepted the record.
#[cfg(feature = "native")]
pub async fn publish_billing(
    client: &RelayClient,
    keypair: &Keypair,
    ip: IpAddr,
    port: u16,
    tenant: &str,
) -> Result<(), PublishError> {
    client
        .publish(&build_billing_packet(keypair, ip, port, tenant))
        .await
}

/// Resolve an opsfold endpoint from a published record.
#[cfg(feature = "native")]
pub async fn resolve_opsfold(
    client: &RelayClient,
    public_key: &PublicKey,
) -> Option<OpsfoldEndpoint> {
    let packet = client.resolve_most_recent(public_key).await?;
    let ep = resolve_service_packet(&packet, OPSFOLD_SERVICE)?;
    Some(OpsfoldEndpoint {
        region: ep
            .metadata
            .get("region")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        url: ep.url,
    })
}

/// Resolve a billing endpoint from a published record.
#[cfg(feature = "native")]
pub async fn resolve_billing(
    client: &RelayClient,
    public_key: &PublicKey,
) -> Option<ServiceEndpoint> {
    let packet = client.resolve_most_recent(public_key).await?;
    resolve_service_packet(&packet, BILLING_SERVICE)
}

/// Resolve a mesh-model service endpoint from a published record.
#[cfg(feature = "native")]
pub async fn resolve_mesh_model(
    client: &RelayClient,
    public_key: &PublicKey,
) -> Option<ServiceEndpoint> {
    let packet = client.resolve_most_recent(public_key).await?;
    resolve_service_packet(&packet, MESH_MODEL_SERVICE)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_relay_list_is_trimmed_ordered_and_without_blanks() {
        assert_eq!(
            parse_relay_list("http://a:6881, http://b:6881 ,,"),
            ["http://a:6881", "http://b:6881"]
        );
        assert!(parse_relay_list("").is_empty());
        assert!(parse_relay_list(" , ,").is_empty());
        assert_eq!(
            parse_relay_list("https://relay.example"),
            ["https://relay.example"]
        );
    }

    use super::*;

    /// The seed derivation IS the identity: change it and every published endpoint silently
    /// renames itself. Pinned against the literal it has always produced.
    #[test]
    fn a_dialkey_names_one_stable_identity() {
        let a = keypair_from_dialkey("tas-cloud-01");
        assert_eq!(a.to_z32(), keypair_from_dialkey("tas-cloud-01").to_z32());
        assert_ne!(a.to_z32(), keypair_from_dialkey("tas-cloud-02").to_z32());
        assert_eq!(
            dialkey_seed("x"),
            sha256(b"x:pkarr"),
            "the suffix is part of the identity"
        );
    }

    #[test]
    fn an_opsfold_packet_resolves_back_to_the_endpoint_it_advertised() {
        let k = keypair_from_dialkey("d1");
        let p = build_opsfold_packet(&k, "10.7.46.107".parse().unwrap(), 8081, "tas-cloud");
        let ep = resolve_service_packet(&p, OPSFOLD_SERVICE).expect("resolves");
        assert_eq!(ep.url, "http://10.7.46.107:8081");
        assert_eq!(
            ep.metadata.get("region").map(String::as_str),
            Some("tas-cloud")
        );
        assert_eq!(
            ep.metadata.get("path").map(String::as_str),
            Some(OPSFOLD_PATH)
        );
    }

    #[test]
    fn an_ipv6_endpoint_round_trips_through_the_aaaa_record() {
        let k = keypair_from_dialkey("d6");
        let p = build_opsfold_packet(&k, "2001:db8::7".parse().unwrap(), 9000, "r");
        let ep = resolve_service_packet(&p, OPSFOLD_SERVICE).expect("resolves");
        assert_eq!(ep.url, "http://2001:db8::7:9000");
    }

    /// The reason the combined builder exists: one packet carries one sequence number, so two
    /// separate publishes would leave the relay holding only the later one.
    #[test]
    fn a_combined_packet_carries_both_services_at_one_sequence() {
        let k = keypair_from_dialkey("d2");
        let p = build_combined_packet(
            &k,
            "192.0.2.9".parse().unwrap(),
            8081,
            9090,
            "tas-cloud",
            "acme",
        );
        let ops = resolve_service_packet(&p, OPSFOLD_SERVICE).expect("opsfold resolves");
        let bill = resolve_service_packet(&p, BILLING_SERVICE).expect("billing resolves");
        assert_eq!(ops.url, "http://192.0.2.9:8081");
        assert_eq!(bill.url, "http://192.0.2.9:9090");
        assert_eq!(
            bill.metadata.get("tenant").map(String::as_str),
            Some("acme")
        );
        // one apex address, not one per service
        let addrs = p
            .records()
            .iter()
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_)))
            .count();
        assert_eq!(
            addrs, 1,
            "the apex address must not be duplicated per service"
        );
    }

    /// A record survives the exact bytes a relay stores and returns.
    #[test]
    fn a_packet_survives_the_relay_wire_form() {
        let k = keypair_from_dialkey("d3");
        let p = build_mesh_model_packet(
            &k,
            "198.51.100.4".parse().unwrap(),
            7000,
            &[("model", "qwen3-8b"), ("quant", "q20")],
        );
        let back = SignedPacket::from_relay_bytes(k.public_key(), &p.to_relay_bytes()).unwrap();
        let ep = resolve_service_packet(&back, MESH_MODEL_SERVICE).expect("resolves");
        assert_eq!(ep.url, "http://198.51.100.4:7000");
        assert_eq!(
            ep.metadata.get("model").map(String::as_str),
            Some("qwen3-8b")
        );
    }

    /// Asking for a service the packet does not advertise is `None`, not another service's
    /// endpoint — the SRV lookup is keyed by the full `<service>.<key>` name.
    #[test]
    fn resolving_a_service_that_was_not_published_is_none() {
        let k = keypair_from_dialkey("d4");
        let p = build_opsfold_packet(&k, "192.0.2.1".parse().unwrap(), 8081, "r");
        assert!(resolve_service_packet(&p, BILLING_SERVICE).is_none());
        assert!(resolve_service_packet(&p, MESH_MODEL_SERVICE).is_none());
    }

    #[cfg(feature = "native")]
    #[test]
    fn a_relay_url_is_the_key_under_the_relay_base() {
        let k = keypair_from_dialkey("d5");
        let pk = k.public_key();
        assert_eq!(
            RelayClient::url("https://relay.pkarr.org/", &pk),
            format!("https://relay.pkarr.org/{}", pk.to_z32())
        );
    }
}
