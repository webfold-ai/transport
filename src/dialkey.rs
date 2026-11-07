//! Dialkey-based peer addressing — native, on this crate's own signed-DNS stack.
//!
//! A dialkey is a shared secret that deterministically derives an Ed25519 identity (`PeerId`).
//! A sidecar publishes its transport address (`PeerAddr`) under its dialkey, and resolves peers by
//! their dialkey. Multiple services can be advertised in the same signed packet.
//!
//! ## This no longer requires the `pkarr` crate
//!
//! Records are built from [`super::dns`] (RFC 1035 wire format) and signed by
//! [`super::signed_dns`] (Ed25519 over BEP44's bencode preimage) — the same pair
//! [`super::pkarr`] already sits on. The published bytes are unchanged, so a node running this
//! and a node running the real `pkarr` crate resolve each other's records.
//!
//! ## Why the client is a type parameter
//!
//! [`publish`] and [`resolve`] are generic over [`DialkeyTransport`]. Two clients implement it:
//!
//! * `super::pkarr::RelayClient` — native, no `pkarr` dependency (under the on-by-default `native` feature).
//! * `pkarr::Client` — only under the `federation` feature.
//!
//! The generic exists because callers outside this crate already hold one or the other. Making
//! the parameter concrete would have forced every one of them to change on the same commit;
//! making it generic lets a consumer migrate when it chooses and delete its own `pkarr`
//! dependency at that point. The `federation` impl is the transition shim, not the destination —
//! see `docs/rfcs/0019-native-p2p-pkarr-removal.md` for what is left to remove.

use crate::{PeerAddr, PeerId};
use crate::prim::sha256;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;

use super::dns::{Name, RData, Record};
#[cfg(feature = "native")]
use super::pkarr::{PublishError, RelayClient};
use super::signed_dns::SignedPacket;

const RECORD_TTL: u32 = 300;
/// The ops-plane service record — any service of the opsfold mesh publishes
/// under this type; the `path` metadata entry names the actual HTTP surface.
pub const OPSFOLD_SERVICE: &str = "_opsfold._tcp";
const BILLING_SERVICE: &str = "_billing._tcp";
const OPSFOLD_PATH: &str = "/v1/ops/gateway";
const BILLING_PATH: &str = "/v1/billing";

/// The **secret** Ed25519 seed a dialkey implies. Never log, store, publish or send it.
///
/// The `:pkarr` suffix is load-bearing history, not a leftover: it is inside the SHA-256 that
/// produces the identity, so changing it would silently rename every endpoint already published.
/// It matches [`super::pkarr`]'s own derivation byte for byte.
///
/// Crate-private on purpose. `peer_id` used to return this value, which put the secret behind a
/// name documented everywhere else as the public key; the long name is there so a call site reads
/// as handling a secret.
pub(crate) fn secret_seed_do_not_expose(dialkey: &str) -> [u8; 32] {
    let mut input = String::with_capacity(dialkey.len() + 7);
    input.push_str(dialkey);
    input.push_str(":pkarr");
    sha256(input.as_bytes())
}

/// The `PeerId` a dialkey implies: the Ed25519 **public** key of [`native_keypair`]`(dialkey)`.
///
/// This is the identity a [`Transport`](super::Transport) bound with
/// [`NativeEndpoint::bind_with_dialkey`](super::native::NativeEndpoint::bind_with_dialkey)
/// presents in the handshake, and the key whose z-base32 form is the dialkey's published name.
/// It is public: safe to log, pin, publish and gossip. The secret half never leaves this crate.
///
/// # Breaking change (0.2.0)
/// Before 0.2.0 this returned the 32-byte *secret seed* (`SHA-256(dialkey ++ ":pkarr")`). A
/// caller that fed the result back in as a secret (`bind_with_key(peer_id(k))`, or
/// `ed25519_pubkey(peer_id(k))`) must switch to `NativeEndpoint::bind_with_dialkey` or
/// `native_keypair(k).public_key()` — see CHANGELOG.md.
#[must_use]
pub fn peer_id(dialkey: &str) -> PeerId {
    *native_keypair(dialkey).public_key().as_bytes()
}

/// Derive the native signing keypair from a dialkey.
///
/// Always available. Identical seed to [`keypair`]'s legacy form, so the two name the same
/// endpoint.
#[must_use]
pub fn native_keypair(dialkey: &str) -> super::signed_dns::Keypair {
    super::signed_dns::Keypair::from_secret_key(&secret_seed_do_not_expose(dialkey))
}

/// Derive a signing keypair from a dialkey.
///
/// Under `federation` this returns the `pkarr` crate's `Keypair`, because `crate::ops::federation`
/// still hands it to `pkarr`-typed code. Without the feature it is [`native_keypair`]. Both are
/// the same 32-byte seed and therefore the same published name.
#[cfg(feature = "federation")]
#[must_use]
pub fn keypair(dialkey: &str) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&secret_seed_do_not_expose(dialkey))
}

/// Derive a signing keypair from a dialkey. See the `federation` variant above.
#[cfg(not(feature = "federation"))]
#[must_use]
pub fn keypair(dialkey: &str) -> super::signed_dns::Keypair {
    native_keypair(dialkey)
}

/// Service to advertise under a dialkey.
#[derive(Clone, Debug)]
pub struct DialkeyServiceInfo {
    pub service: String,
    pub port: u16,
    pub metadata: HashMap<String, String>,
}

/// A service resolved from a dialkey.
#[derive(Clone, Debug)]
pub struct DialkeyService {
    pub peer_addr: PeerAddr,
    pub service: String,
    pub metadata: HashMap<String, String>,
}

fn service_name(public_key_str: &str, service: &str) -> String {
    format!("{}.{}", service, public_key_str)
}

/// TXT attribute strings for a service, sorted by key.
///
/// `HashMap` iteration order is not stable between runs. The record bytes are what gets signed,
/// so an unsorted encoding would make two publishes of identical data produce different packets —
/// harmless for correctness, but it defeats byte-comparison in tests and in any relay that
/// de-duplicates. Sorting makes the packet a function of the data alone.
fn sorted_entries(metadata: &HashMap<String, String>) -> Vec<String> {
    let mut entries: Vec<String> = metadata.iter().map(|(k, v)| format!("{k}={v}")).collect();
    entries.sort();
    entries
}

// ── native record construction ───────────────────────────────────────────────────────────────

/// The records advertising `services` under `dialkey`'s name: one A/AAAA at the key's own apex
/// label, and an SRV + TXT pair per service pointing at that apex.
///
/// The apex address appears exactly once no matter how many services share it — a second copy
/// would be wasted bytes against BEP44's 1000-byte ceiling, which multi-service publishes are the
/// most likely to hit.
fn service_records(
    keypair: &super::signed_dns::Keypair,
    ip: IpAddr,
    services: &[DialkeyServiceInfo],
) -> Vec<Record> {
    let apex_str = keypair.to_z32();
    let apex = Name::from_ascii(&apex_str).expect("a z-base32 key is a valid dns label");

    let mut out = Vec::with_capacity(services.len() * 2 + 1);
    for svc in services {
        let Ok(name) = Name::from_ascii(&service_name(&apex_str, &svc.service)) else {
            continue; // a service label that is not a legal DNS name cannot be published
        };
        out.push(Record::new(
            name.clone(),
            RECORD_TTL,
            RData::Srv { priority: 0, weight: 0, port: svc.port, target: apex.clone() },
        ));
        out.push(Record::new(
            name,
            RECORD_TTL,
            RData::Txt(sorted_entries(&svc.metadata).into_iter().map(String::into_bytes).collect()),
        ));
    }
    out.push(match ip {
        IpAddr::V4(a) => Record::new(apex, RECORD_TTL, RData::A(a)),
        IpAddr::V6(a) => Record::new(apex, RECORD_TTL, RData::Aaaa(a)),
    });
    out
}

/// Microseconds since the epoch — BEP44's sequence number, so a later publish outranks an earlier
/// one at the relay.
#[cfg_attr(not(feature = "native"), allow(dead_code))] // the RelayClient publish path is its only caller
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Build the signed packet advertising `services` under `dialkey`.
///
/// # Errors
/// [`super::signed_dns::SignedDnsError::ValueTooLong`] if the encoded records exceed BEP44's
/// 1000-byte value limit — which is a real ceiling on how many services one dialkey can carry.
pub fn build_packet(
    dialkey: &str,
    ip: IpAddr,
    services: &[DialkeyServiceInfo],
    seq: u64,
) -> Result<SignedPacket, super::signed_dns::SignedDnsError> {
    let kp = native_keypair(dialkey);
    SignedPacket::new(&kp, &service_records(&kp, ip, services), seq)
}

/// Read one service back out of a signed packet.
///
/// Refuses a packet not published under `dialkey`'s own key. In the [`resolve`] path the packet
/// was fetched *by* that key so the two always agree — but the returned `PeerAddr` stamps
/// `peer_id(dialkey)` while the record labels come from the packet, and nothing else in the type
/// system ties those two together. Checking here means a mismatch cannot produce a
/// `DialkeyService` whose identity and address came from different keys.
#[cfg_attr(not(feature = "native"), allow(dead_code))] // read back only by the relay-client resolver (and tests)
fn service_from_packet(packet: &SignedPacket, dialkey: &str, service: &str) -> Option<DialkeyService> {
    let key_str = native_keypair(dialkey).to_z32();
    if packet.public_key().to_z32() != key_str {
        return None;
    }
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
            RData::Srv { port: p, target: t, .. } => {
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

    Some(DialkeyService {
        peer_addr: PeerAddr::new(peer_id(dialkey), ip?.to_string(), port?),
        service: service.to_string(),
        metadata,
    })
}

// ── the client abstraction ───────────────────────────────────────────────────────────────────

/// What [`publish`] and [`resolve`] need from a client.
///
/// Implemented for `RelayClient` (native, under the `native` feature) and, under `federation`, for `pkarr::Client`. The
/// futures are explicitly `Send` so callers can spawn them; an `async fn` in a trait would leave
/// that unbounded and break every `tokio::spawn` at the call site instead of here.
pub trait DialkeyTransport {
    /// How this client reports a failed publish.
    type Error: core::fmt::Display;

    /// Publish `services` under `dialkey`, all sharing `ip`.
    fn publish_services(
        &self,
        dialkey: &str,
        ip: IpAddr,
        services: &[DialkeyServiceInfo],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Resolve one service published under `dialkey`.
    fn resolve_service(
        &self,
        dialkey: &str,
        service: &str,
    ) -> impl Future<Output = Option<DialkeyService>> + Send;
}

#[cfg(feature = "native")]
impl DialkeyTransport for RelayClient {
    type Error = PublishError;

    fn publish_services(
        &self,
        dialkey: &str,
        ip: IpAddr,
        services: &[DialkeyServiceInfo],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // Built before the async block so the borrow of `services` does not outlive the call.
        let packet = build_packet(dialkey, ip, services, now_micros());
        async move {
            let packet = packet.map_err(|e| PublishError::AllRelaysFailed(e.to_string()))?;
            self.publish(&packet).await
        }
    }

    fn resolve_service(
        &self,
        dialkey: &str,
        service: &str,
    ) -> impl Future<Output = Option<DialkeyService>> + Send {
        let dialkey = dialkey.to_string();
        let service = service.to_string();
        async move {
            let kp = native_keypair(&dialkey);
            let packet = self.resolve_most_recent(&kp.public_key()).await?;
            service_from_packet(&packet, &dialkey, &service)
        }
    }
}

/// The legacy client, kept only so consumers that still construct a `pkarr::Client` compile
/// unchanged while they migrate. It publishes the same bytes as the native path.
#[cfg(feature = "federation")]
impl DialkeyTransport for pkarr::Client {
    type Error = pkarr::errors::PublishError;

    fn publish_services(
        &self,
        dialkey: &str,
        ip: IpAddr,
        services: &[DialkeyServiceInfo],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        use pkarr::dns::Name as PkName;
        use pkarr::dns::rdata::{RData as PkRData, SRV, TXT};

        let kp = keypair(dialkey);
        let key_str = kp.public_key().to_string();
        let apex = PkName::new(&key_str).expect("public key is a valid dns name").into_owned();

        let mut builder = pkarr::SignedPacket::builder();
        let prepared: Vec<(String, Vec<String>, u16)> = services
            .iter()
            .map(|s| (service_name(&key_str, &s.service), sorted_entries(&s.metadata), s.port))
            .collect();
        for (svc_name, entries, port) in &prepared {
            let name = PkName::new(svc_name).expect("service name is valid").into_owned();
            let srv = SRV { priority: 0, weight: 0, port: *port, target: apex.clone() };
            let mut txt = TXT::new().into_owned();
            for entry in entries {
                txt = txt.with_string(entry).expect("txt entry is valid").into_owned();
            }
            builder = builder
                .rdata(name.clone(), PkRData::SRV(srv), RECORD_TTL)
                .txt(name, txt, RECORD_TTL);
        }
        let builder = match ip {
            IpAddr::V4(addr) => builder.a(apex, addr, RECORD_TTL),
            IpAddr::V6(addr) => builder.aaaa(apex, addr, RECORD_TTL),
        };
        let packet = builder.sign(&kp).expect("signing succeeds");
        async move { self.publish(&packet).await.map(|_stored_node_count| ()) }
    }

    fn resolve_service(
        &self,
        dialkey: &str,
        service: &str,
    ) -> impl Future<Output = Option<DialkeyService>> + Send {
        let dialkey = dialkey.to_string();
        let service = service.to_string();
        async move {
            use pkarr::dns::rdata::RData as PkRData;
            let kp = keypair(&dialkey);
            let packet = self
                .resolve(&kp.public_key(), pkarr::ResolvePolicy::CacheFirst)
                .await
                .ok()?;
            let key_str = kp.public_key().to_string();
            let want = service_name(&key_str, &service);

            let mut port = None;
            let mut target = None;
            let mut metadata = HashMap::new();
            for record in packet.all_resource_records() {
                if record.name.to_string() != want {
                    continue;
                }
                match &record.rdata {
                    PkRData::SRV(srv) => {
                        port = Some(srv.port);
                        target = Some(srv.target.to_string());
                    }
                    PkRData::TXT(txt) => {
                        for (k, v) in txt.attributes() {
                            if let Some(v) = v {
                                metadata.insert(k.to_string(), v.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }

            let target_name = target.as_deref()?;
            let mut ip = None;
            for record in packet.all_resource_records() {
                if record.name.to_string() != target_name {
                    continue;
                }
                match &record.rdata {
                    PkRData::A(a) => ip = Some(IpAddr::V4(a.address.into())),
                    PkRData::AAAA(aaaa) => ip = Some(IpAddr::V6(aaaa.address.into())),
                    _ => {}
                }
            }

            Some(DialkeyService {
                peer_addr: PeerAddr::new(peer_id(&dialkey), ip?.to_string(), port?),
                service: service.to_string(),
                metadata,
            })
        }
    }
}

// ── the public surface ───────────────────────────────────────────────────────────────────────

/// Publish one or more services under a dialkey.
///
/// All services share the same IP address (the sidecar's host). Each service gets its own SRV
/// record (port) and TXT record (metadata), in **one** packet: a record carries a single sequence
/// number, so publishing two services separately makes the second overwrite the first and the
/// loser then resolves as absent.
///
/// # Errors
/// Whatever the client reports — no relay accepted the record, or the records did not fit BEP44's
/// value limit.
pub async fn publish<C: DialkeyTransport>(
    client: &C,
    dialkey: &str,
    ip: IpAddr,
    services: &[DialkeyServiceInfo],
) -> Result<(), C::Error> {
    client.publish_services(dialkey, ip, services).await
}

/// Resolve a service advertised under a dialkey.
///
/// Returns a `DialkeyService` containing the `PeerAddr` (peer_id + host + port) and any metadata
/// published in the service TXT record. `None` when no relay holds a record that verifies under
/// the dialkey's own key — an unverifiable answer is discarded rather than returned.
pub async fn resolve<C: DialkeyTransport>(
    client: &C,
    dialkey: &str,
    service: &str,
) -> Option<DialkeyService> {
    client.resolve_service(dialkey, service).await
}

/// Build an opsfold service advertisement.
#[must_use]
pub fn opsfold_service(port: u16, region: &str) -> DialkeyServiceInfo {
    opsfold_service_with_path(port, region, OPSFOLD_PATH)
}

/// Build an ops-plane service advertisement whose HTTP surface is a path other
/// than the gateway — e.g. webhook-delivery publishing its `/metrics` so the
/// mesh can resolve it without any peer-side configuration.
#[must_use]
pub fn opsfold_service_with_path(port: u16, region: &str, path: &str) -> DialkeyServiceInfo {
    let mut metadata = HashMap::new();
    metadata.insert("region".to_string(), region.to_string());
    metadata.insert("path".to_string(), path.to_string());
    DialkeyServiceInfo { service: OPSFOLD_SERVICE.to_string(), port, metadata }
}

/// Build a billing service advertisement.
#[must_use]
pub fn billing_service(port: u16, tenant: &str) -> DialkeyServiceInfo {
    let mut metadata = HashMap::new();
    metadata.insert("tenant".to_string(), tenant.to_string());
    metadata.insert("path".to_string(), BILLING_PATH.to_string());
    DialkeyServiceInfo { service: BILLING_SERVICE.to_string(), port, metadata }
}

/// The Lyrium scenario-ingestion service — a Lyrium worker (or whatever runs
/// `lyrium::scenario::run_bounded`) publishes discovery under this type so a peer can find where
/// to POST a serialized `RunResult` without hardcoded configuration, the same shape
/// [`opsfold_service`] already gives the ops-plane mesh. `path` is the fixed prefix; the one
/// existing handler at this surface (`opsfold::integrations::twin_http::http_router`) appends
/// `/services/simulate/{subject_id}` — the id trails as a `*id` wildcard segment because a
/// canonical subject id contains literal `/` (`scope/kind/key`).
pub const LYRIUM_SIM_SERVICE: &str = "_lyrium-sim._tcp";
const LYRIUM_SIM_PATH: &str = "/api/twin";

/// Build a Lyrium scenario-ingestion service advertisement.
#[must_use]
pub fn lyrium_sim_service(port: u16, region: &str) -> DialkeyServiceInfo {
    let mut metadata = HashMap::new();
    metadata.insert("region".to_string(), region.to_string());
    metadata.insert("path".to_string(), LYRIUM_SIM_PATH.to_string());
    DialkeyServiceInfo { service: LYRIUM_SIM_SERVICE.to_string(), port, metadata }
}

// ── mesh-model service ────────────────────────────────────────────────────────────────────

/// The mesh model service name for dialkey-published peers.
pub const MESH_MODEL_SERVICE: &str = "_mesh-model._tcp";

/// Build a mesh-model service advertisement for dialkey publishing.
/// `metadata` is key-value pairs describing the peer's capabilities.
#[must_use]
pub fn mesh_model_service(port: u16, metadata: &[(String, String)]) -> DialkeyServiceInfo {
    DialkeyServiceInfo {
        service: MESH_MODEL_SERVICE.to_string(),
        port,
        metadata: metadata.iter().cloned().collect(),
    }
}

/// Resolve a mesh-model service from a dialkey.
pub async fn resolve_mesh_model<C: DialkeyTransport>(
    client: &C,
    dialkey: &str,
) -> Option<DialkeyService> {
    resolve(client, dialkey, MESH_MODEL_SERVICE).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialkey_peer_id_is_deterministic() {
        let a = peer_id("meteroid");
        let b = peer_id("meteroid");
        assert_eq!(a, b);
    }

    #[test]
    fn dialkey_peer_id_differs_by_dialkey() {
        let a = peer_id("meteroid");
        let b = peer_id("flexprice");
        assert_ne!(a, b);
    }

    #[test]
    fn opsfold_service_with_path_carries_the_real_surface() {
        let svc = opsfold_service_with_path(8092, "default", "/metrics");
        assert_eq!(svc.service, OPSFOLD_SERVICE);
        assert_eq!(svc.port, 8092);
        assert_eq!(svc.metadata.get("path").map(|s| s.as_str()), Some("/metrics"));
        assert_eq!(svc.metadata.get("region").map(|s| s.as_str()), Some("default"));
    }

    #[test]
    fn lyrium_sim_service_advertises_the_twin_http_prefix() {
        let svc = lyrium_sim_service(8093, "tas-cloud");
        assert_eq!(svc.service, LYRIUM_SIM_SERVICE);
        assert_eq!(svc.port, 8093);
        assert_eq!(svc.metadata.get("path").map(|s| s.as_str()), Some(LYRIUM_SIM_PATH));
        assert_eq!(svc.metadata.get("region").map(|s| s.as_str()), Some("tas-cloud"));
    }

    /// The identity must not move: `native_keypair` and the legacy `keypair` are the same seed,
    /// and the seed is the published name. A divergence here renames every live endpoint.
    #[test]
    fn the_native_keypair_matches_the_documented_derivation() {
        let expect = hashtrinity::crypto::sha256(b"meteroid:pkarr");
        assert_eq!(secret_seed_do_not_expose("meteroid"), expect);
        assert_eq!(
            native_keypair("meteroid").to_z32(),
            super::super::pkarr::keypair_from_dialkey("meteroid").to_z32(),
            "dialkey and transport::pkarr must derive the same identity from one dialkey"
        );
    }

    // ── the `peer_id` contract, and the checker that guards it ───────────────────────────────
    //
    // `peer_id` once returned the secret seed. A test that says `assert_ne!(peer_id(k), seed)`
    // next to a hand-written broken function proves nothing about the real module, so the
    // contract is one checker, `check_peer_id_contract`, over a `Derivation` (the three functions
    // that together define a dialkey's identity). It is run on the real module and on mutants
    // built by wrapping or altering the real functions; the real one must be `Ok` and every
    // mutant must be `Err` for the property the mutation breaks.

    /// A literal TEST dialkey — not a real credential — and the values the pre-fix code derived
    /// from it on main 30fdaf7 (captured before this change): the seed, its Ed25519 public key,
    /// and that key's z-base32 form, which is the label `build_packet` publishes under.
    const GOLDEN_DIALKEY: &str = "g17-test-dialkey";
    const GOLDEN_SEED_HEX: &str = "f312899db1b911aad45adc946d31875a58e810242652eba4fac63966a3bad73e";
    const GOLDEN_PUBLIC_HEX: &str = "30966ac5fa1bdd49aec9b9101bf63359704d01dc00597f934f7d7bca9bc5c47b";
    const GOLDEN_Z32: &str = "gnmgitx4dxqwumsjzrebz7tumfar4yqhybcz9r4xxi7hig6fat7o";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The three functions that define a dialkey's identity: the public id, the secret seed it
    /// is derived from, and the name the dialkey publishes under.
    struct Derivation<'a> {
        peer_id: &'a dyn Fn(&str) -> PeerId,
        seed: &'a dyn Fn(&str) -> [u8; 32],
        published_label: &'a dyn Fn(&str) -> String,
    }

    /// Every violated property, by name. `Ok` only if none is.
    fn check_peer_id_contract(d: &Derivation<'_>) -> Result<(), Vec<&'static str>> {
        use hashtrinity::crypto::ed25519_pubkey;
        let mut bad = Vec::new();
        let keys = [GOLDEN_DIALKEY, "meteroid", "flexprice", "tas-edge", "k"];

        // Golden vectors: the only checks a coordinated mutation of all three functions cannot pass.
        if hex(&(d.seed)(GOLDEN_DIALKEY)) != GOLDEN_SEED_HEX {
            bad.push("golden-seed");
        }
        if hex(&(d.peer_id)(GOLDEN_DIALKEY)) != GOLDEN_PUBLIC_HEX {
            bad.push("golden-public-key");
        }
        if (d.published_label)(GOLDEN_DIALKEY) != GOLDEN_Z32 {
            bad.push("golden-published-name");
        }

        for k in keys {
            let (id, seed) = ((d.peer_id)(k), (d.seed)(k));
            if id == seed {
                bad.push("peer-id-is-the-secret-seed");
            }
            if id != ed25519_pubkey(&seed) {
                bad.push("peer-id-is-not-the-public-key-of-the-seed");
            }
            let label_of_id = super::super::signed_dns::PublicKey::from_bytes(&id).map(|p| p.to_z32()).ok();
            if label_of_id != Some((d.published_label)(k)) {
                bad.push("peer-id-does-not-name-the-published-endpoint");
            }
        }
        if (d.peer_id)("meteroid") == (d.peer_id)("flexprice") {
            bad.push("different-dialkeys-share-an-id");
        }
        if (d.peer_id)("meteroid") != (d.peer_id)("meteroid") {
            bad.push("not-deterministic");
        }

        bad.sort_unstable();
        bad.dedup();
        if bad.is_empty() { Ok(()) } else { Err(bad) }
    }

    /// The label `build_packet` really publishes under — not recomputed by the test.
    fn real_published_label(dialkey: &str) -> String {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        build_packet(dialkey, ip, &[opsfold_service(1, "r")], 1).unwrap().public_key().to_z32()
    }

    #[test]
    fn the_real_dialkey_module_satisfies_the_peer_id_contract() {
        let real = Derivation {
            peer_id: &peer_id,
            seed: &secret_seed_do_not_expose,
            published_label: &real_published_label,
        };
        assert_eq!(check_peer_id_contract(&real), Ok(()));
    }

    /// Each mutant wraps or alters the real functions and goes through the SAME checker.
    #[test]
    fn the_checker_rejects_mutants_of_the_real_module() {
        use hashtrinity::crypto::{ed25519_pubkey, sha256};
        let z32 = |id: PeerId| super::super::signed_dns::PublicKey::from_bytes(&id).unwrap().to_z32();
        // Run one mutant: replace some of the real functions, keep the rest real.
        let run = |peer: &dyn Fn(&str) -> PeerId,
                   seed: &dyn Fn(&str) -> [u8; 32],
                   label: &dyn Fn(&str) -> String| {
            check_peer_id_contract(&Derivation { peer_id: peer, seed, published_label: label })
        };
        let rejected = |r: Result<(), Vec<&'static str>>, must_flag: &str| {
            let flagged = r.expect_err("mutant must be rejected");
            assert!(flagged.iter().any(|f| *f == must_flag), "flagged {flagged:?}, expected {must_flag}");
        };

        // 1. The original bug: peer_id hands back the secret seed.
        rejected(
            run(&secret_seed_do_not_expose, &secret_seed_do_not_expose, &real_published_label),
            "peer-id-is-the-secret-seed",
        );
        // 2. The public key of a DIFFERENT derivation (another suffix).
        let other_suffix = |k: &str| ed25519_pubkey(&sha256(format!("{k}:other").as_bytes()));
        rejected(
            run(&other_suffix, &secret_seed_do_not_expose, &real_published_label),
            "peer-id-is-not-the-public-key-of-the-seed",
        );
        // 3. The `:pkarr` suffix dropped from peer_id only.
        let no_suffix_id = |k: &str| ed25519_pubkey(&sha256(k.as_bytes()));
        rejected(
            run(&no_suffix_id, &secret_seed_do_not_expose, &real_published_label),
            "golden-public-key",
        );
        // 4. The suffix dropped EVERYWHERE, consistently — internally coherent, so only the golden
        //    vectors can reject it, and they are what pins the already-published endpoint names.
        let no_suffix_seed = |k: &str| sha256(k.as_bytes());
        let no_suffix_label = |k: &str| z32(ed25519_pubkey(&sha256(k.as_bytes())));
        let flagged = run(&no_suffix_id, &no_suffix_seed, &no_suffix_label).unwrap_err();
        assert!(flagged.contains(&"golden-seed") && flagged.contains(&"golden-published-name"), "{flagged:?}");
        // 5. peer_id right, but the endpoint is published under a different name.
        rejected(
            run(&peer_id, &secret_seed_do_not_expose, &no_suffix_label),
            "peer-id-does-not-name-the-published-endpoint",
        );
        // 6. Every dialkey collapses to one id.
        let constant = |_: &str| peer_id(GOLDEN_DIALKEY);
        rejected(
            run(&constant, &secret_seed_do_not_expose, &real_published_label),
            "different-dialkeys-share-an-id",
        );
        // 7. The public key with one bit flipped (the right derivation, corrupted on the way out).
        let flipped = |k: &str| {
            let mut id = peer_id(k);
            id[31] ^= 1;
            id
        };
        rejected(
            run(&flipped, &secret_seed_do_not_expose, &real_published_label),
            "peer-id-is-not-the-public-key-of-the-seed",
        );
    }

    /// The independent cross-check on the golden vectors: the secret seed is the documented
    /// `SHA-256(dialkey ++ ":pkarr")` and its public key is `peer_id`.
    #[test]
    fn peer_id_is_the_public_key_not_the_secret_for_the_golden_dialkey() {
        let seed = hashtrinity::crypto::sha256(format!("{GOLDEN_DIALKEY}:pkarr").as_bytes());
        assert_eq!(hex(&seed), GOLDEN_SEED_HEX);
        let id = peer_id(GOLDEN_DIALKEY);
        assert_eq!(hex(&id), GOLDEN_PUBLIC_HEX);
        assert_ne!(id, seed);
        assert_eq!(id, *native_keypair(GOLDEN_DIALKEY).public_key().as_bytes());
        assert_eq!(native_keypair(GOLDEN_DIALKEY).to_z32(), GOLDEN_Z32);
    }

    /// The names already published must not move: the packet's record labels are
    /// `<service>.<z32 of the public key>` and the apex is the bare z32 label.
    #[test]
    fn the_published_endpoint_names_are_unchanged() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let packet = build_packet(GOLDEN_DIALKEY, ip, &[opsfold_service(8081, "r")], 1).unwrap();
        assert_eq!(packet.public_key().to_z32(), GOLDEN_Z32);
        let names: Vec<String> = packet
            .records()
            .iter()
            .map(|r| r.name.to_ascii())
            .collect();
        assert!(names.contains(&format!("{OPSFOLD_SERVICE}.{GOLDEN_Z32}.")), "{names:?}");
        assert!(names.contains(&format!("{GOLDEN_Z32}.")), "{names:?}");
    }

    /// The leak path the bug opened: a resolved service stamps `peer_id(dialkey)` into its
    /// `PeerAddr`, which consumers log, store and gossip (`PeerAddr::to_string` embeds the id).
    /// Neither the string form nor `Debug` of what `resolve` returns may contain the seed.
    #[test]
    fn a_resolved_peer_addr_carries_the_public_id_and_never_the_seed() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let packet = build_packet(GOLDEN_DIALKEY, ip, &[opsfold_service(8081, "r")], 1).unwrap();
        let svc = service_from_packet(&packet, GOLDEN_DIALKEY, OPSFOLD_SERVICE).unwrap();
        assert_eq!(hex(&svc.peer_addr.peer_id), GOLDEN_PUBLIC_HEX);
        for rendered in [svc.peer_addr.to_string(), format!("{:?}", svc), format!("{:?}", svc.peer_addr)] {
            assert!(!rendered.contains(GOLDEN_SEED_HEX), "seed leaked into {rendered}");
        }
        assert!(svc.peer_addr.to_string().contains(GOLDEN_PUBLIC_HEX));
    }

    /// The round trip the module exists for: publish-shaped records go in, a resolved
    /// `DialkeyService` comes out, with host, port and metadata intact.
    #[test]
    fn a_dialkey_record_round_trips_through_the_signed_packet() {
        let services = vec![opsfold_service(8081, "tas-cloud"), billing_service(8092, "acme")];
        let ip: IpAddr = "10.7.46.107".parse().unwrap();
        let packet = build_packet("meteroid", ip, &services, 1_700_000_000_000_000).unwrap();

        let ops = service_from_packet(&packet, "meteroid", OPSFOLD_SERVICE).unwrap();
        assert_eq!(ops.peer_addr.host, "10.7.46.107");
        assert_eq!(ops.peer_addr.port, 8081);
        assert_eq!(ops.peer_addr.peer_id, peer_id("meteroid"));
        assert_eq!(ops.metadata.get("region").map(String::as_str), Some("tas-cloud"));
        assert_eq!(ops.metadata.get("path").map(String::as_str), Some(OPSFOLD_PATH));

        let bill = service_from_packet(&packet, "meteroid", BILLING_SERVICE).unwrap();
        assert_eq!(bill.peer_addr.port, 8092);
        assert_eq!(bill.metadata.get("tenant").map(String::as_str), Some("acme"));
    }

    /// Two services in one packet, one apex address. A second copy is wasted bytes against
    /// BEP44's 1000-byte ceiling, which is exactly what multi-service publishes press on.
    #[test]
    fn the_apex_address_appears_once_per_packet() {
        let services = vec![opsfold_service(8081, "r"), billing_service(8092, "t")];
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let packet = build_packet("k", ip, &services, 1).unwrap();
        let addrs = packet
            .records()
            .iter()
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_)))
            .count();
        assert_eq!(addrs, 1, "one host, one address record");
    }

    /// A resolved record is only believed under the key that published it — the whole point of
    /// naming a service by its key.
    #[test]
    fn a_record_does_not_resolve_under_a_different_dialkey() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let packet = build_packet("real", ip, &[opsfold_service(80, "r")], 1).unwrap();
        assert!(service_from_packet(&packet, "real", OPSFOLD_SERVICE).is_some());
        assert!(
            service_from_packet(&packet, "impostor", OPSFOLD_SERVICE).is_none(),
            "the service label embeds the publisher's key, so another dialkey must not match"
        );
    }

    /// Metadata order must not leak `HashMap` iteration order into the signed bytes: the same
    /// inputs must produce the same packet.
    #[test]
    fn the_encoding_is_deterministic_across_runs() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let svc = |()| {
            let mut m = HashMap::new();
            m.insert("z".to_string(), "1".to_string());
            m.insert("a".to_string(), "2".to_string());
            m.insert("m".to_string(), "3".to_string());
            vec![DialkeyServiceInfo { service: "_x._tcp".to_string(), port: 1, metadata: m }]
        };
        let a = build_packet("k", ip, &svc(()), 7).unwrap();
        let b = build_packet("k", ip, &svc(()), 7).unwrap();
        assert_eq!(a.to_relay_bytes(), b.to_relay_bytes());
    }

    /// BEP44's value limit is a real ceiling on services-per-dialkey. It must be refused, not
    /// silently truncated into a record advertising fewer services than the caller asked for.
    #[test]
    fn too_many_services_is_an_error_not_a_truncation() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let many: Vec<DialkeyServiceInfo> = (0..100)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("path".to_string(), format!("/surface/{i}/with/a/long/tail"));
                DialkeyServiceInfo { service: format!("_svc{i}._tcp"), port: 1000 + i, metadata: m }
            })
            .collect();
        assert_eq!(
            build_packet("k", ip, &many, 1).unwrap_err(),
            super::super::signed_dns::SignedDnsError::ValueTooLong
        );
    }

    /// The interop test that settles whether the native path can talk to real-`pkarr` peers:
    /// the same dialkey must derive the same public name under both stacks. If this ever fails,
    /// every record published by a migrated node becomes invisible to an unmigrated one.
    #[cfg(feature = "federation")]
    #[test]
    fn the_native_and_pkarr_identities_are_the_same_name() {
        for dk in ["meteroid", "tas-edge", "notify-plane"] {
            assert_eq!(
                native_keypair(dk).to_z32(),
                keypair(dk).public_key().to_string(),
                "z-base32 label must match the pkarr crate's for dialkey {dk}"
            );
            // Independent of this crate's own Ed25519: the real `pkarr` crate's public key bytes
            // are `peer_id`, and are not the seed.
            assert_eq!(&peer_id(dk), keypair(dk).public_key().as_bytes(), "peer_id for {dk}");
            assert_ne!(peer_id(dk), secret_seed_do_not_expose(dk), "peer_id must not be the seed");
        }
    }

    /// BEP44 preimage compatibility: the bytes the native stack signs are the bytes the `pkarr`
    /// crate signs, so a signature made by either verifies under the other.
    #[cfg(feature = "federation")]
    #[test]
    fn a_native_signature_verifies_as_a_pkarr_signature() {
        use pkarr::SignedPacket as PkSignedPacket;
        let ip: IpAddr = "10.7.46.107".parse().unwrap();
        let native = build_packet("meteroid", ip, &[opsfold_service(8081, "tas-cloud")], 42)
            .unwrap();
        let wire = native.to_relay_bytes();

        // The pkarr crate parses and verifies the native relay payload against the same key.
        let pk = keypair("meteroid").public_key();
        let parsed = PkSignedPacket::from_relay_payload(&pk, &wire.clone().into());
        assert!(
            parsed.is_ok(),
            "the pkarr crate must accept a natively-signed relay payload: {:?}",
            parsed.err()
        );
        let parsed = parsed.unwrap();
        assert_eq!(parsed.timestamp().as_u64(), 42, "seq must survive the crossing");
    }
}
