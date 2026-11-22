#![expect(
    clippy::unwrap_used,
    clippy::panic,
    dead_code,
    reason = "shared test helpers; each test binary uses a subset"
)]
//! Shared helpers: build zones and independently validate DNSSEC with hickory's verifier.

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::Verifier;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, RrKey};
use std::collections::BTreeMap;
use tas_dns::build::{build_zone, ServerIdentity, SignedZone, Timings};
use tas_dns::keys::KeyProvider;
use tas_dns::names::{parse_fqdn, wire_id};
use tas_dns::records::ZoneLimits;
use tas_dns::zone::{hex32, DnssecPolicy, Registration, Zone};

pub const T0: u64 = 1_800_000_000;

pub fn identity() -> ServerIdentity {
    ServerIdentity {
        nameservers: vec![
            parse_fqdn("ns1.tas.example").unwrap(),
            parse_fqdn("ns2.tas.example").unwrap(),
        ],
        hostmaster: parse_fqdn("hostmaster.tas.example").unwrap(),
        soa_minimum: 300,
        ns_ttl: 3600,
    }
}

pub const BODY: &str = r#"{"records":[
 {"name":"www","ttl":300,"type":"A","data":"198.51.100.10"},
 {"name":"www","ttl":300,"type":"AAAA","data":"2001:db8::10"},
 {"name":"@","ttl":300,"type":"MX","data":{"preference":10,"exchange":"mail.acme.example"}},
 {"name":"@","ttl":300,"type":"CAA","data":{"flags":0,"tag":"issue","value":"letsencrypt.org"}},
 {"name":"*.dev","ttl":300,"type":"A","data":"198.51.100.20"},
 {"name":"api","ttl":300,"type":"CNAME","data":"www.acme.example"},
 {"name":"a.b.c","ttl":300,"type":"TXT","data":["empty non-terminals above"]}
]}"#;

pub fn registration(apex: &str, policy: Option<DnssecPolicy>) -> Registration {
    let dn = match policy {
        Some(p) => format!(
            r#","dnssec":{{"ksk_gen":{},"ksk_next":{},"origin":{}}}"#,
            p.ksk_gen,
            p.ksk_next.map_or("null".to_string(), |n| n.to_string()),
            p.origin
        ),
        None => String::new(),
    };
    let body = format!(
        r#"{{"apex":"{apex}","tenant":"acme","owner":"{}","state":"active"{dn}}}"#,
        hex32(&[9u8; 32])
    );
    Registration::parse(&wire_id(&parse_fqdn(apex).unwrap()), 1, 1, body.as_bytes()).unwrap()
}

pub fn zone(apex: &str, version: u64, policy: Option<DnssecPolicy>) -> Zone {
    let reg = registration(apex, policy);
    Zone::from_update(&reg, 1, version, BODY.as_bytes(), &ZoneLimits::default()).unwrap()
}

pub fn build(z: &Zone, keys: &dyn KeyProvider, t: &Timings, now: u64) -> SignedZone {
    build_zone(z, &identity(), Some(keys), t, now).unwrap()
}

pub fn rrset<'a>(
    z: &'a SignedZone,
    name: &str,
    ty: RecordType,
) -> &'a hickory_proto::rr::RecordSet {
    let n = parse_fqdn(name).unwrap();
    z.records
        .get(&RrKey::new(n.into(), ty))
        .unwrap_or_else(|| panic!("no {ty} at {name}"))
}

pub fn dnskeys(z: &SignedZone) -> Vec<DNSKEY> {
    rrset(z, &z.origin.to_ascii(), RecordType::DNSKEY)
        .records_without_rrsigs()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect()
}

pub fn rrsigs_of(set: &hickory_proto::rr::RecordSet) -> Vec<RRSIG> {
    set.rrsigs()
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

/// Validate every `RRSIG` on `set` against `keys` (a DNSKEY `RRset` as a validator would hold it) at
/// time `at`: at least one signature must verify under a zone key whose tag matches, be inside
/// its validity window, and `require_sep` demands the signer is a KSK. Returns the number of
/// signatures that verified.
pub fn validate(
    set: &hickory_proto::rr::RecordSet,
    keys: &[DNSKEY],
    at: u64,
    require_sep: Option<bool>,
) -> usize {
    let records: Vec<Record> = set.records_without_rrsigs().cloned().collect();
    let mut ok = 0;
    for sig in rrsigs_of(set) {
        let inp = sig.input();
        let inception = u64::from(inp.sig_inception.get());
        let expiration = u64::from(inp.sig_expiration.get());
        if at < inception || at > expiration {
            continue;
        }
        for k in keys {
            if !k.zone_key() || k.calculate_key_tag().unwrap() != inp.key_tag {
                continue;
            }
            if let Some(sep) = require_sep {
                if k.secure_entry_point() != sep {
                    continue;
                }
            }
            if k.verify_rrsig(set.name(), DNSClass::IN, &sig, records.iter())
                .is_ok()
            {
                ok += 1;
            }
        }
    }
    ok
}

pub fn all_sets(z: &SignedZone) -> BTreeMap<(String, RecordType), &hickory_proto::rr::RecordSet> {
    z.records
        .iter()
        .map(|(k, v)| ((Name::from(k.name.clone()).to_ascii(), k.record_type), v))
        .collect()
}

// ── live node harness ────────────────────────────────────────────────────────────────────────

use hickory_net::client::Client;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tas_dns::db::{DbConfig, ZoneDb};
use tas_dns::keys::DerivedKeyProvider;
use tas_dns::metrics::Metrics;
use tas_dns::node::Node;
use tas_dns::objects::{registration_object, update_object, RegistrationSpec};
use tas_dns::server::{serve_tcp, serve_udp, ServerCtx, ServerLimits};
use tas_dns::store::MemoryObjectStore;
use tas_dns::zone::RegState;
use tokio::net::{TcpListener, UdpSocket};
use transport::signed_dns::Keypair;
use transport::zone_sync::ApplyOutcome;

pub fn kp(n: u8) -> Keypair {
    Keypair::from_secret_key(&[n; 32])
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct TestNode {
    pub node: Arc<Node>,
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub registrar: Keypair,
    pub challenge_key: Keypair,
    pub shutdown: tokio::sync::watch::Sender<bool>,
    pub metrics: Arc<Metrics>,
    pub clock: Arc<AtomicU64>,
    pub ctx: Arc<ServerCtx>,
    pub keys: Arc<DerivedKeyProvider>,
    seq: AtomicU64,
}

pub async fn start(limits: ServerLimits) -> TestNode {
    start_with(limits, true).await
}

pub async fn start_with(limits: ServerLimits, with_keys: bool) -> TestNode {
    let registrar = kp(1);
    let challenge_key = kp(2);
    let mut cfg = DbConfig::new(*registrar.public_key().as_bytes());
    cfg.challenge_zone = Some(parse_fqdn("chal.tas.example").unwrap());
    cfg.challenge_authority = Some(*challenge_key.public_key().as_bytes());
    let clock = Arc::new(AtomicU64::new(unix_now()));
    let c2 = clock.clone();
    let clk: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || c2.load(Ordering::SeqCst));
    let metrics = Arc::new(Metrics::default());
    let (db, _) = ZoneDb::open(
        cfg,
        Arc::new(MemoryObjectStore::new()),
        metrics.clone(),
        clk.clone(),
    )
    .unwrap();
    let keys = Arc::new(DerivedKeyProvider::random().unwrap());
    let provider: Option<Arc<dyn KeyProvider>> = if with_keys { Some(keys.clone()) } else { None };
    let node = Node::new(
        Arc::new(db),
        metrics.clone(),
        identity(),
        Timings::default(),
        provider,
        clk,
    );
    let ctx = ServerCtx::new(node.serving.clone(), metrics.clone(), limits);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(serve_udp(Arc::new(udp), ctx.clone(), rx.clone()));
    tokio::spawn(serve_tcp(tcp, ctx.clone(), rx));
    TestNode {
        node,
        udp: udp_addr,
        tcp: tcp_addr,
        registrar,
        challenge_key,
        shutdown: tx,
        metrics,
        clock,
        ctx,
        keys,
        seq: AtomicU64::new(1),
    }
}

impl TestNode {
    /// Register `apex` for `tenant` (owner key `owner`), publish `body` as version `version`, and serve it.
    pub fn add_zone(
        &self,
        apex: &str,
        tenant: &str,
        owner: &Keypair,
        version: u64,
        body: &str,
        policy: Option<DnssecPolicy>,
    ) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let spec = RegistrationSpec {
            apex,
            tenant,
            owner: *owner.public_key().as_bytes(),
            owner_epoch: 1,
            seq,
            state: RegState::Active,
            quarantine_until: 0,
            dnssec: policy,
        };
        assert_eq!(
            self.node
                .db
                .apply_object(registration_object(&self.registrar, &spec).unwrap()),
            ApplyOutcome::Applied
        );
        assert_eq!(
            self.node
                .db
                .apply_object(update_object(owner, apex, 1, version, body.as_bytes()).unwrap()),
            ApplyOutcome::Applied
        );
        self.node.rebuild_zone(
            &parse_fqdn(apex).unwrap(),
            self.clock.load(Ordering::SeqCst),
        );
    }
}

pub fn udp_client(addr: SocketAddr) -> Client<TokioRuntimeProvider> {
    let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
    let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(conn);
    tokio::spawn(bg);
    client
}

pub async fn tcp_client(addr: SocketAddr) -> Client<TokioRuntimeProvider> {
    let (fut, sender) = TcpClientStream::new(
        addr,
        None,
        Some(std::time::Duration::from_secs(5)),
        TokioRuntimeProvider::default(),
    );
    let (client, bg) = Client::<TokioRuntimeProvider>::new(fut.await.unwrap(), sender);
    tokio::spawn(bg);
    client
}

/// Raw query packet.
pub fn query_packet(
    id: u16,
    name: &str,
    ty: RecordType,
    edns: Option<(u16, bool)>,
    rd: bool,
) -> Vec<u8> {
    use hickory_proto::op::Edns;
    use hickory_proto::serialize::binary::BinEncodable;
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = rd;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), ty));
    if let Some((size, dnssec_ok)) = edns {
        let mut e = Edns::new();
        e.set_max_payload(size);
        e.set_dnssec_ok(dnssec_ok);
        m.set_edns(e);
    }
    m.to_bytes().unwrap()
}

pub fn parse(bytes: &[u8]) -> Message {
    use hickory_proto::serialize::binary::BinDecodable;
    Message::from_bytes(bytes).unwrap()
}

/// One UDP exchange from a fresh socket; `None` if no reply within `wait_ms`.
pub async fn udp_exchange(server: SocketAddr, pkt: &[u8], wait_ms: u64) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(pkt, server).await.unwrap();
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(
        std::time::Duration::from_millis(wait_ms),
        s.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// One TCP exchange (length-prefixed) on a fresh connection.
pub async fn tcp_exchange(server: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(server).await.ok()?;
    let mut framed = u16::try_from(pkt.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(pkt);
    s.write_all(&framed).await.ok()?;
    let mut l = [0u8; 2];
    tokio::time::timeout(std::time::Duration::from_secs(3), s.read_exact(&mut l))
        .await
        .ok()?
        .ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(l))];
    tokio::time::timeout(std::time::Duration::from_secs(3), s.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    Some(body)
}

pub fn msg_type_is_response(m: &Message) -> bool {
    m.metadata.message_type == MessageType::Response
}

pub fn op_notify() -> OpCode {
    OpCode::Notify
}
