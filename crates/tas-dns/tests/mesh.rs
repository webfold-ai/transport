#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tas_dns::challenge_auth::{ChallengeAuthority, MeshPublisher};
use tas_dns::db::{DbConfig, ZoneDb};
use tas_dns::mesh::{self, MeshConfig};
use tas_dns::metrics::Metrics;
use tas_dns::node::Node;
use tas_dns::objects::{registration_object, update_object, RegistrationSpec};
use tas_dns::server::{serve_tcp, serve_udp, ServerCtx, ServerLimits};
use tas_dns::store::{FileObjectStore, MemoryObjectStore, ObjectStore};
use tas_dns::zone::{RegState, TenantId};
use tokio::net::{TcpListener, UdpSocket};
use transport::dialkey;
use transport::native::NativeEndpoint;
use transport::zone_sync::{
    root_of, ApplyOutcome, ObjectKind, PeerPolicy, SessionLimits, SignedObject, SyncClient,
    SyncStore,
};
use transport::{PeerAddr, Transport};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct MeshNode {
    udp: std::net::SocketAddr,
    db: Arc<ZoneDb>,
    mesh: mesh::Mesh,
    addr: PeerAddr,
    stop: tokio::sync::watch::Sender<bool>,
    _node: Arc<Node>,
}

async fn spawn_node(
    dialkey: &str,
    port: u16,
    peers: Vec<PeerAddr>,
    publishers: Vec<[u8; 32]>,
    store: Arc<dyn ObjectStore>,
) -> MeshNode {
    spawn_node_pulling(
        dialkey,
        port,
        peers,
        publishers,
        store,
        Duration::from_millis(150),
    )
    .await
}

async fn spawn_node_pulling(
    dialkey: &str,
    port: u16,
    peers: Vec<PeerAddr>,
    publishers: Vec<[u8; 32]>,
    store: Arc<dyn ObjectStore>,
    pull_interval: Duration,
) -> MeshNode {
    let mut cfg = DbConfig::new(*kp(1).public_key().as_bytes());
    cfg.challenge_zone = Some(tas_dns::names::parse_fqdn("chal.tas.example").unwrap());
    cfg.challenge_authority = Some(*kp(2).public_key().as_bytes());
    let metrics = Arc::new(Metrics::default());
    let clk: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix_now);
    let (db, _) = ZoneDb::open(cfg, store, metrics.clone(), clk.clone()).unwrap();
    let db = Arc::new(db);
    let node = Node::new(
        db.clone(),
        metrics.clone(),
        identity(),
        tas_dns::build::Timings::default(),
        None,
        clk,
    );
    node.rebuild_all();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(node.clone().run(db.subscribe(), rx.clone()));
    let ctx = ServerCtx::new(
        node.serving.clone(),
        metrics.clone(),
        ServerLimits::default(),
    );
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    tokio::spawn(serve_udp(Arc::new(udp), ctx.clone(), rx.clone()));
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve_tcp(tcp, ctx, rx.clone()));
    let mesh = mesh::start(
        db.clone(),
        metrics,
        MeshConfig {
            bind: format!("127.0.0.1:{port}"),
            dialkey: dialkey.to_string(),
            peers,
            publishers,
            pull_interval,
            io_timeout: Duration::from_secs(3),
            limits: SessionLimits::default(),
        },
        rx,
    )
    .await
    .unwrap();
    let addr = PeerAddr::new(mesh.id, "127.0.0.1", port);
    MeshNode {
        udp: udp_addr,
        db,
        mesh,
        addr,
        stop,
        _node: node,
    }
}

fn spec<'a>(
    apex: &'a str,
    tenant: &'a str,
    owner: &transport::signed_dns::Keypair,
    seq: u64,
) -> RegistrationSpec<'a> {
    RegistrationSpec {
        apex,
        tenant,
        owner: *owner.public_key().as_bytes(),
        owner_epoch: 1,
        seq,
        state: RegState::Active,
        quarantine_until: 0,
        dnssec: None,
    }
}

fn body(ip: &str) -> Vec<u8> {
    format!(r#"{{"records":[{{"name":"www","ttl":300,"type":"A","data":"{ip}"}}]}}"#).into_bytes()
}

async fn www(node: &MeshNode) -> Option<String> {
    let r = parse(
        &udp_exchange(
            node.udp,
            &query_packet(1, "www.acme.example.", RecordType::A, None, false),
            500,
        )
        .await?,
    );
    r.answers.iter().find_map(|a| match &a.data {
        RData::A(ip) => Some(ip.0.to_string()),
        _ => None,
    })
}

async fn eventually<F: std::future::Future<Output = bool>>(mut f: impl FnMut() -> F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not reached in 10 s");
}

async fn client(dialkey: &str) -> (SyncClient, [u8; 32]) {
    let ep = Arc::new(
        NativeEndpoint::bind_with_dialkey("127.0.0.1:0", dialkey)
            .await
            .unwrap(),
    );
    let id = Transport::id(&*ep);
    (SyncClient::new(ep, Duration::from_secs(3)), id)
}

struct Evil(Vec<SignedObject>);
impl SyncStore for Evil {
    fn summaries(
        &self,
        after: Option<transport::zone_sync::SummaryKey>,
        limit: usize,
    ) -> Vec<transport::zone_sync::Summary> {
        let mut v: Vec<_> = self
            .0
            .iter()
            .map(SignedObject::summary)
            .filter(|s| after.is_none_or(|a| s.key() > a))
            .collect();
        v.sort_by_key(transport::zone_sync::Summary::key);
        v.truncate(limit);
        v
    }
    fn get(&self, kind: ObjectKind, h: &[u8; 32]) -> Option<SignedObject> {
        self.0
            .iter()
            .find(|o| o.kind() == kind && &o.id_hash() == h)
            .cloned()
    }
    fn apply(&self, _o: SignedObject, _f: [u8; 32]) -> ApplyOutcome {
        ApplyOutcome::Invalid
    }
}

#[tokio::test]
async fn zones_replicate_between_nodes_and_every_update_is_verified_on_arrival() {
    let (pub_client, pub_id) = client("publisher-dialkey").await;
    let (pa, pb) = (free_port(), free_port());
    let (ida, idb) = (dialkey::peer_id("node-a"), dialkey::peer_id("node-b"));
    let a = spawn_node(
        "node-a",
        pa,
        vec![PeerAddr::new(idb, "127.0.0.1", pb)],
        vec![pub_id],
        Arc::new(MemoryObjectStore::new()),
    )
    .await;
    let b = spawn_node(
        "node-b",
        pb,
        vec![PeerAddr::new(ida, "127.0.0.1", pa)],
        vec![pub_id],
        Arc::new(MemoryObjectStore::new()),
    )
    .await;
    assert_eq!(a.mesh.id, ida);

    let owner = dialkey::native_keypair("acme-owner-dialkey");
    let reg = registration_object(&kp(1), &spec("acme.example", "acme", &owner, 1)).unwrap();
    let v1 = update_object(&owner, "acme.example", 1, 1, &body("198.51.100.1")).unwrap();
    let out = pub_client.push(&a.addr, &[reg, v1.clone()]).await.unwrap();
    assert_eq!(out, vec![ApplyOutcome::Applied, ApplyOutcome::Applied]);
    // node B never heard from the publisher: it gets the zone from the mesh
    eventually(|| async { www(&b).await.as_deref() == Some("198.51.100.1") }).await;
    assert_eq!(www(&a).await.as_deref(), Some("198.51.100.1"));
    eventually(|| async { root_of(&*a.db) == root_of(&*b.db) }).await;

    // an update replicates too
    let v2 = update_object(&owner, "acme.example", 1, 2, &body("198.51.100.2")).unwrap();
    assert_eq!(
        pub_client
            .push(&b.addr, std::slice::from_ref(&v2))
            .await
            .unwrap(),
        vec![ApplyOutcome::Applied]
    );
    eventually(|| async { www(&a).await.as_deref() == Some("198.51.100.2") }).await;

    // rollback and replay of v1 against either node are refused and change nothing
    for n in [&a, &b] {
        assert_eq!(
            pub_client
                .push(&n.addr, std::slice::from_ref(&v1))
                .await
                .unwrap(),
            vec![ApplyOutcome::Stale]
        );
        assert_eq!(
            pub_client
                .push(&n.addr, std::slice::from_ref(&v2))
                .await
                .unwrap(),
            vec![ApplyOutcome::Duplicate]
        );
        assert_eq!(www(n).await.as_deref(), Some("198.51.100.2"));
    }
    // a fork (same version, different content) is refused and the first stands
    let fork = update_object(&owner, "acme.example", 1, 2, &body("203.0.113.66")).unwrap();
    assert_eq!(
        pub_client.push(&a.addr, &[fork]).await.unwrap(),
        vec![ApplyOutcome::Fork]
    );
    // an update signed by a different key
    let forged = update_object(&kp(77), "acme.example", 1, 50, &body("203.0.113.66")).unwrap();
    assert_eq!(
        pub_client.push(&a.addr, &[forged]).await.unwrap(),
        vec![ApplyOutcome::Unauthorized]
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(www(&a).await.as_deref(), Some("198.51.100.2"));
    assert_eq!(www(&b).await.as_deref(), Some("198.51.100.2"));
    let _ = (a.stop.send(true), b.stop.send(true));
}

#[tokio::test]
async fn a_compromised_mesh_peer_cannot_inject_forged_stale_or_forked_state() {
    let (pub_client, pub_id) = client("publisher-dialkey-2").await;
    let (evil_client, evil_id) = client("evil-peer-dialkey").await;
    let pb = free_port();
    // B trusts "evil" as a mesh PEER (worst case: an authenticated member turns hostile)
    let b = spawn_node(
        "node-b2",
        pb,
        vec![PeerAddr::new(evil_id, "127.0.0.1", free_port())],
        vec![pub_id],
        Arc::new(MemoryObjectStore::new()),
    )
    .await;
    let owner = kp(10);
    pub_client
        .push(
            &b.addr,
            &[
                registration_object(&kp(1), &spec("acme.example", "acme", &owner, 1)).unwrap(),
                update_object(&owner, "acme.example", 1, 5, &body("198.51.100.5")).unwrap(),
            ],
        )
        .await
        .unwrap();
    eventually(|| async { www(&b).await.as_deref() == Some("198.51.100.5") }).await;

    let attacker = kp(66);
    let evil_objects = vec![
        update_object(&attacker, "acme.example", 1, 99, &body("203.0.113.66")).unwrap(), // forged, higher version
        update_object(&owner, "acme.example", 1, 4, &body("203.0.113.66")).unwrap(),     // rollback
        update_object(&owner, "acme.example", 1, 5, &body("203.0.113.66")).unwrap(),     // fork
        update_object(&owner, "acme.example", 2, 6, &body("203.0.113.66")).unwrap(), // wrong epoch
        update_object(
            &owner,
            "acme.example",
            1,
            7,
            br#"{"records":[{"name":"@","ttl":300,"type":"NS","data":"ns.evil.example"}]}"#,
        )
        .unwrap(), // invalid content
        registration_object(&attacker, &spec("acme.example", "evil", &attacker, 2)).unwrap(), // registration not by the registrar
        registration_object(&attacker, &spec("new.example", "evil", &attacker, 1)).unwrap(),
    ];
    let outcomes = evil_client.push(&b.addr, &evil_objects).await.unwrap();
    assert_eq!(
        outcomes,
        vec![
            ApplyOutcome::Unauthorized,
            ApplyOutcome::Stale,
            ApplyOutcome::Fork,
            ApplyOutcome::Unauthorized,
            ApplyOutcome::Invalid,
            ApplyOutcome::Unauthorized,
            ApplyOutcome::Unauthorized,
        ]
    );
    assert_eq!(www(&b).await.as_deref(), Some("198.51.100.5"));
    assert!(b
        .db
        .registration(&tas_dns::names::parse_fqdn("new.example").unwrap())
        .is_none());
    assert_eq!(b.db.tenant_zone_count(&TenantId::new("evil").unwrap()), 0);

    // the pull path: the hostile peer SERVES a forged "newer" object and B fetches then refuses it
    let evil_ep = Arc::new(
        NativeEndpoint::bind_with_dialkey("127.0.0.1:0", "evil-peer-dialkey")
            .await
            .unwrap(),
    );
    let evil_port: u16 = Transport::local_addr(&*evil_ep)
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let policy = Arc::new(PeerPolicy::new().with_peer(b.mesh.id));
    tokio::spawn(transport::zone_sync::serve(
        evil_ep,
        Arc::new(Evil(evil_objects[..1].to_vec())),
        policy,
        SessionLimits::default(),
        rx,
    ));
    let report = b
        .mesh
        .client
        .pull(
            &PeerAddr::new(evil_id, "127.0.0.1", evil_port),
            &*b.mesh.store,
        )
        .await
        .unwrap();
    assert_eq!(
        (report.applied, report.rejected),
        (0, 1),
        "fetched and refused: {report:?}"
    );
    assert_eq!(www(&b).await.as_deref(), Some("198.51.100.5"));
    let _ = (tx.send(true), b.stop.send(true));
}

#[tokio::test]
async fn rollback_protection_survives_a_restart_and_unknown_identities_are_dropped() {
    let (pub_client, pub_id) = client("publisher-dialkey-3").await;
    let (stranger, _) = client("stranger-dialkey").await;
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(FileObjectStore::open(dir.path()).unwrap());
    let owner = kp(10);
    let v1 = update_object(&owner, "acme.example", 1, 1, &body("198.51.100.1")).unwrap();
    let v2 = update_object(&owner, "acme.example", 1, 2, &body("198.51.100.2")).unwrap();
    let p1 = free_port();
    let b = spawn_node("node-b3", p1, vec![], vec![pub_id], store.clone()).await;
    pub_client
        .push(
            &b.addr,
            &[
                registration_object(&kp(1), &spec("acme.example", "acme", &owner, 1)).unwrap(),
                v1.clone(),
                v2,
            ],
        )
        .await
        .unwrap();
    eventually(|| async { www(&b).await.as_deref() == Some("198.51.100.2") }).await;
    // a stranger (not a peer, not a publisher) is dropped before any request is read
    assert!(stranger
        .push(&b.addr, std::slice::from_ref(&v1))
        .await
        .is_err());
    let _ = b.stop.send(true);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // restart on the same disk
    let b2 = spawn_node(
        "node-b3",
        free_port(),
        vec![],
        vec![pub_id],
        Arc::new(FileObjectStore::open(dir.path()).unwrap()),
    )
    .await;
    assert_eq!(
        www(&b2).await.as_deref(),
        Some("198.51.100.2"),
        "state restored from signed objects"
    );
    assert_eq!(
        pub_client.push(&b2.addr, &[v1]).await.unwrap(),
        vec![ApplyOutcome::Stale],
        "the high-water mark survived the restart"
    );
    let _ = b2.stop.send(true);
}

#[tokio::test]
async fn a_dns01_token_is_served_by_every_nameserver_before_publish_returns_and_a_down_node_fails_closed(
) {
    let (ca_client, ca_id) = client("acme-worker-dialkey").await;
    let (pa, pb) = (free_port(), free_port());
    let (ida, idb) = (dialkey::peer_id("node-a4"), dialkey::peer_id("node-b4"));
    let a = spawn_node(
        "node-a4",
        pa,
        vec![PeerAddr::new(idb, "127.0.0.1", pb)],
        vec![ca_id],
        Arc::new(MemoryObjectStore::new()),
    )
    .await;
    let b = spawn_node(
        "node-b4",
        pb,
        vec![PeerAddr::new(ida, "127.0.0.1", pa)],
        vec![ca_id],
        Arc::new(MemoryObjectStore::new()),
    )
    .await;

    // the worker keeps its own replica and publishes to BOTH nameservers, requiring both
    let mut cfg = DbConfig::new(*kp(1).public_key().as_bytes());
    cfg.challenge_zone = Some(tas_dns::names::parse_fqdn("chal.tas.example").unwrap());
    cfg.challenge_authority = Some(*kp(2).public_key().as_bytes());
    let clk: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix_now);
    let (wdb, _) = ZoneDb::open(
        cfg,
        Arc::new(MemoryObjectStore::new()),
        Arc::new(Metrics::default()),
        clk.clone(),
    )
    .unwrap();
    let publisher = Arc::new(MeshPublisher::new(
        ca_client,
        vec![a.addr.clone(), b.addr.clone()],
        2,
    ));
    let auth = Arc::new(ChallengeAuthority::new(
        kp(2),
        tas_dns::names::parse_fqdn("chal.tas.example").unwrap(),
        Arc::new(wdb),
        publisher,
        clk,
    ));
    let tenant = TenantId::new("tenant-a").unwrap();
    let binding = auth.bind(&tenant, "acme.example").await.unwrap();
    let fq = format!("{}.", binding.target);
    let txt = |n: &MeshNode| {
        let (udp, fq) = (n.udp, fq.clone());
        async move {
            let r = parse(
                &udp_exchange(
                    udp,
                    &query_packet(3, &fq, RecordType::TXT, None, false),
                    500,
                )
                .await
                .unwrap(),
            );
            (r.metadata.response_code, r.answers.len())
        }
    };
    assert_eq!(txt(&a).await.0, ResponseCode::NXDomain);
    auth.publish_token(&tenant, "acme.example", "valueXYZ")
        .await
        .unwrap();
    // no waiting: publish returned only after both nodes held the token
    assert_eq!(txt(&a).await, (ResponseCode::NoError, 1));
    assert_eq!(txt(&b).await, (ResponseCode::NoError, 1));
    auth.clear_token(&tenant, "acme.example", "valueXYZ")
        .await
        .unwrap();
    assert_eq!(txt(&a).await.0, ResponseCode::NXDomain);
    assert_eq!(txt(&b).await.0, ResponseCode::NXDomain);

    // one nameserver down: the publish fails, so ACME does not proceed to validation
    let _ = b.stop.send(true);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(auth
        .publish_token(&tenant, "acme.example", "second")
        .await
        .is_err());
    let _ = a.stop.send(true);
    let _ = ida;
    let _ = Ordering::SeqCst;
}

#[tokio::test]
async fn publisher_pushes_are_forwarded_to_peers_without_waiting_for_anti_entropy() {
    let (pub_client, pub_id) = client("publisher-dialkey-5").await;
    let (pa, pb) = (free_port(), free_port());
    let (ida, idb) = (dialkey::peer_id("node-a5"), dialkey::peer_id("node-b5"));
    // an hour between pulls: only forwarding can get the zone to B inside the test
    let slow = Duration::from_secs(3600);
    let a = spawn_node_pulling(
        "node-a5",
        pa,
        vec![PeerAddr::new(idb, "127.0.0.1", pb)],
        vec![pub_id],
        Arc::new(MemoryObjectStore::new()),
        slow,
    )
    .await;
    let b = spawn_node_pulling(
        "node-b5",
        pb,
        vec![PeerAddr::new(ida, "127.0.0.1", pa)],
        vec![pub_id],
        Arc::new(MemoryObjectStore::new()),
        slow,
    )
    .await;
    // the first (immediate) pull round happened at startup, before any zone existed
    tokio::time::sleep(Duration::from_millis(500)).await;
    let owner = kp(10);
    pub_client
        .push(
            &a.addr,
            &[
                registration_object(&kp(1), &spec("acme.example", "acme", &owner, 1)).unwrap(),
                update_object(&owner, "acme.example", 1, 1, &body("198.51.100.9")).unwrap(),
            ],
        )
        .await
        .unwrap();
    eventually(|| async { www(&b).await.as_deref() == Some("198.51.100.9") }).await;
    let _ = (a.stop.send(true), b.stop.send(true));
}
