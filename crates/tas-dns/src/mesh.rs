//! The node's membership in the transport mesh: serve the sync protocol, keep in step with
//! peers (anti-entropy pull), and forward what a publisher hands this node to the other nodes.
//!
//! **Membership is explicit.** Peers and publishers are pinned by Ed25519 identity — the
//! identity a dialkey derives — and the handshake proves it. There is no discovery of members:
//! a mesh of nameservers is a handful of known machines, and "anyone who can find us" is not a
//! membership rule. (`transport::dialkey` / pkarr remain the right tool to resolve a peer's
//! *address* from its dialkey if addresses move; the trust decision stays the pinned key.)

use crate::db::ZoneDb;
use crate::escape::esc;
use crate::metrics::Metrics;
use std::sync::Arc;
use std::time::Duration;
use transport::native::NativeEndpoint;
use transport::zone_sync::{
    self, ApplyOutcome, ObjectKind, PeerPolicy, Role, SessionLimits, SignedObject, Summary,
    SummaryKey, SyncClient, SyncStore,
};
use transport::{PeerAddr, PeerId, Transport};

/// Mesh settings.
#[derive(Clone)]
pub struct MeshConfig {
    /// Listen address for the sync protocol.
    pub bind: String,
    /// The dialkey that derives this node's identity (a secret: never logged).
    pub dialkey: String,
    /// The other nameservers.
    pub peers: Vec<PeerAddr>,
    /// Identities allowed to push (control plane, ACME worker).
    pub publishers: Vec<PeerId>,
    /// Time between anti-entropy rounds.
    pub pull_interval: Duration,
    /// Per-message network timeout.
    pub io_timeout: Duration,
    /// Server-side session limits.
    pub limits: SessionLimits,
}

impl std::fmt::Debug for MeshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshConfig")
            .field("bind", &self.bind)
            .field("peers", &self.peers.len())
            .field("publishers", &self.publishers.len())
            .finish_non_exhaustive()
    }
}

/// Parse `hex-peer-id@host:port` (or the `bedrock-transport://` form).
pub fn parse_peer(s: &str) -> Option<PeerAddr> {
    if s.starts_with("bedrock-transport://") {
        return PeerAddr::parse(s);
    }
    PeerAddr::parse(&format!("bedrock-transport://{s}"))
}

/// Parse a 64-hex-digit identity.
pub fn parse_peer_id(s: &str) -> Option<PeerId> {
    let a = PeerAddr::parse(&format!("bedrock-transport://{s}@h:1"))?;
    Some(a.peer_id)
}

/// Lower-case hex of a peer id.
#[must_use]
pub fn peer_id_hex(id: &PeerId) -> String {
    use std::fmt::Write as _;
    id.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The store the sync protocol sees: the database, plus forwarding of publisher-originated
/// objects to the other nodes.
pub struct MeshStore {
    db: Arc<ZoneDb>,
    policy: Arc<PeerPolicy>,
    forward: tokio::sync::mpsc::UnboundedSender<SignedObject>,
}

impl SyncStore for MeshStore {
    fn summaries(&self, after: Option<SummaryKey>, limit: usize) -> Vec<Summary> {
        self.db.summaries(after, limit)
    }

    fn get(&self, kind: ObjectKind, id_hash: &[u8; 32]) -> Option<SignedObject> {
        self.db.get(kind, id_hash)
    }

    fn apply(&self, object: SignedObject, from: PeerId) -> ApplyOutcome {
        let out = self.db.apply(object.clone(), from);
        if out == ApplyOutcome::Applied && self.policy.role(&from) == Some(Role::Publisher) {
            let _ = self.forward.send(object);
        }
        out
    }
}

/// A running mesh endpoint.
pub struct Mesh {
    /// This node's public identity.
    pub id: PeerId,
    /// The address the sync protocol listens on.
    pub addr: String,
    /// The store the protocol serves (also usable for manual pulls).
    pub store: Arc<MeshStore>,
    /// The dialler.
    pub client: SyncClient,
}

/// Bind the endpoint and start the serve, forward and anti-entropy tasks.
pub async fn start(
    db: Arc<ZoneDb>,
    metrics: Arc<Metrics>,
    cfg: MeshConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<Mesh> {
    let endpoint = Arc::new(NativeEndpoint::bind_with_dialkey(&cfg.bind, &cfg.dialkey).await?);
    let id = Transport::id(&*endpoint);
    let addr = Transport::local_addr(&*endpoint)?;
    let mut policy = PeerPolicy::new();
    for p in &cfg.peers {
        policy = policy.with_peer(p.peer_id);
    }
    for p in &cfg.publishers {
        policy = policy.with_publisher(*p);
    }
    let policy = Arc::new(policy);
    let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel::<SignedObject>();
    let store = Arc::new(MeshStore {
        db,
        policy: policy.clone(),
        forward: ftx,
    });
    let client = SyncClient::new(endpoint.clone(), cfg.io_timeout);

    tokio::spawn(zone_sync::serve(
        endpoint,
        store.clone(),
        policy,
        cfg.limits,
        shutdown.clone(),
    ));

    // forward publisher-originated objects to every peer (best effort; anti-entropy heals)
    {
        let (client, peers, mut sd) = (client.clone(), cfg.peers.clone(), shutdown.clone());
        tokio::spawn(async move {
            loop {
                let obj = tokio::select! {
                    () = crate::server::wait_shutdown(&mut sd) => return,
                    o = frx.recv() => match o { Some(o) => o, None => return },
                };
                for p in &peers {
                    let _ = client.push(p, std::slice::from_ref(&obj)).await;
                }
            }
        });
    }

    // anti-entropy
    {
        let (client, store, peers, mut sd, m) = (
            client.clone(),
            store.clone(),
            cfg.peers.clone(),
            shutdown,
            metrics,
        );
        let interval = cfg.pull_interval;
        tokio::spawn(async move {
            let mut failing: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
            loop {
                for p in &peers {
                    match client.pull(p, &*store).await {
                        Ok(r) => {
                            m.sync_pulls.inc();
                            if failing.remove(&p.peer_id) {
                                tracing::info!(target: "tas_dns::mesh", peer = %esc(&peer_id_hex(&p.peer_id)), "peer reachable again");
                            }
                            if r.forks > 0 || r.rejected > 0 {
                                tracing::warn!(target: "tas_dns::alert", peer = %esc(&peer_id_hex(&p.peer_id)), forks = r.forks, rejected = r.rejected, "peer offered objects this node refused");
                            }
                        }
                        Err(e) => {
                            m.sync_errors.inc();
                            if failing.insert(p.peer_id) {
                                tracing::warn!(target: "tas_dns::mesh", peer = %esc(&peer_id_hex(&p.peer_id)), error = %e, "pull from peer failed");
                            }
                        }
                    }
                }
                tokio::select! {
                    () = crate::server::wait_shutdown(&mut sd) => return,
                    () = tokio::time::sleep(interval) => {}
                }
            }
        });
    }
    Ok(Mesh {
        id,
        addr,
        store,
        client,
    })
}
