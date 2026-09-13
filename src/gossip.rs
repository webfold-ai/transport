#![cfg(feature = "runtime-tokio")]

//! Native gossip protocol — epidemic broadcast on any Transport, no iroh-gossip.
//!
//! Replaces `iroh_gossip::api::Gossip` with a simple, proven protocol: each peer fans out
//! received messages to all known peers (with a small fanout and a seen-set to prevent loops).
//! This is the same algorithm Bedrock's existing `sangdb::gossip` uses, but on the native
//! transport instead of iroh-gossip.
//!
//! ## The protocol
//! 1. `broadcast(data)`: send to all known peers
//! 2. On receiving a message: check seen-set, if new → deliver + re-broadcast to fanout peers
//! 3. Periodic `gossip`: exchange known-peers lists (membership propagation)
//!
//! ## The HashTrinity face
//! - **NB/Set** = the seen-set (which messages we've already relayed — idempotent)
//! - **B/Map** = the peer map (PeerId → Connection — the known peers)
//! - **B/U** = the message counter (how many messages we've sent/received)
//! - **self** = the gossip itself (the medium turned on itself — broadcast)

use super::{Transport, PeerId};
use hashtrinity::crypto::blake3;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A gossip topic — identified by a 32-byte hash of the topic name (BLAKE3).
pub type TopicId = [u8; 32];

/// Compute a topic ID from a name — deterministic, collision-resistant (BLAKE3).
pub fn topic_id_for(name: &str) -> TopicId {
    blake3(name.as_bytes())
}

/// A gossip message — what gets broadcast over the topic.
#[derive(Clone, Debug)]
pub struct GossipMessage {
    pub topic: TopicId,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
    pub origin: PeerId,
}

/// The gossip bus — manages topics, peers, and the seen-set.
pub struct GossipBus {
    endpoint_id: PeerId,
    topics: Arc<Mutex<Vec<TopicId>>>,
    seen: Arc<Mutex<HashSet<[u8; 32]>>>,
    peers: Arc<Mutex<Vec<(PeerId, String)>>>,
    delivered: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl GossipBus {
    pub fn new(endpoint_id: PeerId) -> Self {
        GossipBus {
            endpoint_id,
            topics: Arc::new(Mutex::new(Vec::new())),
            seen: Arc::new(Mutex::new(HashSet::new())),
            peers: Arc::new(Mutex::new(Vec::new())),
            delivered: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Join a topic.
    pub async fn join(&self, topic: TopicId) {
        self.topics.lock().await.push(topic);
    }

    /// Add a known peer (PeerId + address).
    pub async fn add_peer(&self, peer_id: PeerId, addr: String) {
        self.peers.lock().await.push((peer_id, addr));
    }

    /// Whether this bus has joined `topic`.
    pub async fn joined(&self, topic: TopicId) -> bool {
        self.topics.lock().await.contains(&topic)
    }

    /// Broadcast a message to all known peers on a topic.
    /// Returns the message hash (BLAKE3 of the data).
    ///
    /// Local delivery is gated on `topic` having been joined; the `topic` argument used to be
    /// ignored entirely, so a bus surfaced every message regardless of which topic it carried.
    pub async fn broadcast(&self, topic: TopicId, data: Vec<u8>) -> [u8; 32] {
        let hash = blake3(&data);
        self.seen.lock().await.insert(hash);
        if self.joined(topic).await {
            self.delivered.lock().await.push(data);
        }
        hash
    }

    /// Process a received message — returns true if it was new (should re-broadcast).
    ///
    /// Novelty is a property of the seen-set, not of subscription: a message on a topic this bus
    /// has not joined is still new and still worth relaying, it is just not delivered *here*.
    pub async fn receive(&self, msg: GossipMessage) -> bool {
        let mut seen = self.seen.lock().await;
        if seen.contains(&msg.hash) {
            return false;
        }
        seen.insert(msg.hash);
        drop(seen);
        if self.joined(msg.topic).await {
            self.delivered.lock().await.push(msg.data.clone());
        }
        true
    }

    /// Drain delivered messages (for the consumer to process).
    pub async fn drain_delivered(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.delivered.lock().await)
    }

    /// Known peer addresses (for fanout).
    pub async fn peer_addrs(&self) -> Vec<String> {
        self.peers.lock().await.iter().map(|(_, a)| a.clone()).collect()
    }

    /// This endpoint's ID.
    pub fn id(&self) -> PeerId {
        self.endpoint_id
    }
}

/// Wire format for a gossip message: `[topic (32)][hash (32)][origin (32)][len (8)][data]`.
pub fn encode_message(msg: &GossipMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(104 + msg.data.len());
    out.extend_from_slice(&msg.topic);
    out.extend_from_slice(&msg.hash);
    out.extend_from_slice(&msg.origin);
    out.extend_from_slice(&(msg.data.len() as u64).to_le_bytes());
    out.extend_from_slice(&msg.data);
    out
}

/// Decode a gossip message from a byte buffer.
pub fn decode_message(buf: &[u8]) -> Option<GossipMessage> {
    if buf.len() < 104 {
        return None;
    }
    let topic: [u8; 32] = buf[..32].try_into().ok()?;
    let hash: [u8; 32] = buf[32..64].try_into().ok()?;
    let origin: [u8; 32] = buf[64..96].try_into().ok()?;
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&buf[96..104]);
    let len = u64::from_le_bytes(len_bytes) as usize;
    if buf.len() < 104 + len {
        return None;
    }
    Some(GossipMessage {
        topic,
        hash,
        origin,
        data: buf[104..104 + len].to_vec(),
    })
}

// ── GossipTopic: the high-level broadcast/recv wrapper ───────────────────────────

use super::native::NativeEndpoint;
use crate::masq::Bytes;

#[derive(Debug)]
pub enum GossipError {
    Bind(String),
    Subscribe(String),
    Broadcast(String),
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipError::Bind(e) => write!(f, "gossip bind: {e}"),
            GossipError::Subscribe(e) => write!(f, "gossip subscribe: {e}"),
            GossipError::Broadcast(e) => write!(f, "gossip broadcast: {e}"),
        }
    }
}

impl std::error::Error for GossipError {}

/// Bind a native gossip endpoint — convenience over `NativeEndpoint::bind`.
pub async fn bind_with_bootstrap(_bootstrap: &[super::PeerAddr]) -> Result<NativeEndpoint, GossipError> {
    NativeEndpoint::bind("0.0.0.0:0").await.map_err(|e| GossipError::Bind(e.to_string()))
}

/// ALPN for the gossip protocol. `NativeEndpoint::connect` currently ignores it; it is sent so the
/// dispatch exists the moment the endpoint multiplexes protocols.
pub const GOSSIP_ALPN: &[u8] = b"bedrock/gossip/0";

/// Largest gossip frame accepted from a peer (1 MiB). A larger frame is truncated by
/// `BiStream::read` rather than allocated for, so a peer cannot drive this side's memory.
pub const MAX_GOSSIP_FRAME: usize = 1024 * 1024;

/// A gossip topic subscription — broadcast/recv on a topic over a native endpoint.
pub struct GossipTopic {
    bus: std::sync::Arc<GossipBus>,
    /// The joined topic. `broadcast` publishes here; it used to publish to
    /// `topic_id_for("default")` regardless of what was joined, so two topics on one bus were
    /// indistinguishable on the wire.
    topic: TopicId,
    delivered: tokio::sync::Mutex<Vec<Bytes>>,
    /// Present only for [`GossipTopic::join_networked`] — the endpoint used to dial peers.
    endpoint: Option<std::sync::Arc<NativeEndpoint>>,
    peers: Vec<super::PeerAddr>,
    _accept: Option<tokio::task::JoinHandle<()>>,
}

impl GossipTopic {
    /// Join a gossip topic on a native endpoint — local delivery only, no peers dialled.
    ///
    /// There is no background pump: [`GossipTopic::recv`] drains the bus itself. A pump used to
    /// run here and *discarded* everything it drained (it bound `msgs` and only tested
    /// `is_empty()`), racing `recv` for the same queue — every message the pump won was lost. The
    /// consumer is the one drainer, which is also what `sangdb::gossip::GossipLog`'s own pump
    /// already assumes.
    ///
    /// Use [`GossipTopic::join_networked`] for cross-machine fan-out.
    pub async fn join(
        endpoint: &NativeEndpoint,
        topic: TopicId,
        peers: Vec<super::PeerAddr>,
    ) -> Result<Self, GossipError> {
        let bus = std::sync::Arc::new(GossipBus::new(endpoint.id()));
        bus.join(topic).await;
        for peer in &peers {
            bus.add_peer(peer.peer_id, peer.to_string()).await;
        }
        Ok(GossipTopic {
            bus,
            topic,
            delivered: tokio::sync::Mutex::new(Vec::new()),
            endpoint: None,
            peers,
            _accept: None,
        })
    }

    /// Join a gossip topic with real network fan-out: [`GossipTopic::broadcast`] dials every peer
    /// and writes the encoded message, and an accept loop feeds inbound frames into the bus.
    ///
    /// Takes an owned `Arc<NativeEndpoint>` because the accept loop outlives the call. `peers` are
    /// dialled by `host:port`; `PeerAddr`'s own string form is a `bedrock-transport://` URL, which
    /// is what the bus records for display but is not a dialable address.
    pub async fn join_networked(
        endpoint: std::sync::Arc<NativeEndpoint>,
        topic: TopicId,
        peers: Vec<super::PeerAddr>,
    ) -> Result<Self, GossipError> {
        use super::Transport;

        let bus = std::sync::Arc::new(GossipBus::new(endpoint.id()));
        bus.join(topic).await;
        for peer in &peers {
            bus.add_peer(peer.peer_id, peer.to_string()).await;
        }

        let accept_bus = bus.clone();
        let accept_ep = endpoint.clone();
        let accept = tokio::spawn(async move {
            while let Some(conn) = accept_ep.accept().await {
                let bus = accept_bus.clone();
                tokio::spawn(async move {
                    use super::Connection;
                    let Ok((_send, mut recv)) = conn.accept_bi().await else { return };
                    let mut buf = vec![0u8; MAX_GOSSIP_FRAME];
                    // One frame per connection: a gossip message is a datagram, not a session.
                    if let Ok(n) = recv.read(&mut buf).await {
                        if let Some(msg) = decode_message(&buf[..n]) {
                            bus.receive(msg).await;
                        }
                    }
                });
            }
        });

        Ok(GossipTopic {
            bus,
            topic,
            delivered: tokio::sync::Mutex::new(Vec::new()),
            endpoint: Some(endpoint),
            peers,
            _accept: Some(accept),
        })
    }

    /// Broadcast `data` to all known peers on this topic.
    ///
    /// Always delivers locally. When the topic was joined with [`GossipTopic::join_networked`],
    /// also dials each peer and writes the framed message. A peer that fails to dial is skipped —
    /// gossip is best-effort by construction, and one unreachable peer must not fail the publish
    /// for the reachable ones.
    pub async fn broadcast(&self, data: Bytes) -> Result<(), GossipError> {
        use super::{Connection, Transport};

        let data_vec = data.to_vec();
        let hash = self.bus.broadcast(self.topic, data_vec.clone()).await;

        let Some(endpoint) = self.endpoint.as_ref() else { return Ok(()) };
        let msg = GossipMessage { topic: self.topic, hash, data: data_vec, origin: self.bus.id() };
        let framed = encode_message(&msg);
        for peer in &self.peers {
            let addr = format!("{}:{}", peer.host, peer.port);
            let Ok(conn) = endpoint.connect(&addr, GOSSIP_ALPN).await else { continue };
            let Ok((mut send, _recv)) = conn.open_bi().await else { continue };
            if send.write_all(&framed).await.is_ok() {
                let _ = send.finish().await;
            }
        }
        Ok(())
    }

    /// Take the next message if one is already available, without waiting.
    ///
    /// `None` means "nothing pending right now", not "closed" — a drain loop over a topic wants
    /// this, since [`GossipTopic::recv`] never yields `None` and so can never end such a loop.
    pub async fn try_recv(&self) -> Option<Bytes> {
        {
            let mut d = self.delivered.lock().await;
            if !d.is_empty() {
                return Some(d.remove(0));
            }
        }
        let msgs = self.bus.drain_delivered().await;
        if msgs.is_empty() {
            return None;
        }
        let mut d = self.delivered.lock().await;
        for m in msgs {
            d.push(Bytes::from(m));
        }
        if d.is_empty() { None } else { Some(d.remove(0)) }
    }

    /// Receive the next message on this topic, waiting until one arrives.
    pub async fn recv(&self) -> Option<Bytes> {
        loop {
            if let Some(bytes) = self.try_recv().await {
                return Some(bytes);
            }
            tokio::task::yield_now().await;
        }
    }

    /// Number of pending messages.
    pub async fn len(&self) -> usize {
        self.delivered.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_id_is_deterministic() {
        assert_eq!(topic_id_for("test"), topic_id_for("test"));
        assert_ne!(topic_id_for("test"), topic_id_for("other"));
    }

    #[test]
    fn encode_decode_round_trips() {
        let msg = GossipMessage {
            topic: topic_id_for("test"),
            hash: blake3(b"hello"),
            origin: [42u8; 32],
            data: b"hello gossip".to_vec(),
        };
        let encoded = encode_message(&msg);
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded.topic, msg.topic);
        assert_eq!(decoded.hash, msg.hash);
        assert_eq!(decoded.origin, msg.origin);
        assert_eq!(decoded.data, msg.data);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        assert!(decode_message(b"too short").is_none());
        assert!(decode_message(&[0u8; 50]).is_none());
    }

    #[tokio::test]
    async fn bus_delivers_only_joined_topics() {
        let bus = GossipBus::new([1u8; 32]);
        bus.join(topic_id_for("joined")).await;

        bus.broadcast(topic_id_for("other"), b"not mine".to_vec()).await;
        assert!(bus.drain_delivered().await.is_empty(), "a topic never joined must not deliver");

        bus.broadcast(topic_id_for("joined"), b"mine".to_vec()).await;
        assert_eq!(bus.drain_delivered().await, vec![b"mine".to_vec()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn networked_broadcast_reaches_a_peer() {
        use super::super::{PeerAddr, Transport};
        use std::sync::Arc;

        let ep_a = Arc::new(NativeEndpoint::bind("127.0.0.1:0").await.expect("bind a"));
        let ep_b = Arc::new(NativeEndpoint::bind("127.0.0.1:0").await.expect("bind b"));

        let b_addr = ep_b.local_addr().expect("addr b");
        let (host, port) = b_addr.rsplit_once(':').expect("host:port");
        let b_peer = PeerAddr::new(ep_b.id(), host, port.parse::<u16>().expect("port"));

        let topic = topic_id_for("fanout");
        let a = GossipTopic::join_networked(ep_a, topic, vec![b_peer]).await.expect("join a");
        let b = GossipTopic::join_networked(ep_b, topic, vec![]).await.expect("join b");

        a.broadcast(Bytes::from_static(b"over the wire")).await.expect("broadcast");

        let got = tokio::time::timeout(std::time::Duration::from_secs(10), b.recv())
            .await
            .expect("peer received within timeout");
        assert_eq!(got.as_deref(), Some(&b"over the wire"[..]));
    }

    #[tokio::test]
    async fn seen_set_prevents_duplicates() {
        let bus = GossipBus::new([1u8; 32]);
        let topic = topic_id_for("test");
        let hash = bus.broadcast(topic, b"hello".to_vec()).await;

        // broadcast already marked this hash as seen, so receive returns false
        let msg = GossipMessage {
            topic,
            hash,
            origin: [2u8; 32],
            data: b"hello".to_vec(),
        };
        assert!(!bus.receive(msg.clone()).await, "broadcast already marked as seen");

        // A NEW message (different hash) should be accepted
        let new_hash = blake3(b"world");
        let new_msg = GossipMessage {
            topic,
            hash: new_hash,
            origin: [2u8; 32],
            data: b"world".to_vec(),
        };
        assert!(bus.receive(new_msg.clone()).await, "new message should be accepted");
        assert!(!bus.receive(new_msg).await, "duplicate should be rejected");
    }
}
