//! # transport — the native P2P transport layer (subsumes iroh)
//!
//! iroh provides QUIC connections, Ed25519 identity, NAT traversal, gossip, and blob transfer.
//! The crypto primitives are already in `hashtrinity-crypto` (QUIC packet seal/open, Ed25519,
//! AES-GCM, HKDF, BLAKE3). This module provides the **transport layer** natively, cutting iroh:
//!
//! - **Phase 1**: the Transport/Connection/BiStream traits (the abstraction cut)
//! - **Phase 2**: TCP+TLS implementation (`NativeEndpoint`, tokio TcpStream + hashtrinity-rustls)
//! - **Phase 3**: native gossip protocol (`GossipBus`, epidemic broadcast on any Transport)
//! - **Phase 4**: native QUIC transport (packet/frame layer on hashtrinity-crypto's crypto)
//!
//! ## The HashTrinity face
//! - **NB/Set** = the peer set (known peers — presence, the address book)
//! - **B/Map** = the connection map (PeerId → Connection — replace on new connection)
//! - **B/U** = the stream accumulator (bytes read/written — the flow)
//! - **self** = the gossip protocol (the medium turned on itself — broadcast)

pub mod native;
pub mod gossip;
pub mod bastion;
pub mod quic;
/// The DNS wire format, native — RFC 1035 messages encoded and decoded here rather than by
/// `hickory_proto` (`edge_dns`) or `simple-dns` (arriving through the `pkarr` crate). The naming
/// twin of [`native`], which did the same for `iroh::Endpoint`.
pub mod dns;
/// Self-authenticating DNS records — an Ed25519 key signs a [`dns`] message and z-base32-encodes
/// into the label it publishes under. The native replacement for the `pkarr` crate's format half.
pub mod signed_dns;
pub mod pkarr;
pub mod dialkey;
#[cfg(feature = "federation")]
pub mod federation;
pub mod latency;
pub mod discovery;
/// tas-edge — the SaaS hostname layer (managed subdomains, BYO custom hostnames). Pure
/// registry logic over hashtrinity, so it is always compiled; only the DNS halves need a dep.
pub mod edge;
#[cfg(feature = "bind-edge-dns")]
pub mod edge_dns;
/// Proof-of-control checks for BYO hostnames. The sweep and its `DnsProbe` seam are always
/// compiled (and unit-tested against a static probe); only the real resolver is gated.
pub mod edge_verify;
/// The edge data plane: hostname -> authenticated peer. Supplies the one thing
/// `native_lib::proxy` cannot express (an upstream that is a PeerId, not a host:port) and
/// reuses that module for everything else.
pub mod edge_proxy;
#[cfg(feature = "bind-overlay")]
pub mod control;
pub mod provision;
/// HTTP types (`Method`, `Uri`, `HeaderMap`, `Request`/`Response`) — lifted verbatim from
/// bedrock's `native_lib::http_types`, paired with [`http_client`].
pub mod http_types;
/// The plain/TLS stream, connection pool, and request/response wire I/O underneath
/// [`http_client`]. Lifted verbatim from bedrock's `native_lib::wire`.
pub(crate) mod wire;
/// A minimal async HTTP client (GET/PUT + bytes), used by [`pkarr::RelayClient`] to talk to
/// pkarr relays — "native, always available, no `pkarr` [crate] dependency" per
/// `dialkey.rs`'s own doc comment, so this isn't behind an opt-in feature.
pub mod http_client;

use std::future::Future;
use std::io;
use std::pin::Pin;

/// A peer's identity — an Ed25519 public key (32 bytes). Same as iroh's `EndpointId`.
pub type PeerId = [u8; 32];

/// This host's outward-facing address — the source IP the kernel would use to reach the wider
/// network.
///
/// **No packet is sent.** `connect` on a UDP socket is a purely local operation: it asks the
/// kernel to pin a route and a source address, which `local_addr` then reads back. The remote
/// address only has to be routable-looking, never reachable, so this works on a host with no
/// internet access and costs one syscall pair.
///
/// This replaces the `local-ip-address` crate, which reached **14 crates exclusively** —
/// `neli` for netlink, plus `derive_builder`/`darling`/`getset`/`strsim`/`ident_case` of
/// proc-macro machinery — to answer this one question. Enumerating every interface and picking
/// among them is the harder way to ask it; the routing table already knows the answer, and this
/// is how you read it.
///
/// Prefers IPv4 and falls back to IPv6, matching what the crate it replaces returned.
///
/// # Errors
/// [`io::Error`] if neither family yields a bound socket — a host with no configured route.
pub fn local_ip() -> io::Result<std::net::IpAddr> {
    fn probe(bind: &str, peer: &str) -> io::Result<std::net::IpAddr> {
        let sock = std::net::UdpSocket::bind(bind)?;
        sock.connect(peer)?;
        Ok(sock.local_addr()?.ip())
    }
    // 198.51.100.0/24 and 2001:db8::/32 are the RFC-reserved documentation ranges: routable in
    // form, guaranteed never to belong to a real host, so nothing is contacted even by accident.
    probe("0.0.0.0:0", "198.51.100.1:80").or_else(|_| probe("[::]:0", "[2001:db8::1]:80"))
}

/// A boxed async future — the object-safe return type for trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bi-directional byte stream — one half of a `open_bi`/`accept_bi` pair.
///
/// For TCP+TLS: one direction of a TCP connection (read OR write).
/// For QUIC: a QUIC uni-directional stream (send OR recv).
pub trait BiStream: Send {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<()>>;
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    fn finish<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>>;
}

/// A connection to a peer — can open and accept bi-directional stream pairs.
///
/// A bi-directional stream pair is `(send: Box<dyn BiStream>, recv: Box<dyn BiStream>)`.
pub trait Connection: Send + Sync {
    /// Open a new bi-directional stream pair. Returns (send, recv).
    fn open_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>>;
    /// Accept a bi-directional stream pair from the peer.
    fn accept_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>>;
    /// The peer's identity (Ed25519 public key).
    fn peer_id(&self) -> PeerId;
    /// Close the connection.
    fn close<'a>(&'a self) -> BoxFuture<'a, io::Result<()>>;
}

/// A network endpoint — binds, accepts connections, connects to peers.
///
/// This is the native replacement for `iroh::Endpoint`. Both the TCP+TLS implementation
/// (`NativeEndpoint`) and the future QUIC implementation (`QuicEndpoint`) satisfy this trait.
pub trait Transport: Send + Sync {
    type Connection: Connection;

    /// This endpoint's identity (Ed25519 public key).
    fn id(&self) -> PeerId;

    /// Connect to a peer at `addr` (host:port format for TCP, or an iroh ticket for QUIC).
    fn connect<'a>(&'a self, addr: &'a str, alpn: &'a [u8]) -> BoxFuture<'a, io::Result<Self::Connection>>;

    /// Accept one incoming connection.
    fn accept<'a>(&'a self) -> BoxFuture<'a, Option<Self::Connection>>;

    /// This endpoint's listen address.
    fn local_addr(&self) -> io::Result<String>;
}

/// A serializable peer address — for out-of-band exchange (tickets, QR codes, etc.).
/// Format: `bedrock-transport://<peer_id_hex>@<host>:<port>`
#[derive(Clone, Debug, PartialEq)]
pub struct PeerAddr {
    pub peer_id: PeerId,
    pub host: String,
    pub port: u16,
}

impl PeerAddr {
    pub fn new(peer_id: PeerId, host: impl Into<String>, port: u16) -> Self {
        PeerAddr { peer_id, host: host.into(), port }
    }

    pub fn to_string(&self) -> String {
        format!(
            "bedrock-transport://{}@{}:{}",
            self.peer_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            self.host, self.port
        )
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("bedrock-transport://")?;
        let (id_hex, addr) = rest.split_once('@')?;
        let (host, port_str) = addr.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        let mut peer_id = [0u8; 32];
        if id_hex.len() != 64 { return None; }
        for i in 0..32 {
            peer_id[i] = u8::from_str_radix(&id_hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(PeerAddr { peer_id, host: host.to_string(), port })
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for PeerAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| "invalid peer address".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_addr_round_trips() {
        let id = [42u8; 32];
        let addr = PeerAddr::new(id, "10.0.0.1", 4242);
        let s = addr.to_string();
        let parsed = PeerAddr::parse(&s).unwrap();
        assert_eq!(parsed.peer_id, id);
        assert_eq!(parsed.host, "10.0.0.1");
        assert_eq!(parsed.port, 4242);
    }
}
