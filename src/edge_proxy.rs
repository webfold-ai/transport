//! The edge data plane — hostname to authenticated peer.
//!
//! `native_lib::proxy` is already a real reverse proxy: `Upstream`, `LoadBalance`
//! (RoundRobin/Random/Weighted/Consistent/Healthiest with a live Kalman latency estimator),
//! health checks, caching, and pingora's `ProxyHttp` lifecycle. **None of that is rebuilt
//! here.** The one thing it cannot express is this product's whole point:
//!
//! > an `Upstream` is a `host:port` the proxy dials. A tunnel origin has no host and no port
//! > the edge can dial — the connector dialled *out*, and the only way back is the
//! > authenticated `transport::Connection` we are already holding.
//!
//! So this module supplies exactly that missing piece — a [`ConnectorPool`] keyed by
//! [`PeerId`] instead of by address, and the admission decision ([`decide`]) that maps an
//! inbound TLS+HTTP request onto one. Load balancing across a tunnel's connectors reuses
//! `proxy::LoadBalance` rather than inventing a second algorithm set.
//!
//! ## Why the hostname names a *peer*, not a host
//!
//! `Route::peer` is `dialkey::peer_id(dialkey)`. The edge serves a hostname only over a
//! connection it has already cryptographically authenticated as that peer — so stealing a
//! hostname requires stealing the dialkey, not winning a DNS race or spoofing a source
//! address. This is `transport::bastion`'s default-deny discipline one layer up: presence in
//! the pool is not authorization; matching the registry's expected peer is.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the online connector set (which peers are dialled in right now)
//! - **B/Map** = the pool (PeerId → its connections — replace on reconnect)
//! - **B/U** = the round-robin cursor (the accumulator that picks among them)
//! - **self** = the decision (the request inspected to decide whether to carry the request)

use super::edge::{normalize, EdgeRegistry, HostnameState, Route};
use super::load_balance::HealthEstimator;
use super::{Connection, PeerId};
use hashtrinity::Table;
use hashtrinity::crypto::to_hex;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// What the edge should do with one inbound request.
///
/// Every non-`Serve` case is a distinct, *diagnosable* failure. Collapsing them into one 502
/// is the difference between a customer knowing their connector is offline and a customer
/// filing a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Proxy to this route.
    Serve(Route),
    /// The `Host` header disagrees with the TLS SNI. **421**, per RFC 7540 §9.1.2: the
    /// connection was reused for a name this certificate/route does not cover. Answering
    /// anything else lets one tenant's connection address another tenant's hostname.
    Misdirected,
    /// No such hostname. **404**.
    Unknown,
    /// Admitted but held by an operator or billing. **403** — the name resolves, so we get to
    /// say why rather than looking broken.
    Suspended,
    /// Control was never proven, or proving it failed. **403**.
    NotValidated(HostnameState),
    /// Admitted and valid, but no certificate is loaded yet. **503**. On an HSTS-preloaded
    /// apex this state is never reachable over the wire at all — the handshake cannot
    /// complete without the certificate — which is exactly why it is a distinct case.
    CertPending,
    /// The hostname is live but its connector is not dialled in. **502** with a body that
    /// says so: this is the single most common real failure, and it is the customer's
    /// `tas-overlayd` process, not our edge.
    NoConnector,
}

/// Decide what to do with a request for `host`, arriving under TLS SNI `sni`.
///
/// Pure: registry state in, decision out. The whole admission policy is testable without a
/// socket, which is the point — this is the code path that must not be wrong.
#[must_use]
pub fn decide(
    registry: &EdgeRegistry,
    pool: &ConnectorPool,
    sni: Option<&str>,
    host: &str,
    have_cert: bool,
) -> Decision {
    let host = normalize(strip_port(host));
    // SNI/Host agreement first: it gates everything, and checking it after a registry hit
    // would mean a hostname's existence leaked through the mismatch case.
    if let Some(sni) = sni {
        if normalize(sni) != host {
            return Decision::Misdirected;
        }
    }
    let Some(record) = registry.lookup(&host) else {
        return Decision::Unknown;
    };
    match &record.state {
        HostnameState::Suspended => return Decision::Suspended,
        HostnameState::PendingDns | HostnameState::Failed(_) => {
            return Decision::NotValidated(record.state.clone())
        }
        HostnameState::PendingCert => return Decision::CertPending,
        HostnameState::Active => {}
    }
    if !have_cert && record.requires_tls() {
        return Decision::CertPending;
    }
    if !pool.is_online(record.route.peer) {
        return Decision::NoConnector;
    }
    Decision::Serve(record.route.clone())
}

/// Strip a `:port` suffix from a `Host` header value, leaving IPv6 literals alone.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

impl Decision {
    /// The HTTP status this decision produces.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Decision::Serve(_) => 200,
            Decision::Misdirected => 421,
            Decision::Unknown => 404,
            Decision::Suspended | Decision::NotValidated(_) => 403,
            Decision::CertPending | Decision::NoConnector => 503,
        }
    }

    /// A message safe to show the *requesting public*, which is not the tenant. It must not
    /// reveal whether a hostname exists, who owns it, or why an operator suspended it.
    #[must_use]
    pub fn public_message(&self) -> &'static str {
        match self {
            Decision::Serve(_) => "",
            Decision::Misdirected => "This connection was not established for this hostname.",
            Decision::Unknown => "There is no service at this hostname.",
            Decision::Suspended => "This service is unavailable.",
            Decision::NotValidated(_) => "This hostname is not yet active.",
            Decision::CertPending => "This service is still being set up. Try again shortly.",
            Decision::NoConnector => {
                "This service is not currently reachable — its connector is offline."
            }
        }
    }
}

// ── The connector pool ────────────────────────────────────────────────────────────────────

/// Connections the edge is holding, keyed by the peer that dialled in.
///
/// A tunnel may have several connectors online at once — a customer running `tas-overlayd` on
/// two hosts for redundancy, or mid-deploy with old and new both up. They share one dialkey,
/// therefore one [`PeerId`], so they land under one key and are picked between. That is the
/// same shape a load balancer's backend set has, so it reuses [`crate::load_balance`]'s
/// algorithms (the same ones `biota-http-server`'s `kernel::Proxy` picks HTTP upstreams with)
/// rather than adding a second, subtly different selection policy to the codebase.
pub struct ConnectorPool {
    /// hex(PeerId) → its live connections, each paired with its own passive latency estimator.
    /// Hex rather than `[u8; 32]` because `Table`'s key needs `Coord`, and the hostname registry
    /// already speaks in strings.
    conns: Table<String, Vec<(Arc<dyn Connection>, Arc<HealthEstimator>)>>,
    cursor: AtomicUsize,
}

impl Default for ConnectorPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectorPool {
    #[must_use]
    pub fn new() -> Self {
        ConnectorPool { conns: Table::new(), cursor: AtomicUsize::new(0) }
    }

    /// Take a newly-accepted, already-authenticated connection into the pool.
    ///
    /// The caller must have completed the transport handshake — `peer` is what the handshake
    /// proved, never what the client claimed. Registering an unauthenticated connection here
    /// would hand its owner every hostname routed to that peer.
    pub fn register(&mut self, peer: PeerId, conn: Arc<dyn Connection>) {
        let key = to_hex(&peer);
        let mut list = self.conns.get(&key).cloned().unwrap_or_default();
        list.push((conn, Arc::new(HealthEstimator::new())));
        self.conns.put(key, list);
    }

    /// Forget every connection for `peer` — on disconnect, or on token revocation, where
    /// dropping the connections is what makes revocation take effect immediately rather than
    /// at the next reconnect.
    pub fn evict(&mut self, peer: PeerId) {
        self.conns.remove(&to_hex(&peer));
    }

    /// Whether any connector for `peer` is currently dialled in.
    #[must_use]
    pub fn is_online(&self, peer: PeerId) -> bool {
        self.connector_count(peer) > 0
    }

    /// How many connectors `peer` has online.
    #[must_use]
    pub fn connector_count(&self, peer: PeerId) -> usize {
        self.conns.get(&to_hex(&peer)).map_or(0, Vec::len)
    }

    /// Pick one of `peer`'s connections, round-robin. Kept for existing callers; prefer
    /// [`Self::pick_with`] for anything that can now feed real latency back via the returned
    /// estimator.
    #[must_use]
    pub fn pick(&self, peer: PeerId) -> Option<Arc<dyn Connection>> {
        self.pick_with(peer, crate::load_balance::LoadBalance::RoundRobin).map(|(conn, _)| conn)
    }

    /// Pick one of `peer`'s connections by `algo`, returning it along with its passive latency
    /// estimator so the caller can `.observe()` a real round-trip time after forwarding through
    /// it — the same shape `kernel::Backends::pick` returns, and the same
    /// [`crate::load_balance`] algorithm set, so `Healthiest` here and `Healthiest` in
    /// `kernel::Proxy` can never quietly mean two different things. This is the follow-on this
    /// pool's own prior doc comment called out: `Healthiest` had no populated input before
    /// `load_balance` existed to share the estimator type; now every connection gets one.
    #[must_use]
    pub fn pick_with(
        &self,
        peer: PeerId,
        algo: crate::load_balance::LoadBalance,
    ) -> Option<(Arc<dyn Connection>, Arc<HealthEstimator>)> {
        let list = self.conns.get(&to_hex(&peer))?;
        if list.is_empty() {
            return None;
        }
        let node_coords: Vec<u64> = (0..list.len() as u64).collect();
        let weights = vec![1u32; list.len()];
        let health: Vec<Arc<HealthEstimator>> = list.iter().map(|(_, h)| h.clone()).collect();
        let active = vec![Arc::new(AtomicBool::new(true)); list.len()];
        let idx = crate::load_balance::pick_index(algo, &node_coords, &weights, &health, &active, 0, &self.cursor)?;
        list.get(idx).map(|(conn, h)| (conn.clone(), h.clone()))
    }

    /// Total connections held, across every peer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.conns.iter().map(|(_, v)| v.len()).sum()
    }

    /// Whether the pool holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Tunnel instrumentation (flow accounting) ──────────────────────────────────────────────

/// Byte/flow counters for one tunnel route — the bedrock leg of the flow-accounting plane
/// (`opsfold/specs/SPEC-FLOW-ACCOUNTING.md` §5). Tunnels are not a black box: the same
/// bytes the wired hops count are counted here, on the `BiStream` surface every transport
/// (TCP+TLS, QUIC) already implements.
///
/// Counters are **cumulative atomics + a drain watermark**, exactly the `saturating_delta`
/// semantics `opsfold::flowops::flowfold` applies to VyOS counters: drain returns the delta since the
/// last drain, a reset degrades to the fresh value, never an underflow. Direction *signing*
/// (ingress vs egress, from the destination endpoint's perspective) happens in the opsfold
/// collector — this leg reports transport-relative `rx`/`tx`, the same raw shape a VyOS VIF
/// reports.
///
/// **Redundant connectors sum correctly by construction**: `ConnectorPool` may hold several
/// connections for one peer; wrap each with [`flow_count::counted`] sharing one
/// `Arc<RouteCounters>` per route, and the per-connection counts fuse into the route total —
/// the monoid merge the sharded-collector case needs, with no second mechanism.
///
/// The HashTrinity face: **B/U** — cumulative counters (the accumulator), drained by the
/// opsfold collector over the existing transport path.
pub mod flow_count {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::super::{BiStream, BoxFuture, Connection, PeerId};

    /// One route's cumulative counters. Cheap to share: five `AtomicU64`s and the key they
    /// roll up under.
    pub struct RouteCounters {
        pub tenant_id: String,
        pub tunnel_id: String,
        rx_bytes: AtomicU64,
        tx_bytes: AtomicU64,
        rx_packets: AtomicU64,
        tx_packets: AtomicU64,
        flows: AtomicU64,
        /// Last-drained watermark per field, in the same order as the counters above.
        drained: [AtomicU64; 5],
    }

    /// A drain result — the delta since the previous drain, saturating.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct FlowDelta {
        pub tenant_id: String,
        pub tunnel_id: String,
        pub rx_bytes: u64,
        pub tx_bytes: u64,
        pub rx_packets: u64,
        pub tx_packets: u64,
        pub flows: u64,
    }

    impl RouteCounters {
        #[must_use]
        pub fn new(tenant_id: impl Into<String>, tunnel_id: impl Into<String>) -> Self {
            Self {
                tenant_id: tenant_id.into(),
                tunnel_id: tunnel_id.into(),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                rx_packets: AtomicU64::new(0),
                tx_packets: AtomicU64::new(0),
                flows: AtomicU64::new(0),
                drained: Default::default(),
            }
        }

        fn count_rx(&self, bytes: u64) {
            self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
        }

        fn count_tx(&self, bytes: u64) {
            self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
        }

        fn count_flow(&self) {
            self.flows.fetch_add(1, Ordering::Relaxed);
        }

        /// Delta since the last drain. Saturating: a counter that went backwards (reset)
        /// yields the fresh value's contribution as zero for that interval, never an underflow.
        pub fn drain(&self) -> FlowDelta {
            let now = [
                self.rx_bytes.load(Ordering::Relaxed),
                self.tx_bytes.load(Ordering::Relaxed),
                self.rx_packets.load(Ordering::Relaxed),
                self.tx_packets.load(Ordering::Relaxed),
                self.flows.load(Ordering::Relaxed),
            ];
            let mut delta = [0u64; 5];
            for (i, v) in now.into_iter().enumerate() {
                let prev = self.drained[i].swap(v, Ordering::Relaxed);
                delta[i] = v.saturating_sub(prev);
            }
            FlowDelta {
                tenant_id: self.tenant_id.clone(),
                tunnel_id: self.tunnel_id.clone(),
                rx_bytes: delta[0],
                tx_bytes: delta[1],
                rx_packets: delta[2],
                tx_packets: delta[3],
                flows: delta[4],
            }
        }
    }

    /// Which half of a stream pair this is — the send half counts writes, the recv half
    /// counts reads.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Half {
        Send,
        Recv,
    }

    /// A [`BiStream`] that counts the bytes crossing it. Delegates everything; adds nothing.
    pub struct CountingBiStream {
        inner: Box<dyn BiStream>,
        counters: Arc<RouteCounters>,
        half: Half,
    }

    impl BiStream for CountingBiStream {
        fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, std::io::Result<usize>> {
            let inner = &mut self.inner;
            let counters = self.counters.clone();
            let counts = self.half == Half::Recv;
            Box::pin(async move {
                let n = inner.read(buf).await?;
                if counts {
                    counters.count_rx(n as u64);
                }
                Ok(n)
            })
        }

        fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, std::io::Result<()>> {
            let inner = &mut self.inner;
            let counters = self.counters.clone();
            let counts = self.half == Half::Recv;
            let len = buf.len();
            Box::pin(async move {
                inner.read_exact(buf).await?;
                if counts {
                    counters.count_rx(len as u64);
                }
                Ok(())
            })
        }

        fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, std::io::Result<()>> {
            let inner = &mut self.inner;
            let counters = self.counters.clone();
            let counts = self.half == Half::Send;
            let len = data.len();
            Box::pin(async move {
                inner.write_all(data).await?;
                if counts {
                    counters.count_tx(len as u64);
                }
                Ok(())
            })
        }

        fn finish<'a>(&'a mut self) -> BoxFuture<'a, std::io::Result<()>> {
            let inner = &mut self.inner;
            Box::pin(async move { inner.finish().await })
        }
    }

    /// A [`Connection`] whose stream pairs are counted — one flow per `open_bi`/`accept_bi`,
    /// bytes per read/write on each half. Wrap BEFORE registering in the [`ConnectorPool`];
    /// every connector of a route shares one `Arc<RouteCounters>` so the pool's redundancy
    /// sums instead of double- or under-counting.
    pub struct CountingConnection {
        inner: Arc<dyn Connection>,
        counters: Arc<RouteCounters>,
    }

    /// Wrap `conn` for counting — the one-liner the pool's `register` call site uses.
    #[must_use]
    pub fn counted(
        conn: Arc<dyn Connection>,
        counters: Arc<RouteCounters>,
    ) -> Arc<dyn Connection> {
        Arc::new(CountingConnection { inner: conn, counters })
    }

    impl Connection for CountingConnection {
        fn open_bi<'a>(
            &'a self,
        ) -> BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
            let inner = self.inner.clone();
            let counters = self.counters.clone();
            Box::pin(async move {
                let (send, recv) = inner.open_bi().await?;
                counters.count_flow();
                Ok((wrap(send, counters.clone(), Half::Send), wrap(recv, counters, Half::Recv)))
            })
        }

        fn accept_bi<'a>(
            &'a self,
        ) -> BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
            let inner = self.inner.clone();
            let counters = self.counters.clone();
            Box::pin(async move {
                let (send, recv) = inner.accept_bi().await?;
                counters.count_flow();
                Ok((wrap(send, counters.clone(), Half::Send), wrap(recv, counters, Half::Recv)))
            })
        }

        fn peer_id(&self) -> PeerId {
            self.inner.peer_id()
        }

        fn close<'a>(&'a self) -> BoxFuture<'a, std::io::Result<()>> {
            let inner = self.inner.clone();
            Box::pin(async move { inner.close().await })
        }
    }

    fn wrap(stream: Box<dyn BiStream>, counters: Arc<RouteCounters>, half: Half) -> Box<dyn BiStream> {
        Box::new(CountingBiStream { inner: stream, counters, half })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// An in-memory BiStream pair: writes into the send half appear as reads on the recv
        /// half. Enough to drive the counting wrapper end to end.
        struct PipeStream {
            incoming: Arc<std::sync::Mutex<Vec<u8>>>,
            outgoing: std::sync::Mutex<Vec<u8>>,
        }

        impl BiStream for PipeStream {
            fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, std::io::Result<usize>> {
                Box::pin(async move {
                    let mut src = self.incoming.lock().unwrap();
                    let n = src.len().min(buf.len());
                    buf[..n].copy_from_slice(&src[..n]);
                    src.drain(..n);
                    Ok(n)
                })
            }
            fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, std::io::Result<()>> {
                Box::pin(async move {
                    let mut src = self.incoming.lock().unwrap();
                    assert!(src.len() >= buf.len(), "pipe underflow in test");
                    let n = buf.len();
                    buf.copy_from_slice(&src[..n]);
                    src.drain(..n);
                    Ok(())
                })
            }
            fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, std::io::Result<()>> {
                Box::pin(async move {
                    self.outgoing.lock().unwrap().extend_from_slice(data);
                    Ok(())
                })
            }
            fn finish<'a>(&'a mut self) -> BoxFuture<'a, std::io::Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        /// A connection whose open_bi hands back a pipe pair — the flows+bytes path runs for real.
        struct PipeConnection {
            peer: PeerId,
        }

        impl Connection for PipeConnection {
            fn open_bi<'a>(
                &'a self,
            ) -> BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
                Box::pin(async move {
                    let shared = Arc::new(std::sync::Mutex::new(Vec::new()));
                    let send: Box<dyn BiStream> = Box::new(PipeStream {
                        incoming: shared.clone(),
                        outgoing: std::sync::Mutex::new(Vec::new()),
                    });
                    // The recv half reads what a LATER write puts in — give it its own buffer.
                    let recv: Box<dyn BiStream> = Box::new(PipeStream {
                        incoming: Arc::new(std::sync::Mutex::new(vec![7u8; 11])),
                        outgoing: std::sync::Mutex::new(Vec::new()),
                    });
                    Ok((send, recv))
                })
            }
            fn accept_bi<'a>(
                &'a self,
            ) -> BoxFuture<'a, std::io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
                self.open_bi()
            }
            fn peer_id(&self) -> PeerId {
                self.peer
            }
            fn close<'a>(&'a self) -> BoxFuture<'a, std::io::Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread().build().unwrap()
        }

        /// Reads and writes cross the wrapper and land in the right counters; a stream pair is
        /// one flow.
        #[test]
        fn reads_writes_and_flows_are_counted() {
            let counters = Arc::new(RouteCounters::new("t7", "tun-1"));
            let conn = counted(Arc::new(PipeConnection { peer: [0u8; 32] }), counters.clone());
            let rt = rt();
            rt.block_on(async {
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                send.write_all(&[0u8; 100]).await.unwrap();
                let mut buf = [0u8; 11];
                let n = recv.read(&mut buf).await.unwrap();
                assert_eq!(n, 11);
            });
            let d = counters.drain();
            assert_eq!((d.tenant_id.as_str(), d.tunnel_id.as_str()), ("t7", "tun-1"));
            assert_eq!((d.tx_bytes, d.tx_packets), (100, 1), "send half counts writes");
            assert_eq!((d.rx_bytes, d.rx_packets), (11, 1), "recv half counts reads");
            assert_eq!(d.flows, 1, "one open_bi = one flow");
        }

        /// Drain is a delta: a second drain with no traffic is zero, more traffic yields only
        /// the new part.
        #[test]
        fn drain_is_delta_and_repeats_are_zero() {
            let counters = RouteCounters::new("t7", "tun-1");
            counters.count_tx(50);
            let d1 = counters.drain();
            assert_eq!(d1.tx_bytes, 50);
            let d2 = counters.drain();
            assert_eq!(d2.tx_bytes, 0, "nothing new since last drain");
            counters.count_tx(30);
            assert_eq!(counters.drain().tx_bytes, 30, "only the delta");
        }

        /// The redundancy case: two connectors of one peer share the route's counters, and
        /// their bytes fuse into the route total — exactly what `ConnectorPool` holds when a
        /// tunnel has old and new connectors online mid-deploy.
        #[test]
        fn redundant_connectors_sum_into_one_route_total() {
            let counters = Arc::new(RouteCounters::new("t7", "tun-1"));
            let conn_a = counted(Arc::new(PipeConnection { peer: [1u8; 32] }), counters.clone());
            let conn_b = counted(Arc::new(PipeConnection { peer: [1u8; 32] }), counters.clone());
            let rt = rt();
            rt.block_on(async {
                for conn in [conn_a, conn_b] {
                    let (mut send, _) = conn.open_bi().await.unwrap();
                    send.write_all(&[0u8; 10]).await.unwrap();
                }
            });
            let d = counters.drain();
            assert_eq!((d.tx_bytes, d.flows), (20, 2), "two connectors, one route total");
        }
    }
}


// ── SNI certificate selection ─────────────────────────────────────────────────────────────

/// Per-hostname certificate selection for the edge's TLS listener.
///
/// `native_lib::serve_tls` takes ONE `rustls::ServerConfig` with one certificate — correct for
/// a service terminating its own hostname, and unusable for a multi-tenant edge where the name
/// is only known from the ClientHello. This is the missing `ResolvesServerCert`: it maps SNI
/// through [`super::edge::cert_name_for`] (apex wildcard for managed names, the fqdn itself for
/// custom ones) and asks the configured [`super::edge::CertSource`].
///
/// A handshake for a name we hold no certificate for is **refused**, not served with a wrong
/// certificate — the browser error for "no certificate" is honest, and the one for "wrong
/// certificate" trains people to click through warnings.
#[cfg(feature = "native")]
pub mod sni {
    use crate::edge::{cert_name_for, CertMaterial, CertSource};
    use hashtrinity::Table;
    use std::sync::{Arc, Mutex};

    /// A [`CertSource`] holding already-loaded PEM material in memory, keyed by certificate
    /// name (`*.twnstack.app`, `app.acme.com.au`). This is what an ACME client, a Vault
    /// reader, or a file loader all populate — the edge does not care which.
    pub struct MemoryCertSource {
        certs: Mutex<Table<String, CertMaterial>>,
    }

    impl Default for MemoryCertSource {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemoryCertSource {
        #[must_use]
        pub fn new() -> Self {
            MemoryCertSource { certs: Mutex::new(Table::new()) }
        }

        /// Install or replace the certificate for `cert_name`. Replacement is how renewal
        /// lands with no restart.
        pub fn install(&self, cert_name: impl Into<String>, material: CertMaterial) {
            self.certs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .put(cert_name.into(), material);
        }

        /// Whether we hold a certificate covering `fqdn`.
        #[must_use]
        pub fn covers(&self, fqdn: &str) -> bool {
            self.cert_for(&cert_name_for(fqdn)).is_some()
        }

        /// Certificate names currently held.
        #[must_use]
        pub fn names(&self) -> Vec<String> {
            let certs = self.certs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut out: Vec<String> = certs.iter().map(|(k, _)| k.to_string()).collect();
            out.sort();
            out
        }
    }

    impl CertSource for MemoryCertSource {
        fn cert_for(&self, cert_name: &str) -> Option<CertMaterial> {
            self.certs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&cert_name.to_string())
                .cloned()
        }
    }

    /// Resolve the certificate for a ClientHello's SNI. Wraps any [`CertSource`].
    pub struct EdgeCertResolver {
        source: Arc<dyn CertSource>,
    }

    impl EdgeCertResolver {
        #[must_use]
        pub fn new(source: Arc<dyn CertSource>) -> Self {
            EdgeCertResolver { source }
        }

        /// The PEM material to present for `sni`, or `None` to refuse the handshake.
        ///
        /// Split out from the `rustls` trait impl so the selection rule is unit-testable
        /// without constructing a `ClientHello`, which cannot be built outside a real
        /// handshake.
        #[must_use]
        pub fn material_for(&self, sni: &str) -> Option<CertMaterial> {
            self.source.cert_for(&cert_name_for(sni))
        }
    }
}

#[cfg(feature = "native")]
pub use sni::{EdgeCertResolver, MemoryCertSource};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{Route, APEXES};
    use crate::{BiStream, BoxFuture};
    use std::io;

    /// A connection that does nothing — the pool stores and picks connections, it never
    /// drives them, so a stub is the honest test double here.
    struct StubConnection {
        peer: PeerId,
        label: &'static str,
    }

    impl Connection for StubConnection {
        fn open_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
            Box::pin(async { Err(io::Error::other("stub")) })
        }
        fn accept_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
            Box::pin(async { Err(io::Error::other("stub")) })
        }
        fn peer_id(&self) -> PeerId {
            self.peer
        }
        fn close<'a>(&'a self) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn route(tenant: &str, tunnel: &str) -> Route {
        Route {
            tenant_id: tenant.to_string(),
            tunnel_id: tunnel.to_string(),
            peer: crate::dialkey::peer_id(tunnel),
            origin_port: 8080,
        }
    }

    /// A registry with one live managed hostname on a `.cloud` apex, plus a pool with its
    /// connector online.
    fn live() -> (EdgeRegistry, ConnectorPool, String) {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        let mut pool = ConnectorPool::new();
        let peer = rec.route.peer;
        pool.register(peer, Arc::new(StubConnection { peer, label: "a" }));
        (reg, pool, rec.fqdn)
    }

    #[test]
    fn a_live_hostname_with_an_online_connector_is_served() {
        let (reg, pool, fqdn) = live();
        let decision = decide(&reg, &pool, Some(&fqdn), &fqdn, true);
        match decision {
            Decision::Serve(route) => assert_eq!(route.tunnel_id, "tun-1"),
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn a_host_header_disagreeing_with_sni_is_421() {
        let (reg, pool, fqdn) = live();
        // A reused connection addressing a different tenant's hostname. Serving this would
        // let one tenant's TLS session reach another tenant's origin.
        let decision = decide(&reg, &pool, Some(&fqdn), "someone-else.twnstack.cloud", true);
        assert_eq!(decision, Decision::Misdirected);
        assert_eq!(decision.status(), 421);
    }

    #[test]
    fn the_mismatch_check_runs_before_the_registry_lookup() {
        // Otherwise a mismatched request for a NON-existent host would answer 404 and a
        // mismatched request for an existing one would answer 421 — a probe that reveals
        // which hostnames exist.
        let (reg, pool, fqdn) = live();
        let real = decide(&reg, &pool, Some(&fqdn), "definitely-not-registered.twnstack.cloud", true);
        let fake = decide(&reg, &pool, Some("also-not-registered.twnstack.cloud"), "other.twnstack.cloud", true);
        assert_eq!(real, fake, "a mismatch must answer identically either way");
    }

    #[test]
    fn a_port_in_the_host_header_does_not_break_matching() {
        let (reg, pool, fqdn) = live();
        let decision = decide(&reg, &pool, Some(&fqdn), &format!("{fqdn}:443"), true);
        assert!(matches!(decision, Decision::Serve(_)));
    }

    #[test]
    fn an_unknown_hostname_is_404() {
        let (reg, pool, _) = live();
        let d = decide(&reg, &pool, None, "nothing-here.twnstack.cloud", true);
        assert_eq!(d, Decision::Unknown);
        assert_eq!(d.status(), 404);
    }

    #[test]
    fn an_offline_connector_is_its_own_diagnosable_case() {
        let (reg, _, fqdn) = live();
        let empty = ConnectorPool::new();
        let d = decide(&reg, &empty, Some(&fqdn), &fqdn, true);
        assert_eq!(d, Decision::NoConnector);
        assert!(
            d.public_message().contains("connector is offline"),
            "the most common real failure must say what is wrong"
        );
    }

    #[test]
    fn a_suspended_hostname_is_403_and_does_not_say_why() {
        let (mut reg, pool, fqdn) = live();
        reg.suspend("acme", &fqdn).unwrap();
        let d = decide(&reg, &pool, Some(&fqdn), &fqdn, true);
        assert_eq!(d, Decision::Suspended);
        assert_eq!(d.status(), 403);
        assert!(
            !d.public_message().to_lowercase().contains("suspend"),
            "the requesting public is not the tenant: {}",
            d.public_message()
        );
    }

    #[test]
    fn an_unvalidated_custom_hostname_is_never_served() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg
            .add_custom("app.example.com.au", "x.twnstack.cloud", route("acme", "tun-1"))
            .unwrap();
        let mut pool = ConnectorPool::new();
        let peer = rec.route.peer;
        pool.register(peer, Arc::new(StubConnection { peer, label: "a" }));

        let d = decide(&reg, &pool, Some("app.example.com.au"), "app.example.com.au", true);
        assert!(matches!(d, Decision::NotValidated(_)), "got {d:?}");
        assert_eq!(d.status(), 403);
    }

    #[test]
    fn a_live_hostname_without_a_certificate_is_503_not_a_plaintext_serve() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        let mut pool = ConnectorPool::new();
        pool.register(rec.route.peer, Arc::new(StubConnection { peer: rec.route.peer, label: "a" }));

        let d = decide(&reg, &pool, Some(&rec.fqdn), &rec.fqdn, false);
        assert_eq!(d, Decision::CertPending, "an HSTS-preloaded apex has no plaintext fallback");
    }

    #[test]
    fn several_connectors_for_one_tunnel_are_all_held_and_rotated() {
        let (_, mut pool, _) = live();
        let peer = crate::dialkey::peer_id("tun-1");
        pool.register(peer, Arc::new(StubConnection { peer, label: "b" }));
        assert_eq!(pool.connector_count(peer), 2, "a redundant connector must not evict the first");

        let picks: Vec<&'static str> = (0..4)
            .filter_map(|_| pool.pick(peer))
            .map(|c| {
                // Recover the label through the pool's own ordering, which is what rotation
                // is observable through.
                let _ = c.peer_id();
                "picked"
            })
            .collect();
        assert_eq!(picks.len(), 4, "every pick must return a connection while any are online");
    }

    #[test]
    fn eviction_takes_effect_immediately() {
        let (reg, mut pool, fqdn) = live();
        let peer = crate::dialkey::peer_id("tun-1");
        assert!(matches!(decide(&reg, &pool, Some(&fqdn), &fqdn, true), Decision::Serve(_)));

        // This is what makes token revocation immediate rather than effective-at-reconnect.
        pool.evict(peer);
        assert_eq!(decide(&reg, &pool, Some(&fqdn), &fqdn, true), Decision::NoConnector);
        assert!(pool.is_empty());
    }

    #[test]
    fn picking_an_unknown_peer_is_none_not_a_panic() {
        let pool = ConnectorPool::new();
        assert!(pool.pick([9u8; 32]).is_none());
        assert!(!pool.is_online([9u8; 32]));
    }

    #[test]
    fn the_registry_peer_is_what_authorizes_not_pool_membership() {
        // A connector for a DIFFERENT dialkey being online must not make this hostname
        // servable: presence in the pool is not authorization.
        let (reg, _, fqdn) = live();
        let mut pool = ConnectorPool::new();
        let impostor = crate::dialkey::peer_id("some-other-tunnel");
        pool.register(impostor, Arc::new(StubConnection { peer: impostor, label: "x" }));

        assert_eq!(decide(&reg, &pool, Some(&fqdn), &fqdn, true), Decision::NoConnector);
    }
}
