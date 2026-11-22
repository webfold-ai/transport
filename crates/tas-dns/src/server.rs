//! The wire: UDP and TCP listeners, the request policy in front of hickory's `Catalog`, and the
//! response path (EDNS cap, truncation, RRL).
//!
//! hickory's own `Server` is deliberately not used: it spawns a task per datagram without a
//! bound, accepts any number of TCP connections, logs every query name at `info`, and offers no
//! hook before parsing. Here every packet first passes, in order: size bound, source sanity,
//! per-source budget, an in-flight permit — all before a byte is parsed — then policy, then the
//! catalog. The catalog, zone lookup semantics, NSEC proofs and the message codec are hickory's.
//!
//! ## What an authoritative-only server must refuse, and where
//!
//! * not `OpCode::Query` (UPDATE, NOTIFY, STATUS...) -> NOTIMP
//! * more or fewer than one question -> FORMERR
//! * class other than IN (so `version.bind` CH TXT too) -> REFUSED
//! * AXFR / IXFR, from anyone -> REFUSED (there are no zone transfers; replication is the mesh)
//! * names outside every hosted zone, with or without RD -> REFUSED (the catalog); RA is never set
//! * a hosted zone whose keys are unavailable -> SERVFAIL, never unsigned data under a stale DS
//! * unsupported EDNS version -> BADVERS (the catalog)

use crate::authority::Serving;
use crate::metrics::Metrics;
use crate::rrl::{Limiter, ResponseClass, Rrl, RrlDecision};
use async_trait::async_trait;
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::proto::op::{Edns, OpCode, ResponseCode};
use hickory_server::proto::rr::{DNSClass, Record, RecordType};
use hickory_server::proto::serialize::binary::BinEncoder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

/// Every bound on the wire path.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Largest UDP query accepted (anything bigger is dropped unparsed).
    pub max_udp_query: usize,
    /// Largest TCP query accepted.
    pub max_tcp_query: usize,
    /// UDP response size ceiling regardless of what the client advertises (DNS flag day 2020).
    pub edns_cap: u16,
    /// Queries being processed at once (UDP and TCP together).
    pub max_in_flight: usize,
    /// Open TCP connections.
    pub tcp_max_conns: usize,
    /// Open TCP connections per source address.
    pub tcp_per_ip: u32,
    /// Idle time allowed between TCP queries.
    pub tcp_idle: Duration,
    /// Queries served on one TCP connection.
    pub tcp_max_queries: u32,
    /// Longest a TCP connection may live.
    pub tcp_max_life: Duration,
    /// Per-network query budget (per second) and burst.
    pub budget_rate: u32,
    /// Burst headroom of the budget.
    pub budget_burst: u32,
    /// Response rate limit (identical responses per second per network) and burst.
    pub rrl_rate: u32,
    /// Burst headroom of RRL.
    pub rrl_burst: u32,
    /// Every Nth RRL-denied response is sent truncated (0 = never).
    pub rrl_slip: u32,
    /// Slots in each limiter table (memory bound).
    pub table_slots: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_udp_query: 1232,
            max_tcp_query: 4096,
            edns_cap: 1232,
            max_in_flight: 2048,
            tcp_max_conns: 512,
            tcp_per_ip: 8,
            tcp_idle: Duration::from_secs(8),
            tcp_max_queries: 100,
            tcp_max_life: Duration::from_secs(30),
            budget_rate: 200,
            budget_burst: 400,
            rrl_rate: 20,
            rrl_burst: 40,
            rrl_slip: 2,
            table_slots: 1 << 16,
        }
    }
}

/// Request policy in front of the catalog.
pub struct TasHandler {
    serving: Arc<Serving>,
    metrics: Arc<Metrics>,
}

impl TasHandler {
    /// A handler over `serving`.
    #[must_use]
    pub fn new(serving: Arc<Serving>, metrics: Arc<Metrics>) -> Self {
        TasHandler { serving, metrics }
    }

    async fn error<R: ResponseHandler>(
        request: &Request,
        code: ResponseCode,
        mut rh: R,
    ) -> ResponseInfo {
        let edns = request.edns.as_ref().map(|_| {
            let mut e = Edns::new();
            e.set_version(0);
            e.set_max_payload(1232);
            e.set_rcode_high(code.high());
            e
        });
        let resp = MessageResponseBuilder::new(&request.queries, edns.as_ref())
            .error_msg(&request.metadata, code);
        match rh.send_response(resp).await {
            Ok(i) => i,
            Err(_) => ResponseInfo::from(hickory_server::proto::op::Header {
                metadata: hickory_server::proto::op::Metadata::new(
                    request.metadata.id,
                    hickory_server::proto::op::MessageType::Response,
                    request.metadata.op_code,
                ),
                counts: hickory_server::proto::op::HeaderCounts::default(),
            }),
        }
    }
}

#[async_trait]
impl RequestHandler for TasHandler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        if request.metadata.op_code != OpCode::Query {
            return Self::error(request, ResponseCode::NotImp, response_handle).await;
        }
        let Ok(info) = request.request_info() else {
            return Self::error(request, ResponseCode::FormErr, response_handle).await;
        };
        let q = info.query;
        if q.query_class() != DNSClass::IN {
            return Self::error(request, ResponseCode::Refused, response_handle).await;
        }
        if matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR) {
            self.metrics.transfers_refused.inc();
            return Self::error(request, ResponseCode::Refused, response_handle).await;
        }
        if self.serving.is_failed(q.name()) {
            return Self::error(request, ResponseCode::ServFail, response_handle).await;
        }
        let catalog = self.serving.catalog();
        RequestHandler::handle_request::<R, T>(&*catalog, request, response_handle).await
    }
}

/// Everything the listeners share.
pub struct ServerCtx {
    handler: TasHandler,
    limiter: Limiter,
    rrl: Rrl,
    /// Counters.
    pub metrics: Arc<Metrics>,
    serving: Arc<Serving>,
    limits: ServerLimits,
    start: Instant,
    in_flight: Arc<Semaphore>,
    tcp_slots: Arc<Semaphore>,
    tcp_ips: Mutex<HashMap<IpAddr, u32>>,
}

impl ServerCtx {
    /// Build the shared context.
    #[must_use]
    pub fn new(serving: Arc<Serving>, metrics: Arc<Metrics>, limits: ServerLimits) -> Arc<Self> {
        Arc::new(ServerCtx {
            handler: TasHandler::new(serving.clone(), metrics.clone()),
            limiter: Limiter::new(limits.table_slots, limits.budget_rate, limits.budget_burst),
            rrl: Rrl::new(
                limits.table_slots,
                limits.rrl_rate,
                limits.rrl_burst,
                limits.rrl_slip,
            ),
            metrics,
            serving,
            in_flight: Arc::new(Semaphore::new(limits.max_in_flight.max(1))),
            tcp_slots: Arc::new(Semaphore::new(limits.tcp_max_conns.max(1))),
            tcp_ips: Mutex::new(HashMap::new()),
            limits,
            start: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }
}

/// Resolve when `rx` becomes `true` (or its sender is gone).
pub async fn wait_shutdown(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// A source address we can and should answer.
fn sane_source(a: &SocketAddr) -> bool {
    let ip = a.ip();
    a.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v4) => !v4.is_broadcast(),
            IpAddr::V6(_) => true,
        }
}

// ── response encoding ────────────────────────────────────────────────────────────────────────

fn encode<'a>(
    response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    max: u16,
) -> Result<(ResponseInfo, Vec<u8>), NetError> {
    let mut bytes = Vec::with_capacity(512);
    let mut enc = BinEncoder::new(&mut bytes);
    enc.set_max_size(max);
    let info = response
        .destructive_emit(&mut enc)
        .map_err(NetError::from)?;
    Ok((info, bytes))
}

/// An empty truncated copy of `full` (header + question), for RRL "slip".
fn slip_response(full: &[u8]) -> Option<Vec<u8>> {
    if full.len() < 12 {
        return None;
    }
    let mut i = 12usize;
    loop {
        let l = usize::from(*full.get(i)?);
        i += 1;
        if l == 0 {
            break;
        }
        if l & 0xC0 != 0 {
            return None;
        }
        i += l;
    }
    let end = i.checked_add(4)?;
    let mut out = full.get(..end)?.to_vec();
    *out.get_mut(2)? |= 0x02; // TC
    for b in out.get_mut(6..12)? {
        *b = 0; // ANCOUNT, NSCOUNT, ARCOUNT
    }
    Some(out)
}

#[derive(Clone)]
struct QueryCtx {
    qname: Arc<str>,
    qtype: u16,
    zone: Arc<str>,
}

fn class_of(code: ResponseCode, answers: u16, q: &QueryCtx) -> ResponseClass<'_> {
    match (code, answers) {
        (ResponseCode::NoError, a) if a > 0 => ResponseClass::Answer {
            qname: &q.qname,
            qtype: q.qtype,
        },
        (ResponseCode::NoError, _) => ResponseClass::Negative {
            zone: &q.zone,
            rcode: 0,
        },
        (ResponseCode::NXDomain, _) => ResponseClass::Negative {
            zone: &q.zone,
            rcode: 3,
        },
        (c, _) => ResponseClass::Error {
            rcode: u16::from(c),
        },
    }
}

#[derive(Clone)]
struct UdpResponder {
    sock: Arc<UdpSocket>,
    dst: SocketAddr,
    ctx: Arc<ServerCtx>,
    q: QueryCtx,
}

#[async_trait]
impl ResponseHandler for UdpResponder {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let cap = self.ctx.limits.edns_cap.max(512);
        let max = response
            .edns()
            .map_or(512, Edns::max_payload)
            .clamp(512, cap);
        let (info, bytes) = encode(response, max)?;
        let m = &self.ctx.metrics;
        m.count_rcode(u16::from(info.response_code));
        if info.truncation {
            m.truncated.inc();
        }
        let class = class_of(info.response_code, info.counts().answers, &self.q);
        let out = match self.ctx.rrl.check(self.dst.ip(), &class, self.ctx.now_ms()) {
            RrlDecision::Send => Some(bytes),
            RrlDecision::Drop => {
                m.rrl_dropped.inc();
                None
            }
            RrlDecision::Slip => {
                m.rrl_slipped.inc();
                slip_response(&bytes)
            }
        };
        if let Some(b) = out {
            // a failed send (ICMP unreachable, full buffer) is not an error for the query
            let _ = self.sock.send_to(&b, self.dst).await;
        }
        Ok(info)
    }
}

#[derive(Clone)]
struct TcpResponder {
    w: Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    ctx: Arc<ServerCtx>,
}

#[async_trait]
impl ResponseHandler for TcpResponder {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let (info, bytes) = encode(response, u16::MAX)?;
        self.ctx.metrics.count_rcode(u16::from(info.response_code));
        let len = u16::try_from(bytes.len()).map_err(|_| NetError::from("response too large"))?;
        let mut framed = Vec::with_capacity(bytes.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&bytes);
        let mut w = self.w.lock().await;
        match tokio::time::timeout(Duration::from_secs(5), w.write_all(&framed)).await {
            Ok(Ok(())) => Ok(info),
            _ => Err(NetError::from("tcp write failed")),
        }
    }
}

fn query_ctx(ctx: &ServerCtx, request: &Request) -> QueryCtx {
    match request.request_info() {
        Ok(i) => {
            let name = i.query.name();
            let zone = ctx
                .serving
                .zone_of(name)
                .map(|z| z.to_string())
                .unwrap_or_default();
            QueryCtx {
                qname: Arc::from(name.to_string().to_ascii_lowercase()),
                qtype: u16::from(i.query.query_type()),
                zone: Arc::from(zone),
            }
        }
        Err(_) => QueryCtx {
            qname: Arc::from(""),
            qtype: 0,
            zone: Arc::from(""),
        },
    }
}

// ── UDP ──────────────────────────────────────────────────────────────────────────────────────

/// Serve DNS over UDP on `sock` until `shutdown`.
pub async fn serve_udp(
    sock: Arc<UdpSocket>,
    ctx: Arc<ServerCtx>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let max = ctx.limits.max_udp_query;
    let mut buf = vec![0u8; max + 1];
    loop {
        let received = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            r = sock.recv_from(&mut buf) => r,
        };
        let Ok((len, src)) = received else {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        if len > max {
            ctx.metrics.oversize.inc();
            continue;
        }
        if !sane_source(&src) {
            continue;
        }
        if !ctx.limiter.allow(src.ip(), ctx.now_ms()) {
            ctx.metrics.budget_dropped.inc();
            continue;
        }
        let Ok(permit) = ctx.in_flight.clone().try_acquire_owned() else {
            ctx.metrics.overload_dropped.inc();
            continue;
        };
        let Some(data) = buf.get(..len).map(<[u8]>::to_vec) else {
            continue;
        };
        let (sock, ctx) = (sock.clone(), ctx.clone());
        tokio::spawn(async move {
            let _permit = permit;
            handle_datagram(data, src, sock, ctx).await;
        });
    }
}

async fn handle_datagram(
    data: Vec<u8>,
    src: SocketAddr,
    sock: Arc<UdpSocket>,
    ctx: Arc<ServerCtx>,
) {
    if data.len() < 12 {
        ctx.metrics.malformed.inc();
        return;
    }
    // QR=1: a response sent to a server port is a reflection attempt; never answer it
    if data.get(2).is_some_and(|b| b & 0x80 != 0) {
        ctx.metrics.malformed.inc();
        return;
    }
    ctx.metrics.queries_udp.inc();
    let Ok(request) = Request::from_bytes(data.clone(), src, Protocol::Udp) else {
        ctx.metrics.malformed.inc();
        // Header is intact (>= 12 bytes, QR=0): answer FORMERR, header only, through RRL.
        let mut out = data.get(..12).map(<[u8]>::to_vec).unwrap_or_default();
        if let Some(b) = out.get_mut(2) {
            *b = 0x80 | (*b & 0x78); // QR, keep opcode, clear AA/TC/RD
        }
        if let Some(b) = out.get_mut(3) {
            *b = 0x01; // FORMERR
        }
        for b in out.get_mut(4..12).unwrap_or(&mut []) {
            *b = 0;
        }
        let q = QueryCtx {
            qname: Arc::from(""),
            qtype: 0,
            zone: Arc::from(""),
        };
        ctx.metrics.count_rcode(1);
        if ctx.rrl.check(
            src.ip(),
            &class_of(ResponseCode::FormErr, 0, &q),
            ctx.now_ms(),
        ) == RrlDecision::Send
        {
            let _ = sock.send_to(&out, src).await;
        } else {
            ctx.metrics.rrl_dropped.inc();
        }
        return;
    };
    let q = query_ctx(&ctx, &request);
    let responder = UdpResponder {
        sock,
        dst: src,
        ctx: ctx.clone(),
        q,
    };
    let _ = RequestHandler::handle_request::<_, TokioTime>(&ctx.handler, &request, responder).await;
}

// ── TCP ──────────────────────────────────────────────────────────────────────────────────────

struct IpGuard {
    ctx: Arc<ServerCtx>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self
            .ctx
            .tcp_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
        self.ctx.metrics.tcp_open.dec();
    }
}

/// Serve DNS over TCP (RFC 7766 framing; RFC 9210: TCP is a first-class transport) until `shutdown`.
pub async fn serve_tcp(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            r = listener.accept() => r,
        };
        let Ok((stream, src)) = accepted else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        if !sane_source(&src) || !ctx.limiter.allow(src.ip(), ctx.now_ms()) {
            ctx.metrics.budget_dropped.inc();
            continue;
        }
        let Ok(slot) = ctx.tcp_slots.clone().try_acquire_owned() else {
            ctx.metrics.tcp_refused.inc();
            continue;
        };
        {
            let mut m = ctx
                .tcp_ips
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let n = m.entry(src.ip()).or_insert(0);
            if *n >= ctx.limits.tcp_per_ip {
                ctx.metrics.tcp_refused.inc();
                continue;
            }
            *n += 1;
        }
        ctx.metrics.tcp_open.inc();
        let guard = IpGuard {
            ctx: ctx.clone(),
            ip: src.ip(),
        };
        let ctx2 = ctx.clone();
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _guard = guard;
            tokio::select! {
                () = wait_shutdown(&mut sd) => {}
                () = tcp_conn(stream, src, ctx2) => {}
            }
        });
    }
}

async fn tcp_conn(stream: tokio::net::TcpStream, src: SocketAddr, ctx: Arc<ServerCtx>) {
    let (mut r, w) = stream.into_split();
    let w = Arc::new(tokio::sync::Mutex::new(w));
    let deadline = Instant::now() + ctx.limits.tcp_max_life;
    for _ in 0..ctx.limits.tcp_max_queries {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let wait = ctx.limits.tcp_idle.min(remaining);
        let mut lenb = [0u8; 2];
        if !matches!(
            tokio::time::timeout(wait, r.read_exact(&mut lenb)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let len = usize::from(u16::from_be_bytes(lenb));
        if len < 12 || len > ctx.limits.max_tcp_query {
            ctx.metrics.oversize.inc();
            return; // framing is unrecoverable once the length is untrusted
        }
        let mut data = vec![0u8; len];
        if !matches!(
            tokio::time::timeout(wait, r.read_exact(&mut data)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        if !ctx.limiter.allow(src.ip(), ctx.now_ms()) {
            ctx.metrics.budget_dropped.inc();
            return;
        }
        let Ok(permit) = ctx.in_flight.clone().try_acquire_owned() else {
            ctx.metrics.overload_dropped.inc();
            return;
        };
        ctx.metrics.queries_tcp.inc();
        if data.get(2).is_some_and(|b| b & 0x80 != 0) {
            ctx.metrics.malformed.inc();
            return;
        }
        let Ok(request) = Request::from_bytes(data, src, Protocol::Tcp) else {
            ctx.metrics.malformed.inc();
            return;
        };
        let responder = TcpResponder {
            w: w.clone(),
            ctx: ctx.clone(),
        };
        let _ =
            RequestHandler::handle_request::<_, TokioTime>(&ctx.handler, &request, responder).await;
        drop(permit);
    }
}
