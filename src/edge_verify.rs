//! Proof-of-control checks for BYO custom hostnames — the outbound half of `transport::edge`.
//!
//! `edge_dns` is the authority we *serve*; this is the recursive client we *ask*. Before the
//! edge will serve `app.acme.com.au` it must observe, in the customer's own DNS, either the
//! challenge TXT or a CNAME pointing at the managed hostname we handed them
//! ([`super::edge::Challenge`]).
//!
//! ## Why this must not consult our own authority
//!
//! The whole point of the check is that the answer comes from the *customer's* nameservers,
//! reached the way the public internet reaches them. Resolving through a split-horizon view,
//! a local hosts file, or our own [`super::edge_dns::ZoneAuthority`] would let a name we
//! already control satisfy a challenge about a name we do not — which is the entire
//! vulnerability class this check exists to close. [`NativeProbe::public`] therefore uses an
//! explicit public recursive configuration rather than the host's `/etc/resolv.conf`, and
//! [`NativeProbe::with_resolvers`] exists only for operators who deliberately run their own
//! trusted recursor.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the observed record set (what the customer's DNS actually publishes)
//! - **B/Map** = the sweep result (hostname → resulting state)
//! - **B/U** = the probe counter, kept by the registry
//! - **self** = the challenge (a DNS name proving control of a DNS name)

use super::edge::{Challenge, EdgeRegistry, HostnameState};
use super::BoxFuture;

/// What one probe saw in the customer's DNS for a challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    /// TXT strings found at `challenge.txt_name`.
    pub txt: Vec<String>,
    /// CNAME targets found at `challenge.fqdn`.
    pub cname: Vec<String>,
}

impl Observed {
    /// Whether what we saw satisfies `challenge` by either accepted proof.
    #[must_use]
    pub fn proves(&self, challenge: &Challenge) -> bool {
        self.proves_under(challenge, ProofPolicy::TxtOrCname)
    }

    /// As [`Self::proves`], restricted to the proofs `policy` allows.
    #[must_use]
    pub fn proves_under(&self, challenge: &Challenge, policy: ProofPolicy) -> bool {
        challenge.satisfied_by_txt(&self.txt)
            || (policy == ProofPolicy::TxtOrCname && challenge.satisfied_by_cname(&self.cname))
    }
}

/// Which observations count as proof of control.
///
/// A CNAME to our managed hostname proves only that *someone once pointed* the name at us. A
/// forgotten CNAME to a label that another tenant later holds (after the release quarantine
/// lapses) satisfies it without the domain owner doing anything. The TXT token is derived from a
/// server secret bound to the exact hostname and tenant, so only the domain's DNS controller can
/// publish it. The default is therefore [`ProofPolicy::TxtOnly`]; `TxtOrCname` is the lower-
/// friction option for deployments that accept the residual risk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProofPolicy {
    #[default]
    TxtOnly,
    TxtOrCname,
}

/// The DNS lookups a validation sweep needs. A trait so the sweep is testable without a
/// network — the alternative is a validation path only ever exercised in production.
pub trait DnsProbe: Send + Sync {
    /// Look up the challenge's TXT name and the hostname's CNAME, in the customer's DNS.
    fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed>;
}

/// Run one validation pass over every hostname awaiting proof.
///
/// Returns each hostname's resulting state so a caller can log or notify. `max_probes` caps
/// how many failed checks a hostname absorbs before it is failed outright — see
/// [`EdgeRegistry::record_probe`].
/// As [`sweep`], for a registry shared behind a tokio mutex (the edge's shape), under a
/// [`ProofPolicy`]. The registry lock is **not** held while the probe talks to the network: the
/// work list is snapshotted, probed lock-free, and each outcome applied under a short lock.
#[cfg(feature = "runtime-tokio")]
pub async fn sweep_shared(
    probe: &dyn DnsProbe,
    registry: &tokio::sync::Mutex<EdgeRegistry>,
    max_probes: i64,
    policy: ProofPolicy,
) -> Vec<(String, HostnameState)> {
    let pending = registry.lock().await.pending_validation();
    let mut results = Vec::with_capacity(pending.len());
    for record in pending {
        let Some(challenge) = record.challenge.as_ref() else { continue };
        let proven = probe.observe(challenge).await.proves_under(challenge, policy);
        if let Ok(state) = registry.lock().await.record_probe(&record.fqdn, proven, max_probes) {
            results.push((record.fqdn, state));
        }
    }
    results
}

pub async fn sweep(
    probe: &dyn DnsProbe,
    registry: &mut EdgeRegistry,
    max_probes: i64,
) -> Vec<(String, HostnameState)> {
    let pending = registry.pending_validation();
    let mut results = Vec::with_capacity(pending.len());
    for record in pending {
        let Some(challenge) = record.challenge.as_ref() else {
            continue;
        };
        let observed = probe.observe(challenge).await;
        let proven = observed.proves(challenge);
        if let Ok(state) = registry.record_probe(&record.fqdn, proven, max_probes) {
            results.push((record.fqdn, state));
        }
    }
    results
}

// ── The native resolver probe ─────────────────────────────────────────────────────────

/// A real recursive-resolver probe on this crate's own [`crate::dns`] wire format (UDP, with
/// TCP retry on truncation). Replaces the earlier hickory-resolver probe, which depended on a
/// crate that was never declared and so never compiled.
#[cfg(feature = "native")]
mod native_probe {
    use super::{Challenge, DnsProbe, Observed};
    use crate::dns::{Flags, Message, Name, Question, RData, Record, RecordType, ResponseCode};
    use crate::BoxFuture;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// How far a customer's CNAME chain is followed. Real chains are 1-3 hops; the cap exists
    /// so a looping chain terminates.
    const MAX_CNAME_HOPS: usize = 8;

    /// How one query is asked.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct QueryOptions {
        /// Set the RD bit: ask a recursive resolver to do the work. Clear it for a direct
        /// question to an authoritative server.
        pub recursion_desired: bool,
        /// Send an EDNS0 OPT record with the DO bit (RFC 3225), so a signed zone's answer carries
        /// its RRSIGs and DNSKEY/DS data. Also advertises a 1232-byte UDP payload.
        pub dnssec_ok: bool,
    }

    /// The UDP payload size advertised with EDNS0 (the DNS-flag-day-2020 recommendation: small
    /// enough to avoid fragmentation).
    const EDNS_UDP_PAYLOAD: u16 = 1232;
    /// OPT TTL field: extended-rcode 0, version 0, DO bit set (RFC 3225 §3).
    const EDNS_DO_TTL: u32 = 0x0000_8000;

    /// A one-shot DNS client on this crate's own wire format: UDP from a fresh random source port
    /// with a random id, TCP retry on truncation, and a reply believed only if it answers exactly
    /// the question asked (id, QR bit and echoed question). It is the transport under both the
    /// proof-of-control probe and [`crate::dns_health`].
    #[derive(Clone, Debug)]
    pub struct DnsClient {
        pub timeout: Duration,
    }

    impl Default for DnsClient {
        fn default() -> Self {
            DnsClient { timeout: Duration::from_secs(3) }
        }
    }

    impl DnsClient {
        #[must_use]
        pub fn new(timeout: Duration) -> Self {
            DnsClient { timeout }
        }

        /// Ask `server` one question. `None` on timeout, a transport error, an unparseable reply or
        /// one that does not answer this question; otherwise the reply **whatever its rcode** (the
        /// caller decides whether SERVFAIL or REFUSED matters — for a health check it does).
        pub async fn query(&self, server: SocketAddr, name: &Name, qtype: RecordType, opts: QueryOptions) -> Option<Message> {
            let id_bytes = crate::prim::random_bytes(2);
            let id = u16::from_be_bytes([*id_bytes.first()?, *id_bytes.get(1)?]);
            let mut query = Message {
                id,
                flags: Flags { recursion_desired: opts.recursion_desired, ..Flags::default() },
                questions: vec![Question::new(name.clone(), qtype)],
                ..Message::default()
            };
            if opts.dnssec_ok {
                query.additionals.push(Record { name: Name::root(), class: EDNS_UDP_PAYLOAD, ttl: EDNS_DO_TTL, data: RData::Unknown(41, Vec::new()) });
            }
            let reply = match tokio::time::timeout(self.timeout, udp_exchange(server, &query)).await {
                Ok(Some(m)) => m,
                _ => return None,
            };
            let reply = if reply.flags.truncated {
                tokio::time::timeout(self.timeout, tcp_exchange(server, &query)).await.ok()??
            } else {
                reply
            };
            answers_question(&query, &reply).then_some(reply)
        }
    }

    pub struct NativeProbe {
        resolvers: Vec<SocketAddr>,
        timeout: Duration,
    }

    impl NativeProbe {
        /// Resolve through public recursive resolvers from two independent operators
        /// (Cloudflare, Google), deliberately ignoring this host's own resolver configuration.
        /// A validation check that can be satisfied through our own split-horizon view is not
        /// a check. Two operators because one being unreachable would fail every pending
        /// validation at once and look like every customer misconfiguring their DNS.
        #[must_use]
        pub fn public() -> Self {
            Self::with_resolvers(
                ["1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53", "8.8.4.4:53"]
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect(),
            )
        }

        /// A probe using exactly these recursors, tried in order until one answers. Only
        /// correct where the operator runs a trusted recursor with no split-horizon view of
        /// customer domains.
        #[must_use]
        pub fn with_resolvers(resolvers: Vec<SocketAddr>) -> Self {
            NativeProbe { resolvers, timeout: Duration::from_secs(3) }
        }

        /// Ask each recursor in turn; the first usable (NOERROR / NXDOMAIN) answer wins.
        async fn query(&self, name: &str, qtype: RecordType) -> Option<Message> {
            let qname = Name::from_ascii(name).ok()?;
            let client = DnsClient::new(self.timeout);
            for resolver in &self.resolvers {
                let opts = QueryOptions { recursion_desired: true, dnssec_ok: false };
                if let Some(m) = client.query(*resolver, &qname, qtype, opts).await {
                    // Anything but a definitive answer (SERVFAIL, REFUSED...) tries the next recursor.
                    if matches!(m.flags.response_code, ResponseCode::NoError | ResponseCode::NxDomain) {
                        return Some(m);
                    }
                }
            }
            None
        }
    }

    /// A reply is usable only if it answers THIS question: id, QR bit and echoed question must
    /// match. Anything else is noise or an off-path spoof attempt and is treated as no answer.
    fn answers_question(query: &Message, reply: &Message) -> bool {
        reply.flags.response && reply.id == query.id && reply.questions.first() == query.questions.first()
    }

    async fn udp_exchange(resolver: SocketAddr, query: &Message) -> Option<Message> {
        let bind = if resolver.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        // A fresh socket per query: the OS picks a random source port, which is half of the
        // off-path spoofing defence (the random id is the other half).
        let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
        socket.send_to(&query.to_bytes(), resolver).await.ok()?;
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.ok()?;
            if from != resolver {
                continue;
            }
            if let Ok(m) = Message::from_bytes(&buf[..n]) {
                if m.id == query.id {
                    return Some(m);
                }
            }
        }
    }

    async fn tcp_exchange(resolver: SocketAddr, query: &Message) -> Option<Message> {
        let mut stream = tokio::net::TcpStream::connect(resolver).await.ok()?;
        let bytes = query.to_bytes();
        let len = u16::try_from(bytes.len()).ok()?;
        stream.write_all(&len.to_be_bytes()).await.ok()?;
        stream.write_all(&bytes).await.ok()?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        stream.read_exact(&mut body).await.ok()?;
        Message::from_bytes(&body).ok()
    }

    impl DnsProbe for NativeProbe {
        fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed> {
            Box::pin(async move {
                let mut observed = Observed::default();

                // TXT at `_twn-challenge.<fqdn>`. A TXT record is a SEQUENCE of <=255-byte
                // strings on the wire; segments are joined before comparison.
                if let Some(reply) = self.query(&challenge.txt_name, RecordType::Txt).await {
                    for record in &reply.answers {
                        if let RData::Txt(segments) = &record.data {
                            observed.txt.push(String::from_utf8_lossy(&segments.concat()).into_owned());
                        }
                    }
                }

                // The CNAME chain from the hostname itself. Asked for explicitly (rather than
                // following an address lookup) so we see the aliases, not what they resolve to.
                let mut current = challenge.fqdn.clone();
                for _ in 0..MAX_CNAME_HOPS {
                    let Some(reply) = self.query(&current, RecordType::Cname).await else { break };
                    let Ok(owner) = Name::from_ascii(&current) else { break };
                    let next = reply.answers.iter().find_map(|r| match &r.data {
                        RData::Cname(target) if r.name == owner => Some(target.to_ascii()),
                        _ => None,
                    });
                    match next {
                        Some(target) => {
                            observed.cname.push(target.clone());
                            current = target;
                        }
                        None => break,
                    }
                }
                observed
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::dns::Record;
        use tokio::net::{TcpListener, UdpSocket};

        /// Serve canned answers: `answer(query) -> Message`. UDP only unless `tcp` is set.
        async fn serve(
            answer: impl Fn(&Message) -> Message + Send + Sync + 'static,
            truncate_udp: bool,
        ) -> SocketAddr {
            let answer = std::sync::Arc::new(answer);
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            let udp = UdpSocket::bind(addr).await.unwrap();
            let a = answer.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((n, peer)) = udp.recv_from(&mut buf).await else { return };
                    let Ok(q) = Message::from_bytes(&buf[..n]) else { continue };
                    let mut r = if truncate_udp {
                        let mut r = Message::response(q.id);
                        r.questions = q.questions.clone();
                        r.flags.truncated = true;
                        r
                    } else {
                        a(&q)
                    };
                    r.id = q.id;
                    let _ = udp.send_to(&r.to_bytes(), peer).await;
                }
            });
            let a = answer;
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = tcp.accept().await else { return };
                    let a = a.clone();
                    tokio::spawn(async move {
                        let mut l = [0u8; 2];
                        if s.read_exact(&mut l).await.is_err() { return }
                        let mut body = vec![0u8; usize::from(u16::from_be_bytes(l))];
                        if s.read_exact(&mut body).await.is_err() { return }
                        let Ok(q) = Message::from_bytes(&body) else { return };
                        let r = a(&q).to_bytes();
                        let _ = s.write_all(&u16::try_from(r.len()).unwrap().to_be_bytes()).await;
                        let _ = s.write_all(&r).await;
                    });
                }
            });
            addr
        }

        fn reply_to(q: &Message, answers: Vec<Record>) -> Message {
            let mut r = Message::response(q.id);
            r.questions = q.questions.clone();
            r.answers = answers;
            r
        }

        fn challenge() -> Challenge {
            Challenge::derive("app.acme.com.au", "acme", "amber-wren-1a2b3c.tascloud.app", b"s")
        }

        #[tokio::test]
        async fn follows_a_multi_hop_cname_chain_to_our_target() {
            let ch = challenge();
            let addr = serve(
                |q| {
                    let name = q.questions[0].name.to_ascii();
                    let rec = |from: &str, to: &str| {
                        Record::new(Name::from_ascii(from).unwrap(), 60, RData::Cname(Name::from_ascii(to).unwrap()))
                    };
                    match name.as_str() {
                        "app.acme.com.au." => reply_to(q, vec![rec("app.acme.com.au", "edge.vendor.example")]),
                        "edge.vendor.example." => reply_to(q, vec![rec("edge.vendor.example", "amber-wren-1a2b3c.tascloud.app")]),
                        _ => reply_to(q, vec![]),
                    }
                },
                false,
            )
            .await;
            let observed = NativeProbe::with_resolvers(vec![addr]).observe(&ch).await;
            assert!(observed.proves(&ch), "chain landed on the target: {observed:?}");
        }

        #[tokio::test]
        async fn txt_proof_is_read_and_segments_are_joined() {
            let ch = challenge();
            let token = ch.token.clone();
            let addr = serve(
                move |q| {
                    if q.questions[0].qtype == RecordType::Txt {
                        let (a, b) = token.split_at(30);
                        reply_to(q, vec![
                            Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![b"v=spf1 ~all".to_vec()])),
                            Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![a.as_bytes().to_vec(), b.as_bytes().to_vec()])),
                        ])
                    } else {
                        reply_to(q, vec![])
                    }
                },
                false,
            )
            .await;
            assert!(NativeProbe::with_resolvers(vec![addr]).observe(&ch).await.proves(&ch));
        }

        #[tokio::test]
        async fn truncated_udp_answers_are_retried_over_tcp() {
            let ch = challenge();
            let token = ch.token.clone();
            let addr = serve(
                move |q| {
                    reply_to(q, vec![Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![token.clone().into_bytes()]))])
                },
                true,
            )
            .await;
            assert!(NativeProbe::with_resolvers(vec![addr]).observe(&ch).await.proves(&ch));
        }

        #[tokio::test]
        async fn a_dead_first_resolver_fails_over_to_the_next() {
            let ch = challenge();
            let token = ch.token.clone();
            let live = serve(
                move |q| reply_to(q, vec![Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![token.clone().into_bytes()]))]),
                false,
            )
            .await;
            // A bound-but-silent UDP socket: the first recursor never answers.
            let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut probe = NativeProbe::with_resolvers(vec![dead.local_addr().unwrap(), live]);
            probe.timeout = Duration::from_millis(300);
            assert!(probe.observe(&ch).await.proves(&ch));
        }

        #[tokio::test]
        async fn the_client_asks_for_dnssec_records_only_when_told_to_and_surfaces_every_rcode() {
            // The server reports back what it was sent: RD bit, whether an OPT record carried
            // DO, and the advertised payload size, all in the answer's TXT strings.
            let addr = serve(
                |q| {
                    let opt = q.additionals.iter().find(|r| r.data.record_type() == RecordType::Unknown(41));
                    let describe = format!(
                        "rd={} opt={} do={} size={}",
                        q.flags.recursion_desired,
                        opt.is_some(),
                        opt.is_some_and(|o| o.ttl & 0x8000 != 0),
                        opt.map_or(0, |o| o.class)
                    );
                    let mut r = reply_to(q, vec![Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![describe.into_bytes()]))]);
                    if q.questions[0].name.to_ascii() == "refused.example." {
                        r.answers.clear();
                        r.flags.response_code = ResponseCode::Refused;
                    }
                    r
                },
                false,
            )
            .await;
            let client = DnsClient::new(Duration::from_secs(2));
            let ask = |name: &str, opts: QueryOptions| {
                let name = Name::from_ascii(name).unwrap();
                let client = client.clone();
                async move { client.query(addr, &name, RecordType::Txt, opts).await }
            };
            let text = |m: &Message| match &m.answers[0].data {
                RData::Txt(s) => String::from_utf8(s.concat()).unwrap(),
                other => panic!("{other:?}"),
            };
            let plain = ask("x.example", QueryOptions { recursion_desired: true, dnssec_ok: false }).await.unwrap();
            assert_eq!(text(&plain), "rd=true opt=false do=false size=0", "no EDNS unless asked");
            let signed = ask("x.example", QueryOptions { recursion_desired: false, dnssec_ok: true }).await.unwrap();
            assert_eq!(text(&signed), "rd=false opt=true do=true size=1232");
            let refused = ask("refused.example", QueryOptions::default()).await.expect("a REFUSED reply is a reply");
            assert_eq!(refused.flags.response_code, ResponseCode::Refused);
            // ...while the proof-of-control probe still treats it as "try the next resolver".
            let probe = NativeProbe::with_resolvers(vec![addr]);
            assert!(probe.query("refused.example", RecordType::Txt).await.is_none());
        }

        #[tokio::test]
        async fn a_reply_with_the_wrong_question_is_not_believed() {
            let ch = challenge();
            let token = ch.token.clone();
            let addr = serve(
                move |q| {
                    // Spoof-shaped: right id, but the echoed question is for another name.
                    let mut r = reply_to(q, vec![Record::new(q.questions[0].name.clone(), 60, RData::Txt(vec![token.clone().into_bytes()]))]);
                    r.questions = vec![Question::new(Name::from_ascii("other.example").unwrap(), q.questions[0].qtype)];
                    r
                },
                false,
            )
            .await;
            assert!(!NativeProbe::with_resolvers(vec![addr]).observe(&ch).await.proves(&ch));
        }
    }
}

#[cfg(feature = "native")]
pub use native_probe::{DnsClient, NativeProbe, QueryOptions};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{HostnameState, Route};
    use apeiron::map::hashtrinity::Table;

    /// A probe answering from a fixed table — the customer's DNS as we would find it.
    struct StaticProbe {
        txt: Table<String, Vec<String>>,
        cname: Table<String, Vec<String>>,
    }

    impl StaticProbe {
        fn new() -> Self {
            StaticProbe { txt: Table::new(), cname: Table::new() }
        }
        fn with_txt(mut self, name: &str, values: Vec<&str>) -> Self {
            self.txt.put(name.to_string(), values.into_iter().map(String::from).collect());
            self
        }
        fn with_cname(mut self, name: &str, targets: Vec<&str>) -> Self {
            self.cname.put(name.to_string(), targets.into_iter().map(String::from).collect());
            self
        }
    }

    impl DnsProbe for StaticProbe {
        fn observe<'a>(&'a self, challenge: &'a Challenge) -> BoxFuture<'a, Observed> {
            Box::pin(async move {
                Observed {
                    txt: self.txt.get(&challenge.txt_name).cloned().unwrap_or_default(),
                    cname: self.cname.get(&challenge.fqdn).cloned().unwrap_or_default(),
                }
            })
        }
    }

    fn route() -> Route {
        Route {
            tenant_id: "acme".to_string(),
            tunnel_id: "tun-1".to_string(),
            peer: crate::dialkey::peer_id("tun-1"),
            origin_port: 8080,
        }
    }

    fn registry_with_pending() -> (EdgeRegistry, Challenge) {
        let mut reg = EdgeRegistry::new(b"secret".to_vec());
        let apex = crate::edge::APEXES.iter().find(|a| a.zone == "tascloud.app").unwrap();
        reg.claim_managed_label(apex, "amber-wren-1a2b3c", route()).unwrap();
        let rec = reg
            .add_custom("app.example.com.au", "amber-wren-1a2b3c.tascloud.app", route())
            .unwrap();
        let challenge = rec.challenge.clone().unwrap();
        (reg, challenge)
    }

    #[tokio::test]
    async fn the_txt_proof_validates() {
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_txt(&challenge.txt_name, vec![&challenge.token]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, HostnameState::PendingCert);
    }

    #[cfg(feature = "runtime-tokio")]
    #[tokio::test]
    async fn txt_only_policy_refuses_a_cname_that_may_be_a_forgotten_record() {
        let (reg, challenge) = registry_with_pending();
        let reg = tokio::sync::Mutex::new(reg);
        let probe = StaticProbe::new().with_cname(&challenge.fqdn, vec![&challenge.cname_target]);
        let results = sweep_shared(&probe, &reg, 5, ProofPolicy::TxtOnly).await;
        assert_eq!(results[0].1, HostnameState::PendingDns, "a CNAME alone must not prove control by default");
        let results = sweep_shared(&probe, &reg, 5, ProofPolicy::TxtOrCname).await;
        assert_eq!(results[0].1, HostnameState::PendingCert, "...unless the deployment opts in");

        let (reg, challenge) = registry_with_pending();
        let reg = tokio::sync::Mutex::new(reg);
        let probe = StaticProbe::new().with_txt(&challenge.txt_name, vec![&challenge.token]);
        assert_eq!(sweep_shared(&probe, &reg, 5, ProofPolicy::default()).await[0].1, HostnameState::PendingCert);
    }

    #[tokio::test]
    async fn the_cname_proof_validates() {
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_cname(&challenge.fqdn, vec![&challenge.cname_target]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingCert);
    }

    #[tokio::test]
    async fn a_cname_to_someone_elses_hostname_does_not_validate() {
        let (mut reg, challenge) = registry_with_pending();
        // Pointing at a DIFFERENT tenant's managed hostname must not prove anything — it is
        // still "a CNAME into our zone", which a naive suffix check would accept.
        let probe = StaticProbe::new().with_cname(&challenge.fqdn, vec!["someone-else-9f8e7d.tascloud.app"]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingDns, "must still be unproven");
    }

    #[tokio::test]
    async fn a_token_issued_for_another_domain_does_not_validate() {
        let (mut reg, challenge) = registry_with_pending();
        let foreign = Challenge::derive("app.other.com.au", "acme", "x.tascloud.app", b"secret");
        let probe = StaticProbe::new().with_txt(&challenge.txt_name, vec![&foreign.token]);

        let results = sweep(&probe, &mut reg, 5).await;
        assert_eq!(results[0].1, HostnameState::PendingDns);
    }

    #[tokio::test]
    async fn an_unconfigured_domain_eventually_fails_rather_than_polling_forever() {
        let (mut reg, _challenge) = registry_with_pending();
        let probe = StaticProbe::new();

        for _ in 0..2 {
            assert_eq!(sweep(&probe, &mut reg, 3).await[0].1, HostnameState::PendingDns);
        }
        let last = sweep(&probe, &mut reg, 3).await;
        assert!(matches!(last[0].1, HostnameState::Failed(_)));
        assert!(sweep(&probe, &mut reg, 3).await.is_empty(), "a failed hostname leaves the sweep");
    }

    #[tokio::test]
    async fn a_sweep_over_nothing_pending_is_a_no_op() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        assert!(sweep(&StaticProbe::new(), &mut reg, 5).await.is_empty());
    }

    #[tokio::test]
    async fn extra_unrelated_txt_records_do_not_prevent_validation() {
        // Real zones carry SPF, DMARC, verification tokens from five other vendors. The
        // proof must be "one of these matches", not "the only record is ours".
        let (mut reg, challenge) = registry_with_pending();
        let probe = StaticProbe::new().with_txt(
            &challenge.txt_name,
            vec!["v=spf1 include:_spf.google.com ~all", "some-other-vendor=abc123", &challenge.token],
        );

        assert_eq!(sweep(&probe, &mut reg, 5).await[0].1, HostnameState::PendingCert);
    }
}
