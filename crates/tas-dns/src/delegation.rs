//! Onboarding checks (RFC 0032 §3.1, §3.5): before a registration is signed for a customer
//! zone, prove from the parent's own answers that the delegation is real, is ours alone, and
//! cannot strand the zone behind a stale DS.
//!
//! [`DelegationCheck::evaluate`] is pure: parent facts in, verdict out. Where the facts come
//! from is a [`ParentProbe`]; tests inject a fake, production uses [`StubParentProbe`], which
//! asks the parent zone's own nameservers (not a resolver's cache) over UDP with TCP fallback.

use crate::build::DsData;
use crate::escape::esc;
use async_trait::async_trait;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the parent zone says about a child zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentView {
    /// The parent zone that was asked.
    pub parent_zone: Name,
    /// The NS names the parent delegates the child to.
    pub ns: BTreeSet<Name>,
    /// The DS records the parent holds for the child.
    pub ds: Vec<DsData>,
}

/// Why the parent could not be consulted. Always fail-closed: no view, no onboarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// No parent zone or no parent nameserver could be found.
    NoParent,
    /// Nameservers did not answer, or answered SERVFAIL / garbage.
    Unreachable(String),
    /// Parent nameservers disagreed with each other.
    Inconsistent,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::NoParent => f.write_str("no parent zone found"),
            ProbeError::Unreachable(w) => write!(f, "parent unreachable: {}", esc(w)),
            ProbeError::Inconsistent => f.write_str("parent nameservers disagree"),
        }
    }
}

/// Source of parent-side facts.
#[async_trait]
pub trait ParentProbe: Send + Sync {
    /// The parent's NS and DS records for `zone`.
    async fn parent_view(&self, zone: &Name) -> Result<ParentView, ProbeError>;
}

/// What we intend to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// The DS records for the KSKs we hold, if the zone will be signed; empty means unsigned.
    pub expected_ds: Vec<DsData>,
}

/// The acceptance rules.
#[derive(Debug, Clone)]
pub struct DelegationCheck {
    /// Our nameserver names.
    pub our_nameservers: BTreeSet<Name>,
    /// How many of our nameservers the parent must delegate to (capped at how many we have).
    pub min_ns: usize,
}

/// The DS situation of an accepted delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsState {
    /// Unsigned zone, no DS at the parent: nothing to do.
    Unsigned,
    /// Signed zone, no DS at the parent yet: the zone is served signed but insecure until the
    /// customer (or CDS automation) publishes these DS records.
    SignedAwaitingDs {
        /// The DS records the parent should add.
        publish: Vec<DsData>,
    },
    /// Signed zone, and the parent's DS matches a key we hold.
    SignedAnchored {
        /// Parent DS records that match none of our keys (harmless but should be removed).
        extra: Vec<DsData>,
    },
}

/// An accepted delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// How many of our nameservers are delegated.
    pub ours: usize,
    /// DS situation.
    pub ds: DsState,
}

/// Why a delegation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// The parent has no NS records for the zone: the customer has not delegated yet.
    NotDelegated,
    /// The parent delegates to nameservers that are not ours (lame / split / third-party).
    Lame {
        /// The foreign nameserver names.
        foreign: Vec<String>,
    },
    /// Fewer of our nameservers are delegated than required.
    Insufficient {
        /// Delegated to us.
        have: usize,
        /// Required.
        need: usize,
    },
    /// The parent holds a DS for the zone and we hold no matching key: validating resolvers
    /// would SERVFAIL the zone as soon as we served it.
    StaleDs,
    /// The parent holds a DS but the zone would be served unsigned.
    UnsignedUnderDs,
    /// The parent could not be consulted.
    Probe(ProbeError),
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::NotDelegated => f.write_str("the parent zone does not delegate this zone"),
            DelegationError::Lame { foreign } => write!(f, "the parent delegates to nameservers that are not ours: {}", foreign.iter().map(|n| esc(n)).collect::<Vec<_>>().join(", ")),
            DelegationError::Insufficient { have, need } => write!(f, "only {have} of our nameservers are delegated, {need} required"),
            DelegationError::StaleDs => f.write_str("the parent holds a DS record that matches none of our keys; remove it first"),
            DelegationError::UnsignedUnderDs => f.write_str("the parent holds a DS record but the zone would be served unsigned; remove the DS or enable DNSSEC"),
            DelegationError::Probe(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DelegationError {}

impl DelegationCheck {
    /// The pure rule set.
    pub fn evaluate(
        &self,
        view: &ParentView,
        expect: &Expectation,
    ) -> Result<Verdict, DelegationError> {
        if view.ns.is_empty() {
            return Err(DelegationError::NotDelegated);
        }
        let foreign: Vec<String> = view
            .ns
            .iter()
            .filter(|n| !self.our_nameservers.contains(*n))
            .map(hickory_proto::rr::Name::to_ascii)
            .collect();
        if !foreign.is_empty() {
            return Err(DelegationError::Lame { foreign });
        }
        let ours = view.ns.len();
        let need = self.min_ns.min(self.our_nameservers.len()).max(1);
        if ours < need {
            return Err(DelegationError::Insufficient { have: ours, need });
        }
        let signed = !expect.expected_ds.is_empty();
        let ds = if view.ds.is_empty() {
            if signed {
                DsState::SignedAwaitingDs {
                    publish: expect.expected_ds.clone(),
                }
            } else {
                DsState::Unsigned
            }
        } else if !signed {
            return Err(DelegationError::UnsignedUnderDs);
        } else {
            let (mine, extra): (Vec<&DsData>, Vec<&DsData>) =
                view.ds.iter().partition(|d| expect.expected_ds.contains(d));
            if mine.is_empty() {
                return Err(DelegationError::StaleDs);
            }
            DsState::SignedAnchored {
                extra: extra.into_iter().cloned().collect(),
            }
        };
        Ok(Verdict { ours, ds })
    }

    /// Ask `probe`, then evaluate.
    pub async fn check(
        &self,
        probe: &dyn ParentProbe,
        zone: &Name,
        expect: &Expectation,
    ) -> Result<Verdict, DelegationError> {
        let view = probe
            .parent_view(zone)
            .await
            .map_err(DelegationError::Probe)?;
        self.evaluate(&view, expect)
    }
}

// ── the real probe ───────────────────────────────────────────────────────────────────────────

/// Finds the parent zone's nameservers through a recursive resolver, then asks THOSE servers
/// (recursion off, DO on) what they say about the child. The resolver is used only for
/// discovery (parent zone cut, nameserver addresses); the delegation facts come from the
/// parent's own authoritative answers, and every parent nameserver that answers must agree.
///
/// Not performed: DNSSEC validation of the parent's answers. A forged parent answer requires an
/// on-path attacker on this host's egress path; run the probe from a network you trust, or put a
/// validating resolver in `resolver` and extend this probe to require the AD bit.
pub struct StubParentProbe {
    resolver: SocketAddr,
    parent_port: u16,
    timeout: Duration,
}

const MAX_PARENT_DEPTH: usize = 6;
const MAX_PARENT_NS: usize = 4;

impl StubParentProbe {
    /// A probe using `resolver` for discovery; parent nameservers are queried on port 53.
    #[must_use]
    pub fn new(resolver: SocketAddr) -> Self {
        StubParentProbe {
            resolver,
            parent_port: 53,
            timeout: Duration::from_secs(3),
        }
    }

    /// Override the port parent nameservers are queried on (tests).
    #[must_use]
    pub fn with_parent_port(mut self, port: u16) -> Self {
        self.parent_port = port;
        self
    }

    async fn ask(
        &self,
        server: SocketAddr,
        name: &Name,
        ty: RecordType,
        recurse: bool,
    ) -> Result<Message, ProbeError> {
        let mut query = Message::query();
        query.metadata.op_code = OpCode::Query;
        query.metadata.id = random_id().map_err(|()| {
            ProbeError::Unreachable(
                "the system RNG failed; not sending a query with a predictable ID".into(),
            )
        })?;
        query.metadata.recursion_desired = recurse;
        query.add_query(Query::query(name.clone(), ty));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        query.set_edns(edns);
        let bytes = query
            .to_bytes()
            .map_err(|_| ProbeError::Unreachable("encode".into()))?;
        let bind: SocketAddr = if server.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        sock.send_to(&bytes, server)
            .await
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let first = loop {
            let (n, from) = tokio::time::timeout(self.timeout, sock.recv_from(&mut buf))
                .await
                .map_err(|_| ProbeError::Unreachable("timeout".into()))?
                .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
            if from != server {
                continue; // not from the server we asked
            }
            let parsed = Message::from_bytes(buf.get(..n).unwrap_or(&[]))
                .map_err(|_| ProbeError::Unreachable("garbage".into()))?;
            if parsed.metadata.id == query.metadata.id {
                break parsed;
            }
        };
        if !first.metadata.truncation {
            return Ok(first);
        }
        // truncated: retry over TCP
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(server))
            .await
            .map_err(|_| ProbeError::Unreachable("tcp timeout".into()))?
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        let mut framed = u16::try_from(bytes.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&bytes);
        stream
            .write_all(&framed)
            .await
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| ProbeError::Unreachable("tcp timeout".into()))?
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut body))
            .await
            .map_err(|_| ProbeError::Unreachable("tcp timeout".into()))?
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        let reply =
            Message::from_bytes(&body).map_err(|_| ProbeError::Unreachable("garbage".into()))?;
        if reply.metadata.id != query.metadata.id {
            return Err(ProbeError::Unreachable("id mismatch".into()));
        }
        Ok(reply)
    }

    async fn ns_names(&self, zone: &Name) -> Result<Option<BTreeSet<Name>>, ProbeError> {
        let m = self.ask(self.resolver, zone, RecordType::NS, true).await?;
        if m.metadata.response_code != ResponseCode::NoError {
            return Ok(None);
        }
        let set: BTreeSet<Name> = m
            .answers
            .iter()
            .filter(|r| r.name.to_lowercase() == zone.to_lowercase())
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.to_lowercase()),
                _ => None,
            })
            .collect();
        Ok((!set.is_empty()).then_some(set))
    }

    async fn address_of(&self, host: &Name) -> Option<IpAddr> {
        for ty in [RecordType::A, RecordType::AAAA] {
            if let Ok(m) = self.ask(self.resolver, host, ty, true).await {
                for r in &m.answers {
                    if let Some(ip) = r.data.ip_addr() {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }
}

/// A DNS message ID from the system RNG. The ID (with the kernel's random source port) is what a
/// spoofed answer has to guess, so a failing RNG must stop the query: the old `let _ = fill(..)`
/// sent every query with ID 0 and nobody noticed.
fn random_id() -> Result<u16, ()> {
    random_id_with(&|b| {
        use aws_lc_rs::rand::SecureRandom;
        aws_lc_rs::rand::SystemRandom::new().fill(b).map_err(|_| ())
    })
}

/// [`random_id`] over an injectable fill (the test seam).
fn random_id_with(fill: &dyn Fn(&mut [u8]) -> Result<(), ()>) -> Result<u16, ()> {
    let mut b = [0u8; 2];
    fill(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

#[async_trait]
impl ParentProbe for StubParentProbe {
    async fn parent_view(&self, zone: &Name) -> Result<ParentView, ProbeError> {
        // 1. the closest enclosing zone cut
        let mut parent = zone.base_name();
        let mut parent_ns = None;
        for _ in 0..MAX_PARENT_DEPTH {
            if parent.is_root() {
                break;
            }
            if let Some(ns) = self.ns_names(&parent).await? {
                parent_ns = Some(ns);
                break;
            }
            parent = parent.base_name();
        }
        let parent_ns = parent_ns.ok_or(ProbeError::NoParent)?;

        // 2. ask each parent nameserver directly, and require agreement
        let mut views: Vec<(BTreeSet<Name>, Vec<DsData>)> = Vec::new();
        for host in parent_ns.iter().take(MAX_PARENT_NS) {
            let Some(ip) = self.address_of(host).await else {
                continue;
            };
            let server = SocketAddr::new(ip, self.parent_port);
            let (Ok(ns_msg), Ok(ds_msg)) = (
                self.ask(server, zone, RecordType::NS, false).await,
                self.ask(server, zone, RecordType::DS, false).await,
            ) else {
                continue;
            };
            if matches!(
                ns_msg.metadata.response_code,
                ResponseCode::ServFail | ResponseCode::Refused
            ) || ds_msg.metadata.response_code == ResponseCode::ServFail
            {
                continue;
            }
            let zl = zone.to_lowercase();
            let ns: BTreeSet<Name> = ns_msg
                .answers
                .iter()
                .chain(ns_msg.authorities.iter())
                .filter(|r| r.name.to_lowercase() == zl)
                .filter_map(|r| match &r.data {
                    RData::NS(n) => Some(n.0.to_lowercase()),
                    _ => None,
                })
                .collect();
            let mut ds: Vec<DsData> = ds_msg
                .answers
                .iter()
                .filter(|r| r.name.to_lowercase() == zl)
                .filter_map(|r| match &r.data {
                    RData::DNSSEC(DNSSECRData::DS(d)) => Some(DsData {
                        key_tag: d.key_tag(),
                        algorithm: u8::from(d.algorithm()),
                        digest_type: u8::from(d.digest_type()),
                        digest: d.digest().to_vec(),
                    }),
                    _ => None,
                })
                .collect();
            ds.sort_by(|a, b| (a.key_tag, &a.digest).cmp(&(b.key_tag, &b.digest)));
            views.push((ns, ds));
        }
        let Some((first_ns, first_ds)) = views.first().cloned() else {
            return Err(ProbeError::Unreachable(
                "no parent nameserver answered".into(),
            ));
        };
        if views.iter().any(|(n, d)| *n != first_ns || *d != first_ds) {
            return Err(ProbeError::Inconsistent);
        }
        Ok(ParentView {
            parent_zone: parent,
            ns: first_ns,
            ds: first_ds,
        })
    }
}

#[cfg(test)]
mod rng_tests {
    use super::{random_id, random_id_with};

    #[test]
    fn a_failing_rng_stops_the_query_instead_of_sending_id_zero() {
        assert!(random_id_with(&|_| Err(())).is_err());
        // The old behaviour: ignore the error and keep the zero-filled buffer.
        assert_eq!(
            random_id_with(&|b| {
                b.fill(0);
                Ok(())
            }),
            Ok(0),
            "a source that succeeds is trusted; only failure is refused"
        );
    }

    #[test]
    fn the_system_rng_gives_varying_ids() {
        let ids: std::collections::HashSet<u16> =
            (0..64).filter_map(|_| random_id().ok()).collect();
        assert!(
            ids.len() > 32,
            "64 draws of 16 bits should rarely repeat: {}",
            ids.len()
        );
    }
}
