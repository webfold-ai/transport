#![cfg(feature = "native")]

//! Internal DNS for dialkey-published services — answers from a [`RelayStore`].
//!
//! A service publishes a signed packet under its key (see [`crate::dialkey`]): an `A`/`AAAA` at
//! the key's own label, and for each service an `SRV` and `TXT` at `<service>.<key>`. This serves
//! those records as ordinary DNS under an internal zone, so anything that speaks DNS can find a
//! service by name:
//!
//! ```text
//! _billing._tcp.<z32>.mesh.internal.   SRV   0 0 8080 <z32>.mesh.internal.
//! <z32>.mesh.internal.                 A     10.0.0.7
//! ```
//!
//! Names inside a packet are relative to the key, so every owner name and every `SRV` target is
//! qualified with the zone on the way out; without that a resolver following the target would
//! look for `<z32>.` at the root.
//!
//! ## What it does and does not do
//!
//! - **Authoritative only.** Anything outside the zone is `REFUSED`; recursion is never offered.
//! - **A name that holds records but not the type asked for** is `NOERROR` with no answers
//!   (`NODATA`); a name with no records, or a key the relay does not hold, is `NXDOMAIN`. Both
//!   carry the zone's `SOA` so a resolver has a negative-cache TTL
//!   ([`crate::edge_dns::SOA_MINIMUM_TTL`]).
//! - **Unparseable input and responses are never answered.**
//! - **No DNSSEC.** The records are already signed by their author, but that signature is over
//!   the packet, not a DNSSEC chain a validating resolver can check. Treat answers as trusted
//!   only as far as the network between resolver and relay is.
//!
//! Hand a [`MeshZone`] to [`crate::edge_dns::serve_udp_with`] and
//! [`crate::edge_dns::serve_tcp_with`].

use crate::dns::{Message, Name, Question, RData, Record, RecordType, ResponseCode};
use crate::edge_dns::{DnsHandler, SOA_MINIMUM_TTL};
use crate::pkarr_relay::{unix_now, RelayStore};
use crate::signed_dns::PublicKey;
use std::sync::Arc;

/// Why a zone could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneError(pub String);

impl core::fmt::Display for ZoneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZoneError {}

/// The internal zone, backed by a [`RelayStore`].
pub struct MeshZone {
    store: Arc<RelayStore>,
    zone: Name,
    soa: Record,
    ns: Record,
}

impl MeshZone {
    /// A zone named `zone` (for example `mesh.internal`), with `primary_ns` and `hostmaster` for
    /// its `SOA` and apex `NS`.
    ///
    /// # Errors
    /// If any name is not a valid DNS name, or `zone` is the root.
    pub fn new(
        store: Arc<RelayStore>,
        zone: &str,
        primary_ns: &str,
        hostmaster: &str,
    ) -> Result<Self, ZoneError> {
        let name = |s: &str| Name::from_ascii(s).map_err(|e| ZoneError(format!("{s:?}: {e:?}")));
        let zone_name = name(zone)?;
        if zone_name.labels().is_empty() {
            return Err(ZoneError("the zone cannot be the root".into()));
        }
        let (mname, rname) = (name(primary_ns)?, name(hostmaster)?);
        let soa = Record::new(
            zone_name.clone(),
            SOA_MINIMUM_TTL,
            RData::Soa {
                mname: mname.clone(),
                rname,
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 604_800,
                minimum: SOA_MINIMUM_TTL,
            },
        );
        let ns = Record::new(zone_name.clone(), 300, RData::Ns(mname));
        Ok(MeshZone {
            store,
            zone: zone_name,
            soa,
            ns,
        })
    }

    /// Answer one query as of `now` (seconds since the epoch). `None` means stay silent.
    #[must_use]
    pub fn answer_at(&self, query: &[u8], now: u64) -> Option<Vec<u8>> {
        let q = Message::from_bytes(query).ok()?;
        if q.flags.response {
            return None; // never answer an answer
        }
        if q.flags.opcode != 0 {
            return Some(Message::error(q.id, q.flags.opcode, ResponseCode::NotImp).to_bytes());
        }
        let [question] = q.questions.as_slice() else {
            return Some(Message::error(q.id, 0, ResponseCode::FormErr).to_bytes());
        };
        let mut reply = Message::response(q.id);
        reply.flags.authoritative = true;
        reply.flags.recursion_desired = q.flags.recursion_desired;
        reply.questions.push(question.clone());

        let zl = self.zone.labels().len();
        let ql = question.name.labels();
        let in_zone = ql.len() >= zl
            && ql[ql.len() - zl..]
                .iter()
                .zip(self.zone.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if !in_zone {
            reply.flags.authoritative = false;
            reply.flags.response_code = ResponseCode::Refused;
            return Some(reply.to_bytes());
        }

        let prefix = &ql[..ql.len() - zl];
        if prefix.is_empty() {
            self.apex(&mut reply, question);
        } else {
            self.service(&mut reply, question, prefix, now);
        }
        Some(reply.to_bytes())
    }

    fn apex(&self, reply: &mut Message, q: &Question) {
        match q.qtype {
            RecordType::Soa => reply.answers.push(self.soa.clone()),
            RecordType::Ns => reply.answers.push(self.ns.clone()),
            RecordType::Unknown(255) => {
                reply.answers.push(self.soa.clone());
                reply.answers.push(self.ns.clone());
            }
            _ => reply.authorities.push(self.soa.clone()), // the apex exists: NODATA
        }
    }

    fn service(&self, reply: &mut Message, q: &Question, prefix: &[String], now: u64) {
        let negative = |reply: &mut Message, code: ResponseCode| {
            reply.flags.response_code = code;
            reply.authorities.push(self.soa.clone());
        };
        // The key is always the last label before the zone; service labels precede it.
        let Some(key) = prefix.last().and_then(|l| PublicKey::from_z32(l).ok()) else {
            return negative(reply, ResponseCode::NxDomain);
        };
        let Some(packet) = self.store.get_packet(&key, now) else {
            return negative(reply, ResponseCode::NxDomain);
        };
        let Ok(owner) = Name::from_ascii(&prefix.join(".")) else {
            return negative(reply, ResponseCode::NxDomain);
        };
        let records = packet.records();
        let here: Vec<&Record> = records.iter().filter(|r| r.name == owner).collect();
        if here.is_empty() {
            return negative(reply, ResponseCode::NxDomain);
        }
        let wanted = |t: RecordType| q.qtype == RecordType::Unknown(255) || q.qtype == t;
        for r in here.iter().filter(|r| wanted(r.data.record_type())) {
            reply.answers.push(self.qualify(r));
            // An SRV is useless without the address of its target; supply it.
            if let RData::Srv { target, .. } = &r.data {
                for extra in records.iter().filter(|x| x.name == *target) {
                    if matches!(extra.data, RData::A(_) | RData::Aaaa(_)) {
                        reply.additionals.push(self.qualify(extra));
                    }
                }
            }
        }
        if reply.answers.is_empty() {
            reply.authorities.push(self.soa.clone()); // NODATA: the name exists, the type does not
        }
    }

    /// `record` with its owner name (and `SRV` target) moved under the zone.
    fn qualify(&self, record: &Record) -> Record {
        let under = |n: &Name| {
            let mut s = n.labels().join(".");
            s.push('.');
            s.push_str(&self.zone.labels().join("."));
            Name::from_ascii(&s).unwrap_or_else(|_| n.clone())
        };
        let mut out = record.clone();
        out.name = under(&record.name);
        if let RData::Srv {
            priority,
            weight,
            port,
            target,
        } = &record.data
        {
            out.data = RData::Srv {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: under(target),
            };
        }
        out
    }
}

impl DnsHandler for MeshZone {
    fn handle<'a>(&'a self, query: &'a [u8]) -> crate::BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { self.answer_at(query, unix_now()) })
    }
}
