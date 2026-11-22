//! The challenge zone as a hickory `ZoneHandler`, answering from live [`ZoneDb`] state on every
//! query (so a token the issuance worker was told is published is served the instant the node
//! has applied it, and an expired token stops being served at its expiry with no rebuild).
//!
//! What it serves, exhaustively:
//!
//! * apex `SOA` and `NS`;
//! * `TXT` at `<label>.<zone>` when `<label>` is bound and has at least one unexpired token.
//!
//! Everything else is a negative answer: any other type at a live label is NODATA (the name
//! exists, only TXT is ever served), and every other name — an unbound label, a name with more
//! labels, a wildcard-looking name — is NXDOMAIN with the SOA. There is no CNAME, no wildcard,
//! no ANY expansion, no way for a tenant to add data: the only writer is the challenge
//! authority, and it can only write tokens.

use crate::build::ServerIdentity;
use crate::db::ZoneDb;
use async_trait::async_trait;
use hickory_server::dnssec::NxProofKind;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{NS, SOA, TXT};
use hickory_server::proto::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType, TSigResponseContext,
};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    Nsec3QueryInfo, ZoneHandler, ZoneType,
};
use std::sync::Arc;

/// TTL of served tokens: short, so a cleared token does not linger in a cache.
pub const TOKEN_TTL: u32 = 10;

/// The live challenge zone.
pub struct ChallengeZoneHandler {
    origin: LowerName,
    apex: Name,
    db: Arc<ZoneDb>,
    id: ServerIdentity,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl ChallengeZoneHandler {
    /// A handler for `apex` over `db`.
    #[must_use]
    pub fn new(
        apex: Name,
        db: Arc<ZoneDb>,
        id: ServerIdentity,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        ChallengeZoneHandler {
            origin: LowerName::new(&apex),
            apex,
            db,
            id,
            clock,
        }
    }

    fn serial(&self) -> u32 {
        u32::try_from((self.clock)() & 0xffff_ffff).unwrap_or(1)
    }

    fn soa_set(&self) -> RecordSet {
        let serial = self.serial();
        let mname = self
            .id
            .nameservers
            .first()
            .cloned()
            .unwrap_or_else(|| self.apex.clone());
        let soa = SOA::new(
            mname,
            self.id.hostmaster.clone(),
            serial,
            3_600,
            600,
            1_209_600,
            self.id.soa_minimum,
        );
        let mut set = RecordSet::new(self.apex.clone(), RecordType::SOA, serial);
        set.insert(
            Record::from_rdata(self.apex.clone(), self.id.soa_minimum, RData::SOA(soa)),
            serial,
        );
        set
    }

    fn ns_set(&self) -> RecordSet {
        let mut set = RecordSet::new(self.apex.clone(), RecordType::NS, 0);
        for ns in &self.id.nameservers {
            set.insert(
                Record::from_rdata(self.apex.clone(), self.id.ns_ttl, RData::NS(NS(ns.clone()))),
                0,
            );
        }
        set
    }

    fn answer(
        &self,
        name: &LowerName,
        qtype: RecordType,
        lo: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        use LookupControlFlow::Continue;
        if !self.origin.zone_of(name) {
            return Continue(Err(LookupError::from(ResponseCode::Refused)));
        }
        let qtype = if qtype == RecordType::ANY {
            // minimal ANY: one RRset, TXT if the name has tokens, else SOA at the apex
            if *name == self.origin {
                RecordType::SOA
            } else {
                RecordType::TXT
            }
        } else {
            qtype
        };
        if *name == self.origin {
            return match qtype {
                RecordType::SOA => Continue(Ok(AuthLookup::answers(
                    LookupRecords::new(lo, Arc::new(self.soa_set())),
                    None,
                ))),
                RecordType::NS => Continue(Ok(AuthLookup::answers(
                    LookupRecords::new(lo, Arc::new(self.ns_set())),
                    None,
                ))),
                _ => Continue(Err(LookupError::NameExists)),
            };
        }
        let one_label_deep =
            usize::from(name.num_labels()) == usize::from(self.apex.num_labels()) + 1;
        let label = name
            .iter()
            .next()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .unwrap_or_default();
        let tokens = if one_label_deep {
            self.live_tokens(&label)
        } else {
            Vec::new()
        };
        if tokens.is_empty() {
            return Continue(Err(LookupError::from(ResponseCode::NXDomain)));
        }
        if qtype != RecordType::TXT {
            return Continue(Err(LookupError::NameExists));
        }
        let owner = Name::from(name.clone());
        let mut set = RecordSet::new(owner.clone(), RecordType::TXT, 0);
        for t in tokens {
            set.insert(
                Record::from_rdata(owner.clone(), TOKEN_TTL, RData::TXT(TXT::new(vec![t]))),
                0,
            );
        }
        Continue(Ok(AuthLookup::answers(
            LookupRecords::new(lo, Arc::new(set)),
            None,
        )))
    }

    fn live_tokens(&self, label: &str) -> Vec<String> {
        match self.db.challenge(label) {
            Some(c) if !c.released => {
                let now = (self.clock)();
                c.tokens
                    .into_iter()
                    .filter(|(_, exp)| *exp > now)
                    .map(|(v, _)| v)
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

#[async_trait]
impl ZoneHandler for ChallengeZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _ri: Option<&RequestInfo<'_>>,
        lo: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.answer(name, rtype, lo)
    }

    async fn search(
        &self,
        request: &Request,
        lo: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        match request.request_info() {
            Ok(i) => (self.answer(i.query.name(), i.query.query_type(), lo), None),
            Err(e) => (LookupControlFlow::Break(Err(e)), None),
        }
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lo: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Ok(AuthLookup::Empty))
    }

    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lo: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Ok(AuthLookup::Empty))
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}
