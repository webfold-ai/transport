//! The serving engine's view of zones: one hickory [`ZoneHandler`] per zone, atomically
//! swappable, collected into a [`Catalog`] that the request handler consults.
//!
//! All lookup semantics — NXDOMAIN vs NODATA with the SOA, CNAME chasing, wildcard matching,
//! minimal ANY (RFC 8482), NSEC proofs — are hickory's `InMemoryZoneHandler`; this module only
//! feeds it the fully assembled (and, when signed, pre-signed) record sets from
//! [`crate::build`] and swaps them atomically when a zone changes, so a query never observes a
//! half-updated zone.

use crate::build::{DsData, SignedZone};
use async_trait::async_trait;
use hickory_server::dnssec::NxProofKind;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::{
    LowerName, Name, RecordSet, RecordType, RrKey, TSigResponseContext,
};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    Nsec3QueryInfo, ZoneHandler, ZoneType,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};

static NSEC: NxProofKind = NxProofKind::Nsec;

/// Poison-tolerant lock helpers: a panicked writer must not take the DNS plane down.
fn rd<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn wr<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn mx<T>(l: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    l.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Name-existence facts about one built zone, kept beside hickory's handler so that
/// RFC 4592 wildcard synthesis and RFC 4035 denial proofs are decided by code this crate tests,
/// not by the engine's approximations (see [`ZoneIndex::gate`]).
#[derive(Default)]
struct ZoneIndex {
    /// Names that own at least one `RRset`.
    owners: BTreeSet<Name>,
    /// `(owner, type code)` of every `RRset`.
    exact: BTreeSet<(Name, u16)>,
    /// Owners plus every ancestor down to the apex (empty non-terminals included).
    exist: BTreeSet<Name>,
    /// NSEC `RRsets` by owner (signed zones only).
    nsec: BTreeMap<Name, Arc<RecordSet>>,
}

/// What the index says about a query before the engine sees it.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// Let the engine answer.
    Delegate,
    /// The name exists but holds nothing of this type (and no wildcard may apply).
    NoData,
    /// The name does not exist and no wildcard at its closest encloser matches.
    NxDomain,
}

impl ZoneIndex {
    fn build(origin: &Name, records: &BTreeMap<RrKey, RecordSet>) -> Self {
        let mut ix = ZoneIndex::default();
        for (k, set) in records {
            let owner = Name::from(k.name.clone());
            ix.exact.insert((owner.clone(), u16::from(k.record_type)));
            ix.owners.insert(owner.clone());
            let mut n = owner;
            loop {
                ix.exist.insert(n.clone());
                if n == *origin || n.is_root() {
                    break;
                }
                n = n.base_name();
            }
            if k.record_type == RecordType::NSEC {
                ix.nsec
                    .insert(Name::from(k.name.clone()), Arc::new(set.clone()));
            }
        }
        ix
    }

    fn gate(&self, origin: &Name, name: &Name, rtype: RecordType) -> Gate {
        if !origin.zone_of(name) {
            return Gate::Delegate; // the engine refuses it
        }
        if self.owners.contains(name) {
            let any =
                rtype == RecordType::ANY || rtype == RecordType::AXFR || rtype == RecordType::IXFR;
            if any
                || self.exact.contains(&(name.clone(), u16::from(rtype)))
                || self
                    .exact
                    .contains(&(name.clone(), u16::from(RecordType::CNAME)))
            {
                return Gate::Delegate;
            }
            // RFC 4592 2.2.1: a wildcard never answers for a name that exists
            return Gate::NoData;
        }
        if self.exist.contains(name) {
            return Gate::NoData; // empty non-terminal
        }
        // closest encloser, then its wildcard
        let mut ce = name.base_name();
        while !self.exist.contains(&ce) {
            if ce == *origin || ce.is_root() {
                break;
            }
            ce = ce.base_name();
        }
        let wildcard = star_of(&ce);
        if wildcard.as_ref().is_some_and(|w| self.owners.contains(w)) {
            Gate::Delegate
        } else {
            Gate::NxDomain
        }
    }

    /// The NSEC `RRset` at or most closely preceding `name` in canonical order.
    fn closest_nsec(&self, name: &Name) -> Option<Arc<RecordSet>> {
        self.nsec
            .range(..=name)
            .next_back()
            .or_else(|| self.nsec.iter().next_back())
            .map(|(_, s)| s.clone())
    }

    fn proofs(&self, origin: &Name, name: &Name) -> Vec<Arc<RecordSet>> {
        if let Some(own) = self.nsec.get(name) {
            return vec![own.clone()];
        }
        let mut out: Vec<Arc<RecordSet>> = Vec::new();
        if let Some(c) = self.closest_nsec(name) {
            out.push(c);
        }
        let mut ce = name.base_name();
        while !self.exist.contains(&ce) && ce != *origin && !ce.is_root() {
            ce = ce.base_name();
        }
        if let Some(w) = star_of(&ce).and_then(|w| self.closest_nsec(&w)) {
            if !out.iter().any(|o| o.name() == w.name()) {
                out.push(w);
            }
        }
        out
    }
}

/// `*.<name>`: the wildcard that would synthesise answers for children of `name`.
fn star_of(name: &Name) -> Option<Name> {
    name.prepend_label("*").ok()
}

struct Cur {
    h: Arc<InMemoryZoneHandler>,
    signed: bool,
    idx: Arc<ZoneIndex>,
}

/// A swappable zone handler.
struct SwapZone {
    origin: LowerName,
    cur: RwLock<Cur>,
}

impl SwapZone {
    fn current(&self) -> (Arc<InMemoryZoneHandler>, bool, Arc<ZoneIndex>) {
        let g = rd(&self.cur);
        (g.h.clone(), g.signed, g.idx.clone())
    }
}

#[async_trait]
impl ZoneHandler for SwapZone {
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
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let (h, _, idx) = self.current();
        let origin = Name::from(self.origin.clone());
        match idx.gate(&origin, &Name::from(name.clone()), rtype) {
            Gate::Delegate => h.lookup(name, rtype, request_info, lookup_options).await,
            Gate::NoData => LookupControlFlow::Continue(Err(LookupError::NameExists)),
            Gate::NxDomain => {
                LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::NXDomain)))
            }
        }
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        match request.request_info() {
            Ok(info) => (
                self.lookup(
                    info.query.name(),
                    info.query.query_type(),
                    Some(&info),
                    lookup_options,
                )
                .await,
                None,
            ),
            Err(e) => (LookupControlFlow::Break(Err(e)), None),
        }
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let (_, _, idx) = self.current();
        let origin = Name::from(self.origin.clone());
        let proofs = idx.proofs(&origin, &Name::from(name.clone()));
        LookupControlFlow::Continue(Ok(AuthLookup::answers(
            LookupRecords::many(lookup_options, proofs),
            None,
        )))
    }

    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.current().0.nsec3_records(info, lookup_options).await
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        if self.current().1 {
            Some(&NSEC)
        } else {
            None
        }
    }
}

/// What the serving layer knows about one installed zone.
#[derive(Debug, Clone)]
pub struct ZoneInfo {
    /// Zone version (SOA serial).
    pub version: u64,
    /// Whether it is signed.
    pub signed: bool,
    /// When it must be rebuilt.
    pub refresh_at: u64,
    /// Earliest `RRSIG` expiry (0 if unsigned).
    pub earliest_expiry: u64,
    /// DS records a parent should hold.
    pub ds: Vec<DsData>,
    /// True if the zone cannot be served correctly (keys unavailable): queries get SERVFAIL.
    pub failed: bool,
}

struct Entry {
    handler: Arc<dyn ZoneHandler>,
    /// Present for swappable (signed/unsigned tenant) zones; absent for dynamic handlers.
    swap: Option<Arc<SwapZone>>,
    info: ZoneInfo,
}

/// The set of zones this node serves.
pub struct Serving {
    zones: Mutex<HashMap<LowerName, Entry>>,
    catalog: RwLock<Arc<Catalog>>,
}

impl Default for Serving {
    fn default() -> Self {
        Self::new()
    }
}

fn build_handler(z: SignedZone) -> (Arc<InMemoryZoneHandler>, Arc<ZoneIndex>) {
    let idx = Arc::new(ZoneIndex::build(&z.origin, &z.records));
    let mut h = InMemoryZoneHandler::empty(
        z.origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        if z.signed {
            Some(NxProofKind::Nsec)
        } else {
            None
        },
    );
    let map = h.records_get_mut();
    for (k, v) in z.records {
        map.insert(k, Arc::new(v));
    }
    (Arc::new(h), idx)
}

impl Serving {
    /// An empty serving set (every query is REFUSED).
    #[must_use]
    pub fn new() -> Self {
        Serving {
            zones: Mutex::new(HashMap::new()),
            catalog: RwLock::new(Arc::new(Catalog::new())),
        }
    }

    fn rebuild_catalog(&self, zones: &HashMap<LowerName, Entry>) {
        let mut c = Catalog::new();
        for (name, e) in zones {
            if e.info.failed {
                continue; // answered SERVFAIL by the request handler, never by data
            }
            c.upsert(name.clone(), vec![e.handler.clone()]);
        }
        *wr(&self.catalog) = Arc::new(c);
    }

    /// Install or replace a zone. Replacement of an existing zone is a pointer swap.
    pub fn install(&self, z: SignedZone) -> Result<(), String> {
        let origin = LowerName::new(&z.origin);
        let info = ZoneInfo {
            version: u64::from(z.serial),
            signed: z.signed,
            refresh_at: z.refresh_at,
            earliest_expiry: z.earliest_expiry,
            ds: z.ds.clone(),
            failed: false,
        };
        let signed = z.signed;
        let (handler, idx) = build_handler(z);
        let mut zones = mx(&self.zones);
        let existed_ok = zones
            .get(&origin)
            .is_some_and(|e| !e.info.failed && e.swap.is_some());
        if let Some((e, swap)) = zones
            .get_mut(&origin)
            .filter(|e| !e.info.failed)
            .and_then(|e| e.swap.clone().map(|s| (e, s)))
        {
            *wr(&swap.cur) = Cur {
                h: handler,
                signed,
                idx,
            };
            e.info = info;
        } else {
            let swap = Arc::new(SwapZone {
                origin: origin.clone(),
                cur: RwLock::new(Cur {
                    h: handler,
                    signed,
                    idx,
                }),
            });
            zones.insert(
                origin,
                Entry {
                    handler: swap.clone(),
                    swap: Some(swap),
                    info,
                },
            );
        }
        if !existed_ok {
            self.rebuild_catalog(&zones);
        }
        Ok(())
    }

    /// Mark a zone as unservable (e.g. DNSSEC keys unavailable): queries get SERVFAIL rather
    /// than unsigned data under a DS the parent holds.
    pub fn install_failed(&self, apex: &Name, version: u64, retry_at: u64) {
        let origin = LowerName::new(apex);
        let mut zones = mx(&self.zones);
        let placeholder =
            InMemoryZoneHandler::empty(apex.clone(), ZoneType::Primary, AxfrPolicy::Deny, None);
        let swap = Arc::new(SwapZone {
            origin: origin.clone(),
            cur: RwLock::new(Cur {
                h: Arc::new(placeholder),
                signed: false,
                idx: Arc::new(ZoneIndex::default()),
            }),
        });
        zones.insert(
            origin,
            Entry {
                handler: swap.clone(),
                swap: Some(swap),
                info: ZoneInfo {
                    version,
                    signed: true,
                    refresh_at: retry_at,
                    earliest_expiry: 0,
                    ds: Vec::new(),
                    failed: true,
                },
            },
        );
        self.rebuild_catalog(&zones);
    }

    /// Install a handler that answers from live state on every query (the challenge zone).
    pub fn install_dynamic(&self, apex: &Name, handler: Arc<dyn ZoneHandler>) {
        let origin = LowerName::new(apex);
        let mut zones = mx(&self.zones);
        zones.insert(
            origin,
            Entry {
                handler,
                swap: None,
                info: ZoneInfo {
                    version: 0,
                    signed: false,
                    refresh_at: u64::MAX,
                    earliest_expiry: 0,
                    ds: Vec::new(),
                    failed: false,
                },
            },
        );
        self.rebuild_catalog(&zones);
    }

    /// Stop serving a zone (released or removed).
    pub fn remove(&self, apex: &Name) {
        let mut zones = mx(&self.zones);
        if zones.remove(&LowerName::new(apex)).is_some() {
            self.rebuild_catalog(&zones);
        }
    }

    /// The catalog for the request handler (a cheap `Arc` clone).
    #[must_use]
    pub fn catalog(&self) -> Arc<Catalog> {
        rd(&self.catalog).clone()
    }

    /// Info about one zone.
    #[must_use]
    pub fn info(&self, apex: &Name) -> Option<ZoneInfo> {
        mx(&self.zones)
            .get(&LowerName::new(apex))
            .map(|e| e.info.clone())
    }

    /// True if `qname` falls under a zone marked failed.
    #[must_use]
    pub fn is_failed(&self, qname: &LowerName) -> bool {
        let zones = mx(&self.zones);
        let mut n = qname.clone();
        loop {
            if let Some(e) = zones.get(&n) {
                return e.info.failed;
            }
            if n.is_root() {
                return false;
            }
            n = n.base_name();
        }
    }

    /// The apex of the zone `qname` falls in, if any.
    #[must_use]
    pub fn zone_of(&self, qname: &LowerName) -> Option<LowerName> {
        let zones = mx(&self.zones);
        let mut n = qname.clone();
        loop {
            if zones.contains_key(&n) {
                return Some(n);
            }
            if n.is_root() {
                return None;
            }
            n = n.base_name();
        }
    }

    /// Snapshot of every zone: apex, info.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(Name, ZoneInfo)> {
        mx(&self.zones)
            .iter()
            .map(|(k, e)| (Name::from(k.clone()), e.info.clone()))
            .collect()
    }

    /// Apexes whose `refresh_at` has passed.
    #[must_use]
    pub fn due(&self, now: u64) -> Vec<Name> {
        mx(&self.zones)
            .iter()
            .filter(|(_, e)| e.info.refresh_at <= now)
            .map(|(k, _)| Name::from(k.clone()))
            .collect()
    }

    /// Number of zones installed.
    #[must_use]
    pub fn len(&self) -> usize {
        mx(&self.zones).len()
    }

    /// True if no zone is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
