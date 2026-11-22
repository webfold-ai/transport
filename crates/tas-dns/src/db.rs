//! The zone database: the authoritative, validated, replicated state of a node.
//!
//! [`ZoneDb`] is the [`SyncStore`] the mesh protocol talks to. Everything that changes it —
//! from a peer, from a publisher, from disk at startup — goes through the same three entry
//! points ([`ZoneDb::apply_registration`], [`ZoneDb::apply_update`], [`ZoneDb::apply_challenge`]),
//! each of which is **fail-closed**: an object is applied only if every check passes, and the
//! reason for any refusal is returned (and, for the security-relevant ones, alerted).
//!
//! ## Trust chain
//!
//! ```text
//! registrar key (configured trust anchor)
//!   └─ signs Registration(apex) : tenant, owner key, owner epoch, state, DNSSEC policy
//!        └─ owner key (dialkey-derived Ed25519) signs Update(apex, epoch, version): the records
//! challenge authority key (configured)
//!   └─ signs Challenge(label): tenant, name, tokens
//! ```
//!
//! A node believes an update only if (1) the apex has an *active* registration signed by the
//! registrar, (2) the update's signer is that registration's owner key, (3) its epoch is the
//! registration's owner epoch, (4) `(epoch, version)` is strictly newer than what is held, and
//! (5) the records pass the strict validation of [`crate::records`].

use crate::challenge::{parse_challenge, ChallengeState};
use crate::error::ValidationError;
use crate::escape::esc;
use crate::metrics::{outcome_index, Metrics};
use crate::names::{self, from_wire_id};
use crate::records::ZoneLimits;
use crate::store::ObjectStore;
use crate::zone::{RegState, Registration, TenantId, Zone};
use hickory_proto::rr::Name;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};
use transport::zone_sync::{
    id_hash, ApplyOutcome, ObjectKind, SignedObject, Summary, SummaryKey, SyncStore,
};
use transport::PeerId;

/// Static configuration of a database.
#[derive(Clone)]
pub struct DbConfig {
    /// The control plane's public key: the only signer of registrations.
    pub registrar: [u8; 32],
    /// The ACME challenge authority's public key (None: no challenge zone on this node).
    pub challenge_authority: Option<[u8; 32]>,
    /// The challenge zone apex.
    pub challenge_zone: Option<Name>,
    /// Per-zone record limits.
    pub limits: ZoneLimits,
    /// Active zones one tenant may hold.
    pub max_zones_per_tenant: usize,
    /// Active zones in total.
    pub max_zones_total: usize,
    /// Challenge labels one tenant may hold (labels are permanent, so this is a lifetime cap).
    pub max_labels_per_tenant: usize,
    /// Challenge labels in total.
    pub max_labels_total: usize,
    /// Apexes tenants may never register, nor register anything under or above.
    pub reserved: Vec<Name>,
}

impl DbConfig {
    /// Defaults around a registrar key.
    #[must_use]
    pub fn new(registrar: [u8; 32]) -> Self {
        DbConfig {
            registrar,
            challenge_authority: None,
            challenge_zone: None,
            limits: ZoneLimits::default(),
            max_zones_per_tenant: 100,
            max_zones_total: 200_000,
            max_labels_per_tenant: 5000,
            max_labels_total: 1_000_000,
            reserved: Vec::new(),
        }
    }
}

/// A change the serving layer must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbEvent {
    /// A zone (or its registration) changed.
    Zone(Name),
    /// Challenge state changed.
    Challenge,
}

struct Held {
    obj: SignedObject,
    summary: Summary,
}

#[derive(Default)]
struct Inner {
    objects: BTreeMap<SummaryKey, Held>,
    regs: HashMap<Vec<u8>, Registration>,
    zones: HashMap<Vec<u8>, Arc<Zone>>,
    challenges: HashMap<String, ChallengeState>,
    bindings: HashMap<(String, String), String>,
    tenant_active: HashMap<TenantId, usize>,
    tenant_labels: HashMap<TenantId, usize>,
    active_total: usize,
}

/// The replicated zone database.
pub struct ZoneDb {
    cfg: DbConfig,
    store: Arc<dyn ObjectStore>,
    metrics: Arc<Metrics>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    inner: Mutex<Inner>,
    events: Mutex<Vec<tokio::sync::mpsc::UnboundedSender<DbEvent>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn store_key(o: &SignedObject) -> String {
    let c = match o.kind() {
        ObjectKind::Registration => 'r',
        ObjectKind::Update => 'u',
        ObjectKind::Challenge => 'c',
    };
    let mut s = String::with_capacity(66);
    s.push(c);
    s.push('-');
    for b in o.id_hash() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// What happened to an object against what is held.
enum Order {
    Newer,
    Decided(ApplyOutcome),
}

fn compare(held: Option<&Held>, new: &SignedObject) -> Order {
    let Some(h) = held else { return Order::Newer };
    let (cur, nw) = (h.obj.order(), new.order());
    match nw.cmp(&cur) {
        std::cmp::Ordering::Greater => Order::Newer,
        std::cmp::Ordering::Equal if h.summary.digest == new.digest() => {
            Order::Decided(ApplyOutcome::Duplicate)
        }
        std::cmp::Ordering::Equal => Order::Decided(ApplyOutcome::Fork),
        std::cmp::Ordering::Less => Order::Decided(ApplyOutcome::Stale),
    }
}

impl ZoneDb {
    /// Open a database over `store`, replaying every persisted object through the live
    /// validation path. Returns the database and the number of stored objects that were refused.
    pub fn open(
        cfg: DbConfig,
        store: Arc<dyn ObjectStore>,
        metrics: Arc<Metrics>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> std::io::Result<(Self, usize)> {
        let db = ZoneDb {
            cfg,
            store,
            metrics,
            clock,
            inner: Mutex::new(Inner::default()),
            events: Mutex::new(Vec::new()),
        };
        let (files, skipped) = db.store.load_all()?;
        let mut refused = skipped.len();
        for s in &skipped {
            tracing::warn!(target: "tas_dns::store", file = %s, "stored object skipped (unreadable or oversized)");
        }
        let mut objs = Vec::new();
        for (key, bytes) in files {
            match SignedObject::decode(&bytes) {
                Ok(o) => objs.push(o),
                Err(e) => {
                    refused += 1;
                    tracing::warn!(target: "tas_dns::store", key = %esc(&key), error = %e, "stored object refused (does not verify)");
                }
            }
        }
        // registrations first, then updates, then challenges: dependencies before dependants
        objs.sort_by_key(|o| match o.kind() {
            ObjectKind::Registration => (0u8, o.version()),
            ObjectKind::Update => (1, o.version()),
            ObjectKind::Challenge => (2, o.version()),
        });
        for o in objs {
            let out = db.apply_inner(o, false);
            if !matches!(out, ApplyOutcome::Applied | ApplyOutcome::Duplicate) {
                refused += 1;
                tracing::warn!(target: "tas_dns::store", outcome = ?out, "stored object not re-applied");
            }
        }
        Ok((db, refused))
    }

    /// Receive [`DbEvent`]s. Any number of subscribers; a dropped receiver is forgotten.
    pub fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<DbEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        lock(&self.events).push(tx);
        rx
    }

    fn emit(&self, e: &DbEvent) {
        lock(&self.events).retain(|tx| tx.send(e.clone()).is_ok());
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &DbConfig {
        &self.cfg
    }

    // ── reads ────────────────────────────────────────────────────────────────────────────────

    /// The registration for `apex`.
    #[must_use]
    pub fn registration(&self, apex: &Name) -> Option<Registration> {
        lock(&self.inner).regs.get(&names::wire_id(apex)).cloned()
    }

    /// The zone to serve for `apex`: its current content, or an empty zone while the
    /// registration is active and no valid update is held. None when unregistered or released.
    #[must_use]
    pub fn zone(&self, apex: &Name) -> Option<Arc<Zone>> {
        let g = lock(&self.inner);
        let id = names::wire_id(apex);
        let reg = g.regs.get(&id)?;
        if reg.state != RegState::Active {
            return None;
        }
        Some(
            g.zones
                .get(&id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Zone::empty(reg))),
        )
    }

    /// Apexes with an active registration.
    #[must_use]
    pub fn active_apexes(&self) -> Vec<Name> {
        lock(&self.inner)
            .regs
            .values()
            .filter(|r| r.state == RegState::Active)
            .map(|r| r.apex.clone())
            .collect()
    }

    /// Number of active zones a tenant holds.
    #[must_use]
    pub fn tenant_zone_count(&self, t: &TenantId) -> usize {
        lock(&self.inner).tenant_active.get(t).copied().unwrap_or(0)
    }

    /// All challenge labels with at least one live token at `now`: `(label, tokens)`.
    #[must_use]
    pub fn live_challenges(&self, now: u64) -> Vec<(String, Vec<String>)> {
        let g = lock(&self.inner);
        let mut out: Vec<(String, Vec<String>)> = g
            .challenges
            .iter()
            .filter(|(_, c)| !c.released)
            .filter_map(|(l, c)| {
                let live: Vec<String> = c
                    .tokens
                    .iter()
                    .filter(|(_, exp)| *exp > now)
                    .map(|(v, _)| v.clone())
                    .collect();
                (!live.is_empty()).then(|| (l.clone(), live))
            })
            .collect();
        out.sort();
        out
    }

    /// The label bound to `(tenant, name)`, if any.
    #[must_use]
    pub fn label_for(&self, tenant: &TenantId, name: &str) -> Option<String> {
        lock(&self.inner)
            .bindings
            .get(&(tenant.as_str().to_string(), name.to_string()))
            .cloned()
    }

    /// The state of a label.
    #[must_use]
    pub fn challenge(&self, label: &str) -> Option<ChallengeState> {
        lock(&self.inner).challenges.get(label).cloned()
    }

    /// Whether `label` has ever been bound (labels are never reissued).
    #[must_use]
    pub fn label_exists(&self, label: &str) -> bool {
        lock(&self.inner).challenges.contains_key(label)
    }

    /// The newest challenge version held for `label` (0 if none).
    #[must_use]
    pub fn challenge_version(&self, label: &str) -> u64 {
        lock(&self.inner)
            .challenges
            .get(label)
            .map_or(0, |c| c.version)
    }

    // ── writes ───────────────────────────────────────────────────────────────────────────────

    fn finish(&self, kind: ObjectKind, out: ApplyOutcome) -> ApplyOutcome {
        let i = outcome_index(out);
        let arr = match kind {
            ObjectKind::Registration => &self.metrics.registrations,
            ObjectKind::Update => &self.metrics.updates,
            ObjectKind::Challenge => &self.metrics.challenges,
        };
        if let Some(c) = arr.get(i) {
            c.inc();
        }
        out
    }

    fn alert(what: &str, kind: ObjectKind, id: &[u8], detail: &str) {
        let name =
            from_wire_id(id).map_or_else(|_| "<invalid-id>".to_string(), |n| esc(&n.to_ascii()));
        tracing::warn!(target: "tas_dns::alert", what, kind = ?kind, object = %name, detail = %esc(detail), "replication anomaly");
    }

    fn apply_inner(&self, obj: SignedObject, persist: bool) -> ApplyOutcome {
        let kind = obj.kind();
        let out = match kind {
            ObjectKind::Registration => self.apply_registration(obj, persist),
            ObjectKind::Update => self.apply_update(obj, persist),
            ObjectKind::Challenge => self.apply_challenge(obj, persist),
        };
        self.finish(kind, out)
    }

    fn commit(&self, g: &mut Inner, obj: SignedObject, persist: bool) -> bool {
        if persist && self.store.put(&store_key(&obj), &obj.encode()).is_err() {
            tracing::error!(target: "tas_dns::store", "object could not be persisted; refusing it");
            return false;
        }
        let summary = obj.summary();
        g.objects.insert(summary.key(), Held { obj, summary });
        true
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear sequence; splitting it would obscure the order of the steps"
    )]
    fn apply_registration(&self, obj: SignedObject, persist: bool) -> ApplyOutcome {
        if obj.signer() != &self.cfg.registrar {
            Self::alert(
                "registration signed by a key that is not the registrar",
                obj.kind(),
                obj.id(),
                "",
            );
            return ApplyOutcome::Unauthorized;
        }
        let Ok(reg) = Registration::parse(obj.id(), obj.epoch(), obj.version(), obj.body()) else {
            return ApplyOutcome::Invalid;
        };
        let now = self.now();
        let mut g = lock(&self.inner);
        let id = obj.id().to_vec();
        let key = (obj.kind().code(), id_hash(obj.kind(), &id));
        match compare(g.objects.get(&key), &obj) {
            Order::Decided(o) => {
                if o == ApplyOutcome::Fork {
                    Self::alert(
                        "registrar signed two different registrations at one version",
                        obj.kind(),
                        &id,
                        "fork",
                    );
                }
                return o;
            }
            Order::Newer => {}
        }
        // reserved platform names, and cross-tenant shadowing
        for r in &self.cfg.reserved {
            if r.zone_of(&reg.apex) || reg.apex.zone_of(r) {
                Self::alert("registration overlaps a reserved apex", obj.kind(), &id, "");
                return ApplyOutcome::Unauthorized;
            }
        }
        if let Some(cz) = &self.cfg.challenge_zone {
            if cz.zone_of(&reg.apex) || reg.apex.zone_of(cz) {
                Self::alert(
                    "registration overlaps the challenge zone",
                    obj.kind(),
                    &id,
                    "",
                );
                return ApplyOutcome::Unauthorized;
            }
        }
        for other in g.regs.values() {
            if other.apex != reg.apex
                && other.tenant != reg.tenant
                && other.state == RegState::Active
                && (other.apex.zone_of(&reg.apex) || reg.apex.zone_of(&other.apex))
            {
                Self::alert(
                    "registration would shadow or be shadowed by another tenant's zone",
                    obj.kind(),
                    &id,
                    "",
                );
                return ApplyOutcome::Unauthorized;
            }
        }
        let cur = g.regs.get(&id).cloned();
        if let Some(cur) = &cur {
            if reg.seq <= cur.seq {
                return ApplyOutcome::Invalid;
            }
            if reg.tenant != cur.tenant {
                // first valid delegation wins: another tenant may take the apex only after a
                // release, and only once the quarantine has elapsed
                let free = cur.state == RegState::Released && now >= cur.quarantine_until;
                if !free {
                    Self::alert(
                        "apex already delegated to another tenant",
                        obj.kind(),
                        &id,
                        "",
                    );
                    return ApplyOutcome::Unauthorized;
                }
            }
            if reg.owner != cur.owner && reg.owner_epoch <= cur.owner_epoch {
                return ApplyOutcome::Invalid; // a new owner key needs a new owner epoch
            }
            if cur.state == RegState::Released
                && reg.state == RegState::Released
                && reg.quarantine_until < cur.quarantine_until
            {
                return ApplyOutcome::Invalid; // quarantine can only be extended
            }
        }
        // quotas (a re-registration of an already-active apex does not count again)
        let was_active = cur.as_ref().is_some_and(|c| c.state == RegState::Active);
        if reg.state == RegState::Active
            && !was_active
            && (g.active_total >= self.cfg.max_zones_total
                || g.tenant_active.get(&reg.tenant).copied().unwrap_or(0)
                    >= self.cfg.max_zones_per_tenant)
        {
            return ApplyOutcome::Quota;
        }
        if !self.commit(&mut g, obj, persist) {
            return ApplyOutcome::Invalid;
        }
        // counts
        if was_active {
            if let Some(c) = cur.as_ref() {
                if let Some(n) = g.tenant_active.get_mut(&c.tenant) {
                    *n = n.saturating_sub(1);
                }
                g.active_total = g.active_total.saturating_sub(1);
            }
        }
        if reg.state == RegState::Active {
            *g.tenant_active.entry(reg.tenant.clone()).or_insert(0) += 1;
            g.active_total += 1;
        }
        let apex = reg.apex.clone();
        g.regs.insert(id.clone(), reg);
        // the held update stays valid only while it still matches the (new) registration
        Self::revalidate_update(&mut g, &id, &self.cfg.limits);
        drop(g);
        self.emit(&DbEvent::Zone(apex));
        ApplyOutcome::Applied
    }

    /// Re-derive the served zone for `id` from the held update and the current registration.
    fn revalidate_update(g: &mut Inner, id: &[u8], limits: &ZoneLimits) {
        let key = (ObjectKind::Update.code(), id_hash(ObjectKind::Update, id));
        let zone = match (g.regs.get(id), g.objects.get(&key)) {
            (Some(reg), Some(h))
                if reg.state == RegState::Active
                    && h.obj.signer() == &reg.owner
                    && h.obj.epoch() == reg.owner_epoch =>
            {
                Zone::from_update(reg, h.obj.epoch(), h.obj.version(), h.obj.body(), limits).ok()
            }
            _ => None,
        };
        match zone {
            Some(z) => {
                g.zones.insert(id.to_vec(), Arc::new(z));
            }
            None => {
                g.zones.remove(id);
            }
        }
    }

    fn apply_update(&self, obj: SignedObject, persist: bool) -> ApplyOutcome {
        let id = obj.id().to_vec();
        let mut g = lock(&self.inner);
        let Some(reg) = g.regs.get(&id).cloned() else {
            return ApplyOutcome::Unauthorized;
        };
        if reg.state != RegState::Active
            || obj.signer() != &reg.owner
            || obj.epoch() != reg.owner_epoch
        {
            Self::alert(
                "update not signed by the registered owner key/epoch",
                obj.kind(),
                &id,
                "",
            );
            return ApplyOutcome::Unauthorized;
        }
        let key = (obj.kind().code(), id_hash(obj.kind(), &id));
        match compare(g.objects.get(&key), &obj) {
            Order::Decided(o) => {
                match o {
                    ApplyOutcome::Fork => Self::alert(
                        "owner signed two different zones at one version",
                        obj.kind(),
                        &id,
                        "fork",
                    ),
                    ApplyOutcome::Stale => Self::alert(
                        "rolled-back or replayed update refused",
                        obj.kind(),
                        &id,
                        "stale",
                    ),
                    _ => {}
                }
                return o;
            }
            Order::Newer => {}
        }
        let zone = match Zone::from_update(
            &reg,
            obj.epoch(),
            obj.version(),
            obj.body(),
            &self.cfg.limits,
        ) {
            Ok(z) => z,
            Err(e) => {
                Self::alert(
                    "update refused by validation",
                    obj.kind(),
                    &id,
                    &e.to_string(),
                );
                return ApplyOutcome::Invalid;
            }
        };
        if !self.commit(&mut g, obj, persist) {
            return ApplyOutcome::Invalid;
        }
        g.zones.insert(id, Arc::new(zone));
        drop(g);
        self.emit(&DbEvent::Zone(reg.apex));
        ApplyOutcome::Applied
    }

    fn apply_challenge(&self, obj: SignedObject, persist: bool) -> ApplyOutcome {
        let (Some(auth), Some(cz)) = (
            self.cfg.challenge_authority,
            self.cfg.challenge_zone.as_ref(),
        ) else {
            return ApplyOutcome::Unauthorized;
        };
        if obj.signer() != &auth {
            Self::alert(
                "challenge object signed by a key that is not the challenge authority",
                obj.kind(),
                obj.id(),
                "",
            );
            return ApplyOutcome::Unauthorized;
        }
        if obj.epoch() != 1 {
            return ApplyOutcome::Invalid;
        }
        let now = self.now();
        let Ok((label, st)) = parse_challenge(obj.id(), cz, obj.version(), obj.body(), now) else {
            return ApplyOutcome::Invalid;
        };
        let mut g = lock(&self.inner);
        let id = obj.id().to_vec();
        let key = (obj.kind().code(), id_hash(obj.kind(), &id));
        match compare(g.objects.get(&key), &obj) {
            Order::Decided(o) => {
                if o == ApplyOutcome::Fork {
                    Self::alert(
                        "challenge authority signed two different states at one version",
                        obj.kind(),
                        &id,
                        "fork",
                    );
                }
                return o;
            }
            Order::Newer => {}
        }
        let bind_key = (st.tenant.as_str().to_string(), st.name.clone());
        if let Some(prev) = g.challenges.get(&label) {
            // permanent binding: tenant and name never change for a label
            if prev.tenant != st.tenant || prev.name != st.name {
                Self::alert(
                    "challenge label rebound to a different tenant or name",
                    obj.kind(),
                    &id,
                    "binding changed",
                );
                return ApplyOutcome::Invalid;
            }
        } else {
            if let Some(other) = g.bindings.get(&bind_key) {
                if other != &label {
                    Self::alert(
                        "tenant and name already have a different challenge label",
                        obj.kind(),
                        &id,
                        "duplicate binding",
                    );
                    return ApplyOutcome::Invalid;
                }
            }
            if g.challenges.len() >= self.cfg.max_labels_total
                || g.tenant_labels.get(&st.tenant).copied().unwrap_or(0)
                    >= self.cfg.max_labels_per_tenant
            {
                return ApplyOutcome::Quota;
            }
        }
        if !self.commit(&mut g, obj, persist) {
            return ApplyOutcome::Invalid;
        }
        if !g.challenges.contains_key(&label) {
            *g.tenant_labels.entry(st.tenant.clone()).or_insert(0) += 1;
            g.bindings.insert(bind_key, label.clone());
        }
        g.challenges.insert(label, st);
        drop(g);
        self.emit(&DbEvent::Challenge);
        ApplyOutcome::Applied
    }

    /// Apply `obj` as a trusted-origin-agnostic offer (verified signature assumed).
    pub fn apply_object(&self, obj: SignedObject) -> ApplyOutcome {
        self.apply_inner(obj, true)
    }

    /// Number of held objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        lock(&self.inner).objects.len()
    }

    /// The held object for `(kind, id)`.
    #[must_use]
    pub fn object(&self, kind: ObjectKind, id: &[u8]) -> Option<SignedObject> {
        lock(&self.inner)
            .objects
            .get(&(kind.code(), id_hash(kind, id)))
            .map(|h| h.obj.clone())
    }
}

impl SyncStore for ZoneDb {
    fn summaries(&self, after: Option<SummaryKey>, limit: usize) -> Vec<Summary> {
        use std::ops::Bound::{Excluded, Unbounded};
        let g = lock(&self.inner);
        let lo = after.map_or(Unbounded, Excluded);
        g.objects
            .range((lo, Unbounded))
            .take(limit)
            .map(|(_, h)| h.summary)
            .collect()
    }

    fn get(&self, kind: ObjectKind, id_hash: &[u8; 32]) -> Option<SignedObject> {
        lock(&self.inner)
            .objects
            .get(&(kind.code(), *id_hash))
            .map(|h| h.obj.clone())
    }

    fn apply(&self, object: SignedObject, _from: PeerId) -> ApplyOutcome {
        self.apply_inner(object, true)
    }
}

/// Map a validation error to the outcome a peer sees.
#[must_use]
pub fn outcome_for(e: &ValidationError) -> ApplyOutcome {
    match e {
        ValidationError::Limit(_) => ApplyOutcome::Quota,
        _ => ApplyOutcome::Invalid,
    }
}
