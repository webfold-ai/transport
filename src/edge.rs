//! `tas-edge` — the multi-tenant hostname layer: Cloudflare-for-SaaS parity on our own zones.
//!
//! This is the naming/admission half of the tunnel product whose transport half is
//! `transport::bastion` (default-deny per-peer grants) and `transport::native` (the
//! authenticated connection a `tas-overlayd` connector dials out on). A tunnel is useless
//! until a *name* resolves to the edge and a *certificate* exists for it; this module is
//! that layer, and nothing else.
//!
//! ## Two kinds of hostname
//!
//! - **Managed** — `amber-lyrebird-3f9c.twnstack.app`, a label under one of the apexes we
//!   are authoritative for ([`APEXES`]). The label is *derived from the tunnel's dialkey*
//!   ([`label_for_dialkey`]), so a connector can compute its own hostname offline and the
//!   name survives re-provisioning. Covered by that apex's wildcard certificate.
//! - **Custom** — `app.acme.com.au`, a domain the customer owns and points at us. Ownership
//!   is proven before we will serve it ([`Challenge`]), and it needs its own certificate
//!   because a wildcard for someone else's zone is not a thing we can (or should) hold.
//!
//! ## The `.app`/`.dev` constraint is real, not cosmetic
//!
//! `twnstack.app`, `twnbox.app`, `twnstack.dev` and `twnbox.dev` sit under Google-operated
//! TLDs that are on the **HSTS preload list as whole TLDs**. Browsers refuse plaintext HTTP
//! to any name under them — there is no "serves over http:// while the certificate is
//! pending" grace period the way there is on `.cloud`. So for those apexes a hostname is
//! *unusable* until its certificate exists, and handing the customer the URL earlier hands
//! them a hard browser error. [`Apex::hsts_preloaded`] carries this, and
//! [`HostnameRecord::is_servable`] enforces it rather than leaving it to a caller to
//! remember.
//!
//! ## What this module does NOT do (stated, not hidden)
//!
//! **There is no ACME client here.** Issuance is a seam ([`CertSource`]), not an
//! implementation: the resolver asks for a certificate by name and serves what it is given.
//! A file/Vault-backed source works today; an ACME client (JWS, order flow, DNS-01 against
//! [`super::edge_dns`] for the wildcards, HTTP-01/TLS-ALPN-01 for custom hostnames) is the
//! next slice and slots in behind the same trait. Claiming automated issuance before that
//! exists would be claiming a thing that isn't here.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the hostname set (which names the edge admits at all — presence)
//! - **B/Map** = the route map (hostname → tenant/tunnel/peer — last write wins)
//! - **B/U** = the validation attempt counter (how many probes a pending name has cost)
//! - **self** = the challenge (the name used to prove control of the name)

use super::PeerId;
use hashtrinity::Table;
use hashtrinity::crypto::{sha256, to_hex};

/// An apex zone this platform is authoritative for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Apex {
    /// The zone itself, e.g. `"twnstack.app"`. Always lowercase, no trailing dot.
    pub zone: &'static str,
    /// Whether the TLD is HSTS-preloaded as a whole (`.app`, `.dev`). When true a hostname
    /// under this apex CANNOT be served — or even usefully handed to a customer — before its
    /// certificate exists, because browsers will not fall back to plaintext.
    pub hsts_preloaded: bool,
}

impl Apex {
    /// The wildcard certificate name covering one label under this apex.
    #[must_use]
    pub fn wildcard(&self) -> String {
        format!("*.{}", self.zone)
    }
}

/// Every apex the edge answers for. `tasmanian.cloud` is the platform's own zone (the portal
/// lives there); the rest are the customer-facing pool.
pub const APEXES: &[Apex] = &[
    Apex { zone: "tasmanian.cloud", hsts_preloaded: false },
    Apex { zone: "twnstack.cloud",  hsts_preloaded: false },
    Apex { zone: "twnstack.app",    hsts_preloaded: true  },
    Apex { zone: "twnbox.app",      hsts_preloaded: true  },
    Apex { zone: "twnstack.dev",    hsts_preloaded: true  },
    Apex { zone: "twnbox.dev",      hsts_preloaded: true  },
];

/// The apex a fully-qualified name sits directly under, if any.
///
/// Only a *direct* child matches: `a.twnstack.app` yes, `b.a.twnstack.app` no. That is not a
/// simplification — it is the exact set a single wildcard certificate covers, so allowing
/// deeper names here would admit names we cannot present a certificate for.
#[must_use]
pub fn apex_of(fqdn: &str) -> Option<&'static Apex> {
    let fqdn = normalize(fqdn);
    APEXES.iter().find(|apex| {
        fqdn.strip_suffix(apex.zone)
            .and_then(|head| head.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    })
}

/// Lowercase, strip a trailing root dot. Every hostname entering this module goes through
/// here so `Foo.TWNSTACK.app.` and `foo.twnstack.app` are one key, not two.
#[must_use]
pub fn normalize(fqdn: &str) -> String {
    fqdn.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `label` is a legal single DNS label for our purposes: 1–63 chars, `a-z0-9-`, not
/// starting or ending with a hyphen, and no `xn--` (we do not mint punycode).
#[must_use]
pub fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && !label.starts_with("xn--")
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `fqdn` is a plausible customer-owned domain we could serve: at least two labels,
/// each individually valid, total length within the DNS limit, and NOT under one of our own
/// apexes (a customer cannot "bring" a name we already control).
#[must_use]
pub fn is_valid_custom_hostname(fqdn: &str) -> bool {
    let fqdn = normalize(fqdn);
    if fqdn.len() > 253 || fqdn.split('.').count() < 2 {
        return false;
    }
    if APEXES.iter().any(|a| fqdn == a.zone || fqdn.ends_with(&format!(".{}", a.zone))) {
        return false;
    }
    fqdn.split('.').all(is_valid_label)
}

// ── Label generation ──────────────────────────────────────────────────────────────────────

/// Pronounceable halves for a generated label. Kept deliberately small and boring: these end
/// up in URLs customers read aloud on support calls, so no ambiguous spellings and no words
/// that collide with reserved names below.
const ADJECTIVES: &[&str] = &[
    "amber", "azure", "brisk", "bright", "calm", "clever", "coral", "crisp", "dusk", "eager",
    "fable", "fern", "gentle", "glad", "granite", "harbor", "ivory", "jade", "keen", "lucid",
    "mellow", "misty", "noble", "olive", "opal", "pearl", "quiet", "rapid", "russet", "sable",
    "solar", "swift", "tidal", "topaz", "umber", "vivid", "warm", "wren", "zesty", "zephyr",
];

const NOUNS: &[&str] = &[
    "banksia", "bellbird", "bramble", "cascade", "cedar", "cove", "current", "delta", "dingo",
    "ember", "estuary", "fjord", "galah", "granite", "harbour", "heath", "ibis", "inlet",
    "jarrah", "kelp", "lantern", "ledger", "lyrebird", "meadow", "mesa", "numbat", "orchard",
    "pelican", "quokka", "quoll", "ridge", "rosella", "sandbar", "summit", "thicket", "tundra",
    "verdant", "wallaby", "willow", "wombat",
];

/// Reserved labels the generator will never emit and a customer may never claim. These are
/// names infrastructure and humans assume mean something specific.
const RESERVED_LABELS: &[&str] = &[
    "www", "api", "app", "admin", "portal", "mail", "smtp", "imap", "pop", "ns", "ns1", "ns2",
    "dns", "mx", "edge", "cdn", "status", "docs", "blog", "billing", "auth", "login", "sso",
    "id", "console", "dashboard", "static", "assets", "cdn1", "test", "staging", "prod",
    "internal", "vpn", "git", "registry", "acme", "_acme-challenge", "localhost", "root",
];

/// Whether a label is reserved (never generated, never claimable by a customer).
#[must_use]
pub fn is_reserved_label(label: &str) -> bool {
    RESERVED_LABELS.contains(&label)
}

/// The managed label for a dialkey — deterministic, pronounceable, `adj-noun-xxxxxx`.
///
/// Deterministic on purpose, matching [`super::dialkey::peer_id`]'s own philosophy: a
/// connector holding only its dialkey can compute the hostname it will be reachable at with
/// no round trip, and the name is stable across re-provisioning of the same tunnel.
///
/// `attempt` exists because determinism does not excuse us from collisions: the registry
/// checks, and on a clash the caller retries with `attempt + 1`, which reshuffles the whole
/// label rather than appending a counter to a taken name.
#[must_use]
pub fn label_for_dialkey(dialkey: &str, attempt: u32) -> String {
    let digest = sha256(format!("{dialkey}:tas-edge-label:{attempt}").as_bytes());
    let adj = ADJECTIVES[usize::from(digest[0]) % ADJECTIVES.len()];
    let noun = NOUNS[usize::from(digest[1]) % NOUNS.len()];
    // 24 bits of suffix — enough that a collision is a registry retry, not a routine event,
    // and short enough to read out over the phone.
    let suffix = to_hex(&digest[2..5]);
    format!("{adj}-{noun}-{suffix}")
}

// ── Hostname records ──────────────────────────────────────────────────────────────────────

/// Where a hostname's traffic goes: a tenant's tunnel, reached over an authenticated
/// [`super::Transport`] connection to the connector's dialkey-derived [`PeerId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub tenant_id: String,
    pub tunnel_id: String,
    /// The connector's identity — `dialkey::peer_id(dialkey)`. The edge serves this hostname
    /// only over a connection it has already authenticated as this peer.
    pub peer: PeerId,
    /// The port the connector forwards to on its own side of the tunnel.
    pub origin_port: u16,
}

/// A hostname's lifecycle. Managed names skip straight past `PendingDns` (we are the
/// authority, so there is nothing to prove); custom names walk the whole ladder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostnameState {
    /// Custom hostname awaiting proof of control (CNAME to us, or the TXT token).
    PendingDns,
    /// Control proven; awaiting a certificate.
    PendingCert,
    /// Serving.
    Active,
    /// Held by an operator or by billing — resolves, refuses to serve.
    Suspended,
    /// Terminal for this attempt; carries why, so the portal can show a real reason.
    Failed(String),
}

/// Managed (ours) or custom (the customer's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostnameKind {
    Managed,
    Custom,
}

/// One admitted hostname.
#[derive(Clone, Debug)]
pub struct HostnameRecord {
    pub fqdn: String,
    pub kind: HostnameKind,
    pub route: Route,
    pub state: HostnameState,
    /// The certificate name that covers this hostname: an apex wildcard for managed names,
    /// the fqdn itself for custom ones. This is what [`CertSource`] is asked for.
    pub cert_name: String,
    /// Set for custom hostnames until control is proven.
    pub challenge: Option<Challenge>,
}

impl HostnameRecord {
    /// Whether the edge may actually serve this name right now.
    ///
    /// Deliberately stricter than `state == Active` for HSTS-preloaded apexes: on `.app`/
    /// `.dev` a name without a certificate is not "degraded", it is a browser error, so it
    /// must never reach a listener that would answer on `:80`.
    #[must_use]
    pub fn is_servable(&self, have_cert: bool) -> bool {
        match self.state {
            HostnameState::Active => have_cert || !self.requires_tls(),
            _ => false,
        }
    }

    /// Whether plaintext is categorically unavailable for this name.
    #[must_use]
    pub fn requires_tls(&self) -> bool {
        apex_of(&self.fqdn).is_some_and(|a| a.hsts_preloaded) || self.kind == HostnameKind::Custom
    }
}

/// The proof-of-control challenge issued for a custom hostname.
///
/// Two independent ways to satisfy it, matching what a customer can actually do at the two
/// stages of a migration:
///
/// - **`txt`** — publish `TXT <txt_name> = <token>` *before* moving any traffic. This is
///   pre-validation: it proves control while the domain still points at their old host, so a
///   certificate can be issued and the cutover is a single DNS change with no downtime.
/// - **`cname`** — point `CNAME <fqdn> → <cname_target>` at their managed hostname. This is
///   the delegation itself; once it resolves to us, control is self-evident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub fqdn: String,
    /// `_twn-challenge.<fqdn>` — where the token goes.
    pub txt_name: String,
    /// The exact value the TXT record must contain.
    pub token: String,
    /// The managed hostname the customer CNAMEs to.
    pub cname_target: String,
}

impl Challenge {
    /// Derive the challenge for `fqdn`. The token is unguessable without `registry_secret`
    /// but stable given it, so re-opening the portal shows the same record to publish rather
    /// than invalidating what the customer already pasted into their DNS provider.
    #[must_use]
    pub fn derive(fqdn: &str, tenant_id: &str, cname_target: &str, registry_secret: &[u8]) -> Self {
        let fqdn = normalize(fqdn);
        let mut input = Vec::with_capacity(registry_secret.len() + fqdn.len() + tenant_id.len() + 16);
        input.extend_from_slice(registry_secret);
        input.extend_from_slice(b":tas-edge-challenge:");
        input.extend_from_slice(fqdn.as_bytes());
        input.push(b':');
        input.extend_from_slice(tenant_id.as_bytes());
        Challenge {
            txt_name: format!("_twn-challenge.{fqdn}"),
            token: to_hex(&sha256(&input)),
            cname_target: normalize(cname_target),
            fqdn,
        }
    }

    /// Whether any of the TXT values published at `txt_name` satisfies this challenge.
    #[must_use]
    pub fn satisfied_by_txt(&self, values: &[String]) -> bool {
        values.iter().any(|v| v.trim().eq_ignore_ascii_case(&self.token))
    }

    /// Whether the observed CNAME chain lands on the target we handed out.
    #[must_use]
    pub fn satisfied_by_cname(&self, targets: &[String]) -> bool {
        targets.iter().any(|t| normalize(t) == self.cname_target)
    }
}

// ── The registry ──────────────────────────────────────────────────────────────────────────

/// Why a hostname could not be admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeError {
    /// The name is syntactically unusable.
    InvalidHostname(String),
    /// The label is one we never hand out.
    ReservedLabel(String),
    /// Already claimed — by this tenant or another (the message never says which, so the
    /// registry can't be used to enumerate other tenants' hostnames).
    Taken(String),
    /// No such hostname in this tenant.
    NotFound(String),
    /// The caller's tenant does not own this hostname.
    Forbidden(String),
    /// Every generation attempt collided — the label space for this dialkey is exhausted,
    /// which in practice means something is wrong, not that we ran out of names.
    NoLabelAvailable,
}

impl std::fmt::Display for EdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeError::InvalidHostname(h) => write!(f, "invalid hostname: {h}"),
            EdgeError::ReservedLabel(l) => write!(f, "reserved label: {l}"),
            EdgeError::Taken(h) => write!(f, "hostname already taken: {h}"),
            EdgeError::NotFound(h) => write!(f, "no such hostname: {h}"),
            EdgeError::Forbidden(h) => write!(f, "hostname belongs to another tenant: {h}"),
            EdgeError::NoLabelAvailable => write!(f, "could not generate a free label"),
        }
    }
}

impl std::error::Error for EdgeError {}

/// How many label generations to try before giving up.
const LABEL_ATTEMPTS: u32 = 32;

/// The hostname table the edge admits traffic from and the DNS server answers out of.
///
/// Every mutating method takes the caller's `tenant_id` and refuses to touch another
/// tenant's row — the same tenancy discipline `transport::control` applies to overlay state,
/// for the same reason: this is the surface a multi-tenant control plane calls.
pub struct EdgeRegistry {
    hosts: Table<String, HostnameRecord>,
    /// hostname → tenant, kept alongside `hosts` so an existence check for a name in ANOTHER
    /// tenant can answer "taken" without exposing the record.
    owner: Table<String, String>,
    /// Probe attempts spent per pending hostname — the B/U face. Bounds how long a never-
    /// configured custom hostname is polled for.
    probes: Table<String, i64>,
    /// Secret backing challenge-token derivation.
    secret: Vec<u8>,
}

impl EdgeRegistry {
    /// A registry whose challenge tokens are derived under `secret`. The secret must be
    /// stable across restarts (a Vault-held value, not a per-process random) or every
    /// pending custom hostname's published TXT record stops matching.
    #[must_use]
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        EdgeRegistry {
            hosts: Table::new(),
            owner: Table::new(),
            probes: Table::new(),
            secret: secret.into(),
        }
    }

    /// Claim a managed hostname for a tunnel, deriving the label from its dialkey.
    ///
    /// Returns the record with `state = Active`: we are authoritative for the apex and the
    /// wildcard certificate already covers the name, so there is nothing to validate. On
    /// `.app`/`.dev` "active" still does not mean servable until the wildcard is actually
    /// loaded — see [`HostnameRecord::is_servable`].
    pub fn claim_managed(
        &mut self,
        apex: &Apex,
        dialkey: &str,
        route: Route,
    ) -> Result<HostnameRecord, EdgeError> {
        for attempt in 0..LABEL_ATTEMPTS {
            let label = label_for_dialkey(dialkey, attempt);
            if is_reserved_label(&label) {
                continue;
            }
            let fqdn = format!("{label}.{}", apex.zone);
            if self.owner.get(&fqdn).is_some() {
                continue;
            }
            let record = HostnameRecord {
                fqdn: fqdn.clone(),
                kind: HostnameKind::Managed,
                route: route.clone(),
                state: HostnameState::Active,
                cert_name: apex.wildcard(),
                challenge: None,
            };
            self.owner.put(fqdn.clone(), route.tenant_id.clone());
            self.hosts.put(fqdn, record.clone());
            return Ok(record);
        }
        Err(EdgeError::NoLabelAvailable)
    }

    /// Claim a specific managed label (an operator override or a customer-chosen vanity
    /// name), rather than the dialkey-derived one.
    pub fn claim_managed_label(
        &mut self,
        apex: &Apex,
        label: &str,
        route: Route,
    ) -> Result<HostnameRecord, EdgeError> {
        let label = label.trim().to_ascii_lowercase();
        if !is_valid_label(&label) {
            return Err(EdgeError::InvalidHostname(label));
        }
        if is_reserved_label(&label) {
            return Err(EdgeError::ReservedLabel(label));
        }
        let fqdn = format!("{label}.{}", apex.zone);
        if self.owner.get(&fqdn).is_some() {
            return Err(EdgeError::Taken(fqdn));
        }
        let record = HostnameRecord {
            fqdn: fqdn.clone(),
            kind: HostnameKind::Managed,
            route: route.clone(),
            state: HostnameState::Active,
            cert_name: apex.wildcard(),
            challenge: None,
        };
        self.owner.put(fqdn.clone(), route.tenant_id.clone());
        self.hosts.put(fqdn, record.clone());
        Ok(record)
    }

    /// Register a customer-owned hostname. Lands in [`HostnameState::PendingDns`] with a
    /// [`Challenge`] to publish — it is NOT served until control is proven.
    pub fn add_custom(
        &mut self,
        fqdn: &str,
        cname_target: &str,
        route: Route,
    ) -> Result<HostnameRecord, EdgeError> {
        let fqdn = normalize(fqdn);
        if !is_valid_custom_hostname(&fqdn) {
            return Err(EdgeError::InvalidHostname(fqdn));
        }
        if self.owner.get(&fqdn).is_some() {
            return Err(EdgeError::Taken(fqdn));
        }
        let challenge = Challenge::derive(&fqdn, &route.tenant_id, cname_target, &self.secret);
        let record = HostnameRecord {
            fqdn: fqdn.clone(),
            kind: HostnameKind::Custom,
            route: route.clone(),
            state: HostnameState::PendingDns,
            cert_name: fqdn.clone(),
            challenge: Some(challenge),
        };
        self.owner.put(fqdn.clone(), route.tenant_id.clone());
        self.hosts.put(fqdn, record.clone());
        Ok(record)
    }

    /// The record for `fqdn`, regardless of tenant — the *edge data plane's* lookup, which
    /// has already authenticated the connection and needs the route, not an authorization
    /// check. Control-plane callers use [`Self::get_for_tenant`].
    #[must_use]
    pub fn lookup(&self, fqdn: &str) -> Option<&HostnameRecord> {
        self.hosts.get(&normalize(fqdn))
    }

    /// The record for `fqdn`, only if `tenant_id` owns it.
    pub fn get_for_tenant(&self, tenant_id: &str, fqdn: &str) -> Result<&HostnameRecord, EdgeError> {
        let fqdn = normalize(fqdn);
        match self.owner.get(&fqdn) {
            None => Err(EdgeError::NotFound(fqdn)),
            Some(owner) if owner != tenant_id => Err(EdgeError::Forbidden(fqdn)),
            Some(_) => self.hosts.get(&fqdn).ok_or(EdgeError::NotFound(fqdn)),
        }
    }

    /// Every hostname belonging to `tenant_id`.
    #[must_use]
    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<HostnameRecord> {
        self.hosts
            .iter()
            .filter(|(_, r)| r.route.tenant_id == tenant_id)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Every hostname pointing at `tunnel_id` — what the portal shows on a tunnel, and what
    /// must be torn down when the tunnel is destroyed.
    #[must_use]
    pub fn list_for_tunnel(&self, tunnel_id: &str) -> Vec<HostnameRecord> {
        self.hosts
            .iter()
            .filter(|(_, r)| r.route.tunnel_id == tunnel_id)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Hostnames still waiting on proof of control — the validation worker's work list.
    #[must_use]
    pub fn pending_validation(&self) -> Vec<HostnameRecord> {
        self.hosts
            .iter()
            .filter(|(_, r)| r.state == HostnameState::PendingDns)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Record the outcome of one validation probe.
    ///
    /// `proven` advances `PendingDns → PendingCert`. A failed probe increments the attempt
    /// counter and, past `max_probes`, fails the hostname with a reason a human can act on —
    /// polling a hostname whose owner never configured DNS forever is a slow leak, not
    /// patience.
    pub fn record_probe(
        &mut self,
        fqdn: &str,
        proven: bool,
        max_probes: i64,
    ) -> Result<HostnameState, EdgeError> {
        let fqdn = normalize(fqdn);
        let Some(record) = self.hosts.get(&fqdn) else {
            return Err(EdgeError::NotFound(fqdn));
        };
        let mut record = record.clone();
        if proven {
            record.state = HostnameState::PendingCert;
        } else {
            self.probes.add(fqdn.clone(), 1);
            if self.probes.count(&fqdn) >= max_probes {
                record.state = HostnameState::Failed(format!(
                    "no CNAME to {} and no matching TXT at {} after {max_probes} checks",
                    record.challenge.as_ref().map_or("the edge", |c| c.cname_target.as_str()),
                    record.challenge.as_ref().map_or("_twn-challenge", |c| c.txt_name.as_str()),
                ));
            }
        }
        let state = record.state.clone();
        self.hosts.put(fqdn, record);
        Ok(state)
    }

    /// Mark a hostname's certificate as present — `PendingCert → Active`.
    pub fn cert_ready(&mut self, fqdn: &str) -> Result<(), EdgeError> {
        let fqdn = normalize(fqdn);
        let Some(record) = self.hosts.get(&fqdn) else {
            return Err(EdgeError::NotFound(fqdn));
        };
        let mut record = record.clone();
        record.state = HostnameState::Active;
        self.hosts.put(fqdn, record);
        Ok(())
    }

    /// Suspend a hostname — it keeps resolving (so the customer sees our page, not a dead
    /// name) but the edge refuses to proxy it.
    pub fn suspend(&mut self, tenant_id: &str, fqdn: &str) -> Result<(), EdgeError> {
        self.set_state_checked(tenant_id, fqdn, HostnameState::Suspended)
    }

    /// Un-suspend back to `Active`.
    pub fn resume(&mut self, tenant_id: &str, fqdn: &str) -> Result<(), EdgeError> {
        self.set_state_checked(tenant_id, fqdn, HostnameState::Active)
    }

    fn set_state_checked(
        &mut self,
        tenant_id: &str,
        fqdn: &str,
        state: HostnameState,
    ) -> Result<(), EdgeError> {
        let fqdn = normalize(fqdn);
        let mut record = self.get_for_tenant(tenant_id, &fqdn)?.clone();
        record.state = state;
        self.hosts.put(fqdn, record);
        Ok(())
    }

    /// Release a hostname. Managed labels become claimable again; custom ones are simply
    /// forgotten (the customer's DNS is theirs to clean up).
    pub fn release(&mut self, tenant_id: &str, fqdn: &str) -> Result<(), EdgeError> {
        let fqdn = normalize(fqdn);
        self.get_for_tenant(tenant_id, &fqdn)?;
        self.hosts.remove(&fqdn);
        self.owner.remove(&fqdn);
        self.probes.remove(&fqdn);
        Ok(())
    }

    /// Every distinct certificate name the edge must hold to serve what it has admitted —
    /// the apex wildcards in use plus every validated custom hostname. This is the issuance
    /// worker's work list.
    #[must_use]
    pub fn required_cert_names(&self) -> Vec<String> {
        let mut seen: Table<String, bool> = Table::new();
        let mut out = Vec::new();
        for (_, record) in self.hosts.iter() {
            if matches!(record.state, HostnameState::PendingDns | HostnameState::Failed(_)) {
                continue;
            }
            if !seen.has(&record.cert_name) {
                seen.mark(record.cert_name.clone());
                out.push(record.cert_name.clone());
            }
        }
        out.sort();
        out
    }

    /// How many hostnames the registry holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.len() == 0
    }
}

// ── Certificate resolution ────────────────────────────────────────────────────────────────

/// Where certificates come from. The edge asks by name; an implementation may read files,
/// Vault, or (eventually) an ACME cache. Kept a trait so no part of the edge is coupled to a
/// particular issuance story.
pub trait CertSource: Send + Sync {
    /// The PEM chain and PKCS8 key for `cert_name`, or `None` if we do not hold one.
    /// `cert_name` is exactly what [`HostnameRecord::cert_name`] carries: an apex wildcard
    /// (`*.twnstack.app`) or a custom fqdn.
    fn cert_for(&self, cert_name: &str) -> Option<CertMaterial>;
}

/// A certificate as it comes out of a [`CertSource`].
#[derive(Clone, Debug)]
pub struct CertMaterial {
    pub chain_pem: String,
    pub key_pem: String,
}

/// The certificate name that covers `fqdn` under this registry's rules — the wildcard for a
/// managed name, the name itself for a custom one.
///
/// This is the SNI resolution rule, kept pure and testable rather than living inside a
/// `ResolvesServerCert` impl where it could only be exercised through a TLS handshake.
#[must_use]
pub fn cert_name_for(fqdn: &str) -> String {
    let fqdn = normalize(fqdn);
    match apex_of(&fqdn) {
        Some(apex) => apex.wildcard(),
        None => fqdn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(tenant: &str, tunnel: &str) -> Route {
        Route {
            tenant_id: tenant.to_string(),
            tunnel_id: tunnel.to_string(),
            peer: super::super::dialkey::peer_id(tunnel),
            origin_port: 8080,
        }
    }

    #[test]
    fn apex_matches_only_direct_children() {
        assert_eq!(apex_of("amber-wren-1a2b3c.twnstack.app").unwrap().zone, "twnstack.app");
        assert_eq!(apex_of("AMBER-WREN.TWNSTACK.APP.").unwrap().zone, "twnstack.app");
        assert!(apex_of("deep.amber-wren.twnstack.app").is_none(), "wildcard covers one label only");
        assert!(apex_of("twnstack.app").is_none(), "the apex itself is not a child");
        assert!(apex_of("app.acme.com.au").is_none());
    }

    #[test]
    fn hsts_preloaded_apexes_are_flagged() {
        for zone in ["twnstack.app", "twnbox.app", "twnstack.dev", "twnbox.dev"] {
            let apex = APEXES.iter().find(|a| a.zone == zone).unwrap();
            assert!(apex.hsts_preloaded, "{zone} is under an HSTS-preloaded TLD");
        }
        for zone in ["tasmanian.cloud", "twnstack.cloud"] {
            let apex = APEXES.iter().find(|a| a.zone == zone).unwrap();
            assert!(!apex.hsts_preloaded);
        }
    }

    #[test]
    fn labels_are_deterministic_and_well_formed() {
        let a = label_for_dialkey("tunnel-abc", 0);
        let b = label_for_dialkey("tunnel-abc", 0);
        assert_eq!(a, b, "the same dialkey must always yield the same hostname");
        assert!(is_valid_label(&a), "generated label must be a legal DNS label: {a}");
        assert_ne!(a, label_for_dialkey("tunnel-abc", 1), "retry reshuffles the whole label");
        assert_ne!(a, label_for_dialkey("tunnel-xyz", 0));
    }

    #[test]
    fn generated_labels_never_collide_with_reserved_names() {
        for i in 0..2000u32 {
            let label = label_for_dialkey(&format!("dialkey-{i}"), 0);
            assert!(!is_reserved_label(&label), "generator emitted reserved label {label}");
            assert!(is_valid_label(&label));
        }
    }

    #[test]
    fn custom_hostname_validation_rejects_our_own_zones() {
        assert!(is_valid_custom_hostname("app.acme.com.au"));
        assert!(is_valid_custom_hostname("acme.com.au"));
        assert!(!is_valid_custom_hostname("anything.twnstack.app"), "cannot 'bring' a name we own");
        assert!(!is_valid_custom_hostname("twnbox.dev"));
        assert!(!is_valid_custom_hostname("localhost"), "single label is not a domain");
        assert!(!is_valid_custom_hostname("-bad.example.com"));
    }

    #[test]
    fn managed_claim_is_stable_for_a_dialkey() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let mut reg = EdgeRegistry::new(b"test-secret".to_vec());
        let rec = reg.claim_managed(apex, "dialkey-one", route("acme", "tun-1")).unwrap();
        assert_eq!(rec.fqdn, format!("{}.twnstack.app", label_for_dialkey("dialkey-one", 0)));
        assert_eq!(rec.cert_name, "*.twnstack.app");
        assert_eq!(rec.state, HostnameState::Active);
        assert!(rec.challenge.is_none(), "we are authoritative — nothing to prove");
    }

    #[test]
    fn a_colliding_dialkey_gets_a_different_label_not_an_error() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let first = reg.claim_managed(apex, "same-dialkey", route("acme", "tun-1")).unwrap();
        // A second tenant deriving the identical label must be given a free one instead.
        let second = reg.claim_managed(apex, "same-dialkey", route("other", "tun-2")).unwrap();
        assert_ne!(first.fqdn, second.fqdn);
        assert_eq!(second.fqdn, format!("{}.twnstack.app", label_for_dialkey("same-dialkey", 1)));
    }

    #[test]
    fn reserved_labels_cannot_be_claimed() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let err = reg.claim_managed_label(apex, "admin", route("acme", "t")).unwrap_err();
        assert_eq!(err, EdgeError::ReservedLabel("admin".to_string()));
    }

    #[test]
    fn custom_hostname_starts_pending_and_is_not_servable() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg
            .add_custom("app.acme.com.au", "amber-wren-1a2b3c.twnstack.app", route("acme", "tun-1"))
            .unwrap();
        assert_eq!(rec.state, HostnameState::PendingDns);
        assert_eq!(rec.cert_name, "app.acme.com.au", "custom names need their own certificate");
        assert!(!rec.is_servable(true), "unproven control must never serve, certificate or not");
        let challenge = rec.challenge.unwrap();
        assert_eq!(challenge.txt_name, "_twn-challenge.app.acme.com.au");
        assert_eq!(challenge.cname_target, "amber-wren-1a2b3c.twnstack.app");
    }

    #[test]
    fn challenge_tokens_are_stable_and_domain_bound() {
        let a = Challenge::derive("app.acme.com.au", "acme", "x.twnstack.app", b"secret");
        let b = Challenge::derive("APP.ACME.COM.AU.", "acme", "x.twnstack.app", b"secret");
        assert_eq!(a.token, b.token, "the same name must not re-issue a different token");
        let other_domain = Challenge::derive("app.other.com.au", "acme", "x.twnstack.app", b"secret");
        assert_ne!(a.token, other_domain.token);
        let other_tenant = Challenge::derive("app.acme.com.au", "rival", "x.twnstack.app", b"secret");
        assert_ne!(a.token, other_tenant.token, "a token must not transfer between tenants");
        let other_secret = Challenge::derive("app.acme.com.au", "acme", "x.twnstack.app", b"other");
        assert_ne!(a.token, other_secret.token, "the token must be unguessable without the secret");
    }

    #[test]
    fn challenge_is_satisfied_by_either_proof() {
        let c = Challenge::derive("app.acme.com.au", "acme", "x.twnstack.app", b"s");
        assert!(c.satisfied_by_txt(&[c.token.clone()]));
        assert!(c.satisfied_by_txt(&["noise".into(), c.token.to_uppercase()]));
        assert!(!c.satisfied_by_txt(&["noise".into()]));
        assert!(c.satisfied_by_cname(&["X.TWNSTACK.APP.".into()]), "case and root dot must not matter");
        assert!(!c.satisfied_by_cname(&["someone-else.twnstack.app".into()]));
    }

    #[test]
    fn validation_walks_pending_to_active() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        reg.add_custom("app.acme.com.au", "x.twnstack.app", route("acme", "tun-1")).unwrap();
        assert_eq!(reg.pending_validation().len(), 1);

        let state = reg.record_probe("app.acme.com.au", true, 10).unwrap();
        assert_eq!(state, HostnameState::PendingCert);
        assert!(reg.pending_validation().is_empty());

        reg.cert_ready("app.acme.com.au").unwrap();
        let rec = reg.lookup("app.acme.com.au").unwrap();
        assert_eq!(rec.state, HostnameState::Active);
        assert!(rec.is_servable(true));
        assert!(!rec.is_servable(false), "custom hostnames have no plaintext fallback");
    }

    #[test]
    fn a_never_configured_hostname_fails_instead_of_polling_forever() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        reg.add_custom("app.acme.com.au", "x.twnstack.app", route("acme", "tun-1")).unwrap();
        for _ in 0..2 {
            assert_eq!(reg.record_probe("app.acme.com.au", false, 3).unwrap(), HostnameState::PendingDns);
        }
        let state = reg.record_probe("app.acme.com.au", false, 3).unwrap();
        match state {
            HostnameState::Failed(reason) => {
                assert!(reason.contains("x.twnstack.app"), "the failure must name what to fix: {reason}");
                assert!(reason.contains("_twn-challenge.app.acme.com.au"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(reg.pending_validation().is_empty(), "a failed hostname leaves the work list");
    }

    #[test]
    fn tenancy_is_enforced_on_every_control_path() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg.claim_managed(apex, "dk", route("acme", "tun-1")).unwrap();

        assert!(matches!(reg.get_for_tenant("rival", &rec.fqdn), Err(EdgeError::Forbidden(_))));
        assert!(matches!(reg.suspend("rival", &rec.fqdn), Err(EdgeError::Forbidden(_))));
        assert!(matches!(reg.release("rival", &rec.fqdn), Err(EdgeError::Forbidden(_))));
        assert!(reg.get_for_tenant("acme", &rec.fqdn).is_ok());

        // The data plane still resolves it — it has already authenticated the connection.
        assert!(reg.lookup(&rec.fqdn).is_some());
    }

    #[test]
    fn taken_hostname_does_not_leak_the_owning_tenant() {
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        // The tenant id is deliberately NOT a substring of the hostname, so the assertion
        // below tests what it claims to rather than matching the domain by accident.
        reg.add_custom("app.example.com.au", "x.twnstack.app", route("tenant-mercury", "t1")).unwrap();
        let err = reg
            .add_custom("app.example.com.au", "y.twnstack.app", route("tenant-venus", "t2"))
            .unwrap_err();
        assert_eq!(err, EdgeError::Taken("app.example.com.au".to_string()));
        assert!(
            !err.to_string().contains("mercury"),
            "a probe from another tenant must not learn who holds the name: {err}"
        );
    }

    #[test]
    fn suspension_stops_serving_without_dropping_the_name() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg.claim_managed(apex, "dk", route("acme", "tun-1")).unwrap();
        reg.suspend("acme", &rec.fqdn).unwrap();
        assert!(!reg.lookup(&rec.fqdn).unwrap().is_servable(true));
        assert!(reg.lookup(&rec.fqdn).is_some(), "a suspended name still resolves");
        reg.resume("acme", &rec.fqdn).unwrap();
        assert!(reg.lookup(&rec.fqdn).unwrap().is_servable(true));
    }

    #[test]
    fn release_frees_the_label_for_reuse() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let first = reg.claim_managed(apex, "dk", route("acme", "tun-1")).unwrap();
        reg.release("acme", &first.fqdn).unwrap();
        let second = reg.claim_managed(apex, "dk", route("other", "tun-2")).unwrap();
        assert_eq!(first.fqdn, second.fqdn, "the freed label is derivable again");
    }

    #[test]
    fn cert_names_collapse_to_one_wildcard_per_apex() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.app").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        for i in 0..5 {
            reg.claim_managed(apex, &format!("dk-{i}"), route("acme", &format!("tun-{i}"))).unwrap();
        }
        reg.add_custom("app.acme.com.au", "x.twnstack.app", route("acme", "tun-c")).unwrap();

        // The pending custom hostname is NOT yet in the issuance list — proving control
        // comes first, or we would be asking a CA for a name we cannot validate.
        assert_eq!(reg.required_cert_names(), vec!["*.twnstack.app".to_string()]);

        reg.record_probe("app.acme.com.au", true, 5).unwrap();
        assert_eq!(
            reg.required_cert_names(),
            vec!["*.twnstack.app".to_string(), "app.acme.com.au".to_string()],
            "five managed hostnames still need exactly one wildcard"
        );
    }

    #[test]
    fn cert_name_resolution_matches_the_record() {
        assert_eq!(cert_name_for("amber-wren-1a2b3c.twnstack.app"), "*.twnstack.app");
        assert_eq!(cert_name_for("app.acme.com.au"), "app.acme.com.au");
        assert_eq!(cert_name_for("deep.nested.twnstack.app"), "deep.nested.twnstack.app");
    }

    #[test]
    fn routes_carry_the_dialkey_derived_peer_identity() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        let rec = reg.claim_managed(apex, "dk", route("acme", "tun-7")).unwrap();
        assert_eq!(
            rec.route.peer,
            super::super::dialkey::peer_id("tun-7"),
            "the edge must only serve this hostname over a connection authenticated as this peer"
        );
    }

    #[test]
    fn listings_are_scoped() {
        let apex = APEXES.iter().find(|a| a.zone == "twnstack.cloud").unwrap();
        let mut reg = EdgeRegistry::new(b"s".to_vec());
        reg.claim_managed(apex, "dk-1", route("acme", "tun-1")).unwrap();
        reg.claim_managed(apex, "dk-2", route("acme", "tun-2")).unwrap();
        reg.claim_managed(apex, "dk-3", route("rival", "tun-3")).unwrap();

        assert_eq!(reg.list_for_tenant("acme").len(), 2);
        assert_eq!(reg.list_for_tenant("rival").len(), 1);
        assert_eq!(reg.list_for_tunnel("tun-1").len(), 1);
        assert_eq!(reg.len(), 3);
    }
}
