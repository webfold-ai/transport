//! The edge's hostname authority: `transport::edge::EdgeRegistry` plus what the data plane and
//! control plane share around it.
//!
//! Before this module the edge accepted any syntactically non-empty hostname at
//! `POST /control/tunnels`, with no notion of tenant, apex, reserved labels, proof of control,
//! or which connector a name belongs to — any holder of the (shared) control secret could claim
//! any name, and a tunnel claim was never bound to the dialling agent's identity. Now:
//!
//! - a hostname must be **admitted** (`Op::AdmitManaged` / `Op::AdmitCustom`) through
//!   `transport::edge`'s rules before an agent can enrol it;
//! - the first agent enrolment **binds** the connector's identity to the name
//!   ([`Op::BindPeer`]); a tunnel claim from any other peer is refused;
//! - admissions are **journaled** (append-only JSONL, fsynced) and replayed at boot, so a restart
//!   does not drop every customer's hostname. Certificate state is not journaled: certificates
//!   live in the `FileCertStore`, and the renewal engine re-activates waiting hostnames from it.
//!
//! The journal is a command log, replayed through the same code path as live requests. Release
//! quarantine restarts at replay time (it can only be longer than the original — the safe
//! direction).
//!
//! ## Releasing a custom hostname revokes its certificate
//!
//! A custom hostname has a dedicated certificate whose private key we hold; once the name is
//! released that key is a credential for a name that is no longer ours until the certificate
//! expires (up to 90 days). So [`Op::Release`] of a **custom** name does not just stop routing it:
//! the certificate is taken out of the store (it is no longer served) and queued for revocation
//! (reason `cessationOfOperation`) in the durable [`RevocationQueue`] shared with the renewal
//! engine, which retries until the CA has revoked it or it expires. Decisions, and the alternative
//! rejected:
//!
//! - **At release, not only at prune.** The engine prunes unrequired certificates after seven days;
//!   waiting that long to revoke leaves the credential live for the week it is least watched.
//!   The prune path still revokes (it is the backstop for a release whose queueing failed, and for
//!   a certificate an in-flight order installs after the release).
//! - **Never block or fail the release.** Queueing is local and durable; the CA is never called
//!   on the release path. If even the queue write fails the certificate stays in the store, the
//!   release succeeds, `edge_lb_revocation_enqueue_failures_total` counts it and the prune retries.
//! - **The key is never dropped before the revocation is on record**
//!   ([`transport::acme_renew::retire_for_revocation`] writes the queue entry first).
//! - **Managed names are never revoked.** They share the apex wildcard, which every other hostname
//!   under the apex is still using.
//! - **Not on journal replay.** A replayed release describes the past; the store may by now hold a
//!   *new* tenant's certificate for the same name (the quarantine has lapsed), which must not be revoked.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};
use transport::acme_renew::{
    cert_validity, retire_for_revocation, CertStatus, CertStore, Retired, RevocationQueue,
};
use transport::edge::{
    cert_name_for, normalize, CertSource, EdgeError, EdgeRegistry, HostnameKind, HostnameRecord,
    HostnameState, Route, TlsMode, APEXES, UNBOUND_PEER,
};
use transport::edge_proxy::{
    decide, decide_passthrough, sni_route, ConnectorPool, Decision, SniRoute,
};
use transport::edge_verify::ProofPolicy;
use transport::PeerId;

use crate::http01::ChallengeStore;
use crate::metrics::Metrics;

/// One state-changing operation. Serialised as one JSON line in the journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    AdmitManaged {
        tenant_id: String,
        tunnel_id: String,
        apex: String,
        /// A vanity label; otherwise the label is derived from `dialkey`.
        label: Option<String>,
        dialkey: Option<String>,
        tls_mode: String,
        origin_port: u16,
        /// Hex Ed25519 public key of the connector, when the portal already knows it.
        agent_peer: Option<String>,
    },
    AdmitCustom {
        tenant_id: String,
        tunnel_id: String,
        fqdn: String,
        cname_target: String,
        tls_mode: String,
        origin_port: u16,
        agent_peer: Option<String>,
    },
    /// Proof of control for a custom hostname passed (journaled so a restart keeps it).
    Validated {
        fqdn: String,
    },
    Release {
        tenant_id: String,
        fqdn: String,
    },
    SetTlsMode {
        tenant_id: String,
        fqdn: String,
        tls_mode: String,
    },
    Suspend {
        tenant_id: String,
        fqdn: String,
    },
    Resume {
        tenant_id: String,
        fqdn: String,
    },
    BindPeer {
        fqdn: String,
        peer: String,
        origin_port: u16,
    },
}

/// Why an operation was refused. Mapped to HTTP statuses by the control API.
#[derive(Debug, PartialEq, Eq)]
pub enum AdmitError {
    Invalid(String),
    Conflict(String),
    Forbidden(String),
    NotFound(String),
    Internal(String),
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitError::Invalid(m)
            | AdmitError::Conflict(m)
            | AdmitError::Forbidden(m)
            | AdmitError::NotFound(m)
            | AdmitError::Internal(m) => f.write_str(m),
        }
    }
}

impl From<EdgeError> for AdmitError {
    fn from(e: EdgeError) -> Self {
        let m = e.to_string();
        match e {
            EdgeError::InvalidHostname(_)
            | EdgeError::ReservedLabel(_)
            | EdgeError::InvalidCnameTarget(_) => AdmitError::Invalid(m),
            EdgeError::Taken(_) | EdgeError::PeerConflict(_) | EdgeError::BadState(_) => {
                AdmitError::Conflict(m)
            }
            EdgeError::Forbidden(_) => AdmitError::Forbidden(m),
            EdgeError::NotFound(_) => AdmitError::NotFound(m),
            EdgeError::NoLabelAvailable => AdmitError::Internal(m),
        }
    }
}

/// Append-only, fsynced command log.
pub struct Journal {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl Journal {
    /// Open (creating) the journal at `path` and return it with every op already in it, in order.
    ///
    /// # Errors
    /// If the file cannot be opened, or a line does not parse — the edge refuses to start on a
    /// journal it cannot replay rather than quietly dropping customers' hostnames.
    pub fn open(path: impl Into<PathBuf>) -> Result<(Self, Vec<Op>), String> {
        let path = path.into();
        let existing = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let mut ops = Vec::new();
        for (i, line) in existing.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            ops.push(
                serde_json::from_str::<Op>(line)
                    .map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?,
            );
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))?;
        Ok((
            Journal {
                path,
                file: Mutex::new(file),
            },
            ops,
        ))
    }

    fn append(&self, op: &Op) -> Result<(), String> {
        let mut line = serde_json::to_string(op).map_err(|e| e.to_string())?;
        line.push('\n');
        let mut f = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.write_all(line.as_bytes())
            .map_err(|e| format!("writing {}: {e}", self.path.display()))?;
        f.sync_data()
            .map_err(|e| format!("syncing {}: {e}", self.path.display()))
    }
}

/// Everything the data plane and control plane share about hostnames.
pub struct EdgeState {
    pub registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
    /// Which connectors are dialled in right now (keyed by authenticated peer identity).
    pub pool: Mutex<ConnectorPool>,
    /// Where certificates come from, once TLS hosting is configured.
    certs: Mutex<Option<Arc<dyn CertSource>>>,
    /// The last renewal-pass status, for `GET /control/certs`.
    cert_status: Mutex<Vec<CertStatus>>,
    /// HTTP-01 tokens currently being served.
    pub challenges: Arc<ChallengeStore>,
    /// Which observations prove control of a custom hostname.
    pub proof: ProofPolicy,
    journal: Option<Journal>,
    /// Counters and health results reported by `/control/metrics` and `/control/health`.
    pub metrics: Arc<Metrics>,
    /// Where a released custom hostname's certificate goes to be revoked (certificate hosting only).
    revoker: Mutex<Option<Revoker>>,
    /// CA resilience telemetry (CA standing, root-program verdicts, CT findings, RNG self-check),
    /// shown by `/control/metrics` and `/control/health`. Empty unless certificate hosting is on.
    pub ca: crate::ca::CaTelemetry,
}

/// The store a certificate is retired from and the queue it is retired into.
struct Revoker {
    store: Arc<dyn CertStore>,
    queue: Arc<RevocationQueue>,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn parse_tls_mode(s: &str) -> Result<TlsMode, AdmitError> {
    match s {
        "terminate" | "" => Ok(TlsMode::Terminate),
        "passthrough" => Ok(TlsMode::Passthrough),
        other => Err(AdmitError::Invalid(format!(
            "tls_mode must be 'terminate' or 'passthrough', not '{other}'"
        ))),
    }
}

fn parse_peer(hex: &str) -> Result<PeerId, AdmitError> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AdmitError::Invalid(
            "peer must be 64 hex characters (an Ed25519 public key)".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| AdmitError::Invalid("bad peer hex".into()))?;
    }
    if out == UNBOUND_PEER {
        return Err(AdmitError::Invalid("peer must not be all zero".into()));
    }
    Ok(out)
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Lower-case hex of a peer id.
#[must_use]
pub fn peer_hex(peer: &PeerId) -> String {
    use std::fmt::Write as _;
    peer.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl EdgeState {
    /// A state whose challenge tokens are derived under `secret` (must be stable across restarts,
    /// or every pending custom hostname's published TXT record stops matching) and which logs to
    /// `journal` when set.
    #[must_use]
    pub fn new(secret: &[u8], proof: ProofPolicy, journal: Option<Journal>) -> Arc<Self> {
        Arc::new(EdgeState {
            registry: Arc::new(tokio::sync::Mutex::new(EdgeRegistry::new(secret.to_vec()))),
            pool: Mutex::new(ConnectorPool::new()),
            certs: Mutex::new(None),
            cert_status: Mutex::new(Vec::new()),
            challenges: Arc::new(ChallengeStore::default()),
            proof,
            metrics: {
                let m = Arc::new(Metrics::default());
                m.set_journal_enabled(journal.is_some());
                m
            },
            journal,
            revoker: Mutex::new(None),
            ca: crate::ca::CaTelemetry::default(),
        })
    }

    /// An empty, journal-less state (tests; also what a plain `EdgeLb::build` uses).
    #[must_use]
    pub fn ephemeral() -> Arc<Self> {
        Self::new(b"edge-lb-ephemeral", ProofPolicy::default(), None)
    }

    /// Replay journaled operations through the live code path. Individual failures (e.g. a
    /// quarantine collision on replay) are logged and skipped; they cannot be fatal because the
    /// journal is the record of what *was* accepted.
    pub async fn replay(&self, ops: Vec<Op>) {
        let total = ops.len();
        let mut failed = 0usize;
        for op in ops {
            if let Err(e) = self.apply_inner(&op, true).await {
                failed += 1;
                warn!(error = %e, ?op, "journal replay: operation no longer applies; skipped");
            }
        }
        self.metrics.record_replay(total as u64, failed as u64);
        info!(total, failed, "hostname journal replayed");
    }

    /// Let a release of a custom hostname retire its certificate from `store` into `queue`
    /// (see the module docs). Without this, releases never touch certificates.
    pub fn set_revoker(&self, store: Arc<dyn CertStore>, queue: Arc<RevocationQueue>) {
        self.metrics.set_revocation_queue(queue.clone());
        *self
            .revoker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Revoker { store, queue });
    }

    /// The validity span of the certificate held for `cert_name`, in seconds.
    #[must_use]
    pub fn cert_lifetime(&self, cert_name: &str) -> Option<i64> {
        let source = self
            .certs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        cert_validity(&source.cert_for(cert_name)?.chain_pem).map(|v| v.lifetime())
    }

    /// After a custom hostname's release: retire its certificate. `None` when there is nothing to
    /// report (no revoker configured). Never fails the release.
    fn retire_released(&self, cert_name: &str, now: i64) -> Option<&'static str> {
        let guard = self
            .revoker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let revoker = guard.as_ref()?;
        match retire_for_revocation(revoker.store.as_ref(), &revoker.queue, cert_name, now) {
            Ok(Retired::Queued) => {
                info!(cert = %cert_name, "released hostname's certificate removed from service and queued for revocation");
                Some("queued")
            }
            Ok(Retired::NotHeld) => Some("no_certificate"),
            Ok(Retired::SharedWildcard) => None,
            Err(e) => {
                self.metrics.record_revocation_enqueue_failure();
                warn!(cert = %cert_name, error = %e, "could not queue the released hostname's certificate for revocation; it stays in the store and the prune retries");
                Some("deferred")
            }
        }
    }

    /// Install the certificate source (enables `have_cert` in admission decisions).
    pub fn set_cert_source(&self, source: Arc<dyn CertSource>) {
        *self
            .certs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    pub fn set_cert_status(&self, status: Vec<CertStatus>) {
        *self
            .cert_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
    }

    #[must_use]
    pub fn cert_status(&self) -> Vec<CertStatus> {
        self.cert_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether a certificate covering `host` is held. With no certificate source installed the
    /// edge is not the TLS terminator (it sits behind one, or is overlay-only), so certificate
    /// presence is not a gate and this is `true`.
    #[must_use]
    pub fn have_cert(&self, host: &str) -> bool {
        self.certs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_none_or(|c| c.cert_for(&cert_name_for(host)).is_some())
    }

    /// Admission verdict for a request to `host`, arriving under TLS SNI `sni` (`None` on a
    /// plaintext connection); `None` when the name is not in the registry at all (the caller
    /// falls back to the static route table).
    pub async fn decide(&self, host: &str, sni: Option<&str>) -> Option<Decision> {
        let have_cert = self.have_cert(host);
        let reg = self.registry.lock().await;
        reg.lookup(&normalize(strip_port(host)))?;
        let pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(decide(&reg, &pool, sni, host, have_cert))
    }

    /// The first routing decision on a new TLS connection (see `transport::edge_proxy::sni_route`).
    pub async fn sni_route(&self, sni: &str) -> SniRoute {
        sni_route(&*self.registry.lock().await, sni)
    }

    /// Admission for a passthrough connection named `sni`.
    pub async fn decide_passthrough(&self, sni: &str) -> Decision {
        let reg = self.registry.lock().await;
        let pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        decide_passthrough(&reg, &pool, Some(sni))
    }

    /// Run one proof-of-control sweep and journal each hostname it advances, so a restart does
    /// not send a validated customer back through `PendingDns`.
    pub async fn sweep(
        &self,
        probe: &dyn transport::edge_verify::DnsProbe,
        max_probes: i64,
    ) -> Vec<(String, HostnameState)> {
        let results =
            transport::edge_verify::sweep_shared(probe, &self.registry, max_probes, self.proof)
                .await;
        for (fqdn, state) in &results {
            if matches!(state, HostnameState::PendingCert | HostnameState::Active) {
                if let Some(j) = &self.journal {
                    if let Err(e) = j.append(&Op::Validated { fqdn: fqdn.clone() }) {
                        self.metrics.record_journal_write_failure();
                        warn!(%fqdn, error = %e, "journal: could not record validation");
                    }
                }
            }
        }
        results
    }

    /// Apply a live operation: validate through `transport::edge`, mutate, journal.
    ///
    /// # Errors
    /// [`AdmitError`] for anything the registry refuses; `Internal` if the journal write fails
    /// (the in-memory change has been applied — the caller should surface the 500).
    pub async fn apply(&self, op: &Op) -> Result<Value, AdmitError> {
        self.apply_inner(op, false).await
    }

    async fn apply_inner(&self, op: &Op, replay: bool) -> Result<Value, AdmitError> {
        let (mut out, retire) = {
            let mut reg = self.registry.lock().await;
            // What a release is releasing, read before it is gone: only a live (non-replay) release of
            // a custom hostname retires a certificate, and only one no other hostname still needs.
            let released_cert = match op {
                Op::Release { fqdn, .. } if !replay => reg
                    .lookup(&normalize(fqdn))
                    .filter(|r| r.kind == HostnameKind::Custom && !r.cert_name.starts_with("*."))
                    .map(|r| r.cert_name.clone()),
                _ => None,
            };
            let out = Self::mutate(&mut reg, op, self.proof)?;
            let retire = released_cert.filter(|name| !reg.required_cert_names().contains(name));
            (out, retire)
        };
        if let Some(cert_name) = retire {
            if let Some(outcome) = self.retire_released(&cert_name, unix_now()) {
                out["certificate_revocation"] = json!(outcome);
            }
        }
        if !replay {
            if let Some(j) = &self.journal {
                j.append(op).map_err(|e| {
                    self.metrics.record_journal_write_failure();
                    AdmitError::Internal(format!("journal: {e}"))
                })?;
            }
        }
        Ok(out)
    }

    fn mutate(reg: &mut EdgeRegistry, op: &Op, _proof: ProofPolicy) -> Result<Value, AdmitError> {
        match op {
            Op::AdmitManaged {
                tenant_id,
                tunnel_id,
                apex,
                label,
                dialkey,
                tls_mode,
                origin_port,
                agent_peer,
            } => {
                let apex = APEXES
                    .iter()
                    .find(|a| a.zone == normalize(apex))
                    .ok_or_else(|| {
                        AdmitError::Invalid(format!("'{apex}' is not one of the edge's apexes"))
                    })?;
                let route = Route {
                    tenant_id: tenant_id.clone(),
                    tunnel_id: tunnel_id.clone(),
                    peer: agent_peer
                        .as_deref()
                        .map(parse_peer)
                        .transpose()?
                        .unwrap_or(UNBOUND_PEER),
                    origin_port: *origin_port,
                };
                let record = match (label.as_deref(), dialkey.as_deref()) {
                    (Some(label), _) => reg.claim_managed_label(apex, label, route)?,
                    (None, Some(dialkey)) => reg.claim_managed(apex, dialkey, route)?,
                    (None, None) => {
                        return Err(AdmitError::Invalid(
                            "a managed hostname needs a 'label' or a 'dialkey'".into(),
                        ))
                    }
                };
                reg.set_tls_mode(tenant_id, &record.fqdn, parse_tls_mode(tls_mode)?)?;
                Ok(view(reg.lookup(&record.fqdn).unwrap_or(&record)))
            }
            Op::AdmitCustom {
                tenant_id,
                tunnel_id,
                fqdn,
                cname_target,
                tls_mode,
                origin_port,
                agent_peer,
            } => {
                let route = Route {
                    tenant_id: tenant_id.clone(),
                    tunnel_id: tunnel_id.clone(),
                    peer: agent_peer
                        .as_deref()
                        .map(parse_peer)
                        .transpose()?
                        .unwrap_or(UNBOUND_PEER),
                    origin_port: *origin_port,
                };
                let record = reg.add_custom(fqdn, cname_target, route)?;
                reg.set_tls_mode(tenant_id, &record.fqdn, parse_tls_mode(tls_mode)?)?;
                Ok(view(reg.lookup(&record.fqdn).unwrap_or(&record)))
            }
            Op::Validated { fqdn } => {
                reg.record_probe(fqdn, true, i64::MAX)?;
                Ok(json!({ "fqdn": fqdn }))
            }
            Op::Release { tenant_id, fqdn } => {
                reg.release(tenant_id, fqdn)?;
                Ok(json!({ "fqdn": normalize(fqdn), "status": "released" }))
            }
            Op::SetTlsMode {
                tenant_id,
                fqdn,
                tls_mode,
            } => {
                reg.set_tls_mode(tenant_id, fqdn, parse_tls_mode(tls_mode)?)?;
                Ok(reg.lookup(fqdn).map_or(Value::Null, view))
            }
            Op::Suspend { tenant_id, fqdn } => {
                reg.suspend(tenant_id, fqdn)?;
                Ok(reg.lookup(fqdn).map_or(Value::Null, view))
            }
            Op::Resume { tenant_id, fqdn } => {
                reg.resume(tenant_id, fqdn)?;
                Ok(reg.lookup(fqdn).map_or(Value::Null, view))
            }
            Op::BindPeer {
                fqdn,
                peer,
                origin_port,
            } => {
                reg.bind_peer(fqdn, parse_peer(peer)?, *origin_port)?;
                Ok(reg.lookup(fqdn).map_or(Value::Null, view))
            }
        }
    }

    /// The hostname's record, only if `tenant_id` owns it.
    pub async fn get_for_tenant(&self, tenant_id: &str, fqdn: &str) -> Result<Value, AdmitError> {
        let reg = self.registry.lock().await;
        Ok(view(reg.get_for_tenant(tenant_id, fqdn)?))
    }

    pub async fn list_for_tenant(&self, tenant_id: &str) -> Vec<Value> {
        let reg = self.registry.lock().await;
        let mut all: Vec<Value> = reg.list_for_tenant(tenant_id).iter().map(view).collect();
        all.sort_by(|a, b| a["fqdn"].as_str().cmp(&b["fqdn"].as_str()));
        all
    }

    /// The connector identity currently expected for `fqdn` (None if unknown or unbound).
    pub async fn expected_peer(&self, fqdn: &str) -> Option<PeerId> {
        let reg = self.registry.lock().await;
        reg.lookup(fqdn)
            .map(|r| r.route.peer)
            .filter(|p| *p != UNBOUND_PEER)
    }
}

/// The JSON a hostname is shown as. Never includes the registry secret; the challenge is the
/// customer-facing instruction (what to publish), which is exactly what the portal displays.
#[must_use]
pub fn view(record: &HostnameRecord) -> Value {
    let state = match &record.state {
        HostnameState::PendingDns => json!({ "status": "pending_dns" }),
        HostnameState::PendingCert => json!({ "status": "pending_cert" }),
        HostnameState::Active => json!({ "status": "active" }),
        HostnameState::Suspended => json!({ "status": "suspended" }),
        HostnameState::Failed(why) => json!({ "status": "failed", "reason": why }),
    };
    json!({
        "fqdn": record.fqdn,
        "kind": match record.kind { HostnameKind::Managed => "managed", HostnameKind::Custom => "custom" },
        "tenant_id": record.route.tenant_id,
        "tunnel_id": record.route.tunnel_id,
        "tls_mode": match record.tls_mode { TlsMode::Terminate => "terminate", TlsMode::Passthrough => "passthrough" },
        "cert_name": record.cert_name,
        "origin_port": record.route.origin_port,
        "connector": if record.route.peer == UNBOUND_PEER { Value::Null } else { Value::String(peer_hex(&record.route.peer)) },
        "state": state,
        "challenge": record.challenge.as_ref().map(|c| json!({
            "txt_name": c.txt_name,
            "txt_value": c.token,
            "cname_target": c.cname_target,
        })),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    fn managed(label: &str, tenant: &str) -> Op {
        Op::AdmitManaged {
            tenant_id: tenant.into(),
            tunnel_id: format!("tun-{label}"),
            apex: "tascloud.app".into(),
            label: Some(label.into()),
            dialkey: None,
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        }
    }

    #[tokio::test]
    async fn admission_follows_transport_edge_rules() {
        let st = EdgeState::ephemeral();
        let ok = st.apply(&managed("my-app", "acme")).await.unwrap();
        assert_eq!(ok["fqdn"], "my-app.tascloud.app");
        assert_eq!(
            ok["connector"],
            Value::Null,
            "no connector bound until the agent enrols"
        );

        // reserved label, taken label, unknown apex, no label/dialkey
        assert!(matches!(
            st.apply(&managed("admin", "acme")).await,
            Err(AdmitError::Invalid(_))
        ));
        assert!(matches!(
            st.apply(&managed("my-app", "rival")).await,
            Err(AdmitError::Conflict(_))
        ));
        let mut op = managed("x", "acme");
        if let Op::AdmitManaged { apex, .. } = &mut op {
            *apex = "evil.example".into();
        }
        assert!(matches!(st.apply(&op).await, Err(AdmitError::Invalid(_))));
        let mut op = managed("y", "acme");
        if let Op::AdmitManaged { label, .. } = &mut op {
            *label = None;
        }
        assert!(matches!(st.apply(&op).await, Err(AdmitError::Invalid(_))));
    }

    #[tokio::test]
    async fn custom_hostnames_need_a_cname_target_the_tenant_owns_and_report_the_challenge() {
        let st = EdgeState::ephemeral();
        st.apply(&managed("mine", "acme")).await.unwrap();
        let custom = |target: &str, tenant: &str| Op::AdmitCustom {
            tenant_id: tenant.into(),
            tunnel_id: "t".into(),
            fqdn: "app.acme.com.au".into(),
            cname_target: target.into(),
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        };
        assert!(
            matches!(
                st.apply(&custom("mine.tascloud.app", "rival")).await,
                Err(AdmitError::Invalid(_))
            ),
            "not the rival's label"
        );
        let v = st
            .apply(&custom("mine.tascloud.app", "acme"))
            .await
            .unwrap();
        assert_eq!(v["state"]["status"], "pending_dns");
        assert_eq!(v["challenge"]["txt_name"], "_twn-challenge.app.acme.com.au");
        assert_eq!(v["challenge"]["txt_value"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn the_journal_replays_admissions_bindings_and_validation_after_a_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hostnames.jsonl");
        let peer = "ab".repeat(32);
        {
            let (j, ops) = Journal::open(&path).unwrap();
            assert!(ops.is_empty());
            let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
            st.apply(&managed("mine", "acme")).await.unwrap();
            st.apply(&Op::BindPeer {
                fqdn: "mine.tascloud.app".into(),
                peer: peer.clone(),
                origin_port: 9000,
            })
            .await
            .unwrap();
            st.apply(&Op::AdmitCustom {
                tenant_id: "acme".into(),
                tunnel_id: "t".into(),
                fqdn: "app.acme.com.au".into(),
                cname_target: "mine.tascloud.app".into(),
                tls_mode: "terminate".into(),
                origin_port: 8080,
                agent_peer: None,
            })
            .await
            .unwrap();
            st.apply(&Op::Validated {
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();
            st.apply(&Op::Suspend {
                tenant_id: "acme".into(),
                fqdn: "mine.tascloud.app".into(),
            })
            .await
            .unwrap();
            // A refused op must NOT reach the journal.
            assert!(st.apply(&managed("admin", "acme")).await.is_err());
        }
        let (j, ops) = Journal::open(&path).unwrap();
        assert_eq!(ops.len(), 5, "only accepted operations are journaled");
        let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
        st.replay(ops).await;

        let mine = st
            .get_for_tenant("acme", "mine.tascloud.app")
            .await
            .unwrap();
        assert_eq!(
            mine["connector"], peer,
            "the connector binding survived the restart"
        );
        assert_eq!(mine["origin_port"], 9000);
        assert_eq!(mine["state"]["status"], "suspended");
        let custom = st.get_for_tenant("acme", "app.acme.com.au").await.unwrap();
        assert_eq!(
            custom["state"]["status"], "pending_cert",
            "validated stays validated"
        );
        assert_eq!(
            st.expected_peer("mine.tascloud.app").await,
            Some([0xab; 32])
        );
    }

    #[test]
    fn an_unreadable_journal_line_refuses_to_start_rather_than_dropping_hostnames() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("j.jsonl");
        std::fs::write(&path, "{\"op\":\"validated\",\"fqdn\":\"a.b\"}\nnot json\n").unwrap();
        let err = Journal::open(&path).err().expect("must refuse");
        assert!(err.contains(":2:"), "names the bad line: {err}");
    }

    #[tokio::test]
    async fn peer_binding_is_first_come_and_a_second_peer_is_a_conflict() {
        let st = EdgeState::ephemeral();
        st.apply(&managed("mine", "acme")).await.unwrap();
        let bind = |peer: &str| Op::BindPeer {
            fqdn: "mine.tascloud.app".into(),
            peer: peer.into(),
            origin_port: 1,
        };
        st.apply(&bind(&"11".repeat(32))).await.unwrap();
        st.apply(&bind(&"11".repeat(32))).await.unwrap();
        assert!(matches!(
            st.apply(&bind(&"22".repeat(32))).await,
            Err(AdmitError::Conflict(_))
        ));
        assert!(matches!(
            st.apply(&bind("nothex")).await,
            Err(AdmitError::Invalid(_))
        ));
        assert!(matches!(
            st.apply(&bind(&"00".repeat(32))).await,
            Err(AdmitError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn decide_is_none_for_unknown_names_and_reports_connector_state_for_known_ones() {
        let st = EdgeState::ephemeral();
        assert!(st.decide("nothing.tascloud.app", None).await.is_none());
        st.apply(&managed("mine", "acme")).await.unwrap();
        // No certificate source installed: the edge is not the TLS terminator, so only the
        // connector gates the name.
        assert_eq!(
            st.decide("mine.tascloud.app", None).await,
            Some(Decision::NoConnector)
        );
        // With a source installed (and empty), tascloud.app is HSTS-preloaded: no certificate =>
        // 503 CertPending, never a plaintext serve.
        st.set_cert_source(Arc::new(transport::edge_proxy::MemoryCertSource::default()));
        assert_eq!(
            st.decide("mine.tascloud.app", None).await,
            Some(Decision::CertPending)
        );
        // SNI that disagrees with Host is 421 whatever else is true.
        assert_eq!(
            st.decide("mine.tascloud.app", Some("other.tascloud.app"))
                .await,
            Some(Decision::Misdirected)
        );
    }

    // ── revoke-on-release ─────────────────────────────────────────────────────────────────

    use transport::acme_renew::{CertStore, RevocationQueue};
    use transport::edge::CertMaterial;
    use transport::edge_proxy::MemoryCertSource;

    /// A real self-signed certificate and PKCS#8 key for `name`.
    fn cert_for(name: &str) -> CertMaterial {
        use rcgen::{date_time_ymd, CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.not_before = date_time_ymd(2027, 1, 14);
        params.not_after = date_time_ymd(2027, 4, 15);
        CertMaterial {
            chain_pem: params.self_signed(&key).unwrap().pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn custom_op(fqdn: &str, tenant: &str) -> Op {
        Op::AdmitCustom {
            tenant_id: tenant.into(),
            tunnel_id: "t".into(),
            fqdn: fqdn.into(),
            cname_target: "mine.tascloud.app".into(),
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        }
    }

    /// A state with a managed host `mine`, a validated custom name `app.acme.com.au`, certificates
    /// for the custom name and the apex wildcard installed, and a revoker over them.
    async fn hosted() -> (Arc<EdgeState>, Arc<MemoryCertSource>, Arc<RevocationQueue>) {
        let st = EdgeState::ephemeral();
        st.apply(&managed("mine", "acme")).await.unwrap();
        st.apply(&custom_op("app.acme.com.au", "acme"))
            .await
            .unwrap();
        st.apply(&Op::Validated {
            fqdn: "app.acme.com.au".into(),
        })
        .await
        .unwrap();
        let store = Arc::new(MemoryCertSource::new());
        store
            .put("app.acme.com.au", cert_for("app.acme.com.au"))
            .unwrap();
        store
            .put("*.tascloud.app", cert_for("tascloud.app"))
            .unwrap();
        let queue = Arc::new(RevocationQueue::in_memory());
        st.set_revoker(store.clone() as Arc<dyn CertStore>, queue.clone());
        (st, store, queue)
    }

    #[tokio::test]
    async fn releasing_a_custom_hostname_stops_serving_its_certificate_and_queues_it_for_revocation(
    ) {
        let (st, store, queue) = hosted().await;
        let before = store.cert_for("app.acme.com.au").unwrap();

        let out = st
            .apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "App.Acme.com.au".into(),
            })
            .await
            .unwrap();
        assert_eq!(out["status"], "released");
        assert_eq!(out["certificate_revocation"], "queued");
        assert!(
            store.cert_for("app.acme.com.au").is_none(),
            "the dedicated certificate is no longer served"
        );
        assert_eq!(queue.len(), 1);
        let status = queue.status();
        assert_eq!(status[0].name, "app.acme.com.au");
        assert_eq!(status[0].attempts, 0);
        // The queue holds the very certificate (and, internally, its key) that was in service.
        assert_eq!(
            status[0].not_after,
            transport::acme_renew::cert_validity(&before.chain_pem).map(|v| v.not_after)
        );
        assert!(
            store.cert_for("*.tascloud.app").is_some(),
            "the shared wildcard is untouched"
        );
    }

    #[tokio::test]
    async fn releasing_a_managed_hostname_never_touches_certificates_even_the_last_one_under_the_apex(
    ) {
        let (st, store, queue) = hosted().await;
        // Release the custom name first (so `mine` is the last host under the wildcard), then `mine`.
        st.apply(&Op::Release {
            tenant_id: "acme".into(),
            fqdn: "app.acme.com.au".into(),
        })
        .await
        .unwrap();
        let out = st
            .apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "mine.tascloud.app".into(),
            })
            .await
            .unwrap();
        assert!(out.get("certificate_revocation").is_none(), "{out}");
        assert!(
            store.cert_for("*.tascloud.app").is_some(),
            "a wildcard is shared: one hostname leaving never retires it"
        );
        assert_eq!(
            queue.len(),
            1,
            "only the custom name's certificate is queued"
        );
        assert_eq!(queue.status()[0].name, "app.acme.com.au");
    }

    #[tokio::test]
    async fn a_release_with_no_certificate_yet_or_no_revoker_is_unremarkable() {
        let (st, store, queue) = hosted().await;
        store.remove("app.acme.com.au"); // validated, certificate not issued yet
        let out = st
            .apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();
        assert_eq!(out["certificate_revocation"], "no_certificate");
        assert!(queue.is_empty());

        // Hosting off: no revoker, no key in the response, release as before.
        let plain = EdgeState::ephemeral();
        plain.apply(&managed("mine", "acme")).await.unwrap();
        plain
            .apply(&custom_op("app.acme.com.au", "acme"))
            .await
            .unwrap();
        let out = plain
            .apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            out,
            json!({ "fqdn": "app.acme.com.au", "status": "released" })
        );
    }

    #[tokio::test]
    async fn a_refused_release_retires_nothing() {
        let (st, store, queue) = hosted().await;
        // Another tenant cannot release (and so cannot cause the revocation of) acme's name.
        assert!(matches!(
            st.apply(&Op::Release {
                tenant_id: "rival".into(),
                fqdn: "app.acme.com.au".into()
            })
            .await,
            Err(AdmitError::Forbidden(_))
        ));
        assert!(matches!(
            st.apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "nothing.example.org".into()
            })
            .await,
            Err(AdmitError::NotFound(_))
        ));
        assert!(store.cert_for("app.acme.com.au").is_some() && queue.is_empty());
    }

    #[tokio::test]
    async fn a_release_succeeds_even_when_the_revocation_cannot_be_queued_and_the_certificate_stays(
    ) {
        let (st, store, _queue) = hosted().await;
        let dir = tempfile::TempDir::new().unwrap();
        let qdir = dir.path().join("revocations");
        let broken = Arc::new(RevocationQueue::open(&qdir).unwrap());
        std::fs::remove_dir_all(&qdir).unwrap(); // the queue's directory vanishes
        st.set_revoker(store.clone() as Arc<dyn CertStore>, broken.clone());

        let out = st
            .apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .expect("the release is not blocked");
        assert_eq!(out["status"], "released");
        assert_eq!(out["certificate_revocation"], "deferred");
        assert!(
            store.cert_for("app.acme.com.au").is_some(),
            "key not dropped before the revocation is on record"
        );
        assert!(broken.is_empty());
        assert!(
            st.get_for_tenant("acme", "app.acme.com.au").await.is_ok()
                || st.decide("app.acme.com.au", None).await.is_none(),
            "the name itself is released"
        );
        let text = crate::metrics::render_prometheus(&st, &[], 1_800_000_000);
        assert!(
            text.contains("edge_lb_revocation_enqueue_failures_total 1"),
            "the failure is counted for alerting"
        );
    }

    #[tokio::test]
    async fn replaying_a_journaled_release_never_revokes_a_certificate() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("h.jsonl");
        {
            let (j, _) = Journal::open(&path).unwrap();
            let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
            st.apply(&managed("mine", "acme")).await.unwrap();
            st.apply(&custom_op("app.acme.com.au", "acme"))
                .await
                .unwrap();
            st.apply(&Op::Release {
                tenant_id: "acme".into(),
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();
        }
        // Reboot: the store now holds a certificate under that name (a later tenant's, say).
        let (j, ops) = Journal::open(&path).unwrap();
        let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
        let store = Arc::new(MemoryCertSource::new());
        store
            .put("app.acme.com.au", cert_for("app.acme.com.au"))
            .unwrap();
        let queue = Arc::new(RevocationQueue::in_memory());
        st.set_revoker(store.clone() as Arc<dyn CertStore>, queue.clone());
        st.replay(ops).await;
        assert!(
            store.cert_for("app.acme.com.au").is_some(),
            "history must not revoke what is in service now"
        );
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn journal_replay_and_write_failures_are_counted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("h.jsonl");
        {
            let (j, _) = Journal::open(&path).unwrap();
            let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
            assert_eq!(
                st.metrics.journal(),
                crate::metrics::JournalStats {
                    enabled: true,
                    ..Default::default()
                }
            );
            st.apply(&managed("mine", "acme")).await.unwrap();
        }
        // A journal line that no longer applies (the label is taken by the time it replays).
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&serde_json::to_string(&managed("mine", "rival")).unwrap());
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        let (j, ops) = Journal::open(&path).unwrap();
        let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(j));
        st.replay(ops).await;
        let stats = st.metrics.journal();
        assert_eq!(
            (
                stats.replayed,
                stats.replay_ops,
                stats.replay_failed,
                stats.write_failures
            ),
            (true, 2, 1, 0)
        );

        // An append that fails: the accepted change is reported as a 500 AND counted.
        let ro = Journal {
            path: path.clone(),
            file: Mutex::new(std::fs::File::open(&path).unwrap()),
        }; // read-only handle
        let st = EdgeState::new(b"secret", ProofPolicy::default(), Some(ro));
        assert!(matches!(
            st.apply(&managed("other", "acme")).await,
            Err(AdmitError::Internal(_))
        ));
        assert_eq!(st.metrics.journal().write_failures, 1);
        assert_eq!(st.metrics.journal().replay_ops, 0);
    }
}
