//! The control channel: the control plane pushes signed configs over the transport mesh.
//!
//! ## Two independent checks
//!
//! 1. **Transport identity.** The listener is a `transport::native::NativeEndpoint`: a mutually
//!    authenticated, forward-secret, AEAD-sealed channel whose handshake proves the peer holds the
//!    Ed25519 key it claims. We then require that key to be the configured control-plane key
//!    (constant-time compare); any other peer is dropped before it can send a byte we parse.
//! 2. **Document signature.** The pushed bytes are a [`crate::signed_config`] envelope, verified
//!    against the same key, with sequence numbers and rollback refusal. This is what makes the
//!    config authentic *at rest* (it is persisted and re-verified at boot) and survives a bug or
//!    misconfiguration in channel authentication: the channel is defence in depth, the signature
//!    is the authority.
//!
//! Wire: the pusher opens a stream and sends **one frame** containing the envelope; the LB
//! answers with one frame, `ok:<seq>` or `err:<code>` (codes from
//! [`ConfigError::code`](crate::signed_config::ConfigError::code); never document contents).
//!
//! ## Abuse story
//!
//! The endpoint binds an internal (mesh) address only. Unauthenticated peers can reach only the
//! transport handshake, which is bounded by the transport crate (256 in flight, 10 s each); only
//! the control key's holder gets past it, and at most two pushes are handled at once, each under
//! a 10 s deadline and a 64 KiB bound.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apeiron::map::hashtrinity::crypto::ct_eq;
use tokio::sync::{watch, Semaphore};
use transport::native::NativeEndpoint;
use transport::{Connection as _, Transport as _};

use crate::loglimit::unix_now;
use crate::metrics::ConfigResult;
use crate::signed_config::{ConfigError, ConfigStore, MAX_ENVELOPE};
use crate::userspace::Shared;

const PUSH_DEADLINE: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"tas-lb-config/1";

/// Verifies, persists and applies a signed config, and accounts for the outcome. The only path by
/// which a backend set reaches the Director.
pub struct Applier {
    store: ConfigStore,
    shared: Arc<Shared>,
}

impl Applier {
    /// Wire a store to the shared state.
    #[must_use]
    pub fn new(store: ConfigStore, shared: Arc<Shared>) -> Self {
        Applier { store, shared }
    }

    /// Load the persisted last good config at boot (same checks as a push).
    pub fn load_persisted(&self) {
        match self.store.load_persisted() {
            Ok(Some(a)) => {
                self.commit(a.seq, &a.set);
                tracing::info!(seq = a.seq, "loaded persisted config");
            }
            Ok(None) => tracing::info!(
                "no persisted config; refusing flows until the control plane pushes one"
            ),
            Err(e) => self.alert(
                &e,
                "persisted config failed verification; moved aside, waiting for a push",
            ),
        }
    }

    /// Verify and apply a pushed envelope; on any failure the last good config stays in force.
    ///
    /// # Errors
    /// [`ConfigError`] describing the refusal.
    pub fn apply(&self, bytes: &[u8]) -> Result<u64, ConfigError> {
        match self.store.apply(bytes) {
            Ok(a) => {
                self.commit(a.seq, &a.set);
                Ok(a.seq)
            }
            Err(e) => {
                self.alert(&e, "config refused; keeping the last good config");
                Err(e)
            }
        }
    }

    fn commit(&self, seq: u64, set: &crate::backend::BackendSet) {
        if let Err(e) = self.shared.director.apply_set(set, Instant::now()) {
            // Unreachable after validation; still fail loudly rather than silently.
            tracing::error!(target: "tas_lb::alert", error = %e, "verified config could not be applied");
            return;
        }
        let m = &self.shared.metrics;
        m.config_seq.store(seq, Ordering::Relaxed);
        m.config_applied_unix.store(unix_now(), Ordering::Relaxed);
        m.config_result(ConfigResult::Applied);
        tracing::info!(seq, backends = set.backends.len(), cluster = %set.cluster, "config applied");
    }

    fn alert(&self, e: &ConfigError, what: &str) {
        let m = &self.shared.metrics;
        m.config_result(e.result());
        m.config_rejected_unix.store(unix_now(), Ordering::Relaxed);
        // `tas_lb::alert` is the target alerting keys on; the text never includes document contents.
        tracing::error!(target: "tas_lb::alert", reason = e.code(), "{what}");
    }

    /// Sequence number in force.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.store.last_seq()
    }
}

/// Accept pushes until `shutdown` fires.
pub async fn serve(
    endpoint: Arc<NativeEndpoint>,
    signer: [u8; 32],
    applier: Arc<Applier>,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(2));
    loop {
        let conn = tokio::select! {
            c = endpoint.accept() => match c { Some(c) => c, None => return },
            _ = shutdown.changed() => return,
        };
        if !ct_eq(&conn.peer_id(), &signer) {
            applier
                .shared
                .metrics
                .config_result(ConfigResult::PeerRejected);
            if applier.shared.logs.allow(unix_now()) {
                tracing::warn!(target: "tas_lb::alert", "control connection from a peer that is not the control plane; dropped");
            }
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let applier = applier.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(PUSH_DEADLINE, async {
                let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                    return;
                };
                let mut buf = vec![0u8; MAX_ENVELOPE + 1];
                let Ok(n) = recv.read(&mut buf).await else {
                    return;
                };
                let reply = if n > MAX_ENVELOPE {
                    applier
                        .shared
                        .metrics
                        .config_result(ConfigResult::Malformed);
                    "err:too_large".to_string()
                } else {
                    match applier.apply(buf.get(..n).unwrap_or(&[])) {
                        Ok(seq) => format!("ok:{seq}"),
                        Err(e) => format!("err:{}", e.code()),
                    }
                };
                let _ = send.write_all(reply.as_bytes()).await;
            })
            .await;
        });
    }
}

/// The LB's answer to a push.
#[derive(Debug, PartialEq, Eq)]
pub enum PushReply {
    /// Applied; the sequence number now in force.
    Accepted(u64),
    /// Refused, with the error code.
    Refused(String),
}

/// Why a push could not be completed.
#[derive(Debug)]
pub enum PushError {
    /// Could not connect or handshake.
    Connect(String),
    /// The peer is not the LB identity the caller pinned.
    WrongPeer,
    /// I/O after connecting.
    Io(String),
    /// The reply was not understood.
    BadReply,
}

impl core::fmt::Display for PushError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PushError::Connect(e) => write!(f, "push: connect failed: {e}"),
            PushError::WrongPeer => f.write_str("push: peer is not the pinned LB identity"),
            PushError::Io(e) => write!(f, "push: i/o: {e}"),
            PushError::BadReply => f.write_str("push: unintelligible reply"),
        }
    }
}

impl std::error::Error for PushError {}

/// The control plane's side: push `envelope` to the LB at `lb_addr` over `endpoint` (whose
/// identity must be the configured signer key), verifying the LB is the pinned `expected_lb`.
///
/// # Errors
/// [`PushError`] on connection, identity or I/O failure.
pub async fn push(
    endpoint: &NativeEndpoint,
    lb_addr: &str,
    expected_lb: &[u8; 32],
    envelope: &[u8],
) -> Result<PushReply, PushError> {
    let conn = endpoint
        .connect(lb_addr, ALPN)
        .await
        .map_err(|e| PushError::Connect(e.to_string()))?;
    if !ct_eq(&conn.peer_id(), expected_lb) {
        return Err(PushError::WrongPeer);
    }
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| PushError::Io(e.to_string()))?;
    send.write_all(envelope)
        .await
        .map_err(|e| PushError::Io(e.to_string()))?;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(PUSH_DEADLINE, recv.read(&mut buf))
        .await
        .map_err(|_| PushError::Io("timed out waiting for a reply".into()))?
        .map_err(|e| PushError::Io(e.to_string()))?;
    let text = std::str::from_utf8(buf.get(..n).unwrap_or(&[])).map_err(|_| PushError::BadReply)?;
    if let Some(seq) = text.strip_prefix("ok:") {
        return seq
            .parse()
            .map(PushReply::Accepted)
            .map_err(|_| PushError::BadReply);
    }
    text.strip_prefix("err:")
        .map(|c| PushReply::Refused(c.to_string()))
        .ok_or(PushError::BadReply)
}
