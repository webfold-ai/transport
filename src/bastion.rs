//! P2P port forwarding + bastion session recording — a transport primitive.
//!
//! Two capabilities sharing one mechanism: **default-deny, per-peer grants + one-time enrollment
//! tokens**. A port is exposed by a grant — `(port) -> peer key` — served only to a peer the
//! transport has cryptographically authenticated. An unknown peer is refused unless it presents
//! a one-time enrollment token.
//!
//! This was formerly `bindings::bastion` (iroh-backed). Now it's `transport::bastion` (native),
//! using `transport::PeerId` ([u8; 32] Ed25519 pubkey) and `transport::Transport`/`Connection`.
//!
//! ## The HashTrinity face
//! - **NB/Set** = the grant set (which peers may access which ports — presence, idempotent)
//! - **B/Map** = the pin map (PeerId → label — the enrolled identity, replace)
//! - **B/U** = the session counter (monotone session IDs — the accumulator)
//! - **self** = the session recording (the medium turned on itself — bytes observed)

use super::PeerId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A session's direction — `Inbound` from the peer, `Outbound` to the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Every byte a forwarded session carries, plus its lifecycle. Implement to write to an audit
/// chain, a file, or memory (for tests).
pub trait SessionRecorder: Send + Sync {
    fn session_started(&self, session_id: u64, peer: PeerId, port: u16);
    fn record(&self, session_id: u64, direction: Direction, data: &[u8]);
    fn session_ended(&self, session_id: u64);
}

/// Discards everything — the default when recording isn't needed.
pub struct NullRecorder;
impl SessionRecorder for NullRecorder {
    fn session_started(&self, _: u64, _: PeerId, _: u16) {}
    fn record(&self, _: u64, _: Direction, _: &[u8]) {}
    fn session_ended(&self, _: u64) {}
}

#[derive(Clone)]
struct Grant {
    peer: PeerId,
    label: String,
    expires_at: Option<Instant>,
}

struct PendingToken {
    label: String,
    expires_at: Instant,
}

/// The default-deny access table: grants, pins, and enrollment tokens.
/// All operations are quick synchronous map lookups guarded by a plain Mutex.
pub struct BastionAccess {
    grants: Mutex<HashMap<u16, Vec<Grant>>>,
    pins: Mutex<HashMap<PeerId, String>>,
    pending_tokens: Mutex<HashMap<[u8; 32], PendingToken>>,
}

impl Default for BastionAccess {
    fn default() -> Self { Self::new() }
}

impl BastionAccess {
    #[must_use]
    pub fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
            pins: Mutex::new(HashMap::new()),
            pending_tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a one-time enrollment token under `label`, valid for `ttl`.
    #[must_use]
    pub fn mint_enrollment_token(&self, label: impl Into<String>, ttl: Duration) -> [u8; 32] {
        let token = random_bytes_32();
        self.pending_tokens.lock().unwrap_or_else(|e| e.into_inner()).insert(
            token,
            PendingToken { label: label.into(), expires_at: Instant::now() + ttl },
        );
        token
    }

    /// Present `token` as `peer`. On success, peer is pinned and token is spent.
    pub fn enroll(&self, token: &[u8; 32], peer: PeerId) -> Result<String, String> {
        let mut tokens = self.pending_tokens.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pending) = tokens.remove(token) else {
            return Err("enrollment token unknown or already spent".to_string());
        };
        if Instant::now() > pending.expires_at {
            return Err("enrollment token expired".to_string());
        }
        drop(tokens);
        self.pins.lock().unwrap_or_else(|e| e.into_inner()).insert(peer, pending.label.clone());
        Ok(pending.label)
    }

    /// Pin `peer` under `label` directly (no token — operator already knows this key).
    pub fn pin(&self, peer: PeerId, label: impl Into<String>) {
        self.pins.lock().unwrap_or_else(|e| e.into_inner()).insert(peer, label.into());
    }

    /// Grant `peer` access to `port`, optionally expiring after `ttl`.
    pub fn grant(&self, port: u16, peer: PeerId, label: impl Into<String>, ttl: Option<Duration>) {
        let expires_at = ttl.map(|d| Instant::now() + d);
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
            .entry(port).or_default()
            .push(Grant { peer, label: label.into(), expires_at });
    }

    /// Revoke `port`'s grants — for `peer` specifically if given.
    pub fn revoke(&self, port: u16, peer: Option<PeerId>) {
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        match peer {
            Some(peer) => { if let Some(list) = grants.get_mut(&port) { list.retain(|g| g.peer != peer); } }
            None => { grants.remove(&port); }
        }
    }

    /// Default deny: `true` only if `peer` holds a non-expired grant for `port`.
    #[must_use]
    pub fn is_allowed(&self, port: u16, peer: PeerId) -> bool {
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = grants.get(&port) else { return false };
        let now = Instant::now();
        list.iter().any(|g| g.peer == peer && g.expires_at.is_none_or(|exp| now <= exp))
    }

    /// Snapshot of every grant.
    #[must_use]
    pub fn list_grants(&self) -> Vec<GrantInfo> {
        let now = Instant::now();
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
            .iter()
            .flat_map(|(&port, grants)| grants.iter().map(move |g| GrantInfo {
                port, peer: g.peer, label: g.label.clone(),
                expired: g.expires_at.is_some_and(|exp| now > exp),
            }))
            .collect()
    }
}

/// One row of `BastionAccess::list_grants`.
#[derive(Clone, Debug)]
pub struct GrantInfo {
    pub port: u16,
    pub peer: PeerId,
    pub label: String,
    pub expired: bool,
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One shared session-id space for every bastion data-plane implementation (native transport
/// here, `bindings::bastion`'s iroh-specific forwarding loop) — a single counter, not one per
/// implementation, so two implementations active in the same process can't collide on the same
/// session id (a real integrity property for a `SessionRecorder` audit sink keyed by it).
#[must_use]
pub fn next_session_id() -> u64 {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn random_bytes_32() -> [u8; 32] {
    let v = crate::prim::random_bytes(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deny() {
        let access = BastionAccess::new();
        let peer = [42u8; 32];
        assert!(!access.is_allowed(22, peer));
    }

    #[test]
    fn grant_allows() {
        let access = BastionAccess::new();
        let peer = [42u8; 32];
        access.grant(22, peer, "alice", None);
        assert!(access.is_allowed(22, peer));
    }

    #[test]
    fn revoke_removes() {
        let access = BastionAccess::new();
        let peer = [42u8; 32];
        access.grant(22, peer, "alice", None);
        access.revoke(22, Some(peer));
        assert!(!access.is_allowed(22, peer));
    }

    #[test]
    fn enrollment_token_is_one_time() {
        let access = BastionAccess::new();
        let peer = [7u8; 32];
        let token = access.mint_enrollment_token("bob", Duration::from_secs(300));
        assert!(access.enroll(&token, peer).is_ok());
        assert!(access.enroll(&token, peer).is_err(), "token spent");
    }

    #[test]
    fn expired_grant_denies() {
        let access = BastionAccess::new();
        let peer = [42u8; 32];
        access.grant(22, peer, "alice", Some(Duration::from_millis(0)));
        std::thread::sleep(Duration::from_millis(10));
        assert!(!access.is_allowed(22, peer));
    }

    #[test]
    fn list_grants_reports_expired() {
        let access = BastionAccess::new();
        let peer = [42u8; 32];
        access.grant(8080, peer, "web", None);
        access.grant(22, peer, "ssh", Some(Duration::from_millis(0)));
        std::thread::sleep(Duration::from_millis(10));
        let grants = access.list_grants();
        assert_eq!(grants.len(), 2);
        let ssh = grants.iter().find(|g| g.port == 22).unwrap();
        assert!(ssh.expired);
        let web = grants.iter().find(|g| g.port == 8080).unwrap();
        assert!(!web.expired);
    }
}
