#![cfg(feature = "runtime-tokio")]
//! Owner-signed object replication over the native transport — the zone half of the mesh.
//!
//! [`super::signed_dns`] / [`super::pkarr`] publish ONE signed DNS message of at most 1000 bytes
//! (BEP44) per key, through a relay that is a cache. That is the right shape for a service
//! announcement and the wrong one for a DNS zone: a zone is kilobytes, changes by whole-snapshot
//! replacement, and must be fetched from peers that are authenticated, not from a public
//! cache. This module keeps the part of the signed-DNS design that matters — **the author's key
//! signs a monotone sequence number, and the receiver believes the signature, not the channel** —
//! and moves it onto [`super::native`]'s authenticated, sealed connections, with a bounded
//! anti-entropy protocol on top.
//!
//! ## What is replicated
//!
//! A [`SignedObject`]: `(kind, id, signer, epoch, version, body, signature)`. The sync layer does
//! not know what `body` means. It guarantees only:
//!
//! * **Authenticity** — the signature verifies under `signer` over a domain-separated,
//!   length-prefixed preimage ([`SignedObject::verify`]). There is no unverified constructor on
//!   the receive path: [`SignedObject::decode`] verifies.
//! * **Order** — objects are ordered by `(epoch, version)`; a replica keeps the highest and
//!   refuses lower ones ([`ApplyOutcome::Stale`]). Two *different* objects with the same
//!   `(epoch, version)` are a fork ([`ApplyOutcome::Fork`]): the signer signed two histories.
//!   Which `signer` is *authorised* for an `id` is the store's decision — the sync layer
//!   carries the claim, [`SyncStore::apply`] decides.
//! * **Bounded work** — every length is checked before allocation; every wait has a timeout.
//!
//! ## The protocol (one request/response at a time on the connection's single sealed stream)
//!
//! ```text
//! ROOT                      -> ROOT_REPLY  blake3 over every summary row, in order
//! LIST  after, limit        -> SUMMARIES   (kind, blake3(id), epoch, version, digest) rows, sorted
//! GET   [(kind, id-hash)]   -> OBJECTS     the full signed objects
//! PUSH  [object]            -> ACK         one [`ApplyOutcome`] per object
//! ```
//!
//! Every message is a fixed 8-byte header frame (`ver, type, 0, 0, len:u32`) then, if `len > 0`, a
//! body frame of exactly `len` bytes: [`super::native`]'s `read_exact` demands frame == buffer, so
//! the reader never allocates on an unauthenticated length (the `len` is checked against
//! [`MAX_MESSAGE`] first).
//!
//! **Who may connect.** The handshake proves the peer's Ed25519 identity ([`PeerId`]).
//! [`PeerPolicy`] then maps that identity to a role: a `peer` (another mesh node) may
//! LIST/GET/PUSH; a `publisher` (the control plane, the ACME worker) may only PUSH; anyone else
//! is dropped before a byte is read. Membership is an explicit pinned set, not discovery.
//!
//! ## Why not `gossip`, `pkarr` or `bastion`
//!
//! * `gossip` carries no sender authentication on a message (`origin` is a claim) and its
//!   seen-set grows without bound; it also has no way to *fetch* state, only to push it.
//! * `signed_dns`/`pkarr`: 1000-byte values and a public relay. Kept as the model for the
//!   signature/sequence semantics, not used as the carrier.
//! * `bastion` is a port-forwarding grant table; the pinned-peer idea is reused in
//!   [`PeerPolicy`], the port semantics are not.

use crate::native::NativeEndpoint;
use crate::signed_dns::{Keypair, PublicKey};
use crate::{BiStream, Connection, PeerAddr, PeerId, Transport};
use hashtrinity::crypto::blake3;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Protocol identifier, passed to `connect` as the ALPN.
pub const SYNC_ALPN: &[u8] = b"tascloud/zone-sync/0";
/// Longest object id (a DNS name in wire form fits).
pub const MAX_ID_LEN: usize = 255;
/// Largest object body accepted anywhere on the wire. A store may enforce a smaller cap.
pub const MAX_BODY_LEN: usize = 256 * 1024;
/// Most summary rows in one LIST reply.
pub const MAX_SUMMARY_PAGE: usize = 1024;
/// Most objects named in one GET.
pub const MAX_GET_IDS: usize = 16;
/// Most objects in one PUSH / OBJECTS message.
pub const MAX_PUSH_OBJECTS: usize = 8;
/// Largest message body, below the sealed frame ceiling (1 MiB) of [`super::native`].
pub const MAX_MESSAGE: usize = 1_000_000;

const DOMAIN: &[u8] = b"tascloud/zone-sync/v1\0";
const WIRE_VERSION: u8 = 0;
/// Fixed size of an encoded [`Summary`] row.
const SUMMARY_LEN: usize = 1 + 32 + 8 + 8 + 32;

/// What kind of fact an object is. The sync layer treats all kinds alike; the store gives them
/// meaning (who may sign which).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// A control-plane-signed statement of who owns an id and under what policy.
    Registration,
    /// An owner-signed whole-snapshot replacement of an id's contents.
    Update,
    /// A per-label ACME challenge state, signed by the challenge authority.
    Challenge,
}

impl ObjectKind {
    /// The stable one-byte wire / sort code of this kind.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            ObjectKind::Registration => 1,
            ObjectKind::Update => 2,
            ObjectKind::Challenge => 3,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(ObjectKind::Registration),
            2 => Some(ObjectKind::Update),
            3 => Some(ObjectKind::Challenge),
            _ => None,
        }
    }
}

/// Why an object or message could not be built, parsed, trusted or exchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// A length, count or field was outside its bound, or the bytes ended early.
    Malformed(&'static str),
    /// The signature does not verify under the declared signer.
    BadSignature,
    /// The peer on the other end of the connection is not the one we dialled.
    PeerMismatch,
    /// The peer sent a message of the wrong type or an error.
    Protocol(&'static str),
    /// A timeout elapsed.
    Timeout,
    /// The connection failed.
    Io(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Malformed(w) => write!(f, "zone-sync: malformed ({w})"),
            SyncError::BadSignature => f.write_str("zone-sync: signature does not verify"),
            SyncError::PeerMismatch => f.write_str("zone-sync: connected peer is not the pinned identity"),
            SyncError::Protocol(w) => write!(f, "zone-sync: protocol violation ({w})"),
            SyncError::Timeout => f.write_str("zone-sync: timed out"),
            SyncError::Io(e) => write!(f, "zone-sync: io: {e}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        SyncError::Io(e.kind().to_string())
    }
}

// ── the signed object ────────────────────────────────────────────────────────────────────────

/// One replicated, signed fact. Constructed only by [`SignedObject::sign`] (the author) or
/// [`SignedObject::decode`] (which verifies), so a value that exists has been checked.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedObject {
    kind: ObjectKind,
    id: Vec<u8>,
    signer: [u8; 32],
    epoch: u64,
    version: u64,
    body: Vec<u8>,
    signature: [u8; 64],
}

impl fmt::Debug for SignedObject {
    /// Never prints `body`: it is tenant-controlled and may be large.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedObject")
            .field("kind", &self.kind)
            .field("id_len", &self.id.len())
            .field("epoch", &self.epoch)
            .field("version", &self.version)
            .field("body_len", &self.body.len())
            .finish()
    }
}

fn check_bounds(id: &[u8], body: &[u8]) -> Result<(), SyncError> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(SyncError::Malformed("id length"));
    }
    if body.len() > MAX_BODY_LEN {
        return Err(SyncError::Malformed("body length"));
    }
    Ok(())
}

/// The bytes a signature covers: domain tag, kind, then every field length-prefixed or fixed
/// width, so no choice of one field can shift bytes into another.
fn preimage(kind: ObjectKind, id: &[u8], signer: &[u8; 32], epoch: u64, version: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 1 + 2 + id.len() + 32 + 16 + 4 + body.len());
    out.extend_from_slice(DOMAIN);
    out.push(kind.code());
    out.extend_from_slice(&u16::try_from(id.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(signer);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(body);
    out
}

impl SignedObject {
    /// Sign a new object as `keypair`.
    ///
    /// # Errors
    /// [`SyncError::Malformed`] if `id` or `body` is outside its bound.
    pub fn sign(
        keypair: &Keypair,
        kind: ObjectKind,
        id: Vec<u8>,
        epoch: u64,
        version: u64,
        body: Vec<u8>,
    ) -> Result<Self, SyncError> {
        check_bounds(&id, &body)?;
        let signer = *keypair.public_key().as_bytes();
        let signature = keypair.sign(&preimage(kind, &id, &signer, epoch, version, &body));
        Ok(SignedObject { kind, id, signer, epoch, version, body, signature })
    }

    /// Check the bounds and the signature. `decode` has already done this; it is public so a
    /// caller holding an object from elsewhere can re-check.
    ///
    /// # Errors
    /// [`SyncError::Malformed`] or [`SyncError::BadSignature`].
    pub fn verify(&self) -> Result<(), SyncError> {
        check_bounds(&self.id, &self.body)?;
        let key = PublicKey::from_bytes(&self.signer).map_err(|_| SyncError::Malformed("signer key"))?;
        let msg = preimage(self.kind, &self.id, &self.signer, self.epoch, self.version, &self.body);
        if key.verify(&msg, &self.signature) {
            Ok(())
        } else {
            Err(SyncError::BadSignature)
        }
    }

    /// The object's kind.
    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// The object's id (for zones: the apex in uncompressed wire form).
    #[must_use]
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// The public key that signed this object. Authorisation is the store's decision.
    #[must_use]
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }

    /// The object's epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The object's version within its epoch.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The opaque, signed payload.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// `(epoch, version)`: the order replicas keep.
    #[must_use]
    pub fn order(&self) -> (u64, u64) {
        (self.epoch, self.version)
    }

    /// BLAKE3 of the full encoding: equal digests mean byte-identical objects.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        blake3(&self.encode())
    }

    /// The fixed-size key this object is listed under.
    #[must_use]
    pub fn id_hash(&self) -> [u8; 32] {
        id_hash(self.kind, &self.id)
    }

    /// Its summary row.
    #[must_use]
    pub fn summary(&self) -> Summary {
        Summary { kind: self.kind, id_hash: self.id_hash(), epoch: self.epoch, version: self.version, digest: self.digest() }
    }

    /// Wire / disk form: `kind ‖ id_len:u16 ‖ id ‖ signer ‖ epoch ‖ version ‖ body_len:u32 ‖ body ‖ sig`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + self.id.len() + 32 + 16 + 4 + self.body.len() + 64);
        out.push(self.kind.code());
        out.extend_from_slice(&u16::try_from(self.id.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&u32::try_from(self.body.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&self.body);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse AND verify. Lengths are checked before anything is copied.
    ///
    /// # Errors
    /// [`SyncError::Malformed`] on any bound or truncation, [`SyncError::BadSignature`] if the
    /// signature does not verify.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        let mut r = Reader::new(bytes);
        let kind = ObjectKind::from_code(r.u8()?).ok_or(SyncError::Malformed("kind"))?;
        let id_len = usize::from(r.u16()?);
        if id_len == 0 || id_len > MAX_ID_LEN {
            return Err(SyncError::Malformed("id length"));
        }
        let id = r.take(id_len)?.to_vec();
        let signer: [u8; 32] = r.take(32)?.try_into().map_err(|_| SyncError::Malformed("signer"))?;
        let epoch = r.u64()?;
        let version = r.u64()?;
        let body_len = usize::try_from(r.u32()?).map_err(|_| SyncError::Malformed("body length"))?;
        if body_len > MAX_BODY_LEN {
            return Err(SyncError::Malformed("body length"));
        }
        let body = r.take(body_len)?.to_vec();
        let signature: [u8; 64] = r.take(64)?.try_into().map_err(|_| SyncError::Malformed("signature"))?;
        if !r.is_empty() {
            return Err(SyncError::Malformed("trailing bytes"));
        }
        let obj = SignedObject { kind, id, signer, epoch, version, body, signature };
        obj.verify()?;
        Ok(obj)
    }
}

/// The fixed-size listing key for an object id.
#[must_use]
pub fn id_hash(kind: ObjectKind, id: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + id.len());
    input.push(kind.code());
    input.extend_from_slice(id);
    blake3(&input)
}

/// One row of a LIST: enough to decide whether a peer's copy is newer, equal or forked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Kind of the object.
    pub kind: ObjectKind,
    /// [`id_hash`] of its id.
    pub id_hash: [u8; 32],
    /// Epoch of the held object.
    pub epoch: u64,
    /// Version of the held object.
    pub version: u64,
    /// [`SignedObject::digest`] of the held object.
    pub digest: [u8; 32],
}

impl Summary {
    /// The sort / pagination key.
    #[must_use]
    pub fn key(&self) -> SummaryKey {
        (self.kind.code(), self.id_hash)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind.code());
        out.extend_from_slice(&self.id_hash);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.digest);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, SyncError> {
        let kind = ObjectKind::from_code(r.u8()?).ok_or(SyncError::Malformed("kind"))?;
        let id_hash: [u8; 32] = r.take(32)?.try_into().map_err(|_| SyncError::Malformed("id hash"))?;
        let epoch = r.u64()?;
        let version = r.u64()?;
        let digest: [u8; 32] = r.take(32)?.try_into().map_err(|_| SyncError::Malformed("digest"))?;
        Ok(Summary { kind, id_hash, epoch, version, digest })
    }
}

/// `(kind code, id hash)`: summaries are sorted and paged by this.
pub type SummaryKey = (u8, [u8; 32]);

/// Bounds-checked cursor; every accessor fails instead of panicking.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SyncError> {
        let end = self.pos.checked_add(n).ok_or(SyncError::Malformed("length overflow"))?;
        let out = self.buf.get(self.pos..end).ok_or(SyncError::Malformed("truncated"))?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, SyncError> {
        Ok(*self.take(1)?.first().ok_or(SyncError::Malformed("truncated"))?)
    }

    fn u16(&mut self) -> Result<u16, SyncError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| SyncError::Malformed("truncated"))?))
    }

    fn u32(&mut self) -> Result<u32, SyncError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| SyncError::Malformed("truncated"))?))
    }

    fn u64(&mut self) -> Result<u64, SyncError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| SyncError::Malformed("truncated"))?))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

// ── the store contract ───────────────────────────────────────────────────────────────────────

/// What applying a verified object did. The sync layer only relays it; the store decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The object was newer and is now held.
    Applied,
    /// The same object (same digest) was already held.
    Duplicate,
    /// A newer `(epoch, version)` is already held; this one was refused (rollback / replay).
    Stale,
    /// A different object with the same `(epoch, version)` is held: the signer forked history.
    /// Refused, and the store is expected to alert.
    Fork,
    /// Failed the store's validation (bad content, over a limit).
    Invalid,
    /// The signer is not authorised for this id, or the id is not registered.
    Unauthorized,
    /// A quota (zones per tenant, store size) would be exceeded.
    Quota,
}

impl ApplyOutcome {
    fn code(self) -> u8 {
        match self {
            ApplyOutcome::Applied => 0,
            ApplyOutcome::Duplicate => 1,
            ApplyOutcome::Stale => 2,
            ApplyOutcome::Fork => 3,
            ApplyOutcome::Invalid => 4,
            ApplyOutcome::Unauthorized => 5,
            ApplyOutcome::Quota => 6,
        }
    }

    fn from_code(c: u8) -> Self {
        match c {
            0 => ApplyOutcome::Applied,
            1 => ApplyOutcome::Duplicate,
            2 => ApplyOutcome::Stale,
            3 => ApplyOutcome::Fork,
            5 => ApplyOutcome::Unauthorized,
            6 => ApplyOutcome::Quota,
            _ => ApplyOutcome::Invalid,
        }
    }

    /// Whether the object is now (or already was) held, i.e. the peer is not behind on it.
    #[must_use]
    pub fn is_held(self) -> bool {
        matches!(self, ApplyOutcome::Applied | ApplyOutcome::Duplicate)
    }
}

/// The replica a node exposes to the sync protocol. Every method is synchronous and quick; the
/// implementation owns its locking and persistence.
pub trait SyncStore: Send + Sync + 'static {
    /// Up to `limit` summaries whose key is strictly greater than `after`, in key order.
    fn summaries(&self, after: Option<SummaryKey>, limit: usize) -> Vec<Summary>;
    /// The held object for `(kind, id_hash)`.
    fn get(&self, kind: ObjectKind, id_hash: &[u8; 32]) -> Option<SignedObject>;
    /// Offer a signature-verified object. `from` is the authenticated peer that delivered it
    /// (never an authorisation by itself — the signer is what matters).
    fn apply(&self, object: SignedObject, from: PeerId) -> ApplyOutcome;
}

/// BLAKE3 over every summary row of `store` in key order: two replicas with equal roots hold
/// byte-identical state, so an unchanged mesh costs one round trip per peer.
#[must_use]
pub fn root_of(store: &dyn SyncStore) -> [u8; 32] {
    let mut buf = Vec::new();
    let mut after = None;
    loop {
        let page = store.summaries(after, MAX_SUMMARY_PAGE);
        let Some(last) = page.last() else { break };
        after = Some(last.key());
        let full = page.len() >= MAX_SUMMARY_PAGE;
        for s in &page {
            s.encode_into(&mut buf);
        }
        if !full {
            break;
        }
    }
    blake3(&buf)
}

// ── peer policy ──────────────────────────────────────────────────────────────────────────────

/// What an authenticated connection may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Another mesh node: LIST, GET, PUSH, ROOT.
    Peer,
    /// A writer outside the mesh (control plane, ACME worker): PUSH only.
    Publisher,
}

/// The pinned set of identities allowed to talk to this node. Default deny.
#[derive(Clone, Debug, Default)]
pub struct PeerPolicy {
    peers: HashSet<PeerId>,
    publishers: HashSet<PeerId>,
}

impl PeerPolicy {
    /// An empty (deny-all) policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `id` as a mesh peer.
    #[must_use]
    pub fn with_peer(mut self, id: PeerId) -> Self {
        self.peers.insert(id);
        self
    }

    /// Allow `id` as a push-only publisher.
    #[must_use]
    pub fn with_publisher(mut self, id: PeerId) -> Self {
        self.publishers.insert(id);
        self
    }

    /// The role `id` holds, if any. A peer outranks a publisher entry for the same key.
    #[must_use]
    pub fn role(&self, id: &PeerId) -> Option<Role> {
        if self.peers.contains(id) {
            Some(Role::Peer)
        } else if self.publishers.contains(id) {
            Some(Role::Publisher)
        } else {
            None
        }
    }
}

// ── wire messages ────────────────────────────────────────────────────────────────────────────

const T_ROOT: u8 = 1;
const T_ROOT_REPLY: u8 = 2;
const T_LIST: u8 = 3;
const T_SUMMARIES: u8 = 4;
const T_GET: u8 = 5;
const T_OBJECTS: u8 = 6;
const T_PUSH: u8 = 7;
const T_ACK: u8 = 8;
const T_ERROR: u8 = 255;

/// Error codes carried by `T_ERROR`.
const E_FORBIDDEN: u8 = 1;
const E_MALFORMED: u8 = 2;

async fn send_msg(send: &mut dyn BiStream, ty: u8, body: &[u8]) -> Result<(), SyncError> {
    if body.len() > MAX_MESSAGE {
        return Err(SyncError::Malformed("message too large"));
    }
    let len = u32::try_from(body.len()).map_err(|_| SyncError::Malformed("message too large"))?;
    let mut hdr = [0u8; 8];
    hdr[0] = WIRE_VERSION;
    hdr[1] = ty;
    hdr[4..8].copy_from_slice(&len.to_be_bytes());
    send.write_all(&hdr).await?;
    if !body.is_empty() {
        send.write_all(body).await?;
    }
    Ok(())
}

async fn recv_msg(recv: &mut dyn BiStream, idle: Duration) -> Result<(u8, Vec<u8>), SyncError> {
    let mut hdr = [0u8; 8];
    tokio::time::timeout(idle, recv.read_exact(&mut hdr)).await.map_err(|_| SyncError::Timeout)??;
    if hdr[0] != WIRE_VERSION {
        return Err(SyncError::Protocol("version"));
    }
    let len = usize::try_from(u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]))
        .map_err(|_| SyncError::Malformed("length"))?;
    if len > MAX_MESSAGE {
        return Err(SyncError::Malformed("message too large"));
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        tokio::time::timeout(idle, recv.read_exact(&mut body)).await.map_err(|_| SyncError::Timeout)??;
    }
    Ok((hdr[1], body))
}

fn encode_objects(objs: &[SignedObject]) -> Result<Vec<u8>, SyncError> {
    if objs.len() > MAX_PUSH_OBJECTS {
        return Err(SyncError::Malformed("too many objects"));
    }
    let mut out = vec![u8::try_from(objs.len()).unwrap_or(u8::MAX)];
    for o in objs {
        let enc = o.encode();
        out.extend_from_slice(&u32::try_from(enc.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&enc);
    }
    if out.len() > MAX_MESSAGE {
        return Err(SyncError::Malformed("message too large"));
    }
    Ok(out)
}

/// Decode a counted list of objects, verifying each. One bad object fails the message: a peer
/// that sends a forgery is not trusted for the rest of it.
fn decode_objects(body: &[u8]) -> Result<Vec<SignedObject>, SyncError> {
    let mut r = Reader::new(body);
    let n = usize::from(r.u8()?);
    if n > MAX_PUSH_OBJECTS {
        return Err(SyncError::Malformed("too many objects"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = usize::try_from(r.u32()?).map_err(|_| SyncError::Malformed("object length"))?;
        out.push(SignedObject::decode(r.take(len)?)?);
    }
    if !r.is_empty() {
        return Err(SyncError::Malformed("trailing bytes"));
    }
    Ok(out)
}

// ── the server side ──────────────────────────────────────────────────────────────────────────

/// Server limits. Every wait is bounded; every session is bounded in requests.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// Sessions served at once; further connections wait in the accept queue.
    pub max_sessions: usize,
    /// Longest a peer may be silent between requests.
    pub idle_timeout: Duration,
    /// Requests served on one connection before it is closed.
    pub max_requests: u32,
}

impl Default for SessionLimits {
    fn default() -> Self {
        SessionLimits { max_sessions: 32, idle_timeout: Duration::from_secs(20), max_requests: 4096 }
    }
}

/// Serve the sync protocol on `endpoint` until `shutdown` flips to `true`.
///
/// Connections whose authenticated identity has no role in `policy` are dropped without a read.
pub async fn serve(
    endpoint: Arc<NativeEndpoint>,
    store: Arc<dyn SyncStore>,
    policy: Arc<PeerPolicy>,
    limits: SessionLimits,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_sessions.max(1)));
    loop {
        let conn = tokio::select! {
            () = wait_shutdown(&mut shutdown) => return,
            c = Transport::accept(&*endpoint) => match c { Some(c) => c, None => return },
        };
        let Some(role) = policy.role(&Connection::peer_id(&conn)) else {
            continue; // not a member: drop (and with it the connection)
        };
        let Ok(permit) = slots.clone().acquire_owned().await else { return };
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = session(conn, role, store, limits).await;
        });
    }
}

async fn wait_shutdown(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn session(
    conn: crate::native::NativeConnection,
    role: Role,
    store: Arc<dyn SyncStore>,
    limits: SessionLimits,
) -> Result<(), SyncError> {
    let peer = Connection::peer_id(&conn);
    let (mut send, mut recv) = Connection::accept_bi(&conn).await?;
    for _ in 0..limits.max_requests {
        let (ty, body) = match recv_msg(&mut *recv, limits.idle_timeout).await {
            Ok(m) => m,
            Err(SyncError::Io(_)) => return Ok(()), // peer closed
            Err(e) => return Err(e),
        };
        if role == Role::Publisher && ty != T_PUSH {
            send_msg(&mut *send, T_ERROR, &[E_FORBIDDEN]).await?;
            return Ok(());
        }
        let reply = handle(ty, &body, &*store, peer);
        match reply {
            Ok((rty, rbody)) => send_msg(&mut *send, rty, &rbody).await?,
            Err(_) => {
                send_msg(&mut *send, T_ERROR, &[E_MALFORMED]).await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Pure request handler: bytes in, bytes out, no socket.
fn handle(ty: u8, body: &[u8], store: &dyn SyncStore, peer: PeerId) -> Result<(u8, Vec<u8>), SyncError> {
    match ty {
        T_ROOT => {
            if !body.is_empty() {
                return Err(SyncError::Malformed("ROOT body"));
            }
            Ok((T_ROOT_REPLY, root_of(store).to_vec()))
        }
        T_LIST => {
            let mut r = Reader::new(body);
            let has_after = r.u8()?;
            let kind = r.u8()?;
            let hash: [u8; 32] = r.take(32)?.try_into().map_err(|_| SyncError::Malformed("after"))?;
            let limit = usize::from(r.u16()?).clamp(1, MAX_SUMMARY_PAGE);
            if !r.is_empty() || has_after > 1 {
                return Err(SyncError::Malformed("LIST body"));
            }
            let after = (has_after == 1).then_some((kind, hash));
            let rows = store.summaries(after, limit);
            let mut out = Vec::with_capacity(3 + rows.len() * SUMMARY_LEN);
            out.extend_from_slice(&u16::try_from(rows.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.push(u8::from(rows.len() >= limit));
            for s in &rows {
                s.encode_into(&mut out);
            }
            Ok((T_SUMMARIES, out))
        }
        T_GET => {
            let mut r = Reader::new(body);
            let n = usize::from(r.u8()?);
            if n > MAX_GET_IDS {
                return Err(SyncError::Malformed("GET count"));
            }
            let mut found = Vec::new();
            let mut total = 1usize;
            for _ in 0..n {
                let kind = ObjectKind::from_code(r.u8()?).ok_or(SyncError::Malformed("kind"))?;
                let hash: [u8; 32] = r.take(32)?.try_into().map_err(|_| SyncError::Malformed("hash"))?;
                if let Some(o) = store.get(kind, &hash) {
                    let enc_len = o.encode().len() + 4;
                    // keep the reply under the frame ceiling and the per-message object cap;
                    // the requester asks again for what did not fit
                    if total + enc_len > MAX_MESSAGE || found.len() >= MAX_PUSH_OBJECTS {
                        break;
                    }
                    total += enc_len;
                    found.push(o);
                }
            }
            if !r.is_empty() && found.len() < n {
                // fine: we stopped early for size; the unread tail is the requester's to retry
            } else if !r.is_empty() {
                return Err(SyncError::Malformed("GET body"));
            }
            Ok((T_OBJECTS, encode_objects(&found)?))
        }
        T_PUSH => {
            let objs = decode_objects(body)?;
            let mut out = vec![u8::try_from(objs.len()).unwrap_or(u8::MAX)];
            for o in objs {
                out.push(store.apply(o, peer).code());
            }
            Ok((T_ACK, out))
        }
        _ => Err(SyncError::Protocol("unknown message type")),
    }
}

// ── the client side ──────────────────────────────────────────────────────────────────────────

/// What one pull from one peer achieved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullReport {
    /// True if the peer's root matched ours and nothing was fetched.
    pub in_sync: bool,
    /// Objects fetched and newly held.
    pub applied: usize,
    /// Objects fetched that were already held or older.
    pub redundant: usize,
    /// Objects fetched that the store refused as forks.
    pub forks: usize,
    /// Objects fetched that the store refused for any other reason.
    pub rejected: usize,
}

/// A dialer for the sync protocol.
#[derive(Clone)]
pub struct SyncClient {
    endpoint: Arc<NativeEndpoint>,
    io_timeout: Duration,
}

impl SyncClient {
    /// A client dialling from `endpoint`, with a per-message timeout.
    #[must_use]
    pub fn new(endpoint: Arc<NativeEndpoint>, io_timeout: Duration) -> Self {
        SyncClient { endpoint, io_timeout }
    }

    async fn dial(
        &self,
        peer: &PeerAddr,
    ) -> Result<(Box<dyn BiStream>, Box<dyn BiStream>, crate::native::NativeConnection), SyncError> {
        let addr = format!("{}:{}", peer.host, peer.port);
        let conn = tokio::time::timeout(self.io_timeout, Transport::connect(&*self.endpoint, &addr, SYNC_ALPN))
            .await
            .map_err(|_| SyncError::Timeout)??;
        if Connection::peer_id(&conn) != peer.peer_id {
            return Err(SyncError::PeerMismatch);
        }
        let (send, recv) = Connection::open_bi(&conn).await?;
        Ok((send, recv, conn))
    }

    /// Anti-entropy pull: compare roots; if they differ, walk the peer's summaries and fetch
    /// every object it holds newer than (or different from) ours, applying each via `store`.
    ///
    /// # Errors
    /// Any transport, framing or pinning failure. A rejected *object* is not an error: it is
    /// counted in the report.
    pub async fn pull(&self, peer: &PeerAddr, store: &dyn SyncStore) -> Result<PullReport, SyncError> {
        let (mut send, mut recv, _conn) = self.dial(peer).await?;
        let t = self.io_timeout;
        let mut report = PullReport::default();

        send_msg(&mut *send, T_ROOT, &[]).await?;
        let (ty, body) = recv_msg(&mut *recv, t).await?;
        if ty != T_ROOT_REPLY || body.len() != 32 {
            return Err(SyncError::Protocol("ROOT reply"));
        }
        if body == root_of(store) {
            report.in_sync = true;
            return Ok(report);
        }

        let mut want: Vec<(ObjectKind, [u8; 32])> = Vec::new();
        let mut after: Option<SummaryKey> = None;
        loop {
            let mut req = Vec::with_capacity(36);
            match after {
                Some((k, h)) => {
                    req.push(1);
                    req.push(k);
                    req.extend_from_slice(&h);
                }
                None => {
                    req.push(0);
                    req.push(0);
                    req.extend_from_slice(&[0u8; 32]);
                }
            }
            req.extend_from_slice(&u16::try_from(MAX_SUMMARY_PAGE).unwrap_or(u16::MAX).to_be_bytes());
            send_msg(&mut *send, T_LIST, &req).await?;
            let (ty, body) = recv_msg(&mut *recv, t).await?;
            if ty != T_SUMMARIES {
                return Err(SyncError::Protocol("SUMMARIES reply"));
            }
            let mut r = Reader::new(&body);
            let n = usize::from(r.u16()?);
            let more = r.u8()? == 1;
            if n > MAX_SUMMARY_PAGE {
                return Err(SyncError::Malformed("summary count"));
            }
            let mut last = None;
            for _ in 0..n {
                let s = Summary::decode(&mut r)?;
                // the peer must keep its promise of strictly increasing keys, or paging never ends
                if let Some(prev) = last {
                    if s.key() <= prev {
                        return Err(SyncError::Protocol("summaries out of order"));
                    }
                }
                if let Some(a) = after {
                    if s.key() <= a {
                        return Err(SyncError::Protocol("summaries did not advance"));
                    }
                }
                last = Some(s.key());
                if peer_is_ahead(store, &s) {
                    want.push((s.kind, s.id_hash));
                }
            }
            if !r.is_empty() {
                return Err(SyncError::Malformed("trailing bytes"));
            }
            match (more, last) {
                (true, Some(k)) => after = Some(k),
                _ => break,
            }
        }

        for chunk in want.chunks(MAX_GET_IDS) {
            let mut pending: Vec<(ObjectKind, [u8; 32])> = chunk.to_vec();
            // The peer may return fewer than asked (size cap): ask again for the remainder.
            for _ in 0..MAX_GET_IDS {
                if pending.is_empty() {
                    break;
                }
                let mut req = vec![u8::try_from(pending.len()).unwrap_or(u8::MAX)];
                for (k, h) in &pending {
                    req.push(k.code());
                    req.extend_from_slice(h);
                }
                send_msg(&mut *send, T_GET, &req).await?;
                let (ty, body) = recv_msg(&mut *recv, t).await?;
                if ty != T_OBJECTS {
                    return Err(SyncError::Protocol("OBJECTS reply"));
                }
                let objs = decode_objects(&body)?;
                if objs.is_empty() {
                    break; // the peer no longer holds what it listed
                }
                for o in objs {
                    pending.retain(|(k, h)| !(*k == o.kind() && *h == o.id_hash()));
                    match store.apply(o, peer.peer_id) {
                        ApplyOutcome::Applied => report.applied += 1,
                        ApplyOutcome::Duplicate | ApplyOutcome::Stale => report.redundant += 1,
                        ApplyOutcome::Fork => report.forks += 1,
                        _ => report.rejected += 1,
                    }
                }
            }
        }
        Ok(report)
    }

    /// Push objects to `peer`, returning the store's verdict on each, in order.
    ///
    /// # Errors
    /// Any transport, framing or pinning failure.
    pub async fn push(&self, peer: &PeerAddr, objects: &[SignedObject]) -> Result<Vec<ApplyOutcome>, SyncError> {
        let (mut send, mut recv, _conn) = self.dial(peer).await?;
        let mut out = Vec::with_capacity(objects.len());
        for chunk in objects.chunks(MAX_PUSH_OBJECTS) {
            send_msg(&mut *send, T_PUSH, &encode_objects(chunk)?).await?;
            let (ty, body) = recv_msg(&mut *recv, self.io_timeout).await?;
            match ty {
                T_ACK => {}
                T_ERROR => return Err(SyncError::Protocol("peer refused the push")),
                _ => return Err(SyncError::Protocol("ACK reply")),
            }
            let mut r = Reader::new(&body);
            let n = usize::from(r.u8()?);
            if n != chunk.len() {
                return Err(SyncError::Protocol("ACK count"));
            }
            for _ in 0..n {
                out.push(ApplyOutcome::from_code(r.u8()?));
            }
        }
        Ok(out)
    }
}

/// Whether the peer's summary describes something we should fetch: we hold nothing for the id,
/// the peer's `(epoch, version)` is higher, or it is equal but a different object (a fork we
/// want the evidence of).
fn peer_is_ahead(store: &dyn SyncStore, theirs: &Summary) -> bool {
    match store.get(theirs.kind, &theirs.id_hash) {
        None => true,
        Some(ours) => {
            let o = ours.order();
            let t = (theirs.epoch, theirs.version);
            t > o || (t == o && ours.digest() != theirs.digest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn kp(tag: u8) -> Keypair {
        Keypair::from_secret_key(&[tag; 32])
    }

    fn obj(signer: u8, kind: ObjectKind, id: &str, epoch: u64, version: u64, body: &[u8]) -> SignedObject {
        SignedObject::sign(&kp(signer), kind, id.as_bytes().to_vec(), epoch, version, body.to_vec()).unwrap()
    }

    /// A toy replica: keeps the highest `(epoch, version)` per `(kind, id)`.
    #[derive(Default)]
    struct MemStore {
        held: Mutex<BTreeMap<SummaryKey, SignedObject>>,
        /// Ids a pretend authorisation rule refuses.
        deny_signer: Mutex<Option<[u8; 32]>>,
    }

    impl SyncStore for MemStore {
        fn summaries(&self, after: Option<SummaryKey>, limit: usize) -> Vec<Summary> {
            let held = self.held.lock().unwrap();
            held.iter()
                .filter(|(k, _)| after.is_none_or(|a| **k > a))
                .take(limit)
                .map(|(_, o)| o.summary())
                .collect()
        }

        fn get(&self, kind: ObjectKind, id_hash: &[u8; 32]) -> Option<SignedObject> {
            self.held.lock().unwrap().get(&(kind.code(), *id_hash)).cloned()
        }

        fn apply(&self, object: SignedObject, _from: PeerId) -> ApplyOutcome {
            if *self.deny_signer.lock().unwrap() == Some(*object.signer()) {
                return ApplyOutcome::Unauthorized;
            }
            let mut held = self.held.lock().unwrap();
            let key = (object.kind().code(), object.id_hash());
            match held.get(&key) {
                None => {
                    held.insert(key, object);
                    ApplyOutcome::Applied
                }
                Some(cur) if object.order() > cur.order() => {
                    held.insert(key, object);
                    ApplyOutcome::Applied
                }
                Some(cur) if object.order() == cur.order() => {
                    if cur.digest() == object.digest() {
                        ApplyOutcome::Duplicate
                    } else {
                        ApplyOutcome::Fork
                    }
                }
                Some(_) => ApplyOutcome::Stale,
            }
        }
    }

    #[test]
    fn an_object_round_trips_and_any_altered_byte_fails() {
        let o = obj(1, ObjectKind::Update, "example.", 1, 7, b"zone body");
        let enc = o.encode();
        assert_eq!(SignedObject::decode(&enc).unwrap(), o);
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x01;
            assert!(SignedObject::decode(&bad).is_err(), "flipping byte {i} must not decode");
        }
    }

    #[test]
    fn version_epoch_kind_and_id_are_inside_the_signature() {
        let o = obj(2, ObjectKind::Update, "example.", 1, 7, b"b");
        let enc = o.encode();
        // epoch and version live at fixed offsets after the id
        let id_len = o.id().len();
        let epoch_at = 1 + 2 + id_len + 32;
        let mut forged = enc.clone();
        forged[epoch_at + 7] ^= 1;
        assert_eq!(SignedObject::decode(&forged), Err(SyncError::BadSignature));
        let mut forged = enc.clone();
        forged[epoch_at + 15] = 99;
        assert_eq!(SignedObject::decode(&forged), Err(SyncError::BadSignature));
        let mut forged = enc;
        forged[0] = ObjectKind::Registration.code();
        assert_eq!(SignedObject::decode(&forged), Err(SyncError::BadSignature), "kind is domain-separated");
    }

    #[test]
    fn truncated_and_oversized_inputs_are_errors_not_panics() {
        let o = obj(3, ObjectKind::Registration, "z.example.", 1, 1, &[7u8; 300]);
        let enc = o.encode();
        for cut in 0..enc.len() {
            assert!(SignedObject::decode(&enc[..cut]).is_err());
        }
        let mut trailing = enc.clone();
        trailing.push(0);
        assert!(SignedObject::decode(&trailing).is_err());
        assert!(SignedObject::sign(&kp(1), ObjectKind::Update, vec![b'a'; 256], 1, 1, vec![]).is_err());
        assert!(SignedObject::sign(&kp(1), ObjectKind::Update, vec![], 1, 1, vec![]).is_err());
        assert!(SignedObject::sign(&kp(1), ObjectKind::Update, vec![1], 1, 1, vec![0; MAX_BODY_LEN + 1]).is_err());
        // a declared body length over the cap is refused before any copy
        let mut huge = enc.clone();
        let at = 1 + 2 + o.id().len() + 32 + 16;
        huge[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(SignedObject::decode(&huge), Err(SyncError::Malformed("body length")));
    }

    #[test]
    fn debug_never_prints_the_body() {
        let o = obj(1, ObjectKind::Update, "example.", 1, 1, b"SECRET-TENANT-DATA");
        assert!(!format!("{o:?}").contains("SECRET"));
    }

    #[test]
    fn the_wire_handlers_reject_garbage_without_panicking() {
        let store = MemStore::default();
        for ty in 0..=255u8 {
            for body in [&[][..], &[0u8][..], &[255u8; 40][..], &[1u8; 7][..]] {
                let _ = handle(ty, body, &store, [0; 32]);
            }
        }
        // a PUSH that claims 8 objects but carries none
        assert!(handle(T_PUSH, &[8], &store, [0; 32]).is_err());
        // a GET naming more than the cap
        assert!(handle(T_GET, &[200], &store, [0; 32]).is_err());
    }

    #[test]
    fn root_changes_when_any_object_does() {
        let a = MemStore::default();
        let b = MemStore::default();
        assert_eq!(root_of(&a), root_of(&b));
        let o1 = obj(1, ObjectKind::Update, "a.example.", 1, 1, b"x");
        a.apply(o1.clone(), [0; 32]);
        assert_ne!(root_of(&a), root_of(&b));
        b.apply(o1, [0; 32]);
        assert_eq!(root_of(&a), root_of(&b));
        a.apply(obj(1, ObjectKind::Update, "a.example.", 1, 2, b"x"), [0; 32]);
        assert_ne!(root_of(&a), root_of(&b));
    }

    async fn node(seed: &str) -> (Arc<NativeEndpoint>, PeerAddr) {
        let ep = Arc::new(NativeEndpoint::bind_with_dialkey("127.0.0.1:0", seed).await.unwrap());
        let addr = Transport::local_addr(&*ep).unwrap();
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
        (ep.clone(), PeerAddr::new(Transport::id(&*ep), "127.0.0.1", port))
    }

    /// Two in-process nodes over real sockets: B pulls what A holds, and a second pull is a
    /// one-round-trip no-op.
    #[tokio::test]
    async fn a_peer_pulls_missing_and_newer_objects_and_then_is_in_sync() {
        let (ep_a, addr_a) = node("zs-a").await;
        let (ep_b, _addr_b) = node("zs-b").await;
        let store_a = Arc::new(MemStore::default());
        let store_b = Arc::new(MemStore::default());
        for i in 0..40u64 {
            store_a.apply(obj(1, ObjectKind::Update, &format!("z{i}.example."), 1, i + 1, b"body"), [0; 32]);
        }
        store_a.apply(obj(1, ObjectKind::Registration, "z1.example.", 1, 1, b"reg"), [0; 32]);
        // B already holds an OLDER z3
        store_b.apply(obj(1, ObjectKind::Update, "z3.example.", 1, 1, b"old"), [0; 32]);

        let policy = Arc::new(PeerPolicy::new().with_peer(Transport::id(&*ep_b)));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let srv = tokio::spawn(serve(ep_a.clone(), store_a.clone(), policy, SessionLimits::default(), rx));

        let client = SyncClient::new(ep_b.clone(), Duration::from_secs(5));
        let r = client.pull(&addr_a, &*store_b).await.unwrap();
        assert!(!r.in_sync);
        assert_eq!(r.applied, 41);
        assert_eq!(root_of(&*store_a), root_of(&*store_b));
        let again = client.pull(&addr_a, &*store_b).await.unwrap();
        assert!(again.in_sync);
        tx.send(true).unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn a_non_member_is_dropped_and_a_wrong_pinned_identity_is_refused() {
        let (ep_a, addr_a) = node("zs-a2").await;
        let (ep_b, _) = node("zs-b2").await;
        let (ep_c, _) = node("zs-c2").await;
        let store_a = Arc::new(MemStore::default());
        store_a.apply(obj(1, ObjectKind::Update, "z.example.", 1, 1, b"x"), [0; 32]);
        let policy = Arc::new(PeerPolicy::new().with_peer(Transport::id(&*ep_b)));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let srv = tokio::spawn(serve(ep_a.clone(), store_a, policy, SessionLimits::default(), rx));

        // C is not in the policy: the server drops it; the pull errors rather than hangs
        let store_c = MemStore::default();
        let client_c = SyncClient::new(ep_c.clone(), Duration::from_secs(2));
        assert!(client_c.pull(&addr_a, &store_c).await.is_err());
        assert!(store_c.summaries(None, 10).is_empty());

        // B dials A but pins the wrong identity: refused client-side
        let store_b = MemStore::default();
        let client_b = SyncClient::new(ep_b.clone(), Duration::from_secs(2));
        let mut wrong = addr_a.clone();
        wrong.peer_id = [9u8; 32];
        assert_eq!(client_b.pull(&wrong, &store_b).await, Err(SyncError::PeerMismatch));
        tx.send(true).unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn publishers_may_push_but_not_read_and_forks_and_stale_are_reported() {
        let (ep_a, addr_a) = node("zs-a3").await;
        let (ep_p, _) = node("zs-p3").await;
        let store_a = Arc::new(MemStore::default());
        let policy = Arc::new(PeerPolicy::new().with_publisher(Transport::id(&*ep_p)));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let srv = tokio::spawn(serve(ep_a.clone(), store_a.clone(), policy, SessionLimits::default(), rx));
        let client = SyncClient::new(ep_p.clone(), Duration::from_secs(5));

        let v2 = obj(1, ObjectKind::Update, "z.example.", 1, 2, b"two");
        let v1 = obj(1, ObjectKind::Update, "z.example.", 1, 1, b"one");
        let v2_forked = obj(1, ObjectKind::Update, "z.example.", 1, 2, b"TWO-DIFFERENT");
        let out = client.push(&addr_a, &[v2.clone(), v1, v2.clone(), v2_forked]).await.unwrap();
        assert_eq!(
            out,
            vec![ApplyOutcome::Applied, ApplyOutcome::Stale, ApplyOutcome::Duplicate, ApplyOutcome::Fork]
        );
        // the held object is still the first v2
        let held = store_a.get(ObjectKind::Update, &v2.id_hash()).unwrap();
        assert_eq!(held.digest(), v2.digest());

        // a publisher cannot read: its pull is refused
        let local = MemStore::default();
        assert!(client.pull(&addr_a, &local).await.is_err());
        tx.send(true).unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn an_unauthorised_signer_is_reported_by_the_store() {
        let (ep_a, addr_a) = node("zs-a4").await;
        let (ep_p, _) = node("zs-p4").await;
        let store_a = Arc::new(MemStore::default());
        *store_a.deny_signer.lock().unwrap() = Some(*kp(5).public_key().as_bytes());
        let policy = Arc::new(PeerPolicy::new().with_publisher(Transport::id(&*ep_p)));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let srv = tokio::spawn(serve(ep_a, store_a.clone(), policy, SessionLimits::default(), rx));
        let client = SyncClient::new(ep_p, Duration::from_secs(5));
        let out = client.push(&addr_a, &[obj(5, ObjectKind::Update, "z.example.", 1, 1, b"x")]).await.unwrap();
        assert_eq!(out, vec![ApplyOutcome::Unauthorized]);
        assert!(store_a.summaries(None, 10).is_empty());
        tx.send(true).unwrap();
        srv.await.unwrap();
    }

    #[test]
    fn peer_policy_is_default_deny_and_a_peer_outranks_a_publisher_entry() {
        let p = PeerPolicy::new().with_publisher([1; 32]).with_peer([2; 32]).with_publisher([2; 32]);
        assert_eq!(p.role(&[1; 32]), Some(Role::Publisher));
        assert_eq!(p.role(&[2; 32]), Some(Role::Peer));
        assert_eq!(p.role(&[3; 32]), None);
    }
}
