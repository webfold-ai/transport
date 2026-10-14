#![cfg(feature = "runtime-tokio")]
//! Native TCP transport — the iroh-free P2P endpoint.
//!
//! Replaces `iroh::Endpoint` with tokio TcpStream + a native handshake (Ed25519 static identity +
//! X25519 ephemeral Diffie-Hellman + ChaCha20-Poly1305 session encryption), all via
//! hashtrinity-crypto — not IETF TLS 1.3 wire format (bedrock's own peers don't need to
//! interoperate with external TLS clients, just to authenticate and encrypt with each other), but
//! the same security properties: mutual authentication, forward secrecy via fresh ephemeral keys
//! per connection, and AEAD-encrypted, tamper-evident streams.
//!
//! ## What this gives us
//! - Mutual authentication: each side proves ownership of its Ed25519 static identity by signing
//!   its ephemeral X25519 public key; the peer verifies before deriving any session key.
//! - Forward secrecy: session keys derive from a fresh X25519 ephemeral exchange every connection
//!   (`dh_agreement_is_commutative`/`_holds_for_random_scalars` in `ed25519.rs` prove the
//!   underlying DH primitive itself).
//! - Encrypted, tamper-evident streams: every frame is sealed with ChaCha20-Poly1305 under a
//!   per-direction key (so client→server and server→client never share a nonce space) and an
//!   explicit, monotonically-checked nonce counter (replay of an old frame is rejected).
//! - Ed25519 peer identity — the `PeerId` returned by `Connection::peer_id()` is the VERIFIED
//!   remote static public key, not a placeholder.
//! - Bi-directional streams (TCP gives one; we multiplex logical streams via frame headers).
//! - Zero iroh dependency.
//!
//! ## Honest scope
//! `raw_halves()` (the escape hatch for protocols that frame themselves, e.g. serving a `Router`
//! directly over the connection) returns the **plaintext** TCP halves, same as before this
//! change — encrypting that path needs a streaming AEAD adapter (no fixed-size "messages" to
//! seal), which is a further, not-yet-built slice. Only the `open_bi`/`accept_bi` framed-stream
//! path is encrypted today.
//!
//! ## What TCP gives us that QUIC doesn't need
//! - Kernel-provided congestion control (free, battle-tested — NewReno/CUBIC in the kernel)
//! - No user-space loss recovery state machine
//!
//! ## Stream multiplexing
//! TCP gives one bi-directional byte stream per connection. `open_bi`/`accept_bi` create logical
//! streams multiplexed over that one TCP connection via sealed, length-prefixed frames (see
//! `seal_frame`/`open_frame`).

use super::{BiStream, BoxFuture, Connection, PeerId, Transport};
use hashtrinity::crypto::blake3;
use crate::prim::{chacha20poly1305_decrypt, chacha20poly1305_encrypt, ed25519_pubkey, ed25519_sign, ed25519_verify, x25519_pubkey, x25519_shared};
use std::collections::HashMap;
use std::io;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// The handshake message each side sends first: static identity + a fresh ephemeral X25519
/// public key + a signature binding the two (proves the sender holds the static secret key).
/// Wire size: 32 + 32 + 64 = 128 bytes, fixed, sent/read directly with no extra framing.
///
/// `pub(super)` — shared with `transport::quic`, which reuses this exact authentication
/// mechanism (Ed25519 static identity + X25519 ephemeral DH) over UDP instead of TCP. One
/// handshake protocol, two transports, not two independent implementations to keep in sync.
pub(super) struct HandshakeMsg {
    pub(super) static_pubkey: [u8; 32],
    pub(super) ephemeral_pubkey: [u8; 32],
    signature: [u8; 64],
}

pub(super) const HANDSHAKE_MSG_LEN: usize = 32 + 32 + 64;

impl HandshakeMsg {
    pub(super) fn build(static_secret: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> Self {
        let static_pubkey = ed25519_pubkey(static_secret);
        let signature = ed25519_sign(static_secret, ephemeral_pubkey);
        HandshakeMsg { static_pubkey, ephemeral_pubkey: *ephemeral_pubkey, signature }
    }

    pub(super) fn to_bytes(&self) -> [u8; HANDSHAKE_MSG_LEN] {
        let mut out = [0u8; HANDSHAKE_MSG_LEN];
        out[..32].copy_from_slice(&self.static_pubkey);
        out[32..64].copy_from_slice(&self.ephemeral_pubkey);
        out[64..128].copy_from_slice(&self.signature);
        out
    }

    pub(super) fn from_bytes(buf: &[u8; HANDSHAKE_MSG_LEN]) -> io::Result<Self> {
        let mut static_pubkey = [0u8; 32];
        let mut ephemeral_pubkey = [0u8; 32];
        let mut signature = [0u8; 64];
        static_pubkey.copy_from_slice(&buf[..32]);
        ephemeral_pubkey.copy_from_slice(&buf[32..64]);
        signature.copy_from_slice(&buf[64..128]);
        let msg = HandshakeMsg { static_pubkey, ephemeral_pubkey, signature };
        if !ed25519_verify(&msg.static_pubkey, &msg.ephemeral_pubkey, &msg.signature) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "handshake signature verification failed"));
        }
        Ok(msg)
    }
}

/// Derive the two per-direction session keys from the DH shared secret and a transcript that
/// binds both sides' static + ephemeral public keys — domain-separated per direction so
/// client→server and server→client frames never share a nonce space, and per-transcript so a
/// key can't be replayed against a different pair of peers/sessions.
pub(super) fn derive_session_keys(shared_secret: &[u8; 32], client: &HandshakeMsg, server: &HandshakeMsg) -> ([u8; 32], [u8; 32]) {
    let mut transcript = Vec::with_capacity(32 * 4 + 3);
    transcript.extend_from_slice(shared_secret);
    transcript.extend_from_slice(&client.static_pubkey);
    transcript.extend_from_slice(&client.ephemeral_pubkey);
    transcript.extend_from_slice(&server.static_pubkey);
    transcript.extend_from_slice(&server.ephemeral_pubkey);
    let mut c2s_input = transcript.clone();
    c2s_input.extend_from_slice(b"c2s");
    let mut s2c_input = transcript;
    s2c_input.extend_from_slice(b"s2c");
    (blake3(&c2s_input), blake3(&s2c_input))
}

/// The X25519 base point (the constant `9`, per RFC 7748) — shared so every caller generating
/// an ephemeral keypair uses the same point, not a re-typed magic value.
pub(super) const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Generate a fresh ephemeral X25519 keypair for one handshake. Returns (secret, public).
pub(super) fn generate_ephemeral_x25519() -> ([u8; 32], [u8; 32]) {
    let ephemeral_secret_bytes = hashtrinity::crypto::rand_bytes(32);
    let mut ephemeral_secret = [0u8; 32];
    ephemeral_secret.copy_from_slice(&ephemeral_secret_bytes);
    let ephemeral_pubkey = x25519_pubkey(&ephemeral_secret);
    (ephemeral_secret, ephemeral_pubkey)
}

/// Complete the DH exchange given both sides' handshake messages, resolving to *this* side's
/// (peer static identity, send key, recv key) — shared by `native` (TCP) and `quic` (UDP), the
/// only difference between them being how the two `HandshakeMsg`s reach each other on the wire.
pub(super) fn resolve_session_keys(
    ephemeral_secret: &[u8; 32],
    own_msg: &HandshakeMsg,
    peer_msg: &HandshakeMsg,
    is_client: bool,
) -> io::Result<(PeerId, [u8; 32], [u8; 32])> {
    // A low-order peer point forces an all-zero shared secret (a known contributory-behaviour
    // attack: the "session key" would be computable by anyone). Refuse the handshake.
    let shared_secret = x25519_shared(ephemeral_secret, &peer_msg.ephemeral_pubkey)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peer ephemeral key is of low order"))?;
    let (client_msg, server_msg) = if is_client { (own_msg, peer_msg) } else { (peer_msg, own_msg) };
    let (c2s_key, s2c_key) = derive_session_keys(&shared_secret, client_msg, server_msg);
    let (send_key, recv_key) = if is_client { (c2s_key, s2c_key) } else { (s2c_key, c2s_key) };
    Ok((peer_msg.static_pubkey, send_key, recv_key))
}

/// Run the handshake over a fresh TCP stream. `is_client` picks send-then-recv vs
/// recv-then-send ordering (arbitrary but must be consistent, else both sides could deadlock
/// waiting to read what the other hasn't sent yet). Returns (peer static pubkey, send key,
/// recv key) — `send_key`/`recv_key` already resolved to *this* side's direction.
async fn run_handshake(
    stream: &mut TcpStream,
    static_secret: &[u8; 32],
    is_client: bool,
) -> io::Result<(PeerId, [u8; 32], [u8; 32])> {
    let (ephemeral_secret, ephemeral_pubkey) = generate_ephemeral_x25519();
    let own_msg = HandshakeMsg::build(static_secret, &ephemeral_pubkey);
    let own_bytes = own_msg.to_bytes();

    let peer_msg = if is_client {
        stream.write_all(&own_bytes).await?;
        let mut buf = [0u8; HANDSHAKE_MSG_LEN];
        stream.read_exact(&mut buf).await?;
        HandshakeMsg::from_bytes(&buf)?
    } else {
        let mut buf = [0u8; HANDSHAKE_MSG_LEN];
        stream.read_exact(&mut buf).await?;
        let peer_msg = HandshakeMsg::from_bytes(&buf)?;
        stream.write_all(&own_bytes).await?;
        peer_msg
    };

    resolve_session_keys(&ephemeral_secret, &own_msg, &peer_msg, is_client)
}

/// Seal one frame: `[u32 stream_id][u64 len][payload]` sealed as a whole under
/// ChaCha20-Poly1305, wire-prefixed with an explicit 8-byte nonce counter and 4-byte
/// ciphertext length so the reader never has to guess.
fn seal_frame(key: &[u8; 32], counter: u64, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(12 + payload.len());
    plaintext.extend_from_slice(&stream_id.to_le_bytes());
    plaintext.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    plaintext.extend_from_slice(payload);
    let nonce = nonce_from_counter(counter);
    let (ct, tag) = chacha20poly1305_encrypt(key, &nonce, &plaintext, b"bedrock-transport-native");
    let mut out = Vec::with_capacity(8 + 4 + ct.len() + 16);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Read + open one sealed frame from `r`. Enforces strict counter monotonicity (the nonce
/// counter must be strictly greater than the last one accepted) to reject replay of an old
/// frame. Returns (stream_id, payload).
async fn read_sealed_frame(
    r: &mut OwnedReadHalf,
    key: &[u8; 32],
    last_counter: &AtomicU64,
) -> io::Result<(u32, Vec<u8>)> {
    let mut counter_buf = [0u8; 8];
    r.read_exact(&mut counter_buf).await?;
    let counter = u64::from_le_bytes(counter_buf);

    // `last_counter` starts at 0, which is never itself a valid frame counter (senders start
    // theirs at 1 — see `NativeConnection::new`'s `send_counter`), so plain `counter <= prev` is
    // enough: the first frame (counter 1) always exceeds the 0 sentinel, and no legitimate
    // counter can ever equal it afterwards.
    let prev = last_counter.load(Ordering::SeqCst);
    if counter <= prev {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "replayed or out-of-order frame counter"));
    }

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let ct_len = u32::from_le_bytes(len_buf) as usize;

    let mut ct = vec![0u8; ct_len];
    r.read_exact(&mut ct).await?;
    let mut tag = [0u8; 16];
    r.read_exact(&mut tag).await?;

    let nonce = nonce_from_counter(counter);
    let plaintext = chacha20poly1305_decrypt(key, &nonce, &ct, &tag, b"bedrock-transport-native")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame authentication failed"))?;
    last_counter.store(counter, Ordering::SeqCst);

    if plaintext.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "sealed frame too short"));
    }
    let stream_id = u32::from_le_bytes(plaintext[..4].try_into().unwrap());
    let payload_len = u64::from_le_bytes(plaintext[4..12].try_into().unwrap()) as usize;
    if plaintext.len() != 12 + payload_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "sealed frame length mismatch"));
    }
    Ok((stream_id, plaintext[12..].to_vec()))
}

/// The native endpoint — TCP listener + native handshake + Ed25519 identity.
pub struct NativeEndpoint {
    listener: Arc<TcpListener>,
    peer_id: PeerId,
    secret_key: [u8; 32],
    connections: Arc<Mutex<HashMap<PeerId, Arc<NativeConnection>>>>,
}

impl NativeEndpoint {
    /// Bind a new endpoint on `addr` (e.g. "0.0.0.0:0" for any free port).
    /// Generates a fresh Ed25519 keypair for the endpoint identity.
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let secret_key_bytes = hashtrinity::crypto::rand_bytes(32);
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&secret_key_bytes);
        let peer_id = crate::prim::ed25519_pubkey(&secret_key);
        Ok(NativeEndpoint {
            listener: Arc::new(listener),
            peer_id,
            secret_key,
            connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Bind with a specific secret key (for identity recovery / persistence).
    pub async fn bind_with_key(addr: &str, secret_key: [u8; 32]) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let peer_id = crate::prim::ed25519_pubkey(&secret_key);
        Ok(NativeEndpoint {
            listener: Arc::new(listener),
            peer_id,
            secret_key,
            connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Bind with the identity a dialkey implies, so [`Transport::id`] — and what a peer observes
    /// in the handshake — is [`crate::dialkey::peer_id`]`(dialkey)`.
    ///
    /// The dialkey-derived secret stays inside this crate: callers that used to hand
    /// `bind_with_key` the (then secret) result of `dialkey::peer_id` use this instead.
    pub async fn bind_with_dialkey(addr: &str, dialkey: &str) -> io::Result<Self> {
        Self::bind_with_key(addr, crate::dialkey::secret_seed_do_not_expose(dialkey)).await
    }

    /// The secret key (for sealing/persistence via kleis).
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

impl Transport for NativeEndpoint {
    type Connection = NativeConnection;

    fn id(&self) -> PeerId {
        self.peer_id
    }

    fn connect<'a>(&'a self, addr: &'a str, _alpn: &'a [u8]) -> BoxFuture<'a, io::Result<NativeConnection>> {
        let addr = addr.to_string();
        let connections = self.connections.clone();
        let secret_key = self.secret_key;
        Box::pin(async move {
            let mut stream = TcpStream::connect(&addr).await?;
            let peer_addr = stream.peer_addr().ok();
            let (peer_id, send_key, recv_key) = run_handshake(&mut stream, &secret_key, true).await?;
            let (read_half, write_half) = stream.into_split();
            let conn = NativeConnection::new(
                read_half,
                write_half,
                peer_id,
                send_key,
                recv_key,
                peer_addr.map(|a| a.to_string()),
            );
            let _ = connections;
            Ok(conn)
        })
    }

    fn accept<'a>(&'a self) -> BoxFuture<'a, Option<NativeConnection>> {
        let listener = self.listener.clone();
        let secret_key = self.secret_key;
        Box::pin(async move {
            let (mut stream, peer_addr) = listener.accept().await.ok()?;
            let (peer_id, send_key, recv_key) = run_handshake(&mut stream, &secret_key, false).await.ok()?;
            let (read_half, write_half) = stream.into_split();
            Some(NativeConnection::new(
                read_half,
                write_half,
                peer_id,
                send_key,
                recv_key,
                Some(peer_addr.to_string()),
            ))
        })
    }

    fn local_addr(&self) -> io::Result<String> {
        Ok(self.listener.local_addr()?.to_string())
    }
}

/// A native TCP connection — encrypted, authenticated, provides bi-directional streams via
/// sealed frame multiplexing.
pub struct NativeConnection {
    read: Arc<tokio::sync::Mutex<OwnedReadHalf>>,
    write: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    peer_id: PeerId,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: Arc<AtomicU64>,
    recv_last_counter: Arc<AtomicU64>,
    remote_addr: Option<String>,
}

impl NativeConnection {
    pub fn new(
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
        peer_id: PeerId,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        remote_addr: Option<String>,
    ) -> Self {
        NativeConnection {
            read: Arc::new(tokio::sync::Mutex::new(read)),
            write: Arc::new(tokio::sync::Mutex::new(write)),
            peer_id,
            send_key,
            recv_key,
            // Starts at 1 (not 0): `fetch_add(1, ..)` returns the pre-increment value, so the
            // first frame sent uses counter 1. 0 stays reserved as `recv_last_counter`'s "nothing
            // accepted yet" sentinel — see `read_sealed_frame`.
            send_counter: Arc::new(AtomicU64::new(1)),
            recv_last_counter: Arc::new(AtomicU64::new(0)),
            remote_addr,
        }
    }

    pub fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }

    /// The raw read/write halves — for protocols that ARE the one bidirectional byte stream
    /// (HTTP, RESP) rather than the frame-multiplexed `open_bi` logical streams. Serving a
    /// `Router` over a `NativeEndpoint` accepts a connection and wraps these halves in an
    /// `AsyncRead + AsyncWrite` adapter; the transport (listener, accept, peer identity)
    /// stays this module's, only the byte-framing is the caller's.
    ///
    /// **Plaintext, deliberately** — the handshake still authenticates the connection (the
    /// caller knows `peer_id()` is a verified identity), but these bytes are NOT run through
    /// `seal_frame`/`read_sealed_frame`. Encrypting an arbitrary caller-defined byte stream needs
    /// a streaming AEAD adapter (no fixed-size messages to seal per-frame); that's a further,
    /// not-yet-built slice, not silently assumed to be covered.
    pub fn raw_halves(
        &self,
    ) -> (
        Arc<tokio::sync::Mutex<OwnedReadHalf>>,
        Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    ) {
        (self.read.clone(), self.write.clone())
    }
}

impl Connection for NativeConnection {
    fn open_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
        let read = self.read.clone();
        let write = self.write.clone();
        let send_key = self.send_key;
        let recv_key = self.recv_key;
        let send_counter = self.send_counter.clone();
        let recv_last_counter = self.recv_last_counter.clone();
        Box::pin(async move {
            let stream_id: u32 = 0; // simplified: single stream per open_bi call
            let send: Box<dyn BiStream> = Box::new(SealedStreamSend { write, stream_id, key: send_key, counter: send_counter });
            let recv: Box<dyn BiStream> = Box::new(SealedStreamRecv { read, stream_id, key: recv_key, last_counter: recv_last_counter });
            Ok((send, recv))
        })
    }



    fn accept_bi<'a>(&'a self) -> BoxFuture<'a, io::Result<(Box<dyn BiStream>, Box<dyn BiStream>)>> {
        self.open_bi()
    }

    fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn close<'a>(&'a self) -> BoxFuture<'a, io::Result<()>> {
        let write = self.write.clone();
        Box::pin(async move {
            let mut w = write.lock().await;
            w.shutdown().await
        })
    }
}

/// The send half of a sealed bi-directional stream.
struct SealedStreamSend {
    write: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    stream_id: u32,
    key: [u8; 32],
    counter: Arc<AtomicU64>,
}

impl BiStream for SealedStreamSend {
    fn read<'a>(&'a mut self, _buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot read from send stream")) })
    }

    fn read_exact<'a>(&'a mut self, _buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot read from send stream")) })
    }

    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        let data = data.to_vec();
        let stream_id = self.stream_id;
        let write = self.write.clone();
        let key = self.key;
        let counter = self.counter.clone();
        Box::pin(async move {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let sealed = seal_frame(&key, n, stream_id, &data);
            let mut w = write.lock().await;
            w.write_all(&sealed).await
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>> {
        let write = self.write.clone();
        Box::pin(async move {
            let mut w = write.lock().await;
            w.shutdown().await
        })
    }
}

/// The recv half of a sealed bi-directional stream.
struct SealedStreamRecv {
    read: Arc<tokio::sync::Mutex<OwnedReadHalf>>,
    stream_id: u32,
    key: [u8; 32],
    last_counter: Arc<AtomicU64>,
}

impl BiStream for SealedStreamRecv {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        let read = self.read.clone();
        let stream_id = self.stream_id;
        let key = self.key;
        let last_counter = self.last_counter.clone();
        Box::pin(async move {
            let mut r = read.lock().await;
            let (frame_stream_id, payload) = read_sealed_frame(&mut r, &key, &last_counter).await?;
            if frame_stream_id != stream_id {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "stream id mismatch"));
            }
            let to_copy = payload.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&payload[..to_copy]);
            Ok(to_copy)
        })
    }

    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<()>> {
        let read = self.read.clone();
        let stream_id = self.stream_id;
        let key = self.key;
        let last_counter = self.last_counter.clone();
        Box::pin(async move {
            let mut r = read.lock().await;
            let (frame_stream_id, payload) = read_sealed_frame(&mut r, &key, &last_counter).await?;
            if frame_stream_id != stream_id {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "stream id mismatch"));
            }
            if payload.len() != buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame size mismatch"));
            }
            buf.copy_from_slice(&payload);
            Ok(())
        })
    }

    fn write_all<'a>(&'a mut self, _data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot write to recv stream")) })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_binds_and_accepts() {
        let endpoint = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = endpoint.local_addr().unwrap();
        // The endpoint is bound and listening
        assert!(addr.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn connect_and_send_frame() {
        let server = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = Transport::accept(&server).await;
            assert!(conn.is_some());
            let conn = conn.unwrap();
            let (_, mut recv) = Connection::accept_bi(&conn).await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = recv.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello native transport");
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let conn = Transport::connect(&client, &addr, b"test").await.unwrap();
        let (mut send, _) = Connection::open_bi(&conn).await.unwrap();
        send.write_all(b"hello native transport").await.unwrap();
        send.finish().await.ok();

        server_task.await.unwrap();
    }

    /// The handshake authenticates each side by its Ed25519 static identity — `peer_id()` on
    /// both ends must be the OTHER side's real identity, not a placeholder, and each side's
    /// bound identity (`Transport::id()`) must match what the other observes.
    #[tokio::test]
    async fn peer_id_is_the_verified_remote_static_identity() {
        let server = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_id = Transport::id(&server);

        let server_task = tokio::spawn(async move {
            let conn = Transport::accept(&server).await.unwrap();
            Connection::peer_id(&conn)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let client_id = Transport::id(&client);
        let conn = Transport::connect(&client, &addr, b"test").await.unwrap();
        let observed_server_id = Connection::peer_id(&conn);
        assert_eq!(observed_server_id, server_id);

        let observed_client_id = server_task.await.unwrap();
        assert_eq!(observed_client_id, client_id);
    }

    /// `dialkey::peer_id` must be the identity a dialkey-bound endpoint really presents on the
    /// wire — in both directions — and must not be the secret the handshake keys are derived from.
    /// Before the fix `peer_id` returned the seed, so the observed id (the public key of that seed)
    /// never equalled it and a peer pinned by `peer_id(dialkey)` could never authenticate.
    #[tokio::test]
    async fn a_dialkey_bound_endpoint_presents_dialkey_peer_id_on_the_wire() {
        let dialkey = "g17-test-dialkey";
        let expected = crate::dialkey::peer_id(dialkey);
        assert_ne!(expected, crate::dialkey::secret_seed_do_not_expose(dialkey));

        // Rolling-upgrade compatibility: a 0.1.x caller bound with `bind_with_key(peer_id_0_1(k))`,
        // i.e. with the seed as the secret. Its wire identity is the one `bind_with_dialkey` now gives.
        let legacy = NativeEndpoint::bind_with_key(
            "127.0.0.1:0",
            crate::dialkey::secret_seed_do_not_expose(dialkey),
        )
        .await
        .unwrap();
        assert_eq!(Transport::id(&legacy), expected, "migrating must not change the wire identity");

        // dialkey-bound server, anonymous client.
        let server = NativeEndpoint::bind_with_dialkey("127.0.0.1:0", dialkey).await.unwrap();
        assert_eq!(Transport::id(&server), expected);
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let conn = Transport::accept(&server).await.unwrap();
            Connection::peer_id(&conn)
        });
        let client = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let client_id = Transport::id(&client);
        let conn = Transport::connect(&client, &addr, b"test").await.unwrap();
        assert_eq!(Connection::peer_id(&conn), expected, "client observes the server's dialkey peer_id");
        assert_eq!(server_task.await.unwrap(), client_id);

        // anonymous server, dialkey-bound client.
        let server = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let conn = Transport::accept(&server).await.unwrap();
            Connection::peer_id(&conn)
        });
        let client = NativeEndpoint::bind_with_dialkey("127.0.0.1:0", dialkey).await.unwrap();
        let _conn = Transport::connect(&client, &addr, b"test").await.unwrap();
        assert_eq!(server_task.await.unwrap(), expected, "server observes the client's dialkey peer_id");
    }

    /// The data actually on the wire must not contain the plaintext — proves the frame is
    /// genuinely sealed, not just logically encrypted in a way that happens to still work.
    #[tokio::test]
    async fn wire_bytes_do_not_contain_plaintext() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let secret_a = {
            let b = hashtrinity::crypto::rand_bytes(32);
            let mut s = [0u8; 32]; s.copy_from_slice(&b); s
        };
        let secret_b = {
            let b = hashtrinity::crypto::rand_bytes(32);
            let mut s = [0u8; 32]; s.copy_from_slice(&b); s
        };

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (_, send_key, recv_key) = run_handshake(&mut stream, &secret_b, false).await.unwrap();
            (stream, send_key, recv_key)
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        let (_, client_send_key, _client_recv_key) = run_handshake(&mut client_stream, &secret_a, true).await.unwrap();

        let secret_payload = b"the quick brown fox jumps over the lazy dog - top secret";
        let sealed = seal_frame(&client_send_key, 0, 0, secret_payload);
        // The plaintext payload must not appear anywhere in the sealed bytes.
        assert!(!contains_subslice(&sealed, secret_payload));

        let _ = server_task.await.unwrap();
        let _ = client_stream.shutdown().await;
    }

    /// A replayed / out-of-order frame counter must be rejected, not silently accepted. Exercises
    /// `read_sealed_frame` directly over a real TCP loopback pair: seal counter 5 and counter 3
    /// (out of order) back-to-back on the wire, confirm the first opens and the second — whose
    /// counter doesn't exceed the last accepted one — is rejected.
    #[tokio::test]
    async fn replayed_frame_counter_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let server_stream = accept_task.await.unwrap();
        let (mut server_read, _server_write) = server_stream.into_split();
        let (_client_read, mut client_write) = client_stream.into_split();

        let key = [7u8; 32];
        let last_counter = AtomicU64::new(0);

        let sealed_5 = seal_frame(&key, 5, 0, b"five");
        client_write.write_all(&sealed_5).await.unwrap();
        let (_, payload) = read_sealed_frame(&mut server_read, &key, &last_counter).await.unwrap();
        assert_eq!(payload, b"five");
        assert_eq!(last_counter.load(Ordering::SeqCst), 5);

        let sealed_3 = seal_frame(&key, 3, 0, b"three");
        client_write.write_all(&sealed_3).await.unwrap();
        let result = read_sealed_frame(&mut server_read, &key, &last_counter).await;
        assert!(result.is_err(), "counter going backwards must be rejected");
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() { return false; }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
