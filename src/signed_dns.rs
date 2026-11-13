//! Self-authenticating DNS records — a public key IS the name.
//!
//! The discovery half of the native P2P stack, and the third module in the same line as
//! [`super::native`] (which replaced `iroh::Endpoint`) and [`super::dns`] (which replaced the two
//! external DNS stacks). This one replaces the `pkarr` crate: an Ed25519 keypair signs a DNS
//! message, the public key z-base32-encodes into the label it is published under, and any reader
//! verifies the record against the name it asked for. No certificate authority, no registrar —
//! the name and the key are the same fact.
//!
//! ## The format, and why each part of it is fixed
//!
//! A published value is `signature(64) ‖ seq(8, big-endian) ‖ v`, where `v` is an encoded DNS
//! message (RFC 1035, via [`super::dns`]) and `seq` is a microsecond timestamp used as BEP44's
//! monotonic sequence number. The signature covers **not** those bytes directly but the bencode
//! preimage BEP44 specifies:
//!
//! ```text
//! 3:seqi<seq>e1:v<len>:<v bytes>
//! ```
//!
//! That indirection is load-bearing rather than ceremonial: it length-prefixes `v` inside the
//! signed region, so no choice of `seq` digits can shift bytes between the two fields and
//! produce a second message with the same signature.
//!
//! Two consequences the code depends on:
//!
//! * **Encoding must be deterministic.** [`super::dns::Message::to_bytes`] never compresses
//!   names, so one set of records has exactly one byte string. An encoder free to pick between
//!   two valid encodings would make a signature unverifiable by anyone who re-encoded.
//! * **`seq` is a timestamp, so newer wins.** A relay keeps the highest `seq` it has seen for a
//!   key; a replayed older record is refused by comparison, not by memory of having seen it.
//!
//! ## What this does not do
//!
//! No Mainline DHT. The `pkarr` crate's `relays` feature — the HTTP path — is the one this
//! workspace used, and it is what [`super::pkarr`] drives on top of this module. A DHT client is
//! a separate piece of work, and pretending otherwise would hide a real gap.

use super::dns::{DnsError, Message, Record};
use crate::base32::ZBASE32;
use crate::prim::{ed25519_pubkey, ed25519_sign, ed25519_verify};

/// Length of the value a relay will accept, per BEP44. A DNS message over this cannot be
/// published, and truncating it silently would publish records the author did not write.
pub const MAX_VALUE_LEN: usize = 1000;

/// Why a signed record could not be built, parsed or trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedDnsError {
    /// The z-base32 label was not 32 bytes of key.
    BadPublicKey,
    /// The payload was shorter than the 72-byte `signature ‖ seq` prefix.
    Truncated,
    /// The signature did not verify against the key the record was published under. This is the
    /// one that matters: it is the difference between a record and a claim.
    BadSignature,
    /// The value exceeded [`MAX_VALUE_LEN`].
    ValueTooLong,
    /// The value was not a decodable DNS message.
    Dns(DnsError),
}

impl core::fmt::Display for SignedDnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignedDnsError::BadPublicKey => f.write_str("signed-dns: not a 32-byte public key"),
            SignedDnsError::Truncated => f.write_str("signed-dns: payload shorter than its header"),
            SignedDnsError::BadSignature => {
                f.write_str("signed-dns: signature does not verify under the published key")
            }
            SignedDnsError::ValueTooLong => f.write_str("signed-dns: value over the BEP44 limit"),
            SignedDnsError::Dns(e) => write!(f, "signed-dns: {e}"),
        }
    }
}

impl std::error::Error for SignedDnsError {}

impl From<DnsError> for SignedDnsError {
    fn from(e: DnsError) -> Self {
        SignedDnsError::Dns(e)
    }
}

/// An Ed25519 public key — and therefore a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The z-base32 label this key publishes under — 52 characters, the form that appears in a
    /// relay URL and as a DNS label.
    #[must_use]
    pub fn to_z32(&self) -> String {
        ZBASE32.encode(self.0)
    }

    /// Parse a z-base32 label back into a key.
    ///
    /// # Errors
    /// [`SignedDnsError::BadPublicKey`] if it is not valid z-base32 of exactly 32 bytes.
    pub fn from_z32(s: &str) -> Result<Self, SignedDnsError> {
        let raw = ZBASE32
            .decode(s)
            .map_err(|_| SignedDnsError::BadPublicKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| SignedDnsError::BadPublicKey)?;
        Ok(PublicKey(bytes))
    }

    /// Build from raw bytes.
    ///
    /// # Errors
    /// [`SignedDnsError::BadPublicKey`] unless the slice is exactly 32 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, SignedDnsError> {
        let bytes: [u8; 32] = b.try_into().map_err(|_| SignedDnsError::BadPublicKey)?;
        Ok(PublicKey(bytes))
    }

    /// Whether `sig` is this key's signature over `msg`.
    #[must_use]
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        ed25519_verify(&self.0, msg, sig)
    }
}

/// A signing key. Holds the 32-byte seed; the public half is derived, never stored, so the two
/// cannot drift apart.
#[derive(Clone)]
pub struct Keypair {
    seed: [u8; 32],
}

impl core::fmt::Debug for Keypair {
    /// Prints the PUBLIC half only. A `Debug` that renders a private key puts it in every log
    /// line that ever formats the containing struct.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public_key().to_z32())
            .finish()
    }
}

impl Keypair {
    /// From a 32-byte secret seed. Deterministic: the same seed is always the same identity,
    /// which is what lets a dialkey name a stable endpoint without storing a key file.
    #[must_use]
    pub fn from_secret_key(seed: &[u8; 32]) -> Self {
        Keypair { seed: *seed }
    }

    /// The public half.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(ed25519_pubkey(&self.seed))
    }

    /// This identity's z-base32 label.
    #[must_use]
    pub fn to_z32(&self) -> String {
        self.public_key().to_z32()
    }

    /// Sign arbitrary bytes.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        ed25519_sign(&self.seed, msg)
    }
}

/// BEP44's signable preimage: `3:seqi<seq>e1:v<len>:<value>`.
///
/// Built here rather than inline at the two call sites so signing and verifying provably agree —
/// a preimage that differs between the two is a bug that presents as "the record is corrupt".
fn preimage(seq: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 32);
    out.extend_from_slice(b"3:seqi");
    out.extend_from_slice(seq.to_string().as_bytes());
    out.extend_from_slice(b"e1:v");
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out
}

/// A DNS message signed by the key it is published under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPacket {
    public_key: PublicKey,
    signature: [u8; 64],
    seq: u64,
    value: Vec<u8>,
}

impl SignedPacket {
    /// Encode `records` as a DNS message, sign it at `seq`, and return the signed packet.
    ///
    /// `seq` is a microsecond timestamp; a relay keeps the highest it has seen per key, so a
    /// caller republishing must pass a strictly larger value or be ignored.
    ///
    /// # Errors
    /// [`SignedDnsError::ValueTooLong`] if the encoded message exceeds [`MAX_VALUE_LEN`].
    pub fn new(keypair: &Keypair, records: &[Record], seq: u64) -> Result<Self, SignedDnsError> {
        let mut msg = Message::response(0);
        msg.flags.authoritative = true;
        msg.answers = records.to_vec();
        let value = msg.to_bytes();
        if value.len() > MAX_VALUE_LEN {
            return Err(SignedDnsError::ValueTooLong);
        }
        let signature = keypair.sign(&preimage(seq, &value));
        Ok(SignedPacket {
            public_key: keypair.public_key(),
            signature,
            seq,
            value,
        })
    }

    /// Parse a relay payload — `signature ‖ seq ‖ v` — **and verify it** against `public_key`.
    ///
    /// There is deliberately no unverified constructor: a `SignedPacket` that exists has been
    /// checked, so no caller can forget to.
    ///
    /// # Errors
    /// [`SignedDnsError::Truncated`] if shorter than 72 bytes, [`SignedDnsError::BadSignature`]
    /// if the signature does not verify.
    pub fn from_relay_bytes(public_key: PublicKey, body: &[u8]) -> Result<Self, SignedDnsError> {
        let sig_bytes = body.get(0..64).ok_or(SignedDnsError::Truncated)?;
        let seq_bytes = body.get(64..72).ok_or(SignedDnsError::Truncated)?;
        let value = body.get(72..).ok_or(SignedDnsError::Truncated)?.to_vec();
        if value.len() > MAX_VALUE_LEN {
            return Err(SignedDnsError::ValueTooLong);
        }
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SignedDnsError::Truncated)?;
        let seq = u64::from_be_bytes(
            seq_bytes
                .try_into()
                .map_err(|_| SignedDnsError::Truncated)?,
        );
        if !public_key.verify(&preimage(seq, &value), &signature) {
            return Err(SignedDnsError::BadSignature);
        }
        Ok(SignedPacket {
            public_key,
            signature,
            seq,
            value,
        })
    }

    /// The relay wire form: `signature(64) ‖ seq(8, big-endian) ‖ v`.
    #[must_use]
    pub fn to_relay_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72 + self.value.len());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.value);
        out
    }

    /// The key this record is published under.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// The sequence number (microsecond timestamp).
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Decode the carried DNS message.
    ///
    /// # Errors
    /// [`SignedDnsError::Dns`] if the signed bytes are not a decodable message. Note this can
    /// only happen for a record whose signature ALREADY verified — i.e. the author signed
    /// something malformed, not an attacker altered it.
    pub fn message(&self) -> Result<Message, SignedDnsError> {
        Ok(Message::from_bytes(&self.value)?)
    }

    /// The records carried, or empty if the message does not decode.
    #[must_use]
    pub fn records(&self) -> Vec<Record> {
        self.message().map(|m| m.answers).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::dns::{Name, RData, RecordType};
    use super::*;

    fn kp(tag: u8) -> Keypair {
        Keypair::from_secret_key(&[tag; 32])
    }

    fn records() -> Vec<Record> {
        vec![
            Record::new(
                Name::from_ascii("_opsfold._tcp").unwrap(),
                300,
                RData::Srv {
                    priority: 0,
                    weight: 0,
                    port: 8081,
                    target: Name::from_ascii("host.local").unwrap(),
                },
            ),
            Record::new(
                Name::from_ascii("_opsfold._tcp").unwrap(),
                300,
                RData::Txt(vec![b"region=tas-cloud".to_vec()]),
            ),
        ]
    }

    #[test]
    fn a_keypair_is_deterministic_in_its_seed() {
        assert_eq!(kp(7).to_z32(), kp(7).to_z32());
        assert_ne!(kp(7).to_z32(), kp(8).to_z32());
        assert_eq!(
            kp(7).to_z32().len(),
            52,
            "a 32-byte key is a 52-character label"
        );
    }

    #[test]
    fn a_public_key_round_trips_through_its_label() {
        let pk = kp(3).public_key();
        assert_eq!(PublicKey::from_z32(&pk.to_z32()).unwrap(), pk);
        assert_eq!(
            PublicKey::from_z32("not-a-key"),
            Err(SignedDnsError::BadPublicKey)
        );
    }

    /// `Debug` must never render the private half — otherwise every log line that formats a
    /// containing struct leaks the identity.
    #[test]
    fn debug_shows_the_public_half_only() {
        let k = kp(5);
        let shown = format!("{k:?}");
        assert!(shown.contains(&k.to_z32()));
        assert!(!shown.contains("seed"), "{shown}");
    }

    #[test]
    fn a_signed_packet_round_trips_through_the_relay_form() {
        let k = kp(1);
        let p = SignedPacket::new(&k, &records(), 1_700_000_000_000_000).unwrap();
        let back = SignedPacket::from_relay_bytes(k.public_key(), &p.to_relay_bytes()).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.seq(), 1_700_000_000_000_000);
        let recs = back.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data.record_type(), RecordType::Srv);
        assert_eq!(recs[1].data.record_type(), RecordType::Txt);
    }

    /// The property the whole module exists for: a record that has been altered does not verify,
    /// and every byte of the payload is covered.
    #[test]
    fn any_altered_byte_fails_verification() {
        let k = kp(2);
        let p = SignedPacket::new(&k, &records(), 42).unwrap();
        let good = p.to_relay_bytes();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                SignedPacket::from_relay_bytes(k.public_key(), &bad),
                Err(SignedDnsError::BadSignature),
                "flipping byte {i} must break verification"
            );
        }
    }

    /// A record signed by one key must not verify under another — the name IS the key, so this
    /// is what stops anyone publishing under someone else's label.
    #[test]
    fn a_record_does_not_verify_under_a_different_key() {
        let p = SignedPacket::new(&kp(1), &records(), 9).unwrap();
        assert_eq!(
            SignedPacket::from_relay_bytes(kp(2).public_key(), &p.to_relay_bytes()),
            Err(SignedDnsError::BadSignature)
        );
    }

    /// The signature covers `seq`, so an old record cannot be replayed with a higher sequence to
    /// beat a newer one at the relay.
    #[test]
    fn the_sequence_number_is_inside_the_signature() {
        let k = kp(4);
        let p = SignedPacket::new(&k, &records(), 100).unwrap();
        let mut forged = p.to_relay_bytes();
        forged[64..72].copy_from_slice(&999u64.to_be_bytes());
        assert_eq!(
            SignedPacket::from_relay_bytes(k.public_key(), &forged),
            Err(SignedDnsError::BadSignature)
        );
    }

    /// The preimage is length-prefixed, so no choice of `seq` digits can shift bytes into `v` and
    /// yield a second (seq, v) pair with the same signed bytes.
    #[test]
    fn the_preimage_is_unambiguous_across_seq_and_value() {
        assert_eq!(preimage(1, b"ab"), b"3:seqi1e1:v2:ab".to_vec());
        // "12" ‖ "b" and "1" ‖ "2b" must not collide
        assert_ne!(preimage(12, b"b"), preimage(1, b"2b"));
    }

    #[test]
    fn a_short_payload_is_truncated_not_a_panic() {
        let k = kp(6);
        let p = SignedPacket::new(&k, &records(), 1).unwrap();
        let bytes = p.to_relay_bytes();
        for cut in 0..72 {
            assert_eq!(
                SignedPacket::from_relay_bytes(k.public_key(), &bytes[..cut]),
                Err(SignedDnsError::Truncated),
                "a {cut}-byte payload is short of the header"
            );
        }
    }

    #[test]
    fn a_value_over_the_bep44_limit_is_refused_rather_than_truncated() {
        let big: Vec<Record> = (0..200)
            .map(|i| {
                Record::new(
                    Name::from_ascii(&format!("r{i}.example.com")).unwrap(),
                    300,
                    RData::Txt(vec![vec![b'x'; 200]]),
                )
            })
            .collect();
        assert_eq!(
            SignedPacket::new(&kp(1), &big, 1).unwrap_err(),
            SignedDnsError::ValueTooLong
        );
    }
}
