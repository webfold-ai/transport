//! The DNS wire format — RFC 1035 messages, encoded and decoded natively.
//!
//! This is the naming twin of [`super::native`]: that module replaced `iroh::Endpoint` with a
//! handshake built on `hashtrinity::crypto`, and this one replaces the external DNS stacks with
//! the wire format itself. Two of them had accumulated — `hickory_proto` under
//! [`super::edge_dns`], and `simple-dns` arriving transitively through the `pkarr` crate under
//! [`super::pkarr`] — for the same job, in the same crate.
//!
//! The format is small and fixed: a 12-byte header, then four sections of records, each record a
//! name, a 16-bit type, a 16-bit class, a 32-bit TTL and a length-prefixed payload. Depending on
//! a crate for it is the multiple-independent-reimplementation pattern a masquerade closes —
//! the same argument `hashtrinity::base64`'s own header makes.
//!
//! ## What is here, and what is deliberately not
//!
//! **Decoding accepts name compression** (RFC 1035 §4.1.4 — the `0xC0` pointer): real resolvers
//! emit it, so a server that cannot read it cannot answer. Pointers are followed with a budget
//! and a strictly-decreasing-offset rule, so a self-referential packet terminates instead of
//! hanging the thread that parsed it.
//!
//! **Encoding never compresses.** An uncompressed message is always legal, every resolver reads
//! it, and it is what a signed record REQUIRES: `SignedPacket`'s signature covers the encoded
//! bytes, so an encoder allowed to choose between two valid encodings of the same records would
//! make the signature depend on that choice. One input, one byte string.
//!
//! `RecordType`/`RData` cover what the two consumers use — A, AAAA, NS, CNAME, SOA, TXT, CAA,
//! SRV — plus [`RData::Unknown`], which round-trips any other type byte-for-byte rather than
//! dropping it. An authority that silently discards records it does not model is worse than one
//! that carries them through.
//!
//! **DNSSEC records** (RFC 4034): `DS`, `DNSKEY`, `RRSIG` and `NSEC` are modelled so the health
//! checks in [`crate::dns_health`] can read a signed zone. They are *parsed and re-encoded*, not
//! validated here: nothing in this module checks a signature. The record types are the associated
//! constants [`RecordType::DS`] and friends rather than new enum variants (they are
//! `Unknown(code)` underneath, so `from_code`/`code` stay a bijection and an exhaustive `match`
//! on [`RecordType`] elsewhere keeps compiling); the payloads are real [`RData`] variants.
//! Every length is bounds-checked against the record's own RDLENGTH before it is used.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Why a message could not be parsed. One flat type: every variant is "the bytes were not a
/// DNS message", and a caller's only recovery is to drop the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The buffer ended in the middle of a field.
    Truncated,
    /// A label exceeded 63 bytes, or a name exceeded 255.
    NameTooLong,
    /// A compression pointer looped, or the pointer budget was exhausted.
    BadPointer,
    /// A name label was not valid ASCII, or contained a dot.
    BadLabel,
}

impl core::fmt::Display for DnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DnsError::Truncated => "dns: message ended mid-field",
            DnsError::NameTooLong => "dns: label or name over the RFC 1035 limit",
            DnsError::BadPointer => "dns: compression pointer looped or ran out of budget",
            DnsError::BadLabel => "dns: label is not valid ASCII",
        })
    }
}

impl std::error::Error for DnsError {}

const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;
/// A packet cannot contain more pointer hops than it has bytes; this bounds a pathological chain
/// well under that while leaving every legitimate packet room.
const MAX_POINTER_HOPS: usize = 64;

/// A domain name as its sequence of labels — `["www", "example", "com"]`, root being empty.
///
/// Labels are stored decoded. Comparison is case-insensitive, because DNS is: a query for
/// `WWW.Example.COM` must match a zone entry written `www.example.com`.
#[derive(Debug, Clone, Default)]
pub struct Name {
    labels: Vec<String>,
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}
impl Eq for Name {}

impl Name {
    /// The root name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Name { labels: Vec::new() }
    }

    /// Parse a presentation-form name. A trailing dot is optional and carries no meaning here —
    /// every name this type holds is absolute.
    ///
    /// # Errors
    /// [`DnsError::BadLabel`] for a non-ASCII or empty interior label, [`DnsError::NameTooLong`]
    /// past the RFC limits.
    pub fn from_ascii(s: &str) -> Result<Self, DnsError> {
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Name::root());
        }
        let mut labels = Vec::new();
        let mut total = 1usize; // the root's own zero-length terminator
        for part in trimmed.split('.') {
            if part.is_empty() || part.len() > MAX_LABEL {
                return Err(if part.is_empty() {
                    DnsError::BadLabel
                } else {
                    DnsError::NameTooLong
                });
            }
            if !part.is_ascii() {
                return Err(DnsError::BadLabel);
            }
            total += 1 + part.len();
            if total > MAX_NAME {
                return Err(DnsError::NameTooLong);
            }
            labels.push(part.to_string());
        }
        Ok(Name { labels })
    }

    /// The labels, outermost first.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Whether this name is `other`, or a subdomain of it — the zone-membership test an
    /// authoritative server runs on every query.
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        if other.labels.len() > self.labels.len() {
            return false;
        }
        let off = self.labels.len() - other.labels.len();
        self.labels[off..]
            .iter()
            .zip(&other.labels)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Presentation form, always with the trailing dot (`www.example.com.`, root is `.`).
    #[must_use]
    pub fn to_ascii(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        let mut s = String::new();
        for l in &self.labels {
            s.push_str(l);
            s.push('.');
        }
        s
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(u8::try_from(l.len()).unwrap_or(0));
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
    }

    /// The canonical wire form (RFC 4034 §6.2): uncompressed, every label lower-cased. This is
    /// the owner-name encoding a DS digest is computed over (RFC 4034 §5.1.4).
    #[must_use]
    pub fn canonical_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1);
        for l in &self.labels {
            out.push(u8::try_from(l.len()).unwrap_or(0));
            out.extend(l.bytes().map(|b| b.to_ascii_lowercase()));
        }
        out.push(0);
        out
    }

    /// Decode at `pos`, following compression pointers. Returns the name and the offset just past
    /// the name **in the original stream** — which for a pointer is 2 bytes, not the length of
    /// what it pointed at.
    fn decode(buf: &[u8], pos: usize) -> Result<(Name, usize), DnsError> {
        let mut labels = Vec::new();
        let mut at = pos;
        let mut after: Option<usize> = None;
        let mut hops = 0usize;
        let mut total = 1usize;
        loop {
            let len = *buf.get(at).ok_or(DnsError::Truncated)?;
            if len & 0xC0 == 0xC0 {
                // a pointer: the low 14 bits are the target offset
                let hi = usize::from(len & 0x3F) << 8;
                let lo = usize::from(*buf.get(at + 1).ok_or(DnsError::Truncated)?);
                let target = hi | lo;
                // A pointer must go strictly BACKWARDS. That single rule makes a loop
                // impossible: each hop lands nearer the start, so the chain is finite.
                if target >= at {
                    return Err(DnsError::BadPointer);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(DnsError::BadPointer);
                }
                if after.is_none() {
                    after = Some(at + 2);
                }
                at = target;
                continue;
            }
            if len == 0 {
                at += 1;
                break;
            }
            let len = usize::from(len);
            if len > MAX_LABEL {
                return Err(DnsError::NameTooLong);
            }
            let start = at + 1;
            let end = start + len;
            let raw = buf.get(start..end).ok_or(DnsError::Truncated)?;
            total += 1 + len;
            if total > MAX_NAME {
                return Err(DnsError::NameTooLong);
            }
            labels.push(String::from_utf8_lossy(raw).into_owned());
            at = end;
        }
        Ok((Name { labels }, after.unwrap_or(at)))
    }
}

/// A resource record type. [`RecordType::Unknown`] carries any code this enum does not name, so
/// an unmodelled type round-trips instead of being dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Ns,
    Cname,
    Soa,
    Txt,
    Srv,
    Caa,
    /// Any other type code, including the `255` of a wildcard query.
    Unknown(u16),
}

impl RecordType {
    /// DNSSEC delegation signer (RFC 4034 §5), held at the parent side of a zone cut.
    pub const DS: RecordType = RecordType::Unknown(43);
    /// DNSSEC signature over an RRset (RFC 4034 §3).
    pub const RRSIG: RecordType = RecordType::Unknown(46);
    /// DNSSEC authenticated denial of existence (RFC 4034 §4).
    pub const NSEC: RecordType = RecordType::Unknown(47);
    /// DNSSEC public key (RFC 4034 §2).
    pub const DNSKEY: RecordType = RecordType::Unknown(48);

    /// The wire code.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
            RecordType::Srv => 33,
            RecordType::Caa => 257,
            RecordType::Unknown(c) => c,
        }
    }

    /// From the wire code.
    #[must_use]
    pub fn from_code(c: u16) -> Self {
        match c {
            1 => RecordType::A,
            2 => RecordType::Ns,
            5 => RecordType::Cname,
            6 => RecordType::Soa,
            16 => RecordType::Txt,
            28 => RecordType::Aaaa,
            33 => RecordType::Srv,
            257 => RecordType::Caa,
            other => RecordType::Unknown(other),
        }
    }
}

/// A record's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// One or more character-strings. DNS TXT is a LIST — a 300-byte value is three strings on
    /// the wire, and joining them on read would not round-trip.
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Caa {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    /// DNSSEC delegation signer (RFC 4034 §5.1).
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    /// DNSSEC public key (RFC 4034 §2.1). `flags` bit 7 (`0x0100`) is the zone-key bit, bit 15
    /// (`0x0001`) the secure-entry-point (KSK) bit.
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    /// DNSSEC signature (RFC 4034 §3.1). `expiration`/`inception` are 32-bit *serial-number
    /// arithmetic* timestamps (RFC 4034 §3.1.5), not plain unix seconds past 2106 — see
    /// [`serial_secs_until`].
    Rrsig {
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
        signature: Vec<u8>,
    },
    /// Authenticated denial (RFC 4034 §4.1): the next owner name and the raw type bit maps
    /// (read them with [`nsec_types`]). Modelled only so a signed zone's negative answers parse.
    Nsec { next: Name, type_bitmaps: Vec<u8> },
    /// A type this enum does not model, carried through verbatim.
    Unknown(u16, Vec<u8>),
}

/// DNSKEY flag: the key is a zone key (RFC 4034 §2.1.1).
pub const DNSKEY_ZONE: u16 = 0x0100;
/// DNSKEY flag: secure entry point, i.e. a KSK (RFC 4034 §2.1.1, RFC 3757).
pub const DNSKEY_SEP: u16 = 0x0001;

/// The RFC 4034 appendix B key tag of a DNSKEY — the 16-bit hint an RRSIG and a DS carry to say
/// which key they refer to. Not a security property (collisions are easy); a DS match also checks
/// the algorithm and the digest.
#[must_use]
pub fn dnskey_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let rdata = dnskey_rdata(flags, protocol, algorithm, public_key);
    if algorithm == 1 {
        // RSA/MD5 (long obsolete): the tag is the next-to-last 16 bits of the modulus.
        return match rdata.len().checked_sub(3).and_then(|i| rdata.get(i..i + 2)) {
            Some(b) => u16::from_be_bytes([b[0], b[1]]),
            None => 0,
        };
    }
    let mut acc: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        acc = acc.wrapping_add(if i & 1 == 1 { u32::from(*b) } else { u32::from(*b) << 8 });
    }
    acc = acc.wrapping_add((acc >> 16) & 0xFFFF);
    u16::try_from(acc & 0xFFFF).unwrap_or(0)
}

/// The DNSKEY RDATA wire form (`flags ‖ protocol ‖ algorithm ‖ public key`) — what a key tag and a
/// DS digest are computed over.
#[must_use]
pub fn dnskey_rdata(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public_key.len());
    out.extend_from_slice(&flags.to_be_bytes());
    out.push(protocol);
    out.push(algorithm);
    out.extend_from_slice(public_key);
    out
}

/// Seconds from `now` (unix seconds) until the RRSIG timestamp `ts`, negative when it is in the
/// past. RRSIG times are 32-bit serial numbers compared with RFC 1982 arithmetic, so the answer
/// is right across the 2106 wrap as long as the two are within ±68 years — which any signature
/// that matters is.
#[must_use]
pub fn serial_secs_until(ts: u32, now: i64) -> i64 {
    // Truncation of `now` to 32 bits is the point: serial arithmetic works modulo 2^32.
    let now32 = u32::try_from(now.rem_euclid(1 << 32)).unwrap_or(0);
    i64::from(i32::from_ne_bytes(ts.wrapping_sub(now32).to_ne_bytes()))
}

/// The record types named by an NSEC/NSEC3 type bit map (RFC 4034 §4.1.2). `None` if the map is
/// malformed (a window block that overruns, an empty or over-long block, or windows that do not
/// strictly increase) — never a panic on hostile input.
#[must_use]
pub fn nsec_types(bitmaps: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut last_window: Option<u8> = None;
    while i < bitmaps.len() {
        let window = *bitmaps.get(i)?;
        let len = usize::from(*bitmaps.get(i + 1)?);
        if len == 0 || len > 32 || last_window.is_some_and(|w| window <= w) {
            return None;
        }
        let block = bitmaps.get(i + 2..i + 2 + len)?;
        for (byte_i, byte) in block.iter().enumerate() {
            for bit in 0..8u16 {
                if byte & (0x80 >> bit) != 0 {
                    out.push(u16::from(window) * 256 + u16::try_from(byte_i).ok()? * 8 + bit);
                }
            }
        }
        last_window = Some(window);
        i += 2 + len;
    }
    Some(out)
}

impl RData {
    /// The record type this payload belongs to.
    #[must_use]
    pub fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::Aaaa(_) => RecordType::Aaaa,
            RData::Ns(_) => RecordType::Ns,
            RData::Cname(_) => RecordType::Cname,
            RData::Soa { .. } => RecordType::Soa,
            RData::Txt(_) => RecordType::Txt,
            RData::Srv { .. } => RecordType::Srv,
            RData::Caa { .. } => RecordType::Caa,
            RData::Ds { .. } => RecordType::DS,
            RData::Dnskey { .. } => RecordType::DNSKEY,
            RData::Rrsig { .. } => RecordType::RRSIG,
            RData::Nsec { .. } => RecordType::NSEC,
            RData::Unknown(c, _) => RecordType::Unknown(*c),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            RData::Ns(n) | RData::Cname(n) => n.encode(out),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                mname.encode(out);
                rname.encode(out);
                for v in [serial, refresh, retry, expire, minimum] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            RData::Txt(strings) => {
                for s in strings {
                    out.push(u8::try_from(s.len()).unwrap_or(255));
                    out.extend_from_slice(&s[..s.len().min(255)]);
                }
            }
            RData::Srv { priority, weight, port, target } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                target.encode(out);
            }
            RData::Caa { flags, tag, value } => {
                out.push(*flags);
                out.push(u8::try_from(tag.len()).unwrap_or(0));
                out.extend_from_slice(tag.as_bytes());
                out.extend_from_slice(value);
            }
            RData::Ds { key_tag, algorithm, digest_type, digest } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.push(*algorithm);
                out.push(*digest_type);
                out.extend_from_slice(digest);
            }
            RData::Dnskey { flags, protocol, algorithm, public_key } => {
                out.extend_from_slice(&dnskey_rdata(*flags, *protocol, *algorithm, public_key));
            }
            RData::Rrsig { type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature } => {
                out.extend_from_slice(&type_covered.code().to_be_bytes());
                out.push(*algorithm);
                out.push(*labels);
                for v in [original_ttl, expiration, inception] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out.extend_from_slice(&key_tag.to_be_bytes());
                signer.encode(out); // RFC 4034 §3.1.7: never compressed
                out.extend_from_slice(signature);
            }
            RData::Nsec { next, type_bitmaps } => {
                next.encode(out); // RFC 4034 §4.1.1: never compressed
                out.extend_from_slice(type_bitmaps);
            }
            RData::Unknown(_, raw) => out.extend_from_slice(raw),
        }
    }

    fn decode(buf: &[u8], pos: usize, len: usize, rtype: RecordType) -> Result<Self, DnsError> {
        let body = buf.get(pos..pos + len).ok_or(DnsError::Truncated)?;
        let be32 = |b: &[u8], i: usize| -> Result<u32, DnsError> {
            Ok(u32::from_be_bytes(
                b.get(i..i + 4)
                    .ok_or(DnsError::Truncated)?
                    .try_into()
                    .map_err(|_| DnsError::Truncated)?,
            ))
        };
        let be16 = |b: &[u8], i: usize| -> Result<u16, DnsError> {
            Ok(u16::from_be_bytes(
                b.get(i..i + 2)
                    .ok_or(DnsError::Truncated)?
                    .try_into()
                    .map_err(|_| DnsError::Truncated)?,
            ))
        };
        Ok(match rtype {
            RecordType::A => {
                let o: [u8; 4] = body.try_into().map_err(|_| DnsError::Truncated)?;
                RData::A(Ipv4Addr::from(o))
            }
            RecordType::Aaaa => {
                let o: [u8; 16] = body.try_into().map_err(|_| DnsError::Truncated)?;
                RData::Aaaa(Ipv6Addr::from(o))
            }
            // Names inside RDATA may themselves be compressed, so they decode against the WHOLE
            // buffer, not the slice — a pointer can reach back before `pos`.
            RecordType::Ns => RData::Ns(Name::decode(buf, pos)?.0),
            RecordType::Cname => RData::Cname(Name::decode(buf, pos)?.0),
            RecordType::Soa => {
                let (mname, a) = Name::decode(buf, pos)?;
                let (rname, b) = Name::decode(buf, a)?;
                let rest = buf.get(b..pos + len).ok_or(DnsError::Truncated)?;
                RData::Soa {
                    mname,
                    rname,
                    serial: be32(rest, 0)?,
                    refresh: be32(rest, 4)?,
                    retry: be32(rest, 8)?,
                    expire: be32(rest, 12)?,
                    minimum: be32(rest, 16)?,
                }
            }
            RecordType::Txt => {
                let mut strings = Vec::new();
                let mut i = 0usize;
                while i < body.len() {
                    let n = usize::from(body[i]);
                    let s = body.get(i + 1..i + 1 + n).ok_or(DnsError::Truncated)?;
                    strings.push(s.to_vec());
                    i += 1 + n;
                }
                RData::Txt(strings)
            }
            RecordType::Srv => RData::Srv {
                priority: be16(body, 0)?,
                weight: be16(body, 2)?,
                port: be16(body, 4)?,
                target: Name::decode(buf, pos + 6)?.0,
            },
            RecordType::Caa => {
                let flags = *body.first().ok_or(DnsError::Truncated)?;
                let tl = usize::from(*body.get(1).ok_or(DnsError::Truncated)?);
                let tag = body.get(2..2 + tl).ok_or(DnsError::Truncated)?;
                RData::Caa {
                    flags,
                    tag: String::from_utf8_lossy(tag).into_owned(),
                    value: body.get(2 + tl..).unwrap_or(&[]).to_vec(),
                }
            }
            RecordType::DS => RData::Ds {
                key_tag: be16(body, 0)?,
                algorithm: *body.get(2).ok_or(DnsError::Truncated)?,
                digest_type: *body.get(3).ok_or(DnsError::Truncated)?,
                digest: body.get(4..).ok_or(DnsError::Truncated)?.to_vec(),
            },
            RecordType::DNSKEY => RData::Dnskey {
                flags: be16(body, 0)?,
                protocol: *body.get(2).ok_or(DnsError::Truncated)?,
                algorithm: *body.get(3).ok_or(DnsError::Truncated)?,
                public_key: body.get(4..).ok_or(DnsError::Truncated)?.to_vec(),
            },
            RecordType::RRSIG => {
                // type(2) alg(1) labels(1) ottl(4) exp(4) inc(4) tag(2) = 18 fixed bytes, then the
                // signer name, then the signature to the end of the RDATA. The fixed part is
                // checked first so the name is never read from outside the record.
                if body.len() < 18 {
                    return Err(DnsError::Truncated);
                }
                let (signer, after) = Name::decode(buf, pos + 18)?;
                // The name must end inside this record, or its "signature" would be read out of
                // the next record.
                let signature = buf.get(after..pos + len).ok_or(DnsError::Truncated)?.to_vec();
                RData::Rrsig {
                    type_covered: RecordType::from_code(be16(body, 0)?),
                    algorithm: *body.get(2).ok_or(DnsError::Truncated)?,
                    labels: *body.get(3).ok_or(DnsError::Truncated)?,
                    original_ttl: be32(body, 4)?,
                    expiration: be32(body, 8)?,
                    inception: be32(body, 12)?,
                    key_tag: be16(body, 16)?,
                    signer,
                    signature,
                }
            }
            RecordType::NSEC => {
                let (next, after) = Name::decode(buf, pos)?;
                RData::Nsec { next, type_bitmaps: buf.get(after..pos + len).ok_or(DnsError::Truncated)?.to_vec() }
            }
            RecordType::Unknown(c) => RData::Unknown(c, body.to_vec()),
        })
    }
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    /// Wire class; `1` is IN, and nothing else occurs in practice.
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

impl Record {
    /// An IN-class record with `ttl` seconds.
    #[must_use]
    pub fn new(name: Name, ttl: u32, data: RData) -> Self {
        Record { name, class: 1, ttl, data }
    }
}

/// One question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: u16,
}

impl Question {
    /// An IN-class question.
    #[must_use]
    pub fn new(name: Name, qtype: RecordType) -> Self {
        Question { name, qtype, qclass: 1 }
    }
}

/// The 4-bit response code (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl ResponseCode {
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NxDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Other(c) => c,
        }
    }
    #[must_use]
    pub fn from_code(c: u8) -> Self {
        match c & 0x0F {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NxDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            other => ResponseCode::Other(other),
        }
    }
}

/// The header's flag word, unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// false = query, true = response.
    pub response: bool,
    /// 0 = standard query; anything else we answer `NotImp`.
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
}

impl Default for ResponseCode {
    fn default() -> Self {
        ResponseCode::NoError
    }
}

impl Flags {
    fn to_bits(self) -> u16 {
        let mut v = 0u16;
        if self.response {
            v |= 0x8000;
        }
        v |= u16::from(self.opcode & 0x0F) << 11;
        if self.authoritative {
            v |= 0x0400;
        }
        if self.truncated {
            v |= 0x0200;
        }
        if self.recursion_desired {
            v |= 0x0100;
        }
        if self.recursion_available {
            v |= 0x0080;
        }
        v |= u16::from(self.response_code.code() & 0x0F);
        v
    }

    fn from_bits(v: u16) -> Self {
        Flags {
            response: v & 0x8000 != 0,
            opcode: u8::try_from((v >> 11) & 0x0F).unwrap_or(0),
            authoritative: v & 0x0400 != 0,
            truncated: v & 0x0200 != 0,
            recursion_desired: v & 0x0100 != 0,
            recursion_available: v & 0x0080 != 0,
            response_code: ResponseCode::from_code(u8::try_from(v & 0x0F).unwrap_or(0)),
        }
    }
}

/// A complete DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// A response shell echoing `id`, with QR set.
    #[must_use]
    pub fn response(id: u16) -> Self {
        Message {
            id,
            flags: Flags { response: true, ..Flags::default() },
            ..Message::default()
        }
    }

    /// A response carrying nothing but an error code — the shape an authority returns for a
    /// query it will not serve.
    #[must_use]
    pub fn error(id: u16, opcode: u8, code: ResponseCode) -> Self {
        Message {
            id,
            flags: Flags { response: true, opcode, response_code: code, ..Flags::default() },
            ..Message::default()
        }
    }

    /// Encode to the wire. Never compressed — see the module doc for why that is a requirement
    /// and not a shortcut.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_bits().to_be_bytes());
        for n in [
            self.questions.len(),
            self.answers.len(),
            self.authorities.len(),
            self.additionals.len(),
        ] {
            out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        }
        for q in &self.questions {
            q.name.encode(&mut out);
            out.extend_from_slice(&q.qtype.code().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for r in section {
                r.name.encode(&mut out);
                out.extend_from_slice(&r.data.record_type().code().to_be_bytes());
                out.extend_from_slice(&r.class.to_be_bytes());
                out.extend_from_slice(&r.ttl.to_be_bytes());
                // length-prefixed payload: write a placeholder, fill it once the length is known
                let at = out.len();
                out.extend_from_slice(&[0, 0]);
                r.data.encode(&mut out);
                let len = u16::try_from(out.len() - at - 2).unwrap_or(u16::MAX);
                out[at..at + 2].copy_from_slice(&len.to_be_bytes());
            }
        }
        out
    }

    /// Decode from the wire.
    ///
    /// # Errors
    /// [`DnsError`] if the buffer is truncated, a name is malformed, or a compression pointer
    /// does not point strictly backwards.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, DnsError> {
        let hdr = buf.get(0..12).ok_or(DnsError::Truncated)?;
        let be16 = |i: usize| u16::from_be_bytes([hdr[i], hdr[i + 1]]);
        let (id, flags) = (be16(0), Flags::from_bits(be16(2)));
        let (nq, na, nauth, nadd) = (be16(4), be16(6), be16(8), be16(10));

        let mut pos = 12usize;
        let mut questions = Vec::new();
        for _ in 0..nq {
            let (name, next) = Name::decode(buf, pos)?;
            let t = buf.get(next..next + 4).ok_or(DnsError::Truncated)?;
            questions.push(Question {
                name,
                qtype: RecordType::from_code(u16::from_be_bytes([t[0], t[1]])),
                qclass: u16::from_be_bytes([t[2], t[3]]),
            });
            pos = next + 4;
        }

        let read_section = |count: u16, pos: &mut usize| -> Result<Vec<Record>, DnsError> {
            let mut out = Vec::new();
            for _ in 0..count {
                let (name, next) = Name::decode(buf, *pos)?;
                let h = buf.get(next..next + 10).ok_or(DnsError::Truncated)?;
                let rtype = RecordType::from_code(u16::from_be_bytes([h[0], h[1]]));
                let class = u16::from_be_bytes([h[2], h[3]]);
                let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
                let rdlen = usize::from(u16::from_be_bytes([h[8], h[9]]));
                let data = RData::decode(buf, next + 10, rdlen, rtype)?;
                out.push(Record { name, class, ttl, data });
                *pos = next + 10 + rdlen;
            }
            Ok(out)
        };
        let answers = read_section(na, &mut pos)?;
        let authorities = read_section(nauth, &mut pos)?;
        let additionals = read_section(nadd, &mut pos)?;

        Ok(Message { id, flags, questions, answers, authorities, additionals })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn a_name_round_trips_through_presentation_form() {
        assert_eq!(n("www.example.com").to_ascii(), "www.example.com.");
        assert_eq!(n("www.example.com.").labels().len(), 3);
        assert_eq!(Name::from_ascii(".").unwrap(), Name::root());
        assert_eq!(Name::from_ascii("").unwrap(), Name::root());
    }

    /// DNS is case-insensitive, so a query for `WWW.EXAMPLE.COM` must match a zone written in
    /// lower case. Getting this wrong makes an authority intermittently NXDOMAIN.
    #[test]
    fn names_compare_without_regard_to_case() {
        assert_eq!(n("WWW.Example.COM"), n("www.example.com"));
        assert!(n("a.b.EXAMPLE.com").is_subdomain_of(&n("example.COM")));
        assert!(!n("example.com").is_subdomain_of(&n("a.example.com")));
        assert!(n("example.com").is_subdomain_of(&n("example.com")));
    }

    #[test]
    fn a_label_over_sixty_three_bytes_is_refused() {
        let long = "a".repeat(64);
        assert_eq!(Name::from_ascii(&long), Err(DnsError::NameTooLong));
        assert_eq!(Name::from_ascii("a..b"), Err(DnsError::BadLabel));
    }

    #[test]
    fn every_modelled_rdata_round_trips_through_the_wire() {
        let cases = vec![
            RData::A("192.0.2.1".parse().unwrap()),
            RData::Aaaa("2001:db8::1".parse().unwrap()),
            RData::Ns(n("ns1.example.com")),
            RData::Cname(n("target.example.com")),
            RData::Txt(vec![b"v=spf1 -all".to_vec()]),
            RData::Srv { priority: 10, weight: 5, port: 8443, target: n("svc.example.com") },
            RData::Caa { flags: 0, tag: "issue".into(), value: b"letsencrypt.org".to_vec() },
            RData::Soa {
                mname: n("ns1.example.com"),
                rname: n("hostmaster.example.com"),
                serial: 2026_08_15,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 300,
            },
            RData::Unknown(99, vec![1, 2, 3, 4]),
        ];
        for data in cases {
            let mut m = Message::response(0x1234);
            m.answers.push(Record::new(n("example.com"), 300, data.clone()));
            let back = Message::from_bytes(&m.to_bytes()).expect("round trip");
            assert_eq!(back.answers.len(), 1, "{data:?}");
            assert_eq!(back.answers[0].data, data, "{data:?}");
        }
    }

    /// TXT is a LIST of character-strings on the wire. A 300-byte value is legally three
    /// strings, and joining them on read would not round-trip.
    #[test]
    fn txt_keeps_its_strings_separate() {
        let data = RData::Txt(vec![b"part-one".to_vec(), b"part-two".to_vec()]);
        let mut m = Message::response(1);
        m.answers.push(Record::new(n("x.example.com"), 60, data.clone()));
        let back = Message::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(back.answers[0].data, data);
    }

    #[test]
    fn the_header_flags_survive_a_round_trip() {
        let mut m = Message::response(0xBEEF);
        m.flags.authoritative = true;
        m.flags.recursion_desired = true;
        m.flags.recursion_available = false;
        m.flags.response_code = ResponseCode::NxDomain;
        m.questions.push(Question::new(n("example.com"), RecordType::A));
        let back = Message::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(back.id, 0xBEEF);
        assert_eq!(back.flags, m.flags);
        assert_eq!(back.questions, m.questions);
    }

    /// A real resolver's query, hand-built with a compression pointer in the answer section —
    /// the shape this decoder has to accept even though it never emits it.
    #[test]
    fn a_compressed_name_decodes_to_the_name_it_points_at() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001u16.to_be_bytes()); // id
        buf.extend_from_slice(&0x8400u16.to_be_bytes()); // response + authoritative
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&1u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let qname_at = buf.len();
        n("example.com").encode(&mut buf);
        buf.extend_from_slice(&1u16.to_be_bytes()); // A
        buf.extend_from_slice(&1u16.to_be_bytes()); // IN
        // the answer's name is a POINTER back to the question's name
        buf.push(0xC0);
        buf.push(u8::try_from(qname_at).unwrap());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[192, 0, 2, 7]);

        let m = Message::from_bytes(&buf).expect("a compressed message must decode");
        assert_eq!(m.questions[0].name, n("example.com"));
        assert_eq!(m.answers[0].name, n("example.com"), "the pointer resolved");
        assert_eq!(m.answers[0].data, RData::A("192.0.2.7".parse().unwrap()));
    }

    /// A pointer that does not go strictly backwards is refused rather than followed. Without
    /// this rule a self-referential packet parks a thread forever — a remote input hanging the
    /// server that read it.
    #[test]
    fn a_self_referential_pointer_is_refused_not_followed() {
        let mut buf = vec![0u8; 12];
        buf[4] = 0;
        buf[5] = 1; // one question
        let at = buf.len();
        buf.push(0xC0);
        buf.push(u8::try_from(at).unwrap()); // points at ITSELF
        buf.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(Message::from_bytes(&buf), Err(DnsError::BadPointer));

        // and a forward pointer, likewise
        let mut fwd = vec![0u8; 12];
        fwd[5] = 1;
        fwd.push(0xC0);
        fwd.push(200);
        fwd.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(Message::from_bytes(&fwd), Err(DnsError::BadPointer));
    }

    #[test]
    fn a_truncated_message_is_an_error_not_a_panic() {
        let mut m = Message::response(7);
        m.answers.push(Record::new(n("example.com"), 60, RData::A(Ipv4Addr::LOCALHOST)));
        let full = m.to_bytes();
        for cut in 0..full.len() {
            // must never panic; the only acceptable outcomes are Ok or a DnsError
            let _ = Message::from_bytes(&full[..cut]);
        }
    }

    /// The encoder is deterministic: the same records always produce the same bytes. A signed
    /// record depends on this — a signature over a non-deterministic encoding is unverifiable.
    #[test]
    fn encoding_is_deterministic() {
        let mut m = Message::response(42);
        m.answers.push(Record::new(n("a.example.com"), 300, RData::A(Ipv4Addr::LOCALHOST)));
        m.answers.push(Record::new(
            n("b.example.com"),
            300,
            RData::Txt(vec![b"hello".to_vec()]),
        ));
        assert_eq!(m.to_bytes(), m.to_bytes());
        assert_eq!(Message::from_bytes(&m.to_bytes()).unwrap().to_bytes(), m.to_bytes());
    }

    // ── DNSSEC records (RFC 4034) ─────────────────────────────────────────────────────────

    /// The DNSKEY from RFC 4034 §5.4 (`dskey.example.com`, key id 60485).
    const RFC4034_KEY_B64: &str =
        "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==";

    fn rfc4034_key() -> Vec<u8> {
        crate::pem::base64_decode(RFC4034_KEY_B64).unwrap()
    }

    fn dnssec_samples() -> Vec<RData> {
        vec![
            RData::Ds { key_tag: 60485, algorithm: 5, digest_type: 2, digest: vec![0xd4; 32] },
            RData::Ds { key_tag: 1, algorithm: 13, digest_type: 4, digest: Vec::new() },
            RData::Dnskey { flags: 257, protocol: 3, algorithm: 13, public_key: vec![7; 64] },
            RData::Dnskey { flags: 256, protocol: 3, algorithm: 15, public_key: Vec::new() },
            RData::Rrsig {
                type_covered: RecordType::DNSKEY,
                algorithm: 13,
                labels: 2,
                original_ttl: 3600,
                expiration: 1_800_000_000,
                inception: 1_790_000_000,
                key_tag: 4242,
                signer: n("Example.COM"),
                signature: vec![0xab; 64],
            },
            RData::Rrsig {
                type_covered: RecordType::Unknown(999),
                algorithm: 8,
                labels: 0,
                original_ttl: 0,
                expiration: u32::MAX,
                inception: 0,
                key_tag: 0,
                signer: Name::root(),
                signature: Vec::new(),
            },
            RData::Nsec { next: n("b.example.com"), type_bitmaps: vec![0, 6, 0x40, 0x01, 0, 0, 0, 0x03] },
            RData::Nsec { next: Name::root(), type_bitmaps: Vec::new() },
        ]
    }

    #[test]
    fn dnssec_records_round_trip_through_the_wire() {
        for data in dnssec_samples() {
            let mut m = Message::response(0x4242);
            m.answers.push(Record::new(n("example.com"), 300, data.clone()));
            // a record after it proves the RDLENGTH bookkeeping leaves the stream aligned
            m.answers.push(Record::new(n("example.com"), 300, RData::A(Ipv4Addr::LOCALHOST)));
            let back = Message::from_bytes(&m.to_bytes()).unwrap_or_else(|e| panic!("{data:?}: {e}"));
            assert_eq!(back.answers.len(), 2, "{data:?}");
            assert_eq!(back.answers[0].data, data);
            assert_eq!(back.answers[1].data, RData::A(Ipv4Addr::LOCALHOST));
            assert_eq!(back.to_bytes(), m.to_bytes(), "encoding is canonical for {data:?}");
        }
    }

    #[test]
    fn dnssec_record_types_are_the_unknown_codes_underneath() {
        for (t, code) in [(RecordType::DS, 43), (RecordType::RRSIG, 46), (RecordType::NSEC, 47), (RecordType::DNSKEY, 48)] {
            assert_eq!(t.code(), code);
            assert_eq!(RecordType::from_code(code), t);
        }
        assert_eq!(RData::Ds { key_tag: 0, algorithm: 0, digest_type: 0, digest: vec![] }.record_type(), RecordType::DS);
        assert_eq!(RData::Nsec { next: Name::root(), type_bitmaps: vec![] }.record_type(), RecordType::NSEC);
        // A DS that arrives as a record this build does not recognise would be `Unknown(43, ..)`;
        // the wire decoder must turn it into the typed payload.
        let mut m = Message::response(1);
        m.answers.push(Record::new(n("x.example"), 5, RData::Unknown(43, vec![0, 9, 13, 2, 0xaa])));
        let back = Message::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(back.answers[0].data, RData::Ds { key_tag: 9, algorithm: 13, digest_type: 2, digest: vec![0xaa] });
    }

    #[test]
    fn key_tag_matches_the_rfc_4034_worked_example() {
        assert_eq!(dnskey_key_tag(256, 3, 5, &rfc4034_key()), 60485);
        // The tag depends on every byte of the key and on the flags.
        let mut other = rfc4034_key();
        other[10] ^= 1;
        assert_ne!(dnskey_key_tag(256, 3, 5, &other), 60485);
        assert_ne!(dnskey_key_tag(257, 3, 5, &rfc4034_key()), 60485);
        // The obsolete RSA/MD5 form and degenerate input neither panic nor read out of range.
        let _ = dnskey_key_tag(256, 3, 1, &rfc4034_key());
        let _ = dnskey_key_tag(0, 0, 1, &[]);
        let _ = dnskey_key_tag(0, 0, 8, &[]);
    }

    #[test]
    fn canonical_wire_lowercases_and_never_compresses() {
        assert_eq!(n("DsKey.Example.COM").canonical_wire(), b"\x05dskey\x07example\x03com\x00".to_vec());
        assert_eq!(Name::root().canonical_wire(), vec![0]);
    }

    #[test]
    fn rrsig_times_use_serial_arithmetic() {
        let now = 1_800_000_000i64;
        assert_eq!(serial_secs_until(1_800_000_100, now), 100);
        assert_eq!(serial_secs_until(1_799_999_000, now), -1000);
        assert_eq!(serial_secs_until(1_800_000_000, now), 0);
        // Across the 2106 wrap: `now` just before 2^32, the signature expiring just after it.
        let near_wrap = (1i64 << 32) - 10;
        assert_eq!(serial_secs_until(5, near_wrap), 15, "expires 15 s after the 32-bit counter wraps");
        assert_eq!(serial_secs_until(u32::MAX - 20, near_wrap), -11);
        // And past the wrap on the clock side.
        assert_eq!(serial_secs_until(100, (1i64 << 32) + 40), 60);
    }

    #[test]
    fn nsec_type_bitmaps_decode_and_malformed_ones_are_none() {
        // window 0: bits for A(1), MX(15), RRSIG(46)=window0 byte5 bit6, NSEC(47); window 1: CAA(257)
        let bm = [0u8, 6, 0x40, 0x01, 0, 0, 0, 0x03, 1, 1, 0x40];
        assert_eq!(nsec_types(&bm), Some(vec![1, 15, 46, 47, 257]));
        assert_eq!(nsec_types(&[]), Some(vec![]));
        for bad in [&[0u8][..], &[0, 0][..], &[0, 33, 1][..], &[0, 2, 1][..], &[1, 1, 0x80, 0, 1, 0x80][..], &[0, 1, 0x80, 0, 1, 0x80][..]] {
            assert_eq!(nsec_types(bad), None, "{bad:?}");
        }
    }

    /// Wire bytes of a message holding one record of `rtype` with a raw RDATA, for hand-built
    /// malformed payloads.
    fn raw_record_message(rtype: u16, rdata: &[u8], rdlen_override: Option<u16>) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        buf[7] = 1; // one answer
        buf.extend_from_slice(b"\x01a\x00");
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&60u32.to_be_bytes());
        buf.extend_from_slice(&rdlen_override.unwrap_or(u16::try_from(rdata.len()).unwrap()).to_be_bytes());
        buf.extend_from_slice(rdata);
        buf
    }

    #[test]
    fn malformed_dnssec_rdata_is_an_error_not_a_panic() {
        // Too short for the fixed part, for every type.
        for rtype in [43u16, 46, 47, 48] {
            for len in 0..20usize {
                let rdata = vec![0u8; len];
                let r = Message::from_bytes(&raw_record_message(rtype, &rdata, None));
                // Whatever the outcome, it must not panic; the short ones must be refused.
                if (rtype == 43 || rtype == 48) && len < 4 || rtype == 46 && len < 19 {
                    assert!(r.is_err(), "type {rtype} len {len} must be refused: {r:?}");
                }
            }
        }
        // RDLENGTH larger than the packet.
        assert!(Message::from_bytes(&raw_record_message(48, &[1, 1, 3, 13], Some(500))).is_err());
        // An RRSIG whose signer name runs past the end of its own RDATA into the bytes after it.
        let mut rdata = vec![0u8; 18];
        rdata.extend_from_slice(b"\x05abcde"); // a label that the RDATA ends in the middle of
        let mut wire = raw_record_message(46, &rdata, None);
        wire.extend_from_slice(b"\x00tail-bytes-that-are-not-part-of-the-record");
        assert!(Message::from_bytes(&wire).is_err(), "the signer name must end inside its record");
        // A signer name that is a self pointer (header 12 + owner 3 + record header 10 + 18 fixed = 43).
        let mut rdata = vec![0u8; 18];
        rdata.extend_from_slice(&[0xC0, 43]);
        assert_eq!(Message::from_bytes(&raw_record_message(46, &rdata, None)), Err(DnsError::BadPointer));
        // NSEC with an unterminated next-name.
        assert!(Message::from_bytes(&raw_record_message(47, b"\x03abc", None)).is_err());
        // RRSIG with a pointer in the signer name is accepted (resolvers may compress it).
        let mut m = Message::response(3);
        m.questions.push(Question::new(n("example.com"), RecordType::DNSKEY));
        let mut wire = m.to_bytes();
        wire[7] = 1; // ancount = 1
        wire.extend_from_slice(&[0xC0, 12]); // owner: pointer to the question name
        wire.extend_from_slice(&46u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        let mut rd = vec![0u8, 48, 13, 2, 0, 0, 0x0e, 0x10, 0x6b, 0x49, 0xd2, 0, 0x6a, 0xfc, 0xe9, 0x00, 0x10, 0x92];
        rd.extend_from_slice(&[0xC0, 12]); // signer: pointer
        rd.extend_from_slice(&[9u8; 8]);
        wire.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&rd);
        let back = Message::from_bytes(&wire).expect("compressed signer name");
        match &back.answers[0].data {
            RData::Rrsig { signer, signature, type_covered, .. } => {
                assert_eq!(*signer, n("example.com"));
                assert_eq!(signature, &vec![9u8; 8]);
                assert_eq!(*type_covered, RecordType::DNSKEY);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A tiny deterministic generator, so the fuzz-style tests are reproducible.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn garbage_and_mutated_dnssec_messages_never_panic() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        // Pure noise, with the header's section counts forced high so the record parser runs.
        for _ in 0..20_000 {
            let len = usize::try_from(rng.next() % 200).unwrap();
            let mut buf: Vec<u8> = (0..len).map(|_| u8::try_from(rng.next() & 0xff).unwrap()).collect();
            if buf.len() >= 12 {
                buf[4] = 0;
                buf[5] = 1;
                buf[6] = 0;
                buf[7] = u8::try_from(1 + rng.next() % 4).unwrap();
            }
            let _ = Message::from_bytes(&buf);
        }
        // Valid messages carrying every DNSSEC type, with random bit flips, truncation and
        // length-field corruption.
        let mut m = Message::response(9);
        m.questions.push(Question::new(n("example.com"), RecordType::DNSKEY));
        for data in dnssec_samples() {
            m.answers.push(Record::new(n("example.com"), 1, data));
        }
        let good = m.to_bytes();
        assert_eq!(Message::from_bytes(&good).unwrap().answers.len(), m.answers.len());
        for _ in 0..30_000 {
            let mut buf = good.clone();
            for _ in 0..(1 + rng.next() % 4) {
                let at = usize::try_from(rng.next()).unwrap() % buf.len();
                buf[at] ^= u8::try_from(1 + rng.next() % 255).unwrap();
            }
            if rng.next().is_multiple_of(3) {
                buf.truncate(usize::try_from(rng.next()).unwrap() % (buf.len() + 1));
            }
            let _ = Message::from_bytes(&buf);
        }
        for cut in 0..good.len() {
            let _ = Message::from_bytes(&good[..cut]);
        }
    }
}
