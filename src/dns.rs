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
    /// A type this enum does not model, carried through verbatim.
    Unknown(u16, Vec<u8>),
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

        let mut read_section = |count: u16, pos: &mut usize| -> Result<Vec<Record>, DnsError> {
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
}
