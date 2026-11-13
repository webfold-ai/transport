//! ClientHello SNI peeking — the front half of SNI-routed TLS **passthrough**.
//!
//! The edge normally terminates TLS with a certificate for the name ([`crate::edge_proxy::sni`]).
//! A customer who needs end-to-end TLS to their own origin (their certificate, their client-cert
//! policy, no platform in the plaintext path) needs the opposite: read just enough of the first
//! flight to learn the *server name*, pick the tunnel for it, and splice the raw bytes through
//! without ever holding a key. Only the SNI is visible before the handshake completes, so SNI is
//! the whole routing input.
//!
//! This module is that peek and nothing else: a pure, allocation-light, bounds-checked parser
//! over the bytes read so far. It is attacker-facing (the first bytes of any connection to the
//! edge reach it), so it is deliberately strict:
//!
//! - anything that is not a TLS handshake record carrying a ClientHello is [`Hello::Invalid`];
//! - a ClientHello fragmented across several records is [`Hello::Invalid`] too (real clients do
//!   not fragment it; allowing it would mean buffering attacker-controlled amounts);
//! - at most one `server_name` extension and one `host_name` entry (ambiguity between what the
//!   router sees and what the origin sees is a routing-bypass primitive);
//! - the name must be a plain DNS name; IP literals are not permitted in SNI (RFC 6066 §3).
//!
//! The caller owns the policy: read until the answer is not [`Hello::NeedMore`], with a hard cap
//! of [`MAX_HELLO_BYTES`] and a short timeout, then decide with
//! [`crate::edge_proxy::decide_passthrough`]. The bytes peeked must be replayed to the origin
//! unchanged.

/// Most bytes a ClientHello record can occupy (5-byte header + 2^14 payload). A caller that has
/// read this many without a verdict should drop the connection.
pub const MAX_HELLO_BYTES: usize = 5 + 16_384;

/// What the bytes read so far say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hello {
    /// A ClientHello naming this host (lowercased, no trailing dot).
    Sni(String),
    /// A well-formed ClientHello with no `server_name`. Cannot be routed.
    NoSni,
    /// Not enough bytes yet; read more and call again.
    NeedMore,
    /// Not a ClientHello we are willing to route. Close the connection.
    Invalid,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A plain DNS name as SNI carries it: ASCII letters/digits/hyphen/dot, labels 1-63, total <= 253,
/// not an IPv4 literal. Returned lowercased.
fn clean_host(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?.to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.contains("..") || s.starts_with('.') || s.ends_with('.') {
        return None;
    }
    let ok_chars = s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let ok_labels = s
        .split('.')
        .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'));
    let is_ipv4_literal = s.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    (ok_chars && ok_labels && !is_ipv4_literal).then_some(s)
}

/// Inspect the first bytes of a connection.
#[must_use]
pub fn peek_sni(buf: &[u8]) -> Hello {
    // Reject early on the first byte so a non-TLS client is not held waiting for 5 bytes.
    match buf.first() {
        None => return Hello::NeedMore,
        Some(0x16) => {}
        Some(_) => return Hello::Invalid,
    }
    if let Some(&major) = buf.get(1) {
        if major != 3 {
            return Hello::Invalid;
        }
    }
    let Some(header) = buf.get(..5) else {
        return Hello::NeedMore;
    };
    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_len == 0 || record_len > 16_384 {
        return Hello::Invalid;
    }
    let Some(record) = buf.get(5..5 + record_len) else {
        return Hello::NeedMore;
    };

    // From here the record is complete: any shortfall inside it is malformed, not "read more".
    parse_client_hello(record).map_or(Hello::Invalid, |h| h)
}

fn parse_client_hello(record: &[u8]) -> Option<Hello> {
    let mut r = Reader(record);
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let len_bytes = r.take(3)?;
    let hs_len = (usize::from(len_bytes[0]) << 16)
        | (usize::from(len_bytes[1]) << 8)
        | usize::from(len_bytes[2]);
    // The handshake message must fit in this record: fragmentation across records is refused.
    let mut hello = Reader(r.take(hs_len)?);
    if !r.is_empty() {
        return None; // trailing data after the ClientHello in the same record
    }

    hello.take(2)?; // legacy_version
    hello.take(32)?; // random
    hello.vec8()?; // legacy_session_id
    let suites = hello.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    if hello.vec8()?.is_empty() {
        return None; // legacy_compression_methods must carry at least "null"
    }
    if hello.is_empty() {
        return Some(Hello::NoSni); // TLS <= 1.1 style hello without extensions
    }
    let mut exts = Reader(hello.vec16()?);
    if !hello.is_empty() {
        return None;
    }

    let mut found: Option<String> = None;
    let mut seen_sni_ext = false;
    while !exts.is_empty() {
        let ext_type = exts.u16()?;
        let data = exts.vec16()?;
        if ext_type != 0 {
            continue;
        }
        if seen_sni_ext {
            return None; // duplicate server_name extension
        }
        seen_sni_ext = true;
        let mut list = Reader(Reader(data).vec16()?);
        while !list.is_empty() {
            let name_type = list.u8()?;
            let name = list.vec16()?;
            if name_type != 0 {
                continue; // unknown name types are skipped per RFC 6066
            }
            if found.is_some() {
                return None; // more than one host_name
            }
            found = Some(clean_host(name)?);
        }
    }
    Some(found.map_or(Hello::NoSni, Hello::Sni))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    /// A genuine ClientHello, produced by the same rustls the edge serves with.
    fn real_hello(host: &str) -> Vec<u8> {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from(host.to_string()).unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn a_real_client_hello_yields_its_server_name() {
        assert_eq!(
            peek_sni(&real_hello("app.acme.com.au")),
            Hello::Sni("app.acme.com.au".into())
        );
        assert_eq!(
            peek_sni(&real_hello("amber-wren-1a2b3c.tascloud.app")),
            Hello::Sni("amber-wren-1a2b3c.tascloud.app".into())
        );
    }

    #[test]
    fn every_truncation_asks_for_more_or_is_rejected_and_never_panics() {
        let hello = real_hello("app.acme.com.au");
        for cut in 0..hello.len() {
            let v = peek_sni(&hello[..cut]);
            assert!(
                matches!(v, Hello::NeedMore),
                "a prefix of a good hello is only ever 'need more' (cut {cut}): {v:?}"
            );
        }
        assert!(matches!(peek_sni(&hello), Hello::Sni(_)));
    }

    #[test]
    fn non_tls_and_wrong_record_types_are_invalid_immediately() {
        assert_eq!(peek_sni(b"GET / HTTP/1.1\r\n"), Hello::Invalid);
        assert_eq!(
            peek_sni(b"G"),
            Hello::Invalid,
            "decided on the first byte, no waiting for five"
        );
        assert_eq!(
            peek_sni(&[0x16, 0x02, 0, 0, 5]),
            Hello::Invalid,
            "SSLv2-style major version"
        );
        assert_eq!(
            peek_sni(&[0x15, 3, 3, 0, 2, 1, 0]),
            Hello::Invalid,
            "alert record"
        );
        assert_eq!(
            peek_sni(&[0x16, 3, 1, 0, 0]),
            Hello::Invalid,
            "empty record"
        );
        assert_eq!(
            peek_sni(&[0x16, 3, 1, 0xff, 0xff]),
            Hello::Invalid,
            "oversized record length"
        );
        assert_eq!(peek_sni(&[]), Hello::NeedMore);
    }

    #[test]
    fn single_byte_corruptions_never_panic_and_never_invent_a_different_name() {
        let hello = real_hello("app.acme.com.au");
        for i in 0..hello.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut bad = hello.clone();
                bad[i] ^= flip;
                match peek_sni(&bad) {
                    Hello::Sni(h) => assert!(
                        h == "app.acme.com.au"
                            || h.bytes().all(|b| b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || b == b'-'
                                || b == b'.'),
                        "a corrupted hello may only yield a syntactically valid name: {h}"
                    ),
                    _ => {}
                }
            }
        }
    }

    /// Hand-built hello so the strictness rules can be probed precisely.
    fn build(exts: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.push(0); // session id
        body.extend([0, 2, 0x13, 0x01]); // one cipher suite
        body.extend([1, 0]); // null compression
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    fn sni_ext(names: &[(u8, &str)]) -> Vec<u8> {
        let mut list = Vec::new();
        for (t, n) in names {
            list.push(*t);
            list.extend((n.len() as u16).to_be_bytes());
            list.extend(n.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        let mut ext = vec![0, 0];
        ext.extend((data.len() as u16).to_be_bytes());
        ext.extend(data);
        ext
    }

    #[test]
    fn names_are_lowercased_and_must_be_plain_dns_names() {
        assert_eq!(
            peek_sni(&build(&sni_ext(&[(0, "App.ACME.com.au")]))),
            Hello::Sni("app.acme.com.au".into())
        );
        for bad in [
            "",
            "1.2.3.4",
            "a..b",
            ".a.b",
            "a.b.",
            "-a.example.com",
            "a_b.example.com",
            "exa mple.com",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert_eq!(
                peek_sni(&build(&sni_ext(&[(0, bad)]))),
                Hello::Invalid,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn ambiguous_server_name_encodings_are_refused() {
        let two_names = sni_ext(&[(0, "a.example.com"), (0, "b.example.com")]);
        assert_eq!(
            peek_sni(&build(&two_names)),
            Hello::Invalid,
            "two host_name entries"
        );
        let mut two_exts = sni_ext(&[(0, "a.example.com")]);
        two_exts.extend(sni_ext(&[(0, "b.example.com")]));
        assert_eq!(
            peek_sni(&build(&two_exts)),
            Hello::Invalid,
            "duplicate extension"
        );
        // Unknown name types are skipped, the host_name still counts.
        assert_eq!(
            peek_sni(&build(&sni_ext(&[(7, "ignored"), (0, "a.example.com")]))),
            Hello::Sni("a.example.com".into())
        );
    }

    #[test]
    fn a_hello_without_server_name_is_no_sni_not_an_error() {
        assert_eq!(peek_sni(&build(&[])), Hello::NoSni);
        let other_ext = [0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d]; // supported_groups only
        assert_eq!(peek_sni(&build(&other_ext)), Hello::NoSni);
    }

    #[test]
    fn a_hello_fragmented_across_records_or_with_trailing_junk_is_refused() {
        let mut rec = build(&sni_ext(&[(0, "a.example.com")]));
        // Claim a handshake length longer than the record holds (fragmentation).
        rec[7] = 0x7f;
        assert_eq!(peek_sni(&rec), Hello::Invalid);
        // Junk after the ClientHello inside the same record.
        let mut rec = build(&sni_ext(&[(0, "a.example.com")]));
        rec.push(0xaa);
        let n = u16::from_be_bytes([rec[3], rec[4]]) + 1;
        rec[3..5].copy_from_slice(&n.to_be_bytes());
        assert_eq!(peek_sni(&rec), Hello::Invalid);
    }
}
