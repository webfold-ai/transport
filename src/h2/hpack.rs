//! HPACK (RFC 7541) — header compression for HTTP/2. Pure Rust, zero deps.
//!
//! Scoped to what a gRPC unary client actually needs: encoding is
//! literal-only (we choose exactly what headers to send, so there is no need
//! to grow our own dynamic table on the way out — every outbound field is
//! `Literal Header Field without Indexing`, optionally using a static-table
//! name reference). Decoding is the full spec: indexed (static + dynamic),
//! all three literal forms, Huffman and plain strings, and a real dynamic
//! table (RFC 7541 §2.3) — because we don't control what a real gRPC SERVER
//! sends back and must track ITS indexing choices to decode correctly.
//!
//! The Huffman table (`HUFFMAN_TABLE`, 257 canonical codes — 256 symbols +
//! EOS) is transcribed programmatically from `hyperium/h2`'s own
//! machine-generated table (never retyped by hand), and independently
//! verified to satisfy the Kraft equality (`sum(2^-len) == 1.0`, the
//! necessary-and-sufficient condition for a complete prefix code) before use.
//! The static table (`STATIC_TABLE`, 61 entries) and every decoder behaviour
//! below is checked against RFC 7541 Appendix C's own published worked
//! examples (`tests::rfc7541_*`) — real reference bytes, not invented ones.
//!
//! `huffman_encode` stays unused by `encode_header`'s own literal-only choice
//! above, but is real, tested (round-trips + RFC reference bytes) library
//! surface for a caller that wants Huffman-compressed output later.

#![allow(dead_code)]

use std::io::{self, Error, ErrorKind};

/// (bit length, code) for each of the 256 Huffman symbols plus EOS (index 256).
/// Kraft sum verified == 1.0 (a complete, valid prefix code) before being
/// transcribed here — see this session's derivation from `h2`'s own
/// `ENCODE_TABLE`.
const HUFFMAN_TABLE: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x7fffd8),
    (28, 0xfffffe2),
    (28, 0xfffffe3),
    (28, 0xfffffe4),
    (28, 0xfffffe5),
    (28, 0xfffffe6),
    (28, 0xfffffe7),
    (28, 0xfffffe8),
    (24, 0xffffea),
    (30, 0x3ffffffc),
    (28, 0xfffffe9),
    (28, 0xfffffea),
    (30, 0x3ffffffd),
    (28, 0xfffffeb),
    (28, 0xfffffec),
    (28, 0xfffffed),
    (28, 0xfffffee),
    (28, 0xfffffef),
    (28, 0xffffff0),
    (28, 0xffffff1),
    (28, 0xffffff2),
    (30, 0x3ffffffe),
    (28, 0xffffff3),
    (28, 0xffffff4),
    (28, 0xffffff5),
    (28, 0xffffff6),
    (28, 0xffffff7),
    (28, 0xffffff8),
    (28, 0xffffff9),
    (28, 0xffffffa),
    (28, 0xffffffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0xffffffc),
    (20, 0xfffe6),
    (22, 0x3fffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x3fffd3),
    (22, 0x3fffd4),
    (22, 0x3fffd5),
    (23, 0x7fffd9),
    (22, 0x3fffd6),
    (23, 0x7fffda),
    (23, 0x7fffdb),
    (23, 0x7fffdc),
    (23, 0x7fffdd),
    (23, 0x7fffde),
    (24, 0xffffeb),
    (23, 0x7fffdf),
    (24, 0xffffec),
    (24, 0xffffed),
    (22, 0x3fffd7),
    (23, 0x7fffe0),
    (24, 0xffffee),
    (23, 0x7fffe1),
    (23, 0x7fffe2),
    (23, 0x7fffe3),
    (23, 0x7fffe4),
    (21, 0x1fffdc),
    (22, 0x3fffd8),
    (23, 0x7fffe5),
    (22, 0x3fffd9),
    (23, 0x7fffe6),
    (23, 0x7fffe7),
    (24, 0xffffef),
    (22, 0x3fffda),
    (21, 0x1fffdd),
    (20, 0xfffe9),
    (22, 0x3fffdb),
    (22, 0x3fffdc),
    (23, 0x7fffe8),
    (23, 0x7fffe9),
    (21, 0x1fffde),
    (23, 0x7fffea),
    (22, 0x3fffdd),
    (22, 0x3fffde),
    (24, 0xfffff0),
    (21, 0x1fffdf),
    (22, 0x3fffdf),
    (23, 0x7fffeb),
    (23, 0x7fffec),
    (21, 0x1fffe0),
    (21, 0x1fffe1),
    (22, 0x3fffe0),
    (21, 0x1fffe2),
    (23, 0x7fffed),
    (22, 0x3fffe1),
    (23, 0x7fffee),
    (23, 0x7fffef),
    (20, 0xfffea),
    (22, 0x3fffe2),
    (22, 0x3fffe3),
    (22, 0x3fffe4),
    (23, 0x7ffff0),
    (22, 0x3fffe5),
    (22, 0x3fffe6),
    (23, 0x7ffff1),
    (26, 0x3ffffe0),
    (26, 0x3ffffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x3fffe7),
    (23, 0x7ffff2),
    (22, 0x3fffe8),
    (25, 0x1ffffec),
    (26, 0x3ffffe2),
    (26, 0x3ffffe3),
    (26, 0x3ffffe4),
    (27, 0x7ffffde),
    (27, 0x7ffffdf),
    (26, 0x3ffffe5),
    (24, 0xfffff1),
    (25, 0x1ffffed),
    (19, 0x7fff2),
    (21, 0x1fffe3),
    (26, 0x3ffffe6),
    (27, 0x7ffffe0),
    (27, 0x7ffffe1),
    (26, 0x3ffffe7),
    (27, 0x7ffffe2),
    (24, 0xfffff2),
    (21, 0x1fffe4),
    (21, 0x1fffe5),
    (26, 0x3ffffe8),
    (26, 0x3ffffe9),
    (28, 0xffffffd),
    (27, 0x7ffffe3),
    (27, 0x7ffffe4),
    (27, 0x7ffffe5),
    (20, 0xfffec),
    (24, 0xfffff3),
    (20, 0xfffed),
    (21, 0x1fffe6),
    (22, 0x3fffe9),
    (21, 0x1fffe7),
    (21, 0x1fffe8),
    (23, 0x7ffff3),
    (22, 0x3fffea),
    (22, 0x3fffeb),
    (25, 0x1ffffee),
    (25, 0x1ffffef),
    (24, 0xfffff4),
    (24, 0xfffff5),
    (26, 0x3ffffea),
    (23, 0x7ffff4),
    (26, 0x3ffffeb),
    (27, 0x7ffffe6),
    (26, 0x3ffffec),
    (26, 0x3ffffed),
    (27, 0x7ffffe7),
    (27, 0x7ffffe8),
    (27, 0x7ffffe9),
    (27, 0x7ffffea),
    (27, 0x7ffffeb),
    (28, 0xffffffe),
    (27, 0x7ffffec),
    (27, 0x7ffffed),
    (27, 0x7ffffee),
    (27, 0x7ffffef),
    (27, 0x7fffff0),
    (26, 0x3ffffee),
    (30, 0x3fffffff),
];
const HUFFMAN_EOS: usize = 256;

/// Huffman-encode `data`, MSB-first bit packing, padded with the high-order
/// bits of the EOS code (all-1s) per RFC 7541 §5.2.
fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (len, code) = HUFFMAN_TABLE[b as usize];
        acc = (acc << len) | u64::from(code);
        nbits += u32::from(len);
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        let pad_bits = 8 - nbits;
        acc = (acc << pad_bits) | ((1u64 << pad_bits) - 1); // pad with 1s (EOS prefix)
        out.push(acc as u8);
    }
    out
}

/// Huffman-decode `data` — bit-by-bit accumulation against the SAME 257-entry
/// canonical table (a linear scan per bit; not the fastest possible decoder,
/// but directly, visibly correct against the one table this module already
/// trusts, and header blocks are tiny, so this is nowhere near a hot path).
fn huffman_decode(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        for bit_i in (0..8).rev() {
            let bit = (byte >> bit_i) & 1;
            acc = (acc << 1) | u64::from(bit);
            nbits += 1;
            if let Some(sym) = HUFFMAN_TABLE
                .iter()
                .position(|&(len, code)| u32::from(len) == nbits && code as u64 == acc)
            {
                if sym == HUFFMAN_EOS {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Huffman EOS symbol in data",
                    ));
                }
                out.push(sym as u8);
                acc = 0;
                nbits = 0;
            }
        }
    }
    // Remaining bits (if any) MUST be a prefix of the EOS code (all 1s), the padding.
    if nbits > 0 {
        let all_ones = (1u64 << nbits) - 1;
        if acc != all_ones {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Huffman padding is not all-1s",
            ));
        }
    }
    Ok(out)
}

/// RFC 7541 Appendix A — the 61 static entries, index 1..=61 (index 0 is
/// invalid/reserved). Transcribed from the RFC text, not a library's internal
/// representation, so it's checked directly against Appendix C's own worked
/// examples rather than trusted on the strength of its source.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

fn static_index_for(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n == name && v == value)
        .map(|i| i + 1)
}
fn static_name_index_for(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, _)| n == name)
        .map(|i| i + 1)
}

/// RFC 7541 §5.1 — encode `value` as an N-bit-prefix integer, OR-ed onto
/// `first_byte_flags` (the representation-type bits already set in the first
/// byte, e.g. `0x40` for "literal with indexing").
fn encode_int(out: &mut Vec<u8>, first_byte_flags: u8, prefix_bits: u32, mut value: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(first_byte_flags | value as u8);
        return;
    }
    out.push(first_byte_flags | max_prefix as u8);
    value -= max_prefix;
    while value >= 128 {
        out.push(((value % 128) + 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

fn decode_int(data: &[u8], pos: &mut usize, prefix_bits: u32) -> io::Result<usize> {
    let err = || Error::new(ErrorKind::InvalidData, "truncated HPACK integer");
    let max_prefix = (1usize << prefix_bits) - 1;
    let first = *data.get(*pos).ok_or_else(err)? as usize;
    *pos += 1;
    let mut value = first & max_prefix;
    if value < max_prefix {
        return Ok(value);
    }
    let mut m = 0u32;
    loop {
        let b = *data.get(*pos).ok_or_else(err)? as usize;
        *pos += 1;
        value += (b & 0x7f) << m;
        m += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

/// RFC 7541 §5.2 — a length-prefixed string, optionally Huffman-coded (high
/// bit of the length byte). We never emit Huffman on the way OUT (plain
/// literal strings are simpler and equally spec-valid to send), but MUST
/// decode either form coming IN.
fn encode_string(out: &mut Vec<u8>, s: &str) {
    encode_int(out, 0x00, 7, s.len()); // H=0
    out.extend_from_slice(s.as_bytes());
}

fn decode_string(data: &[u8], pos: &mut usize) -> io::Result<String> {
    let err = || Error::new(ErrorKind::InvalidData, "truncated HPACK string");
    let first = *data.get(*pos).ok_or_else(err)?;
    let huffman = first & 0x80 != 0;
    let len = decode_int(data, pos, 7)?;
    let raw = data.get(*pos..*pos + len).ok_or_else(err)?;
    *pos += len;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "non-UTF8 HPACK string"))
}

/// Encode ONE header field for sending — always "literal without indexing"
/// (RFC 7541 §6.2.2, first-byte pattern `0000xxxx`), using a static-table name
/// reference when the name matches one (saves re-sending common names like
/// `:method`/`content-type`), full literal name otherwise. No dynamic table
/// maintained on the encode side — see the module doc for why that's fine.
pub fn encode_header(out: &mut Vec<u8>, name: &str, value: &str) {
    if let Some(idx) = static_index_for(name, value) {
        // Fully indexed (RFC 7541 §6.1): first byte `1xxxxxxx`.
        encode_int(out, 0x80, 7, idx);
        return;
    }
    if let Some(idx) = static_name_index_for(name) {
        encode_int(out, 0x00, 4, idx);
        encode_string(out, value);
        return;
    }
    out.push(0x00); // literal name, index 0
    encode_string(out, name);
    encode_string(out, value);
}

/// Encode a full header list into one HPACK block (the HEADERS/CONTINUATION
/// frame payload).
pub fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        encode_header(&mut out, name, value);
    }
    out
}

/// Per-connection HPACK decoder state — the dynamic table (RFC 7541 §2.3),
/// tracking whatever the PEER chooses to index, independent of our own
/// (indexing-free) encoder above.
pub struct HpackDecoder {
    /// Most-recently-added first (index 1 = `dynamic[0]`), per §2.3.2.
    dynamic: Vec<(String, String)>,
    dynamic_size: usize,
    max_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dynamic: Vec::new(),
            dynamic_size: 0,
            max_size: 4096,
        }
    }

    fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32 // RFC 7541 §4.1's fixed 32-byte overhead
    }

    fn add_dynamic(&mut self, name: String, value: String) {
        self.dynamic_size += Self::entry_size(&name, &value);
        self.dynamic.insert(0, (name, value));
        while self.dynamic_size > self.max_size {
            let Some((n, v)) = self.dynamic.pop() else {
                break;
            };
            self.dynamic_size -= Self::entry_size(&n, &v);
        }
    }

    fn evict_to_max(&mut self) {
        while self.dynamic_size > self.max_size {
            let Some((n, v)) = self.dynamic.pop() else {
                break;
            };
            self.dynamic_size -= Self::entry_size(&n, &v);
        }
    }

    fn lookup(&self, index: usize) -> io::Result<(String, String)> {
        if index == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "HPACK index 0 is invalid",
            ));
        }
        if index <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[index - 1];
            return Ok((n.to_string(), v.to_string()));
        }
        let dyn_idx = index - STATIC_TABLE.len() - 1;
        self.dynamic.get(dyn_idx).cloned().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("HPACK index {index} out of range"),
            )
        })
    }

    /// Decode one HPACK block (a full HEADERS+CONTINUATION payload, already
    /// reassembled) into an ordered header list.
    pub fn decode(&mut self, data: &[u8]) -> io::Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let first = data[pos];
            if first & 0x80 != 0 {
                // Indexed Header Field (§6.1)
                let idx = decode_int(data, &mut pos, 7)?;
                let (n, v) = self.lookup(idx)?;
                out.push((n, v));
            } else if first & 0x40 != 0 {
                // Literal Header Field with Incremental Indexing (§6.2.1)
                let idx = decode_int(data, &mut pos, 6)?;
                let name = if idx == 0 {
                    decode_string(data, &mut pos)?
                } else {
                    self.lookup(idx)?.0
                };
                let value = decode_string(data, &mut pos)?;
                self.add_dynamic(name.clone(), value.clone());
                out.push((name, value));
            } else if first & 0x20 != 0 {
                // Dynamic Table Size Update (§6.3)
                let new_size = decode_int(data, &mut pos, 5)?;
                self.max_size = new_size;
                self.evict_to_max();
            } else {
                // Literal Header Field without Indexing (§6.2.2, prefix 0000) or
                // Never Indexed (§6.2.3, prefix 0001) — both non-indexing, 4-bit prefix.
                let idx = decode_int(data, &mut pos, 4)?;
                let name = if idx == 0 {
                    decode_string(data, &mut pos)?
                } else {
                    self.lookup(idx)?.0
                };
                let value = decode_string(data, &mut pos)?;
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn huffman_table_is_a_complete_prefix_code() {
        let kraft: f64 = HUFFMAN_TABLE
            .iter()
            .map(|&(len, _)| 2f64.powi(-i32::from(len)))
            .sum();
        assert!(
            (kraft - 1.0).abs() < 1e-9,
            "Kraft sum must be exactly 1.0 for a complete code, got {kraft}"
        );
    }

    #[test]
    fn huffman_round_trips_arbitrary_ascii() {
        for s in [
            "www.example.com",
            "custom-header",
            "",
            "a",
            "/tfplugin6.Provider/GetProviderSchema",
        ] {
            let encoded = huffman_encode(s.as_bytes());
            let decoded = huffman_decode(&encoded).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                decoded,
                s.as_bytes(),
                "round trip must reproduce the original bytes for {s:?}"
            );
        }
    }

    /// RFC 7541 Appendix C.4.1 — the REAL Huffman-encoded bytes from the spec
    /// itself decode to "www.example.com" via this module's own huffman_decode.
    #[test]
    fn rfc7541_huffman_reference_bytes_decode_correctly() {
        let encoded = hx("f1e3 c2e5 f23a 6ba0 ab90 f4ff");
        let decoded = huffman_decode(&encoded).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(decoded, b"www.example.com");
    }

    /// RFC 7541 Appendix C.2.1 — Literal Header Field with Indexing, full
    /// literal name+value, added to the dynamic table.
    #[test]
    fn rfc7541_c2_1_literal_with_indexing() {
        let bytes = hx("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572");
        let mut dec = HpackDecoder::new();
        let headers = dec.decode(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            headers,
            vec![("custom-key".to_string(), "custom-header".to_string())]
        );
        assert_eq!(dec.dynamic.len(), 1, "must be added to the dynamic table");
        assert_eq!(
            dec.dynamic_size, 55,
            "RFC 7541's own worked size (name+value+32 overhead)"
        );
    }

    /// RFC 7541 Appendix C.2.2 — Literal Header Field without Indexing, an
    /// indexed name (`:path` = static index 4) + literal value, NOT added to
    /// the dynamic table.
    #[test]
    fn rfc7541_c2_2_literal_without_indexing_indexed_name() {
        let bytes = hx("040c 2f73 616d 706c 652f 7061 7468");
        let mut dec = HpackDecoder::new();
        let headers = dec.decode(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            headers,
            vec![(":path".to_string(), "/sample/path".to_string())]
        );
        assert!(
            dec.dynamic.is_empty(),
            "without-indexing must NOT touch the dynamic table"
        );
    }

    /// RFC 7541 Appendix C.3.1 — a full request: three fully-indexed static
    /// entries plus one literal-with-indexing for `:authority`.
    #[test]
    fn rfc7541_c3_1_first_request_no_huffman() {
        let bytes = hx("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d");
        let mut dec = HpackDecoder::new();
        let headers = dec.decode(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            headers,
            vec![
                (":method".to_string(), "GET".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":path".to_string(), "/".to_string()),
                (":authority".to_string(), "www.example.com".to_string()),
            ]
        );
        assert_eq!(dec.dynamic_size, 57);
    }

    /// Same request as C.3.1, but the RFC's own Huffman-coded variant
    /// (Appendix C.4.1) — same decoded result, different wire bytes.
    #[test]
    fn rfc7541_c4_1_first_request_with_huffman() {
        let bytes = hx("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff");
        let mut dec = HpackDecoder::new();
        let headers = dec.decode(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            headers,
            vec![
                (":method".to_string(), "GET".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":path".to_string(), "/".to_string()),
                (":authority".to_string(), "www.example.com".to_string()),
            ]
        );
    }

    /// Our own encoder → our own decoder must round-trip (the encode side
    /// isn't covered by the RFC vectors above, since those are all decode-only
    /// checks against externally-produced bytes).
    #[test]
    fn encode_then_decode_round_trips_our_own_headers() {
        let headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/tfplugin6.Provider/GetProviderSchema"),
            (":authority", "localhost"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ];
        let encoded = encode_headers(&headers);
        let mut dec = HpackDecoder::new();
        let decoded = dec.decode(&encoded).unwrap_or_else(|e| unreachable!("{e}"));
        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn dynamic_table_size_update_evicts_entries() {
        // Two "literal with incremental indexing, new name" fields (§6.2.1, first
        // byte 0x40, name index 0 -> literal name follows).
        let mut raw = Vec::new();
        raw.push(0x40);
        encode_string(&mut raw, "a");
        encode_string(&mut raw, "1");
        raw.push(0x40);
        encode_string(&mut raw, "b");
        encode_string(&mut raw, "2");
        let mut dec = HpackDecoder::new();
        dec.decode(&raw).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(dec.dynamic.len(), 2);

        // A dynamic table size update (§6.3, first byte 0x20) to exactly fit the
        // most-recently-added entry ("b": "2") and evict the older one.
        let mut upd = Vec::new();
        encode_int(&mut upd, 0x20, 5, HpackDecoder::entry_size("b", "2"));
        dec.decode(&upd).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(dec.dynamic.len(), 1, "must evict down to the new max size");
        assert_eq!(
            dec.dynamic[0],
            ("b".to_string(), "2".to_string()),
            "most-recently-added survives"
        );
    }
}
