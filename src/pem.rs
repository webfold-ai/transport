//! PEM / base64 plumbing shared by the certificate paths (ACME key output, the SNI resolver,
//! the on-disk certificate store, the `notAfter` reader). Standard-alphabet base64 only — PEM
//! never uses the URL-safe one.

/// Decode standard base64, ignoring ASCII whitespace. `None` on any character outside the
/// alphabet or a length that cannot be valid.
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let body = clean.strip_suffix(b"==").or_else(|| clean.strip_suffix(b"=")).unwrap_or(&clean);
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * (4 - chunk.len()) as u32;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// The decoded DER of every `-----BEGIN <label>-----` block, in order of appearance. A cert
/// chain PEM has one block per certificate, leaf first.
#[must_use]
pub fn blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        match base64_decode(&after[..stop]) {
            Some(der) => out.push(der),
            None => return Vec::new(), // a corrupt block poisons the whole PEM
        }
        rest = &after[stop + end.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_padding_length() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9v\nYmE=").unwrap(), b"fooba");
        assert!(base64_decode("Zm9v!").is_none());
        assert!(base64_decode("Z").is_none());
    }

    #[test]
    fn pem_blocks_are_returned_in_order_and_a_corrupt_one_poisons_all() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nYmFy\n-----END CERTIFICATE-----\n";
        assert_eq!(blocks(pem, "CERTIFICATE"), vec![b"foo".to_vec(), b"bar".to_vec()]);
        assert!(blocks(pem, "PRIVATE KEY").is_empty());
        let bad = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(blocks(bad, "CERTIFICATE").is_empty());
    }
}
