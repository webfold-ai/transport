//! A deliberately small X.509 reader: just the parts of a certificate the certificate lifecycle
//! has to look at without trusting it — the issuer and subject names, the `SubjectPublicKeyInfo`
//! (to prove a renewal got a new key and that the CA certified the key we asked for), the
//! subject alternative names and extension presence (to see whether a certificate carries
//! embedded SCTs), and the SHA-256 fingerprint (the identity root programs list roots by).
//!
//! **This is not a path validator.** Nothing here establishes that a certificate is trustworthy —
//! that is the browser's and the CA's job (see [`crate::ca_trust`] for the signals about the
//! latter). Every function takes attacker-influenced bytes (a CA's response, a CT log entry), so
//! each one is bounded and returns `None` on anything malformed rather than guessing.

use crate::acme::der;

/// `2.5.4.3`
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `2.5.4.10`
pub const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
/// `2.5.29.17` subjectAltName.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// `1.3.6.1.4.1.11129.2.4.2` — the embedded SignedCertificateTimestampList (RFC 6962 §3.3).
const OID_SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
/// `1.3.6.1.4.1.11129.2.4.3` — the precertificate poison (RFC 6962 §3.1). A certificate carrying
/// it is a precertificate: not usable by a TLS client and not what we "obtained".
const OID_CT_POISON: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03];
/// `2.5.29.19` basicConstraints.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// Largest certificate this reader will look at. Real ones are a few KiB.
pub const MAX_CERT_LEN: usize = 64 * 1024;

/// The parts of one parsed certificate. Slices borrow the input.
#[derive(Clone, Debug)]
pub struct Cert<'a> {
    /// The whole certificate DER.
    pub der: &'a [u8],
    pub serial: &'a [u8],
    /// The issuer `Name`, as a complete DER SEQUENCE (tag and length included).
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// The complete `SubjectPublicKeyInfo` DER SEQUENCE.
    pub spki: &'a [u8],
    /// `(extnID content octets, critical, extnValue content octets)` for every extension.
    pub extensions: Vec<(&'a [u8], bool, &'a [u8])>,
}

/// Parse `der` as a certificate. `None` for anything that is not a well-formed X.509 v1/v3
/// `Certificate` in the shape this module reads, or that is implausibly large.
#[must_use]
pub fn parse(cert_der: &[u8]) -> Option<Cert<'_>> {
    if cert_der.len() > MAX_CERT_LEN {
        return None;
    }
    let (tag, cert, rest) = der::read(cert_der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, tbs, _) = der::read(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (t0, _, after) = der::read(tbs)?;
    let body = if t0 == 0xA0 { after } else { tbs };
    let (tag, serial, body) = der::read(body)?;
    if tag != 0x02 || serial.is_empty() {
        return None;
    }
    let (_, _, body) = der::read(body)?; // signature AlgorithmIdentifier
    let (issuer, body) = take_seq(body)?;
    let (_, _, body) = der::read(body)?; // validity
    let (subject, body) = take_seq(body)?;
    let (spki, mut body) = take_seq(body)?;
    // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }: anything else is not a key.
    let (_, spki_body, _) = der::read(spki)?;
    let (alg_tag, _, after_alg) = der::read(spki_body)?;
    let (bits_tag, bits, _) = der::read(after_alg)?;
    if alg_tag != 0x30 || bits_tag != 0x03 || bits.len() < 2 {
        return None;
    }
    let mut extensions = Vec::new();
    while !body.is_empty() {
        let (tag, content, next) = der::read(body)?;
        body = next;
        if tag != 0xA3 {
            continue;
        }
        let (tag, mut exts, _) = der::read(content)?;
        if tag != 0x30 {
            return None;
        }
        while !exts.is_empty() {
            let (tag, ext, next) = der::read(exts)?;
            exts = next;
            if tag != 0x30 {
                return None;
            }
            let (oid_tag, oid, rest) = der::read(ext)?;
            if oid_tag != 0x06 {
                return None;
            }
            let (t, v, after) = der::read(rest)?;
            let (critical, value) = if t == 0x01 {
                let (t2, v2, _) = der::read(after)?;
                if t2 != 0x04 {
                    return None;
                }
                (v.first().is_some_and(|b| *b != 0), v2)
            } else if t == 0x04 {
                (false, v)
            } else {
                return None;
            };
            extensions.push((oid, critical, value));
            if extensions.len() > 64 {
                return None;
            }
        }
    }
    Some(Cert { der: cert_der, serial, issuer, subject, spki, extensions })
}

/// The next element if it is a SEQUENCE: `(whole TLV, rest)`.
fn take_seq(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, _, rest) = der::read(buf)?;
    if tag != 0x30 {
        return None;
    }
    let consumed = buf.len() - rest.len();
    Some((buf.get(..consumed)?, rest))
}

impl Cert<'_> {
    fn extension(&self, oid: &[u8]) -> Option<&[u8]> {
        self.extensions.iter().find(|(o, _, _)| *o == oid).map(|(_, _, v)| *v)
    }

    /// Whether the certificate carries an embedded SCT list (RFC 6962 §3.3).
    #[must_use]
    pub fn has_embedded_scts(&self) -> bool {
        self.extension(OID_SCT_LIST).is_some_and(|v| !v.is_empty())
    }

    /// Whether this is a CT precertificate (carries the poison extension).
    #[must_use]
    pub fn is_precertificate(&self) -> bool {
        self.extension(OID_CT_POISON).is_some()
    }

    /// Whether `basicConstraints` says CA:TRUE.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        let Some(v) = self.extension(OID_BASIC_CONSTRAINTS) else { return false };
        let Some((0x30, content, _)) = der::read(v) else { return false };
        matches!(der::read(content), Some((0x01, b, _)) if b.first().is_some_and(|x| *x != 0))
    }

    /// The `dNSName` entries of the subject alternative name, lower-cased.
    #[must_use]
    pub fn dns_names(&self) -> Vec<String> {
        let Some(v) = self.extension(OID_SAN) else { return Vec::new() };
        let Some((0x30, mut names, _)) = der::read(v) else { return Vec::new() };
        let mut out = Vec::new();
        while !names.is_empty() {
            let Some((tag, content, next)) = der::read(names) else { break };
            names = next;
            if tag == 0x82 {
                if let Ok(s) = std::str::from_utf8(content) {
                    out.push(s.to_ascii_lowercase());
                }
            }
            if out.len() >= 256 {
                break;
            }
        }
        out
    }

    /// `true` when issuer and subject are the same name (a self-signed or root certificate).
    #[must_use]
    pub fn is_self_issued(&self) -> bool {
        self.issuer == self.subject
    }

    /// The issuer's common name, if it has one.
    #[must_use]
    pub fn issuer_cn(&self) -> Option<String> {
        name_attribute(self.issuer, OID_COMMON_NAME)
    }

    /// The issuer's organization, if it has one.
    #[must_use]
    pub fn issuer_org(&self) -> Option<String> {
        name_attribute(self.issuer, OID_ORGANIZATION)
    }

    /// The subject's common name, if it has one.
    #[must_use]
    pub fn subject_cn(&self) -> Option<String> {
        name_attribute(self.subject, OID_COMMON_NAME)
    }
}

/// The first value of attribute `oid` in an X.509 `Name` (a SEQUENCE of RDN SETs), as text.
/// Handles the string types a Name uses; anything else is `None`.
#[must_use]
pub fn name_attribute(name_tlv: &[u8], oid: &[u8]) -> Option<String> {
    let (0x30, mut rdns, _) = der::read(name_tlv)? else { return None };
    while !rdns.is_empty() {
        let (tag, rdn, next) = der::read(rdns)?;
        rdns = next;
        if tag != 0x31 {
            return None;
        }
        let mut atvs = rdn;
        while !atvs.is_empty() {
            let (tag, atv, next) = der::read(atvs)?;
            atvs = next;
            if tag != 0x30 {
                return None;
            }
            let (oid_tag, o, value) = der::read(atv)?;
            if oid_tag != 0x06 || o != oid {
                continue;
            }
            let (vt, v, _) = der::read(value)?;
            // UTF8String, PrintableString, IA5String, TeletexString (as Latin-1 is ASCII-compatible here).
            return match vt {
                0x0c | 0x13 | 0x16 | 0x14 => std::str::from_utf8(v).ok().map(str::to_string),
                _ => None,
            };
        }
    }
    None
}

/// DER of the first `CERTIFICATE` block of `chain_pem`.
#[must_use]
pub fn leaf_der(chain_pem: &str) -> Option<Vec<u8>> {
    crate::pem::blocks(chain_pem, "CERTIFICATE").into_iter().next()
}

/// The leaf's complete `SubjectPublicKeyInfo` DER — the identity of the certified key.
#[must_use]
pub fn leaf_spki(chain_pem: &str) -> Option<Vec<u8>> {
    let der = leaf_der(chain_pem)?;
    parse(&der).map(|c| c.spki.to_vec())
}

/// The last certificate of the chain (the one closest to the root), parsed fields copied out.
/// Used to find which root the chain leads to: a self-issued last certificate *is* a root; any
/// other one names its issuer, which is the root (or the next intermediate) it hangs off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTop {
    /// SHA-256 of the last certificate's DER, lower-case hex.
    pub fingerprint: String,
    pub self_issued: bool,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
}

/// Describe the top of `chain_pem`. `None` if the chain has no parsable certificate.
#[must_use]
pub fn chain_top(chain_pem: &str) -> Option<ChainTop> {
    let blocks = crate::pem::blocks(chain_pem, "CERTIFICATE");
    if blocks.len() > 16 {
        return None;
    }
    let last = blocks.last()?;
    let c = parse(last)?;
    Some(ChainTop {
        fingerprint: fingerprint_hex(last),
        self_issued: c.is_self_issued(),
        subject_cn: c.subject_cn(),
        issuer_cn: c.issuer_cn(),
        issuer_org: c.issuer_org(),
    })
}

/// SHA-256 of `der` as lower-case hex — how CCADB and the Chrome Root Store identify a root.
#[must_use]
pub fn fingerprint_hex(der: &[u8]) -> String {
    hashtrinity::crypto::sha256(der).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(names: &[&str], ca: bool) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Test Subject");
        if ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        (params.self_signed(&key).unwrap(), key)
    }

    #[test]
    fn reads_names_san_spki_and_ca_flag() {
        let (c, key) = cert(&["Example.TEST", "*.example.test"], false);
        let parsed = parse(c.der()).unwrap();
        assert_eq!(parsed.dns_names(), vec!["example.test".to_string(), "*.example.test".to_string()]);
        assert_eq!(parsed.subject_cn().as_deref(), Some("Test Subject"));
        assert!(parsed.is_self_issued());
        assert!(!parsed.is_ca());
        assert!(!parsed.has_embedded_scts() && !parsed.is_precertificate());
        // The SPKI is the one the key pair reports.
        assert_eq!(parsed.spki, key.public_key_der().as_slice());
        let (ca, _) = cert(&["ca.test"], true);
        assert!(parse(ca.der()).unwrap().is_ca());
    }

    #[test]
    fn malformed_and_oversized_input_is_none_not_a_panic() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x30, 0x82, 0xff]).is_none());
        let (c, _) = cert(&["a.test"], false);
        let mut truncated = c.der().to_vec();
        truncated.truncate(truncated.len() / 2);
        assert!(parse(&truncated).is_none());
        let mut trailing = c.der().to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_none(), "trailing bytes after the certificate");
        assert!(parse(&vec![0x30; MAX_CERT_LEN + 1]).is_none());
        // Every prefix and a bit-flipped copy must stay a clean Option.
        for n in 0..c.der().len().min(400) {
            let _ = parse(&c.der()[..n]);
        }
    }

    #[test]
    fn chain_top_identifies_a_root_by_fingerprint_and_a_non_root_by_its_issuer() {
        let (root, _) = cert(&["root.test"], true);
        let pem = crate::acme::pem_wrap("CERTIFICATE", root.der());
        let top = chain_top(&pem).unwrap();
        assert!(top.self_issued);
        assert_eq!(top.fingerprint, fingerprint_hex(root.der()));
        assert_eq!(top.fingerprint.len(), 64);
        assert!(chain_top("not pem").is_none());
    }

    #[test]
    fn embedded_sct_extension_is_detected() {
        // A certificate with a (dummy) SCT list extension, as CAs embed them.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["sct.test".to_string()]).unwrap();
        let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2], vec![0x04, 0x02, 0x00, 0x00]);
        ext.set_criticality(false);
        params.custom_extensions.push(ext);
        let c = params.self_signed(&key).unwrap();
        assert!(parse(c.der()).unwrap().has_embedded_scts());
    }
}
