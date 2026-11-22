//! Strict DNS name handling. Names are lower-cased, ASCII-only (IDNs must arrive as A-labels),
//! and limited to the characters real zones need: letters, digits, `-`, and `_` (for service
//! labels such as `_dmarc` / `_sip._tcp`). A `*` is accepted only as a whole leftmost label.

use crate::error::ValidationError;
use hickory_proto::rr::Name;

/// Longest label.
pub const MAX_LABEL: usize = 63;
/// Longest name in presentation form without the trailing dot (wire form is then <= 255).
pub const MAX_NAME: usize = 253;

fn label_ok(label: &str, leftmost: bool) -> Result<(), ValidationError> {
    if label.is_empty() {
        return Err(ValidationError::Name("empty label"));
    }
    if label.len() > MAX_LABEL {
        return Err(ValidationError::Name("label longer than 63"));
    }
    if label == "*" {
        return if leftmost {
            Ok(())
        } else {
            Err(ValidationError::Name("wildcard must be the leftmost label"))
        };
    }
    let bytes = label.as_bytes();
    let underscore = bytes.first() == Some(&b'_');
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_';
        if !ok {
            return Err(ValidationError::Name("character outside [a-z0-9_-]"));
        }
    }
    if !underscore && (bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-')) {
        return Err(ValidationError::Name("hyphen at label edge"));
    }
    // `xn--` labels must be well-formed A-labels in shape (the encoding itself is the author's).
    if label.starts_with("xn--") && label.len() == 4 {
        return Err(ValidationError::Name("empty punycode label"));
    }
    Ok(())
}

/// Validate an absolute name (an optional trailing dot is accepted and removed) and return the
/// canonical lower-case, dot-less presentation form. Upper-case input is folded.
pub fn canonical(s: &str) -> Result<String, ValidationError> {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() {
        return Err(ValidationError::Name("empty name"));
    }
    if s.len() > MAX_NAME {
        return Err(ValidationError::Name("name longer than 253"));
    }
    let lower = s.to_ascii_lowercase();
    for (i, l) in lower.split('.').enumerate() {
        label_ok(l, i == 0)?;
    }
    Ok(lower)
}

/// An absolute, validated, lower-case name.
pub fn parse_fqdn(s: &str) -> Result<Name, ValidationError> {
    let c = canonical(s)?;
    let n = Name::from_ascii(format!("{c}.")).map_err(|_| ValidationError::Name("unparseable"))?;
    if n.len() > 255 {
        return Err(ValidationError::Name("wire form longer than 255"));
    }
    Ok(n)
}

/// A name that may not contain a wildcard (zone apexes, rdata targets, challenge names).
pub fn parse_fqdn_no_wildcard(s: &str) -> Result<Name, ValidationError> {
    let c = canonical(s)?;
    if c.split('.').any(|l| l == "*") {
        return Err(ValidationError::Name("wildcard not allowed here"));
    }
    parse_fqdn(&c)
}

/// The DNS root `.` (used only for null-MX / unavailable-SRV targets, by explicit "." input).
#[must_use]
pub fn root() -> Name {
    Name::root()
}

/// Resolve a record owner name against `apex`: `@` is the apex, a name without a trailing dot is
/// relative to the apex, a name with a trailing dot is absolute and must lie at or under it.
pub fn owner_in_apex(spec: &str, apex: &Name) -> Result<Name, ValidationError> {
    if spec == "@" {
        return Ok(apex.clone());
    }
    let apex_s = apex.to_ascii();
    let apex_s = apex_s.strip_suffix('.').unwrap_or(&apex_s).to_string();
    let abs = if let Some(abs) = spec.strip_suffix('.') {
        abs.to_string()
    } else {
        // relative: validate the relative part, then append
        let rel = canonical(spec)?;
        format!("{rel}.{apex_s}")
    };
    let c = canonical(&abs)?;
    if c != apex_s && !c.ends_with(&format!(".{apex_s}")) {
        return Err(ValidationError::OutsideApex);
    }
    parse_fqdn(&c)
}

/// Whether `name` is the apex or lies under it.
#[must_use]
pub fn within(apex: &Name, name: &Name) -> bool {
    apex.zone_of(name)
}

/// Canonical DNS wire form of a validated name (lower-case, uncompressed), used as the mesh id.
#[must_use]
pub fn wire_id(name: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    for l in &name.to_lowercase() {
        out.push(u8::try_from(l.len()).unwrap_or(63));
        out.extend_from_slice(l);
    }
    out.push(0);
    out
}

/// Inverse of [`wire_id`], strictly validating (so an id from the mesh is as trusted as a string).
pub fn from_wire_id(id: &[u8]) -> Result<Name, ValidationError> {
    let mut labels: Vec<String> = Vec::new();
    let mut i = 0usize;
    loop {
        let len = usize::from(
            *id.get(i)
                .ok_or(ValidationError::Name("truncated wire id"))?,
        );
        i += 1;
        if len == 0 {
            break;
        }
        if len > MAX_LABEL {
            return Err(ValidationError::Name("label longer than 63"));
        }
        let l = id
            .get(i..i + len)
            .ok_or(ValidationError::Name("truncated wire id"))?;
        i += len;
        labels.push(String::from_utf8(l.to_vec()).map_err(|_| ValidationError::Name("non-ascii"))?);
    }
    if i != id.len() {
        return Err(ValidationError::Name("trailing bytes after root"));
    }
    let n = parse_fqdn_no_wildcard(&labels.join("."))?;
    if wire_id(&n) != id {
        return Err(ValidationError::Name("wire id is not canonical"));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]

    use super::*;

    #[test]
    fn accepts_ordinary_and_service_names_and_folds_case() {
        assert_eq!(canonical("WWW.Example.COM.").unwrap(), "www.example.com");
        assert!(canonical("_sip._tcp.example.com").is_ok());
        assert!(canonical("xn--bcher-kva.example").is_ok());
        assert!(canonical("*.example.com").is_ok());
    }

    #[test]
    fn rejects_bad_syntax() {
        for bad in [
            "",
            ".",
            "a..b",
            "-a.example",
            "a-.example",
            "a b.example",
            "a\u{e9}.example",
            "a/b.example",
            "foo.*.example",
            "*a.example",
            "a.example\n",
            "x".repeat(64).as_str(),
        ] {
            assert!(canonical(bad).is_err(), "{bad:?}");
        }
        let long = format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(60),
            "e".repeat(60)
        );
        assert!(canonical(&long).is_err(), "over 253");
    }

    #[test]
    fn owners_resolve_inside_the_apex_only() {
        let apex = parse_fqdn("acme.example").unwrap();
        assert_eq!(owner_in_apex("@", &apex).unwrap(), apex);
        assert_eq!(
            owner_in_apex("www", &apex).unwrap().to_ascii(),
            "www.acme.example."
        );
        assert_eq!(
            owner_in_apex("*.dev", &apex).unwrap().to_ascii(),
            "*.dev.acme.example."
        );
        assert_eq!(
            owner_in_apex("a.acme.example.", &apex).unwrap().to_ascii(),
            "a.acme.example."
        );
        assert_eq!(
            owner_in_apex("other.example.", &apex),
            Err(ValidationError::OutsideApex)
        );
        assert_eq!(
            owner_in_apex("evilacme.example.", &apex),
            Err(ValidationError::OutsideApex)
        );
        assert_eq!(
            owner_in_apex("acme.example.acme.example.", &apex)
                .unwrap()
                .to_ascii(),
            "acme.example.acme.example."
        );
        assert_eq!(
            owner_in_apex("acme.example.example.", &apex),
            Err(ValidationError::OutsideApex)
        );
        assert!(owner_in_apex("www.", &apex).is_err());
    }

    #[test]
    fn wire_id_round_trips_and_rejects_garbage() {
        let n = parse_fqdn("a.b.example").unwrap();
        assert_eq!(from_wire_id(&wire_id(&n)).unwrap(), n);
        assert!(from_wire_id(&[]).is_err());
        assert!(from_wire_id(&[5, b'a']).is_err());
        assert!(
            from_wire_id(&[1, b'A', 0]).is_err(),
            "upper case is not canonical wire"
        );
        assert!(from_wire_id(&[1, b'a', 0, 0]).is_err());
        assert!(from_wire_id(&[1, 0xff, 0]).is_err());
    }
}
