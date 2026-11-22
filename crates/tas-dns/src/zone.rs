//! The zone data model: tenant, apex, ownership registration, DNSSEC policy, validated records.

use crate::error::ValidationError;
use crate::names;
use crate::records::{self, ValidRecord, ZoneLimits};
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};

/// A tenant identifier: `[a-z0-9][a-z0-9_-]{0,62}`. Every zone, label and quota is keyed by it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Validate and wrap.
    pub fn new(s: &str) -> Result<Self, ValidationError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 63
            && b.first()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_');
        if ok {
            Ok(TenantId(s.to_string()))
        } else {
            Err(ValidationError::Tenant)
        }
    }

    /// The identifier text (validated, safe to log).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The DNSSEC algorithm in use: ECDSA P-256 / SHA-256 (algorithm 13).
pub const DNSSEC_ALGORITHM_NUMBER: u8 = 13;

/// Per-zone DNSSEC policy, carried in the control-plane-signed registration so every node derives
/// the same key schedule without coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecPolicy {
    /// KSK generation currently in use (and in the parent DS set).
    pub ksk_gen: u32,
    /// Next KSK generation being introduced (double-DS rollover), if any.
    pub ksk_next: Option<u32>,
    /// Unix time the ZSK schedule counts from: generation `g` is active from `origin + g * period`.
    pub origin: u64,
}

/// Registration state of an apex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegState {
    /// Served.
    Active,
    /// Released: not served; the apex is quarantined until `quarantine_until`.
    Released,
}

/// The decoded body of a [`transport::zone_sync::ObjectKind::Registration`] object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationDoc {
    /// The apex.
    pub apex: String,
    /// Owning tenant.
    pub tenant: String,
    /// Hex Ed25519 public key of the zone owner (dialkey-derived).
    pub owner: String,
    /// Active or released.
    pub state: RegState,
    /// For `released`: unix time before which no other tenant may register the apex.
    #[serde(default)]
    pub quarantine_until: u64,
    /// DNSSEC policy; absent means the zone is served unsigned.
    #[serde(default)]
    pub dnssec: Option<DnssecPolicy>,
}

/// A validated registration (what a node enforces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The apex.
    pub apex: Name,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owner's Ed25519 public key.
    pub owner: [u8; 32],
    /// Owner epoch (changes when the owner key changes).
    pub owner_epoch: u64,
    /// Registration sequence number (the envelope version).
    pub seq: u64,
    /// Active or released.
    pub state: RegState,
    /// Quarantine end for a released apex.
    pub quarantine_until: u64,
    /// DNSSEC policy.
    pub dnssec: Option<DnssecPolicy>,
}

fn unhex32(s: &str) -> Result<[u8; 32], ValidationError> {
    if s.len() != 64 {
        return Err(ValidationError::Rdata("owner key length"));
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let h = |b: u8| -> Result<u8, ValidationError> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(ValidationError::Rdata("owner key hex")),
            }
        };
        let hi = h(*pair
            .first()
            .ok_or(ValidationError::Rdata("owner key hex"))?)?;
        let lo = h(*pair.get(1).ok_or(ValidationError::Rdata("owner key hex"))?)?;
        *out.get_mut(i)
            .ok_or(ValidationError::Rdata("owner key length"))? = hi << 4 | lo;
    }
    Ok(out)
}

/// Lower-case hex of 32 bytes.
#[must_use]
pub fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &x in b {
        s.push(char::from(HEX[usize::from(x >> 4)]));
        s.push(char::from(HEX[usize::from(x & 15)]));
    }
    s
}

impl Registration {
    /// Parse and validate a registration body. `id` is the envelope id (apex wire form): it must
    /// agree with the body, so a registration cannot be replayed under a different object id.
    pub fn parse(
        id: &[u8],
        owner_epoch: u64,
        seq: u64,
        body: &[u8],
    ) -> Result<Self, ValidationError> {
        if body.len() > 4096 {
            return Err(ValidationError::Limit("registration body"));
        }
        let doc: RegistrationDoc =
            serde_json::from_slice(body).map_err(|_| ValidationError::Parse)?;
        let apex = names::parse_fqdn_no_wildcard(&doc.apex)?;
        if names::wire_id(&apex) != id {
            return Err(ValidationError::Name(
                "registration id does not match its apex",
            ));
        }
        if apex.num_labels() < 2 {
            // a single-label apex would be a TLD; tenants never own one
            return Err(ValidationError::Name("apex needs at least two labels"));
        }
        Ok(Registration {
            apex,
            tenant: TenantId::new(&doc.tenant)?,
            owner: unhex32(&doc.owner)?,
            owner_epoch,
            seq,
            state: doc.state,
            quarantine_until: doc.quarantine_until,
            dnssec: doc.dnssec,
        })
    }
}

/// A served zone at one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Owning tenant.
    pub tenant: TenantId,
    /// The apex.
    pub apex: Name,
    /// Owner epoch the content was signed under.
    pub epoch: u64,
    /// Monotone version; also the SOA serial.
    pub version: u64,
    /// Validated tenant records (no SOA/NS: the server generates those).
    pub records: Vec<ValidRecord>,
    /// DNSSEC policy from the registration, if the zone is signed.
    pub dnssec: Option<DnssecPolicy>,
}

impl Zone {
    /// Build a zone from a registration and an update body. The SOA serial is the version, so
    /// versions must fit in 32 bits.
    pub fn from_update(
        reg: &Registration,
        epoch: u64,
        version: u64,
        body: &[u8],
        limits: &ZoneLimits,
    ) -> Result<Self, ValidationError> {
        if version == 0 || version > u64::from(u32::MAX) {
            return Err(ValidationError::Limit("version must be 1..=u32::MAX"));
        }
        let records = records::parse_body(body, &reg.apex, limits)?;
        Ok(Zone {
            tenant: reg.tenant.clone(),
            apex: reg.apex.clone(),
            epoch,
            version,
            records,
            dnssec: reg.dnssec,
        })
    }

    /// An empty zone (registered, no update yet): served with only SOA/NS so the delegation is
    /// not lame while the owner prepares content.
    #[must_use]
    pub fn empty(reg: &Registration) -> Self {
        Zone {
            tenant: reg.tenant.clone(),
            apex: reg.apex.clone(),
            epoch: reg.owner_epoch,
            version: 0,
            records: Vec::new(),
            dnssec: reg.dnssec,
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "test assertions on fixtures")]

    use super::*;

    pub(crate) fn reg_body(apex: &str, tenant: &str, owner: &[u8; 32]) -> Vec<u8> {
        format!(
            r#"{{"apex":"{apex}","tenant":"{tenant}","owner":"{}","state":"active"}}"#,
            hex32(owner)
        )
        .into_bytes()
    }

    #[test]
    fn tenant_ids_are_validated() {
        for ok in ["acme", "a1", "a_b-c", "0x"] {
            assert!(TenantId::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-a", "A", "a b", "a.b", "a\n", &"a".repeat(64)] {
            assert!(TenantId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_registration_must_match_its_object_id_and_have_a_valid_owner() {
        let apex = names::parse_fqdn("acme.example").unwrap();
        let id = names::wire_id(&apex);
        let owner = [7u8; 32];
        let ok = Registration::parse(&id, 1, 1, &reg_body("acme.example", "acme", &owner)).unwrap();
        assert_eq!(ok.owner, owner);
        let other = names::wire_id(&names::parse_fqdn("other.example").unwrap());
        assert!(
            Registration::parse(&other, 1, 1, &reg_body("acme.example", "acme", &owner)).is_err()
        );
        assert!(Registration::parse(
            &id,
            1,
            1,
            br#"{"apex":"acme.example","tenant":"acme","owner":"zz","state":"active"}"#
        )
        .is_err());
        assert!(Registration::parse(
            &id,
            1,
            1,
            br#"{"apex":"acme.example","tenant":"Acme","owner":"00","state":"active"}"#
        )
        .is_err());
        let tld = names::wire_id(&names::parse_fqdn("com").unwrap());
        assert!(
            Registration::parse(&tld, 1, 1, &reg_body("com", "acme", &owner)).is_err(),
            "a TLD is never delegable"
        );
    }
}
