//! The ACME challenge zone: model, node-side validation and serving form (this file), and the
//! issuance-side authority that binds labels and publishes tokens (bottom of file).
//!
//! A customer publishes one record, once, at their own DNS provider:
//! `_acme-challenge.<name> CNAME <label>.<challenge-zone>`. The label is permanently bound to
//! the `(tenant, name)` that first asked for it. The zone serves **only TXT** at
//! `<label>.<challenge-zone>`: the apex SOA/NS are the only other data.

use crate::error::ValidationError;
use crate::names::{self, parse_fqdn_no_wildcard};
use crate::zone::TenantId;
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};

/// Length of a label: 20 random bytes in lower-case base32 (160 bits, so unguessable).
pub const LABEL_LEN: usize = 32;
/// Most live tokens per label (`example.com` and `*.example.com` in one order need two).
pub const MAX_TOKENS: usize = 4;
/// Longest accepted token (ACME dns-01 values are 43 base64url characters).
pub const MAX_TOKEN_LEN: usize = 128;
/// Furthest into the future a token expiry may lie.
pub const MAX_TOKEN_LIFETIME: u64 = 3600;

/// One published TXT value and its expiry (a safety net if the worker dies before clearing it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDoc {
    /// The TXT value.
    pub v: String,
    /// Unix time after which it is no longer served.
    pub exp: u64,
}

/// The signed body of a challenge-label object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeDoc {
    /// The tenant the label is bound to.
    pub tenant: String,
    /// The name (no `*.` prefix) the label validates.
    pub name: String,
    /// Live tokens.
    pub tokens: Vec<TokenDoc>,
    /// The binding was released by its tenant. The label stays reserved and is never reissued.
    pub released: bool,
}

/// A validated challenge label state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeState {
    /// Bound tenant.
    pub tenant: TenantId,
    /// Bound name, canonical.
    pub name: String,
    /// Live tokens `(value, expiry)`.
    pub tokens: Vec<(String, u64)>,
    /// Released flag.
    pub released: bool,
    /// Object version.
    pub version: u64,
}

fn label_ok(l: &str) -> bool {
    l.len() == LABEL_LEN
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// The name `<label>.<challenge_zone>` as a wire id.
pub fn label_id(label: &str, challenge_zone: &Name) -> Result<Vec<u8>, ValidationError> {
    if !label_ok(label) {
        return Err(ValidationError::Name("challenge label shape"));
    }
    let n = parse_fqdn_no_wildcard(&format!("{label}.{}", challenge_zone.to_ascii()))?;
    Ok(names::wire_id(&n))
}

/// Validate the object id and body of a challenge object. Returns the label and state.
pub fn parse_challenge(
    id: &[u8],
    challenge_zone: &Name,
    version: u64,
    body: &[u8],
    now: u64,
) -> Result<(String, ChallengeState), ValidationError> {
    if body.len() > 4096 {
        return Err(ValidationError::Limit("challenge body"));
    }
    let n = names::from_wire_id(id)?;
    if usize::from(n.num_labels()) != usize::from(challenge_zone.num_labels()) + 1
        || !challenge_zone.zone_of(&n)
    {
        return Err(ValidationError::Name(
            "challenge id is not exactly one label under the challenge zone",
        ));
    }
    let label = n
        .iter()
        .next()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .unwrap_or_default();
    if !label_ok(&label) {
        return Err(ValidationError::Name("challenge label shape"));
    }
    let doc: ChallengeDoc = serde_json::from_slice(body).map_err(|_| ValidationError::Parse)?;
    let name = names::canonical(&doc.name)?;
    if name.split('.').any(|l| l == "*") {
        return Err(ValidationError::Name(
            "challenge name must not contain a wildcard",
        ));
    }
    if doc.tokens.len() > MAX_TOKENS {
        return Err(ValidationError::Limit("tokens per label"));
    }
    let mut tokens = Vec::new();
    for t in doc.tokens {
        let ok = !t.v.is_empty()
            && t.v.len() <= MAX_TOKEN_LEN
            && t.v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(ValidationError::Rdata("token charset or length"));
        }
        if t.exp > now.saturating_add(MAX_TOKEN_LIFETIME) {
            return Err(ValidationError::Ttl);
        }
        tokens.push((t.v, t.exp));
    }
    if doc.released && !tokens.is_empty() {
        return Err(ValidationError::Conflict(
            "a released label carries no tokens",
        ));
    }
    Ok((
        label,
        ChallengeState {
            tenant: TenantId::new(&doc.tenant)?,
            name,
            tokens,
            released: doc.released,
            version,
        },
    ))
}
