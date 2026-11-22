//! Error types. Messages never embed tenant-controlled text unescaped: where a tenant string
//! must be named, it goes through [`crate::escape::esc`].

use core::fmt;

/// Why a name, record, zone body or update was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A name or label broke the syntax rules (length, charset, wildcard placement).
    Name(&'static str),
    /// A record's data was out of range or malformed.
    Rdata(&'static str),
    /// A TTL outside the allowed window.
    Ttl,
    /// A record name that is not at or under the zone apex.
    OutsideApex,
    /// The same `RRset` constrained by CNAME exclusivity or singleton rules.
    Conflict(&'static str),
    /// A size or count cap was exceeded.
    Limit(&'static str),
    /// The body did not parse (JSON shape, unknown field/type).
    Parse,
    /// A tenant identifier broke the identifier rules.
    Tenant,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Name(w) => write!(f, "invalid name: {w}"),
            ValidationError::Rdata(w) => write!(f, "invalid rdata: {w}"),
            ValidationError::Ttl => f.write_str("ttl outside the allowed window"),
            ValidationError::OutsideApex => f.write_str("record name is outside the zone apex"),
            ValidationError::Conflict(w) => write!(f, "record conflict: {w}"),
            ValidationError::Limit(w) => write!(f, "limit exceeded: {w}"),
            ValidationError::Parse => f.write_str("zone body does not parse"),
            ValidationError::Tenant => f.write_str("invalid tenant identifier"),
        }
    }
}

impl std::error::Error for ValidationError {}
