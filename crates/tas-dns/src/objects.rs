//! Constructors for the signed objects the control plane and zone owners produce.
//!
//! These are the *author* side of the replication protocol: the registrar signs registrations,
//! an owner signs whole-zone snapshots. Nodes never call these; they only verify.

use crate::names::{parse_fqdn_no_wildcard, wire_id};
use crate::zone::{hex32, DnssecPolicy, RegState, RegistrationDoc};
use transport::signed_dns::Keypair;
use transport::zone_sync::{ObjectKind, SignedObject, SyncError};

/// What a registration says (the delegation act's content).
#[derive(Debug, Clone)]
pub struct RegistrationSpec<'a> {
    /// The apex being delegated.
    pub apex: &'a str,
    /// Owning tenant.
    pub tenant: &'a str,
    /// The zone owner's Ed25519 public key (dialkey-derived).
    pub owner: [u8; 32],
    /// Owner epoch (bump when the owner key changes).
    pub owner_epoch: u64,
    /// Registration sequence number (strictly increasing).
    pub seq: u64,
    /// Active or released.
    pub state: RegState,
    /// For a release: no other tenant may register the apex before this unix time.
    pub quarantine_until: u64,
    /// DNSSEC policy, if the zone is to be signed.
    pub dnssec: Option<DnssecPolicy>,
}

/// Sign a registration (the delegation act). `registrar` is the control plane's key.
pub fn registration_object(
    registrar: &Keypair,
    spec: &RegistrationSpec<'_>,
) -> Result<SignedObject, SyncError> {
    let apex_name = parse_fqdn_no_wildcard(spec.apex).map_err(|_| SyncError::Malformed("apex"))?;
    let doc = RegistrationDoc {
        apex: apex_name.to_ascii().trim_end_matches('.').to_string(),
        tenant: spec.tenant.to_string(),
        owner: hex32(&spec.owner),
        state: spec.state,
        quarantine_until: spec.quarantine_until,
        dnssec: spec.dnssec,
    };
    let body = serde_json::to_vec(&doc).map_err(|_| SyncError::Malformed("registration body"))?;
    SignedObject::sign(
        registrar,
        ObjectKind::Registration,
        wire_id(&apex_name),
        spec.owner_epoch,
        spec.seq,
        body,
    )
}

/// Sign a whole-zone snapshot as the zone owner. `body` is the JSON records document.
pub fn update_object(
    owner: &Keypair,
    apex: &str,
    epoch: u64,
    version: u64,
    body: &[u8],
) -> Result<SignedObject, SyncError> {
    let apex_name = parse_fqdn_no_wildcard(apex).map_err(|_| SyncError::Malformed("apex"))?;
    SignedObject::sign(
        owner,
        ObjectKind::Update,
        wire_id(&apex_name),
        epoch,
        version,
        body.to_vec(),
    )
}
