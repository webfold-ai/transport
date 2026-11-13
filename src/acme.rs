//! ACME v2 (RFC 8555) client — the piece `edge.rs`'s own doc comment for [`crate::edge::CertSource`]
//! called out as missing: "a file/Vault-backed source works today; **an ACME client (JWS, order
//! flow, DNS-01 against...) is eventually.**" This is that client, supporting both challenge
//! types: HTTP-01 ([`AcmeClient::issue`] — the default, no DNS provider API dependency, and
//! the edge already terminates plain HTTP for exactly this purpose per
//! [`crate::edge::HostnameRecord::requires_tls`]) and DNS-01 ([`AcmeClient::issue_dns01`] —
//! required for wildcard names, the only way to validate `*.tascloud.app` because no HTTP
//! request can be made to a wildcard, and the natural choice for any apex under an HSTS-
//! preloaded TLD where the browser refuses plaintext before the cert exists).
//!
//! **Certificate keys are ECDSA P-256, not Ed25519.** The first version of this client
//! finalized with an Ed25519 CSR. Publicly trusted CAs do not issue Ed25519 subscriber
//! certificates (the CA/Browser Forum Baseline Requirements permit only RSA and ECDSA
//! P-256/P-384/P-521 keys; Let's Encrypt rejects the CSR), so every real order would have
//! failed at `finalize` — after the authorizations had already consumed validation rate
//! limit. P-256 is also exactly the intersection with what the edge can serve: the serving
//! provider (`hashtrinity::rustls`) loads Ed25519 and ECDSA-P256 PKCS#8 keys only.
//!
//! **The crypto is not reinvented here.** `apeiron::map::hashtrinity::crypto::{jwt,acme,certgen}` already
//! carries the non-secret primitives ACME needs — (the JWS signing and key generation are
//! `aws-lc-rs`, see [`AccountKey`]),
//! `b64url`/`jwk_thumbprint_ec_p256` (RFC 7638), `acme_key_authorization` (RFC 8555 §8.1), and
//! down to a doc comment on the `acme`
//! submodule explicitly scoping itself as "the thumbprint + key-authorization + CSR; **the HTTP
//! flow is a client**." Nor is the HTTP transport reinvented: [`crate::http_client::Client`] is
//! already this crate's real TLS+HTTP/1.1 client (used today by [`crate::pkarr::RelayClient`]) —
//! this module is only the ACME-specific part: directory discovery, nonce handling, JWS envelope
//! construction, and the account/order/authorization/challenge/finalize state machine.
//!
//! **DNS-01 responder.** The edge already has the authoritative DNS for the apex zones it
//! issues for ([`crate::edge_dns::ZoneAuthority`]). The DNS-01 wiring is
//! [`crate::edge_dns::Dns01Authority`] — an `Arc<Mutex<ZoneAuthority>>` wrapped to implement
//! [`Dns01Responder`]. `publish_txt(name, value)` calls `set_acme_token(name, value)`; a real
//! resolver asking `_acme-challenge.<name>` TXT then gets the token back. `remove_txt` does the
//! inverse with `clear_acme_token`. `edge_dns.rs`'s test suite (`acme_dns01_tokens_are_served_and_can_be_cleared`,
//! `two_concurrent_orders_both_get_their_token`) covers the underlying storage; the
//! `acme_dns01_responder_round_trips_through_edge_dns` test below exercises the trait impl
//! itself, so a regression in either half is caught.
//!
//! **Beyond the basic order flow**: External Account Binding for CAs that require it
//! ([`AcmeClient::new_with_eab`], RFC 8555 §7.3.4), account key rollover
//! ([`AcmeClient::rollover_account_key`], §7.3.5), ACME Renewal Information
//! ([`AcmeClient::renewal_info`], RFC 9773 — consumed by [`crate::acme_renew`]'s engine), the
//! `replaces` member of `newOrder` so a renewal is recognised as one
//! ([`AcmeClient::issue_replacing`], RFC 9773 §5) and certificate revocation
//! ([`AcmeClient::revoke_certificate`], RFC 8555 §7.6) signed either by the account or — for the
//! key-compromise case, or when the account that ordered the certificate is gone — by the
//! certificate's own key ([`AcmeClient::revoke_certificate_with_key`]).
//!
//! **What's genuinely verified here vs. not**: every pure step (JWS/JWK construction, the
//! flattened-JSON envelope ACME's wire format needs — not the compact `a.b.c` form
//! `jwt_sign_es256` returns — the CSR's PKCS#8 key wrapping, the DNS-01 responder round-trip
//! through the edge authoritative DNS) has a real unit test. The end-to-end HTTP flow
//! against a live ACME server (Let's Encrypt or a local Pebble instance) is NOT exercised
//! by an automated test in this sandbox — no outbound HTTPS to a real CA, no public HTTP-01
//! listener, and no real DNS-01 resolver are available here. That is a real, disclosed gap,
//! not a silently-assumed one.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use apeiron::map::hashtrinity::crypto::acme::{
    acme_key_authorization, b64url, jwk_thumbprint_ec_p256,
};
use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::certkey::{CertKeyGen, KeyAlg, KeyPolicy, OsCertKeyGen};
use crate::edge::CertMaterial;
use crate::http_client::Client;
use crate::http_types::header;

/// Let's Encrypt's real production and staging directories — the two URLs any real deployment
/// actually points at. Not fetched by default; callers pass one to [`AcmeClient::new`].
pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Hand-rolled rather than derived: this crate's own [`crate::http_types::Error`] takes the same
/// approach (plain enum + manual `Display`/`std::error::Error`) rather than a `thiserror`
/// dependency, and there is nothing here a derive macro would meaningfully shorten.
#[derive(Debug)]
pub enum AcmeError {
    Http(crate::http_types::Error),
    BadResponse(String),
    Rejected {
        status: u16,
        detail: String,
    },
    /// The CA is rate limiting this account or identifier set (HTTP 429 or a `rateLimited`
    /// problem). Distinct from `Rejected` because the right response is to wait, not to
    /// retry on the normal schedule — hammering a rate limit extends it.
    RateLimited {
        retry_after_secs: Option<u64>,
        detail: String,
    },
    MissingNonce,
    AuthorizationFailed(String),
    OrderNotValid,
    ChallengeSetup,
    /// Something on our side stopped the order before or after the CA was involved: the system
    /// RNG failed generating the certificate key, the key was refused by the key policy, the CSR
    /// could not be signed. Never a reason to try another CA.
    Local(String),
    /// The CA answered, but with a certificate or response that cannot be right: the issued
    /// certificate does not certify the key we asked for, or lacks the names we asked for.
    CaMisbehaved(String),
}

/// What kind of failure an [`AcmeError`] is — the input to the CA fail-over decision
/// ([`crate::ca_resilience`]). The classes are deliberately few: the engine's only questions are
/// "would another CA help?" and "does this count against this CA's health?".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    /// The CA is rate limiting this account or name set. Waiting is the answer; another CA is
    /// not (and moving a rate-limited renewal elsewhere would hide the problem).
    RateLimited,
    /// Our side failed. Another CA cannot help and the CA's health is not in question.
    Local,
    /// The CA is unreachable, timing out, erroring (5xx, `serverInternal`) or returning junk.
    CaSide,
    /// The CA answered and refused: a 4xx problem, a failed authorization, an order that went
    /// invalid. Might be our configuration (DNS, CAA) or the CA's policy; counts against the CA
    /// after repeated occurrences, and a standby may be tried for the order.
    Refused,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Http(e) => write!(f, "talking to the ACME server: {e}"),
            AcmeError::BadResponse(s) => write!(
                f,
                "ACME server returned a response this client could not parse: {s}"
            ),
            AcmeError::Rejected { status, detail } => {
                write!(f, "ACME server rejected the request ({status}): {detail}")
            }
            AcmeError::RateLimited {
                retry_after_secs,
                detail,
            } => match retry_after_secs {
                Some(s) => write!(
                    f,
                    "ACME server is rate limiting us (retry after {s}s): {detail}"
                ),
                None => write!(f, "ACME server is rate limiting us: {detail}"),
            },
            AcmeError::MissingNonce => write!(
                f,
                "no Replay-Nonce header on a response that was supposed to carry one"
            ),
            AcmeError::AuthorizationFailed(url) => {
                write!(f, "authorization {url} did not reach the valid state")
            }
            AcmeError::OrderNotValid => {
                write!(f, "order did not reach the valid state after finalization")
            }
            AcmeError::ChallengeSetup => {
                write!(f, "ACME challenge responder rejected publishing the proof")
            }
            AcmeError::Local(s) => write!(f, "local failure before the CA could issue: {s}"),
            AcmeError::CaMisbehaved(s) => {
                write!(f, "the CA returned something that cannot be right: {s}")
            }
        }
    }
}

impl std::error::Error for AcmeError {}

impl AcmeError {
    /// Whether the CA refused with the ACME problem `urn:ietf:params:acme:error:{kind}`
    /// (RFC 8555 §6.7), e.g. `"unauthorized"` or `"alreadyReplaced"`.
    #[must_use]
    pub fn is_problem(&self, kind: &str) -> bool {
        matches!(self, AcmeError::Rejected { detail, .. } if detail.contains(&format!("urn:ietf:params:acme:error:{kind}")))
    }

    /// How to treat this failure when deciding whether to change CA (see [`FailureClass`]).
    #[must_use]
    pub fn class(&self) -> FailureClass {
        match self {
            AcmeError::RateLimited { .. } => FailureClass::RateLimited,
            AcmeError::ChallengeSetup | AcmeError::Local(_) => FailureClass::Local,
            AcmeError::Http(_)
            | AcmeError::BadResponse(_)
            | AcmeError::MissingNonce
            | AcmeError::CaMisbehaved(_) => FailureClass::CaSide,
            AcmeError::Rejected { status, .. } if *status >= 500 => FailureClass::CaSide,
            AcmeError::Rejected { .. } if self.is_problem("serverInternal") => FailureClass::CaSide,
            AcmeError::Rejected { .. }
            | AcmeError::AuthorizationFailed(_)
            | AcmeError::OrderNotValid => FailureClass::Refused,
        }
    }

    /// Seconds the CA asked us to wait, if it said.
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            AcmeError::RateLimited {
                retry_after_secs, ..
            } => *retry_after_secs,
            _ => None,
        }
    }
}

impl From<crate::http_types::Error> for AcmeError {
    fn from(e: crate::http_types::Error) -> Self {
        AcmeError::Http(e)
    }
}

/// The account signing key — P-256 ECDSA, the most broadly supported ACME account key type.
/// Generate once per account and persist it; a lost account key just means re-registering (an
/// ACME account carries no certificate state itself, only authorization history).
///
/// All key generation and signing is `aws-lc-rs` (FIPS-validated with the `fips` feature,
/// constant-time scalar arithmetic). The previous implementation used a hand-written P-256 whose
/// scalar multiplication branched on secret bits.
#[derive(Clone)]
pub struct AccountKey {
    pair: std::sync::Arc<EcdsaKeyPair>,
}

impl AccountKey {
    /// A fresh random account key.
    ///
    /// # Errors
    /// Only if the system RNG fails.
    pub fn generate() -> Result<Self, AcmeError> {
        Self::generate_with(&OsCertKeyGen)
    }

    /// [`Self::generate`] through an explicit generator (the test seam; production is [`OsCertKeyGen`]).
    ///
    /// # Errors
    /// If the generator fails.
    pub fn generate_with(keygen: &dyn CertKeyGen) -> Result<Self, AcmeError> {
        let pair = keygen
            .generate(KeyAlg::P256)
            .map_err(|e| AcmeError::Local(e.to_string()))?;
        Ok(AccountKey {
            pair: std::sync::Arc::new(pair),
        })
    }

    /// Wrap an existing 32-byte P-256 private scalar (e.g. loaded from a sealed store).
    ///
    /// # Errors
    /// If the scalar is zero or not below the curve order.
    pub fn from_bytes(secret: [u8; 32]) -> Result<Self, AcmeError> {
        // RFC 5915 ECPrivateKey { version 1, privateKey }; the public point is derived on parse.
        let ec_private_key = der::seq(&[der::uint(&[1]), der::tlv(0x04, &secret)]);
        let pair =
            EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &ec_private_key)
                .map_err(|e| AcmeError::BadResponse(format!("invalid P-256 account key: {e}")))?;
        Ok(AccountKey {
            pair: std::sync::Arc::new(pair),
        })
    }

    /// Load a P-256 key from the PKCS#8 PEM this module writes for certificate keys
    /// (`CertMaterial::key_pem`), so the certificate's own key can sign a revocation (RFC 8555
    /// §7.6: the JWS is signed with the key of the certificate being revoked). Same type as an
    /// account key because that is all a JWS signer is.
    ///
    /// # Errors
    /// If `pem` holds no `PRIVATE KEY` block or the key is not ECDSA P-256. The error never
    /// echoes key material.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, AcmeError> {
        let der = crate::pem::blocks(pem, "PRIVATE KEY")
            .into_iter()
            .next()
            .ok_or_else(|| {
                AcmeError::BadResponse("no PKCS#8 private key in the certificate key PEM".into())
            })?;
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der).map_err(|_| {
                AcmeError::BadResponse(
                    "the certificate key is not an ECDSA P-256 PKCS#8 key".into(),
                )
            })?;
        Ok(AccountKey {
            pair: std::sync::Arc::new(pair),
        })
    }

    /// The raw 32-byte private scalar, for sealing into a store. Handle as a secret.
    ///
    /// # Errors
    /// Only on an internal aws-lc failure.
    pub fn to_bytes(&self) -> Result<[u8; 32], AcmeError> {
        use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
        let bin: EcPrivateKeyBin<'static> = self
            .pair
            .private_key()
            .as_be_bytes()
            .map_err(|_| AcmeError::BadResponse("cannot export account key".into()))?;
        bin.as_ref()
            .try_into()
            .map_err(|_| AcmeError::BadResponse("account key is not 32 bytes".into()))
    }

    /// `x‖y` of the public point.
    fn xy(&self) -> [u8; 64] {
        let mut xy = [0u8; 64];
        // SEC1 uncompressed: 0x04 ‖ x ‖ y
        xy.copy_from_slice(&self.pair.public_key().as_ref()[1..]);
        xy
    }

    /// ES256 over `message` (SHA-256 is applied inside), raw `r‖s` as JWS requires.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AcmeError> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|_| {
                AcmeError::Local("ECDSA signing failed (system RNG or crypto module)".into())
            })
    }

    /// The JWK this key presents in `newAccount`'s protected header (no `kid` yet — the CA
    /// hasn't assigned an account URL until that request succeeds).
    fn jwk(&self) -> Value {
        let xy = self.xy();
        let (x, y) = xy.split_at(32);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(x),
            "y": b64url(y),
        })
    }

    /// RFC 7638 thumbprint of this key's JWK — the key-authorization ingredient.
    #[must_use]
    pub fn thumbprint(&self) -> [u8; 32] {
        let xy = self.xy();
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&xy[..32]);
        yb.copy_from_slice(&xy[32..]);
        jwk_thumbprint_ec_p256(&xb, &yb)
    }
}

/// Load the 32-byte ACME account key at `path`, creating it (0600, atomically, from the system
/// RNG) on first run. One account key per CA.
///
/// # Errors
/// I/O failure, a malformed file, or an RNG failure. A damaged key is **never** silently replaced:
/// a new key is a new ACME account, which would orphan the CAA `accounturi` published for the old.
pub fn load_or_create_account_key(path: &std::path::Path) -> Result<AccountKey, AcmeError> {
    load_or_create_account_key_with(path, &OsCertKeyGen)
}

/// [`load_or_create_account_key`] through an explicit generator (the test seam).
///
/// # Errors
/// As [`load_or_create_account_key`].
pub fn load_or_create_account_key_with(
    path: &std::path::Path,
    keygen: &dyn CertKeyGen,
) -> Result<AccountKey, AcmeError> {
    let local = |m: String| AcmeError::Local(m);
    match std::fs::read(path) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| local(format!("{} must be exactly 32 bytes", path.display())))?;
            AccountKey::from_bytes(arr).map_err(|e| local(format!("{}: {e}", path.display())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = AccountKey::generate_with(keygen)?;
            let bytes = key.to_bytes()?;
            crate::certkey::write_private_atomic(path, &bytes)
                .map_err(|e| local(format!("{}: {e}", path.display())))?;
            Ok(key)
        }
        Err(e) => Err(local(format!("{}: {e}", path.display()))),
    }
}

/// The credentials a CA hands out for External Account Binding (RFC 8555 §7.3.4): a key
/// identifier and an HMAC key that tie a new ACME account to an account the CA already knows
/// (a customer in its billing system). ZeroSSL, Google Trust Services, Sectigo and most
/// commercial CAs require it on `newAccount`; Let's Encrypt does not.
///
/// The key is a secret: `Debug` prints the `kid` and redacts the key, and nothing in this module
/// logs it.
#[derive(Clone)]
pub struct ExternalAccountBinding {
    /// The CA's key identifier (the `kid` of the binding JWS — not the ACME account URL).
    pub kid: String,
    /// The raw HMAC-SHA-256 key.
    pub hmac_key: Vec<u8>,
}

impl ExternalAccountBinding {
    /// From the base64url key as CAs publish it. Unpadded base64url is what RFC 8555 §7.3.4 and
    /// the CAs' dashboards use; trailing `=` padding, surrounding whitespace and (since the two
    /// alphabets do not overlap) the standard `+`/`/` alphabet are tolerated too.
    ///
    /// # Errors
    /// If `key_b64` is not valid base64 or decodes to nothing.
    pub fn from_base64url(kid: impl Into<String>, key_b64: &str) -> Result<Self, AcmeError> {
        let standard = key_b64.trim().replace('-', "+").replace('_', "/");
        match crate::pem::base64_decode(&standard) {
            Some(hmac_key) if !hmac_key.is_empty() => Ok(ExternalAccountBinding {
                kid: kid.into(),
                hmac_key,
            }),
            _ => Err(AcmeError::BadResponse(
                "external account binding key is not valid base64url".to_string(),
            )),
        }
    }

    /// The `externalAccountBinding` member of the `newAccount` payload: a flattened JWS whose
    /// protected header is `{alg: HS256, kid, url}` (no nonce — RFC 8555 §7.3.4), whose payload
    /// is the account's public JWK, MACed with the CA's key.
    fn jws(&self, account: &AccountKey, new_account_url: &str) -> Value {
        let protected_b64 = b64url(
            json!({ "alg": "HS256", "kid": self.kid, "url": new_account_url })
                .to_string()
                .as_bytes(),
        );
        let payload_b64 = b64url(account.jwk().to_string().as_bytes());
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.hmac_key);
        let tag = hmac::sign(&key, format!("{protected_b64}.{payload_b64}").as_bytes());
        json!({ "protected": protected_b64, "payload": payload_b64, "signature": b64url(tag.as_ref()) })
    }
}

impl std::fmt::Debug for ExternalAccountBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalAccountBinding")
            .field("kid", &self.kid)
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

/// Build the flattened-JSON JWS body ACME's wire format requires: `{"protected","payload","signature"}`
/// as JSON string members, not the compact `header.payload.sig` dot form (that form is for tokens
/// carried inside another envelope, e.g. an `Authorization:` header — ACME's own request bodies
/// ARE the JWS, JSON-serialized).
///
/// `payload_json` is `""` for a POST-as-GET (RFC 8555 §6.3) — the empty string, not `"{}"` or
/// `null`, per the spec's own worked examples.
fn flattened_jws(
    account: &AccountKey,
    protected: &Value,
    payload_json: &str,
) -> Result<String, AcmeError> {
    let protected_b64 = b64url(protected.to_string().as_bytes());
    let payload_b64 = b64url(payload_json.as_bytes());
    let sig = account.sign(format!("{protected_b64}.{payload_b64}").as_bytes())?;
    Ok(json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(&sig),
    })
    .to_string())
}

/// How a request identifies its signer (RFC 8555 §6.2: exactly one of `jwk`/`kid`).
enum Auth<'a> {
    /// The account's `kid`, signed by the account key — everything after `newAccount`.
    Kid,
    /// The account's public JWK, signed by the account key — `newAccount` itself.
    AccountJwk,
    /// A public JWK that is **not** the account's, signed by the matching private key — the
    /// certificate's own key, for a revocation (RFC 8555 §7.6).
    KeyJwk(&'a AccountKey),
}

/// The protected header for a request signed with the account's own key + `kid` (every request
/// after `newAccount` succeeds).
fn protected_header_kid(kid: &str, nonce: &str, url: &str) -> Value {
    json!({ "alg": "ES256", "kid": kid, "nonce": nonce, "url": url })
}

/// The protected header for `newAccount` itself — no `kid` yet, so the JWK travels instead
/// (RFC 8555 §6.2: exactly one of `jwk`/`kid` on every request).
fn protected_header_jwk(account: &AccountKey, nonce: &str, url: &str) -> Value {
    json!({ "alg": "ES256", "jwk": account.jwk(), "nonce": nonce, "url": url })
}

#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    /// Account key rollover endpoint (RFC 8555 §7.3.5); a CA that does not offer it makes
    /// [`AcmeClient::rollover_account_key`] fail with an explanatory error.
    #[serde(rename = "keyChange", default)]
    pub key_change: Option<String>,
    /// ACME Renewal Information base URL (RFC 9773); `None` for a CA without ARI.
    #[serde(rename = "renewalInfo", default)]
    pub renewal_info: Option<String>,
    /// Certificate revocation endpoint (RFC 8555 §7.6); `None` makes
    /// [`AcmeClient::revoke_certificate`] fail with an explanatory error.
    #[serde(rename = "revokeCert", default)]
    pub revoke_cert: Option<String>,
    /// The CA's `meta` object: terms of service, and the ACME profiles it offers.
    #[serde(default)]
    pub meta: DirectoryMeta,
}

/// The parts of a directory's `meta` this client reads.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DirectoryMeta {
    /// Certificate profiles the CA offers (draft-ietf-acme-profiles): name -> description.
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, String>,
}

/// Why a certificate is being revoked — the RFC 5280 `CRLReason` subset that RFC 8555 §7.6 and
/// the public CAs accept for a subscriber-initiated revocation. The wire value is the numeric code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    /// The private key is, or may be, in someone else's hands. The CA may then revoke other
    /// certificates sharing the key and blocks the key from future issuance.
    KeyCompromise,
    AffiliationChanged,
    Superseded,
    /// The name is no longer in service — what releasing a customer hostname is.
    CessationOfOperation,
}

impl RevocationReason {
    /// The RFC 5280 `CRLReason` code sent as `reason`.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            RevocationReason::Unspecified => 0,
            RevocationReason::KeyCompromise => 1,
            RevocationReason::AffiliationChanged => 3,
            RevocationReason::Superseded => 4,
            RevocationReason::CessationOfOperation => 5,
        }
    }
}

/// What a revocation request achieved. Both are success: a certificate someone already revoked
/// (a retry whose first attempt landed but whose answer was lost, or an operator who revoked it
/// by hand) is exactly as revoked as one we just did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationOutcome {
    Revoked,
    /// The CA answered `alreadyRevoked` (RFC 8555 §7.6).
    AlreadyRevoked,
}

/// The CA's advice on when to renew one certificate (RFC 9773 `suggestedWindow`), unix seconds.
/// Any instant in `start..=end` is acceptable to the CA; spreading renewals across the window
/// (see [`crate::acme_renew::ari_renew_at`]) is what lets it smooth load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalWindow {
    pub start: i64,
    pub end: i64,
    /// A human-readable page explaining why the CA suggests this window (`explanationURL`).
    pub explanation_url: Option<String>,
    /// The CA's `Retry-After` for this resource: seconds before asking again.
    pub retry_after_secs: Option<u64>,
}

#[derive(Deserialize)]
struct RenewalInfoResponse {
    #[serde(rename = "suggestedWindow")]
    suggested_window: SuggestedWindow,
    #[serde(rename = "explanationURL", default)]
    explanation_url: Option<String>,
}

#[derive(Deserialize)]
struct SuggestedWindow {
    start: String,
    end: String,
}

/// A `renewalInfo` response body -> window. RFC 9773 §4.2 makes a window whose `end` does not
/// follow its `start` invalid, so it is an error here rather than a renew-immediately signal.
fn parse_renewal_info(
    body: &str,
    retry_after_secs: Option<u64>,
) -> Result<RenewalWindow, AcmeError> {
    let info: RenewalInfoResponse = serde_json::from_str(body)
        .map_err(|e| AcmeError::BadResponse(format!("renewalInfo: {e}")))?;
    let time = |what: &str, v: &str| {
        parse_rfc3339(v).ok_or_else(|| {
            AcmeError::BadResponse(format!(
                "renewalInfo: suggestedWindow.{what} {v:?} is not an RFC 3339 timestamp"
            ))
        })
    };
    let (start, end) = (
        time("start", &info.suggested_window.start)?,
        time("end", &info.suggested_window.end)?,
    );
    if end <= start {
        return Err(AcmeError::BadResponse(
            "renewalInfo: suggestedWindow ends before it starts".to_string(),
        ));
    }
    Ok(RenewalWindow {
        start,
        end,
        explanation_url: info.explanation_url,
        retry_after_secs,
    })
}

/// The RFC 9773 §4.1 certificate ID for the leaf of `chain_pem`: the base64url of the Authority
/// Key Identifier's `keyIdentifier`, `.`, and the base64url of the serial number's DER INTEGER
/// content octets. The content octets are used as encoded — including the leading `0x00` DER
/// adds when the serial's high bit is set (RFC 9773 appendix A: serial `0x87654321` is
/// `AIdlQyE`, not `h2VDIQ`). `None` if there is no certificate, no AKI `keyIdentifier`, or the
/// DER is malformed.
#[must_use]
pub fn ari_cert_id(chain_pem: &str) -> Option<String> {
    let cert = crate::pem::blocks(chain_pem, "CERTIFICATE")
        .into_iter()
        .next()?;
    let (aki, serial) = der::aki_and_serial(&cert)?;
    Some(format!("{}.{}", b64url(aki), b64url(serial)))
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrderResponse {
    pub status: String,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationResponse {
    pub status: String,
    pub identifier: Identifier,
    pub challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    /// Present for `http-01`/`dns-01`/`tls-alpn-01`. Other challenge types a CA may offer
    /// alongside them (newer drafts) have no token — they must not make the whole authorization
    /// unparseable, since we only ever act on the two types we implement.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub status: String,
    /// The problem document the CA attaches to a failed challenge.
    #[serde(default)]
    pub error: Option<Value>,
}

/// Registers/deregisters the token an HTTP-01 challenge needs served at
/// `/.well-known/acme-challenge/{token}` — implemented by whatever owns the edge's real HTTP
/// listener (`biota-http-server`'s `kernel::Proxy`/`Router`, in this workspace), so this crate
/// never needs to depend on an HTTP server to prove domain control over HTTP.
///
/// Returns a boxed future rather than an `async fn` so the trait stays object-safe (this crate's
/// own [`crate::Connection`]/[`crate::Transport`] traits use the same [`crate::BoxFuture`]
/// pattern rather than pulling in an `async-trait` dependency).
pub trait Http01Responder: Send + Sync {
    fn serve_token<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
    ) -> crate::BoxFuture<'a, Result<(), AcmeError>>;
    fn remove_token<'a>(&'a self, token: &'a str) -> crate::BoxFuture<'a, ()>;
}

/// Publishes a DNS-01 TXT value at `_acme-challenge.{name}`. `publish_txt` must
/// return only once the CA can query the authoritative DNS server for the value.
/// Removing one value must preserve any other concurrent challenge at that name.
pub trait Dns01Responder: Send + Sync {
    fn publish_txt<'a>(
        &'a self,
        name: &'a str,
        value: &'a str,
    ) -> crate::BoxFuture<'a, Result<(), AcmeError>>;
    fn remove_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, ()>;
}

enum ChallengeResponder<'a> {
    Http(&'a dyn Http01Responder),
    Dns(&'a dyn Dns01Responder),
}

fn header_str(resp: &crate::http_types::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// How an [`AcmeClient`] generates certificate keys and bounds its requests.
#[derive(Clone)]
pub struct ClientOptions {
    /// Where certificate keys come from. Production: [`OsCertKeyGen`]; tests inject a failing one.
    pub keygen: Arc<dyn CertKeyGen>,
    /// The algorithm of the certificate key generated for each order.
    pub key_alg: KeyAlg,
    /// What a certificate key may be. Applied to the algorithm before generating and to the key
    /// after.
    pub key_policy: KeyPolicy,
    /// How long one request to the CA (connect, send, read the whole answer) may take. The HTTP
    /// client has no deadline of its own; without this a CA that accepts the connection and then
    /// says nothing would hang issuance forever, which is the failure a CA-fail-over exists for.
    pub request_timeout: Duration,
    /// The ACME profile to request in `newOrder` (draft-ietf-acme-profiles) -- e.g. a CA's
    /// `tlsserver` profile, which drops client-auth EKU and the subject common name. Sent only
    /// when the CA's directory advertises that profile; otherwise the order is placed without it
    /// (a CA that does not know a profile rejects the order, which would be worse than the default).
    pub profile: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            keygen: Arc::new(OsCertKeyGen),
            key_alg: KeyAlg::P256,
            key_policy: KeyPolicy::default(),
            request_timeout: Duration::from_secs(60),
            profile: None,
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("key_alg", &self.key_alg)
            .field("key_policy", &self.key_policy)
            .field("request_timeout", &self.request_timeout)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// `fut`, abandoned with an [`AcmeError::Http`] if it takes longer than `limit`.
async fn bounded<T>(
    limit: Duration,
    what: &str,
    fut: impl std::future::Future<Output = Result<T, AcmeError>>,
) -> Result<T, AcmeError> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(AcmeError::Http(crate::http_types::Error::Http(format!(
            "{what} timed out after {}s",
            limit.as_secs()
        )))),
    }
}

/// One ACME account + its live nonce, driving the order/authorization/challenge/finalize state
/// machine against a real ACME server via [`crate::http_client::Client`].
pub struct AcmeClient {
    directory_url: String,
    opts: ClientOptions,
    directory: Directory,
    /// Behind a lock because [`Self::rollover_account_key`] swaps it; every request snapshots it
    /// (`AccountKey` is a cheap `Arc` clone), so a request is always signed by one whole key.
    account: StdMutex<AccountKey>,
    kid: StdMutex<Option<String>>,
    nonce: StdMutex<Option<String>>,
}

/// Seconds since the unix epoch (0 if the clock is before it).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A `Retry-After` value (RFC 9110 §10.2.3) as a delay in seconds: either `delay-seconds` or an
/// HTTP-date (`Sun, 06 Nov 1994 08:49:37 GMT`), measured from `now`. A date in the past is a delay
/// of 0. Anything else is `None` — the caller falls back to its own backoff.
#[must_use]
pub fn parse_retry_after(value: &str, now: i64) -> Option<u64> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(secs);
    }
    let when = parse_imf_fixdate(v)?;
    Some(u64::try_from(when.saturating_sub(now)).unwrap_or(0))
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` -> unix seconds. Only the preferred IMF-fixdate form (the one
/// HTTP/1.1 senders MUST generate); the obsolete RFC 850 / asctime forms are not accepted.
fn parse_imf_fixdate(v: &str) -> Option<i64> {
    let (_, rest) = v.split_once(", ")?;
    let mut it = rest.split(' ');
    let day: i64 = it.next()?.parse().ok()?;
    let month = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let (h, m, s): (i64, i64, i64) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    if it.next()? != "GMT"
        || it.next().is_some()
        || !(1..=31).contains(&day)
        || h > 23
        || m > 59
        || s > 60
        || !(1970..=9999).contains(&year)
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + s)
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard Hinnant's algorithm).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An RFC 3339 timestamp (`2026-10-15T08:30:00Z`, `...:00.123+10:00`) -> unix seconds, the
/// fraction truncated. Strict: fixed-width fields, a real calendar date, `T` between date and
/// time, and a mandatory `Z`/`±HH:MM` offset — what ACME servers emit for RFC 9773's
/// `suggestedWindow`, with nothing lenient to mis-parse a hostile response.
pub(crate) fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if !s.is_ascii() {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let d = b.get(from..to)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |acc, c| acc * 10 + i64::from(c - b'0')))
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(at(4, b'-')
        && at(7, b'-')
        && (at(10, b'T') || at(10, b't'))
        && at(13, b':')
        && at(16, b':'))
    {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if year < 1
        || !(1..=12).contains(&month)
        || !(1..=days_in_month).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let mut i = 19;
    if at(i, b'.') {
        let digits_from = i + 1;
        i = digits_from;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == digits_from {
            return None;
        }
    }
    let offset = if (at(i, b'Z') || at(i, b'z')) && b.len() == i + 1 {
        0
    } else if (at(i, b'+') || at(i, b'-')) && b.len() == i + 6 && at(i + 3, b':') {
        let secs = num(i + 1, i + 3).filter(|h| *h <= 23)? * 3600
            + num(i + 4, i + 6).filter(|m| *m <= 59)? * 60;
        if at(i, b'-') {
            -secs
        } else {
            secs
        }
    } else {
        return None;
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec - offset)
}

impl AcmeClient {
    /// Fetch the directory and register the account (RFC 8555's `newAccount` is idempotent for
    /// an already-registered key: the CA returns the existing account's URL as `Location`).
    ///
    /// # Errors
    /// Any transport failure, or the CA rejecting account creation.
    pub async fn new(
        directory_url: &str,
        account: AccountKey,
        contact_email: Option<&str>,
    ) -> Result<Self, AcmeError> {
        Self::new_with_eab(directory_url, account, contact_email, None).await
    }

    /// [`Self::new`] for a CA that requires External Account Binding (RFC 8555 §7.3.4): the
    /// `newAccount` request carries an `externalAccountBinding` JWS proving the caller holds
    /// `eab`'s CA-issued credentials. `None` is exactly [`Self::new`]. A CA that requires a
    /// binding and gets none answers `externalAccountRequired`, surfaced as
    /// [`AcmeError::Rejected`].
    ///
    /// # Errors
    /// Any transport failure, or the CA rejecting account creation (including a binding it does
    /// not recognise).
    pub async fn new_with_eab(
        directory_url: &str,
        account: AccountKey,
        contact_email: Option<&str>,
        eab: Option<ExternalAccountBinding>,
    ) -> Result<Self, AcmeError> {
        Self::connect(
            directory_url,
            account,
            contact_email,
            eab,
            ClientOptions::default(),
        )
        .await
    }

    /// [`Self::new_with_eab`] with explicit [`ClientOptions`]: the certificate key algorithm and
    /// generator, the key policy and the per-request deadline.
    ///
    /// # Errors
    /// As [`Self::new_with_eab`], plus a key algorithm the policy refuses.
    pub async fn connect(
        directory_url: &str,
        account: AccountKey,
        contact_email: Option<&str>,
        eab: Option<ExternalAccountBinding>,
        opts: ClientOptions,
    ) -> Result<Self, AcmeError> {
        opts.key_policy
            .check_alg(opts.key_alg)
            .map_err(|e| AcmeError::Local(e.to_string()))?;
        let body = bounded(opts.request_timeout, "fetching the ACME directory", async {
            Ok(Client::new()
                .get(directory_url)
                .send()
                .await?
                .text()
                .await?)
        })
        .await?;
        let directory: Directory =
            serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

        let client = AcmeClient {
            directory_url: directory_url.to_string(),
            opts,
            directory,
            account: StdMutex::new(account),
            kid: StdMutex::new(None),
            nonce: StdMutex::new(None),
        };
        client.refresh_nonce().await?;
        client.create_account(contact_email, eab.as_ref()).await?;
        Ok(client)
    }

    /// The directory URL this client was created against.
    #[must_use]
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// Whether the CA's directory advertises ACME Renewal Information (RFC 9773).
    #[must_use]
    pub fn supports_ari(&self) -> bool {
        self.directory.renewal_info.is_some()
    }

    /// The key requests are signed with right now.
    fn account(&self) -> AccountKey {
        self.account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn refresh_nonce(&self) -> Result<(), AcmeError> {
        let resp = bounded(self.opts.request_timeout, "fetching an ACME nonce", async {
            Ok(Client::new().head(&self.directory.new_nonce).send().await?)
        })
        .await?;
        let nonce = header_str(&resp, "replay-nonce").ok_or(AcmeError::MissingNonce)?;
        *self.nonce.lock().unwrap() = Some(nonce);
        Ok(())
    }

    fn take_nonce(&self) -> Result<String, AcmeError> {
        self.nonce
            .lock()
            .unwrap()
            .take()
            .ok_or(AcmeError::MissingNonce)
    }

    fn store_nonce_from(&self, resp: &crate::http_types::Response) {
        if let Some(n) = header_str(resp, "replay-nonce") {
            *self.nonce.lock().unwrap() = Some(n);
        }
    }

    async fn create_account(
        &self,
        contact_email: Option<&str>,
        eab: Option<&ExternalAccountBinding>,
    ) -> Result<(), AcmeError> {
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if let Some(email) = contact_email {
            payload["contact"] = json!([format!("mailto:{email}")]);
        }
        if let Some(eab) = eab {
            // No nonce inside the binding, so the same bytes survive a `badNonce` re-sign.
            payload["externalAccountBinding"] =
                eab.jws(&self.account(), &self.directory.new_account);
        }
        // Same nonce/rate-limit handling as every other request; the only difference is that the
        // account does not exist yet, so the JWS carries the public key (`jwk`) instead of a `kid`.
        let (status, kid, body) = self
            .send_jws(
                &self.directory.new_account,
                &payload.to_string(),
                Auth::AccountJwk,
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected {
                status,
                detail: body,
            });
        }
        let kid = kid.ok_or_else(|| {
            AcmeError::BadResponse("newAccount response had no Location".to_string())
        })?;
        *self.kid.lock().unwrap() = Some(kid);
        Ok(())
    }

    /// The CA-assigned account URL (the ACME `kid`) once registered — the value to put in a CAA
    /// `accounturi=` parameter (RFC 8657) so only this account can obtain certificates.
    #[must_use]
    pub fn account_url(&self) -> Option<String> {
        self.kid.lock().ok().and_then(|k| k.clone())
    }

    fn kid(&self) -> Result<String, AcmeError> {
        self.kid
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| AcmeError::BadResponse("no account kid yet".to_string()))
    }

    /// Replace the account's signing key with `new_key` at the CA (RFC 8555 §7.3.5 `keyChange`)
    /// and, once the CA has accepted, sign everything that follows with it. The account URL
    /// ([`Self::account_url`]) and its authorization history are unchanged; the old key stops
    /// working for the account.
    ///
    /// The request is a JWS signed by the OLD key (`kid`, `url` = `keyChange`) whose payload is
    /// an inner JWS signed by the NEW key (`jwk` = the new public key, `url` = `keyChange`, no
    /// nonce) over `{"account": <account URL>, "oldKey": <old public JWK>}` — so the CA sees
    /// both keys vouch for the swap.
    ///
    /// Persist `new_key` (e.g. [`AccountKey::to_bytes`] into the sealed store) as soon as this
    /// returns: the old key no longer identifies the account. If this fails the client keeps
    /// signing with the old key. Do not run orders concurrently with a rollover; one signed
    /// under the old key just before the CA switched is rejected and has to be retried.
    ///
    /// # Errors
    /// The CA's directory has no `keyChange`, `new_key` is the key already in use, any transport
    /// failure, or the CA rejecting the change (e.g. `new_key` already belongs to another
    /// account, a 409).
    pub async fn rollover_account_key(&self, new_key: AccountKey) -> Result<(), AcmeError> {
        let url = self.directory.key_change.as_deref().ok_or_else(|| {
            AcmeError::BadResponse("this CA's directory has no keyChange URL, so it does not support account key rollover".to_string())
        })?;
        let old_key = self.account();
        if old_key.thumbprint() == new_key.thumbprint() {
            return Err(AcmeError::BadResponse(
                "the new account key is the key already in use".to_string(),
            ));
        }
        let inner_payload = json!({ "account": self.kid()?, "oldKey": old_key.jwk() });
        let inner_protected = json!({ "alg": "ES256", "jwk": new_key.jwk(), "url": url });
        let inner = flattened_jws(&new_key, &inner_protected, &inner_payload.to_string())?;
        // The outer JWS is built by `send_jws` like any kid-authenticated request, so it gets the
        // same nonce, `badNonce` and rate-limit handling, signed by the still-current old key.
        let (status, _, body) = self.send_signed(url, &inner).await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected {
                status,
                detail: body,
            });
        }
        *self
            .account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_key;
        Ok(())
    }

    /// The CA's renewal advice for a certificate it issued (ACME Renewal Information, RFC 9773):
    /// the window in which it suggests renewing — typically earlier than the usual schedule when
    /// the certificate is affected by a revocation event or an incident. `chain_pem` is the
    /// certificate chain as issued (only the leaf is read).
    ///
    /// `Ok(None)` when there is no advice: the directory has no `renewalInfo`, or the CA does not
    /// know the certificate (404). The lookup is an unauthenticated GET and costs no nonce.
    /// [`RenewalWindow::retry_after_secs`] is the CA's `Retry-After`: do not ask again sooner.
    ///
    /// # Errors
    /// The certificate has no Authority Key Identifier to build the lookup ID from, any transport
    /// failure, a CA error or rate limit, or a response that is not a valid window.
    pub async fn renewal_info(&self, chain_pem: &str) -> Result<Option<RenewalWindow>, AcmeError> {
        let Some(base) = self.directory.renewal_info.as_deref() else {
            return Ok(None);
        };
        let id = ari_cert_id(chain_pem)
            .ok_or_else(|| AcmeError::BadResponse("certificate has no Authority Key Identifier keyIdentifier, so it has no ARI certificate ID".to_string()))?;
        let (status, retry_after_secs, body) = bounded(
            self.opts.request_timeout,
            "fetching renewal information",
            async {
                let resp = Client::new()
                    .get(format!("{}/{id}", base.trim_end_matches('/')))
                    .send()
                    .await?;
                let status = resp.status().as_u16();
                let retry_after_secs = header_str(&resp, "retry-after")
                    .and_then(|v| parse_retry_after(&v, unix_now()));
                Ok((status, retry_after_secs, resp.text().await?))
            },
        )
        .await?;
        match status {
            200 => parse_renewal_info(&body, retry_after_secs).map(Some),
            404 => Ok(None),
            429 => Err(AcmeError::RateLimited {
                retry_after_secs,
                detail: body,
            }),
            _ => Err(AcmeError::Rejected {
                status,
                detail: body,
            }),
        }
    }

    /// POST a JWS-signed request and return `(status, body)`. `payload_json` is `""` for a
    /// POST-as-GET.
    async fn post_signed(&self, url: &str, payload_json: &str) -> Result<(u16, String), AcmeError> {
        let (status, _, body) = self.send_signed(url, payload_json).await?;
        Ok((status, body))
    }

    /// Same as [`Self::post_signed`] but also returns the `Location` header — `newOrder` is
    /// the call that needs it.
    async fn post_signed_with_location(
        &self,
        url: &str,
        payload_json: &str,
    ) -> Result<(u16, Option<String>, String), AcmeError> {
        self.send_signed(url, payload_json).await
    }

    /// The one place a signed request leaves this client. Handles the two failure modes every
    /// real CA produces routinely and a naive client treats as fatal:
    ///
    /// - **`badNonce`** (RFC 8555 §6.5): a nonce is single-use and the CA may expire it; the
    ///   error response carries a fresh one, so the request is simply re-signed and re-sent.
    /// - **rate limits**: surfaced as [`AcmeError::RateLimited`] with `Retry-After`, so the
    ///   renewal engine can back off for as long as the CA asked.
    async fn send_signed(
        &self,
        url: &str,
        payload_json: &str,
    ) -> Result<(u16, Option<String>, String), AcmeError> {
        self.send_jws(url, payload_json, Auth::Kid).await
    }

    /// [`Self::send_signed`] with the choice of key identification: `AccountJwk` is for
    /// `newAccount` (no account URL exists yet), `KeyJwk` for a revocation signed by the
    /// certificate's key, everything else uses the account `kid`.
    async fn send_jws(
        &self,
        url: &str,
        payload_json: &str,
        auth: Auth<'_>,
    ) -> Result<(u16, Option<String>, String), AcmeError> {
        const MAX_ATTEMPTS: usize = 3;
        for attempt in 1..=MAX_ATTEMPTS {
            let nonce = match self.take_nonce() {
                Ok(n) => n,
                Err(AcmeError::MissingNonce) => {
                    self.refresh_nonce().await?;
                    self.take_nonce()?
                }
                Err(e) => return Err(e),
            };
            let account = self.account();
            let (signer, protected) = match &auth {
                Auth::AccountJwk => (account.clone(), protected_header_jwk(&account, &nonce, url)),
                Auth::Kid => (
                    account.clone(),
                    protected_header_kid(&self.kid()?, &nonce, url),
                ),
                Auth::KeyJwk(key) => ((*key).clone(), protected_header_jwk(key, &nonce, url)),
            };
            let jws = flattened_jws(&signer, &protected, payload_json)?;
            let (status, location, retry_after_secs, body) =
                bounded(self.opts.request_timeout, "an ACME request", async {
                    let resp = Client::new()
                        .post(url)
                        .header(header::CONTENT_TYPE, "application/jose+json")
                        .body(jws.into_bytes())
                        .send()
                        .await?;
                    self.store_nonce_from(&resp);
                    let status = resp.status().as_u16();
                    let location = header_str(&resp, header::LOCATION);
                    let retry_after_secs = header_str(&resp, "retry-after")
                        .and_then(|v| parse_retry_after(&v, unix_now()));
                    Ok((status, location, retry_after_secs, resp.text().await?))
                })
                .await?;
            if status == 429 || body.contains("urn:ietf:params:acme:error:rateLimited") {
                return Err(AcmeError::RateLimited {
                    retry_after_secs,
                    detail: body,
                });
            }
            if status == 400
                && body.contains("urn:ietf:params:acme:error:badNonce")
                && attempt < MAX_ATTEMPTS
            {
                continue;
            }
            return Ok((status, location, body));
        }
        Err(AcmeError::MissingNonce)
    }

    /// Run the full issuance flow for `domains` via HTTP-01, returning the issued certificate
    /// once the order reaches `valid`.
    ///
    /// # Errors
    /// Any transport failure, a rejected order, an authorization that never validates, or the
    /// responder refusing to serve the challenge token.
    pub async fn issue(
        &self,
        domains: &[&str],
        responder: &dyn Http01Responder,
    ) -> Result<CertMaterial, AcmeError> {
        self.issue_with(domains, ChallengeResponder::Http(responder), None)
            .await
    }

    /// Issue a certificate via DNS-01, including wildcard names.
    pub async fn issue_dns01(
        &self,
        domains: &[&str],
        responder: &dyn Dns01Responder,
    ) -> Result<CertMaterial, AcmeError> {
        self.issue_with(domains, ChallengeResponder::Dns(responder), None)
            .await
    }

    /// [`Self::issue`] for a renewal: the order names the certificate it replaces
    /// (`replaces`, RFC 9773 §5), which CAs use to recognise a renewal — Let's Encrypt, for one,
    /// exempts a replacement order from its new-order and duplicate-certificate rate limits.
    /// `previous_chain_pem` is the chain being replaced (only the leaf is read).
    ///
    /// `replaces` is sent only when the CA advertises ARI in its directory and the previous leaf
    /// has an ARI certificate ID ([`ari_cert_id`]); otherwise this is exactly [`Self::issue`].
    /// If the CA refuses the order because of the `replaces` member (`alreadyReplaced` — a replacement
    /// is already under way or done, `malformed`, `unauthorized` — the certificate belongs to
    /// another account) the order is placed once more without it: a renewal that cannot claim the
    /// rate-limit exemption is still a renewal.
    ///
    /// # Errors
    /// As [`Self::issue`].
    pub async fn issue_replacing(
        &self,
        domains: &[&str],
        responder: &dyn Http01Responder,
        previous_chain_pem: &str,
    ) -> Result<CertMaterial, AcmeError> {
        self.issue_with(
            domains,
            ChallengeResponder::Http(responder),
            self.replaces_id(previous_chain_pem),
        )
        .await
    }

    /// [`Self::issue_dns01`] for a renewal; see [`Self::issue_replacing`].
    ///
    /// # Errors
    /// As [`Self::issue_dns01`].
    pub async fn issue_dns01_replacing(
        &self,
        domains: &[&str],
        responder: &dyn Dns01Responder,
        previous_chain_pem: &str,
    ) -> Result<CertMaterial, AcmeError> {
        self.issue_with(
            domains,
            ChallengeResponder::Dns(responder),
            self.replaces_id(previous_chain_pem),
        )
        .await
    }

    /// The `replaces` value for an order replacing `previous_chain_pem`, if the CA supports it.
    fn replaces_id(&self, previous_chain_pem: &str) -> Option<String> {
        self.directory.renewal_info.as_ref()?;
        ari_cert_id(previous_chain_pem)
    }

    /// Revoke `cert_der_or_pem` (a DER certificate, or PEM whose first `CERTIFICATE` block is
    /// taken — pass the leaf or the whole chain) with the **account** key (RFC 8555 §7.6). The CA
    /// accepts this only for a certificate issued to this account or for names the account holds
    /// valid authorizations for. `AlreadyRevoked` is success, not an error.
    ///
    /// # Errors
    /// The CA's directory has no `revokeCert`, the input is not a certificate, any transport
    /// failure, or the CA refusing (`unauthorized` for a certificate this account has no claim
    /// to; use [`Self::revoke_certificate_with_key`] if you hold its private key).
    pub async fn revoke_certificate(
        &self,
        cert_der_or_pem: &[u8],
        reason: RevocationReason,
    ) -> Result<RevocationOutcome, AcmeError> {
        self.revoke_with(cert_der_or_pem, reason, Auth::Kid).await
    }

    /// As [`Self::revoke_certificate`], but the request is signed with the **certificate's own
    /// private key** (`certificate_key_pem`, the PKCS#8 PEM of `CertMaterial::key_pem`) and carries its
    /// public key as the JWK. That proves possession of the key, so it needs no account at all:
    /// the route for a key compromise (whoever holds the key can do this, which is why a
    /// compromised key should be revoked at once) and for a certificate ordered by an account we no
    /// longer hold the key of.
    ///
    /// # Errors
    /// As [`Self::revoke_certificate`], plus a key that is not an ECDSA P-256 PKCS#8 key.
    pub async fn revoke_certificate_with_key(
        &self,
        cert_der_or_pem: &[u8],
        certificate_key_pem: &str,
        reason: RevocationReason,
    ) -> Result<RevocationOutcome, AcmeError> {
        let key = AccountKey::from_pkcs8_pem(certificate_key_pem)?;
        self.revoke_with(cert_der_or_pem, reason, Auth::KeyJwk(&key))
            .await
    }

    async fn revoke_with(
        &self,
        cert_der_or_pem: &[u8],
        reason: RevocationReason,
        auth: Auth<'_>,
    ) -> Result<RevocationOutcome, AcmeError> {
        let url = self.directory.revoke_cert.as_deref().ok_or_else(|| {
            AcmeError::BadResponse(
                "this CA's directory has no revokeCert URL, so it does not support revocation"
                    .to_string(),
            )
        })?;
        let der = leaf_der(cert_der_or_pem)?;
        let payload = json!({ "certificate": b64url(&der), "reason": reason.code() });
        let (status, _, body) = self.send_jws(url, &payload.to_string(), auth).await?;
        if (200..300).contains(&status) {
            return Ok(RevocationOutcome::Revoked);
        }
        let err = AcmeError::Rejected {
            status,
            detail: body,
        };
        if err.is_problem("alreadyRevoked") {
            return Ok(RevocationOutcome::AlreadyRevoked);
        }
        Err(err)
    }

    async fn issue_with(
        &self,
        domains: &[&str],
        responder: ChallengeResponder<'_>,
        replaces: Option<String>,
    ) -> Result<CertMaterial, AcmeError> {
        if domains.is_empty() || domains.len() > 100 {
            return Err(AcmeError::Local(format!(
                "an order needs between 1 and 100 names, not {}",
                domains.len()
            )));
        }
        // The certificate key comes first, before the CA is asked for anything. A new one per
        // order -- a renewal never reuses the key of the certificate it replaces -- generated by
        // the injected generator and checked against the key policy. If the system RNG fails the
        // order stops here: no authorization has been spent and no certificate for a predictable
        // key can exist.
        let alg = self.opts.key_alg;
        self.opts
            .key_policy
            .check_alg(alg)
            .map_err(|e| AcmeError::Local(e.to_string()))?;
        let cert_key = self
            .opts
            .keygen
            .generate(alg)
            .map_err(|e| AcmeError::Local(e.to_string()))?;
        let key_pem = key_to_pkcs8_pem(&cert_key, alg)?;
        self.opts
            .key_policy
            .check_pkcs8_pem(&key_pem)
            .map_err(|e| {
                AcmeError::Local(format!("the generated certificate key is refused: {e}"))
            })?;
        let csr_b64 = b64url(&csr(&cert_key, alg, domains)?);

        let identifiers: Vec<Value> = domains
            .iter()
            .map(|d| json!({ "type": "dns", "value": d }))
            .collect();
        let mut order_payload = json!({ "identifiers": identifiers });
        if let Some(profile) = &self.opts.profile {
            if self.directory.meta.profiles.contains_key(profile) {
                order_payload["profile"] = json!(profile);
            } else {
                tracing::warn!(profile = %profile, "the CA does not advertise this ACME profile; ordering without one");
            }
        }
        if let Some(id) = &replaces {
            order_payload["replaces"] = json!(id);
        }
        let (mut status, mut order_location, mut body) = self
            .post_signed_with_location(&self.directory.new_order, &order_payload.to_string())
            .await?;
        if replaces.is_some() && !(200..300).contains(&status) {
            let refused = AcmeError::Rejected {
                status,
                detail: body.clone(),
            };
            if refused.is_problem("alreadyReplaced")
                || refused.is_problem("malformed")
                || refused.is_problem("unauthorized")
            {
                tracing::info!(
                    status,
                    "the CA refused the order's `replaces`; ordering without it"
                );
                if let Some(o) = order_payload.as_object_mut() {
                    o.remove("replaces");
                }
                (status, order_location, body) = self
                    .post_signed_with_location(
                        &self.directory.new_order,
                        &order_payload.to_string(),
                    )
                    .await?;
            }
        }
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected {
                status,
                detail: body,
            });
        }
        let order: OrderResponse =
            serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

        for authz_url in &order.authorizations {
            self.complete_authorization(authz_url, &responder).await?;
        }

        let (status, body) = self
            .post_signed(&order.finalize, &json!({ "csr": csr_b64 }).to_string())
            .await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected {
                status,
                detail: body,
            });
        }
        let mut finalized: OrderResponse =
            serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

        // Finalization is async on the CA's side — poll the order URL (POST-as-GET) until it
        // reports `valid` (a certificate URL appears) or `invalid`.
        for _ in 0..20 {
            if finalized.status == "valid" {
                break;
            }
            if finalized.status == "invalid" {
                return Err(AcmeError::OrderNotValid);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Some(url) = &order_location {
                let (_, body) = self.post_signed(url, "").await?;
                finalized = serde_json::from_str(&body)
                    .map_err(|e| AcmeError::BadResponse(e.to_string()))?;
            }
        }
        let cert_url = finalized.certificate.ok_or(AcmeError::OrderNotValid)?;
        let (status, chain_pem) = self.post_signed(&cert_url, "").await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected {
                status,
                detail: chain_pem,
            });
        }

        verify_issued(&chain_pem, &cert_key, alg, domains)?;
        Ok(CertMaterial { chain_pem, key_pem })
    }

    async fn complete_authorization(
        &self,
        authz_url: &str,
        responder: &ChallengeResponder<'_>,
    ) -> Result<(), AcmeError> {
        let (_, body) = self.post_signed(authz_url, "").await?;
        let authz: AuthorizationResponse =
            serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;
        if authz.status == "valid" {
            return Ok(());
        }
        let kind = match responder {
            ChallengeResponder::Http(_) => "http-01",
            ChallengeResponder::Dns(_) => "dns-01",
        };
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.kind == kind)
            .ok_or_else(|| AcmeError::AuthorizationFailed(authz_url.to_string()))?;

        let key_auth = acme_key_authorization(&challenge.token, &self.account().thumbprint());
        let dns_name = authz.identifier.value.trim_start_matches("*.");
        let dns_value = b64url(&crate::prim::sha256(key_auth.as_bytes()));
        match responder {
            ChallengeResponder::Http(r) => r.serve_token(&challenge.token, &key_auth).await?,
            ChallengeResponder::Dns(r) => r.publish_txt(dns_name, &dns_value).await?,
        }

        // Tell the CA the challenge is ready to be fetched (an empty JSON object payload, not
        // POST-as-GET's empty string — RFC 8555 §7.5.1's worked example sends `{}`).
        let result = async {
            let (status, body) = self.post_signed(&challenge.url, "{}").await?;
            if !(200..300).contains(&status) {
                return Err(AcmeError::Rejected {
                    status,
                    detail: body,
                });
            }
            self.poll_authorization(authz_url).await
        }
        .await;
        match responder {
            ChallengeResponder::Http(r) => r.remove_token(&challenge.token).await,
            ChallengeResponder::Dns(r) => r.remove_txt(dns_name, &dns_value).await,
        }
        result
    }

    async fn poll_authorization(&self, authz_url: &str) -> Result<(), AcmeError> {
        for _ in 0..20 {
            let (_, body) = self.post_signed(authz_url, "").await?;
            let authz: AuthorizationResponse =
                serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;
            match authz.status.as_str() {
                "valid" => return Ok(()),
                "invalid" => {
                    // Surface *why* (CAA, unauthorized, DNS timeout...) — the bare URL is
                    // useless to the operator reading the renewal status.
                    let why = authz
                        .challenges
                        .iter()
                        .find_map(|c| c.error.as_ref())
                        .and_then(|e| e.get("detail").and_then(Value::as_str))
                        .unwrap_or("no detail from the CA");
                    return Err(AcmeError::AuthorizationFailed(format!(
                        "{authz_url} ({why})"
                    )));
                }
                _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        Err(AcmeError::AuthorizationFailed(authz_url.to_string()))
    }
}

/// The DER of the certificate in `input`: raw DER (a SEQUENCE, so it starts `0x30`) or PEM, whose
/// first `CERTIFICATE` block is taken. Sanity-checked as one complete DER element and bounded, so
/// a hostile or truncated input is refused before it is put in a request.
fn leaf_der(input: &[u8]) -> Result<Vec<u8>, AcmeError> {
    /// Real certificates are a few KiB; a chain PEM a few tens. Nothing legitimate is near this.
    const MAX_INPUT: usize = 256 * 1024;
    let bad = |m: &str| AcmeError::BadResponse(format!("not a certificate to revoke: {m}"));
    if input.len() > MAX_INPUT {
        return Err(bad("input is implausibly large"));
    }
    let der = if input.first() == Some(&0x30) {
        input.to_vec()
    } else {
        let text = std::str::from_utf8(input).map_err(|_| bad("neither DER nor PEM"))?;
        crate::pem::blocks(text, "CERTIFICATE")
            .into_iter()
            .next()
            .ok_or_else(|| bad("no CERTIFICATE block"))?
    };
    match der::read(&der) {
        Some((0x30, content, rest)) if rest.is_empty() && !content.is_empty() => Ok(der),
        _ => Err(bad("malformed DER")),
    }
}

/// Minimal DER writer/reader — just the shapes a PKCS#10 CSR, a PKCS#8 EC key, an X.509
/// validity window and an RFC 9773 certificate ID (AKI + serial) need. No general ASN.1: every
/// structure written here has a fixed shape.
pub(crate) mod der {
    #[must_use]
    pub fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            return vec![n as u8];
        }
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }

    #[must_use]
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(len(content.len()));
        out.extend_from_slice(content);
        out
    }

    #[must_use]
    pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &items.concat())
    }

    /// Minimal non-negative INTEGER from a big-endian magnitude.
    #[must_use]
    pub fn uint(magnitude: &[u8]) -> Vec<u8> {
        let trimmed: &[u8] = match magnitude.iter().position(|b| *b != 0) {
            Some(i) => &magnitude[i..],
            None => &[0],
        };
        let mut c = Vec::with_capacity(trimmed.len() + 1);
        if trimmed[0] & 0x80 != 0 {
            c.push(0);
        }
        c.extend_from_slice(trimmed);
        tlv(0x02, &c)
    }

    /// BIT STRING with zero unused bits.
    #[must_use]
    pub fn bit_string(content: &[u8]) -> Vec<u8> {
        let mut c = vec![0u8];
        c.extend_from_slice(content);
        tlv(0x03, &c)
    }

    /// `(keyIdentifier of the Authority Key Identifier extension, serialNumber content octets)` of
    /// a DER X.509 certificate — the two halves of an RFC 9773 certificate ID. `None` if the
    /// certificate is malformed, has no AKI extension, or the AKI carries no `keyIdentifier`.
    #[must_use]
    pub fn aki_and_serial(cert: &[u8]) -> Option<(&[u8], &[u8])> {
        let (tag, cert, _) = read(cert)?;
        let (tag2, tbs, _) = read(cert)?;
        if tag != 0x30 || tag2 != 0x30 {
            return None;
        }
        // TBSCertificate: [0] version OPTIONAL, serial, signature alg, issuer, validity, subject,
        // spki, [1] issuerUID OPTIONAL, [2] subjectUID OPTIONAL, [3] extensions OPTIONAL.
        let (t0, _, after) = read(tbs)?;
        let rest = if t0 == 0xA0 { after } else { tbs };
        let (tag, serial, mut rest) = read(rest)?;
        if tag != 0x02 || serial.is_empty() {
            return None;
        }
        for _ in 0..5 {
            rest = read(rest)?.2;
        }
        while !rest.is_empty() {
            let (tag, content, next) = read(rest)?;
            rest = next;
            if tag != 0xA3 {
                continue;
            }
            let (tag, mut exts, _) = read(content)?;
            if tag != 0x30 {
                return None;
            }
            while !exts.is_empty() {
                let (tag, ext, next) = read(exts)?;
                exts = next;
                let (oid_tag, oid, body) = read(ext)?;
                if tag != 0x30 || oid_tag != 0x06 || oid != super::OID_AUTHORITY_KEY_IDENTIFIER {
                    continue;
                }
                // extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING { AuthorityKeyIdentifier }
                let (t, v, after) = read(body)?;
                let (t, value) = if t == 0x01 {
                    let (t, v, _) = read(after)?;
                    (t, v)
                } else {
                    (t, v)
                };
                let (tag, mut aki, _) = read(value)?;
                if t != 0x04 || tag != 0x30 {
                    return None;
                }
                while !aki.is_empty() {
                    let (tag, content, next) = read(aki)?;
                    aki = next;
                    if tag == 0x80 {
                        return Some((content, serial)); // keyIdentifier [0] IMPLICIT OCTET STRING
                    }
                }
                return None;
            }
        }
        None
    }

    /// Read one TLV: `(tag, content, rest-after-it)`. `None` on any malformed/truncated input.
    #[must_use]
    pub fn read(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let tag = *buf.first()?;
        let l0 = *buf.get(1)?;
        let (n, hdr) = if l0 < 0x80 {
            (usize::from(l0), 2)
        } else {
            let k = usize::from(l0 & 0x7f);
            if k == 0 || k > 4 {
                return None;
            }
            let mut n = 0usize;
            for i in 0..k {
                n = (n << 8) | usize::from(*buf.get(2 + i)?);
            }
            (n, 2 + k)
        };
        let end = hdr.checked_add(n)?;
        Some((tag, buf.get(hdr..end)?, buf.get(end..)?))
    }
}

// OID contents (without tag/length).
#[cfg(test)]
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]; // 1.2.840.113549.1.9.14
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11]; // 2.5.29.17
const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23]; // 2.5.29.35

/// The SEC1 uncompressed point `04 ‖ x ‖ y`.
fn ec_point(pair: &EcdsaKeyPair) -> Vec<u8> {
    pair.public_key().as_ref().to_vec()
}

/// Raw `r‖s` -> DER `SEQUENCE { INTEGER r, INTEGER s }` (what X.509/PKCS#10 carry).
fn ecdsa_sig_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    der::seq(&[der::uint(r), der::uint(s)])
}

/// A PKCS#10 CSR (ECDSA / SHA-2 matching the key's curve) with `domains` as dNSName SANs and an
/// empty subject — the ACME `finalize` request body. CAs take the identifiers from the SAN, not
/// the subject.
pub(crate) fn csr(
    pair: &EcdsaKeyPair,
    alg: KeyAlg,
    domains: &[&str],
) -> Result<Vec<u8>, AcmeError> {
    let names: Vec<Vec<u8>> = domains
        .iter()
        .map(|d| der::tlv(0x82, d.as_bytes()))
        .collect(); // [2] dNSName
    let san_ext = der::seq(&[
        der::tlv(0x06, OID_SUBJECT_ALT_NAME),
        der::tlv(0x04, &der::seq(&names)),
    ]);
    let ext_req = der::seq(&[
        der::tlv(0x06, OID_EXTENSION_REQUEST),
        der::tlv(0x31, &der::seq(&[san_ext])),
    ]);
    let spki = crate::certkey::spki_der(pair, alg);
    let cri = der::seq(&[
        der::uint(&[0]),
        der::seq(&[]),
        spki,
        der::tlv(0xA0, &ext_req),
    ]);
    let sig = pair.sign(&SystemRandom::new(), &cri).map_err(|_| {
        AcmeError::Local("could not sign the CSR (system RNG or crypto module)".into())
    })?;
    if sig.as_ref().len() != 2 * alg.component_len() {
        return Err(AcmeError::Local(
            "the CSR signature has an unexpected length".into(),
        ));
    }
    Ok(der::seq(&[
        cri,
        der::seq(&[der::tlv(0x06, alg.signature_oid())]),
        der::bit_string(&ecdsa_sig_der(sig.as_ref())),
    ]))
}

/// PKCS#8 `PrivateKeyInfo` for an EC key, PEM-wrapped, in the shape `openssl genpkey` emits (the
/// SEC1 `ECPrivateKey` carries the public point) — what `CertMaterial::key_pem` promises and what
/// the serving provider loads.
pub(crate) fn key_to_pkcs8_pem(pair: &EcdsaKeyPair, alg: KeyAlg) -> Result<String, AcmeError> {
    use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
    let sk: EcPrivateKeyBin<'static> = pair
        .private_key()
        .as_be_bytes()
        .map_err(|_| AcmeError::Local("could not export the certificate key".into()))?;
    let ec_private_key = der::seq(&[
        der::uint(&[1]),
        der::tlv(0x04, sk.as_ref()),
        der::tlv(0xA1, &der::bit_string(&ec_point(pair))), // [1] publicKey
    ]);
    let pkcs8 = der::seq(&[
        der::uint(&[0]),
        crate::certkey::ec_algorithm_identifier(alg),
        der::tlv(0x04, &ec_private_key),
    ]);
    Ok(pem_wrap("PRIVATE KEY", &pkcs8))
}

/// What a CA's answer must satisfy before it is believed: the leaf certifies **the key we
/// generated for this order** (a CA that certifies some other key has either mis-issued or been
/// confused with another order, and a certificate for a key we do not hold is useless at best),
/// and it covers every name we asked for. A failure is [`AcmeError::CaMisbehaved`]: it is the CA's
/// output that is wrong, and the engine counts it against the CA.
pub(crate) fn verify_issued(
    chain_pem: &str,
    pair: &EcdsaKeyPair,
    alg: KeyAlg,
    domains: &[&str],
) -> Result<(), AcmeError> {
    let leaf = crate::x509::leaf_der(chain_pem)
        .ok_or_else(|| AcmeError::CaMisbehaved("the issued chain has no certificate".into()))?;
    let cert = crate::x509::parse(&leaf).ok_or_else(|| {
        AcmeError::CaMisbehaved("the issued leaf is not a parsable certificate".into())
    })?;
    if cert.spki != crate::certkey::spki_der(pair, alg).as_slice() {
        return Err(AcmeError::CaMisbehaved(
            "the issued certificate does not certify the key generated for this order".into(),
        ));
    }
    let have = cert.dns_names();
    for want in domains {
        if !have.iter().any(|h| h.eq_ignore_ascii_case(want)) {
            return Err(AcmeError::CaMisbehaved(format!(
                "the issued certificate does not cover {want}"
            )));
        }
    }
    Ok(())
}

/// Test helpers: a P-256 key, its CSR and PKCS#8 PEM. The production path is
/// [`AcmeClient`]'s `issue_with`, which goes through [`ClientOptions::keygen`].
#[cfg(test)]
pub(crate) fn generate_cert_key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

#[cfg(test)]
pub(crate) fn csr_p256(pair: &EcdsaKeyPair, domains: &[&str]) -> Vec<u8> {
    csr(pair, KeyAlg::P256, domains).unwrap()
}

#[cfg(test)]
pub(crate) fn p256_key_to_pkcs8_pem(pair: &EcdsaKeyPair) -> String {
    key_to_pkcs8_pem(pair, KeyAlg::P256).unwrap()
}

pub(crate) fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = base64_standard(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn base64_standard(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(d.len() * 4 / 3 + 4);
    for chunk in d.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(A[((n >> 18) & 63) as usize] as char);
        s.push(A[((n >> 12) & 63) as usize] as char);
        s.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn retry_after_accepts_seconds_and_http_dates() {
        assert_eq!(parse_retry_after("120", 0), Some(120));
        assert_eq!(parse_retry_after(" 7 ", 0), Some(7));
        // 1994-11-06T08:49:37Z = 784111777
        assert_eq!(
            parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 - 90),
            Some(90)
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 + 5),
            Some(0),
            "a date in the past is no wait"
        );
        // leap day and the epoch
        assert_eq!(parse_imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_imf_fixdate("Thu, 29 Feb 2024 12:00:00 GMT"),
            Some(1_709_208_000)
        );
        for bad in [
            "",
            "soon",
            "-5",
            "Sun, 06 Nov 1994 08:49:37 PST",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 25:49:37 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
        ] {
            assert_eq!(parse_retry_after(bad, 0), None, "{bad:?}");
        }
    }

    use super::*;
    use apeiron::map::hashtrinity::crypto::sha256;

    fn test_account() -> AccountKey {
        // A fixed, arbitrary 32-byte scalar — deterministic tests, not a real account.
        AccountKey::from_bytes([7u8; 32]).unwrap()
    }

    #[test]
    fn flattened_jws_has_three_string_fields_not_the_compact_dot_form() {
        let account = test_account();
        let protected =
            protected_header_jwk(&account, "test-nonce", "https://example.test/new-account");
        let jws = flattened_jws(&account, &protected, "{}").unwrap();
        let parsed: Value = serde_json::from_str(&jws).unwrap();
        assert!(parsed["protected"].is_string());
        assert!(parsed["payload"].is_string());
        assert!(parsed["signature"].is_string());
        // None of the three fields themselves contain an embedded '.' — b64url's alphabet has none.
        for field in ["protected", "payload", "signature"] {
            assert!(!parsed[field].as_str().unwrap().contains('.'));
        }
    }

    #[test]
    fn protected_header_jwk_carries_no_kid_and_protected_header_kid_carries_no_jwk() {
        let account = test_account();
        let with_jwk = protected_header_jwk(&account, "n", "https://x/new-account");
        assert!(with_jwk.get("jwk").is_some());
        assert!(with_jwk.get("kid").is_none());

        let with_kid = protected_header_kid("https://x/acct/1", "n", "https://x/new-order");
        assert!(with_kid.get("kid").is_some());
        assert!(with_kid.get("jwk").is_none());
    }

    #[test]
    fn account_thumbprint_is_deterministic() {
        let a = test_account();
        let b = test_account();
        assert_eq!(a.thumbprint(), b.thumbprint());
    }

    #[test]
    fn different_keys_have_different_thumbprints() {
        let a = AccountKey::from_bytes([1u8; 32]).unwrap();
        let b = AccountKey::from_bytes([2u8; 32]).unwrap();
        assert_ne!(a.thumbprint(), b.thumbprint());
    }

    #[test]
    fn directory_deserializes_the_fields_this_client_needs() {
        let json = r#"{"newNonce":"https://x/new-nonce","newAccount":"https://x/new-acct","newOrder":"https://x/new-order","keyChange":"https://x/key-change"}"#;
        let dir: Directory = serde_json::from_str(json).unwrap();
        assert_eq!(dir.new_nonce, "https://x/new-nonce");
    }

    #[test]
    fn an_authorization_with_challenge_types_we_do_not_implement_still_parses() {
        // Shape taken from a real Pebble authorization: a challenge object with no `token`.
        let json = r#"{"status":"pending","identifier":{"type":"dns","value":"example.test"},
            "challenges":[
              {"type":"http-01","url":"https://x/c/1","token":"t1","status":"pending"},
              {"type":"dns-account-01","url":"https://x/c/2","status":"pending"},
              {"type":"dns-01","url":"https://x/c/3","token":"t3","status":"pending","validated":"x","extra":1}]}"#;
        let authz: AuthorizationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(authz.challenges.len(), 3);
        assert!(authz
            .challenges
            .iter()
            .find(|c| c.kind == "dns-01")
            .is_some_and(|c| c.token == "t3"));
        assert!(authz
            .challenges
            .iter()
            .find(|c| c.kind == "dns-account-01")
            .is_some_and(|c| c.token.is_empty()));
    }

    #[test]
    fn order_response_deserializes_with_no_certificate_yet() {
        let json = r#"{"status":"pending","authorizations":["https://x/authz/1"],"finalize":"https://x/finalize/1"}"#;
        let order: OrderResponse = serde_json::from_str(json).unwrap();
        assert_eq!(order.status, "pending");
        assert!(order.certificate.is_none());
    }

    fn base64_decode_for_test(s: &str) -> Vec<u8> {
        fn val(c: u8) -> u32 {
            match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            }
        }
        let clean: Vec<u8> = s
            .bytes()
            .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
            .collect();
        let mut out = Vec::new();
        for chunk in clean.chunks(4) {
            let n = chunk.iter().fold(0u32, |acc, &c| (acc << 6) | val(c));
            let shift = (4 - chunk.len()) * 6;
            let n = n << shift;
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        out
    }

    #[test]
    fn key_authorization_matches_hashtrinitys_own_acme_helper() {
        let account = test_account();
        let key_auth = acme_key_authorization("test-token", &account.thumbprint());
        assert!(key_auth.starts_with("test-token."));
        // Same inputs -> same output, every time (a responder serving this at a well-known path
        // must be able to recompute it identically on every poll).
        let key_auth2 = acme_key_authorization("test-token", &account.thumbprint());
        assert_eq!(key_auth, key_auth2);
    }

    // ── P-256 CSR / key ───────────────────────────────────────────────────────────────────

    fn b64url_decode_for_test(s: &str) -> Vec<u8> {
        base64_decode_for_test(&s.replace('-', "+").replace('_', "/"))
    }

    /// Pull `(cri_der, sec1_point, raw_sig)` out of a CSR so its signature can be checked.
    fn split_csr(csr: &[u8]) -> (Vec<u8>, [u8; 64], [u8; 64]) {
        let (tag, body, rest) = der::read(csr).unwrap();
        assert_eq!(tag, 0x30);
        assert!(rest.is_empty());
        let (_, cri_content, after_cri) = der::read(body).unwrap();
        let cri_der = body[..body.len() - after_cri.len()].to_vec();
        let (_, sigalg, after_alg) = der::read(after_cri).unwrap();
        assert_eq!(der::read(sigalg).unwrap().1, OID_ECDSA_SHA256);
        let (bt, sig_bits, _) = der::read(after_alg).unwrap();
        assert_eq!(bt, 0x03);
        assert_eq!(sig_bits[0], 0, "no unused bits");
        let (_, sig_seq, _) = der::read(&sig_bits[1..]).unwrap();
        let (_, r, rest) = der::read(sig_seq).unwrap();
        let (_, sv, _) = der::read(rest).unwrap();
        let mut raw = [0u8; 64];
        let r = if r[0] == 0 && r.len() > 1 { &r[1..] } else { r };
        let sv = if sv[0] == 0 && sv.len() > 1 {
            &sv[1..]
        } else {
            sv
        };
        raw[32 - r.len()..32].copy_from_slice(r);
        raw[64 - sv.len()..].copy_from_slice(sv);
        // cri: version, subject, spki, attrs
        let (_, _, rest) = der::read(cri_content).unwrap();
        let (_, _, rest) = der::read(rest).unwrap();
        let (_, spki, _) = der::read(rest).unwrap();
        let (_, _, after_alg) = der::read(spki).unwrap();
        let (_, point_bits, _) = der::read(after_alg).unwrap();
        assert_eq!(point_bits[1], 0x04);
        let mut pk = [0u8; 64];
        pk.copy_from_slice(&point_bits[2..]);
        (cri_der, pk, raw)
    }

    #[test]
    fn csr_is_a_valid_self_signed_p256_pkcs10() {
        let key = generate_cert_key();
        let csr = csr_p256(&key, &["*.tascloud.app", "tascloud.app"]);
        let (cri, pk, sig) = split_csr(&csr);
        assert_eq!(
            pk.as_slice(),
            &key.public_key().as_ref()[1..],
            "CSR carries the key's public point"
        );
        assert!(
            apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(&pk, &sha256(&cri), &sig),
            "CSR proves possession of the key"
        );
        for d in ["*.tascloud.app", "tascloud.app"] {
            assert!(
                cri.windows(d.len()).any(|w| w == d.as_bytes()),
                "{d} must be a SAN"
            );
        }
        // Tampering with the request info invalidates the signature.
        let mut bad = cri.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
            &pk,
            &sha256(&bad),
            &sig
        ));
    }

    #[test]
    fn der_uint_is_minimal_and_non_negative() {
        assert_eq!(der::uint(&[0, 0, 0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(
            der::uint(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80],
            "high bit needs a leading zero"
        );
        assert_eq!(der::uint(&[0, 0]), vec![0x02, 0x01, 0x00]);
        let long = der::tlv(0x04, &[7u8; 300]);
        assert_eq!(
            der::read(&long).unwrap().1.len(),
            300,
            "long-form lengths round-trip"
        );
    }

    #[test]
    fn account_keys_reject_invalid_scalars_round_trip_and_sign_verifiably() {
        assert!(
            AccountKey::from_bytes([0u8; 32]).is_err(),
            "zero is not a key"
        );
        assert!(
            AccountKey::from_bytes([0xff; 32]).is_err(),
            "above the group order is not a key"
        );

        let fixed = AccountKey::from_bytes([7u8; 32]).unwrap();
        assert_eq!(
            fixed.to_bytes().unwrap(),
            [7u8; 32],
            "sealed-store round trip"
        );
        let again = AccountKey::from_bytes(fixed.to_bytes().unwrap()).unwrap();
        assert_eq!(again.thumbprint(), fixed.thumbprint());

        let generated = AccountKey::generate().unwrap();
        assert_ne!(generated.thumbprint(), fixed.thumbprint());
        // What aws-lc signs, the (independent) verifier in hashtrinity accepts: r||s over SHA-256.
        let msg = b"protected.payload";
        let sig: [u8; 64] = generated.sign(msg).unwrap().try_into().unwrap();
        assert!(apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
            &generated.xy(),
            &sha256(msg),
            &sig
        ));
        assert!(!apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
            &fixed.xy(),
            &sha256(msg),
            &sig
        ));
    }

    /// The key we hand back must load in the provider the edge actually serves with.
    #[test]
    fn issued_key_pem_loads_in_the_edge_serving_provider() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::SignatureScheme;
        let sk = generate_cert_key();
        let pem = p256_key_to_pkcs8_pem(&sk);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes = base64_decode_for_test(&body);
        // The aws-lc-rs provider the edge serves with.
        for provider in [crate::edge_proxy::sni::provider()] {
            let key = provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    der_bytes.clone(),
                )))
                .expect("serving provider loads our PKCS#8");
            assert!(key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some());
        }
        // Same layout as `openssl genpkey` emits for P-256: 138 bytes with the public point.
        assert_eq!(der_bytes.len(), 138);
    }

    // ── Full protocol against a mock CA ───────────────────────────────────────────────────
    //
    // A real HTTP server on loopback that behaves like a CA where it matters: it checks every
    // JWS signature, enforces single-use nonces (and injects one `badNonce`), requires the
    // DNS-01 value to actually be published before it validates, and verifies the CSR.

    mod mock_ca {
        use super::*;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        #[derive(Default)]
        pub struct FakeDns {
            pub published: Mutex<Vec<(String, String)>>,
            pub removed: Mutex<Vec<(String, String)>>,
        }

        impl Dns01Responder for FakeDns {
            fn publish_txt<'a>(
                &'a self,
                name: &'a str,
                value: &'a str,
            ) -> crate::BoxFuture<'a, Result<(), AcmeError>> {
                Box::pin(async move {
                    self.published
                        .lock()
                        .unwrap()
                        .push((name.to_string(), value.to_string()));
                    Ok(())
                })
            }
            fn remove_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, ()> {
                Box::pin(async move {
                    self.removed
                        .lock()
                        .unwrap()
                        .push((name.to_string(), value.to_string()));
                })
            }
        }

        #[derive(Default)]
        pub struct State {
            pub base: String,
            pub nonces: Vec<String>,
            pub counter: u32,
            pub acct_pk: Option<[u8; 64]>,
            pub thumbprint: [u8; 32],
            pub inject_bad_nonce_once: bool,
            /// Answer the first `newAccount` with `badNonce`.
            pub inject_bad_nonce_on_account: bool,
            pub rate_limit_new_order: bool,
            pub challenged: Vec<u32>,
            pub finalized_csr_ok: bool,
            /// The public point `x‖y` of the CSR the CA last finalized, which the certificate it
            /// hands out then certifies (a real CA certifies the CSR's key).
            pub csr_point: Option<[u8; 64]>,
            /// Serial number content octets of issued leaves (default: a counter).
            pub leaf_serial: Option<Vec<u8>>,
            pub issued: u32,
            pub bad_nonce_seen: u32,
            pub dns: Option<Arc<FakeDns>>,
            /// `(kid, hmac key)` of the one external account this CA knows.
            pub eab: Option<(String, Vec<u8>)>,
            /// Refuse `newAccount` without an `externalAccountBinding`.
            pub require_eab: bool,
            pub eab_accepted: u32,
            /// Leave `keyChange` out of the directory.
            pub no_key_change: bool,
            /// Answer a (fully verified) `keyChange` with 409, as for a key another account owns.
            pub reject_key_change: bool,
            pub key_changes: u32,
            /// `(status, Retry-After, body)` served for every ARI lookup; `None` = the directory
            /// has no `renewalInfo`.
            pub ari: Option<(u16, Option<String>, String)>,
            pub ari_requests: Vec<String>,
            /// The JWK public point of the most recent request if it was identified by `jwk`
            /// (`None` when by `kid`).
            pub last_jwk: Option<[u8; 64]>,
            /// Leave `revokeCert` out of the directory.
            pub no_revoke_cert: bool,
            /// Profiles advertised in the directory's `meta`.
            pub profiles: Vec<String>,
            /// Certificate returned for every order (default: a placeholder that is not a real
            /// certificate).
            pub cert_pem: Option<String>,
            /// Every `newOrder` payload received, failed attempts included.
            pub orders: Vec<Value>,
            /// Refuse a `newOrder` that has `replaces` with 409 `alreadyReplaced`.
            pub already_replaced: bool,
            /// DER certificates the CA will accept a `jwk`-signed revocation for, with the key
            /// they carry (what a real CA reads out of the certificate itself).
            pub cert_keys: Vec<(Vec<u8>, [u8; 64])>,
            /// Refuse every `kid`-signed revocation as `unauthorized` (a certificate this
            /// account has no claim to).
            pub revoke_unauthorized_for_kid: bool,
            /// `(der, reason, signed by the certificate key rather than the account)`.
            pub revoked: Vec<(Vec<u8>, Option<u64>, bool)>,
        }

        fn fresh_nonce(st: &mut State) -> String {
            st.counter += 1;
            let n = format!("nonce-{}", st.counter);
            st.nonces.push(n.clone());
            n
        }

        struct Reply {
            status: u16,
            headers: Vec<(String, String)>,
            body: String,
        }

        fn problem(status: u16, kind: &str, st: &mut State) -> Reply {
            Reply {
                status,
                headers: vec![("Replay-Nonce".into(), fresh_nonce(st))],
                body: format!(
                    r#"{{"type":"urn:ietf:params:acme:error:{kind}","detail":"mock {kind}"}}"#
                ),
            }
        }

        /// Returns the decoded payload, or the error reply to send.
        fn verify_jws(st: &mut State, url: &str, body: &str) -> Result<String, Reply> {
            let v: Value = serde_json::from_str(body).map_err(|_| Reply {
                status: 400,
                headers: vec![],
                body: "{}".into(),
            })?;
            let (p, pl, sg) = (
                v["protected"].as_str().unwrap(),
                v["payload"].as_str().unwrap(),
                v["signature"].as_str().unwrap(),
            );
            let protected: Value = serde_json::from_slice(&b64url_decode_for_test(p)).unwrap();
            let nonce = protected["nonce"].as_str().unwrap().to_string();
            match st.nonces.iter().position(|n| *n == nonce) {
                Some(i) => {
                    st.nonces.remove(i);
                }
                None => {
                    st.bad_nonce_seen += 1;
                    return Err(problem(400, "badNonce", st));
                }
            }
            assert_eq!(
                protected["url"].as_str().unwrap(),
                url,
                "JWS url header must match the request URL"
            );
            let pk: [u8; 64] = if let Some(jwk) = protected.get("jwk") {
                assert!(protected.get("kid").is_none());
                let mut pk = [0u8; 64];
                pk[..32].copy_from_slice(&b64url_decode_for_test(jwk["x"].as_str().unwrap()));
                pk[32..].copy_from_slice(&b64url_decode_for_test(jwk["y"].as_str().unwrap()));
                // Only `newAccount` introduces the account key; any other `jwk` request (a revocation
                // by the certificate's key) is signed by a key that is not the account's.
                if url.ends_with("/new-acct") {
                    st.acct_pk = Some(pk);
                }
                st.last_jwk = Some(pk);
                pk
            } else {
                assert_eq!(
                    protected["kid"].as_str().unwrap(),
                    format!("{}/acct/1", st.base)
                );
                st.last_jwk = None;
                st.acct_pk.expect("account registered first")
            };
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&b64url_decode_for_test(sg));
            assert!(
                apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
                    &pk,
                    &sha256(format!("{p}.{pl}").as_bytes()),
                    &sig
                ),
                "bad JWS signature on {url}"
            );
            Ok(String::from_utf8(b64url_decode_for_test(pl)).unwrap())
        }

        fn jwk_point(jwk: &Value) -> [u8; 64] {
            assert_eq!(
                (jwk["kty"].as_str(), jwk["crv"].as_str()),
                (Some("EC"), Some("P-256"))
            );
            assert_eq!(
                jwk.as_object().unwrap().len(),
                4,
                "a public JWK is exactly kty, crv, x, y: {jwk}"
            );
            let mut pk = [0u8; 64];
            pk[..32].copy_from_slice(&b64url_decode_for_test(jwk["x"].as_str().unwrap()));
            pk[32..].copy_from_slice(&b64url_decode_for_test(jwk["y"].as_str().unwrap()));
            pk
        }

        /// RFC 8555 §7.3.4, as a CA checks it. `Ok` also when this CA has no EAB configured
        /// (it ignores a binding it did not ask for).
        fn check_eab(st: &mut State, url: &str, payload: &str) -> Result<(), Reply> {
            let v: Value = serde_json::from_str(payload).unwrap();
            let Some(eab) = v.get("externalAccountBinding") else {
                return if st.require_eab {
                    Err(problem(403, "externalAccountRequired", st))
                } else {
                    Ok(())
                };
            };
            let Some((kid, key)) = st.eab.clone() else {
                return Ok(());
            };
            let (p, pl, sg) = (
                eab["protected"].as_str().unwrap(),
                eab["payload"].as_str().unwrap(),
                eab["signature"].as_str().unwrap(),
            );
            assert_eq!(
                eab.as_object().unwrap().len(),
                3,
                "a flattened JWS: protected, payload, signature"
            );
            let protected: Value = serde_json::from_slice(&b64url_decode_for_test(p)).unwrap();
            assert_eq!(protected["alg"], "HS256");
            assert_eq!(
                protected["url"], url,
                "the binding names the same URL as the outer JWS"
            );
            assert!(
                protected.get("nonce").is_none(),
                "RFC 8555 §7.3.4: no nonce inside the binding"
            );
            assert_eq!(
                protected.as_object().unwrap().len(),
                3,
                "alg, kid, url and nothing else: {protected}"
            );
            let jwk: Value = serde_json::from_slice(&b64url_decode_for_test(pl)).unwrap();
            assert_eq!(
                jwk_point(&jwk),
                st.acct_pk.unwrap(),
                "the binding's payload is the key signing newAccount"
            );
            // Judge the MAC with a HMAC that is not the one the client used (aws-lc).
            let expect = apeiron::map::hashtrinity::crypto::hmac_sha256(
                &key,
                format!("{p}.{pl}").as_bytes(),
            );
            if protected["kid"] != kid {
                return Err(problem(401, "unauthorized", st));
            }
            if b64url_decode_for_test(sg) != expect {
                return Err(problem(401, "unauthorized", st));
            }
            st.eab_accepted += 1;
            Ok(())
        }

        /// RFC 8555 §7.3.5: the (outer-verified) payload is an inner JWS by the new key over
        /// `{account, oldKey}`. Returns the new public key on success.
        fn check_key_change(st: &State, url: &str, outer_payload: &str) -> [u8; 64] {
            let inner: Value = serde_json::from_str(outer_payload)
                .expect("the outer payload is the inner JWS, JSON-serialized");
            assert_eq!(inner.as_object().unwrap().len(), 3, "flattened JWS");
            let (p, pl, sg) = (
                inner["protected"].as_str().unwrap(),
                inner["payload"].as_str().unwrap(),
                inner["signature"].as_str().unwrap(),
            );
            let protected: Value = serde_json::from_slice(&b64url_decode_for_test(p)).unwrap();
            assert_eq!(protected["alg"], "ES256");
            assert_eq!(
                protected["url"], url,
                "inner url is the keyChange URL, like the outer one"
            );
            assert!(
                protected.get("nonce").is_none(),
                "RFC 8555 §7.3.5: no nonce in the inner JWS"
            );
            assert!(
                protected.get("kid").is_none(),
                "the inner JWS identifies the NEW key by jwk"
            );
            assert_eq!(
                protected.as_object().unwrap().len(),
                3,
                "alg, jwk, url: {protected}"
            );
            let new_pk = jwk_point(&protected["jwk"]);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&b64url_decode_for_test(sg));
            assert!(
                apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
                    &new_pk,
                    &sha256(format!("{p}.{pl}").as_bytes()),
                    &sig
                ),
                "the inner JWS must be signed by the new key"
            );
            let payload: Value = serde_json::from_slice(&b64url_decode_for_test(pl)).unwrap();
            assert_eq!(
                payload.as_object().unwrap().len(),
                2,
                "account and oldKey only: {payload}"
            );
            assert_eq!(
                payload["account"],
                format!("{}/acct/1", st.base),
                "the account URL, which does not change"
            );
            assert_eq!(
                jwk_point(&payload["oldKey"]),
                st.acct_pk.unwrap(),
                "oldKey is the key the account has now"
            );
            assert_ne!(new_pk, st.acct_pk.unwrap());
            new_pk
        }

        fn authz(st: &State, n: u32) -> String {
            let done = st.challenged.contains(&n) && {
                // Validate like a CA: the expected TXT value must be live in DNS right now.
                let token = format!("tok{n}");
                let expect = b64url(&sha256(
                    acme_key_authorization(&token, &st.thumbprint).as_bytes(),
                ));
                st.dns
                    .as_ref()
                    .unwrap()
                    .published
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(name, v)| name == "tascloud.app" && *v == expect)
            };
            let status = if done { "valid" } else { "pending" };
            format!(
                r#"{{"status":"{status}","identifier":{{"type":"dns","value":"tascloud.app"}},"wildcard":{},"challenges":[{{"type":"http-01","url":"{b}/chall/{n}","token":"x","status":"pending"}},{{"type":"dns-01","url":"{b}/chall/{n}","token":"tok{n}","status":"{status}"}}]}}"#,
                n == 1,
                b = st.base
            )
        }

        fn route(st: &mut State, method: &str, path: &str, body: &str) -> Reply {
            let url = format!("{}{}", st.base, path);
            let ok = |st: &mut State, status: u16, extra: Vec<(String, String)>, body: String| {
                let mut headers = vec![("Replay-Nonce".to_string(), fresh_nonce(st))];
                headers.extend(extra);
                Reply {
                    status,
                    headers,
                    body,
                }
            };
            match (method, path) {
                ("GET", "/directory") => Reply {
                    status: 200,
                    headers: vec![],
                    body: {
                        let b = &st.base;
                        let mut dir = format!(
                            r#"{{"newNonce":"{b}/new-nonce","newAccount":"{b}/new-acct","newOrder":"{b}/new-order""#
                        );
                        if !st.no_key_change {
                            dir.push_str(&format!(r#","keyChange":"{b}/key-change""#));
                        }
                        if st.ari.is_some() {
                            // Pebble-style: no trailing slash; the client adds it.
                            dir.push_str(&format!(r#","renewalInfo":"{b}/renewal-info""#));
                        }
                        if !st.no_revoke_cert {
                            dir.push_str(&format!(r#","revokeCert":"{b}/revoke-cert""#));
                        }
                        if !st.profiles.is_empty() {
                            let list: Vec<String> = st
                                .profiles
                                .iter()
                                .map(|p| format!(r#""{p}":"{p} profile""#))
                                .collect();
                            dir.push_str(&format!(
                                r#","meta":{{"profiles":{{{}}}}}"#,
                                list.join(",")
                            ));
                        }
                        dir.push('}');
                        dir
                    },
                },
                ("GET", p) if p.starts_with("/renewal-info/") => {
                    st.ari_requests.push(p.to_string());
                    let (status, retry_after, body) = st
                        .ari
                        .clone()
                        .expect("ARI is configured when it is requested");
                    let headers = retry_after
                        .map(|r| vec![("Retry-After".to_string(), r)])
                        .unwrap_or_default();
                    Reply {
                        status,
                        headers,
                        body,
                    }
                }
                ("HEAD", "/new-nonce") => ok(st, 200, vec![], String::new()),
                ("POST", p) => {
                    let payload = match verify_jws(st, &url, body) {
                        Ok(p) => p,
                        Err(r) => return r,
                    };
                    match p {
                        "/new-acct" if st.inject_bad_nonce_on_account => {
                            st.inject_bad_nonce_on_account = false;
                            problem(400, "badNonce", st)
                        }
                        "/new-acct" => {
                            if let Err(refusal) = check_eab(st, &url, &payload) {
                                return refusal;
                            }
                            ok(
                                st,
                                201,
                                vec![("Location".into(), format!("{}/acct/1", st.base))],
                                "{}".into(),
                            )
                        }
                        "/key-change" => {
                            let new_pk = check_key_change(st, &url, &payload);
                            if st.reject_key_change {
                                return problem(409, "conflict", st);
                            }
                            let (x, y): ([u8; 32], [u8; 32]) = (
                                new_pk[..32].try_into().unwrap(),
                                new_pk[32..].try_into().unwrap(),
                            );
                            st.acct_pk = Some(new_pk);
                            st.thumbprint =
                                apeiron::map::hashtrinity::crypto::acme::jwk_thumbprint_ec_p256(
                                    &x, &y,
                                );
                            st.key_changes += 1;
                            ok(st, 200, vec![], "{}".into())
                        }
                        "/new-order" => {
                            if st.rate_limit_new_order {
                                let mut r = problem(429, "rateLimited", st);
                                r.headers.push(("Retry-After".into(), "3600".into()));
                                return r;
                            }
                            if st.inject_bad_nonce_once {
                                st.inject_bad_nonce_once = false;
                                // The signature was fine; the CA just decided the nonce expired.
                                return problem(400, "badNonce", st);
                            }
                            let ids: Value = serde_json::from_str(&payload).unwrap();
                            assert_eq!(ids["identifiers"].as_array().unwrap().len(), 2);
                            st.orders.push(ids.clone());
                            if st.already_replaced && ids.get("replaces").is_some() {
                                return problem(409, "alreadyReplaced", st);
                            }
                            let b = st.base.clone();
                            ok(
                                st,
                                201,
                                vec![("Location".into(), format!("{b}/order/1"))],
                                format!(
                                    r#"{{"status":"pending","authorizations":["{b}/authz/1","{b}/authz/2"],"finalize":"{b}/finalize/1"}}"#
                                ),
                            )
                        }
                        "/authz/1" | "/authz/2" => {
                            assert_eq!(payload, "", "authz fetch is a POST-as-GET (empty payload)");
                            let n: u32 = p.rsplit('/').next().unwrap().parse().unwrap();
                            let body = authz(st, n);
                            ok(st, 200, vec![], body)
                        }
                        "/chall/1" | "/chall/2" => {
                            assert_eq!(payload, "{}");
                            let n: u32 = p.rsplit('/').next().unwrap().parse().unwrap();
                            st.challenged.push(n);
                            ok(st, 200, vec![], r#"{"status":"processing"}"#.into())
                        }
                        "/finalize/1" => {
                            let v: Value = serde_json::from_str(&payload).unwrap();
                            let csr = b64url_decode_for_test(v["csr"].as_str().unwrap());
                            let (cri, pk, sig) = split_csr(&csr);
                            st.csr_point = Some(pk);
                            st.finalized_csr_ok =
                                apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
                                    &pk,
                                    &sha256(&cri),
                                    &sig,
                                ) && cri.windows(14).any(|w| w == b"*.tascloud.app");
                            let b = st.base.clone();
                            ok(
                                st,
                                200,
                                vec![],
                                format!(
                                    r#"{{"status":"valid","authorizations":[],"finalize":"{b}/finalize/1","certificate":"{b}/cert/1"}}"#
                                ),
                            )
                        }
                        "/cert/1" => {
                            let pem = st.cert_pem.clone().unwrap_or_else(|| issue_for_csr(st));
                            ok(st, 200, vec![], pem)
                        }
                        "/revoke-cert" => {
                            let v: Value = serde_json::from_str(&payload).unwrap();
                            assert_eq!(
                                v.as_object().unwrap().len(),
                                2,
                                "certificate and reason, nothing else: {v}"
                            );
                            let der = b64url_decode_for_test(v["certificate"].as_str().unwrap());
                            assert!(
                                !v["certificate"].as_str().unwrap().contains(['=', '+', '/']),
                                "base64url without padding"
                            );
                            let reason = v["reason"].as_u64();
                            if st.revoked.iter().any(|(d, _, _)| *d == der) {
                                return problem(400, "alreadyRevoked", st);
                            }
                            let by_cert_key = st.last_jwk.is_some();
                            let authorised = match st.last_jwk {
                                None => !st.revoke_unauthorized_for_kid,
                                Some(pk) => st.cert_keys.iter().any(|(d, k)| *d == der && *k == pk),
                            };
                            if !authorised {
                                return problem(403, "unauthorized", st);
                            }
                            st.revoked.push((der, reason, by_cert_key));
                            ok(st, 200, vec![], String::new())
                        }
                        other => panic!("mock CA: unexpected POST {other}"),
                    }
                }
                other => panic!("mock CA: unexpected request {other:?}"),
            }
        }

        async fn handle(mut conn: tokio::net::TcpStream, state: Arc<Mutex<State>>) {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, content_len) = loop {
                let n = conn.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                    let cl = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    break (pos + 4, cl);
                }
            };
            while buf.len() < head_end + content_len {
                let n = conn.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut first = head.lines().next().unwrap().split(' ');
            let (method, path) = (
                first.next().unwrap().to_string(),
                first.next().unwrap().to_string(),
            );
            let body = String::from_utf8_lossy(&buf[head_end..head_end + content_len]).to_string();
            let reply = route(&mut state.lock().unwrap(), &method, &path, &body);
            let mut out = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            for (k, v) in &reply.headers {
                out.push_str(&format!("{k}: {v}\r\n"));
            }
            out.push_str("\r\n");
            if method != "HEAD" {
                out.push_str(&reply.body);
            }
            let _ = conn.write_all(out.as_bytes()).await;
        }

        /// A real certificate (AKI = the RFC 9773 vector's, so it has an ARI ID) for the key in the
        /// CSR the CA last finalized and the names of the order it last accepted — what a CA does.
        fn issue_for_csr(st: &mut State) -> String {
            struct CsrKey(Vec<u8>);
            impl rcgen::PublicKeyData for CsrKey {
                fn der_bytes(&self) -> &[u8] {
                    &self.0
                }
                fn algorithm(&self) -> &rcgen::SignatureAlgorithm {
                    &rcgen::PKCS_ECDSA_P256_SHA256
                }
            }
            let names: Vec<String> = st
                .orders
                .last()
                .and_then(|o| o["identifiers"].as_array().cloned())
                .map(|a| {
                    a.iter()
                        .filter_map(|i| i["value"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let point = st
                .csr_point
                .expect("a certificate is fetched only after finalize");
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&point);
            st.issued += 1;
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_identifier_method =
                rcgen::KeyIdMethod::PreSpecified(super::RFC9773_AKI.to_vec());
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let mut params = rcgen::CertificateParams::new(names).unwrap();
            let serial = st
                .leaf_serial
                .clone()
                .unwrap_or_else(|| st.issued.to_be_bytes().to_vec());
            params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
            params.use_authority_key_identifier_extension = true;
            params.signed_by(&CsrKey(sec1), &ca, &ca_key).unwrap().pem()
        }

        pub async fn start(account: &AccountKey) -> (String, Arc<Mutex<State>>, Arc<FakeDns>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let dns = Arc::new(FakeDns::default());
            let state = Arc::new(Mutex::new(State {
                base: base.clone(),
                thumbprint: account.thumbprint(),
                dns: Some(dns.clone()),
                ..State::default()
            }));
            let st = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((conn, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(handle(conn, st.clone()));
                }
            });
            (format!("{base}/directory"), state, dns)
        }
    }

    #[tokio::test]
    async fn dns01_wildcard_order_completes_against_a_signature_checking_ca() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        state.lock().unwrap().inject_bad_nonce_once = true;

        let client = AcmeClient::new(&dir, account, Some("ops@example.test"))
            .await
            .expect("account registers");
        let cert = client
            .issue_dns01(&["*.tascloud.app", "tascloud.app"], dns.as_ref())
            .await
            .expect("order completes");

        assert!(cert.chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let st = state.lock().unwrap();
        assert!(
            st.finalized_csr_ok,
            "CA verified the CSR signature and SANs"
        );
        assert_eq!(
            st.bad_nonce_seen, 0,
            "the injected badNonce was retried transparently, not a client bug"
        );
        let published = dns.published.lock().unwrap();
        assert_eq!(
            published.len(),
            2,
            "wildcard + apex both need a TXT value at the same name"
        );
        assert!(published.iter().all(|(n, _)| n == "tascloud.app"));
        assert_eq!(
            dns.removed.lock().unwrap().len(),
            2,
            "every challenge value is cleaned up afterwards"
        );
    }

    #[tokio::test]
    async fn account_creation_survives_a_bad_nonce() {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        state.lock().unwrap().inject_bad_nonce_on_account = true;
        let client = AcmeClient::new(&dir, account, None)
            .await
            .expect("newAccount is retried with a fresh nonce");
        assert!(client.account_url().is_some());
    }

    #[tokio::test]
    async fn a_ca_rate_limit_is_surfaced_with_its_retry_after() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        state.lock().unwrap().rate_limit_new_order = true;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let err = client
            .issue_dns01(&["*.tascloud.app", "tascloud.app"], dns.as_ref())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AcmeError::RateLimited {
                    retry_after_secs: Some(3600),
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(err.retry_after_secs(), Some(3600));
        assert!(
            dns.published.lock().unwrap().is_empty(),
            "no challenge was published for a refused order"
        );
    }

    // ── External Account Binding (RFC 8555 §7.3.4) ───────────────────────────────────────

    const EAB_KEY: [u8; 32] = [0x42; 32];

    fn eab_ca(state: &std::sync::Mutex<mock_ca::State>, require: bool) {
        let mut st = state.lock().unwrap();
        st.eab = Some(("eab-kid-1".to_string(), EAB_KEY.to_vec()));
        st.require_eab = require;
    }

    #[test]
    fn eab_keys_are_base64url_and_never_printed() {
        let raw = vec![0xfb, 0xff, 0xbf, 0xfe, 0x01];
        let url = b64url(&raw);
        assert!(
            url.contains('-') && url.contains('_'),
            "the vector must exercise the URL-safe alphabet: {url}"
        );
        for text in [
            url.clone(),
            format!("{url}="),
            format!(" {url}\n"),
            url.replace('-', "+").replace('_', "/"),
        ] {
            assert_eq!(
                ExternalAccountBinding::from_base64url("k", &text)
                    .unwrap()
                    .hmac_key,
                raw,
                "{text:?}"
            );
        }
        for bad in ["", "   ", "A", "!!!!", "====", "ab$d"] {
            assert!(
                ExternalAccountBinding::from_base64url("k", bad).is_err(),
                "{bad:?}"
            );
        }

        let eab = ExternalAccountBinding::from_base64url("eab-kid-1", &url).unwrap();
        let shown = format!("{eab:?} {eab:#?}");
        assert!(
            shown.contains("eab-kid-1") && shown.contains("<redacted>"),
            "{shown}"
        );
        assert!(
            !shown.contains(&url)
                && !shown.contains("251")
                && !shown.contains("0xfb")
                && !shown.contains("fb"),
            "the key leaked into Debug: {shown}"
        );
        let err = ExternalAccountBinding::from_base64url("k", "ab$d")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("ab$d"), "an invalid key is not echoed: {err}");
    }

    #[test]
    fn eab_jws_binds_the_account_key_with_hmac_sha256_and_no_nonce() {
        let account = test_account();
        let eab = ExternalAccountBinding {
            kid: "eab-kid-1".to_string(),
            hmac_key: EAB_KEY.to_vec(),
        };
        let jws = eab.jws(&account, "https://ca.test/new-acct");
        let (p, pl, sg) = (
            jws["protected"].as_str().unwrap(),
            jws["payload"].as_str().unwrap(),
            jws["signature"].as_str().unwrap(),
        );
        let protected: Value = serde_json::from_slice(&b64url_decode_for_test(p)).unwrap();
        assert_eq!(
            protected,
            json!({ "alg": "HS256", "kid": "eab-kid-1", "url": "https://ca.test/new-acct" })
        );
        let payload: Value = serde_json::from_slice(&b64url_decode_for_test(pl)).unwrap();
        assert_eq!(
            payload,
            account.jwk(),
            "the payload is the same JWK the outer newAccount JWS carries"
        );
        // Checked with a HMAC implementation other than the aws-lc one the client uses.
        assert_eq!(
            b64url_decode_for_test(sg),
            apeiron::map::hashtrinity::crypto::hmac_sha256(
                &EAB_KEY,
                format!("{p}.{pl}").as_bytes()
            )
        );
        assert_eq!(b64url_decode_for_test(sg).len(), 32);
    }

    #[tokio::test]
    async fn a_ca_that_requires_eab_accepts_only_a_binding_made_with_its_key() {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        eab_ca(&state, true);

        let err = AcmeClient::new(&dir, account.clone(), None)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(&err, AcmeError::Rejected { status: 403, detail } if detail.contains("externalAccountRequired")),
            "{err}"
        );

        let wrong_key = ExternalAccountBinding {
            kid: "eab-kid-1".to_string(),
            hmac_key: vec![0x43; 32],
        };
        let err = AcmeClient::new_with_eab(&dir, account.clone(), None, Some(wrong_key))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(err, AcmeError::Rejected { status: 401, .. }),
            "{err}"
        );
        let wrong_kid = ExternalAccountBinding {
            kid: "someone-else".to_string(),
            hmac_key: EAB_KEY.to_vec(),
        };
        let err = AcmeClient::new_with_eab(&dir, account.clone(), None, Some(wrong_kid))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(err, AcmeError::Rejected { status: 401, .. }),
            "{err}"
        );
        assert_eq!(state.lock().unwrap().eab_accepted, 0);

        let good = ExternalAccountBinding::from_base64url("eab-kid-1", &b64url(&EAB_KEY)).unwrap();
        let client = AcmeClient::new_with_eab(&dir, account, Some("ops@example.test"), Some(good))
            .await
            .expect("a valid binding registers the account");
        assert!(client.account_url().is_some());
        assert_eq!(
            state.lock().unwrap().eab_accepted,
            1,
            "the CA verified the binding (kid, url, payload JWK, MAC)"
        );
    }

    #[tokio::test]
    async fn eab_survives_a_bad_nonce_and_is_optional_for_a_ca_that_does_not_ask() {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        eab_ca(&state, true);
        state.lock().unwrap().inject_bad_nonce_on_account = true;
        let eab = ExternalAccountBinding {
            kid: "eab-kid-1".to_string(),
            hmac_key: EAB_KEY.to_vec(),
        };
        AcmeClient::new_with_eab(&dir, account.clone(), None, Some(eab.clone()))
            .await
            .expect("re-signed with a fresh nonce, same binding");
        assert_eq!(state.lock().unwrap().eab_accepted, 1);

        // A CA with no EAB policy ignores a binding it did not ask for.
        let (dir2, state2, _dns2) = mock_ca::start(&account).await;
        AcmeClient::new_with_eab(&dir2, account, None, Some(eab))
            .await
            .expect("harmless extra member");
        assert_eq!(state2.lock().unwrap().eab_accepted, 0);
    }

    // ── Account key rollover (RFC 8555 §7.3.5) ───────────────────────────────────────────

    const ALL_NAMES: [&str; 2] = ["*.tascloud.app", "tascloud.app"];

    #[tokio::test]
    async fn rollover_switches_signing_to_the_new_key_and_the_account_url_does_not_change() {
        let old = test_account();
        let new = AccountKey::from_bytes([9u8; 32]).unwrap();
        let (dir, state, dns) = mock_ca::start(&old).await;
        let client = AcmeClient::new(&dir, old.clone(), None).await.unwrap();
        let account_url = client.account_url().unwrap();
        client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect("an order under the old key");

        client
            .rollover_account_key(new.clone())
            .await
            .expect("rollover");
        {
            // The mock checked both signatures and the inner payload (see `check_key_change`).
            let st = state.lock().unwrap();
            assert_eq!(st.key_changes, 1);
            assert_eq!(
                st.acct_pk,
                Some(new.xy()),
                "the CA now knows the account by the new key"
            );
            assert_eq!(st.bad_nonce_seen, 0);
        }
        assert_eq!(
            client.account_url().unwrap(),
            account_url,
            "the account is the same account"
        );
        assert_eq!(client.account().thumbprint(), new.thumbprint());

        // A whole new order: every request is verified under the new key by the CA, and the
        // DNS-01 values are derived from the new key's thumbprint (the mock only validates a
        // value computed from it).
        dns.published.lock().unwrap().clear();
        client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect("an order signed by the new key");
        let expect: Vec<String> = (1..=2)
            .map(|n| {
                b64url(&sha256(
                    acme_key_authorization(&format!("tok{n}"), &new.thumbprint()).as_bytes(),
                ))
            })
            .collect();
        let published: Vec<String> = dns
            .published
            .lock()
            .unwrap()
            .iter()
            .map(|(_, v)| v.clone())
            .collect();
        assert_eq!(published, expect);
    }

    #[tokio::test]
    async fn a_rejected_rollover_leaves_the_client_on_its_old_key() {
        let old = test_account();
        let (dir, state, dns) = mock_ca::start(&old).await;
        state.lock().unwrap().reject_key_change = true;
        let client = AcmeClient::new(&dir, old.clone(), None).await.unwrap();

        let err = client
            .rollover_account_key(AccountKey::from_bytes([9u8; 32]).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(err, AcmeError::Rejected { status: 409, .. }),
            "{err}"
        );
        assert_eq!(client.account().thumbprint(), old.thumbprint());
        assert_eq!(state.lock().unwrap().acct_pk, Some(old.xy()));
        client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect("still signing with, and known by, the old key");
    }

    #[tokio::test]
    async fn rollover_needs_a_key_change_endpoint_and_a_different_key() {
        let old = test_account();
        let (dir, state, _dns) = mock_ca::start(&old).await;
        state.lock().unwrap().no_key_change = true;
        let client = AcmeClient::new(&dir, old.clone(), None).await.unwrap();
        let err = client
            .rollover_account_key(AccountKey::from_bytes([9u8; 32]).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AcmeError::BadResponse(m) if m.contains("keyChange")),
            "{err}"
        );
        assert_eq!(state.lock().unwrap().key_changes, 0);

        let (dir, _state, _dns) = mock_ca::start(&old).await;
        let client = AcmeClient::new(&dir, old.clone(), None).await.unwrap();
        let err = client.rollover_account_key(old).await.unwrap_err();
        assert!(
            matches!(&err, AcmeError::BadResponse(m) if m.contains("already in use")),
            "{err}"
        );
    }

    #[test]
    fn directory_exposes_key_change_and_renewal_info_when_offered() {
        let full = r#"{"newNonce":"https://x/n","newAccount":"https://x/a","newOrder":"https://x/o","keyChange":"https://x/kc","renewalInfo":"https://x/ari","meta":{"termsOfService":"x"}}"#;
        let dir: Directory = serde_json::from_str(full).unwrap();
        assert_eq!(
            (dir.key_change.as_deref(), dir.renewal_info.as_deref()),
            (Some("https://x/kc"), Some("https://x/ari"))
        );
        let bare: Directory = serde_json::from_str(
            r#"{"newNonce":"https://x/n","newAccount":"https://x/a","newOrder":"https://x/o"}"#,
        )
        .unwrap();
        assert_eq!(
            (bare.key_change, bare.renewal_info),
            (None, None),
            "a CA without them still parses"
        );
    }

    // ── ACME Renewal Information (RFC 9773) ──────────────────────────────────────────────

    /// RFC 9773 appendix A's example: AKI keyIdentifier 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4,
    /// serial 0x87654321, certificate ID `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`.
    const RFC9773_AKI: [u8; 20] = [
        0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3, 0x7B, 0x84, 0x7B, 0xA0, 0xAE,
        0x2C, 0xDE, 0x01, 0xC8, 0xD4,
    ];
    const RFC9773_CERT_ID: &str = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    /// A real (rcgen-made) end-entity certificate issued by a CA whose key identifier is `aki`,
    /// carrying `serial` and — when `with_aki` — the AKI extension naming that CA.
    fn rcgen_leaf(aki: &[u8], serial: &[u8], with_aki: bool) -> String {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(aki.to_vec());
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        params.use_authority_key_identifier_extension = with_aki;
        params.signed_by(&leaf_key, &ca, &ca_key).unwrap().pem()
    }

    #[test]
    fn ari_cert_id_of_a_real_certificate_matches_the_rfc_9773_example() {
        assert_eq!(
            b64url(&RFC9773_AKI),
            RFC9773_CERT_ID.split('.').next().unwrap(),
            "the vector's AKI half"
        );
        let pem = rcgen_leaf(&RFC9773_AKI, &[0x87, 0x65, 0x43, 0x21], true);
        assert_eq!(ari_cert_id(&pem).as_deref(), Some(RFC9773_CERT_ID));
        // A chain: only the leaf (first block) is read.
        let chain = format!("{pem}{}", rcgen_leaf(&[7; 20], &[1], true));
        assert_eq!(ari_cert_id(&chain).as_deref(), Some(RFC9773_CERT_ID));
    }

    #[test]
    fn ari_cert_id_keeps_the_der_leading_zero_only_where_der_has_one() {
        let id = |serial: &[u8]| {
            ari_cert_id(&rcgen_leaf(&RFC9773_AKI, serial, true))
                .unwrap()
                .split_once('.')
                .unwrap()
                .1
                .to_string()
        };
        // High bit set -> DER content is 00 87 65 43 21 -> "AIdlQyE" (not "h2VDIQ", the 4-byte form).
        assert_eq!(id(&[0x87, 0x65, 0x43, 0x21]), "AIdlQyE");
        assert_eq!(
            id(&[0x00, 0x87, 0x65, 0x43, 0x21]),
            "AIdlQyE",
            "an explicit leading zero is the same integer"
        );
        // High bit clear -> no padding byte: 01 02 03.
        assert_eq!(id(&[0x01, 0x02, 0x03]), b64url(&[1, 2, 3]));
        // A full 20-byte serial (the CA/B Forum maximum) round-trips.
        let long: Vec<u8> = (1..=20).collect();
        assert_eq!(id(&long), b64url(&long));
    }

    #[test]
    fn ari_cert_id_is_none_without_an_aki_or_for_junk() {
        assert_eq!(
            ari_cert_id(&rcgen_leaf(&RFC9773_AKI, &[1, 2, 3], false)),
            None,
            "no AKI extension"
        );
        assert_eq!(ari_cert_id(""), None);
        assert_eq!(
            ari_cert_id("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
            None
        );
        // Truncations of a real certificate never panic and never yield an ID.
        let pem = rcgen_leaf(&RFC9773_AKI, &[1, 2, 3], true);
        let der = crate::pem::blocks(&pem, "CERTIFICATE").remove(0);
        for cut in 0..der.len() {
            assert!(der::aki_and_serial(&der[..cut]).is_none(), "cut at {cut}");
        }
    }

    #[test]
    fn rfc3339_parses_offsets_and_fractions_and_rejects_everything_else() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-01-01T00:00:00Z", 946_684_800),
            ("2024-02-29T12:00:00Z", 1_709_208_000),
            ("2024-02-29T12:00:00.999999999Z", 1_709_208_000),
            ("2024-02-29t12:00:00z", 1_709_208_000),
            ("2026-10-15T08:30:00Z", 1_792_053_000),
            ("2026-10-15T18:30:00+10:00", 1_792_053_000),
            ("2026-10-15T03:00:00-05:30", 1_792_053_000),
            ("2100-03-01T00:00:00Z", 4_107_542_400),
            ("2024-12-31T23:59:59Z", 1_735_689_599),
            ("1999-12-31T23:59:59Z", 946_684_799),
        ] {
            assert_eq!(parse_rfc3339(text), Some(unix), "{text}");
            // Agrees with the (lenient, millisecond) parser the HTTP client carries, where that
            // one accepts the spelling at all (it wants an upper-case `T`).
            if text.contains('T') {
                assert_eq!(
                    crate::http_client::parse_rfc3339(text).map(|ms| ms.div_euclid(1000)),
                    Some(unix),
                    "{text}"
                );
            }
        }
        for bad in [
            "",
            "soon",
            "2024-02-29",
            "2023-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-00-10T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-02-29T24:00:00Z",
            "2024-02-29T00:60:00Z",
            "2024-02-29T00:00:61Z",
            "2024-02-29T12:00:00",
            "2024-02-29 12:00:00Z",
            "2024-02-29T12:00:00.Z",
            "2024-02-29T12:00:00Zjunk",
            "2024-02-29T12:00:00+25:00",
            "2024-02-29T12:00:00+10:60",
            "2024-02-29T12:00:00+1000",
            "2024-2-29T12:00:00Z",
            "２０２４-02-29T12:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn renewal_info_bodies_become_windows_and_invalid_ones_are_errors() {
        let w = parse_renewal_info(
            r#"{"suggestedWindow":{"start":"2026-10-15T08:30:00Z","end":"2026-10-17T08:30:00.5Z"},"explanationURL":"https://ca.test/why","somethingNew":1}"#,
            Some(21_600),
        )
        .unwrap();
        assert_eq!(
            w,
            RenewalWindow {
                start: 1_792_053_000,
                end: 1_792_053_000 + 2 * 86_400,
                explanation_url: Some("https://ca.test/why".into()),
                retry_after_secs: Some(21_600)
            }
        );
        let w = parse_renewal_info(
            r#"{"suggestedWindow":{"start":"2026-10-15T08:30:00Z","end":"2026-10-15T08:30:01Z"}}"#,
            None,
        )
        .unwrap();
        assert_eq!((w.explanation_url, w.retry_after_secs), (None, None));
        for bad in [
            "",
            "{}",
            r#"{"suggestedWindow":{}}"#,
            r#"{"suggestedWindow":{"start":"2026-10-15T08:30:00Z"}}"#,
            r#"{"suggestedWindow":{"start":"yesterday","end":"2026-10-15T08:30:00Z"}}"#,
            r#"{"suggestedWindow":{"start":"2026-10-15T08:30:00Z","end":"2026-10-15T08:30:00Z"}}"#,
            r#"{"suggestedWindow":{"start":"2026-10-16T08:30:00Z","end":"2026-10-15T08:30:00Z"}}"#,
            r#"{"suggestedWindow":{"start":1,"end":2}}"#,
        ] {
            assert!(
                matches!(
                    parse_renewal_info(bad, None),
                    Err(AcmeError::BadResponse(_))
                ),
                "{bad:?}"
            );
        }
    }

    const ARI_BODY: &str = r#"{"suggestedWindow":{"start":"2026-10-15T08:30:00Z","end":"2026-10-17T08:30:00Z"},"explanationURL":"https://ca.test/why"}"#;

    #[tokio::test]
    async fn renewal_info_asks_for_the_certificate_id_and_reports_the_window_and_retry_after() {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        state.lock().unwrap().ari = Some((200, Some("21600".to_string()), ARI_BODY.to_string()));
        let client = AcmeClient::new(&dir, account, None).await.unwrap();

        let pem = rcgen_leaf(&RFC9773_AKI, &[0x87, 0x65, 0x43, 0x21], true);
        let w = client
            .renewal_info(&pem)
            .await
            .expect("lookup")
            .expect("the CA has advice");
        assert_eq!(
            w,
            RenewalWindow {
                start: 1_792_053_000,
                end: 1_792_053_000 + 2 * 86_400,
                explanation_url: Some("https://ca.test/why".to_string()),
                retry_after_secs: Some(21_600),
            }
        );
        assert_eq!(
            state.lock().unwrap().ari_requests,
            vec![format!("/renewal-info/{RFC9773_CERT_ID}")]
        );
        assert_eq!(
            state.lock().unwrap().nonces.len(),
            1,
            "an unauthenticated GET: it neither takes nor burns a nonce"
        );

        // A directory URL with a trailing slash does not double it.
        let mut with_slash = AcmeClient::new(&dir, test_account(), None).await.unwrap();
        with_slash.directory.renewal_info =
            with_slash.directory.renewal_info.map(|u| format!("{u}/"));
        with_slash.renewal_info(&pem).await.unwrap().unwrap();
        assert_eq!(
            state.lock().unwrap().ari_requests[1],
            format!("/renewal-info/{RFC9773_CERT_ID}")
        );
    }

    #[tokio::test]
    async fn renewal_info_is_none_without_ari_and_other_failures_are_typed_errors() {
        let account = test_account();
        let pem = rcgen_leaf(&RFC9773_AKI, &[1, 2, 3], true);

        // No `renewalInfo` in the directory: no advice, and not even a request.
        let (dir, state, _dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account.clone(), None).await.unwrap();
        assert_eq!(client.renewal_info(&pem).await.unwrap(), None);
        assert!(state.lock().unwrap().ari_requests.is_empty());
        assert_eq!(
            client.renewal_info("not a certificate").await.unwrap(),
            None,
            "nothing to ask about, nothing to ask"
        );

        let cases: [(u16, Option<&str>, &str); 4] = [
            (404, None, "{}"),
            (
                429,
                Some("120"),
                r#"{"type":"urn:ietf:params:acme:error:rateLimited"}"#,
            ),
            (500, None, "oops"),
            (200, None, "<html>"),
        ];
        let mut results = Vec::new();
        for (status, retry_after, body) in cases {
            let (dir, state, _dns) = mock_ca::start(&account).await;
            state.lock().unwrap().ari =
                Some((status, retry_after.map(str::to_string), body.to_string()));
            let client = AcmeClient::new(&dir, account.clone(), None).await.unwrap();
            results.push(client.renewal_info(&pem).await);
        }
        assert!(
            matches!(results[0], Ok(None)),
            "a CA that does not know the certificate has no advice: {:?}",
            results[0]
        );
        assert!(
            matches!(
                results[1],
                Err(AcmeError::RateLimited {
                    retry_after_secs: Some(120),
                    ..
                })
            ),
            "{:?}",
            results[1]
        );
        assert!(
            matches!(results[2], Err(AcmeError::Rejected { status: 500, .. })),
            "{:?}",
            results[2]
        );
        assert!(
            matches!(results[3], Err(AcmeError::BadResponse(_))),
            "{:?}",
            results[3]
        );

        // With ARI offered, a certificate that cannot name an AKI is an error, not silence.
        let (dir, state, _dns) = mock_ca::start(&account).await;
        state.lock().unwrap().ari = Some((200, None, ARI_BODY.to_string()));
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let err = client
            .renewal_info(&rcgen_leaf(&RFC9773_AKI, &[1, 2, 3], false))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AcmeError::BadResponse(m) if m.contains("Authority Key Identifier")),
            "{err}"
        );
        assert!(state.lock().unwrap().ari_requests.is_empty());
    }

    // ── Revocation (RFC 8555 §7.6) ───────────────────────────────────────────────────────

    /// A real leaf certificate together with its PKCS#8 key and the public point a CA would read
    /// out of it, as `(chain_pem, key_pem, x‖y)`.
    fn rcgen_leaf_with_key(serial: &[u8]) -> (String, String, [u8; 64]) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(RFC9773_AKI.to_vec());
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["app.acme.com.au".to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        params.use_authority_key_identifier_extension = true;
        let pem = params.signed_by(&leaf_key, &ca, &ca_key).unwrap().pem();
        let mut point = [0u8; 64];
        point.copy_from_slice(&leaf_key.public_key_raw()[1..]);
        (pem, leaf_key.serialize_pem(), point)
    }

    fn der_of(pem: &str) -> Vec<u8> {
        crate::pem::blocks(pem, "CERTIFICATE").remove(0)
    }

    #[test]
    fn revocation_reasons_are_the_rfc_5280_codes_and_none_is_certificate_hold() {
        let all = [
            (RevocationReason::Unspecified, 0),
            (RevocationReason::KeyCompromise, 1),
            (RevocationReason::AffiliationChanged, 3),
            (RevocationReason::Superseded, 4),
            (RevocationReason::CessationOfOperation, 5),
        ];
        for (reason, code) in all {
            assert_eq!(reason.code(), code);
        }
        // 2 (CA compromise), 6 (certificateHold, which ACME forbids) and 7 (unused) cannot be expressed.
        assert!(![2u8, 6, 7]
            .iter()
            .any(|c| all.iter().any(|(r, _)| r.code() == *c)));
    }

    #[tokio::test]
    async fn revoking_with_the_account_key_names_the_certificate_and_reason_and_a_repeat_is_success(
    ) {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let (pem, _key, _pk) = rcgen_leaf_with_key(&[1, 2, 3]);

        let outcome = client
            .revoke_certificate(pem.as_bytes(), RevocationReason::CessationOfOperation)
            .await
            .expect("revoked");
        assert_eq!(outcome, RevocationOutcome::Revoked);
        assert_eq!(
            state.lock().unwrap().revoked,
            vec![(der_of(&pem), Some(5), false)],
            "the CA saw this certificate, reason 5, signed by the account (kid)"
        );
        assert_eq!(state.lock().unwrap().bad_nonce_seen, 0);

        // alreadyRevoked is success: the certificate is as revoked as we wanted.
        let again = client
            .revoke_certificate(pem.as_bytes(), RevocationReason::CessationOfOperation)
            .await
            .expect("alreadyRevoked is handled");
        assert_eq!(again, RevocationOutcome::AlreadyRevoked);
        assert_eq!(state.lock().unwrap().revoked.len(), 1);

        // Raw DER is accepted too, and a whole chain revokes its leaf (the first block).
        let (pem2, _, _) = rcgen_leaf_with_key(&[9]);
        let chain = format!("{pem2}{pem}");
        client
            .revoke_certificate(&der_of(&pem2), RevocationReason::Superseded)
            .await
            .unwrap();
        assert_eq!(
            client
                .revoke_certificate(chain.as_bytes(), RevocationReason::Superseded)
                .await
                .unwrap(),
            RevocationOutcome::AlreadyRevoked
        );
        assert_eq!(
            state.lock().unwrap().revoked[1],
            (der_of(&pem2), Some(4), false)
        );
    }

    #[tokio::test]
    async fn a_revocation_the_account_has_no_claim_to_is_refused_and_the_certificates_own_key_can_still_revoke_it(
    ) {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account.clone(), None).await.unwrap();
        let (pem, key_pem, pk) = rcgen_leaf_with_key(&[4, 5, 6]);
        {
            let mut st = state.lock().unwrap();
            st.revoke_unauthorized_for_kid = true;
            st.cert_keys.push((der_of(&pem), pk));
        }
        let err = client
            .revoke_certificate(pem.as_bytes(), RevocationReason::KeyCompromise)
            .await
            .unwrap_err();
        assert!(
            err.is_problem("unauthorized")
                && matches!(err, AcmeError::Rejected { status: 403, .. }),
            "{err}"
        );

        // Signed with the certificate's own key, embedded as the JWK: no account needed.
        let outcome = client
            .revoke_certificate_with_key(pem.as_bytes(), &key_pem, RevocationReason::KeyCompromise)
            .await
            .expect("key-signed revocation");
        assert_eq!(outcome, RevocationOutcome::Revoked);
        {
            let st = state.lock().unwrap();
            assert_eq!(
                st.revoked,
                vec![(der_of(&pem), Some(1), true)],
                "reason keyCompromise, signed by the certificate key"
            );
            assert_eq!(
                st.last_jwk,
                Some(pk),
                "the JWK was the certificate's key, not the account's"
            );
            assert_ne!(Some(pk), st.acct_pk);
        }
        assert_eq!(
            client
                .revoke_certificate_with_key(
                    pem.as_bytes(),
                    &key_pem,
                    RevocationReason::KeyCompromise
                )
                .await
                .unwrap(),
            RevocationOutcome::AlreadyRevoked
        );

        // Someone else's key cannot revoke it: the CA compares the JWK with the certificate's key.
        let (pem2, _own_key, pk2) = rcgen_leaf_with_key(&[7]);
        state.lock().unwrap().cert_keys.push((der_of(&pem2), pk2));
        let (_, other_key, _) = rcgen_leaf_with_key(&[8]);
        let err = client
            .revoke_certificate_with_key(
                pem2.as_bytes(),
                &other_key,
                RevocationReason::KeyCompromise,
            )
            .await
            .unwrap_err();
        assert!(err.is_problem("unauthorized"), "{err}");
        // The account key is untouched by all of this.
        assert_eq!(client.account().thumbprint(), account.thumbprint());
    }

    #[tokio::test]
    async fn revocation_refuses_non_certificates_and_a_ca_without_revoke_cert_before_sending_anything(
    ) {
        let account = test_account();
        let (dir, state, _dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account.clone(), None).await.unwrap();
        let (pem, key_pem, _) = rcgen_leaf_with_key(&[1]);
        let der = der_of(&pem);
        let mut chopped = der.clone();
        chopped.truncate(der.len() - 5);
        let mut trailing = der.clone();
        trailing.extend_from_slice(b"junk");
        let big = vec![0x30u8; 300 * 1024];
        for (what, input) in [
            ("empty", Vec::new()),
            ("text", b"hello".to_vec()),
            (
                "pem without a certificate",
                b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_vec(),
            ),
            ("truncated DER", chopped),
            ("DER with trailing bytes", trailing),
            ("oversized", big),
            ("not UTF-8, not DER", vec![0xff, 0xfe, 0x00]),
        ] {
            let err = client
                .revoke_certificate(&input, RevocationReason::Unspecified)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, AcmeError::BadResponse(m) if m.contains("not a certificate to revoke")),
                "{what}: {err}"
            );
        }
        for bad_key in [
            "",
            "not a pem",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            let err = client
                .revoke_certificate_with_key(
                    pem.as_bytes(),
                    bad_key,
                    RevocationReason::KeyCompromise,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, AcmeError::BadResponse(_)),
                "{bad_key:?}: {err}"
            );
            assert!(
                !err.to_string().contains("AAAA"),
                "key text is not echoed: {err}"
            );
        }
        assert!(state.lock().unwrap().revoked.is_empty());

        let (dir2, state2, _dns2) = mock_ca::start(&account).await;
        state2.lock().unwrap().no_revoke_cert = true;
        let client2 = AcmeClient::new(&dir2, account, None).await.unwrap();
        let err = client2
            .revoke_certificate(pem.as_bytes(), RevocationReason::Unspecified)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AcmeError::BadResponse(m) if m.contains("revokeCert")),
            "{err}"
        );
        let err = client2
            .revoke_certificate_with_key(pem.as_bytes(), &key_pem, RevocationReason::Unspecified)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AcmeError::BadResponse(m) if m.contains("revokeCert")),
            "{err}"
        );
    }

    #[test]
    fn certificate_keys_load_as_signers_only_when_they_are_p256_pkcs8() {
        let key = generate_cert_key();
        let pem = p256_key_to_pkcs8_pem(&key);
        let signer = AccountKey::from_pkcs8_pem(&pem).expect("the PEM this module writes loads");
        assert_eq!(
            signer.xy().as_slice(),
            &key.public_key().as_ref()[1..],
            "same key"
        );
        let sig: [u8; 64] = signer.sign(b"m").unwrap().try_into().unwrap();
        assert!(apeiron::map::hashtrinity::crypto::ecdsa_p256_verify(
            &signer.xy(),
            &sha256(b"m"),
            &sig
        ));

        let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .unwrap()
            .serialize_pem();
        assert!(
            AccountKey::from_pkcs8_pem(&ed25519).is_err(),
            "an Ed25519 key cannot sign ES256"
        );
        assert!(AccountKey::from_pkcs8_pem("").is_err());
        assert!(AccountKey::from_pkcs8_pem(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        )
        .is_err());
    }

    // ── `replaces` (RFC 9773 §5) ─────────────────────────────────────────────────────────

    /// A mock CA that advertises ARI and hands out one real certificate (with an AKI) for every order.
    async fn replacing_ca() -> (
        String,
        std::sync::Arc<std::sync::Mutex<mock_ca::State>>,
        std::sync::Arc<mock_ca::FakeDns>,
        AccountKey,
        String,
    ) {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        let pem = rcgen_leaf(&RFC9773_AKI, &[0x87, 0x65, 0x43, 0x21], true);
        {
            let mut st = state.lock().unwrap();
            st.ari = Some((200, None, ARI_BODY.to_string()));
            st.leaf_serial = Some(vec![0x87, 0x65, 0x43, 0x21]);
        }
        (dir, state, dns, account, pem)
    }

    #[tokio::test]
    async fn a_renewal_order_carries_the_certificate_it_replaces_and_a_first_issuance_does_not() {
        let (dir, state, dns, account, _pem) = replacing_ca().await;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();

        let first = client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect("first issuance");
        let renewed = client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), &first.chain_pem)
            .await
            .expect("renewal");
        assert!(renewed.chain_pem.contains("BEGIN CERTIFICATE"));

        let orders = state.lock().unwrap().orders.clone();
        assert_eq!(orders.len(), 2);
        assert!(
            orders[0].get("replaces").is_none(),
            "a first issuance replaces nothing: {}",
            orders[0]
        );
        assert_eq!(
            orders[1]["replaces"], RFC9773_CERT_ID,
            "the renewal names the ARI certificate ID of the previous leaf: {}",
            orders[1]
        );
        assert_eq!(
            orders[1]["identifiers"], orders[0]["identifiers"],
            "same names"
        );
        assert_eq!(
            orders[1].as_object().unwrap().len(),
            2,
            "identifiers and replaces only"
        );
    }

    #[tokio::test]
    async fn replaces_is_left_out_where_it_cannot_help_and_a_refusal_of_it_falls_back_to_a_plain_order(
    ) {
        // A CA without ARI never sees `replaces` (RFC 9773 §5: only if the directory has renewalInfo).
        let (dir, state, dns, account, pem) = replacing_ca().await;
        state.lock().unwrap().ari = None;
        let client = AcmeClient::new(&dir, account.clone(), None).await.unwrap();
        client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), &pem)
            .await
            .unwrap();
        assert!(
            state.lock().unwrap().orders[0].get("replaces").is_none(),
            "no ARI in the directory"
        );

        // A previous certificate with no AKI has no certificate ID to name.
        let (dir, state, dns, account2, _) = replacing_ca().await;
        let client = AcmeClient::new(&dir, account2, None).await.unwrap();
        client
            .issue_dns01_replacing(
                &ALL_NAMES,
                dns.as_ref(),
                &rcgen_leaf(&RFC9773_AKI, &[1], false),
            )
            .await
            .unwrap();
        client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), "not a certificate")
            .await
            .unwrap();
        assert!(state
            .lock()
            .unwrap()
            .orders
            .iter()
            .all(|o| o.get("replaces").is_none()));

        // alreadyReplaced (a replacement is under way or done): ordered once more without it, and
        // the renewal still succeeds.
        let (dir, state, dns, _, pem) = replacing_ca().await;
        state.lock().unwrap().already_replaced = true;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let cert = client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), &pem)
            .await
            .expect("falls back to a plain order");
        assert!(cert.chain_pem.contains("BEGIN CERTIFICATE"));
        let orders = state.lock().unwrap().orders.clone();
        assert_eq!(orders.len(), 2, "the refused attempt and the retry");
        assert!(
            orders[0].get("replaces").is_some() && orders[1].get("replaces").is_none(),
            "{orders:?}"
        );

        // Anything else a CA says about the order is not swallowed: a rate limit surfaces as such.
        let (dir, state, dns, _, pem) = replacing_ca().await;
        state.lock().unwrap().rate_limit_new_order = true;
        let client = AcmeClient::new(&dir, test_account(), None).await.unwrap();
        let err = client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), &pem)
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::RateLimited { .. }), "{err}");
        assert_eq!(state.lock().unwrap().orders.len(), 0);
    }

    #[test]
    fn directory_exposes_revoke_cert_when_offered() {
        let d: Directory = serde_json::from_str(r#"{"newNonce":"https://x/n","newAccount":"https://x/a","newOrder":"https://x/o","revokeCert":"https://x/r"}"#).unwrap();
        assert_eq!(d.revoke_cert.as_deref(), Some("https://x/r"));
        let bare: Directory = serde_json::from_str(
            r#"{"newNonce":"https://x/n","newAccount":"https://x/a","newOrder":"https://x/o"}"#,
        )
        .unwrap();
        assert_eq!(bare.revoke_cert, None);
    }

    // ── Entropy, key policy and CA-output checks ─────────────────────────────────────────

    /// A key generator whose RNG has failed.
    #[derive(Debug)]
    struct FailingKeyGen;
    impl CertKeyGen for FailingKeyGen {
        fn generate(&self, _: KeyAlg) -> Result<EcdsaKeyPair, crate::certkey::KeyGenError> {
            Err(crate::certkey::KeyGenError("injected RNG failure".into()))
        }
    }

    #[tokio::test]
    async fn issuance_fails_closed_before_the_ca_is_asked_for_anything_when_the_rng_fails() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        let opts = ClientOptions {
            keygen: Arc::new(FailingKeyGen),
            ..ClientOptions::default()
        };
        let client = AcmeClient::connect(&dir, account, None, None, opts)
            .await
            .expect("registering the account needs no certificate key");
        let err = client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect_err("no key, no certificate");
        assert!(
            matches!(&err, AcmeError::Local(m) if m.contains("injected RNG failure")),
            "{err}"
        );
        assert_eq!(
            err.class(),
            FailureClass::Local,
            "our failure is never held against the CA"
        );
        let st = state.lock().unwrap();
        assert!(
            st.orders.is_empty(),
            "no order was placed, so no authorization was spent: {:?}",
            st.orders
        );
        assert!(st.challenged.is_empty());
        assert_eq!(st.issued, 0);
    }

    #[test]
    fn an_account_key_is_not_generated_when_the_rng_fails() {
        assert!(matches!(
            AccountKey::generate_with(&FailingKeyGen),
            Err(AcmeError::Local(_))
        ));
    }

    #[tokio::test]
    async fn every_order_gets_a_new_key_and_the_certificate_certifies_it() {
        let account = test_account();
        let (dir, _state, dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let a = client.issue_dns01(&ALL_NAMES, dns.as_ref()).await.unwrap();
        let b = client
            .issue_dns01_replacing(&ALL_NAMES, dns.as_ref(), &a.chain_pem)
            .await
            .unwrap();
        assert_ne!(
            a.key_pem, b.key_pem,
            "a renewal must not reuse the key of the certificate it replaces"
        );
        assert_ne!(
            crate::x509::leaf_spki(&a.chain_pem),
            crate::x509::leaf_spki(&b.chain_pem)
        );
        for m in [&a, &b] {
            let key = AccountKey::from_pkcs8_pem(&m.key_pem).unwrap();
            let spki = crate::x509::leaf_spki(&m.chain_pem).unwrap();
            let pk = key.pair.public_key().as_ref().to_vec();
            assert!(spki.ends_with(&pk), "the leaf certifies the key in key_pem");
        }
    }

    #[tokio::test]
    async fn a_ca_that_certifies_some_other_key_or_other_names_is_refused() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        // A well-formed certificate for a different key.
        let (other_chain, _, _) = rcgen_leaf_with_key(&[9]);
        state.lock().unwrap().cert_pem = Some(other_chain);
        let err = client
            .issue_dns01(&ALL_NAMES, dns.as_ref())
            .await
            .expect_err("the key is not ours");
        assert!(
            matches!(&err, AcmeError::CaMisbehaved(m) if m.contains("does not certify the key")),
            "{err}"
        );
        assert_eq!(
            err.class(),
            FailureClass::CaSide,
            "mis-issuance counts against the CA"
        );
        // A certificate for the right key family but a name we did not ask for, and no certificate at all.
        let pair = generate_cert_key();
        let (chain, _, _) = rcgen_leaf_with_key(&[1]);
        let err = verify_issued(&chain, &pair, KeyAlg::P256, &["app.acme.com.au"]).unwrap_err();
        assert!(
            matches!(&err, AcmeError::CaMisbehaved(m) if m.contains("does not certify the key")),
            "{err}"
        );
        assert!(verify_issued("garbage", &pair, KeyAlg::P256, &["x.test"]).is_err());
    }

    #[test]
    fn a_p384_csr_and_key_are_well_formed_and_the_policy_gate_applies() {
        use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_ASN1};
        let pair = OsCertKeyGen.generate(KeyAlg::P384).unwrap();
        let csr_der = csr(&pair, KeyAlg::P384, &["a.example.test"]).unwrap();
        let (_, csr_body, _) = der::read(&csr_der).unwrap();
        let (t, _, rest) = der::read(csr_body).unwrap();
        assert_eq!(t, 0x30);
        let cri = &csr_body[..csr_body.len() - rest.len()];
        let (_, alg, rest) = der::read(rest).unwrap();
        assert_eq!(der::read(alg).unwrap().1, KeyAlg::P384.signature_oid());
        let (bit_tag, bits, _) = der::read(rest).unwrap();
        assert_eq!(bit_tag, 0x03);
        // The signature (a DER ECDSA-Sig-Value after the unused-bits octet) verifies under the CSR's public key.
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pair.public_key().as_ref())
            .verify(cri, &bits[1..])
            .expect("P-384 CSR signature");
        let pem = key_to_pkcs8_pem(&pair, KeyAlg::P384).unwrap();
        assert_eq!(
            KeyPolicy::default().check_pkcs8_pem(&pem).unwrap(),
            crate::certkey::KeyKind::Ec(crate::certkey::EcCurve::P384)
        );
        assert!(KeyPolicy {
            allow_p384: false,
            ..KeyPolicy::default()
        }
        .check_pkcs8_pem(&pem)
        .is_err());
    }

    #[tokio::test]
    async fn a_client_configured_with_a_refused_key_algorithm_does_not_start() {
        let account = test_account();
        let (dir, _state, _dns) = mock_ca::start(&account).await;
        let opts = ClientOptions {
            key_alg: KeyAlg::P384,
            key_policy: KeyPolicy {
                allow_p384: false,
                ..KeyPolicy::default()
            },
            ..ClientOptions::default()
        };
        let err = AcmeClient::connect(&dir, account, None, None, opts)
            .await
            .err()
            .expect("P-384 is not allowed by this policy");
        assert!(matches!(err, AcmeError::Local(_)), "{err}");
    }

    #[tokio::test]
    async fn a_ca_that_accepts_the_connection_and_says_nothing_times_out_as_a_ca_side_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/directory", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((c, _)) = listener.accept().await {
                held.push(c); // never answers
            }
        });
        let opts = ClientOptions {
            request_timeout: Duration::from_millis(300),
            ..ClientOptions::default()
        };
        let started = std::time::Instant::now();
        let err = AcmeClient::connect(&url, test_account(), None, None, opts)
            .await
            .err()
            .expect("must not hang");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(err.class(), FailureClass::CaSide);
    }

    #[test]
    fn failures_are_classed_for_the_fail_over_decision() {
        use FailureClass::*;
        let rejected = |status, detail: &str| AcmeError::Rejected {
            status,
            detail: detail.into(),
        };
        assert_eq!(
            AcmeError::RateLimited {
                retry_after_secs: None,
                detail: String::new()
            }
            .class(),
            RateLimited
        );
        assert_eq!(rejected(503, "").class(), CaSide);
        assert_eq!(rejected(500, "").class(), CaSide);
        assert_eq!(
            rejected(
                200,
                r#"{"type":"urn:ietf:params:acme:error:serverInternal"}"#
            )
            .class(),
            CaSide
        );
        assert_eq!(
            rejected(403, r#"{"type":"urn:ietf:params:acme:error:unauthorized"}"#).class(),
            Refused
        );
        assert_eq!(
            rejected(
                400,
                r#"{"type":"urn:ietf:params:acme:error:rejectedIdentifier"}"#
            )
            .class(),
            Refused
        );
        assert_eq!(AcmeError::AuthorizationFailed("x".into()).class(), Refused);
        assert_eq!(AcmeError::OrderNotValid.class(), Refused);
        assert_eq!(AcmeError::MissingNonce.class(), CaSide);
        assert_eq!(AcmeError::BadResponse("x".into()).class(), CaSide);
        assert_eq!(AcmeError::CaMisbehaved("x".into()).class(), CaSide);
        assert_eq!(
            AcmeError::Http(crate::http_types::Error::Http("x".into())).class(),
            CaSide
        );
        assert_eq!(AcmeError::ChallengeSetup.class(), Local);
        assert_eq!(AcmeError::Local("x".into()).class(), Local);
    }

    #[test]
    fn certificate_material_never_prints_its_key() {
        let pair = generate_cert_key();
        let material = CertMaterial {
            chain_pem: "chain".into(),
            key_pem: p256_key_to_pkcs8_pem(&pair),
        };
        let shown = format!("{material:?}");
        assert!(
            !shown.contains("PRIVATE") && !shown.contains(&material.key_pem[28..60]),
            "{shown}"
        );
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn the_account_key_is_created_0600_once_and_a_damaged_one_is_never_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "acct-key-{}",
            crate::entropy::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("acct.key");
        // RNG failure: nothing is written.
        assert!(matches!(
            load_or_create_account_key_with(&path, &FailingKeyGen),
            Err(AcmeError::Local(_))
        ));
        assert!(!path.exists());
        let first = load_or_create_account_key(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&path).unwrap().len(), 32);
        let again = load_or_create_account_key(&path).unwrap();
        assert_eq!(
            first.thumbprint(),
            again.thumbprint(),
            "the same account on every start"
        );
        std::fs::write(&path, b"short").unwrap();
        assert!(load_or_create_account_key(&path).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"short",
            "a damaged key is left alone, not replaced"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_profile_is_requested_only_when_the_ca_advertises_it() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        state.lock().unwrap().profiles = vec!["tlsserver".into(), "classic".into()];
        let with = |profile: &str| ClientOptions {
            profile: Some(profile.into()),
            ..ClientOptions::default()
        };
        let client = AcmeClient::connect(&dir, account.clone(), None, None, with("tlsserver"))
            .await
            .unwrap();
        client.issue_dns01(&ALL_NAMES, dns.as_ref()).await.unwrap();
        let client = AcmeClient::connect(&dir, account.clone(), None, None, with("shortlived"))
            .await
            .unwrap();
        client.issue_dns01(&ALL_NAMES, dns.as_ref()).await.unwrap();
        let client = AcmeClient::connect(&dir, account, None, None, ClientOptions::default())
            .await
            .unwrap();
        client.issue_dns01(&ALL_NAMES, dns.as_ref()).await.unwrap();
        let orders = state.lock().unwrap().orders.clone();
        assert_eq!(orders[0]["profile"], "tlsserver");
        assert!(
            orders[1].get("profile").is_none(),
            "an unadvertised profile is left out rather than failing the order: {}",
            orders[1]
        );
        assert!(orders[2].get("profile").is_none());
    }
}
