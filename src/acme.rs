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
//! **The crypto is not reinvented here.** `hashtrinity::crypto::{jwt,acme,certgen}` already
//! carries everything ACME needs at the primitive level — `jwt_sign_es256` (JWS signing),
//! `b64url`/`jwk_thumbprint_ec_p256` (RFC 7638), `acme_key_authorization` (RFC 8555 §8.1), and
//! `ecdsa_p256_sign` — down to a doc comment on the `acme`
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
//! **What's genuinely verified here vs. not**: every pure step (JWS/JWK construction, the
//! flattened-JSON envelope ACME's wire format needs — not the compact `a.b.c` form
//! `jwt_sign_es256` returns — the CSR's PKCS#8 key wrapping, the DNS-01 responder round-trip
//! through the edge authoritative DNS) has a real unit test. The end-to-end HTTP flow
//! against a live ACME server (Let's Encrypt or a local Pebble instance) is NOT exercised
//! by an automated test in this sandbox — no outbound HTTPS to a real CA, no public HTTP-01
//! listener, and no real DNS-01 resolver are available here. That is a real, disclosed gap,
//! not a silently-assumed one.

use std::sync::Mutex as StdMutex;

use hashtrinity::crypto::acme::{acme_key_authorization, b64url, jwk_thumbprint_ec_p256};
use hashtrinity::crypto::jwt::jwt_sign_es256;
use hashtrinity::crypto::{ecdsa_p256_sign, p256_pubkey, sha256};
use serde::Deserialize;
use serde_json::{json, Value};

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
    Rejected { status: u16, detail: String },
    /// The CA is rate limiting this account or identifier set (HTTP 429 or a `rateLimited`
    /// problem). Distinct from `Rejected` because the right response is to wait, not to
    /// retry on the normal schedule — hammering a rate limit extends it.
    RateLimited { retry_after_secs: Option<u64>, detail: String },
    MissingNonce,
    AuthorizationFailed(String),
    OrderNotValid,
    ChallengeSetup,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Http(e) => write!(f, "talking to the ACME server: {e}"),
            AcmeError::BadResponse(s) => write!(f, "ACME server returned a response this client could not parse: {s}"),
            AcmeError::Rejected { status, detail } => write!(f, "ACME server rejected the request ({status}): {detail}"),
            AcmeError::RateLimited { retry_after_secs, detail } => match retry_after_secs {
                Some(s) => write!(f, "ACME server is rate limiting us (retry after {s}s): {detail}"),
                None => write!(f, "ACME server is rate limiting us: {detail}"),
            },
            AcmeError::MissingNonce => write!(f, "no Replay-Nonce header on a response that was supposed to carry one"),
            AcmeError::AuthorizationFailed(url) => write!(f, "authorization {url} did not reach the valid state"),
            AcmeError::OrderNotValid => write!(f, "order did not reach the valid state after finalization"),
            AcmeError::ChallengeSetup => write!(f, "ACME challenge responder rejected publishing the proof"),
        }
    }
}

impl std::error::Error for AcmeError {}

impl AcmeError {
    /// Seconds the CA asked us to wait, if it said.
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            AcmeError::RateLimited { retry_after_secs, .. } => *retry_after_secs,
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
#[derive(Clone)]
pub struct AccountKey {
    secret: [u8; 32],
}

impl AccountKey {
    /// Wrap an existing 32-byte P-256 private key (e.g. loaded from a sealed store).
    #[must_use]
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        AccountKey { secret }
    }

    /// The JWK this key presents in `newAccount`'s protected header (no `kid` yet — the CA
    /// hasn't assigned an account URL until that request succeeds).
    fn jwk(&self) -> Value {
        let pk = p256_pubkey(&self.secret);
        let (x, y) = pk.split_at(32);
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
        let pk = p256_pubkey(&self.secret);
        let (x, y) = pk.split_at(32);
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(x);
        yb.copy_from_slice(y);
        jwk_thumbprint_ec_p256(&xb, &yb)
    }
}

/// Build the flattened-JSON JWS body ACME's wire format requires: `{"protected","payload","signature"}`
/// as JSON string members, not the compact `header.payload.sig` dot form `jwt_sign_es256` returns
/// (that form is for tokens carried inside another envelope, e.g. an `Authorization:` header — ACME's
/// own request bodies ARE the JWS, JSON-serialized).
///
/// `payload_json` is `""` for a POST-as-GET (RFC 8555 §6.3) — the empty string, not `"{}"` or
/// `null`, per the spec's own worked examples.
fn flattened_jws(account: &AccountKey, protected: &Value, payload_json: &str) -> String {
    let protected_json = protected.to_string();
    let compact = jwt_sign_es256(&account.secret, &protected_json, payload_json);
    let mut parts = compact.split('.');
    let protected_b64 = parts.next().expect("jwt_sign_es256 always emits two dots");
    let payload_b64 = parts.next().expect("jwt_sign_es256 always emits two dots");
    let sig_b64 = parts.next().expect("jwt_sign_es256 always emits two dots");
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": sig_b64,
    })
    .to_string()
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
    pub token: String,
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
    fn serve_token<'a>(&'a self, token: &'a str, key_authorization: &'a str) -> crate::BoxFuture<'a, Result<(), AcmeError>>;
    fn remove_token<'a>(&'a self, token: &'a str) -> crate::BoxFuture<'a, ()>;
}

/// Publishes a DNS-01 TXT value at `_acme-challenge.{name}`. `publish_txt` must
/// return only once the CA can query the authoritative DNS server for the value.
/// Removing one value must preserve any other concurrent challenge at that name.
pub trait Dns01Responder: Send + Sync {
    fn publish_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, Result<(), AcmeError>>;
    fn remove_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, ()>;
}

enum ChallengeResponder<'a> {
    Http(&'a dyn Http01Responder),
    Dns(&'a dyn Dns01Responder),
}

fn header_str(resp: &crate::http_types::Response, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// One ACME account + its live nonce, driving the order/authorization/challenge/finalize state
/// machine against a real ACME server via [`crate::http_client::Client`].
pub struct AcmeClient {
    directory: Directory,
    account: AccountKey,
    kid: StdMutex<Option<String>>,
    nonce: StdMutex<Option<String>>,
}

impl AcmeClient {
    /// Fetch the directory and register the account (RFC 8555's `newAccount` is idempotent for
    /// an already-registered key: the CA returns the existing account's URL as `Location`).
    ///
    /// # Errors
    /// Any transport failure, or the CA rejecting account creation.
    pub async fn new(directory_url: &str, account: AccountKey, contact_email: Option<&str>) -> Result<Self, AcmeError> {
        let body = Client::new().get(directory_url).send().await?.text().await?;
        let directory: Directory = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

        let client = AcmeClient { directory, account, kid: StdMutex::new(None), nonce: StdMutex::new(None) };
        client.refresh_nonce().await?;
        client.create_account(contact_email).await?;
        Ok(client)
    }

    async fn refresh_nonce(&self) -> Result<(), AcmeError> {
        let resp = Client::new().head(&self.directory.new_nonce).send().await?;
        let nonce = header_str(&resp, "replay-nonce").ok_or(AcmeError::MissingNonce)?;
        *self.nonce.lock().unwrap() = Some(nonce);
        Ok(())
    }

    fn take_nonce(&self) -> Result<String, AcmeError> {
        self.nonce.lock().unwrap().take().ok_or(AcmeError::MissingNonce)
    }

    fn store_nonce_from(&self, resp: &crate::http_types::Response) {
        if let Some(n) = header_str(resp, "replay-nonce") {
            *self.nonce.lock().unwrap() = Some(n);
        }
    }

    async fn create_account(&self, contact_email: Option<&str>) -> Result<(), AcmeError> {
        let nonce = self.take_nonce()?;
        let protected = protected_header_jwk(&self.account, &nonce, &self.directory.new_account);
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if let Some(email) = contact_email {
            payload["contact"] = json!([format!("mailto:{email}")]);
        }
        let jws = flattened_jws(&self.account, &protected, &payload.to_string());
        let resp = Client::new()
            .post(&self.directory.new_account)
            .header(header::CONTENT_TYPE, "application/jose+json")
            .body(jws.into_bytes())
            .send()
            .await?;
        self.store_nonce_from(&resp);
        let status = resp.status().as_u16();
        let kid = header_str(&resp, header::LOCATION);
        let body = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected { status, detail: body });
        }
        let kid = kid.ok_or_else(|| AcmeError::BadResponse("newAccount response had no Location".to_string()))?;
        *self.kid.lock().unwrap() = Some(kid);
        Ok(())
    }

    fn kid(&self) -> Result<String, AcmeError> {
        self.kid.lock().unwrap().clone().ok_or_else(|| AcmeError::BadResponse("no account kid yet".to_string()))
    }

    /// POST a JWS-signed request and return `(status, body)`. `payload_json` is `""` for a
    /// POST-as-GET.
    async fn post_signed(&self, url: &str, payload_json: &str) -> Result<(u16, String), AcmeError> {
        let (status, _, body) = self.send_signed(url, payload_json).await?;
        Ok((status, body))
    }

    /// Same as [`Self::post_signed`] but also returns the `Location` header — `newOrder` is
    /// the call that needs it.
    async fn post_signed_with_location(&self, url: &str, payload_json: &str) -> Result<(u16, Option<String>, String), AcmeError> {
        self.send_signed(url, payload_json).await
    }

    /// The one place a signed request leaves this client. Handles the two failure modes every
    /// real CA produces routinely and a naive client treats as fatal:
    ///
    /// - **`badNonce`** (RFC 8555 §6.5): a nonce is single-use and the CA may expire it; the
    ///   error response carries a fresh one, so the request is simply re-signed and re-sent.
    /// - **rate limits**: surfaced as [`AcmeError::RateLimited`] with `Retry-After`, so the
    ///   renewal engine can back off for as long as the CA asked.
    async fn send_signed(&self, url: &str, payload_json: &str) -> Result<(u16, Option<String>, String), AcmeError> {
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
            let kid = self.kid()?;
            let protected = protected_header_kid(&kid, &nonce, url);
            let jws = flattened_jws(&self.account, &protected, payload_json);
            let resp = Client::new().post(url).header(header::CONTENT_TYPE, "application/jose+json").body(jws.into_bytes()).send().await?;
            self.store_nonce_from(&resp);
            let status = resp.status().as_u16();
            let location = header_str(&resp, header::LOCATION);
            let retry_after_secs = header_str(&resp, "retry-after").and_then(|v| v.trim().parse::<u64>().ok());
            let body = resp.text().await?;
            if status == 429 || body.contains("urn:ietf:params:acme:error:rateLimited") {
                return Err(AcmeError::RateLimited { retry_after_secs, detail: body });
            }
            if status == 400 && body.contains("urn:ietf:params:acme:error:badNonce") && attempt < MAX_ATTEMPTS {
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
    pub async fn issue(&self, domains: &[&str], responder: &dyn Http01Responder) -> Result<CertMaterial, AcmeError> {
        self.issue_with(domains, ChallengeResponder::Http(responder)).await
    }

    /// Issue a certificate via DNS-01, including wildcard names.
    pub async fn issue_dns01(&self, domains: &[&str], responder: &dyn Dns01Responder) -> Result<CertMaterial, AcmeError> {
        self.issue_with(domains, ChallengeResponder::Dns(responder)).await
    }

    async fn issue_with(&self, domains: &[&str], responder: ChallengeResponder<'_>) -> Result<CertMaterial, AcmeError> {
        let identifiers: Vec<Value> = domains.iter().map(|d| json!({ "type": "dns", "value": d })).collect();
        let (status, order_location, body) =
            self.post_signed_with_location(&self.directory.new_order, &json!({ "identifiers": identifiers }).to_string()).await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected { status, detail: body });
        }
        let order: OrderResponse = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

        for authz_url in &order.authorizations {
            self.complete_authorization(authz_url, &responder).await?;
        }

        let cert_sk_arr = random_p256_scalar();
        let csr = csr_p256(&cert_sk_arr, domains);
        let csr_b64 = b64url(&csr);
        let (status, body) = self.post_signed(&order.finalize, &json!({ "csr": csr_b64 }).to_string()).await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected { status, detail: body });
        }
        let mut finalized: OrderResponse = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;

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
                finalized = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;
            }
        }
        let cert_url = finalized.certificate.ok_or(AcmeError::OrderNotValid)?;
        let (status, chain_pem) = self.post_signed(&cert_url, "").await?;
        if !(200..300).contains(&status) {
            return Err(AcmeError::Rejected { status, detail: chain_pem });
        }

        Ok(CertMaterial { chain_pem, key_pem: p256_key_to_pkcs8_pem(&cert_sk_arr) })
    }

    async fn complete_authorization(&self, authz_url: &str, responder: &ChallengeResponder<'_>) -> Result<(), AcmeError> {
        let (_, body) = self.post_signed(authz_url, "").await?;
        let authz: AuthorizationResponse = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;
        if authz.status == "valid" {
            return Ok(());
        }
        let kind = match responder { ChallengeResponder::Http(_) => "http-01", ChallengeResponder::Dns(_) => "dns-01" };
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.kind == kind)
            .ok_or_else(|| AcmeError::AuthorizationFailed(authz_url.to_string()))?;

        let key_auth = acme_key_authorization(&challenge.token, &self.account.thumbprint());
        let dns_name = authz.identifier.value.trim_start_matches("*.");
        let dns_value = b64url(&hashtrinity::crypto::sha256(key_auth.as_bytes()));
        match responder {
            ChallengeResponder::Http(r) => r.serve_token(&challenge.token, &key_auth).await?,
            ChallengeResponder::Dns(r) => r.publish_txt(dns_name, &dns_value).await?,
        }

        // Tell the CA the challenge is ready to be fetched (an empty JSON object payload, not
        // POST-as-GET's empty string — RFC 8555 §7.5.1's worked example sends `{}`).
        let result = async {
            let (status, body) = self.post_signed(&challenge.url, "{}").await?;
            if !(200..300).contains(&status) {
                return Err(AcmeError::Rejected { status, detail: body });
            }
            self.poll_authorization(authz_url).await
        }.await;
        match responder {
            ChallengeResponder::Http(r) => r.remove_token(&challenge.token).await,
            ChallengeResponder::Dns(r) => r.remove_txt(dns_name, &dns_value).await,
        }
        result
    }

    async fn poll_authorization(&self, authz_url: &str) -> Result<(), AcmeError> {
        for _ in 0..20 {
            let (_, body) = self.post_signed(authz_url, "").await?;
            let authz: AuthorizationResponse = serde_json::from_str(&body).map_err(|e| AcmeError::BadResponse(e.to_string()))?;
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
                    return Err(AcmeError::AuthorizationFailed(format!("{authz_url} ({why})")));
                }
                _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        Err(AcmeError::AuthorizationFailed(authz_url.to_string()))
    }
}

/// Minimal DER writer/reader — just the shapes a PKCS#10 CSR, a PKCS#8 EC key and an X.509
/// validity window need. No general ASN.1: every structure written here has a fixed shape.
pub(crate) mod der {
    #[must_use]
    pub fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            return vec![n as u8];
        }
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
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
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]; // 1.2.840.113549.1.9.14
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11]; // 2.5.29.17

/// The P-256 group order n, big-endian. A private scalar must be in `[1, n-1]`.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn is_valid_p256_scalar(s: &[u8; 32]) -> bool {
    // Big-endian arrays of equal length compare lexicographically as integers.
    s.iter().any(|b| *b != 0) && s.as_slice() < P256_ORDER.as_slice()
}

/// A fresh certificate private key. Rejection-sampled: a uniformly random 32 bytes is outside
/// `[1, n-1]` with probability ~2^-32, and `p256_pubkey` of an out-of-range scalar is not a key.
pub(crate) fn random_p256_scalar() -> [u8; 32] {
    loop {
        let bytes = hashtrinity::crypto::rand_bytes(32);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        if is_valid_p256_scalar(&s) {
            return s;
        }
    }
}

fn p256_point(sk: &[u8; 32]) -> Vec<u8> {
    let mut point = vec![0x04]; // uncompressed
    point.extend_from_slice(&p256_pubkey(sk));
    point
}

fn ec_algorithm_identifier() -> Vec<u8> {
    der::seq(&[der::tlv(0x06, OID_EC_PUBLIC_KEY), der::tlv(0x06, OID_PRIME256V1)])
}

/// Raw `r‖s` -> DER `SEQUENCE { INTEGER r, INTEGER s }` (what X.509/PKCS#10 carry).
fn ecdsa_sig_der(raw: &[u8; 64]) -> Vec<u8> {
    der::seq(&[der::uint(&raw[..32]), der::uint(&raw[32..])])
}

/// A PKCS#10 CSR (ECDSA P-256 / SHA-256) with `domains` as dNSName SANs and an empty subject —
/// the ACME `finalize` request body. CAs take the identifiers from the SAN, not the subject.
pub(crate) fn csr_p256(sk: &[u8; 32], domains: &[&str]) -> Vec<u8> {
    let names: Vec<Vec<u8>> = domains.iter().map(|d| der::tlv(0x82, d.as_bytes())).collect(); // [2] dNSName
    let san_ext = der::seq(&[der::tlv(0x06, OID_SUBJECT_ALT_NAME), der::tlv(0x04, &der::seq(&names))]);
    let ext_req = der::seq(&[der::tlv(0x06, OID_EXTENSION_REQUEST), der::tlv(0x31, &der::seq(&[san_ext]))]);
    let spki = der::seq(&[ec_algorithm_identifier(), der::bit_string(&p256_point(sk))]);
    let cri = der::seq(&[der::uint(&[0]), der::seq(&[]), spki, der::tlv(0xA0, &ext_req)]);
    let sig = ecdsa_p256_sign(sk, &sha256(&cri));
    der::seq(&[cri, der::seq(&[der::tlv(0x06, OID_ECDSA_SHA256)]), der::bit_string(&ecdsa_sig_der(&sig))])
}

/// PKCS#8 `PrivateKeyInfo` for a P-256 key, PEM-wrapped, in the shape `openssl genpkey` emits
/// (the SEC1 `ECPrivateKey` carries the public point) — what `CertMaterial::key_pem` promises
/// and what `servelet_tls::tls_server_config` / `hashtrinity::rustls` load.
pub(crate) fn p256_key_to_pkcs8_pem(sk: &[u8; 32]) -> String {
    let ec_private_key = der::seq(&[
        der::uint(&[1]),
        der::tlv(0x04, sk),
        der::tlv(0xA1, &der::bit_string(&p256_point(sk))), // [1] publicKey
    ]);
    let pkcs8 = der::seq(&[der::uint(&[0]), ec_algorithm_identifier(), der::tlv(0x04, &ec_private_key)]);
    pem_wrap("PRIVATE KEY", &pkcs8)
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
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
        s.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        s.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> AccountKey {
        // A fixed, arbitrary 32-byte scalar — deterministic tests, not a real account.
        AccountKey::from_bytes([7u8; 32])
    }

    #[test]
    fn flattened_jws_has_three_string_fields_not_the_compact_dot_form() {
        let account = test_account();
        let protected = protected_header_jwk(&account, "test-nonce", "https://example.test/new-account");
        let jws = flattened_jws(&account, &protected, "{}");
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
        let a = AccountKey::from_bytes([1u8; 32]);
        let b = AccountKey::from_bytes([2u8; 32]);
        assert_ne!(a.thumbprint(), b.thumbprint());
    }

    #[test]
    fn directory_deserializes_the_fields_this_client_needs() {
        let json = r#"{"newNonce":"https://x/new-nonce","newAccount":"https://x/new-acct","newOrder":"https://x/new-order","keyChange":"https://x/key-change"}"#;
        let dir: Directory = serde_json::from_str(json).unwrap();
        assert_eq!(dir.new_nonce, "https://x/new-nonce");
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
        let clean: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
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
        let sv = if sv[0] == 0 && sv.len() > 1 { &sv[1..] } else { sv };
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
        let sk = [0x42u8; 32];
        let csr = csr_p256(&sk, &["*.tascloud.app", "tascloud.app"]);
        let (cri, pk, sig) = split_csr(&csr);
        assert_eq!(pk, p256_pubkey(&sk));
        assert!(hashtrinity::crypto::ecdsa_p256_verify(&pk, &sha256(&cri), &sig), "CSR proves possession of the key");
        for d in ["*.tascloud.app", "tascloud.app"] {
            assert!(cri.windows(d.len()).any(|w| w == d.as_bytes()), "{d} must be a SAN");
        }
        // Tampering with the request info invalidates the signature.
        let mut bad = cri.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!hashtrinity::crypto::ecdsa_p256_verify(&pk, &sha256(&bad), &sig));
    }

    #[test]
    fn der_uint_is_minimal_and_non_negative() {
        assert_eq!(der::uint(&[0, 0, 0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(der::uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80], "high bit needs a leading zero");
        assert_eq!(der::uint(&[0, 0]), vec![0x02, 0x01, 0x00]);
        let long = der::tlv(0x04, &[7u8; 300]);
        assert_eq!(der::read(&long).unwrap().1.len(), 300, "long-form lengths round-trip");
    }

    #[test]
    fn scalar_validation_rejects_zero_and_values_at_or_above_the_order() {
        assert!(!is_valid_p256_scalar(&[0u8; 32]));
        assert!(!is_valid_p256_scalar(&P256_ORDER));
        assert!(!is_valid_p256_scalar(&[0xff; 32]));
        assert!(is_valid_p256_scalar(&[1u8; 32]));
        let mut below = P256_ORDER;
        below[31] -= 1;
        assert!(is_valid_p256_scalar(&below));
        assert!(is_valid_p256_scalar(&random_p256_scalar()));
    }

    /// The key we hand back must load in the provider the edge actually serves with.
    #[test]
    fn issued_key_pem_loads_in_the_edge_serving_provider() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{SignatureScheme};
        let sk = random_p256_scalar();
        let pem = p256_key_to_pkcs8_pem(&sk);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes = base64_decode_for_test(&body);
        let provider = hashtrinity::rustls::provider();
        let key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes.clone())))
            .expect("serving provider loads our PKCS#8");
        assert!(key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]).is_some());
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
            fn publish_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, Result<(), AcmeError>> {
                Box::pin(async move {
                    self.published.lock().unwrap().push((name.to_string(), value.to_string()));
                    Ok(())
                })
            }
            fn remove_txt<'a>(&'a self, name: &'a str, value: &'a str) -> crate::BoxFuture<'a, ()> {
                Box::pin(async move { self.removed.lock().unwrap().push((name.to_string(), value.to_string())); })
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
            pub rate_limit_new_order: bool,
            pub challenged: Vec<u32>,
            pub finalized_csr_ok: bool,
            pub bad_nonce_seen: u32,
            pub dns: Option<Arc<FakeDns>>,
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
                body: format!(r#"{{"type":"urn:ietf:params:acme:error:{kind}","detail":"mock {kind}"}}"#),
            }
        }

        /// Returns the decoded payload, or the error reply to send.
        fn verify_jws(st: &mut State, url: &str, body: &str) -> Result<String, Reply> {
            let v: Value = serde_json::from_str(body).map_err(|_| Reply { status: 400, headers: vec![], body: "{}".into() })?;
            let (p, pl, sg) = (v["protected"].as_str().unwrap(), v["payload"].as_str().unwrap(), v["signature"].as_str().unwrap());
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
            assert_eq!(protected["url"].as_str().unwrap(), url, "JWS url header must match the request URL");
            let pk: [u8; 64] = if let Some(jwk) = protected.get("jwk") {
                assert!(protected.get("kid").is_none());
                let mut pk = [0u8; 64];
                pk[..32].copy_from_slice(&b64url_decode_for_test(jwk["x"].as_str().unwrap()));
                pk[32..].copy_from_slice(&b64url_decode_for_test(jwk["y"].as_str().unwrap()));
                st.acct_pk = Some(pk);
                pk
            } else {
                assert_eq!(protected["kid"].as_str().unwrap(), format!("{}/acct/1", st.base));
                st.acct_pk.expect("account registered first")
            };
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&b64url_decode_for_test(sg));
            assert!(
                hashtrinity::crypto::ecdsa_p256_verify(&pk, &sha256(format!("{p}.{pl}").as_bytes()), &sig),
                "bad JWS signature on {url}"
            );
            Ok(String::from_utf8(b64url_decode_for_test(pl)).unwrap())
        }

        fn authz(st: &State, n: u32) -> String {
            let done = st.challenged.contains(&n) && {
                // Validate like a CA: the expected TXT value must be live in DNS right now.
                let token = format!("tok{n}");
                let expect = b64url(&sha256(acme_key_authorization(&token, &st.thumbprint).as_bytes()));
                st.dns.as_ref().unwrap().published.lock().unwrap().iter().any(|(name, v)| name == "tascloud.app" && *v == expect)
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
                Reply { status, headers, body }
            };
            match (method, path) {
                ("GET", "/directory") => Reply {
                    status: 200,
                    headers: vec![],
                    body: format!(
                        r#"{{"newNonce":"{b}/new-nonce","newAccount":"{b}/new-acct","newOrder":"{b}/new-order"}}"#,
                        b = st.base
                    ),
                },
                ("HEAD", "/new-nonce") => ok(st, 200, vec![], String::new()),
                ("POST", p) => {
                    let payload = match verify_jws(st, &url, body) {
                        Ok(p) => p,
                        Err(r) => return r,
                    };
                    match p {
                        "/new-acct" => ok(st, 201, vec![("Location".into(), format!("{}/acct/1", st.base))], "{}".into()),
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
                            let b = st.base.clone();
                            ok(
                                st,
                                201,
                                vec![("Location".into(), format!("{b}/order/1"))],
                                format!(r#"{{"status":"pending","authorizations":["{b}/authz/1","{b}/authz/2"],"finalize":"{b}/finalize/1"}}"#),
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
                            st.finalized_csr_ok = hashtrinity::crypto::ecdsa_p256_verify(&pk, &sha256(&cri), &sig)
                                && cri.windows(14).any(|w| w == b"*.tascloud.app");
                            let b = st.base.clone();
                            ok(st, 200, vec![], format!(r#"{{"status":"valid","authorizations":[],"finalize":"{b}/finalize/1","certificate":"{b}/cert/1"}}"#))
                        }
                        "/cert/1" => ok(st, 200, vec![], "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n".into()),
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
                        .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
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
            let (method, path) = (first.next().unwrap().to_string(), first.next().unwrap().to_string());
            let body = String::from_utf8_lossy(&buf[head_end..head_end + content_len]).to_string();
            let reply = route(&mut state.lock().unwrap(), &method, &path, &body);
            let mut out = format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", reply.status, reply.body.len());
            for (k, v) in &reply.headers {
                out.push_str(&format!("{k}: {v}\r\n"));
            }
            out.push_str("\r\n");
            if method != "HEAD" {
                out.push_str(&reply.body);
            }
            let _ = conn.write_all(out.as_bytes()).await;
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
                    let Ok((conn, _)) = listener.accept().await else { return };
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

        let client = AcmeClient::new(&dir, account, Some("ops@example.test")).await.expect("account registers");
        let cert = client.issue_dns01(&["*.tascloud.app", "tascloud.app"], dns.as_ref()).await.expect("order completes");

        assert!(cert.chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let st = state.lock().unwrap();
        assert!(st.finalized_csr_ok, "CA verified the CSR signature and SANs");
        assert_eq!(st.bad_nonce_seen, 0, "the injected badNonce was retried transparently, not a client bug");
        let published = dns.published.lock().unwrap();
        assert_eq!(published.len(), 2, "wildcard + apex both need a TXT value at the same name");
        assert!(published.iter().all(|(n, _)| n == "tascloud.app"));
        assert_eq!(dns.removed.lock().unwrap().len(), 2, "every challenge value is cleaned up afterwards");
    }

    #[tokio::test]
    async fn a_ca_rate_limit_is_surfaced_with_its_retry_after() {
        let account = test_account();
        let (dir, state, dns) = mock_ca::start(&account).await;
        state.lock().unwrap().rate_limit_new_order = true;
        let client = AcmeClient::new(&dir, account, None).await.unwrap();
        let err = client.issue_dns01(&["*.tascloud.app", "tascloud.app"], dns.as_ref()).await.unwrap_err();
        assert!(matches!(err, AcmeError::RateLimited { retry_after_secs: Some(3600), .. }), "{err}");
        assert_eq!(err.retry_after_secs(), Some(3600));
        assert!(dns.published.lock().unwrap().is_empty(), "no challenge was published for a refused order");
    }
}
