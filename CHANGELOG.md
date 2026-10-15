# Changelog

## 0.3.0 — certificate lifecycle, edge admission, aws-lc-rs

**BREAKING** (see "Migration" at the end).

### Certificates and ACME
- **`edge_dns` compiles.** It was written against `hickory-proto`, never a buildable dependency, so
  the authoritative DNS and the DNS-01 responder did not build in any configuration. Ported to the
  native `dns` module; compiled and tested by default. `HickoryProbe` (also unbuildable) is replaced
  by `edge_verify::NativeProbe` (UDP + TCP fallback, CNAME-chain following, spoof-resistant reply
  matching, resolver failover). The `bind-edge-dns` feature remains as an empty alias.
- **ACME certificate keys are ECDSA P-256.** The finalize CSR was Ed25519, which public CAs do not
  issue; every real order would have failed after spending validation rate limit.
- `badNonce` is retried transparently; 429/`rateLimited` surfaces as `AcmeError::RateLimited` with
  `Retry-After`; a failed authorization carries the CA's reason.
- **New `acme_renew`**: the renewal engine nothing implemented. Renews at a percentage of each
  certificate's own lifetime, exponential backoff with per-name jitter honouring `Retry-After`, keeps
  last-known-good on failure, rejects junk/expired CA output, fails never-issued hostnames after N
  attempts (never a baseline wildcard, never a hostname already serving), prunes unrequired certs after
  a grace period, `FileCertStore` persists across restarts (atomic, 0600). Baseline = every apex wildcard.
- CAA records can be bound to the ACME account and `dns-01` (`ZoneConfig::with_caa_account_uri`).

### Crypto
- **ACME account/certificate keys, JWS signing and CSR signing now use `aws-lc-rs`** instead of
  hashtrinity's hand-written P-256 (variable-time scalar multiplication). The edge serves TLS
  (`EdgeCertResolver::server_config`) and the HTTP client terminates/originates TLS on aws-lc-rs;
  `ring` is no longer enabled. New `fips` feature builds the FIPS-validated module and restricts
  providers to FIPS-approved suites (needs Go + CMake; if `bindgen` fails with a `syn` conflict run
  `cargo update -p prettyplease --precise 0.2.37`).

### Edge naming and admission
- `APEXES` = tasmanian.cloud, tascloud.app, tascloud.dev, tasmaniancloud.{app,dev,com.au,au}.
- A custom hostname's CNAME proof target must be an **active managed hostname of the same tenant**.
- Released managed labels are **quarantined 30 days** against other tenants (dangling-CNAME takeover).
- `cert_ready` only moves `PendingCert -> Active` (a certificate could previously lift a suspension);
  new `activate_cert` / `cert_failed`.
- Custom hostnames no public CA can certify (special-use TLDs, numeric TLD) are rejected; reserved
  labels cover platform surfaces.
- `EdgeCertResolver` is a real `ResolvesServerCert` with a digest-keyed cache (SNI -> certificate).
- **TLS passthrough by SNI**: `tls_hello::peek_sni` (strict ClientHello parser), `TlsMode::Passthrough`,
  `sni_route`, `decide_passthrough`. Passthrough names need no certificate and are never issued one.
- `Decision::NoConnector.status()` is 502, matching its documentation (was 503).

### Native transport
- **`NativeEndpoint::accept` no longer lets one stalled peer block the listener.** It ran the
  handshake inline with no timeout, so a TCP connection that said nothing held every later
  dial-in hostage indefinitely. Handshakes now run concurrently (at most 256) on an acceptor task,
  each under `HANDSHAKE_TIMEOUT` (10 s, also applied to `connect`). `accept` yields only
  connections whose peer proved its identity.
- Edge helpers: `EdgeRegistry::bind_peer`, `ZoneAuthority::set_caa_account_uri`,
  `edge_verify::{ProofPolicy, sweep_shared}`, `RenewalEngine::run_forever_with`.
- A test pins that the edge's server config negotiates hybrid `X25519MLKEM768` and still serves
  classical-only clients.

### Migration
- `AccountKey::from_bytes` now returns `Result` (new: `generate`, `to_bytes`).
- `EdgeRegistry::add_custom` returns `InvalidCnameTarget` unless the target is an active managed
  hostname of the same tenant. `HostnameRecord` has a new `tls_mode` field.
- `release` of a managed label no longer frees it immediately for other tenants.
- Hostnames under `twnstack.*` / `twnbox.*` are no longer edge apexes.
- `MemoryCertSource::install` unchanged; new `remove`, and `CertStore` for writable stores.

## 0.2.0 — BREAKING: `dialkey::peer_id` returns the public key

### The defect

`dialkey::peer_id(dialkey)` returned `SHA-256(dialkey ++ ":pkarr")` — the 32-byte **secret** Ed25519
seed that `native_keypair` feeds to `Keypair::from_secret_key`. Everywhere else `PeerId` is the
Ed25519 **public** key (`lib.rs`, `bastion.rs`, `discovery.rs`, the handshake in `native.rs`/`quic.rs`).
So anything that logged, pinned, published, gossiped or stored `peer_id(dialkey)` exposed a secret
derived from the dialkey (anyone holding the seed can sign records under the dialkey's name), and
anything comparing it with a real peer's public key never matched. It behaved this way in every
revision of this repo (`057d9ae` onwards, `v0.1.0` included).

`PeerAddr`, `DialkeyService` (from `dialkey::resolve`) and `federation::Mount` stamp `peer_id(dialkey)`
into their `PeerAddr`, and `PeerAddr::to_string()` embeds it as hex, so those leaked it too.

### The change

- `dialkey::peer_id(dialkey)` now returns the **public** key of `dialkey::native_keypair(dialkey)`.
  Safe to log, pin, publish and gossip.
- The seed function is `pub(crate)` (`dialkey::secret_seed_do_not_expose`): there is no public
  dialkey→seed function and deliberately no replacement for the old behaviour. (An endpoint built
  with `bind_with_dialkey`/`bind_with_key` still hands out its own secret through the pre-existing
  `NativeEndpoint::secret_key()` persistence getter — that is by design, not a path from `peer_id`.)
- **Unchanged, on purpose:** the derivation (`SHA-256(dialkey ++ ":pkarr")` → Ed25519), therefore the
  keypair, the z-base32 name a dialkey publishes under, and every record already published. Golden
  vectors in `dialkey.rs` pin this.
- New `NativeEndpoint::bind_with_dialkey(addr, dialkey)`: binds an endpoint whose identity (and the
  id a peer observes in the handshake) is exactly `dialkey::peer_id(dialkey)`, without the caller
  deriving the secret.
- `http_client`, `wire`, `pkarr::RelayClient` (and its `DialkeyTransport` impl) and the
  `pkarr::publish_*/resolve_*` helpers are now gated on `native`; `--no-default-features` compiles
  (it did not: `http_client` used tokio/rustls/tracing ungated). `flate2` is optional under `native`.
  `tokio` is a dev-dependency so the always-compiled modules' tests build without features.
- Version 0.1.0 → 0.2.0.

### Migrating a caller

Callers that only compared, pinned, logged or displayed the id need nothing; they now get the public
key, which is what they wanted. Callers that used the result as a **secret** must move:

| Before (0.1.x) | After (0.2.0) |
|---|---|
| `NativeEndpoint::bind_with_key(addr, dialkey::peer_id(k))` | `NativeEndpoint::bind_with_dialkey(addr, k)` |
| `hashtrinity::crypto::ed25519_pubkey(&dialkey::peer_id(k))` (the identity the handshake reports) | `dialkey::peer_id(k)` |
| `Keypair::from_secret_key(&dialkey::peer_id(k))` | `dialkey::native_keypair(k)` |

Correctly migrated callers keep the same wire identity (tested: `bind_with_dialkey(k)` presents the same
public key `bind_with_key(peer_id_0_1(k))` did), so a rolling upgrade across both sides is compatible.
Callers that left the old value in a log, store or published record have exposed a secret derived
from the dialkey; whether to rotate is the owner's decision, and this release does not rotate anything.
