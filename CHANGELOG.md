# Changelog

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
- The secret seed is `pub(crate)` (`dialkey::secret_seed_do_not_expose`) and is not reachable from
  outside the crate. There is deliberately no public replacement for the old behaviour.
- **Unchanged, on purpose:** the derivation (`SHA-256(dialkey ++ ":pkarr")` → Ed25519), therefore the
  keypair, the z-base32 name a dialkey publishes under, and every record already published. Golden
  vectors in `dialkey.rs` pin this.
- New `NativeEndpoint::bind_with_dialkey(addr, dialkey)`: binds an endpoint whose identity (and the
  id a peer observes in the handshake) is exactly `dialkey::peer_id(dialkey)`, without the secret
  leaving this crate.
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

Correctly migrated callers keep the same wire identity (`bind_with_dialkey(k)` presents the same
public key `bind_with_key(peer_id_0_1(k))` did), so a rolling upgrade across both sides is compatible.
Callers that left the old value in a log, store or published record should treat the dialkey as
exposed and rotate it.
