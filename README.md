# Ptyktos/transport

> Transport kernel — TCP, TLS, DNS, signed dialkeys, gossip, edge mesh routing.

Unix-composable: each module is small and focused. The kernel primitives (DNS resolver,
signed dialkey derivation) work without any async runtime; the tokio + rustls
adapters sit behind the `native` feature.

## Modules

- `bastion` — TOR/onion-style entry guard
- `control` — control channel primitives
- `dialkey` — Ed25519-signed dial keys (verify pubkey + target before connect). `peer_id(dialkey)` is the **public** key (0.2.0, breaking: it returned the secret seed before; see CHANGELOG.md)
- `discovery` — service discovery
- `dns` — DNS resolver / authoritatives
- `edge` — edge mesh routing
- `edge_dns` — edge-local DNS
- `edge_proxy` — reverse-proxy edge face
- `edge_verify` — verify edge identities
- `gossip` — PUB/SUB gossip broadcast (used by sangdb's sync protocol)
- `pkarr_relay` — a pkarr relay **server**: the other half of `pkarr::RelayClient`
- `mesh_dns` — authoritative DNS for dialkey-published services, answering from a relay's records

## `meshd`: internal service discovery

`meshd` is one process that runs a pkarr relay and an authoritative DNS zone, so services publish
and find each other by dialkey without a third party:

```text
service  --dialkey::publish-->  meshd :6881   (PUT /<key>, GET /<key>)
anything --DNS---------------->  meshd :5353   _billing._tcp.<key>.mesh.internal  SRV / TXT, <key>.mesh.internal  A
```

Point services at it with `PKARR_RELAYS=http://meshd:6881` (`RelayClient::from_env`). Configuration
is environment variables, documented at the top of [`src/bin/meshd.rs`](src/bin/meshd.rs).

```sh
docker build --secret id=gh_token,env=GH_TOKEN -t meshd:local .     # see the Dockerfile
GH_TOKEN=... docker compose -f docker-compose.meshd.yml up -d --build
```

What the relay enforces: a record is stored only if it is signed by the key in its URL; sequence
numbers only go up (an older record is `409`); bodies, key count and (optionally) record age are
bounded; publishing can be restricted to a list of keys; records persist across restarts and are
re-verified on load. What it does not do:

- **No authentication on reads or on `PUT` beyond the signature and the allowlist.** `RelayClient`
  cannot send credentials, so keep the port on a private interface.
- **No Mainline DHT**, the same stated gap as `pkarr`.
- **No DNSSEC.** Records are signed by their author, which is not a chain a validating resolver can
  check.
- **Not a QUIC relay, a bastion or a VPN.** `quic.rs` is a packet and frame codec; its connection
  state machine (loss recovery, congestion control) is not built, and the native transport that
  exists is TCP with its own authenticated handshake. `meshd` does discovery only; it does not
  forward traffic between peers.
- **The image was not built where this was written** (no Docker daemon). The release binary was
  built with `--locked`, checked to need only libc, libm and libgcc, and run as uid 65532 with a
  clean environment; `docker build` itself has not been run.

The pins in `Cargo.toml` are kept current by `caretaker-pins` (Ptyktos/caretaker,
`docs/git-pins.md`); do not edit them by hand.

## Build

```sh
cargo build                          # default = `native`: tokio + rustls adapters, http_client, pkarr relay client
cargo build --no-default-features      # wire-format-only zero-dep kernel
```
