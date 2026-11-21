# transport

A transport kernel for Rust: **TCP, TLS, DNS, signed dialkeys, gossip and edge-mesh routing**,
in small modules you can take one at a time.

## Why this instead of the obvious alternative

Most projects reach for `tokio` + `rustls` (or `hyper` + `reqwest`) and write the rest
themselves: a resolver, a connection pool, a mesh, and — the part that is usually skipped — a
way to know **who** the peer on the other end is. That is a lot of surface to own, and the
identity part is the one that has to be right in the presence of an adversary.

This crate is that surface, factored so you can take one piece of it:

| what you would otherwise write | what you use here |
|---|---|
| a resolver with caching, negative answers and a search policy | `dns`, `signed_dns`, `mesh_dns`, `edge_dns`, `dns_health`, `zone_sync` |
| "who is this peer?" — usually trust-on-first-use | `dialkey`: an Ed25519-signed key **carried by the record that names the service**, verified **before** you dial |
| a pub/sub bus for discovery | `gossip` (PUB/SUB), `discovery`, `pkarr`, `pkarr_relay` |
| a TLS/QUIC extension of your own | `tls_hello`, `certkey`, `x509`, `pem`, `ca_trust`, `ca_policy`, `ca_resilience`, `ct_monitor`, `acme`, `acme_renew`, `quic` |
| a reverse proxy for the edge | `edge`, `edge_proxy`, `edge_verify`, `edge_dns` |
| a bastion or a control channel | `bastion`, `control` |
| an HTTP client you had to write | `http_client`, `http_types` |
| the plumbing around it | `base32`, `entropy`, `prim`, `latency`, `provision`, `federation`, `sync`, `native` |

Three things this crate does that a hand-rolled stack usually does not:

1. **Identity before connect.** A *dialkey* is an Ed25519 signature over the target's key and
   address, carried by the record that names the service. You verify the signature **before**
   the connection is made, so a peer cannot present the key you did not ask for.
   `peer_id(dialkey)` is the **public** key (0.2.0; before that it returned the secret seed —
   see `CHANGELOG.md`).
2. **The core needs no runtime.** The kernel primitives — the resolver, the dialkey derivation,
   the packet builders — build with **no async runtime and no TLS stack**:
   `cargo build --no-default-features` pulls in nothing. The tokio + rustls adapters sit
   behind the `native` feature, which is on by default. So the wire formats are usable in a
   CLI, a build script, or a target that will never see a socket.
3. **Unix-composable.** Every module is small and focused. Take `dialkey` without the mesh, or
   `dns` without the gossip.

## Modules

- `bastion` — onion-style entry guard
- `control` — control-channel primitives
- `dialkey` — Ed25519-signed dial keys (verify pubkey **and** target before connecting)
- `discovery` — service discovery
- `dns` — resolver and authoritative servers
- `signed_dns` — DNS records with a signature
- `mesh_dns` — authoritative DNS for dialkey-published services
- `edge` / `edge_dns` / `edge_proxy` / `edge_verify` — edge-mesh routing, edge-local DNS, the
  reverse-proxy edge face, and edge identity verification
- `gossip` — PUB/SUB gossip broadcast
- `pkarr` / `pkarr_relay` — the pkarr client, and a pkarr relay **server**
- `http_client` / `http_types` — an HTTP client and its types
- `quic` — a QUIC packet and frame **codec** (no connection state machine — see the limits)
- `tls_hello` / `certkey` / `x509` / `pem` / `ca_*` / `acme*` — the TLS and certificate surface
- `base32` / `entropy` / `prim` / `latency` / `provision` / `federation` / `sync` / `native` —
  the plumbing

## `meshd`: service discovery without a third party

`meshd` is one process that runs a pkarr relay and an authoritative DNS zone, so services
publish and find each other by dialkey with nobody else involved:

```text
service  --dialkey::publish-->  meshd :6881   (PUT /<key>, GET /<key>)
anything --DNS---------------->  meshd :5353   _billing._tcp.<key>.mesh.internal  SRV / TXT, <key>.mesh.internal  A
```

Point services at it with `PKARR_RELAYS=http://meshd:6881` (`RelayClient::from_env`).
Configuration is environment variables, documented at the top of
[`src/bin/meshd.rs`](src/bin/meshd.rs).

```sh
docker build --secret id=gh_token,env=GH_TOKEN -t meshd:local .     # see the Dockerfile
GH_TOKEN=... docker compose -f docker-compose.meshd.yml up -d --build
```

What the relay enforces: a record is stored only if it is signed by the key in its URL;
sequence numbers only go up (an older record is `409`); bodies, key count and — optionally —
record age are bounded; publishing can be restricted to a list of keys; records persist across
restarts and are re-verified on load.

## What it does not do — disclosed, not hidden

- **No authentication on reads or on `PUT` beyond the signature and the allowlist.** The relay
  client cannot send credentials, so keep the port on a private interface.
- **No Mainline DHT**, the same stated gap as `pkarr`.
- **No DNSSEC.** Records are signed by their author, which is not a chain a validating resolver
  can check.
- **Not a QUIC relay, a bastion or a VPN.** `quic` is a packet and frame codec; its connection
  state machine (loss recovery, congestion control) is not built, and the native transport that
  does exist is TCP with its own authenticated handshake. `meshd` does discovery only — it does
  not forward traffic between peers.
- **The container image was not built where this was written** (no Docker daemon). The release
  binary was built with `--locked`, checked to need only libc, libm and libgcc, and run as uid
  65532 with a clean environment; `docker build` itself has not been run.

## Build

```sh
cargo build                          # default = `native`: tokio + rustls adapters, http_client, pkarr relay client
cargo build --no-default-features    # wire-format-only zero-dep kernel
```

## Features

| feature | what it adds |
|---|---|
| `native` (default) | tokio + rustls adapters, the HTTP client, the pkarr relay client |
| `runtime-tokio` | the tokio-gated modules (`native`, `gossip`, `quic`) |
| `federation` | the pkarr client |
| `fips` | FIPS 140-3 validated cryptography for everything this crate signs or terminates with (needs Go + CMake at build time) |

## Integration

```toml
[dependencies]
transport = { git = "https://github.com/webfold-ai/transport", rev = "<pin>" }
```

## License

SPDX: `Apache-2.0`. See [`LICENSE`](LICENSE).
