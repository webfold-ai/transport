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
2. **The kernel adapters are opt-in.** `cargo build --no-default-features` disables
   the kernel's tokio + rustls adapters; shared substrate and wire-format dependencies
   remain. The adapters sit behind `native`, which is on by default. The packet and
   identity primitives can be used without enabling the service packages.
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

## Connectivity services (one canonical home)

The workspace also owns `tas-lb`, `tas-dns`, `edge-lb`, `mesh-acl-reconciler`
and `console-ws-proxy`, lifted from hosting-runtime. They are separate packages;
plain `cargo build` still selects the kernel. Nix exports the four service
binaries as packages. Maglev and the existing consistent-ring selector live in
`transport::load_balance`; edge admission and Host parsing stay in
`transport::edge_proxy`. There are no copied implementations in hosting-runtime.

See [the lift record](docs/hosting-edge-lift.md) for before/after test counts,
five negative controls, design sources, consumer pins and deployment limits.

## What it does not do — disclosed, not hidden

- **No authentication on reads or on `PUT` beyond the signature and the allowlist.** The relay
  client cannot send credentials, so keep the port on a private interface.
- **No Mainline DHT**, the same stated gap as `pkarr`.
- **The kernel/meshd signed-record protocol is not DNSSEC.** The separate `tas-dns`
  service provides authoritative DNSSEC, delegated zones and ACME challenge zones;
  its DNSSEC tests are not proof that meshd's records have a validating DNSSEC chain.
- **Not a QUIC relay, a bastion or a VPN.** `quic` is a packet and frame codec; its connection
  state machine (loss recovery, congestion control) is not built, and the native transport that
  does exist is TCP with its own authenticated handshake. `meshd` does discovery only — it does
  not forward traffic between peers. `tas-lb` now forwards TCP/UDP and `edge-lb`
  implements HTTP/tunnel/SNI forwarding, but lifting them does not supply the missing
  QUIC state machine, NAT traversal or a complete NetBird replacement.
- **OCI images were not built for this lift.** Nix package derivation evaluation is
  metadata validation, not a container runtime test. The default-feature binaries
  and the documented test suites were built/run on the build box; no production
  DNS, firewall, mesh enrollment or service was changed.

## Build

```sh
cargo build                          # default = `native`: tokio + rustls adapters, http_client, pkarr relay client
cargo build --no-default-features    # kernel without tokio/TLS adapters; shared substrate deps remain
cargo build -p tas-lb -p tas-dns -p edge-lb -p mesh-acl-reconciler -p console-ws-proxy
```

## Features

| feature | what it adds |
|---|---|
| `native` (default) | tokio + rustls adapters, the HTTP client, the pkarr relay client |
| `runtime-tokio` | the tokio-gated modules (`native`, `gossip`, `quic`) |
| `federation` | the pkarr client |
| `fips` | selects the aws-lc/rustls FIPS build (needs Go + CMake); this feature alone is not end-to-end application certification |

## Integration

```toml
[dependencies]
transport = { git = "https://github.com/webfold-ai/transport", rev = "<pin>" }
```

## License

SPDX: `Apache-2.0`. See [`LICENSE`](LICENSE).
