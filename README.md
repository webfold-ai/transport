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

## Build

```sh
cargo build                          # default = `native`: tokio + rustls adapters, http_client, pkarr relay client
cargo build --no-default-features      # wire-format-only zero-dep kernel
```
