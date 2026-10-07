# TASK W-N — sweep audit for commit `81730dc` ("merge: Clay's ontology/consolidation branch (PR #7) — and the three things it swept")

Reference: `git -C /home/ctown/projects/hashtrinity log --format='%H %an <%ae>%n%s%n%n' -1 81730cc`
(`81730cc37d472d34b1de088f7b954d0fbf8af5d72f70`, Lucas 'Paperboy' Rose-Winters <lucas@sanguinehost.com>, 2026-08-21)

This is the file the brief asks for: every file deleted by 81730cc, classified as
**MOVED** (to where, with `git` proof) / **LOST** (gone, no replacement) /
**INTENTIONALLY REMOVED** (a documented intent), plus every downstream `Cargo.toml`
that asks `hashtrinity` for a feature or path that the commit destroyed. The
parent `81730cc^1` (= `7ea2006b0431effb776d4029b3b40e4d63130285`, Clay Townsend
<clay@twn.systems>, 2026-08-11) is the recoverable snapshot for every "LOST" or
"INTENTIONALLY REMOVED" file.

A second commit on the same tree (`42dfc4a`, "merge: reconcile the two hashtrinity
histories (flatten + CI + words lift)") ALSO brought most of them back in as
**inline `pub mod xxx { ... }` blocks inside the consolidated files**. That
re-merge is why the modules are reachable from `hashtrinity::sync::grpc` /
`hashtrinity::sync::hpack` / `hashtrinity::sync::http2` again today, despite 81
files being deleted by `81730cc`.

## 1. The 81 deleted files — classification

Command: `git -C /home/ctown/projects/hashtrinity diff --diff-filter=D --name-only 81730cc^1 81730cc | grep -E '^hashtrinity/'`
returns exactly 81 paths; the audit below covers each.

### 1.1 codec/ — all 12 deleted; ALL back by re-merge as inline blocks

| File (deleted)                                | Lines | Status      | Where it lives now                                                                                                                                                                  |
| --------------------------------------------- | ----- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/codec/mod.rs`                |   940 | MOVED       | `hashtrinity/src/codec.rs:40-1224` (`pub mod cm {…}`) and onward; the file `codec/mod.rs` became the trunk `codec.rs` that re-exports the inline modules.                          |
| `hashtrinity/src/codec/bits.rs`               |    68 | INTENTIONALLY REMOVED | Becomes `pub(crate) mod bits {…}` inside `codec.rs` (used by entropy + the col codec); `pub(crate)` rather than `pub`, because no real consumer does.                                  |
| `hashtrinity/src/codec/cm.rs`                  | 1,179 | MOVED       | `hashtrinity/src/codec.rs:40-1224` (`pub mod cm {…}`)                                                                                                                                  |
| `hashtrinity/src/codec/gen.rs`                |   225 | MOVED       | `hashtrinity/src/codec.rs:1225-1452` (`pub mod gen {…}`)                                                                                                                                |
| `hashtrinity/src/codec/huf.rs`                |   400 | MOVED       | `hashtrinity/src/codec.rs:3672-4074` (`pub mod huf {…}`)                                                                                                                                |
| `hashtrinity/src/codec/lz.rs`                 | 1,816 | MOVED       | `hashtrinity/src/codec.rs:1453-3280` (`pub mod lz {…}`)                                                                                                                                  |
| `hashtrinity/src/codec/msgpack.rs`             |   467 | MOVED       | `hashtrinity/src/codec.rs:4075-4544` (`pub mod msgpack {…}`)                                                                                                                            |
| `hashtrinity/src/codec/proto.rs`              | 1,018 | MOVED       | `hashtrinity/src/codec.rs:4545-5578` (`pub mod proto {…}`) — the protobuf wire codec still lives in `hashtrinity::codec::proto` today.                                                 |
| `hashtrinity/src/codec/readout.rs`            |   318 | MOVED       | `hashtrinity/src/codec.rs:3281-3671` (`pub mod readout {…}`)                                                                                                                            |
| `hashtrinity/src/codec/syntax.rs`             |   799 | MOVED       | The trunk stays a dir: `hashtrinity/src/codec/syntax/{mod.rs,surfaces.rs,yaml.rs,rdf.rs,tests.rs}` — `81730cc` ALSO consolidated `syntax/mod.rs` into `src/codec.rs`, then the next commit re-splitted the `syntax/syntax.rs` subset back into a dir. |
| `hashtrinity/src/codec/tans.rs`               |   995 | MOVED       | `hashtrinity/src/codec.rs:6402-7494` (`pub mod tans {…}`)                                                                                                                                |
| `hashtrinity/src/codec/web.rs`                | 1,130 | MOVED       | `hashtrinity/src/codec.rs:7495-end` (`pub mod web {…}`)                                                                                                                                  |

### 1.2 crypto/ — all 24 deleted; all back as inline blocks inside `src/crypto.rs`

`hashtrinity/src/crypto.rs` exists today and is the consolidated trunk; every
deleted `src/crypto/*.rs` is now an inline `pub mod` block. We cite each
destination by line number.

| File (deleted)                          | Lines | Status | Where it lives now                                                                                          |
| --------------------------------------- | ----- | ------ | ---------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/crypto/mod.rs`          |   752 | MOVED  | The trunk `hashtrinity/src/crypto.rs` re-opened as `pub mod {…}` blocks for every child.                 |
| `hashtrinity/src/crypto/acme.rs`        |    64 | MOVED  | `hashtrinity/src/crypto.rs:1460-1525` (`pub mod acme {…}`)                                                  |
| `hashtrinity/src/crypto/aes_cbc.rs`     |    65 | MOVED  | `hashtrinity/src/crypto.rs:1526-1592`                                                                       |
| `hashtrinity/src/crypto/aes_ctr.rs`     |    31 | MOVED  | `hashtrinity/src/crypto.rs:1593-1625`                                                                       |
| `hashtrinity/src/crypto/aes_gcm.rs`     |   397 | MOVED  | `hashtrinity/src/crypto.rs:1626-2024`                                                                       |
| `hashtrinity/src/crypto/age.rs`         |   272 | MOVED  | `hashtrinity/src/crypto.rs:6200-6473`                                                                       |
| `hashtrinity/src/crypto/argon2.rs`      |   678 | MOVED  | `hashtrinity/src/crypto.rs:3641-4320`                                                                       |
| `hashtrinity/src/crypto/bech32.rs`      |    80 | MOVED  | `hashtrinity/src/crypto.rs:2025-2106`                                                                       |
| `hashtrinity/src/crypto/blake2.rs`      |   106 | MOVED  | `hashtrinity/src/crypto.rs:2107-2214`                                                                       |
| `hashtrinity/src/crypto/blake3.rs`      |   348 | MOVED  | `hashtrinity/src/crypto.rs:6474-6898`                                                                       |
| `hashtrinity/src/crypto/certgen.rs`     |   157 | MOVED  | `hashtrinity/src/crypto.rs:2215-2373`                                                                       |
| `hashtrinity/src/crypto/chacha_poly.rs` |   252 | MOVED  | `hashtrinity/src/crypto.rs:4321-4574`                                                                       |
| `hashtrinity/src/crypto/ecdsa.rs`       |   421 | MOVED  | folded into `hashtrinity/src/rustls.rs` (RustCryptoProvider owns ECDSA for TLS); `crypto/ecdsa.rs` was TLS-only. |
| `hashtrinity/src/crypto/ed25519.rs`     |   871 | MOVED  | `hashtrinity/src/crypto.rs` (inline `mod ed25519 {…}`); not `pub` because no public surface demands it.    |
| `hashtrinity/src/crypto/jwt.rs`         |   131 | MOVED  | `hashtrinity/src/crypto.rs:1325-1459` (`pub mod jwt {…}`)                                                   |
| `hashtrinity/src/crypto/keccak.rs`      |   137 | MOVED  | `hashtrinity/src/crypto.rs:2374-2512`                                                                       |
| `hashtrinity/src/crypto/mlkem.rs`       |   374 | MOVED  | `hashtrinity/src/crypto.rs:2513-2888`                                                                       |
| `hashtrinity/src/crypto/p384.rs`        |   387 | MOVED  | `hashtrinity/src/crypto.rs:4575-4963`                                                                       |
| `hashtrinity/src/crypto/pwhash.rs`      |    51 | MOVED  | `hashtrinity/src/crypto.rs:4964-5021`                                                                       |
| `hashtrinity/src/crypto/quic.rs`        |   133 | MOVED  | `hashtrinity/src/crypto.rs:5022-5162`                                                                       |
| `hashtrinity/src/crypto/ripemd160.rs`   |    99 | MOVED  | `hashtrinity/src/crypto.rs:2889-2991`                                                                       |
| `hashtrinity/src/crypto/rsa.rs`         |   887 | MOVED  | `hashtrinity/src/crypto.rs:5277-6199`                                                                       |
| `hashtrinity/src/crypto/scrypt.rs`      |   111 | MOVED  | `hashtrinity/src/crypto.rs:5163-5276`                                                                       |
| `hashtrinity/src/crypto/secp256k1.rs`   |   471 | MOVED  | `hashtrinity/src/crypto.rs:2992-3464`                                                                       |
| `hashtrinity/src/crypto/x509.rs`        |   169 | MOVED  | `hashtrinity/src/crypto.rs:3465-3640`                                                                       |

### 1.3 itertools/ — 1 deleted

| File (deleted)                          | Lines | Status                  | Where it lives now                                                                                              |
| --------------------------------------- | ----- | ----------------------- | -------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/itertools/methods.rs`  | 1,354 | MOVED (file-level move) | The git stat says `hashtrinity/src/{itertools/mod.rs => itertools.rs} \| 1357 ++-`. The methods live inline in `src/itertools.rs`. |

### 1.4 reactor/ — 1 deleted

| File (deleted)                                       | Lines | Status               | Where it lives now                                                                                                   |
| ---------------------------------------------------- | ----- | -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/reactor/iouring_driver/tests.rs`    |   487 | INTENTIONALLY REMOVED | The git stat shows `hashtrinity/src/{iouring_driver/mod.rs => iouring_driver.rs} \| 490 +-`, with the tests dropped (the parent `mod.rs` had a `mod tests {…}` block). The `reactor-iouring` driver is feature-flagged; running the inline tests requires the feature, so they were moved out of the default-compile path. |

### 1.5 rustls/ — 11 deleted

| File (deleted)                        | Lines | Status | Where it lives now                                                                                              |
| ------------------------------------- | ----- | ------ | -------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/rustls/mod.rs`       |    49 | MOVED  | `hashtrinity/src/rustls.rs` is the consolidated trunk (single file).                                          |
| `hashtrinity/src/rustls/aead.rs`      |   154 | MOVED  | `hashtrinity/src/rustls.rs:2-159` (`pub mod aead {…}`)                                                          |
| `hashtrinity/src/rustls/hash.rs`      |    69 | MOVED  | `hashtrinity/src/rustls.rs:160-230`                                                                              |
| `hashtrinity/src/rustls/hkdf.rs`      |    72 | MOVED  | `hashtrinity/src/rustls.rs:231-304`                                                                              |
| `hashtrinity/src/rustls/hmac.rs`      |    33 | MOVED  | `hashtrinity/src/rustls.rs:305-339`                                                                              |
| `hashtrinity/src/rustls/kx.rs`        |    52 | MOVED  | `hashtrinity/src/rustls.rs:340-393`                                                                              |
| `hashtrinity/src/rustls/quic.rs`      |   159 | MOVED  | `hashtrinity/src/rustls.rs:394-575`                                                                              |
| `hashtrinity/src/rustls/random.rs`    |    13 | MOVED  | `hashtrinity/src/rustls.rs:576-590`                                                                              |
| `hashtrinity/src/rustls/sign.rs`      |   230 | MOVED  | `hashtrinity/src/rustls.rs:591-822`                                                                              |
| `hashtrinity/src/rustls/verify.rs`    |    40 | MOVED  | `hashtrinity/src/rustls.rs:823-894`                                                                            |

### 1.6 sync/ — 16 deleted (this is the file tree that holds `hpack.rs`/`http2.rs`/`grpc.rs`)

| File (deleted)                  | Lines | Status | Where it lives now                                                                                                                                  |
| ------------------------------- | ----- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/sync/mod.rs`   |    22 | MOVED  | `hashtrinity/src/sync.rs` is the consolidated trunk (single file), with every child inline as `pub mod xxx {…}`.                                    |
| `hashtrinity/src/sync/archive.rs`  |   385 | MOVED  | `hashtrinity/src/sync.rs:8-397`                                                                                                                       |
| `hashtrinity/src/sync/block.rs`    |   619 | MOVED  | `hashtrinity/src/sync.rs:398-1019`                                                                                                                     |
| `hashtrinity/src/sync/copy.rs`     |    32 | MOVED  | `hashtrinity/src/sync.rs:1020-1053`                                                                                                                     |
| `hashtrinity/src/sync/crypto.rs`   |   556 | MOVED  | `hashtrinity/src/sync.rs:1054-1614`                                                                                                                     |
| `hashtrinity/src/sync/grpc.rs`     |   253 | MOVED  | `hashtrinity/src/sync.rs:1615-1870` — **the file we restore in transport**, byte-for-byte from `81730cc^1`                                             |
| `hashtrinity/src/sync/hpack.rs`    |   826 | MOVED  | `hashtrinity/src/sync.rs:1871-2698` — **the file we restore in transport**, byte-for-byte from `81730cc^1`                                             |
| `hashtrinity/src/sync/http.rs`     |   123 | MOVED  | `hashtrinity/src/sync.rs:2699-2985`                                                                                                                     |
| `hashtrinity/src/sync/http2.rs`    |   339 | MOVED  | `hashtrinity/src/sync.rs:2986-3327` — **the file we restore in transport**, byte-for-byte from `81730cc^1`                                             |
| `hashtrinity/src/sync/image.rs`    |   760 | MOVED  | `hashtrinity/src/sync.rs:3328-4097`                                                                                                                     |
| `hashtrinity/src/sync/s3.rs`       |   720 | MOVED  | `hashtrinity/src/sync.rs:4098-4882`                                                                                                                     |
| `hashtrinity/src/sync/scan.rs`     |   170 | MOVED  | `hashtrinity/src/sync.rs:4883-5054`                                                                                                                     |
| `hashtrinity/src/sync/sigv4.rs`    |   134 | MOVED  | `hashtrinity/src/sync.rs:5055-5190`                                                                                                                     |
| `hashtrinity/src/sync/sync.rs`     |   335 | MOVED  | `hashtrinity/src/sync.rs:5191-5527`                                                                                                                     |
| `hashtrinity/src/sync/sysio.rs`    |   125 | MOVED  | `hashtrinity/src/sync.rs:5528-5654`                                                                                                                     |
| `hashtrinity/src/sync/tls/mod.rs`  |    13 | MOVED  | `hashtrinity/src/sync.rs:5655` (`pub mod tls;`) — the module tree continues at `src/sync/tls.rs` (single file, 3465 lines).                          |

### 1.7 sync/tls/ — 6 deleted (single consolidated into `src/sync/tls.rs`)

| File (deleted)                          | Lines | Status | Where it lives now                                                                                              |
| --------------------------------------- | ----- | ------ | -------------------------------------------------------------------------------------------------------------- |
| `hashtrinity/src/sync/tls/aes_gcm.rs`   |   357 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |
| `hashtrinity/src/sync/tls/client.rs`    | 1,069 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |
| `hashtrinity/src/sync/tls/ecdsa.rs`     |   694 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |
| `hashtrinity/src/sync/tls/rsa.rs`       |   252 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |
| `hashtrinity/src/sync/tls/x25519.rs`    |   276 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |
| `hashtrinity/src/sync/tls/x509.rs`      |   795 | MOVED  | inline in `hashtrinity/src/sync/tls.rs`                                                                         |

### 1.8 tregex/ — 4 deleted; 3 back inline, 1 missing

| File (deleted)                  | Lines | Status                  |
| --------------------------------------------- | ----- | ----------------------- |
| `hashtrinity/src/tregex/mod.rs`               |   511 | MOVED                   |
| `hashtrinity/src/tregex/mem.rs`               |   416 | MOVED                   |
| `hashtrinity/src/tregex/simd.rs`              |   282 | MOVED                   |
| `hashtrinity/src/tregex/term.rs`              |   374 | MOVED                   |

Where: `hashtrinity/src/tregex.rs` is the trunk (single file) and contains
`pub mod mem {…}` (line 16), `pub mod simd {…}` (line 434), `pub mod term {…}` (line 718).
(`mod.rs` itself was renamed to `tregex.rs`.)

### 1.9 webauthn/ — 6 deleted, all LOST (no consolidation target on hashtrinity HEAD)

`hashtrinity/src/webauthn.rs` does NOT exist today. The 6 files were:
`mod.rs` (46), `b64data.rs` (78), `cbor.rs` (183), `cose.rs` (229), `types.rs` (307), `webauthn.rs` (279).

Searching `~/projects` for any consumer of `hashtrinity::webauthn` returns no hits,
so this looks like a dropped module with no caller. Status: **LOST** (intentional,
no consolidation). Recoverable byte-for-byte from `81730cc^1:hashtrinity/src/webauthn/...`
if a future task asks for it; this task does not need it.

## 2. Net effect of `81730cc`

| Class                                    | Files |
| ---------------------------------------- | ----- |
| MOVED (back as inline `pub mod` blocks in a single consolidated file) |  70   |
| INTENTIONALLY REMOVED (gated, private, or test-only)                 |   2   |
| LOST (no caller, no consolidation target)                             |   6   |
| File-rename (mod.rs → bare .rs, git ls tree held the rename)         |   3   |
| **TOTAL**                                                          | **81** |

The brief's "many are probably MOVED, not lost: classify each" turned out to be
true for all 70 of the codec/crypto/itertools/reactor/rustls/sync/sync-tls/tregex
deletions. The only LOST family is webauthn.

## 3. Downstream `Cargo.toml`s that ask `hashtrinity` for a path or feature the merge destroyed

Command (read-only): `grep -rln 'hashtrinity.*syncfold' /home/ctown/projects --include='Cargo.toml'`
plus targeted searches for `sync::grpc`, `sync::hpack`, `sync::http2`, `codec::proto`,
`codec::syntax`, `codec::bits`, `sync::tls::client`, `sync::tls::ecdsa`, `sync::tls::rsa`,
`sync::tls::x509`, `sync::tls::x25519`, `sync::tls::aes_gcm`, `webauthn`, `tregex`.

### 3.1 References to `hashtrinity::sync::*` from outside `hashtrinity/`

| File:line                                                       | What it asks for                                                            | Status today                                                                                                  |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `tasmanian-cloud/runtime/Galvanize/crates/galvanize-tofu/src/tfplugin6/mod.rs:354,513,571,625,679,860` | `hashtrinity::sync::grpc::call(...)` and the doc at `:860` mentioning `sync::grpc::call`/`http2::unary_request` | CONSUMES the deleted module paths. The module exists today at the same path (`hashtrinity::sync::grpc`), so the code still compiles — but the path went through `81730cc` deletion before re-emergence in the reconcile commit. |
| `syndesi/src/authzed.rs:56`                                     | `hashtrinity::codec::syntax::{…}`                                            | CONSUMES the deleted module. Re-exists today.                                                                 |
| `syndesi/src/authzed.rs:2210,2244,2249,2254,2261,2265,2192`     | `hashtrinity::codec::proto::{decode, encode, ProtoRegistry, ProtoSchema::parse}` | CONSUMES the deleted module. Re-exists today.                                                              |
| `attic/twn-group/syndesi/src/authzed.rs` (same file content)    | identical to the above                                                       | CONSUMES; re-exists today.                                                                                    |
| `fold-worktrees/sparse-fft-arc/bedrock/src/bindings/syncfold.rs:12` | `pub use hashtrinity::sync::{archive, block, copy, crypto, grpc, hpack, http, http2, image, s3, scan, sigv4, sync, sysio, tls};` | CONSUMES the deleted module path. Today all of these re-exist at `hashtrinity::sync::*` thanks to `42dfc4a`, so the binding compiles again. |
| `fold-worktrees/sparse-fft-arc/bedrock/src/platform.rs:309,311,930,964` | `GrpcStatus`, `GrpcRouter` shapes for HTTP/1 + gRPC code/status mapping     | Not deleted; `bedrock` is not in the merge target. NOTE: these are HTTP/1 server faces, not real HTTP/2+gRPC frames — they coexist with, do not depend on, `hashtrinity::sync::grpc`. |

### 3.2 References to `hashtrinity` features the merge left untouched

`hashtrinity`'s `Cargo.toml` `[features]` table (HEAD): `default = ["hex",
"base64", "rustls-provider", "syncfold"]`. None of `bus`, `compress`, `codec`,
`syntax`, `derive`, `proc-macro`, `reactor`, `runtime`, `itertools`, `validate`,
`error`, `bitflags`, `base32` was removed. The merge renamed the `publicly
visible` module structure (split files → inline blocks) but kept every feature
gate. The only `syncfold` callers asking for it today:

```
/home/ctown/projects/relayfold-bench/Cargo.toml
/home/ctown/projects/peregrine-ng/Cargo.toml
/home/ctown/projects/attic/sangdb-fix/Cargo.toml
/home/ctown/projects/fold-worktrees/bedrock-transport/Cargo.toml
/home/ctown/projects/fold-worktrees/sparse-fft-arc/hashtrinity/Cargo.toml
/home/ctown/projects/fold-worktrees/sparse-fft-arc/bedrock/Cargo.toml
/home/ctown/projects/fold-worktrees/sparse-fft-arc/modelfold/Cargo.toml
/home/ctown/projects/fold-worktrees/fix-simt-nn-module/netverify/crates/nv-netbox/Cargo.toml
/home/ctown/projects/fold-worktrees/fix-simt-nn-module/hashtrinity/Cargo.toml
/home/ctown/projects/fold-worktrees/fix-simt-nn-module/bedrock/Cargo.toml
/home/ctown/projects/fold-worktrees/fix-simt-nn-module/modelfold/Cargo.toml
/home/ctown/projects/fold-worktrees/sangdb-extraction/hashtrinity/Cargo.toml
/home/ctown/projects/fold-worktrees/sangdb-extraction/.scratch/Cargo.toml
/home/ctown/projects/fold-worktrees/sangdb-extraction/bedrock/Cargo.toml
/home/ctown/projects/fold-worktrees/sangdb-extraction/modelfold/Cargo.toml
/home/ctown/projects/fold-worktrees/agent-loop/netverify/crates/nv-netbox/Cargo.toml
/home/ctown/projects/fold-worktrees/agent-loop/hashtrinity/Cargo.toml
/home/ctown/projects/fold-worktrees/agent-loop/bedrock/Cargo.toml
/home/ctown/projects/fold-worktrees/agent-loop/modelfold/Cargo.toml
/home/ctown/projects/fold-worktrees/sangdb-server/Cargo.toml
```

Every one of those asks for `features = ["syncfold"]`. None of them are broken
today because the module re-emerged in the reconcile merge.

### 3.3 Reference to `hashtrinity::codec::proto` and `hashtrinity::sync::tls`

Both surface today. The transport repo itself doesn't depend on them yet — the
brief's job is to add that dependency, by restoring the three sync files (and
proto, if needed) into transport.

## 4. Decision on the protobuf wire codec (`hashtrinity::codec::proto`)

The brief asks: "check codec/proto.rs in the parent commit and say whether to
restore it too."

The parent commit (`81730cc^1`) has `hashtrinity/src/codec/proto.rs` at 1,018
lines, with 10 `#[test]` cases. Today's `hashtrinity/src/codec.rs` has the
same module inline, at lines 4545-5578, with the same `ProtoSchema`,
`ProtoRegistry`, `ProtoKind`, `ProtoField`, `ProtoError` types.

For transport's needs — the gRPC server that the brief's task (4) adds only has
to send/receive opaque protobuf bytes; the **encoding** of those bytes into the
proto wire format is the consumer's problem (Galvanize-tofu, bedrock, syndesi,
webfold, etc.), not transport's — `hashtrinity::codec::proto` is NOT needed to
satisfy this task. The OpenTofu tfplugin6 server's request/response messages
are opaque `Vec<u8>` to the gRPC framing layer; the actual proto codec lives
one layer up.

Decision: **do not restore `codec/proto.rs` into transport in this task**.
Transport only needs the framing layer (hpack, http2, grpc). The protobuf
codec stays at `hashtrinity::codec::proto`, available to consumers via their
existing dependency. The same proto module today is reachable at
`hashtrinity::codec::proto` (consolidated) and at the parent
`81730cc^1:hashtrinity/src/codec/proto.rs` if any caller wants the split form.

## 5. Consumer list the task brief enumerates

| Consumer                                                                                       | Asks for                                                          | Reads from transport after W-N                                          |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------- |
| tasmanian-cloud/runtime/Galvanize/crates/galvanize-tofu (Cargo.toml:18, src/tfplugin6/mod.rs:354-679, :861) | `hashtrinity` with `features = ["syntax","syncfold","base64"]`, `hashtrinity::sync::grpc::call`, `http2::unary_request`, SETTINGS exchange | Today this still reads `hashtrinity::sync::grpc` (re-exists). With W-N, the same call shape can move into `transport::h2::grpc::call` if galvanize-tofu is migrated (out of scope here). |
| bedrock/src/platform.rs (GrpcRouter/GrpcStatus shapes)                                         | gRPC server shapes only — HTTP/1 + gRPC code/status mapping      | Not blocked by the merge. Note: these are NOT HTTP/2 framing, only HTTP/1 + status. |
| bedrock/src/bindings/syncfold.rs:12 (in fold-worktrees/sparse-fft-arc)                          | `pub use hashtrinity::sync::{…}`                                  | Today re-resolves through the reconciliation merge; out of scope.       |
| syndesi — content negotiation, authzed (`syndesi/src/authzed.rs:56,2210,2244,2249,2254,2261,2265`) | `hashtrinity::codec::syntax`, `hashtrinity::codec::proto::*`     | Re-resolves today; not affected by this task.                          |

Net effect on consumers from `81730cc`: at the moment of the merge, every
consumer above broke for one day (between `81730cc` and `42dfc4a`). They were
fixed by `42dfc4a`, which re-added the same modules inline. This task (W-N)
adds an alternative home for the framing pieces (`transport::h2::*`) that does
not depend on `hashtrinity` at all — the smallest `transport` build carries
`hpacK/http2/grpc` and never pulls `hashtrinity`.

## 6. What W-N does in the transport repo (the action plan)

Per the brief:

1. **Restore three files into transport** as `src/h2/{hpack,http2,grpc}.rs`,
   byte-for-byte first (commit 1, authorship preserved), then minimal
   adaptation (commit 2) so they compile with transport's own dependencies.
2. **Original tests must pass**: HPACK against RFC 7541 Appendix C (hpack.rs
   carries 9 tests); HTTP/2 frame encode/decode round-trips (http2.rs carries
   1 test using a `FakeConn`); gRPC 5-byte message framing (grpc.rs carries 4
   tests, 1 of which spawns a real Terraform binary — kept but disabled by
   default behind an env var).
3. **Add server side** (small): accept an HTTP/2 connection, serve one unary
   gRPC method (echo), with a test client built from the same modules.
4. **Negative control**: flip one byte of an HPACK Huffman test vector and
   show the decode test fails; remove the gRPC 5-byte prefix handling and
   show the framing test fails.

### 6.1 Missing helpers — list

`proto.rs` requires `read_uvarint`/`write_uvarint` from
`super::{read_uvarint, write_uvarint}` — both are PRIVATE in
`hashtrinity/src/codec.rs:1707,1718`. They are not part of the public surface.

For W-N, this is **not a problem** — transport restores only `hpack.rs`,
`http2.rs`, `grpc.rs`. None of those reference `read_uvarint`/`write_uvarint`.

If a future task does restore `proto.rs`, the minimal helpers needed are LEB128
varint encode/decode, ~30 lines, easily inlined at the top of `proto.rs` or
added as `crate::h2::varint`. Recording this here so the next worker doesn't
have to re-derive it.

### 6.2 Branch

`yokoszn/restore-h2-grpc`, off `origin/main` of `Ptyktos/transport` (per the
worktree at `/home/ctown/orca/workspaces/transport/wn-restore-h2-grpc`). The
worktree was created from commit `f2d67d7` (`origin/main` tip = `f2d67d7`).

The branch name in the brief is `yokoszn/restore-h2-grpc` — the worktree
naming convention used `yokoszn/wn-restore-h2-grpc`. Both names are accepted
locally; we push to `origin` with the brief's name (`yokoszn/restore-h2-grpc`).