# Hosting edge services: canonical source and verification

Operately: `lift-hosting-runtime-edge-BNoBncQ7r82CFL0wVLiIBn`.

## One home, not five wrappers

| Capability | Canonical implementation | Boundary |
|---|---|---|
| TCP/UDP front load balancer | `crates/tas-lb` | Userspace forwarding, connection tracking/pinning, drain, PROXY v2, signed backend generations; XDP is a trait seam, not an implemented data plane. |
| Authoritative DNS | `crates/tas-dns` | Hickory server, DNSSEC, signed replicated zones, delegation and bound ACME challenge zone. Not a replacement for the kernel's signed-record codec. |
| HTTP/SNI/tunnel edge | `crates/edge-lb` | Owns HTTP forwarding and deployment policy; delegates tunnel admission/connector selection to `transport::edge_proxy`. |
| Desired/actual mesh ACL reconciliation | `crates/mesh-acl-reconciler` | Membership diff and provider adapters. Incomplete provider operations still return explicit errors; no claim that the native transport now replaces all provider control planes. |
| Console WebSocket forwarding | `crates/console-ws-proxy` | Origin/session/tenant/expiry/signature checks and single-use tickets; existing cache/credential substrate, not another store. |

Weighted Maglev moved OUT of tas-lb into
`transport::load_balance::maglev`. The old tas-lb module is only a public
re-export for source compatibility: there is no implementation copy. Relayfold
already re-exports selection from this same kernel. Its consistent-ring policy
and Maglev have different contracts (request selection vs stable new-flow
selection plus connection pinning); they remain named policies in **one home**,
not interchangeable algorithms or two LB engines. No relayfold source change is
needed for this relocation.

The duplicate Host-port parser was deleted from edge-lb; both service routing
and kernel admission use `transport::edge_proxy::strip_host_port`. The kernel's
`ConnectorPool`, admission decisions and SNI certificate resolver were already
consumed by the service and were not copied or replaced. The service's HTTP
request/response lifecycle is not a second copy of that transport policy.

All lifted direct legacy hashtrinity dependencies were removed. Table/crypto
users now name the kernel's exact apeiron revision
`85b404b8dc89903c5c588a2cd1d10bfa5b9e64bc`; the error derive uses thiserror.
No hashtrinity source was edited. Existing hosting cache/support dependencies
remain pinned in their original repository; their transitive legacy substrate
pins are not falsely described as removed from the entire graph.

## Baseline and evidence

Source inputs:

- hosting-runtime main `60d0d9fee8d6c48f64540164401ba9ef2581084f`;
  the prerequisite standalone-dependency PR #83 at
  `04201bb1b072d156edca3289997ad3ba46288224`.
- Before-lift support repair `212736bdbe70e5aeffe8118a9c23c42e3ef1bbfa`:
  only the root kleis dependency changed from the non-compiling biota copy to
  iotaDB `208e6e94a2ad00c226c2030776045f8d465cdb93`. All five crate source
  bodies remained unchanged. The unmodified five-package build failed in
  biota-kleis; that is recorded, not counted as executed tests.
- Baseline transport pin `74e3ce1beb2988cb4ddf20c20a501e73e83bd9e4`;
  target kernel base `52d413a66305ca17d81061c67e8acb85e87df059`.
  The before/after kernels are explicitly different revisions. These are
  correctness regression receipts on the same SYNTHETIC test cases, **not a
  controlled transport performance comparison**.

Build box: Linux x86_64, rustc `1.99.0 (b940084d7 2026-09-28)`.
Cargo commands run only through box-run, serially, with incremental/debug-info
disabled to bound disposable target size. No local Rust build, production
service, public DNS/firewall change or mesh enrollment was performed.

| Crate | Before: unit cases passed / harness seconds | After: unit cases passed / harness seconds | Planted control |
|---|---|---|---|
| console-ws-proxy | 38 / 0.05 | 38 / 0.05 | inverted ticket signature check fails tamper regression |
| edge-lb | 115 / 3.03 | 115 / 3.01 | inverted control-secret check fails authorization regression |
| mesh-acl-reconciler | 7 / 0.00 | 8 / 0.00 | inverted revocation membership fails new exact-pair diff regression |
| tas-dns | 36 / 0.09 | 36 / 0.07 | bypassing apex containment fails owner-scope regression |
| tas-lb | 105 / 0.07 | 97 / 0.06 | inverted backend signature check fails altered-byte regression |

Eight Maglev cases moved with their implementation into the kernel; they were
not dropped. The default-feature kernel gate passes 487 cases, including those
eight. The one new ACL-diff case explains the net increase in service+Maglev
coverage. Harness seconds are incidental suite execution times, **not service
latency or throughput**. No winner, production load, QUIC/VPN or saturation claim
is made from them.

All five default-feature packages build, including every shipped binary. Five
negative controls compile and fail their intended test, not merely the build.
The runner restores each source byte-for-byte and records both hashes:
`verification/edge-lift-negative-controls.py` (box-run mirror only).

Integration suites report 106 cases passing after provisioning the REAL
notification-service binary as a loopback fixture and correcting the process-local
file descriptor limit for the concurrent-flow case. Two Pebble tests return early
when their opt-in fixtures are absent: **104 integration cases exercised; two
Pebble scenarios NOT exercised**. The initial smoke failure was a missing sibling
binary; the initial concurrency failure was `EMFILE`, not hidden by skipping a
case or loosening an assertion. A child-only `ulimit -n 8192` runs that exact
concurrency case successfully; no host-wide limit changed.

The kernel all-features run passes 668 runtime cases with three ignored, before
hitting a pre-existing invalid federation doctest. That example now type-checks
as a non-running network example and adds an executable offline builder example;
the focused doctest gate passes all three. Unchanged runtime cases were not
rerun to manufacture a second result. FIPS build prerequisites came from locked
Nix Go; no host installation was made. Lock resolution also updates prettyplease
to 0.3.0 so bindgen's Syn 3 types match its formatter; forcing Syn 2 is invalid
because current async-trait requires Syn 3.

Nix inputs match every git source/revision in Cargo.lock, including distinct
existing support-substrate revisions. The edge binary derivation evaluates on
the box. Full Nix derivations/OCI images, non-Linux targets, and live DNSSEC/ACME
Pebble/FIPS deployment certification are **not claimed tested**.

## Reproduce

On an admitted build-box mirror (not the workstation):

```sh
export PATH=$HOME/.cargo/bin:$PATH
export RUSTC_WRAPPER= CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
ulimit -n 8192
cargo build --locked -p tas-lb -p tas-dns -p edge-lb -p mesh-acl-reconciler -p console-ws-proxy
cargo test --locked -p tas-lb -p tas-dns -p edge-lb -p mesh-acl-reconciler -p console-ws-proxy --lib
cargo test --locked -p transport --lib
# Integration needs notification-service in the same target/debug directory or PATH:
cargo test --locked -p tas-lb -p tas-dns -p edge-lb --test '*'
python3 verification/edge-lift-negative-controls.py
sh verification/all-features-on-box.sh
cargo fmt --all -- --check
```

Only ordinary authenticated dependency fetches are used. Builder read access to
the pinned platform repositories is necessary; this is not a promise of anonymous
builds of every service in the public workspace. Plain Cargo selects the kernel;
the service packages are explicit, while Nix workspace checks cover them together.

## Design basis / replacement inventory

The reviewed design source is Tasmanian-Cloud/tasmanian-cloud revision
`6e0fa4c9fc084a9ed1a75d83b5f9ea6313efaafd`, specifically RFC 0003 (trust boundary),
0027 (scoped external-compute federation), 0030 (substrate/autoscaling boundary),
ZTNA architecture and NetBird FMEA. Private operational documents are referenced,
not republished into this public repository.

The retained invariants are private management, explicit tenant/identity grants,
scoped outbound federation with no broad network routes, verification rather than
peer self-report, bounded/revocable credentials and an independent recovery path.
The NetBird inventory still includes control/discovery availability, DNS, NAT/relay
reachability, identity refresh, ACL drift, stale-peer removal and setup-key rotation.
A crate relocation does **not** demonstrate those operational replacement drills.
NetBird remains transitional until those paths are exercised. `cdn.webfold.ai`
remains the intended customer-CNAME connectivity anchor, not an endpoint deployed
by this patch. In particular QUIC connection state, complete NAT/VPN forwarding,
and authenticated reads on the pkarr relay remain explicitly missing.
