//! HTTP/2 + HPACK + gRPC framing, lifted byte-for-byte from
//! `hashtrinity/src/sync/{hpack,http2,grpc}.rs` at commit `81730cc^1`
//! (= `7ea2006b0431effb776d4029b3b40e4d63130285`, Clay Townsend, 2026-08-11),
//! then minimally adapted (imports only) for transport's module paths.
//!
//! Lives behind the `h2` Cargo feature so a consumer that doesn't need gRPC
//! (and doesn't want the `~1,400` lines and the doctests on them) can skip it
//! with `--no-default-features --features h2` or just `--no-default-features`.
//! The transport README still calls this crate the protocol kernel; HTTP/2 +
//! HPACK + gRPC framing is part of that kernel but is gated because (a) every
//! dependency it brings lives behind the flag, and (b) the `#[ignore]`d live
//! integration test against a real OpenTofu provider binary is a substantial
//! runtime artefact the kernel itself does not need.
//!
//! Authorship of each submodule: Clay Townsend <clay@twn.systems> (the
//! original author of the parent `hashtrinity/src/sync/{hpack,http2,grpc}.rs`
//! in the deletion branch). Adaptation commit by the W-N worker for transport.

pub mod hpack;
pub mod http2;
pub mod grpc;