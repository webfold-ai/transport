//! End-to-end tests: real sockets on loopback, a real `tas-lb`, real backends.
#![expect(clippy::unwrap_used, reason = "test code: assertions on fixtures")]

mod common;
mod config_push;
mod limits;
mod pinning;
mod proxy;
mod transfer;
