//! # tas-lb — the front L4 load balancer (RFC 0031)
//!
//! See `docs/tas-lb.md` for the design, the decisions and their alternatives. In one paragraph:
//! customer TCP/UDP arrives on the VIP, is forwarded to a set of `edge-lb` backends, and
//! **established flows are pinned** by a connection-tracking table while Maglev hashing chooses
//! only for *new* flows. Removed or unhealthy backends are drained, not cut. PROXY protocol v2 is
//! sent to backends (and accepted only from configured trusted senders). The backend set is a
//! document signed by the control plane, with sequence numbers and rollback refusal; a bad
//! document is refused and the last good one keeps serving. The userspace data plane sits behind
//! the [`director::Forwarder`] trait so an XDP plane can replace it.

#![forbid(unsafe_code)]

pub mod admin;
pub mod backend;
pub mod cidr;
pub mod config;
pub mod control;
pub mod director;
pub mod flows;
pub mod health;
pub mod identity;
pub mod lb;
pub mod loglimit;
// Source-compatible export of the one implementation in the transport kernel.
pub use transport::load_balance::maglev;
pub mod metrics;
pub mod probe;
pub mod proxy_protocol;
pub mod ratelimit;
pub mod signed_config;
pub mod tcp;
pub mod udp;
pub mod userspace;
