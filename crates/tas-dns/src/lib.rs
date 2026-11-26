#![forbid(unsafe_code)]
//! tas-dns: managed authoritative DNS for customer zones and the ACME challenge zone.

pub mod authority;
pub mod build;
pub mod challenge;
pub mod challenge_auth;
pub mod challenge_zone;
pub mod config;
pub mod db;
pub mod delegation;
pub mod error;
pub mod escape;
pub mod keys;
pub mod mesh;
pub mod metrics;
pub mod names;
pub mod node;
pub mod objects;
pub mod records;
pub mod rrl;
pub mod server;
pub mod store;
pub mod zone;
