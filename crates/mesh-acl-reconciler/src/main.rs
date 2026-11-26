//! Entry point — wires the adapter registry, opens the DB pool, runs the loop.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mesh_acl_reconciler::{adapter::AdapterRegistry, adapter::StubAdapter, Reconciler};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("MESH_ACL_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;

    let mut adapters = AdapterRegistry::new();
    // Real adapters land in their own crates and register here. Until then,
    // the reconciler runs against the stub — the diff is computed but
    // pushes log + skip.
    adapters.register("tas-cloud-managed-netbird", Arc::new(StubAdapter));
    adapters.register("customer-netbird", Arc::new(StubAdapter));
    adapters.register("customer-tailscale", Arc::new(StubAdapter));
    adapters.register("wireguard-direct", Arc::new(StubAdapter));
    adapters.register("warpgate-gateway", Arc::new(StubAdapter));

    let interval_secs: u64 = std::env::var("RECONCILE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_600);

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = cancel_tx.send(true);
    });

    Reconciler::new(pool, adapters, Duration::from_secs(interval_secs))
        .run(cancel_rx)
        .await?;

    Ok(())
}
