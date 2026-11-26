//! `tas-lb` entrypoint: `tas-lb <static-config.json>` (or `TAS_LB_CONFIG`).
//!
//! Logs are structured JSON on stderr (`RUST_LOG` filters). SIGINT/SIGTERM trigger a graceful
//! shutdown. A config that does not validate, or a socket that cannot be bound, is a failed start.

use tas_lb::config::StaticConfig;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("TAS_LB_CONFIG").ok());
    let Some(path) = path else {
        tracing::error!("usage: tas-lb <static-config.json> (or set TAS_LB_CONFIG)");
        return std::process::ExitCode::from(2);
    };
    let cfg = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|t| StaticConfig::from_json(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "static configuration refused");
            return std::process::ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "could not start the runtime");
            return std::process::ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        let lb = match tas_lb::lb::start(cfg).await {
            Ok(lb) => lb,
            Err(e) => {
                tracing::error!(error = %e, "start failed");
                return std::process::ExitCode::from(1);
            }
        };
        wait_for_signal().await;
        tracing::info!("shutting down");
        lb.shutdown().await;
        std::process::ExitCode::SUCCESS
    })
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        // Without signal handlers, run until killed.
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
