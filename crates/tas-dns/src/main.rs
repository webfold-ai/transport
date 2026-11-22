//! `tas-dns`: the managed authoritative DNS daemon. Configuration is environment variables
//! (see `docs/tas-dns.md`); secrets are file paths. `tas-dns init-master <path>` creates the
//! DNSSEC master; `tas-dns node-id <dialkey-file>` prints the mesh identity to pin elsewhere.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tas_dns::build::ServerIdentity;
use tas_dns::config::Config;
use tas_dns::db::{DbConfig, ZoneDb};
use tas_dns::keys::{DerivedKeyProvider, KeyProvider};
use tas_dns::mesh::{self, MeshConfig};
use tas_dns::metrics::{serve_metrics, Metrics};
use tas_dns::node::Node;
use tas_dns::server::{serve_tcp, serve_udp, ServerCtx};
use tas_dns::store::FileObjectStore;
use tokio::net::{TcpListener, UdpSocket};
use transport::zone_sync::SessionLimits;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Read a secret file that must be a regular, private (0600) file.
fn read_private(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let meta =
        std::fs::symlink_metadata(path).map_err(|_| "cannot stat the secret file".to_string())?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err("the secret file must be a regular file with mode 0600".into());
    }
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|_| "cannot read the secret file".to_string())
}

fn say(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init-master") => {
            let Some(path) = args.get(1) else {
                say("usage: tas-dns init-master <path>");
                return ExitCode::from(2);
            };
            return match DerivedKeyProvider::create(Path::new(path)) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    say(&format!("init-master failed: {e}"));
                    ExitCode::FAILURE
                }
            };
        }
        Some("node-id") => {
            let Some(path) = args.get(1) else {
                say("usage: tas-dns node-id <dialkey-file>");
                return ExitCode::from(2);
            };
            return match read_private(Path::new(path)) {
                Ok(dk) => {
                    say(&mesh::peer_id_hex(&transport::dialkey::peer_id(&dk)));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    say(&e);
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }

    let vars: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("TAS_DNS_"))
        .collect();
    let cfg = match Config::from_map(&vars) {
        Ok(c) => c,
        Err(e) => {
            say(&format!("configuration error: {e}"));
            return ExitCode::from(2);
        }
    };
    init_logging(&cfg);
    match run(cfg).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(target: "tas_dns", error = %tas_dns::escape::esc(&e), "fatal");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_new(&cfg.log_filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if cfg.log_json {
        b.json().init();
    } else {
        b.init();
    }
}

async fn run(cfg: Config) -> Result<(), String> {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix_now);
    let metrics = Arc::new(Metrics::default());

    let mut dbc = DbConfig::new(cfg.registrar);
    dbc.challenge_zone = cfg.challenge_zone.clone();
    dbc.challenge_authority = cfg.challenge_authority;
    dbc.reserved = cfg.reserved.clone();
    dbc.max_zones_per_tenant = cfg.max_zones_per_tenant;
    let store = Arc::new(
        FileObjectStore::open(&cfg.data_dir.join("objects"))
            .map_err(|e| format!("data dir: {e}"))?,
    );
    let (db, refused) = ZoneDb::open(dbc, store, metrics.clone(), clock.clone())
        .map_err(|e| format!("loading the zone store: {e}"))?;
    if refused > 0 {
        tracing::warn!(target: "tas_dns::store", refused, "stored objects were refused at startup");
    }
    let db = Arc::new(db);

    let keys: Option<Arc<dyn KeyProvider>> = if let Some(p) = &cfg.key_master_file {
        Some(Arc::new(
            DerivedKeyProvider::load(p).map_err(|e| e.to_string())?,
        ))
    } else {
        tracing::warn!(target: "tas_dns", "no DNSSEC master configured: zones with a DNSSEC policy will answer SERVFAIL");
        None
    };
    let identity = ServerIdentity {
        nameservers: cfg.nameservers.clone(),
        hostmaster: cfg.hostmaster.clone(),
        soa_minimum: 300,
        ns_ttl: 3600,
    };
    let node = Node::new(
        db.clone(),
        metrics.clone(),
        identity,
        cfg.timings,
        keys,
        clock.clone(),
    );
    node.rebuild_all();
    tracing::info!(target: "tas_dns", zones = node.serving.len(), "zones loaded");

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();

    let ctx = ServerCtx::new(node.serving.clone(), metrics.clone(), cfg.limits.clone());
    let udp = UdpSocket::bind(cfg.udp_bind)
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    let tcp = TcpListener::bind(cfg.tcp_bind)
        .await
        .map_err(|e| format!("tcp bind: {e}"))?;
    let mlisten = TcpListener::bind(cfg.metrics_bind)
        .await
        .map_err(|e| format!("metrics bind: {e}"))?;
    tasks.spawn(serve_udp(Arc::new(udp), ctx.clone(), stop_rx.clone()));
    tasks.spawn(serve_tcp(tcp, ctx, stop_rx.clone()));
    tasks.spawn(serve_metrics(
        mlisten,
        metrics.clone(),
        node.serving.clone(),
        unix_now,
        stop_rx.clone(),
    ));
    tasks.spawn(node.clone().run(db.subscribe(), stop_rx.clone()));

    if let Some(ms) = &cfg.mesh {
        let dialkey = read_private(&ms.dialkey_file)?;
        let m = mesh::start(
            db.clone(),
            metrics.clone(),
            MeshConfig {
                bind: ms.bind.clone(),
                dialkey,
                peers: ms.peers.clone(),
                publishers: ms.publishers.clone(),
                pull_interval: Duration::from_secs(ms.pull_secs.max(1)),
                io_timeout: Duration::from_secs(5),
                limits: SessionLimits::default(),
            },
            stop_rx.clone(),
        )
        .await
        .map_err(|e| format!("mesh bind: {e}"))?;
        tracing::info!(target: "tas_dns::mesh", id = %mesh::peer_id_hex(&m.id), addr = %tas_dns::escape::esc(&m.addr), peers = ms.peers.len(), "mesh up");
    }

    tracing::info!(target: "tas_dns", udp = %cfg.udp_bind, tcp = %cfg.tcp_bind, metrics = %cfg.metrics_bind, "serving");
    wait_for_signal().await;
    tracing::info!(target: "tas_dns", "shutting down");
    let _ = stop_tx.send(true);
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        tracing::warn!(target: "tas_dns", "tasks did not finish in 5 s; exiting");
    }
    Ok(())
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
