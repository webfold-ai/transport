//! Entrypoint — env-driven wiring for the edge load balancer.
//!
//! ## Env vars
//!
//! | Var | Default | Required? |
//! |---|---|---|
//! | `EDGE_LB_BIND` | `0.0.0.0:8080` (`127.0.0.1:8080` with hosting on) | no — the plaintext app + `/control/*` listener. With hosting on, the control surface is served **only** here, never on the public TLS front |
//! | `EDGE_LB_ROUTES` | — | no — comma-separated `host=backend` entries; backend is `http://host:port` (static) or `dialkey://<dialkey>#<service>` (plane-resolved, re-resolved every 60s). Tunnel hostnames are not listed here: they are admitted through the control API |
//! | `EDGE_LB_TLS_CERT` / `EDGE_LB_TLS_KEY` | — | no — PEM file paths; both set ⇒ the listener terminates TLS with that one pair. **Legacy**; refused when certificate hosting is on |
//! | `EDGE_LB_HOSTNAME_JOURNAL` | — | no — JSONL journal of admitted hostnames and connector bindings; replayed at boot, the edge refuses to start if it does not replay. Unset ⇒ admissions are lost on restart (warned) |
//! | `EDGE_LB_REGISTRY_SECRET` | derived from the control secret | no — keys the custom-hostname challenge tokens; must be stable across restarts |
//! | `EDGE_LB_CERT_DIR` | — | no — **enables certificate hosting** (see `hosting.rs` for the rest: `EDGE_LB_ACME_DIRECTORY`, `_ACME_ACCOUNT_KEY`, `_ACME_CONTACT`, `_DNS_BIND`, `_DNS_NS`, `_EDGE_V4/_V6`, `_CAA_ISSUERS`, `_PROOF_POLICY`, intervals) |
//! | `EDGE_LB_CA_POLICY` | — | no — path of the **CA allow-list** (JSON; see `transport::ca_policy`): every CA the edge may obtain certificates from, each with its directory, own account key, EAB, CAA domain and status (`active`/`standby`/`retiring`/`distrusted`). Replaces the single-CA `EDGE_LB_ACME_*` / `_CAA_ISSUERS` variables (setting both is refused); polled for changes. See `docs/runbooks/edge-ca-distrust.md` |
//! | `EDGE_LB_CA_STATE_DIR` / `_CA_TRUST` / `_CA_TRUST_INTERVAL_SECS` / `_CT_MONITOR` / `_CT_INTERVAL_SECS` / `_REQUIRE_SCTS` | `<cert dir>/ca-state` / `on` / `21600` / `on` / `21600` / `auto` | no — where the CA journal, ledger, account book and health live; the root-program (CCADB, Chrome Root Store) distrust watch; the Certificate Transparency monitor; whether issued certificates must carry embedded SCTs |
//! | `EDGE_LB_TLS_BIND` / `EDGE_LB_HTTP_BIND` | `0.0.0.0:443` / `0.0.0.0:80` | no — with hosting on: the SNI-routed TLS front, and the HTTP-01 + redirect listener |
//! | `EDGE_LB_TUNNEL_BIND` | — | no — the overlay tunnel listener (`overlay-agent`s dial in here; RFC 0008 §8) |
//! | `EDGE_LB_CONTROL_SECRET` | — | no — guards the `/control/*` surface (tunnel enrollment + releases); unset ⇒ the control surface is disabled |
//! | `EDGE_LB_RELEASE_JOURNAL` | — | no — path of the durable release journal (JSONL, fsynced per flip). Set ⇒ promotes/rollbacks survive a restart; the edge **refuses to start** if the journal does not replay. Unset ⇒ flips are in-memory only (warned at boot) |
//! | `EDGE_LB_ADMISSION_FILE` | — | no — JSON `admission::AdmissionOverlay` applied at boot and rewritten when `PUT /control/admission` tightens the rules; the edge refuses to start if it does not parse. The baseline admission rules (CGI argument injection, traversal, the `PHP2Shell` upload-progress field, ...) are always on and cannot be disabled by this file |
//!
//! Example routes for the notification surface (RFC 0009 §11):
//!
//! ```text
//! EDGE_LB_ROUTES="ntfy.tas.cloud=http://127.0.0.1:8094,ntfy.customer.example=dialkey://<notify-plane-dialkey>#_notify._tcp"
//! ```
//!
//! Startup logs the bind addr and each registered route — never the
//! dialkeys (a dialkey IS the capability).

use std::sync::Arc;

use anyhow::Context as _;
use edge_lb::edge_state::{EdgeState, Journal};
use edge_lb::hosting::{self, HostingConfig};
use edge_lb::{router, BackendSpec, EdgeLb};
use tracing::{info, warn};

const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// With certificate hosting on, the plaintext listener carries `/control/*`; it defaults to loopback.
const DEFAULT_HOSTED_BIND: &str = "127.0.0.1:8080";
const DEFAULT_TLS_BIND: &str = "0.0.0.0:443";
const DEFAULT_HTTP_BIND: &str = "0.0.0.0:80";

/// How often the off-path TLS reload re-reads the PEM paths.
const CERT_RELOAD: std::time::Duration = std::time::Duration::from_secs(3600);

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "linear env-driven wiring; splitting it would only scatter the boot order"
)]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let hosting_cfg =
        HostingConfig::from_lookup(env).map_err(|e| anyhow::anyhow!("certificate hosting: {e}"))?;
    let hosted = hosting_cfg.is_some();
    let bind = env("EDGE_LB_BIND").unwrap_or_else(|| {
        if hosted {
            DEFAULT_HOSTED_BIND
        } else {
            DEFAULT_BIND
        }
        .to_string()
    });

    let mut routes = Vec::new();
    for entry in env("EDGE_LB_ROUTES").unwrap_or_default().split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (host, spec) =
            BackendSpec::parse(entry).map_err(|e| anyhow::anyhow!("route entry '{entry}': {e}"))?;
        info!(%host, "route registered");
        routes.push((host, spec));
    }

    let control_secret = env("EDGE_LB_CONTROL_SECRET");
    if routes.is_empty() && control_secret.is_none() {
        anyhow::bail!("nothing to serve: set EDGE_LB_ROUTES and/or EDGE_LB_CONTROL_SECRET (hostnames are admitted through the control API)");
    }

    // ── hostname registry: admissions and connector bindings survive a restart ────────────
    let registry_secret = env("EDGE_LB_REGISTRY_SECRET")
        .or_else(|| {
            control_secret
                .as_ref()
                .map(|s| format!("tas-edge-registry:{s}"))
        })
        .unwrap_or_else(|| "tas-edge-registry:unset".to_string());
    if hosted {
        // The tokens that prove a customer controls a name are keyed by this secret: a placeholder
        // (or the built-in default above) would make them guessable.
        match env("EDGE_LB_REGISTRY_SECRET").or_else(|| control_secret.clone()) {
            Some(s) => transport::entropy::check_secret_strength(
                "EDGE_LB_REGISTRY_SECRET (or EDGE_LB_CONTROL_SECRET, which it is derived from)",
                s.as_bytes(),
                32,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?,
            None => anyhow::bail!("certificate hosting needs EDGE_LB_REGISTRY_SECRET or EDGE_LB_CONTROL_SECRET: the built-in default would make every proof-of-control token guessable"),
        }
    }
    let proof = hosting_cfg
        .as_ref()
        .map_or_else(Default::default, |c| c.proof);
    let (journal, replay) = if let Some(path) = env("EDGE_LB_HOSTNAME_JOURNAL") {
        let (j, ops) =
            Journal::open(&path).map_err(|e| anyhow::anyhow!("hostname journal: {e}"))?;
        (Some(j), ops)
    } else {
        warn!("EDGE_LB_HOSTNAME_JOURNAL unset — admitted hostnames and connector bindings are lost on restart");
        (None, Vec::new())
    };
    let state = EdgeState::new(registry_secret.as_bytes(), proof, journal);
    state.replay(replay).await;

    let edge = EdgeLb::build_with_state(routes, state.clone()).await;

    // ── request admission: the baseline is always on; the file can only tighten it ─────────
    if let Some(path) = env("EDGE_LB_ADMISSION_FILE") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            let meta = std::fs::metadata(&path)
                .map_err(|e| anyhow::anyhow!("admission file {}: {e}", path.display()))?;
            if meta.len() > 256 * 1024 {
                anyhow::bail!("admission file {} is over 256 KiB", path.display());
            }
            let raw = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("admission file {}: {e}", path.display()))?;
            let overlay: edge_lb::admission::AdmissionOverlay = serde_json::from_slice(&raw)
                .map_err(|e| anyhow::anyhow!("admission file {}: {e}", path.display()))?;
            edge.tighten_admission(&overlay)
                .map_err(|e| anyhow::anyhow!("admission file {}: {e}", path.display()))?;
            info!(path = %path.display(), "admission overlay applied");
        }
        let _ = edge.admission_file.set(path);
    }

    // ── release journal: promote/rollback state survives a restart ────────
    if let Some(path) = env("EDGE_LB_RELEASE_JOURNAL") {
        let controller = edge_lb::rollout::RolloutController::with_journal(Box::new(
            edge_lb::rollout::FileJournal::new(&path),
        ))
        .map_err(|e| anyhow::anyhow!("release journal {path}: {e}"))?;
        info!(%path, releases = controller.snapshot().len(), "release journal replayed");
        *edge
            .rollout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = controller;
    } else {
        warn!("EDGE_LB_RELEASE_JOURNAL unset — promotes and rollbacks are in-memory and are lost on restart");
    }

    // ── overlay tunnels (RFC 0008 §8): tenant agents dial in here ─────────
    if let Some(tunnel_bind) = env("EDGE_LB_TUNNEL_BIND") {
        let registry = edge.tunnels.clone();
        let listener_secret = control_secret.clone().unwrap_or_default();
        let bind_for_task = tunnel_bind.clone();
        tokio::spawn(async move {
            edge_lb::tunnel::run_tunnel_listener(&bind_for_task, registry, &listener_secret).await
        });
        info!("tunnel listener on {tunnel_bind}");
    }

    // ── certificate hosting (ACME + authoritative DNS + SNI front) ─────────
    let hosting = if let Some(cfg) = hosting_cfg {
        if env("EDGE_LB_TLS_CERT").is_some() || env("EDGE_LB_TLS_KEY").is_some() {
            anyhow::bail!("EDGE_LB_TLS_CERT/KEY (one static pair) cannot be combined with certificate hosting (EDGE_LB_CERT_DIR)");
        }
        Some(
            hosting::start(cfg, state.clone())
                .await
                .map_err(|e| anyhow::anyhow!("certificate hosting: {e}"))?,
        )
    } else {
        None
    };

    // ── the apps: public (data plane) and private (data plane + control) ───
    let public_app = router(edge.clone());
    let private_app = if let Some(secret) = &control_secret {
        let secret = Arc::new(secret.clone());
        let app = edge_lb::control::mount(public_app.clone(), &edge, &secret);
        edge_lb::release_api::mount(app, &edge, &secret)
    } else {
        warn!("EDGE_LB_CONTROL_SECRET unset — hostname admission, tunnel enrollment and releases are DISABLED");
        public_app.clone()
    };

    let mut servers: tokio::task::JoinSet<anyhow::Result<()>> = tokio::task::JoinSet::new();

    if let Some(hosting) = hosting {
        let tls_bind = env("EDGE_LB_TLS_BIND").unwrap_or_else(|| DEFAULT_TLS_BIND.to_string());
        let http_bind = env("EDGE_LB_HTTP_BIND").unwrap_or_else(|| DEFAULT_HTTP_BIND.to_string());
        let tls_listener = tokio::net::TcpListener::bind(&tls_bind)
            .await
            .with_context(|| format!("binding {tls_bind}"))?;
        let (e, app, cfg) = (edge.clone(), public_app, hosting.server_config.clone());
        servers.spawn(async move {
            edge_lb::front::serve(tls_listener, e, app, cfg)
                .await
                .context("tls front")
        });
        let http_app = edge_lb::http01::router(state.clone());
        servers.spawn(async move {
            servelet_h1::serve(&http_bind, http_app)
                .await
                .context("http-01 listener")
        });
        info!("certificate hosting on: tls front {tls_bind}, plaintext control/app {bind}");
        let b = bind.clone();
        servers.spawn(async move { servelet_h1::serve(&b, private_app).await.context("serve") });
    } else {
        // ── legacy: one listener, optionally one static TLS pair ───────────
        match (env("EDGE_LB_TLS_CERT"), env("EDGE_LB_TLS_KEY")) {
            (Some(cert), Some(key)) => {
                let mut cert_manager = edge_lb::acme::CertManager::new();
                let config = cert_manager
                    .load(
                        "default",
                        std::path::PathBuf::from(&cert),
                        std::path::PathBuf::from(&key),
                    )
                    .map_err(|e| anyhow::anyhow!("tls config: {e}"))?;
                // Rotation runs off-path: re-read the PEM paths, swap only when the new pair builds
                // — a bad rotation keeps the last-known-good (INV-06).
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(CERT_RELOAD).await;
                        match cert_manager.reload_if_changed() {
                            Ok(swapped) if swapped > 0 => {
                                info!("TLS certs reloaded ({swapped} changed)")
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("TLS cert reload failed — keeping last-known-good: {e}")
                            }
                        }
                    }
                });
                info!("edge terminating TLS (single static pair; legacy)");
                let b = bind.clone();
                servers.spawn(async move {
                    servelet_tls::serve_tls(&b, private_app, config)
                        .await
                        .context("serve_tls")
                });
            }
            (None, None) => {
                warn!("EDGE_LB_TLS_CERT/KEY unset and certificate hosting off — edge is PLAINTEXT (overlay-only deployments only)");
                let b = bind.clone();
                servers.spawn(
                    async move { servelet_h1::serve(&b, private_app).await.context("serve") },
                );
            }
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!("EDGE_LB_TLS_CERT and EDGE_LB_TLS_KEY must be set together")
            }
        }
    }

    info!("edge-lb listening on {bind}");
    match servers.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(join)) => Err(anyhow::anyhow!("listener task failed: {join}")),
        None => Ok(()),
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,edge_lb=debug"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
