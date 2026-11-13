//! `meshd` — the internal service-discovery node: a pkarr relay and an authoritative DNS zone.
//!
//! Services publish their endpoints under a dialkey (`transport::dialkey::publish`) to this
//! relay; anything on the network resolves them either through the relay (`dialkey::resolve`) or
//! as ordinary DNS under the internal zone:
//!
//! ```text
//! _billing._tcp.<key>.mesh.internal.  SRV  0 0 8080 <key>.mesh.internal.
//! ```
//!
//! Configuration is environment variables (a container's native form); every one has a default.
//!
//! | Variable | Default | |
//! |---|---|---|
//! | `MESHD_HTTP_BIND` | `0.0.0.0:6881` | the relay (`PUT`/`GET /<key>`, `GET /health`) |
//! | `MESHD_DNS_BIND` | `0.0.0.0:5353` | UDP and TCP DNS; `off` serves the relay only |
//! | `MESHD_ZONE` | `mesh.internal` | the zone this node is authoritative for |
//! | `MESHD_NS`, `MESHD_HOSTMASTER` | `ns.<zone>`, `hostmaster.<zone>` | the zone's SOA and NS |
//! | `MESHD_DATA_DIR` | `/var/lib/meshd` | records persist here; `memory` keeps none |
//! | `MESHD_MAX_KEYS` | `100000` | most distinct keys held |
//! | `MESHD_MAX_AGE_SECS` | unset | stop serving a record this long after it was last written; unset keeps records until replaced |
//! | `MESHD_ALLOW_KEYS_FILE` | unset | one z-base-32 key per line (`#` comments); when set, only these keys may publish |
//!
//! `meshd --healthcheck` asks a running instance on this host for `/health` and exits 0 or 1,
//! so a container needs no curl.
//!
//! Put it on a private interface. Reads are open by design (the records are public), and
//! `RelayClient` cannot send credentials, so who may publish is decided by the allowlist and by
//! where the port is reachable.

use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use transport::edge_dns::{serve_tcp_with, serve_udp_with, DnsHandler};
use transport::mesh_dns::MeshZone;
use transport::pkarr_relay::{serve, unix_now, Limits, RelayStore};
use transport::signed_dns::PublicKey;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match env(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("{name}={v:?} is not valid")),
    }
}

fn allow_list(path: &str) -> Result<HashSet<[u8; 32]>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("MESHD_ALLOW_KEYS_FILE {path}: {e}"))?;
    let mut keys = HashSet::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let key = PublicKey::from_z32(line)
            .map_err(|_| format!("{path}:{}: {line:?} is not a z-base-32 public key", i + 1))?;
        keys.insert(*key.as_bytes());
    }
    Ok(keys)
}

/// `GET /health` against this host's own relay.
async fn healthcheck() -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bind = env("MESHD_HTTP_BIND").unwrap_or_else(|| "0.0.0.0:6881".into());
    // Probe the address meshd really listens on; only a wildcard bind is probed on loopback.
    let target = match bind.parse::<std::net::SocketAddr>() {
        Ok(mut a) => {
            if a.ip().is_unspecified() {
                a.set_ip(if a.is_ipv4() {
                    std::net::Ipv4Addr::LOCALHOST.into()
                } else {
                    std::net::Ipv6Addr::LOCALHOST.into()
                });
            }
            a.to_string()
        }
        Err(_) => format!("127.0.0.1:{}", bind.rsplit(':').next().unwrap_or("6881")),
    };
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(target).await.ok()?;
        s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.ok()?;
        Some(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"))
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        return if healthcheck().await {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("meshd: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let http_bind = env("MESHD_HTTP_BIND").unwrap_or_else(|| "0.0.0.0:6881".into());
    let dns_bind = env("MESHD_DNS_BIND").unwrap_or_else(|| "0.0.0.0:5353".into());
    let zone = env("MESHD_ZONE").unwrap_or_else(|| "mesh.internal".into());
    let ns = env("MESHD_NS").unwrap_or_else(|| format!("ns.{zone}"));
    let hostmaster = env("MESHD_HOSTMASTER").unwrap_or_else(|| format!("hostmaster.{zone}"));
    let data_dir = env("MESHD_DATA_DIR").unwrap_or_else(|| "/var/lib/meshd".into());

    let limits = Limits {
        max_keys: env_parse("MESHD_MAX_KEYS", 100_000usize)?,
        max_age: env("MESHD_MAX_AGE_SECS")
            .map(|v| {
                v.trim()
                    .parse::<u64>()
                    .map(Duration::from_secs)
                    .map_err(|_| format!("MESHD_MAX_AGE_SECS={v:?} is not valid"))
            })
            .transpose()?,
        allow: env("MESHD_ALLOW_KEYS_FILE")
            .map(|p| allow_list(&p))
            .transpose()?,
    };
    let closed = limits.allow.as_ref().map(HashSet::len);

    let store = if data_dir == "memory" {
        eprintln!("meshd: records are kept in memory only; they are lost on restart");
        Arc::new(RelayStore::in_memory(limits))
    } else {
        let (store, report) = RelayStore::open(&data_dir, limits)
            .map_err(|e| format!("MESHD_DATA_DIR {data_dir}: {e}"))?;
        eprintln!(
            "meshd: loaded {} records from {data_dir} ({} files skipped)",
            report.loaded, report.skipped
        );
        Arc::new(store)
    };
    match closed {
        Some(n) => eprintln!("meshd: publishing is restricted to {n} allowed keys"),
        None => eprintln!("meshd: any key may publish; keep this port on a private network"),
    }

    let listener = tokio::net::TcpListener::bind(&http_bind)
        .await
        .map_err(|e| format!("MESHD_HTTP_BIND {http_bind}: {e}"))?;
    eprintln!("meshd: relay listening on {http_bind}");

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn({
        let store = Arc::clone(&store);
        async move {
            serve(listener, store)
                .await
                .map_err(|e| format!("relay: {e}"))
        }
    });
    if dns_bind != "off" {
        let handler: Arc<dyn DnsHandler> = Arc::new(
            MeshZone::new(Arc::clone(&store), &zone, &ns, &hostmaster)
                .map_err(|e| format!("MESHD_ZONE: {e}"))?,
        );
        for (proto, h, bind) in [
            ("udp", Arc::clone(&handler), dns_bind.clone()),
            ("tcp", handler, dns_bind.clone()),
        ] {
            tasks.spawn(async move {
                let r = if proto == "udp" {
                    serve_udp_with(&bind, h).await
                } else {
                    serve_tcp_with(&bind, h).await
                };
                r.map_err(|e| format!("dns {proto} {bind}: {e}"))
            });
        }
        eprintln!("meshd: dns for {zone} listening on {dns_bind} (udp and tcp)");
    }
    tasks.spawn({
        let store = Arc::clone(&store);
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let swept = store.sweep(unix_now());
                if swept > 0 {
                    eprintln!("meshd: dropped {swept} expired records");
                }
            }
        }
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => { eprintln!("meshd: terminating"); Ok(()) }
        _ = tokio::signal::ctrl_c() => { eprintln!("meshd: interrupted"); Ok(()) }
        done = tasks.join_next() => match done {
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(format!("task failed: {e}")),
            _ => Ok(()),
        },
    }
}
