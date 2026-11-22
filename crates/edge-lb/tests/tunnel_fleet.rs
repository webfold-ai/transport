//! Fleet smoke — the zero-touch loop with real binaries: a tenant origin
//! (`notification-service` ntfy surface), the edge (`edge-lb` with its
//! tunnel listener + control API), and the fleet agent (`overlay-agent`
//! lib, in-process) enrolling, dialling in, claiming its hostname and
//! serving. A publish THROUGH the edge must arrive at the origin via the
//! authenticated tunnel — the L4/relay path, no inbound ports.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code: deterministic assertions on spawned binaries; spawn_edge retries with retries, and the integration flow is inherently multi-step"
)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use overlay_agent::{enroll, serve_forever, AgentConfig};
use reqwest::StatusCode;
use tempfile::TempDir;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Scoped(Child);
impl Drop for Scoped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn edge-lb with a tunnel listener; retries on the ephemeral-port
/// collision (probe-and-release races the origin's random BIND).
fn spawn_edge(
    edge_dir: &TempDir,
    control_secret: &str,
    ntfy_port: u16,
) -> (Scoped, std::fs::File, u16, u16) {
    for _ in 0..8 {
        // Re-roll BOTH ports per attempt — probe-and-release races the
        // origin's own random BIND.
        let edge_port = free_port();
        let tunnel_port = free_port();
        let log = std::fs::File::create(edge_dir.path().join("edge.log")).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_edge-lb"))
            .env(
                "EDGE_LB_ROUTES",
                format!("static.test=http://127.0.0.1:{ntfy_port}"),
            )
            .env("EDGE_LB_BIND", format!("127.0.0.1:{edge_port}"))
            .env("EDGE_LB_TUNNEL_BIND", format!("127.0.0.1:{tunnel_port}"))
            .env("EDGE_LB_CONTROL_SECRET", control_secret)
            .env("NOTIFICATION_SERVICE_DIR", edge_dir.path())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(400));
        let log_text =
            std::fs::read_to_string(edge_dir.path().join("edge.log")).unwrap_or_default();
        let serving = log_text.contains("edge-lb listening on")
            && log_text.contains("tunnel listener on")
            && !log_text.contains("Address already in use")
            && !log_text.contains("bind failed");
        if serving {
            return (Scoped(child), log, edge_port, tunnel_port);
        }
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "edge never came up: {}",
        std::fs::read_to_string(edge_dir.path().join("edge.log")).unwrap_or_default()
    );
}

fn bin(name: &str) -> std::path::PathBuf {
    // Sibling binaries live in the same target profile dir (cargo rebuilds
    // THIS crate's own bin, so the edge is fresh via CARGO_BIN_EXE; the
    // notification-service binary is probed from the target dir).
    let me = std::env::current_exe().unwrap();
    let mut path = me.parent().unwrap().to_path_buf();
    path.pop(); // deps -> <profile>
    let candidate = path.join(name);
    if candidate.exists() {
        return candidate;
    }
    std::path::PathBuf::from(name)
}

async fn admit_managed(
    client: &reqwest::Client,
    edge_port: u16,
    secret: &str,
    label: &str,
    tenant: &str,
) {
    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/control/hostnames"))
        .header("x-control-secret", secret)
        .json(&serde_json::json!({
            "op": "admit_managed", "tenant_id": tenant, "tunnel_id": format!("tun-{label}"), "apex": "tascloud.app",
            "label": label, "dialkey": null, "tls_mode": "terminate", "origin_port": 8080, "agent_peer": null
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "admission: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn wait_http(client: &reqwest::Client, url: &str, want: StatusCode) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status() == want {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn zero_touch_tunnel_serves_requests_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,overlay_agent=debug,edge_lb=debug")
        .with_test_writer()
        .try_init();
    let control_secret = "fleet-smoke-secret";

    // ── origin: the notification-service ntfy surface ──────────────────────
    let svc_dir = TempDir::new().unwrap();
    let api_port = free_port();
    let ntfy_port = free_port();
    let svc = Command::new(bin("notification-service"))
        .env("BIND", format!("127.0.0.1:{api_port}"))
        .env("NTFY_BIND", format!("127.0.0.1:{ntfy_port}"))
        .env("NOTIFICATION_SERVICE_DIR", svc_dir.path())
        .env("NOTIFICATION_SERVICE_SECRET", "fleet-smoke")
        .env("NOTIFICATION_SERVICE_TICK_MS", "100")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _svc = Scoped(svc);

    // ── the edge: proxy + control API + tunnel listener ────────────────────
    let edge_dir = TempDir::new().unwrap();
    let (_edge, _edge_log, edge_port, tunnel_port) =
        spawn_edge(&edge_dir, control_secret, ntfy_port);
    let client = reqwest::Client::new();
    assert!(
        wait_http(
            &client,
            &format!("http://127.0.0.1:{edge_port}/"),
            StatusCode::NOT_FOUND
        )
        .await,
        "edge never came up"
    );

    // ── the fleet agent: enroll → dial → claim → serve ─────────────────────
    let agent_dir = TempDir::new().unwrap();
    let cfg = AgentConfig {
        edge_tunnel_addr: format!("127.0.0.1:{tunnel_port}"),
        control_url: format!("http://127.0.0.1:{edge_port}"),
        control_secret: control_secret.to_string(),
        hostname: "ntfy-overlay.tascloud.app".to_string(),
        local_port: ntfy_port,
        identity_file: agent_dir
            .path()
            .join("id.key")
            .to_string_lossy()
            .to_string(),
        version: Some("0.1.0-test".into()),
        pipes: 2,
        splice_pipes: 0,
    };
    // The platform admits the hostname first; the agent then binds its key to it.
    admit_managed(&client, edge_port, control_secret, "ntfy-overlay", "fleet").await;
    enroll(&cfg).await.unwrap();
    let serve_cfg = cfg.clone();
    let agent_task = tokio::spawn(async move {
        serve_forever(serve_cfg).await;
    });

    // ── publish through the edge → over the tunnel → the origin ────────────
    // Mint a real token at the origin's API (the origin is on the private
    // network; the EDGE route is what we're proving).
    let token: serde_json::Value = client
        .post(format!("http://127.0.0.1:{api_port}/v1/tokens"))
        .header("x-tenant-id", "fleet")
        .header("x-notification-service-secret", "fleet-smoke")
        .header("content-type", "application/json")
        .body(r#"{"label":"fleet-smoke"}"#)
        .send()
        .await
        .expect("origin API reachable")
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap().to_string();

    // Publish over the ntfy wire, THROUGH the edge, down the tunnel. The
    // agent dials asynchronously — retry with a deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut published: Option<reqwest::Response> = None;
    while std::time::Instant::now() < deadline {
        let resp = client
            .post(format!("http://127.0.0.1:{edge_port}/deploys"))
            .header("host", "ntfy-overlay.tascloud.app")
            .header("authorization", format!("Bearer {token}"))
            .header("title", "Over the tunnel")
            .body("hello from the overlay")
            .send()
            .await
            .unwrap();
        let status = resp.status();
        if status == StatusCode::OK {
            published = Some(resp);
            break;
        }
        if !(status == StatusCode::BAD_GATEWAY || status == StatusCode::NOT_FOUND) {
            published = Some(resp);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let resp = published.unwrap_or_else(|| {
        let log = std::fs::read_to_string(edge_dir.path().join("edge.log")).unwrap_or_default();
        panic!("publish never settled\n--- edge log ---\n{log}");
    });
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "publish through the tunnel failed: {}\n--- edge log ---\n{}",
        resp.text().await.unwrap_or_default(),
        std::fs::read_to_string(edge_dir.path().join("edge.log")).unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["topic"], "deploys");
    assert_eq!(body["message"], "hello from the overlay");

    // The origin's inbox saw it (proves the full loop, not a static route).
    let inbox: serde_json::Value = client
        .get(format!("http://127.0.0.1:{api_port}/v1/inbox"))
        .header("x-tenant-id", "fleet")
        .header("x-notification-service-secret", "fleet-smoke")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["reference"], "ntfy:deploys");

    agent_task.abort();
}

#[tokio::test]
async fn control_api_rejects_bad_secret() {
    let edge_dir = TempDir::new().unwrap();
    let (_edge, _edge_log, edge_port, _tunnel_port) =
        spawn_edge(&edge_dir, "right-secret", free_port());
    let client = reqwest::Client::new();
    assert!(
        wait_http(
            &client,
            &format!("http://127.0.0.1:{edge_port}/"),
            StatusCode::NOT_FOUND
        )
        .await,
        "edge never came up"
    );

    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/control/tunnels"))
        .header("x-control-secret", "wrong")
        .json(&serde_json::json!({ "hostname": "h.test", "port": 8080, "peer": "ab".repeat(32) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Right secret, but the hostname was never admitted: no tunnel for an arbitrary name.
    let enrol =
        serde_json::json!({ "hostname": "h.tascloud.app", "port": 8080, "peer": "ab".repeat(32) });
    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/control/tunnels"))
        .header("x-control-secret", "right-secret")
        .json(&enrol)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "the control secret alone must not claim a hostname"
    );

    admit_managed(&client, edge_port, "right-secret", "h", "acme").await;
    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/control/tunnels"))
        .header("x-control-secret", "right-secret")
        .json(&enrol)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "enrollment of an admitted hostname with the right secret"
    );
}
