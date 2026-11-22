//! Edge smoke — boots the REAL `edge-lb` binary in front of the REAL
//! `notification-service` binary and publishes through the edge by Host
//! header, exactly as a customer's ntfy app would. Proves the custom LB
//! (the servelet proxy lifecycle) terminates the wire path.

#![expect(
    clippy::unwrap_used,
    reason = "test code: deterministic assertions on spawned binaries"
)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use reqwest::StatusCode;
use tempfile::TempDir;

/// The sibling notification-service binary — same target dir, sibling crate.
fn notification_service_bin() -> PathBuf {
    let me = std::env::current_exe().unwrap();
    let dir = me.parent().unwrap();
    // tests binaries live in target/<profile>/deps; the workspace bins live
    // in target/<profile>.
    let mut path = dir.to_path_buf();
    path.pop(); // deps -> <profile>
    let candidate = path.join("notification-service");
    if candidate.exists() {
        return candidate;
    }
    // Fallback: PATH (CI builds may install it).
    PathBuf::from("notification-service")
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_health(url: &str) -> bool {
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status() == StatusCode::OK {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn edge_routes_ntfy_host_to_the_notification_service() {
    // ── boot the notification service ──────────────────────────────────────
    let svc_dir = TempDir::new().unwrap();
    let svc_port = free_port();
    let ntfy_port = free_port();
    let svc = Command::new(notification_service_bin())
        .env("BIND", format!("127.0.0.1:{svc_port}"))
        .env("NTFY_BIND", format!("127.0.0.1:{ntfy_port}"))
        .env("NOTIFICATION_SERVICE_DIR", svc_dir.path())
        .env("NOTIFICATION_SERVICE_SECRET", "edge-smoke-secret")
        .env("NOTIFICATION_SERVICE_TICK_MS", "100")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _svc_guard = Scoped(svc);
    assert!(
        wait_health(&format!("http://127.0.0.1:{svc_port}/v1/healthz")).await,
        "notification-service never healthy"
    );

    // ── boot the edge in front of it ───────────────────────────────────────
    let edge_dir = TempDir::new().unwrap();
    let edge_port = free_port();
    let edge = Command::new(env!("CARGO_BIN_EXE_edge-lb"))
        .env(
            "EDGE_LB_ROUTES",
            format!("ntfy.test=http://127.0.0.1:{ntfy_port}"),
        )
        .env("EDGE_LB_BIND", format!("127.0.0.1:{edge_port}"))
        .env("NOTIFICATION_SERVICE_DIR", edge_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _edge_guard = Scoped(edge);
    // No /health on the edge itself — poll a harmless unknown host instead
    // (404 proves the listener is up).
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let resp = client
            .get(format!("http://127.0.0.1:{edge_port}/"))
            .header("host", "unknown.test")
            .send()
            .await;
        if resp
            .as_ref()
            .is_ok_and(|r| r.status() == StatusCode::NOT_FOUND)
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "edge never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ── mint a token through the service, then publish THROUGH THE EDGE ────
    let token_resp = client
        .post(format!("http://127.0.0.1:{svc_port}/v1/tokens"))
        .header("x-tenant-id", "edge-tenant")
        .header("x-notification-service-secret", "edge-smoke-secret")
        .header("content-type", "application/json")
        .body(r#"{"label":"edge-smoke"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::CREATED);
    let token: serde_json::Value = token_resp.json().await.unwrap();
    let token = token["token"].as_str().unwrap();

    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/deploys"))
        .header("host", "ntfy.test")
        .header("authorization", format!("Bearer {token}"))
        .header("title", "Through the edge")
        .body("edge works")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "publish through the edge");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["topic"], "deploys");
    assert_eq!(body["message"], "edge works");

    // ── unknown host through the edge is 404 (no existence leaks) ──────────
    let resp = client
        .post(format!("http://127.0.0.1:{edge_port}/deploys"))
        .header("host", "not-registered.test")
        .header("authorization", format!("Bearer {token}"))
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Keeps the spawned child alive for the test's duration (Drop kills it).
struct Scoped(Child);
impl Drop for Scoped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
