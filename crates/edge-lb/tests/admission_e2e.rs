//! Request admission through the REAL `edge-lb` binary, over real TCP, in front of a recording
//! upstream. The property under test is the one the platform cares about: **a refused request never
//! reaches the tenant**. The upstream records the request line of everything it receives; every
//! hostile request below must be answered by the edge and absent from that record.
//!
//! The spellings are the ones the public exploits for the CGI argument-injection family
//! (CVE-2012-1823, CVE-2024-4577) and `PHP2Shell` (CVE-2026-109619, the session-upload-progress field)
//! use, sent as raw bytes so nothing between the test and the edge normalises them.

#![expect(
    clippy::unwrap_used,
    reason = "test code: deterministic assertions on spawned binaries"
)]

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Scoped(Child);
impl Drop for Scoped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A tiny HTTP/1.1 upstream: records each request line, answers 200 `ok`.
async fn recording_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let line =
                    String::from_utf8_lossy(buf.split(|&b| b == b'\r').next().unwrap_or_default())
                        .into_owned();
                log.lock().unwrap().push(line);
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// Send raw bytes, return (status, body).
async fn raw(port: u16, request: &[u8]) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return (0, String::new());
    };
    if s.write_all(request).await.is_err() {
        return (0, String::new());
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nhost: app.test\r\nconnection: close\r\n\r\n").into_bytes()
}

fn multipart(field: &str) -> Vec<u8> {
    let body = format!(
        "--B7\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n1\r\n--B7\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\nPNG\r\n--B7--\r\n"
    );
    format!(
        "POST /upload HTTP/1.1\r\nhost: app.test\r\nconnection: close\r\ncontent-type: multipart/form-data; boundary=B7\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The denied field sits behind a field whose *content* holds `prefix--B7--suffix`. PHP does not treat
/// that as the closing delimiter and still parses the later part.
fn multipart_hidden_behind_embedded_delimiter() -> Vec<u8> {
    let body = "--B7\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nprefix--B7--suffix\r\n--B7\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n--B7--\r\n";
    format!(
        "POST /upload HTTP/1.1\r\nhost: app.test\r\nconnection: close\r\ncontent-type: multipart/form-data; boundary=B7\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn boot(edge_port: u16, upstream: u16, dir: &TempDir) -> Scoped {
    let child = Command::new(env!("CARGO_BIN_EXE_edge-lb"))
        .env(
            "EDGE_LB_ROUTES",
            format!("app.test=http://127.0.0.1:{upstream}"),
        )
        .env("EDGE_LB_BIND", format!("127.0.0.1:{edge_port}"))
        .env("EDGE_LB_CONTROL_SECRET", "ctl-secret")
        .env("EDGE_LB_ADMISSION_FILE", dir.path().join("admission.json"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Scoped(child)
}

async fn wait_up(port: u16) {
    for _ in 0..150 {
        let (status, _) = raw(port, &get("/")).await;
        if status != 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    unreachable!("edge never came up on {port}");
}

#[tokio::test]
async fn hostile_requests_are_answered_by_the_edge_and_never_reach_the_tenant() {
    let (up_port, seen) = recording_upstream().await;
    let dir = TempDir::new().unwrap();
    let port = free_port();
    let _edge = boot(port, up_port, &dir);
    wait_up(port).await;
    seen.lock().unwrap().clear();

    // A normal request is proxied.
    let (status, body) = raw(port, &get("/index.php?page=2&q=a+b")).await;
    assert_eq!((status, body.as_str()), (200, "ok"));
    assert_eq!(seen.lock().unwrap().len(), 1);
    seen.lock().unwrap().clear();

    // CGI argument injection, every public spelling.
    let hostile: Vec<(&str, Vec<u8>, u16)> = vec![
        ("CVE-2012-1823 -s", get("/index.php?-s"), 403),
        ("CVE-2012-1823 -d", get("/index.php?-d+allow_url_include%3dOn+-d+auto_prepend_file%3dphp://input"), 403),
        ("CVE-2024-4577 soft hyphen", get("/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"), 403),
        ("CVE-2024-4577 utf8 soft hyphen", get("/index.php?%C2%ADd+allow_url_include%3d1"), 403),
        ("traversal", get("/static/%2e%2e/%2e%2e/etc/passwd"), 400),
        ("double-encoded traversal", get("/static/%252e%252e/%252e%252e/etc/passwd"), 400),
        ("overlong utf-8", get("/static/%c0%ae%c0%ae/etc/passwd"), 400),
        ("nul truncation", get("/uploads/shell.php%00.jpg"), 400),
        ("backslash", get("/static\\..\\x"), 400),
        ("PHP2Shell upload progress", multipart("PHP_SESSION_UPLOAD_PROGRESS"), 403),
        ("PHP2Shell upload progress, lower case", multipart("php_session_upload_progress"), 403),
        ("PHP2Shell upload progress behind an embedded closing delimiter", multipart_hidden_behind_embedded_delimiter(), 403),
        ("oversized session id", format!("GET / HTTP/1.1\r\nhost: app.test\r\ncookie: PHPSESSID={}\r\nconnection: close\r\n\r\n", "a".repeat(5000)).into_bytes(), 400),
        ("malformed session id", b"GET / HTTP/1.1\r\nhost: app.test\r\ncookie: PHPSESSID=../../etc/passwd\r\nconnection: close\r\n\r\n".to_vec(), 400),
    ];
    for (name, req, want) in &hostile {
        let (status, body) = raw(port, req).await;
        assert_eq!(status, *want, "{name}: body {body:?}");
        assert!(
            !body.contains("passwd") && !body.contains("PHP_SESSION"),
            "{name}: the refusal must not echo the request: {body:?}"
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        seen.lock().unwrap().clone(),
        Vec::<String>::new(),
        "a refused request reached the tenant"
    );

    // An ordinary upload still goes through (the rule is a field name, not "multipart").
    let (status, _) = raw(port, &multipart("title")).await;
    assert_eq!(status, 200);
    assert_eq!(seen.lock().unwrap().len(), 1);

    // Unknown hostnames get the same refusal as known ones (admission runs before routing).
    let (status, _) = raw(
        port,
        b"GET /x.php?-s HTTP/1.1\r\nhost: nobody.test\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn an_emergency_rule_pushed_through_the_control_api_takes_effect_at_once_and_survives_a_restart(
) {
    let (up_port, seen) = recording_upstream().await;
    let dir = TempDir::new().unwrap();
    let port = free_port();
    let edge = boot(port, up_port, &dir);
    wait_up(port).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/control/admission");

    // A custom progress field name is not blocked by the baseline...
    assert_eq!(raw(port, &multipart("MY_PROGRESS_FIELD")).await.0, 200);
    // ...the control API needs the secret...
    let r = client
        .put(&url)
        .body(r#"{"deny_multipart_fields":["MY_PROGRESS_FIELD"]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // ...and then it is blocked immediately, with no restart and no rebuild.
    let r = client
        .put(&url)
        .header("x-control-secret", "ctl-secret")
        .body(r#"{"deny_multipart_fields":["MY_PROGRESS_FIELD"]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
    assert_eq!(raw(port, &multipart("MY_PROGRESS_FIELD")).await.0, 403);
    assert_eq!(
        raw(port, &multipart("PHP_SESSION_UPLOAD_PROGRESS")).await.0,
        403,
        "the baseline entry stays"
    );

    // The overlay cannot loosen or disable anything.
    for body in [
        r#"{"max_target_bytes":99999999}"#,
        r#"{"deny_multipart_fields":[]}"#,
    ] {
        let r = client
            .put(&url)
            .header("x-control-secret", "ctl-secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    for body in [
        r#"{"disable_cgi_rule":true}"#,
        r#"{"max_params":0}"#,
        r#"{"deny_multipart_fields":["bad name"]}"#,
        "not json",
    ] {
        let r = client
            .put(&url)
            .header("x-control-secret", "ctl-secret")
            .body(body)
            .send()
            .await
            .unwrap();
        assert!(
            r.status() == 400 || r.status() == 422,
            "{body}: {}",
            r.status()
        );
    }
    assert_eq!(
        raw(port, &get("/index.php?-s")).await.0,
        403,
        "baseline rules cannot be turned off"
    );
    let cfg: serde_json::Value = client
        .get(&url)
        .header("x-control-secret", "ctl-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(cfg["config"]["deny_multipart_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "MY_PROGRESS_FIELD"));
    assert_eq!(cfg["config"]["max_target_bytes"], 8192);

    // Metrics count the refusals by rule.
    let metrics = client
        .get(format!("http://127.0.0.1:{port}/control/metrics"))
        .header("x-control-secret", "ctl-secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("edge_lb_admission_rejected_total{rule=\"denied_multipart_field\"} 2"),
        "{metrics}"
    );
    assert!(
        metrics.contains("edge_lb_admission_rejected_total{rule=\"cgi_argument_injection\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("edge_lb_admission_rejected_total{rule=\"nul_byte\"} 0"),
        "every rule is exported, zero included"
    );

    // Persisted, and a restarted edge enforces it.
    let persisted = std::fs::read_to_string(dir.path().join("admission.json")).unwrap();
    assert!(persisted.contains("MY_PROGRESS_FIELD"), "{persisted}");
    drop(edge);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let port2 = free_port();
    let _edge2 = boot(port2, up_port, &dir);
    wait_up(port2).await;
    seen.lock().unwrap().clear();
    assert_eq!(
        raw(port2, &multipart("MY_PROGRESS_FIELD")).await.0,
        403,
        "the pushed rule must survive a restart"
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_corrupt_admission_file_stops_the_edge_from_starting_rather_than_running_unchecked() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("admission.json"), "{ not json").unwrap();
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_edge-lb"))
        .env("EDGE_LB_ROUTES", "app.test=http://127.0.0.1:1")
        .env("EDGE_LB_BIND", format!("127.0.0.1:{port}"))
        .env("EDGE_LB_ADMISSION_FILE", dir.path().join("admission.json"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(s) = child.try_wait().unwrap() {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let _ = child.kill();
    assert!(
        status.is_ok_and(|s| !s.success()),
        "edge started with an unparseable admission file"
    );
}
