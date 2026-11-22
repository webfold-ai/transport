//! Hermetic end-to-end tests of the edge with the real pieces wired together: admission API,
//! tunnel listener, `overlay-agent`, the SNI TLS front, per-SNI certificates and TLS passthrough.
//! Everything runs in-process on loopback; the origin is a tiny HTTP/TLS server defined here.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::many_single_char_names,
    reason = "test code: deterministic assertions on spawned servers"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use edge_lb::edge_state::EdgeState;
use edge_lb::{control, front, router, tunnel, EdgeLb};
use overlay_agent::AgentConfig;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport::edge::CertMaterial;
use transport::edge_proxy::{EdgeCertResolver, MemoryCertSource};
use transport::Transport as _;

const SECRET: &str = "e2e-control-secret";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ── the origin ─────────────────────────────────────────────────────────────────────────

/// A minimal HTTP/1.1 origin: `/echo` returns the body, `/slow` takes 400 ms, `/headers` returns
/// the request head, `/chunked` answers chunked, `/count` counts requests. Closes after each reply.
async fn origin() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let hits = h.clone();
            tokio::spawn(async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p;
                    }
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let want = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + 4 + want {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = buf[head_end + 4..head_end + 4 + want].to_vec();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let response: Vec<u8> = match path.as_str() {
                    "/slow" => {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nslow".to_vec()
                    }
                    "/headers" => {
                        let mut r = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", head.len()).into_bytes();
                        r.extend_from_slice(head.as_bytes());
                        r
                    }
                    "/chunked" => b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec(),
                    _ => {
                        let mut r = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
                        r.extend_from_slice(&body);
                        r
                    }
                };
                let _ = s.write_all(&response).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, hits)
}

// ── the edge ───────────────────────────────────────────────────────────────────────────

struct Harness {
    edge: Arc<EdgeLb>,
    /// Plain listener serving the app and `/control/*`.
    http: String,
    tunnel_addr: String,
    http_client: reqwest::Client,
}

async fn boot() -> Harness {
    let state = EdgeState::ephemeral();
    let edge = EdgeLb::build_with_state(Vec::new(), state).await;
    let app = control::mount(router(edge.clone()), &edge, &Arc::new(SECRET.to_string()));
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let b = bind.clone();
    tokio::spawn(async move {
        let _ = servelet_h1::serve(&b, app).await;
    });
    let endpoint = tunnel::bind_tunnel_endpoint("127.0.0.1:0", &tunnel::tunnel_dialkey(SECRET))
        .await
        .unwrap();
    let tunnel_addr = endpoint.local_addr().unwrap();
    tokio::spawn(tunnel::serve_tunnel_endpoint(
        endpoint,
        edge.tunnels.clone(),
    ));
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let h = Harness {
        edge,
        http: format!("http://{bind}"),
        tunnel_addr,
        http_client,
    };
    for _ in 0..100 {
        if TcpStream::connect(&bind).await.is_ok() {
            return h;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("edge never listened");
}

impl Harness {
    async fn control(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut rb = self
            .http_client
            .request(method, format!("{}{path}", self.http))
            .header("x-control-secret", SECRET);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn admit(&self, label: &str, tenant: &str, tls_mode: &str, origin_port: u16) {
        let (st, v) = self
            .control(
                reqwest::Method::POST,
                "/control/hostnames",
                Some(json!({ "op": "admit_managed", "tenant_id": tenant, "tunnel_id": format!("tun-{label}"), "apex": "tascloud.app",
                             "label": label, "dialkey": null, "tls_mode": tls_mode, "origin_port": origin_port, "agent_peer": null })),
            )
            .await;
        assert_eq!(st, 201, "{v}");
    }

    fn agent(
        &self,
        host: &str,
        origin_port: u16,
        dir: &std::path::Path,
        pipes: usize,
        splice: usize,
    ) -> AgentConfig {
        AgentConfig {
            edge_tunnel_addr: self.tunnel_addr.clone(),
            control_url: self.http.clone(),
            control_secret: SECRET.to_string(),
            hostname: host.to_string(),
            local_port: origin_port,
            identity_file: dir
                .join(format!("{host}.key"))
                .to_string_lossy()
                .to_string(),
            version: Some("e2e".into()),
            pipes,
            splice_pipes: splice,
        }
    }

    /// GET/POST through the plain listener with a chosen Host.
    async fn via_edge(
        &self,
        method: reqwest::Method,
        host: &str,
        path: &str,
        body: Vec<u8>,
        extra: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut rb = self
            .http_client
            .request(method, format!("{}{path}", self.http))
            .header("host", host)
            .body(body);
        for (k, v) in extra {
            rb = rb.header(*k, *v);
        }
        rb.send().await.unwrap()
    }

    async fn wait_status(&self, host: &str, path: &str, want: u16, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self
                .via_edge(reqwest::Method::GET, host, path, Vec::new(), &[])
                .await
                .status()
                .as_u16()
                == want
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn binary_bodies_headers_and_chunked_origins_cross_the_tunnel_intact() {
    let h = boot().await;
    let (origin_port, _) = origin().await;
    h.admit("app-1", "acme", "terminate", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = h.agent("app-1.tascloud.app", origin_port, dir.path(), 3, 0);
    overlay_agent::enroll(&cfg).await.unwrap();
    let agent = tokio::spawn(overlay_agent::serve_forever(cfg));
    assert!(
        h.wait_status("app-1.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await,
        "tunnel never came up"
    );

    // 100 KB of every byte value: not UTF-8, longer than a sealed frame, contains CRLFCRLF.
    let mut body: Vec<u8> = (0..100_000u32)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    body.extend_from_slice(b"\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
    let resp = h
        .via_edge(
            reqwest::Method::POST,
            "app-1.tascloud.app",
            "/echo",
            body.clone(),
            &[],
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().to_vec(),
        body,
        "binary body must survive byte for byte"
    );

    // Provenance: one Host, the edge's forwarding headers, no client-forged ones.
    let resp = h
        .via_edge(
            reqwest::Method::GET,
            "app-1.tascloud.app",
            "/headers",
            Vec::new(),
            &[
                ("x-forwarded-for", "6.6.6.6"),
                ("x-forwarded-proto", "https"),
                ("x-real-ip", "6.6.6.6"),
                ("forwarded", "for=6.6.6.6"),
            ],
        )
        .await;
    let seen = resp.text().await.unwrap().to_ascii_lowercase();
    assert_eq!(
        seen.matches("\r\nhost:").count(),
        1,
        "exactly one Host: {seen}"
    );
    assert!(seen.contains("host: app-1.tascloud.app"), "{seen}");
    assert!(
        seen.contains("x-forwarded-proto: http\r\n"),
        "plain listener => http: {seen}"
    );
    assert!(
        seen.contains("x-forwarded-for: 127.0.0.1"),
        "the real peer, not the forged one: {seen}"
    );
    assert!(
        !seen.contains("6.6.6.6") && !seen.contains("x-real-ip") && !seen.contains("forwarded: "),
        "{seen}"
    );

    // Chunked origin => single framed response; duplicate Set-Cookie preserved.
    let resp = h
        .via_edge(
            reqwest::Method::GET,
            "app-1.tascloud.app",
            "/chunked",
            Vec::new(),
            &[],
        )
        .await;
    assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
    assert_eq!(resp.text().await.unwrap(), "abcdef");

    // HEAD: headers, no body.
    let resp = h
        .via_edge(
            reqwest::Method::HEAD,
            "app-1.tascloud.app",
            "/echo",
            Vec::new(),
            &[],
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.unwrap().is_empty());
    agent.abort();
}

#[tokio::test]
async fn pipes_serve_requests_concurrently() {
    let h = boot().await;
    let (origin_port, _) = origin().await;
    h.admit("par", "acme", "terminate", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = h.agent("par.tascloud.app", origin_port, dir.path(), 4, 0);
    overlay_agent::enroll(&cfg).await.unwrap();
    let agent = tokio::spawn(overlay_agent::serve_forever(cfg));
    assert!(
        h.wait_status("par.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await
    );
    // wait for all four pipes
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.edge.tunnels.list().first().is_none_or(|t| t.pipes < 4) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let t = Instant::now();
    let get = || {
        h.via_edge(
            reqwest::Method::GET,
            "par.tascloud.app",
            "/slow",
            Vec::new(),
            &[],
        )
    };
    let (a, b, c, d) = tokio::join!(get(), get(), get(), get());
    for r in [a, b, c, d] {
        assert_eq!(r.status(), 200);
    }
    assert!(
        t.elapsed() < Duration::from_millis(1300),
        "4 × 400 ms requests took {:?}: they were serialised",
        t.elapsed()
    );
    agent.abort();
}

#[tokio::test]
async fn a_different_connector_cannot_take_an_enrolled_hostname() {
    let h = boot().await;
    let (origin_port, hits) = origin().await;
    h.admit("mine", "acme", "terminate", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    let legit = h.agent("mine.tascloud.app", origin_port, dir.path(), 1, 0);
    overlay_agent::enroll(&legit).await.unwrap();
    let legit_task = tokio::spawn(overlay_agent::serve_forever(legit));
    assert!(
        h.wait_status("mine.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await
    );
    let before = hits.load(Ordering::SeqCst);

    // The impostor holds the shared control secret and its own identity. Enrolment is refused…
    let other = tempfile::TempDir::new().unwrap();
    let impostor = h.agent("mine.tascloud.app", origin_port + 1, other.path(), 1, 1);
    let err = overlay_agent::enroll(&impostor)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("403"), "{err}");
    // …and dialling in anyway (workers retry enrolment first, so go below them) attaches nothing.
    let impostor_task = tokio::spawn(overlay_agent::serve_forever(impostor));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        h.edge.tunnels.list()[0].pipes,
        1,
        "only the enrolled connector's pipe is attached"
    );
    // Traffic still reaches the legitimate origin only.
    assert_eq!(
        h.via_edge(
            reqwest::Method::GET,
            "mine.tascloud.app",
            "/echo",
            Vec::new(),
            &[]
        )
        .await
        .status(),
        200
    );
    assert_eq!(hits.load(Ordering::SeqCst), before + 1);
    legit_task.abort();
    impostor_task.abort();
}

#[tokio::test]
async fn suspension_cuts_service_at_once_and_resumption_self_heals_without_operator_help() {
    let h = boot().await;
    let (origin_port, _) = origin().await;
    h.admit("susp", "acme", "terminate", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = h.agent("susp.tascloud.app", origin_port, dir.path(), 1, 0);
    overlay_agent::enroll(&cfg).await.unwrap();
    let agent = tokio::spawn(overlay_agent::serve_forever(cfg));
    assert!(
        h.wait_status("susp.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await
    );

    let (st, _) = h
        .control(
            reqwest::Method::POST,
            "/control/hostnames/susp.tascloud.app/suspend",
            Some(json!({ "tenant_id": "acme" })),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        h.via_edge(
            reqwest::Method::GET,
            "susp.tascloud.app",
            "/echo",
            Vec::new(),
            &[]
        )
        .await
        .status(),
        403,
        "suspended is refused immediately"
    );
    let (st, _) = h
        .control(
            reqwest::Method::POST,
            "/control/hostnames/susp.tascloud.app/resume",
            Some(json!({ "tenant_id": "acme" })),
        )
        .await;
    assert_eq!(st, 200);
    // The suspension dropped the tunnel; the agent re-enrols (same key) and re-dials by itself.
    assert!(
        h.wait_status("susp.tascloud.app", "/echo", 200, Duration::from_secs(20))
            .await,
        "agent did not recover"
    );

    // Release: the name stops routing and stays quarantined against another tenant.
    let (st, _) = h
        .control(
            reqwest::Method::DELETE,
            "/control/hostnames/susp.tascloud.app?tenant_id=acme",
            None,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(
        h.via_edge(
            reqwest::Method::GET,
            "susp.tascloud.app",
            "/echo",
            Vec::new(),
            &[]
        )
        .await
        .status(),
        404
    );
    let (st, _) = h
        .control(
            reqwest::Method::POST,
            "/control/hostnames",
            Some(json!({ "op": "admit_managed", "tenant_id": "rival", "tunnel_id": "x", "apex": "tascloud.app", "label": "susp", "dialkey": null, "tls_mode": "terminate", "origin_port": 1, "agent_peer": null })),
        )
        .await;
    assert_eq!(st, 409, "released label is quarantined");
    agent.abort();
}

// ── TLS ────────────────────────────────────────────────────────────────────────────────

fn cert_for(name: &str) -> CertMaterial {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    CertMaterial {
        chain_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

fn tls_client(trust: &CertMaterial) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for der in transport::pem::blocks(&trust.chain_pem, "CERTIFICATE") {
        roots
            .add(rustls::pki_types::CertificateDer::from(der))
            .unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        transport::edge_proxy::sni::provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// Start the TLS front over `config` and return its address.
async fn start_front(h: &Harness, config: Arc<rustls::ServerConfig>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(front::serve(
        listener,
        h.edge.clone(),
        router(h.edge.clone()),
        config,
    ));
    addr
}

async fn https_get(
    connector: &tokio_rustls::TlsConnector,
    addr: &str,
    sni: &str,
    host: &str,
    path: &str,
) -> std::io::Result<(u16, String)> {
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = connector.connect(name, tcp).await?;
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, text))
}

#[tokio::test]
async fn the_tls_front_presents_the_per_sni_certificate_enforces_host_sni_agreement_and_refuses_unknown_names(
) {
    let h = boot().await;
    let (origin_port, _) = origin().await;
    h.admit("tls-1", "acme", "terminate", origin_port).await;
    h.admit("tls-2", "rival", "terminate", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    for host in ["tls-1.tascloud.app", "tls-2.tascloud.app"] {
        let cfg = h.agent(host, origin_port, dir.path(), 1, 0);
        overlay_agent::enroll(&cfg).await.unwrap();
        tokio::spawn(overlay_agent::serve_forever(cfg));
    }
    let wildcard = cert_for("*.tascloud.app");
    let source = Arc::new(MemoryCertSource::new());
    source.install("*.tascloud.app", wildcard.clone());
    h.edge.state.set_cert_source(source.clone());
    let config = Arc::new(EdgeCertResolver::new(source))
        .server_config()
        .unwrap();
    let addr = start_front(&h, config).await;
    let connector = tls_client(&wildcard);

    assert!(
        h.wait_status("tls-1.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await
    );
    assert!(
        h.wait_status("tls-2.tascloud.app", "/echo", 200, Duration::from_secs(15))
            .await
    );

    let (st, text) = https_get(
        &connector,
        &addr,
        "tls-1.tascloud.app",
        "tls-1.tascloud.app",
        "/headers",
    )
    .await
    .unwrap();
    assert_eq!(st, 200, "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("x-forwarded-proto: https"),
        "{text}"
    );

    // Same connection name, other tenant's Host: 421, and tls-2's origin is never reached.
    let (st, _) = https_get(
        &connector,
        &addr,
        "tls-1.tascloud.app",
        "tls-2.tascloud.app",
        "/echo",
    )
    .await
    .unwrap();
    assert_eq!(
        st, 421,
        "SNI/Host disagreement is misdirected, never cross-tenant"
    );

    // A name nobody admitted completes no handshake (and a wildcard does not cover two labels).
    assert!(
        https_get(
            &connector,
            &addr,
            "nobody.tascloud.app",
            "nobody.tascloud.app",
            "/"
        )
        .await
        .is_err()
            || {
                // The wildcard cert is presented for any single label; the *request* is then a 404.
                let (st, _) = https_get(
                    &connector,
                    &addr,
                    "nobody.tascloud.app",
                    "nobody.tascloud.app",
                    "/",
                )
                .await
                .unwrap();
                st == 404
            }
    );
    assert!(https_get(
        &connector,
        &addr,
        "a.b.tascloud.app",
        "a.b.tascloud.app",
        "/"
    )
    .await
    .is_err());
    // No SNI at all: closed, nothing presented.
    let mut raw = TcpStream::connect(&addr).await.unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut sink)).await;
    assert!(sink.is_empty(), "a non-TLS client gets nothing back");
}

#[tokio::test]
async fn passthrough_names_are_spliced_to_the_tenants_own_tls_server_and_the_edge_holds_no_key() {
    let h = boot().await;

    // The tenant's own TLS origin, with its own certificate for the passthrough name.
    let tenant_cert = cert_for("pt.tascloud.app");
    let chain: Vec<_> = transport::pem::blocks(&tenant_cert.chain_pem, "CERTIFICATE")
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        transport::pem::blocks(&tenant_cert.key_pem, "PRIVATE KEY").remove(0),
    ));
    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        transport::edge_proxy::sni::provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = origin_listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let _ = tls.read(&mut buf).await;
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\nconnection: close\r\n\r\nhello-from-pt\n").await;
                let _ = tls.shutdown().await;
            });
        }
    });

    h.admit("pt", "acme", "passthrough", origin_port).await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = h.agent("pt.tascloud.app", origin_port, dir.path(), 1, 2);
    overlay_agent::enroll(&cfg).await.unwrap();
    let agent = tokio::spawn(overlay_agent::serve_forever(cfg));

    // The edge has NO certificate source at all: it must not need (or hold) a key for this name.
    let empty = Arc::new(MemoryCertSource::new());
    let config = Arc::new(EdgeCertResolver::new(empty))
        .server_config()
        .unwrap();
    let addr = start_front(&h, config).await;
    // The client trusts ONLY the tenant's certificate: success proves the handshake terminated at
    // the tenant's origin, not at the edge.
    let connector = tls_client(&tenant_cert);

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last;
    loop {
        match https_get(&connector, &addr, "pt.tascloud.app", "pt.tascloud.app", "/").await {
            Ok((200, text)) => {
                assert!(text.ends_with("hello-from-pt\n"), "{text}");
                break;
            }
            other => last = format!("{other:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "passthrough never worked: {last}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Several flows in a row each take (and spend) a splice pipe; the agent replenishes them.
    for _ in 0..4 {
        let (st, _) = https_get(&connector, &addr, "pt.tascloud.app", "pt.tascloud.app", "/")
            .await
            .unwrap();
        assert_eq!(st, 200);
    }
    // An unadmitted name is not spliced anywhere.
    assert!(https_get(
        &connector,
        &addr,
        "other.tascloud.app",
        "other.tascloud.app",
        "/"
    )
    .await
    .is_err());
    agent.abort();
}
