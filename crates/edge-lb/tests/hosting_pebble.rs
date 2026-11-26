//! Certificate hosting against **Pebble**, Let's Encrypt's independent ACME test CA.
//!
//! Boots `hosting::start` exactly as `edge-lb`'s `main` does — durable cert store, ACME account,
//! authoritative DNS on a real socket, renewal engine, validation sweep — and proves that the
//! apex wildcards are issued by an unrelated CA that validates DNS-01 by querying *our* DNS, that
//! the certificates land in the store and the edge's status, and that the SNI TLS front then
//! presents them in a real handshake verified against Pebble's root.
//!
//! It then goes on to the lifecycle of a **custom** hostname: its dedicated certificate is issued
//! over HTTP-01, and releasing the name takes the certificate out of service and gets it revoked
//! at Pebble (which marks it revoked, reason `cessationOfOperation`) while the shared apex
//! wildcard stays valid; and the DNS health run, the Prometheus metrics and `/control/health`
//! report on all of it.
//!
//! Skipped unless `PEBBLE_BIN` and `PEBBLE_SRC` are set (see `transport/tests/pebble.rs`).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::too_many_lines,
    reason = "test code: deterministic assertions on spawned servers; skip notice goes to stderr"
)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use edge_lb::edge_state::{EdgeState, Op};
use edge_lb::hosting::{self, HostingConfig};
use edge_lb::{front, router, EdgeLb};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::edge_verify::ProofPolicy;

const ACME_PORT: u16 = 14510;
const MGMT_PORT: u16 = 14511;
const DNS_PORT: u16 = 25353;
/// Pebble's resolver: forwards the platform apexes to the edge's authority above and answers
/// everything else (the customer's name) with 127.0.0.1, so HTTP-01 reaches our listener.
const DNS_FRONT_PORT: u16 = 25354;
const HTTP01_PORT: u16 = 15012;

struct Pebble(Child);
impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The DNS Pebble asks (see [`DNS_FRONT_PORT`]).
struct FrontDns;

impl transport::edge_dns::DnsHandler for FrontDns {
    fn handle<'a>(&'a self, query: &'a [u8]) -> transport::BoxFuture<'a, Option<Vec<u8>>> {
        use transport::dns::{Flags, Message, Question, RData, Record, RecordType, ResponseCode};
        Box::pin(async move {
            let q = Message::from_bytes(query).ok()?;
            let question = q.questions.first().cloned()?;
            let name = question
                .name
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if transport::edge::APEXES
                .iter()
                .any(|a| name == a.zone || name.ends_with(&format!(".{}", a.zone)))
            {
                let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
                sock.send_to(query, ("127.0.0.1", DNS_PORT)).await.ok()?;
                let mut buf = vec![0u8; 4096];
                let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
                    .await
                    .ok()?
                    .ok()?;
                return Some(buf[..n].to_vec());
            }
            let mut r = Message::response(q.id);
            r.flags = Flags {
                response: true,
                recursion_desired: q.flags.recursion_desired,
                recursion_available: true,
                response_code: ResponseCode::NoError,
                ..Flags::default()
            };
            r.questions = vec![Question::new(question.name.clone(), question.qtype)];
            if question.qtype == RecordType::A {
                r.answers.push(Record::new(
                    question.name.clone(),
                    1,
                    RData::A("127.0.0.1".parse().ok()?),
                ));
            }
            Some(r.to_bytes())
        })
    }
}

/// Pebble's own verdict on a certificate (`/cert-status-by-serial/<hex>` on its management port).
async fn pebble_status(mgmt: &reqwest::Client, chain_pem: &str) -> (String, Option<u64>) {
    let id = transport::acme::ari_cert_id(chain_pem).expect("certificate id");
    let serial = transport::pem::base64_decode(
        &id.split_once('.')
            .unwrap()
            .1
            .replace('-', "+")
            .replace('_', "/"),
    )
    .unwrap();
    let hex = serial.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let body = mgmt
        .get(format!(
            "https://localhost:{MGMT_PORT}/cert-status-by-serial/{hex}"
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).expect(&body);
    (
        v["Status"].as_str().unwrap().to_string(),
        v["Reason"].as_u64(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosting_issues_every_apex_wildcard_and_the_front_serves_it() {
    let (Some(bin), Some(src)) = (
        std::env::var_os("PEBBLE_BIN"),
        std::env::var_os("PEBBLE_SRC"),
    ) else {
        eprintln!("SKIPPED: set PEBBLE_BIN and PEBBLE_SRC to run the Pebble hosting test");
        return;
    };
    let src = PathBuf::from(src);
    let work = tempfile::TempDir::new().unwrap();
    let minica = std::fs::read_to_string(src.join("test/certs/pebble.minica.pem")).unwrap();
    std::fs::write(work.path().join("minica.pem"), &minica).unwrap();
    std::env::set_var("SSL_CERT_FILE", work.path().join("minica.pem"));

    let config = format!(
        r#"{{"pebble":{{"listenAddress":"127.0.0.1:{ACME_PORT}","managementListenAddress":"127.0.0.1:{MGMT_PORT}",
"certificate":"{c}","privateKey":"{k}","httpPort":{HTTP01_PORT},"tlsPort":15011,"ocspResponderURL":"",
"externalAccountBindingRequired":false,"retryAfter":{{"authz":1,"order":1}},"keyAlgorithm":"ecdsa",
"profiles":{{"default":{{"description":"default","validityPeriod":7776000}}}}}}}}"#,
        c = src.join("test/certs/localhost/cert.pem").display(),
        k = src.join("test/certs/localhost/key.pem").display(),
    );
    std::fs::write(work.path().join("pebble.json"), config).unwrap();
    // Pebble's resolver, in front of the edge's own authority.
    {
        let handler: Arc<dyn transport::edge_dns::DnsHandler> = Arc::new(FrontDns);
        let bind = format!("127.0.0.1:{DNS_FRONT_PORT}");
        tokio::spawn(transport::edge_dns::serve_udp_with(
            Box::leak(bind.clone().into_boxed_str()),
            handler.clone(),
        ));
        tokio::spawn(transport::edge_dns::serve_tcp_with(
            Box::leak(bind.into_boxed_str()),
            handler,
        ));
    }
    let log = std::fs::File::create(work.path().join("pebble.log")).unwrap();
    let _pebble = Pebble(
        Command::new(bin)
            .args([
                "-config",
                work.path().join("pebble.json").to_str().unwrap(),
                "-dnsserver",
                &format!("127.0.0.1:{DNS_FRONT_PORT}"),
            ])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            .env("PEBBLE_WFE_AUTHZREUSE", "0")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn pebble"),
    );
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ACME_PORT))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let env: std::collections::HashMap<String, String> = [
        (
            "EDGE_LB_CERT_DIR",
            work.path().join("certs").to_string_lossy().to_string(),
        ),
        (
            "EDGE_LB_ACME_DIRECTORY",
            format!("https://localhost:{ACME_PORT}/dir"),
        ),
        (
            "EDGE_LB_ACME_ACCOUNT_KEY",
            work.path().join("acct.key").to_string_lossy().to_string(),
        ),
        (
            "EDGE_LB_ACME_CONTACT",
            "mailto:ops@example.test".to_string(),
        ),
        ("EDGE_LB_DNS_BIND", format!("127.0.0.1:{DNS_PORT}")),
        ("EDGE_LB_DNS_NS", "ns1.tascloud.app".to_string()),
        ("EDGE_LB_EDGE_V4", "127.0.0.1".to_string()),
        ("EDGE_LB_CAA_ISSUERS", "pebble.letsencrypt.org".to_string()),
        // The root-program watch and CT monitor fetch the real CCADB / Chrome / crt.sh endpoints:
        // off here so the test stays hermetic (they are exercised in `hosting_ca_pebble.rs`'s sibling
        // tests in `transport` with fakes).
        ("EDGE_LB_CA_TRUST", "off".to_string()),
        ("EDGE_LB_CT_MONITOR", "off".to_string()),
        ("EDGE_LB_SWEEP_INTERVAL_SECS", "1".to_string()),
        ("EDGE_LB_RENEW_INTERVAL_SECS", "2".to_string()),
        // The health checks ask the edge's own authority, as a monitor inside the platform would.
        ("EDGE_LB_HEALTH_RESOLVERS", format!("127.0.0.1:{DNS_PORT}")),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let cfg = HostingConfig::from_lookup(|k| env.get(k).cloned())
        .unwrap()
        .unwrap();
    assert_eq!(cfg.proof, ProofPolicy::TxtOnly);

    let state = EdgeState::ephemeral();
    state
        .apply(&Op::AdmitManaged {
            tenant_id: "acme".into(),
            tunnel_id: "t".into(),
            apex: "tascloud.app".into(),
            label: Some("mine".into()),
            dialkey: None,
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        })
        .await
        .unwrap();
    let hosting = hosting::start(cfg, state.clone())
        .await
        .expect("hosting starts against Pebble");
    // The `:80` listener the CA's HTTP-01 validation reaches (main.rs mounts the same router on :80).
    {
        let app = edge_lb::http01::router(state.clone());
        tokio::spawn(
            async move { servelet_h1::serve(&format!("127.0.0.1:{HTTP01_PORT}"), app).await },
        );
    }

    // Every apex wildcard is issued by the engine's first pass.
    let wanted: Vec<String> = transport::acme_renew::apex_wildcards();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = state.cert_status();
        let have: Vec<_> = wanted
            .iter()
            .filter(|w| {
                status
                    .iter()
                    .any(|s| &s.name == *w && s.not_after.is_some())
            })
            .collect();
        if have.len() == wanted.len() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "only {}/{} wildcards issued; statuses: {:?}\n--- pebble ---\n{}",
            have.len(),
            wanted.len(),
            status,
            std::fs::read_to_string(work.path().join("pebble.log")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    for s in state.cert_status() {
        assert_eq!(s.consecutive_failures, 0, "{s:?}");
        assert!(
            s.seconds_left.unwrap() > 80 * 86_400,
            "a fresh 90-day certificate: {s:?}"
        );
    }
    assert!(state.have_cert("mine.tascloud.app"));
    // The managed name became servable once its wildcard landed (certificate gate, not just state).
    let decision = state.decide("mine.tascloud.app", None).await.unwrap();
    assert_eq!(
        decision,
        transport::edge_proxy::Decision::NoConnector,
        "cert present; only the connector is missing"
    );
    // Durable: a fresh store over the same directory sees every certificate.
    let reopened = transport::acme_renew::FileCertStore::open(work.path().join("certs")).unwrap();
    for w in &wanted {
        assert!(
            transport::edge::CertSource::cert_for(&reopened, w).is_some(),
            "{w} not on disk"
        );
    }

    // The SNI front presents the Pebble-issued certificate, verified against Pebble's root.
    let root_pem = {
        let ca = reqwest::Certificate::from_pem(minica.as_bytes()).unwrap();
        let c = reqwest::Client::builder()
            .add_root_certificate(ca)
            .build()
            .unwrap();
        c.get(format!("https://localhost:{MGMT_PORT}/roots/0"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };
    let edge = EdgeLb::build_with_state(Vec::new(), state.clone()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(front::serve(
        listener,
        edge.clone(),
        router(edge),
        hosting.server_config.clone(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    for der in transport::pem::blocks(&root_pem, "CERTIFICATE") {
        roots
            .add(rustls::pki_types::CertificateDer::from(der))
            .unwrap();
    }
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        transport::edge_proxy::sni::provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("mine.tascloud.app".to_string()).unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("handshake against the Pebble-issued wildcard");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: mine.tascloud.app\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 502"),
        "cert OK, connector offline => 502 from the edge, got: {text}"
    );

    // The bare apex is on the same certificate (the wildcard order also names the apex): the
    // client verifies the SAN for "tascloud.app" itself, so this fails if the apex was omitted.
    assert!(state.have_cert("tascloud.app"));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("tascloud.app".to_string()).unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("handshake for the bare apex against the Pebble-issued certificate");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: tascloud.app\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 404"),
        "apex is served TLS-wise; nothing is routed there yet"
    );

    // ═══ a custom hostname: issue, release, revoke ═══════════════════════════════════════════
    let mgmt = {
        let ca = reqwest::Certificate::from_pem(minica.as_bytes()).unwrap();
        reqwest::Client::builder()
            .add_root_certificate(ca)
            .build()
            .unwrap()
    };
    let custom_op = |op: &str| match op {
        "admit" => Op::AdmitCustom {
            tenant_id: "acme".into(),
            tunnel_id: "t".into(),
            fqdn: "app.acme.com.au".into(),
            cname_target: "mine.tascloud.app".into(),
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        },
        _ => Op::Release {
            tenant_id: "acme".into(),
            fqdn: "app.acme.com.au".into(),
        },
    };
    state.apply(&custom_op("admit")).await.unwrap();
    state
        .apply(&Op::Validated {
            fqdn: "app.acme.com.au".into(),
        })
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    let custom_chain = loop {
        if let Some(m) =
            transport::edge::CertSource::cert_for(hosting.store.as_ref(), "app.acme.com.au")
        {
            break m.chain_pem;
        }
        assert!(
            Instant::now() < deadline,
            "no certificate for the custom name; statuses {:?}\n--- pebble ---\n{}",
            state.cert_status(),
            std::fs::read_to_string(work.path().join("pebble.log")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let wildcard_chain =
        transport::edge::CertSource::cert_for(hosting.store.as_ref(), "*.tascloud.app")
            .unwrap()
            .chain_pem;
    assert_eq!(pebble_status(&mgmt, &custom_chain).await.0, "Valid");
    assert_eq!(pebble_status(&mgmt, &wildcard_chain).await.0, "Valid");
    assert!(state.have_cert("app.acme.com.au"));

    // Release: the dedicated certificate leaves service at once and is queued; the worker has the CA revoke it.
    let released = state.apply(&custom_op("release")).await.unwrap();
    assert_eq!(released["certificate_revocation"], "queued", "{released}");
    assert!(
        transport::edge::CertSource::cert_for(hosting.store.as_ref(), "app.acme.com.au").is_none(),
        "no longer served"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (status, reason) = pebble_status(&mgmt, &custom_chain).await;
        if status == "Revoked" {
            assert_eq!(reason, Some(5), "cessationOfOperation");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Pebble never saw the revocation; queue: {:?}",
            hosting.revocations.status()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !hosting.revocations.is_empty() {
        assert!(
            Instant::now() < deadline,
            "revoked at the CA but still queued: {:?}",
            hosting.revocations.status()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        std::fs::read_dir(work.path().join("certs/revocations"))
            .unwrap()
            .next()
            .is_none(),
        "the key was destroyed with the entry"
    );
    // The wildcard every managed hostname shares was not touched.
    assert_eq!(pebble_status(&mgmt, &wildcard_chain).await.0, "Valid");
    assert!(
        transport::edge::CertSource::cert_for(hosting.store.as_ref(), "*.tascloud.app").is_some()
    );
    let released_managed = state
        .apply(&Op::Release {
            tenant_id: "acme".into(),
            fqdn: "mine.tascloud.app".into(),
        })
        .await
        .unwrap();
    assert!(released_managed.get("certificate_revocation").is_none());
    assert_eq!(
        pebble_status(&mgmt, &wildcard_chain).await.0,
        "Valid",
        "releasing a managed hostname never revokes the shared wildcard"
    );

    // ═══ telemetry ═══════════════════════════════════════════════════════════════════════════
    let deadline = Instant::now() + Duration::from_secs(60);
    while state.metrics.health().is_none() {
        assert!(
            Instant::now() < deadline,
            "the DNS health run never completed"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let text = edge_lb::metrics::render_prometheus(&state, &[], now);
    assert!(
        text.contains(r#"edge_lb_cert_seconds_left{name="*.tascloud.app"}"#),
        "{text}"
    );
    assert!(text.contains("edge_lb_revocation_pending 0"), "{text}");
    assert!(
        text.contains("edge_lb_dns_health_runs_total 1")
            || text.contains("edge_lb_dns_health_runs_total 2"),
        "{text}"
    );
    assert!(
        text.contains("edge_lb_acme_account_key_age_seconds"),
        "{text}"
    );
    let health = edge_lb::metrics::health_json(&state, &[], now);
    assert_eq!(
        health["dns"]["zones"].as_array().unwrap().len(),
        transport::edge::APEXES.len(),
        "{health}"
    );
    assert_eq!(health["revocation"]["pending"], 0);
}
