//! The edge's **CA-distrust drill**, end to end through `hosting::start` against two independent
//! ACME CAs (two **Pebble** instances, each with its own root and intermediate).
//!
//! Boots the edge exactly as `main` does, with an `EDGE_LB_CA_POLICY` file naming CA A `active` and
//! CA B `standby`, and proves what the runbook (`docs/runbooks/edge-ca-distrust.md`) relies on:
//!
//! 1. every apex wildcard is issued by A (the active CA), is attributed to it in the status, and the
//!    authoritative DNS serves CAA for **both** CAs (the union of active and standby);
//! 2. a policy file that is not valid is refused and the previous policy stays in force (counted);
//! 3. editing the file to mark A `distrusted` is picked up while the edge runs: A drops out of CAA,
//!    every certificate is re-issued by B, the superseded certificates are revoked at A, and the metrics follow.
//!
//! Pebble does not check CAA, so what CAA would have stopped is verified at the record level (what
//! our authoritative server serves). The root-program watch and CT monitor are switched off here:
//! they fetch the real CCADB/Chrome/crt.sh endpoints, and that logic is tested hermetically in
//! `transport/tests/ca_drill.rs` and the crate's unit tests.
//!
//! Skipped unless `PEBBLE_BIN` and `PEBBLE_SRC` are set (see `transport/tests/pebble.rs`).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "test code: deterministic assertions on spawned servers; skip notice goes to stderr"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use edge_lb::edge_state::EdgeState;
use edge_lb::hosting::{self, HostingConfig};

const A_ACME: u16 = 14700;
const A_MGMT: u16 = 14701;
const B_ACME: u16 = 14710;
const B_MGMT: u16 = 14711;
const DNS_PORT: u16 = 25360;
/// Pebble's resolver: forwards the platform apexes to the edge's authority above.
const DNS_FRONT_PORT: u16 = 25361;

struct Pebble(Child);
impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The DNS both Pebbles ask: the platform apexes go to the edge's own authority.
struct FrontDns;

impl transport::edge_dns::DnsHandler for FrontDns {
    fn handle<'a>(&'a self, query: &'a [u8]) -> transport::BoxFuture<'a, Option<Vec<u8>>> {
        use transport::dns::{Flags, Message, Question, ResponseCode};
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
                return forward(query).await;
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
            Some(r.to_bytes())
        })
    }
}

async fn forward(query: &[u8]) -> Option<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    sock.send_to(query, ("127.0.0.1", DNS_PORT)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.get(..n).map(<[u8]>::to_vec)
}

async fn start_pebble(
    bin: &std::ffi::OsString,
    src: &Path,
    work: &Path,
    tag: &str,
    acme: u16,
    mgmt: u16,
    http01: u16,
    tls: u16,
) -> Pebble {
    let config = format!(
        r#"{{"pebble":{{"listenAddress":"127.0.0.1:{acme}","managementListenAddress":"127.0.0.1:{mgmt}",
"certificate":"{c}","privateKey":"{k}","httpPort":{http01},"tlsPort":{tls},"ocspResponderURL":"",
"externalAccountBindingRequired":false,"retryAfter":{{"authz":1,"order":1}},"keyAlgorithm":"ecdsa",
"profiles":{{"default":{{"description":"default","validityPeriod":7776000}}}}}}}}"#,
        c = src.join("test/certs/localhost/cert.pem").display(),
        k = src.join("test/certs/localhost/key.pem").display(),
    );
    std::fs::write(work.join(format!("pebble-{tag}.json")), config).unwrap();
    let log = std::fs::File::create(work.join(format!("pebble-{tag}.log"))).unwrap();
    let pebble = Pebble(
        Command::new(bin)
            .args([
                "-config",
                work.join(format!("pebble-{tag}.json")).to_str().unwrap(),
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
        if tokio::net::TcpStream::connect(("127.0.0.1", acme))
            .await
            .is_ok()
        {
            return pebble;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("pebble {tag} did not start");
}

/// Pebble's own verdict on a certificate (`/cert-status-by-serial/<hex>` on its management port).
async fn pebble_status(
    mgmt: &reqwest::Client,
    port: u16,
    chain_pem: &str,
) -> (String, Option<u64>) {
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
            "https://localhost:{port}/cert-status-by-serial/{hex}"
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

async fn mgmt_pem(mgmt: &reqwest::Client, port: u16, path: &str) -> Vec<u8> {
    let pem = mgmt
        .get(format!("https://localhost:{port}/{path}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    transport::pem::blocks(&pem, "CERTIFICATE")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no certificate at {path}: {pem}"))
}

fn issuer_cn(chain_pem: &str) -> String {
    let der = transport::x509::leaf_der(chain_pem).unwrap();
    transport::x509::parse(&der).unwrap().issuer_cn().unwrap()
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// The CAA records our authoritative server serves for `tascloud.app`, as `(tag, value)`.
async fn served_caa() -> Vec<(String, String)> {
    use transport::dns::{Flags, Message, Name, Question, RData, RecordType};
    let q = Message {
        id: 7,
        flags: Flags {
            recursion_desired: true,
            ..Flags::default()
        },
        questions: vec![Question::new(
            Name::from_ascii("tascloud.app.").unwrap(),
            RecordType::Caa,
        )],
        ..Message::default()
    };
    // Over TCP: the full CAA set does not fit a 512-byte UDP answer (the server rightly truncates).
    let reply = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let wire = q.to_bytes();
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", DNS_PORT))
            .await
            .unwrap();
        tcp.write_all(&u16::try_from(wire.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&wire).await.unwrap();
        let mut len = [0u8; 2];
        tcp.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        tcp.read_exact(&mut buf).await.unwrap();
        buf
    };
    let parsed = Message::from_bytes(&reply).unwrap();
    assert!(!parsed.flags.truncated, "a TCP answer is never truncated");
    parsed
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Caa { tag, value, .. } => {
                Some((tag.clone(), String::from_utf8_lossy(value).into_owned()))
            }
            _ => None,
        })
        .collect()
}

fn caa_mentions(caa: &[(String, String)], domain: &str) -> bool {
    caa.iter()
        .any(|(_, v)| v.split(';').next().is_some_and(|d| d.trim() == domain))
}

/// Replace the policy file the way an operator's tooling does: write beside it, then rename.
fn write_policy(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn metrics_text(state: &Arc<EdgeState>) -> String {
    edge_lb::metrics::render_prometheus(state, &[], now())
}

async fn wait_for(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_edge_moves_every_certificate_to_the_standby_when_the_active_ca_is_distrusted() {
    let (Some(bin), Some(src)) = (
        std::env::var_os("PEBBLE_BIN"),
        std::env::var_os("PEBBLE_SRC"),
    ) else {
        eprintln!("SKIPPED: set PEBBLE_BIN and PEBBLE_SRC to run the Pebble CA-distrust test");
        return;
    };
    let src = PathBuf::from(src);
    let work = tempfile::TempDir::new().unwrap();
    let minica = std::fs::read_to_string(src.join("test/certs/pebble.minica.pem")).unwrap();
    std::fs::write(work.path().join("minica.pem"), &minica).unwrap();
    std::env::set_var("SSL_CERT_FILE", work.path().join("minica.pem"));

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
    let _a = start_pebble(&bin, &src, work.path(), "a", A_ACME, A_MGMT, 15702, 15701).await;
    let _b = start_pebble(&bin, &src, work.path(), "b", B_ACME, B_MGMT, 15712, 15711).await;

    let mgmt = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(minica.as_bytes()).unwrap())
        .build()
        .unwrap();
    let (root_a, root_b) = (
        mgmt_pem(&mgmt, A_MGMT, "roots/0").await,
        mgmt_pem(&mgmt, B_MGMT, "roots/0").await,
    );
    let cn = |der: Vec<u8>| transport::x509::parse(&der).unwrap().subject_cn().unwrap();
    let (cn_a, cn_b) = (
        cn(mgmt_pem(&mgmt, A_MGMT, "intermediates/0").await),
        cn(mgmt_pem(&mgmt, B_MGMT, "intermediates/0").await),
    );
    assert_ne!(cn_a, cn_b, "two independent CAs");

    let policy_path = work.path().join("ca-policy.json");
    let policy = |a_status: &str| {
        serde_json::json!({
            "version": 1,
            "failover": {"fail_threshold": 3, "bench_secs": 3600, "bench_max_secs": 86400, "max_failovers_per_day": 50},
            "cas": [
                {"name": "pebble-a", "directory_url": format!("https://localhost:{A_ACME}/dir"),
                 "caa_domain": "ca-a.example.test", "status": a_status,
                 "account_key_file": work.path().join("a.key").to_str().unwrap(),
                 "contact": "ops@example.test", "issuer_names": [cn_a],
                 "trust_roots": [{"sha256": transport::x509::fingerprint_hex(&root_a)}]},
                {"name": "pebble-b", "directory_url": format!("https://localhost:{B_ACME}/dir"),
                 "caa_domain": "ca-b.example.test", "status": "standby",
                 "account_key_file": work.path().join("b.key").to_str().unwrap(),
                 "contact": "ops@example.test", "issuer_names": [cn_b],
                 "trust_roots": [{"sha256": transport::x509::fingerprint_hex(&root_b)}]}
            ]
        })
        .to_string()
    };
    write_policy(&policy_path, &policy("active"));

    let env: std::collections::HashMap<String, String> = [
        (
            "EDGE_LB_CERT_DIR",
            work.path().join("certs").to_string_lossy().to_string(),
        ),
        (
            "EDGE_LB_CA_POLICY",
            policy_path.to_string_lossy().to_string(),
        ),
        ("EDGE_LB_CA_POLL_SECS", "1".to_string()),
        ("EDGE_LB_CA_TRUST", "off".to_string()),
        ("EDGE_LB_CT_MONITOR", "off".to_string()),
        ("EDGE_LB_DNS_BIND", format!("127.0.0.1:{DNS_PORT}")),
        ("EDGE_LB_DNS_NS", "ns1.tascloud.app".to_string()),
        ("EDGE_LB_EDGE_V4", "127.0.0.1".to_string()),
        ("EDGE_LB_SWEEP_INTERVAL_SECS", "1".to_string()),
        ("EDGE_LB_RENEW_INTERVAL_SECS", "2".to_string()),
        ("EDGE_LB_HEALTH_RESOLVERS", format!("127.0.0.1:{DNS_PORT}")),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let cfg = HostingConfig::from_lookup(|k| env.get(k).cloned())
        .unwrap()
        .unwrap();

    let state = EdgeState::ephemeral();
    let hosting = hosting::start(cfg, state.clone())
        .await
        .expect("hosting starts against two Pebbles");
    let wanted: Vec<String> = transport::acme_renew::apex_wildcards();

    // ═══ 1. A issues everything; CAA names both CAs ═════════════════════════════════════════
    wait_for("every wildcard issued", 120, || {
        let status = state.cert_status();
        wanted
            .iter()
            .all(|w| status.iter().any(|s| &s.name == w && s.not_after.is_some()))
    })
    .await;
    let mut old_chains = Vec::new();
    for w in &wanted {
        let held = transport::edge::CertSource::cert_for(hosting.store.as_ref(), w).unwrap();
        assert_eq!(
            issuer_cn(&held.chain_pem),
            cn_a,
            "{w} issued by the active CA"
        );
        assert_eq!(
            pebble_status(&mgmt, A_MGMT, &held.chain_pem).await.0,
            "Valid"
        );
        old_chains.push((w.clone(), held.chain_pem));
    }
    for s in state.cert_status() {
        assert_eq!(
            s.ca.as_deref(),
            Some("pebble-a"),
            "attributed to the issuing CA: {s:?}"
        );
        assert_eq!(s.migration, transport::acme_renew::Migration::None, "{s:?}");
    }
    let caa = served_caa().await;
    assert!(caa_mentions(&caa, "ca-a.example.test"), "{caa:?}");
    assert!(
        caa_mentions(&caa, "ca-b.example.test"),
        "the standby may issue too: {caa:?}"
    );
    assert!(
        caa.iter()
            .any(|(t, v)| t == "issuewild" && v.contains("ca-b.example.test")),
        "issuewild is published for the wildcards: {caa:?}"
    );
    assert!(
        caa.iter()
            .all(|(_, v)| !v.contains("ca-b.example.test") || v.contains("accounturi=")),
        "every entry is bound to our account at that CA: {caa:?}"
    );
    let m = metrics_text(&state);
    assert!(
        m.contains(r#"edge_lb_ca_status{ca="pebble-a",configured="active",effective="active"} 1"#),
        "{m}"
    );
    assert!(
        m.contains(
            r#"edge_lb_ca_status{ca="pebble-b",configured="standby",effective="standby"} 1"#
        ),
        "{m}"
    );
    assert!(m.contains("edge_lb_rng_selfcheck_ok 1"), "{m}");
    let health = edge_lb::metrics::health_json(&state, &[], now());
    assert_eq!(health["ca"]["cas"].as_array().unwrap().len(), 2, "{health}");

    // ═══ 2. a broken policy file is refused; the previous one stays in force ════════════════
    write_policy(&policy_path, "{ this is not a policy");
    wait_for("the broken file to be refused", 15, || {
        metrics_text(&state).contains("edge_lb_ca_policy_reload_errors_total 1")
    })
    .await;
    assert!(
        metrics_text(&state).contains(
            r#"edge_lb_ca_status{ca="pebble-a",configured="active",effective="active"} 1"#
        ),
        "a refused reload changes nothing"
    );

    // ═══ 3. A is distrusted: CAA drops it, B re-issues, A revokes ═══
    write_policy(&policy_path, &policy("distrusted"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let m = metrics_text(&state);
        if m.contains(r#"edge_lb_ca_status{ca="pebble-a",configured="distrusted""#) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the edited policy was never picked up:\n{m}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let status = state.cert_status();
        let moved = wanted.iter().all(|w| {
            status.iter().any(|s| {
                &s.name == w
                    && s.ca.as_deref() == Some("pebble-b")
                    && s.migration == transport::acme_renew::Migration::None
                    && s.consecutive_failures == 0
            })
        });
        if moved {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "certificates never moved to the standby; statuses {status:?}\n--- pebble A ---\n{}\n--- pebble B ---\n{}",
            std::fs::read_to_string(work.path().join("pebble-a.log")).unwrap_or_default(),
            std::fs::read_to_string(work.path().join("pebble-b.log")).unwrap_or_default(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Nothing is left waiting under A once the pass is over (the pending-migration gauge is
    // refreshed by the engine at the end of each pass).
    let h = edge_lb::metrics::health_json(&state, &[], now());
    assert!(
        !h["ca"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "ca_certificates_awaiting_migration"),
        "{h}"
    );
    for w in &wanted {
        let held = transport::edge::CertSource::cert_for(hosting.store.as_ref(), w).unwrap();
        assert_eq!(
            issuer_cn(&held.chain_pem),
            cn_b,
            "{w} re-issued by the standby"
        );
        assert_eq!(
            pebble_status(&mgmt, B_MGMT, &held.chain_pem).await.0,
            "Valid"
        );
    }
    // The superseded certificates are revoked at the CA that issued them, distrusted or not.
    let deadline = Instant::now() + Duration::from_secs(90);
    for (w, chain) in &old_chains {
        loop {
            let (status, reason) = pebble_status(&mgmt, A_MGMT, chain).await;
            if status == "Revoked" {
                assert_eq!(reason, Some(5), "{w}: cessationOfOperation (superseded)");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{w}: the superseded certificate is still {status} at A; queue: {:?}",
                hosting.revocations.status()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    // CAA no longer lets A issue; B alone remains.
    let mut caa = served_caa().await;
    let deadline = Instant::now() + Duration::from_secs(15);
    while caa_mentions(&caa, "ca-a.example.test") {
        assert!(
            Instant::now() < deadline,
            "CAA still lets the distrusted CA issue: {caa:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        caa = served_caa().await;
    }
    assert!(caa_mentions(&caa, "ca-b.example.test"), "{caa:?}");

    // The telemetry agrees.
    let m = metrics_text(&state);
    assert!(
        m.contains(
            r#"edge_lb_ca_status{ca="pebble-a",configured="distrusted",effective="distrusted"} 1"#
        ),
        "{m}"
    );
    assert!(m.contains(r#"edge_lb_ca_eligible{ca="pebble-a"} 0"#), "{m}");
    assert!(m.contains(r#"edge_lb_ca_eligible{ca="pebble-b"} 1"#), "{m}");
    assert!(
        m.contains(&format!(
            r#"edge_lb_ca_certificates{{ca="pebble-b"}} {}"#,
            wanted.len()
        )),
        "every certificate is now under B:\n{m}"
    );
    assert!(
        m.contains(r#"edge_lb_ca_certificates{ca="pebble-a"} 0"#),
        "{m}"
    );
    // The key of each re-issued certificate is new: no renewal reuses the previous key.
    for (w, old) in &old_chains {
        let new = transport::edge::CertSource::cert_for(hosting.store.as_ref(), w).unwrap();
        assert_ne!(
            transport::x509::leaf_spki(old),
            transport::x509::leaf_spki(&new.chain_pem),
            "{w}: the key was reused across the move"
        );
    }
    // Everything on disk is private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["a.key", "b.key"] {
            let mode = std::fs::metadata(work.path().join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
    }
}
