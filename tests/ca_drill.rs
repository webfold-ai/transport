//! The **CA-distrust drill**, end to end against two independent ACME CAs (two Pebble instances,
//! each with its own root and intermediate): what the operator runbook
//! (`docs/runbooks/edge-ca-distrust.md`) does, run by the real renewal engine over the real
//! multi-CA issuer, the real native DNS server and real TLS handshakes.
//!
//! * `the_drill_moves_every_certificate_to_the_standby_updates_caa_and_revokes_the_old_ones` --
//!   issue everything from CA A, publish CAA for both CAs, flip A to `distrusted`, republish CAA
//!   without A, re-issue every certificate from B, revoke A's at A, then check with clients that
//!   trust only B / only A.
//! * `a_trust_watch_verdict_alone_drives_the_same_migration` -- no policy edit: the watch finds
//!   A's root missing from both programs' data, the issuer escalates after two agreeing
//!   evaluations, and the engine moves the fleet.
//! * `a_dead_primary_is_failed_over_within_the_order_and_then_benched` -- A is killed; the order
//!   that hit it is completed by B, alerted and journaled, and A is benched after repeated failures.
//! * `a_ca_that_is_not_on_the_list_is_never_contacted` -- the allow-list gate against a live CA.
//!
//! Pebble does **not** check CAA, so what CAA would have stopped is verified at the record level
//! (what our authoritative server serves, judged by `dns_health::evaluate_caa`), not by a CA
//! refusing. Skipped unless `PEBBLE_BIN` and `PEBBLE_SRC` are set (see `tests/pebble.rs`).
#![cfg(feature = "native")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::acme::{AcmeError, ClientOptions, Http01Responder};
use transport::acme_renew::{
    cert_validity, CertIssuer, CertStore, FileCertStore, RenewalEngine, RenewalPolicy,
    RevocationQueue,
};
use transport::ca_policy::{CaPolicy, CaStatus};
use transport::ca_resilience::{AcmeCaConnector, AlertKind, MultiCaIssuer, StatePaths};
use transport::ca_trust::{evaluate, ChromeAnchor, ChromeStore, MozillaRoot, MozillaStore};
use transport::dns::{Flags, Message, Name, Question, RData, Record, RecordType, ResponseCode};
use transport::dns_health::{
    evaluate_caa, parse_caa_issue, CaaObservation, CaaRecord, CaaScope, CaaTarget,
};
use transport::edge::{CertSource, EdgeRegistry, HostnameState, Route, APEXES};
use transport::edge_dns::{
    serve_tcp_with, serve_udp_with, Dns01Authority, DnsHandler, ZoneAuthority, ZoneConfig,
};
use transport::edge_proxy::EdgeCertResolver;

#[derive(Clone, Copy)]
struct Ports {
    acme: u16,
    mgmt: u16,
    http01: u16,
    tls: u16,
}

const PORTS_A: Ports = Ports {
    acme: 14600,
    mgmt: 14601,
    http01: 15602,
    tls: 15601,
};
const PORTS_B: Ports = Ports {
    acme: 14610,
    mgmt: 14611,
    http01: 15612,
    tls: 15611,
};
const PORTS_A2: Ports = Ports {
    acme: 14620,
    mgmt: 14621,
    http01: 15622,
    tls: 15621,
};
const PORTS_B2: Ports = Ports {
    acme: 14630,
    mgmt: 14631,
    http01: 15632,
    tls: 15631,
};
const PORTS_A3: Ports = Ports {
    acme: 14640,
    mgmt: 14641,
    http01: 15642,
    tls: 15641,
};
const PORTS_B3: Ports = Ports {
    acme: 14650,
    mgmt: 14651,
    http01: 15652,
    tls: 15651,
};

/// The tests share `SSL_CERT_FILE` (read once, process-wide, by the HTTP client's TLS config).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Pebble(Child);
impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Default, Clone)]
struct Http01 {
    tokens: Arc<Mutex<HashMap<String, String>>>,
}

impl Http01Responder for Http01 {
    fn serve_token<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
    ) -> transport::BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async move {
            self.tokens
                .lock()
                .unwrap()
                .insert(token.to_string(), key_authorization.to_string());
            Ok(())
        })
    }
    fn remove_token<'a>(&'a self, token: &'a str) -> transport::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.tokens.lock().unwrap().remove(token);
        })
    }
}

async fn serve_http01(responder: Http01, port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind http-01 port");
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        let r = responder.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            let token = path
                .strip_prefix("/.well-known/acme-challenge/")
                .unwrap_or("");
            let body = r.tokens.lock().unwrap().get(token).cloned();
            let reply = match body {
                Some(b) => format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            };
            let _ = s.write_all(reply.as_bytes()).await;
        });
    }
}

struct TestDns {
    authority: Arc<tokio::sync::Mutex<ZoneAuthority>>,
    registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
}

impl DnsHandler for TestDns {
    fn handle<'a>(&'a self, query: &'a [u8]) -> transport::BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let q = Message::from_bytes(query).ok()?;
            let question = q.questions.first().cloned()?;
            let name = question
                .name
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if APEXES
                .iter()
                .any(|a| name == a.zone || name.ends_with(&format!(".{}", a.zone)))
            {
                let reg = self.registry.lock().await;
                return self.authority.lock().await.answer(query, &reg);
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
                    RData::A("127.0.0.1".parse().unwrap()),
                ));
            }
            Some(r.to_bytes())
        })
    }
}

async fn serve_dns(
    authority: Arc<tokio::sync::Mutex<ZoneAuthority>>,
    registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
) -> SocketAddr {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handler: Arc<dyn DnsHandler> = Arc::new(TestDns {
        authority,
        registry,
    });
    let bind: &'static str = Box::leak(addr.to_string().into_boxed_str());
    tokio::spawn(serve_udp_with(bind, handler.clone()));
    tokio::spawn(serve_tcp_with(bind, handler));
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

fn route(tenant: &str, tunnel: &str) -> Route {
    Route {
        tenant_id: tenant.into(),
        tunnel_id: tunnel.into(),
        peer: transport::dialkey::peer_id(tunnel),
        origin_port: 8080,
    }
}

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "cadrill-{tag}-{}",
        transport::entropy::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn pebble_paths() -> Option<(OsString, PathBuf)> {
    let (Some(bin), Some(src)) = (
        std::env::var_os("PEBBLE_BIN"),
        std::env::var_os("PEBBLE_SRC"),
    ) else {
        eprintln!(
            "SKIPPED: set PEBBLE_BIN and PEBBLE_SRC (see tests/pebble.rs) to run the CA drill"
        );
        return None;
    };
    Some((bin, PathBuf::from(src)))
}

async fn start_pebble(
    bin: &OsString,
    src: &Path,
    work: &Path,
    dns_addr: SocketAddr,
    ports: Ports,
    tag: &str,
) -> Pebble {
    let ca_cert = std::fs::read_to_string(src.join("test/certs/pebble.minica.pem")).unwrap();
    std::fs::write(work.join("minica.pem"), &ca_cert).unwrap();
    // Both Pebbles' listeners present certificates from the same test CA, which is the one the
    // ACME client trusts (rustls-native-certs honours SSL_CERT_FILE). Their *issuing* CAs are
    // independent and generated fresh at start.
    std::env::set_var("SSL_CERT_FILE", work.join("minica.pem"));
    let config = format!(
        r#"{{"pebble":{{"listenAddress":"127.0.0.1:{acme}","managementListenAddress":"127.0.0.1:{mgmt}",
"certificate":"{c}","privateKey":"{k}","httpPort":{http01},"tlsPort":{tls},"ocspResponderURL":"",
"externalAccountBindingRequired":false,"externalAccountMACKeys":{{}},
"retryAfter":{{"authz":1,"order":1}},"keyAlgorithm":"ecdsa",
"profiles":{{"default":{{"description":"default","validityPeriod":7776000}}}}}}}}"#,
        acme = ports.acme,
        mgmt = ports.mgmt,
        http01 = ports.http01,
        tls = ports.tls,
        c = src.join("test/certs/localhost/cert.pem").display(),
        k = src.join("test/certs/localhost/key.pem").display(),
    );
    std::fs::write(work.join(format!("pebble-{tag}.json")), config).unwrap();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join(format!("pebble-{tag}.log")))
        .map_or_else(|_| Stdio::null(), Stdio::from);
    let log2 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join(format!("pebble-{tag}.log")))
        .map_or_else(|_| Stdio::null(), Stdio::from);
    let pebble = Pebble(
        Command::new(bin)
            .args([
                "-config",
                work.join(format!("pebble-{tag}.json")).to_str().unwrap(),
                "-dnsserver",
                &dns_addr.to_string(),
            ])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            .env("PEBBLE_WFE_AUTHZREUSE", "0")
            .stdout(log)
            .stderr(log2)
            .spawn()
            .expect("spawn pebble"),
    );
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ports.acme))
            .await
            .is_ok()
        {
            return pebble;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("pebble {tag} did not start");
}

async fn mgmt_pem(port: u16, path: &str) -> Vec<u8> {
    let pem = transport::http_client::Client::new()
        .get(format!("https://localhost:{port}/{path}"))
        .send()
        .await
        .expect("management GET")
        .text()
        .await
        .expect("body");
    transport::pem::blocks(&pem, "CERTIFICATE")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no certificate at {path}: {pem}"))
}

async fn pebble_cert_status(mgmt_port: u16, chain_pem: &str) -> (String, Option<u64>) {
    let id = transport::acme::ari_cert_id(chain_pem).expect("an ARI id has the serial");
    let serial_b64 = id
        .split_once('.')
        .unwrap()
        .1
        .replace('-', "+")
        .replace('_', "/");
    let serial = transport::pem::base64_decode(&serial_b64).unwrap();
    let hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
    let body = transport::http_client::Client::new()
        .get(format!(
            "https://localhost:{mgmt_port}/cert-status-by-serial/{hex}"
        ))
        .send()
        .await
        .expect("cert-status")
        .text()
        .await
        .expect("status body");
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("status {hex}: {e}: {body}"));
    (
        v["Status"].as_str().unwrap().to_string(),
        v["Reason"].as_u64(),
    )
}

fn leaf_issuer_cn(chain_pem: &str) -> String {
    let der = transport::x509::leaf_der(chain_pem).unwrap();
    transport::x509::parse(&der).unwrap().issuer_cn().unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Everything the drills share: two Pebbles, our DNS, a registry needing a wildcard and a custom name.
struct Drill {
    registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
    authority: Arc<tokio::sync::Mutex<ZoneAuthority>>,
    work: PathBuf,
    http01: Http01,
    ports: (Ports, Ports),
    root_a: Vec<u8>,
    root_b: Vec<u8>,
    intermediate_cn_a: String,
    intermediate_cn_b: String,
    a: Option<Pebble>,
    _b: Pebble,
}

impl Drill {
    async fn start(tag: &str, ports_a: Ports, ports_b: Ports) -> Option<Drill> {
        let (bin, src) = pebble_paths()?;
        let registry = Arc::new(tokio::sync::Mutex::new(EdgeRegistry::new(
            b"drill-secret-0123456789abcdef0123456789".to_vec(),
        )));
        {
            let mut reg = registry.lock().await;
            let apex = APEXES.iter().find(|a| a.zone == "tascloud.app").unwrap();
            reg.claim_managed_label(apex, "mine", route("acme", "t0"))
                .unwrap();
            reg.add_custom("app.acme.com.au", "mine.tascloud.app", route("acme", "t1"))
                .unwrap();
            reg.record_probe("app.acme.com.au", true, 5).unwrap();
            assert_eq!(
                reg.lookup("app.acme.com.au").unwrap().state,
                HostnameState::PendingCert
            );
        }
        let authority = Arc::new(tokio::sync::Mutex::new(ZoneAuthority::new(
            Vec::new(),
            vec!["127.0.0.1".parse().unwrap()],
            vec![],
        )));
        let dns_addr = serve_dns(authority.clone(), registry.clone()).await;
        let work = scratch(tag);
        let a = start_pebble(&bin, &src, &work, dns_addr, ports_a, "a").await;
        let b = start_pebble(&bin, &src, &work, dns_addr, ports_b, "b").await;
        let http01 = Http01::default();
        tokio::spawn(serve_http01(http01.clone(), ports_a.http01));
        tokio::spawn(serve_http01(http01.clone(), ports_b.http01));
        let (root_a, root_b) = (
            mgmt_pem(ports_a.mgmt, "roots/0").await,
            mgmt_pem(ports_b.mgmt, "roots/0").await,
        );
        let cn = |der: Vec<u8>| transport::x509::parse(&der).unwrap().subject_cn().unwrap();
        let (intermediate_cn_a, intermediate_cn_b) = (
            cn(mgmt_pem(ports_a.mgmt, "intermediates/0").await),
            cn(mgmt_pem(ports_b.mgmt, "intermediates/0").await),
        );
        assert_ne!(intermediate_cn_a, intermediate_cn_b, "two independent CAs");
        assert_ne!(root_a, root_b);
        Some(Drill {
            registry,
            authority,
            work,
            http01,
            ports: (ports_a, ports_b),
            root_a,
            root_b,
            intermediate_cn_a,
            intermediate_cn_b,
            a: Some(a),
            _b: b,
        })
    }

    /// The policy file text: A active, B standby, exactly as an operator would write it, with each
    /// CA's real root fingerprint and issuer name.
    fn policy_json(&self, a_status: &str, b_status: &str) -> String {
        serde_json::json!({
            "version": 1,
            "failover": {"fail_threshold": 3, "bench_secs": 3600, "bench_max_secs": 86400, "max_failovers_per_day": 50},
            "cas": [
                {"name": "pebble-a", "directory_url": format!("https://localhost:{}/dir", self.ports.0.acme), "caa_domain": "ca-a.example.test",
                 "status": a_status, "account_key_file": self.work.join("a.key").to_str().unwrap(), "contact": "ops@example.test",
                 "issuer_names": [self.intermediate_cn_a], "trust_roots": [{"sha256": transport::x509::fingerprint_hex(&self.root_a)}]},
                {"name": "pebble-b", "directory_url": format!("https://localhost:{}/dir", self.ports.1.acme), "caa_domain": "ca-b.example.test",
                 "status": b_status, "account_key_file": self.work.join("b.key").to_str().unwrap(), "contact": "ops@example.test",
                 "issuer_names": [self.intermediate_cn_b], "trust_roots": [{"sha256": transport::x509::fingerprint_hex(&self.root_b)}]}
            ]
        })
        .to_string()
    }

    fn multi_issuer(&self, policy: CaPolicy) -> Arc<MultiCaIssuer> {
        let connector = Arc::new(AcmeCaConnector {
            dns01: Arc::new(Dns01Authority(self.authority.clone())),
            http01: Some(Arc::new(self.http01.clone())),
            options: ClientOptions::default(),
            default_contact: None,
        });
        let state = self.work.join("state");
        std::fs::create_dir_all(&state).unwrap();
        Arc::new(MultiCaIssuer::new(policy, connector, &StatePaths::in_dir(&state)).unwrap())
    }

    /// Publish `issuer`'s CAA plan on every zone and return the records as DNS serves them.
    async fn publish_caa(&self, issuer: &MultiCaIssuer) -> Vec<(String, String)> {
        let plan = issuer.caa_plan(&["dns-01".to_string()]);
        let zones = APEXES
            .iter()
            .map(|a| {
                ZoneConfig::new(a.zone, vec![format!("ns1.{}", a.zone)])
                    .with_caa_records(plan.records.clone())
            })
            .collect();
        *self.authority.lock().await =
            ZoneAuthority::new(zones, vec!["127.0.0.1".parse().unwrap()], vec![]);
        self.served_caa().await
    }

    async fn served_caa(&self) -> Vec<(String, String)> {
        let reg = self.registry.lock().await;
        let q = Message {
            id: 9,
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
        let reply = Message::from_bytes(
            &self
                .authority
                .lock()
                .await
                .answer(&q.to_bytes(), &reg)
                .unwrap(),
        )
        .unwrap();
        reply
            .answers
            .iter()
            .filter_map(|r| {
                if let RData::Caa { tag, value, .. } = &r.data {
                    Some((tag.clone(), String::from_utf8_lossy(value).into_owned()))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// A client that trusts exactly `root` and nothing else, doing a real TLS handshake with `sni`
/// against the certificate the edge would present from `store`.
async fn handshake(store: Arc<FileCertStore>, root: &[u8], sni: &str) -> Result<(), String> {
    let resolver = Arc::new(EdgeCertResolver::new(store as Arc<dyn CertSource>));
    let acceptor = tokio_rustls::TlsAcceptor::from(resolver.server_config().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(root.to_vec()))
        .unwrap();
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let (c, s) = tokio::io::duplex(32 * 1024);
    let server = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let r = connector
        .connect(name, c)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let _ = server.await;
    r
}

fn caa_findings(
    plan_policy: &transport::dns_health::CaaPolicy,
    served: &[(String, String)],
    wildcard: bool,
) -> Vec<transport::dns_health::Finding> {
    let records: Vec<CaaRecord> = served
        .iter()
        .map(|(tag, value)| CaaRecord {
            flags: 0,
            tag: tag.clone(),
            value: value.as_bytes().to_vec(),
        })
        .collect();
    let obs = CaaObservation {
        name: "tascloud.app".into(),
        lookup_failed: false,
        found_at: Some("tascloud.app".into()),
        records,
    };
    evaluate_caa(
        &obs,
        &CaaTarget {
            name: "tascloud.app".into(),
            wildcard,
            scope: CaaScope::Own,
        },
        plan_policy,
    )
}

fn engine(
    store: &Arc<FileCertStore>,
    issuer: Arc<MultiCaIssuer>,
    queue: &Arc<RevocationQueue>,
) -> RenewalEngine<FileCertStore, Arc<MultiCaIssuer>> {
    RenewalEngine::new(store.clone(), issuer, RenewalPolicy::default())
        .with_revocations(queue.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_drill_moves_every_certificate_to_the_standby_updates_caa_and_revokes_the_old_ones() {
    let _serial = SERIAL.lock().await;
    let Some(d) = Drill::start("drill", PORTS_A, PORTS_B).await else {
        return;
    };
    let issuer = d.multi_issuer(CaPolicy::from_json(&d.policy_json("active", "standby")).unwrap());
    assert!(
        CaPolicy::from_json(&d.policy_json("active", "standby"))
            .unwrap()
            .lint()
            .iter()
            .all(|f| f.severity <= transport::ca_policy::Severity::Info),
        "the drill's policy is clean"
    );

    // ── 0. Both CAs have an account before either is needed, and DNS authorises both.
    let failed = issuer.connect_all().await;
    assert!(failed.is_empty(), "{failed:?}");
    let accounts = issuer.accounts();
    assert_eq!(accounts.len(), 2);
    let served = d.publish_caa(&issuer).await;
    let issue: Vec<&String> = served
        .iter()
        .filter(|(t, _)| t == "issue")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(issue.len(), 2, "{served:?}");
    assert!(
        issue[0].starts_with("ca-a.example.test; accounturi=")
            && issue[0].contains(&accounts["pebble-a"]),
        "{issue:?}"
    );
    assert!(
        issue[1].starts_with("ca-b.example.test; accounturi=")
            && issue[1].contains(&accounts["pebble-b"]),
        "{issue:?}"
    );
    let health_policy = issuer
        .caa_plan(&["dns-01".to_string()])
        .health_policy(Some("http-01"));
    assert_eq!(
        caa_findings(&health_policy, &served, true),
        vec![],
        "the published CAA is exactly the union, each CA on its own account"
    );

    // ── 1. Everything is issued by A.
    let store = Arc::new(FileCertStore::open(d.work.join("certs")).unwrap());
    let queue = Arc::new(RevocationQueue::open(d.work.join("certs").join("revocations")).unwrap());
    let mut eng = engine(&store, issuer.clone(), &queue);
    let report = eng.run_once(now(), &d.registry).await;
    assert!(report.failed.is_empty(), "{report:?}");
    let mut issued = report.issued.clone();
    issued.sort();
    assert_eq!(
        issued,
        vec!["*.tascloud.app".to_string(), "app.acme.com.au".to_string()]
    );
    let old: Vec<(String, transport::edge::CertMaterial)> = issued
        .iter()
        .map(|n| (n.clone(), store.cert_for(n).unwrap()))
        .collect();
    for (name, m) in &old {
        assert_eq!(issuer.ca_name(m).as_deref(), Some("pebble-a"), "{name}");
        assert_eq!(
            leaf_issuer_cn(&m.chain_pem),
            d.intermediate_cn_a,
            "{name}: really issued by Pebble A's intermediate"
        );
        assert_eq!(
            pebble_cert_status(d.ports.0.mgmt, &m.chain_pem).await.0,
            "Valid"
        );
    }
    assert_ne!(
        old[0].1.key_pem, old[1].1.key_pem,
        "distinct keys per certificate"
    );
    // A real client that trusts only A accepts them; one that trusts only B does not.
    assert!(
        handshake(store.clone(), &d.root_a, "amber-lyrebird.tascloud.app")
            .await
            .is_ok()
    );
    assert!(
        handshake(store.clone(), &d.root_b, "amber-lyrebird.tascloud.app")
            .await
            .is_err(),
        "B's root does not vouch for A's certificates"
    );
    // The registry's waiting custom hostname was activated by the first issuance.
    assert_eq!(
        d.registry
            .lock()
            .await
            .lookup("app.acme.com.au")
            .unwrap()
            .state,
        HostnameState::Active
    );
    // A pass later nothing is due.
    assert!(eng
        .run_once(now() + 60, &d.registry)
        .await
        .issued
        .is_empty());

    // ── 2. The incident: A is distrusted. The operator edits the policy file and it is reloaded.
    issuer.set_policy(CaPolicy::from_json(&d.policy_json("distrusted", "active")).unwrap());
    assert_eq!(issuer.effective("pebble-a"), CaStatus::Distrusted);
    // 2a. CAA is republished from the new plan: A is gone, B remains (and still needs no change for the switch).
    let served = d.publish_caa(&issuer).await;
    let issue: Vec<&String> = served
        .iter()
        .filter(|(t, _)| t == "issue")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(issue.len(), 1, "{served:?}");
    assert!(
        issue[0].starts_with("ca-b.example.test; accounturi=")
            && !served.iter().any(|(_, v)| v.contains("ca-a.example.test")),
        "{served:?}"
    );
    let health_policy = issuer
        .caa_plan(&["dns-01".to_string()])
        .health_policy(Some("http-01"));
    assert_eq!(caa_findings(&health_policy, &served, true), vec![]);
    // The health check would flag a stale record that still authorises A.
    let stale = vec![
        (
            "issue".to_string(),
            format!(
                "ca-a.example.test; accounturi={}; validationmethods=dns-01",
                accounts["pebble-a"]
            ),
        ),
        ("issue".to_string(), issue[0].clone()),
    ];
    assert!(
        caa_findings(&health_policy, &stale, true)
            .iter()
            .any(|f| f.kind.as_str() == "caa_unknown_ca"),
        "the stale record is a finding"
    );

    // ── 3. The engine re-issues everything from B, first, in one pass, and revokes A's certificates at A.
    let t = now() + 3600;
    let report = eng.run_once(t, &d.registry).await;
    assert!(report.failed.is_empty(), "{report:?}");
    let mut moved = report.issued.clone();
    moved.sort();
    assert_eq!(
        moved, issued,
        "every certificate from the distrusted CA was replaced"
    );
    assert_eq!(report.revoked.len(), 2, "{report:?}");
    assert!(queue.is_empty(), "the revocations landed");
    for (name, m) in &old {
        let new = store.cert_for(name).unwrap();
        assert_eq!(issuer.ca_name(&new).as_deref(), Some("pebble-b"), "{name}");
        assert_eq!(leaf_issuer_cn(&new.chain_pem), d.intermediate_cn_b);
        assert_ne!(
            new.key_pem, m.key_pem,
            "{name}: the replacement has a new key"
        );
        assert!(cert_validity(&new.chain_pem).is_some());
        // Pebble A forgot the old one with reason cessationOfOperation (5); Pebble B holds the new one as valid.
        assert_eq!(
            pebble_cert_status(d.ports.0.mgmt, &m.chain_pem).await,
            ("Revoked".to_string(), Some(5)),
            "{name}"
        );
        assert_eq!(
            pebble_cert_status(d.ports.1.mgmt, &new.chain_pem).await.0,
            "Valid"
        );
    }

    // ── 4. Verify with real clients: a client that trusts only B accepts every name now; one that
    //      trusts only the old root A does not (it would see a B certificate).
    for sni in ["amber-lyrebird.tascloud.app", "app.acme.com.au"] {
        assert!(
            handshake(store.clone(), &d.root_b, sni).await.is_ok(),
            "{sni}: a client trusting only B accepts the new certificate"
        );
        assert!(
            handshake(store.clone(), &d.root_a, sni).await.is_err(),
            "{sni}: a client trusting only A no longer sees an A certificate"
        );
    }
    // The audit trail names what happened.
    let j = issuer.journal().recent(200);
    assert!(
        j.iter().any(|e| e.event == "policy_reloaded")
            && j.iter()
                .filter(|e| e.event == "issued" && e.ca == "pebble-b")
                .count()
                == 2,
        "{j:?}"
    );
    // And nothing is left to do.
    assert!(eng.run_once(t + 60, &d.registry).await.issued.is_empty());
    let _ = std::fs::remove_dir_all(&d.work);
}

fn program_data_without(root_a: &[u8], root_b: &[u8]) -> (MozillaStore, ChromeStore) {
    // Both root programs list B's root and have dropped A's.
    let sha_b = transport::x509::fingerprint_hex(root_b);
    let _ = root_a;
    (
        MozillaStore {
            roots: vec![MozillaRoot {
                owner: "B".into(),
                name: "Pebble Root B".into(),
                sha256: sha_b.clone(),
                websites: true,
                tls_distrust_after: None,
            }],
        },
        ChromeStore {
            version_major: Some(43),
            anchors: vec![ChromeAnchor {
                sha256: sha_b,
                label: None,
                tls_distrust_after: None,
                name_constrained: false,
            }],
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trust_watch_verdict_alone_drives_the_same_migration() {
    let _serial = SERIAL.lock().await;
    let Some(d) = Drill::start("watch", PORTS_A2, PORTS_B2).await else {
        return;
    };
    let issuer = d.multi_issuer(CaPolicy::from_json(&d.policy_json("active", "standby")).unwrap());
    issuer.connect_all().await;
    d.publish_caa(&issuer).await;
    let store = Arc::new(FileCertStore::open(d.work.join("certs")).unwrap());
    let queue = Arc::new(RevocationQueue::open(d.work.join("certs").join("revocations")).unwrap());
    let mut eng = engine(&store, issuer.clone(), &queue);
    let report = eng.run_once(now(), &d.registry).await;
    assert_eq!(report.issued.len(), 2, "{report:?}");
    assert!(report
        .issued
        .iter()
        .all(|n| issuer.ca_name(&store.cert_for(n).unwrap()).as_deref() == Some("pebble-a")));

    // The programs' data now lacks A's root. One evaluation is not enough to move the fleet...
    let policy = issuer.policy();
    let (moz, chr) = program_data_without(&d.root_a, &d.root_b);
    let verdicts = evaluate(&policy, Ok(&moz), Ok(&chr), &[], now());
    assert!(
        matches!(&verdicts[0].combined, transport::ca_trust::TrustVerdict::Distrusted { reason } if reason.contains("not in Mozilla's root store")),
        "{verdicts:?}"
    );
    assert_eq!(
        verdicts[1].combined,
        transport::ca_trust::TrustVerdict::Trusted
    );
    assert!(issuer.apply_trust(&verdicts).is_empty());
    assert!(
        eng.run_once(now() + 10, &d.registry)
            .await
            .issued
            .is_empty(),
        "a single evaluation changes nothing"
    );
    // ...a failed fetch in between changes nothing, and the second agreeing evaluation does.
    let unknown = evaluate(&policy, Err("503"), Err("503"), &[], now());
    assert!(issuer.apply_trust(&unknown).is_empty());
    assert_eq!(issuer.apply_trust(&verdicts), vec!["pebble-a".to_string()]);
    assert_eq!(issuer.effective("pebble-a"), CaStatus::Distrusted);
    assert!(issuer.alerts().count(AlertKind::StandingChanged) >= 1);

    let report = eng.run_once(now() + 3600, &d.registry).await;
    assert!(
        report.failed.is_empty() && report.issued.len() == 2 && report.revoked.len() == 2,
        "{report:?}"
    );
    for n in &report.issued {
        assert_eq!(
            issuer.ca_name(&store.cert_for(n).unwrap()).as_deref(),
            Some("pebble-b")
        );
    }
    assert!(handshake(store.clone(), &d.root_b, "app.acme.com.au")
        .await
        .is_ok());
    assert!(handshake(store.clone(), &d.root_a, "app.acme.com.au")
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&d.work);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_primary_is_failed_over_within_the_order_and_then_benched() {
    let _serial = SERIAL.lock().await;
    let Some(mut d) = Drill::start("dead", PORTS_A3, PORTS_B3).await else {
        return;
    };
    let issuer = d.multi_issuer(CaPolicy::from_json(&d.policy_json("active", "standby")).unwrap());
    assert!(issuer.connect_all().await.is_empty());
    d.publish_caa(&issuer).await;
    // CA A dies after our accounts are registered (its connection is cached, its port now refuses).
    drop(d.a.take());
    tokio::time::sleep(Duration::from_millis(300)).await;

    let store = Arc::new(FileCertStore::open(d.work.join("certs")).unwrap());
    let queue = Arc::new(RevocationQueue::open(d.work.join("certs").join("revocations")).unwrap());
    let mut eng = engine(&store, issuer.clone(), &queue);
    let report = eng.run_once(now(), &d.registry).await;
    assert!(
        report.failed.is_empty() && report.issued.len() == 2,
        "the standby completed the orders the dead primary could not: {report:?}"
    );
    for n in &report.issued {
        let m = store.cert_for(n).unwrap();
        assert_eq!(issuer.ca_name(&m).as_deref(), Some("pebble-b"));
        assert_eq!(leaf_issuer_cn(&m.chain_pem), d.intermediate_cn_b);
    }
    let alerts = issuer.alerts();
    assert_eq!(
        alerts.count(AlertKind::Failover),
        2,
        "one fall back per order: {:?}",
        alerts.recent()
    );
    let j = issuer.journal().recent(100);
    assert!(
        j.iter()
            .filter(|e| e.event == "failure" && e.ca == "pebble-a")
            .count()
            == 2
            && j.iter()
                .any(|e| e.event == "failover" && e.ca == "pebble-b"),
        "{j:?}"
    );

    // More orders while A is down: the third consecutive failure benches it, after which B is simply tried first.
    let mut third = None;
    for i in 0..3 {
        third = Some(issuer.issue(&format!("extra{i}.example.com.au")).await);
    }
    let _ = third;
    let views = issuer.views();
    assert!(views[0].benched_until > now(), "{views:?}");
    assert_eq!(alerts.count(AlertKind::CaBenched), 1);
    let failovers_before = alerts.count(AlertKind::Failover);
    let m = issuer.issue("after-bench.example.com.au").await;
    // (HTTP-01 for an unrouted name still validates against our permissive test DNS.)
    assert!(m.is_ok(), "{m:?}");
    assert_eq!(
        alerts.count(AlertKind::Failover),
        failovers_before,
        "a benched CA is not retried, so no fall back is needed"
    );
    let _ = std::fs::remove_dir_all(&d.work);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ca_that_is_not_on_the_list_is_never_contacted() {
    let _serial = SERIAL.lock().await;
    let Some(d) = Drill::start("gate", PORTS_A3, PORTS_B3).await else {
        return;
    };
    // The policy lists only B. A is a perfectly good CA with a working ACME endpoint -- but not approved.
    let mut v: serde_json::Value =
        serde_json::from_str(&d.policy_json("active", "active")).unwrap();
    v["cas"].as_array_mut().unwrap().remove(0);
    let policy = CaPolicy::from_json(&v.to_string()).unwrap();
    let a_url = format!("https://localhost:{}/dir", d.ports.0.acme);
    let e = policy.admit(&a_url, &HashMap::new()).unwrap_err();
    assert!(e.0.contains("not on the CA allow-list"), "{e}");
    let issuer = d.multi_issuer(policy);
    let m = issuer
        .issue("gate.example.com.au")
        .await
        .expect("B is on the list");
    assert_eq!(leaf_issuer_cn(&m.chain_pem), d.intermediate_cn_b);
    // Pebble A saw no request at all: its management API has issued nothing.
    let a_cert_count = transport::http_client::Client::new()
        .get(format!("https://localhost:{}/roots/0", d.ports.0.mgmt))
        .send()
        .await
        .is_ok();
    assert!(
        a_cert_count,
        "A is up (so not contacting it was the gate's doing, not an outage)"
    );
    let log = std::fs::read_to_string(d.work.join("pebble-a.log")).unwrap_or_default();
    assert!(
        !log.contains("/sa/") && !log.contains("acct") && !log.contains("new-order"),
        "Pebble A was never asked for an account or an order:\n{log}"
    );
    // Positive control: the same check does see a request when one is made, so the absence above means something.
    let _ = transport::acme::AcmeClient::new(
        &a_url,
        transport::acme::AccountKey::generate().unwrap(),
        None,
    )
    .await
    .expect("A works when asked directly");
    let log = std::fs::read_to_string(d.work.join("pebble-a.log")).unwrap_or_default();
    assert!(
        log.contains("acct") || log.contains("/sa/") || log.contains("account"),
        "the control request left a mark in Pebble's log:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&d.work);
}

#[test]
fn caa_values_parse_back_into_the_union_the_plan_describes() {
    // Pure sanity on the record format the drill relies on (no Pebble needed).
    let v = parse_caa_issue(
        b"ca-a.example.test; accounturi=https://a/acct/1; validationmethods=dns-01",
    )
    .unwrap();
    assert_eq!(v.issuer, "ca-a.example.test");
    assert_eq!(v.params.len(), 2);
}
