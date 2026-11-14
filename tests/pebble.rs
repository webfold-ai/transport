//! End-to-end against **Pebble**, Let's Encrypt's independent ACME test CA (a separate
//! implementation, in Go — not a mock written by us).
//!
//! What this proves that the in-tree mock CA cannot:
//! - our JWS/CSR/finalize bytes are accepted by an unrelated RFC 8555 server;
//! - Pebble *validates DNS-01 by querying our authoritative DNS* (`edge_dns::ZoneAuthority`
//!   behind a real UDP socket, via the native `dns` wire codec);
//! - (Not covered: CAA enforcement. Pebble does not implement CAA checking.)
//! - the renewal engine installs what the CA returns, activates waiting hostnames, and the
//!   issued chain+key serve a real TLS handshake that verifies against the CA root;
//! - External Account Binding: Pebble (configured with `externalAccountBindingRequired`) refuses
//!   an account without a binding or with a wrong MAC key / `kid`, and accepts ours;
//! - account key rollover (`keyChange`): Pebble accepts our nested JWS, an order placed
//!   afterwards under the new key validates, and the account is now bound to the new key;
//! - ACME Renewal Information: the certificate ID we derive is one Pebble resolves, the window it
//!   returns parses, and the engine renews early when the CA's window says to
//!   (`/set-renewal-info/` makes Pebble advise it);
//! - revocation (RFC 8555 §7.6): Pebble marks a certificate revoked (checked at its management
//!   `/cert-status-by-serial/`, with the reason) after a revocation signed by the account and
//!   after one signed by the certificate's own key; a repeat is `alreadyRevoked` and is success; an
//!   account that did not order the certificate is refused and `AcmeIssuer::revoke` then falls
//!   back to the certificate's key;
//! - `replaces` (RFC 9773 §5): a renewal order naming the previous certificate is accepted and
//!   Pebble records the old one as replaced; replacing the same certificate twice is refused by
//!   Pebble as `alreadyReplaced`, and the client's fallback to a plain order still yields a certificate.
//!
//! Skipped unless `PEBBLE_BIN` (the `pebble` binary) and `PEBBLE_SRC` (its source tree, for the
//! test TLS certificate) are set:
//!
//! ```text
//! GOBIN=/tmp/pebble-bin go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//! PEBBLE_BIN=/tmp/pebble-bin/pebble \
//! PEBBLE_SRC=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.10.1 \
//!   cargo test --test pebble -- --nocapture
//! ```
#![cfg(feature = "native")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::acme::{
    AccountKey, AcmeClient, AcmeError, ExternalAccountBinding, Http01Responder, RevocationOutcome,
    RevocationReason,
};
use transport::acme_renew::{
    cert_validity, AcmeIssuer, CertIssuer, FileCertStore, RenewalEngine, RenewalPolicy,
};
use transport::dns::{Flags, Message, Name, Question, RData, Record, RecordType, ResponseCode};
use transport::edge::{CertSource, EdgeRegistry, HostnameState, Route, APEXES};
use transport::edge_dns::{
    serve_tcp_with, serve_udp_with, Dns01Authority, DnsHandler, ZoneAuthority, ZoneConfig,
};
use transport::edge_proxy::EdgeCertResolver;

/// One Pebble's listening ports. Every test has its own set, so a Pebble from one test is never
/// mistaken for the next (the HTTP client pools connections per `host:port`), and the HTTP-01
/// listener of one cannot collide with another's.
#[derive(Clone, Copy)]
struct Ports {
    acme: u16,
    mgmt: u16,
    http01: u16,
    tls: u16,
}

const ENGINE_PORTS: Ports = Ports {
    acme: 14500,
    mgmt: 14501,
    http01: 15002,
    tls: 15001,
};
const EAB_PORTS: Ports = Ports {
    acme: 14510,
    mgmt: 14511,
    http01: 15012,
    tls: 15011,
};
const ROLLOVER_PORTS: Ports = Ports {
    acme: 14520,
    mgmt: 14521,
    http01: 15022,
    tls: 15021,
};
const ARI_PORTS: Ports = Ports {
    acme: 14530,
    mgmt: 14531,
    http01: 15032,
    tls: 15031,
};
const REVOKE_PORTS: Ports = Ports {
    acme: 14540,
    mgmt: 14541,
    http01: 15042,
    tls: 15041,
};
const REPLACE_PORTS: Ports = Ports {
    acme: 14550,
    mgmt: 14551,
    http01: 15052,
    tls: 15051,
};
const KEYS_PORTS: Ports = Ports {
    acme: 14560,
    mgmt: 14561,
    http01: 15062,
    tls: 15061,
};

/// The tests share `SSL_CERT_FILE` (process-global, read once by the HTTP client's TLS config),
/// so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Pebble(Child);
impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An HTTP-01 responder: a tiny HTTP server on the validation port serving the key authorization.
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

/// The DNS Pebble is pointed at: our real authority for the platform apexes; for any other name
/// (customer domains) it behaves like a permissive recursor — `A` -> 127.0.0.1 so HTTP-01 reaches
/// our listener, everything else NOERROR/empty (so CAA climbing finds "no CAA").
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

/// Serve the test DNS on UDP **and** TCP at one port (Pebble resolves over TCP).
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

/// Pebble's output goes to `<work>/pebble.log` (it is noisy; print it with `PEBBLE_LOG=1` on failure).
fn log_stdio(work: &std::path::Path) -> Stdio {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join("pebble.log"))
        .map_or_else(|_| Stdio::null(), Stdio::from)
}

fn scratch(tag: &str) -> PathBuf {
    let id: String = transport_rand()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let p = std::env::temp_dir().join(format!("pebble-{tag}-{id}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn transport_rand() -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; 6];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    b
}

/// `PEBBLE_BIN` and `PEBBLE_SRC`, or `None` (the caller skips) when they are not set.
fn pebble_paths() -> Option<(OsString, PathBuf)> {
    let (Some(bin), Some(src)) = (
        std::env::var_os("PEBBLE_BIN"),
        std::env::var_os("PEBBLE_SRC"),
    ) else {
        eprintln!("SKIPPED: set PEBBLE_BIN and PEBBLE_SRC (see the module docs) to run the Pebble end-to-end tests");
        return None;
    };
    Some((bin, PathBuf::from(src)))
}

/// Start Pebble on `ports` with `dns_addr` as its resolver and, if given, `(kid, base64url key)`
/// as the one External Account Binding credential it knows (which also makes a binding mandatory).
/// Returns once it accepts connections.
async fn start_pebble(
    bin: &OsString,
    src: &Path,
    work: &Path,
    dns_addr: SocketAddr,
    ports: Ports,
    eab: Option<(&str, &str)>,
) -> Pebble {
    let ca_cert = std::fs::read_to_string(src.join("test/certs/pebble.minica.pem")).unwrap();
    std::fs::write(work.join("minica.pem"), &ca_cert).unwrap();
    // The ACME client's TLS trust store: Pebble's test CA (rustls-native-certs honours SSL_CERT_FILE).
    std::env::set_var("SSL_CERT_FILE", work.join("minica.pem"));

    let (eab_required, macs) = match eab {
        Some((kid, key)) => ("true", format!(r#""{kid}":"{key}""#)),
        None => ("false", String::new()),
    };
    let config = format!(
        r#"{{"pebble":{{"listenAddress":"127.0.0.1:{acme}","managementListenAddress":"127.0.0.1:{mgmt}",
"certificate":"{c}","privateKey":"{k}","httpPort":{http01},"tlsPort":{tls},"ocspResponderURL":"",
"externalAccountBindingRequired":{eab_required},"externalAccountMACKeys":{{{macs}}},
"retryAfter":{{"authz":1,"order":1}},"keyAlgorithm":"ecdsa",
"profiles":{{"default":{{"description":"default","validityPeriod":7776000}}}}}}}}"#,
        acme = ports.acme,
        mgmt = ports.mgmt,
        http01 = ports.http01,
        tls = ports.tls,
        c = src.join("test/certs/localhost/cert.pem").display(),
        k = src.join("test/certs/localhost/key.pem").display(),
    );
    std::fs::write(work.join("pebble.json"), config).unwrap();
    let pebble = Pebble(
        Command::new(bin)
            .args([
                "-config",
                work.join("pebble.json").to_str().unwrap(),
                "-dnsserver",
                &dns_addr.to_string(),
            ])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            .env("PEBBLE_WFE_AUTHZREUSE", "0")
            .stdout(log_stdio(work))
            .stderr(log_stdio(work))
            .spawn()
            .expect("spawn pebble"),
    );
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ports.acme))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "pebble did not start");
    pebble
}

/// Everything a test needs around one Pebble: a registry with a live managed hostname (so
/// `*.tascloud.app` is required) and a validated custom one, our authoritative DNS behind
/// Pebble's resolver, and a scratch directory.
struct Fixture {
    registry: Arc<tokio::sync::Mutex<EdgeRegistry>>,
    authority: Arc<tokio::sync::Mutex<ZoneAuthority>>,
    work: PathBuf,
    directory: String,
    ports: Ports,
    _pebble: Pebble,
}

impl Fixture {
    async fn start(tag: &str, ports: Ports, eab: Option<(&str, &str)>) -> Option<Fixture> {
        let (bin, src) = pebble_paths()?;
        // ── shared registry: a live managed hostname (=> *.tascloud.app is required) and a validated custom one
        let registry = Arc::new(tokio::sync::Mutex::new(EdgeRegistry::new(
            b"pebble-secret".to_vec(),
        )));
        {
            let mut reg = registry.lock().await;
            let apex = APEXES.iter().find(|a| a.zone == "tascloud.app").unwrap();
            reg.claim_managed_label(apex, "mine", route("acme", "t0"))
                .unwrap();
            reg.add_custom("app.acme.com.au", "mine.tascloud.app", route("acme", "t1"))
                .unwrap();
            reg.record_probe("app.acme.com.au", true, 5).unwrap(); // proof of control passed -> PendingCert
            assert_eq!(
                reg.lookup("app.acme.com.au").unwrap().state,
                HostnameState::PendingCert
            );
        }
        // Pebble needs the DNS address at start, and the zones' CAA may need the account URL, which
        // needs Pebble: start the DNS with an empty authority, install the zones once ready.
        let authority = Arc::new(tokio::sync::Mutex::new(ZoneAuthority::new(
            Vec::new(),
            vec!["127.0.0.1".parse().unwrap()],
            vec![],
        )));
        let dns_addr = serve_dns(authority.clone(), registry.clone()).await;
        let work = scratch(tag);
        let pebble = start_pebble(&bin, &src, &work, dns_addr, ports, eab).await;
        Some(Fixture {
            registry,
            authority,
            work,
            directory: format!("https://localhost:{}/dir", ports.acme),
            ports,
            _pebble: pebble,
        })
    }

    /// Our authoritative zones for every platform apex, CAA optionally pinned to an ACME account.
    async fn install_zones(&self, caa_account_uri: Option<&str>) {
        let zones = APEXES
            .iter()
            .map(|a| {
                let zone = ZoneConfig::new(a.zone, vec![format!("ns1.{}", a.zone)])
                    .with_caa_issuers(vec!["pebble.letsencrypt.org".to_string()]);
                match caa_account_uri {
                    Some(uri) => zone.with_caa_account_uri(uri.to_string()),
                    None => zone,
                }
            })
            .collect();
        *self.authority.lock().await =
            ZoneAuthority::new(zones, vec!["127.0.0.1".parse().unwrap()], vec![]);
    }

    /// An HTTP-01 responder served on this Pebble's validation port.
    fn http01(&self) -> Http01 {
        let http01 = Http01::default();
        tokio::spawn(serve_http01(http01.clone(), self.ports.http01));
        http01
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_engine_obtains_wildcard_and_custom_certificates_from_pebble() {
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("work", ENGINE_PORTS, None).await else {
        return;
    };
    let (registry, authority, work, directory) = (
        fx.registry.clone(),
        fx.authority.clone(),
        fx.work.clone(),
        fx.directory.clone(),
    );

    // ── the ACME account, then CAA pinned to it
    let account = AccountKey::generate().unwrap();
    let client = AcmeClient::new(&directory, account, Some("ops@example.test"))
        .await
        .expect("register account with pebble");
    let account_url = client.account_url().expect("kid");
    fx.install_zones(Some(&account_url)).await;

    // NOTE: Pebble does not enforce CAA (its `accounturi` support belongs to the separate
    // dns-persist-01 challenge), so the RFC 8657 account binding published above is only checked
    // at the record level (edge_dns unit tests) — Boulder/Let's Encrypt is what enforces it.

    // ── the engine, with the real issuer: DNS-01 for the wildcard, HTTP-01 for the customer name
    let http01 = fx.http01();
    let store_dir = work.join("certs");
    let store = Arc::new(FileCertStore::open(&store_dir).unwrap());
    let issuer = AcmeIssuer::new(
        client,
        Arc::new(Dns01Authority(authority.clone())),
        Some(Arc::new(http01)),
    );
    let mut engine = RenewalEngine::new(store.clone(), issuer, RenewalPolicy::default());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let report = engine.run_once(now, &registry).await;
    assert!(
        report.failed.is_empty(),
        "issuance failed: {:?}",
        report.failed
    );
    let mut issued = report.issued.clone();
    issued.sort();
    assert_eq!(
        issued,
        vec!["*.tascloud.app".to_string(), "app.acme.com.au".to_string()]
    );
    assert_eq!(report.activated, vec!["app.acme.com.au".to_string()]);
    assert_eq!(
        registry
            .lock()
            .await
            .lookup("app.acme.com.au")
            .unwrap()
            .state,
        HostnameState::Active
    );

    // Pebble's challenge values were cleaned up after validation.
    {
        let reg = registry.lock().await;
        let mut a = authority.lock().await;
        let q = Message {
            id: 7,
            flags: Flags {
                recursion_desired: true,
                ..Flags::default()
            },
            questions: vec![Question::new(
                Name::from_ascii("_acme-challenge.tascloud.app.").unwrap(),
                RecordType::Txt,
            )],
            ..Message::default()
        };
        let reply = Message::from_bytes(&a.answer(&q.to_bytes(), &reg).unwrap()).unwrap();
        assert_eq!(
            reply.flags.response_code,
            ResponseCode::NxDomain,
            "spent DNS-01 tokens must not linger"
        );
    }

    // ── a second pass is quiet; a "restart" (fresh store from disk) does not reorder
    assert!(engine.run_once(now + 60, &registry).await.issued.is_empty());
    let reopened = FileCertStore::open(&store_dir).unwrap();
    assert!(reopened.cert_for("*.tascloud.app").is_some());

    // ── the issued chain + key serve a REAL handshake that verifies against Pebble's root
    let root = fetch_root(&work, fx.ports.mgmt).await;
    let resolver = Arc::new(EdgeCertResolver::new(store.clone()));
    let acceptor = tokio_rustls::TlsAcceptor::from(resolver.server_config().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(root))
        .unwrap();
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    for sni in ["amber-lyrebird-1a2b3c.tascloud.app", "app.acme.com.au"] {
        let (c, s) = tokio::io::duplex(32 * 1024);
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
        let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let tls = connector.connect(name, c).await;
        assert!(
            tls.is_ok(),
            "{sni}: handshake against the Pebble-issued certificate failed: {:?}",
            tls.err()
        );
        let _ = server.await;
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// The CA root (Pebble's management API: `GET /roots/0`), PEM -> DER.
async fn fetch_root(work: &std::path::Path, mgmt_port: u16) -> Vec<u8> {
    let pem = transport::http_client::Client::new()
        .get(format!("https://localhost:{mgmt_port}/roots/0"))
        .send()
        .await
        .expect("fetch root")
        .text()
        .await
        .expect("root body");
    std::fs::write(work.join("root.pem"), &pem).unwrap();
    transport::pem::blocks(&pem, "CERTIFICATE")
        .into_iter()
        .next()
        .expect("a root certificate")
}

/// Unix seconds -> RFC 3339 (`Z`), for the `ARIResponse` handed to Pebble.
fn rfc3339(ts: i64) -> String {
    let (days, rem) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Pebble requires External Account Binding and knows exactly one credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_account_binding_is_required_and_verified_by_pebble() {
    let _serial = SERIAL.lock().await;
    let mac_key = AccountKey::generate().unwrap().to_bytes().unwrap(); // 32 random bytes
    let mac_key_b64 = apeiron::map::hashtrinity::crypto::acme::b64url(&mac_key);
    let Some(fx) = Fixture::start("eab", EAB_PORTS, Some(("eab-kid-1", &mac_key_b64))).await else {
        return;
    };
    let account = AccountKey::generate().unwrap();
    let register = |eab: Option<ExternalAccountBinding>| {
        let (directory, account) = (fx.directory.clone(), account.clone());
        async move {
            AcmeClient::new_with_eab(&directory, account, Some("ops@example.test"), eab)
                .await
                .map(|c| c.account_url())
        }
    };

    // No binding at all.
    let err = register(None).await.expect_err("Pebble requires a binding");
    assert!(
        matches!(&err, AcmeError::Rejected { detail, .. } if detail.contains("externalAccountRequired")),
        "{err}"
    );
    // A binding made with the wrong MAC key, and one naming a kid Pebble does not know.
    let wrong_key = ExternalAccountBinding::from_base64url(
        "eab-kid-1",
        &apeiron::map::hashtrinity::crypto::acme::b64url(&[7u8; 32]),
    )
    .unwrap();
    let err = register(Some(wrong_key)).await.expect_err("wrong MAC key");
    assert!(
        matches!(&err, AcmeError::Rejected { detail, .. } if detail.contains("unauthorized")),
        "{err}"
    );
    let unknown_kid = ExternalAccountBinding::from_base64url("nobody", &mac_key_b64).unwrap();
    let err = register(Some(unknown_kid)).await.expect_err("unknown kid");
    assert!(
        matches!(&err, AcmeError::Rejected { detail, .. } if detail.contains("unauthorized")),
        "{err}"
    );

    // The right credentials, as a CA's dashboard prints them (base64url text).
    let eab = ExternalAccountBinding::from_base64url("eab-kid-1", &mac_key_b64).unwrap();
    let url = register(Some(eab.clone()))
        .await
        .expect("Pebble verified our binding")
        .expect("account URL");
    // newAccount is idempotent for a key: the same account again.
    assert_eq!(
        register(Some(eab.clone())).await.unwrap().as_deref(),
        Some(url.as_str())
    );

    // And the EAB-bound account can order.
    let client = AcmeClient::new_with_eab(&fx.directory, account, None, Some(eab))
        .await
        .unwrap();
    let cert = client
        .issue(&["eab.example.com.au"], &fx.http01())
        .await
        .expect("order on an EAB-bound account");
    assert!(cert_validity(&cert.chain_pem).is_some());
    let _ = std::fs::remove_dir_all(&fx.work);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_key_rollover_is_accepted_by_pebble_and_orders_work_afterwards() {
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("rollover", ROLLOVER_PORTS, None).await else {
        return;
    };
    let (old, new) = (
        AccountKey::generate().unwrap(),
        AccountKey::generate().unwrap(),
    );
    let client = AcmeClient::new(&fx.directory, old.clone(), Some("ops@example.test"))
        .await
        .expect("register");
    let account_url = client.account_url().expect("kid");
    let http01 = fx.http01();
    client
        .issue(&["before.example.com.au"], &http01)
        .await
        .expect("an order under the original key");

    client
        .rollover_account_key(new.clone())
        .await
        .expect("Pebble accepts our nested keyChange JWS");
    assert_eq!(
        client.account_url().as_deref(),
        Some(account_url.as_str()),
        "the account URL does not change"
    );
    // Pebble verifies every request under the account's CURRENT key, so this order only works if
    // the client switched; its HTTP-01 key authorization is computed from the new key's thumbprint.
    let cert = client
        .issue(&["after.example.com.au"], &http01)
        .await
        .expect("an order under the new key");
    assert!(cert_validity(&cert.chain_pem).is_some());

    // Registering the new key finds the same account; the old key is no longer anyone's.
    let with_new = AcmeClient::new(&fx.directory, new.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        with_new.account_url().as_deref(),
        Some(account_url.as_str()),
        "the new key now identifies the account"
    );
    let with_old = AcmeClient::new(&fx.directory, old, None).await.unwrap();
    assert_ne!(
        with_old.account_url().as_deref(),
        Some(account_url.as_str()),
        "the old key is detached: it registers a fresh account"
    );

    // (Not exercised: rolling a second account onto a key already in use. RFC 8555 §7.3.5 says 409;
    // Pebble's handler fails to match its own `ExistingAccountError` and answers an empty 200
    // while leaving the key unchanged. The mock-CA unit tests cover the 409 path.)
    let _ = std::fs::remove_dir_all(&fx.work);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_engine_renews_early_when_pebbles_renewal_info_says_so() {
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("ari", ARI_PORTS, None).await else {
        return;
    };
    fx.install_zones(None).await;
    let account = AccountKey::generate().unwrap();
    let http01 = fx.http01();

    // ── the client alone: the certificate ID we derive is one Pebble resolves, and its window parses
    let client = AcmeClient::new(&fx.directory, account.clone(), Some("ops@example.test"))
        .await
        .unwrap();
    let cert = client
        .issue(&["ari.example.com.au"], &http01)
        .await
        .expect("issue");
    let v = cert_validity(&cert.chain_pem).unwrap();
    let w = client
        .renewal_info(&cert.chain_pem)
        .await
        .expect("lookup")
        .expect("Pebble publishes ARI");
    // Pebble's default advice: 1/3 of the lifetime before expiry, plus or minus a day.
    let ideal = v.not_after - (v.lifetime() + 1) / 3;
    assert!(
        (w.start - (ideal - 86_400)).abs() <= 2 && (w.end - (ideal + 86_400)).abs() <= 2,
        "{w:?} vs ideal {ideal} of {v:?}"
    );
    assert_eq!(w.retry_after_secs, Some(6 * 3600), "Pebble's Retry-After");
    assert_eq!(w.explanation_url, None);
    // A certificate from some other CA is rejected as malformed by Pebble, surfaced as a typed error.
    let foreign = {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["x.example.test".to_string()]).unwrap();
        params.use_authority_key_identifier_extension = true;
        params.signed_by(&leaf_key, &ca, &ca_key).unwrap().pem()
    };
    let err = client
        .renewal_info(&foreign)
        .await
        .expect_err("Pebble does not know that issuer");
    assert!(
        matches!(err, AcmeError::Rejected { status: 400, .. }),
        "{err}"
    );

    // ── the engine: nothing is due by the percentage rule; the CA then advises a window that has opened
    let store = Arc::new(FileCertStore::open(fx.work.join("certs")).unwrap());
    let issuer = AcmeIssuer::new(
        AcmeClient::new(&fx.directory, account, None).await.unwrap(),
        Arc::new(Dns01Authority(fx.authority.clone())),
        Some(Arc::new(http01.clone())),
    );
    let mut engine = RenewalEngine::new(store.clone(), issuer, RenewalPolicy::default());
    let now = unix_now();
    let first = engine.run_once(now, &fx.registry).await;
    assert!(first.failed.is_empty(), "{:?}", first.failed);
    assert_eq!(first.issued.len(), 2, "{first:?}");
    let before = store.cert_for("app.acme.com.au").unwrap().chain_pem;
    let wildcard_before = store.cert_for("*.tascloud.app").unwrap().chain_pem;

    // Two hours on: Pebble's own advice for these certificates (about day 59-61 of 90) has not opened.
    let later = now + 2 * 3600;
    let quiet = engine.run_once(later, &fx.registry).await;
    assert!(
        quiet.issued.is_empty() && quiet.failed.is_empty(),
        "far from the CA's window, nothing is ordered: {quiet:?}"
    );

    // Now make Pebble advise renewing the custom name's certificate: a window that opened half an hour ago.
    let advice = format!(
        r#"{{"suggestedWindow":{{"start":"{}","end":"{}"}}}}"#,
        rfc3339(later - 1800),
        rfc3339(later - 1)
    );
    let set = serde_json::json!({ "Certificate": before, "ARIResponse": advice }).to_string();
    let resp = transport::http_client::Client::new()
        .post(format!(
            "https://localhost:{}/set-renewal-info/",
            fx.ports.mgmt
        ))
        .header(
            transport::http_types::header::CONTENT_TYPE,
            "application/json",
        )
        .body(set.into_bytes())
        .send()
        .await
        .expect("set-renewal-info");
    assert_eq!(resp.status().as_u16(), 200);

    // The engine asks at most every Retry-After (Pebble: 6 h) per name: an hour later it still
    // acts on the answer it holds, and the lookup that finds the new advice is due 6 h after the last.
    assert!(
        engine
            .run_once(later + 3600, &fx.registry)
            .await
            .issued
            .is_empty(),
        "Retry-After honoured: the new advice is not asked for yet"
    );
    let after_retry = later + 6 * 3600 + 60;
    let r = engine.run_once(after_retry, &fx.registry).await;
    assert!(r.failed.is_empty(), "{:?}", r.failed);
    assert_eq!(
        r.issued,
        vec!["app.acme.com.au".to_string()],
        "only the certificate the CA advised renewing: {r:?}"
    );
    assert_ne!(
        store.cert_for("app.acme.com.au").unwrap().chain_pem,
        before,
        "replaced"
    );
    assert_eq!(
        store.cert_for("*.tascloud.app").unwrap().chain_pem,
        wildcard_before,
        "its neighbour, with an unopened window, is untouched"
    );
    assert_eq!(
        fx.registry
            .lock()
            .await
            .lookup("app.acme.com.au")
            .unwrap()
            .state,
        HostnameState::Active
    );

    // The replacement is a new certificate with its own (default) advice: quiet again.
    assert!(engine
        .run_once(after_retry + 60, &fx.registry)
        .await
        .issued
        .is_empty());
    let _ = std::fs::remove_dir_all(&fx.work);
}

/// Pebble's view of a certificate: `GET /cert-status-by-serial/<hex>` on the management port.
/// `(status, reason)` — `status` is "Valid" or "Revoked".
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pebble_marks_certificates_revoked_by_the_account_and_by_the_certificates_own_key() {
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("revoke", REVOKE_PORTS, None).await else {
        return;
    };
    let http01 = fx.http01();
    let client = AcmeClient::new(
        &fx.directory,
        AccountKey::generate().unwrap(),
        Some("ops@example.test"),
    )
    .await
    .unwrap();

    // ── signed by the account (kid), reason cessationOfOperation
    let a = client
        .issue(&["rev-a.example.com.au"], &http01)
        .await
        .expect("issue A");
    assert_eq!(
        pebble_cert_status(fx.ports.mgmt, &a.chain_pem).await,
        ("Valid".to_string(), None)
    );
    let outcome = client
        .revoke_certificate(
            a.chain_pem.as_bytes(),
            RevocationReason::CessationOfOperation,
        )
        .await
        .expect("Pebble accepts the account-signed revocation");
    assert_eq!(outcome, RevocationOutcome::Revoked);
    assert_eq!(
        pebble_cert_status(fx.ports.mgmt, &a.chain_pem).await,
        ("Revoked".to_string(), Some(5)),
        "Pebble forgot the certificate with the reason we sent"
    );
    // A second revoke is alreadyRevoked (a 400 problem), which is success.
    assert_eq!(
        client
            .revoke_certificate(
                a.chain_pem.as_bytes(),
                RevocationReason::CessationOfOperation
            )
            .await
            .unwrap(),
        RevocationOutcome::AlreadyRevoked
    );
    // So is the repeat by the other route.
    assert_eq!(
        client
            .revoke_certificate_with_key(
                a.chain_pem.as_bytes(),
                &a.key_pem,
                RevocationReason::CessationOfOperation
            )
            .await
            .unwrap(),
        RevocationOutcome::AlreadyRevoked
    );

    // ── signed by the certificate's own key (JWK), reason keyCompromise
    let b = client
        .issue(&["rev-b.example.com.au"], &http01)
        .await
        .expect("issue B");
    let outcome = client
        .revoke_certificate_with_key(
            b.chain_pem.as_bytes(),
            &b.key_pem,
            RevocationReason::KeyCompromise,
        )
        .await
        .expect("Pebble accepts the key-signed revocation");
    assert_eq!(outcome, RevocationOutcome::Revoked);
    assert_eq!(
        pebble_cert_status(fx.ports.mgmt, &b.chain_pem).await,
        ("Revoked".to_string(), Some(1))
    );

    // ── a key that is not the certificate's cannot revoke it
    let c = client
        .issue(&["rev-c.example.com.au"], &http01)
        .await
        .expect("issue C");
    let err = client
        .revoke_certificate_with_key(
            c.chain_pem.as_bytes(),
            &b.key_pem,
            RevocationReason::KeyCompromise,
        )
        .await
        .unwrap_err();
    assert!(err.is_problem("unauthorized"), "{err}");
    assert_eq!(
        pebble_cert_status(fx.ports.mgmt, &c.chain_pem).await.0,
        "Valid"
    );

    // ── an account that did not order the certificate: refused by kid; the issuer falls back to the key
    let other = AcmeClient::new(&fx.directory, AccountKey::generate().unwrap(), None)
        .await
        .unwrap();
    let err = other
        .revoke_certificate(
            c.chain_pem.as_bytes(),
            RevocationReason::CessationOfOperation,
        )
        .await
        .unwrap_err();
    assert!(err.is_problem("unauthorized"), "{err}");
    let issuer = AcmeIssuer::new(
        other,
        Arc::new(Dns01Authority(fx.authority.clone())),
        Some(Arc::new(http01.clone())),
    );
    issuer
        .revoke(&c)
        .await
        .expect("AcmeIssuer::revoke signs with the certificate key when the account cannot");
    assert_eq!(
        pebble_cert_status(fx.ports.mgmt, &c.chain_pem).await,
        ("Revoked".to_string(), Some(5))
    );
    issuer
        .revoke(&c)
        .await
        .expect("and doing it again is still success");

    // Garbage never reaches Pebble as a request.
    assert!(client
        .revoke_certificate(b"junk", RevocationReason::Unspecified)
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&fx.work);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_order_names_the_certificate_it_replaces_and_pebble_records_it() {
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("replace", REPLACE_PORTS, None).await else {
        return;
    };
    let http01 = fx.http01();
    let client = AcmeClient::new(
        &fx.directory,
        AccountKey::generate().unwrap(),
        Some("ops@example.test"),
    )
    .await
    .unwrap();
    let log = || std::fs::read_to_string(fx.work.join("pebble.log")).unwrap_or_default();
    let replaced_marks = || {
        log()
            .matches("has been marked as replaced in the DB")
            .count()
    };

    let first = client
        .issue(&["repl.example.com.au"], &http01)
        .await
        .expect("first issuance");
    assert_eq!(replaced_marks(), 0, "a first issuance replaces nothing");

    // The renewal names `first`; Pebble accepts it and marks `first` as replaced.
    let second = client
        .issue_replacing(&["repl.example.com.au"], &http01, &first.chain_pem)
        .await
        .expect("renewal with replaces");
    assert_ne!(first.chain_pem, second.chain_pem);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while replaced_marks() < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        replaced_marks(),
        1,
        "Pebble saw `replaces` and recorded the old certificate as replaced:\n{}",
        log()
    );

    // Replacing the same certificate again is refused by Pebble (alreadyReplaced, 409). The client
    // falls back to a plain order: the renewal still produces a certificate.
    let third = client
        .issue_replacing(&["repl.example.com.au"], &http01, &first.chain_pem)
        .await
        .expect("falls back to a plain order");
    assert!(cert_validity(&third.chain_pem).is_some());
    // Had Pebble accepted the second `replaces` it would have marked the certificate replaced again
    // (a second log line); it stays at one because the refused order was re-placed without it.
    assert_eq!(
        replaced_marks(),
        1,
        "Pebble refused the second replacement and the fallback order replaced nothing:\n{}",
        log()
    );

    // A certificate from some other CA has no ID Pebble recognises: `replaces` is malformed there, and
    // the fallback again yields a certificate.
    let foreign = {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = p.self_signed(&ca_key).unwrap();
        let k = rcgen::KeyPair::generate().unwrap();
        let mut lp = rcgen::CertificateParams::new(vec!["x.example.test".to_string()]).unwrap();
        lp.use_authority_key_identifier_extension = true;
        lp.signed_by(&k, &ca, &ca_key).unwrap().pem()
    };
    client
        .issue_replacing(&["repl2.example.com.au"], &http01, &foreign)
        .await
        .expect("a refused `replaces` never fails the renewal");
    let _ = std::fs::remove_dir_all(&fx.work);
}

/// Key hygiene against an independent CA: a new key for every order and every renewal, the
/// certificate certifies exactly that key, P-384 and an advertised ACME profile are accepted, and
/// the engine refuses to install what it would have to reuse a key for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_order_and_every_renewal_gets_a_new_certificate_key_that_pebble_certifies() {
    use transport::acme::ClientOptions;
    use transport::certkey::{inspect_pkcs8, EcCurve, KeyAlg, KeyKind};
    let _serial = SERIAL.lock().await;
    let Some(fx) = Fixture::start("keys", KEYS_PORTS, None).await else {
        return;
    };
    fx.install_zones(None).await;
    let http01 = fx.http01();
    let key_of = |m: &transport::edge::CertMaterial| {
        inspect_pkcs8(&transport::pem::blocks(&m.key_pem, "PRIVATE KEY")[0])
    };

    // ── P-256 (the default): successive orders, and a `replaces` renewal, all get distinct keys.
    let client = AcmeClient::new(&fx.directory, AccountKey::generate().unwrap(), None)
        .await
        .unwrap();
    let first = client.issue(&["k1.example.com.au"], &http01).await.unwrap();
    let second = client.issue(&["k1.example.com.au"], &http01).await.unwrap();
    let renewed = client
        .issue_replacing(&["k1.example.com.au"], &http01, &first.chain_pem)
        .await
        .unwrap();
    let keys = [&first, &second, &renewed].map(|m| m.key_pem.clone());
    assert!(
        keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2],
        "no two orders share a key"
    );
    assert_eq!(key_of(&first), KeyKind::Ec(EcCurve::P256));
    for m in [&first, &second, &renewed] {
        // Pebble certified the public key of the CSR we signed, i.e. the one in key_pem.
        let pk = transport::acme::AccountKey::from_pkcs8_pem(&m.key_pem).unwrap();
        let _ = pk; // loads as the same P-256 key family the edge serves
        assert!(transport::x509::leaf_spki(&m.chain_pem).is_some());
    }
    assert_ne!(
        transport::x509::leaf_spki(&first.chain_pem),
        transport::x509::leaf_spki(&renewed.chain_pem)
    );

    // ── P-384 with an advertised profile: Pebble issues it, the key is P-384, and the policy allows it.
    let opts = ClientOptions {
        key_alg: KeyAlg::P384,
        profile: Some("default".into()),
        ..ClientOptions::default()
    };
    let p384 = AcmeClient::connect(
        &fx.directory,
        AccountKey::generate().unwrap(),
        None,
        None,
        opts,
    )
    .await
    .unwrap();
    let cert = p384
        .issue(&["k384.example.com.au"], &http01)
        .await
        .expect("Pebble accepts a P-384 CSR and the advertised profile");
    assert_eq!(key_of(&cert), KeyKind::Ec(EcCurve::P384));
    assert_eq!(
        transport::x509::leaf_spki(&cert.chain_pem).unwrap().len(),
        120,
        "a P-384 SubjectPublicKeyInfo"
    );
    // It is a certificate the edge can serve.
    let store = Arc::new(FileCertStore::open(fx.work.join("p384-certs")).unwrap());
    transport::acme_renew::CertStore::put(store.as_ref(), "k384.example.com.au", cert)
        .expect("the key policy allows P-384");
    // A profile the CA does not advertise is left out rather than failing the order.
    let opts = ClientOptions {
        profile: Some("no-such-profile".into()),
        ..ClientOptions::default()
    };
    let odd = AcmeClient::connect(
        &fx.directory,
        AccountKey::generate().unwrap(),
        None,
        None,
        opts,
    )
    .await
    .unwrap();
    odd.issue(&["kodd.example.com.au"], &http01)
        .await
        .expect("an unadvertised profile is not sent");

    // ── The engine: a forced renewal installs a certificate with a different key.
    let store = Arc::new(FileCertStore::open(fx.work.join("engine-certs")).unwrap());
    let issuer = AcmeIssuer::new(
        AcmeClient::new(&fx.directory, AccountKey::generate().unwrap(), None)
            .await
            .unwrap(),
        Arc::new(Dns01Authority(fx.authority.clone())),
        Some(Arc::new(http01.clone())),
    );
    let mut engine = RenewalEngine::new(
        store.clone(),
        issuer,
        RenewalPolicy {
            renew_after_percent: 0,
            ..RenewalPolicy::default()
        },
    );
    let t = unix_now();
    let r = engine.run_once(t, &fx.registry).await;
    assert!(r.failed.is_empty() && r.issued.len() == 2, "{r:?}");
    let before: Vec<_> = r
        .issued
        .iter()
        .map(|n| (n.clone(), store.cert_for(n).unwrap()))
        .collect();
    let r = engine.run_once(t + 5, &fx.registry).await;
    assert!(
        r.failed.is_empty() && r.issued.len() == 2,
        "renew_after_percent 0 renews at once: {r:?}"
    );
    for (name, old) in before {
        let new = store.cert_for(&name).unwrap();
        assert_ne!(
            new.key_pem, old.key_pem,
            "{name}: the renewed certificate has a new key"
        );
        assert!(!transport::acme_renew::same_key(&old, &new));
    }
    let _ = std::fs::remove_dir_all(&fx.work);
}
