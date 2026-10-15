//! End-to-end against **Pebble**, Let's Encrypt's independent ACME test CA (a separate
//! implementation, in Go — not a mock written by us).
//!
//! What this proves that the in-tree mock CA cannot:
//! - our JWS/CSR/finalize bytes are accepted by an unrelated RFC 8555 server;
//! - Pebble *validates DNS-01 by querying our authoritative DNS* (`edge_dns::ZoneAuthority`
//!   behind a real UDP socket, via the native `dns` wire codec);
//! - (Not covered: CAA enforcement. Pebble does not implement CAA checking.)
//! - the renewal engine installs what the CA returns, activates waiting hostnames, and the
//!   issued chain+key serve a real TLS handshake that verifies against the CA root.
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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::acme::{AccountKey, AcmeClient, AcmeError, Http01Responder};
use transport::acme_renew::{AcmeIssuer, FileCertStore, RenewalEngine, RenewalPolicy};
use transport::dns::{Flags, Message, Name, Question, RData, Record, RecordType, ResponseCode};
use transport::edge::{CertSource, EdgeRegistry, HostnameState, Route, APEXES};
use transport::edge_dns::{serve_tcp_with, serve_udp_with, Dns01Authority, DnsHandler, ZoneAuthority, ZoneConfig};
use transport::edge_proxy::EdgeCertResolver;

const ACME_PORT: u16 = 14500;
const MGMT_PORT: u16 = 14501;
const HTTP01_PORT: u16 = 15002;

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
    fn serve_token<'a>(&'a self, token: &'a str, key_authorization: &'a str) -> transport::BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async move {
            self.tokens.lock().unwrap().insert(token.to_string(), key_authorization.to_string());
            Ok(())
        })
    }
    fn remove_token<'a>(&'a self, token: &'a str) -> transport::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.tokens.lock().unwrap().remove(token);
        })
    }
}

async fn serve_http01(responder: Http01) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", HTTP01_PORT)).await.expect("bind http-01 port");
    loop {
        let Ok((mut s, _)) = listener.accept().await else { return };
        let r = responder.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            let token = path.strip_prefix("/.well-known/acme-challenge/").unwrap_or("");
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
            let name = question.name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            if APEXES.iter().any(|a| name == a.zone || name.ends_with(&format!(".{}", a.zone))) {
                let reg = self.registry.lock().await;
                return self.authority.lock().await.answer(query, &reg);
            }
            let mut r = Message::response(q.id);
            r.flags = Flags { response: true, recursion_desired: q.flags.recursion_desired, recursion_available: true, response_code: ResponseCode::NoError, ..Flags::default() };
            r.questions = vec![Question::new(question.name.clone(), question.qtype)];
            if question.qtype == RecordType::A {
                r.answers.push(Record::new(question.name.clone(), 1, RData::A("127.0.0.1".parse().unwrap())));
            }
            Some(r.to_bytes())
        })
    }
}

/// Serve the test DNS on UDP **and** TCP at one port (Pebble resolves over TCP).
async fn serve_dns(authority: Arc<tokio::sync::Mutex<ZoneAuthority>>, registry: Arc<tokio::sync::Mutex<EdgeRegistry>>) -> SocketAddr {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handler: Arc<dyn DnsHandler> = Arc::new(TestDns { authority, registry });
    let bind: &'static str = Box::leak(addr.to_string().into_boxed_str());
    tokio::spawn(serve_udp_with(bind, handler.clone()));
    tokio::spawn(serve_tcp_with(bind, handler));
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

fn route(tenant: &str, tunnel: &str) -> Route {
    Route { tenant_id: tenant.into(), tunnel_id: tunnel.into(), peer: transport::dialkey::peer_id(tunnel), origin_port: 8080 }
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
    let id: String = transport_rand().iter().map(|b| format!("{b:02x}")).collect();
    let p = std::env::temp_dir().join(format!("pebble-{tag}-{id}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn transport_rand() -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; 6];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_engine_obtains_wildcard_and_custom_certificates_from_pebble() {
    let (Some(bin), Some(src)) = (std::env::var_os("PEBBLE_BIN"), std::env::var_os("PEBBLE_SRC")) else {
        eprintln!("SKIPPED: set PEBBLE_BIN and PEBBLE_SRC (see the module docs) to run the Pebble end-to-end test");
        return;
    };
    let src = PathBuf::from(src);

    // ── shared registry: a live managed hostname (=> *.tascloud.app is required) and a validated custom one
    let registry = Arc::new(tokio::sync::Mutex::new(EdgeRegistry::new(b"pebble-secret".to_vec())));
    {
        let mut reg = registry.lock().await;
        let apex = APEXES.iter().find(|a| a.zone == "tascloud.app").unwrap();
        reg.claim_managed_label(apex, "mine", route("acme", "t0")).unwrap();
        reg.add_custom("app.acme.com.au", "mine.tascloud.app", route("acme", "t1")).unwrap();
        reg.record_probe("app.acme.com.au", true, 5).unwrap(); // proof of control passed -> PendingCert
        assert_eq!(reg.lookup("app.acme.com.au").unwrap().state, HostnameState::PendingCert);
    }

    // ── our authoritative DNS, with CAA bound to OUR ACME account (account registered below)
    let work = scratch("work");
    let ca_cert = std::fs::read_to_string(src.join("test/certs/pebble.minica.pem")).unwrap();
    std::fs::write(work.join("minica.pem"), &ca_cert).unwrap();
    // The ACME client's TLS trust store: Pebble's test CA (rustls-native-certs honours SSL_CERT_FILE).
    std::env::set_var("SSL_CERT_FILE", work.join("minica.pem"));

    // Pebble needs the DNS address at start, and the CAA needs the account URL, which needs Pebble:
    // start the DNS with an empty authority first, then install the zones once the account exists.
    let authority = Arc::new(tokio::sync::Mutex::new(ZoneAuthority::new(Vec::new(), vec!["127.0.0.1".parse().unwrap()], vec![])));
    let dns_addr = serve_dns(authority.clone(), registry.clone()).await;

    let config = format!(
        r#"{{"pebble":{{"listenAddress":"127.0.0.1:{ACME_PORT}","managementListenAddress":"127.0.0.1:{MGMT_PORT}",
"certificate":"{c}","privateKey":"{k}","httpPort":{HTTP01_PORT},"tlsPort":15001,"ocspResponderURL":"",
"externalAccountBindingRequired":false,"retryAfter":{{"authz":1,"order":1}},"keyAlgorithm":"ecdsa",
"profiles":{{"default":{{"description":"default","validityPeriod":7776000}}}}}}}}"#,
        c = src.join("test/certs/localhost/cert.pem").display(),
        k = src.join("test/certs/localhost/key.pem").display(),
    );
    std::fs::write(work.join("pebble.json"), config).unwrap();
    let _pebble = Pebble(
        Command::new(bin)
            .args(["-config", work.join("pebble.json").to_str().unwrap(), "-dnsserver", &dns_addr.to_string()])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            .env("PEBBLE_WFE_AUTHZREUSE", "0")
            .stdout(log_stdio(&work))
            .stderr(log_stdio(&work))
            .spawn()
            .expect("spawn pebble"),
    );
    let directory = format!("https://localhost:{ACME_PORT}/dir");
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ACME_PORT)).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "pebble did not start");

    // ── the ACME account, then CAA pinned to it
    let account = AccountKey::generate().unwrap();
    let client = AcmeClient::new(&directory, account, Some("ops@example.test")).await.expect("register account with pebble");
    let account_url = client.account_url().expect("kid");
    {
        let zones = APEXES
            .iter()
            .map(|a| {
                ZoneConfig::new(a.zone, vec![format!("ns1.{}", a.zone)])
                    .with_caa_issuers(vec!["pebble.letsencrypt.org".to_string()])
                    .with_caa_account_uri(account_url.clone())
            })
            .collect();
        *authority.lock().await = ZoneAuthority::new(zones, vec!["127.0.0.1".parse().unwrap()], vec![]);
    }

    // NOTE: Pebble does not enforce CAA (its `accounturi` support belongs to the separate
    // dns-persist-01 challenge), so the RFC 8657 account binding published above is only checked
    // at the record level (edge_dns unit tests) — Boulder/Let's Encrypt is what enforces it.

    // ── the engine, with the real issuer: DNS-01 for the wildcard, HTTP-01 for the customer name
    let http01 = Http01::default();
    tokio::spawn(serve_http01(http01.clone()));
    let store_dir = work.join("certs");
    let store = Arc::new(FileCertStore::open(&store_dir).unwrap());
    let issuer = AcmeIssuer::new(client, Arc::new(Dns01Authority(authority.clone())), Some(Arc::new(http01)));
    let mut engine = RenewalEngine::new(store.clone(), issuer, RenewalPolicy::default());

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let report = engine.run_once(now, &registry).await;
    assert!(report.failed.is_empty(), "issuance failed: {:?}", report.failed);
    let mut issued = report.issued.clone();
    issued.sort();
    assert_eq!(issued, vec!["*.tascloud.app".to_string(), "app.acme.com.au".to_string()]);
    assert_eq!(report.activated, vec!["app.acme.com.au".to_string()]);
    assert_eq!(registry.lock().await.lookup("app.acme.com.au").unwrap().state, HostnameState::Active);

    // Pebble's challenge values were cleaned up after validation.
    {
        let reg = registry.lock().await;
        let mut a = authority.lock().await;
        let q = Message {
            id: 7,
            flags: Flags { recursion_desired: true, ..Flags::default() },
            questions: vec![Question::new(Name::from_ascii("_acme-challenge.tascloud.app.").unwrap(), RecordType::Txt)],
            ..Message::default()
        };
        let reply = Message::from_bytes(&a.answer(&q.to_bytes(), &reg).unwrap()).unwrap();
        assert_eq!(reply.flags.response_code, ResponseCode::NxDomain, "spent DNS-01 tokens must not linger");
    }

    // ── a second pass is quiet; a "restart" (fresh store from disk) does not reorder
    assert!(engine.run_once(now + 60, &registry).await.issued.is_empty());
    let reopened = FileCertStore::open(&store_dir).unwrap();
    assert_eq!(reopened.cert_for("*.tascloud.app").is_some(), true);

    // ── the issued chain + key serve a REAL handshake that verifies against Pebble's root
    let root = fetch_root(&work).await;
    let resolver = Arc::new(EdgeCertResolver::new(store.clone()));
    let acceptor = tokio_rustls::TlsAcceptor::from(resolver.server_config().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(root)).unwrap();
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
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
        assert!(tls.is_ok(), "{sni}: handshake against the Pebble-issued certificate failed: {:?}", tls.err());
        let _ = server.await;
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// The CA root (Pebble's management API: `GET /roots/0`), PEM -> DER.
async fn fetch_root(work: &std::path::Path) -> Vec<u8> {
    let pem = transport::http_client::Client::new()
        .get(format!("https://localhost:{MGMT_PORT}/roots/0"))
        .send()
        .await
        .expect("fetch root")
        .text()
        .await
        .expect("root body");
    std::fs::write(work.join("root.pem"), &pem).unwrap();
    transport::pem::blocks(&pem, "CERTIFICATE").into_iter().next().expect("a root certificate")
}
