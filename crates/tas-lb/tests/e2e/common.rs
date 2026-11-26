//! Shared harness for the end-to-end tests: real sockets on loopback, real backends (distinct
//! 127.0.0.x addresses on one port, because the signed set names backend IPs and each listener
//! supplies the port), a real `tas-lb` started through `lb::start`, and a control plane that signs
//! with a dialkey-derived key exactly as production does.
#![expect(clippy::unwrap_used, reason = "test harness: assertions on fixtures")]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tas_lb::backend::{BackendSet, BackendSpec, HealthSpec};
use tas_lb::config::StaticConfig;
use tas_lb::lb::{self, RunningLb};
use tas_lb::proxy_protocol::{self, Command, Header};
use tas_lb::signed_config::{self, ConfigError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use transport::signed_dns::Keypair;

pub const DIALKEY: &str = "tas-lb-test-control-plane-dialkey";
pub const CLUSTER: &str = "pop-test";

/// The control plane's signing key, derived from a dialkey like every other mesh identity.
pub fn control_kp() -> Keypair {
    transport::dialkey::native_keypair(DIALKEY)
}

pub fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[derive(Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a bag of independent test-backend switches"
)]
pub struct Behavior {
    /// Expect a PROXY v2 header first (and record it).
    pub expect_proxy: bool,
    /// Send "<name>\n" after the header.
    pub greet: bool,
    /// After the client half-closes, send "bye\n" and close.
    pub trailer_on_eof: bool,
    /// On client EOF, keep the connection open forever (a backend that ignores half-close).
    pub hold_after_eof: bool,
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            expect_proxy: true,
            greet: true,
            trailer_on_eof: false,
            hold_after_eof: false,
        }
    }
}

pub struct TestBackend {
    pub name: String,
    pub ip: IpAddr,
    pub port: u16,
    pub headers: Arc<Mutex<Vec<Header>>>,
    pub received: Arc<Mutex<Vec<u8>>>,
    pub accepted: Arc<AtomicUsize>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
    behavior: Behavior,
}

impl TestBackend {
    pub async fn start(name: &str, last_octet: u8, port: u16, behavior: Behavior) -> TestBackend {
        let ip: IpAddr = format!("127.0.0.{last_octet}").parse().unwrap();
        let mut b = TestBackend {
            name: name.to_string(),
            ip,
            port,
            headers: Arc::default(),
            received: Arc::default(),
            accepted: Arc::default(),
            accept_task: None,
            behavior,
        };
        b.listen().await;
        b
    }

    async fn listen(&mut self) {
        let l = TcpListener::bind(SocketAddr::new(self.ip, self.port))
            .await
            .unwrap();
        let (name, headers, received, accepted, behavior) = (
            self.name.clone(),
            self.headers.clone(),
            self.received.clone(),
            self.accepted.clone(),
            self.behavior,
        );
        self.accept_task = Some(tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let (name, headers, received, accepted) = (
                    name.clone(),
                    headers.clone(),
                    received.clone(),
                    accepted.clone(),
                );
                tokio::spawn(async move {
                    if behavior.expect_proxy {
                        match proxy_protocol::read_from(&mut s).await {
                            Ok(h) if h.command == Command::Proxy => headers.lock().unwrap().push(h),
                            _ => return, // LOCAL (health probe) or garbage: not a flow
                        }
                    }
                    accepted.fetch_add(1, Ordering::SeqCst);
                    if behavior.greet && s.write_all(format!("{name}\n").as_bytes()).await.is_err()
                    {
                        return;
                    }
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) => {
                                if behavior.hold_after_eof {
                                    tokio::time::sleep(Duration::from_secs(3600)).await;
                                    return;
                                }
                                if behavior.trailer_on_eof {
                                    let _ = s.write_all(b"bye\n").await;
                                }
                                let _ = s.shutdown().await;
                                return;
                            }
                            Ok(n) => {
                                received
                                    .lock()
                                    .unwrap()
                                    .extend_from_slice(&buf[..n.min(256)]);
                                if s.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
        }));
    }

    /// Stop accepting (the port closes), as if the backend died. Established connections live on.
    pub fn stop_listening(&mut self) {
        if let Some(t) = self.accept_task.take() {
            t.abort();
        }
    }

    pub async fn restart_listening(&mut self) {
        self.stop_listening();
        // The aborted task drops the listener asynchronously; retry briefly.
        for _ in 0..50 {
            if TcpListener::bind(SocketAddr::new(self.ip, self.port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.listen().await;
    }

    pub fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: self.name.clone(),
            ip: self.ip,
            weight: 100,
            drain: false,
        }
    }
}

pub struct UdpBackend {
    pub name: String,
    pub ip: IpAddr,
    pub datagrams: Arc<Mutex<Vec<Vec<u8>>>>,
    pub headers: Arc<Mutex<Vec<Header>>>,
    task: tokio::task::JoinHandle<()>,
}

impl UdpBackend {
    /// Replies to every datagram with `<name>:<payload>`. With `expect_proxy` the datagram is
    /// prefixed with a PROXY v2 header, which is parsed, recorded in `datagrams` as the payload
    /// remainder, and stripped before replying.
    pub async fn start(name: &str, last_octet: u8, port: u16, expect_proxy: bool) -> UdpBackend {
        let ip: IpAddr = format!("127.0.0.{last_octet}").parse().unwrap();
        let sock = UdpSocket::bind(SocketAddr::new(ip, port)).await.unwrap();
        let datagrams: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let headers: Arc<Mutex<Vec<Header>>> = Arc::default();
        let (n2, d2, h2) = (name.to_string(), datagrams.clone(), headers.clone());
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let mut payload = &buf[..n];
                if expect_proxy {
                    match proxy_protocol::parse(payload) {
                        Ok((h, used)) => {
                            h2.lock().unwrap().push(h);
                            payload = &payload[used..];
                        }
                        Err(_) => continue,
                    }
                }
                d2.lock().unwrap().push(payload.to_vec());
                let mut reply = format!("{n2}:").into_bytes();
                reply.extend_from_slice(payload);
                let _ = sock.send_to(&reply, from).await;
            }
        });
        UdpBackend {
            name: name.to_string(),
            ip,
            datagrams,
            headers,
            task,
        }
    }

    pub fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: self.name.clone(),
            ip: self.ip,
            weight: 100,
            drain: false,
        }
    }
}

impl Drop for UdpBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn fast_health() -> HealthSpec {
    HealthSpec {
        interval_ms: 50,
        timeout_ms: 50,
        rise: 2,
        fall: 2,
        passive: true,
        port: None,
    }
}

pub fn make_set(specs: Vec<BackendSpec>) -> BackendSet {
    BackendSet {
        cluster: CLUSTER.into(),
        hash_key: "5a".repeat(32),
        send_proxy_v2: true,
        drain_timeout_ms: 600,
        health: fast_health(),
        backends: specs,
    }
}

#[expect(
    clippy::struct_field_names,
    reason = "the harness is named for what it wraps"
)]
pub struct Lb {
    pub lb: RunningLb,
    pub _dir: tempfile::TempDir,
    pub tcp_addr: SocketAddr,
}

#[derive(Default)]
pub struct LbOpts {
    pub limits: Option<serde_json::Value>,
    /// Extra / replacement listeners as JSON (defaults to one plain TCP listener named "main").
    pub listeners: Option<Vec<serde_json::Value>>,
    pub backend_port: u16,
    pub control: bool,
    pub dir: Option<std::path::PathBuf>,
    pub min_seq: u64,
}

pub fn static_config(o: &LbOpts, dir: &std::path::Path) -> StaticConfig {
    let listeners = o.listeners.clone().unwrap_or_else(|| {
        vec![serde_json::json!({"name": "main", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": o.backend_port})]
    });
    let pk = control_kp().public_key();
    let mut v = serde_json::json!({
        "cluster": CLUSTER,
        "state_dir": dir,
        "signer_key": pk.to_z32(),
        "metrics_bind": "127.0.0.1:0",
        "listeners": listeners,
        "allow_loopback_backends": true,
        "min_config_seq": o.min_seq,
    });
    if o.control {
        v["control"] = serde_json::json!({"bind": "127.0.0.1:0"});
    }
    let mut limits = serde_json::json!({
        "new_flows_per_source_per_sec": 0,
        "max_flows_per_source": 0,
        "tcp_idle_timeout_secs": 30,
        "shutdown_grace_secs": 2,
    });
    if let Some(extra) = &o.limits {
        for (k, val) in extra.as_object().unwrap() {
            limits[k] = val.clone();
        }
    }
    v["limits"] = limits;
    StaticConfig::from_json(&v.to_string()).unwrap()
}

pub async fn start_lb(o: LbOpts) -> Lb {
    let owned = tempfile::tempdir().unwrap();
    let dir = o.dir.clone().unwrap_or_else(|| owned.path().to_path_buf());
    let cfg = static_config(&o, &dir);
    let lb = lb::start(cfg).await.unwrap();
    let tcp_addr = lb
        .listeners
        .iter()
        .find(|l| l.proto == tas_lb::config::ListenerProto::Tcp)
        .map_or(lb.metrics_addr, |l| l.addr);
    Lb {
        lb,
        _dir: owned,
        tcp_addr,
    }
}

impl Lb {
    pub fn push(&self, seq: u64, set: &BackendSet) -> Result<u64, ConfigError> {
        self.lb
            .apply_signed(&signed_config::sign_set(&control_kp(), seq, set).unwrap())
    }

    /// Wait until exactly the backends named in `up` take new flows.
    pub async fn wait_eligible(&self, up: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ids: Vec<String> = self
                .lb
                .shared()
                .director
                .generation()
                .map(|g| g.members().iter().map(|m| m.id.clone()).collect())
                .unwrap_or_default();
            let mut have: Vec<&str> = ids.iter().map(String::as_str).collect();
            have.sort_unstable();
            let mut want = up.to_vec();
            want.sort_unstable();
            if have == want {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for eligible set {want:?}, have {have:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn metrics(&self) -> String {
        http_get(self.lb.metrics_addr, "/metrics").await.1
    }
}

pub async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    http_request(addr, "GET", path).await
}

pub async fn http_request(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

/// Read one metric value by exact series text, e.g. `tas_lb_rejected_total{reason="per_source"}`.
pub fn metric(text: &str, series: &str) -> u64 {
    text.lines()
        .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Connect through the LB and read the backend's greeting line.
pub async fn connect_named(addr: SocketAddr) -> (TcpStream, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let name = read_line(&mut s).await;
    (s, name)
}

pub async fn read_line(s: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut b))
            .await
            .unwrap()
            .unwrap_or(0);
        if n == 0 || b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    String::from_utf8(line).unwrap()
}

/// Send `msg` and read back exactly `msg.len()` bytes.
pub async fn echo_roundtrip(s: &mut TcpStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    s.write_all(msg).await?;
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "echo timed out"))??;
    Ok(got)
}

/// True if the connection is reset or closed (EOF / error) within `within`.
pub async fn is_closed_within(s: &mut TcpStream, within: Duration) -> bool {
    let mut b = [0u8; 1];
    match tokio::time::timeout(within, s.read(&mut b)).await {
        Ok(Ok(0) | Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

pub async fn eventually(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// FNV-1a over a running stream of bytes.
#[derive(Clone, Copy)]
pub struct Fnv(pub u64);
impl Fnv {
    pub fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    pub fn update(&mut self, data: &[u8]) {
        for b in data {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// Capture every tracing event of the whole test process (all levels) so a test can assert what
/// the logs do and do not contain.
pub static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogWriter;
impl std::io::Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct MakeLogWriter;
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeLogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        LogWriter
    }
}

pub fn init_logs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(MakeLogWriter)
                .finish(),
        );
    });
}

/// Connect and read a greeting; `None` if the LB refused (reset / closed before a greeting).
pub async fn try_connect_named(addr: SocketAddr) -> Option<(TcpStream, String)> {
    let mut s = TcpStream::connect(addr).await.ok()?;
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await {
            Ok(Ok(1)) if b[0] != b'\n' => line.push(b[0]),
            Ok(Ok(1)) => return Some((s, String::from_utf8(line).ok()?)),
            _ => return None,
        }
    }
}

/// Read and discard until the connection ends (EOF or reset); false if it is still open at `within`.
pub async fn drains_to_close(s: &mut TcpStream, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    let mut b = [0u8; 256];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, s.read(&mut b)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}
