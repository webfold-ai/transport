//! Throughput smoke benchmark (not a gate): loopback TCP through a real `tas-lb` versus the same
//! traffic straight to the backend.
//!
//! ```text
//! cargo run --release --example throughput -- [MIB_PER_DIRECTION=2048] [CONNECTIONS=4] [SECONDS_FOR_CPS=3]
//! ```
//!
//! Everything shares one machine (client, LB, backend) and one runtime, so absolute numbers are a
//! floor for the userspace plane, not a capacity figure; the ratio against "direct" is the useful
//! part. It reports upload and download goodput, and new-connection rate (connect + 1-byte
//! round trip).
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    reason = "benchmark binary: reports to stdout, fixture setup"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tas_lb::backend::{BackendSet, BackendSpec, HealthSpec};
use tas_lb::config::StaticConfig;
use tas_lb::signed_config::sign_set;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport::signed_dns::Keypair;

/// Backend protocol: first byte `U` (sink until EOF, reply `k`), `D` + u64 BE length (send that
/// many bytes, then close), `P` (reply `p`).
async fn backend(listener: TcpListener) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let _ = s.set_nodelay(true);
            let mut op = [0u8; 1];
            if s.read_exact(&mut op).await.is_err() {
                return;
            }
            match op[0] {
                b'U' => {
                    let mut buf = vec![0u8; 256 * 1024];
                    while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
                    let _ = s.write_all(b"k").await;
                }
                b'D' => {
                    let mut len = [0u8; 8];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut left = u64::from_be_bytes(len);
                    let chunk = vec![0xA5u8; 256 * 1024];
                    while left > 0 {
                        let n = usize::try_from(left).unwrap_or(usize::MAX).min(chunk.len());
                        if s.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        left -= n as u64;
                    }
                }
                _ => {
                    let _ = s.write_all(b"p").await;
                }
            }
        });
    }
}

async fn upload(addr: SocketAddr, bytes: u64) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"U").await.unwrap();
    let chunk = vec![0x5Au8; 256 * 1024];
    let mut left = bytes;
    while left > 0 {
        let n = usize::try_from(left).unwrap_or(usize::MAX).min(chunk.len());
        s.write_all(&chunk[..n]).await.unwrap();
        left -= n as u64;
    }
    s.shutdown().await.unwrap();
    let mut ack = [0u8; 1];
    s.read_exact(&mut ack).await.unwrap();
}

async fn download(addr: SocketAddr, bytes: u64) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"D").await.unwrap();
    s.write_all(&bytes.to_be_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0u64;
    while got < bytes {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "short download");
        got += n as u64;
    }
}

async fn conn_rate(addr: SocketAddr, workers: usize, dur: Duration) -> f64 {
    let done = Arc::new(AtomicU64::new(0));
    let stop = Instant::now() + dur;
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let done = done.clone();
        tasks.push(tokio::spawn(async move {
            while Instant::now() < stop {
                let Ok(mut s) = TcpStream::connect(addr).await else {
                    continue;
                };
                if s.write_all(b"P").await.is_err() {
                    continue;
                }
                let mut r = [0u8; 1];
                if s.read_exact(&mut r).await.is_ok() {
                    done.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    done.load(Ordering::Relaxed) as f64 / dur.as_secs_f64()
}

async fn run(label: &str, addr: SocketAddr, mib: u64, conns: usize, cps_secs: u64) {
    let per = mib * 1024 * 1024 / conns as u64;
    let total = per * conns as u64;
    let t = Instant::now();
    futures_join(conns, |_| upload(addr, per)).await;
    let up = total as f64 / t.elapsed().as_secs_f64() / (1024.0 * 1024.0);
    let t = Instant::now();
    futures_join(conns, |_| download(addr, per)).await;
    let down = total as f64 / t.elapsed().as_secs_f64() / (1024.0 * 1024.0);
    let cps = conn_rate(addr, 32, Duration::from_secs(cps_secs)).await;
    println!("{label:>8}: upload {up:9.0} MiB/s   download {down:9.0} MiB/s   new connections {cps:9.0}/s");
}

async fn futures_join<F, Fut>(n: usize, f: F)
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let tasks: Vec<_> = (0..n).map(|i| tokio::spawn(f(i))).collect();
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mib: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(2048);
    let conns: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(4);
    let cps_secs: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(3);

    let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = b.local_addr().unwrap();
    tokio::spawn(backend(b));

    let signer = Keypair::from_secret_key(&[0x42; 32]);
    let dir = std::env::temp_dir().join(format!("tas-lb-bench-{}", std::process::id()));
    let cfg = StaticConfig::from_json(
        &serde_json::json!({
            "cluster": "bench",
            "state_dir": dir,
            "signer_key": signer.public_key().to_z32(),
            "metrics_bind": "127.0.0.1:0",
            "listeners": [{"name": "bench", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": backend_addr.port()}],
            "allow_loopback_backends": true,
            "limits": {"max_flows": 65_536, "max_pending": 8192, "accept_backlog": 4096,
                       "max_flows_per_source": 0, "new_flows_per_source_per_sec": 0}
        })
        .to_string(),
    )
    .unwrap();
    let lb = tas_lb::lb::start(cfg).await.unwrap();
    let set = BackendSet {
        cluster: "bench".into(),
        hash_key: "42".repeat(32),
        send_proxy_v2: false,
        drain_timeout_ms: 1000,
        health: HealthSpec::default(),
        backends: vec![BackendSpec {
            id: "b".into(),
            ip: backend_addr.ip(),
            weight: 100,
            drain: false,
        }],
    };
    lb.apply_signed(&sign_set(&signer, 1, &set).unwrap())
        .unwrap();
    while !lb.shared().director.is_ready() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let lb_addr = lb.listeners[0].addr;

    println!("tas-lb throughput smoke: {mib} MiB per direction over {conns} connections, loopback, one process");
    run("direct", backend_addr, mib, conns, cps_secs).await;
    run("via tas-lb", lb_addr, mib, conns, cps_secs).await;
    lb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
