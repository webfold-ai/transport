//! Data-plane behaviour with real sockets: large transfers, many concurrent flows, half-close,
//! idle timeout, graceful shutdown.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::*;

async fn one_backend_lb(
    behavior: Behavior,
    limits: Option<serde_json::Value>,
) -> (Lb, TestBackend) {
    let port = free_tcp_port();
    let b = TestBackend::start("solo", 41, port, behavior).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits,
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![b.spec()])).unwrap();
    lb.wait_eligible(&["solo"]).await;
    (lb, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_bidirectional_transfer_arrives_intact() {
    const TOTAL: usize = 96 * 1024 * 1024;
    let (lb, _b) = one_backend_lb(Behavior::default(), None).await;
    let (s, name) = connect_named(lb.tcp_addr).await;
    assert_eq!(name, "solo");
    let (mut rd, mut wr) = s.into_split();

    let writer = tokio::spawn(async move {
        let mut h = Fnv::new();
        let mut sent = 0usize;
        let mut chunk = vec![0u8; 61_441]; // deliberately not a power of two
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        while sent < TOTAL {
            let n = chunk.len().min(TOTAL - sent);
            for b in &mut chunk[..n] {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = u8::try_from((x >> 24) & 0xFF).unwrap_or(0);
            }
            h.update(&chunk[..n]);
            wr.write_all(&chunk[..n]).await.unwrap();
            sent += n;
        }
        wr.shutdown().await.unwrap();
        h.0
    });
    let mut h = Fnv::new();
    let mut got = 0usize;
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = rd.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        got += n;
    }
    assert_eq!(got, TOTAL);
    assert_eq!(
        h.0,
        writer.await.unwrap(),
        "echoed bytes differ from sent bytes"
    );
    let m = lb.metrics().await;
    assert!(metric(&m, "tas_lb_bytes_up_total") >= TOTAL as u64);
    assert!(metric(&m, "tas_lb_bytes_down_total") >= TOTAL as u64);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_flows_all_complete_and_accounting_returns_to_zero() {
    const N: usize = 1200;
    let port = free_tcp_port();
    let mut backends = Vec::new();
    for i in 0..4u8 {
        backends
            .push(TestBackend::start(&format!("b{i}"), 51 + i, port, Behavior::default()).await);
    }
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits: Some(
            serde_json::json!({"max_flows": 4096, "max_pending": 4096, "accept_backlog": 4096}),
        ),
        ..LbOpts::default()
    })
    .await;
    lb.push(
        1,
        &make_set(backends.iter().map(TestBackend::spec).collect()),
    )
    .unwrap();
    lb.wait_eligible(&["b0", "b1", "b2", "b3"]).await;

    let addr = lb.tcp_addr;
    let mut tasks = Vec::new();
    for i in 0..N {
        tasks.push(tokio::spawn(async move {
            let (mut s, name) = connect_named(addr).await;
            // Hold the flow open concurrently with all the others before doing any I/O.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let msg = vec![u8::try_from(i % 251).unwrap(); 4096];
            assert_eq!(echo_roundtrip(&mut s, &msg).await.unwrap(), msg);
            name
        }));
    }
    let mut per: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for t in tasks {
        *per.entry(t.await.unwrap()).or_default() += 1;
    }
    assert_eq!(per.values().sum::<usize>(), N);
    assert!(per.len() == 4, "{per:?}");
    // Balanced to within reason (keyed hash over 1200 flows, 4 equal backends).
    assert!(
        per.values().all(|n| *n > N / 4 / 2 && *n < N / 4 * 2),
        "{per:?}"
    );
    eventually("all flows released", Duration::from_secs(5), || {
        lb.lb.shared().flows.is_empty()
    })
    .await;
    assert!(backends
        .iter()
        .all(|b| b.accepted.load(std::sync::atomic::Ordering::SeqCst) > 0));
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_lets_the_other_direction_finish() {
    let (lb, _b) = one_backend_lb(
        Behavior {
            trailer_on_eof: true,
            ..Behavior::default()
        },
        None,
    )
    .await;
    let (mut s, _) = connect_named(lb.tcp_addr).await;
    s.write_all(b"request").await.unwrap();
    s.shutdown().await.unwrap(); // FIN: the request is complete, the response is still to come
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rest, b"requestbye\n",
        "echo then the trailer sent only after the backend saw our FIN"
    );
    eventually("flow released", Duration::from_secs(3), || {
        lb.lb.shared().flows.is_empty()
    })
    .await;
    let m = lb.metrics().await;
    assert_eq!(metric(&m, "tas_lb_flows_closed_total{reason=\"clean\"}"), 1);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_half_closed_flow_does_not_linger_past_the_half_close_timeout() {
    let (lb, _b) = one_backend_lb(
        Behavior {
            greet: false,
            hold_after_eof: true,
            ..Behavior::default()
        },
        Some(serde_json::json!({"half_close_timeout_secs": 1, "tcp_idle_timeout_secs": 60})),
    )
    .await;
    // The backend ignores our FIN and never closes: without a bound this flow would live forever.
    let mut s = TcpStream::connect(lb.tcp_addr).await.unwrap();
    assert_eq!(echo_roundtrip(&mut s, b"x").await.unwrap(), b"x");
    s.shutdown().await.unwrap();
    let t = std::time::Instant::now();
    assert!(is_closed_within(&mut s, Duration::from_secs(5)).await);
    assert!(
        t.elapsed() >= Duration::from_millis(800),
        "the half-close grace period was honoured"
    );
    eventually("flow released", Duration::from_secs(3), || {
        lb.lb.shared().flows.is_empty()
    })
    .await;
    let m = lb.metrics().await;
    assert_eq!(
        metric(
            &m,
            "tas_lb_flows_closed_total{reason=\"half_close_timeout\"}"
        ),
        1
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_flow_is_reset_but_an_active_one_is_not() {
    let (lb, _b) = one_backend_lb(
        Behavior::default(),
        Some(serde_json::json!({"tcp_idle_timeout_secs": 1})),
    )
    .await;
    let (mut idle, _) = connect_named(lb.tcp_addr).await;
    let (mut busy, _) = connect_named(lb.tcp_addr).await;
    for _ in 0..8 {
        assert_eq!(echo_roundtrip(&mut busy, b"ping").await.unwrap(), b"ping");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        is_closed_within(&mut idle, Duration::from_secs(2)).await,
        "idle flow must be reset"
    );
    assert_eq!(
        echo_roundtrip(&mut busy, b"ping").await.unwrap(),
        b"ping",
        "traffic in either direction keeps a flow alive"
    );
    let m = lb.metrics().await;
    assert_eq!(metric(&m, "tas_lb_flows_closed_total{reason=\"idle\"}"), 1);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_stops_reading_trips_the_write_stall_bound_and_frees_the_flow() {
    let (lb, _b) = one_backend_lb(
        Behavior {
            greet: false,
            ..Behavior::default()
        },
        Some(serde_json::json!({"write_stall_timeout_secs": 1, "buffer_bytes": 4096})),
    )
    .await;
    // Send a lot, never read the echo: socket buffers fill, the LB's write to us stalls.
    let mut s = TcpStream::connect(lb.tcp_addr).await.unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if s.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .await;
    eventually("stalled flow released", Duration::from_secs(10), || {
        lb.lb.shared().flows.is_empty()
    })
    .await;
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_waits_for_flows_then_resets_the_rest() {
    let port = free_tcp_port();
    let b = TestBackend::start("solo", 61, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits: Some(serde_json::json!({"shutdown_grace_secs": 1})),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![b.spec()])).unwrap();
    lb.wait_eligible(&["solo"]).await;
    let addr = lb.tcp_addr;
    let (mut s, _) = connect_named(addr).await;
    let started = std::time::Instant::now();
    lb.lb.shutdown().await;
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "shutdown waited for the grace period"
    );
    assert!(
        is_closed_within(&mut s, Duration::from_secs(2)).await,
        "remaining flows are reset after the grace period"
    );
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "no longer listening"
    );
}
