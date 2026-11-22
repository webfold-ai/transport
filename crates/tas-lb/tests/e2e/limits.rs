//! Bounds under abuse: per-source and global flow limits, per-source rate, the bounded setup queue,
//! UDP limits and idle expiry. Each refusal must be counted and must not leak accounting.

use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

use crate::common::*;

async fn lb_with(limits: serde_json::Value, trusted: &[&str]) -> (Lb, TestBackend) {
    let port = free_tcp_port();
    let b = TestBackend::start("solo", 81, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits: Some(limits),
        listeners: Some(vec![serde_json::json!({"name": "main", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port, "trusted_proxy_cidrs": trusted})]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![b.spec()])).unwrap();
    lb.wait_eligible(&["solo"]).await;
    (lb, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_source_flow_limit_refuses_the_excess_and_frees_on_close() {
    let (lb, _b) = lb_with(serde_json::json!({"max_flows_per_source": 3}), &[]).await;
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(try_connect_named(lb.tcp_addr).await.unwrap());
    }
    for _ in 0..5 {
        assert!(
            try_connect_named(lb.tcp_addr).await.is_none(),
            "the fourth concurrent flow from one source is refused"
        );
    }
    assert_eq!(
        metric(
            &lb.metrics().await,
            "tas_lb_rejected_total{reason=\"per_source\"}"
        ),
        5
    );
    assert_eq!(lb.lb.shared().flows.len(), 3, "refusals leak no accounting");
    drop(held.pop());
    let mut again = None;
    for _ in 0..50 {
        again = try_connect_named(lb.tcp_addr).await;
        if again.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(again.is_some(), "closing a flow frees its slot");
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_source_limit_applies_to_the_client_named_by_a_trusted_header_not_to_the_sender() {
    use tas_lb::proxy_protocol::{encode, Transport};
    use tokio::io::AsyncWriteExt;
    let (lb, _b) = lb_with(
        serde_json::json!({"max_flows_per_source": 2}),
        &["127.0.0.0/8"],
    )
    .await;
    let connect_as = |client: &str| {
        let client: std::net::SocketAddr = client.parse().unwrap();
        let addr = lb.tcp_addr;
        async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(
                encode(
                    client,
                    "198.51.100.7:443".parse().unwrap(),
                    Transport::Stream,
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut line = [0u8; 5];
            match tokio::time::timeout(
                Duration::from_secs(2),
                tokio::io::AsyncReadExt::read_exact(&mut s, &mut line),
            )
            .await
            {
                Ok(Ok(_)) => Some(s),
                _ => None,
            }
        }
    };
    // One trusted sender (127.0.0.1) fronting many clients: each client gets its own budget.
    let mut held = Vec::new();
    for c in [
        "203.0.113.1:1",
        "203.0.113.1:2",
        "203.0.113.2:1",
        "203.0.113.2:2",
        "203.0.113.3:1",
    ] {
        let conn = connect_as(c).await;
        assert!(conn.is_some(), "{c} within its own limit");
        held.push(conn.unwrap());
    }
    assert!(
        connect_as("203.0.113.1:3").await.is_none(),
        "client .1 is at its limit of 2"
    );
    assert!(
        connect_as("203.0.113.3:2").await.is_some(),
        "client .3 still has budget"
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_global_flow_limit_holds() {
    let (lb, _b) = lb_with(serde_json::json!({"max_flows": 4}), &[]).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(try_connect_named(lb.tcp_addr).await.unwrap());
    }
    for _ in 0..4 {
        assert!(try_connect_named(lb.tcp_addr).await.is_none());
    }
    assert_eq!(
        metric(
            &lb.metrics().await,
            "tas_lb_rejected_total{reason=\"max_flows\"}"
        ),
        4
    );
    assert_eq!(lb.lb.shared().flows.len(), 4);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_source_new_flow_rate_limit_throttles_a_connection_storm() {
    let (lb, _b) = lb_with(serde_json::json!({"new_flows_per_source_per_sec": 5}), &[]).await;
    let mut ok = 0u64;
    let mut handles = Vec::new();
    for _ in 0..40 {
        if let Some(c) = try_connect_named(lb.tcp_addr).await {
            ok += 1;
            handles.push(c); // keep them open; they are not what is being limited here
        }
    }
    // Fixed one-second windows allow at most 2x the limit across a boundary.
    assert!((5..=10).contains(&ok), "{ok} of 40 admitted");
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_rejected_total{reason=\"rate_limited\"}"),
        40 - ok
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_senders_cannot_grow_the_setup_queue_past_its_bound() {
    // Every connection from 127.0.0.1 is a trusted sender that owes a header; two setup permits.
    let (lb, _b) = lb_with(
        serde_json::json!({"max_pending": 2, "proxy_header_timeout_ms": 500}),
        &["127.0.0.0/8"],
    )
    .await;
    let mut conns = Vec::new();
    let mut closed_fast = 0;
    for _ in 0..10 {
        // A refusal may beat connect()'s own completion; that is a fast close too.
        match TcpStream::connect(lb.tcp_addr).await {
            Ok(c) => conns.push(c),
            Err(_) => closed_fast += 1,
        }
    }
    // The 8 beyond the bound are reset immediately; the 2 holding permits wait out the timeout.
    for c in &mut conns {
        if is_closed_within(c, Duration::from_millis(30)).await {
            closed_fast += 1;
        }
    }
    assert_eq!(
        closed_fast, 8,
        "exactly the connections beyond max_pending are refused at once"
    );
    assert_eq!(
        metric(
            &lb.metrics().await,
            "tas_lb_rejected_total{reason=\"pending_full\"}"
        ),
        8
    );
    // The permit holders time out and release their permits.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_proxy_in_rejected_total{reason=\"timeout\"}"),
        2
    );
    // Capacity is back.
    let mut s = TcpStream::connect(lb.tcp_addr).await.unwrap();
    assert!(
        !is_closed_within(&mut s, Duration::from_millis(250)).await,
        "a new connection now gets a setup permit"
    );
    lb.lb.shutdown().await;
}

async fn ask(vip: std::net::SocketAddr, c: &UdpSocket, payload: &'static [u8]) -> Option<usize> {
    c.send_to(payload, vip).await.unwrap();
    let mut buf = [0u8; 700];
    tokio::time::timeout(Duration::from_millis(500), c.recv_from(&mut buf))
        .await
        .ok()
        .map(|r| r.unwrap().0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_flows_are_limited_per_source_and_expire_when_idle() {
    let port = free_udp_port();
    let ub = UdpBackend::start("u1", 82, port, true).await;
    let _tcp = TestBackend::start("u1", 82, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits: Some(serde_json::json!({"max_flows_per_source": 2, "udp_idle_timeout_secs": 1, "udp_max_datagram": 600})),
        listeners: Some(vec![
            serde_json::json!({"name": "dgram", "proto": "udp", "bind": "127.0.0.1:0", "backend_port": port}),
            serde_json::json!({"name": "main", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port}),
        ]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![ub.spec()])).unwrap();
    lb.wait_eligible(&["u1"]).await;
    let vip = lb
        .lb
        .listeners
        .iter()
        .find(|l| l.name == "dgram")
        .unwrap()
        .addr;

    let (c1, c2, c3) = (
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    );
    assert!(ask(vip, &c1, b"1").await.is_some());
    assert!(ask(vip, &c2, b"2").await.is_some());
    assert!(
        ask(vip, &c3, b"3").await.is_none(),
        "third flow from one source exceeds max_flows_per_source"
    );
    assert_eq!(
        metric(
            &lb.metrics().await,
            "tas_lb_rejected_total{reason=\"per_source\"}"
        ),
        1
    );

    // Oversize datagram: dropped and counted, not truncated and forwarded.
    let big = vec![9u8; 601];
    c1.send_to(&big, vip).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        metric(
            &lb.metrics().await,
            "tas_lb_rejected_total{reason=\"udp_too_big\"}"
        ),
        1
    );

    // Idle expiry frees the table and the per-source budget.
    eventually("udp flows expire", Duration::from_secs(5), || {
        lb.lb.shared().flows.is_empty()
    })
    .await;
    assert!(
        ask(vip, &c3, b"3").await.is_some(),
        "after expiry the budget is back"
    );
    lb.lb.shutdown().await;
}
