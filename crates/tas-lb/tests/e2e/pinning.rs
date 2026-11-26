//! The reviewer's concern, end to end: an established flow is never remapped while its backend is
//! healthy and in the set; removed / unhealthy backends drain; health transitions steer NEW flows.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

use crate::common::*;

async fn four_backends(port: u16) -> Vec<TestBackend> {
    let mut v = Vec::new();
    for (i, n) in ["a", "b", "c", "d"].iter().enumerate() {
        v.push(
            TestBackend::start(n, 21 + u8::try_from(i).unwrap(), port, Behavior::default()).await,
        );
    }
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_flows_stay_on_their_backend_through_any_change_to_the_set() {
    let port = free_tcp_port();
    let backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    lb.push(
        1,
        &make_set(backends.iter().map(TestBackend::spec).collect()),
    )
    .unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;

    // 80 established flows, each remembering which backend greeted it.
    let mut flows = Vec::new();
    let mut spread: HashMap<String, usize> = HashMap::new();
    for _ in 0..80 {
        let (s, name) = connect_named(lb.tcp_addr).await;
        *spread.entry(name.clone()).or_default() += 1;
        flows.push((s, name));
    }
    assert!(
        spread.len() >= 3,
        "new flows should spread over the set: {spread:?}"
    );

    // Heavy churn: new hash key, reweights, two new backends, one admin-drained... but a, b, c, d
    // (the owners of every established flow) stay healthy and in the set.
    let e = TestBackend::start("e", 25, port, Behavior::default()).await;
    let f = TestBackend::start("f", 26, port, Behavior::default()).await;
    let mut set = make_set(
        backends
            .iter()
            .map(TestBackend::spec)
            .chain([e.spec(), f.spec()])
            .collect(),
    );
    set.hash_key = "17".repeat(32);
    set.backends[0].weight = 900;
    set.backends[1].weight = 1;
    set.backends[4].drain = true;
    lb.push(2, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d", "f"]).await;
    set.hash_key = "99".repeat(32);
    set.backends[5].weight = 500;
    lb.push(3, &set).unwrap();

    // Every established flow still works, and its echo comes from the same connection (the
    // backend that greeted it is the only one that can answer on it).
    for (i, (s, name)) in flows.iter_mut().enumerate() {
        let msg = format!("flow-{i}-{name}").into_bytes();
        assert_eq!(echo_roundtrip(s, &msg).await.unwrap(), msg);
    }
    // And the per-backend flow gauges still account for exactly the original spread.
    let m = lb.metrics().await;
    for (name, n) in &spread {
        assert_eq!(
            metric(&m, &format!("tas_lb_backend_flows{{backend=\"{name}\"}}")),
            *n as u64,
            "{name}"
        );
    }
    assert_eq!(
        metric(&m, "tas_lb_flows_closed_total{reason=\"drain_reset\"}"),
        0
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_flows_are_pinned_by_the_tracking_table_not_by_the_hash() {
    let port = free_udp_port();
    let mut ubs = Vec::new();
    for (i, n) in ["a", "b", "c", "d"].iter().enumerate() {
        ubs.push(UdpBackend::start(n, 31 + u8::try_from(i).unwrap(), port, true).await);
    }
    // The TCP probe port is unused for UDP-only flows; health needs something listening on it, so
    // run TCP health targets on the same ports.
    let mut tcp = Vec::new();
    for (i, n) in ["a", "b", "c", "d"].iter().enumerate() {
        tcp.push(
            TestBackend::start(n, 31 + u8::try_from(i).unwrap(), port, Behavior::default()).await,
        );
    }
    let lb = start_lb(LbOpts {
        backend_port: port,
        listeners: Some(vec![
            serde_json::json!({"name": "dgram", "proto": "udp", "bind": "127.0.0.1:0", "backend_port": port}),
            serde_json::json!({"name": "main", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port}),
        ]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(ubs.iter().map(UdpBackend::spec).collect()))
        .unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;
    let udp_addr = lb
        .lb
        .listeners
        .iter()
        .find(|l| l.name == "dgram")
        .unwrap()
        .addr;

    // 60 client sockets = 60 flows.
    let mut clients = Vec::new();
    let mut first: Vec<String> = Vec::new();
    for i in 0..60 {
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(format!("hello-{i}").as_bytes(), udp_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let reply = String::from_utf8(buf[..n].to_vec()).unwrap();
        let (name, rest) = reply.split_once(':').unwrap();
        assert_eq!(rest, format!("hello-{i}"));
        first.push(name.to_string());
        clients.push(c);
    }
    assert!(first.iter().collect::<std::collections::HashSet<_>>().len() >= 3);

    // Change the set under them: new key, new members, reweight, drain one of the others.
    let e = UdpBackend::start("e", 35, port, true).await;
    let _e_tcp = TestBackend::start("e", 35, port, Behavior::default()).await;
    let mut set = make_set(ubs.iter().map(UdpBackend::spec).chain([e.spec()]).collect());
    set.hash_key = "c3".repeat(32);
    set.backends[0].weight = 1000;
    set.backends[3].drain = true; // d: admin drain, flows must keep working until the deadline
    lb.push(2, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "e"]).await;

    // Every established UDP flow still reaches its original backend.
    for (i, c) in clients.iter().enumerate() {
        c.send_to(format!("again-{i}").as_bytes(), udp_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let reply = String::from_utf8(buf[..n].to_vec()).unwrap();
        assert_eq!(
            reply.split_once(':').unwrap().0,
            first[i],
            "client {i} was remapped"
        );
    }
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_backend_drains_then_its_flows_are_reset_and_it_takes_no_new_flows() {
    let port = free_tcp_port();
    let backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(backends.iter().map(TestBackend::spec).collect());
    set.drain_timeout_ms = 700;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;

    let mut on_d = Vec::new();
    let mut others = Vec::new();
    for _ in 0..60 {
        let (s, name) = connect_named(lb.tcp_addr).await;
        if name == "d" {
            on_d.push(s)
        } else {
            others.push(s)
        }
    }
    assert!(!on_d.is_empty());

    // Remove d.
    set.backends.remove(3);
    lb.push(2, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c"]).await;
    for _ in 0..40 {
        let (_s, name) = connect_named(lb.tcp_addr).await;
        assert_ne!(name, "d", "a removed backend must take no new flows");
    }

    // During the drain window (700 ms; the supervisor ticks every 100 ms, so by now several ticks
    // have run) its flows keep working...
    tokio::time::sleep(Duration::from_millis(350)).await;
    for s in &mut on_d {
        assert_eq!(
            echo_roundtrip(s, b"still-here").await.unwrap(),
            b"still-here"
        );
    }
    // ...and after the deadline they are reset, while everyone else is untouched.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    for s in &mut on_d {
        assert!(
            is_closed_within(s, Duration::from_secs(2)).await,
            "drain deadline must reset the flow"
        );
    }
    for s in &mut others {
        assert_eq!(
            echo_roundtrip(s, b"unaffected").await.unwrap(),
            b"unaffected"
        );
    }
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_flows_closed_total{reason=\"drain_reset\"}"),
        on_d.len() as u64
    );
    // The backend is gone once its flows are.
    eventually("d deleted", Duration::from_secs(3), || {
        !lb.lb.shared().director.gauges().iter().any(|g| g.id == "d")
    })
    .await;
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flows_that_finish_inside_the_drain_window_are_never_reset() {
    let port = free_tcp_port();
    let backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(backends.iter().map(TestBackend::spec).collect());
    set.drain_timeout_ms = 5000;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;
    let mut on_d = Vec::new();
    for _ in 0..40 {
        let (s, name) = connect_named(lb.tcp_addr).await;
        if name == "d" {
            on_d.push(s);
        }
    }
    set.backends.remove(3);
    lb.push(2, &set).unwrap();
    // The clients finish politely before the deadline.
    for mut s in on_d {
        s.write_all(b"done").await.unwrap();
        s.shutdown().await.unwrap();
        drop(s);
    }
    eventually("d deleted with no resets", Duration::from_secs(3), || {
        !lb.lb.shared().director.gauges().iter().any(|g| g.id == "d")
    })
    .await;
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_flows_closed_total{reason=\"drain_reset\"}"),
        0
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unhealthy_backend_stops_getting_new_flows_and_gets_them_back_on_recovery() {
    let port = free_tcp_port();
    let mut backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(backends.iter().map(TestBackend::spec).collect());
    set.drain_timeout_ms = 60_000;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;

    // An established flow on b (find one).
    let mut on_b = loop {
        let (s, name) = connect_named(lb.tcp_addr).await;
        if name == "b" {
            break s;
        }
    };
    backends[1].stop_listening(); // b's port closes: probes fail
    lb.wait_eligible(&["a", "c", "d"]).await;
    for _ in 0..40 {
        assert_ne!(
            connect_named(lb.tcp_addr).await.1,
            "b",
            "an unhealthy backend must take no new flows"
        );
    }
    // Its established flow is not touched while the drain window is open.
    assert_eq!(echo_roundtrip(&mut on_b, b"alive").await.unwrap(), b"alive");

    backends[1].restart_listening().await;
    lb.wait_eligible(&["a", "b", "c", "d"]).await;
    let mut saw_b = false;
    for _ in 0..80 {
        saw_b |= connect_named(lb.tcp_addr).await.1 == "b";
    }
    assert!(saw_b, "a recovered backend takes new flows again");
    assert_eq!(
        echo_roundtrip(&mut on_b, b"still-alive").await.unwrap(),
        b"still-alive"
    );
    let m = lb.metrics().await;
    assert!(metric(&m, "tas_lb_health_transitions_total{to=\"down\"}") >= 1);
    assert!(metric(&m, "tas_lb_health_transitions_total{to=\"up\"}") >= 5);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unhealthy_backend_that_stays_down_has_its_flows_reset_at_the_deadline() {
    let port = free_tcp_port();
    let mut backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(backends.iter().map(TestBackend::spec).collect());
    set.drain_timeout_ms = 500;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await;
    let mut on_c = loop {
        let (s, name) = connect_named(lb.tcp_addr).await;
        if name == "c" {
            break s;
        }
    };
    backends[2].stop_listening();
    lb.wait_eligible(&["a", "b", "d"]).await;
    assert!(is_closed_within(&mut on_c, Duration::from_secs(4)).await);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_backend_not_yet_detected_is_skipped_by_a_retry_and_demoted_by_passive_failures() {
    let port = free_tcp_port();
    let mut backends = four_backends(port).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(backends.iter().map(TestBackend::spec).collect());
    // Active probing so slow it cannot be what notices: passive failures must do it.
    set.health.interval_ms = 60_000;
    set.health.timeout_ms = 1000;
    set.health.rise = 1;
    set.health.fall = 3;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["a", "b", "c", "d"]).await; // the first probe round marks everyone Up
    backends[0].stop_listening();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Every connection succeeds (retry lands on a live backend) and none is served by `a`.
    let mut conns = Vec::new();
    for _ in 0..60 {
        let (s, name) = connect_named(lb.tcp_addr).await;
        assert_ne!(name, "a");
        conns.push(s);
    }
    let m = lb.metrics().await;
    assert!(
        metric(&m, "tas_lb_health_transitions_total{to=\"down\"}") >= 1,
        "passive failures demote the dead backend"
    );
    lb.wait_eligible(&["b", "c", "d"]).await;
    lb.lb.shutdown().await;
}
