//! The signed config path end to end: mesh push, rollback refusal, fail closed, persistence,
//! the metrics endpoint, and the "logs never contain payload" property.

use std::time::Duration;

use tas_lb::control::{self, PushReply};
use tas_lb::proxy_protocol::{encode, Transport};
use tas_lb::signed_config::{sign_body, sign_set};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use transport::native::NativeEndpoint;

use crate::common::*;

async fn control_plane_endpoint() -> NativeEndpoint {
    // The control plane's mesh identity IS its dialkey-derived key; configs are signed with it too.
    NativeEndpoint::bind_with_dialkey("127.0.0.1:0", DIALKEY)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_verified_config_the_lb_fails_closed_and_reports_not_ready() {
    let port = free_tcp_port();
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    // The LB resets so fast that the reset can beat connect()'s own completion: both count.
    if let Ok(mut s) = TcpStream::connect(lb.tcp_addr).await {
        assert!(is_closed_within(&mut s, Duration::from_secs(2)).await);
    }
    let (status, _) = http_get(lb.lb.metrics_addr, "/readyz").await;
    assert_eq!(status, 503);
    assert_eq!(
        http_get(lb.lb.metrics_addr, "/healthz").await.0,
        200,
        "liveness is separate from readiness"
    );
    let m = lb.metrics().await;
    assert_eq!(metric(&m, "tas_lb_config_loaded"), 0);
    assert_eq!(
        metric(&m, "tas_lb_rejected_total{reason=\"no_backend\"}"),
        1
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_config_keeps_the_last_good_one_serving_and_raises_the_alert_metrics() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 91, port, Behavior::default()).await;
    let b = TestBackend::start("b", 92, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    lb.push(100, &make_set(vec![a.spec()])).unwrap();
    lb.wait_eligible(&["a"]).await;
    let (mut held, _) = connect_named(lb.tcp_addr).await;

    let good_b = make_set(vec![b.spec()]);
    // Rollback and replay.
    for seq in [100, 99, 1] {
        assert!(lb.push(seq, &good_b).is_err(), "seq {seq}");
    }
    // Wrong signer.
    let impostor = transport::signed_dns::Keypair::from_secret_key(&[9; 32]);
    assert!(lb
        .lb
        .apply_signed(&sign_set(&impostor, 200, &good_b).unwrap())
        .is_err());
    // Wrong cluster.
    let mut other = good_b.clone();
    other.cluster = "other-pop".into();
    assert!(lb.push(201, &other).is_err());
    // Signed garbage and structural garbage.
    assert!(lb
        .lb
        .apply_signed(&sign_body(&control_kp(), 202, b"{\"nope\":1}").unwrap())
        .is_err());
    assert!(lb.lb.apply_signed(b"TASLBCF1 not a document").is_err());
    // Invalid contents (loopback is allowed here; an unspecified address never is).
    let mut invalid = good_b.clone();
    invalid.backends[0].ip = "0.0.0.0".parse().unwrap();
    assert!(lb.push(203, &invalid).is_err());

    assert_eq!(
        lb.lb.config_seq(),
        100,
        "no refused document moved the floor"
    );
    // Still serving from the last good config, established and new flows alike.
    assert_eq!(echo_roundtrip(&mut held, b"x").await.unwrap(), b"x");
    assert_eq!(connect_named(lb.tcp_addr).await.1, "a");

    let m = lb.metrics().await;
    assert_eq!(metric(&m, "tas_lb_config_total{result=\"applied\"}"), 1);
    assert_eq!(metric(&m, "tas_lb_config_total{result=\"rollback\"}"), 3);
    assert_eq!(
        metric(&m, "tas_lb_config_total{result=\"bad_signature\"}"),
        1
    );
    assert_eq!(
        metric(&m, "tas_lb_config_total{result=\"wrong_cluster\"}"),
        1
    );
    assert_eq!(metric(&m, "tas_lb_config_total{result=\"invalid\"}"), 2);
    assert_eq!(metric(&m, "tas_lb_config_total{result=\"malformed\"}"), 1);
    assert!(
        metric(&m, "tas_lb_config_rejected_unixtime") > 0,
        "the alert gauge moved"
    );
    assert_eq!(metric(&m, "tas_lb_config_seq"), 100);

    // A newer, good config then applies.
    lb.push(300, &good_b).unwrap();
    lb.wait_eligible(&["b"]).await;
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_plane_pushes_over_the_sealed_mesh_and_replays_are_refused() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 93, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        control: true,
        ..LbOpts::default()
    })
    .await;
    let (ctl_addr, lb_id) = lb.lb.control.clone().unwrap();
    let cp = control_plane_endpoint().await;

    let doc = sign_set(&control_kp(), 1_000, &make_set(vec![a.spec()])).unwrap();
    assert_eq!(
        control::push(&cp, &ctl_addr, &lb_id, &doc).await.unwrap(),
        PushReply::Accepted(1_000)
    );
    lb.wait_eligible(&["a"]).await;
    assert_eq!(connect_named(lb.tcp_addr).await.1, "a");

    // The identical document again is a replay; an older one is a rollback.
    assert_eq!(
        control::push(&cp, &ctl_addr, &lb_id, &doc).await.unwrap(),
        PushReply::Refused("rollback".into())
    );
    let older = sign_set(&control_kp(), 5, &make_set(vec![a.spec()])).unwrap();
    assert_eq!(
        control::push(&cp, &ctl_addr, &lb_id, &older).await.unwrap(),
        PushReply::Refused("rollback".into())
    );
    // A control plane that pins the wrong LB identity refuses to send anything.
    assert!(matches!(
        control::push(&cp, &ctl_addr, &[7u8; 32], &doc).await,
        Err(control::PushError::WrongPeer)
    ));
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_peer_that_is_not_the_control_plane_gets_nothing_through() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 94, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        control: true,
        ..LbOpts::default()
    })
    .await;
    let (ctl_addr, lb_id) = lb.lb.control.clone().unwrap();

    // A perfectly valid, correctly signed document, pushed by a peer with some other identity
    // (say, a leaked document). The transport handshake succeeds for any key; the LB must drop it.
    let stranger = NativeEndpoint::bind("127.0.0.1:0").await.unwrap();
    let doc = sign_set(&control_kp(), 50, &make_set(vec![a.spec()])).unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        control::push(&stranger, &ctl_addr, &lb_id, &doc),
    )
    .await;
    assert!(!matches!(r, Ok(Ok(PushReply::Accepted(_)))), "{r:?}");
    eventually("peer rejection counted", Duration::from_secs(2), || {
        // counters are read synchronously from the shared state
        lb.lb.shared().metrics.config.get(7) == 1
    })
    .await;
    assert_eq!(lb.lb.config_seq(), 0);
    assert!(!lb.lb.shared().director.is_configured());
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_good_config_and_its_rollback_floor_survive_a_restart() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 95, port, Behavior::default()).await;
    let state = tempfile::tempdir().unwrap();
    let lb = start_lb(LbOpts {
        backend_port: port,
        dir: Some(state.path().to_path_buf()),
        ..LbOpts::default()
    })
    .await;
    lb.push(500, &make_set(vec![a.spec()])).unwrap();
    lb.wait_eligible(&["a"]).await;
    lb.lb.shutdown().await;

    // Restart on the same state directory with no push: serves from the persisted document.
    let lb2 = start_lb(LbOpts {
        backend_port: port,
        dir: Some(state.path().to_path_buf()),
        ..LbOpts::default()
    })
    .await;
    assert_eq!(lb2.lb.config_seq(), 500);
    lb2.wait_eligible(&["a"]).await;
    assert_eq!(connect_named(lb2.tcp_addr).await.1, "a");
    // An attacker replaying an older (validly signed) document after the restart is refused.
    assert!(lb2.push(499, &make_set(vec![a.spec()])).is_err());
    lb2.lb.shutdown().await;

    // The operator can also revoke by raising the static floor.
    let lb3 = start_lb(LbOpts {
        backend_port: port,
        dir: Some(state.path().to_path_buf()),
        min_seq: 500,
        ..LbOpts::default()
    })
    .await;
    assert!(
        !lb3.lb.shared().director.is_configured(),
        "persisted seq 500 is not above the floor 500"
    );
    lb3.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_persisted_config_is_not_believed() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 96, port, Behavior::default()).await;
    let state = tempfile::tempdir().unwrap();
    let lb = start_lb(LbOpts {
        backend_port: port,
        dir: Some(state.path().to_path_buf()),
        ..LbOpts::default()
    })
    .await;
    lb.push(7, &make_set(vec![a.spec()])).unwrap();
    lb.lb.shutdown().await;
    let path = state.path().join("config.signed");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[40] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
    let lb2 = start_lb(LbOpts {
        backend_port: port,
        dir: Some(state.path().to_path_buf()),
        ..LbOpts::default()
    })
    .await;
    assert!(!lb2.lb.shared().director.is_configured());
    assert_eq!(
        metric(
            &lb2.metrics().await,
            "tas_lb_config_total{result=\"bad_signature\"}"
        ),
        1
    );
    assert!(state.path().join("config.signed.rejected").exists());
    lb2.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_metrics_endpoint_serves_aggregates_only_and_rejects_everything_else() {
    let port = free_tcp_port();
    let a = TestBackend::start("a", 97, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![a.spec()])).unwrap();
    lb.wait_eligible(&["a"]).await;
    let (mut s, _) = connect_named(lb.tcp_addr).await;
    let client = s.local_addr().unwrap();
    assert_eq!(
        echo_roundtrip(&mut s, b"CANARY-PAYLOAD-0451")
            .await
            .unwrap(),
        b"CANARY-PAYLOAD-0451"
    );

    let (status, body) = http_get(lb.lb.metrics_addr, "/metrics").await;
    assert_eq!(status, 200);
    assert!(body.contains("tas_lb_backend_up{backend=\"a\",health=\"up\",admin=\"active\"} 1"));
    assert!(body.contains("tas_lb_flows_active 1"));
    assert!(!body.contains("CANARY"), "no payload in metrics");
    assert!(
        !body.contains(&client.to_string()),
        "no client addresses in metrics"
    );
    assert_eq!(http_get(lb.lb.metrics_addr, "/readyz").await.0, 200);
    assert_eq!(http_get(lb.lb.metrics_addr, "/debug/pprof").await.0, 404);
    assert_eq!(
        http_request(lb.lb.metrics_addr, "POST", "/metrics").await.0,
        405
    );
    // Garbage and an oversize head do not hurt it.
    let mut g = TcpStream::connect(lb.lb.metrics_addr).await.unwrap();
    g.write_all(&vec![b'A'; 8192]).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::io::AsyncReadExt::read_to_end(&mut g, &mut out).await;
    assert_eq!(http_get(lb.lb.metrics_addr, "/healthz").await.0, 200);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logs_never_contain_payload_or_header_contents() {
    init_logs();
    let port = free_tcp_port();
    let b = TestBackend::start("a", 98, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        listeners: Some(vec![
            serde_json::json!({"name": "plain", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port}),
            serde_json::json!({"name": "behind", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port, "trusted_proxy_cidrs": ["127.0.0.0/8"]}),
        ]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![b.spec()])).unwrap();
    lb.wait_eligible(&["a"]).await;
    let plain = lb
        .lb
        .listeners
        .iter()
        .find(|l| l.name == "plain")
        .unwrap()
        .addr;
    let behind = lb
        .lb
        .listeners
        .iter()
        .find(|l| l.name == "behind")
        .unwrap()
        .addr;

    // Ordinary traffic with a canary payload.
    let (mut s, _) = connect_named(plain).await;
    echo_roundtrip(&mut s, b"PAYLOAD-CANARY-7731")
        .await
        .unwrap();
    // A spoofed header whose TLV carries a canary, from an untrusted... both of ours are loopback,
    // so use a malformed header on the trusted listener and a spoof on a fresh untrusted path.
    let mut bad = encode(
        "203.0.113.9:1".parse().unwrap(),
        "198.51.100.7:443".parse().unwrap(),
        Transport::Stream,
    )
    .as_bytes()
    .to_vec();
    bad[12] = 0x11; // wrong version -> refused and logged
    bad.extend_from_slice(b"TLV-CANARY-5519");
    let mut t = TcpStream::connect(behind).await.unwrap();
    t.write_all(&bad).await.unwrap();
    assert!(is_closed_within(&mut t, Duration::from_secs(2)).await);
    // Invalid config pushes (the hash key is secret and appears in the rejected document).
    let mut set = make_set(vec![b.spec()]);
    set.hash_key = "SECRET-HASH-KEY-CANARY".into();
    assert!(lb.push(2, &set).is_err());
    lb.lb.shutdown().await;

    let logs = String::from_utf8(LOGS.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("listening") && logs.contains("config applied"),
        "the capture works and the LB logs"
    );
    for canary in [
        "PAYLOAD-CANARY-7731",
        "TLV-CANARY-5519",
        "SECRET-HASH-KEY-CANARY",
        &"5a".repeat(32),
    ] {
        assert!(!logs.contains(canary), "logs leaked {canary}");
    }
}
