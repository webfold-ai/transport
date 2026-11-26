//! PROXY protocol v2 on the wire: emitted to backends with the real client and VIP; accepted on the
//! frontend only from trusted senders; spoofs from everyone else rejected and counted.

use std::net::SocketAddr;
use std::time::Duration;

use tas_lb::proxy_protocol::{self, Command, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::common::*;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

async fn lb_with_listeners(port: u16, trusted: &[&str]) -> (Lb, TestBackend) {
    let b = TestBackend::start("solo", 71, port, Behavior::default()).await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        limits: Some(serde_json::json!({"proxy_header_timeout_ms": 300})),
        listeners: Some(vec![
            serde_json::json!({"name": "plain", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port}),
            serde_json::json!({"name": "behind-proxy", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port, "trusted_proxy_cidrs": trusted}),
        ]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![b.spec()])).unwrap();
    lb.wait_eligible(&["solo"]).await;
    (lb, b)
}

fn addr_of(lb: &Lb, name: &str) -> SocketAddr {
    lb.lb
        .listeners
        .iter()
        .find(|l| l.name == name)
        .unwrap()
        .addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_backend_receives_the_real_client_and_vip_in_a_v2_header_before_any_payload() {
    let port = free_tcp_port();
    let (lb, b) = lb_with_listeners(port, &[]).await;
    let vip = addr_of(&lb, "plain");
    let (mut s, _) = connect_named(vip).await;
    let client = s.local_addr().unwrap();
    assert_eq!(
        echo_roundtrip(&mut s, b"payload").await.unwrap(),
        b"payload"
    );
    let headers = b.headers.lock().unwrap().clone();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].command, Command::Proxy);
    assert_eq!(headers[0].transport, Transport::Stream);
    assert_eq!(
        headers[0].addrs,
        Some((client, vip)),
        "source address preserved via PROXY v2"
    );
    assert_eq!(
        &b.received.lock().unwrap()[..],
        b"payload",
        "the header is not part of the payload"
    );
    assert_eq!(metric(&lb.metrics().await, "tas_lb_proxy_out_total"), 1);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_proxy_off_the_backend_sees_only_the_payload() {
    let port = free_tcp_port();
    let b = TestBackend::start(
        "plain",
        72,
        port,
        Behavior {
            expect_proxy: false,
            ..Behavior::default()
        },
    )
    .await;
    let lb = start_lb(LbOpts {
        backend_port: port,
        ..LbOpts::default()
    })
    .await;
    let mut set = make_set(vec![b.spec()]);
    set.send_proxy_v2 = false;
    lb.push(1, &set).unwrap();
    lb.wait_eligible(&["plain"]).await;
    let (mut s, name) = connect_named(lb.tcp_addr).await;
    assert_eq!(name, "plain");
    assert_eq!(
        echo_roundtrip(&mut s, b"raw-bytes").await.unwrap(),
        b"raw-bytes"
    );
    assert!(b.received.lock().unwrap().starts_with(b"raw-bytes"));
    assert_eq!(metric(&lb.metrics().await, "tas_lb_proxy_out_total"), 0);
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trusted_senders_header_is_honoured_end_to_end() {
    let port = free_tcp_port();
    let (lb, b) = lb_with_listeners(port, &["127.0.0.0/8"]).await;
    let mut s = TcpStream::connect(addr_of(&lb, "behind-proxy"))
        .await
        .unwrap();
    let hdr = proxy_protocol::encode(
        sa("203.0.113.9:4242"),
        sa("198.51.100.7:443"),
        Transport::Stream,
    );
    s.write_all(hdr.as_bytes()).await.unwrap();
    s.write_all(b"hello").await.unwrap();
    assert_eq!(read_line(&mut s).await, "solo");
    let mut got = [0u8; 5];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    let headers = b.headers.lock().unwrap().clone();
    assert_eq!(
        headers[0].addrs,
        Some((sa("203.0.113.9:4242"), sa("198.51.100.7:443"))),
        "the original client survives a second hop"
    );
    assert_eq!(&b.received.lock().unwrap()[..], b"hello");
    assert_eq!(
        metric(&lb.metrics().await, "tas_lb_proxy_in_accepted_total"),
        1
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trusted_sender_must_send_a_valid_header_and_every_failure_is_counted_by_reason() {
    let port = free_tcp_port();
    let (lb, b) = lb_with_listeners(port, &["127.0.0.0/8"]).await;
    let addr = addr_of(&lb, "behind-proxy");

    // No header at all: an HTTP request.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(is_closed_within(&mut s, Duration::from_secs(2)).await);

    // Silence (header timeout 300 ms).
    let mut s = TcpStream::connect(addr).await.unwrap();
    assert!(is_closed_within(&mut s, Duration::from_secs(2)).await);

    // A datagram-transport header on a stream listener.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        proxy_protocol::encode(
            sa("203.0.113.9:1"),
            sa("198.51.100.7:443"),
            Transport::Datagram,
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(is_closed_within(&mut s, Duration::from_secs(2)).await);

    // A signature then a malformed TLV region.
    let mut bad = proxy_protocol::SIGNATURE.to_vec();
    bad.extend_from_slice(&[0x21, 0x11, 0x00, 0x11]);
    bad.extend_from_slice(&[203, 0, 113, 9, 198, 51, 100, 7, 0x10, 0x92, 0x01, 0xBB]);
    bad.extend_from_slice(&[0x01, 0x00, 0x09, b'h', b'2']);
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&bad).await.unwrap();
    assert!(is_closed_within(&mut s, Duration::from_secs(2)).await);

    let m = lb.metrics().await;
    assert_eq!(
        metric(
            &m,
            "tas_lb_proxy_in_rejected_total{reason=\"bad_signature\"}"
        ),
        1
    );
    assert_eq!(
        metric(&m, "tas_lb_proxy_in_rejected_total{reason=\"timeout\"}"),
        1
    );
    assert_eq!(
        metric(
            &m,
            "tas_lb_proxy_in_rejected_total{reason=\"transport_mismatch\"}"
        ),
        1
    );
    assert_eq!(
        metric(&m, "tas_lb_proxy_in_rejected_total{reason=\"bad_tlv\"}"),
        1
    );
    assert_eq!(
        metric(&m, "tas_lb_proxy_in_accepted_total"),
        0,
        "no header was accepted"
    );
    assert!(
        b.headers.lock().unwrap().is_empty(),
        "nothing reached the backend"
    );
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spoofed_header_from_an_untrusted_sender_is_rejected_counted_and_never_forwarded() {
    let port = free_tcp_port();
    let (lb, b) = lb_with_listeners(port, &["10.0.0.0/8"]).await; // 127.0.0.1 is NOT trusted
                                                                  // Both listeners: the "plain" one has no trust list, "behind-proxy" trusts only 10/8.
    for name in ["plain", "behind-proxy"] {
        let mut s = TcpStream::connect(addr_of(&lb, name)).await.unwrap();
        let hdr = proxy_protocol::encode(
            sa("203.0.113.9:4242"),
            sa("198.51.100.7:443"),
            Transport::Stream,
        );
        let mut first = hdr.as_bytes().to_vec();
        first.extend_from_slice(b"SPOOF-PAYLOAD");
        s.write_all(&first).await.unwrap();
        assert!(
            drains_to_close(&mut s, Duration::from_secs(2)).await,
            "{name}: the spoofing connection is reset"
        );
    }
    eventually("both counted", Duration::from_secs(2), || {
        b.headers.lock().unwrap().len() == 2
    })
    .await;
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_rejected_total{reason=\"proxy_untrusted\"}"),
        2
    );
    // The backend only ever saw the LB's own header (with the true client), never the claimed one,
    // and none of the spoofed bytes.
    for h in b.headers.lock().unwrap().iter() {
        assert_eq!(
            h.addrs.unwrap().0.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }
    assert!(b.received.lock().unwrap().is_empty());
    lb.lb.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_udp_plane_sends_a_header_per_datagram_and_refuses_spoofed_signatures() {
    let port = free_udp_port();
    let ub = UdpBackend::start("u1", 73, port, true).await;
    let _tcp = TestBackend::start("u1", 73, port, Behavior::default()).await; // health target
    let lb = start_lb(LbOpts {
        backend_port: port,
        listeners: Some(vec![serde_json::json!({"name": "dgram", "proto": "udp", "bind": "127.0.0.1:0", "backend_port": port}),
                             serde_json::json!({"name": "main", "proto": "tcp", "bind": "127.0.0.1:0", "backend_port": port})]),
        ..LbOpts::default()
    })
    .await;
    lb.push(1, &make_set(vec![ub.spec()])).unwrap();
    lb.wait_eligible(&["u1"]).await;
    let vip = addr_of(&lb, "dgram");

    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..3 {
        c.send_to(format!("d{i}").as_bytes(), vip).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), c.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], format!("u1:d{i}").as_bytes());
    }
    let headers = ub.headers.lock().unwrap().clone();
    assert_eq!(headers.len(), 3, "a header on every datagram");
    for h in &headers {
        assert_eq!(h.transport, Transport::Datagram);
        assert_eq!(h.addrs, Some((c.local_addr().unwrap(), vip)));
    }

    // A fresh sender whose first datagram is a spoofed PROXY header: dropped, counted, no flow.
    let evil = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let spoof = proxy_protocol::encode(
        sa("203.0.113.9:4242"),
        sa("198.51.100.7:53"),
        Transport::Datagram,
    );
    evil.send_to(spoof.as_bytes(), vip).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(400), evil.recv_from(&mut buf))
            .await
            .is_err(),
        "no reply: nothing was forwarded"
    );
    let m = lb.metrics().await;
    assert_eq!(
        metric(&m, "tas_lb_rejected_total{reason=\"proxy_untrusted\"}"),
        1
    );
    assert_eq!(ub.datagrams.lock().unwrap().len(), 3);
    lb.lb.shutdown().await;
}
