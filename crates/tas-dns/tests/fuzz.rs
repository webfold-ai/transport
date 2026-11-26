#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions on fixtures"
)]
mod common;
use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tas_dns::server::ServerLimits;

const ZONE: &str = r#"{"records":[{"name":"www","ttl":300,"type":"A","data":"198.51.100.10"}]}"#;

#[tokio::test]
async fn oversized_and_malformed_packets_are_dropped_or_formerr_without_panicking() {
    static PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        PANICS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        prev(i);
    }));
    let limits = ServerLimits {
        budget_rate: 100_000,
        budget_burst: 100_000,
        rrl_rate: 100_000,
        rrl_burst: 100_000,
        ..ServerLimits::default()
    };
    let t = {
        let t = start(limits).await;
        t.add_zone(
            "acme.example",
            "acme",
            &kp(10),
            1,
            ZONE,
            Some(tas_dns::zone::DnssecPolicy {
                ksk_gen: 0,
                ksk_next: None,
                origin: unix_now() - 10,
            }),
        );
        t
    };
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // oversize datagram
    sock.send_to(&vec![0u8; 3000], t.udp).await.unwrap();
    // pseudo-random garbage, every length 0..300, plus bit-flipped valid queries
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut below = move |n: usize| -> usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(n).unwrap()).unwrap()
    };
    let valid = query_packet(
        0x1234,
        "www.acme.example.",
        RecordType::A,
        Some((1232, true)),
        true,
    );
    for len in 0..300usize {
        let junk: Vec<u8> = (0..len)
            .map(|_| u8::try_from(below(256)).unwrap())
            .collect();
        sock.send_to(&junk, t.udp).await.unwrap();
        let mut m = valid.clone();
        for _ in 0..=(len % 4) {
            let i = below(m.len());
            m[i] ^= 1 << below(8);
        }
        sock.send_to(&m, t.udp).await.unwrap();
        let cut = below(valid.len());
        sock.send_to(&valid[..cut], t.udp).await.unwrap();
    }
    // the same abuse over TCP framing: lying lengths, truncated bodies, junk
    for i in 0..40usize {
        use tokio::io::AsyncWriteExt;
        let mut s = tokio::net::TcpStream::connect(t.tcp).await.unwrap();
        let junk: Vec<u8> = (0..(i * 7 % 200))
            .map(|_| u8::try_from(below(256)).unwrap())
            .collect();
        let _ = s.write_all(&junk).await;
        let mut f = u16::try_from(valid.len() + i)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        f.extend_from_slice(&valid[..valid.len().min(i + 12)]);
        let _ = s.write_all(&f).await;
        drop(s);
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // still alive and correct
    let r = parse(
        &udp_exchange(t.udp, &valid, 2000)
            .await
            .expect("server answers after the abuse"),
    );
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        PANICS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no task panicked"
    );
    assert!(t.metrics.malformed.get() > 0 && t.metrics.oversize.get() >= 1);
    let _ = std::panic::take_hook();
}
