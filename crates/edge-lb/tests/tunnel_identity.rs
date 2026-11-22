//! The tunnel identity round trip: the `PeerId` the edge presents on the wire for a control
//! secret equals the `PeerId` the overlay-agent derives and pins for the same secret, and neither
//! moved when `transport` made `dialkey::peer_id` the PUBLIC key (0.2.0).
//!
//! Context: before 0.2.0, `dialkey::peer_id(k)` returned the secret seed. The edge bound with
//! `bind_with_key(peer_id(k))` and the agent pinned `ed25519_pubkey(&peer_id(k))`. Against 0.2.0 both
//! lines still compile, but each silently double-derives (the public key becomes a secret). The edge
//! must use `bind_with_dialkey` and the agent `peer_id`, and they must move together.
//!
//! ONE checker, [`check_identity`], decides for the real code and for the source-level mutants
//! (compiled only by `RUSTFLAGS=--cfg=mutant_*`; they alter the real call sites in
//! `edge_lb::tunnel::bind_tunnel_endpoint` and `overlay_agent::peer_for_dialkey`):
//!
//! | build | edge | agent | checker |
//! |---|---|---|---|
//! | real | `bind_with_dialkey` | `peer_id` | `Ok` |
//! | `mutant_edge_old_form` | `bind_with_key(peer_id(k))` | `peer_id` | `Err(EdgeAgentDisagree)` |
//! | `mutant_agent_old_form` | `bind_with_dialkey` | `ed25519_pubkey(&peer_id(k))` | `Err(EdgeAgentDisagree)` |
//! | both | `bind_with_key(peer_id(k))` | `ed25519_pubkey(&peer_id(k))` | `Err(ChangedVsLegacy)` — the round trip alone passes (both sides wrong the same way); only the legacy and golden comparisons see it |
//!
//! The `LEGACY_*` hex constants are the identities the PRE-0.2.0 code presented: the control-secret
//! one was measured by running the real `run_tunnel_listener` and the real `expected_edge_peer` at
//! transport `30fdaf7` on the build box (both printed the same value); the dialkey one is the
//! public-key golden vector of Ptyktos/transport#7. All keys here are literal test keys.

#![expect(
    clippy::unwrap_used,
    reason = "test code: deterministic assertions on loopback endpoints"
)]

use apeiron::map::hashtrinity;
use std::time::Duration;

use edge_lb::tunnel::{bind_tunnel_endpoint, run_tunnel_listener, TunnelRegistry};
use overlay_agent::{peer_for_dialkey, AgentConfig};
use transport::native::NativeEndpoint;
use transport::{Connection, Transport};

/// Public key of `native_keypair("g17-test-dialkey")`: the identity a 0.1.x
/// `bind_with_key(peer_id("g17-test-dialkey"))` endpoint presented, and `peer_id` of it in 0.2.0
/// (golden vector, Ptyktos/transport#7).
const LEGACY_G17_PUBLIC_HEX: &str =
    "30966ac5fa1bdd49aec9b9101bf63359704d01dc00597f934f7d7bca9bc5c47b";
/// What 0.1.x `dialkey::peer_id("g17-test-dialkey")` returned: the SECRET seed
/// `SHA-256(dialkey ++ ":pkarr")`. Public test material (a literal test dialkey's seed).
const LEGACY_G17_SEED_HEX: &str =
    "f312899db1b911aad45adc946d31875a58e810242652eba4fac63966a3bad73e";
const G17: &str = "g17-test-dialkey";

/// The control secret whose pre-0.2.0 wire identity was measured at transport `30fdaf7`
/// (real `run_tunnel_listener` observed by a dialling endpoint; real `expected_edge_peer`).
const MEASURED_SECRET: &str = "g19a-test-control-secret";
const LEGACY_MEASURED_SECRET_PUBLIC_HEX: &str =
    "6c10f18df369481b09c50f6485622ba24e47e781263a2fa12979df478fbd35a7";

const STEP: Duration = Duration::from_secs(5);

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn agent_cfg(control_secret: &str) -> AgentConfig {
    AgentConfig {
        edge_tunnel_addr: String::new(),
        control_url: String::new(),
        control_secret: control_secret.to_string(),
        hostname: "h.test".to_string(),
        local_port: 1,
        identity_file: String::new(),
        version: None,
        pipes: 1,
        splice_pipes: 0,
    }
}

/// The identity a 0.1.x edge presented for `dialkey`: the REAL transport endpoint, bound the way
/// the old code bound it (`bind_with_key` with `SHA-256(dialkey ++ ":pkarr")` as the secret).
async fn legacy_wire_identity(dialkey: &str) -> [u8; 32] {
    let seed = hashtrinity::crypto::sha256(format!("{dialkey}:pkarr").as_bytes());
    let endpoint = NativeEndpoint::bind_with_key("127.0.0.1:0", seed)
        .await
        .unwrap();
    Transport::id(&endpoint)
}

/// Dial `addr` with an anonymous endpoint and return the identity the handshake reports for the
/// listener. Retries while the listener is still binding.
async fn dial_identity(addr: &str) -> Result<[u8; 32], String> {
    let client = NativeEndpoint::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout(STEP, client.connect(addr, b"tas-overlay/tunnel/1")).await {
            Ok(Ok(conn)) => return Ok(conn.peer_id()),
            Ok(Err(e)) if std::time::Instant::now() >= deadline => {
                return Err(format!("dial {addr}: {e}"))
            }
            Err(_) => return Err(format!("dial {addr}: handshake timed out")),
            Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// What the real edge presents for `control_secret`: the real `run_tunnel_listener` on a loopback
/// port, observed by a dialling endpoint.
async fn edge_wire_identity(control_secret: &str) -> Result<[u8; 32], String> {
    let addr = format!("127.0.0.1:{}", free_port());
    let (bind, secret) = (addr.clone(), control_secret.to_string());
    let listener = tokio::spawn(async move {
        run_tunnel_listener(
            &bind,
            TunnelRegistry::new(edge_lb::edge_state::EdgeState::ephemeral()),
            &secret,
        )
        .await;
    });
    let id = dial_identity(&addr).await;
    listener.abort();
    id
}

/// What the real edge's endpoint presents for a bare `dialkey` (real `bind_tunnel_endpoint`).
async fn dialkey_wire_identity(dialkey: &str) -> Result<[u8; 32], String> {
    let endpoint = bind_tunnel_endpoint("127.0.0.1:0", dialkey)
        .await
        .map_err(|e| e.to_string())?;
    let addr = endpoint.local_addr().map_err(|e| e.to_string())?;
    let acceptor = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.accept()).await;
    });
    let id = dial_identity(&addr).await;
    acceptor.abort();
    id
}

#[derive(Debug, PartialEq, Eq)]
enum Violation {
    /// The real edge listener and the real agent disagree about who the edge is.
    EdgeAgentDisagree(String),
    /// The identities agree with each other but differ from what the 0.1.x endpoint presented.
    ChangedVsLegacy(String),
    /// A pinned literal (measured or golden vector) moved.
    GoldenDrift(String),
    /// Different control secrets collapsed onto one identity, or the checker could not run.
    Degenerate(String),
}

/// One checker for the real implementation and the source-level mutants. Order matters: the
/// round trip first (so a one-sided regression is named as a disagreement), then the legacy and
/// golden comparisons (the only ones that see both sides drifting together).
async fn check_identity() -> Result<(), Violation> {
    use Violation::{ChangedVsLegacy, Degenerate, EdgeAgentDisagree, GoldenDrift};

    let secrets: Vec<String> = std::iter::once(MEASURED_SECRET.to_string())
        .chain((0..6).map(|i| format!("g19a-synthetic-control-secret-{i}")))
        .collect();
    let mut wires = Vec::new();

    // 1. Round trip: edge wire identity == agent pin, for every secret; the agent's pin for a
    //    DIFFERENT secret must not match (so "everything equal" cannot pass).
    for secret in &secrets {
        let wire = edge_wire_identity(secret).await.map_err(Degenerate)?;
        let pinned = agent_cfg(secret).expected_edge_peer();
        if wire != pinned {
            return Err(EdgeAgentDisagree(format!(
                "secret {secret}: edge presents {}, agent pins {}",
                hex(&wire),
                hex(&pinned)
            )));
        }
        wires.push(wire);
    }
    let other = agent_cfg("g19a-some-other-control-secret").expected_edge_peer();
    if wires.contains(&other) {
        return Err(Degenerate(
            "an unrelated secret's pin equals a real edge identity".into(),
        ));
    }
    for (i, a) in wires.iter().enumerate() {
        if wires[i + 1..].contains(a) {
            return Err(Degenerate(
                "two control secrets share one edge identity".into(),
            ));
        }
    }

    // 2. Unchanged vs what the 0.1.x code presented on the wire (live legacy endpoint).
    for (secret, wire) in secrets.iter().zip(&wires) {
        let legacy = legacy_wire_identity(&edge_lb::tunnel::tunnel_dialkey(secret)).await;
        if *wire != legacy {
            return Err(ChangedVsLegacy(format!(
                "secret {secret}: edge now presents {}, 0.1.x presented {}",
                hex(wire),
                hex(&legacy)
            )));
        }
    }

    // 3. Golden literals (hard-coded old identities).
    if hex(&wires[0]) != LEGACY_MEASURED_SECRET_PUBLIC_HEX {
        return Err(GoldenDrift(format!(
            "control secret {MEASURED_SECRET}: {} != measured 0.1.x {LEGACY_MEASURED_SECRET_PUBLIC_HEX}",
            hex(&wires[0])
        )));
    }
    let g17_wire = dialkey_wire_identity(G17).await.map_err(Degenerate)?;
    if hex(&g17_wire) != LEGACY_G17_PUBLIC_HEX {
        return Err(GoldenDrift(format!(
            "{G17}: edge presents {} != golden {LEGACY_G17_PUBLIC_HEX}",
            hex(&g17_wire)
        )));
    }
    if hex(&peer_for_dialkey(G17)) != LEGACY_G17_PUBLIC_HEX {
        return Err(GoldenDrift(format!(
            "{G17}: agent pins {} != golden {LEGACY_G17_PUBLIC_HEX}",
            hex(&peer_for_dialkey(G17))
        )));
    }
    Ok(())
}

#[tokio::test]
async fn edge_identity_equals_agent_pin_and_did_not_move_from_0_1_x() {
    let verdict = check_identity().await;

    #[cfg(not(any(mutant_edge_old_form, mutant_agent_old_form)))]
    assert_eq!(verdict, Ok(()));

    #[cfg(all(mutant_edge_old_form, not(mutant_agent_old_form)))]
    assert!(
        matches!(verdict, Err(Violation::EdgeAgentDisagree(_))),
        "edge_old_form must be caught as an edge/agent disagreement: {verdict:?}"
    );

    #[cfg(all(mutant_agent_old_form, not(mutant_edge_old_form)))]
    assert!(
        matches!(verdict, Err(Violation::EdgeAgentDisagree(_))),
        "agent_old_form must be caught as an edge/agent disagreement: {verdict:?}"
    );

    // Both sides wrong the same way: the round trip PASSES, only the legacy comparison sees it.
    #[cfg(all(mutant_edge_old_form, mutant_agent_old_form))]
    assert!(
        matches!(verdict, Err(Violation::ChangedVsLegacy(_))),
        "the consistent double derive must be caught against the 0.1.x identity: {verdict:?}"
    );
}

/// The measured/golden literals are what the OLD code produced, independent of this tree's
/// derivation: the live 0.1.x-style endpoint (`bind_with_key(SHA-256(k ++ ":pkarr"))`) presents
/// the transport golden vector, and the seed it was keyed with is what 0.1.x `peer_id` returned.
#[tokio::test]
async fn legacy_seed_endpoint_presents_the_golden_public_key() {
    let seed = hashtrinity::crypto::sha256(format!("{G17}:pkarr").as_bytes());
    assert_eq!(
        hex(&seed),
        LEGACY_G17_SEED_HEX,
        "0.1.x peer_id returned the secret seed"
    );
    assert_eq!(hex(&legacy_wire_identity(G17).await), LEGACY_G17_PUBLIC_HEX);
    assert_ne!(
        LEGACY_G17_SEED_HEX, LEGACY_G17_PUBLIC_HEX,
        "peer_id must no longer be the seed"
    );
}

/// The real agent path (`serve_forever`: enroll, dial, PIN, claim) against the real edge listener:
/// the tunnel attaches only when the agent's pin equals the edge's wire identity. A stub control
/// API answers the enrollment. Under a one-sided mutant the agent refuses the edge and this fails.
#[tokio::test]
async fn real_agent_attaches_to_the_real_edge_only_with_the_same_control_secret() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn stub_control_api() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let want: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + want {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = sock
                        .write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await;
                });
            }
        });
        port
    }

    async fn online_after(agent_secret: &str, within: Duration) -> bool {
        let tunnel_port = free_port();
        let registry = TunnelRegistry::new(edge_lb::edge_state::EdgeState::ephemeral());
        let (bind, reg) = (format!("127.0.0.1:{tunnel_port}"), registry.clone());
        let listener = tokio::spawn(async move {
            run_tunnel_listener(&bind, reg, "g19a-edge-control-secret").await;
        });
        let control_port = stub_control_api().await;
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = AgentConfig {
            edge_tunnel_addr: format!("127.0.0.1:{tunnel_port}"),
            control_url: format!("http://127.0.0.1:{control_port}"),
            control_secret: agent_secret.to_string(),
            hostname: "h.test".to_string(),
            local_port: 1,
            identity_file: dir.path().join("id.key").to_string_lossy().to_string(),
            version: None,
            pipes: 1,
            splice_pipes: 0,
        };
        // The edge enrols the connector by its public key; the claim is checked against it.
        registry
            .register("h.test", 8080, None, cfg.own_peer().unwrap())
            .unwrap();
        let agent = tokio::spawn(async move { overlay_agent::serve_forever(cfg).await });
        let deadline = std::time::Instant::now() + within;
        let mut online = false;
        while std::time::Instant::now() < deadline {
            if registry
                .list()
                .iter()
                .any(|t| t.hostname == "h.test" && t.online)
            {
                online = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        agent.abort();
        listener.abort();
        online
    }

    assert!(
        online_after("g19a-edge-control-secret", Duration::from_secs(15)).await,
        "an agent holding the edge's control secret must authenticate the edge and attach"
    );
    // Negative control on the real path: the same agent code with the wrong secret refuses the
    // edge's identity ("edge peer mismatch") and never attaches.
    assert!(
        !online_after("g19a-wrong-control-secret", Duration::from_secs(4)).await,
        "an agent with the wrong control secret must not attach"
    );
}
