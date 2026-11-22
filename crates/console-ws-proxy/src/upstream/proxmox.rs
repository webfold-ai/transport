//! Proxmox-side console connector.
//!
//! Proxmox exposes three console flavours, all over a Proxmox-minted
//! one-shot vnc-ticket + WebSocket:
//!
//! ```text
//!   QEMU VNC       :  POST  /api2/json/nodes/{node}/qemu/{vmid}/vncproxy        → ticket + port
//!                     wss://{node}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port=&vncticket=
//!   QEMU serial    :  POST  /api2/json/nodes/{node}/qemu/{vmid}/termproxy       → ticket + port
//!                     wss://{node}:8006/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port=&vncticket=
//!   LXC pct-exec   :  POST  /api2/json/nodes/{node}/lxc/{vmid}/termproxy        → ticket + port
//!                     wss://{node}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket?port=&vncticket=
//! ```
//!
//! The browser never sees the node IP — it only ever talks to
//! `console-ws-proxy`, which mints the Proxmox vnc-ticket on the browser's
//! behalf and opens the upstream WS itself.
//!
//! Auth to the Proxmox API uses an **API token**
//! (`Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID`), not a per-user
//! cookie. The token comes from operator-side `OpenBao` via the
//! [`ProxmoxCredentialResolver`] trait — no credentials live in this
//! crate, and per `docs/decisions/2026-05-06-m2m-internal-auth-coverage.md`
//! (umbrella) the resolver impl must NOT reach `std::env::var` for the
//! token in production paths.
//!
//! TLS verification is always on (webpki-roots). For self-signed Proxmox
//! certs, the operator-side install is responsible for adding the issuing
//! CA to the system trust store on the console-ws-proxy host. Pinned CA
//! support per-target is a v2 feature.

use std::time::Duration;

use http::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use uuid::Uuid;

use crate::{ConsoleKind, ConsoleTicket, ProxyError, UpstreamStream};

/// Proxmox API token + node coordinates resolved for a given deployment.
///
/// The caller (typically the runtime's deployment registry) hands us this;
/// we never read it from env / disk.
#[derive(Clone, Debug)]
pub struct ProxmoxConsoleTarget {
    /// e.g. `https://10.0.20.11:8006` — never returned to the browser.
    pub api_base: String,
    /// Proxmox node name (as known to the cluster, not DNS).
    pub node: String,
    /// QEMU VMID or LXC CTID.
    pub vmid: u32,
    /// `qemu` for VMs, `lxc` for containers.
    pub vm_kind: VmKind,
    /// Full Proxmox API token, including realm + token-id + secret. Format:
    /// `USER@REALM!TOKENID=SECRET-UUID`. Stored in `OpenBao`, fetched per
    /// session by the resolver.
    pub api_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmKind {
    Qemu,
    Lxc,
}

impl VmKind {
    fn path_segment(self) -> &'static str {
        match self {
            VmKind::Qemu => "qemu",
            VmKind::Lxc => "lxc",
        }
    }
}

/// Resolves a deployment_id to its Proxmox console target. Production
/// implementation hits the runtime's deployment registry + Vault; tests
/// pass a static fixture.
#[async_trait::async_trait]
pub trait ProxmoxCredentialResolver: Send + Sync {
    async fn resolve(&self, deployment_id: Uuid) -> Result<ProxmoxConsoleTarget, ProxyError>;
}

/// What the Proxmox `/vncproxy` and `/termproxy` endpoints return.
#[derive(Debug, Deserialize)]
struct PveProxyTicket {
    /// One-shot ticket — passed back as a query param on the websocket URL.
    ticket: String,
    /// Per-session VNC port on the node.
    port: u32,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    upid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PveProxyResponse {
    data: PveProxyTicket,
}

/// A Proxmox-minted vnc-ticket + the port the upstream WebSocket listens on.
#[derive(Debug, Clone)]
pub struct PveTicket {
    pub ticket: String,
    pub port: u32,
    /// Echoed by Proxmox for diagnostics; carried through to callers that
    /// want to log it. Not used internally by the connector.
    pub user: Option<String>,
    /// Echoed by Proxmox for diagnostics; carried through to callers.
    pub upid: Option<String>,
}

/// Mint a Proxmox vnc-ticket for the given target + console kind.
pub async fn mint_proxmox_ticket(
    target: &ProxmoxConsoleTarget,
    kind: ConsoleKind,
) -> Result<PveTicket, ProxyError> {
    let endpoint = match kind {
        ConsoleKind::Vnc => "vncproxy",
        ConsoleKind::Serial | ConsoleKind::LxcExec => "termproxy",
    };
    let url = format!(
        "{}/api2/json/nodes/{}/{}/{}/{}",
        target.api_base.trim_end_matches('/'),
        target.node,
        target.vm_kind.path_segment(),
        target.vmid,
        endpoint,
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .https_only(true)
        .build()
        .map_err(|e| ProxyError::Proxmox(format!("reqwest build: {e}")))?;

    let resp = client
        .post(&url)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("PVEAPIToken={}", target.api_token))
                .map_err(|e| ProxyError::Proxmox(format!("token header: {e}")))?,
        )
        .send()
        .await
        .map_err(|e| ProxyError::Proxmox(format!("POST {endpoint}: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(ProxyError::Proxmox(format!(
            "{endpoint} returned {status}: {}",
            resp.text().await.unwrap_or_default()
        )));
    }

    let body: PveProxyResponse = resp
        .json()
        .await
        .map_err(|e| ProxyError::Proxmox(format!("decode {endpoint}: {e}")))?;

    Ok(PveTicket {
        ticket: body.data.ticket,
        port: body.data.port,
        user: body.data.user,
        upid: body.data.upid,
    })
}

/// Construct the upstream Proxmox vncwebsocket URL — never returned to the
/// browser.
fn upstream_url(target: &ProxmoxConsoleTarget, ticket: &PveTicket) -> String {
    format!(
        "{}/api2/json/nodes/{}/{}/{}/vncwebsocket?port={}&vncticket={}",
        target
            .api_base
            .trim_end_matches('/')
            .replace("https://", "wss://")
            .replace("http://", "ws://"),
        target.node,
        target.vm_kind.path_segment(),
        target.vmid,
        ticket.port,
        url_encode(&ticket.ticket),
    )
}

/// Percent-encode for query-string values. Unreserved per RFC 3986 plus
/// nothing else — Proxmox vnc-tickets contain reserved chars (':' '@'
/// '/') that must be encoded.
fn url_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            // write! into a String never fails.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Connect to the Proxmox VNC websocket using the just-minted ticket.
///
/// TLS verification always on (webpki-roots). Returns the upgraded
/// `WebSocketStream` ready to be passed to [`crate::pump`].
pub async fn connect_vnc(
    target: &ProxmoxConsoleTarget,
    pve_ticket: &PveTicket,
) -> Result<UpstreamStream, ProxyError> {
    let url = upstream_url(target, pve_ticket);
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|e| ProxyError::UpstreamConnect(format!("build req: {e}")))?;

    // Proxmox needs the API token on the upgrade so the vnc-ticket can be
    // associated with an auth context server-side.
    let auth = format!("PVEAPIToken={}", target.api_token);
    req.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth)
            .map_err(|e| ProxyError::UpstreamConnect(format!("auth header: {e}")))?,
    );

    let (stream, _resp) = connect_async(req)
        .await
        .map_err(|e| ProxyError::UpstreamConnect(e.to_string()))?;

    Ok(stream)
}

/// One-shot end-to-end: resolve target → mint Proxmox ticket → open
/// upstream WS. Caller still has to call [`crate::pump`] with the
/// downstream WS.
pub async fn open_proxmox_console(
    ticket: &ConsoleTicket,
    resolver: &dyn ProxmoxCredentialResolver,
) -> Result<UpstreamStream, ProxyError> {
    let target = resolver.resolve(ticket.deployment_id).await?;
    enforce_kind_matches_vm_kind(ticket.kind, target.vm_kind)?;
    let pve_ticket = mint_proxmox_ticket(&target, ticket.kind).await?;
    connect_vnc(&target, &pve_ticket).await
}

fn enforce_kind_matches_vm_kind(kind: ConsoleKind, vm_kind: VmKind) -> Result<(), ProxyError> {
    let ok = matches!(
        (kind, vm_kind),
        (ConsoleKind::Vnc | ConsoleKind::Serial, VmKind::Qemu)
            | (ConsoleKind::LxcExec, VmKind::Lxc)
    );
    if ok {
        Ok(())
    } else {
        Err(ProxyError::Proxmox(format!(
            "console kind {kind:?} not valid for vm kind {vm_kind:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ProxmoxConsoleTarget {
        ProxmoxConsoleTarget {
            api_base: "https://10.0.20.11:8006".into(),
            node: "tas-px-01".into(),
            vmid: 12345,
            vm_kind: VmKind::Qemu,
            api_token: "ops@pam!cws=00000000-0000-0000-0000-000000000000".into(),
        }
    }

    fn pve() -> PveTicket {
        PveTicket {
            ticket: "PVEVNC:abc:def".into(),
            port: 5900,
            user: None,
            upid: None,
        }
    }

    #[test]
    fn upstream_url_qemu_vnc_replaces_https_with_wss_and_hides_node() {
        let url = upstream_url(&target(), &pve());
        assert!(url.starts_with("wss://10.0.20.11:8006/"), "got {url}");
        assert!(url.contains("/qemu/12345/vncwebsocket"), "got {url}");
        assert!(url.contains("port=5900"), "got {url}");
        assert!(url.contains("vncticket=PVEVNC%3Aabc%3Adef"), "got {url}");
    }

    #[test]
    fn upstream_url_lxc_uses_lxc_path_segment() {
        let mut t = target();
        t.vm_kind = VmKind::Lxc;
        t.vmid = 9000;
        let url = upstream_url(&t, &pve());
        assert!(url.contains("/lxc/9000/vncwebsocket"), "got {url}");
    }

    #[test]
    fn kind_vs_vm_kind_compat_matrix() {
        assert!(enforce_kind_matches_vm_kind(ConsoleKind::Vnc, VmKind::Qemu).is_ok());
        assert!(enforce_kind_matches_vm_kind(ConsoleKind::Serial, VmKind::Qemu).is_ok());
        assert!(enforce_kind_matches_vm_kind(ConsoleKind::LxcExec, VmKind::Lxc).is_ok());

        assert!(enforce_kind_matches_vm_kind(ConsoleKind::Vnc, VmKind::Lxc).is_err());
        assert!(enforce_kind_matches_vm_kind(ConsoleKind::LxcExec, VmKind::Qemu).is_err());
        assert!(enforce_kind_matches_vm_kind(ConsoleKind::Serial, VmKind::Lxc).is_err());
    }

    #[test]
    fn url_encode_handles_proxmox_ticket_specials() {
        assert_eq!(url_encode("PVEVNC:abc"), "PVEVNC%3Aabc");
        assert_eq!(url_encode("a=b&c"), "a%3Db%26c");
        assert_eq!(url_encode("plain-segment_42.x~"), "plain-segment_42.x~");
    }

    #[test]
    fn upstream_url_lxc_termproxy_translates_to_vncwebsocket_path() {
        // Proxmox API minted from `termproxy` endpoint, but the WS URL is
        // always `/vncwebsocket` (Proxmox quirk — both VNC and terminal
        // upgrade through the same WS path with different ticket payloads).
        let mut t = target();
        t.vm_kind = VmKind::Lxc;
        let url = upstream_url(&t, &pve());
        assert!(url.contains("/lxc/12345/vncwebsocket"));
    }
}
