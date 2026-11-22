//! The Tas Cloud edge load balancer — hostname routing on the Ptyktos servelet HTTP surface.
//! Runs the reverse-proxy lifecycle (RFC 0008 §4.7).
//!
//! This is the custom LB the platform runs instead of a generic proxy:
//! [`EdgeLb`] runs each request through [`proxy`] (filter, upstream choice, forward) and resolves its upstream
//! by `Host` header from a backend table with two entry kinds:
//!
//! - **Static** — `http://host:port` (today's overlay wiring, e.g. the
//!   notification-service ntfy listener).
//! - **Dialkey** — `dialkey://<dialkey>#<service-label>`: resolved through
//!   [`transport::dialkey::resolve`] at boot and re-resolved on a
//!   refresh interval, so a backend that re-publishes on its plane (the
//!   Notify plane's `_notify._tcp`) is re-registered without a restart. This
//!   is the "resolve through the overlay, no A/AAAA records" path for
//!   service backends; the connector/tunnel phase (a peer dialling *in* over
//!   `transport::Connection`, `transport::edge_proxy`) is the
//!   follow-on.
//!
//! Admission mirrors `transport::edge_proxy::decide`'s discipline: unknown
//! hostnames answer **404** without revealing anything, a request whose
//! `Host` disagrees with the TLS SNI answers **421** (RFC 7540 §9.1.2), and
//! a host with no backend registered answers **502** with a body that says
//! the backend is unregistered, not that the edge is broken.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use servelet_core::{Request, Response, StatusCode};
use servelet_router::Router;

use crate::proxy::{forward, Session, Upstream};
use tracing::{info, warn};

pub mod acme;
pub mod admission;
pub mod ca;
pub mod control;
pub mod edge_state;
pub mod front;
pub mod hosting;
pub mod http01;
pub mod metrics;
pub mod proxy;
pub mod readiness;
pub mod release_api;
pub mod rollout;
pub mod tunnel;

use crate::edge_state::EdgeState;
use crate::tunnel::RelayError;
use transport::edge_proxy::{strip_host_port as strip_port, Decision};

/// What the listener learned about the connection a request arrived on. Injected per connection
/// (`Router::with_state`) so the request path can enforce SNI/Host agreement and tell the tenant
/// whether the client really used HTTPS.
#[derive(Clone, Debug, Default)]
pub struct ConnMeta {
    /// The TLS SNI the client sent; `None` on a plaintext connection.
    pub sni: Option<String>,
    /// Whether the connection is TLS.
    pub tls: bool,
}

/// How often dialkey backends are re-resolved and re-registered.
pub const DIALKEY_REFRESH: Duration = Duration::from_secs(60);

/// One registered route: hostname → backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendSpec {
    /// `http://host:port` — dialed directly.
    Static { host: String, port: u16 },
    /// `dialkey://<dialkey>#<service>` — resolved via
    /// [`transport::dialkey::resolve`] on a refresh interval.
    Dialkey { dialkey: String, service: String },
}

impl BackendSpec {
    /// Parse one `host=backend` entry from the `EDGE_LB_ROUTES` wire form.
    ///
    /// # Errors
    /// String — a malformed entry is refused at boot, never at request time.
    pub fn parse(spec: &str) -> Result<(String, Self), String> {
        let (host, backend) = spec
            .split_once('=')
            .ok_or_else(|| format!("route entry '{spec}' must be host=backend"))?;
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() || host.contains('/') {
            return Err(format!("route host '{host}' is invalid"));
        }
        let backend = backend.trim();
        let parsed = if let Some(rest) = backend.strip_prefix("dialkey://") {
            let (dialkey, service) = rest.split_once('#').ok_or_else(|| {
                format!("dialkey backend '{backend}' must be dialkey://<key>#<service>")
            })?;
            if dialkey.is_empty() || service.is_empty() {
                return Err(format!("dialkey backend '{backend}' has empty parts"));
            }
            Self::Dialkey {
                dialkey: dialkey.to_string(),
                service: service.to_string(),
            }
        } else if let Some(rest) = backend.strip_prefix("http://") {
            let (host, port) = rest
                .rsplit_once(':')
                .ok_or_else(|| format!("static backend '{backend}' must be http://host:port"))?;
            let port = port
                .parse::<u16>()
                .map_err(|e| format!("static backend '{backend}' bad port: {e}"))?;
            Self::Static {
                host: host.to_string(),
                port,
            }
        } else {
            return Err(format!(
                "backend '{backend}' must be http://host:port or dialkey://<key>#<service>"
            ));
        };
        Ok((host, parsed))
    }

    /// The initial upstream set for this spec (statics immediately; a
    /// dialkey that resolves resolves, otherwise empty until the refresh).
    pub async fn resolve(&self) -> Vec<Upstream> {
        match self {
            Self::Static { host, port } => vec![Upstream::http(host.clone(), *port)],
            Self::Dialkey { dialkey, service } => {
                let client = transport::pkarr::RelayClient::new();
                if let Some(svc) = transport::dialkey::resolve(&client, dialkey, service).await {
                    let host = svc.peer_addr.host.clone();
                    let port = svc.peer_addr.port;
                    info!(%host, %port, service = %service, "dialkey backend resolved");
                    vec![Upstream::http(host, port)]
                } else {
                    warn!(dialkey, service = %service, "dialkey backend not published yet");
                    Vec::new()
                }
            }
        }
    }
}

/// The edge load balancer — one instance, `EDGE_LB_ROUTES`-configured.
pub struct EdgeLb {
    /// hostname → live upstream set (round-robin picked).
    backends: Mutex<HashMap<String, Vec<Upstream>>>,
    /// The route specs — kept so the dialkey refresh loop can re-resolve.
    specs: Mutex<Vec<(String, BackendSpec)>>,
    cursor: AtomicUsize,
    /// Overlay tunnels — tenant origins dialled in via `overlay-agent`
    /// (RFC 0008 §8); requests for those hostnames are relayed raw over the
    /// authenticated pipe instead of proxied.
    pub tunnels: tunnel::TunnelRegistry,
    /// Hostname admission, connector pool, certificate source — shared with the control plane and
    /// the TLS front.
    pub state: Arc<EdgeState>,
    /// The release controller — alias-flip deployment authority (INV-02/03).
    /// The deploy driver stages a unit here, probes it, and flips the alias;
    /// routing consults [`RolloutController::live_target`] as the first
    /// authority for a hostname.
    pub rollout: std::sync::Mutex<crate::rollout::RolloutController>,
    /// Request admission rules (see [`admission`]): the always-on baseline plus whatever the
    /// operator has tightened at runtime. Read on every request, replaced as a whole.
    admission: std::sync::RwLock<Arc<admission::AdmissionConfig>>,
    /// Where tightened admission rules are persisted (`EDGE_LB_ADMISSION_FILE`), so an emergency
    /// rule pushed through the control API survives a restart. Set once at boot.
    pub admission_file: std::sync::OnceLock<std::path::PathBuf>,
}

impl EdgeLb {
    /// Build from parsed routes; spawns the dialkey refresh loop (every
    /// [`DIALKEY_REFRESH`], each `dialkey://` backend is re-resolved and
    /// re-registered — a backend that re-publishes on its plane appears
    /// without a restart).
    pub async fn build(routes: Vec<(String, BackendSpec)>) -> Arc<Self> {
        Self::build_with_state(routes, EdgeState::ephemeral()).await
    }

    /// As [`Self::build`], over a caller-supplied [`EdgeState`] (journaled, cert-hosting).
    pub async fn build_with_state(
        routes: Vec<(String, BackendSpec)>,
        state: Arc<EdgeState>,
    ) -> Arc<Self> {
        let mut backends = HashMap::new();
        for (host, spec) in &routes {
            let resolved = spec.resolve().await;
            backends.insert(host.clone(), resolved);
        }
        let lb = Arc::new(Self {
            backends: Mutex::new(backends),
            specs: Mutex::new(routes),
            cursor: AtomicUsize::new(0),
            tunnels: tunnel::TunnelRegistry::new(state.clone()),
            state,
            rollout: std::sync::Mutex::new(crate::rollout::RolloutController::new()),
            admission: std::sync::RwLock::new(Arc::new(admission::AdmissionConfig::default())),
            admission_file: std::sync::OnceLock::new(),
        });
        let task_lb = lb.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(DIALKEY_REFRESH).await;
                task_lb.refresh_dialkeys().await;
            }
        });
        lb
    }

    /// Re-resolve every dialkey backend from its plane.
    pub async fn refresh_dialkeys(&self) {
        let specs = self
            .specs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for (host, spec) in &specs {
            if let BackendSpec::Dialkey { .. } = spec {
                let resolved = spec.resolve().await;
                if let Ok(mut backends) = self.backends.lock() {
                    backends.insert(host.clone(), resolved);
                }
            }
        }
    }

    fn host_of(req: &Request) -> Option<String> {
        req.headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| strip_port(h).to_ascii_lowercase())
    }

    /// Relay one public request over a registered tunnel pipe: rebuild the HTTP/1.1 message
    /// (binary-safe, one `Host`, no client-supplied forwarding headers), push it through an idle
    /// pipe, and turn the framed response back into a [`Response`].
    async fn relay_over_tunnel(
        &self,
        session: &Session,
        host: &str,
        https: bool,
    ) -> Result<Response, RelayError> {
        let req = session.req_header();
        let raw = build_tunnel_request(req, host, https).map_err(RelayError::Failed)?;
        let head_only = req.method() == servelet_core::Method::HEAD;
        let relayed = self.tunnels.relay(host, &raw, head_only).await?;
        Ok(into_response(relayed))
    }

    /// The `(host, port)` the rollout controller currently serves for `host`,
    /// if a release is live and its target is a plain `http://host:port`.
    fn live_release(&self, host: &str) -> Option<(String, u16)> {
        let rollout = self
            .rollout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let target = rollout.live_target(host)?;
        let parsed = crate::rollout::http_target(target);
        if parsed.is_none() {
            warn!(%host, %target, "live release target is not http://host:port; ignoring it for routing");
        }
        parsed
    }

    fn pick(&self, host: &str) -> Option<Upstream> {
        let backends = self
            .backends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = backends.get(host)?;
        if list.is_empty() {
            return None;
        }
        let n = self.cursor.fetch_add(1, Ordering::Relaxed);
        Some(list[n % list.len()].clone())
    }
}

fn http_status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Turn a framed tunnel response into the edge's response: hop-by-hop headers dropped, every
/// other header kept **including duplicates** (`Set-Cookie`), body untouched.
fn into_response(relayed: tunnel::RelayedResponse) -> Response {
    let mut resp = Response::new(http_status(relayed.status), relayed.body);
    for (name, value) in relayed.headers {
        // content-length is recomputed from the body by the writer — except for a HEAD response,
        // which declares a length it does not carry, so there the origin's value is the point.
        let keep_length = name.eq_ignore_ascii_case("content-length") && resp.body.is_empty();
        if is_hop_by_hop(&name) && !keep_length {
            continue;
        }
        resp.headers.append(
            name,
            servelet_core::HeaderValue::from(String::from_utf8_lossy(&value).into_owned()),
        );
    }
    resp
}

/// Hop-by-hop headers never cross the tunnel (the pipe is per-tenant).
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "content-length"
    )
}

/// Headers the edge sets itself; a client-supplied copy is dropped so a visitor cannot forge
/// the provenance a tenant's app may trust.
fn is_edge_owned(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-real-ip"
            | "expect"
    )
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Serialise `req` for the tunnel as raw bytes. Unlike the first version this never goes through
/// `String`: a binary body (an upload, a protobuf, a gzip stream) is carried byte for byte.
fn build_tunnel_request(req: &Request, host: &str, https: bool) -> Result<Vec<u8>, String> {
    let method = req.method().to_string();
    let target = req.uri().path_and_query();
    if !is_token(&method) || target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("request line contains forbidden characters".to_string());
    }
    let body = req.body();
    let mut raw = Vec::with_capacity(256 + body.len());
    raw.extend_from_slice(format!("{method} {target} HTTP/1.1\r\nhost: {host}\r\n").as_bytes());
    for (name, value) in req.headers().iter() {
        if is_hop_by_hop(name) || is_edge_owned(name) {
            continue;
        }
        let bytes = value.as_bytes();
        if !is_token(name) || bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err("request header contains forbidden characters".to_string());
        }
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(bytes);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(
        format!(
            "x-forwarded-host: {host}\r\nx-forwarded-proto: {}\r\n",
            if https { "https" } else { "http" }
        )
        .as_bytes(),
    );
    if let Some(ip) = req.connection_info().peer_addr() {
        raw.extend_from_slice(format!("x-forwarded-for: {ip}\r\n").as_bytes());
    }
    raw.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
    raw.extend_from_slice(body);
    Ok(raw)
}

impl EdgeLb {
    /// First phase of every public request. Answers it here when the host is
    /// unknown or the host is a tunnel; returns `true` once `session` holds the
    /// response, so no upstream is chosen.
    async fn request_filter(&self, session: &mut Session) -> bool {
        let Some(host) = Self::host_of(session.req_header()) else {
            session.set_resp(Response::new(
                StatusCode::BAD_REQUEST,
                "missing Host header",
            ));
            return true;
        };
        let meta = session
            .req_header()
            .app_data::<ConnMeta>()
            .cloned()
            .unwrap_or_default();

        // 1. The admission registry (managed + custom hostnames, tunnels) decides first.
        if let Some(decision) = self.state.decide(&host, meta.sni.as_deref()).await {
            match decision {
                Decision::Serve(_) => {
                    match self.relay_over_tunnel(session, &host, meta.tls).await {
                        Ok(resp) => session.set_resp(resp),
                        Err(RelayError::Failed(e)) => {
                            warn!(%host, error = %e, "tunnel relay failed");
                            session.set_resp(Response::new(
                                StatusCode::BAD_GATEWAY,
                                "the connector returned an invalid response",
                            ));
                        }
                        Err(e @ (RelayError::NoTunnel | RelayError::Unavailable(_))) => {
                            warn!(%host, error = %e, "no connector pipe available");
                            session.set_resp(Response::new(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "the connector is busy or offline",
                            ));
                        }
                    }
                }
                other => session.set_resp(Response::new(
                    http_status(other.status()),
                    other.public_message(),
                )),
            }
            return true;
        }

        // 2. An SNI that disagrees with Host is misdirected even for names the registry does not
        //    hold (RFC 7540 §9.1.2): the connection was set up for a different name.
        if meta.sni.as_deref().is_some_and(|sni| sni != host) {
            session.set_resp(Response::new(
                StatusCode::from_u16(421).unwrap_or(StatusCode::BAD_REQUEST),
                "This connection was not established for this hostname.",
            ));
            return true;
        }

        // 3. Static / dialkey / promoted-release routes (EDGE_LB_ROUTES and the rollout controller).
        let known = self.backends.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(&host)
            // A promoted release (production alias or preview) makes a hostname
            // routable without an `EDGE_LB_ROUTES` entry.
            || self.live_release(&host).is_some();
        if !known {
            // Unknown hostnames answer identically whether or not they exist
            // in any registry — no existence leaks (edge_proxy discipline).
            session.set_resp(Response::new(
                StatusCode::NOT_FOUND,
                "no service at this hostname",
            ));
            return true;
        }
        false
    }

    /// Second phase: the upstream the request is forwarded to.
    fn upstream_peer(&self, session: &Session) -> Result<Upstream, String> {
        let host = Self::host_of(session.req_header()).unwrap_or_default();
        // The live release is the first authority for a hostname: a flip
        // (promote or rollback) moves traffic here, with no restart.
        if let Some((rhost, rport)) = self.live_release(&host) {
            return Ok(Upstream::http(rhost, rport));
        }
        self.pick(&host).ok_or_else(|| {
            format!(
                "no backend registered for '{host}' (its connector is not published on its plane)"
            )
        })
    }

    /// The admission configuration in force.
    #[must_use]
    pub fn admission_config(&self) -> Arc<admission::AdmissionConfig> {
        self.admission
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Tighten the admission rules. The result is never less strict than what is in force (see
    /// [`admission::AdmissionConfig::tightened`]); a refused overlay changes nothing. Returns the
    /// configuration now in force.
    pub fn tighten_admission(
        &self,
        overlay: &admission::AdmissionOverlay,
    ) -> Result<Arc<admission::AdmissionConfig>, admission::OverlayError> {
        let mut guard = self
            .admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = Arc::new(guard.tightened(overlay)?);
        *guard = next.clone();
        Ok(next)
    }

    /// Run request admission. `Some(response)` means the request was refused and counted.
    ///
    /// The rules run on **two views of the target**: the raw request line, and the
    /// `path_and_query` the edge forwards. They differ when servelet's URI parser reads a `://`
    /// inside a relative target's query as a scheme separator (`/a?x=http://b/..%2f` is forwarded as
    /// `/..%2f`), and a filter that looked at only one of them would admit what the other lets
    /// through. Both must pass.
    fn admit_request(&self, req: &Request) -> Option<Response> {
        let headers: Vec<(&str, &[u8])> = req
            .headers()
            .iter()
            .map(|(n, v)| (n, v.as_bytes()))
            .collect();
        let cfg = self.admission_config();
        let raw = req.uri().to_string();
        let forwarded = req.uri().path_and_query();
        for target in [raw.as_str(), forwarded] {
            if let admission::Verdict::Reject(rule) = admission::check(
                &cfg,
                &admission::RequestView {
                    target,
                    headers: &headers,
                    body: req.body(),
                },
            ) {
                self.state.metrics.record_admission_reject(rule.as_str());
                return Some(Response::new(
                    http_status(rule.status()),
                    "request refused by edge admission",
                ));
            }
            if raw == forwarded {
                break;
            }
        }
        None
    }

    /// The full request path: admission, filter, pick an upstream, forward.
    pub async fn handle(&self, req: Request) -> Response {
        // Before routing, so the rules protect every route (static, dialkey, release, tunnel) and an
        // unknown hostname gets the same answer for a hostile request as a known one.
        if let Some(refused) = self.admit_request(&req) {
            return refused;
        }
        let mut session = Session::new(req);
        if self.request_filter(&mut session).await {
            return session.into_response();
        }
        match self.upstream_peer(&session) {
            Ok(upstream) => match forward(&session, &upstream).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(upstream = %upstream.host, error = %e, "upstream forward failed");
                    Response::new(StatusCode::BAD_GATEWAY, e)
                }
            },
            Err(e) => Response::new(StatusCode::BAD_GATEWAY, e),
        }
    }
}

/// The edge's HTTP app: every request goes through [`EdgeLb::handle`].
pub fn router(edge: Arc<EdgeLb>) -> Router {
    Router::new().fallback(move |req: Request| {
        let edge = edge.clone();
        async move { edge.handle(req).await }
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use servelet_core::Method;

    #[test]
    fn parses_static_and_dialkey_backends() {
        let (host, spec) = BackendSpec::parse("ntfy.tas.cloud=http://127.0.0.1:8094").unwrap();
        assert_eq!(host, "ntfy.tas.cloud");
        assert_eq!(
            spec,
            BackendSpec::Static {
                host: "127.0.0.1".into(),
                port: 8094
            }
        );

        let (host, spec) =
            BackendSpec::parse("ntfy.example.com=dialkey://notify-plane-key#_notify._tcp").unwrap();
        assert_eq!(host, "ntfy.example.com");
        assert_eq!(
            spec,
            BackendSpec::Dialkey {
                dialkey: "notify-plane-key".into(),
                service: "_notify._tcp".into()
            }
        );
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(BackendSpec::parse("no-equals").is_err());
        assert!(BackendSpec::parse("h=ftp://x:1").is_err());
        assert!(BackendSpec::parse("h=dialkey://onlykey").is_err());
        assert!(BackendSpec::parse("h=http://host:nope").is_err());
        assert!(BackendSpec::parse("bad/host=http://h:1").is_err());
    }

    #[test]
    fn strip_port_handles_ipv6() {
        assert_eq!(strip_port("ntfy.tas.cloud:443"), "ntfy.tas.cloud");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]:443");
        assert_eq!(strip_port("ntfy.tas.cloud"), "ntfy.tas.cloud");
    }

    #[tokio::test]
    async fn unknown_host_is_404_static_host_is_served() {
        let edge = Arc::new(
            EdgeLb::build(vec![(
                "ntfy.test".to_string(),
                BackendSpec::Static {
                    host: "127.0.0.1".into(),
                    port: 1,
                },
            )])
            .await,
        );
        let mut req = Request::new(Method::GET, "/health".parse().unwrap());
        req.headers_mut()
            .insert("host", servelet_core::HeaderValue::from("unknown.test"));
        let resp = edge.handle(req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let mut req = Request::new(Method::GET, "/health".parse().unwrap());
        req.headers_mut()
            .insert("host", servelet_core::HeaderValue::from("ntfy.test"));
        let resp = edge.handle(req).await;
        // Backend 127.0.0.1:1 is a dead port → 502 (the upstream_peer error
        // path), which still proves routing picked the right host.
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_promoted_release_makes_a_hostname_routable_and_a_rollback_moves_it() {
        use crate::rollout::{Probe, ProbeResult, ReleaseUnit};
        let edge = EdgeLb::build(Vec::new()).await;
        let ready: Probe = Box::new(|_| ProbeResult::Ready);
        let status_for = |edge: Arc<EdgeLb>| async move {
            let mut req = Request::new(Method::GET, "/".parse().unwrap());
            req.headers_mut().insert(
                "host",
                servelet_core::HeaderValue::from("site--feat-x.tascloud.dev"),
            );
            edge.handle(req).await.status()
        };

        // Nothing promoted: unknown host, 404.
        assert_eq!(status_for(edge.clone()).await, StatusCode::NOT_FOUND);

        // Promote a release whose backend is a dead port: now the host is
        // known and routed (502 from the dead upstream), not 404.
        {
            let mut r = edge.rollout.lock().unwrap();
            r.stage(
                "site--feat-x.tascloud.dev",
                ReleaseUnit {
                    id: "r1".into(),
                    target: "http://127.0.0.1:1".into(),
                },
            );
            r.probe_and_flip("site--feat-x.tascloud.dev", &ready)
                .unwrap();
        }
        assert_eq!(
            edge.live_release("site--feat-x.tascloud.dev"),
            Some(("127.0.0.1".to_string(), 1))
        );
        assert_eq!(status_for(edge.clone()).await, StatusCode::BAD_GATEWAY);

        // A second release moves the routing target; a rollback moves it back.
        {
            let mut r = edge.rollout.lock().unwrap();
            r.stage(
                "site--feat-x.tascloud.dev",
                ReleaseUnit {
                    id: "r2".into(),
                    target: "http://127.0.0.1:2".into(),
                },
            );
            r.probe_and_flip("site--feat-x.tascloud.dev", &ready)
                .unwrap();
        }
        assert_eq!(
            edge.live_release("site--feat-x.tascloud.dev"),
            Some(("127.0.0.1".to_string(), 2))
        );
        edge.rollout
            .lock()
            .unwrap()
            .rollback("site--feat-x.tascloud.dev")
            .unwrap();
        assert_eq!(
            edge.live_release("site--feat-x.tascloud.dev"),
            Some(("127.0.0.1".to_string(), 1))
        );
    }

    #[tokio::test]
    async fn admission_refuses_hostile_requests_before_routing_and_counts_them() {
        let edge = Arc::new(
            EdgeLb::build(vec![(
                "app.test".to_string(),
                BackendSpec::Static {
                    host: "127.0.0.1".into(),
                    port: 1,
                },
            )])
            .await,
        );
        let send = |host: &'static str, target: &'static str| {
            let edge = edge.clone();
            async move {
                let mut req = Request::new(Method::GET, target.parse().unwrap());
                req.headers_mut()
                    .insert("host", servelet_core::HeaderValue::from(host));
                edge.handle(req).await.status().as_u16()
            }
        };
        // Known and unknown hosts get the same refusal; a clean request still routes (502: dead upstream).
        assert_eq!(
            send("app.test", "/index.php?-d+auto_prepend_file%3dphp://input").await,
            403
        );
        assert_eq!(send("unknown.test", "/index.php?-s").await, 403);
        assert_eq!(send("app.test", "/a/%2e%2e/b").await, 400);
        // servelet reads the '://' in this query as a scheme separator and forwards "/..%2f..%2fetc":
        // the filter must judge what is forwarded, not only what was received.
        assert_eq!(
            send("app.test", "/index.php?u=http://x/..%2f..%2fetc").await,
            400
        );
        assert_eq!(send("app.test", "/index.php?x=1").await, 502);
        assert_eq!(send("unknown.test", "/index.php?x=1").await, 404);
        let rejects = edge.state.metrics.admission_rejects();
        assert_eq!(
            rejects,
            vec![("cgi_argument_injection", 2), ("encoded_traversal", 2)]
        );
        // Tightening takes effect on the next request and cannot be undone by a looser overlay.
        let o = admission::AdmissionOverlay {
            max_target_bytes: Some(16),
            ..Default::default()
        };
        edge.tighten_admission(&o).unwrap();
        assert_eq!(send("app.test", "/index.php?x=1234567890").await, 414);
        let loose = admission::AdmissionOverlay {
            max_target_bytes: Some(8192),
            ..Default::default()
        };
        assert_eq!(edge.tighten_admission(&loose).unwrap().max_target_bytes, 16);
    }

    #[tokio::test]
    async fn missing_host_header_is_400() {
        let edge = Arc::new(
            EdgeLb::build(vec![(
                "ntfy.test".to_string(),
                BackendSpec::Static {
                    host: "127.0.0.1".into(),
                    port: 1,
                },
            )])
            .await,
        );
        let req = Request::new(Method::GET, "/health".parse().unwrap());
        let resp = edge.handle(req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
