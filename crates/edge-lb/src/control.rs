//! The edge's control API for hostnames, tunnels and certificates (secret-guarded; the portal is
//! its caller). Releases keep their handlers in `main.rs`.
//!
//! ```text
//! POST   /control/hostnames                       admit a managed or custom hostname (body = edge_state::Op)
//! GET    /control/hostnames?tenant_id=T           a tenant's hostnames (+ the challenge to publish)
//! GET    /control/hostnames/:fqdn?tenant_id=T    one hostname
//! DELETE /control/hostnames/:fqdn?tenant_id=T    release (30-day quarantine) and revoke its tunnel
//! POST   /control/hostnames/:fqdn/suspend|resume {"tenant_id": T}
//! POST   /control/hostnames/:fqdn/tls-mode       {"tenant_id": T, "tls_mode": "terminate"|"passthrough"}
//! POST   /control/tunnels                         enrol the connector for an ADMITTED hostname
//! GET    /control/tunnels                         tunnels and how many pipes each holds
//! DELETE /control/tunnels/:hostname              drop a tunnel's pipes (the binding stays)
//! GET    /control/certs                           per-name certificate status
//! GET    /control/metrics                         Prometheus text: certs, revocation backlog, journal,
//!                                                 tunnels, DNS health, ACME account key age
//! GET    /control/health                          JSON: overall status and the findings behind it
//! GET    /control/admission                       the request-admission rules in force
//! PUT    /control/admission                       tighten them (virtual patch; body = admission::AdmissionOverlay).
//!                                                 Can only add deny-list entries and lower limits; persisted to
//!                                                 EDGE_LB_ADMISSION_FILE when set
//! ```
//!
//! The tenant id is supplied by the caller and trusted because the caller holds the control
//! secret; every state-changing call is validated by `transport::edge` (reserved labels, apex
//! membership, CNAME target ownership, release quarantine) and journaled before it is acknowledged.

use apeiron::map::hashtrinity;
use std::sync::Arc;

use serde_json::{json, Value};
use servelet_core::{Method, Request, Response, StatusCode};
use servelet_router::Router;

use crate::edge_state::{peer_hex, AdmitError, Op};
use crate::EdgeLb;

pub(crate) fn authorized(req: &Request, secret: &str) -> bool {
    req.headers()
        .get("x-control-secret")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| hashtrinity::crypto::ct_eq(s.as_bytes(), secret.as_bytes()))
}

fn json_response(status: u16, body: &Value) -> Response {
    Response::new(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        body.to_string(),
    )
    .with_header("content-type", "application/json")
}

fn error_response(e: &AdmitError) -> Response {
    let (status, code) = match e {
        AdmitError::Invalid(_) => (422, "invalid"),
        AdmitError::Conflict(_) => (409, "conflict"),
        AdmitError::Forbidden(_) => (403, "forbidden"),
        AdmitError::NotFound(_) => (404, "not_found"),
        AdmitError::Internal(_) => (500, "internal"),
    };
    json_response(status, &json!({ "error": code, "message": e.to_string() }))
}

fn bad_request(msg: &str) -> Response {
    json_response(400, &json!({ "error": "bad_request", "message": msg }))
}

/// `?name=value` from the request target, percent-decoded.
fn query_param(req: &Request, name: &str) -> Option<String> {
    let (_, q) = req.uri().path_and_query().split_once('?')?;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_body(req: &Request) -> Option<Value> {
    serde_json::from_slice(req.body()).ok()
}

/// The `{fqdn}` in `/control/hostnames/:fqdn[/suffix]`.
fn path_fqdn<'a>(req: &'a Request, suffix: &str) -> Option<&'a str> {
    let rest = req.uri().path().strip_prefix("/control/hostnames/")?;
    let fqdn = if suffix.is_empty() {
        rest
    } else {
        rest.strip_suffix(suffix)?
    };
    (!fqdn.is_empty() && !fqdn.contains('/')).then_some(fqdn)
}

// ── hostnames ──────────────────────────────────────────────────────────────────────────

async fn admit(edge: &EdgeLb, req: &Request) -> Response {
    let Some(body) = json_body(req) else {
        return bad_request("invalid JSON");
    };
    let op: Op = match serde_json::from_value(body) {
        Ok(op) => op,
        Err(e) => return bad_request(&format!("not a hostname operation: {e}")),
    };
    if !matches!(op, Op::AdmitManaged { .. } | Op::AdmitCustom { .. }) {
        return bad_request("POST /control/hostnames admits hostnames; use the per-hostname routes for other changes");
    }
    match edge.state.apply(&op).await {
        Ok(view) => json_response(201, &view),
        Err(e) => error_response(&e),
    }
}

async fn list(edge: &EdgeLb, req: &Request) -> Response {
    let Some(tenant) = query_param(req, "tenant_id") else {
        return bad_request("tenant_id is required");
    };
    json_response(
        200,
        &json!({ "hostnames": edge.state.list_for_tenant(&tenant).await }),
    )
}

async fn get_one(edge: &EdgeLb, req: &Request) -> Response {
    let (Some(fqdn), Some(tenant)) = (path_fqdn(req, ""), query_param(req, "tenant_id")) else {
        return bad_request("tenant_id is required");
    };
    match edge.state.get_for_tenant(&tenant, fqdn).await {
        Ok(v) => json_response(200, &v),
        Err(e) => error_response(&e),
    }
}

async fn release(edge: &EdgeLb, req: &Request) -> Response {
    let (Some(fqdn), Some(tenant)) = (path_fqdn(req, ""), query_param(req, "tenant_id")) else {
        return bad_request("tenant_id is required");
    };
    let fqdn = fqdn.to_ascii_lowercase();
    match edge
        .state
        .apply(&Op::Release {
            tenant_id: tenant,
            fqdn: fqdn.clone(),
        })
        .await
    {
        Ok(v) => {
            // The name no longer routes; its pipes must not outlive it.
            edge.tunnels.revoke(&fqdn);
            json_response(200, &v)
        }
        Err(e) => error_response(&e),
    }
}

async fn transition(edge: &EdgeLb, req: &Request, action: &str) -> Response {
    let Some(fqdn) = path_fqdn(req, &format!("/{action}")) else {
        return bad_request("bad path");
    };
    let Some(body) = json_body(req) else {
        return bad_request("invalid JSON");
    };
    let Some(tenant) = body.get("tenant_id").and_then(Value::as_str) else {
        return bad_request("tenant_id is required");
    };
    let fqdn = fqdn.to_ascii_lowercase();
    let tenant_id = tenant.to_string();
    let op = match action {
        "suspend" => Op::Suspend {
            tenant_id,
            fqdn: fqdn.clone(),
        },
        "resume" => Op::Resume {
            tenant_id,
            fqdn: fqdn.clone(),
        },
        "tls-mode" => {
            let Some(mode) = body.get("tls_mode").and_then(Value::as_str) else {
                return bad_request("tls_mode is required");
            };
            Op::SetTlsMode {
                tenant_id,
                fqdn: fqdn.clone(),
                tls_mode: mode.to_string(),
            }
        }
        _ => return bad_request("unknown action"),
    };
    match edge.state.apply(&op).await {
        Ok(v) => {
            if action == "suspend" {
                // Suspension stops new requests at admission; dropping the pipes also ends
                // connections already in flight rather than letting them run on.
                edge.tunnels.revoke(&fqdn);
            }
            json_response(200, &v)
        }
        Err(e) => error_response(&e),
    }
}

// ── tunnels ────────────────────────────────────────────────────────────────────────────

/// Enrol the connector for an admitted hostname: binds `peer` to the name (journaled) and opens
/// the tunnel slot its pipes may attach to. Idempotent for the same peer; a different peer is
/// refused (403) — re-binding is a revoke-and-readmit decision, not an enrolment side effect.
async fn enrol(edge: &EdgeLb, req: &Request) -> Response {
    let Some(body) = json_body(req) else {
        return bad_request("invalid JSON");
    };
    let Some(hostname) = body.get("hostname").and_then(Value::as_str) else {
        return bad_request("hostname required");
    };
    let Some(port) = body
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
    else {
        return bad_request("port required (1-65535)");
    };
    let Some(peer_hex_in) = body.get("peer").and_then(Value::as_str) else {
        return bad_request("peer required: the connector's Ed25519 public key (64 hex chars)");
    };
    let version = body
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let hostname = hostname.trim().to_ascii_lowercase();

    // Only a hostname that went through admission can have a tunnel.
    let known = edge.state.registry.lock().await.lookup(&hostname).is_some();
    if !known {
        return json_response(
            409,
            &json!({ "error": "not_admitted", "message": "hostname has not been admitted; POST /control/hostnames first" }),
        );
    }
    if let Err(e) = edge
        .state
        .apply(&Op::BindPeer {
            fqdn: hostname.clone(),
            peer: peer_hex_in.to_ascii_lowercase(),
            origin_port: port,
        })
        .await
    {
        return match e {
            AdmitError::Conflict(m) => {
                json_response(403, &json!({ "error": "peer_mismatch", "message": m }))
            }
            other => error_response(&other),
        };
    }
    let Some(peer) = edge.state.expected_peer(&hostname).await else {
        return json_response(
            500,
            &json!({ "error": "internal", "message": "peer binding was not recorded" }),
        );
    };
    match edge.tunnels.register(&hostname, port, version, peer) {
        Ok(true) => json_response(
            201,
            &json!({ "hostname": hostname, "status": "registered", "peer": peer_hex(&peer) }),
        ),
        Ok(false) => json_response(
            200,
            &json!({ "hostname": hostname, "status": "already_registered", "peer": peer_hex(&peer) }),
        ),
        Err(e) => json_response(403, &json!({ "error": "peer_mismatch", "message": e })),
    }
}

fn tunnels_json(edge: &EdgeLb) -> Value {
    let tunnels: Vec<Value> = edge
        .tunnels
        .list()
        .into_iter()
        .map(|t| json!({ "hostname": t.hostname, "port": t.port, "version": t.version, "online": t.online, "pipes": t.pipes }))
        .collect();
    json!({ "tunnels": tunnels })
}

fn revoke_tunnel(edge: &EdgeLb, req: &Request) -> Response {
    let Some(hostname) = req
        .uri()
        .path()
        .strip_prefix("/control/tunnels/")
        .filter(|h| !h.is_empty() && !h.contains('/'))
    else {
        return bad_request("bad path");
    };
    let hostname = hostname.to_ascii_lowercase();
    if edge.tunnels.revoke(&hostname) {
        json_response(200, &json!({ "hostname": hostname, "status": "revoked" }))
    } else {
        json_response(
            404,
            &json!({ "error": "not_found", "message": "no such tunnel" }),
        )
    }
}

// ── certificates ───────────────────────────────────────────────────────────────────────

fn certs_json(edge: &EdgeLb) -> Value {
    let certs: Vec<Value> = edge
        .state
        .cert_status()
        .into_iter()
        .map(|c| {
            json!({
                "name": c.name,
                "not_after": c.not_after,
                "seconds_left": c.seconds_left,
                "consecutive_failures": c.consecutive_failures,
                "next_attempt": c.next_attempt,
                "last_error": c.last_error,
                // The CA that issued the held certificate, and whether it is waiting to be moved.
                "ca": c.ca,
                "migration": match c.migration {
                    transport::acme_renew::Migration::None => "none",
                    transport::acme_renew::Migration::Retiring => "retiring",
                    transport::acme_renew::Migration::Distrusted => "distrusted",
                },
            })
        })
        .collect();
    json!({ "certs": certs })
}

// ── telemetry ──────────────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn metrics_text(edge: &EdgeLb) -> Response {
    let body = crate::metrics::render_prometheus(&edge.state, &edge.tunnels.list(), unix_now());
    Response::new(StatusCode::OK, body)
        .with_header("content-type", "text/plain; version=0.0.4; charset=utf-8")
}

fn health(edge: &EdgeLb) -> Response {
    json_response(
        200,
        &crate::metrics::health_json(&edge.state, &edge.tunnels.list(), unix_now()),
    )
}

// ── request admission (virtual patches) ────────────────────────────────────────────────

fn admission_get(edge: &EdgeLb) -> Response {
    json_response(
        200,
        &json!({ "config": *edge.admission_config(), "persisted_to": edge.admission_file.get() }),
    )
}

fn admission_put(edge: &EdgeLb, req: &Request) -> Response {
    let overlay: crate::admission::AdmissionOverlay = match serde_json::from_slice(req.body()) {
        Ok(o) => o,
        Err(e) => return bad_request(&format!("not an admission overlay: {e}")),
    };
    let next = match edge.tighten_admission(&overlay) {
        Ok(n) => n,
        Err(e) => {
            return json_response(
                422,
                &json!({ "error": "invalid", "message": e.to_string() }),
            )
        }
    };
    let persisted = match edge.admission_file.get() {
        None => json!(null),
        Some(path) => match persist_overlay(path, &next.as_overlay()) {
            Ok(()) => json!(path),
            Err(e) => {
                // The rules ARE in force (stricter is safe); the operator must know they will not
                // survive a restart.
                tracing::error!(path = %path.display(), error = %e, "admission overlay applied but not persisted");
                return json_response(
                    500,
                    &json!({ "error": "not_persisted", "applied": true, "message": e.to_string() }),
                );
            }
        },
    };
    json_response(200, &json!({ "config": *next, "persisted_to": persisted }))
}

/// Write `overlay` to `path` atomically (temp file in the same directory, fsync, rename).
fn persist_overlay(
    path: &std::path::Path,
    overlay: &crate::admission::AdmissionOverlay,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(overlay).map_err(std::io::Error::other)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

// ── mounting ───────────────────────────────────────────────────────────────────────────

/// Add the hostname/tunnel/cert routes to `app`, each behind the control secret.
pub fn mount(app: Router, edge: &Arc<EdgeLb>, secret: &Arc<String>) -> Router {
    macro_rules! guarded {
        ($edge:ident, $secret:ident, |$e:ident, $r:ident| $body:expr) => {{
            let $edge = $edge.clone();
            let $secret = $secret.clone();
            move |$r: Request| {
                let $e = $edge.clone();
                let secret = $secret.clone();
                async move {
                    if !authorized(&$r, &secret) {
                        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
                    }
                    let $e: &EdgeLb = &$e;
                    $body
                }
            }
        }};
    }
    app.route(
        Method::POST,
        "/control/hostnames",
        guarded!(edge, secret, |e, r| admit(e, &r).await),
    )
    .route(
        Method::GET,
        "/control/hostnames",
        guarded!(edge, secret, |e, r| list(e, &r).await),
    )
    .route(
        Method::GET,
        "/control/hostnames/:fqdn",
        guarded!(edge, secret, |e, r| get_one(e, &r).await),
    )
    .route(
        Method::DELETE,
        "/control/hostnames/:fqdn",
        guarded!(edge, secret, |e, r| release(e, &r).await),
    )
    .route(
        Method::POST,
        "/control/hostnames/:fqdn/suspend",
        guarded!(edge, secret, |e, r| transition(e, &r, "suspend").await),
    )
    .route(
        Method::POST,
        "/control/hostnames/:fqdn/resume",
        guarded!(edge, secret, |e, r| transition(e, &r, "resume").await),
    )
    .route(
        Method::POST,
        "/control/hostnames/:fqdn/tls-mode",
        guarded!(edge, secret, |e, r| transition(e, &r, "tls-mode").await),
    )
    .route(
        Method::POST,
        "/control/tunnels",
        guarded!(edge, secret, |e, r| enrol(e, &r).await),
    )
    .route(
        Method::GET,
        "/control/tunnels",
        guarded!(edge, secret, |e, _r| json_response(200, &tunnels_json(e))),
    )
    .route(
        Method::DELETE,
        "/control/tunnels/:hostname",
        guarded!(edge, secret, |e, r| revoke_tunnel(e, &r)),
    )
    .route(
        Method::GET,
        "/control/certs",
        guarded!(edge, secret, |e, _r| json_response(200, &certs_json(e))),
    )
    .route(
        Method::GET,
        "/control/metrics",
        guarded!(edge, secret, |e, _r| metrics_text(e)),
    )
    .route(
        Method::GET,
        "/control/health",
        guarded!(edge, secret, |e, _r| health(e)),
    )
    .route(
        Method::GET,
        "/control/admission",
        guarded!(edge, secret, |e, _r| admission_get(e)),
    )
    .route(
        Method::PUT,
        "/control/admission",
        guarded!(edge, secret, |e, r| admission_put(e, &r)),
    )
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;
    use servelet_core::HeaderValue;

    const SECRET: &str = "s3cret";

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
        secret: Option<&str>,
    ) -> (u16, Value) {
        let mut req = Request::new(method, path.parse().unwrap());
        req.headers_mut()
            .insert("host", HeaderValue::from("edge.test"));
        if let Some(s) = secret {
            req.headers_mut()
                .insert("x-control-secret", HeaderValue::from(s));
        }
        if let Some(b) = body {
            req = req.with_body(b.to_string());
        }
        let resp = app.handle(req).await;
        let v = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        (resp.status.as_u16(), v)
    }

    async fn app() -> (Router, Arc<EdgeLb>) {
        let edge = EdgeLb::build(Vec::new()).await;
        (
            mount(Router::new(), &edge, &Arc::new(SECRET.to_string())),
            edge,
        )
    }

    fn managed(label: &str, tenant: &str) -> Value {
        json!({ "op": "admit_managed", "tenant_id": tenant, "tunnel_id": "t1", "apex": "tascloud.app",
                "label": label, "dialkey": null, "tls_mode": "terminate", "origin_port": 8080, "agent_peer": null })
    }

    #[tokio::test]
    async fn every_route_demands_the_control_secret() {
        let (app, _) = app().await;
        for (m, p) in [
            (Method::POST, "/control/hostnames"),
            (Method::GET, "/control/hostnames?tenant_id=a"),
            (Method::GET, "/control/hostnames/x.tascloud.app?tenant_id=a"),
            (
                Method::DELETE,
                "/control/hostnames/x.tascloud.app?tenant_id=a",
            ),
            (Method::POST, "/control/hostnames/x.tascloud.app/suspend"),
            (Method::POST, "/control/tunnels"),
            (Method::GET, "/control/tunnels"),
            (Method::DELETE, "/control/tunnels/x.tascloud.app"),
            (Method::GET, "/control/certs"),
            (Method::GET, "/control/metrics"),
            (Method::GET, "/control/health"),
        ] {
            assert_eq!(
                call(&app, m.clone(), p, None, None).await.0,
                401,
                "{m:?} {p}"
            );
            assert_eq!(call(&app, m, p, None, Some("wrong")).await.0, 401);
        }
    }

    #[tokio::test]
    async fn admission_enrolment_and_release_follow_the_registry_rules() {
        let (app, edge) = app().await;
        let s = Some(SECRET);
        let peer = "ab".repeat(32);

        // A tunnel for a name nobody admitted is refused: the shared secret alone no longer
        // lets a caller claim an arbitrary hostname.
        let (st, v) = call(
            &app,
            Method::POST,
            "/control/tunnels",
            Some(json!({ "hostname": "mine.tascloud.app", "port": 8080, "peer": peer })),
            s,
        )
        .await;
        assert_eq!((st, v["error"].as_str()), (409, Some("not_admitted")));

        let (st, v) = call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(managed("mine", "acme")),
            s,
        )
        .await;
        assert_eq!(st, 201, "{v}");
        assert_eq!(v["fqdn"], "mine.tascloud.app");
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/hostnames",
                Some(managed("admin", "acme")),
                s
            )
            .await
            .0,
            422,
            "reserved label"
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/hostnames",
                Some(managed("mine", "rival")),
                s
            )
            .await
            .0,
            409,
            "taken"
        );

        let enrol = |peer: &str| json!({ "hostname": "mine.tascloud.app", "port": 8080, "version": "1", "peer": peer });
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/tunnels",
                Some(enrol(&peer)),
                s
            )
            .await
            .0,
            201
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/tunnels",
                Some(enrol(&peer)),
                s
            )
            .await
            .0,
            200,
            "idempotent"
        );
        let (st, v) = call(
            &app,
            Method::POST,
            "/control/tunnels",
            Some(enrol(&"cd".repeat(32))),
            s,
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (403, Some("peer_mismatch")),
            "a second connector cannot take the name"
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/tunnels",
                Some(json!({ "hostname": "mine.tascloud.app", "port": 8080 })),
                s
            )
            .await
            .0,
            400,
            "peer is mandatory"
        );

        // Tenant isolation on reads and releases.
        assert_eq!(
            call(
                &app,
                Method::GET,
                "/control/hostnames/mine.tascloud.app?tenant_id=rival",
                None,
                s
            )
            .await
            .0,
            403
        );
        let (st, v) = call(
            &app,
            Method::GET,
            "/control/hostnames?tenant_id=acme",
            None,
            s,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(v["hostnames"][0]["connector"], peer);
        assert_eq!(
            call(
                &app,
                Method::DELETE,
                "/control/hostnames/mine.tascloud.app?tenant_id=rival",
                None,
                s
            )
            .await
            .0,
            403
        );

        let (st, v) = call(
            &app,
            Method::DELETE,
            "/control/hostnames/mine.tascloud.app?tenant_id=acme",
            None,
            s,
        )
        .await;
        assert_eq!((st, v["status"].as_str()), (200, Some("released")));
        assert!(
            !edge.tunnels.is_registered("mine.tascloud.app"),
            "release revokes the tunnel"
        );
        // Quarantine: the next tenant cannot take the label.
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/hostnames",
                Some(managed("mine", "rival")),
                s
            )
            .await
            .0,
            409
        );
    }

    #[tokio::test]
    async fn suspend_stops_service_and_drops_the_tunnel_and_resume_restores_admission() {
        let (app, edge) = app().await;
        let s = Some(SECRET);
        call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(managed("mine", "acme")),
            s,
        )
        .await;
        call(
            &app,
            Method::POST,
            "/control/tunnels",
            Some(json!({ "hostname": "mine.tascloud.app", "port": 8080, "peer": "ab".repeat(32) })),
            s,
        )
        .await;
        let (st, v) = call(
            &app,
            Method::POST,
            "/control/hostnames/mine.tascloud.app/suspend",
            Some(json!({ "tenant_id": "acme" })),
            s,
        )
        .await;
        assert_eq!(
            (st, v["state"]["status"].as_str()),
            (200, Some("suspended"))
        );
        assert!(!edge.tunnels.is_registered("mine.tascloud.app"));
        assert_eq!(
            edge.state.decide("mine.tascloud.app", None).await,
            Some(transport::edge_proxy::Decision::Suspended)
        );
        let (st, v) = call(
            &app,
            Method::POST,
            "/control/hostnames/mine.tascloud.app/resume",
            Some(json!({ "tenant_id": "acme" })),
            s,
        )
        .await;
        assert_eq!((st, v["state"]["status"].as_str()), (200, Some("active")));
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/control/hostnames/mine.tascloud.app/resume",
                Some(json!({ "tenant_id": "rival" })),
                s
            )
            .await
            .0,
            403
        );
    }

    #[tokio::test]
    async fn custom_hostnames_report_the_challenge_and_tls_mode_changes_are_validated() {
        let (app, _) = app().await;
        let s = Some(SECRET);
        call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(managed("mine", "acme")),
            s,
        )
        .await;
        let custom = json!({ "op": "admit_custom", "tenant_id": "acme", "tunnel_id": "t", "fqdn": "app.acme.com.au",
                             "cname_target": "mine.tascloud.app", "tls_mode": "passthrough", "origin_port": 443, "agent_peer": null });
        let (st, v) = call(&app, Method::POST, "/control/hostnames", Some(custom), s).await;
        assert_eq!(st, 201, "{v}");
        assert_eq!(v["state"]["status"], "pending_dns");
        assert_eq!(v["tls_mode"], "passthrough");
        assert_eq!(v["challenge"]["txt_name"], "_twn-challenge.app.acme.com.au");
        let (st, _) = call(
            &app,
            Method::POST,
            "/control/hostnames/app.acme.com.au/tls-mode",
            Some(json!({ "tenant_id": "acme", "tls_mode": "bogus" })),
            s,
        )
        .await;
        assert_eq!(st, 422);
        // Not an admission op.
        let (st, _) = call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(json!({ "op": "suspend", "tenant_id": "acme", "fqdn": "x" })),
            s,
        )
        .await;
        assert_eq!(st, 400);
    }

    #[test]
    fn percent_decoding_is_total() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[tokio::test]
    async fn metrics_and_health_are_served_to_the_secret_holder_in_their_formats() {
        let (app, edge) = app().await;
        let s = Some(SECRET);
        let call_raw = |path: &'static str, secret: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut req = Request::new(Method::GET, path.parse().unwrap());
                req.headers_mut()
                    .insert("host", HeaderValue::from("edge.test"));
                if let Some(sec) = secret {
                    req.headers_mut()
                        .insert("x-control-secret", HeaderValue::from(sec));
                }
                let resp = app.handle(req).await;
                let ct = resp
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (
                    resp.status.as_u16(),
                    ct,
                    String::from_utf8_lossy(&resp.body).into_owned(),
                )
            }
        };
        // Without or with the wrong secret: 401 and no body worth reading.
        for path in ["/control/metrics", "/control/health"] {
            for secret in [None, Some("wrong")] {
                let (status, _, body) = call_raw(path, secret).await;
                assert_eq!(status, 401, "{path}");
                assert!(
                    !body.contains("edge_lb_") && !body.contains("status"),
                    "{body}"
                );
            }
        }
        edge.state
            .set_cert_status(vec![transport::acme_renew::CertStatus {
                name: "*.tascloud.app".into(),
                not_after: Some(2_000_000_000),
                seconds_left: Some(7200),
                consecutive_failures: 1,
                next_attempt: 5,
                last_error: Some("boom".into()),
                ca: None,
                migration: transport::acme_renew::Migration::None,
            }]);
        let (status, ct, body) = call_raw("/control/metrics", Some(SECRET)).await;
        assert_eq!(status, 200);
        assert!(ct.starts_with("text/plain; version=0.0.4"), "{ct}");
        assert!(
            body.contains("edge_lb_cert_seconds_left{name=\"*.tascloud.app\"} 7200\n"),
            "{body}"
        );
        assert!(body.contains("edge_lb_cert_consecutive_failures{name=\"*.tascloud.app\"} 1\n"));
        assert!(body.contains("# TYPE edge_lb_revocation_pending gauge"));

        // A tunnel's pipes appear per host.
        let peer = "ab".repeat(32);
        call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(managed("mine", "acme")),
            s,
        )
        .await;
        call(
            &app,
            Method::POST,
            "/control/tunnels",
            Some(json!({ "hostname": "mine.tascloud.app", "port": 8080, "peer": peer })),
            s,
        )
        .await;
        let (_, _, body) = call_raw("/control/metrics", Some(SECRET)).await;
        assert!(
            body.contains("edge_lb_tunnel_pipes{host=\"mine.tascloud.app\"} 0\n"),
            "{body}"
        );

        let (status, v) = call(&app, Method::GET, "/control/health", None, s).await;
        assert_eq!(status, 200);
        assert_eq!(v["status"], "degraded", "the renewal is failing");
        assert_eq!(v["certificates"]["failing"], 1);
        assert_eq!(v["certificates"]["names"][0]["last_error"], "boom");
        assert_eq!(v["tunnels"]["total"], 1);
        assert_eq!(v["dns"], Value::Null, "no health run has completed yet");
    }

    #[tokio::test]
    async fn releasing_a_custom_hostname_over_http_reports_its_certificate_going_to_revocation() {
        use transport::acme_renew::{CertStore, RevocationQueue};
        use transport::edge::CertSource;
        let (app, edge) = app().await;
        let s = Some(SECRET);
        call(
            &app,
            Method::POST,
            "/control/hostnames",
            Some(managed("mine", "acme")),
            s,
        )
        .await;
        let custom = json!({ "op": "admit_custom", "tenant_id": "acme", "tunnel_id": "t", "fqdn": "app.acme.com.au",
                             "cname_target": "mine.tascloud.app", "tls_mode": "terminate", "origin_port": 443, "agent_peer": null });
        assert_eq!(
            call(&app, Method::POST, "/control/hostnames", Some(custom), s)
                .await
                .0,
            201
        );
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["app.acme.com.au".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2027, 1, 14);
        params.not_after = rcgen::date_time_ymd(2027, 4, 15);
        let cert = transport::edge::CertMaterial {
            chain_pem: params.self_signed(&key).unwrap().pem(),
            key_pem: key.serialize_pem(),
        };
        let store = Arc::new(transport::edge_proxy::MemoryCertSource::new());
        store.put("app.acme.com.au", cert).unwrap();
        let queue = Arc::new(RevocationQueue::in_memory());
        edge.state
            .set_revoker(store.clone() as Arc<dyn CertStore>, queue.clone());
        edge.state
            .apply(&crate::edge_state::Op::Validated {
                fqdn: "app.acme.com.au".into(),
            })
            .await
            .unwrap();

        let (st, v) = call(
            &app,
            Method::DELETE,
            "/control/hostnames/app.acme.com.au?tenant_id=acme",
            None,
            s,
        )
        .await;
        assert_eq!(
            (
                st,
                v["status"].as_str(),
                v["certificate_revocation"].as_str()
            ),
            (200, Some("released"), Some("queued")),
            "{v}"
        );
        assert!(store.cert_for("app.acme.com.au").is_none());
        let (_, health) = call(&app, Method::GET, "/control/health", None, s).await;
        assert_eq!(health["revocation"]["pending"], 1);
        assert_eq!(
            health["revocation"]["entries"][0]["name"],
            "app.acme.com.au"
        );
        assert_eq!(health["status"], "degraded");
    }
}
