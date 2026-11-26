//! The release (alias-flip) control API: stage, probe, rollback, retire, cancel, list.
//!
//! Lives in the library, not `main.rs`, so the routes are testable. (Moving it exposed that the
//! old registration used `{hostname}` for path parameters — this router spells them `:hostname` —
//! so every parameterised route here, and tunnel revocation, never matched a real hostname.)

use std::sync::{Arc, Mutex};

use servelet_core::{Method, Request, Response, StatusCode};
use servelet_router::Router;

use crate::rollout::{Probe, ProbeResult, ReleaseUnit};
use crate::EdgeLb;

fn control_release_stage(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let body: Result<serde_json::Value, _> = serde_json::from_slice(req.body());
    let Ok(body) = body else {
        return Response::new(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    let Some(hostname) = body.get("hostname").and_then(|v| v.as_str()) else {
        return Response::new(StatusCode::BAD_REQUEST, "hostname required");
    };
    let Some(unit_id) = body.get("unit_id").and_then(|v| v.as_str()) else {
        return Response::new(StatusCode::BAD_REQUEST, "unit_id required");
    };
    let Some(target) = body.get("target").and_then(|v| v.as_str()) else {
        return Response::new(StatusCode::BAD_REQUEST, "target required");
    };
    let mut rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    rollout.stage(
        hostname,
        ReleaseUnit {
            id: unit_id.to_string(),
            target: target.to_string(),
        },
    );
    // Staging NEVER moves the alias (INV-02) — the release is pending until
    // a probe passes; the response says staged, not live.
    Response::new(
        StatusCode::CREATED,
        serde_json::json!({ "hostname": hostname, "status": "staged" }).to_string(),
    )
}

const READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// `POST /control/releases/{hostname}/probe`.
///
/// Body `{"path": "/healthz"}` makes the **edge** probe the staged unit (a `2xx` flips the
/// alias). The legacy `{"ok": bool}` / `{"ready": bool}` forms still work but flip on the
/// caller's word; new callers should send `path`.
async fn control_release_probe(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let path = req.uri().path();
    let Some(hostname) = path
        .strip_prefix("/control/releases/")
        .and_then(|rest| rest.strip_suffix("/probe"))
    else {
        return Response::new(StatusCode::BAD_REQUEST, "bad path");
    };
    let body: Result<serde_json::Value, _> = serde_json::from_slice(req.body());
    let Ok(body) = body else {
        return Response::new(StatusCode::BAD_REQUEST, "invalid JSON");
    };

    let result = if let Some(probe_path) = body.get("path").and_then(serde_json::Value::as_str) {
        // Read the staged unit, release the lock, probe over the network, re-lock to flip.
        let pending = rollout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending(hostname);
        let Some(unit) = pending else {
            return Response::new(StatusCode::NOT_FOUND, "no staged release for this alias");
        };
        crate::readiness::http_ready(&unit.target, probe_path, READINESS_TIMEOUT).await
    } else {
        let ok = body
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .or_else(|| body.get("ready").and_then(serde_json::Value::as_bool));
        let Some(ok) = ok else {
            return Response::new(
                StatusCode::BAD_REQUEST,
                "path (string) or ok/ready (bool) required",
            );
        };
        if ok {
            ProbeResult::Ready
        } else {
            ProbeResult::NotReady
        }
    };

    let probe: Probe = Box::new(move |_| result.clone());
    let mut rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match rollout.probe_and_flip(hostname, &probe) {
        Ok(ProbeResult::Ready) => Response::new(
            StatusCode::OK,
            serde_json::json!({ "hostname": hostname, "status": "live" }).to_string(),
        ),
        Ok(ProbeResult::NotReady) => Response::new(
            StatusCode::OK,
            serde_json::json!({ "hostname": hostname, "status": "not_ready" }).to_string(),
        ),
        Ok(ProbeResult::ProbeError(e)) => Response::new(StatusCode::BAD_GATEWAY, e),
        Err(e) if e.contains("no staged") => Response::new(StatusCode::NOT_FOUND, e),
        Err(e) => Response::new(
            StatusCode::from_u16(409).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            e,
        ),
    }
}

/// `POST /control/releases/{hostname}/retire`: take the hostname out of service (a torn-down
/// preview). Journaled before it takes effect.
fn control_release_retire(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let Some(hostname) = req
        .uri()
        .path()
        .strip_prefix("/control/releases/")
        .and_then(|rest| rest.strip_suffix("/retire"))
    else {
        return Response::new(StatusCode::BAD_REQUEST, "bad path");
    };
    let mut rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match rollout.retire(hostname) {
        Ok(unit) => Response::new(
            StatusCode::OK,
            serde_json::json!({ "hostname": hostname, "status": "retired", "unit_id": &unit.id })
                .to_string(),
        ),
        Err(e) if e.contains("no live release") => Response::new(StatusCode::NOT_FOUND, e),
        Err(e) => Response::new(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

fn control_release_rollback(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let path = req.uri().path();
    let Some(hostname) = path
        .strip_prefix("/control/releases/")
        .and_then(|rest| rest.strip_suffix("/rollback"))
    else {
        return Response::new(StatusCode::BAD_REQUEST, "bad path");
    };
    let mut rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Rollback is a pointer flip, never a redeploy (INV-03).
    match rollout.rollback(hostname) {
        Ok(unit) => Response::new(
            StatusCode::OK,
            serde_json::json!({
                "hostname": hostname,
                "status": "rolled_back",
                "unit_id": &unit.id,
                "target": &unit.target
            })
            .to_string(),
        ),
        Err(e) if e.contains("no previous") => Response::new(StatusCode::NOT_FOUND, e),
        Err(e) => Response::new(
            StatusCode::from_u16(409).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            e,
        ),
    }
}

fn control_release_cancel(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let path = req.uri().path();
    let Some(hostname) = path.strip_prefix("/control/releases/") else {
        return Response::new(StatusCode::BAD_REQUEST, "bad path");
    };
    let mut rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if rollout.cancel(hostname) {
        Response::new(
            StatusCode::OK,
            serde_json::json!({ "hostname": hostname, "status": "cancelled" }).to_string(),
        )
    } else {
        Response::new(
            StatusCode::NOT_FOUND,
            "no pending release for this hostname",
        )
    }
}

fn control_release_list(
    rollout: &Mutex<crate::rollout::RolloutController>,
    secret: &str,
    req: &Request,
) -> Response {
    if !crate::control::authorized(req, secret) {
        return Response::new(StatusCode::UNAUTHORIZED, "bad or missing x-control-secret");
    }
    let rollout = rollout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let releases: Vec<serde_json::Value> = rollout
        .snapshot()
        .iter()
        .map(|(alias, state)| release_json(alias, state))
        .collect();
    Response::new(
        StatusCode::OK,
        serde_json::json!({ "releases": releases }).to_string(),
    )
}

/// One release state as the wire JSON for `GET /control/releases`.
fn release_json(alias: &str, state: &crate::rollout::ReleaseState) -> serde_json::Value {
    match state {
        crate::rollout::ReleaseState::Pending { unit, previous } => serde_json::json!({
            "hostname": alias,
            "state": "pending",
            "unit": { "id": &unit.id, "target": &unit.target },
            "previous": previous
                .as_ref()
                .map(|p| serde_json::json!({ "id": &p.id, "target": &p.target }))
        }),
        crate::rollout::ReleaseState::Live { unit, previous } => serde_json::json!({
            "hostname": alias,
            "state": "live",
            "unit": { "id": &unit.id, "target": &unit.target },
            "previous": previous
                .as_ref()
                .map(|p| serde_json::json!({ "id": &p.id, "target": &p.target }))
        }),
    }
}

/// Add the `/control/releases` routes to `app`, each behind the control secret.
pub fn mount(app: Router, edge: &Arc<EdgeLb>, secret: &Arc<String>) -> Router {
    macro_rules! handler {
        ($f:ident) => {{
            let edge = edge.clone();
            let secret = secret.clone();
            move |req: Request| {
                let edge = edge.clone();
                let secret = secret.clone();
                async move { $f(&edge.rollout, &secret, &req) }
            }
        }};
    }
    let probe = {
        let edge = edge.clone();
        let secret = secret.clone();
        move |req: Request| {
            let edge = edge.clone();
            let secret = secret.clone();
            async move { control_release_probe(&edge.rollout, &secret, &req).await }
        }
    };
    app.route(
        Method::POST,
        "/control/releases",
        handler!(control_release_stage),
    )
    .route(Method::POST, "/control/releases/:hostname/probe", probe)
    .route(
        Method::POST,
        "/control/releases/:hostname/rollback",
        handler!(control_release_rollback),
    )
    .route(
        Method::POST,
        "/control/releases/:hostname/retire",
        handler!(control_release_retire),
    )
    .route(
        Method::DELETE,
        "/control/releases/:hostname",
        handler!(control_release_cancel),
    )
    .route(
        Method::GET,
        "/control/releases",
        handler!(control_release_list),
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

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: &str,
    ) -> (u16, serde_json::Value) {
        let mut req = Request::new(method, path.parse().unwrap()).with_body(body.to_string());
        req.headers_mut()
            .insert("host", HeaderValue::from("edge.test"));
        req.headers_mut()
            .insert("x-control-secret", HeaderValue::from("s"));
        let resp = app.handle(req).await;
        (
            resp.status.as_u16(),
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Regression: these routes were registered with `{hostname}` and so never matched a real
    /// hostname — probing, rolling back, retiring and cancelling were unreachable.
    #[tokio::test]
    async fn parameterised_release_routes_match_real_hostnames() {
        let edge = EdgeLb::build(Vec::new()).await;
        let app = mount(Router::new(), &edge, &Arc::new("s".to_string()));
        let host = "site--feat-x.tascloud.dev";

        let (st, _) = call(
            &app,
            Method::POST,
            "/control/releases",
            &format!(r#"{{"hostname":"{host}","unit_id":"r1","target":"http://127.0.0.1:1"}}"#),
        )
        .await;
        assert_eq!(st, 201);
        let (st, v) = call(
            &app,
            Method::POST,
            &format!("/control/releases/{host}/probe"),
            r#"{"ok":true}"#,
        )
        .await;
        assert_eq!((st, v["status"].as_str()), (200, Some("live")));
        let (st, _) = call(
            &app,
            Method::POST,
            "/control/releases",
            &format!(r#"{{"hostname":"{host}","unit_id":"r2","target":"http://127.0.0.1:2"}}"#),
        )
        .await;
        assert_eq!(st, 201);
        let (st, v) = call(
            &app,
            Method::POST,
            &format!("/control/releases/{host}/probe"),
            r#"{"ok":true}"#,
        )
        .await;
        assert_eq!((st, v["status"].as_str()), (200, Some("live")));
        let (st, v) = call(
            &app,
            Method::POST,
            &format!("/control/releases/{host}/rollback"),
            "",
        )
        .await;
        assert_eq!((st, v["unit_id"].as_str()), (200, Some("r1")));
        let (st, v) = call(
            &app,
            Method::POST,
            &format!("/control/releases/{host}/retire"),
            "",
        )
        .await;
        assert_eq!((st, v["status"].as_str()), (200, Some("retired")));
        // cancel of a pending release
        let (st, _) = call(
            &app,
            Method::POST,
            "/control/releases",
            &format!(r#"{{"hostname":"{host}","unit_id":"r3","target":"http://127.0.0.1:3"}}"#),
        )
        .await;
        assert_eq!(st, 201);
        let (st, v) = call(
            &app,
            Method::DELETE,
            &format!("/control/releases/{host}"),
            "",
        )
        .await;
        assert_eq!((st, v["status"].as_str()), (200, Some("cancelled")));
        let (st, v) = call(&app, Method::GET, "/control/releases", "").await;
        assert_eq!(st, 200);
        assert!(v["releases"].is_array());
    }
}
