//! Router-level probe: control routes + fallback behave on the servelet router.
//! Router (the fleet smoke hit a 404 from the fallback — isolate whether
//! the route registration or the request path is the problem).

#![expect(clippy::unwrap_used, reason = "test code: deterministic assertions")]

use edge_lb::{BackendSpec, EdgeLb};
use servelet_core::{Method, Request, Response, StatusCode};
use std::sync::Arc;

#[tokio::test]
async fn control_route_registers_and_dispatches() {
    let edge = EdgeLb::build(vec![(
        "static.test".to_string(),
        BackendSpec::Static {
            host: "127.0.0.1".into(),
            port: 1,
        },
    )])
    .await;
    let registry = edge.tunnels.clone();
    let secret = Arc::new("probe-secret".to_string());
    let app = edge_lb::router(edge.clone()).route(
        Method::POST,
        "/control/tunnels",
        move |req: Request| {
            let registry = registry.clone();
            let secret = secret.clone();
            async move {
                if req
                    .headers()
                    .get("x-control-secret")
                    .and_then(|v| v.to_str().ok())
                    != Some(secret.as_str())
                {
                    return Response::new(StatusCode::UNAUTHORIZED, "bad secret");
                }
                let _ = registry;
                Response::new(StatusCode::CREATED, "registered")
            }
        },
    );

    // Wrong secret: the ROUTE must match (401 from the handler), not the
    // fallback (404 unknown hostname).
    let mut req = Request::new(Method::POST, "/control/tunnels".parse().unwrap());
    req.headers_mut()
        .insert("host", servelet_core::HeaderValue::from("127.0.0.1"));
    req.headers_mut().insert(
        "x-control-secret",
        servelet_core::HeaderValue::from("wrong"),
    );
    let resp = app.clone().handle(req).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "route must match before the fallback — got {}",
        resp.status().as_u16()
    );

    // Right secret → 201 from the handler.
    let mut req = Request::new(Method::POST, "/control/tunnels".parse().unwrap());
    req.headers_mut()
        .insert("host", servelet_core::HeaderValue::from("127.0.0.1"));
    req.headers_mut().insert(
        "x-control-secret",
        servelet_core::HeaderValue::from("probe-secret"),
    );
    let resp = app.handle(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}
