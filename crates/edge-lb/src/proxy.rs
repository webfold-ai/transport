//! The request lifecycle every public request runs through: a request filter
//! that may answer directly, then an upstream choice, then a forward.
//!
//! This replaces the `bedrock::{Proxy, ProxyHttp, Session, Upstream}` set. The
//! upstream call is `servelet-client`; the types are `servelet-core`'s.

use std::sync::OnceLock;

use servelet_client::Client;
use servelet_core::{Request, Response, StatusCode};

/// One origin a request is forwarded to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
}

impl Upstream {
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// One public request in flight. The request filter answers it with
/// [`Session::set_resp`]; otherwise it is forwarded to an [`Upstream`].
pub struct Session {
    req: Request,
    resp: Option<Response>,
}

impl Session {
    pub fn new(req: Request) -> Self {
        Self { req, resp: None }
    }

    pub fn req_header(&self) -> &Request {
        &self.req
    }

    pub fn set_resp(&mut self, resp: Response) {
        self.resp = Some(resp);
    }

    pub fn into_response(self) -> Response {
        self.resp.unwrap_or_else(|| {
            Response::new(StatusCode::BAD_GATEWAY, "the edge produced no response")
        })
    }
}

/// The outbound client is shared: its connection pool is what keeps keep-alive
/// connections to the origins warm across requests.
fn client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(Client::new)
}

/// Forward the session's request to `upstream` and return its response. The
/// request's `Host` header is kept, so virtual hosts on the origin still match.
pub async fn forward(session: &Session, upstream: &Upstream) -> Result<Response, String> {
    let req = session.req_header();
    let url = format!(
        "http://{}:{}{}",
        upstream.host,
        upstream.port,
        req.uri().path_and_query()
    );

    let mut outbound = client().request(req.method().clone(), url);
    for (name, value) in req.headers().iter() {
        if crate::is_hop_by_hop(name) {
            continue;
        }
        outbound = outbound.header(name.to_string(), value.as_bytes().to_vec());
    }
    let upstream_resp = outbound
        .body(req.body().to_vec())
        .send()
        .await
        .map_err(|e| format!("upstream {}:{}: {e}", upstream.host, upstream.port))?;

    let status = upstream_resp.status();
    let headers: Vec<(String, Vec<u8>)> = upstream_resp
        .headers()
        .iter()
        .filter(|(name, _)| !crate::is_hop_by_hop(name))
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    let body = upstream_resp.bytes().await;

    let mut resp = Response::new(status, body);
    for (name, value) in headers {
        resp.headers_mut().insert(name, value);
    }
    Ok(resp)
}
