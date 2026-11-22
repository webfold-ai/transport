//! HTTP-01 challenge responses (RFC 8555 §8.3) and the plain `:80` listener that serves them.
//!
//! The ACME client publishes `token → key authorization` into a [`ChallengeStore`]; the CA then
//! fetches `http://<name>/.well-known/acme-challenge/<token>` and expects exactly the key
//! authorization back. That is the only thing this listener serves in the clear. Everything else
//! on `:80` is a `308` to the same path on HTTPS **for names the edge knows**, and a bare `404`
//! otherwise — never an app response, never a redirect that confirms a name the edge does not
//! hold (the same no-existence-leak discipline as the TLS front).
//!
//! The store is process-local and in memory on purpose: a challenge outlives its order by seconds,
//! and a restart mid-order simply fails that order, which the renewal engine retries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use servelet_core::{Method, Request, Response, StatusCode};
use servelet_router::Router;
use transport::acme::{AcmeError, Http01Responder};
use transport::BoxFuture;

use crate::edge_state::EdgeState;

/// Most outstanding tokens held at once. A runaway issuer must not grow this without bound.
const MAX_TOKENS: usize = 4096;

/// Tokens the CA may currently fetch.
#[derive(Default)]
pub struct ChallengeStore {
    tokens: Mutex<HashMap<String, String>>,
}

impl ChallengeStore {
    /// The key authorization published for `token`, if any.
    #[must_use]
    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(token)
            .cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Http01Responder for ChallengeStore {
    fn serve_token<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
    ) -> BoxFuture<'a, Result<(), AcmeError>> {
        Box::pin(async move {
            // RFC 8555 §8.3: a token is base64url. Anything else cannot be a real challenge and
            // must not become a path component we serve.
            if token.is_empty()
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(AcmeError::ChallengeSetup);
            }
            let mut tokens = self
                .tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if tokens.len() >= MAX_TOKENS && !tokens.contains_key(token) {
                return Err(AcmeError::ChallengeSetup);
            }
            tokens.insert(token.to_string(), key_authorization.to_string());
            Ok(())
        })
    }

    fn remove_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(token);
        })
    }
}

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

fn host_of(req: &Request) -> Option<String> {
    let h = req.headers().get("host")?.to_str().ok()?;
    let h = match h.rsplit_once(':') {
        Some((name, port)) if !h.starts_with('[') && port.bytes().all(|b| b.is_ascii_digit()) => {
            name
        }
        _ => h,
    };
    Some(h.to_ascii_lowercase())
}

/// Answer one plain-HTTP request.
pub async fn handle(state: &EdgeState, req: Request) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Response::new(StatusCode::METHOD_NOT_ALLOWED, "");
    }
    let path = req.uri().path().to_string();
    if let Some(token) = path.strip_prefix(CHALLENGE_PREFIX) {
        return match state.challenges.get(token) {
            Some(key_auth) => Response::new(StatusCode::OK, key_auth)
                .with_header("content-type", "application/octet-stream"),
            None => Response::new(StatusCode::NOT_FOUND, ""),
        };
    }
    let Some(host) = host_of(&req) else {
        return Response::new(StatusCode::BAD_REQUEST, "");
    };
    if state.decide(&host, None).await.is_none() {
        return Response::new(StatusCode::NOT_FOUND, "");
    }
    let location = format!("https://{host}{}", req.uri().path_and_query());
    Response::new(
        StatusCode::from_u16(308).unwrap_or(StatusCode::MOVED_PERMANENTLY),
        "",
    )
    .with_header("location", location)
}

/// The `:80` app.
pub fn router(state: Arc<EdgeState>) -> Router {
    Router::new().fallback(move |req: Request| {
        let state = state.clone();
        async move { handle(&state, req).await }
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    fn get(host: &str, path: &str) -> Request {
        let mut r = Request::new(Method::GET, path.parse().unwrap());
        r.headers_mut()
            .insert("host", servelet_core::HeaderValue::from(host));
        r
    }

    #[tokio::test]
    async fn serves_exactly_the_published_key_authorization_until_removed() {
        let st = EdgeState::ephemeral();
        st.challenges
            .serve_token("tok-1_A", "tok-1_A.thumb")
            .await
            .unwrap();
        let ok = handle(
            &st,
            get("anything.example", "/.well-known/acme-challenge/tok-1_A"),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.body, b"tok-1_A.thumb");
        assert_eq!(
            handle(&st, get("a.b", "/.well-known/acme-challenge/other"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        st.challenges.remove_token("tok-1_A").await;
        assert_eq!(
            handle(&st, get("a.b", "/.well-known/acme-challenge/tok-1_A"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn malformed_tokens_and_unbounded_growth_are_refused() {
        let st = EdgeState::ephemeral();
        for bad in ["", "../etc", "a/b", "a b", "t\r\nx"] {
            assert!(
                st.challenges.serve_token(bad, "x").await.is_err(),
                "{bad:?}"
            );
        }
        for i in 0..MAX_TOKENS {
            st.challenges
                .serve_token(&format!("t{i}"), "x")
                .await
                .unwrap();
        }
        assert!(st
            .challenges
            .serve_token("one-too-many", "x")
            .await
            .is_err());
        st.challenges.serve_token("t0", "replaced").await.unwrap(); // overwriting is fine
        assert_eq!(st.challenges.len(), MAX_TOKENS);
    }

    #[tokio::test]
    async fn known_names_redirect_to_https_and_unknown_names_say_nothing() {
        let st = EdgeState::ephemeral();
        st.apply(&crate::edge_state::Op::AdmitManaged {
            tenant_id: "acme".into(),
            tunnel_id: "t".into(),
            apex: "tascloud.app".into(),
            label: Some("mine".into()),
            dialkey: None,
            tls_mode: "terminate".into(),
            origin_port: 8080,
            agent_peer: None,
        })
        .await
        .unwrap();
        let r = handle(&st, get("mine.tascloud.app", "/a?b=1")).await;
        assert_eq!(r.status().as_u16(), 308);
        assert_eq!(
            r.headers().get("location").unwrap().to_str().unwrap(),
            "https://mine.tascloud.app/a?b=1"
        );
        let r = handle(&st, get("nothing.tascloud.app", "/a")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(r.headers().get("location").is_none());

        let post = Request::new(Method::POST, "/".parse().unwrap())
            .with_header("host", "mine.tascloud.app");
        assert_eq!(
            handle(&st, post).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
