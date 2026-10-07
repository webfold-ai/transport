//! gRPC unary calls over [`crate::h2::http2`] — the 5-byte message framing
//! (RFC: 1-byte compression flag + 4-byte big-endian length + the protobuf
//! message bytes) and the standard headers (`content-type: application/grpc`,
//! `te: trailers`), plus `grpc-status`/`grpc-message` trailer handling. Pure
//! Rust, zero deps — the protobuf message bytes themselves are opaque here
//! (encode/decode is [`hashtrinity`]'s job); this module only frames and
//! transports them.

use std::io::{self, Error, ErrorKind, Read, Write};

use crate::h2::http2;

pub struct GrpcResponse {
    pub message: Vec<u8>, // raw protobuf bytes, framing already stripped
    pub grpc_status: i32,
    pub grpc_message: String,
}

/// Frame a single protobuf message the way gRPC puts it on the wire: no
/// compression (flag byte 0), then its length, then the bytes themselves.
fn frame_message(protobuf_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + protobuf_bytes.len());
    out.push(0x00); // uncompressed
    out.extend_from_slice(&(protobuf_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(protobuf_bytes);
    out
}

/// Un-frame ONE gRPC message from `body` (which may be exactly one frame, or
/// occasionally arrive with a trailing partial/duplicate for streaming calls —
/// a unary response is always exactly one frame, so anything past it is
/// ignored rather than erroring).
fn unframe_message(body: &[u8]) -> io::Result<Vec<u8>> {
    let err = || Error::new(ErrorKind::InvalidData, "truncated gRPC message frame");
    if body.len() < 5 {
        if body.is_empty() {
            return Ok(Vec::new()); // a genuinely empty response message (e.g. Empty{})
        }
        return Err(err());
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    body.get(5..5 + len).map(<[u8]>::to_vec).ok_or_else(err)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Call `full_method` (e.g. `"/tfplugin6.Provider/GetProviderSchema"`) with
/// `request_protobuf` as the request message, over an already-connected
/// `io` (our TLS client, a plaintext socket, whatever implements `Read+Write`).
pub fn call(
    io: &mut (impl Read + Write),
    authority: &str,
    full_method: &str,
    request_protobuf: &[u8],
) -> io::Result<GrpcResponse> {
    let headers = [
        (":method", "POST"),
        (":scheme", "http"),
        (":path", full_method),
        (":authority", authority),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-accept-encoding", "identity"),
    ];
    let body = frame_message(request_protobuf);
    let resp = http2::unary_request(io, &headers, &body)?;

    let status = header_value(&resp.headers, ":status");
    if status != Some("200") {
        return Err(Error::new(
            ErrorKind::Other,
            format!("HTTP/2 status {status:?} (expected 200)"),
        ));
    }

    // grpc-status can arrive either as a trailer (the normal unary-call shape)
    // or, for a call that fails before any response headers, as a HEADERS-only
    // response with grpc-status set directly on the (only) HEADERS frame.
    let status_source = if !resp.trailers.is_empty() {
        &resp.trailers
    } else {
        &resp.headers
    };
    let grpc_status: i32 = header_value(status_source, "grpc-status")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let grpc_message = header_value(status_source, "grpc-message")
        .unwrap_or("")
        .to_string();

    let message = unframe_message(&resp.body)?;
    Ok(GrpcResponse {
        message,
        grpc_status,
        grpc_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_then_unframe_round_trips() {
        for msg in [b"".as_slice(), b"hello", &[0u8; 300]] {
            let framed = frame_message(msg);
            assert_eq!(framed[0], 0x00, "compression flag must be 0 (uncompressed)");
            let unframed = unframe_message(&framed).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(unframed, msg);
        }
    }

    #[test]
    fn unframe_rejects_truncated_length_prefix() {
        assert!(unframe_message(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn unframe_accepts_genuinely_empty_body() {
        assert_eq!(
            unframe_message(&[]).unwrap_or_else(|e| unreachable!("{e}")),
            Vec::<u8>::new()
        );
    }
}

// `mod live_check` (the only test in this file at parent commit 7ea2006b) was
// deleted in the W-N adaptation commit. It is the round-trip integration test
// against a real OpenTofu provider binary over TLS+HTTP/2+gRPC (see the
// reverted-to-parent shape at parent commit:81730cc^1:hashtrinity/src/sync/grpc.rs
// for the full body), and its imports — `crate::sync::tls::client::{
// ClientIdentity, TlsClient}` and `crate::sync::tls::{ecdsa, x509}` — reference
// hashtrinity's TLS stack, which lives at `hashtrinity::sync::tls` in the
// consolidated post-reconcile trunk. W-N does not pull that stack into
// transport (transport's TLS path is `rustls` + `tokio-rustls`, already
// declared in Cargo.toml as optional native-only deps). The 3 framing unit
// tests in `mod tests` above ARE preserved; the live_check integration test
// is recorded as MISSING TESTS in docs/h2-grpc/02-adaptation.md, with the
// trigger condition for re-adding it: a hashtrinity-crate-native dependency
// that exposes `TlsClient::connect_with_identity` + AutoMTLS handshake.
