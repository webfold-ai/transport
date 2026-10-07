//! gRPC unary calls over [`crate::sync::http2`] — the 5-byte message framing
//! (RFC: 1-byte compression flag + 4-byte big-endian length + the protobuf
//! message bytes) and the standard headers (`content-type: application/grpc`,
//! `te: trailers`), plus `grpc-status`/`grpc-message` trailer handling. Pure
//! Rust, zero deps — the protobuf message bytes themselves are opaque here
//! (encode/decode is [`hashtrinity`]'s job); this module only frames and
//! transports them.

use std::io::{self, Error, ErrorKind, Read, Write};

use crate::sync::http2;

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

#[cfg(test)]
mod live_check {
    use super::*;
    use crate::sync::tls::client::{ClientIdentity, TlsClient};
    use crate::sync::tls::{ecdsa, x509};
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    /// The full stack, first real call: connect via AutoMTLS to a REAL
    /// go-plugin provider (as `tls::client::live_check` already proved works),
    /// then make an actual `GetProviderSchema` gRPC call over it and check we
    /// get back `grpc-status: 0` and at least SOME protobuf bytes — the first
    /// genuine round trip through crypto + cert + TLS + HTTP/2 + HPACK + gRPC
    /// framing all at once, against the real thing. `GetProviderSchema.Request`
    /// has zero fields (an empty message), so this needs no protobuf encoding
    /// on the way out at all; decoding the response schema is separate,
    /// still-pending work (hashtrinity's proto codec needs `map<K,V>` support
    /// first) — this test only proves the transport, not the schema.
    #[test]
    #[ignore = "spawns a real provider binary and hits its live TLS port — run explicitly"]
    fn get_provider_schema_round_trips_against_a_real_provider() {
        let provider = std::env::var("SYNCFOLD_TEST_PROVIDER_BIN").unwrap_or_else(|_| {
            unreachable!("set SYNCFOLD_TEST_PROVIDER_BIN to an AutoMTLS-capable provider path")
        });

        let curve = ecdsa::p521();
        let (d, qx, qy) = curve
            .generate_keypair()
            .unwrap_or_else(|e| unreachable!("keygen: {e}"));
        let der = x509::build_self_signed_p521(
            &d,
            &qx,
            &qy,
            "localhost",
            &[0x2b],
            1_700_000_000,
            2_100_000_000,
        );
        let pem = x509::to_pem(&der);
        let identity = ClientIdentity {
            cert_der: der,
            private_key: d,
        };

        let mut child = Command::new(&provider)
            .env(
                "TF_PLUGIN_MAGIC_COOKIE",
                "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
            )
            .env("PLUGIN_PROTOCOL_VERSIONS", "6")
            .env("PLUGIN_MIN_PORT", "10000")
            .env("PLUGIN_MAX_PORT", "25000")
            .env("PLUGIN_CLIENT_CERT", &pem)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| unreachable!("spawn provider: {e}"));

        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| unreachable!("no stdout"));
        let mut lines = std::io::BufReader::new(stdout).lines();
        let mut handshake = None;
        for _ in 0..20 {
            let Some(Ok(line)) = lines.next() else { break };
            if line.starts_with("1|") && line.matches('|').count() == 5 {
                handshake = Some(line);
                break;
            }
        }
        let handshake =
            handshake.unwrap_or_else(|| unreachable!("no handshake line seen from provider"));
        // Keep draining stdout in the background for the rest of the test: if the
        // provider logs anything further and nobody reads its stdout pipe, the pipe
        // buffer fills and the provider can block trying to write to it — a stall
        // that looks exactly like an inconsistent, timing-dependent connection
        // failure on OUR side (measured live: the same test failed at different
        // points in the HTTP/2 write sequence across runs, the signature of a
        // starved child process, not a protocol bug).
        std::thread::spawn(move || for _ in lines.by_ref() {});
        let fields: Vec<&str> = handshake.split('|').collect();
        let network = fields[2];
        let addr = fields[3];

        let mut tls = match network {
            "unix" => TlsClient::connect_unix_with_identity(addr, "localhost", Some(&identity)),
            "tcp" => {
                let (host, port_str) = addr
                    .rsplit_once(':')
                    .unwrap_or_else(|| unreachable!("bad addr: {addr}"));
                let port: u16 = port_str
                    .parse()
                    .unwrap_or_else(|e| unreachable!("bad port: {e}"));
                TlsClient::connect_with_identity(host, port, false, Some(&identity))
            }
            other => unreachable!("unexpected network type: {other}"),
        }
        .unwrap_or_else(|e| unreachable!("AutoMTLS handshake failed: {e}"));

        let result = call(
            &mut tls,
            "localhost",
            "/tfplugin6.Provider/GetProviderSchema",
            &[],
        );

        let _ = child.kill();
        let _ = child.wait();

        let resp = result.unwrap_or_else(|e| unreachable!("GetProviderSchema call failed: {e}"));
        assert_eq!(
            resp.grpc_status, 0,
            "grpc-status must be OK, got message: {}",
            resp.grpc_message
        );
        assert!(
            !resp.message.is_empty(),
            "a real provider's schema response must not be empty protobuf bytes"
        );
    }
}
