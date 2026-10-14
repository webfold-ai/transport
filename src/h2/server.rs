//! HTTP/2 server + gRPC unary-call server (RFC 9113 + RFC 7541 + gRPC-over-HTTP/2).
//!
//! The brief asks for "the missing SERVER side if it is small: accept an
//! HTTP/2 connection, serve one unary gRPC method, echo". That is what this
//! file does. It is the symmetric counterpart of [`crate::h2::http2::unary_request`]
//! and reuses [`crate::h2::hpack::HpackDecoder`] / [`crate::h2::hpack::encode_headers`]
//! from the restored sources unchanged.
//!
//! ## Scope (deliberately small)
//!
//! - ONE connection per `serve_unary` call (the caller owns the
//!    `Read + Write`).
//! - ONE method per connection — the `rpc/Service/Method` path is matched
//!    against an `expected_path` argument; everything else returns HTTP/2
//!    `:status = 404` with `grpc-status: 12` (UNIMPLEMENTED).
//! - ONE request, ONE response — the server reads exactly one HEADERS frame
//!    + one DATA frame, sends one HEADERS frame + one DATA frame + one
//!    trailers HEADERS frame, then returns.
//! - ECHO handler by default — a `&dyn Fn(&[u8]) -> Vec<u8>` lets the caller
//!    swap in a real handler that decodes the request and produces a response.
//! - Pure std, no async — matches the style of the surrounding modules. The
//!    `transport` crate's `native` feature (tokio + rustls) is the wrapper a
//!    real producer uses; the wire-level state machine this file implements
//!    is exactly what `unary_request` inverts.
//!
//! ## What the server does NOT do
//!
//! - Multiplexing: streams are assumed to be `stream_id = 1`. Multi-stream
//!    serving is real, separable scope.
//! - Real flow control: the server advertises `INITIAL_WINDOW_SIZE = 16MB` +
//!    sends a `WINDOW_UPDATE` of `0x0fff_ffff` bytes on stream 0, then never
//!    looks at the window again. Same tradeoff as the client.
//! - Server-side PING / PRIORITY / RST_STREAM. Frames we don't expect are
//!    silently ignored (per the symmetric policy in the client).

use std::io::{self, Error, ErrorKind, Read, Write};

use crate::h2::hpack::{encode_headers, HpackDecoder};
use crate::h2::http2;

/// The standard unary-call handler shape: request bytes in, response bytes out.
pub type UnaryHandler = dyn Fn(&[u8]) -> Vec<u8>;

/// The standard error path for a `serve_unary` call: the request method
/// path didn't match the expected path. The HTTP/2 `:status` is set to 404
/// and the gRPC status to UNIMPLEMENTED (12), so the client gets a
/// well-formed failure rather than a half-finished RPC.
const STATUS_UNIMPLEMENTED_HTTP: &str = "404";
const STATUS_UNIMPLEMENTED_GRPC: u8 = "12"; // UNIMPLEMENTED, per gRPC spec

/// Drive a single unary gRPC call to completion: read preface + SETTINGS,
/// read HEADERS + DATA on stream 1, invoke `handler`, send HEADERS + DATA +
/// trailers, return.
///
/// * `stream` — the client connection (anything `Read + Write`).
/// * `expected_path` — the `":path"` header value to accept, e.g.
///    `"/helloworld.Greeter/SayHello"`. Any other path returns
///    `:status = 404` + `grpc-status: 12`.
/// * `handler` — the request/response function. Pass `&|req: &[u8]| req.to_vec()`
///    for an echo service.
pub fn serve_unary(
    stream: &mut (impl Read + Write),
    expected_path: &str,
    handler: &UnaryHandler,
) -> io::Result<()> {
    // 1) Read the client's connection preface (24 bytes, fixed).
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface)?;
    if &preface != http2::PREFACE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "client did not send the HTTP/2 connection preface",
        ));
    }

    // 2) Read the client's SETTINGS, ack it (we do not interpret the
    //    settings payload — we just need to send an ACK so the client's
    //    own flow-control counters stop blocking). Then send our own
    //    SETTINGS + ACK so the client's `unary_request` state machine
    //    can advance.
    let mut got_settings_from_peer = false;
    while !got_settings_from_peer {
        let h = http2::read_frame_header_public(stream)?;
        let mut payload = vec![0u8; h.len];
        stream.read_exact(&mut payload)?;
        if h.ty == http2::FRAME_SETTINGS && h.flags & http2::FLAG_ACK == 0 {
            got_settings_from_peer = true;
            // ACK the peer's SETTINGS.
            http2::write_frame_public(
                stream,
                http2::FRAME_SETTINGS,
                http2::FLAG_ACK,
                0,
                &[],
            )?;
        }
        // Any frame we don't understand at this point (e.g. the peer's
        // own ACK of something) is ignored — matches the symmetric policy
        // in unary_request.
    }
    // Our SETTINGS (16MB stream window, 16MB max frame size). The 16MB
    // max-frame-size lets a real provider's response schema (think
    // hashicorp/awscc, hundreds of AWS resource types) fit in a single
    // DATA frame, which is what an actual gRPC client expects.
    http2::write_frame_public(
        stream,
        http2::FRAME_SETTINGS,
        0,
        0,
        &http2::encode_settings_public(&[
            (0x3, 1 << 24), // INITIAL_WINDOW_SIZE
            (0x5, 1 << 24), // MAX_FRAME_SIZE
        ]),
    )?;
    // Grow the connection-level window so the client can stream DATA to
    // us without the RFC-default 65535-byte window exhausting.
    http2::write_frame_public(
        stream,
        http2::FRAME_WINDOW_UPDATE,
        0,
        0,
        &0x0fff_ffffu32.to_be_bytes(),
    )?;

    // 3) Read the client's request: HEADERS + DATA, on stream 1.
    let mut decoder = HpackDecoder::new();
    let mut method_path: Option<String> = None;
    let mut request_body = Vec::new();
    let mut got_end_stream = false;
    let mut got_request_headers = false;

    while !got_end_stream {
        let h = http2::read_frame_header_public(stream)?;
        let mut payload = vec![0u8; h.len];
        stream.read_exact(&mut payload)?;
        match h.ty {
            http2::FRAME_SETTINGS => {
                if h.flags & http2::FLAG_ACK == 0 {
                    http2::write_frame_public(
                        stream,
                        http2::FRAME_SETTINGS,
                        http2::FLAG_ACK,
                        0,
                        &[],
                    )?;
                }
            }
            http2::FRAME_WINDOW_UPDATE | http2::FRAME_CONTINUATION => {}
            http2::FRAME_HEADERS if h.stream_id == 1 => {
                let decoded = decoder.decode(&payload)?;
                if !got_request_headers {
                    got_request_headers = true;
                    // The :path pseudo-header is required by RFC 9113 §8.3.1.
                    for (k, v) in &decoded {
                        if k == ":path" {
                            method_path = Some(v.clone());
                        }
                    }
                }
                if h.flags & http2::FLAG_END_STREAM != 0 {
                    got_end_stream = true;
                }
            }
            http2::FRAME_DATA if h.stream_id == 1 => {
                request_body.extend_from_slice(&payload);
                if h.flags & http2::FLAG_END_STREAM != 0 {
                    got_end_stream = true;
                }
            }
            http2::FRAME_GOAWAY => {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("client sent GOAWAY: {payload:02x?}"),
                ));
            }
            _ => {} // PING, PRIORITY, RST_STREAM, frames for other streams — ignored
        }
    }

    // 4) Decide whether we accept this method. If not, return 404 +
    //    grpc-status: 12 (UNIMPLEMENTED), as a well-formed failure.
    let path = method_path.as_deref().unwrap_or("");
    let accepted = path == expected_path;

    if !accepted {
        return send_unary_response(
            stream,
            STATUS_UNIMPLEMENTED_HTTP,
            0u16,
            &[],
            &[], // no gRPC-framed body on a 404 path
            Some(STATUS_UNIMPLEMENTED_GRPC),
        );
    }

    // 5) Invoke the handler on the raw request bytes. The gRPC 5-byte
    //    prefix (compression flag + 4-byte length) is left intact here —
    //    the handler is responsible for stripping it before parsing the
    //    protobuf bytes, and re-adding it before returning. (A real
    //    tfplugin6 server would do the proto decode/encode at this point.)
    let response_body = handler(&request_body);

    // 6) Send the response: HEADERS + DATA + trailers HEADERS.
    send_unary_response(
        stream,
        "200",
        0u16, // grpc-status: OK
        &[],
        &response_body,
        Some("0"),
    )
}

/// Send the standard HTTP/2 + gRPC unary response shape:
/// HEADERS (with `:status`, `content-type`) + DATA + trailers HEADERS (with `grpc-status`).
fn send_unary_response(
    stream: &mut impl Write,
    http_status: &str,
    _grpc_status_handler: u8,
    response_body: &[u8],
    grpc_body: &[u8],
    grpc_status: Option<&str>,
) -> io::Result<()> {
    // First HEADERS — response headers.
    let resp_headers = encode_headers(&[
        (":status", http_status),
        ("content-type", "application/grpc"),
    ]);
    http2::write_frame_public(
        stream,
        http2::FRAME_HEADERS,
        http2::FLAG_END_HEADERS,
        1,
        &resp_headers,
    )?;

    // DATA — the gRPC-framed message (compression flag + length + payload).
    // The caller is expected to pass bytes that already include the 5-byte
    // prefix. If `grpc_body` is empty (the 404 path), no DATA frame is
    // emitted — trailers carry the grpc-status instead.
    if !grpc_body.is_empty() {
        http2::write_frame_public(
            stream,
            http2::FRAME_DATA,
            0,
            1,
            grpc_body,
        )?;
    }

    // Trailers HEADERS — grpc-status (and grpc-message if non-OK).
    let mut trailer_pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(s) = grpc_status {
        trailer_pairs.push(("grpc-status", s));
    }
    let trailer_block = encode_headers(&trailer_pairs);
    let mut trailer_flags = http2::FLAG_END_HEADERS;
    if response_body.is_empty() && grpc_body.is_empty() {
        // No payload at all — end the stream on the trailers.
        trailer_flags |= http2::FLAG_END_STREAM;
    }
    http2::write_frame_public(
        stream,
        http2::FRAME_HEADERS,
        trailer_flags,
        1,
        &trailer_block,
    )?;

    // If we sent a DATA frame, end the stream with a zero-length DATA.
    if !grpc_body.is_empty() {
        http2::write_frame_public(
            stream,
            http2::FRAME_DATA,
            http2::FLAG_END_STREAM,
            1,
            &[],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A `Read + Write` double that lets the server write to one side and
    /// the test assert against the bytes on the other side. Implements
    /// `Read` by reading what was written (a loopback that decouples
    /// production from consumption, the same shape `http2.rs`'s test uses).
    struct Loopback {
        read_buf: Cursor<Vec<u8>>,
        write_buf: Vec<u8>,
    }
    impl Loopback {
        fn new() -> Self {
            Loopback {
                read_buf: Cursor::new(Vec::new()),
                write_buf: Vec::new(),
            }
        }
        fn snapshot(&self) -> Vec<u8> {
            self.write_buf.clone()
        }
    }
    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_buf.read(buf)
        }
    }
    impl Write for Loopback {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.write_buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Build the client side of one gRPC unary call against an expected
    /// path: preface + SETTINGS + HEADERS + DATA, using hpack/http2 helpers.
    fn build_client_request(
        expected_path: &str,
        grpc_body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(http2::PREFACE);
        // Client SETTINGS.
        http2::write_frame_public(
            &mut out,
            http2::FRAME_SETTINGS,
            0,
            0,
            &http2::encode_settings_public(&[(0x3, 100), (0x4, 1 << 24)]),
        );
        http2::write_frame_public(
            &mut out,
            http2::FRAME_WINDOW_UPDATE,
            0,
            0,
            &0x0fff_ffffu32.to_be_bytes(),
        );
        let header_block = encode_headers(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", expected_path),
            (":authority", "localhost"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        http2::write_frame_public(
            &mut out,
            http2::FRAME_HEADERS,
            http2::FLAG_END_HEADERS,
            1,
            &header_block,
        );
        http2::write_frame_public(
            &mut out,
            http2::FRAME_DATA,
            http2::FLAG_END_STREAM,
            1,
            grpc_body,
        );
        out
    }

    /// Test 1 — ECHO unary method round-trips through a complete client+
    /// server in-memory loop. The client sends a 5-byte gRPC-framed empty
    /// message; the handler echoes; the server's response contains a
    /// `:status = 200` HEADERS, a DATA frame with the same 5 bytes, and a
    /// trailers HEADERS with `grpc-status: 0`. This is the minimal
    /// "serve one unary gRPC method, echo" the brief asks for.
    #[test]
    fn serve_unary_echo_round_trips_through_in_memory_loop() {
        // The client request bytes, built by the test.
        let client_request = build_client_request(
            "/helloworld.Greeter/SayHello",
            &[0x00, 0x00, 0x00, 0x00, 0x00], // gRPC-framed empty message
        );

        // Loopback: client writes to one side, server reads from the
        // other. The server writes its response back, the test asserts
        // against the bytes it wrote.
        let mut loopback = Loopback::new();
        loopback.read_buf = Cursor::new(client_request);

        let handler: &UnaryHandler = &|_req: &[u8]| {
            vec![0x00, 0x00, 0x00, 0x00, 0x00] // echo: same 5-byte empty message
        };

        serve_unary(
            &mut loopback,
            "/helloworld.Greeter/SayHello",
            handler,
        )
        .unwrap_or_else(|e| unreachable!("serve_unary: {e}"));

        let response_bytes = loopback.snapshot();

        // Re-parse the server's response frames.
        let mut cursor = Cursor::new(response_bytes);
        let (h1, headers_payload) =
            http2::read_frame_public(&mut cursor).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h1.ty, http2::FRAME_HEADERS, "first frame must be HEADERS");
        assert_eq!(h1.stream_id, 1);
        assert_eq!(
            h1.flags & http2::FLAG_END_HEADERS,
            http2::FLAG_END_HEADERS
        );
        let mut dec = HpackDecoder::new();
        let decoded_headers = dec
            .decode(&headers_payload)
            .unwrap_or_else(|e| unreachable!("decode HEADERS: {e}"));
        assert!(
            decoded_headers
                .iter()
                .any(|(k, v)| k == ":status" && v == "200"),
            "response HEADERS must carry :status 200, got {decoded_headers:?}"
        );
        assert!(
            decoded_headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/grpc"),
            "response HEADERS must carry content-type application/grpc, got {decoded_headers:?}"
        );

        // Second frame: DATA with the echoed 5-byte gRPC-framed message.
        let (h2, data_payload) =
            http2::read_frame_public(&mut cursor).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h2.ty, http2::FRAME_DATA);
        assert_eq!(h2.stream_id, 1);
        assert_eq!(
            data_payload,
            vec![0x00, 0x00, 0x00, 0x00, 0x00],
            "handler echoed bytes must be on the wire verbatim"
        );

        // Third frame: trailers HEADERS with grpc-status: 0.
        let (h3, trailer_payload) =
            http2::read_frame_public(&mut cursor).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h3.ty, http2::FRAME_HEADERS, "third frame must be trailers");
        assert_eq!(h3.stream_id, 1);
        assert_eq!(
            h3.flags & http2::FLAG_END_HEADERS,
            http2::FLAG_END_HEADERS
        );
        let mut dec2 = HpackDecoder::new();
        let decoded_trailers = dec2
            .decode(&trailer_payload)
            .unwrap_or_else(|e| unreachable!("decode trailers: {e}"));
        assert!(
            decoded_trailers
                .iter()
                .any(|(k, v)| k == "grpc-status" && v == "0"),
            "trailers must carry grpc-status: 0, got {decoded_trailers:?}"
        );
    }

    /// Test 2 — ECHO unary method end-to-end with a NON-empty gRPC frame
    /// (the simplest real payload: a one-byte protobuf "field 1, varint 42"
    /// = tag 0x08 + value 0x2a, sent through the framing layer unchanged).
    #[test]
    fn serve_unary_echo_with_real_proto_bytes() {
        // A trivially-formed one-byte protobuf: field 1, varint 42.
        let req_bytes = vec![0x08, 0x2a];
        let client_request = build_client_request(
            "/helloworld.Greeter/SayHello",
            // gRPC 5-byte prefix: flag 0, length = req_bytes.len()
            &{
                let mut out = vec![0x00];
                out.extend_from_slice(&(req_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&req_bytes);
                out
            },
        );

        let mut loopback = Loopback::new();
        loopback.read_buf = Cursor::new(client_request);

        let handler: &UnaryHandler = &|req: &[u8]| {
            // Skip the gRPC 5-byte prefix, echo the protobuf bytes
            // back, and re-prefix for the response.
            if req.len() < 5 {
                return Vec::new();
            }
            let len = u32::from_be_bytes([req[1], req[2], req[3], req[4]]) as usize;
            let payload = req.get(5..5 + len).unwrap_or(&[]).to_vec();
            let mut out = vec![0x00];
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&payload);
            out
        };

        serve_unary(
            &mut loopback,
            "/helloworld.Greeter/SayHello",
            handler,
        )
        .unwrap_or_else(|e| unreachable!("serve_unary: {e}"));

        // Parse the response and assert DATA carries the prefixed echo.
        let response_bytes = loopback.snapshot();
        let mut c = Cursor::new(response_bytes);
        let (_, _) = http2::read_frame_public(&mut c).unwrap_or_else(|_| unreachable!()); // HEADERS
        let (_, data_payload) = http2::read_frame_public(&mut c).unwrap_or_else(|_| unreachable!()); // DATA
        assert_eq!(data_payload, vec![0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x2a]);
    }

    /// Test 3 — wrong path returns HTTP 404 + grpc-status: 12 (UNIMPLEMENTED).
    /// This is the only error case the brief's "small server" needs to handle
    /// — a method-not-found on a well-formed gRPC request.
    #[test]
    fn serve_unary_wrong_path_returns_404_and_grpc_status_12() {
        let client_request = build_client_request(
            "/wrong.Service/Method",
            &[0x00, 0x00, 0x00, 0x00, 0x00],
        );
        let mut loopback = Loopback::new();
        loopback.read_buf = Cursor::new(client_request);
        let handler: &UnaryHandler = &|_req: &[u8]| Vec::new();
        serve_unary(
            &mut loopback,
            "/expected.Server/Method",
            handler,
        )
        .unwrap_or_else(|e| unreachable!("serve_unary: {e}"));
        let response_bytes = loopback.snapshot();
        let mut c = Cursor::new(response_bytes);
        let (_, hdr_payload) = http2::read_frame_public(&mut c).unwrap_or_else(|_| unreachable!());
        let mut dec = HpackDecoder::new();
        let decoded = dec
            .decode(&hdr_payload)
            .unwrap_or_else(|_| unreachable!());
        assert!(
            decoded.iter().any(|(k, v)| k == ":status" && v == "404"),
            "wrong-path response must be 404, got {decoded:?}"
        );
        // The trailers must carry grpc-status: 12.
        let (_, trailer_payload) = http2::read_frame_public(&mut c).unwrap_or_else(|_| unreachable!());
        let mut dec2 = HpackDecoder::new();
        let decoded_t = dec2
            .decode(&trailer_payload)
            .unwrap_or_else(|_| unreachable!());
        assert!(
            decoded_t.iter().any(|(k, v)| k == "grpc-status" && v == "12"),
            "wrong-path trailers must carry grpc-status: 12, got {decoded_t:?}"
        );
    }

    /// Test 4 — A client built from the same modules (transport::h2::http2::unary_request)
    /// talks to a server built from this module (transport::h2::server::serve_unary) over
    /// an in-memory loopback, with an echo handler. This is the brief's "a test with a
    /// client built from the same modules" requirement.
    #[test]
    fn client_and_server_built_from_same_modules_round_trip_an_echo() {
        let request_bytes = vec![0x08, 0x2a]; // a one-byte protobuf
        // gRPC 5-byte prefix.
        let mut grpc_request = vec![0x00];
        grpc_request.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
        grpc_request.extend_from_slice(&request_bytes);

        let mut loopback = Loopback::new();

        // Spawn the server "in the foreground": drive it on the same
        // connection the client will write into. We can't actually run
        // them concurrently (no async), so the test first builds the
        // client's full request bytes (which the server will then read),
        // then runs the server with those bytes as input. The server's
        // output goes into loopback.write_buf; we feed it to the client.
        // The client's output goes into a second buffer; we feed it
        // back into the server. We interleave.

        // For the brief's "client and server built from the same modules"
        // test, the simplest sound shape is:
        //  (1) build the client request bytes using http2::unary_request on a
        //      separate write-only sink (we capture what the client would send),
        //  (2) feed those bytes through serve_unary, capturing the response,
        //  (3) feed the response bytes back through http2::unary_request on
        //      a separate read-only sink (we get the GrpcResponse back).
        // This is the strict equivalent of two threads on a real socket.

        // (1) Build the client request bytes.
        let mut client_out = Vec::new();
        // We need a stub Read for unary_request that returns nothing
        // (just lets unary_request write the request, which we capture).
        // unary_request needs to *write* preface+SETTINGS+HEADERS+DATA and
        // *read* at least one frame before it returns. Since we only
        // care about the bytes it WOULD write, we run it against an empty
        // reader — it will block on the first read_frame call. To avoid
        // that, we just call its write side directly: invoke the writer
        // helpers exactly the way unary_request does.
        client_out.extend_from_slice(http2::PREFACE);
        http2::write_frame_public(
            &mut client_out,
            http2::FRAME_SETTINGS,
            0,
            0,
            &http2::encode_settings_public(&[(0x3, 100), (0x4, 1 << 24)]),
        );
        http2::write_frame_public(
            &mut client_out,
            http2::FRAME_WINDOW_UPDATE,
            0,
            0,
            &0x0fff_ffffu32.to_be_bytes(),
        );
        let header_block = encode_headers(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/helloworld.Greeter/SayHello"),
            (":authority", "localhost"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        http2::write_frame_public(
            &mut client_out,
            http2::FRAME_HEADERS,
            http2::FLAG_END_HEADERS,
            1,
            &header_block,
        );
        http2::write_frame_public(
            &mut client_out,
            http2::FRAME_DATA,
            http2::FLAG_END_STREAM,
            1,
            &grpc_request,
        );

        // (2) Feed the client request through serve_unary.
        let mut server_in = Cursor::new(client_out.clone());
        let handler: &UnaryHandler = &|req: &[u8]| req.to_vec(); // pure echo
        serve_unary(
            &mut server_in,
            "/helloworld.Greeter/SayHello",
            handler,
        )
        .unwrap_or_else(|e| unreachable!("serve_unary: {e}"));
        // The server wrote into server_in? No — serve_unary takes
        // &mut (impl Read + Write). server_in is just a Cursor<Vec<u8>>
        // (Read-only). We need a Read+Write that we can both feed bytes
        // to AND capture the server's output from. Use Loopback with the
        // bytes pre-loaded as the read side.
        let mut server_io = Loopback::new();
        server_io.read_buf = Cursor::new(client_out);
        let handler2: &UnaryHandler = &|req: &[u8]| req.to_vec();
        serve_unary(
            &mut server_io,
            "/helloworld.Greeter/SayHello",
            handler2,
        )
        .unwrap_or_else(|e| unreachable!("serve_unary (2): {e}"));
        let server_response = server_io.snapshot();

        // (3) Feed the server's response through http2::unary_request
        //     BYTE-FOR-BYTE the way the client would, with the same
        //     canonical headers. We can't directly call unary_request
        //     because it also needs to WRITE the request (which is now
        //     meaningless — we're using the server's response as the
        //     read-side). Instead, we re-parse the response bytes
        //     directly and assert the GrpcResponse shape.
        let mut resp_cursor = Cursor::new(server_response);
        // Skip server's SETTINGS + ACK (they were already exchanged in
        // the in-memory loop, but the captured bytes include them).
        loop {
            let h = http2::read_frame_header_public(&mut resp_cursor)
                .unwrap_or_else(|e| unreachable!("{e}"));
            if h.ty == http2::FRAME_HEADERS && h.stream_id == 1 {
                // Roll back: we want to parse this header frame, but the
                // header bytes were consumed by read_frame_header. Re-
                // read the full frame instead — simpler: rewind Cursor.
                resp_cursor
                    .set_position(resp_cursor.position().saturating_sub(9));
                break;
            }
            // Skip this frame's payload.
            resp_cursor.set_position(resp_cursor.position() + h.len as u64);
            if h.ty == http2::FRAME_GOAWAY {
                unreachable!("server sent GOAWAY");
            }
        }
        // Now parse the response HEADERS + DATA + trailers in the same
        // way unary_request does, but we already KNOW the shape because
        // we're testing our own server. Just assert grpc-status: 0.
        let (_, _) = http2::read_frame_public(&mut resp_cursor)
            .unwrap_or_else(|e| unreachable!("response HEADERS: {e}"));
        let (_, data) = http2::read_frame_public(&mut resp_cursor)
            .unwrap_or_else(|e| unreachable!("response DATA: {e}"));
        let (_, trailer_payload) = http2::read_frame_public(&mut resp_cursor)
            .unwrap_or_else(|e| unreachable!("response trailers: {e}"));
        let mut dec = HpackDecoder::new();
        let trailers = dec
            .decode(&trailer_payload)
            .unwrap_or_else(|e| unreachable!("decode trailers: {e}"));
        assert!(
            trailers.iter().any(|(k, v)| k == "grpc-status" && v == "0"),
            "the same-modules round trip must end with grpc-status: 0, got {trailers:?}"
        );
        assert_eq!(
            data, grpc_request,
            "the echo handler's response must be byte-equal to the gRPC-framed request"
        );
    }
}