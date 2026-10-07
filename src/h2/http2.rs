//! HTTP/2 framing (RFC 9113) — just enough to drive ONE gRPC unary call per
//! connection: the connection preface, SETTINGS exchange, HEADERS+DATA on a
//! single stream, and reading the response HEADERS/DATA/trailers back. Pure
//! Rust, zero deps, over any [`crate::sync::hpack`]-paired byte stream (this
//! module doesn't care whether the underlying transport is plaintext, our own
//! TLS client, or a Unix socket — it just needs `Read + Write`).
//!
//! Deliberately NOT a general HTTP/2 client: no multiplexing (one stream per
//! connection), no real flow control (we advertise a large enough
//! `INITIAL_WINDOW_SIZE`/`WINDOW_UPDATE` to never need one for a single
//! request/response of realistic size), no server push, no priority. Each of
//! those is real, separable scope a general client would need — this is
//! scoped to what a gRPC unary call over go-plugin's tfplugin6 actually uses.

use std::io::{self, Error, ErrorKind, Read, Write};

use crate::sync::hpack::{encode_headers, HpackDecoder};

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_ACK: u8 = 0x1;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct FrameHeader {
    len: usize,
    ty: u8,
    flags: u8,
    stream_id: u32,
}

fn write_frame(
    w: &mut impl Write,
    ty: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    let mut hdr = [0u8; 9];
    hdr[0] = (len >> 16) as u8;
    hdr[1] = (len >> 8) as u8;
    hdr[2] = len as u8;
    hdr[3] = ty;
    hdr[4] = flags;
    hdr[5..9].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)
}

fn read_frame_header(r: &mut impl Read) -> io::Result<FrameHeader> {
    let mut hdr = [0u8; 9];
    r.read_exact(&mut hdr)?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    let ty = hdr[3];
    let flags = hdr[4];
    let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    Ok(FrameHeader {
        len,
        ty,
        flags,
        stream_id,
    })
}

fn read_frame(r: &mut impl Read) -> io::Result<(FrameHeader, Vec<u8>)> {
    let h = read_frame_header(r)?;
    let mut payload = vec![0u8; h.len];
    r.read_exact(&mut payload)?;
    Ok((h, payload))
}

/// One SETTINGS parameter as `(id, value)`, encoded as 6 bytes (u16 id + u32 value).
fn encode_settings(params: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len() * 6);
    for &(id, val) in params {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&val.to_be_bytes());
    }
    out
}

/// The full response to a unary gRPC call: headers, the single reassembled
/// message body (gRPC-framed: 1-byte compression flag + 4-byte length still
/// attached — [`crate::sync::grpc`] strips that), and trailers (`grpc-status` etc).
pub struct Http2Response {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub trailers: Vec<(String, String)>,
}

/// Perform ONE HTTP/2 request/response over `stream_id = 1`: connection
/// preface, SETTINGS handshake, HEADERS (from `headers`, HPACK-encoded) +
/// DATA (`body`, already framed by the caller — gRPC's 5-byte prefix, if
/// any), then read the response through to its trailers.
pub fn unary_request(
    io: &mut (impl Read + Write),
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<Http2Response> {
    io.write_all(PREFACE)?;
    // SETTINGS_INITIAL_WINDOW_SIZE (16MB) governs a STREAM's flow-control window,
    // but the CONNECTION-level window is a separate accounting that always starts
    // at the RFC default 65535 bytes regardless of any SETTINGS value, and can only
    // grow via an explicit WINDOW_UPDATE on stream 0 — a real provider's schema (a
    // large one, e.g. `hashicorp/awscc`, covering hundreds of AWS resource types)
    // can exceed 65535 bytes easily, and without this the server just stops sending
    // once the default window is exhausted, silently stalling the read loop below
    // (measured live: this exact hang, until this fix).
    write_frame(
        io,
        FRAME_SETTINGS,
        0,
        0,
        &encode_settings(&[(0x3, 100), (0x4, 1 << 24)]),
    )?;
    write_frame(io, FRAME_WINDOW_UPDATE, 0, 0, &0x0fff_ffffu32.to_be_bytes())?;

    let mut decoder = HpackDecoder::new();
    let mut response_headers: Option<Vec<(String, String)>> = None;
    let mut response_body = Vec::new();
    let mut trailers: Vec<(String, String)> = Vec::new();
    let mut got_settings_from_peer = false;

    // Read (and ack) the peer's own SETTINGS before sending HEADERS/DATA — some
    // HTTP/2 servers are strict about not seeing stream frames pipelined ahead of
    // the initial SETTINGS exchange completing, even though the spec technically
    // permits it.
    while !got_settings_from_peer {
        let (h, payload) = read_frame(io)?;
        if h.ty == FRAME_SETTINGS && h.flags & FLAG_ACK == 0 {
            got_settings_from_peer = true;
            write_frame(io, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
        } else if h.ty == FRAME_GOAWAY {
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!("server sent GOAWAY: {payload:02x?}"),
            ));
        }
        // anything else this early (a SETTINGS ACK of ours, etc.) — ignore and keep waiting
    }

    let header_block = encode_headers(headers);
    write_frame(io, FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block)?;
    write_frame(io, FRAME_DATA, FLAG_END_STREAM, 1, body)?;
    // Belt-and-suspenders: also grow stream 1's own window explicitly, in case a
    // peer doesn't apply our SETTINGS_INITIAL_WINDOW_SIZE to this stream in time.
    write_frame(io, FRAME_WINDOW_UPDATE, 0, 1, &0x0fff_ffffu32.to_be_bytes())?;

    loop {
        let (h, payload) = read_frame(io)?;
        match h.ty {
            FRAME_SETTINGS => {
                if h.flags & FLAG_ACK == 0 {
                    got_settings_from_peer = true;
                    write_frame(io, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                }
            }
            FRAME_WINDOW_UPDATE | FRAME_CONTINUATION => {} // no real flow control / no split header blocks expected
            FRAME_HEADERS if h.stream_id == 1 => {
                let decoded = decoder.decode(&payload)?;
                if response_headers.is_none() {
                    response_headers = Some(decoded);
                } else {
                    trailers = decoded;
                }
                if h.flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            FRAME_DATA if h.stream_id == 1 => {
                response_body.extend_from_slice(&payload);
                if h.flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            FRAME_HEADERS | FRAME_DATA => {
                // A frame for a different stream: this client only ever opens stream 1,
                // so anything else is the peer's business (e.g. its own control stream),
                // never ours to interpret — skip without erroring.
            }
            FRAME_GOAWAY => {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("server sent GOAWAY: {payload:02x?}"),
                ));
            }
            _ => {} // PING, PRIORITY, RST_STREAM on frames we don't expect — ignored
        }
    }

    if !got_settings_from_peer {
        // Not fatal by itself (the peer may have sent SETTINGS after our first
        // read loop iteration already handled it) — only a diagnostic signal.
    }

    Ok(Http2Response {
        headers: response_headers.unwrap_or_default(),
        body: response_body,
        trailers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A `Read + Write` double that queues canned frames to read back and
    /// records everything written — exercises `unary_request` without a real
    /// socket or a real server, checking the byte-level framing this module
    /// produces/expects is self-consistent.
    struct FakeConn {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for FakeConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for FakeConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn canned_response() -> Vec<u8> {
        let mut out = Vec::new();
        // SETTINGS (empty, from "server")
        write_frame(&mut out, FRAME_SETTINGS, 0, 0, &[]).unwrap();
        // SETTINGS ACK (to our own SETTINGS)
        write_frame(&mut out, FRAME_SETTINGS, FLAG_ACK, 0, &[]).unwrap();
        // Response HEADERS: :status 200 (indexed, static #8), content-type application/grpc (literal)
        let mut hdr_block = Vec::new();
        crate::sync::hpack::encode_header(&mut hdr_block, ":status", "200");
        crate::sync::hpack::encode_header(&mut hdr_block, "content-type", "application/grpc");
        write_frame(&mut out, FRAME_HEADERS, FLAG_END_HEADERS, 1, &hdr_block).unwrap();
        // DATA: a fake gRPC-framed empty message (compressed=0, len=0)
        write_frame(&mut out, FRAME_DATA, 0, 1, &[0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        // Trailers: grpc-status: 0
        let mut trailer_block = Vec::new();
        crate::sync::hpack::encode_header(&mut trailer_block, "grpc-status", "0");
        write_frame(
            &mut out,
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &trailer_block,
        )
        .unwrap();
        out
    }

    #[test]
    fn unary_request_sends_preface_settings_headers_data_and_parses_response() {
        let mut conn = FakeConn {
            to_read: Cursor::new(canned_response()),
            written: Vec::new(),
        };
        let resp = unary_request(
            &mut conn,
            &[
                (":method", "POST"),
                (":path", "/tfplugin6.Provider/GetProviderSchema"),
            ],
            &[0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .unwrap_or_else(|e| unreachable!("{e}"));

        assert!(
            conn.written.starts_with(PREFACE),
            "must send the HTTP/2 connection preface first"
        );
        assert_eq!(
            resp.headers,
            vec![
                (":status".to_string(), "200".to_string()),
                ("content-type".to_string(), "application/grpc".to_string()),
            ]
        );
        assert_eq!(resp.body, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            resp.trailers,
            vec![("grpc-status".to_string(), "0".to_string())]
        );

        // Our own outbound frames must themselves be well-formed: re-parse what we wrote.
        // Order: our SETTINGS, our connection-level WINDOW_UPDATE, our ACK of the peer's
        // SETTINGS (read before we send HEADERS — see `unary_request`'s doc comment on why),
        // then HEADERS, DATA, and a stream-level WINDOW_UPDATE.
        let mut written = Cursor::new(conn.written[PREFACE.len()..].to_vec());
        let (h1, _) = read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h1.ty, FRAME_SETTINGS);
        let (h_wu, _) = read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h_wu.ty, FRAME_WINDOW_UPDATE);
        assert_eq!(
            h_wu.stream_id, 0,
            "the first WINDOW_UPDATE grows the connection-level window"
        );
        let (h_ack, _) = read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h_ack.ty, FRAME_SETTINGS);
        assert_eq!(
            h_ack.flags & FLAG_ACK,
            FLAG_ACK,
            "must ack the peer's SETTINGS"
        );
        let (h2, headers_payload) =
            read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h2.ty, FRAME_HEADERS);
        assert_eq!(h2.flags & FLAG_END_HEADERS, FLAG_END_HEADERS);
        let mut dec = HpackDecoder::new();
        let sent_headers = dec
            .decode(&headers_payload)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(sent_headers[0], (":method".to_string(), "POST".to_string()));
        let (h3, data_payload) = read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h3.ty, FRAME_DATA);
        assert_eq!(h3.flags & FLAG_END_STREAM, FLAG_END_STREAM);
        assert_eq!(data_payload, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
        let (h4, _) = read_frame(&mut written).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(h4.ty, FRAME_WINDOW_UPDATE);
        assert_eq!(
            h4.stream_id, 1,
            "the second WINDOW_UPDATE grows stream 1's own window"
        );
    }
}
