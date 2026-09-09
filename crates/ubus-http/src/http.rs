//! A minimal HTTP/1.1 server, and the request handling on top of it.
//!
//! Enough HTTP to serve generated clients and no more: `POST` with a
//! `Content-Length` body, JSON in and JSON out. Hand-rolled to keep the crate
//! dependency-free so it cross-compiles to the router trivially — the same
//! reasoning as the rest of the workspace, and the same discipline as speaking
//! ubus rather than linking libubox.
//!
//! It is a **loopback adapter behind ssh**, not an internet-facing server.
//! Where that changes what is correct, it is said at the point it matters.

use crate::bridge::{args_from_json, json_from_decoded};
use crate::route::RouteTable;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use ubus_facade::json::Json;
use ubus_proto::client::{ClientError, Connection};

/// A cap on the header block.
///
/// Without one, a client that opens a connection and sends headers forever
/// holds this thread until the process dies — and a server that handles one
/// connection per thread has no other defence.
const MAX_HEADERS: usize = 100;

/// A cap on the request body.
///
/// The largest legitimate payload here is a whole UCI config, measured at
/// ~55 KB, so 1 MiB is generous by a factor of ~19 while still bounding a
/// hostile or buggy client.
const MAX_BODY: usize = 1024 * 1024;

/// A parsed request: just the parts this adapter acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
}

/// Read one request from a stream.
///
/// # Errors
///
/// A malformed request line, a header block that exceeds the cap, or a body
/// that does not arrive.
pub fn read_request<R: Read>(stream: R) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("reading the request line: {e}"))?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_owned();
    let path = parts.next().ok_or("request line has no path")?.to_owned();

    let mut content_length = 0usize;
    for _ in 0..MAX_HEADERS {
        let mut h = String::new();
        let n = reader
            .read_line(&mut h)
            .map_err(|e| format!("reading headers: {e}"))?;
        if n == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((name, value)) = h.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| "Content-Length is not a number".to_owned())?;
        }
    }

    if content_length > MAX_BODY {
        return Err(format!(
            "body of {content_length} bytes exceeds the {MAX_BODY}-byte cap"
        ));
    }

    let mut body = vec![0u8; content_length];
    reader
        .read_exact(&mut body)
        .map_err(|e| format!("reading the body: {e}"))?;
    let body = String::from_utf8(body).map_err(|_| "the body is not UTF-8".to_owned())?;

    Ok(Request { method, path, body })
}

/// An HTTP status and a JSON payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub body: Json,
}

impl Response {
    fn error(status: u16, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            body: Json::obj([("error", Json::str(message.into()))]),
        }
    }

    /// Render the whole HTTP response.
    #[must_use]
    pub fn render(&self) -> String {
        let body = self.body.render();
        let mut out = String::new();
        out.push_str("HTTP/1.1 ");
        // Rendered through a typed surface rather than assembled: `Display` for
        // the numbers, fixed literals for the syntax.
        out.push_str(&self.status.to_string());
        out.push(' ');
        out.push_str(self.reason);
        out.push_str("\r\nContent-Type: application/json\r\nContent-Length: ");
        out.push_str(&body.len().to_string());
        out.push_str("\r\nConnection: close\r\n\r\n");
        out.push_str(&body);
        out
    }
}

/// Decide what a request means, and perform it.
///
/// Takes the connection as a parameter so this is testable against a mock
/// stream — the whole reason [`Connection`] is generic over `Read + Write`.
pub fn handle<S: Read + Write>(
    req: &Request,
    routes: &RouteTable,
    conn: &mut Connection<S>,
) -> Response {
    if req.method != "POST" {
        // Every façade operation is a POST: ubus has no read/write distinction
        // at the transport, and pretending `uci get` is a GET would invite
        // caching of a value that changes.
        return Response::error(
            405,
            "Method Not Allowed",
            format!(
                "{} is not supported; every ubus operation is a POST",
                req.method
            ),
        );
    }

    let Some(route) = routes.get(&req.path) else {
        return Response::error(
            404,
            "Not Found",
            format!(
                "no ubus operation at {}; the adapter serves only what the façade \
                 describes, and the façade describes only what was measured on a device",
                req.path
            ),
        );
    };

    // ★ NO PRE-REFUSAL on `requires_rpcd_session`, and the reason is a
    // measurement.
    //
    // Every `uci` method DECLARES `ubus_rpc_session` — all 28 of them — but
    // measured 2026-09-08 only `apply`/`confirm`/`rollback` ENFORCE it;
    // `get`/`set`/`add`/`commit`/`revert`/`changes` work over the native socket
    // with no session at all. Gating on the declaration therefore refuses
    // operations that demonstrably work, which is exactly what a first cut of
    // this function did: every request returned 501, including `uci get`.
    //
    // Declaration is not enforcement. So the call is ATTEMPTED and the device
    // decides, and the declaration is kept as a DIAGNOSTIC HINT attached to a
    // failure rather than as a gate in front of a success. For the 236
    // non-uci operations we have measured neither way, which is the stronger
    // argument for letting the device answer.

    let body = if req.body.trim().is_empty() {
        Json::Obj(Vec::new())
    } else {
        match ubus_facade::json::parse(&req.body) {
            Ok(j) => j,
            Err(e) => return Response::error(400, "Bad Request", e.to_string()),
        }
    };

    let args = match args_from_json(&body) {
        Ok(a) => a,
        Err(e) => return Response::error(400, "Bad Request", e),
    };

    match conn.call(&route.object, &route.method, &args) {
        // A method with no return value answers with no payload. Reported as an
        // empty object with an explicit marker rather than as `null`, so a
        // client can tell "succeeded, nothing to report" from "no answer".
        Ok(None) => Response {
            status: 200,
            reason: "OK",
            body: Json::obj([("ok", Json::Bool(true))]),
        },
        Ok(Some(d)) => Response {
            status: 200,
            reason: "OK",
            body: json_from_decoded(&d),
        },
        // ★ The device's own verdict is mapped to a status that means the same
        // thing, so a client is not told "server error" for a request the
        // device understood and declined.
        Err(ClientError::Status(2)) => Response::error(
            400,
            "Bad Request",
            if route.requires_rpcd_session {
                format!(
                    "ubus status 2: invalid argument. {}.{} declares an `ubus_rpc_session`, \
                     which this adapter does not hold — for apply/confirm/rollback that is \
                     the measured cause rather than a malformed argument.",
                    route.object, route.method
                )
            } else {
                "ubus status 2: invalid argument — the device rejected the arguments".to_owned()
            },
        ),
        Err(ClientError::Status(4)) => {
            Response::error(404, "Not Found", "ubus status 4: not found")
        }
        Err(ClientError::Status(6)) => {
            Response::error(403, "Forbidden", "ubus status 6: permission denied")
        }
        Err(ClientError::NoSuchObject(p)) => Response::error(
            404,
            "Not Found",
            format!("the device has no ubus object at {p:?}"),
        ),
        Err(e) => Response::error(502, "Bad Gateway", e.to_string()),
    }
}

/// Serve one connection and close it.
///
/// A fresh ubus connection per HTTP request. Deliberate: a ubus connection
/// carries a peer id and a sequence counter, so sharing one across concurrent
/// requests would interleave sequences and let one request read another's
/// reply — the stale-STATUS bug, reintroduced at a different layer.
///
/// # Errors
///
/// Only a failure to WRITE the response. Everything else — a malformed request,
/// an unreachable ubus, the device's own refusal — becomes a `Response` with a
/// status, because a caller waiting on HTTP deserves an answer rather than a
/// closed socket.
pub fn serve_one(mut stream: TcpStream, routes: &RouteTable, socket: &str) -> Result<(), String> {
    let peer = stream
        .try_clone()
        .map_err(|e| format!("cloning the stream: {e}"))?;

    let response = match read_request(peer) {
        Err(e) => Response::error(400, "Bad Request", e),
        Ok(req) => match Connection::connect_unix(socket) {
            Err(e) => Response::error(
                502,
                "Bad Gateway",
                format!("cannot reach ubus at {socket}: {e}"),
            ),
            Ok(mut conn) => handle(&req, routes, &mut conn),
        },
    };

    stream
        .write_all(response.render().as_bytes())
        .map_err(|e| format!("writing the response: {e}"))
}
