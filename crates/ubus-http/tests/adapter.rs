//! Adapter tests.
//!
//! The request-handling logic is exercised against a **scripted ubus stream**,
//! which is the payoff of `Connection` being generic over `Read + Write`: every
//! branch — including the ones a healthy device cannot produce — is reachable
//! with no device and no socket.
//!
//! One test at the end drives the same `handle()` against a REAL router through
//! an `ssh -L` relay, because a mock only proves we agree with our own reading
//! of the protocol.

use std::io::{Read, Write};
use ubus_facade::json::Json;
use ubus_http::bridge::{args_from_json, json_from_decoded};
use ubus_http::http::{Request, Response, handle, read_request};
use ubus_http::route::RouteTable;
use ubus_proto::client::{Connection, Decoded};

const FACADE: &str = include_str!("../../ubus-facade/tests/fixtures/ubus-facade.openapi.json");

/// The frames a full `Connection::call` exchange needs.
///
/// ★ `call()` is TWO requests — a LOOKUP to resolve the object id, then the
/// INVOKE — so a scripted stream must carry both, at seq 1 and seq 2. A first
/// cut of these tests supplied only one reply and every call-driven test failed;
/// the adapter was fine. Worth stating because the sequence numbers are the
/// whole reason `Connection` can tell its own reply from a stale one.
const HELLO: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x04,
];

/// A LOOKUP reply for `uci`, carrying OBJPATH + OBJID.
const LOOKUP_UCI: &[u8] = &[
    0x00, 0x02, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x14, 0x02, 0x00, 0x00, 0x08,
    0x75, 0x63, 0x69, 0x00, 0x03, 0x00, 0x00, 0x08, 0x57, 0x5a, 0x75, 0xe0,
];

const STATUS_OK_SEQ1: &[u8] = &[
    0x00, 0x01, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00,
];

const STATUS_OK_SEQ2: &[u8] = &[
    0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00,
];

/// An INVOKE reply carrying `{"value":"GL-MT6000"}`.
const DATA_VALUE_SEQ2: &[u8] = &[
    0x00, 0x02, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x20, 0x87, 0x00, 0x00, 0x1c,
    0x83, 0x00, 0x00, 0x16, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x47, 0x4c, 0x2d, 0x4d,
    0x54, 0x36, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00,
];

/// The LOOKUP half every call needs before its INVOKE.
const RESOLVED: &[&[u8]] = &[HELLO, LOOKUP_UCI, STATUS_OK_SEQ1];

/// A scripted stream that resolves `uci`, then replays `after` as the INVOKE.
fn resolved(after: &[&[u8]]) -> Scripted {
    let mut chunks: Vec<&[u8]> = RESOLVED.to_vec();
    chunks.extend_from_slice(after);
    Scripted::new(&chunks)
}

struct Scripted {
    to_read: Vec<u8>,
    pos: usize,
}

impl Scripted {
    fn new(chunks: &[&[u8]]) -> Self {
        Self {
            to_read: chunks.concat(),
            pos: 0,
        }
    }
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.to_read.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.to_read[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn table() -> RouteTable {
    let spec = ubus_facade::json::parse(FACADE).expect("the committed façade must parse");
    RouteTable::from_facade(&spec).expect("and must yield routes")
}

fn post(path: &str, body: &str) -> Request {
    Request {
        method: "POST".to_owned(),
        path: path.to_owned(),
        body: body.to_owned(),
    }
}

// ---- the route table ----

#[test]
fn the_table_serves_every_operation_the_facade_describes() {
    let t = table();
    assert_eq!(t.len(), 264, "one route per façade operation");
    let uci_set = t.get("/uci/set").expect("/uci/set is served");
    assert_eq!(uci_set.object, "uci");
    assert_eq!(uci_set.method, "set");
}

/// ★ The object comes from the SPEC, never from splitting the path.
///
/// A dotted object name is the case that proves it: `/cellular.cm/cm_get_status`
/// splits into three parts, not two, so any path-derivation scheme has to guess
/// where the boundary is. The table does not guess.
#[test]
fn a_dotted_object_name_resolves_from_the_spec_not_the_path() {
    let t = table();
    let r = t
        .get("/cellular.cm/cm_get_status")
        .expect("dotted objects are served");
    assert_eq!(r.object, "cellular.cm");
    assert_eq!(r.method, "cm_get_status");
}

#[test]
fn an_operation_without_x_ubus_object_is_refused_not_guessed() {
    let spec =
        ubus_facade::json::parse(r#"{"paths":{"/a/b":{"post":{"x-ubus-method":"b"}}}}"#).unwrap();
    let err = RouteTable::from_facade(&spec).expect_err("must refuse");
    assert!(err.contains("x-ubus-object"), "{err}");
    assert!(err.contains("will not guess"), "{err}");
}

#[test]
fn a_facade_describing_nothing_is_refused() {
    // A table that served nothing would look like a working adapter that 404s
    // every request.
    let spec = ubus_facade::json::parse(r#"{"paths":{}}"#).unwrap();
    assert!(RouteTable::from_facade(&spec).is_err());
}

// ---- request handling ----

#[test]
fn a_get_is_rejected_because_every_ubus_operation_is_a_post() {
    let mut c = Connection::new(Scripted::new(&[HELLO])).unwrap();
    let mut req = post("/uci/get", "{}");
    req.method = "GET".to_owned();
    let r = handle(&req, &table(), &mut c);
    assert_eq!(r.status, 405);
}

#[test]
fn an_unknown_path_is_a_404_that_says_why() {
    let mut c = Connection::new(Scripted::new(&[HELLO])).unwrap();
    let r = handle(&post("/uci/nonexistent", "{}"), &table(), &mut c);
    assert_eq!(r.status, 404);
    assert!(r.body.render().contains("only what the façade describes"));
}

/// ★ A session-declaring operation is ATTEMPTED, not pre-refused — and the
/// declaration becomes a hint on failure.
///
/// The first cut of `handle()` gated on `requires_rpcd_session` and returned 501
/// for EVERY request, `uci get` included, because all 28 uci methods declare the
/// parameter. Measured: only apply/confirm/rollback enforce it. Declaration is
/// not enforcement, so the device decides.
#[test]
fn a_session_declaring_operation_is_attempted_and_its_failure_explains_why() {
    // The device answers status 2, which is what a missing session looks like.
    let mut status = STATUS_OK_SEQ2.to_vec();
    status[16..20].copy_from_slice(&2u32.to_be_bytes());
    let mut c = Connection::new(resolved(&[&status])).unwrap();
    let r = handle(&post("/uci/apply", "{}"), &table(), &mut c);

    assert_eq!(r.status, 400, "the device's verdict, not a pre-refusal");
    let body = r.body.render();
    assert!(
        body.contains("ubus_rpc_session"),
        "the hint must be there: {body}"
    );
    assert!(
        body.contains("measured cause"),
        "and must say it is the measured cause for apply/confirm/rollback: {body}"
    );
}

/// The complement: an operation that declares a session but SUCCEEDS is not
/// obstructed. `uci set` declares one and works without it.
#[test]
fn a_session_declaring_operation_that_works_is_not_obstructed() {
    let mut c = Connection::new(resolved(&[STATUS_OK_SEQ2])).unwrap();
    let r = handle(
        &post("/uci/set", r#"{"config":"system"}"#),
        &table(),
        &mut c,
    );
    assert_eq!(
        r.status, 200,
        "uci.set declares a session and works without one — measured"
    );
}

#[test]
fn a_successful_call_returns_the_devices_value() {
    let mut c = Connection::new(resolved(&[DATA_VALUE_SEQ2, STATUS_OK_SEQ2])).unwrap();
    let r = handle(
        &post("/uci/get", r#"{"config":"system"}"#),
        &table(),
        &mut c,
    );
    assert_eq!(r.status, 200);
    assert!(r.body.render().contains("GL-MT6000"));
}

/// `uci set` answers with a STATUS and no payload. That is success with nothing
/// to report — reported as such, not as `null` and not as an error.
#[test]
fn a_call_with_no_return_value_is_an_explicit_ok() {
    let mut c = Connection::new(resolved(&[STATUS_OK_SEQ2])).unwrap();
    let r = handle(
        &post("/uci/set", r#"{"config":"system"}"#),
        &table(),
        &mut c,
    );
    assert_eq!(r.status, 200);
    assert!(r.body.render().contains("\"ok\": true"));
}

/// ★ The device's verdict maps to a status that means the same thing.
///
/// A rejected argument must not surface as 500: the device understood the
/// request and declined it, and telling the caller "server error" sends them to
/// the wrong place.
#[test]
fn ubus_status_codes_map_to_matching_http_statuses() {
    for (ubus_code, want_http) in [(2u32, 400u16), (4, 404), (6, 403)] {
        let mut status = STATUS_OK_SEQ2.to_vec();
        status[16..20].copy_from_slice(&ubus_code.to_be_bytes());
        let mut c = Connection::new(resolved(&[&status])).unwrap();
        let r = handle(&post("/uci/get", "{}"), &table(), &mut c);
        assert_eq!(
            r.status, want_http,
            "ubus status {ubus_code} should be HTTP {want_http}, got {}",
            r.status
        );
    }
}

#[test]
fn a_malformed_body_is_a_400_naming_the_offset() {
    let mut c = Connection::new(Scripted::new(&[HELLO])).unwrap();
    let r = handle(&post("/uci/get", "{not json"), &table(), &mut c);
    assert_eq!(r.status, 400);
    assert!(r.body.render().contains("invalid JSON at byte"));
}

#[test]
fn an_empty_body_is_an_empty_argument_set_not_an_error() {
    // `reload_config` and friends take no arguments, and a client that sends no
    // body is making a legitimate call.
    let mut c = Connection::new(resolved(&[STATUS_OK_SEQ2])).unwrap();
    let r = handle(&post("/uci/reload_config", ""), &table(), &mut c);
    assert_eq!(r.status, 200);
}

// ---- the bridge ----

/// ★ A JSON type with no MEASURED ubus counterpart is refused, not coerced.
#[test]
fn unmeasured_json_types_are_refused_with_their_reason() {
    let bool_err = args_from_json(&ubus_facade::json::parse(r#"{"x":true}"#).unwrap())
        .expect_err("boolean must be refused");
    assert!(bool_err.contains("has not measured"), "{bool_err}");

    let null_err = args_from_json(&ubus_facade::json::parse(r#"{"x":null}"#).unwrap())
        .expect_err("null must be refused");
    assert!(null_err.contains("no null"), "{null_err}");

    let big_err = args_from_json(&ubus_facade::json::parse(r#"{"x":99999999999}"#).unwrap())
        .expect_err("an out-of-range integer must be refused");
    assert!(big_err.contains("INT32"), "{big_err}");
}

#[test]
fn a_non_object_body_is_refused() {
    let err = args_from_json(&ubus_facade::json::parse("[1,2]").unwrap()).expect_err("must refuse");
    assert!(err.contains("must be a JSON object"), "{err}");
}

#[test]
fn nested_tables_and_arrays_survive_the_bridge() {
    let body =
        ubus_facade::json::parse(r#"{"values":{"hostname":"plo"},"options":["a","b"]}"#).unwrap();
    let args = args_from_json(&body).expect("measured types pass through");
    assert_eq!(args.len(), 2);
}

/// An unmeasured type the DEVICE sends must stay visible.
#[test]
fn an_unmeasured_reply_type_is_surfaced_rather_than_dropped() {
    let j = json_from_decoded(&Decoded::Unknown {
        type_code: 9,
        bytes: vec![1, 2, 3],
    });
    let s = j.render();
    assert!(s.contains("$ubusUnmeasuredType"), "{s}");
    assert!(s.contains('9'), "{s}");
}

// ---- the HTTP layer ----

#[test]
fn a_request_with_a_body_is_read_whole() {
    let raw = "POST /uci/get HTTP/1.1\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
    let req = read_request(raw.as_bytes()).expect("parses");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/uci/get");
    assert_eq!(req.body, "{\"a\":1}");
}

/// ★ A body cap, because this is a server and an unbounded read is a hang.
#[test]
fn an_oversized_content_length_is_refused_before_reading_it() {
    let raw = "POST /x HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n";
    let err = read_request(raw.as_bytes()).expect_err("must refuse");
    assert!(err.contains("exceeds"), "{err}");
}

#[test]
fn a_response_renders_a_well_formed_http_message() {
    let r = Response {
        status: 200,
        reason: "OK",
        body: Json::obj([("ok", Json::Bool(true))]),
    };
    let s = r.render();
    assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(s.contains("Content-Type: application/json\r\n"));
    // The declared length must match the body actually sent, or a client hangs
    // waiting for bytes that never come.
    let body = s.split("\r\n\r\n").nth(1).expect("a body");
    let declared: usize = s
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|v| v.trim().parse().ok())
        .expect("a Content-Length");
    assert_eq!(declared, body.len(), "Content-Length must match the body");
}

// ---- live ----

/// The same `handle()`, against a real router through an `ssh -L` relay.
///
/// Uses the TCP relay rather than `connect_unix` because the ubus socket is
/// local to the device; on the device itself the adapter needs no relay. See
/// `docs/roteador.md` §16.
#[test]
#[ignore = "needs a real ubus server reachable over a relay; see docs/roteador.md §16"]
fn the_adapter_answers_a_real_device() {
    let Ok(addr) = std::env::var("UBUS_TEST_TCP") else {
        eprintln!("UBUS_TEST_TCP unset — skipping");
        return;
    };
    let s = std::net::TcpStream::connect(&addr).expect("the relay must be reachable");
    let mut conn = Connection::new(s).expect("ubus must greet us");

    let r = handle(
        &post(
            "/uci/get",
            r#"{"config":"system","section":"@system[0]","option":"hostname"}"#,
        ),
        &table(),
        &mut conn,
    );
    assert_eq!(r.status, 200, "body: {}", r.body.render());
    let body = r.body.render();
    eprintln!("  POST /uci/get -> {} {}", r.status, body.trim());
    assert!(
        body.contains("value"),
        "the device's reply must reach the HTTP layer: {body}"
    );
}
