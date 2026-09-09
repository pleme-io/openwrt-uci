//! Framing tests for [`Connection`], driven by a scripted stream.
//!
//! No device and no socket. `Connection` is generic over `Read + Write`
//! precisely so the framing rules — and especially their FAILURE paths — can be
//! exercised deterministically. Several of these cannot be provoked against a
//! real server at all: a well-behaved ubus never sends a stale sequence number,
//! so the guard against one is only testable here.
//!
//! The golden byte sequences below were computed from the format in
//! `PROTOCOL.md` and cross-check against the capture: the STATUS is 20 bytes and
//! the HELLO is 12, matching the real ones in `tests/decode.rs` and
//! `PROTOCOL.md` respectively.

use std::io::{Read, Write};
use ubus_proto::client::{ClientError, Connection, Decoded};

const PEER: u32 = 0xaabb_ccdd;

/// HELLO, as the server sends it unprompted on connect.
const HELLO: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x04,
];

/// STATUS seq 1, code 0 (success).
const STATUS_OK: &[u8] = &[
    0x00, 0x01, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00,
];

/// DATA seq 1 carrying `{"value": "GL-MT6000"}`.
const DATA_VALUE: &[u8] = &[
    0x00, 0x02, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x20, 0x87, 0x00, 0x00, 0x1c,
    0x83, 0x00, 0x00, 0x16, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x47, 0x4c, 0x2d, 0x4d,
    0x54, 0x36, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00,
];

/// Replace a message's type byte, to synthesize a variant of a known-good frame.
fn retype(msg: &[u8], ty: u8) -> Vec<u8> {
    let mut v = msg.to_vec();
    v[1] = ty;
    v
}

/// Rewrite a message's sequence number.
fn reseq(msg: &[u8], seq: u16) -> Vec<u8> {
    let mut v = msg.to_vec();
    v[2..4].copy_from_slice(&seq.to_be_bytes());
    v
}

/// A stream that replays scripted bytes and records what was written.
struct Scripted {
    to_read: Vec<u8>,
    pos: usize,
    pub written: Vec<u8>,
}

impl Scripted {
    fn new(chunks: &[&[u8]]) -> Self {
        Self {
            to_read: chunks.concat(),
            pos: 0,
            written: Vec::new(),
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
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_handshake_takes_our_peer_id_from_the_hello() {
    let c = Connection::new(Scripted::new(&[HELLO])).expect("HELLO completes the handshake");
    assert_eq!(c.peer(), PEER);
}

/// A `Connection` must not exist without a HELLO: its peer id comes from there,
/// and a request that echoes the wrong peer is not a valid request.
#[test]
fn a_first_message_that_is_not_a_hello_is_refused() {
    let err = Connection::new(Scripted::new(&[STATUS_OK])).expect_err("must refuse");
    assert!(
        matches!(err, ClientError::Malformed(ref m) if m.contains("expected HELLO")),
        "{err}"
    );
}

#[test]
fn a_call_returning_a_value_decodes_it() {
    let s = Scripted::new(&[HELLO, DATA_VALUE, STATUS_OK]);
    let mut c = Connection::new(s).unwrap();
    let got = c.invoke(0x1234, "get", &[]).unwrap().expect("a value");
    assert_eq!(
        got.get("value").and_then(Decoded::as_str),
        Some("GL-MT6000")
    );
}

/// `uci set` and `uci commit` answer with a STATUS and no DATA. That is success
/// with nothing to report — `None` — and must not be conflated with an empty
/// table, which would be a value that happened to contain nothing.
#[test]
fn a_method_with_no_return_value_is_none_not_an_empty_table() {
    let s = Scripted::new(&[HELLO, STATUS_OK]);
    let mut c = Connection::new(s).unwrap();
    assert_eq!(c.invoke(0x1234, "set", &[]).unwrap(), None);
}

#[test]
fn a_nonzero_status_is_the_servers_verdict_and_is_reported_as_one() {
    // status 2 = Invalid argument, which is what a rejected argument encoding
    // looks like. It must not arrive as "no data".
    let mut bad = STATUS_OK.to_vec();
    bad[16..20].copy_from_slice(&2u32.to_be_bytes());
    let mut c = Connection::new(Scripted::new(&[HELLO, &bad])).unwrap();
    let err = c
        .invoke(1, "set", &[])
        .expect_err("must surface the status");
    assert!(matches!(err, ClientError::Status(2)), "{err}");
    assert!(
        err.to_string().contains("invalid argument"),
        "the message should say what 2 means: {err}"
    );
}

/// ★ THE test this module exists for.
///
/// A client that reads one message and stops leaves the trailing STATUS queued,
/// and the next request reads it as its own reply — reporting success for a call
/// whose result it never saw. This project made exactly that bug once. The two
/// frames are byte-identical except for `seq`, so `seq` is the only thing that
/// can catch it.
#[test]
fn a_stale_status_from_a_previous_request_is_caught_by_seq() {
    // A STATUS for seq 0 arriving while we await seq 1.
    let stale = reseq(STATUS_OK, 0);
    let mut c = Connection::new(Scripted::new(&[HELLO, &stale])).unwrap();
    let err = c
        .invoke(1, "get", &[])
        .expect_err("a stale reply must not pass");
    assert!(
        matches!(err, ClientError::Malformed(ref m) if m.contains("stale")),
        "{err}"
    );
}

/// Every request drains to its STATUS, so a second call starts clean. If
/// draining were missing, the second call would read the first's STATUS and this
/// would fail on a sequence mismatch.
#[test]
fn two_sequential_calls_do_not_read_each_others_replies() {
    let d2 = reseq(DATA_VALUE, 2);
    let s2 = reseq(STATUS_OK, 2);
    let mut c = Connection::new(Scripted::new(&[HELLO, DATA_VALUE, STATUS_OK, &d2, &s2])).unwrap();

    let first = c.invoke(1, "get", &[]).unwrap().expect("value");
    let second = c.invoke(1, "get", &[]).unwrap().expect("value");
    assert_eq!(first, second, "both calls see their own reply");
}

/// A DATA message whose sequence is right but whose type is not one the reply
/// grammar allows must be reported, not skipped.
#[test]
fn an_unexpected_message_type_in_a_reply_stream_is_refused() {
    let lookup_shaped = retype(DATA_VALUE, 4); // LOOKUP arriving as a reply
    let mut c = Connection::new(Scripted::new(&[HELLO, &lookup_shaped])).unwrap();
    let err = c.invoke(1, "get", &[]).expect_err("must refuse");
    assert!(
        matches!(err, ClientError::Malformed(ref m) if m.contains("unexpected")),
        "{err}"
    );
}

/// ★ An unmeasured blobmsg type must be VISIBLE, not dropped.
///
/// Silently skipping an unrecognised field would report absence for something
/// that was present — the `kotae` failure of rendering `empty` and
/// `unrecognised` as the same answer.
///
/// This is not hypothetical: it is how ARRAY got measured. `uci changes` came
/// back as `Unknown { type_code: 1, bytes: [] }`, which named the type AND
/// preserved the bytes, so a populated one could then be characterised from a
/// real device. Type 1 is consequently measured now, and this test uses **4**,
/// which is not.
#[test]
fn an_unmeasured_blobmsg_type_is_surfaced_as_unknown() {
    // Same frame, inner attribute's type code changed 3 (STRING) -> 4.
    let mut framed = DATA_VALUE.to_vec();
    framed[16] = 0x84;
    let mut c = Connection::new(Scripted::new(&[HELLO, &framed, STATUS_OK])).unwrap();
    let got = c.invoke(1, "get", &[]).unwrap().expect("a value");

    match got.get("value") {
        Some(Decoded::Unknown { type_code, bytes }) => {
            assert_eq!(*type_code, 4);
            assert!(!bytes.is_empty(), "the bytes must be preserved");
        }
        other => panic!("an unmeasured type must not be dropped or guessed: {other:?}"),
    }
}

#[test]
fn a_truncated_stream_is_an_error_not_a_partial_value() {
    // The HELLO, then a header with no body behind it.
    let mut c = Connection::new(Scripted::new(&[HELLO])).unwrap();
    let err = c
        .invoke(1, "get", &[])
        .expect_err("must not invent a reply");
    assert!(matches!(err, ClientError::Io(_)), "{err}");
}

#[test]
fn a_lookup_reports_no_object_rather_than_guessing() {
    // LOOKUP answers with only a STATUS when nothing matches, so `call` must say
    // so rather than proceed against an invented id.
    let mut c = Connection::new(Scripted::new(&[HELLO, STATUS_OK])).unwrap();
    let err = c.call("nope", "get", &[]).expect_err("must refuse");
    assert!(
        matches!(err, ClientError::NoSuchObject(ref p) if p == "nope"),
        "{err}"
    );
}

#[test]
fn the_request_actually_reaches_the_stream() {
    // Guards the degenerate case of a client that decodes a scripted reply
    // without ever having sent anything.
    let s = Scripted::new(&[HELLO, DATA_VALUE, STATUS_OK]);
    let mut c = Connection::new(s).unwrap();
    c.invoke(0x7654_3210, "board", &[]).unwrap();
    // Not asserting exact bytes here — tests/encode.rs owns byte-parity. Only
    // that a request was written, and that it carries our peer and the method.
    let w = &c.into_inner().written;
    assert!(!w.is_empty(), "no request was sent");
    assert!(
        w.windows(4).any(|s| s == PEER.to_be_bytes()),
        "the request must echo the peer id from the HELLO"
    );
    assert!(
        w.windows(5).any(|s| s == b"board"),
        "the method name must be on the wire"
    );
}
