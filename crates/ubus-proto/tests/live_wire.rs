//! End-to-end encoder validation against a real ubus server.
//!
//! `#[ignore]` by default: this needs a device.
//!
//! # What this proves that byte-parity cannot
//!
//! `tests/encode.rs` reproduces the captured INVOKE byte-for-byte, which is
//! strong evidence — but that capture's DATA attribute was **empty**
//! (`87 00 00 04`), so it says nothing about **named blobmsg arguments**. Named
//! args are exactly what `uci get`/`set` need, and their encoding has three
//! independently-wrong-able details: a `namelen` that excludes the NUL, padding
//! of the name field before the value begins, and the type code in the
//! attribute id. A server that dislikes any of them answers `Invalid argument`
//! and names no field.
//!
//! So this drives a real exchange and asserts on a value only the device knows.
//!
//! # How to run it
//!
//! ubus listens on a unix socket, local to the device. Reaching it from a
//! workstation needs a loopback-bound relay on the device plus an `ssh -L`
//! forward — see `docs/roteador.md` §16. Never bind such a relay to a LAN
//! interface: ubus has no authentication, so that would publish
//! root-equivalent control of the device to the whole segment.
//!
//! ```sh
//! ssh root@192.168.8.1 'lua /tmp/ubus-relay.lua 21112' &
//! ssh -L 21112:127.0.0.1:21112 -N root@192.168.8.1 &
//! UBUS_TEST_TCP=127.0.0.1:21112 cargo test --test live_wire -- --ignored --nocapture
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use ubus_proto::encode::{Value, invoke_request, lookup_request};
use ubus_proto::{ATTR_HEADER_LEN, Attr, HEADER_LEN, Header, MessageType, attr_id};

/// Read exactly one message: the 8-byte header, then the single attribute whose
/// declared length the header's payload begins with.
fn read_message(s: &mut TcpStream) -> (Header, Vec<u8>) {
    let mut head = [0u8; HEADER_LEN];
    s.read_exact(&mut head).expect("header");
    let hdr = Header::decode(&head).expect("decodable header");

    let mut attr_head = [0u8; ATTR_HEADER_LEN];
    s.read_exact(&mut attr_head).expect("attr header");
    let declared = (u32::from_be_bytes(attr_head) & 0x00ff_ffff) as usize;

    let mut body = attr_head.to_vec();
    body.resize(declared, 0);
    s.read_exact(&mut body[ATTR_HEADER_LEN..])
        .expect("attr body");
    (hdr, body)
}

/// Drive one request to completion.
///
/// ★ A request is answered by zero or more DATA messages then exactly ONE
/// STATUS. Reading one message and stopping leaves the STATUS queued, and the
/// *next* request reads it as its own reply — reporting success for a call whose
/// result it never saw. That bug was made once already while capturing INVOKE;
/// this drains to the STATUS every time.
fn request(s: &mut TcpStream, bytes: &[u8], seq: u16) -> (Vec<Vec<u8>>, u32) {
    s.write_all(bytes).expect("send");
    let mut data = Vec::new();
    loop {
        let (hdr, body) = read_message(s);
        assert_eq!(hdr.seq, seq, "a reply for a sequence we did not send");
        match hdr.message_type {
            MessageType::Data => data.push(body),
            MessageType::Status => {
                let st = Attr::decode(&body)
                    .unwrap()
                    .children()
                    .next()
                    .expect("STATUS carries a code")
                    .as_u32()
                    .unwrap();
                return (data, st);
            }
            other => panic!("unexpected {other:?} in a reply stream"),
        }
    }
}

#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn our_encoder_drives_a_real_ubus_exchange() {
    let Ok(addr) = std::env::var("UBUS_TEST_TCP") else {
        eprintln!("UBUS_TEST_TCP unset — skipping");
        return;
    };
    let mut s = TcpStream::connect(&addr).expect("relay must be reachable");
    s.set_nodelay(true).ok();

    // 1. The server greets us unprompted and the greeting carries our peer id.
    //    Requests must echo it, so it cannot be invented.
    let (hello, _) = read_message(&mut s);
    assert_eq!(hello.message_type, MessageType::Hello);
    let peer = hello.peer;
    eprintln!("  HELLO: peer {peer:#010x}");

    // 2. LOOKUP the uci object to learn its id. Ids are not stable across
    //    reboots, so they are resolved rather than remembered.
    let (data, status) = request(&mut s, &lookup_request(1, peer, "uci"), 1);
    assert_eq!(status, 0, "LOOKUP must succeed");
    assert!(!data.is_empty(), "LOOKUP must return the object");

    let table = Attr::decode(&data[0]).unwrap();
    let mut obj_id = None;
    let mut obj_path = None;
    for a in table.children() {
        match a.id {
            attr_id::OBJID => obj_id = a.as_u32().ok(),
            attr_id::OBJPATH => obj_path = a.as_str().ok().map(str::to_owned),
            _ => {}
        }
    }
    let obj_id = obj_id.expect("LOOKUP reply carries an OBJID");
    assert_eq!(obj_path.as_deref(), Some("uci"));
    eprintln!("  LOOKUP: uci = {obj_id:#010x}");

    // 3. INVOKE uci.get with NAMED arguments — the part byte-parity cannot
    //    vouch for. The value asserted is one only the device knows.
    let args = vec![
        ("config".to_owned(), Value::str("system")),
        ("section".to_owned(), Value::str("@system[0]")),
        ("option".to_owned(), Value::str("hostname")),
    ];
    let (data, status) = request(&mut s, &invoke_request(2, peer, obj_id, "get", &args), 2);
    assert_eq!(
        status, 0,
        "uci.get must succeed; a nonzero status here means the server rejected \
         our argument encoding"
    );
    assert!(!data.is_empty(), "uci.get must return a value");

    // ★ The reply's named values are nested one level deeper than a first
    // reading suggests. `data[0]` is the message envelope; its children are
    // RAW attributes (id-addressed), and the blobmsg name/value pairs live
    // inside the DATA one. Iterating the envelope's children directly finds no
    // names at all — which presents as "the device returned nothing" rather
    // than as a parse error, because `as_named` correctly returns `None` for a
    // raw attribute instead of inventing a name.
    let envelope = Attr::decode(&data[0]).unwrap();
    let payload = envelope
        .children()
        .find(|a| a.id == attr_id::DATA)
        .expect("a uci.get reply carries a DATA attribute");

    let mut hostname = None;
    for a in payload.children() {
        if let Ok(Some((name, v))) = a.as_named()
            && name == "value"
        {
            hostname = std::str::from_utf8(v)
                .ok()
                .map(|s| s.trim_end_matches('\0').to_owned());
        }
    }
    let hostname = hostname.expect("uci.get returns a `value`");
    eprintln!("  INVOKE uci.get system.@system[0].hostname = {hostname:?}");
    assert!(
        !hostname.is_empty(),
        "the device returned an empty hostname, which means the argument \
         encoding reached the server but addressed nothing"
    );
}
