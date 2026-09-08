//! Decode the bytes captured off a live device.
//!
//! These are not synthetic vectors. Every byte here came off a GL.iNet
//! GL-MT6000's ubus socket on 2026-09-05 (see `PROTOCOL.md`). The point is that
//! the decoder is checked against what a router actually emits, not against
//! what this crate's author believed it emits — the two were not assumed to be
//! the same thing.

use ubus_proto::{Attr, AttrIter, HEADER_LEN, Header, MessageType, ProtoError, pad4};

/// Strip comments and whitespace from the captured hex fixture.
fn fixture() -> Vec<u8> {
    include_str!("fixtures/lookup-response.hex")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|b| u8::from_str_radix(b, 16).expect("fixture must be hex"))
        .collect()
}

fn hello() -> Vec<u8> {
    fixture()[..12].to_vec()
}

fn lookup_reply() -> Vec<u8> {
    fixture()[12..].to_vec()
}

#[test]
fn the_fixture_is_the_size_we_captured() {
    // 12-byte HELLO plus the COMPLETE 656-byte LOOKUP reply.
    assert_eq!(fixture().len(), 668);
    assert_eq!(lookup_reply().len(), 656);
}

#[test]
fn decodes_the_servers_hello() {
    let h = hello();
    let hdr = Header::decode(&h).unwrap();
    assert_eq!(hdr.version, 0);
    assert_eq!(hdr.message_type, MessageType::Hello);
    assert_eq!(hdr.seq, 0);
    // The peer id the server assigned us, big-endian off the wire.
    assert_eq!(hdr.peer, 0xfb05_a0cd);

    // HELLO carries one empty attribute: len 4 means header only.
    let attr = Attr::decode(&h[HEADER_LEN..]).unwrap();
    assert_eq!(attr.total_len, 4);
    assert!(attr.payload.is_empty());
    assert!(!attr.extended);
}

#[test]
fn a_header_round_trips() {
    let h = hello();
    let hdr = Header::decode(&h).unwrap();
    assert_eq!(&hdr.encode()[..], &h[..HEADER_LEN]);
}

#[test]
fn decodes_the_lookup_reply_header() {
    let r = lookup_reply();
    let hdr = Header::decode(&r).unwrap();
    assert_eq!(hdr.message_type, MessageType::Data);
    assert_eq!(hdr.seq, 1, "must echo the seq we sent");
}

#[test]
fn the_top_level_attribute_is_a_table_of_the_declared_length() {
    let r = lookup_reply();
    let top = Attr::decode(&r[HEADER_LEN..]).unwrap();
    // 0x288 = 648. The message is 656 bytes: 8 header + 648 table.
    assert_eq!(top.total_len, 648);
    assert_eq!(top.id, 0, "top level is an unnamed table");
    assert!(!top.extended);
    assert_eq!(top.payload.len(), 644, "len includes its own 4-byte header");
}

#[test]
fn a_truncated_message_is_refused_rather_than_partially_decoded() {
    // ★ Worth keeping as its own test: the first version of this suite used a
    // 96-byte capture and asserted the top-level table decoded. It did not, and
    // the decoder was right — a table declaring 648 bytes inside an 88-byte
    // buffer must fail rather than hand back something that looks complete.
    // The fixture was then re-captured in full; this preserves the property.
    let r = lookup_reply();
    let short = &r[..96];
    assert!(matches!(
        Attr::decode(&short[HEADER_LEN..]),
        Err(ProtoError::Truncated { need: 648, .. })
    ));
}

#[test]
fn walks_the_object_attributes() {
    // The complete 656-byte message, so the whole object is walkable: its
    // path, id, type and full method signature.
    let r = lookup_reply();
    let top = Attr::decode(&r[HEADER_LEN..]).unwrap();
    let attrs: Vec<Attr> = top.children().collect();

    assert!(
        attrs.len() >= 3,
        "expected objpath/objid/objtype, got {}",
        attrs.len()
    );

    // id 2 = OBJPATH, the object's name.
    assert_eq!(attrs[0].id, 2);
    assert_eq!(attrs[0].total_len, 16, "12-byte string + 4-byte header");
    assert_eq!(attrs[0].as_str().unwrap(), "cellular.cm");

    // id 3 = OBJID, a u32.
    assert_eq!(attrs[1].id, 3);
    assert_eq!(attrs[1].as_u32().unwrap(), 0x4dc8_b34c);

    // id 5 = OBJTYPE, a u32.
    assert_eq!(attrs[2].id, 5);
    assert_eq!(attrs[2].as_u32().unwrap(), 0x40d3_587d);
}

#[test]
fn a_named_attribute_splits_into_name_and_value() {
    // The parameter `bus` of method `cm_get_status`, encoded as:
    //   85 00 00 10  00 03 "bus\0" pad  00 00 00 03
    // EXTENDED | id 5 (INT32) | len 16, name "bus", value 3 (= STRING).
    //
    // This is the subtlety worth pinning: the attr's id is the blobmsg TYPE of
    // the field, while the VALUE it carries is the type code of the parameter.
    let bytes = [
        0x85, 0x00, 0x00, 0x10, // EXTENDED | id 5 | len 16
        0x00, 0x03, // namelen 3 (strlen, excludes NUL)
        0x62, 0x75, 0x73, 0x00, // "bus\0"
        0x00, 0x00, // padding to 4-byte boundary
        0x00, 0x00, 0x00, 0x03, // value: 3 = BLOBMSG_TYPE_STRING
    ];
    let attr = Attr::decode(&bytes).unwrap();
    assert!(attr.extended);
    assert_eq!(attr.id, 5);

    let (name, value) = attr.as_named().unwrap().expect("extended attr has a name");
    assert_eq!(name, "bus");
    assert_eq!(value, &[0x00, 0x00, 0x00, 0x03]);
}

#[test]
fn a_raw_attribute_has_no_name() {
    // Guards against inventing a name for unnamed data, which would let a
    // caller treat a raw value as a named field.
    let r = lookup_reply();
    let top = Attr::decode(&r[HEADER_LEN..]).unwrap();
    let objpath = top.children().next().unwrap();
    assert!(!objpath.extended);
    assert_eq!(objpath.as_named().unwrap(), None);
}

// ---- refusal cases: the decoder must fail rather than fabricate ----

#[test]
fn a_truncated_header_is_an_error() {
    assert!(matches!(
        Header::decode(&[0, 2, 0]),
        Err(ProtoError::Truncated { need: 8, got: 3 })
    ));
}

#[test]
fn a_length_shorter_than_its_own_header_is_rejected() {
    // len = 2 is impossible: len INCLUDES the 4-byte header. Accepting it
    // would produce a zero-or-negative stride and walk the stream forever.
    let bytes = [0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(
        Attr::decode(&bytes),
        Err(ProtoError::BadLength { declared: 2 })
    ));
}

#[test]
fn a_length_beyond_the_buffer_is_truncation_not_a_short_read() {
    let bytes = [0x00, 0x00, 0x00, 0x40, 0x01, 0x02];
    assert!(matches!(
        Attr::decode(&bytes),
        Err(ProtoError::Truncated { need: 0x40, got: 6 })
    ));
}

#[test]
fn the_iterator_stops_rather_than_looping_on_malformed_input() {
    // A decoder that skipped bad attributes would hand back a partial view
    // that looks complete. It must stop.
    let bytes = [
        0x00, 0x00, 0x00, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, // one valid attr
        0x00, 0x00, 0x00, 0x01, // then an impossible length
    ];
    let got: Vec<Attr> = AttrIter::new(&bytes).collect();
    assert_eq!(got.len(), 1, "must yield the valid attr then stop");
}

#[test]
fn padding_is_excluded_from_len_but_included_in_stride() {
    // The single easiest way to misparse ubus: len counts the header but not
    // the padding, while the walk to the next attribute needs both.
    assert_eq!(pad4(4), 4);
    assert_eq!(pad4(5), 8);
    assert_eq!(pad4(16), 16);
    assert_eq!(pad4(17), 20);

    let r = lookup_reply();
    let top = Attr::decode(&r[HEADER_LEN..]).unwrap();
    let first = top.children().next().unwrap();
    assert_eq!(first.total_len, 16);
    assert_eq!(first.stride(), 16, "already aligned");
}

#[test]
fn unverified_message_types_keep_their_number() {
    // 0/1/2/4/5 are named because each was seen in a real exchange. Everything
    // else keeps its number rather than acquiring a name the crate has not
    // earned. This test moved once already: it asserted Other(5) until an
    // INVOKE was actually captured, at which point 5 became Invoke and the
    // assertion had to move with the evidence.
    for unverified in [3u8, 6, 7, 8, 9] {
        assert_eq!(
            MessageType::from_u8(unverified),
            MessageType::Other(unverified),
            "type {unverified} has not been observed on the wire"
        );
        assert_eq!(MessageType::from_u8(unverified).to_u8(), unverified);
    }
}

// ---- INVOKE: verified against a live `system.board` call ----

#[test]
fn invoke_and_status_are_named_now_that_they_are_verified() {
    // Both were Other(n) until an actual exchange was captured. Naming them
    // before that would have been claiming knowledge the crate had not earned.
    assert_eq!(MessageType::from_u8(5), MessageType::Invoke);
    assert_eq!(MessageType::from_u8(1), MessageType::Status);
    assert_eq!(MessageType::Invoke.to_u8(), 5);
    assert_eq!(MessageType::Status.to_u8(), 1);
}

#[test]
fn decodes_the_invoke_request_we_actually_sent() {
    // The exact 36 bytes that reached the device and were answered.
    let msg = [
        0x00, 0x05, 0x00, 0x02, 0xd3, 0x99, 0x9b, 0xf9, // INVOKE, seq 2
        0x00, 0x00, 0x00, 0x1c, // table, len 28
        0x03, 0x00, 0x00, 0x08, 0x76, 0xa7, 0x57, 0x0c, // OBJID
        0x04, 0x00, 0x00, 0x0a, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x00, 0x00,
        0x00, // METHOD "board"
        0x87, 0x00, 0x00, 0x04, // DATA, extended, empty
    ];
    let hdr = Header::decode(&msg).unwrap();
    assert_eq!(hdr.message_type, MessageType::Invoke);
    assert_eq!(hdr.seq, 2);

    let table = Attr::decode(&msg[HEADER_LEN..]).unwrap();
    let args: Vec<Attr> = table.children().collect();
    assert_eq!(args.len(), 3, "OBJID, METHOD, DATA");

    assert_eq!(args[0].id, ubus_proto::attr_id::OBJID);
    assert_eq!(args[0].as_u32().unwrap(), 0x76a7_570c);
    assert_eq!(args[1].id, ubus_proto::attr_id::METHOD);
    assert_eq!(args[1].as_str().unwrap(), "board");
    assert_eq!(args[2].id, ubus_proto::attr_id::DATA);
    assert!(args[2].extended, "args are a blobmsg table");
}

#[test]
fn a_status_message_carries_its_return_code() {
    // The 20-byte STATUS that ends a request. status 0 = success.
    let msg = [
        0x00, 0x01, 0x00, 0x01, 0xd3, 0x99, 0x9b, 0xf9, // STATUS, seq 1
        0x00, 0x00, 0x00, 0x0c, // table, len 12
        0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, // attr 1 = 0
    ];
    let hdr = Header::decode(&msg).unwrap();
    assert_eq!(hdr.message_type, MessageType::Status);

    let st = Attr::decode(&msg[HEADER_LEN..])
        .unwrap()
        .children()
        .next()
        .unwrap();
    assert_eq!(st.id, ubus_proto::ATTR_STATUS);
    assert_eq!(st.as_u32().unwrap(), 0, "0 is success");
}

#[test]
fn seq_is_what_distinguishes_a_stale_status_from_our_own() {
    // ★ The bug this pins, made while capturing INVOKE: reading one message and
    // stopping left the LOOKUP's trailing STATUS queued, and the next request
    // read it as its own reply -- reporting success for a call whose result it
    // never saw. The two are byte-identical except for seq.
    let ours = [0x00, 0x01, 0x00, 0x02, 0xd3, 0x99, 0x9b, 0xf9];
    let stale = [0x00, 0x01, 0x00, 0x01, 0xd3, 0x99, 0x9b, 0xf9];

    let a = Header::decode(&ours).unwrap();
    let b = Header::decode(&stale).unwrap();
    assert_eq!(a.message_type, b.message_type, "same type");
    assert_eq!(a.peer, b.peer, "same peer");
    assert_ne!(a.seq, b.seq, "ONLY seq separates them");
}
