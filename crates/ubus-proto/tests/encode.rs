//! Encoder tests, anchored to bytes a real ubus server accepted.
//!
//! # Why byte-parity and not a round-trip
//!
//! Encoding and decoding through our own code proves the two halves agree with
//! each other — which they would even if both were wrong in the same way, and
//! they were written by the same author from the same reading of the same
//! capture. So the load-bearing test here reproduces the exact 36 bytes the
//! device was sent and **answered**. If those bytes match, the encoder is right
//! about the one thing that cannot be argued with.
//!
//! Round-trip tests are kept as well, but as a cheap consistency net rather
//! than as evidence of wire correctness.

use ubus_proto::encode::{Value, blobmsg_type, invoke_request, lookup_request};
use ubus_proto::{Attr, HEADER_LEN, Header, MessageType};

/// The exact INVOKE that reached the device and was answered, from
/// `tests/decode.rs`. Reproduced here as the encoder's target.
const CAPTURED_INVOKE: [u8; 36] = [
    0x00, 0x05, 0x00, 0x02, 0xd3, 0x99, 0x9b, 0xf9, // INVOKE, seq 2
    0x00, 0x00, 0x00, 0x1c, // table, len 28
    0x03, 0x00, 0x00, 0x08, 0x76, 0xa7, 0x57, 0x0c, // OBJID
    0x04, 0x00, 0x00, 0x0a, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x00, 0x00, 0x00, // METHOD "board"
    0x87, 0x00, 0x00, 0x04, // DATA, extended, empty
];

/// ★ THE load-bearing encoder test.
#[test]
fn reproduces_the_invoke_the_device_accepted_byte_for_byte() {
    let built = invoke_request(2, 0xd399_9bf9, 0x76a7_570c, "board", &[]);
    assert_eq!(
        built, CAPTURED_INVOKE,
        "\n built: {built:02x?}\ncaptured: {CAPTURED_INVOKE:02x?}"
    );
}

/// The failure this pins is silent on the wire: a `Vec` that happens to be the
/// right length but wrong at one offset produces `Invalid argument` from the
/// server with no indication of which field was malformed. So diverge
/// deliberately and confirm the comparison above can actually fail.
#[test]
fn a_wrong_method_name_does_not_match_the_capture() {
    let built = invoke_request(2, 0xd399_9bf9, 0x76a7_570c, "boarD", &[]);
    assert_ne!(built, CAPTURED_INVOKE);
}

#[test]
fn the_empty_data_attr_is_emitted_not_omitted() {
    // `87 00 00 04` — extended, id 7 (DATA), length 4, no payload. It marks the
    // argument block as blobmsg. A message without it is a different message,
    // and the capture proves the device wants it.
    let built = invoke_request(2, 0xd399_9bf9, 0x76a7_570c, "board", &[]);
    assert_eq!(&built[32..36], &[0x87, 0x00, 0x00, 0x04]);
}

#[test]
fn an_encoded_invoke_decodes_with_our_own_decoder() {
    let built = invoke_request(7, 0x1234_5678, 0xdead_beef, "get", &[]);
    let hdr = Header::decode(&built).unwrap();
    assert_eq!(hdr.message_type, MessageType::Invoke);
    assert_eq!(hdr.seq, 7);
    assert_eq!(hdr.peer, 0x1234_5678);

    let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
    let args: Vec<Attr> = table.children().collect();
    assert_eq!(args.len(), 3);
    assert_eq!(args[0].as_u32().unwrap(), 0xdead_beef);
    assert_eq!(args[1].as_str().unwrap(), "get");
}

#[test]
fn a_lookup_request_decodes_and_carries_its_path() {
    let built = lookup_request(1, 0x0000_0001, "uci");
    let hdr = Header::decode(&built).unwrap();
    assert_eq!(hdr.message_type, MessageType::Lookup);

    let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
    let args: Vec<Attr> = table.children().collect();
    assert_eq!(args.len(), 1);
    assert_eq!(args[0].id, ubus_proto::attr_id::OBJPATH);
    assert_eq!(args[0].as_str().unwrap(), "uci");
}

/// Named arguments are what `uci set` needs, and the capture's DATA attr is
/// empty — so this is the part byte-parity cannot vouch for. It is asserted
/// against the decoder's `as_named`, which WAS derived from real named bytes
/// (the signature table in the LOOKUP response), and then against the device
/// itself in `openwrt-uci-transport`'s live suite.
#[test]
fn named_string_arguments_round_trip_through_as_named() {
    let args = vec![
        ("config".to_owned(), Value::str("system")),
        ("section".to_owned(), Value::str("@system[0]")),
    ];
    let built = invoke_request(3, 0x1111_1111, 0x2222_2222, "get", &args);

    let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
    let data = table.children().nth(2).expect("DATA is the third attr");
    assert!(data.extended);

    let named: Vec<(String, String)> = data
        .children()
        .map(|a| {
            let (n, v) = a.as_named().unwrap().expect("blobmsg attrs are named");
            // A string value carries its NUL; strip it for comparison.
            let s = std::str::from_utf8(v).unwrap().trim_end_matches('\0');
            (n.to_owned(), s.to_owned())
        })
        .collect();

    assert_eq!(
        named,
        vec![
            ("config".to_owned(), "system".to_owned()),
            ("section".to_owned(), "@system[0]".to_owned()),
        ]
    );
}

/// A nested table is how `uci set` carries `values`.
#[test]
fn a_nested_table_argument_round_trips() {
    let args = vec![(
        "values".to_owned(),
        Value::table([("hostname", Value::str("plo"))]),
    )];
    let built = invoke_request(4, 1, 2, "set", &args);

    let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
    let data = table.children().nth(2).unwrap();
    let outer = data.children().next().unwrap();
    let (name, _) = outer.as_named().unwrap().unwrap();
    assert_eq!(name, "values");
    assert_eq!(outer.id, blobmsg_type::TABLE, "measured: TABLE is 2");
}

/// ★ `namelen` excludes the NUL, and the name field is padded before the value
/// begins. Both are easy to get wrong in a way that shifts every subsequent
/// byte, and a name whose length crosses a 4-byte boundary is where it shows.
#[test]
fn name_padding_is_correct_at_every_length_boundary() {
    for name in ["a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"] {
        let args = vec![(name.to_owned(), Value::str("v"))];
        let built = invoke_request(1, 1, 1, "m", &args);
        let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
        let data = table.children().nth(2).unwrap();
        let attr = data.children().next().unwrap();
        let (got_name, got_val) = attr.as_named().unwrap().unwrap();
        assert_eq!(got_name, name, "name mangled at len {}", name.len());
        assert_eq!(
            std::str::from_utf8(got_val).unwrap().trim_end_matches('\0'),
            "v",
            "value displaced at name len {}",
            name.len()
        );
    }
}

#[test]
fn an_int32_argument_uses_the_measured_type_code() {
    let args = vec![("timeout".to_owned(), Value::I32(30))];
    let built = invoke_request(1, 1, 1, "apply", &args);
    let table = Attr::decode(&built[HEADER_LEN..]).unwrap();
    let data = table.children().nth(2).unwrap();
    let attr = data.children().next().unwrap();
    assert_eq!(attr.id, blobmsg_type::INT32, "measured: INT32 is 5");
    let (_, v) = attr.as_named().unwrap().unwrap();
    assert_eq!(v, &30i32.to_be_bytes());
}
