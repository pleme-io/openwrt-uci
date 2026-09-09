//! Building ubus requests — the write path.
//!
//! The decoder in [`crate`] was derived from captured bytes. So is this. Every
//! constant here is read off the capture in `tests/fixtures/lookup-response.hex`
//! or off the 36-byte INVOKE the device accepted and answered, and the
//! byte-parity test in `tests/encode.rs` reproduces that INVOKE exactly.
//!
//! # Why an encoder is a separate concern from a decoder
//!
//! A decoder is forgiving by nature: it is handed bytes that already worked. An
//! encoder has to be right about the things a decoder never has to decide —
//! which padding is counted in a length and which is not, whether a name's
//! declared length includes its NUL, and where a value begins after a name. Each
//! of those is a place to be silently wrong: the device answers `Invalid
//! argument` and says nothing about which field was malformed.
//!
//! That is why this module is tested against a request that a real ubus server
//! **accepted**, rather than against a round-trip through our own decoder. A
//! round-trip proves the two halves agree with each other, which they would
//! even if both were wrong in the same way.

use crate::{ATTR_HEADER_LEN, EXTENDED_BIT, HEADER_LEN, ID_SHIFT_BITS, MessageType, pad4};

/// blobmsg type codes, as **measured** from the captured LOOKUP response.
///
/// Only the four seen on this wire are named. The rest of libubox's
/// enum is deliberately absent: naming a code this crate has never seen on the
/// wire would be exactly the recollection-over-measurement the project forbids.
///
/// The derivation, so the next reader can re-check it rather than trust it:
///
/// - `82 00 00 44` — extended, id 2, whose payload is the named parameter table
///   of the method `cm_get_status`. A table. ⇒ `TABLE = 2`.
/// - `85 00 00 10` — extended, id 5, payload
///   `00 03 "bus\0" <pad> 00 00 00 03`. The signature `ubus -v list` prints for
///   that parameter is `"bus":"String"`, so the four-byte value `3` is the type
///   code for a string, and the attribute carrying a four-byte integer is
///   itself id 5. ⇒ `STRING = 3`, `INT32 = 5`.
/// - `81 00 00 58` — extended, id 1, returned as the value of `uci changes`'s
///   `changes` key, containing one element which is itself an id-1 attribute
///   holding the four strings `set`, `cfg01e48a`, `<option>`, `<value>`. A list
///   of lists. ⇒ `ARRAY = 1`.
///
///   ★ And the element layout, measured from those same bytes: an array's
///   members are ordinary blobmsg attributes with **`namelen = 0`** — an empty
///   name and its NUL, padded to 4, then the value. So an array is positional
///   and a table is keyed, using one attribute encoding. An **empty** array has
///   a zero-length payload, which is why "no pending changes" arrives as the
///   key being present-and-empty rather than absent.
pub mod blobmsg_type {
    /// A positional list of unnamed attributes.
    pub const ARRAY: u8 = 1;
    /// A table of named attributes.
    pub const TABLE: u8 = 2;
    /// A NUL-terminated string.
    pub const STRING: u8 = 3;
    /// A big-endian 32-bit integer.
    pub const INT32: u8 = 5;
    /// One byte. **Measured 2026-09-09** off `uci.get`'s `.anonymous` field,
    /// which `Decoded::Unknown` surfaced as `type_code: 7, byteLength: 1` —
    /// exactly the characterise-don't-guess path that arm exists for.
    ///
    /// libubox aliases `BLOBMSG_TYPE_BOOL` to `INT8`, so a boolean on this wire
    /// IS an int8. That alias is why this is decoded as a number rather than a
    /// bool: the wire cannot tell them apart, and inventing a bool here would
    /// be an interpretation dressed as a measurement. Callers that know a field
    /// is boolean read `0`/`1`.
    pub const INT8: u8 = 7;
}

/// A blobmsg value, limited to the shapes this crate has measured.
///
/// `uci`'s whole argument surface — `config`, `section`, `option`, `type`,
/// `match`, `values`, `options` — is strings, tables of strings and lists of
/// strings, so these four cover it. An unmeasured type is a compile error
/// rather than a wire surprise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    I32(i32),
    Table(Vec<(String, Value)>),
    /// A positional list. Its members are encoded with an empty name, which is
    /// the layout measured off `uci changes` — see [`blobmsg_type::ARRAY`].
    Array(Vec<Value>),
}

impl Value {
    /// Convenience for the overwhelmingly common case.
    pub fn str(s: impl Into<String>) -> Self {
        Self::Str(s.into())
    }

    /// A table from pairs, so call sites read like the JSON they replace.
    pub fn table<K: Into<String>>(pairs: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Table(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    const fn type_code(&self) -> u8 {
        match self {
            Self::Str(_) => blobmsg_type::STRING,
            Self::I32(_) => blobmsg_type::INT32,
            Self::Table(_) => blobmsg_type::TABLE,
            Self::Array(_) => blobmsg_type::ARRAY,
        }
    }

    /// The value's payload, excluding its blobmsg name.
    fn payload(&self) -> Vec<u8> {
        match self {
            // ★ The NUL is part of the value and IS counted in the length.
            // Dropping it produces a string the server reads as running into
            // whatever follows.
            Self::Str(s) => {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            }
            Self::I32(i) => i.to_be_bytes().to_vec(),
            Self::Table(pairs) => {
                let mut v = Vec::new();
                for (name, val) in pairs {
                    push_named(&mut v, name, val);
                }
                v
            }
            // An array member is a named attribute whose name is EMPTY.
            Self::Array(items) => {
                let mut v = Vec::new();
                for item in items {
                    push_named(&mut v, "", item);
                }
                v
            }
        }
    }
}

/// Write one raw (unnamed) attribute: 4-byte header, payload, padding.
///
/// ★ The padding is written but **not** counted in the declared length. That
/// asymmetry is the single most error-prone fact in this format — the decoder's
/// `pad4` comment records the same trap from the reading side.
fn push_attr(out: &mut Vec<u8>, id: u8, extended: bool, payload: &[u8]) {
    let total_len = ATTR_HEADER_LEN + payload.len();

    // ★ The length field is 24 bits (`LEN_MASK`), so anything from 16 MiB up is
    // UNREPRESENTABLE on this wire. Casting and letting it wrap would emit a
    // structurally valid attribute with a small declared length followed by
    // megabytes the server reads as subsequent attributes — corruption that
    // decodes without erroring. No legitimate ubus call comes close (the
    // largest thing here is a whole `uci` config, measured at 55 KB), so this
    // is a programmer error and says so, rather than silently truncating.
    assert!(
        total_len <= crate::LEN_MASK_BITS as usize,
        "attribute of {total_len} bytes exceeds the 24-bit ubus length field"
    );
    let mut id_len = ((u32::from(id)) << ID_SHIFT_BITS)
        | u32::try_from(total_len).expect("bounded by the assert above");
    if extended {
        id_len |= EXTENDED_BIT;
    }
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len() + (pad4(total_len) - total_len), 0);
}

/// Write one blobmsg (named) attribute.
///
/// Layout, inverted directly from the decoder's `as_named`:
///
/// ```text
/// [u16 be namelen]  [name]  [NUL]  [pad to 4 from 2+namelen+1]  [value]
/// ```
///
/// ★ `namelen` is `strlen` — it **excludes** the NUL, which is nonetheless
/// present. And the name field is padded before the value begins, so the value
/// is not where `2 + namelen + 1` lands.
fn push_named(out: &mut Vec<u8>, name: &str, value: &Value) {
    let name_bytes = name.as_bytes();
    let namelen = name_bytes.len();

    let mut payload = Vec::new();
    payload.extend_from_slice(&(u16::try_from(namelen).unwrap_or(u16::MAX)).to_be_bytes());
    payload.extend_from_slice(name_bytes);
    payload.push(0);
    payload.resize(pad4(2 + namelen + 1), 0);
    payload.extend_from_slice(&value.payload());

    push_attr(out, value.type_code(), true, &payload);
}

/// The 8-byte message header.
#[must_use]
pub fn header(message_type: MessageType, seq: u16, peer: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = 0; // version
    h[1] = message_type.to_u8();
    h[2..4].copy_from_slice(&seq.to_be_bytes());
    h[4..8].copy_from_slice(&peer.to_be_bytes());
    h
}

/// Wrap a set of attributes in the top-level table every message carries.
///
/// The table is id 0 and **not** extended — measured: the captured INVOKE's
/// envelope is `00 00 00 1c`, and its declared 28 bytes are 4 of header plus
/// the 24 its three padded children occupy.
fn envelope(attrs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTR_HEADER_LEN + attrs.len());
    push_attr(&mut out, 0, false, attrs);
    out
}

/// A LOOKUP request: "tell me the object id and signature for this path".
///
/// Path may be a concrete object (`"uci"`) — the reply is one DATA message per
/// matching object, then a STATUS.
#[must_use]
pub fn lookup_request(seq: u16, peer: u32, path: &str) -> Vec<u8> {
    let mut attrs = Vec::new();
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    push_attr(&mut attrs, crate::attr_id::OBJPATH, false, &p);

    let mut msg = header(MessageType::Lookup, seq, peer).to_vec();
    msg.extend_from_slice(&envelope(&attrs));
    msg
}

/// An INVOKE request: call `method` on the object `obj_id` with `args`.
///
/// `obj_id` comes from a prior LOOKUP; it is not stable across reboots, so it
/// must be resolved rather than remembered.
///
/// ★ The DATA attribute is emitted **even when `args` is empty**, extended and
/// zero-length — `87 00 00 04` in the capture. It marks the argument block as
/// blobmsg; omitting it is not the same message.
#[must_use]
pub fn invoke_request(
    seq: u16,
    peer: u32,
    obj_id: u32,
    method: &str,
    args: &[(String, Value)],
) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(
        &mut attrs,
        crate::attr_id::OBJID,
        false,
        &obj_id.to_be_bytes(),
    );

    let mut m = method.as_bytes().to_vec();
    m.push(0);
    push_attr(&mut attrs, crate::attr_id::METHOD, false, &m);

    let mut data = Vec::new();
    for (name, value) in args {
        push_named(&mut data, name, value);
    }
    push_attr(&mut attrs, crate::attr_id::DATA, true, &data);

    let mut msg = header(MessageType::Invoke, seq, peer).to_vec();
    msg.extend_from_slice(&envelope(&attrs));
    msg
}
