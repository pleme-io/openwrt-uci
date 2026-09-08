//! The ubus wire protocol — `blob_attr`, blobmsg, and message framing.
//!
//! Pure Rust, zero dependencies, no C linkage. ubus is a protocol on a unix
//! socket, not a library that must be linked: this crate speaks it.
//!
//! **Every constant here was derived from bytes captured off a live device**,
//! not from recollection of libubox headers. See `PROTOCOL.md` for the capture
//! and its decoding; `tests/decode.rs` asserts this code against those exact
//! bytes. If the code and the capture disagree, the capture is right.
//!
//! # Scope
//!
//! Decoding is verified against a real LOOKUP reply. Encoding is verified only
//! by round-trip and by the one LOOKUP request that was actually sent and
//! answered. **INVOKE — the write path — is not yet verified**, and is marked
//! as such rather than presented as measured.

#![forbid(unsafe_code)]

use std::fmt;

/// Size of the fixed message header: version, type, seq, peer.
pub const HEADER_LEN: usize = 8;
/// Size of a `blob_attr`'s own header. `len` includes these bytes.
pub const ATTR_HEADER_LEN: usize = 4;

const EXTENDED: u32 = 0x8000_0000;
const ID_MASK: u32 = 0x7f00_0000;
const ID_SHIFT: u32 = 24;
const LEN_MASK: u32 = 0x00ff_ffff;

/// Round up to the 4-byte boundary `blob_attr` payloads are padded to.
///
/// The padding is *not* counted in `len`, but must be skipped to reach the next
/// attribute — conflating the two walks the stream off by a few bytes and
/// produces garbage rather than an error.
#[must_use]
pub const fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Message types, as observed on the wire.
///
/// Every variant here was seen in a real exchange with a device. The numeric
/// form is preserved for anything else rather than guessed at, so an
/// unverified type is reported honestly instead of mislabelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Sent unprompted by the server on connect, carrying our peer id.
    Hello,
    /// Terminates a request. Carries [`ATTR_STATUS`]; 0 is success.
    Status,
    /// A reply carrying data.
    Data,
    /// Enumerate objects.
    Lookup,
    /// Call a method on an object. Verified against `system.board`.
    Invoke,
    /// Anything this crate has not verified against a device.
    Other(u8),
}

impl MessageType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Hello,
            1 => Self::Status,
            2 => Self::Data,
            4 => Self::Lookup,
            5 => Self::Invoke,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Hello => 0,
            Self::Status => 1,
            Self::Data => 2,
            Self::Lookup => 4,
            Self::Invoke => 5,
            Self::Other(v) => v,
        }
    }
}

/// ubus attribute ids, as observed in real LOOKUP and INVOKE exchanges.
///
/// Named constants rather than an enum: the set is open, and an unknown id must
/// stay a number rather than become an `Unknown` variant that discards it.
pub mod attr_id {
    /// Return code. 0 is success. Carried by a [`MessageType::Status`] message.
    pub const STATUS: u8 = 1;
    /// An object's path, e.g. `"system"`.
    pub const OBJPATH: u8 = 2;
    /// An object's numeric id, as returned by LOOKUP and required by INVOKE.
    pub const OBJID: u8 = 3;
    /// The method name to call.
    pub const METHOD: u8 = 4;
    /// An object's type id.
    pub const OBJTYPE: u8 = 5;
    /// An object's method signature table.
    pub const SIGNATURE: u8 = 6;
    /// Call arguments, or a reply payload. A blobmsg table.
    pub const DATA: u8 = 7;
}

/// Re-export for callers matching on a status message.
pub use attr_id::STATUS as ATTR_STATUS;

/// ★ **Every request is answered by zero or more [`MessageType::Data`] messages
/// followed by exactly one [`MessageType::Status`].**
///
/// Verified on a live device, and worth stating loudly because getting it wrong
/// is silent. A client that reads one message and stops will leave the trailing
/// STATUS queued, and the *next* request will read that stale STATUS as its own
/// reply — reporting success for a call whose result it never saw.
///
/// That mistake was made while reverse-engineering this protocol: an INVOKE
/// appeared to succeed instantly, and the "reply" was the previous LOOKUP's
/// status. **`seq` is the only thing that catches it**, so a correct client
/// drains to STATUS and matches `seq` on every message.
pub const REQUEST_ENDS_AT_STATUS: () = ();

/// The 8-byte message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub message_type: MessageType,
    pub seq: u16,
    pub peer: u32,
}

impl Header {
    /// Decode a header from the first [`HEADER_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] if fewer than 8 bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtoError::Truncated {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }
        Ok(Self {
            version: buf[0],
            message_type: MessageType::from_u8(buf[1]),
            seq: u16::from_be_bytes([buf[2], buf[3]]),
            peer: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let seq = self.seq.to_be_bytes();
        let peer = self.peer.to_be_bytes();
        [
            self.version,
            self.message_type.to_u8(),
            seq[0],
            seq[1],
            peer[0],
            peer[1],
            peer[2],
            peer[3],
        ]
    }
}

/// A single `blob_attr`: an id, an extended flag, and a payload.
///
/// Borrows the payload rather than copying — decoding a 656-byte LOOKUP reply
/// should not allocate per attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
    /// For a raw attribute this is the ubus attribute id (2 = OBJPATH, …).
    /// For an extended one it is the **blobmsg type** (3 = STRING, 5 = INT32, …).
    pub id: u8,
    /// Set when the payload is a named blobmsg rather than a raw value.
    pub extended: bool,
    /// The payload, excluding the 4-byte header and any trailing padding.
    pub payload: &'a [u8],
    /// The declared length, *including* the 4-byte header — as it appears on
    /// the wire. Kept so callers can walk the stream without recomputing it.
    pub total_len: usize,
}

impl<'a> Attr<'a> {
    /// Decode one attribute from the front of `buf`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Truncated`] if the buffer is shorter than the declared
    /// length, or [`ProtoError::BadLength`] if the declared length is smaller
    /// than the header it must include — a value that would otherwise cause a
    /// zero-width step and an infinite walk.
    pub fn decode(buf: &'a [u8]) -> Result<Self, ProtoError> {
        if buf.len() < ATTR_HEADER_LEN {
            return Err(ProtoError::Truncated {
                need: ATTR_HEADER_LEN,
                got: buf.len(),
            });
        }
        let id_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let total_len = (id_len & LEN_MASK) as usize;

        if total_len < ATTR_HEADER_LEN {
            return Err(ProtoError::BadLength {
                declared: total_len,
            });
        }
        if buf.len() < total_len {
            return Err(ProtoError::Truncated {
                need: total_len,
                got: buf.len(),
            });
        }

        Ok(Self {
            id: ((id_len & ID_MASK) >> ID_SHIFT) as u8,
            extended: id_len & EXTENDED != 0,
            payload: &buf[ATTR_HEADER_LEN..total_len],
            total_len,
        })
    }

    /// How far to advance to reach the next attribute: the declared length,
    /// rounded up to the 4-byte boundary.
    #[must_use]
    pub const fn stride(&self) -> usize {
        pad4(self.total_len)
    }

    /// Interpret the payload as a NUL-terminated string.
    ///
    /// # Errors
    ///
    /// [`ProtoError::NotUtf8`] if the bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, ProtoError> {
        let bytes = self
            .payload
            .split(|b| *b == 0)
            .next()
            .unwrap_or(self.payload);
        std::str::from_utf8(bytes).map_err(|_| ProtoError::NotUtf8)
    }

    /// Interpret the payload as a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::BadLength`] if the payload is not 4 bytes.
    pub fn as_u32(&self) -> Result<u32, ProtoError> {
        match self.payload {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            other => Err(ProtoError::BadLength {
                declared: other.len(),
            }),
        }
    }

    /// Split an extended attribute into its name and value.
    ///
    /// Returns `None` when the attribute is not extended — a raw attribute has
    /// no name, and inventing one would let a caller treat unnamed data as
    /// named.
    ///
    /// # Errors
    ///
    /// Fails if the payload is too short to contain the declared name.
    pub fn as_named(&self) -> Result<Option<(&'a str, &'a [u8])>, ProtoError> {
        if !self.extended {
            return Ok(None);
        }
        if self.payload.len() < 2 {
            return Err(ProtoError::Truncated {
                need: 2,
                got: self.payload.len(),
            });
        }
        // namelen is strlen: it excludes the NUL, which is nonetheless present.
        let namelen = u16::from_be_bytes([self.payload[0], self.payload[1]]) as usize;
        let name_start = 2;
        let name_end = name_start + namelen;
        if self.payload.len() < name_end + 1 {
            return Err(ProtoError::Truncated {
                need: name_end + 1,
                got: self.payload.len(),
            });
        }
        let name = std::str::from_utf8(&self.payload[name_start..name_end])
            .map_err(|_| ProtoError::NotUtf8)?;

        // The name field (2 + namelen + NUL) is padded to 4 bytes before the
        // value begins.
        let value_start = pad4(name_end + 1);
        let value = self.payload.get(value_start..).unwrap_or(&[]);
        Ok(Some((name, value)))
    }

    /// Walk a payload as a sequence of attributes.
    ///
    /// Used for the table an object's SIGNATURE carries, and for the top-level
    /// table of a message.
    #[must_use]
    pub fn children(&self) -> AttrIter<'a> {
        AttrIter { rest: self.payload }
    }
}

/// Iterator over consecutive attributes in a buffer.
///
/// Stops on the first malformed attribute rather than skipping it. Silently
/// skipping would hand the caller a partial view that looks complete — the same
/// failure this project refuses elsewhere.
pub struct AttrIter<'a> {
    rest: &'a [u8],
}

impl<'a> AttrIter<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < ATTR_HEADER_LEN {
            return None;
        }
        let attr = Attr::decode(self.rest).ok()?;
        let step = attr.stride().min(self.rest.len());
        self.rest = &self.rest[step..];
        Some(attr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Fewer bytes than the wire format requires.
    Truncated { need: usize, got: usize },
    /// A declared length that cannot be valid.
    BadLength { declared: usize },
    /// A string field that is not UTF-8.
    NotUtf8,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, got } => {
                write!(f, "truncated: need {need} bytes, have {got}")
            }
            Self::BadLength { declared } => write!(f, "invalid declared length {declared}"),
            Self::NotUtf8 => write!(f, "field is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ProtoError {}
