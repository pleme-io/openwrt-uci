//! A framed ubus connection — the seam between encoded bytes and a call.
//!
//! [`encode`](crate::encode) builds request bytes and the decoder reads reply
//! bytes; neither owns a stream, a peer id, a sequence number, or the rule that
//! a request ends at a STATUS. This module owns exactly those, and nothing else.
//!
//! # Why generic over `Read + Write` rather than tied to a socket
//!
//! ubus listens on a unix socket **local to the device**, so the eventual
//! production caller is an on-device agent using [`Connection::connect_unix`].
//! But the same framing has to be drivable from a workstation over an `ssh -L`
//! relay, and from a test with no I/O at all. Those are three transports and one
//! protocol, so the protocol is written once against `Read + Write` and the
//! transport is the caller's choice.
//!
//! That is also the mockable seam the fleet's TYPED-SPEC triplet asks for: a
//! test injects a scripted stream and exercises every framing rule — including
//! the failure paths — without a device in the room.
//!
//! # What this deliberately does NOT do
//!
//! It does not reuse object ids across calls. A ubus object id is assigned at
//! registration and does not survive a restart of the process that owns the
//! object, so caching one trades a correctness property for a round trip. Each
//! [`Connection::call`] resolves the path it was given.

use crate::encode::{Value, blobmsg_type, invoke_request, lookup_request};
use crate::{ATTR_HEADER_LEN, Attr, HEADER_LEN, Header, MessageType, ProtoError, attr_id};
use std::io::{Read, Write};

/// A value read back off the wire.
///
/// Separate from [`Value`] on purpose. `Value` is what we can *encode*, so it
/// has no arm for a type we have never measured — an unmeasured type is a
/// compile error there. Reading has the opposite obligation: the device may
/// legitimately send a type this crate has not characterised, and dropping it
/// would report absence for something that was present.
///
/// That is not hypothetical — it is how ARRAY got measured. `uci changes`
/// returned `Unknown { type_code: 1, bytes: [] }`, which is what pointed at the
/// type and, because the bytes were preserved, let a populated one be decoded
/// from a real device rather than from libubox headers.
///
/// So [`Decoded::Unknown`] exists to make that case **visible** rather than
/// silent. It is the same discipline as `kotae`: `empty` and `unrecognised` must
/// not render as the same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Str(String),
    I32(i32),
    Table(Vec<(String, Decoded)>),
    /// A positional list — `uci changes` returns one, of lists.
    Array(Vec<Decoded>),
    /// A blobmsg type this crate has not measured. Carries its code and bytes
    /// so a caller can characterise it rather than guess.
    Unknown {
        type_code: u8,
        bytes: Vec<u8>,
    },
}

impl Decoded {
    /// The string value, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The list items, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Decoded]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Look up a key in a table.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Decoded> {
        match self {
            Self::Table(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// One object from a LOOKUP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub path: String,
    pub id: u32,
}

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Proto(ProtoError),
    /// The server completed the request and reported a nonzero status.
    ///
    /// Kept distinct from every other variant because it is the *server's*
    /// verdict on a well-formed exchange, not a failure of ours. `ubus`'s own
    /// codes: 2 is `Invalid argument`, 4 is `Not found`, 6 is `Permission
    /// denied`.
    Status(u32),
    /// A LOOKUP returned no object at that path.
    NoSuchObject(String),
    /// The exchange completed but did not have the shape it must have.
    Malformed(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ubus i/o: {e}"),
            Self::Proto(e) => write!(f, "ubus protocol: {e}"),
            Self::Status(c) => {
                let meaning = match c {
                    2 => " (invalid argument — usually a rejected argument encoding)",
                    4 => " (not found)",
                    6 => " (permission denied)",
                    _ => "",
                };
                write!(f, "ubus returned status {c}{meaning}")
            }
            Self::NoSuchObject(p) => write!(f, "no ubus object at {p:?}"),
            Self::Malformed(m) => write!(f, "malformed ubus reply: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ProtoError> for ClientError {
    fn from(e: ProtoError) -> Self {
        Self::Proto(e)
    }
}

/// A framed ubus connection.
pub struct Connection<S> {
    stream: S,
    peer: u32,
    seq: u16,
}

/// Written by hand rather than derived: a derive would add an `S: Debug` bound,
/// forcing it on every stream type, and a socket has no useful debug form
/// anyway. The connection's own state is what a reader wants.
impl<S> std::fmt::Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &format_args!("{:#010x}", self.peer))
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl<S: Read + Write> Connection<S> {
    /// Take over a connected stream and complete the ubus handshake.
    ///
    /// The server sends a HELLO unprompted on connect, and that HELLO carries
    /// **our** peer id, which every subsequent request must echo. So the
    /// handshake is not optional politeness — a connection whose HELLO has not
    /// been read cannot form a valid request, and a `Connection` therefore
    /// cannot exist without one.
    ///
    /// # Errors
    ///
    /// [`ClientError::Malformed`] if the first message is not a HELLO.
    pub fn new(mut stream: S) -> Result<Self, ClientError> {
        let (hdr, _) = read_message(&mut stream)?;
        if hdr.message_type != MessageType::Hello {
            return Err(ClientError::Malformed(format!(
                "expected HELLO on connect, got {:?}",
                hdr.message_type
            )));
        }
        Ok(Self {
            stream,
            peer: hdr.peer,
            seq: 0,
        })
    }

    /// The peer id the server assigned this connection.
    #[must_use]
    pub const fn peer(&self) -> u32 {
        self.peer
    }

    /// Recover the underlying stream, ending the connection's framing.
    ///
    /// Exists so a caller that needs the socket back — or a test that wants to
    /// inspect what was actually written — does not have to keep a second
    /// handle to it alive alongside this one.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }

    fn next_seq(&mut self) -> u16 {
        // Wrapping is correct rather than merely convenient: seq only has to
        // distinguish a reply from the PREVIOUS request's trailing STATUS, and
        // that is a window of one.
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// Send one request and drain its reply to completion.
    ///
    /// ★ A request is answered by zero or more DATA messages and then **exactly
    /// one** STATUS. Reading one message and stopping leaves the STATUS queued,
    /// and the *next* request reads that stale STATUS as its own reply —
    /// reporting success for a call whose result it never saw. This project made
    /// that exact bug once while capturing INVOKE, which is why draining lives
    /// here, in the one place every call goes through, rather than in each
    /// caller.
    fn exchange(&mut self, bytes: &[u8], seq: u16) -> Result<Vec<Vec<u8>>, ClientError> {
        self.stream.write_all(bytes)?;
        let mut data = Vec::new();
        loop {
            let (hdr, body) = read_message(&mut self.stream)?;
            if hdr.seq != seq {
                return Err(ClientError::Malformed(format!(
                    "reply for seq {} while awaiting {seq} — a stale message is queued",
                    hdr.seq
                )));
            }
            match hdr.message_type {
                MessageType::Data => data.push(body),
                MessageType::Status => {
                    let code = Attr::decode(&body)?
                        .children()
                        .next()
                        .ok_or_else(|| ClientError::Malformed("STATUS carries no code".into()))?
                        .as_u32()?;
                    if code == 0 {
                        return Ok(data);
                    }
                    return Err(ClientError::Status(code));
                }
                other => {
                    return Err(ClientError::Malformed(format!(
                        "unexpected {other:?} in a reply stream"
                    )));
                }
            }
        }
    }

    /// Resolve a path to the objects registered under it.
    ///
    /// # Errors
    ///
    /// Propagates I/O and protocol failures, and a nonzero server status.
    pub fn lookup(&mut self, path: &str) -> Result<Vec<ObjectInfo>, ClientError> {
        let seq = self.next_seq();
        let data = self.exchange(&lookup_request(seq, self.peer, path), seq)?;

        let mut found = Vec::new();
        for msg in &data {
            let table = Attr::decode(msg)?;
            let mut id = None;
            let mut p = None;
            for a in table.children() {
                match a.id {
                    attr_id::OBJID => id = a.as_u32().ok(),
                    attr_id::OBJPATH => p = a.as_str().ok().map(str::to_owned),
                    _ => {}
                }
            }
            if let (Some(id), Some(path)) = (id, p) {
                found.push(ObjectInfo { path, id });
            }
        }
        Ok(found)
    }

    /// Invoke a method on an already-resolved object id.
    ///
    /// # Errors
    ///
    /// Propagates I/O and protocol failures, and a nonzero server status.
    pub fn invoke(
        &mut self,
        obj_id: u32,
        method: &str,
        args: &[(String, Value)],
    ) -> Result<Option<Decoded>, ClientError> {
        let seq = self.next_seq();
        let data = self.exchange(&invoke_request(seq, self.peer, obj_id, method, args), seq)?;

        // A method with no return value answers with a STATUS and no DATA. That
        // is success with nothing to report, not an empty result — `uci set` and
        // `uci commit` both behave this way — so it is `None` rather than an
        // empty table.
        let Some(first) = data.first() else {
            return Ok(None);
        };

        let envelope = Attr::decode(first)?;
        let payload = envelope.children().find(|a| a.id == attr_id::DATA);
        // ★ The named values sit INSIDE the DATA attribute, not among the
        // envelope's children. The envelope's children are raw, id-addressed
        // attributes, so iterating them looks for names where there are none and
        // finds nothing — which presents as "the device returned nothing".
        match payload {
            Some(p) => Ok(Some(decode_named_run(p.payload)?)),
            None => Ok(None),
        }
    }

    /// Resolve `path` and invoke `method` on it.
    ///
    /// # Errors
    ///
    /// [`ClientError::NoSuchObject`] if the path resolves to nothing, plus the
    /// failures of [`Self::lookup`] and [`Self::invoke`].
    pub fn call(
        &mut self,
        path: &str,
        method: &str,
        args: &[(String, Value)],
    ) -> Result<Option<Decoded>, ClientError> {
        let obj = self
            .lookup(path)?
            .into_iter()
            .find(|o| o.path == path)
            .ok_or_else(|| ClientError::NoSuchObject(path.to_owned()))?;
        self.invoke(obj.id, method, args)
    }
}

#[cfg(unix)]
impl Connection<std::os::unix::net::UnixStream> {
    /// Connect to a ubus socket and complete the handshake.
    ///
    /// The default path is `/var/run/ubus/ubus.sock`.
    ///
    /// ★ Measured: that socket's mode is `srw-rw-rw-`, owner `ubus:ubus`. **ubus
    /// itself performs no authentication** — session auth lives in `rpcd`, the
    /// HTTP layer above it. So any local process can do everything this type
    /// exposes, which is why an on-device agent needs no credential, and why a
    /// relay exposing this socket to a network interface would publish
    /// root-equivalent control of the device.
    ///
    /// # Errors
    ///
    /// Propagates the connect failure, and any handshake failure.
    pub fn connect_unix(path: impl AsRef<std::path::Path>) -> Result<Self, ClientError> {
        let s = std::os::unix::net::UnixStream::connect(path)?;
        Self::new(s)
    }
}

/// Read exactly one message: an 8-byte header, then the one attribute whose
/// declared length its first four bytes carry.
fn read_message<S: Read>(s: &mut S) -> Result<(Header, Vec<u8>), ClientError> {
    let mut head = [0u8; HEADER_LEN];
    s.read_exact(&mut head)?;
    let hdr = Header::decode(&head)?;

    let mut attr_head = [0u8; ATTR_HEADER_LEN];
    s.read_exact(&mut attr_head)?;
    let declared = (u32::from_be_bytes(attr_head) & crate::LEN_MASK_BITS) as usize;
    if declared < ATTR_HEADER_LEN {
        return Err(ClientError::Proto(ProtoError::BadLength { declared }));
    }

    let mut body = attr_head.to_vec();
    body.resize(declared, 0);
    s.read_exact(&mut body[ATTR_HEADER_LEN..])?;
    Ok((hdr, body))
}

/// Decode a run of blobmsg attributes into owned named values.
///
/// Takes a byte slice rather than an [`Attr`] so a nested table — whose
/// children begin where its own name ends — is the same call as a top-level
/// one, with no re-wrapping.
fn decode_named_run(buf: &[u8]) -> Result<Decoded, ClientError> {
    let mut pairs = Vec::new();
    for child in crate::AttrIter::new(buf) {
        let Some((name, raw)) = child.as_named()? else {
            // A raw attribute where a blobmsg table should be. Reported rather
            // than skipped: a silently dropped field reads as absent, and this
            // project refuses partial views that look complete.
            return Err(ClientError::Malformed(format!(
                "unnamed attribute (id {}) inside a blobmsg table",
                child.id
            )));
        };
        pairs.push((name.to_owned(), decode_value(child.id, raw)?));
    }
    Ok(Decoded::Table(pairs))
}

fn decode_value(type_code: u8, raw: &[u8]) -> Result<Decoded, ClientError> {
    match type_code {
        blobmsg_type::STRING => {
            let s = std::str::from_utf8(raw)
                .map_err(|_| ClientError::Proto(ProtoError::NotUtf8))?
                .trim_end_matches('\0')
                .to_owned();
            Ok(Decoded::Str(s))
        }
        blobmsg_type::INT32 => {
            let b: [u8; 4] = raw
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| ClientError::Malformed("int32 shorter than 4 bytes".into()))?;
            Ok(Decoded::I32(i32::from_be_bytes(b)))
        }
        blobmsg_type::TABLE => decode_named_run(raw),
        // ★ An array's members carry an EMPTY name (`namelen = 0`), so they are
        // positional. The name is read and discarded rather than ignored, so a
        // member that unexpectedly HAS a name is still decoded by value rather
        // than mistaken for a table.
        blobmsg_type::ARRAY => {
            let mut items = Vec::new();
            for child in crate::AttrIter::new(raw) {
                let Some((_, v)) = child.as_named()? else {
                    return Err(ClientError::Malformed(format!(
                        "raw attribute (id {}) inside a blobmsg array",
                        child.id
                    )));
                };
                items.push(decode_value(child.id, v)?);
            }
            Ok(Decoded::Array(items))
        }
        other => Ok(Decoded::Unknown {
            type_code: other,
            bytes: raw.to_vec(),
        }),
    }
}
