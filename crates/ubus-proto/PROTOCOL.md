# The ubus wire protocol, as measured

Every constant in this crate was **derived from bytes captured off a live
device**, not from recollection of libubox headers. Captured 2026-09-05 from a
GL.iNet GL-MT6000 running OpenWrt 21.02-SNAPSHOT, via a lua unix-socket client
on the device itself. The raw capture is
`tests/fixtures/lookup-response.hex` and is the fixture the decoder is tested
against.

This document is the specification. If it and the code disagree, the capture
decides.

## Transport

A unix stream socket at `/var/run/ubus/ubus.sock`.

**★ Measured: the socket mode is `srw-rw-rw-`, owner `ubus:ubus`.** Any local
user can connect and enumerate objects with no credential whatsoever — verified
by doing exactly that. Session authentication exists only in `rpcd`, the HTTP
layer *above* ubus, not in ubus itself.

Two consequences. Anything with local code execution on an OpenWrt device has
full ubus access, which is a property of the platform worth knowing rather than
discovering. And an on-device agent needs no session, which is why it sidesteps
the rpcd problem described below.

## Message framing

Every message is an 8-byte header followed by exactly one `blob_attr`.
**All integers are big-endian** (network byte order).

```
 0        1        2                 4                          8
 +--------+--------+-----------------+--------------------------+
 | version|  type  |       seq       |           peer           |
 +--------+--------+-----------------+--------------------------+
 |                    blob_attr (see below)                     |
 +--------------------------------------------------------------+
```

Confirmed by the server's HELLO, sent unprompted on connect:

```
00 00 00 00  fb 05 a0 cd  00 00 00 04
 |  |   |         |            |
 |  |   |         |            +-- blob_attr, len 4 => empty payload
 |  |   |         +--------------- peer 0xfb05a0cd, assigned to us
 |  |   +------------------------- seq 0
 |  +----------------------------- type 0 = HELLO
 +-------------------------------- version 0
```

### Message types, as observed

| value | name | evidence |
|---|---|---|
| 0 | HELLO | sent by server on connect |
| 1 | STATUS | terminates every request; carries attr 1, `0` = success |
| 2 | DATA | the LOOKUP reply, and the INVOKE reply payload |
| 4 | LOOKUP | sent, and answered |
| 5 | INVOKE | sent, and answered — verified against `system.board` |

## ★ Every request ends at a STATUS — and getting this wrong is silent

**A request is answered by zero or more DATA messages, then exactly one
STATUS.** Measured, both for LOOKUP and INVOKE:

```
lookup: type=2 seq=1 len=412     <- DATA
lookup: type=1 seq=1 len=20      <- STATUS, request complete
invoke: type=2 seq=2 len=404     <- DATA
invoke: type=1 seq=2 len=28      <- STATUS, request complete
```

A client that reads one message and stops leaves the trailing STATUS queued, and
the **next** request reads that stale STATUS as its own reply — reporting
success for a call whose result it never saw.

This was not theorised. It happened while capturing INVOKE: the call appeared to
return `status=0` in 20 bytes with no payload, which looked like a successful
no-op. It was the previous LOOKUP's status. **`seq` is the only thing that
distinguishes them** — the stale reply carried `seq=1` against a request sent
with `seq=2`.

A correct client drains to STATUS and matches `seq` on every message.

## INVOKE — the write path

Verified by calling `system.board`, a read-only method, as the safest first
exchange. The request carries three attributes:

```
00 05 00 02  d3 99 9b f9        header: type 5 (INVOKE), seq 2
00 00 00 1c                     table, len 28
  03 00 00 08  76 a7 57 0c      OBJID  (id 3) -- from a prior LOOKUP
  04 00 00 0a  "board\0" pad    METHOD (id 4)
  87 00 00 04                   DATA   (id 7, EXTENDED) -- empty args
```

and the reply is a DATA message whose attr 7 holds the result as a blobmsg
table:

```
03 00 00 08  76 a7 57 0c        OBJID echoed
07 00 01 80  ...                DATA, 384-byte payload
  83 00 00 18  00 06 "kernel\0"    "5.4.238"
  83 00 00 1a  00 08 "hostname\0"  "GL-MT6000"
  83 00 00 26  00 06 "system\0"    "ARMv8 Processor rev 4"
```

`0x83` is `EXTENDED | id 3`, i.e. a named STRING.

**OBJID must come from a LOOKUP.** It is not stable across reboots, so a client
resolves the path each session rather than caching the id.

### Attribute ids

| id | name | seen in |
|---|---|---|
| 1 | STATUS | every STATUS message |
| 2 | OBJPATH | LOOKUP request and reply |
| 3 | OBJID | LOOKUP reply, INVOKE request |
| 4 | METHOD | INVOKE request |
| 5 | OBJTYPE | LOOKUP reply |
| 6 | SIGNATURE | LOOKUP reply |
| 7 | DATA | INVOKE request (args) and reply (result) |

## blob_attr

```
 0                                                              4
 +--------------------------------------------------------------+
 |  E |    id (7 bits)   |            len (24 bits)             |
 +--------------------------------------------------------------+
 |                     payload, len - 4 bytes                    |
 |                  padded to a 4-byte boundary                  |
 +--------------------------------------------------------------+
```

- `E` = `0x80000000`, the *extended* flag: set means the payload is a **blobmsg**
  (named), clear means a raw attribute.
- `id` = `0x7f000000 >> 24`.
- **`len` includes the 4-byte header itself.** A 12-byte string payload is
  `len = 16`, which is exactly what the capture shows for `"cellular.cm\0"`.
  Getting this backwards is the single easiest way to misparse the stream.
- Padding to 4 bytes is *not* counted in `len`, but must be skipped when walking
  to the next attribute.

## Attribute ids in a LOOKUP reply

From the capture, against an object we independently knew existed:

| id | meaning | bytes |
|---|---|---|
| 2 | OBJPATH | `02 00 00 10` + `"cellular.cm\0"` |
| 3 | OBJID | `03 00 00 08` + `4d c8 b3 4c` |
| 5 | OBJTYPE | `05 00 00 08` + `40 d3 58 7d` |
| 6 | SIGNATURE | `06 00 02 64` + nested table |

## blobmsg — named attributes

When `E` is set, the payload is prefixed by a name:

```
 0        2                                          
 +--------+------------------------+----------------+
 | namelen|   name + NUL, padded   |     value      |
 +--------+------------------------+----------------+
```

`namelen` is `strlen` — it does **not** include the NUL, but the NUL is present
and the whole name field is padded to a 4-byte boundary.

Worked example from the capture, the method parameter `bus`:

```
85 00 00 10   00 03  62 75 73 00 00 00   00 00 00 03
|             |      |                   |
|             |      |                   +-- value: 3 = BLOBMSG_TYPE_STRING
|             |      +---------------------- "bus\0", padded 6 -> 8
|             +----------------------------- namelen 3 (strlen, no NUL)
+------------------------------------------- E | id 5 (INT32) | len 16
```

★ Note the double meaning that is easy to miss: in a **signature**, the attr's
`id` is the blobmsg *type* of the field (5 = INT32), while the *value* it
carries is the type code of the parameter (3 = STRING). That is how
`ubus -v list` renders `"bus":"String"`.

### blobmsg types

| id | type |
|---|---|
| 0 | UNSPEC |
| 1 | ARRAY |
| 2 | TABLE |
| 3 | STRING |
| 4 | INT64 |
| 5 | INT32 |
| 6 | INT16 |
| 7 | INT8 / BOOL |
| 8 | DOUBLE |

Only STRING, INT32 and TABLE appear in the capture; the rest are from the
published blobmsg definition and are **unverified here.** Marked so rather than
presented as measured.

## Why this crate exists — rpcd is not reachable baremetal

The obvious alternative is to drive `ubus` through `rpcd` over HTTP. Measured on
the device, that path is closed to us:

```
uci CLI                     has NO apply verb at all
ubus call uci apply {...}   Invalid argument   (ubus_rpc_session is required)
ubus call session login     Permission denied  (despite rpcd.@login[0].password='$p$root')
```

So OpenWrt's own confirmed-apply — `uci.apply {rollback, timeout}` with
`confirm`/`rollback` — sits behind a session we cannot currently obtain, and the
`uci` command-line tool does not implement rollback at all.

Speaking ubus directly on the device sidesteps all of it: no session, no HTTP,
no subprocess, and rollback becomes something we implement ourselves from
in-memory state, with our own timeout and our own verification predicate.
