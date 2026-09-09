//! End-to-end validation of [`Connection`] and the encoder against a real ubus.
//!
//! `#[ignore]` by default: this needs a device.
//!
//! # What this proves that the other suites cannot
//!
//! - `tests/encode.rs` reproduces the captured INVOKE byte-for-byte — strong,
//!   but that capture's DATA attribute was **empty**, so it says nothing about
//!   **named blobmsg arguments**, which is exactly what `uci` needs.
//! - `tests/client.rs` exercises every framing rule against a scripted stream —
//!   including failures a well-behaved server never produces — but a mock only
//!   proves we agree with our own reading of the format.
//!
//! Only a device proves the argument encoding is one a real server accepts. So
//! this asserts on values only the device knows.
//!
//! # How to run it
//!
//! ubus is a unix socket, local to the device, so reaching it from a
//! workstation needs a **loopback-bound** relay on the device plus an `ssh -L`
//! forward. See `docs/roteador.md` §16 for the recipe and its two traps
//! (dropbear has no `sftp-server`, so upload with `ssh 'cat > f' < f`, and no
//! `setsid`, so keep the relay's ssh session in the foreground).
//!
//! ★ Never bind such a relay to a LAN interface. ubus performs **no
//! authentication** — its socket is `srw-rw-rw-` and session auth lives only in
//! `rpcd` above it — so a LAN-bound relay publishes root-equivalent control of
//! the device to every host on the segment.
//!
//! ```sh
//! UBUS_TEST_TCP=127.0.0.1:21112 cargo test --test live_wire -- --ignored --nocapture
//! ```
//!
//! An on-device caller needs none of this and uses
//! [`Connection::connect_unix`].

use std::net::TcpStream;
use ubus_proto::client::{Connection, Decoded};
use ubus_proto::encode::Value;

fn connect() -> Option<Connection<TcpStream>> {
    let addr = std::env::var("UBUS_TEST_TCP").ok()?;
    let s = TcpStream::connect(&addr).expect("the relay must be reachable");
    s.set_nodelay(true).ok();
    Some(Connection::new(s).expect("ubus must greet us with a HELLO"))
}

#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn a_lookup_resolves_the_uci_object() {
    let Some(mut c) = connect() else {
        eprintln!("UBUS_TEST_TCP unset — skipping");
        return;
    };
    eprintln!("  peer {:#010x}", c.peer());

    let objs = c.lookup("uci").expect("LOOKUP must succeed");
    let uci = objs
        .iter()
        .find(|o| o.path == "uci")
        .expect("the uci object must exist");
    eprintln!("  uci = {:#010x}", uci.id);

    // Not asserting a literal id: it is assigned at registration and does not
    // survive a restart of the process that owns the object, so pinning it
    // would make this test fail for a reason that is not a defect.
    assert_ne!(uci.id, 0);
}

/// Named string arguments, end to end, asserted on a value only the device
/// knows. This is the case byte-parity cannot reach.
#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn named_arguments_reach_the_server_and_return_its_own_value() {
    let Some(mut c) = connect() else { return };

    let got = c
        .call(
            "uci",
            "get",
            &[
                ("config".to_owned(), Value::str("system")),
                ("section".to_owned(), Value::str("@system[0]")),
                ("option".to_owned(), Value::str("hostname")),
            ],
        )
        .expect("uci.get must succeed; a status here means the server rejected our encoding")
        .expect("uci.get returns a value");

    let hostname = got
        .get("value")
        .and_then(Decoded::as_str)
        .expect("the reply carries a `value`");
    eprintln!("  uci.get system.@system[0].hostname = {hostname:?}");
    assert!(
        !hostname.is_empty(),
        "an empty value means the encoding reached the server but addressed nothing"
    );
}

/// Two calls on one connection. If the STATUS draining in `exchange` were
/// missing, the second call would read the first's trailing STATUS and fail on
/// a sequence mismatch — the bug this project already made once.
#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn sequential_calls_on_one_connection_each_get_their_own_reply() {
    let Some(mut c) = connect() else { return };

    let board = c
        .call("system", "board", &[])
        .expect("system.board must succeed")
        .expect("board returns a value");
    let model = board
        .get("model")
        .and_then(Decoded::as_str)
        .expect("board reports a model");

    let hostname = c
        .call(
            "uci",
            "get",
            &[
                ("config".to_owned(), Value::str("system")),
                ("section".to_owned(), Value::str("@system[0]")),
                ("option".to_owned(), Value::str("hostname")),
            ],
        )
        .expect("the second call must not read the first's STATUS")
        .expect("a value")
        .get("value")
        .and_then(Decoded::as_str)
        .map(str::to_owned)
        .expect("a hostname");

    eprintln!("  system.board model = {model:?}, then uci hostname = {hostname:?}");
    assert!(!model.is_empty());
    assert!(!hostname.is_empty());
}

/// ★ THE WRITE PATH, through our own client, on a real device.
///
/// §7 of the plan requires read **and** write verified on the wire before any
/// operation may enter the generated façade spec. This is the write half.
///
/// # Safety, and why the order of operations is load-bearing
///
/// It writes an option nothing reads onto an existing package, then reverts.
/// Nothing is committed, so `/etc/config` is never touched.
///
/// ★ The revert happens BEFORE any assertion about what was staged. An earlier
/// version asserted first and panicked on a bad assertion — leaving
/// `system.cfg01e48a.ubus_proto_live_probe='staged'` pending on the device,
/// found afterwards by hand. Rust has no `finally`, so the ordering IS the
/// guarantee: capture, undo, then judge what was captured. A test that mutates
/// a real device must be unable to leave it dirty by failing.
#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn a_write_stages_and_reverts_through_our_client() {
    let Some(mut c) = connect() else { return };

    let marker = "ubus_proto_live_probe";
    let base = || {
        vec![
            ("config".to_owned(), Value::str("system")),
            ("section".to_owned(), Value::str("@system[0]")),
        ]
    };
    let pending = |d: &Option<Decoded>| -> usize {
        match d.as_ref().and_then(|d| d.get("changes")) {
            None => 0,
            Some(Decoded::Array(items)) => items.len(),
            Some(other) => panic!("unexpected shape for uci changes: {other:?}"),
        }
    };

    // Refuse to run against a device that already has pending changes: the
    // revert below would discard someone else's staged work.
    //
    // ★ MEASURED HERE: `uci changes` answers with a `changes` key whose value is
    // blobmsg type 1 — an ARRAY — and an EMPTY array has a zero-length payload.
    // So "clean" is the key being PRESENT and empty, not absent, and an earlier
    // guard read those two as the same thing. It arrived as
    // `Unknown { type_code: 1, bytes: [] }` rather than being dropped, which is
    // the whole reason `Decoded::Unknown` exists — and is how ARRAY got measured.
    let pre = c
        .call("uci", "changes", &base())
        .expect("changes must succeed");
    assert_eq!(
        pending(&pre),
        0,
        "device has pending uci changes; refusing to write. pre = {pre:?}"
    );

    // SET — stages into the delta.
    let mut set_args = base();
    set_args.push((
        "values".to_owned(),
        Value::table([(marker, Value::str("staged"))]),
    ));
    c.call("uci", "set", &set_args)
        .expect("uci.set must succeed — a status here is a rejected write encoding");

    // CAPTURE what was staged...
    let staged = c
        .call("uci", "changes", &base())
        .expect("changes must succeed");

    // ...UNDO before judging it...
    c.call("uci", "revert", &base())
        .expect("revert must succeed");
    let after = c
        .call("uci", "changes", &base())
        .expect("changes must succeed");

    // ...and only now assert.
    //
    // ★ On the DECODED structure, never on a Debug string. An earlier version
    // searched `format!("{staged:?}")` for the marker and failed even though the
    // write HAD worked, because the bytes render as decimal numbers rather than
    // as text. A Debug-string assertion can be wrong in both directions and
    // says nothing about shape.
    //
    // The shape, measured: `changes` is an ARRAY of ARRAYs, each inner list
    // being [op, section, option, value].
    let changes = staged
        .as_ref()
        .and_then(|d| d.get("changes"))
        .and_then(Decoded::as_array)
        .expect("changes must decode as an array");

    let entry = changes
        .iter()
        .find_map(|e| {
            let f: Vec<&str> = e.as_array()?.iter().filter_map(Decoded::as_str).collect();
            f.contains(&marker).then_some(f)
        })
        .unwrap_or_else(|| panic!("uci.set reported success but staged nothing: {changes:?}"));

    eprintln!("  staged change: {entry:?}");
    assert_eq!(entry.first(), Some(&"set"), "the op must be `set`");
    assert!(
        entry.contains(&"staged"),
        "the staged VALUE must be on the wire, not just the option name: {entry:?}"
    );

    assert_eq!(
        pending(&after),
        0,
        "revert did not undo the staged change: {after:?}"
    );
    eprintln!("  reverted: device is clean");
}

/// A nonzero status must arrive as the server's verdict, not as an empty value.
#[test]
#[ignore = "needs a real ubus server reachable over a relay; see module docs"]
fn a_nonexistent_config_is_reported_as_a_status_not_as_nothing() {
    let Some(mut c) = connect() else { return };

    let err = c
        .call(
            "uci",
            "get",
            &[(
                "config".to_owned(),
                Value::str("definitely_not_a_package_xyz"),
            )],
        )
        .expect_err("an absent package must not read as success");
    eprintln!("  absent package -> {err}");
}
