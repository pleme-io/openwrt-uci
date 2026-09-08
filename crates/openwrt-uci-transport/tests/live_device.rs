//! Integration test against a real `OpenWrt` device.
//!
//! `#[ignore]` by default: CI has no router, and a test suite that needs one is
//! a suite nobody runs. Enable it deliberately:
//!
//! ```sh
//! OPENWRT_TEST_HOST=192.168.8.1 \
//! OPENWRT_TEST_USER=root \
//! OPENWRT_TEST_JUMP=ops@192.0.2.10 \
//! OPENWRT_TEST_KNOWN_HOSTS=/tmp/routers_known_hosts \
//!   cargo test --test live_device -- --ignored --nocapture
//! ```
//!
//! # What this proves that the mock cannot
//!
//! The mock proves the *logic* is right given a well-formed response. Only a
//! device proves the argv is right, that the jump host works, that the host-key
//! policy maps to flags `ssh` actually accepts, and that a real `uci export`
//! parses. Those are four separate ways to be wrong that no unit test reaches.

use openwrt_uci_transport::{HostKeyPolicy, SshTarget, SshTransport, Transport, UciReader};

/// Build a target from the environment, or skip.
///
/// Returns `None` rather than panicking when unset: an unconfigured run should
/// be a skip, not a failure, or people start ignoring the suite.
fn target_from_env() -> Option<SshTarget> {
    let host = std::env::var("OPENWRT_TEST_HOST").ok()?;
    let user = std::env::var("OPENWRT_TEST_USER").unwrap_or_else(|_| "root".to_owned());

    let mut t = SshTarget::new(&user, &host, "");
    t.host_key_policy = match std::env::var("OPENWRT_TEST_KNOWN_HOSTS") {
        Ok(kh) => HostKeyPolicy::TrustOnFirstUse {
            known_hosts: kh.into(),
        },
        Err(_) => HostKeyPolicy::AcceptAnyInsecure {
            justification: "explicit opt-in integration test against a device on a trusted LAN",
        },
    };
    if let Ok(j) = std::env::var("OPENWRT_TEST_JUMP") {
        t = t.via_jump(&j);
    }
    Some(t)
}

#[test]
#[ignore = "needs a real OpenWrt device; see module docs"]
fn ssh_is_available() {
    SshTransport::probe().expect("an `ssh` binary must be on PATH");
}

#[test]
#[ignore = "needs a real OpenWrt device; see module docs"]
fn reads_and_parses_the_whole_device() {
    let Some(target) = target_from_env() else {
        eprintln!("OPENWRT_TEST_HOST unset — skipping");
        return;
    };
    let mut reader = UciReader::new(SshTransport::new(target));

    let doc = reader.export().expect("device must return parseable UCI");

    // Deliberately loose: this asserts the shape of any OpenWrt device, not the
    // contents of one particular router. A test pinned to 70 packages would
    // fail on router 2 for a reason that is not a defect.
    assert!(
        doc.packages.len() > 10,
        "expected a populated device, got {} packages",
        doc.packages.len()
    );
    for p in ["network", "system"] {
        assert!(doc.package(p).is_some(), "every OpenWrt device has `{p}`");
    }

    eprintln!(
        "  device returned {} packages, {} sections",
        doc.packages.len(),
        doc.packages.iter().map(|p| p.sections.len()).sum::<usize>()
    );
}

#[test]
#[ignore = "needs a real OpenWrt device; see module docs"]
fn a_device_export_round_trips_byte_for_byte() {
    // The strongest available check: the model's core claim, tested against
    // whatever this device actually has rather than against a committed
    // fixture. If a device carries a UCI shape the fixture lacks, this is
    // where it surfaces.
    let Some(target) = target_from_env() else {
        eprintln!("OPENWRT_TEST_HOST unset — skipping");
        return;
    };
    let mut transport = SshTransport::new(target);
    let raw = transport
        .exec("uci export")
        .expect("uci export must run")
        .stdout;

    let doc = openwrt_uci::Document::parse(&raw).expect("device output must parse");
    assert_eq!(doc.render(), raw, "live device export must round-trip");
}

#[test]
#[ignore = "needs a real OpenWrt device; see module docs"]
fn a_missing_package_is_absent_on_a_real_device() {
    // ★ This is the test that caught the defect. It originally asserted the
    // assumption baked into both the code and the mock — that
    // `uci export <nonexistent>` exits 0 with empty output. The device says
    // otherwise: exit 1, stderr "uci: Entry not found". The mock agreed with
    // the code because both were written from the same guess, so no unit test
    // could have found it.
    let Some(target) = target_from_env() else {
        return;
    };
    let mut reader = UciReader::new(SshTransport::new(target));
    assert!(
        reader
            .export_package("definitely_not_a_package")
            .expect("absent package must not be an error")
            .is_none()
    );
}
