//! Tests for the read path, driven entirely by the mock.
//!
//! These use the *real* device fixture as the scripted response, so what is
//! exercised is the same 2,871-line document a router actually returns rather
//! than a toy string.

use openwrt_uci_transport::{HostKeyPolicy, TransportError, UciReader, mock::MockTransport};

const DEVICE_EXPORT: &str = include_str!("../../openwrt-uci/tests/fixtures/device-export.uci");

#[test]
fn export_parses_a_real_device_response() {
    let t = MockTransport::new().on("uci export", DEVICE_EXPORT);
    let mut reader = UciReader::new(t);

    let doc = reader.export().expect("must parse the device export");
    assert_eq!(doc.packages.len(), 70);
    assert!(doc.package("network").is_some());
    assert!(doc.package("wireless").is_some());
}

#[test]
fn export_runs_exactly_the_expected_command() {
    // Guards against a reader that "works" by asking for something else, or
    // that issues extra commands nobody authorised. On a device, every command
    // is a side effect waiting to happen.
    let t = MockTransport::new().on("uci export", DEVICE_EXPORT);
    let mut reader = UciReader::new(t);
    reader.export().unwrap();
    assert_eq!(reader.transport().calls, vec!["uci export"]);
}

#[test]
fn a_missing_package_is_absent_not_an_error() {
    // ★ MEASURED on a live device, not assumed. `uci export <missing>` exits 1
    // with "uci: Entry not found" on stderr — it does NOT exit 0 with empty
    // output, which is what this test originally asserted. The mock agreed with
    // the code because both were written from the same wrong guess; only
    // tests/live_device.rs caught it.
    let t = MockTransport::new().on_failure("uci export nosuch", "uci: Entry not found", 1);
    let mut reader = UciReader::new(t);
    assert!(reader.export_package("nosuch").unwrap().is_none());
}

#[test]
fn an_empty_success_is_also_treated_as_absent() {
    // Belt and braces for a device that signals absence the other way. Cheap,
    // and avoids a confusing parse error on an empty document.
    let t = MockTransport::new().on("uci export nosuch", "");
    let mut reader = UciReader::new(t);
    assert!(reader.export_package("nosuch").unwrap().is_none());
}

#[test]
fn a_uci_failure_that_is_not_absence_is_still_an_error() {
    // The distinction the "Entry not found" match must preserve: a permission
    // error or a corrupt config file is a real failure, not an absent package.
    // Matching on the exit code alone would swallow both.
    let t = MockTransport::new().on_failure("uci export network", "uci: Permission denied", 1);
    let mut reader = UciReader::new(t);
    assert!(matches!(
        reader.export_package("network"),
        Err(TransportError::CommandFailed { .. })
    ));
}

#[test]
fn a_present_package_comes_back_parsed() {
    let t = MockTransport::new().on(
        "uci export dropbear",
        "package dropbear\n\nconfig dropbear 'main'\n\toption Port '22'\n\n",
    );
    let mut reader = UciReader::new(t);
    let pkg = reader.export_package("dropbear").unwrap().expect("present");
    assert_eq!(pkg.name, "dropbear");
    assert_eq!(pkg.section("main").unwrap().option("Port"), Some("22"));
}

#[test]
fn a_failing_command_is_a_command_failure_not_a_parse_failure() {
    // The distinction matters for diagnosis: "uci isn't installed" and "uci
    // returned something odd" send an operator to different places.
    let t = MockTransport::new().on_failure("uci export", "uci: not found", 127);
    let mut reader = UciReader::new(t);
    match reader.export() {
        Err(TransportError::CommandFailed { command, output }) => {
            assert_eq!(command, "uci export");
            assert_eq!(output.exit_code, 127);
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
}

#[test]
fn unparseable_output_is_reported_as_malformed() {
    let t = MockTransport::new().on("uci export", "this is not uci at all\n");
    let mut reader = UciReader::new(t);
    assert!(matches!(reader.export(), Err(TransportError::Malformed(_))));
}

#[test]
fn an_unreachable_device_is_distinguishable_from_a_failing_command() {
    let t = MockTransport::new().unreachable();
    let mut reader = UciReader::new(t);
    assert!(matches!(
        reader.export(),
        Err(TransportError::Unreachable(_))
    ));
}

#[test]
fn the_mock_refuses_unscripted_commands() {
    // A mock that returned empty success for anything unscripted would let a
    // broken caller pass its tests. This asserts the seam itself is honest.
    let t = MockTransport::new().on("uci export", DEVICE_EXPORT);
    let mut reader = UciReader::new(t);
    assert!(reader.export_package("network").is_err());
}

#[test]
fn accept_any_is_the_only_policy_that_does_not_verify() {
    // The whole point of the type: a caller can refuse to write credentials
    // over an unverified channel without re-deriving what "unverified" means.
    assert!(
        HostKeyPolicy::Pinned {
            host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY".into(),
            known_hosts: "/tmp/kh".into(),
        }
        .verifies_identity()
    );
    assert!(
        HostKeyPolicy::TrustOnFirstUse {
            known_hosts: "/tmp/kh".into()
        }
        .verifies_identity()
    );
    assert!(
        !HostKeyPolicy::AcceptAnyInsecure {
            justification: "factory device on a cable in my hand"
        }
        .verifies_identity()
    );
}
