//! Tests for the SSH argv construction.
//!
//! These open no connection. The mapping from [`HostKeyPolicy`] to `ssh` flags
//! is the security-relevant part of this transport, and a mapping that can only
//! be observed by connecting to something is a mapping nobody checks. `args()`
//! is public so the mapping is inspectable, and these assert it.

use openwrt_uci_transport::{HostKeyPolicy, SshTarget};

fn args_of(t: &SshTarget) -> String {
    t.args().join(" ")
}

/// A pinned policy for tests. An `ssh-ed25519` line, because that is the shape
/// `ssh-keyscan` emits and the shape `known_hosts` must receive.
fn pin(known_hosts: &str) -> HostKeyPolicy {
    HostKeyPolicy::Pinned {
        host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY".into(),
        known_hosts: known_hosts.into(),
    }
}

#[test]
fn a_pinned_target_is_strict() {
    let t = SshTarget::new("root", "192.168.8.1", pin("/var/lib/routers/known_hosts"));
    let a = args_of(&t);
    assert!(a.contains("StrictHostKeyChecking=yes"), "{a}");
    // Must NOT disable the known-hosts file: that is what makes strict strict.
    assert!(!a.contains("UserKnownHostsFile=/dev/null"), "{a}");
    assert!(a.ends_with("root@192.168.8.1"), "{a}");
}

/// ★ The regression test for the defect this type was reshaped to fix.
///
/// `Pinned` used to emit `StrictHostKeyChecking=yes` and nothing else, so the
/// key it named never reached argv and the effective check was the invoking
/// user's ambient `~/.ssh/known_hosts`. Measured 2026-09-08: a live sshd
/// accepted `Pinned("SHA256:0000…")`.
///
/// Both files must be named. Redirecting only the user file leaves
/// `/etc/ssh/ssh_known_hosts` able to satisfy the check on the pin's behalf.
#[test]
fn a_pin_names_its_own_known_hosts_and_nulls_the_global_one() {
    let t = SshTarget::new("root", "192.168.8.1", pin("/var/lib/routers/known_hosts"));
    let a = args_of(&t);
    assert!(
        a.contains("UserKnownHostsFile=/var/lib/routers/known_hosts"),
        "a pin that does not redirect known_hosts verifies against ambient trust: {a}"
    );
    assert!(
        a.contains("GlobalKnownHostsFile=/dev/null"),
        "the global known_hosts can otherwise satisfy the pin: {a}"
    );
}

/// Two different pins must produce *different* argv.
///
/// The guard that previously looked like it covered this compared the three
/// policy VARIANTS against each other, which structurally cannot see that two
/// distinct `Pinned` values were identical — a real guard on the wrong axis.
#[test]
fn two_different_pins_are_distinguishable_in_argv() {
    let a = args_of(&SshTarget::new("root", "h", pin("/tmp/kh-one")));
    let b = args_of(&SshTarget::new("root", "h", pin("/tmp/kh-two")));
    assert_ne!(a, b, "two pins collapsed to the same argv");
}

/// The host prefix comes from the target, never the caller, so a pinned key
/// cannot be recorded against a host it was not measured from.
#[test]
fn the_known_hosts_line_is_prefixed_with_the_target_host() {
    let t = SshTarget::new("root", "192.168.8.1", pin("/tmp/kh"));
    let line = t.known_hosts_line().expect("a pinned target has a line");
    assert!(line.starts_with("192.168.8.1 ssh-ed25519 "), "{line}");

    // A non-default port uses the bracketed form ssh actually looks up.
    let mut p = SshTarget::new("root", "192.168.8.1", pin("/tmp/kh"));
    p.port = Some(2222);
    let line = p.known_hosts_line().expect("a pinned target has a line");
    assert!(
        line.starts_with("[192.168.8.1]:2222 ssh-ed25519 "),
        "{line}"
    );
}

/// ★ Multiplexing must be refused for EVERY policy, not just the pinned one.
///
/// A reused `ControlMaster` connection performs no host-key verification — the
/// handshake already happened — so an inherited `ControlMaster auto` silently
/// defeats whatever policy is in force. Measured 2026-09-08 against a live
/// device: with a master socket present, a deliberately wrong pin connected
/// with exit 0, and the whole live suite ran in 0.12s at an 80ms RTT. With
/// these two flags it takes 2.33s and the wrong pin is rejected.
///
/// This is asserted per-policy because the bypass is a property of the
/// transport, not of the policy it happens to be carrying.
#[test]
fn multiplexing_is_refused_for_every_policy() {
    for policy in [
        pin("/tmp/kh"),
        HostKeyPolicy::TrustOnFirstUse {
            known_hosts: "/tmp/kh".into(),
        },
        HostKeyPolicy::AcceptAnyInsecure {
            justification: "test",
        },
    ] {
        let a = args_of(&SshTarget::new("root", "h", policy));
        assert!(
            a.contains("ControlPath=none"),
            "an inherited ControlMaster would skip host-key verification: {a}"
        );
        assert!(a.contains("ControlMaster=no"), "{a}");
    }
}

/// A policy that verifies nothing has no line to write.
#[test]
fn a_non_pinned_policy_has_no_known_hosts_line() {
    let t = SshTarget::new(
        "root",
        "h",
        HostKeyPolicy::AcceptAnyInsecure {
            justification: "test",
        },
    );
    assert!(t.known_hosts_line().is_none());
}

#[test]
fn batch_mode_and_a_timeout_are_always_present() {
    // A reconciler that blocks on a password prompt is a hung reconciler, and
    // one with no timeout hangs forever on a site that went dark. Neither is
    // opt-in.
    for policy in [
        pin("/tmp/kh"),
        HostKeyPolicy::TrustOnFirstUse {
            known_hosts: "/tmp/kh".into(),
        },
        HostKeyPolicy::AcceptAnyInsecure {
            justification: "test",
        },
    ] {
        let t = SshTarget::new("root", "h", pin("/tmp/kh")).with_policy(policy);
        let a = args_of(&t);
        assert!(a.contains("BatchMode=yes"), "{a}");
        assert!(a.contains("ConnectTimeout="), "{a}");
    }
}

#[test]
fn trust_on_first_use_points_at_its_own_known_hosts() {
    let t =
        SshTarget::new("root", "h", pin("/tmp/kh")).with_policy(HostKeyPolicy::TrustOnFirstUse {
            known_hosts: "/var/lib/routers/known_hosts".into(),
        });
    let a = args_of(&t);
    assert!(a.contains("StrictHostKeyChecking=accept-new"), "{a}");
    assert!(
        a.contains("UserKnownHostsFile=/var/lib/routers/known_hosts"),
        "{a}"
    );
}

#[test]
fn accept_any_disables_both_checking_and_the_known_hosts_file() {
    // Both flags are required together. StrictHostKeyChecking=no on its own
    // still RECORDS the key and then fails on a later mismatch, turning a
    // deliberate one-off into a permanent confusing failure. This asserts we
    // do not ship that half-measure.
    let t =
        SshTarget::new("root", "h", pin("/tmp/kh")).with_policy(HostKeyPolicy::AcceptAnyInsecure {
            justification: "factory device on a cable in my hand",
        });
    let a = args_of(&t);
    assert!(a.contains("StrictHostKeyChecking=no"), "{a}");
    assert!(a.contains("UserKnownHostsFile=/dev/null"), "{a}");
}

#[test]
fn a_jump_host_becomes_dash_j() {
    // The reference router is reachable ONLY through a host on its LAN, so
    // this is the path that actually gets used, not a convenience.
    // 192.0.2.0/24 is RFC 5737 TEST-NET-1, reserved for documentation, so this
    // address can never collide with a real host someone is running.
    let t = SshTarget::new("root", "192.168.8.1", pin("/tmp/kh")).via_jump("ops@192.0.2.10");
    let a = args_of(&t);
    assert!(a.contains("-J ops@192.0.2.10"), "{a}");
}

#[test]
fn the_three_policies_produce_three_different_argvs() {
    // Guards the degenerate mapping: a match that fell through to one arm
    // would still compile, still pass every individual assertion above if they
    // happened to overlap, and silently apply one policy everywhere.
    let base = SshTarget::new("root", "h", pin("/tmp/kh"));
    let pinned = args_of(&base.clone().with_policy(pin("/tmp/kh-f")));
    let tofu = args_of(&base.clone().with_policy(HostKeyPolicy::TrustOnFirstUse {
        known_hosts: "/tmp/k".into(),
    }));
    let any = args_of(&base.with_policy(HostKeyPolicy::AcceptAnyInsecure { justification: "t" }));

    assert_ne!(pinned, tofu);
    assert_ne!(tofu, any);
    assert_ne!(pinned, any);
}

#[test]
fn nothing_is_interpolated_into_a_shell_string() {
    // Every element is a separate argv entry. A host name containing a shell
    // metacharacter must remain one argument rather than becoming syntax.
    let mut t = SshTarget::new("root", "h; rm -rf /", pin("/tmp/kh"));
    t.host_key_policy = pin("/tmp/kh-f");
    let args = t.args();
    let last = args.last().unwrap();
    assert_eq!(last, "root@h; rm -rf /");
    assert_eq!(args.iter().filter(|a| a.contains("rm -rf")).count(), 1);
}
