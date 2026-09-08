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

#[test]
fn a_pinned_target_is_strict() {
    let t = SshTarget::new("root", "192.168.8.1", "SHA256:abc");
    let a = args_of(&t);
    assert!(a.contains("StrictHostKeyChecking=yes"), "{a}");
    // Must NOT disable the known-hosts file: that is what makes strict strict.
    assert!(!a.contains("UserKnownHostsFile=/dev/null"), "{a}");
    assert!(a.ends_with("root@192.168.8.1"), "{a}");
}

#[test]
fn batch_mode_and_a_timeout_are_always_present() {
    // A reconciler that blocks on a password prompt is a hung reconciler, and
    // one with no timeout hangs forever on a site that went dark. Neither is
    // opt-in.
    for policy in [
        HostKeyPolicy::Pinned("SHA256:abc".into()),
        HostKeyPolicy::TrustOnFirstUse {
            known_hosts: "/tmp/kh".into(),
        },
        HostKeyPolicy::AcceptAnyInsecure {
            justification: "test",
        },
    ] {
        let t = SshTarget::new("root", "h", "x").with_policy(policy);
        let a = args_of(&t);
        assert!(a.contains("BatchMode=yes"), "{a}");
        assert!(a.contains("ConnectTimeout="), "{a}");
    }
}

#[test]
fn trust_on_first_use_points_at_its_own_known_hosts() {
    let t = SshTarget::new("root", "h", "x").with_policy(HostKeyPolicy::TrustOnFirstUse {
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
    let t = SshTarget::new("root", "h", "x").with_policy(HostKeyPolicy::AcceptAnyInsecure {
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
    let t = SshTarget::new("root", "192.168.8.1", "SHA256:abc").via_jump("ops@192.0.2.10");
    let a = args_of(&t);
    assert!(a.contains("-J ops@192.0.2.10"), "{a}");
}

#[test]
fn the_three_policies_produce_three_different_argvs() {
    // Guards the degenerate mapping: a match that fell through to one arm
    // would still compile, still pass every individual assertion above if they
    // happened to overlap, and silently apply one policy everywhere.
    let base = SshTarget::new("root", "h", "x");
    let pinned = args_of(&base.clone().with_policy(HostKeyPolicy::Pinned("f".into())));
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
    let mut t = SshTarget::new("root", "h; rm -rf /", "x");
    t.host_key_policy = HostKeyPolicy::Pinned("f".into());
    let args = t.args();
    let last = args.last().unwrap();
    assert_eq!(last, "root@h; rm -rf /");
    assert_eq!(args.iter().filter(|a| a.contains("rm -rf")).count(), 1);
}
