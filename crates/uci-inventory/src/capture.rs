//! Turn a live device's whole UCI surface into a committable test fixture.
//!
//! # Why this is a subcommand and not a script
//!
//! The fixtures under `tests/fixtures/` are captures of real routers, and they
//! exist because hand-written fixtures encode what their author EXPECTED a
//! router to look like — which is how a check can be green in the test suite
//! and wrong on the first device it meets.
//!
//! A capture is only useful if it can be REGENERATED, and the first version of
//! this lived outside the crate and re-implemented [`option_is_secret`] and the
//! secret-bearing package list by hand. That is the duplication that must not
//! exist: the day the catalog gains a package, a mirrored copy keeps scrubbing
//! by the old rules and silently commits a credential. There is one authority
//! for what is secret, and this reads it.
//!
//! # The scrubbing contract
//!
//! **Fail-closed.** Every value in a secret-bearing package is replaced unless
//! its field is named in [`STRUCTURAL`], so an unrecognised field is scrubbed
//! by default. Scrubbing by option NAME alone is not enough and was measured
//! not to be: `NordVPN` stores its bearer token in `wireguard.<peer>.username`,
//! and `username` matches no secret substring. The package disposition already
//! knows that package holds credentials — trust it, rather than guessing which
//! field a vendor chose.
//!
//! **Equality classes are preserved, and nothing else is.** Two fields that
//! held the same secret get the same placeholder; two that differed get
//! different ones. That is exactly the information the agreement check reasons
//! about, and it is not recoverable back to a value. No digest is emitted: a
//! hash of a short PSK is brute-forceable, so it would leak the secret through
//! a field that merely looks safe.

use crate::disposition::{classify, option_is_secret, Disposition};
use std::collections::BTreeMap;
use ubus_facade::json::Json;

/// UCI bookkeeping. Identity and ordering must survive or the fixture stops
/// describing the device: `.index` decides positional addresses, `.anonymous`
/// decides whether a section is named at all.
const UCI_META: &[&str] = &[".type", ".name", ".anonymous", ".index"];

/// Fields kept verbatim even inside a secret-bearing package.
///
/// These say how a section is WIRED, never what it proves. The list is
/// deliberately explicit rather than a pattern: it is a small set a reviewer
/// can check, and everything outside it is scrubbed.
///
/// `network` earns its place twice over — it is the discriminator the
/// secrets-agree check groups by, so a fixture that hides it cannot show that
/// a house network and a guest network are compared separately. `enabled` was
/// added after a capture scrubbed `tailscale.settings.enabled` and made a
/// healthy router read as unconfigured in the fixture but not on the wire.
pub const STRUCTURAL: &[&str] = &[
    "network",
    "device",
    "mode",
    "ifname",
    "disabled",
    "enabled",
    "encryption",
    "ssid",
    "band",
    "htmode",
    "channel",
    "country",
    "hidden",
    "isolate",
    "wds",
    "port",
];

/// Build the fixture document for a surveyed device.
///
/// `bodies` is `(package name, uci.get body)` exactly as [`crate::adapter`]
/// answered — the same input [`crate::inventory::survey`] takes, so a fixture
/// and a live run are fed identically.
#[must_use]
pub fn fixture(bodies: &[(String, Json)]) -> Json {
    let mut classes: BTreeMap<String, String> = BTreeMap::new();
    let packages: Vec<Json> = bodies
        .iter()
        .map(|(name, body)| {
            // An unclassified package is scrubbed WHOLE. `survey` refuses it
            // anyway, but a capture must never be the thing that leaks while
            // someone is still deciding what a new package is.
            let whole = !matches!(classify(name), Some(Disposition::Managed | Disposition::DeviceOwned { .. }));
            Json::Arr(vec![Json::str(name), scrub(body, whole, &mut classes)])
        })
        .collect();
    Json::obj([("packages", Json::Arr(packages))])
}

fn placeholder(value: &str, classes: &mut BTreeMap<String, String>) -> Json {
    let next = classes.len() + 1;
    let s = classes.entry(value.to_owned()).or_insert_with(|| format!("SECRET-{next}"));
    Json::Str(s.clone())
}

fn scrub(node: &Json, whole: bool, classes: &mut BTreeMap<String, String>) -> Json {
    match node {
        Json::Obj(fields) => Json::Obj(
            fields
                .iter()
                .map(|(k, v)| {
                    let keep = UCI_META.contains(&k.as_str())
                        || (STRUCTURAL.contains(&k.as_str()) && !option_is_secret(k));
                    if keep {
                        return (k.clone(), v.clone());
                    }
                    match v {
                        Json::Str(s) if !s.is_empty() && (whole || option_is_secret(k)) => {
                            (k.clone(), placeholder(s, classes))
                        }
                        other => (k.clone(), scrub(other, whole, classes)),
                    }
                })
                .collect(),
        ),
        Json::Arr(items) => Json::Arr(items.iter().map(|i| scrub(i, whole, classes)).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubus_facade::json::parse;

    fn body(src: &str) -> Json {
        parse(src).expect("fixture parses")
    }

    fn rendered(j: &Json) -> String {
        format!("{j:?}")
    }

    #[test]
    fn a_secret_bearing_package_is_scrubbed_whole_not_by_field_name() {
        // ★ THE MEASURED LEAK. `username` matches no secret substring, and
        // `NordVPN` puts its bearer token there.
        let b = body(
            r#"{"values":{"peer":{".type":"proto",".name":"peer",".index":0,"username":"TOKEN-e9f2ab0f","endpoint":"vpn.example"}}}"#,
        );
        let out = fixture(&[("wireguard".to_owned(), b)]);
        let s = rendered(&out);
        assert!(!s.contains("TOKEN-e9f2ab0f"), "a bearer token survived scrubbing: {s}");
        assert!(!s.contains("vpn.example"), "whole-package scrubbing must not spare a sibling");
    }

    #[test]
    fn equality_classes_survive_and_values_do_not() {
        let b = body(
            r#"{"values":{
                "a":{".type":"wifi-iface",".name":"a",".index":0,"network":"lan","key":"same"},
                "b":{".type":"wifi-iface",".name":"b",".index":1,"network":"lan","key":"same"},
                "g":{".type":"wifi-iface",".name":"g",".index":2,"network":"guest","key":"other"}
            }}"#,
        );
        let out = fixture(&[("wireless".to_owned(), b)]);
        let s = rendered(&out);
        assert!(!s.contains("\"same\""), "a psk survived");
        assert!(!s.contains("\"other\""), "a psk survived");
        // The two that agreed must still agree; the third must still differ.
        let inv = crate::inventory::survey(&[("wireless".to_owned(), reparse(&out))]).expect("surveys");
        let ag = &inv.packages[0].secret_agreement;
        assert_eq!(ag.len(), 1, "only `lan` has two carriers");
        assert!(ag[0].agree, "equality must survive the scrub");
        assert_eq!(ag[0].network, "lan");
    }

    #[test]
    fn structural_fields_are_kept_so_the_fixture_still_describes_the_device() {
        let b = body(
            r#"{"values":{"settings":{".type":"settings",".name":"settings",".index":0,"enabled":"1","authkey":"tskey-secret"}}}"#,
        );
        let out = fixture(&[("tailscale".to_owned(), b)]);
        let s = rendered(&out);
        assert!(s.contains("\"1\""), "`enabled` is structural and must survive");
        assert!(!s.contains("tskey-secret"), "the auth key must not");
    }

    #[test]
    fn uci_identity_survives_or_the_fixture_stops_describing_the_device() {
        let b = body(
            r#"{"values":{"cfg0a1b":{".type":"wifi-iface",".name":"cfg0a1b",".anonymous":1,".index":3,"key":"k"}}}"#,
        );
        let out = fixture(&[("wireless".to_owned(), b)]);
        let s = rendered(&out);
        assert!(s.contains("cfg0a1b"), "the internal name is the only rename address there is");
        assert!(s.contains("Int(3)") || s.contains('3'), "`.index` decides positional identity");
    }

    /// Round-trip a rendered fixture so a test can survey what was written.
    fn reparse(j: &Json) -> Json {
        let Json::Obj(top) = j else { panic!("not an object") };
        let Json::Arr(pkgs) = top.iter().find(|(k, _)| k == "packages").map(|(_, v)| v).unwrap()
        else {
            panic!("no packages")
        };
        let Json::Arr(pair) = &pkgs[0] else { panic!("not a pair") };
        pair[1].clone()
    }
}
