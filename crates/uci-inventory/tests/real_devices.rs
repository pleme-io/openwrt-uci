//! The checks, run against WHOLE REAL DEVICES.
//!
//! ★ WHY THIS FILE EXISTS. Every other test in this crate is hand-written, and
//! hand-written fixtures encode what the author EXPECTED a router to look like.
//! That is exactly how `secrets-agree-across-bands` shipped green and then
//! failed on first contact with hardware (2026-09-10): it compared every
//! carrier of an option across a whole package, which is correct on a fixture
//! with one network and wrong on any real router, where a guest SSID
//! legitimately has its own password and an `OpenVPN` server key is not its
//! client key. It turned two healthy routers `fitToShip: false`.
//!
//! A hand-written fixture could not have caught that, because the author who
//! wrote the check also wrote the fixture, and both encode the same wrong
//! mental model. Only the device disagreed.
//!
//! So these fixtures are CAPTURED, not authored: the complete `uci.configs` +
//! `uci.get` surface of the two live routers, 57 and 59 packages.
//!
//! ★ THEY CARRY NO SECRETS, and the scrubbing is fail-closed. Every value in a
//! secret-bearing package is replaced unless its field is on an explicit
//! structural allowlist, so an unrecognised field is scrubbed by default. The
//! first pass scrubbed by option NAME alone and leaked a bearer token —
//! `NordVPN` stores its token in `wireguard.<peer>.username`, and `username`
//! matches no secret substring. Trust the package disposition, which already
//! knows the package holds credentials; never guess which field a vendor chose.
//!
//! Replacements preserve EQUALITY CLASSES — two fields that held the same
//! secret hold the same placeholder — which is the whole point: the agreement
//! check reasons about equality, so the fixture must preserve equality and
//! nothing else about the value.

use ubus_facade::json::{parse, Json};
use uci_inventory::inventory::{survey, Inventory};
use uci_inventory::readiness::{judge, ready, Verdict};

fn load(name: &str) -> Inventory {
    let raw = std::fs::read_to_string(format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR")))
        .expect("fixture readable");
    let doc = parse(&raw).expect("fixture parses");
    let Json::Obj(top) = &doc else { panic!("fixture is not an object") };
    let packages = top
        .iter()
        .find(|(k, _)| k == "packages")
        .map(|(_, v)| v)
        .expect("fixture has `packages`");
    let Json::Arr(entries) = packages else { panic!("`packages` is not an array") };
    let pairs: Vec<(String, Json)> = entries
        .iter()
        .map(|e| {
            let Json::Arr(pair) = e else { panic!("entry is not a [name, body] pair") };
            let Json::Str(n) = &pair[0] else { panic!("package name is not a string") };
            (n.clone(), pair[1].clone())
        })
        .collect();
    survey(&pairs).expect("a real device must survey without refusing")
}

/// The device surface is fully classified — no package the catalog has never
/// heard of. This is the check that rots first: a firmware update adds a
/// package and the catalog stops being exhaustive.
#[test]
fn both_real_devices_survey_without_refusing() {
    for d in ["repetidor-buzios", "roteador-buzios"] {
        let inv = load(d);
        assert!(inv.packages.len() > 40, "{d}: surveyed only {} packages", inv.packages.len());
    }
}

/// ★ THE REGRESSION THIS FILE WAS BORN FOR. Both routers are healthy; every
/// check must say so. Before the fix, this asserted false on both.
#[test]
fn both_real_devices_are_fit_to_ship() {
    for d in ["repetidor-buzios", "roteador-buzios"] {
        let checks = judge(&load(d), Some(0));
        let failed: Vec<_> = checks
            .iter()
            .filter_map(|c| match &c.verdict {
                Verdict::Fail(why) => Some(format!("{}: {why}", c.name)),
                _ => None,
            })
            .collect();
        assert!(failed.is_empty(), "{d} is not fit to ship: {failed:#?}");
        assert!(ready(&checks), "{d}: ready() disagrees with the per-check verdicts");
    }
}

/// A guest network legitimately holds a different password from the house
/// network. Grouping by package instead of by network makes that a failure.
#[test]
fn a_guest_network_is_not_a_disagreement() {
    let inv = load("repetidor-buzios");
    let wireless = inv
        .packages
        .iter()
        .find(|p| p.name == "wireless")
        .expect("a router has a wireless package");
    let nets: Vec<&str> = wireless.secret_agreement.iter().map(|a| a.network.as_str()).collect();
    assert!(nets.contains(&"lan"), "the house network must be compared, got {nets:?}");
    assert!(nets.contains(&"guest"), "the guest network must be compared SEPARATELY, got {nets:?}");
    assert!(
        wireless.secret_agreement.iter().all(|a| a.agree),
        "a healthy router disagrees with itself: {:?}",
        wireless.secret_agreement
    );
}

/// ★ TEETH. The fixture is only evidence if it can still go red — a real
/// capture that always passes proves the check runs, not that it detects.
/// This reproduces the ACTUAL 2026-09-09 incident against the real surface:
/// one band of the house network given a different PSK.
#[test]
fn diverging_one_band_of_the_real_device_turns_it_red() {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/fixtures/repetidor-buzios.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture readable");
    // Only the 5 GHz band's key moves. Every other byte of the device stands.
    let doc = parse(&raw).expect("parses");
    let Json::Obj(top) = &doc else { panic!() };
    let Json::Arr(entries) = top.iter().find(|(k, _)| k == "packages").map(|(_, v)| v).unwrap()
    else {
        panic!()
    };
    let mut pairs: Vec<(String, Json)> = Vec::new();
    for e in entries {
        let Json::Arr(pair) = e else { panic!() };
        let Json::Str(n) = &pair[0] else { panic!() };
        let mut body = pair[1].clone();
        if n == "wireless" {
            divert_one_band(&mut body);
        }
        pairs.push((n.clone(), body));
    }
    let inv = survey(&pairs).expect("surveys");
    let checks = judge(&inv, Some(0));
    let c = checks.iter().find(|c| c.name == "secrets-agree-across-bands").expect("check present");
    assert!(
        matches!(c.verdict, Verdict::Fail(_)),
        "a real device with one band's PSK changed must be caught, got {:?}",
        c.verdict
    );
    assert!(!ready(&checks), "the divergence must make the router unfit");
}

/// Give `wifi5g` a PSK that differs from `wifi2g`, leaving everything else.
fn divert_one_band(body: &mut Json) {
    let Json::Obj(top) = body else { return };
    for (k, v) in top.iter_mut() {
        if k != "values" {
            continue;
        }
        let Json::Obj(sections) = v else { return };
        for (name, sec) in sections.iter_mut() {
            if name != "wifi5g" {
                continue;
            }
            let Json::Obj(fields) = sec else { return };
            for (fk, fv) in fields.iter_mut() {
                if fk == "key" {
                    *fv = Json::Str("A-DIFFERENT-PSK".to_owned());
                }
            }
        }
    }
}
