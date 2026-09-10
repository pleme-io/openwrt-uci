//! Is this router fit to ship? — a typed readiness gate.
//!
//! Every check below exists because its absence cost something on real
//! hardware. This is not a generic linter; it is a list of incidents.
//!
//! # ★ WHAT THIS CANNOT SEE, stated first because it is the honest limit
//!
//! It judges the **UCI surface**, reached through the adapter. It therefore
//! cannot observe:
//!
//! - **the actual clock.** UCI has no clock. `ntp.enabled = 1` says time sync
//!   is *declared*, not that the device knows what year it is — and a router
//!   328 days in the past is exactly the failure this file exists for. Read the
//!   clock separately, from the device's own HTTP `Date` header.
//! - **whether `tailscaled` is LOGGED IN.** `tailscale.settings.enabled = 1` only
//!   says the init script will start the daemon. A device can be enabled,
//!   running, and logged out — two of these routers were.
//! - **boot symlinks, `authorized_keys`, running processes.** Not UCI.
//!
//! Reporting READY therefore means "nothing in the declared surface is wrong",
//! never "this device works". Both halves are needed and only one is here.

use crate::inventory::Inventory;

/// One readiness check's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// Not fit to ship, with what to do about it.
    Fail(String),
    /// Cannot be judged from the UCI surface — see the module docs.
    ///
    /// ★ Deliberately NOT a pass. An unobservable property reported as a pass
    /// is how a readiness gate becomes decoration.
    Unobservable(&'static str),
}

/// One check: what it asserts, and the incident that motivated it.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    /// The incident. Kept in the output so a failure explains itself without
    /// anyone going to look for the story.
    pub because: &'static str,
    pub verdict: Verdict,
}

fn option_of<'a>(inv: &'a Inventory, pkg: &str, section: &str, key: &str) -> Option<&'a str> {
    inv.packages
        .iter()
        .find(|p| p.name == pkg)?
        .sections
        .iter()
        .find(|s| s.addr.as_uci() == section)?
        .options
        .get(key)
        .map(String::as_str)
}

/// Judge a surveyed router.
///
/// `uncommitted` is the count from `uci.changes` — the caller supplies it
/// because it is a live query, not part of the inventory.
#[must_use]
pub fn judge(inv: &Inventory, uncommitted: Option<usize>) -> Vec<Check> {
    let mut out = Vec::new();

    // ── 1. Time sync ────────────────────────────────────────────────────────
    out.push(Check {
        name: "ntp-declared",
        because: "a router shipped with system.ntp.enabled UNSET and a clock 328 days \
                  in the past; every TLS handshake failed, so the VPN config download and \
                  the vendor cloud enrolment both failed with errors naming neither the \
                  clock nor each other",
        verdict: match option_of(inv, "system", "ntp", "enabled") {
            Some("1") => Verdict::Pass,
            Some(v) => Verdict::Fail(format!("system.ntp.enabled is {v:?}, want \"1\"")),
            None => Verdict::Fail(
                "system.ntp.enabled is UNSET — stack the `time-synced` profile".to_owned(),
            ),
        },
    });

    // ── 2. The name Tailscale will take ─────────────────────────────────────
    let host = option_of(inv, "system", "system_0", "hostname");
    out.push(Check {
        name: "hostname-not-factory",
        because: "Tailscale derives a node's name from the device hostname; every GL \
                  router ships as GL-MT6000, so three registered as gl-mt6000/-1/-2 and \
                  ORPHANED the fleet names plo's tunnels target — with no error anywhere",
        verdict: match host {
            Some("GL-MT6000") | None => Verdict::Fail(
                "hostname is the factory default (or unset) — stack `fleet-managed` with \
                 fleetManaged.hostname"
                    .to_owned(),
            ),
            Some(_) => Verdict::Pass,
        },
    });

    // ── 3. Reachability after it leaves the room ────────────────────────────
    out.push(Check {
        name: "tailnet-declared",
        because: "`enabled` defaults to 0, so a router with tailscaled installed, its init \
                  script enabled at boot and a populated settings section still runs NOTHING \
                  — which is how one arrived looking configured and dark",
        verdict: match option_of(inv, "tailscale", "settings", "enabled") {
            Some("1") => Verdict::Pass,
            _ => Verdict::Fail(
                "tailscale.settings.enabled is not \"1\" — stack the `tailnet` profile"
                    .to_owned(),
            ),
        },
    });

    // ── 4. Stable identities ────────────────────────────────────────────────
    let anon = inv.managed_sections().filter(|(_, s)| s.addr.is_anonymous()).count();
    out.push(Check {
        name: "no-positional-identity",
        because: "@type[N] renumbers when any earlier section of that type is removed, so a \
                  declaration keeps resolving — to a DIFFERENT section — and a reconciler \
                  then 'corrects' whatever now sits at that index",
        verdict: if anon == 0 {
            Verdict::Pass
        } else {
            Verdict::Fail(format!("{anon} managed sections are positional — run `renames --apply`"))
        },
    });

    // ── 5. Nothing half-applied ─────────────────────────────────────────────
    out.push(Check {
        name: "no-uncommitted-changes",
        because: "staged-but-uncommitted UCI is state no declaration describes; it survives \
                  until something else commits the package and publishes it by accident",
        verdict: match uncommitted {
            Some(0) => Verdict::Pass,
            Some(n) => Verdict::Fail(format!("{n} uncommitted uci changes — commit or revert")),
            None => Verdict::Unobservable("uci.changes was not queried"),
        },
    });

    // ── 6. The fleet marker ─────────────────────────────────────────────────
    out.push(Check {
        name: "fleet-marker",
        because: "the marker is how a device says it is ours; without it a router is adopted \
                  in the chart and anonymous on the wire",
        verdict: match option_of(inv, "roteador", "fleet", "owner") {
            Some(_) => Verdict::Pass,
            None => Verdict::Fail("roteador.fleet.owner is unset — stack `fleet-managed`".to_owned()),
        },
    });

    // ── 7–8. The two things UCI genuinely cannot answer ─────────────────────
    out.push(Check {
        name: "clock-correct",
        because: "the incident above was a WRONG CLOCK, and `ntp.enabled` only declares the \
                  intent to sync",
        verdict: Verdict::Unobservable(
            "UCI has no clock — read the device's HTTP `Date` header instead",
        ),
    });
    out.push(Check {
        name: "tailnet-logged-in",
        because: "a device can be enabled, running, and logged OUT — two of these routers were, \
                  after a network change",
        verdict: Verdict::Unobservable("run `tailscale status` on the device"),
    });

    out
}

/// Fit to ship? Only if nothing FAILED. Unobservables never count as passes.
#[must_use]
pub fn ready(checks: &[Check]) -> bool {
    !checks.iter().any(|c| matches!(c.verdict, Verdict::Fail(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disposition::Disposition;
    use crate::inventory::{Package, Section, SectionAddr};
    use std::collections::BTreeMap;

    fn sec(name: &str, ty: &str, kv: &[(&str, &str)]) -> Section {
        Section {
            addr: SectionAddr::Named(name.to_owned()),
            internal_name: name.to_owned(),
            section_type: ty.to_owned(),
            options: kv.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            secret_options: vec![],
        }
    }
    fn pkg(name: &str, s: Vec<Section>) -> Package {
        Package { name: name.to_owned(), disposition: Disposition::Managed, sections: s }
    }
    fn good() -> Inventory {
        Inventory {
            packages: vec![
                pkg("system", vec![
                    sec("ntp", "timeserver", &[("enabled", "1")]),
                    sec("system_0", "system", &[("hostname", "roteador-natal")]),
                ]),
                pkg("tailscale", vec![sec("settings", "settings", &[("enabled", "1")])]),
                pkg("roteador", vec![sec("fleet", "managed", &[("owner", "pleme-io")])]),
            ],
        }
    }

    #[test]
    fn a_correctly_prepared_router_is_ready() {
        let c = judge(&good(), Some(0));
        assert!(ready(&c), "failures: {:?}", c.iter().filter(|x| matches!(x.verdict, Verdict::Fail(_))).collect::<Vec<_>>());
    }

    #[test]
    fn every_check_detects_its_own_incident() {
        // ★ RED RUN. A readiness gate that has never failed is decoration.
        type Breaker = Box<dyn Fn(&mut Inventory)>;
        let cases: Vec<(&str, Breaker)> = vec![
            ("ntp-declared", Box::new(|i: &mut Inventory| {
                i.packages[0].sections[0].options.clear();
            })),
            ("hostname-not-factory", Box::new(|i: &mut Inventory| {
                i.packages[0].sections[1].options.insert("hostname".into(), "GL-MT6000".into());
            })),
            ("tailnet-declared", Box::new(|i: &mut Inventory| {
                i.packages[1].sections[0].options.clear();
            })),
            ("fleet-marker", Box::new(|i: &mut Inventory| {
                i.packages[2].sections[0].options.clear();
            })),
        ];
        for (name, break_it) in cases {
            let mut inv = good();
            break_it(&mut inv);
            let checks = judge(&inv, Some(0));
            let c = checks.iter().find(|c| c.name == name).expect("check exists");
            assert!(matches!(c.verdict, Verdict::Fail(_)), "{name} did not detect its own defect");
            assert!(!ready(&checks), "{name} failed but the router still read as ready");
        }
    }

    #[test]
    fn a_positional_section_is_refused() {
        let mut inv = good();
        inv.packages[0].sections.push(Section {
            addr: SectionAddr::Anonymous { section_type: "rule".into(), type_index: 0 },
            internal_name: "cfg01".into(),
            section_type: "rule".into(),
            options: BTreeMap::new(),
            secret_options: vec![],
        });
        assert!(!ready(&judge(&inv, Some(0))));
    }

    #[test]
    fn unobservable_is_never_a_pass_and_never_a_fail() {
        // It must not block shipping, and it must not be mistaken for evidence.
        let c = judge(&good(), None);
        let u = c.iter().find(|c| c.name == "clock-correct").unwrap();
        assert!(matches!(u.verdict, Verdict::Unobservable(_)));
        assert!(ready(&c), "an unobservable must not block");
        let staged = c.iter().find(|c| c.name == "no-uncommitted-changes").unwrap();
        assert!(matches!(staged.verdict, Verdict::Unobservable(_)), "unqueried != zero");
    }
}
