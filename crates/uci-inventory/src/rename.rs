//! Giving anonymous sections stable names, so they can be declared at all.
//!
//! # Why this is necessary and not tidying
//!
//! Measured on the live GL-MT6000: of the 80 sections in the managed packages,
//! **41 are anonymous** — and both independent sources agree on exactly which
//! (UCI's own `uci show` renders those 41 as `@type[N]`, and the inventory
//! finds the same 41 carrying UCI's internal `cfgXXXXXX` names; the two *named*
//! sets are identical, not merely the same size).
//!
//! An anonymous section has no stable identity:
//!
//! - `@rule[3]` is **positional**. Delete an earlier `rule` and every later
//!   address silently refers to a *different* section. Not an error — a wrong
//!   answer. On a household router the likeliest cause of that renumbering is
//!   somebody adding a rule in the vendor web UI, after which a reconciler
//!   would faithfully "correct" the wrong sections.
//! - `cfgXXXXXX` is UCI's **internal** name, derived from the file's layout, so
//!   it changes when the file is rewritten. Nothing may depend on it, which is
//!   precisely why renaming away from it cannot break a consumer.
//!
//! So declaring anonymous sections by either address bakes an identity into git
//! that the next edit invalidates. `uci rename` is the fix.
//!
//! # Why renaming is safe
//!
//! A UCI section name is a **label**. Renaming does not change what the config
//! means, and it is *additive* rather than destructive: `@type[N]` still
//! resolves after a rename. Consumers match on content — netifd finds a device
//! by its `name` option (`br-lan`), fw4 matches rules by type and fields — not
//! by the section label. And as above, the label being replaced is one UCI
//! itself treats as unstable.
//!
//! # The names
//!
//! Derived from the section's own content, so the same device yields the same
//! names every time and a reviewer can tell what a section IS from its
//! identity: `rule_allow_dhcp_renew`, not `rule_7`.
//!
//! # Applying them
//!
//! [`apply`] exists, and it is the one mutating path in this crate. It is an
//! **adoption** operation, the sibling of `terraform import`: renaming cannot
//! be expressed as ongoing declarative state, because declaring a section under
//! a new name would CREATE a second section rather than rename the first.
//!
//! Two properties make it safe to run against a live router:
//!
//! - **Renaming does not reload anything.** `uci rename` + `uci commit` rewrite
//!   the config file; they do not restart netifd or fw4. The running network is
//!   untouched, and the renamed file loads identically afterwards because the
//!   name is a label.
//! - **Renames are applied HIGHEST INDEX FIRST.** `@rule[3]` is positional, so
//!   renaming `@rule[0]` first would be fine — a rename does not remove a
//!   section from its type's ordering — but processing downward keeps every
//!   not-yet-applied address valid under any implementation, rather than
//!   relying on that.

use crate::inventory::{Package, SectionAddr};
use std::collections::BTreeSet;

/// Options consulted, in order, to name a section after its own content.
///
/// `name` first because `OpenWrt` already uses it as the human label for
/// firewall rules and zones. The rest are the fields that distinguish sections
/// of a type from each other, measured on the device.
const NAMING_OPTIONS: &[&str] = &[
    "name", "device", "interface", "target", "path", "id", "src", "dest", "ip", "proto", "port",
];

/// A proposed rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    pub package: String,
    /// The positional address, for a human reading the proposal.
    pub from: String,
    /// The address the rename is actually ISSUED against — UCI's internal
    /// section name.
    ///
    /// ★ Not the same as `from`, and that is the whole point. `uci.rename` over
    /// ubus accepts only this form; handed a positional `@type[N]` address it
    /// answers `{"ok": true}` and changes nothing. Measured the hard way: a
    /// 41-rename batch reported complete success and left the device untouched.
    pub internal: String,
    /// The proposed stable name.
    pub to: String,
    /// What the name was derived from, so a reviewer can judge it.
    pub derived_from: String,
}

/// Reduce a value to something UCI accepts as a section name.
///
/// UCI section names are `[A-Za-z0-9_]`, so everything else becomes `_`. Runs
/// collapse and edges are trimmed, or `192.168.8.1` would gain a trailing
/// underscore and `Allow--Ping` a doubled one.
fn slug(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut last_us = true; // suppress a leading underscore
    for c in v.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Propose stable names for every anonymous section in `pkg`.
///
/// Names are unique within the package: a collision gets a numeric suffix, and
/// a section with nothing to name it after falls back to `<type>_<index>`.
#[must_use]
pub fn propose(pkg: &Package) -> Vec<Rename> {
    let mut taken: BTreeSet<String> = pkg
        .sections
        .iter()
        .filter_map(|s| match &s.addr {
            SectionAddr::Named(n) => Some(n.clone()),
            SectionAddr::Anonymous { .. } => None,
        })
        .collect();

    let mut out = Vec::new();
    for s in &pkg.sections {
        let SectionAddr::Anonymous { section_type, type_index } = &s.addr else {
            continue;
        };
        let (base, derived_from) = NAMING_OPTIONS
            .iter()
            .find_map(|k| {
                let v = s.options.get(*k)?;
                let sl = slug(v);
                if sl.is_empty() {
                    return None;
                }
                Some((
                    format!("{}_{}", slug(section_type), sl),
                    format!("{k}={v}"),
                ))
            })
            .unwrap_or_else(|| {
                (
                    format!("{}_{}", slug(section_type), type_index),
                    format!("position (no naming option among {})", NAMING_OPTIONS.join("/")),
                )
            });

        // ── Uniqueness, resolved by adding INFORMATION where there is any ──
        //
        // A numeric suffix is the last resort, not the first. Two sections that
        // collide on their first naming option usually differ on a later one —
        // two `domain` entries share a `name` and differ by `ip`; two
        // `forwarding` entries share a `src` and differ by `dest` — and
        // `domain_console_gl_inet_com_2` tells a reviewer nothing about which
        // of the two it is, while `..._192_168_8_1` tells them everything.
        //
        // Deterministic either way: options are tried in NAMING_OPTIONS order.
        let mut name = base.clone();
        let mut extra = derived_from.clone();
        if taken.contains(&name) {
            for k in NAMING_OPTIONS {
                let Some(v) = s.options.get(*k) else { continue };
                let sl = slug(v);
                if sl.is_empty() || base.ends_with(&sl) {
                    continue;
                }
                let candidate = format!("{base}_{sl}");
                if !taken.contains(&candidate) {
                    name = candidate;
                    extra = format!("{derived_from}, {k}={v}");
                    break;
                }
            }
        }
        // Still colliding: nothing distinguishes them but position.
        let mut n = 2;
        while taken.contains(&name) {
            name = format!("{base}_{n}");
            n += 1;
        }
        taken.insert(name.clone());

        out.push(Rename {
            package: pkg.name.clone(),
            from: s.addr.as_uci(),
            internal: s.internal_name.clone(),
            to: name,
            derived_from: extra,
        });
    }
    out
}

/// Every proposed rename across the managed packages.
#[must_use]
pub fn propose_all(inv: &crate::inventory::Inventory) -> Vec<Rename> {
    inv.managed().flat_map(propose).collect()
}

/// Apply renames through the adapter, highest index first.
///
/// Returns the renames that were applied, in the order applied. Stops at the
/// first failure and returns it along with what had already succeeded — a
/// partial batch is committed and knowable, rather than rolled back into a
/// state nobody has looked at.
///
/// # Errors
///
/// The adapter error, plus the renames applied before it.
pub fn apply(
    adapter: &crate::adapter::Adapter,
    renames: &[Rename],
) -> Result<Vec<Rename>, (Vec<Rename>, crate::adapter::AdapterError)> {
    use ubus_facade::json::Json;

    // Highest index first, per the module docs.
    let mut ordered: Vec<&Rename> = renames.iter().collect();
    ordered.sort_by_key(|r| core::cmp::Reverse(index_of(&r.from)));

    let mut done = Vec::new();
    let mut packages: Vec<String> = Vec::new();
    for r in ordered {
        let req = Json::obj([
            ("config", Json::str(&r.package)),
            // The internal name, never `from` — see `Rename::internal`.
            ("section", Json::str(&r.internal)),
            ("name", Json::str(&r.to)),
        ]);
        if let Err(e) = adapter.post("/uci/rename", &req) {
            return Err((done, e));
        }
        // ★ VERIFY, because `{"ok": true}` was measured to be a lie for this
        // method. A write is not done because the call returned; it is done
        // because reading it back agrees.
        match adapter.post(
            "/uci/get",
            &Json::obj([
                ("config", Json::str(&r.package)),
                ("section", Json::str(&r.to)),
            ]),
        ) {
            Ok(_) => {}
            Err(e) => return Err((done, e)),
        }
        if !packages.contains(&r.package) {
            packages.push(r.package.clone());
        }
        done.push(r.clone());
    }
    // One commit per touched package: uci stages per-package, so committing
    // each once publishes that package's whole batch together.
    for p in &packages {
        if let Err(e) = adapter.post("/uci/commit", &Json::obj([("config", Json::str(p))])) {
            return Err((done, e));
        }
    }
    Ok(done)
}

/// The numeric index inside a positional address, for ordering.
fn index_of(addr: &str) -> usize {
    addr.rsplit_once('[')
        .and_then(|(_, tail)| tail.strip_suffix(']'))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disposition::Disposition;
    use crate::inventory::Section;

    fn anon(t: &str, i: usize, opts: &[(&str, &str)]) -> Section {
        Section {
            addr: SectionAddr::Anonymous { section_type: t.to_owned(), type_index: i },
            internal_name: format!("cfg{i:06x}"),
            section_type: t.to_owned(),
            options: opts.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            secret_options: vec![],
        }
    }
    fn pkg(sections: Vec<Section>) -> Package {
        Package {
            name: "firewall".to_owned(),
            disposition: Disposition::Managed,
            sections,
            secret_agreement: vec![],
        }
    }

    #[test]
    fn names_come_from_content_not_position() {
        let p = pkg(vec![anon("rule", 0, &[("name", "Allow-DHCP-Renew")])]);
        let r = propose(&p);
        assert_eq!(r[0].to, "rule_allow_dhcp_renew");
        assert_eq!(r[0].from, "@rule[0]");
        assert!(r[0].derived_from.contains("Allow-DHCP-Renew"));
    }

    #[test]
    fn slug_collapses_runs_and_trims_edges() {
        // `br-lan` and an IP are the two shapes that show up on the device.
        assert_eq!(slug("br-lan"), "br_lan");
        assert_eq!(slug("192.168.8.1"), "192_168_8_1");
        assert_eq!(slug("Allow--Ping!!"), "allow_ping");
        assert_eq!(slug("!!!"), "");
    }

    #[test]
    fn a_section_with_nothing_to_name_it_after_falls_back_to_position() {
        let p = pkg(vec![anon("defaults", 0, &[("input", "ACCEPT")])]);
        let r = propose(&p);
        assert_eq!(r[0].to, "defaults_0");
        assert!(r[0].derived_from.starts_with("position"));
    }

    #[test]
    fn a_collision_is_resolved_with_information_when_there_is_any() {
        // Measured shape: two `domain` sections share a name and differ by ip.
        // The second must say WHICH it is, not merely that it is the second.
        let p = pkg(vec![
            anon("domain", 0, &[("name", "console.gl-inet.com"), ("ip", "10.0.0.1")]),
            anon("domain", 1, &[("name", "console.gl-inet.com"), ("ip", "192.168.8.1")]),
        ]);
        let r = propose(&p);
        assert_eq!(r[0].to, "domain_console_gl_inet_com");
        assert_eq!(r[1].to, "domain_console_gl_inet_com_192_168_8_1");
        assert!(r[1].derived_from.contains("ip=192.168.8.1"));
    }

    #[test]
    fn a_numeric_suffix_is_the_last_resort_only() {
        // Genuinely indistinguishable except by position.
        let p = pkg(vec![
            anon("rule", 0, &[("name", "Allow-Ping")]),
            anon("rule", 1, &[("name", "Allow-Ping")]),
        ]);
        let r = propose(&p);
        assert_eq!(r[0].to, "rule_allow_ping");
        assert_eq!(r[1].to, "rule_allow_ping_2");
    }

    #[test]
    fn a_proposed_name_never_collides_with_an_existing_named_section() {
        let mut sections = vec![anon("rule", 0, &[("name", "wan_ssh")])];
        sections.push(Section {
            addr: SectionAddr::Named("rule_wan_ssh".to_owned()),
            internal_name: "rule_wan_ssh".to_owned(),
            section_type: "rule".to_owned(),
            options: std::collections::BTreeMap::new(),
            secret_options: vec![],
        });
        let r = propose(&pkg(sections));
        // The obvious name is taken by a real section, so the proposal moves.
        assert_eq!(r[0].to, "rule_wan_ssh_2");
    }

    #[test]
    fn named_sections_are_never_proposed_for_rename() {
        let p = pkg(vec![Section {
            addr: SectionAddr::Named("lan".to_owned()),
            internal_name: "lan".to_owned(),
            section_type: "zone".to_owned(),
            options: std::collections::BTreeMap::new(),
            secret_options: vec![],
        }]);
        assert!(propose(&p).is_empty());
    }

    #[test]
    fn a_proposal_carries_the_internal_name_separately_from_the_display_address() {
        // ★ This is the bug this test exists for. `uci.rename` over ubus accepts
        // ONLY the internal name; given `@rule[0]` it answers {"ok": true} and
        // changes nothing. A 41-rename batch once reported complete success and
        // left the device untouched. So the two must never be conflated, and
        // `internal` must be what the call is issued against.
        let p = pkg(vec![anon("rule", 0, &[("name", "Allow-Ping")])]);
        let r = propose(&p);
        assert_eq!(r[0].from, "@rule[0]", "display address");
        assert_eq!(r[0].internal, "cfg000000", "the address the call must use");
        assert_ne!(r[0].from, r[0].internal, "conflating these is the silent no-op");
    }

    #[test]
    fn positional_index_is_parsed_for_ordering() {
        assert_eq!(index_of("@rule[12]"), 12);
        assert_eq!(index_of("@defaults[0]"), 0);
        // A named address has no index; it sorts as 0 and is never in a batch.
        assert_eq!(index_of("lan"), 0);
    }

    #[test]
    fn proposals_are_deterministic() {
        let p = pkg(vec![
            anon("rule", 0, &[("name", "A")]),
            anon("rule", 1, &[("name", "B")]),
        ]);
        assert_eq!(propose(&p), propose(&p));
    }
}
