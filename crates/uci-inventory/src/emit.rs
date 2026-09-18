//! Turning an inventory into the artifacts that declare it.
//!
//! ★ TYPED EMISSION: every byte here comes from `ubus_facade::json::Json`, the
//! typed AST already used to emit the `OpenAPI` façade. Nothing in this module
//! formats JSON or YAML syntax by hand.
//!
//! JSON rather than YAML is a deliberate reuse rather than a compromise: JSON
//! is a subset of YAML 1.2 and Helm's parser accepts it, so `helm -f
//! derived.json` works and we did not have to grow a second emitter (and a
//! second class of quoting bug) to get a values file.

use crate::inventory::{Inventory, SectionAddr};
use crate::rename::Rename;
use ubus_facade::json::Json;

/// Which sections a derived values document should carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only sections with a stable identity — the safe default.
    StableOnly,
    /// Also sections addressed positionally (`@type[N]`).
    ///
    /// ★ Opt-in, because a positional address committed to git is a latent
    /// wrong answer rather than a latent error: inserting or deleting a section
    /// of the same type renumbers the rest, so a declaration keeps resolving —
    /// to a different section — and a reconciler then "corrects" whatever now
    /// sits at that index. Use only for a throwaway proof, or after the
    /// renames in [`crate::rename`] have been applied.
    IncludePositional,
}

/// The Helm values document for the managed set.
///
/// Shaped to drop straight into `charts/roteador-router` as an extra `-f`, so
/// the derived config composes with the hand-written router values rather than
/// replacing them.
///
/// Defaults to [`Scope::StableOnly`] because the output of this function is
/// meant to be COMMITTED, and the unstable half must not become committed
/// config by omission.
#[must_use]
pub fn helm_values_scoped(inv: &Inventory, scope: Scope) -> Json {
    let sections: Vec<Json> = inv
        .managed_sections()
        .filter(|(_, s)| scope == Scope::IncludePositional || !s.addr.is_anonymous())
        .map(|(pkg, s)| {
            let values: Vec<(String, Json)> = s
                .options
                .iter()
                .map(|(k, v)| (k.clone(), Json::str(v)))
                .collect();
            Json::obj([
                ("config", Json::str(pkg)),
                ("section", Json::str(s.addr.as_uci())),
                ("type", Json::str(&s.section_type)),
                ("values", Json::Obj(values)),
            ])
        })
        .collect();
    // ── ★ Secret-bearing packages contribute their STRUCTURAL options ─────
    // Previously they contributed nothing, so `wireless` was unmanageable
    // whole because one option in it is a PSK — while `channel`, `htmode`,
    // `disabled` and `ssid` sat right beside it, already classified
    // non-secret by the same authority that decides what to scrub.
    //
    // Safe because `uci set` MERGES (measured on a live GL-MT6000,
    // 2026-09-18: setting only `system.@system[0].zonename` left `hostname`
    // untouched), so a section declaring only structural options leaves every
    // undeclared option — the secret included — exactly as the device has it.
    //
    // Fail-closed: an option is emitted only when `option_is_secret` says it
    // is not secret. An unrecognised option is OMITTED, never guessed at.
    let mut sections = sections;
    for (pkg, sec) in inv.structural_sections() {
        if scope != Scope::IncludePositional && sec.addr.is_anonymous() {
            continue;
        }
        let values: Vec<(String, Json)> = sec
            .options
            .iter()
            // ★ ALLOWLIST, not a denylist. `!option_is_secret(k)` is
            // fail-OPEN: it emits anything not RECOGNISED as secret, which is
            // precisely the NordVPN case this crate already measured — a
            // bearer token in a field called `username` matches no secret
            // substring. Caught by
            // `an_unrecognised_option_in_a_secret_package_is_omitted`.
            //
            // `STRUCTURAL` is the capture side's existing allowlist of fields
            // kept verbatim while scrubbing. Reusing it keeps ONE authority
            // for "measurably not material" rather than minting a second list
            // that drifts.
            .filter(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                crate::capture::STRUCTURAL.contains(&lower.as_str())
                    && !crate::disposition::option_is_secret(k)
            })
            .map(|(k, v)| (k.clone(), Json::str(v)))
            .collect();
        // A section whose every option is secret contributes nothing: an
        // empty `values` would declare "this section has no options", which
        // is a claim about the device we have not measured and do not mean.
        if values.is_empty() {
            continue;
        }
        sections.push(Json::obj([
            ("config", Json::str(pkg)),
            ("section", Json::str(sec.addr.as_uci())),
            ("type", Json::str(&sec.section_type)),
            ("values", Json::Obj(values)),
        ]));
    }

    Json::obj([("sections", Json::Arr(sections))])
}

/// [`helm_values_scoped`] with the safe default scope.
#[must_use]
pub fn helm_values(inv: &Inventory) -> Json {
    helm_values_scoped(inv, Scope::StableOnly)
}

/// The import identities for the managed set, in terraform-address order.
///
/// Each entry is `{to, id}` — the shape a config-driven `import` block takes —
/// so the same document can be read by a human, fed to `tofu import`, or lifted
/// into Terraform JSON once magma's support for `import` blocks is confirmed.
///
/// `pending-declarative-import`: magma's handling of config-driven `import`
/// blocks is unmeasured, so today these are consumed by the CLI import path.
#[must_use]
pub fn imports_scoped(inv: &Inventory, scope: Scope) -> Json {
    let entries: Vec<Json> = inv
        .managed_sections()
        .filter(|(_, s)| scope == Scope::IncludePositional || !s.addr.is_anonymous())
        .map(|(pkg, s)| {
            Json::obj([
                ("to", Json::str(terraform_address(pkg, &s.addr))),
                ("id", Json::str(import_id(pkg, &s.addr))),
                ("anonymous", Json::Bool(s.addr.is_anonymous())),
            ])
        })
        .collect();
    Json::obj([("import", Json::Arr(entries))])
}

/// [`imports_scoped`] with the safe default scope.
#[must_use]
pub fn imports(inv: &Inventory) -> Json {
    imports_scoped(inv, Scope::StableOnly)
}

/// The `openwrt_uci_section.<name>` address for a section.
///
/// ★ A terraform address may hold only `[A-Za-z0-9_-]`, so an anonymous
/// section's `@type[N]` cannot be one. It is transliterated to `type_N`. The
/// resulting address is therefore POSITIONAL, and that is a real hazard rather
/// than a cosmetic one: deleting an earlier section of the same type renumbers
/// the rest, so the address keeps resolving — to a different section.
///
/// The fix is `uci rename` (see `SectionAddr::Anonymous`), not a cleverer
/// transliteration.
#[must_use]
pub fn terraform_address(package: &str, addr: &SectionAddr) -> String {
    let mut s = String::from("openwrt_uci_section.");
    s.push_str(package);
    s.push('_');
    match addr {
        SectionAddr::Named(n) => s.push_str(n),
        SectionAddr::Anonymous {
            section_type,
            type_index,
        } => {
            s.push_str(&section_type.replace('-', "_"));
            s.push('_');
            s.push_str(&type_index.to_string());
        }
    }
    s
}

/// The `<config>.<section>` id the provider's `ImportState` parses.
#[must_use]
pub fn import_id(package: &str, addr: &SectionAddr) -> String {
    let mut s = String::from(package);
    s.push('.');
    s.push_str(&addr.as_uci());
    s
}

/// A human-readable coverage report.
///
/// ★ Reports the DENOMINATOR, not just the numerator. "We manage 41 sections"
/// is the claim that rots downward; "41 of 432, and here is why we decline each
/// of the rest" is the claim that stays honest as the device changes.
#[must_use]
pub fn report(inv: &Inventory) -> Json {
    let (pkgs, managed_pkgs, sections, managed_sections) = inv.counts();
    let declined: Vec<Json> = inv
        .packages
        .iter()
        .filter(|p| !p.disposition.is_managed())
        .map(|p| {
            Json::obj([
                ("package", Json::str(&p.name)),
                ("disposition", Json::str(p.disposition.tag())),
                ("why", Json::str(p.disposition.why().unwrap_or(""))),
                (
                    "sections",
                    Json::Int(i64::try_from(p.sections.len()).unwrap_or(i64::MAX)),
                ),
            ])
        })
        .collect();
    let anonymous_managed = inv
        .managed_sections()
        .filter(|(_, s)| s.addr.is_anonymous())
        .count();
    Json::obj([
        (
            "coverage",
            Json::obj([
                (
                    "packagesOnDevice",
                    Json::Int(i64::try_from(pkgs).unwrap_or(i64::MAX)),
                ),
                (
                    "packagesManaged",
                    Json::Int(i64::try_from(managed_pkgs).unwrap_or(i64::MAX)),
                ),
                (
                    "sectionsOnDevice",
                    Json::Int(i64::try_from(sections).unwrap_or(i64::MAX)),
                ),
                (
                    "sectionsManaged",
                    Json::Int(i64::try_from(managed_sections).unwrap_or(i64::MAX)),
                ),
                (
                    "sectionsManagedAnonymous",
                    Json::Int(i64::try_from(anonymous_managed).unwrap_or(i64::MAX)),
                ),
            ]),
        ),
        ("declined", Json::Arr(declined)),
    ])
}

/// Proposed renames, as data a reviewer can read before anything is applied.
///
/// ★ A PROPOSAL, never an action. This crate does not mutate the device: a tool
/// that both decides 41 renames and performs them gives a reviewer nothing to
/// review, and the one thing worth reviewing here is whether each derived name
/// describes the section it will be attached to.
///
/// Deliberately emits the three STRUCTURED fields and no ready-to-paste shell
/// line. A `uci rename ...` string in this output would be an invitation to
/// apply 41 mutations through a shell, which is the authoring path the house
/// style exists to close — the applier should be typed, reading these fields.
#[must_use]
pub fn renames(rs: &[Rename]) -> Json {
    let items: Vec<Json> = rs
        .iter()
        .map(|r| {
            Json::obj([
                ("package", Json::str(&r.package)),
                ("from", Json::str(&r.from)),
                ("internal", Json::str(&r.internal)),
                ("to", Json::str(&r.to)),
                ("derivedFrom", Json::str(&r.derived_from)),
            ])
        })
        .collect();
    Json::obj([
        (
            "count",
            Json::Int(i64::try_from(rs.len()).unwrap_or(i64::MAX)),
        ),
        ("renames", Json::Arr(items)),
    ])
}

/// The `sections:` block as YAML, for a chart values file.
///
/// ★ Exists to delete a hand-rolled converter. The derive pipeline briefly
/// depended on an ad-hoc script that quoted YAML by guessing which strings
/// needed it — a class of bug that corrupts a router's declaration silently
/// and is caught only by an apply going wrong.
///
/// The quoting rule here is DELIBERATELY BLUNT: every scalar is emitted as a
/// double-quoted string with `"` and `\` escaped. UCI option values are
/// strings, so nothing is lost, and quoting everything removes the entire
/// question of which YAML plain-scalar forms would be reinterpreted as bools,
/// nulls, numbers or timestamps. `no`, `on`, `1.0` and `22:00` are all real
/// UCI values and all of them mean something else unquoted.
#[must_use]
pub fn helm_values_yaml(inv: &Inventory, scope: Scope) -> String {
    fn q(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }
    let mut o = String::from("sections:\n");
    let mut rows: Vec<(&str, &crate::inventory::Section)> = inv
        .managed_sections()
        .filter(|(_, s)| scope == Scope::IncludePositional || !s.addr.is_anonymous())
        .collect();
    rows.sort_by(|a, b| (a.0, a.1.addr.as_uci()).cmp(&(b.0, b.1.addr.as_uci())));
    for (pkg, s) in rows {
        o.push_str("  - config: ");
        o.push_str(&q(pkg));
        o.push_str("\n    section: ");
        o.push_str(&q(&s.addr.as_uci()));
        o.push_str("\n    type: ");
        o.push_str(&q(&s.section_type));
        if s.options.is_empty() {
            o.push_str("\n    values: {}\n");
        } else {
            o.push_str("\n    values:\n");
            for (k, v) in &s.options {
                o.push_str("      ");
                o.push_str(&q(k));
                o.push_str(": ");
                o.push_str(&q(v));
                o.push('\n');
            }
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disposition::Disposition;
    use crate::inventory::{Package, Section};
    use std::collections::BTreeMap;

    fn inv() -> Inventory {
        let mut options = BTreeMap::new();
        options.insert("proto".to_owned(), "static".to_owned());
        Inventory {
            packages: vec![
                Package {
                    name: "network".to_owned(),
                    disposition: Disposition::Managed,
                    secret_agreement: vec![],
                    sections: vec![
                        Section {
                            addr: SectionAddr::Named("lan".to_owned()),
                            internal_name: "lan".to_owned(),
                            section_type: "interface".to_owned(),
                            options: options.clone(),
                            secret_options: vec![],
                        },
                        Section {
                            addr: SectionAddr::Anonymous {
                                section_type: "device".to_owned(),
                                type_index: 2,
                            },
                            internal_name: "cfg0a0f15".to_owned(),
                            section_type: "device".to_owned(),
                            options: BTreeMap::new(),
                            secret_options: vec![],
                        },
                    ],
                },
                Package {
                    name: "wireless".to_owned(),
                    disposition: Disposition::SecretBearing { why: "psk" },
                    // ★ A REAL section. This was `vec![]`, which made
                    // `a_secret_bearing_package_contributes_no_sections_to_values`
                    // pass without ever exercising what it claimed to guard —
                    // an empty package contributes nothing under any rule.
                    sections: vec![Section {
                        addr: SectionAddr::Named("default_radio0".to_owned()),
                        internal_name: "default_radio0".to_owned(),
                        section_type: "wifi-iface".to_owned(),
                        options: {
                            let mut o = BTreeMap::new();
                            // structural — an operator tunes these
                            o.insert("ssid".to_owned(), "Buzios".to_owned());
                            o.insert("channel".to_owned(), "4".to_owned());
                            o.insert("htmode".to_owned(), "HE20".to_owned());
                            o.insert("disabled".to_owned(), "0".to_owned());
                            // the PSK — must never travel
                            o.insert("key".to_owned(), "hunter2-the-real-psk".to_owned());
                            // an option no list knows: fail-closed must omit it
                            o.insert("vendor_blob".to_owned(), "unclassified".to_owned());
                            o
                        },
                        secret_options: vec!["key".to_owned()],
                    }],
                    secret_agreement: vec![],
                },
            ],
        }
    }

    #[test]
    fn addresses_are_terraform_legal_and_ids_are_uci_legal() {
        let i = inv();
        let mut got: Vec<(String, String)> = i
            .managed_sections()
            .map(|(p, s)| (terraform_address(p, &s.addr), import_id(p, &s.addr)))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                (
                    "openwrt_uci_section.network_device_2".to_owned(),
                    "network.@device[2]".to_owned()
                ),
                (
                    "openwrt_uci_section.network_lan".to_owned(),
                    "network.lan".to_owned()
                ),
            ]
        );
        // The address must contain nothing terraform rejects.
        for (addr, _) in &got {
            assert!(
                addr.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'),
                "illegal terraform address: {addr}"
            );
        }
    }

    #[test]
    fn yaml_quotes_every_scalar_so_uci_values_survive() {
        // ★ `no`, `on`, `1.0`, `22:00` are all real UCI values and all mean
        // something else as YAML plain scalars. Quoting everything is what
        // makes this safe without a per-value decision.
        let mut options = BTreeMap::new();
        options.insert("a".to_owned(), "no".to_owned());
        options.insert("b".to_owned(), "1.0".to_owned());
        options.insert("c".to_owned(), "22:00".to_owned());
        let inv = Inventory {
            packages: vec![Package {
                name: "x".to_owned(),
                disposition: Disposition::Managed,
                secret_agreement: vec![],
                sections: vec![Section {
                    addr: SectionAddr::Named("s".to_owned()),
                    internal_name: "s".to_owned(),
                    section_type: "t".to_owned(),
                    options,
                    secret_options: vec![],
                }],
            }],
        };
        let y = helm_values_yaml(&inv, Scope::StableOnly);
        assert!(y.contains("\"a\": \"no\""), "got:\n{y}");
        assert!(y.contains("\"b\": \"1.0\""), "got:\n{y}");
        assert!(y.contains("\"c\": \"22:00\""), "got:\n{y}");
    }

    #[test]
    fn the_default_scope_excludes_positional_identities() {
        // inv() has one named and one anonymous managed section.
        let safe = helm_values(&inv()).render();
        assert!(safe.contains("\"section\": \"lan\""));
        assert!(
            !safe.contains("@device[2]"),
            "positional identity in committable output"
        );
        // And the opt-in includes it.
        let all = helm_values_scoped(&inv(), Scope::IncludePositional).render();
        assert!(all.contains("@device[2]"));
    }

    /// ★ THE SAFETY PROPERTY, and it is the one that must never weaken: a
    /// secret's VALUE never reaches the values file.
    #[test]
    fn a_secret_value_never_reaches_the_values_file() {
        let rendered = helm_values(&inv()).render();
        assert!(
            !rendered.contains("hunter2-the-real-psk"),
            "the PSK reached the values file: {rendered}"
        );
        assert!(
            !rendered.contains("\"key\""),
            "the secret OPTION must not be declared at all: {rendered}"
        );
    }

    /// ★ THE GAP THIS CLOSES. `wireless` used to contribute nothing because
    /// one option in it is a PSK, so `channel` and `htmode` — already
    /// classified non-secret by the same authority — were unmanageable.
    ///
    /// Safe because `uci set` MERGES: a section declaring only these leaves
    /// every undeclared option, the PSK included, as the device has it.
    #[test]
    fn a_secret_bearing_package_contributes_its_structural_options() {
        let rendered = helm_values(&inv()).render();
        assert!(rendered.contains("wireless"), "structural section missing");
        for structural in ["ssid", "channel", "htmode", "disabled"] {
            assert!(
                rendered.contains(structural),
                "{structural} is not secret and must be manageable: {rendered}"
            );
        }
        assert!(rendered.contains("network"), "managed packages still emit");
    }

    /// ★ FAIL-CLOSED. An option no list recognises is OMITTED, not guessed at.
    /// Name-matching alone was measured insufficient — NordVPN stores a bearer
    /// token in `wireguard.<peer>.username` — so anything unproven stays out.
    #[test]
    fn an_unrecognised_option_in_a_secret_package_is_omitted() {
        let rendered = helm_values(&inv()).render();
        assert!(
            !rendered.contains("vendor_blob"),
            "an unclassified option must not be emitted from a secret package: {rendered}"
        );
        assert!(
            !rendered.contains("unclassified"),
            "nor its value: {rendered}"
        );
    }

    #[test]
    fn the_report_states_the_denominator_and_the_reasons() {
        let r = report(&inv()).render();
        assert!(r.contains("packagesOnDevice"));
        assert!(r.contains("sectionsOnDevice"));
        // The decline must carry its reason, not just its name.
        assert!(r.contains("secret-bearing"));
        assert!(r.contains("psk"));
    }

    #[test]
    fn anonymous_managed_sections_are_counted_separately() {
        // They are the fragile ones, so the count is surfaced rather than
        // folded into the total.
        let r = report(&inv()).render();
        assert!(r.contains("sectionsManagedAnonymous"));
        assert!(r.contains("\"sectionsManagedAnonymous\": 1"));
    }
}
