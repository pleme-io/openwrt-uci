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
use ubus_facade::json::Json;

/// The Helm values document for the managed set.
///
/// Shaped to drop straight into `charts/roteador-router` as an extra `-f`, so
/// the derived config composes with the hand-written router values rather than
/// replacing them.
#[must_use]
pub fn helm_values(inv: &Inventory) -> Json {
    let sections: Vec<Json> = inv
        .managed_sections()
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
    Json::obj([("sections", Json::Arr(sections))])
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
pub fn imports(inv: &Inventory) -> Json {
    let entries: Vec<Json> = inv
        .managed_sections()
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
        SectionAddr::Anonymous { section_type, type_index } => {
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
                ("sections", Json::Int(i64::try_from(p.sections.len()).unwrap_or(i64::MAX))),
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
                ("packagesOnDevice", Json::Int(i64::try_from(pkgs).unwrap_or(i64::MAX))),
                ("packagesManaged", Json::Int(i64::try_from(managed_pkgs).unwrap_or(i64::MAX))),
                ("sectionsOnDevice", Json::Int(i64::try_from(sections).unwrap_or(i64::MAX))),
                ("sectionsManaged", Json::Int(i64::try_from(managed_sections).unwrap_or(i64::MAX))),
                (
                    "sectionsManagedAnonymous",
                    Json::Int(i64::try_from(anonymous_managed).unwrap_or(i64::MAX)),
                ),
            ]),
        ),
        ("declined", Json::Arr(declined)),
    ])
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
                    sections: vec![
                        Section {
                            addr: SectionAddr::Named("lan".to_owned()),
                            section_type: "interface".to_owned(),
                            options: options.clone(),
                            secret_options: vec![],
                        },
                        Section {
                            addr: SectionAddr::Anonymous {
                                section_type: "device".to_owned(),
                                type_index: 2,
                            },
                            section_type: "device".to_owned(),
                            options: BTreeMap::new(),
                            secret_options: vec![],
                        },
                    ],
                },
                Package {
                    name: "wireless".to_owned(),
                    disposition: Disposition::SecretBearing { why: "psk" },
                    sections: vec![],
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
                ("openwrt_uci_section.network_device_2".to_owned(), "network.@device[2]".to_owned()),
                ("openwrt_uci_section.network_lan".to_owned(), "network.lan".to_owned()),
            ]
        );
        // The address must contain nothing terraform rejects.
        for (addr, _) in &got {
            assert!(
                addr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'),
                "illegal terraform address: {addr}"
            );
        }
    }

    #[test]
    fn a_secret_bearing_package_contributes_no_sections_to_values() {
        let rendered = helm_values(&inv()).render();
        assert!(!rendered.contains("wireless"), "secret pkg reached the values file");
        assert!(rendered.contains("network"));
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
