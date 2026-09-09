//! The device's UCI surface, as typed data.

use crate::disposition::{Disposition, classify, option_is_secret};
use std::collections::BTreeMap;
use ubus_facade::json::Json;

/// How a section is addressed.
///
/// UCI has two kinds and they are not interchangeable, which is the single most
/// consequential fact about managing a router declaratively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionAddr {
    /// `config rule 'wan_ssh'` → addressed as `firewall.wan_ssh`. Stable.
    Named(String),
    /// `config rule` → addressed as `firewall.@rule[2]`.
    ///
    /// ★ POSITIONAL, and therefore fragile: removing an earlier section of the
    /// same type renumbers every later one, so a terraform address that was
    /// correct becomes an address for a DIFFERENT section rather than an error.
    /// `uci rename` converts one to `Named`, which is the real fix.
    Anonymous {
        /// The section type, which is what the index counts within.
        section_type: String,
        /// Position among sections OF THIS TYPE, in file order.
        ///
        /// ★ NOT the `.index` ubus reports. `.index` is the position within the
        /// whole package (counting every section of every type); `@type[N]`
        /// counts only sections of that type. Conflating them yields an address
        /// that resolves to the wrong section, silently.
        type_index: usize,
    },
}

impl SectionAddr {
    /// The `uci` address within its package.
    #[must_use]
    pub fn as_uci(&self) -> String {
        match self {
            Self::Named(n) => n.clone(),
            Self::Anonymous { section_type, type_index } => {
                let mut s = String::from("@");
                s.push_str(section_type);
                s.push('[');
                s.push_str(&type_index.to_string());
                s.push(']');
                s
            }
        }
    }

    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous { .. })
    }
}

/// One UCI section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub addr: SectionAddr,
    pub section_type: String,
    /// Options, with UCI bookkeeping (`.type`, `.name`, `.anonymous`, `.index`)
    /// already removed — those are not options and must never be emitted as if
    /// they were.
    pub options: BTreeMap<String, String>,
    /// Option names in this section that are secret-bearing.
    pub secret_options: Vec<String>,
}

/// One UCI package and what we do with it.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub disposition: Disposition,
    pub sections: Vec<Section>,
}

/// The whole device.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub packages: Vec<Package>,
}

/// Why a survey refused to produce an inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurveyError {
    /// A package exists on the device that the catalog has never heard of.
    ///
    /// The refusal that keeps coverage honest — see `disposition`'s module docs.
    Unclassified(Vec<String>),
    /// A package we declare turned out to hold secret material.
    ///
    /// Not a warning: emitting it would write a key into a values file. The
    /// package must be reclassified `SecretBearing`, or the option waived.
    ManagedPackageHoldsSecret {
        package: String,
        section: String,
        options: Vec<String>,
    },
    /// The device's answer was not the shape the adapter promises.
    Malformed(String),
}

impl core::fmt::Display for SurveyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unclassified(pkgs) => {
                f.write_str("these packages exist on the device but have no disposition: ")?;
                f.write_str(&pkgs.join(", "))?;
                f.write_str(
                    ". Add each to disposition::CATALOG — a package with no entry is refused \
                     rather than defaulted, so that a firmware upgrade cannot quietly add \
                     unmanaged config.",
                )
            }
            Self::ManagedPackageHoldsSecret { package, section, options } => {
                f.write_str("package ")?;
                f.write_str(package)?;
                f.write_str(" is classified `Managed` but ")?;
                f.write_str(section)?;
                f.write_str(" holds secret-bearing option(s): ")?;
                f.write_str(&options.join(", "))?;
                f.write_str(
                    ". Deriving this would put the value in git. Reclassify the package \
                     SecretBearing, or add the option to disposition::NOT_SECRET if it is \
                     measurably not material.",
                )
            }
            Self::Malformed(m) => {
                f.write_str("the device's answer was not the promised shape: ")?;
                f.write_str(m)
            }
        }
    }
}

/// Whether a section name is one UCI generated for an anonymous section.
///
/// `cfg` followed by hex, and nothing else. See the note at its call site for
/// why this is a cross-validated signal rather than a heuristic.
#[must_use]
pub fn is_uci_internal_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("cfg") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit())
}

fn obj<'a>(j: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Obj(pairs) = j {
        pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    } else {
        None
    }
}

/// Render a scalar option value as the string UCI round-trips.
///
/// ubus answers `.anonymous` as INT8 (type code 7, one byte) and `.index` as
/// INT32, so a decoder that only knew strings would drop them. Options
/// themselves are strings in UCI, but a numeric arm costs nothing and a silent
/// drop costs a wrong empty plan.
fn scalar(j: &Json) -> Option<String> {
    match j {
        Json::Str(s) => Some(s.clone()),
        Json::Int(n) => Some(n.to_string()),
        Json::Bool(b) => Some(if *b { "1".to_owned() } else { "0".to_owned() }),
        _ => None,
    }
}

/// Parse one package's `/uci/get {config}` answer into typed sections.
///
/// # Errors
///
/// [`SurveyError::Malformed`] if `values` is absent or not an object.
pub fn parse_package(name: &str, disposition: Disposition, body: &Json) -> Result<Package, SurveyError> {
    let values = obj(body, "values")
        .ok_or_else(|| SurveyError::Malformed(format!("{name}: no `values`")))?;
    let Json::Obj(entries) = values else {
        return Err(SurveyError::Malformed(format!("{name}: `values` is not an object")));
    };

    // Order by the package-wide `.index` so per-type counting matches file
    // order. Without this the type_index is whatever order the JSON happened
    // to arrive in, which is the exact bug that makes @type[N] point at the
    // wrong section.
    let mut raw: Vec<(&String, &Json)> = entries.iter().map(|(k, v)| (k, v)).collect();
    raw.sort_by_key(|(_, v)| {
        obj(v, ".index")
            .and_then(scalar)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(i64::MAX)
    });

    let mut per_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut sections = Vec::new();

    for (key, val) in raw {
        let section_type = obj(val, ".type")
            .and_then(scalar)
            .ok_or_else(|| SurveyError::Malformed(format!("{name}.{key}: no `.type`")))?;

        // ── ★ TWO SIGNALS FOR ANONYMITY, AND THE SECOND IS NOT A GUESS ──────
        //
        // `.anonymous` is the measurement and is preferred. But it arrives as
        // blobmsg INT8, and an adapter predating that decoding renders it as an
        // undecodable value — in which case every section reads as named, which
        // is the single worst way to be wrong here (a positional identity gets
        // committed as if it were stable).
        //
        // The fallback is UCI's own internal naming convention: an anonymous
        // section is given `cfg` + hex. That is not an inference — it was
        // cross-validated against UCI's authoritative rendering on the live
        // device (2026-09-09): of 80 sections in the managed packages, the 41
        // that `uci show` prints as `@type[N]` are exactly the 41 carrying a
        // `cfg`-hex name, and the two NAMED sets were identical, not merely the
        // same size.
        //
        // Applied only when `.anonymous` is undecodable, so a real measurement
        // always wins. A user could pathologically name a section `cfg0a1b`;
        // the cost is one wrongly-proposed rename in a proposal a human reads.
        let anonymous = match obj(val, ".anonymous").and_then(scalar) {
            Some(s) => s == "1" || s.eq_ignore_ascii_case("true"),
            None => is_uci_internal_name(key),
        };

        let seen = per_type.entry(section_type.clone()).or_insert(0);
        let type_index = *seen;
        *seen += 1;

        let addr = if anonymous {
            SectionAddr::Anonymous { section_type: section_type.clone(), type_index }
        } else {
            // `.name` is authoritative; the map key equals it for named
            // sections but relying on the key would break the day it does not.
            SectionAddr::Named(obj(val, ".name").and_then(scalar).unwrap_or_else(|| key.clone()))
        };

        let mut options = BTreeMap::new();
        let mut secret_options = Vec::new();
        if let Json::Obj(fields) = val {
            for (k, v) in fields {
                if k.starts_with('.') {
                    continue; // UCI bookkeeping, not an option
                }
                if option_is_secret(k) {
                    secret_options.push(k.clone());
                    continue; // never carried into the inventory
                }
                if let Some(s) = scalar(v) {
                    options.insert(k.clone(), s);
                }
                // A non-scalar option (a UCI list) is deliberately skipped here
                // rather than flattened: the resource's `values` is a
                // map-of-string, so a list has no representation yet. See
                // `pending-uci-lists` in the crate docs.
            }
        }
        secret_options.sort_unstable();

        sections.push(Section { addr, section_type, options, secret_options });
    }

    Ok(Package { name: name.to_owned(), disposition, sections })
}

/// Assemble an inventory, refusing anything unaccounted for.
///
/// `packages` is `(name, body)` as answered by `/uci/get {config}`.
///
/// # Panics
///
/// Never in practice: the `expect` re-reads a classification already proven
/// present by the filter immediately above it. It is an `expect` rather than a
/// restructure because threading the `Disposition` out of the filter would
/// obscure that the unclassified check is a whole-set gate, not a per-item one.
///
/// # Errors
///
/// [`SurveyError::Unclassified`] naming every package with no catalog entry
/// (reported together, so one run tells you the whole gap rather than the
/// first item of it), or [`SurveyError::ManagedPackageHoldsSecret`].
pub fn survey(packages: &[(String, Json)]) -> Result<Inventory, SurveyError> {
    let mut unclassified: Vec<String> = packages
        .iter()
        .filter(|(n, _)| classify(n).is_none())
        .map(|(n, _)| n.clone())
        .collect();
    if !unclassified.is_empty() {
        unclassified.sort_unstable();
        return Err(SurveyError::Unclassified(unclassified));
    }

    let mut out = Inventory::default();
    for (name, body) in packages {
        let d = classify(name).expect("checked above");
        let pkg = parse_package(name, d, body)?;
        if d.is_managed()
            && let Some(s) = pkg.sections.iter().find(|s| !s.secret_options.is_empty())
        {
            {
                return Err(SurveyError::ManagedPackageHoldsSecret {
                    package: pkg.name.clone(),
                    section: s.addr.as_uci(),
                    options: s.secret_options.clone(),
                });
            }
        }
        out.packages.push(pkg);
    }
    Ok(out)
}

impl Inventory {
    /// Packages we declare.
    pub fn managed(&self) -> impl Iterator<Item = &Package> {
        self.packages.iter().filter(|p| p.disposition.is_managed())
    }

    /// Sections we declare, as `(package, section)`.
    pub fn managed_sections(&self) -> impl Iterator<Item = (&str, &Section)> {
        self.managed()
            .flat_map(|p| p.sections.iter().map(move |s| (p.name.as_str(), s)))
    }

    /// Counts for a report: (packages, managed packages, sections, managed sections).
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.packages.len(),
            self.managed().count(),
            self.packages.iter().map(|p| p.sections.len()).sum(),
            self.managed_sections().count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_json(src: &str) -> Json {
        ubus_facade::json::parse(src).expect("test fixture parses")
    }

    #[test]
    fn type_index_counts_within_type_not_within_package() {
        // Three sections: rule, zone, rule. The second rule is @rule[1] and the
        // zone is @zone[0] — NOT @rule[1]/@zone[1] as a package-wide counter
        // would give. This is the trap the doc comment names.
        let body = pkg_json(
            r#"{"values":{
                "a":{".type":"rule",".anonymous":1,".index":0,"target":"ACCEPT"},
                "b":{".type":"zone",".anonymous":1,".index":1,"name":"lan"},
                "c":{".type":"rule",".anonymous":1,".index":2,"target":"DROP"}
            }}"#,
        );
        let p = parse_package("firewall", Disposition::Managed, &body).expect("parses");
        let addrs: Vec<String> = p.sections.iter().map(|s| s.addr.as_uci()).collect();
        assert_eq!(addrs, vec!["@rule[0]", "@zone[0]", "@rule[1]"]);
    }

    #[test]
    fn index_order_decides_position_not_map_order() {
        // Same three sections, keys chosen so alphabetical order disagrees with
        // `.index`. If the parser trusted map order, z would be @rule[0].
        let body = pkg_json(
            r#"{"values":{
                "z":{".type":"rule",".anonymous":1,".index":2,"target":"LAST"},
                "a":{".type":"rule",".anonymous":1,".index":0,"target":"FIRST"}
            }}"#,
        );
        let p = parse_package("firewall", Disposition::Managed, &body).expect("parses");
        assert_eq!(p.sections[0].options["target"], "FIRST");
        assert_eq!(p.sections[0].addr.as_uci(), "@rule[0]");
    }

    #[test]
    fn uci_internal_names_are_recognised_exactly() {
        assert!(is_uci_internal_name("cfg030f15"));
        assert!(is_uci_internal_name("cfg0a1b2c"));
        // Not internal: no hex tail, non-hex chars, or a different prefix.
        assert!(!is_uci_internal_name("cfg"));
        assert!(!is_uci_internal_name("cfgzz"));
        assert!(!is_uci_internal_name("config1"));
        assert!(!is_uci_internal_name("lan"));
        assert!(!is_uci_internal_name("wan_ssh"));
    }

    #[test]
    fn a_measured_anonymous_flag_beats_the_name_fallback() {
        // `.anonymous: 0` on a cfg-looking name: the MEASUREMENT wins, so this
        // stays named and is never proposed for rename.
        let body = pkg_json(
            r#"{"values":{"cfg0a1b":{".type":"rule",".name":"cfg0a1b",".anonymous":0,".index":0}}}"#,
        );
        let p = parse_package("firewall", Disposition::Managed, &body).expect("parses");
        assert_eq!(p.sections[0].addr, SectionAddr::Named("cfg0a1b".to_owned()));
    }

    #[test]
    fn the_fallback_applies_only_when_anonymous_is_undecodable() {
        // No `.anonymous` at all (an adapter that could not decode INT8) plus a
        // cfg-hex name: treated as anonymous, so it gets a positional address
        // and becomes a rename candidate rather than a fake stable identity.
        let body = pkg_json(
            r#"{"values":{"cfg0a1b":{".type":"rule",".name":"cfg0a1b",".index":0}}}"#,
        );
        let p = parse_package("firewall", Disposition::Managed, &body).expect("parses");
        assert_eq!(p.sections[0].addr.as_uci(), "@rule[0]");
        // ...and a genuinely-named section under the same conditions does not.
        let body2 = pkg_json(r#"{"values":{"lan":{".type":"rule",".name":"lan",".index":0}}}"#);
        let p2 = parse_package("firewall", Disposition::Managed, &body2).expect("parses");
        assert_eq!(p2.sections[0].addr, SectionAddr::Named("lan".to_owned()));
    }

    #[test]
    fn named_sections_use_dot_name_not_the_map_key() {
        let body = pkg_json(
            r#"{"values":{"cfg01":{".type":"interface",".name":"lan",".anonymous":0,".index":0,"proto":"static"}}}"#,
        );
        let p = parse_package("network", Disposition::Managed, &body).expect("parses");
        assert_eq!(p.sections[0].addr, SectionAddr::Named("lan".to_owned()));
    }

    #[test]
    fn uci_bookkeeping_never_becomes_an_option() {
        let body = pkg_json(
            r#"{"values":{"lan":{".type":"interface",".name":"lan",".anonymous":0,".index":0,"proto":"static"}}}"#,
        );
        let p = parse_package("network", Disposition::Managed, &body).expect("parses");
        assert_eq!(p.sections[0].options.keys().collect::<Vec<_>>(), vec!["proto"]);
    }

    #[test]
    fn a_managed_package_holding_a_secret_is_refused() {
        // The whole point: this must not silently emit the key.
        let body = pkg_json(
            r#"{"values":{"w":{".type":"wifi-iface",".name":"w",".anonymous":0,".index":0,"key":"hunter2"}}}"#,
        );
        // `network` is Managed in the catalog; pretend it grew a key.
        let err = survey(&[("network".to_owned(), body)]).expect_err("must refuse");
        match err {
            SurveyError::ManagedPackageHoldsSecret { options, .. } => {
                assert_eq!(options, vec!["key".to_owned()]);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn secret_values_never_reach_the_inventory_even_when_allowed() {
        // A SecretBearing package is surveyed (we still want to KNOW it exists
        // and how many sections it has) but its secret values are dropped.
        let body = pkg_json(
            r#"{"values":{"wg":{".type":"peer",".name":"wg",".anonymous":0,".index":0,"key":"PRIVATE","port":"51820"}}}"#,
        );
        let inv = survey(&[("wireguard".to_owned(), body)]).expect("secret pkgs survey fine");
        let s = &inv.packages[0].sections[0];
        assert!(!s.options.contains_key("key"), "secret value leaked into inventory");
        assert_eq!(s.options["port"], "51820");
        assert_eq!(s.secret_options, vec!["key".to_owned()]);
    }

    #[test]
    fn an_unclassified_package_refuses_and_names_all_of_them() {
        let body = pkg_json(r#"{"values":{}}"#);
        let err = survey(&[
            ("brand_new_thing".to_owned(), body.clone()),
            ("network".to_owned(), body.clone()),
            ("another_new_thing".to_owned(), body),
        ])
        .expect_err("must refuse");
        match err {
            // Both, sorted — one run shows the whole gap.
            SurveyError::Unclassified(p) => assert_eq!(p, vec!["another_new_thing", "brand_new_thing"]),
            other => panic!("wrong error: {other:?}"),
        }
    }
}
