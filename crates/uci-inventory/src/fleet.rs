//! Comparing N routers to each other — what the fleet agrees on, and what it does not.
//!
//! Every other module in this crate reasons about ONE device. This one takes
//! the rendered output of several and answers a question none of them can:
//! *which of these settings are the same everywhere, and is that on purpose?*
//!
//! # The problem this exists for
//!
//! Measured across three GL-MT6000s on 2026-09-12: of 558 distinct
//! `(config, section, option)` triples, **277 are byte-identical on all three**
//! — and only 51 of those were prescribed by any profile. The other **226 agree
//! by coincidence**: three independent onboardings happened to land on the same
//! value, and nothing whatsoever holds them there.
//!
//! That is not a harmless observation. A coincidence reads exactly like a
//! policy — same value, same everywhere, looks deliberate in every diff — so
//! the fleet looks standardized while a single re-derivation of one router can
//! silently end the agreement. Nothing errors, because nothing ever claimed it.
//!
//! ★ AND THE AGREEMENT IS NOT ALWAYS THE POLICY WE WANT. The same measurement
//! found `dropbear.main.PasswordAuth = "on"` and `RootPasswordAuth = "on"`
//! unanimous across all three. Freezing today's agreement as "the fleet
//! baseline" would have enshrined password SSH on every router as policy. So
//! this module REPORTS the agreement and refuses to call it intent — deciding
//! which constants are wanted is a human judgement, made once, in a profile.
//!
//! # What it does NOT do, deliberately
//!
//! It does not write a profile. Emitting the 226 into a generated profile would
//! create a second declaration of settings the per-router files already carry,
//! and the two would be free to disagree — the exact defect being measured, one
//! level up. The honest artifact is the DIVERGENCE VERDICT: a fleet-constant
//! set someone reviewed, and a gate that fails when it stops being constant.
//!
//! # Reading the inputs
//!
//! Input is the chart's own RENDERED output, read through [`crate::rendered`],
//! never the per-router values files. Two reasons. The rendered body is the
//! EFFECTIVE state — derived sections with role profiles already layered over
//! them — which is what actually reaches the device, and the per-router files
//! are not the only thing that decides it. And it reuses one tested extractor
//! rather than adding a YAML parser this crate deliberately does not have (see
//! `rendered`'s header on why that narrowness is the honest tier).

use crate::rendered::{self, RenderError};
use std::collections::BTreeMap;
use ubus_facade::json::Json;

/// One router's contribution: a name, and the settings its render declares.
pub struct Router {
    /// The fleet name, used in reports. Usually the CR name.
    pub name: String,
    /// `(config, section, option) -> value`, from the rendered Terraform body.
    settings: BTreeMap<(String, String, String), String>,
}

impl Router {
    /// Read one router from a rendered `InfrastructureTemplate` manifest.
    ///
    /// # Errors
    ///
    /// Any [`RenderError`] the manifest extraction produces.
    pub fn from_manifest(name: impl Into<String>, manifest: &str) -> Result<Self, RenderError> {
        let mut settings = BTreeMap::new();
        for (_addr, body) in rendered::sections(manifest)? {
            let Json::Obj(fields) = &body else { continue };
            let field = |k: &str| -> Option<String> {
                fields.iter().find(|(n, _)| n == k).and_then(|(_, v)| match v {
                    Json::Str(s) => Some(s.clone()),
                    _ => None,
                })
            };
            // ★ Identity is the PAIR (config, section) — a UCI fact, not a
            // convention. The terraform ADDRESS is not a substitute: it is a
            // flattened `config_section` string, so `network.lan_1` and
            // `network_lan.1` would collide into one key.
            let (Some(config), Some(section)) = (field("config"), field("section")) else {
                continue;
            };
            let values = fields.iter().find(|(n, _)| n == "values").map(|(_, v)| v);
            if let Some(Json::Obj(opts)) = values {
                for (opt, val) in opts {
                    if let Json::Str(s) = val {
                        settings.insert(
                            (config.clone(), section.clone(), opt.clone()),
                            s.clone(),
                        );
                    }
                }
            }
        }
        Ok(Self { name: name.into(), settings })
    }

    /// How many settings this router declares.
    #[must_use]
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Whether this router declares nothing — a render that produced no
    /// sections, which is a finding rather than an empty fleet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }
}

/// How the fleet relates on one `(config, section, option)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Every router declares it, and every value is identical.
    ///
    /// A candidate for policy — and only a candidate. See the module header on
    /// why unanimity is not intent.
    Constant,
    /// Every router declares it and the values differ. Genuinely per-router
    /// (an address, a MAC, a hostname) or a real divergence.
    Divergent,
    /// Some routers declare it and some do not.
    ///
    /// ★ NEVER a baseline candidate, and the reason is a write. A setting
    /// absent from a router is absent because that router has no such SECTION;
    /// prescribing it there would make the provider CREATE the section rather
    /// than update it, which is a mutation on a live device dressed as a
    /// default.
    Partial,
}

/// One `(config, section, option)` and what the fleet does with it.
pub struct Finding {
    pub config: String,
    pub section: String,
    pub option: String,
    pub agreement: Agreement,
    /// `(router name, value)` for every router that declares it, fleet order.
    pub values: Vec<(String, String)>,
}

impl Finding {
    /// The value all routers share, when they share one.
    #[must_use]
    pub fn constant_value(&self) -> Option<&str> {
        match self.agreement {
            Agreement::Constant => self.values.first().map(|(_, v)| v.as_str()),
            _ => None,
        }
    }
}

/// Why a fleet comparison could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetError {
    /// Fewer than two routers. Agreement is a relation; one router has nobody
    /// to agree with, and reporting "100% constant" for a fleet of one is the
    /// vacuous answer this refuses to give.
    TooFewRouters(usize),
    /// A router rendered no settings at all, so every comparison involving it
    /// would be silently narrowed. A REFUSAL, because the arithmetic still
    /// works: an empty router turns every other router's settings `Partial`
    /// and the report would read as a fleet in total disagreement.
    EmptyRouter(String),
}

impl core::fmt::Display for FleetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooFewRouters(n) => write!(
                f,
                "a fleet comparison needs at least 2 routers, got {n} — agreement is a \
                 relation, and a fleet of one agrees with itself vacuously"
            ),
            Self::EmptyRouter(name) => write!(
                f,
                "router {name:?} rendered no settings — refusing, because an empty router \
                 makes every other router's settings look PARTIAL and the report would \
                 read as total fleet disagreement rather than as a failed render"
            ),
        }
    }
}

/// The whole comparison.
pub struct Fleet {
    /// Router names, in the order given.
    pub routers: Vec<String>,
    /// Every `(config, section, option)` any router declares, sorted.
    pub findings: Vec<Finding>,
}

impl Fleet {
    /// Compare N routers.
    ///
    /// # Errors
    ///
    /// [`FleetError::TooFewRouters`] below two, [`FleetError::EmptyRouter`] if
    /// any router rendered nothing.
    pub fn compare(routers: &[Router]) -> Result<Self, FleetError> {
        if routers.len() < 2 {
            return Err(FleetError::TooFewRouters(routers.len()));
        }
        if let Some(r) = routers.iter().find(|r| r.is_empty()) {
            return Err(FleetError::EmptyRouter(r.name.clone()));
        }

        let mut keys: Vec<&(String, String, String)> = Vec::new();
        for r in routers {
            keys.extend(r.settings.keys());
        }
        keys.sort_unstable();
        keys.dedup();

        let findings = keys
            .into_iter()
            .map(|k| {
                let values: Vec<(String, String)> = routers
                    .iter()
                    .filter_map(|r| r.settings.get(k).map(|v| (r.name.clone(), v.clone())))
                    .collect();
                let agreement = if values.len() < routers.len() {
                    Agreement::Partial
                } else if values.iter().all(|(_, v)| v == &values[0].1) {
                    Agreement::Constant
                } else {
                    Agreement::Divergent
                };
                Finding {
                    config: k.0.clone(),
                    section: k.1.clone(),
                    option: k.2.clone(),
                    agreement,
                    values,
                }
            })
            .collect();

        Ok(Self {
            routers: routers.iter().map(|r| r.name.clone()).collect(),
            findings,
        })
    }

    /// Findings of one agreement class.
    #[must_use]
    pub fn of(&self, a: Agreement) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.agreement == a).collect()
    }

    /// Whether the fleet still agrees on everything a baseline pinned.
    ///
    /// `pinned` is the reviewed fleet-constant set as
    /// `(config, section, option) -> value`. A pin that is no longer Constant,
    /// or is Constant at a DIFFERENT value, is a breach.
    ///
    /// ★ Checks the VALUE, not just the class. An option that stayed unanimous
    /// while every router moved together is still a policy change, and a gate
    /// that only asked "is it still constant?" would pass it silently — which
    /// is the whole failure mode being gated against, reintroduced inside the
    /// gate.
    #[must_use]
    pub fn breaches(&self, pinned: &BTreeMap<(String, String, String), String>) -> Vec<Breach> {
        let mut out = Vec::new();
        for (key, want) in pinned {
            let found = self.findings.iter().find(|f| {
                f.config == key.0 && f.section == key.1 && f.option == key.2
            });
            match found {
                None => out.push(Breach {
                    config: key.0.clone(),
                    section: key.1.clone(),
                    option: key.2.clone(),
                    kind: BreachKind::Vanished,
                    want: want.clone(),
                    got: Vec::new(),
                }),
                Some(f) if f.agreement == Agreement::Constant => {
                    let got = f.constant_value().unwrap_or_default();
                    if got != want {
                        out.push(Breach {
                            config: key.0.clone(),
                            section: key.1.clone(),
                            option: key.2.clone(),
                            kind: BreachKind::ValueChanged,
                            want: want.clone(),
                            got: f.values.clone(),
                        });
                    }
                }
                Some(f) => out.push(Breach {
                    config: key.0.clone(),
                    section: key.1.clone(),
                    option: key.2.clone(),
                    kind: if f.agreement == Agreement::Partial {
                        BreachKind::NoLongerUniversal
                    } else {
                        BreachKind::Diverged
                    },
                    want: want.clone(),
                    got: f.values.clone(),
                }),
            }
        }
        out
    }
}

/// How a pinned constant stopped being one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachKind {
    /// Routers disagree where they used to agree.
    Diverged,
    /// A router stopped declaring it — it is no longer on every router.
    NoLongerUniversal,
    /// No router declares it any more.
    Vanished,
    /// Still unanimous, at a different value. A fleet-wide policy change.
    ValueChanged,
}

/// One pinned constant that no longer holds.
pub struct Breach {
    pub config: String,
    pub section: String,
    pub option: String,
    pub kind: BreachKind,
    pub want: String,
    pub got: Vec<(String, String)>,
}

/// The comparison as JSON.
#[must_use]
pub fn report(fleet: &Fleet) -> Json {
    let count = |a: Agreement| i64::try_from(fleet.of(a).len()).unwrap_or(i64::MAX);
    let detail = |a: Agreement| {
        Json::Arr(
            fleet
                .of(a)
                .into_iter()
                .map(|f| {
                    Json::obj([
                        ("config", Json::str(&f.config)),
                        ("section", Json::str(&f.section)),
                        ("option", Json::str(&f.option)),
                        (
                            "values",
                            Json::Obj(
                                f.values
                                    .iter()
                                    .map(|(r, v)| (r.clone(), Json::str(v)))
                                    .collect(),
                            ),
                        ),
                    ])
                })
                .collect(),
        )
    };
    Json::obj([
        (
            "routers",
            Json::Arr(fleet.routers.iter().map(Json::str).collect()),
        ),
        (
            "total",
            Json::Int(i64::try_from(fleet.findings.len()).unwrap_or(i64::MAX)),
        ),
        ("constant", Json::Int(count(Agreement::Constant))),
        ("divergent", Json::Int(count(Agreement::Divergent))),
        ("partial", Json::Int(count(Agreement::Partial))),
        // ★ Divergent is emitted in FULL and constant only as a count by
        // default: the divergences are what a reader acts on, and 277 constants
        // would bury them. `--all` widens it.
        ("divergences", detail(Agreement::Divergent)),
    ])
}

/// The reviewed fleet-constant set, as a pin file.
///
/// ★ AN ARRAY OF EXPLICIT FIELDS, never a map keyed `"config.section.option"`.
/// The flat-key form is what a reader reaches for and it cannot be parsed back:
/// splitting on `.` is ambiguous the moment any segment contains one, and the
/// failure is silent — a mis-split yields a pin naming a triple that no router
/// declares, which `breaches` then reports as `Vanished`. A gate that invents
/// breaches from its own file format is worse than no gate.
///
/// `report_all`'s `constants` map keeps the flat form deliberately: it is for a
/// human to read, and nothing parses it back.
#[must_use]
pub fn pin_file(fleet: &Fleet) -> Json {
    Json::Arr(
        fleet
            .of(Agreement::Constant)
            .into_iter()
            .filter_map(|f| {
                f.constant_value().map(|v| {
                    Json::obj([
                        ("config", Json::str(&f.config)),
                        ("section", Json::str(&f.section)),
                        ("option", Json::str(&f.option)),
                        ("value", Json::str(v)),
                    ])
                })
            })
            .collect(),
    )
}

/// Read a pin file back.
///
/// # Errors
///
/// A message naming what was wrong, never a partial pin: a pin file that loses
/// entries silently would shrink the gate's coverage while still passing.
pub fn read_pin(text: &str) -> Result<BTreeMap<(String, String, String), String>, String> {
    let doc = ubus_facade::json::parse(text.trim()).map_err(|e| format!("{e:?}"))?;
    let Json::Arr(items) = doc else {
        return Err("a pin file is an ARRAY of {config, section, option, value}".to_owned());
    };
    let mut out = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        let Json::Obj(fields) = item else {
            return Err(format!("pin[{i}] is not an object"));
        };
        let get = |k: &str| -> Option<String> {
            fields.iter().find(|(n, _)| n == k).and_then(|(_, v)| match v {
                Json::Str(s) => Some(s.clone()),
                _ => None,
            })
        };
        let (Some(c), Some(s), Some(o), Some(v)) =
            (get("config"), get("section"), get("option"), get("value"))
        else {
            return Err(format!(
                "pin[{i}] needs all four of config, section, option, value as strings"
            ));
        };
        out.insert((c, s, o), v);
    }
    Ok(out)
}

/// The comparison as JSON, including every constant.
#[must_use]
pub fn report_all(fleet: &Fleet) -> Json {
    let Json::Obj(mut pairs) = report(fleet) else {
        unreachable!("report builds an object")
    };
    let constants = Json::Obj(
        fleet
            .of(Agreement::Constant)
            .into_iter()
            .filter_map(|f| {
                f.constant_value()
                    .map(|v| (format!("{}.{}.{}", f.config, f.section, f.option), Json::str(v)))
            })
            .collect(),
    );
    pairs.push(("constants".to_owned(), constants));
    Json::Obj(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap section entries in the manifest shape `rendered` knows how to read.
    ///
    /// Built as a typed `Json` tree and rendered, never interpolated — the same
    /// rule the emitter follows (★★ TYPED EMISSION). A fixture assembled by
    /// string-joining is one missing brace away from testing the PARSER's error
    /// path while appearing to test this module, which is exactly what happened
    /// on the first run here: all 8 tests failed inside the fixture, not the
    /// code under test.
    fn manifest(sections: Vec<(String, Json)>) -> String {
        let tf = Json::obj([(
            "resource",
            Json::obj([("openwrt_uci_section", Json::Obj(sections))]),
        )]);
        let mut out = String::from(
            "apiVersion: pangea.pleme.io/v1alpha1\nkind: InfrastructureTemplate\n\
             metadata:\n  name: t\nspec:\n  source:\n    inline: |\n",
        );
        for line in tf.render().lines() {
            out.push_str("      ");
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn sect(
        addr: &str,
        config: &str,
        section: &str,
        opts: &[(&str, &str)],
    ) -> (String, Json) {
        (
            addr.to_owned(),
            Json::obj([
                ("config", Json::str(config)),
                ("section", Json::str(section)),
                (
                    "values",
                    Json::obj(opts.iter().map(|(k, v)| (*k, Json::str(*v)))),
                ),
            ]),
        )
    }

    fn router(name: &str, body: Vec<(String, Json)>) -> Router {
        Router::from_manifest(name, &manifest(body)).expect("renders")
    }

    #[test]
    fn constant_divergent_and_partial_are_three_different_answers() {
        let a = router(
            "a",
            vec![
                sect("s", "system", "sys", &[("zone", "UTC"), ("host", "a")]),
                sect("c", "chrony", "p", &[("iburst", "yes")]),
            ],
        );
        let b = router(
            "b",
            vec![sect("s", "system", "sys", &[("zone", "UTC"), ("host", "b")])],
        );
        let fleet = Fleet::compare(&[a, b]).expect("compares");

        // same everywhere
        assert_eq!(fleet.of(Agreement::Constant).len(), 1);
        assert_eq!(
            fleet.of(Agreement::Constant)[0].constant_value(),
            Some("UTC")
        );
        // present everywhere, different
        assert_eq!(fleet.of(Agreement::Divergent).len(), 1);
        assert_eq!(fleet.of(Agreement::Divergent)[0].option, "host");
        // only one router has it — NOT a baseline candidate
        assert_eq!(fleet.of(Agreement::Partial).len(), 1);
        assert_eq!(fleet.of(Agreement::Partial)[0].config, "chrony");
    }

    #[test]
    fn a_constant_value_has_no_constant_reading_when_it_is_not_constant() {
        let a = router("a", vec![sect("s", "system", "sys", &[("host", "a")])]);
        let b = router("b", vec![sect("s", "system", "sys", &[("host", "b")])]);
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        assert_eq!(fleet.findings[0].constant_value(), None);
    }

    #[test]
    fn one_router_is_refused_rather_than_reported_as_totally_constant() {
        let a = router("a", vec![sect("s", "system", "sys", &[("zone", "UTC")])]);
        assert_eq!(
            Fleet::compare(&[a]).err(),
            Some(FleetError::TooFewRouters(1))
        );
    }

    #[test]
    fn an_empty_router_is_refused_rather_than_making_the_fleet_look_divided() {
        // ★ The arithmetic WORKS with an empty router — every other router's
        // settings simply become Partial — which is exactly why it must refuse.
        // A failed render would otherwise read as a fleet that agrees on
        // nothing, and the reader would go looking for drift that is not there.
        let a = router("a", vec![sect("s", "system", "sys", &[("zone", "UTC")])]);
        let empty = Router { name: "b".to_owned(), settings: BTreeMap::new() };
        assert_eq!(
            Fleet::compare(&[a, empty]).err(),
            Some(FleetError::EmptyRouter("b".to_owned()))
        );
    }

    fn pin(items: &[(&str, &str, &str, &str)]) -> BTreeMap<(String, String, String), String> {
        items
            .iter()
            .map(|(c, s, o, v)| {
                ((c.to_string(), s.to_string(), o.to_string()), v.to_string())
            })
            .collect()
    }

    #[test]
    fn a_held_pin_is_no_breach() {
        let a = router("a", vec![sect("s", "system", "sys", &[("zone", "UTC")])]);
        let b = router("b", vec![sect("s", "system", "sys", &[("zone", "UTC")])]);
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        assert!(fleet
            .breaches(&pin(&[("system", "sys", "zone", "UTC")]))
            .is_empty());
    }

    #[test]
    fn a_fleet_wide_move_to_a_new_value_is_a_breach_though_still_unanimous() {
        // ★ THE CASE A CLASS-ONLY GATE MISSES. Both routers moved together, so
        // the option is still Constant — a gate asking only "is it constant?"
        // would pass a fleet-wide policy change in silence.
        let a = router("a", vec![sect("s", "dropbear", "main", &[("PasswordAuth", "on")])]);
        let b = router("b", vec![sect("s", "dropbear", "main", &[("PasswordAuth", "on")])]);
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        let breaches = fleet.breaches(&pin(&[("dropbear", "main", "PasswordAuth", "off")]));
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].kind, BreachKind::ValueChanged);
    }

    #[test]
    fn each_way_a_pin_can_break_is_reported_as_its_own_kind() {
        let a = router(
            "a",
            vec![
                sect("s", "system", "sys", &[("a", "1"), ("b", "1")]),
                sect("t", "network", "lan", &[("c", "1")]),
            ],
        );
        let b = router("b", vec![sect("s", "system", "sys", &[("a", "2")])]);
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        let breaches = fleet.breaches(&pin(&[
            ("system", "sys", "a", "1"),  // now divergent
            ("system", "sys", "b", "1"),  // b stopped declaring it
            ("network", "lan", "c", "1"), // only a has it
            ("gone", "gone", "gone", "1"),// nobody has it
        ]));
        let kind = |c: &str| {
            breaches
                .iter()
                .find(|b| b.config == c)
                .map(|b| b.kind)
                .expect("present")
        };
        assert_eq!(kind("system"), BreachKind::Diverged);
        assert_eq!(kind("network"), BreachKind::NoLongerUniversal);
        assert_eq!(kind("gone"), BreachKind::Vanished);
        // `system.sys.b` is Partial (only a declares it) -> NoLongerUniversal
        assert_eq!(breaches.len(), 4);
    }

    #[test]
    fn identity_is_the_pair_not_the_flattened_address() {
        // Two DIFFERENT sections whose flattened terraform addresses would
        // collide. Keying on the address would merge them and report one
        // option where there are two.
        let body = || {
            vec![
                sect("x", "network", "lan_1", &[("v", "a")]),
                sect("y", "network_lan", "1", &[("v", "b")]),
            ]
        };
        let a = router("a", body());
        let b = router("b", body());
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        assert_eq!(fleet.findings.len(), 2);
    }

    #[test]
    fn a_pin_file_round_trips_through_its_own_reader() {
        // ★ THE ANTI-VACUITY CHECK ON THE GATE ITSELF. A pin file that cannot
        // be read back produces a gate that reports breaches invented by its
        // own format. Emit, read, and compare against the fleet it came from.
        let a = router(
            "a",
            vec![sect("s", "system", "sys", &[("zone", "UTC"), ("n", "1")])],
        );
        let b = router(
            "b",
            vec![sect("s", "system", "sys", &[("zone", "UTC"), ("n", "1")])],
        );
        let fleet = Fleet::compare(&[a, b]).expect("compares");
        let text = pin_file(&fleet).render();
        let pinned = read_pin(&text).expect("reads back");
        assert_eq!(pinned.len(), 2);
        assert!(fleet.breaches(&pinned).is_empty());
    }

    #[test]
    fn a_value_containing_a_dot_survives_the_round_trip() {
        // The case the flat "config.section.option" key form loses. Real
        // instance: chrony's `threshold = "1.0"` and system `compat_version`.
        let body = || vec![sect("s", "chrony", "makestep_0", &[("threshold", "1.0")])];
        let fleet = Fleet::compare(&[router("a", body()), router("b", body())]).expect("ok");
        let pinned = read_pin(&pin_file(&fleet).render()).expect("reads back");
        assert_eq!(
            pinned.get(&(
                "chrony".to_owned(),
                "makestep_0".to_owned(),
                "threshold".to_owned()
            )),
            Some(&"1.0".to_owned())
        );
    }

    #[test]
    fn a_malformed_pin_is_refused_rather_than_silently_shortened() {
        // A pin file that dropped entries would shrink the gate's coverage
        // while still passing — the gate going quietly vacuous.
        assert!(read_pin("{}").is_err());
        assert!(read_pin(r#"[{"config":"a"}]"#).is_err());
        assert!(read_pin("not json").is_err());
    }
}
