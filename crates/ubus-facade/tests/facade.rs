//! Catalog and façade tests, anchored to a real device capture.
//!
//! The load-bearing one is [`the_committed_spec_is_exactly_what_the_generator_emits`]:
//! the spec is OUTPUT plus a byte-exact test, never a maintained artifact. Drift
//! is a red test rather than a stale document — the same discipline as `crdgen`.

use ubus_facade::catalog::{Catalog, CatalogError, UbusType};

const CAPTURE: &str = include_str!("fixtures/ubus-v-list.txt");
const GOLDEN: &str = include_str!("fixtures/ubus-facade.openapi.json");

#[test]
fn the_capture_parses_to_the_counts_we_measured() {
    let c = Catalog::parse(CAPTURE).expect("the real capture must parse");
    // Independently reproducible: `grep -c "^'"` and `grep -c '^\t"'` on the
    // fixture give 50 and 264. Those are the numbers `docs/roteador.md` §4
    // records, so this pins the doc's claim to the artifact.
    assert_eq!(c.objects.len(), 50, "objects");
    assert_eq!(c.method_count(), 264, "methods");
}

/// ★ THE test this crate exists for: the committed spec is regenerable.
///
/// If this fails, either the generator changed or the fixture did. Both are real
/// events that deserve a diff — and neither is a document someone forgot to
/// update, which is the failure mode a hand-maintained façade over 264
/// operations has.
#[test]
fn the_committed_spec_is_exactly_what_the_generator_emits() {
    let emitted = ubus_facade::generate(CAPTURE).expect("generation must succeed");
    assert_eq!(
        emitted, GOLDEN,
        "the committed façade is not what the generator emits — regenerate with \
         `cargo run -p ubus-facade -- crates/ubus-facade/tests/fixtures/ubus-v-list.txt \
         > crates/ubus-facade/tests/fixtures/ubus-facade.openapi.json` and review the diff"
    );
}

#[test]
fn the_spec_has_one_operation_per_method() {
    // A count, not a spot check. This is the anti-vacuity half: a generator that
    // silently emitted nothing would pass every assertion about the shape of
    // what it did emit.
    let c = Catalog::parse(CAPTURE).unwrap();
    assert_eq!(GOLDEN.matches("\"operationId\"").count(), c.method_count());
    assert_eq!(
        GOLDEN.matches("\"x-ubus-object\"").count(),
        c.method_count()
    );
}

/// `ubus_rpc_session` is dropped from the schema but remembered as a fact.
#[test]
fn the_rpcd_session_parameter_is_dropped_but_its_requirement_is_recorded() {
    let c = Catalog::parse(CAPTURE).unwrap();
    let uci = c
        .objects
        .iter()
        .find(|o| o.path == "uci")
        .expect("the capture has a uci object");

    for m in &uci.methods {
        assert!(
            !m.params.iter().any(|p| p.name == "ubus_rpc_session"),
            "uci.{} still carries the rpcd session parameter",
            m.name
        );
    }

    // Measured 2026-09-08: apply/confirm/rollback enforce the session; get/set/
    // add/commit/revert/changes do not, though all of them DECLARE it. The
    // declaration is what this flag records.
    let apply = uci.methods.iter().find(|m| m.name == "apply").unwrap();
    assert!(apply.needs_rpcd_session);
    assert!(GOLDEN.contains("\"x-ubus-requires-rpcd-session\""));

    // And it must not have leaked into the emitted document anywhere.
    assert!(
        !GOLDEN.contains("ubus_rpc_session"),
        "the rpcd session parameter reached the generated spec"
    );
}

/// ★ A parameter the device declines to describe must not vanish.
#[test]
fn an_undescribed_parameter_is_counted_and_opens_the_schema() {
    let c = Catalog::parse(CAPTURE).unwrap();
    let m = c
        .objects
        .iter()
        .find(|o| o.path == "cellular.collect")
        .and_then(|o| o.methods.iter().find(|m| m.name == "clean_traffic"))
        .expect("the capture has cellular.collect/clean_traffic");

    assert_eq!(m.undescribed_params, 1, "the bare `(unknown)` field");
    // Its described siblings survive alongside it.
    assert_eq!(m.params.len(), 3, "bus, slot, type");

    // A method with an undescribed parameter must keep an OPEN schema, or a
    // generated client would refuse a call the device accepts.
    assert!(GOLDEN.contains("\"x-ubus-undescribed-params\""));
}

#[test]
fn a_closed_schema_is_the_default_for_fully_described_methods() {
    // The complement of the test above: the relaxation must be the exception.
    let closed = GOLDEN.matches("\"additionalProperties\": false").count();
    let open = GOLDEN.matches("\"additionalProperties\": true").count();
    assert_eq!(open, 1, "exactly one method is incompletely described");
    assert_eq!(closed, 263, "every other method is closed");
}

/// ★ Every `array` property must carry an `items` schema.
///
/// `OpenAPI` 3.0 makes `items` MANDATORY on `type: array`. Omitting it — which is
/// what "we did not measure the element type" naively suggests — produced a
/// document that `forge-gen validate` accepted with **no warnings** while
/// `openapi-generator-cli` refused outright, once per array parameter (45).
///
/// The fix is not a guessed element type: an EMPTY `items` schema is `OpenAPI`'s
/// own way of writing "any value", so it constrains nothing and invents
/// nothing.
///
/// The generalizable lesson, and the reason this test exists rather than a
/// comment: **a passing validator is not evidence that a generator will accept
/// the spec.** Only running a generator is.
#[test]
fn every_array_property_carries_an_items_schema() {
    let c = Catalog::parse(CAPTURE).unwrap();
    let arrays = c
        .objects
        .iter()
        .flat_map(|o| &o.methods)
        .flat_map(|m| &m.params)
        .filter(|p| p.ty == UbusType::Array)
        .count();
    assert_eq!(arrays, 45, "the capture's array parameters");
    assert_eq!(
        GOLDEN.matches("\"items\"").count(),
        arrays,
        "one items schema per array property, or openapi-generator-cli refuses \
         the document"
    );
    assert!(
        GOLDEN.contains("\"items\": {}"),
        "empty schema, not a guess"
    );
}

#[test]
fn object_ids_never_reach_the_spec() {
    // The capture is full of `@575a75e0`. They are ephemeral, so baking one in
    // would make the golden diff fail after any reboot — drift with no defect.
    assert!(CAPTURE.contains('@'), "the capture does carry ids");
    assert!(
        !GOLDEN.contains("575a75e0"),
        "an ephemeral object id reached the generated spec"
    );
}

#[test]
fn dotted_object_names_become_valid_operation_ids() {
    let id = ubus_facade::openapi::operation_id("cellular.cm", "cm_get_status");
    assert_eq!(id, "cellular_cm__cm_get_status");
    assert!(GOLDEN.contains("cellular_cm__cm_get_status"));
    // The path keeps the real name; only the identifier is sanitized.
    assert!(GOLDEN.contains("\"/cellular.cm/cm_get_status\""));
}

// ---- refusals: the parser must not paper over a shape it does not know ----

#[test]
fn an_unmeasured_parameter_type_is_refused_not_defaulted() {
    // Defaulting to `string` would put a lying schema into a generated provider,
    // and it would be discovered by a failed apply rather than here.
    let err = Catalog::parse("'x' @1\n\t\"m\":{\"p\":\"Float128\"}\n").expect_err("must refuse");
    assert!(
        matches!(err, CatalogError::UnknownType { ref ty, .. } if ty == "Float128"),
        "{err}"
    );
}

#[test]
fn a_method_before_any_object_is_refused() {
    let err = Catalog::parse("\t\"m\":{}\n").expect_err("must refuse");
    assert!(matches!(err, CatalogError::Malformed { .. }), "{err}");
}

#[test]
fn an_unrecognised_line_is_refused_rather_than_skipped() {
    // A skipped line yields a catalog that is quietly short, which generates a
    // façade missing operations nobody notices are absent.
    let err = Catalog::parse("'x' @1\nrubbish\n").expect_err("must refuse");
    assert!(
        matches!(err, CatalogError::Malformed { line_no: 2, .. }),
        "{err}"
    );
}

#[test]
fn a_method_with_no_parameters_is_valid_and_empty() {
    let c = Catalog::parse("'x' @1\n\t\"reload_config\":{}\n").expect("valid");
    assert_eq!(c.method_count(), 1);
    assert!(c.objects[0].methods[0].params.is_empty());
    assert_eq!(c.objects[0].methods[0].undescribed_params, 0);
}

#[test]
fn every_measured_type_maps_to_a_json_schema_type() {
    // A matrix over the closed set, so adding a variant without deciding its
    // JSON mapping cannot compile.
    for (t, want) in [
        (UbusType::String, "string"),
        (UbusType::Integer, "integer"),
        (UbusType::Boolean, "boolean"),
        (UbusType::Table, "object"),
        (UbusType::Array, "array"),
    ] {
        assert_eq!(t.json_type(), want);
    }
}

#[test]
fn the_emitted_document_is_valid_json() {
    // No JSON parser here (zero dependencies), so this checks the properties a
    // hand-rolled renderer gets wrong: balance, and no raw control characters
    // inside the document. Both are cheap and both are real failure modes.
    let s = ubus_facade::generate(CAPTURE).unwrap();
    // Compared as counts rather than a signed difference: no casts, and the
    // failure message shows both numbers instead of a delta.
    assert_eq!(
        s.matches('{').count(),
        s.matches('}').count(),
        "unbalanced braces"
    );
    assert_eq!(
        s.matches('[').count(),
        s.matches(']').count(),
        "unbalanced brackets"
    );
    assert!(
        !s.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
        "a raw control character would make the document invalid"
    );
    assert!(s.ends_with("}\n"), "one trailing newline");
}

// ---- the binding between the façade and the IaC resource specs ----

/// ★ Every schema a resource spec names must exist in the façade.
///
/// `iac-forge`'s `CrudMapping` binds a resource to its operations by schema
/// NAME (`create_schema`, `read_schema`, `update_schema`, `delete_schema`). A
/// name with no matching component is not caught by either artifact alone: the
/// TOML parses, the spec validates, and the failure appears when a generator
/// resolves the reference — or worse, generates a resource missing an
/// operation.
///
/// So this is a CROSS-ARTIFACT invariant, and it is checked here because here
/// is the only place both artifacts are in scope. Parsed by hand rather than
/// with a TOML crate to keep this workspace dependency-free; the shape being
/// matched (`x_schema = "Name"`) is fixed by `CrudMapping`.
#[test]
fn every_schema_named_by_a_resource_spec_exists_in_the_facade() {
    const SPEC: &str = include_str!("../../../resources/openwrt_uci_section.toml");

    let named: Vec<&str> = SPEC
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (key, value) = l.split_once('=')?;
            key.trim()
                .ends_with("_schema")
                .then(|| value.trim().trim_matches('"'))
        })
        .collect();

    assert_eq!(
        named.len(),
        4,
        "expected create/read/update/delete schema bindings, got {named:?}"
    );

    for name in &named {
        // The component must be DEFINED, not merely mentioned — a `$ref` to it
        // from a path would satisfy a naive `contains`.
        assert!(
            GOLDEN.contains(&format!("\"{name}\": {{")),
            "resource spec names schema {name:?}, which the façade does not define"
        );
    }
}

/// The endpoints a resource spec names must exist as façade paths too.
#[test]
fn every_endpoint_named_by_a_resource_spec_exists_in_the_facade() {
    const SPEC: &str = include_str!("../../../resources/openwrt_uci_section.toml");

    let endpoints: Vec<&str> = SPEC
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (key, value) = l.split_once('=')?;
            key.trim()
                .ends_with("_endpoint")
                .then(|| value.trim().trim_matches('"'))
        })
        .collect();

    assert_eq!(endpoints.len(), 4, "got {endpoints:?}");
    for e in &endpoints {
        assert!(
            GOLDEN.contains(&format!("\"{e}\": {{")),
            "resource spec names endpoint {e:?}, which the façade does not serve"
        );
    }
}
