//! The `OpenAPI` façade — one synthetic path per ubus operation.
//!
//! # Why a façade exists at all
//!
//! `forge-gen`'s IR is **REST-shaped**: one operation per `(method, path)`.
//! ubus is the opposite — a single endpoint carrying JSON-RPC, where the
//! operation is a *field* of the payload. Pointed at ubus directly, a generator
//! emits **one** operation taking an opaque blob, which generates an SDK that
//! can do anything and helps with nothing.
//!
//! So each ubus `(object, method)` becomes its own synthetic path, with the
//! method's measured parameters as a typed request body. `forge-gen` then sees
//! 264 ordinary REST operations, and a thin façade→ubus adapter turns a call on
//! one back into an INVOKE. Precedent: `akeyless-terraform-resources`.
//!
//! # The spec describes only what has been verified on the wire
//!
//! §7's rule: the spec may only describe operations verified on the wire, or the
//! generated provider is fiction with a type signature. Two consequences are
//! visible in the output.
//!
//! Every operation carries `x-ubus-object` and `x-ubus-method`, so the adapter
//! is a lookup rather than a string transformation of the path — a path is for
//! humans and generators, and deriving the call from it would break the first
//! time an object name contained a character a path escapes.
//!
//! Operations the device declares as needing an rpcd session carry
//! `x-ubus-requires-rpcd-session: true`. Measured 2026-09-08: `uci`'s
//! `get`/`set`/`add`/`commit`/`revert`/`changes` all work over the native socket
//! with **no** session, while `apply`/`confirm`/`rollback` return `Invalid
//! argument` without one. A generated client must not offer the latter as
//! though it were reachable, and the flag is what lets it refuse.

use crate::catalog::{Catalog, Method, UbusType};
use crate::json::Json;

/// Build the façade document for a catalog.
#[must_use]
pub fn build(catalog: &Catalog, version: &str) -> Json {
    let mut paths: Vec<(String, Json)> = Vec::new();

    for object in &catalog.objects {
        for method in &object.methods {
            paths.push((
                format!("/{}/{}", object.path, method.name),
                Json::obj([("post", operation(&object.path, method))]),
            ));
        }
    }

    Json::obj([
        ("openapi", Json::str("3.0.3")),
        (
            "info",
            Json::obj([
                ("title", Json::str("OpenWrt ubus façade")),
                ("version", Json::str(version)),
                (
                    "description",
                    Json::str(
                        "GENERATED — do not edit. One synthetic REST operation per ubus \
                         (object, method), emitted by `ubus-facade` from a real device's \
                         `ubus -v list`. Regenerate and diff rather than editing: drift is \
                         a red test, not a stale document. Object ids are absent on \
                         purpose — they are assigned at registration, do not survive a \
                         restart, and are resolved by LOOKUP at call time.",
                    ),
                ),
            ]),
        ),
        (
            "servers",
            Json::Arr(vec![Json::obj([
                ("url", Json::str("/ubus")),
                (
                    "description",
                    Json::str(
                        "Not an HTTP endpoint. ubus is a unix socket at \
                         /var/run/ubus/ubus.sock; this base path exists because OpenAPI \
                         requires one, and the adapter maps each operation to an INVOKE \
                         via x-ubus-object / x-ubus-method.",
                    ),
                ),
            ])]),
        ),
        ("paths", Json::Obj(paths)),
    ])
}

fn operation(object: &str, method: &Method) -> Json {
    let mut op = vec![
        (
            "operationId".to_owned(),
            Json::str(operation_id(object, &method.name)),
        ),
        (
            "summary".to_owned(),
            Json::str(format!("ubus call {object} {}", method.name)),
        ),
        ("x-ubus-object".to_owned(), Json::str(object)),
        ("x-ubus-method".to_owned(), Json::str(&method.name)),
    ];

    if method.undescribed_params > 0 {
        op.push((
            "x-ubus-undescribed-params".to_owned(),
            // A count of parameters on one method. `try_from` rather than a
            // cast so the impossible case is stated instead of wrapping: a
            // wrapped negative count would emit a spec claiming something
            // absurd, and silently.
            Json::Int(i64::try_from(method.undescribed_params).unwrap_or(i64::MAX)),
        ));
    }

    if method.needs_rpcd_session {
        op.push(("x-ubus-requires-rpcd-session".to_owned(), Json::Bool(true)));
    }

    op.push((
        "requestBody".to_owned(),
        Json::obj([
            ("required", Json::Bool(!method.params.is_empty())),
            (
                "content",
                Json::obj([("application/json", Json::obj([("schema", schema(method))]))]),
            ),
        ]),
    ));

    op.push((
        "responses".to_owned(),
        Json::obj([
            (
                "200",
                Json::obj([
                    (
                        "description",
                        Json::str(
                            "The request completed with ubus status 0. A method with no \
                             return value answers with no payload, which is success with \
                             nothing to report rather than an empty result.",
                        ),
                    ),
                    (
                        "content",
                        Json::obj([(
                            "application/json",
                            Json::obj([("schema", Json::obj([("type", Json::str("object"))]))]),
                        )]),
                    ),
                ]),
            ),
            (
                "default",
                Json::obj([(
                    "description",
                    Json::str(
                        "A nonzero ubus status. 2 = invalid argument (typically a rejected \
                         argument encoding), 4 = not found, 6 = permission denied.",
                    ),
                )]),
            ),
        ]),
    ));

    Json::Obj(op)
}

fn schema(method: &Method) -> Json {
    let props: Vec<(String, Json)> = method
        .params
        .iter()
        .map(|p| {
            let mut fields = vec![("type".to_owned(), Json::str(p.ty.json_type()))];
            // ★ An `Array`'s element type is NOT in `ubus -v list` — the catalog
            // reports the container only. So `items` is an EMPTY SCHEMA, which
            // is OpenAPI's own way of writing "any value": it constrains
            // nothing, and it invents nothing.
            //
            // It cannot simply be omitted. OpenAPI 3.0 makes `items` mandatory
            // on `type: array`, and leaving it out produced a document that
            // `forge-gen validate` accepted with NO WARNINGS while
            // `openapi-generator-cli` refused outright — 45 times, once per
            // array parameter. Measured 2026-09-08.
            //
            // Worth keeping as a lesson about validators: a passing
            // `forge-gen validate` is not evidence that a generator will accept
            // the spec. Only running a generator is.
            if p.ty == UbusType::Array {
                fields.push(("items".to_owned(), Json::Obj(Vec::new())));
                fields.push((
                    "description".to_owned(),
                    Json::str(
                        "Element type is not reported by `ubus -v list`; the empty \
                         `items` schema is unconstrained by measurement, not by \
                         oversight.",
                    ),
                ));
            }
            (p.name.clone(), Json::Obj(fields))
        })
        .collect();

    Json::obj([
        ("type", Json::str("object")),
        // No `required` list: `ubus -v list` reports a method's parameter names
        // and types and says nothing about which are mandatory. Inventing one
        // would make the generated client reject calls the device accepts.
        ("properties", Json::Obj(props)),
        // ★ Closed only when the device described every parameter. A method
        // with an undescribed one must stay OPEN: `false` there would generate
        // a client that refuses a call the device accepts, which is a worse
        // failure than an unconstrained field.
        (
            "additionalProperties",
            Json::Bool(method.undescribed_params > 0),
        ),
    ])
}

/// A stable, unique operation id.
///
/// ubus object names contain dots (`cellular.cm`), which are not valid in the
/// identifiers most generators derive from an `operationId`, so they become
/// underscores. Uniqueness survives because `(object, method)` is unique and the
/// separator is doubled.
#[must_use]
pub fn operation_id(object: &str, method: &str) -> String {
    let sanitize = |s: &str| {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    };
    format!("{}__{}", sanitize(object), sanitize(method))
}
