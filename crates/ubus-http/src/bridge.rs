//! Converting between JSON and ubus values.
//!
//! The two directions are not symmetric, and the asymmetry is the point.
//!
//! Going IN, a request body must become [`Value`], which has only the four
//! blobmsg types this project has measured. A JSON value with no measured ubus
//! counterpart is **refused** rather than coerced: coercing would send the
//! device something other than what the caller wrote, and the caller would be
//! told it succeeded.
//!
//! Coming OUT, a [`Decoded`] may carry `Unknown` — a blobmsg type the device
//! sent and this project has not characterised. That is rendered as a JSON
//! object naming the type code and its byte length, so a reader sees an
//! unrecognised value rather than a missing field.

use ubus_facade::json::Json;
use ubus_proto::client::Decoded;
use ubus_proto::encode::Value;

/// Convert a parsed request body into ubus call arguments.
///
/// # Errors
///
/// A body that is not a JSON object, or a value with no measured ubus type.
pub fn args_from_json(body: &Json) -> Result<Vec<(String, Value)>, String> {
    let Json::Obj(pairs) = body else {
        return Err("the request body must be a JSON object".to_owned());
    };
    pairs
        .iter()
        .map(|(k, v)| value_from_json(v).map(|v| (k.clone(), v)))
        .collect()
}

fn value_from_json(j: &Json) -> Result<Value, String> {
    match j {
        Json::Str(s) => Ok(Value::str(s.clone())),
        Json::Bool(b) => {
            // ★ ubus HAS a boolean type — the catalog declares 38 Boolean
            // parameters — but this project has never seen one ON THE WIRE, so
            // `Value` has no arm for it and inventing a type code would be
            // exactly the recollection-over-measurement the project forbids.
            //
            // Refused with the reason, rather than sent as the string "true",
            // which the device would accept as a different value.
            Err(format!(
                "boolean ({b}) cannot be sent: ubus declares a Boolean type but this \
                 crate has not measured its blobmsg code on the wire. Measure it \
                 against a device and add the arm."
            ))
        }
        Json::Int(i) => i32::try_from(*i)
            .map(Value::I32)
            .map_err(|_| format!("integer {i} does not fit ubus's measured INT32")),
        Json::Arr(items) => items
            .iter()
            .map(value_from_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Json::Obj(pairs) => pairs
            .iter()
            .map(|(k, v)| value_from_json(v).map(|v| (k.clone(), v)))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Table),
        Json::Null => Err(
            "null cannot be sent: ubus has no null, and omitting the field is a \
             different request from sending an empty one"
                .to_owned(),
        ),
    }
}

/// Convert a decoded ubus reply into JSON.
#[must_use]
pub fn json_from_decoded(d: &Decoded) -> Json {
    match d {
        Decoded::Str(s) => Json::str(s.clone()),
        Decoded::I32(i) => Json::Int(i64::from(*i)),
        // ubus aliases BOOL to INT8, so a boolean field renders as 0/1 rather
        // than true/false. Rendering it as a bool would claim to know which of
        // the two the sender meant.
        Decoded::I8(i) => Json::Int(i64::from(*i)),
        Decoded::Array(items) => Json::Arr(items.iter().map(json_from_decoded).collect()),
        Decoded::Table(pairs) => Json::Obj(
            pairs
                .iter()
                .map(|(k, v)| (k.clone(), json_from_decoded(v)))
                .collect(),
        ),
        // Surfaced, never dropped. A reader must be able to tell "the device
        // sent something we do not understand" from "the field was absent".
        Decoded::Unknown { type_code, bytes } => Json::obj([
            ("$ubusUnmeasuredType", Json::Int(i64::from(*type_code))),
            (
                "$byteLength",
                Json::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
            ),
        ]),
    }
}
