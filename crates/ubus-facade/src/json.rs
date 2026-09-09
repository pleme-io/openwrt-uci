//! A typed JSON value and a deterministic renderer.
//!
//! # Why hand-rolled rather than `serde_json`
//!
//! Two reasons, and neither is dependency asceticism for its own sake.
//!
//! The workspace is zero-dependency, and the protocol crates being so is a
//! load-bearing property of this project: it speaks a wire format rather than
//! linking a library. Keeping the generator in the same posture means the whole
//! thing builds anywhere with no vendoring question.
//!
//! More importantly, the fleet's ★★ TYPED EMISSION rule bans `format!()` of
//! emitted syntax: every emitted string must come from a typed surface. A
//! generator that assembled JSON by interpolation would be exactly the banned
//! shape, and would be one unescaped quote away from emitting a document that
//! parses as something else. So the spec is BUILT AS A TREE and rendered once,
//! here — the same discipline as the fleet's `NixAST` and `GraphQLAST`.
//!
//! # Determinism
//!
//! [`Json::Obj`] preserves insertion order rather than sorting, because the
//! generated spec is byte-compared against a committed golden file. A map with
//! nondeterministic iteration order would make that test flap for a reason that
//! is not a defect.

use std::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Str(String),
    Int(i64),
    Bool(bool),
    Arr(Vec<Json>),
    /// An object. Order is insertion order and is preserved on render.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// A string value, from anything string-like.
    pub fn str(s: impl Into<String>) -> Self {
        Self::Str(s.into())
    }

    /// An object from pairs, so call sites read like the document they build.
    pub fn obj<K: Into<String>>(pairs: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Obj(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Render as pretty-printed JSON with a trailing newline.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        let pad = |n: usize| "  ".repeat(n);
        match self {
            Self::Str(s) => write_escaped(out, s),
            // `write!` to a String is infallible; the Result is discarded
            // deliberately rather than unwrapped.
            Self::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Arr(items) if items.is_empty() => out.push_str("[]"),
            Self::Arr(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&pad(depth + 1));
                    item.write(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(depth));
                out.push(']');
            }
            Self::Obj(pairs) if pairs.is_empty() => out.push_str("{}"),
            Self::Obj(pairs) => {
                out.push_str("{\n");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    out.push_str(&pad(depth + 1));
                    write_escaped(out, k);
                    out.push_str(": ");
                    v.write(out, depth + 1);
                    if i + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(depth));
                out.push('}');
            }
        }
    }
}

/// Write a JSON string literal, escaping what RFC 8259 requires.
///
/// ★ The control-character case is the one that matters and the one an
/// interpolating generator gets wrong: a raw byte below 0x20 inside a string
/// makes the document invalid, and the failure surfaces in whatever consumes
/// the spec rather than here.
fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
