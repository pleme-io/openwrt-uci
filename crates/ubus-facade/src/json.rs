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
    /// JSON `null`. Present so a parsed document round-trips; the emitter never
    /// produces one.
    Null,
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
            Self::Null => out.push_str("null"),
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

// ---- parsing ----

/// Parse a JSON document.
///
/// Hand-rolled for the same reason the renderer is: this workspace stays
/// dependency-free so the adapter cross-compiles to a router with no vendoring
/// question. The subset is complete for RFC 8259 with two documented limits
/// below — it is a parser for machine-generated request bodies and our own
/// façade, not a general-purpose one.
///
/// # Errors
///
/// [`ParseError`] with a byte offset. Refusing beats guessing: this reads
/// request bodies that will drive writes to a device.
pub fn parse(input: &str) -> Result<Json, ParseError> {
    let bytes = input.as_bytes();
    let mut p = Parser { bytes, pos: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(ParseError {
            at: p.pos,
            what: "trailing content after the document",
        });
    }
    Ok(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub at: usize,
    pub what: &'static str,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.at, self.what)
    }
}

impl std::error::Error for ParseError {}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn err(&self, what: &'static str) -> ParseError {
        ParseError { at: self.pos, what }
    }

    fn eat(&mut self, lit: &str) -> Result<(), ParseError> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(self.err("expected a literal"))
        }
    }

    fn value(&mut self) -> Result<Json, ParseError> {
        match self.bytes.get(self.pos) {
            Some(b'"') => self.string().map(Json::Str),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b't') => self.eat("true").map(|()| Json::Bool(true)),
            Some(b'f') => self.eat("false").map(|()| Json::Bool(false)),
            Some(b'n') => self.eat("null").map(|()| Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err("not a JSON value")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn object(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // '{'
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(self.err("expected `:` after an object key"));
            }
            self.pos += 1;
            self.skip_ws();
            let val = self.value()?;
            // Duplicate keys are kept rather than merged: RFC 8259 leaves the
            // behaviour undefined, and silently dropping one would lose a field
            // a caller believed it sent.
            pairs.push((key, val));
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(self.err("expected `,` or `}` in an object")),
            }
        }
    }

    fn array(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(self.err("expected `,` or `]` in an array")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(self.err("expected a string"));
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.bytes.get(self.pos) {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| self.err("truncated escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or_else(|| self.err("truncated \\u escape"))?;
                            let hex = std::str::from_utf8(hex)
                                .map_err(|_| self.err("non-ASCII in a \\u escape"))?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| self.err("invalid hex in a \\u escape"))?;
                            self.pos += 4;
                            // ★ LIMIT, stated rather than hidden: a surrogate
                            // pair is REFUSED, not silently replaced. Emitting
                            // U+FFFD here would turn a name we cannot represent
                            // into a name that looks valid, and this parser
                            // feeds device writes.
                            let c = char::from_u32(cp)
                                .ok_or_else(|| self.err("lone surrogate in a \\u escape"))?;
                            out.push(c);
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                Some(_) => {
                    // Walk one whole UTF-8 char, so multibyte content survives.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| self.err("invalid UTF-8 in a string"))?;
                    let c = rest.chars().next().ok_or_else(|| self.err("empty"))?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        while matches!(self.bytes.get(self.pos), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        // ★ LIMIT: integers only. ubus carries INT32 and has no measured float
        // type, so a fractional or exponent form is refused rather than
        // truncated into an integer the device would silently accept as a
        // different value.
        if matches!(self.bytes.get(self.pos), Some(b'.' | b'e' | b'E')) {
            return Err(self.err(
                "fractional and exponent numbers are not supported: ubus has no measured float type",
            ));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        text.parse::<i64>().map(Json::Int).map_err(|_| ParseError {
            at: start,
            what: "number out of range for i64",
        })
    }
}
