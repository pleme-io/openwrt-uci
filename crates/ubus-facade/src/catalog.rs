//! The device's own method catalog, parsed from `ubus -v list`.
//!
//! # Why this is parsed rather than authored
//!
//! The device introspects itself: `ubus -v list` returns every object, every
//! method, and every method's parameter names and types. Hand-maintaining a
//! façade over 264 methods would drift, and drift in a generated SDK is
//! indistinguishable from a feature. So the catalog is a **measurement**, the
//! fixture beside these tests is a real capture, and the differential test
//! degenerates into re-run-and-diff.
//!
//! Same discipline as `crdgen`: the schema is OUTPUT plus a byte-exact test,
//! never a maintained artifact.
//!
//! # Two things this deliberately discards
//!
//! **The object id.** `ubus -v list` prints `'uci' @575a75e0`, but an id is
//! assigned at registration and does not survive a restart of the process that
//! owns the object. Keeping it would bake an ephemeral value into a committed
//! spec and produce drift on every reboot. Ids are resolved by LOOKUP at call
//! time.
//!
//! **`ubus_rpc_session`.** Every `uci` method *declares* it, but it is an
//! artifact of `rpcd` — the HTTP layer above ubus — and measured 2026-09-08 only
//! `apply`, `confirm` and `rollback` actually enforce it. A native client never
//! sends one. Emitting it would put a parameter in the generated SDK that must
//! never be used, so it is dropped at the parse boundary and recorded as
//! [`Method::needs_rpcd_session`] instead: the FACT survives, the misleading
//! parameter does not.

use std::fmt;

/// The closed set of parameter types this catalog uses.
///
/// Measured across the whole 264-method capture: `String` 200, `Integer` 54,
/// `Array` 45, `Boolean` 38, `Table` 18, and nothing else. Closed on purpose —
/// a type outside this set is a [`CatalogError::UnknownType`], never a guess,
/// because guessing would put a wrong schema into a generated provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbusType {
    String,
    Integer,
    Boolean,
    Table,
    Array,
}

impl UbusType {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "String" => Some(Self::String),
            "Integer" => Some(Self::Integer),
            "Boolean" => Some(Self::Boolean),
            "Table" => Some(Self::Table),
            "Array" => Some(Self::Array),
            _ => None,
        }
    }

    /// The JSON Schema type this maps to.
    #[must_use]
    pub const fn json_type(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Table => "object",
            Self::Array => "array",
        }
    }
}

/// One parameter of one method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: UbusType,
}

/// One method on one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    pub name: String,
    pub params: Vec<Param>,
    /// How many parameters the device declined to describe.
    ///
    /// ★ `ubus -v list` can print a bare `"(unknown)"` field with no type —
    /// measured once in 264 methods, on `cellular.collect/clean_traffic`. It is
    /// a parameter that EXISTS but whose name and type ubus's own printer has no
    /// word for.
    ///
    /// Counted rather than dropped, and the count is load-bearing: a schema
    /// that silently omitted it while keeping `additionalProperties: false`
    /// would generate a client that REFUSES a call the device accepts. So an
    /// incompletely-described method must relax its schema, and it can only do
    /// that if the gap is recorded.
    pub undescribed_params: usize,

    /// Whether the device declared `ubus_rpc_session` for this method.
    ///
    /// Kept as a fact even though the parameter itself is dropped. It is the
    /// difference between an operation a native client can drive and one that
    /// needs rpcd, and a generated provider must not offer the latter as if it
    /// were reachable.
    pub needs_rpcd_session: bool,
}

/// One ubus object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub path: String,
    pub methods: Vec<Method>,
}

/// The whole device catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub objects: Vec<Object>,
}

impl Catalog {
    /// Total method count across every object.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.objects.iter().map(|o| o.methods.len()).sum()
    }

    /// Parse the output of `ubus -v list`.
    ///
    /// The format, as captured:
    ///
    /// ```text
    /// 'uci' @575a75e0
    ///     "get":{"config":"String","section":"String"}
    ///     "reload_config":{}
    /// ```
    ///
    /// # Errors
    ///
    /// [`CatalogError`] on any line that is neither an object header, a method,
    /// nor blank. Refusing is deliberate: silently skipping an unrecognised line
    /// would produce a catalog that is quietly short, and a short catalog
    /// generates a façade missing operations nobody notices are absent.
    pub fn parse(input: &str) -> Result<Self, CatalogError> {
        let mut objects: Vec<Object> = Vec::new();

        for (n, raw) in input.lines().enumerate() {
            let line_no = n + 1;
            if raw.trim().is_empty() {
                continue;
            }

            if let Some(rest) = raw.strip_prefix('\'') {
                // `'name' @deadbeef` — the id is discarded, see the module docs.
                let end = rest.find('\'').ok_or(CatalogError::Malformed {
                    line_no,
                    what: "object header has no closing quote",
                })?;
                objects.push(Object {
                    path: rest[..end].to_owned(),
                    methods: Vec::new(),
                });
                continue;
            }

            let trimmed = raw.trim_start();
            if trimmed.starts_with('"') && raw.starts_with(char::is_whitespace) {
                let obj = objects.last_mut().ok_or(CatalogError::Malformed {
                    line_no,
                    what: "method line before any object header",
                })?;
                obj.methods.push(parse_method(trimmed, line_no)?);
                continue;
            }

            return Err(CatalogError::Malformed {
                line_no,
                what: "neither an object header nor a method",
            });
        }

        Ok(Self { objects })
    }
}

fn parse_method(line: &str, line_no: usize) -> Result<Method, CatalogError> {
    let rest = &line[1..];
    let name_end = rest.find('"').ok_or(CatalogError::Malformed {
        line_no,
        what: "method name has no closing quote",
    })?;
    let name = rest[..name_end].to_owned();

    let body = rest[name_end + 1..]
        .trim_start()
        .strip_prefix(':')
        .ok_or(CatalogError::Malformed {
            line_no,
            what: "method name is not followed by `:`",
        })?
        .trim();
    let inner = body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or(CatalogError::Malformed {
            line_no,
            what: "method signature is not a brace-delimited table",
        })?;

    let mut params = Vec::new();
    let mut needs_rpcd_session = false;
    let mut undescribed_params = 0usize;

    for field in inner.split(',').filter(|f| !f.trim().is_empty()) {
        // A bare `"(unknown)"` with no `:type` — see `Method::undescribed_params`.
        if field.trim().trim_matches('"') == "(unknown)" {
            undescribed_params += 1;
            continue;
        }

        let (k, v) = field.split_once(':').ok_or(CatalogError::Malformed {
            line_no,
            what: "parameter is not `\"name\":\"Type\"`",
        })?;
        let key = k.trim().trim_matches('"');
        let val = v.trim().trim_matches('"');

        // Dropped, but remembered — see the module docs.
        if key == "ubus_rpc_session" {
            needs_rpcd_session = true;
            continue;
        }

        let ty = UbusType::parse(val).ok_or_else(|| CatalogError::UnknownType {
            line_no,
            param: key.to_owned(),
            ty: val.to_owned(),
        })?;
        params.push(Param {
            name: key.to_owned(),
            ty,
        });
    }

    Ok(Method {
        name,
        params,
        undescribed_params,
        needs_rpcd_session,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    Malformed {
        line_no: usize,
        what: &'static str,
    },
    /// A parameter type outside the measured set.
    ///
    /// An error rather than a fallback to `string`: a wrong type in a generated
    /// provider is a schema that lies, and it would be discovered by a failed
    /// apply against real infrastructure rather than here.
    UnknownType {
        line_no: usize,
        param: String,
        ty: String,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { line_no, what } => {
                write!(f, "line {line_no}: {what}")
            }
            Self::UnknownType { line_no, param, ty } => write!(
                f,
                "line {line_no}: parameter {param:?} has type {ty:?}, which this \
                 catalog has never measured — add it to UbusType only after \
                 seeing it on a device"
            ),
        }
    }
}

impl std::error::Error for CatalogError {}
