//! The route table, built from the façade rather than from the path.
//!
//! # Why the table exists at all
//!
//! A path like `/uci/set` looks like it could simply be split on `/`. It must
//! not be. ubus object names contain dots (`cellular.cm`) and nothing forbids a
//! character a URL path escapes, so deriving the call from the request path
//! would work for 264 operations and then break silently on the first one that
//! did not. The façade emits `x-ubus-object` and `x-ubus-method` on every
//! operation precisely so the adapter is a **lookup**.
//!
//! Building the table from the spec has a second effect worth having: the
//! adapter can only serve operations the façade describes, and the façade only
//! describes operations measured on a device. An endpoint nobody measured is a
//! 404 here rather than an INVOKE nobody has ever seen answered.

use std::collections::BTreeMap;
use ubus_facade::json::Json;

/// One servable operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub object: String,
    pub method: String,
    /// The device declared this operation as needing an `rpcd` session.
    ///
    /// ★ This is a DECLARATION, not an enforcement, and it does not gate.
    ///
    /// Measured 2026-09-08: of `uci`'s methods, `apply`/`confirm`/`rollback`
    /// genuinely enforce a session while
    /// `get`/`set`/`add`/`commit`/`revert`/`changes` do not — even though all 28
    /// of them declare it. Gating on the declaration refuses operations that
    /// demonstrably work, which a first cut of the adapter did: every request
    /// returned 501, `uci get` included.
    ///
    /// So the call is attempted and the device decides; this flag becomes a
    /// diagnostic hint attached to a `status 2` failure. See `http::handle`.
    pub requires_rpcd_session: bool,
}

/// Path → operation.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: BTreeMap<String, Route>,
}

impl RouteTable {
    /// Build the table from a parsed façade document.
    ///
    /// # Errors
    ///
    /// A document with no `paths`, or an operation missing `x-ubus-object` /
    /// `x-ubus-method`. Both are refusals: a partially-built table would serve
    /// some operations and 404 others for no reason a caller could see.
    pub fn from_facade(spec: &Json) -> Result<Self, String> {
        let paths = get(spec, "paths").ok_or("the façade has no `paths`")?;
        let Json::Obj(entries) = paths else {
            return Err("`paths` is not an object".to_owned());
        };

        let mut routes = BTreeMap::new();
        for (path, item) in entries {
            let post =
                get(item, "post").ok_or_else(|| format!("path {path} has no `post` operation"))?;
            let object = string_at(post, "x-ubus-object").ok_or_else(|| {
                format!("operation {path} has no `x-ubus-object`; the adapter will not guess it from the path")
            })?;
            let method = string_at(post, "x-ubus-method")
                .ok_or_else(|| format!("operation {path} has no `x-ubus-method`"))?;
            let requires_rpcd_session = matches!(
                get(post, "x-ubus-requires-rpcd-session"),
                Some(Json::Bool(true))
            );

            routes.insert(
                path.clone(),
                Route {
                    object,
                    method,
                    requires_rpcd_session,
                },
            );
        }

        if routes.is_empty() {
            // A table that silently served nothing would look like a working
            // adapter that 404s everything.
            return Err("the façade described no operations".to_owned());
        }
        Ok(Self { routes })
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Route> {
        self.routes.get(path)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

fn get<'a>(j: &'a Json, key: &str) -> Option<&'a Json> {
    match j {
        Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn string_at(j: &Json, key: &str) -> Option<String> {
    match get(j, key) {
        Some(Json::Str(s)) => Some(s.clone()),
        _ => None,
    }
}
