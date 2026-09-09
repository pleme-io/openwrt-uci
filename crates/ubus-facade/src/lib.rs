//! Generate an `OpenAPI` façade from an `OpenWrt` device's own method catalog.
//!
//! The device introspects itself, so the façade is a MEASUREMENT rather than an
//! authored artifact: [`catalog`] parses `ubus -v list`, [`openapi`] emits one
//! synthetic REST operation per `(object, method)`, and [`json`] renders it
//! through a typed tree rather than by interpolation.
//!
//! The whole point is that nobody types the 264 operations, so nothing can drift
//! into fiction. Regenerating and diffing is the test.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod json;
pub mod openapi;

/// The façade spec version.
///
/// Bumped by hand when the *shape* of the emitted document changes — not when
/// the device's catalog changes, which is what the golden diff is for.
pub const FACADE_VERSION: &str = "0.1.0";

/// Parse a `ubus -v list` capture and render its façade.
///
/// # Errors
///
/// Propagates [`catalog::CatalogError`] — a malformed line or an unmeasured
/// parameter type. Both are refusals rather than fallbacks: a catalog that
/// silently skipped a line would generate a façade quietly missing operations.
pub fn generate(ubus_v_list: &str) -> Result<String, catalog::CatalogError> {
    let catalog = catalog::Catalog::parse(ubus_v_list)?;
    Ok(openapi::build(&catalog, FACADE_VERSION).render())
}
