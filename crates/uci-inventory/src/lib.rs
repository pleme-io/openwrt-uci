//! Survey an `OpenWrt` device's whole UCI surface, classify every package, and
//! derive declared config from what is actually there.
//!
//! # The problem this exists for
//!
//! A router managed as code is usually managed as *some* code: a handful of
//! sections someone wrote by hand, with no statement of how much of the device
//! that covers. Measured on a GL-MT6000: **72 packages, 2229 assignments, ~432
//! sections.** A chart declaring six of them looks complete and is 1.4%.
//!
//! So the unit of work here is not "declare more" — it is **account for
//! everything**, then derive the declarations for the part we own from the
//! device itself, so what we declare and what exists cannot disagree at the
//! moment of writing.
//!
//! ```text
//! device ──uci.configs──▶ every package name
//!        ──uci.get─────▶ every section, typed
//!                         │
//!                    classify ── unclassified? REFUSE
//!                         │
//!                    ┌────┴─────────────┬──────────────────┐
//!                 Managed          DeviceOwned       SecretBearing
//!                    │              (witnessed,        (witnessed,
//!               derive values        never written)     never in git)
//!               + import ids
//! ```
//!
//! The oracle for "state matches all that exists" is an **empty plan**: import
//! the managed set, apply the derived values, and `plan` reports no changes.
//! Nothing weaker proves it — a green apply only says we wrote what we meant.
//!
//! # Known gaps, named rather than implied
//!
//! `pending-uci-lists`: a UCI option may be a LIST, and the resource's
//! `values` is a map-of-string, so list-valued options are surveyed but not
//! derived.
//!
//! `pending-anonymous-rename`: anonymous sections are addressed positionally,
//! so deleting an earlier section of the same type silently repoints later
//! addresses. `uci rename` is the fix, and it mutates the device.

pub mod adapter;
pub mod disposition;
pub mod emit;
pub mod inventory;
