//! Canonical renderer — the inverse of [`crate::parse`].
//!
//! The layout emitted here is the layout `uci export` emits, measured against a
//! live device: a blank line after every `package` header and after every
//! section's entries, tab-indented entries, LF only, no trailing whitespace,
//! and a trailing newline at end of file.
//!
//! Because that layout is fully regular, the model stores no whitespace and
//! this function regenerates it. The round-trip test is what holds that claim
//! honest.

use crate::{Document, EntryKind, Package, Section};
use std::fmt::Write as _;

pub(crate) fn document(doc: &Document) -> String {
    // Pre-size from the shape of the document rather than growing repeatedly.
    // A real device export is ~55 KB; the estimate only needs to be close.
    let entries: usize = doc
        .packages
        .iter()
        .flat_map(|p| p.sections.iter())
        .map(|s| s.entries.len())
        .sum();
    let mut out = String::with_capacity(entries * 40 + doc.packages.len() * 32);

    for pkg in &doc.packages {
        package(&mut out, pkg);
    }
    out
}

fn package(out: &mut String, pkg: &Package) {
    let _ = writeln!(out, "package {}\n", pkg.name);
    for sec in &pkg.sections {
        section(out, sec);
    }
}

fn section(out: &mut String, sec: &Section) {
    match &sec.name {
        Some(name) => {
            let _ = writeln!(out, "config {} {}", sec.kind, quote(name));
        }
        None => {
            let _ = writeln!(out, "config {}", sec.kind);
        }
    }
    for e in &sec.entries {
        let word = match e.kind {
            EntryKind::Option => "option",
            EntryKind::List => "list",
        };
        let _ = writeln!(out, "\t{word} {} {}", e.key, quote(&e.value));
    }
    out.push('\n');
}

/// Quote a value the way UCI does: single quotes, with an embedded `'`
/// written as `'\''`.
///
/// This is the exact inverse of the parser's unquote. Both sides must move
/// together — a change to one alone shows up as a failed round-trip, which is
/// the point of testing them against a real export rather than each other.
fn quote(value: &str) -> String {
    let mut s = String::with_capacity(value.len() + 2);
    s.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            s.push_str("'\\''");
        } else {
            s.push(ch);
        }
    }
    s.push('\'');
    s
}
