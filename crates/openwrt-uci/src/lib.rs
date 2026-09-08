//! Typed model, parser and renderer for `OpenWrt` UCI configuration.
//!
//! UCI is `OpenWrt`'s configuration algebra. `uci export` emits a text document
//! whose grammar is exactly five line shapes — measured against a live
//! GL.iNet GL-MT6000 (`OpenWrt` 21.02-SNAPSHOT), 2,871 lines across 70 packages,
//! with **zero** lines falling outside them:
//!
//! ```text
//! package <name>
//!
//! config <type> '<name>'          # named section
//! config <type>                   # anonymous section
//! \toption <key> '<value>'
//! \tlist <key> '<value>'
//! ```
//!
//! # Why the model is pure structure
//!
//! The emitted layout is fully regular: a blank line after every `package`
//! header and after every section's entries, tab-indented entries, LF only, no
//! trailing whitespace, and a trailing newline at end of file. Because the
//! layout carries no information, the model does not preserve raw bytes — it
//! stores structure and the renderer regenerates canonical output.
//!
//! That is a claim, not an assumption, and it is the load-bearing one: if it
//! were false, a round-trip would not be byte-identical. It is proven by
//! [`tests/round_trip.rs`] against a real device's full export rather than a
//! synthetic sample.
//!
//! # Scope
//!
//! This crate models the UCI *document*. It is deliberately generic: it parses
//! and renders every package a device carries, including vendor-specific ones
//! (`gl_dpi`, `glconfig`, …), because round-trip fidelity cannot be selective.
//! Typed per-package schemas (`network`, `wireless`, `firewall`, …) are a layer
//! above this one.
//!
//! # Example
//!
//! ```
//! use openwrt_uci::Document;
//!
//! let src = "package dropbear\n\nconfig dropbear 'main'\n\toption Port '22'\n\n";
//! let doc = Document::parse(src).unwrap();
//! assert_eq!(doc.packages.len(), 1);
//! assert_eq!(doc.render(), src);
//! ```

#![forbid(unsafe_code)]

mod parse;
mod render;

pub use parse::ParseError;

/// A complete UCI document — the parsed form of `uci export`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    pub packages: Vec<Package>,
}

/// One `package <name>` block and the sections it contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub sections: Vec<Section>,
}

/// One `config <type> ['<name>']` block.
///
/// `name` is `None` for an anonymous section. Both forms occur in practice —
/// the reference device carried 197 anonymous and 190 named sections, so
/// neither is an edge case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub kind: String,
    pub name: Option<String>,
    pub entries: Vec<Entry>,
}

/// A single `option` or `list` line.
///
/// UCI `list` keys repeat: several entries may share a key, and their order is
/// significant. Modelling entries as an ordered `Vec` rather than a map is what
/// preserves that — a map would silently collapse a multi-valued list and the
/// loss would only surface as a failed round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Option,
    List,
}

impl Document {
    /// Parse a `uci export` document.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] on any line that does not match the UCI grammar,
    /// or on an `option`/`list` appearing before any `config` section.
    /// Unrecognised input is rejected rather than skipped: silently dropping a
    /// line would produce a document that renders successfully and is wrong.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        parse::document(input)
    }

    /// Render back to canonical `uci export` text.
    #[must_use]
    pub fn render(&self) -> String {
        render::document(self)
    }

    /// Borrow a package by name.
    #[must_use]
    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }
}

impl Package {
    /// Borrow a named section. Anonymous sections are never returned.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.name.as_deref() == Some(name))
    }

    /// All sections of a given type, named or anonymous, in document order.
    pub fn sections_of_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Section> {
        self.sections.iter().filter(move |s| s.kind == kind)
    }
}

impl Section {
    /// The value of the first `option` with this key.
    ///
    /// Deliberately ignores `list` entries: a caller asking for a scalar should
    /// not silently receive the first element of a list.
    #[must_use]
    pub fn option(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.kind == EntryKind::Option && e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Every `list` value with this key, in document order.
    pub fn list<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> {
        self.entries
            .iter()
            .filter(move |e| e.kind == EntryKind::List && e.key == key)
            .map(|e| e.value.as_str())
    }
}
