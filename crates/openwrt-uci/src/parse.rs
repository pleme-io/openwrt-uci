//! Line-oriented parser for `uci export` output.
//!
//! The grammar is five line shapes, so this is a small state machine rather
//! than a parser combinator. Every line is classified; anything unclassifiable
//! is an error, never a skip — see [`ParseError`].

use crate::{Document, Entry, EntryKind, Package, Section};
use std::fmt;

/// A line that does not match the UCI grammar.
///
/// Carries the 1-based line number and the offending text, because a parse
/// failure against a 2,871-line device export is useless without both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub text: String,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A line matched none of the five known shapes.
    UnrecognisedLine,
    /// `config` appeared before any `package`.
    SectionOutsidePackage,
    /// `option` or `list` appeared before any `config`.
    EntryOutsideSection,
    /// A `package` line carried no name.
    MissingPackageName,
    /// A `config` line carried no type.
    MissingSectionType,
    /// An `option`/`list` line was missing a key or a value.
    MalformedEntry,
    /// A value was not enclosed in single quotes.
    UnquotedValue,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ParseErrorKind::UnrecognisedLine => "line matches no UCI grammar rule",
            ParseErrorKind::SectionOutsidePackage => "`config` before any `package`",
            ParseErrorKind::EntryOutsideSection => "`option`/`list` before any `config`",
            ParseErrorKind::MissingPackageName => "`package` with no name",
            ParseErrorKind::MissingSectionType => "`config` with no type",
            ParseErrorKind::MalformedEntry => "entry missing a key or value",
            ParseErrorKind::UnquotedValue => "value is not single-quoted",
        };
        write!(f, "line {}: {what}: {:?}", self.line, self.text)
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn document(input: &str) -> Result<Document, ParseError> {
    let mut doc = Document::default();

    for (idx, raw) in input.lines().enumerate() {
        let line = idx + 1;

        if raw.trim().is_empty() {
            continue;
        }

        if let Some(rest) = raw.strip_prefix("package ") {
            let name = rest.trim();
            if name.is_empty() {
                return Err(err(line, raw, ParseErrorKind::MissingPackageName));
            }
            doc.packages.push(Package {
                name: unquote(name, line, raw)?,
                sections: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = raw.strip_prefix("config ") {
            let pkg = doc
                .packages
                .last_mut()
                .ok_or_else(|| err(line, raw, ParseErrorKind::SectionOutsidePackage))?;
            pkg.sections.push(section_header(rest.trim(), line, raw)?);
            continue;
        }

        // Entries are tab-indented. Accept leading spaces too: some tooling
        // reformats exports, and rejecting a semantically identical document
        // over indentation would be a parser that is precious rather than
        // correct. Rendering always emits a tab.
        let trimmed = raw.trim_start_matches(['\t', ' ']);
        let indented = trimmed.len() != raw.len();

        if indented {
            if let Some(rest) = trimmed.strip_prefix("option ") {
                push_entry(&mut doc, EntryKind::Option, rest, line, raw)?;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("list ") {
                push_entry(&mut doc, EntryKind::List, rest, line, raw)?;
                continue;
            }
        }

        return Err(err(line, raw, ParseErrorKind::UnrecognisedLine));
    }

    Ok(doc)
}

fn section_header(rest: &str, line: usize, raw: &str) -> Result<Section, ParseError> {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let kind = parts.next().unwrap_or_default().trim();
    if kind.is_empty() {
        return Err(err(line, raw, ParseErrorKind::MissingSectionType));
    }
    let name = match parts.next().map(str::trim).filter(|s| !s.is_empty()) {
        Some(n) => Some(unquote(n, line, raw)?),
        None => None,
    };
    Ok(Section {
        kind: kind.to_owned(),
        name,
        entries: Vec::new(),
    })
}

fn push_entry(
    doc: &mut Document,
    kind: EntryKind,
    rest: &str,
    line: usize,
    raw: &str,
) -> Result<(), ParseError> {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let key = parts.next().unwrap_or_default().trim();
    let value = parts.next().map(str::trim).unwrap_or_default();
    if key.is_empty() || value.is_empty() {
        return Err(err(line, raw, ParseErrorKind::MalformedEntry));
    }

    let section = doc
        .packages
        .last_mut()
        .and_then(|p| p.sections.last_mut())
        .ok_or_else(|| err(line, raw, ParseErrorKind::EntryOutsideSection))?;

    section.entries.push(Entry {
        kind,
        key: key.to_owned(),
        value: unquote(value, line, raw)?,
    });
    Ok(())
}

/// Strip surrounding single quotes and undo UCI's escaping.
///
/// UCI quotes shell-style: an embedded `'` is written `'\''` — close the quote,
/// an escaped literal quote, reopen. Undoing that here (and redoing it in the
/// renderer) is what keeps a value containing a quote round-trip safe.
///
/// A bare unquoted token is accepted for `package` and section names, which
/// `uci export` emits without quotes.
fn unquote(token: &str, line: usize, raw: &str) -> Result<String, ParseError> {
    if !token.starts_with('\'') {
        // Unquoted: only valid when the token has no whitespace, which is true
        // of every package name and section type UCI emits.
        if token.contains(char::is_whitespace) {
            return Err(err(line, raw, ParseErrorKind::UnquotedValue));
        }
        return Ok(token.to_owned());
    }
    let inner = token
        .strip_prefix('\'')
        .and_then(|t| t.strip_suffix('\''))
        .ok_or_else(|| err(line, raw, ParseErrorKind::UnquotedValue))?;
    Ok(inner.replace("'\\''", "'"))
}

fn err(line: usize, text: &str, kind: ParseErrorKind) -> ParseError {
    ParseError {
        line,
        text: text.to_owned(),
        kind,
    }
}
