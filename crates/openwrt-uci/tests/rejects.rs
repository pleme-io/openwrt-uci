//! Negative tests — the half that makes the round-trip test mean something.
//!
//! `round_trip.rs` proves valid input survives. On its own that is exactly the
//! half a *broken* parser also passes: one that silently skips lines it does
//! not understand would round-trip everything it kept and quietly drop the
//! rest. These tests prove the parser refuses instead of skipping, and that
//! the renderer's output actually depends on the input.

use openwrt_uci::Document;

#[test]
fn an_unrecognised_line_is_an_error_not_a_skip() {
    // The failure mode this guards: a parser that ignores what it cannot
    // classify produces a document that renders cleanly and has silently lost
    // configuration. On a router that is a firewall rule that vanished.
    let src = "package net\n\nconfig iface 'lan'\n\toption proto 'static'\nthis is not uci\n";
    let err = Document::parse(src).expect_err("unknown line must be rejected");
    assert_eq!(err.line, 5, "must report the offending line number");
    assert!(err.text.contains("not uci"));
}

#[test]
fn an_entry_before_any_section_is_rejected() {
    let src = "package net\n\n\toption orphan 'x'\n";
    let err = Document::parse(src).expect_err("orphan entry must be rejected");
    assert_eq!(err.line, 3);
}

#[test]
fn a_section_before_any_package_is_rejected() {
    let src = "config iface 'lan'\n";
    let err = Document::parse(src).expect_err("section outside package must be rejected");
    assert_eq!(err.line, 1);
}

#[test]
fn render_actually_depends_on_the_input() {
    // Guards the degenerate renderer: one that emitted a constant, or echoed
    // its input, would pass a round-trip test while being useless.
    let a = Document::parse("package p\n\nconfig s 'one'\n\toption k 'v'\n\n").unwrap();
    let b = Document::parse("package p\n\nconfig s 'two'\n\toption k 'v'\n\n").unwrap();
    assert_ne!(a.render(), b.render());
}

#[test]
fn a_value_containing_a_quote_survives_the_round_trip() {
    // UCI quotes shell-style: an embedded ' is written '\''. Parser and
    // renderer must be exact inverses, or a password containing an apostrophe
    // corrupts on write. No such value appears in the device fixture, so this
    // is the only place the escaping is exercised.
    let value = "it's \"quoted\" oddly";
    let doc = Document::parse("package p\n\nconfig s 'n'\n\toption k 'x'\n\n").unwrap();
    let mut doc = doc;
    doc.packages[0].sections[0].entries[0].value = value.to_owned();

    let rendered = doc.render();
    assert!(
        rendered.contains(r#"'it'\''s "quoted" oddly'"#),
        "escaping: {rendered}"
    );

    let reparsed = Document::parse(&rendered).expect("escaped value must re-parse");
    assert_eq!(reparsed.packages[0].sections[0].entries[0].value, value);
    assert_eq!(
        reparsed.render(),
        rendered,
        "second round trip must be stable"
    );
}

#[test]
fn anonymous_sections_round_trip_without_gaining_a_name() {
    let src = "package p\n\nconfig anon\n\toption k 'v'\n\n";
    let doc = Document::parse(src).unwrap();
    assert!(doc.packages[0].sections[0].name.is_none());
    assert_eq!(doc.render(), src);
}
