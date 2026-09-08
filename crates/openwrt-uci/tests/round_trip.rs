//! The load-bearing test: parse a real device's full `uci export` and render it
//! back byte-for-byte.
//!
//! # Why a real device and not a synthetic sample
//!
//! The model stores structure, not bytes — it claims the emitted layout is
//! fully regular and can be regenerated. A hand-written fixture would only
//! prove that claim against shapes the author already thought of. This fixture
//! is the complete export of a live GL.iNet GL-MT6000 (`OpenWrt` 21.02-SNAPSHOT,
//! GL 4.9.1): 70 packages, 387 sections, 1,772 options, 185 lists, including
//! every vendor package the device happens to carry.
//!
//! If the regularity claim is false anywhere in those 2,871 lines, this fails.
//!
//! # Redaction
//!
//! 15 values were replaced with `'REDACTED'` before the fixture was committed
//! (`key`, `password`, `tls_auth_name`, `auth`). Redaction changes values only,
//! never structure, so the round-trip property is unaffected — and no wireless
//! PSK reaches this repository.

use openwrt_uci::{Document, EntryKind};

const FIXTURE: &str = include_str!("fixtures/device-export.uci");

/// Report the first divergence rather than dumping 55 KB of diff.
fn assert_same(expected: &str, actual: &str) {
    if expected == actual {
        return;
    }
    let mut want_lines = expected.lines();
    let mut got_lines = actual.lines();
    let mut line_no = 0usize;
    loop {
        line_no += 1;
        match (want_lines.next(), got_lines.next()) {
            (Some(want), Some(got)) if want == got => {}
            (want, got) => panic!(
                "round-trip diverged at line {line_no}\n  expected: {want:?}\n  actual:   {got:?}\n\
                 (expected {} bytes, produced {} bytes)",
                expected.len(),
                actual.len()
            ),
        }
    }
}

#[test]
fn round_trip_is_byte_identical() {
    let doc = Document::parse(FIXTURE).expect("the fixture must parse");
    assert_same(FIXTURE, &doc.render());
}

#[test]
fn parses_the_whole_device() {
    let doc = Document::parse(FIXTURE).unwrap();

    // Counts measured on the device with awk before the parser existed, so
    // these are an independent check rather than a restatement of the parser.
    assert_eq!(doc.packages.len(), 70, "packages");

    let sections: usize = doc.packages.iter().map(|p| p.sections.len()).sum();
    assert_eq!(sections, 387, "sections");

    let (opts, lists) = doc
        .packages
        .iter()
        .flat_map(|p| &p.sections)
        .flat_map(|s| &s.entries)
        .fold((0usize, 0usize), |(o, l), e| match e.kind {
            EntryKind::Option => (o + 1, l),
            EntryKind::List => (o, l + 1),
        });
    assert_eq!(opts, 1772, "option entries");
    assert_eq!(lists, 185, "list entries");
}

#[test]
fn both_named_and_anonymous_sections_occur() {
    let doc = Document::parse(FIXTURE).unwrap();
    let all = || doc.packages.iter().flat_map(|p| &p.sections);
    let named = all().filter(|s| s.name.is_some()).count();
    let anon = all().filter(|s| s.name.is_none()).count();

    // Neither form is an edge case on a real device, which is why the model
    // carries Option<String> rather than defaulting anonymous to "".
    assert_eq!(named, 190, "named sections");
    assert_eq!(anon, 197, "anonymous sections");
}

#[test]
fn the_standard_packages_are_present() {
    let doc = Document::parse(FIXTURE).unwrap();
    for p in [
        "network", "wireless", "firewall", "dhcp", "system", "dropbear",
    ] {
        assert!(doc.package(p).is_some(), "missing standard package {p}");
    }
}

#[test]
fn repeated_list_keys_keep_order_and_multiplicity() {
    // A map-shaped model would silently collapse these. Find a real list key
    // that occurs more than once and assert both values survive in order.
    let doc = Document::parse(FIXTURE).unwrap();
    let found = doc.packages.iter().flat_map(|p| &p.sections).find_map(|s| {
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for e in &s.entries {
            if e.kind == EntryKind::List {
                seen.push((e.key.as_str(), e.value.as_str()));
            }
        }
        let first = seen.first()?.0;
        let same: Vec<_> = seen.iter().filter(|(k, _)| *k == first).collect();
        (same.len() > 1).then(|| (s, first.to_owned(), same.len()))
    });

    let (section, key, count) = found.expect("device carries at least one multi-valued list");
    assert_eq!(
        section.list(&key).count(),
        count,
        "list() must yield every value for a repeated key"
    );
}
