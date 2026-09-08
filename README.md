# openwrt-uci

Typed model, parser and renderer for [OpenWrt](https://openwrt.org) UCI
configuration.

UCI is OpenWrt's configuration algebra. `uci export` emits a text document whose
grammar is exactly five line shapes:

```
package <name>

config <type> '<name>'          # named section
config <type>                   # anonymous section
	option <key> '<value>'
	list <key> '<value>'
```

This crate parses that document into a typed model and renders it back
**byte-for-byte**.

```rust
use openwrt_uci::Document;

let doc = Document::parse(&uci_export_text)?;

let lan = doc.package("network").and_then(|p| p.section("lan"));
let addr = lan.and_then(|s| s.option("ipaddr"));

assert_eq!(doc.render(), uci_export_text);   // byte-identical
```

## Design

**Zero dependencies.** This is the foundational layer of a router SDK, and a
router SDK is exactly the kind of thing people vendor into constrained
environments. The grammar does not need a parser generator.

**The model stores structure, not bytes.** The emitted layout is fully regular —
blank line after each `package` header and each section, tab-indented entries,
LF only, no trailing whitespace — so the renderer regenerates it rather than
preserving it.

That is a claim, and it is tested against a *real device's complete export*
rather than a synthetic sample: 70 packages, 387 sections, 1,772 options and 185
lists from a GL.iNet GL-MT6000 running OpenWrt 21.02-SNAPSHOT. If the regularity
claim were false anywhere in those 2,871 lines, the round-trip test would fail.

**Unrecognised input is rejected, never skipped.** A parser that silently drops
lines it does not understand produces a document that renders cleanly and has
quietly lost configuration — on a router, that is a firewall rule that vanished.
Every line is classified or is a `ParseError` carrying its line number.

**Entries are an ordered `Vec`, not a map.** UCI `list` keys repeat and their
order is significant; a map would silently collapse a multi-valued list.

## Scope

This crate models the UCI *document*, generically — it round-trips every package
a device carries, including vendor-specific ones, because round-trip fidelity
cannot be selective. Typed per-package schemas (`network`, `wireless`,
`firewall`, …) and transports (ubus, SSH) are layers above this one.

## Testing

```
cargo test
```

The suite is deliberately two-sided. `round_trip.rs` proves valid input
survives; `rejects.rs` proves the parser refuses malformed input rather than
skipping it, and that the renderer's output actually depends on its input —
the half a broken implementation would also pass.

The fixture is a real device export with 15 credential-bearing values replaced
by `'REDACTED'`. Redaction changes values only, never structure.

## License

MIT
