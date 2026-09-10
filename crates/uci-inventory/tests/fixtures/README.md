# Captured device surfaces

These are the **complete UCI surface of two live routers** — every package
`uci.configs` names, with every section `uci.get` answers. They are captures,
not authorship.

## Why captured and not written

Every other fixture in this crate is hand-written, and a hand-written fixture
encodes what its author expected a router to look like. That is not a
hypothetical failure mode: `secrets-agree-across-bands` shipped green against
hand-written fixtures and was wrong on the first real device it met
(2026-09-10). It compared every carrier of an option across a whole package —
correct on a fixture with one network, wrong on any real router, where a guest
SSID legitimately has its own password and an OpenVPN server key is not its
client key. It turned two healthy routers `fitToShip: false`.

The author of the check also wrote the fixture, so both encoded the same wrong
model and agreed with each other. Only the device disagreed.

## They contain no secrets

Scrubbing is **fail-closed** and lives in `src/capture.rs`, which reads the
crate's own catalog — there is exactly one definition of what is secret, and a
package added to the catalog is covered the same day.

- Every value in a secret-bearing package is replaced unless its field is on the
  explicit `STRUCTURAL` allowlist. An unrecognised field is scrubbed.
- Scrubbing by option **name** alone is not sufficient, and that is measured:
  NordVPN stores its bearer token in `wireguard.<peer>.username`, and `username`
  matches no secret substring. The first capture leaked it.
- Replacements preserve **equality classes** and nothing else — two fields that
  held the same secret hold the same `SECRET-n`. That is precisely what the
  agreement check reasons about, and it is not reversible to a value.
- No digest is stored. A hash of a short PSK is brute-forceable, so it would
  leak the secret through a field that merely looks safe.

## Regenerating

Fixtures go stale as the devices change, and a stale capture asserts a router
that no longer exists. To refresh one, forward to its adapter and capture:

```
ssh -N -L 19797:127.0.0.1:9797 root@<router>
uci-inventory capture --adapter 127.0.0.1:19797 > tests/fixtures/<name>.json
```

Then re-run the suite. `both_real_devices_are_fit_to_ship` failing after a
refresh means the device really did drift — read the named check before
touching the test.

**Scan any refreshed capture before committing it.** The scrubbing is only as
good as the catalog, and a firmware update can introduce a package the catalog
has not classified yet (those are scrubbed whole, but confirm rather than
assume).
