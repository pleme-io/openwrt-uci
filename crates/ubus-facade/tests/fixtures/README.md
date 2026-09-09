# Façade fixtures

## `ubus-v-list.txt` — the device's own method catalog

`ubus -v list`, captured 2026-09-08 from a live GL.iNet GL-MT6000 running
OpenWrt 21.02-SNAPSHOT r15812+1092. **314 lines, 50 objects, 264 methods** —
the figures `docs/roteador.md` §4 records, pinned here to an artifact so the
doc's claim is checkable rather than remembered.

### Why it is safe to commit

**This is a SIGNATURE catalog. It contains no values.** `ubus -v list` prints
each method's parameter *names* and *types* and nothing else, so a line reading
`"login":{"username":"String","password":"String"}` is a declaration that a
method takes a password — not a password. Verified: no `option`/value syntax
appears anywhere in the file.

That distinction is why this fixture needed no redaction while
`openwrt-uci/tests/fixtures/device-export.uci` did — that one is a config
*dump*, which carries live PSKs. Do not conflate the two when adding fixtures.

### Two shapes a reader will not expect

- **Object ids (`'uci' @575a75e0`) are present here and absent from the
  generated spec, deliberately.** An id is assigned at registration and does
  not survive a restart of the owning process, so committing one would make the
  golden diff fail after any reboot — drift with no defect. Ids are resolved by
  LOOKUP at call time.
- **One method carries a bare `"(unknown)"` field with no type**
  (`cellular.collect/clean_traffic`). It is a parameter that exists but whose
  name and type ubus's own printer has no word for. It is counted, never
  dropped, and it forces that one method's schema to stay open — see
  `catalog::Method::undescribed_params`.

## `ubus-facade.openapi.json` — GENERATED, do not edit

Output of `ubus-facade` over the capture above. Regenerate:

```sh
cargo run -p ubus-facade -- crates/ubus-facade/tests/fixtures/ubus-v-list.txt \
  > crates/ubus-facade/tests/fixtures/ubus-facade.openapi.json
```

`the_committed_spec_is_exactly_what_the_generator_emits` byte-compares the two,
so **drift is a red test rather than a stale document**. Red-run verified in
both directions: perturbing the spec fails the diff, and perturbing the capture
fails both the diff and the 50/264 count assertions.

Editing this file by hand is always the wrong move — change the generator, or
re-capture from a device, then regenerate and review the diff.
