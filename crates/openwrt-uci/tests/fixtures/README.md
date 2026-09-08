# Fixtures

## `device-export.uci`

The complete output of `uci export` from a live GL.iNet GL-MT6000 (Flint 2)
running GL firmware 4.9.1 / OpenWrt 21.02-SNAPSHOT, captured 2026-09-05.
2,871 lines, 70 packages, 387 sections.

This is the **round-trip parity fixture**: `parse → render` must reproduce it
byte for byte. That test is the reason to prefer a real export over a synthetic
one — a hand-written fixture only contains the shapes its author already thought
of, and the whole risk in a config parser is the shape you did not think of.
This one contains 197 anonymous sections against 190 named ones, repeated `list`
keys, empty values, and values with embedded quotes and spaces, none of which
were designed in.

### What was substituted, and what was not

The capture came off somebody's actual router, so identifying values are
replaced. **Every substitution is value-for-value and preserves length class,
character case and position**, so the document's *structure* — the thing under
test — is untouched. 27 of 2,871 lines differ from the raw capture.

| original | replacement | why |
|---|---|---|
| WPA keys, VPN keys, passwords, auth blobs | `REDACTED` | credentials |
| 14 MAC addresses | `00:00:5E:00:53:01`…`:0E` | see below |
| 2 SSIDs naming a person | `example-net`, `example-net-5ghz` | see below |
| the device-id token in 5 vendor strings | `abc` | derived from the MAC |

**Why MACs and SSIDs are treated as sensitive even though neither is a secret.**
Both are broadcast in the clear to anyone in radio range, so it is tempting to
call them public and move on. They are individually harmless and dangerous
*together*: wardriving databases index the (SSID, BSSID) pair against GPS
coordinates, so publishing both is publishing an approximate street address. A
leaked password can be rotated; a BSSID that has been indexed cannot be
un-indexed. That asymmetry is why this is redacted at the same tier as the keys
rather than a tier below them.

The replacement MACs are drawn from `00:00:5E:00:53:00–FF`, which
[RFC 7042 §2.1.2](https://www.rfc-editor.org/rfc/rfc7042#section-2.1.2)
reserves for documentation. They are not merely unlikely to collide with real
hardware — they are guaranteed not to, which a randomly-chosen OUI would not be.

**Not substituted, deliberately:** public NTP pool hostnames, `console.gl-inet.com`,
`1.0.0.1`, and the RFC 1918 addressing. None identifies anyone, and blanking
them would make the fixture less representative of a real device for no gain.
