# `terraform-provider-openwrt`

A Terraform/OpenTofu provider that manages UCI sections on an OpenWrt device,
through the ubus façade over HTTP.

```
tofu ──▶ this provider ──HTTP──▶ ubus-http ──socket──▶ ubusd ──▶ device
```

## Verified end to end against a real GL.iNet GL-MT6000

Not a plan, not a compile check — the full resource lifecycle, then cleaned up:

| step | evidence |
|---|---|
| `tofu apply` | `Creation complete [id=claude_tf_probe.managed_by_tofu]`, and `/etc/config/claude_tf_probe` held `config marker 'managed_by_tofu'` |
| `tofu plan` again | **`No changes. Your infrastructure matches the configuration.`** — the load-bearing one: it proves `Read` reflects the device rather than echoing state |
| `tofu apply` after an edit | `1 changed`, and the device showed `stage='two'` |
| `tofu destroy` | `1 destroyed`, section gone from the file |

Run against a device with a loopback-forwarded ubus socket — see
`nix/docs/roteador.md` §16 for the relay recipe, and note the `ssh -L` form that
forwards a LOCAL UNIX SOCKET to the router's loopback, which lets the adapter's
`connect_unix` work unchanged from a workstation:

```sh
ssh -L /tmp/ubus-fwd.sock:127.0.0.1:21112 root@192.168.8.1 'lua /tmp/ubus-relay.lua 21112' &
ubus-http --spec <facade.json> --socket /tmp/ubus-fwd.sock --listen 127.0.0.1:9797 &
TF_CLI_CONFIG_FILE=<tofurc-with-dev_overrides> tofu apply
```

## ★ This is the MEASURED TARGET, and it is meant to be replaced by generation

Pillar 12 is generation over composition, and `docs/roteador.md` §7 says the
provider is generated. So why is this hand-written?

**Because a generator for an unvalidated output shape is fiction with a type
signature.** The correct order is measure, then generate — the same order that
produced every other artifact here: the UCI model came from a real `uci export`,
the ubus constants from captured bytes, the façade from the device's own
`ubus -v list`.

This file is that measurement. `iac-forge`'s `TerraformBackend` gets written to
emit it, and its output is **byte-compared against this file** — the crdgen
discipline, and the same gate `ubus-facade` already uses for the façade.

**Do not extend this by hand once the generator exists.** Until then it is a
working provider, and the shape it establishes is not guesswork.

## The two corrections the device forced

- **CREATE IS `add`, NOT `set`.** A first cut used `/uci/set` with a `type`, on
  the assumption that `add` only makes anonymous sections. The device returned
  ubus **status 4 (not found)**: `uci set` against a section that does not exist
  yet cannot create it. `uci.add` takes a `name`, and that is what makes a
  section named. The resource spec's `create_endpoint = "/uci/add"` had been
  right all along, and the code's comment claiming otherwise was wrong.
- **Every mutation commits.** UCI stages into a delta, so without an explicit
  `/uci/commit` a created section vanishes on reboot while Terraform's state
  still claimed it existed — state that disagrees with a device after a power
  cycle is worse than a failed apply.

And one thing `Read` must do rather than not: a section that is **gone** calls
`RemoveResource`, not an error. Leaving it in state makes the next plan try to
update something absent.

`.type`, `.name` and `.anonymous` are stripped from the read-back values: they
are UCI bookkeeping, and surfacing them as options would make every plan dirty.
