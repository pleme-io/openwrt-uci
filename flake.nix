{
  description =
    "openwrt-uci — the OpenWrt UCI inventory tooling and the Terraform provider that drives it";

  # ── WHY THIS REPO GREW A FLAKE ──────────────────────────────────────────────
  #
  # `terraform-provider-openwrt` is built from THIS repo but was packaged in
  # `pleme-io/nix` — a PRIVATE repo — as an overlay. That put the only
  # derivation for a public artifact somewhere its consumers cannot reach:
  # `pangea-operator` (public) bakes a provider mirror into its operator image
  # and could not include this provider, so the mirror and the plo host had
  # DIFFERENT provider sets, joined at the node with a `symlinkJoin`. The
  # consequence was concrete rather than theoretical — an operator running as a
  # Pod, from the image, had no router provider at all, so every roteador
  # InfrastructureTemplate would have planned straight into ProviderUnavailable.
  #
  # ★★ TOOL DISTRIBUTION: a repo builds its own artifacts, and consumers are
  # config-only. The derivation belongs here, once, where the source is.
  #
  # ── The vendorHash is MEASURED, not fresh ──────────────────────────────────
  # A fixed-output hash is reused from the store whenever it matches, so a
  # stale one does not fail: it vendors the OLD package set and the build then
  # fails on a missing import. Re-measure it with a fake hash whenever the
  # provider's imports change (last: the `mapplanmodifier` import, 2026-10-24).

  inputs = {
    # The fleet anchor, reached through substrate so this repo cannot drift
    # onto a different nixpkgs than everything it ships beside.
    nixpkgs.follows = "substrate/nixpkgs";
    substrate.url = "github:pleme-io/substrate";
  };

  outputs =
    { self, nixpkgs, substrate, ... }:
    (import "${substrate}/lib/build/go/tool-release-flake.nix" {
      inherit nixpkgs;

      # ── goToolchain is DELIBERATELY left at its null default ─────────────
      # The helper's doc suggests passing `substrate.goToolchains.<system>.stable`
      # to avoid building Go. Tried, then reverted after reading how it is
      # consumed: `mkGoPkgs` takes ONE toolchain and is called PER SYSTEM
      # (tool-release-flake.nix:71), so a single value would hand this darwin
      # workstation's compiler to an x86_64-linux build. The null default is not
      # the slow path being tolerated — it is the only per-system-correct one,
      # deriving the SAME pin (lib/build/go/go-toolchain-pin.json) from each
      # target's own nixpkgs. The first build per system pays for the compiler;
      # every one after is a cache hit.
    })
      {
        toolName = "terraform-provider-openwrt";
        version = "0.1.0";
        src = self;

        # One Go module inside a mostly-Rust repo — the monorepo case the
        # helper documents (`modRoot — Go module root within source`).
        modRoot = "provider/terraform";

        vendorHash = "sha256-4di0oi0tXfEVhBCGXugqv09T6rtsWp37p/zBOH+lDhM=";

        repo = "pleme-io/openwrt-uci";

        # `CGO_ENABLED` is deliberately NOT set, and this is the one knob worth
        # explaining rather than copying. Its contract INVERTS across nixpkgs
        # revisions — a top-level attr on older, `env` only on newer — and
        # setting the wrong form is SILENT: the attribute is ignored, cgo stays
        # on, and the binary gains a libc dependency nothing downstream catches.
        # `nix/lib/go-cgo-contract-witness.nix` exists as a fleet tripwire on
        # exactly that. A provider magma spawns on a glibc host needs no static
        # link, so the safest move is to not touch the knob at all.
      };
}
