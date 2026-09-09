//! What we are allowed to do with each UCI package — and the refusal that makes
//! the answer complete rather than approximate.
//!
//! # Why a classification exists at all
//!
//! Measured on a GL-MT6000 (GL.iNet Flint 2) on 2026-09-09: **72 packages,
//! 2229 assignments, ~200 named sections and ~232 anonymous ones.** Declaring
//! all of it would be the wrong kind of thorough:
//!
//! - **`mtkhnat` alone carries 128 anonymous `queue` sections** — a vendor `HQoS`
//!   table. Declaring 128 queues teaches nobody anything and buries the six
//!   lines that matter.
//! - **Nine packages carry secret material**, including `WireGuard` private keys
//!   (`wireguard.*.key`), the wifi PSK (`wireless.*.key`) and the web-UI
//!   password (`rpcd.*.password`). Deriving those into a values file puts them
//!   in git.
//! - Vendor application packages (`gl_dpi_flow_statistics`, `gl_logread`, …)
//!   hold state their own daemons rewrite. Declaring it means fighting the
//!   device forever and calling the resulting permanent drift "coverage".
//!
//! So the honest unit of progress is not "how many sections do we declare" but
//! **"is every package on the device accounted for"** — with a stated reason
//! for each one we decline.
//!
//! # The gate
//!
//! [`classify`] returns `None` for a package the catalog has never heard of,
//! and every caller treats that as a **refusal**. That is what keeps the
//! denominator honest: a firmware upgrade that introduces a package cannot
//! quietly land in the unmanaged pile, because nothing has a disposition for it
//! and the survey fails naming it.
//!
//! Tier-honest: this is **parse-time-rejected** (a typed refusal at the border
//! of the tool), not unrepresentable. Nothing stops someone writing a chart
//! entry by hand for a `DeviceOwned` package.

/// What we do with a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Declared in our config; drift is detected AND corrected.
    Managed,

    /// The device or its vendor firmware owns this. We never write it.
    ///
    /// This is not "unimportant" — it is "not ours". Declaring it would produce
    /// permanent drift against a daemon that rewrites it.
    DeviceOwned {
        /// Why the device owns it. Shown in the survey, so a reader can
        /// challenge the call rather than inherit it.
        why: &'static str,
    },

    /// Holds material that must never reach git.
    ///
    /// Distinct from `DeviceOwned` because the DESTINATION differs: this is
    /// config we would legitimately want to own, blocked on materialising its
    /// secrets through `cofre` rather than on ownership. Collapsing the two
    /// arms would lose exactly that — the fact that these are pending work and
    /// `DeviceOwned` is a settled decision.
    SecretBearing {
        /// The option(s) that make it secret-bearing, named so the claim is
        /// checkable.
        why: &'static str,
    },
}

impl Disposition {
    /// Whether our config declares this package.
    #[must_use]
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Managed)
    }

    /// A short tag for reports.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::DeviceOwned { .. } => "device-owned",
            Self::SecretBearing { .. } => "secret-bearing",
        }
    }

    /// The stated reason, or `None` for `Managed` (which needs no excuse).
    #[must_use]
    pub const fn why(self) -> Option<&'static str> {
        match self {
            Self::Managed => None,
            Self::DeviceOwned { why } | Self::SecretBearing { why } => Some(why),
        }
    }
}

const MANAGED: Disposition = Disposition::Managed;

/// Every package measured on the device, with what we do about it.
///
/// ★ The list is EXHAUSTIVE against a real device on purpose. A shorter list
/// plus a permissive default would let a new package arrive unnoticed, which is
/// the single failure this whole classification exists to prevent.
pub const CATALOG: &[(&str, Disposition)] = &[
    // ── Managed: standard OpenWrt packages with documented, stable semantics
    // that we actually want to own. Deliberately small. A package earns its way
    // in by being understood, not by being present.
    ("roteador", MANAGED), // ours: the fleet-metadata marker
    ("system", MANAGED),   // hostname, timezone, log sinks
    ("network", MANAGED),  // interfaces, devices, routes
    ("firewall", MANAGED), // zones, forwardings, rules
    ("dhcp", MANAGED),     // dnsmasq + static leases + domains
    ("dropbear", MANAGED), // ssh access policy
    ("chrony", MANAGED),   // time sync
    // ── Secret-bearing: we want these, and cannot have them until the secret
    // is materialised out-of-band. The named option is the blocker.
    ("wireless", Disposition::SecretBearing { why: "wireless.*.key is the wifi PSK" }),
    ("wireguard", Disposition::SecretBearing { why: "wireguard.*.key holds private keys" }),
    ("wireguard_server", Disposition::SecretBearing { why: "server private key" }),
    ("openvpn", Disposition::SecretBearing { why: "embedded keys / auth material" }),
    ("ovpnclient", Disposition::SecretBearing { why: "embedded keys / auth material" }),
    ("ovpnserver", Disposition::SecretBearing { why: "embedded keys / auth material" }),
    ("expressvpn", Disposition::SecretBearing { why: "third-party VPN credentials" }),
    // ★ MEASURED 2026-09-09 and RECLASSIFIED from SecretBearing.
    //
    // The precautionary guess was "may carry an auth key". It does not: the
    // whole UCI surface is `enabled`, `port`, `state_file`, `log_stdout`,
    // `log_stderr` — read by `/etc/init.d/tailscale`, which starts `tailscaled`
    // and never runs `tailscale up`. The node key and auth material live in the
    // file that `state_file` NAMES (`/etc/tailscale/tailscaled.state`), and a
    // path is not material.
    //
    // That split is what makes tailscale declarable at all: the DAEMON is UCI
    // and reconciles like anything else, while the tailnet LOGIN is a one-time
    // bootstrap whose result persists in the state file.
    //
    // `pending-tailscale-login-declared: `tailscale up` is a bootstrap step,
    // like the adapter install — the auth key comes from sops `tailscale/auth-key`.`
    ("tailscale", MANAGED),
    ("zerotier", Disposition::SecretBearing { why: "network identity / secrets" }),
    ("tor", Disposition::SecretBearing { why: "onion service keys" }),
    ("samba4", Disposition::SecretBearing { why: "share credentials" }),
    ("rpcd", Disposition::SecretBearing { why: "rpcd.*.password is the web-UI login" }),
    ("uhttpd", Disposition::SecretBearing {
        why: "uhttpd.*.key names a TLS key; fail-closed until measured as a path, not material",
    }),
    ("stubby", Disposition::SecretBearing { why: "TLS auth material for DNS-over-TLS" }),
    ("glconfig", Disposition::SecretBearing { why: "vendor cloud/device credentials" }),
    ("gl-cloud", Disposition::SecretBearing { why: "vendor cloud enrolment" }),
    ("mptun", Disposition::SecretBearing { why: "tunnel credentials" }),
    ("gl_s2s", Disposition::SecretBearing { why: "site-to-site tunnel credentials" }),
    ("rtty", Disposition::SecretBearing { why: "remote-terminal enrolment token" }),
    // ── Device-owned: the firmware or a vendor daemon writes it.
    ("mtkhnat", Disposition::DeviceOwned { why: "128 vendor HQoS queue sections; hardware offload table" }),
    ("mtkhnat_dummy", Disposition::DeviceOwned { why: "vendor offload placeholder" }),
    ("TRL", Disposition::DeviceOwned { why: "vendor runtime marker" }),
    ("board_special", Disposition::DeviceOwned { why: "per-board hardware facts, set by firmware" }),
    ("switch-button", Disposition::DeviceOwned { why: "hardware button mapping" }),
    ("ubootenv", Disposition::DeviceOwned { why: "bootloader environment" }),
    ("upgrade", Disposition::DeviceOwned { why: "firmware upgrade bookkeeping" }),
    ("fstab", Disposition::DeviceOwned { why: "generated from attached storage" }),
    ("nas", Disposition::DeviceOwned { why: "vendor NAS app state" }),
    ("gl_nas", Disposition::DeviceOwned { why: "vendor NAS app state" }),
    ("minidlna", Disposition::DeviceOwned { why: "vendor media app state" }),
    ("cellular", Disposition::DeviceOwned { why: "modem runtime state" }),
    ("glmodem", Disposition::DeviceOwned { why: "modem runtime state" }),
    ("apnprofile", Disposition::DeviceOwned { why: "carrier APN database shipped by firmware" }),
    ("custom_apn", Disposition::DeviceOwned { why: "carrier APN overrides" }),
    ("repeater", Disposition::DeviceOwned { why: "repeater runtime association state" }),
    ("edgerouter", Disposition::DeviceOwned { why: "vendor feature toggle store" }),
    ("kmwan", Disposition::DeviceOwned { why: "vendor multi-wan daemon state" }),
    ("qos", Disposition::DeviceOwned { why: "vendor QoS app state" }),
    ("sqm", Disposition::DeviceOwned { why: "vendor SQM app state" }),
    ("fullconenat", Disposition::DeviceOwned { why: "vendor NAT feature toggle" }),
    ("sip_alg", Disposition::DeviceOwned { why: "vendor ALG toggle" }),
    ("port_forward", Disposition::DeviceOwned { why: "vendor UI mirror of firewall rules" }),
    ("glforward", Disposition::DeviceOwned { why: "vendor UI mirror of firewall rules" }),
    ("wan-access", Disposition::DeviceOwned { why: "vendor UI mirror of firewall rules" }),
    ("route_policy", Disposition::DeviceOwned { why: "vendor policy-routing app state" }),
    ("glipv6", Disposition::DeviceOwned { why: "vendor IPv6 mode selector" }),
    ("gl-dns-v2", Disposition::DeviceOwned { why: "vendor DNS app state" }),
    ("gl_ddns", Disposition::DeviceOwned { why: "vendor DDNS app state" }),
    ("adguardhome", Disposition::DeviceOwned { why: "third-party app, own config lifecycle" }),
    ("netifyd", Disposition::DeviceOwned { why: "DPI daemon state" }),
    ("netify-proc-flow-actions", Disposition::DeviceOwned { why: "DPI daemon state" }),
    ("gl_dpi", Disposition::DeviceOwned { why: "DPI daemon state" }),
    ("gl_dpi_qos", Disposition::DeviceOwned { why: "DPI daemon state" }),
    ("gl_dpi_content_protection", Disposition::DeviceOwned { why: "DPI daemon state" }),
    ("gl_dpi_flow_statistics", Disposition::DeviceOwned { why: "DPI runtime statistics" }),
    ("gl_category", Disposition::DeviceOwned { why: "DPI category database" }),
    ("gl-tertf", Disposition::DeviceOwned { why: "traffic accounting runtime state" }),
    ("gl_logread", Disposition::DeviceOwned { why: "log daemon state" }),
    ("gl_led", Disposition::DeviceOwned { why: "vendor LED app state" }),
    ("gl_timer", Disposition::DeviceOwned { why: "vendor scheduled-reboot app state" }),
    ("gl_block", Disposition::DeviceOwned { why: "vendor block-device app state" }),
    ("gl-black_white_list", Disposition::DeviceOwned { why: "vendor MAC filter app state" }),
    ("parental_control", Disposition::DeviceOwned { why: "vendor parental-control app state" }),
    ("parental_control_v2", Disposition::DeviceOwned { why: "vendor parental-control app state" }),
    ("parental_control_apps", Disposition::DeviceOwned { why: "vendor app signature database" }),
    ("plugins", Disposition::DeviceOwned { why: "vendor plugin registry" }),
    ("oui-httpd", Disposition::DeviceOwned { why: "vendor web-UI daemon config" }),
    ("switch", Disposition::DeviceOwned { why: "legacy swconfig hardware map" }),
];

/// The disposition for `package`, or `None` if the catalog has never seen it.
///
/// `None` is a **refusal**, not a default — see the module docs.
#[must_use]
pub fn classify(package: &str) -> Option<Disposition> {
    CATALOG
        .iter()
        .find(|(name, _)| *name == package)
        .map(|(_, d)| *d)
}

/// Option names that LOOK secret-bearing but are measured not to be.
///
/// ★ Direction matters here and it is deliberately asymmetric. Secret detection
/// is a SUBSTRING match (below), because an unknown option holding a key must
/// be refused rather than emitted — a false positive costs a line in this list,
/// a false negative puts a private key in git. These are the measured
/// exceptions, each of which contains a trigger substring and is genuinely not
/// secret material.
pub const NOT_SECRET: &[&str] = &[
    "key_type",                   // selects a key ALGORITHM
    "persist_key",                // a boolean
    "tls_auth_name",              // names a file
    "tls_authentication",         // a boolean
    "auth_type",                  // selects an auth MODE
    "client_auth",                // a boolean
    "authoritative",              // dnsmasq flag
    "edns_client_subnet_private", // dnsmasq flag
    "authserver",                 // a hostname
    "keyfile",                    // a PATH, not material
    "keyexchange",                // an algorithm list
    // Measured on the live device 2026-09-09, found BY this gate refusing to
    // derive `dropbear`: both are `on`/`off` flags, not material. Matching is
    // case-insensitive, so `PasswordAuth` arrives here lowercased.
    "passwordauth",
    "rootpasswordauth",
];

const SECRET_SUBSTRINGS: &[&str] = &[
    "key", "password", "passwd", "secret", "token", "psk", "private", "credential", "auth",
];

/// Whether an option name must be treated as secret-bearing.
///
/// Fails closed: unknown names containing a trigger substring are secret.
#[must_use]
pub fn option_is_secret(option: &str) -> bool {
    let lower = option.trim_start_matches('.').to_ascii_lowercase();
    if NOT_SECRET.contains(&lower.as_str()) {
        return false;
    }
    SECRET_SUBSTRINGS.iter().any(|s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_no_duplicate_packages() {
        // A duplicate would make `classify` return whichever came first, so the
        // second, likely-more-considered entry would be silently dead.
        let mut names: Vec<&str> = CATALOG.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate package in CATALOG");
    }

    #[test]
    fn unknown_package_is_refused_not_defaulted() {
        assert!(classify("a_package_from_a_future_firmware").is_none());
    }

    #[test]
    fn every_measured_package_is_classified() {
        // The 72 packages measured on the live GL-MT6000, 2026-09-09. This is
        // the denominator: if the survey ever finds one of these unclassified,
        // the catalog regressed.
        for p in [
            "TRL", "adguardhome", "apnprofile", "board_special", "cellular", "chrony",
            "custom_apn", "dhcp", "dropbear", "edgerouter", "expressvpn", "firewall", "fstab",
            "fullconenat", "gl-black_white_list", "gl-cloud", "gl-dns-v2", "gl-tertf", "gl_block",
            "gl_category", "gl_ddns", "gl_dpi", "gl_dpi_content_protection",
            "gl_dpi_flow_statistics", "gl_dpi_qos", "gl_led", "gl_logread", "gl_nas", "gl_s2s",
            "gl_timer", "glconfig", "glforward", "glipv6", "glmodem", "kmwan", "minidlna",
            "mptun", "mtkhnat", "nas", "netify-proc-flow-actions", "netifyd", "network",
            "openvpn", "oui-httpd", "ovpnclient", "ovpnserver", "parental_control",
            "parental_control_apps", "parental_control_v2", "plugins", "port_forward", "qos",
            "repeater", "roteador", "route_policy", "rpcd", "rtty", "samba4", "sip_alg", "sqm",
            "stubby", "switch-button", "system", "tailscale", "tor", "ubootenv", "uhttpd",
            "upgrade", "wan-access", "wireguard", "wireguard_server", "wireless", "zerotier",
        ] {
            assert!(classify(p).is_some(), "unclassified measured package: {p}");
        }
    }

    #[test]
    fn secret_detection_fails_closed_but_not_blindly() {
        // Real secrets.
        assert!(option_is_secret("key"));
        assert!(option_is_secret("password"));
        assert!(option_is_secret("private_key"));
        assert!(option_is_secret("preshared_key"));
        // Measured non-secrets that contain a trigger substring. Each of these
        // was observed on the device; without NOT_SECRET they would block
        // legitimate managed config.
        assert!(!option_is_secret("key_type"));
        assert!(!option_is_secret("persist_key"));
        assert!(!option_is_secret("auth_type"));
        assert!(!option_is_secret("authoritative"));
        assert!(!option_is_secret("edns_client_subnet_private"));
        // An option nobody has measured yet, containing a trigger: refused.
        assert!(option_is_secret("some_new_api_token"));
    }

    #[test]
    fn managed_set_carries_no_secret_bearing_package() {
        // The two classifications must not disagree: a package cannot be both
        // ours to declare and blocked on secret materialisation.
        for (name, d) in CATALOG {
            if d.is_managed() {
                assert!(
                    !matches!(classify(name), Some(Disposition::SecretBearing { .. })),
                    "{name} is both managed and secret-bearing"
                );
            }
        }
    }

    #[test]
    fn every_declined_package_states_a_reason() {
        for (name, d) in CATALOG {
            if !d.is_managed() {
                let why = d.why().unwrap_or("");
                assert!(
                    why.len() > 8,
                    "{name} declines with no usable reason: {why:?}"
                );
            }
        }
    }
}
