//! The façade→ubus adapter: HTTP in, INVOKE out.
//!
//! # What this closes
//!
//! `ubus-facade` emits an `OpenAPI` document describing 264 operations, and
//! `forge-gen` turns that into SDKs, an MCP server and — eventually — a
//! Terraform provider. Every one of those speaks **HTTP**. The device speaks
//! **ubus on a unix socket**, and its own admin panel is a thin client over a
//! JSON-RPC endpoint.
//!
//! Nothing bridged those two until this crate. That is why the façade's
//! `servers` entry carries the note that its base path is not really an HTTP
//! endpoint: an adapter maps each operation to an INVOKE. This is that adapter,
//! and it is what makes the generated artifacts usable rather than notional.
//!
//! ```text
//! generated SDK / provider / MCP  ──HTTP──▶  ubus-http  ──socket──▶  ubusd
//! ```
//!
//! # Where it is meant to run
//!
//! **On the device.** ubus has no authentication whatsoever — its socket is
//! `srw-rw-rw-` and session auth lives only in `rpcd` above it — so anything
//! that can reach this adapter has root-equivalent control of the router.
//! Therefore:
//!
//! - it binds **loopback by default**, and binding elsewhere is an explicit
//!   argument the operator has to type;
//! - it is zero-dependency, so cross-compiling it to `aarch64-linux-musl` for
//!   the router involves no vendoring question.
//!
//! A remote caller reaches it the same way the live tests reach ubus: an
//! `ssh -L` forward. That keeps the trust boundary at ssh, which has
//! authentication, rather than at an HTTP listener that has none.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod http;
pub mod route;

/// The default listen address.
///
/// Loopback, deliberately. See the module docs: an exposed adapter is an
/// unauthenticated root shell for the device.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9797";

/// The ubus socket path on an `OpenWrt` device.
pub const DEFAULT_SOCKET: &str = "/var/run/ubus/ubus.sock";
