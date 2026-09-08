//! Transport abstraction for reaching an `OpenWrt` device, and the typed
//! host-key policy that governs trusting one.
//!
//! # Why a trait
//!
//! An `OpenWrt` device is reachable several ways — `ssh` running `uci`, the ubus
//! HTTP endpoint, a serial console during bootstrap. They differ in how bytes
//! move, not in what is asked. One trait keeps the UCI layer above from caring,
//! and gives tests a seam that needs no device.
//!
//! # Why host-key policy is a type, not a boolean
//!
//! The reference implementation this replaces had:
//!
//! ```ignore
//! async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool> {
//!     Ok(true)   // "Accept all host keys (like Packer does by default)"
//! }
//! ```
//!
//! That is defensible for an ephemeral build VM whose identity is meaningless,
//! and indefensible for a router that lives at a remote site for years — it
//! accepts a man-in-the-middle silently, on the one connection that carries
//! credentials.
//!
//! The fix is not "remember to pass `true`". It is [`HostKeyPolicy`], where the
//! unsafe option is a variant you must name, spell out, and justify in code.
//! Accepting any key is still possible — a bootstrap over a cable to a
//! factory-fresh device is a real case — but it can no longer happen by
//! omission or by copying a default.

#![forbid(unsafe_code)]

use openwrt_uci::Document;
use std::fmt;

pub mod mock;
pub mod ssh;

pub use ssh::{SshTarget, SshTransport};

/// How to decide whether a server's host key is the one we meant to reach.
///
/// There is deliberately no `Default`. A caller must choose, because the right
/// answer differs between "bootstrapping a factory device over a cable" and
/// "reaching a production router across the internet", and a default would
/// silently pick one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Require this exact key fingerprint. The correct policy for any device
    /// that has been bootstrapped and has a recorded identity.
    Pinned(String),

    /// Accept whatever key is presented on first contact, record it, and
    /// require it to match thereafter.
    ///
    /// Honest about what it buys: it detects a key *change*, not a first-contact
    /// impostor. Adequate on a trusted LAN during bootstrap; not adequate as a
    /// standing policy for a remote device.
    TrustOnFirstUse { known_hosts: std::path::PathBuf },

    /// Accept any key, verifying nothing.
    ///
    /// Named to be unpleasant, and carries a required justification so the
    /// reason is in the source rather than in someone's memory. Legitimate for
    /// a factory device on a cable you are physically holding. Never for a
    /// device with a tailnet address.
    AcceptAnyInsecure { justification: &'static str },
}

impl HostKeyPolicy {
    /// Whether this policy actually verifies identity.
    ///
    /// Exists so that callers with a security-relevant decision (writing
    /// credentials, say) can refuse to proceed over an unverified channel
    /// rather than each re-deriving the check.
    #[must_use]
    pub fn verifies_identity(&self) -> bool {
        !matches!(self, Self::AcceptAnyInsecure { .. })
    }
}

/// The result of running a command on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl Output {
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Debug)]
pub enum TransportError {
    /// The device could not be reached at all.
    Unreachable(String),
    /// Reached, but the host key did not satisfy the policy.
    HostKeyRejected { expected: String, presented: String },
    /// Reached and trusted, but authentication failed.
    AuthFailed(String),
    /// The command ran and failed.
    CommandFailed { command: String, output: Output },
    /// The device answered, but not with something we could parse.
    Malformed(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(d) => write!(f, "device unreachable: {d}"),
            Self::HostKeyRejected {
                expected,
                presented,
            } => write!(
                f,
                "host key mismatch: expected {expected}, device presented {presented}"
            ),
            Self::AuthFailed(d) => write!(f, "authentication failed: {d}"),
            Self::CommandFailed { command, output } => write!(
                f,
                "`{command}` exited {}: {}",
                output.exit_code,
                output.stderr.trim()
            ),
            Self::Malformed(d) => write!(f, "unparseable response: {d}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A way of running commands on an `OpenWrt` device.
///
/// Synchronous by design. Router operations are a handful of round trips over
/// a low-latency link, and an async trait would impose a runtime on every
/// consumer — including a CLI that does one thing and exits — to buy
/// concurrency nothing here needs. A caller wanting to reach four routers at
/// once can spawn four threads.
pub trait Transport {
    /// Run a command and return its output.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the device is unreachable, rejects the
    /// host key, or fails authentication. A command that runs and exits
    /// non-zero is returned as `Ok` with a non-zero `exit_code` — that is a
    /// result, not a transport failure, and conflating them would make
    /// "no such config" indistinguishable from "the network is down".
    fn exec(&mut self, command: &str) -> Result<Output, TransportError>;

    /// A short description of what is on the other end, for diagnostics.
    fn target(&self) -> String;
}

/// Reads UCI configuration from a device over any [`Transport`].
///
/// Read-only by construction: there is no method here that mutates the device.
/// The write path is a separate type, so a caller holding a `UciReader` cannot
/// change a router by accident — and a review can tell read code from write
/// code by its type.
pub struct UciReader<T: Transport> {
    transport: T,
}

impl<T: Transport> UciReader<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Fetch and parse the device's complete UCI configuration.
    ///
    /// # Errors
    ///
    /// Fails if the device is unreachable, if `uci export` exits non-zero, or
    /// if its output does not parse.
    pub fn export(&mut self) -> Result<Document, TransportError> {
        let out = self.transport.exec("uci export")?;
        if !out.success() {
            return Err(TransportError::CommandFailed {
                command: "uci export".to_owned(),
                output: out,
            });
        }
        Document::parse(&out.stdout).map_err(|e| TransportError::Malformed(e.to_string()))
    }

    /// Fetch a single package rather than the whole configuration.
    ///
    /// A package the device does not have is *not* an error: this returns
    /// `Ok(None)`. "Absent" and "failed" are different answers and must not
    /// render the same — collapsing them makes a typo indistinguishable from an
    /// outage.
    ///
    /// # How absence is actually detected
    ///
    /// ★ Measured on a live device (GL-MT6000, `OpenWrt` 21.02), because the
    /// obvious guess is wrong:
    ///
    /// ```text
    /// uci export dropbear                 -> exit 0
    /// uci export definitely_not_a_package -> exit 1, stderr "uci: Entry not found"
    /// ```
    ///
    /// An earlier version of this function assumed absence meant *exit 0 with
    /// empty output*. It does not. That assumption passed every mock-driven
    /// test — because the mock was written from the same assumption — and was
    /// caught only by running against a device. Absence is therefore matched on
    /// the exit code **and** the message, and any other failure is still an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the device is unreachable, if `uci` fails
    /// for any reason other than the package being absent, or if its output
    /// does not parse.
    pub fn export_package(
        &mut self,
        package: &str,
    ) -> Result<Option<openwrt_uci::Package>, TransportError> {
        let cmd = format!("uci export {package}");
        let out = self.transport.exec(&cmd)?;

        if !out.success() {
            if out.stderr.contains("Entry not found") {
                return Ok(None);
            }
            return Err(TransportError::CommandFailed {
                command: cmd,
                output: out,
            });
        }

        // Belt and braces: a device that does signal absence with empty
        // success is handled too, rather than producing a confusing parse
        // error on an empty document.
        if out.stdout.trim().is_empty() {
            return Ok(None);
        }

        let doc =
            Document::parse(&out.stdout).map_err(|e| TransportError::Malformed(e.to_string()))?;
        Ok(doc.packages.into_iter().next())
    }

    /// Borrow the underlying transport, e.g. to report what was reached.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}
