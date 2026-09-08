//! SSH transport built on the system `ssh` binary, driven by typed arguments.
//!
//! # Why the system binary rather than an embedded SSH client
//!
//! Two reasons, both practical rather than ideological:
//!
//! 1. **`ProxyJump`.** An `OpenWrt` router usually lives behind something — the
//!    reference device is reachable only through a host on its LAN. `ssh -J`
//!    solves that in one flag; an embedded client would need the whole
//!    jump-host path reimplemented before the first byte moved.
//! 2. **`known_hosts`, agents, and `~/.ssh/config` already exist** and are what
//!    an operator has already configured. Reimplementing them is how a tool
//!    ends up with its own subtly different trust store.
//!
//! The cost is an `ssh` binary on PATH. That is stated plainly in
//! [`SshTransport::probe`] rather than discovered at the first connection.
//!
//! # This is not shell scripting
//!
//! Every argument is pushed onto an argv vector; nothing is interpolated into a
//! shell string on *our* side, so there is no quoting to get wrong and no
//! injection surface in argument construction.
//!
//! What remains true, and is documented rather than hidden: the *command* is
//! executed by a shell **on the device**. `uci export` is a fixed string, but a
//! caller passing untrusted input to [`Transport::exec`] is passing it to a
//! remote shell. [`SshTransport`] does not sanitise it — sanitising would imply
//! a guarantee it cannot make. The UCI layer above only ever sends commands it
//! constructs itself.

use crate::{HostKeyPolicy, Output, Transport, TransportError};
use std::process::Command;

/// Where a device is and how to reach it.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub port: Option<u16>,
    /// Jump host(s), as `ssh -J` accepts them. The reference router is only
    /// reachable this way, so this is a first-class field rather than an
    /// afterthought.
    pub jump: Option<String>,
    /// Identity file. `None` uses the agent and `~/.ssh/config` defaults.
    pub identity: Option<std::path::PathBuf>,
    pub host_key_policy: HostKeyPolicy,
    /// Connection timeout in seconds. A router at a remote site that has gone
    /// away must fail in bounded time, not hang a reconciler.
    pub connect_timeout_secs: u32,
}

impl SshTarget {
    /// A target with the safe defaults: pinned host key, 10s timeout.
    #[must_use]
    pub fn new(user: &str, host: &str, fingerprint: &str) -> Self {
        Self {
            host: host.to_owned(),
            user: user.to_owned(),
            port: None,
            jump: None,
            identity: None,
            host_key_policy: HostKeyPolicy::Pinned(fingerprint.to_owned()),
            connect_timeout_secs: 10,
        }
    }

    #[must_use]
    pub fn via_jump(mut self, jump: &str) -> Self {
        self.jump = Some(jump.to_owned());
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// The argv this target produces, excluding the remote command.
    ///
    /// Public so it can be asserted in tests without opening a connection —
    /// the mapping from policy to `ssh` flags is security-relevant, and a
    /// mapping nobody can inspect is a mapping nobody has checked.
    #[must_use]
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();

        // BatchMode: never prompt. A reconciler that blocks on a password
        // prompt is a hung reconciler, and an interactive fallback would make
        // an automated run silently depend on a human being present.
        a.push("-o".into());
        a.push("BatchMode=yes".into());

        a.push("-o".into());
        a.push(format!("ConnectTimeout={}", self.connect_timeout_secs));

        match &self.host_key_policy {
            HostKeyPolicy::Pinned(_) => {
                // Strict: the key must already be trusted. The fingerprint
                // itself is verified by ssh against known_hosts; we do not
                // re-implement that comparison.
                a.push("-o".into());
                a.push("StrictHostKeyChecking=yes".into());
            }
            HostKeyPolicy::TrustOnFirstUse { known_hosts } => {
                a.push("-o".into());
                a.push("StrictHostKeyChecking=accept-new".into());
                a.push("-o".into());
                a.push(format!("UserKnownHostsFile={}", known_hosts.display()));
            }
            HostKeyPolicy::AcceptAnyInsecure { .. } => {
                // Both flags are required together. StrictHostKeyChecking=no
                // alone still *records* the key and then fails on a later
                // mismatch, which would turn a deliberate one-off into a
                // permanent, confusing failure.
                a.push("-o".into());
                a.push("StrictHostKeyChecking=no".into());
                a.push("-o".into());
                a.push("UserKnownHostsFile=/dev/null".into());
                a.push("-o".into());
                a.push("LogLevel=ERROR".into());
            }
        }

        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(j) = &self.jump {
            a.push("-J".into());
            a.push(j.clone());
        }
        if let Some(i) = &self.identity {
            a.push("-i".into());
            a.push(i.display().to_string());
        }

        a.push(format!("{}@{}", self.user, self.host));
        a
    }
}

/// A [`Transport`] that reaches a device over SSH.
#[derive(Debug, Clone)]
pub struct SshTransport {
    target: SshTarget,
    calls: Vec<String>,
}

impl SshTransport {
    #[must_use]
    pub fn new(target: SshTarget) -> Self {
        Self {
            target,
            calls: Vec::new(),
        }
    }

    /// Every command this transport has run, in order.
    #[must_use]
    pub fn calls(&self) -> &[String] {
        &self.calls
    }

    /// Confirm an `ssh` binary is available before relying on one.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Unreachable`] if `ssh` is not on PATH. Called
    /// separately from [`Transport::exec`] so that "you have no ssh" is
    /// reported as itself rather than as an unreachable device — they need
    /// different fixes.
    pub fn probe() -> Result<(), TransportError> {
        Command::new("ssh")
            .arg("-V")
            .output()
            .map(|_| ())
            .map_err(|e| TransportError::Unreachable(format!("no `ssh` on PATH: {e}")))
    }
}

impl Transport for SshTransport {
    fn exec(&mut self, command: &str) -> Result<Output, TransportError> {
        self.calls.push(command.to_owned());

        let mut cmd = Command::new("ssh");
        for a in self.target.args() {
            cmd.arg(a);
        }
        cmd.arg(command);

        let out = cmd
            .output()
            .map_err(|e| TransportError::Unreachable(format!("could not run ssh: {e}")))?;

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let code = out.status.code().unwrap_or(-1);

        // ssh returns 255 for its own failures, which is otherwise
        // indistinguishable from a remote command that happened to exit 255.
        // Classifying by exit code alone would report a dead network as a
        // failed `uci` call, so the stderr is inspected to separate them.
        if code == 255 {
            let lower = stderr.to_lowercase();
            if lower.contains("host key verification failed") {
                return Err(TransportError::HostKeyRejected {
                    expected: match &self.target.host_key_policy {
                        HostKeyPolicy::Pinned(f) => f.clone(),
                        other => format!("{other:?}"),
                    },
                    presented: stderr.trim().to_owned(),
                });
            }
            if lower.contains("permission denied") || lower.contains("authentication failed") {
                return Err(TransportError::AuthFailed(stderr.trim().to_owned()));
            }
            return Err(TransportError::Unreachable(stderr.trim().to_owned()));
        }

        Ok(Output {
            stdout,
            stderr,
            exit_code: code,
        })
    }

    fn target(&self) -> String {
        let via = self
            .target
            .jump
            .as_ref()
            .map_or(String::new(), |j| format!(" via {j}"));
        format!("{}@{}{via}", self.target.user, self.target.host)
    }
}
