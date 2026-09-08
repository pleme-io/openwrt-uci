//! A scripted [`Transport`] for tests.
//!
//! Every test that would otherwise need a router uses this. It is in the
//! library rather than behind `#[cfg(test)]` on purpose: consumers building on
//! this crate need the same seam, and making them re-invent it would be the
//! duplication this design exists to prevent.

use crate::{Output, Transport, TransportError};
use std::collections::HashMap;

/// A transport that answers from a script instead of a device.
///
/// Unscripted commands are an **error**, never an empty success. A mock that
/// silently returns "" for anything it was not told about will make a broken
/// caller look like it works, which is the exact failure this crate's parser
/// also refuses to commit.
#[derive(Debug, Default)]
pub struct MockTransport {
    responses: HashMap<String, Output>,
    /// Every command asked of this mock, in order — so a test can assert what
    /// was actually run, not merely what came back.
    pub calls: Vec<String>,
    unreachable: bool,
}

impl MockTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script a successful response.
    #[must_use]
    pub fn on(mut self, command: &str, stdout: &str) -> Self {
        self.responses.insert(
            command.to_owned(),
            Output {
                stdout: stdout.to_owned(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
        self
    }

    /// Script a command that runs and fails.
    #[must_use]
    pub fn on_failure(mut self, command: &str, stderr: &str, exit_code: i32) -> Self {
        self.responses.insert(
            command.to_owned(),
            Output {
                stdout: String::new(),
                stderr: stderr.to_owned(),
                exit_code,
            },
        );
        self
    }

    /// Make the device unreachable, to exercise the failure path that a live
    /// test cannot easily produce on demand.
    #[must_use]
    pub fn unreachable(mut self) -> Self {
        self.unreachable = true;
        self
    }
}

impl Transport for MockTransport {
    fn exec(&mut self, command: &str) -> Result<Output, TransportError> {
        self.calls.push(command.to_owned());
        if self.unreachable {
            return Err(TransportError::Unreachable("mock".to_owned()));
        }
        self.responses.get(command).cloned().ok_or_else(|| {
            TransportError::Unreachable(format!("mock has no script for `{command}`"))
        })
    }

    fn target(&self) -> String {
        "mock".to_owned()
    }
}
