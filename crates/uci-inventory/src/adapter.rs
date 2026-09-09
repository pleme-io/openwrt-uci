//! A minimal client for the `ubus-http` façade adapter.
//!
//! Zero-dependency, like the rest of the workspace. It speaks exactly as much
//! HTTP/1.1 as the adapter serves — POST with a JSON body, read
//! `Content-Length` — and nothing more. Adding an HTTP crate to reach our own
//! adapter would pull a TLS stack and an async runtime into a tool whose entire
//! job is one request per UCI package over loopback.

use std::io::{Read, Write};
use std::net::TcpStream;
use ubus_facade::json::Json;

/// Why a call to the adapter failed.
#[derive(Debug)]
pub enum AdapterError {
    Connect(std::io::Error),
    Io(std::io::Error),
    /// The adapter answered a non-2xx status.
    Status { code: u16, body: String },
    /// The body was not the JSON the adapter promises.
    Body(String),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect(e) => {
                f.write_str("cannot reach the adapter: ")?;
                f.write_str(&e.to_string())?;
                f.write_str(
                    ". It binds LOOPBACK on the router, so a remote caller needs an ssh -L \
                     forward — see nix/docs/roteador.md.",
                )
            }
            Self::Io(e) => f.write_str(&e.to_string()),
            Self::Status { code, body } => {
                f.write_str("adapter returned HTTP ")?;
                f.write_str(&code.to_string())?;
                f.write_str(": ")?;
                f.write_str(body)
            }
            Self::Body(m) => f.write_str(m),
        }
    }
}

/// A connection factory for the adapter at `host:port`.
pub struct Adapter {
    authority: String,
}

impl Adapter {
    /// `authority` is `host:port`, e.g. `127.0.0.1:9797`.
    #[must_use]
    pub fn new(authority: impl Into<String>) -> Self {
        Self { authority: authority.into() }
    }

    /// POST `body` to `path` and parse the answer.
    ///
    /// # Errors
    ///
    /// Connection, I/O, non-2xx status, or an unparseable body.
    pub fn post(&self, path: &str, body: &Json) -> Result<Json, AdapterError> {
        let payload = body.render();
        let mut req = String::new();
        req.push_str("POST ");
        req.push_str(path);
        req.push_str(" HTTP/1.1\r\nHost: ");
        req.push_str(&self.authority);
        req.push_str("\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ");
        req.push_str(&payload.len().to_string());
        req.push_str("\r\n\r\n");
        req.push_str(&payload);

        let mut s = TcpStream::connect(&self.authority).map_err(AdapterError::Connect)?;
        s.write_all(req.as_bytes()).map_err(AdapterError::Io)?;
        let mut raw = Vec::new();
        // `Connection: close` means read-to-EOF is the framing, so no chunked
        // decoding is needed and none is implemented.
        s.read_to_end(&mut raw).map_err(AdapterError::Io)?;
        let text = String::from_utf8_lossy(&raw).into_owned();

        let (head, body_text) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| AdapterError::Body("no header/body separator in response".to_owned()))?;
        let code: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| AdapterError::Body("no status code in response".to_owned()))?;
        if !(200..300).contains(&code) {
            return Err(AdapterError::Status { code, body: body_text.trim().to_owned() });
        }
        ubus_facade::json::parse(body_text.trim())
            .map_err(|e| AdapterError::Body(format!("unparseable body: {e:?}")))
    }

    /// Every UCI package on the device, via `uci.configs`.
    ///
    /// # Errors
    ///
    /// Any [`AdapterError`], or an answer with no `configs` array.
    pub fn packages(&self) -> Result<Vec<String>, AdapterError> {
        let out = self.post("/uci/configs", &Json::obj::<&str>([]))?;
        let Json::Obj(pairs) = &out else {
            return Err(AdapterError::Body("uci.configs did not answer an object".to_owned()));
        };
        let arr = pairs
            .iter()
            .find(|(k, _)| k == "configs")
            .map(|(_, v)| v)
            .ok_or_else(|| AdapterError::Body("uci.configs answered no `configs`".to_owned()))?;
        let Json::Arr(items) = arr else {
            return Err(AdapterError::Body("`configs` is not an array".to_owned()));
        };
        Ok(items
            .iter()
            .filter_map(|j| match j {
                Json::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect())
    }

    /// One whole package, via `uci.get {config}` with no section.
    ///
    /// # Errors
    ///
    /// Any [`AdapterError`].
    pub fn package(&self, name: &str) -> Result<Json, AdapterError> {
        self.post("/uci/get", &Json::obj([("config", Json::str(name))]))
    }
}
