//! `ubus-http` — serve the ubus façade over HTTP on the device.
//!
//! ```sh
//! ubus-http --spec ubus-facade.openapi.json
//! ubus-http --spec facade.json --listen 127.0.0.1:9797 --socket /var/run/ubus/ubus.sock
//! ```
//!
//! ★ Binds LOOPBACK by default and warns loudly if told to do otherwise. ubus
//! has no authentication, so an exposed adapter is an unauthenticated root
//! shell for the router. Reach it remotely with `ssh -L`, which does have
//! authentication.

use std::net::TcpListener;
use ubus_http::route::RouteTable;
use ubus_http::{DEFAULT_LISTEN, DEFAULT_SOCKET};

fn main() -> std::process::ExitCode {
    let mut spec_path = None;
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut socket = DEFAULT_SOCKET.to_owned();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                i += 1;
                spec_path = args.get(i).cloned();
            }
            "--listen" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    listen.clone_from(v);
                }
            }
            "--socket" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    socket.clone_from(v);
                }
            }
            other => {
                eprintln!("ubus-http: unknown argument {other}");
                return std::process::ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let Some(spec_path) = spec_path else {
        eprintln!("ubus-http: --spec <facade.openapi.json> is required");
        return std::process::ExitCode::FAILURE;
    };

    let text = match std::fs::read_to_string(&spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ubus-http: cannot read {spec_path}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let spec = match ubus_facade::json::parse(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ubus-http: {spec_path} is not valid JSON: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let routes = match RouteTable::from_facade(&spec) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ubus-http: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if !listen.starts_with("127.")
        && !listen.starts_with("[::1]")
        && !listen.starts_with("localhost")
    {
        eprintln!(
            "ubus-http: WARNING — listening on {listen}, which is not loopback. ubus has \
             NO authentication, so every host that can reach this port has \
             root-equivalent control of this device. Prefer `ssh -L`."
        );
    }

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ubus-http: cannot bind {listen}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    eprintln!(
        "ubus-http: serving {} ubus operations on {listen}, via {socket}",
        routes.len()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = ubus_http::http::serve_one(s, &routes, &socket) {
                    eprintln!("ubus-http: {e}");
                }
            }
            // One bad accept must not end the server.
            Err(e) => eprintln!("ubus-http: accept failed: {e}"),
        }
    }
    std::process::ExitCode::SUCCESS
}
