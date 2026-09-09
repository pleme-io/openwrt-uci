//! `ubus-facade` — read a `ubus -v list` capture, write its `OpenAPI` façade.
//!
//! ```sh
//! ssh root@router 'ubus -v list' | ubus-facade > facade.openapi.json
//! ubus-facade path/to/ubus-v-list.txt
//! ```
//!
//! Reads stdin when given no path, so it composes with an ssh pipe without a
//! temporary file.

use std::io::Read as _;

fn main() -> std::process::ExitCode {
    let arg = std::env::args().nth(1);
    let input = match arg.as_deref() {
        None | Some("-") => {
            let mut s = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut s) {
                eprintln!("ubus-facade: cannot read stdin: {e}");
                return std::process::ExitCode::FAILURE;
            }
            s
        }
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ubus-facade: cannot read {path}: {e}");
                return std::process::ExitCode::FAILURE;
            }
        },
    };

    match ubus_facade::generate(&input) {
        Ok(spec) => {
            print!("{spec}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ubus-facade: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
