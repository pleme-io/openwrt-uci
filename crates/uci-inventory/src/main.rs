//! `uci-inventory` — survey a router, or derive its declared config.
//!
//! One subcommand does one thing (★★ CLOSED-LOOP MASS-SYNTHESIS): `survey`
//! reports coverage, `values` emits the Helm values for the managed set,
//! `imports` emits the import identities. Nothing does all three, so a caller
//! that wants one is never made to parse the others out of a combined blob.

use std::process::ExitCode;
use uci_inventory::adapter::Adapter;
use uci_inventory::{emit, inventory};

const USAGE: &str = "\
uci-inventory — survey an OpenWrt device's UCI surface and derive declared config

USAGE:
    uci-inventory <survey|values|imports> [--adapter HOST:PORT]

SUBCOMMANDS:
    survey     coverage report: what exists, what we manage, why we decline the rest
    values     Helm values (JSON, which Helm accepts) for the managed set
    imports    {to, id} import identities for the managed set
    renames    proposed stable names for anonymous sections (a PROPOSAL; this
               tool never mutates the device — feed it to uci rename yourself)

OPTIONS:
    --adapter HOST:PORT    the ubus-http façade adapter [default: 127.0.0.1:9797]
    --include-positional   also emit sections addressed as @type[N]. OFF by
                           default: a positional address committed to git keeps
                           resolving after a section is inserted or deleted —
                           to a DIFFERENT section. Apply the `renames` first.

The adapter binds LOOPBACK on the router because ubus has no authentication, so
reaching it from elsewhere means an ssh -L forward.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut authority = "127.0.0.1:9797".to_owned();
    let mut scope = emit::Scope::StableOnly;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--adapter" {
            if let Some(v) = args.get(i + 1) {
                authority.clear();
                authority.push_str(v);
            } else {
                eprintln!("--adapter needs a HOST:PORT");
                return ExitCode::FAILURE;
            }
            i += 2;
        } else if args[i] == "--include-positional" {
            scope = emit::Scope::IncludePositional;
            i += 1;
        } else {
            eprintln!("unknown argument: {}", args[i]);
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    }

    let adapter = Adapter::new(authority);
    let names = match adapter.packages() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let mut bodies = Vec::with_capacity(names.len());
    for n in names {
        match adapter.package(&n) {
            Ok(b) => bodies.push((n, b)),
            Err(e) => {
                eprintln!("reading package {n}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let inv = match inventory::survey(&bodies) {
        Ok(i) => i,
        Err(e) => {
            // A refusal, not a crash: it names what to add and why.
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let out = match cmd.as_str() {
        "survey" => emit::report(&inv),
        "values" => emit::helm_values_scoped(&inv, scope),
        "imports" => emit::imports_scoped(&inv, scope),
        "renames" => emit::renames(&uci_inventory::rename::propose_all(&inv)),
        other => {
            eprintln!("unknown subcommand: {other}");
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", out.render());
    ExitCode::SUCCESS
}
