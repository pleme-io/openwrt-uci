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
    values     Helm values for the managed set (JSON; --yaml for a YAML
               `sections:` block ready to be a chart values file)
    imports    {to, id} import identities for the managed set
    renames    proposed stable names for anonymous sections. A PROPOSAL by
               default; --apply performs them, which is the ONE mutating path
               in this tool. It is an adoption step (the sibling of terraform
               import), because a rename cannot be expressed as declarative
               state: declaring the new name would create a second section.

OPTIONS:
    --adapter HOST:PORT    the ubus-http façade adapter [default: 127.0.0.1:9797]
    --apply                `renames` only: actually perform them. Renaming
                           does not reload netifd or fw4, so the running
                           network is untouched.
    --yaml                 `values` only: emit YAML instead of JSON.
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
    let mut do_apply = false;
    let mut as_yaml = false;
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
        } else if args[i] == "--yaml" {
            as_yaml = true;
            i += 1;
        } else if args[i] == "--apply" {
            do_apply = true;
            i += 1;
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

    if cmd == "values" && as_yaml {
        print!("{}", emit::helm_values_yaml(&inv, scope));
        return ExitCode::SUCCESS;
    }
    let out = match cmd.as_str() {
        "survey" => emit::report(&inv),
        "values" => emit::helm_values_scoped(&inv, scope),
        "imports" => emit::imports_scoped(&inv, scope),
        "renames" => {
            let proposed = uci_inventory::rename::propose_all(&inv);
            if do_apply {
                match uci_inventory::rename::apply(&adapter, &proposed) {
                    Ok(done) => emit::renames(&done),
                    Err((done, e)) => {
                        // Report what DID land before failing: a partial batch
                        // is committed, and a caller needs to know which half.
                        eprintln!("rename failed after {} applied: {e}", done.len());
                        print!("{}", emit::renames(&done).render());
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                emit::renames(&proposed)
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", out.render());
    ExitCode::SUCCESS
}
