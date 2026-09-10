//! `uci-inventory` — survey a router, or derive its declared config.
//!
//! One subcommand does one thing (★★ CLOSED-LOOP MASS-SYNTHESIS): `survey`
//! reports coverage, `values` emits the Helm values for the managed set,
//! `imports` emits the import identities. Nothing does all three, so a caller
//! that wants one is never made to parse the others out of a combined blob.

use std::process::ExitCode;
use ubus_facade::json::Json;
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
    cr <file>  read back a RENDERED InfrastructureTemplate: --tf emits the
               Terraform body for an executor, otherwise a resource summary.
               Needs no device — it reads what the chart produced.
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
    let opts = match parse_flags(&args[1..]) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let (authority, scope, do_apply, as_yaml, tf_only, positional) =
        (opts.authority, opts.scope, opts.apply, opts.yaml, opts.tf, opts.positional);

    // ★ `cr` reads a FILE, so it must not require a device. Connecting first
    // would make judging a render impossible whenever a router is unreachable —
    // exactly when you most want to inspect what was declared.
    if cmd == "cr" {
        return run_cr(positional.as_deref(), tf_only);
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

/// `cr` — read back a rendered `InfrastructureTemplate`.
///
/// Separate from `main` because it is the one subcommand that needs no device:
/// judging a render must stay possible while a router is unreachable.
fn run_cr(path: Option<&str>, tf_only: bool) -> ExitCode {
    let Some(path) = path else {
        eprintln!("cr needs a path to a rendered manifest");
        return ExitCode::FAILURE;
    };
    let manifest = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if tf_only {
        return match uci_inventory::rendered::terraform(&manifest) {
            Ok(tf) => {
                print!("{}", tf.render());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    match uci_inventory::rendered::sections(&manifest) {
        Ok(s) => {
            let addrs: Vec<Json> = s.iter().map(|(n, _)| Json::str(n)).collect();
            print!(
                "{}",
                Json::obj([
                    ("resources", Json::Int(i64::try_from(s.len()).unwrap_or(i64::MAX))),
                    ("addresses", Json::Arr(addrs)),
                ])
                .render()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Every flag this CLI takes, parsed once.
///
/// Lifted out of `main` so the entry point stays readable: argument parsing and
/// dispatch are different jobs, and the pedantic line limit was the nudge.
struct Opts {
    authority: String,
    scope: emit::Scope,
    apply: bool,
    yaml: bool,
    tf: bool,
    positional: Option<String>,
}

fn parse_flags(args: &[String]) -> Result<Opts, ExitCode> {
    let mut o = Opts {
        authority: "127.0.0.1:9797".to_owned(),
        scope: emit::Scope::StableOnly,
        apply: false,
        yaml: false,
        tf: false,
        positional: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--adapter" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--adapter needs a HOST:PORT");
                    return Err(ExitCode::FAILURE);
                };
                o.authority.clear();
                o.authority.push_str(v);
                i += 2;
            }
            "--apply" => {
                o.apply = true;
                i += 1;
            }
            "--yaml" => {
                o.yaml = true;
                i += 1;
            }
            "--tf" => {
                o.tf = true;
                i += 1;
            }
            "--include-positional" => {
                o.scope = emit::Scope::IncludePositional;
                i += 1;
            }
            other if !other.starts_with("--") => {
                o.positional = Some(other.to_owned());
                i += 1;
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprint!("{USAGE}");
                return Err(ExitCode::FAILURE);
            }
        }
    }
    Ok(o)
}
