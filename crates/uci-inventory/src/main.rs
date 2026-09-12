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
    uci-inventory <survey|values|imports|ready|cr|renames|fleet> [--adapter HOST:PORT]

SUBCOMMANDS:
    survey     coverage report: what exists, what we manage, why we decline the rest
    values     Helm values for the managed set (JSON; --yaml for a YAML
               `sections:` block ready to be a chart values file)
    imports    {to, id} import identities for the managed set
    ready      is this router fit to ship? typed checks over the UCI surface,
               each naming the incident that motivated it. Exit 1 if not.
    fleet <file>...
               compare N RENDERED manifests to each other: which settings are
               the same on every router (Constant), differ on all of them
               (Divergent), or are missing from some (Partial). Needs no
               device. ★ A Constant is a CANDIDATE for policy, never proof of
               one — three routers agreed on PasswordAuth=on.
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
    --pin FILE             `fleet` only: enforce a reviewed constant set.
                           Exit 1 naming every constant that no longer holds.
                           An EMPTY pin file is refused, not passed.
    --emit-pin             `fleet` only: write the pin file for review.
                           ★ Review it before committing — a constant is not
                           the same as a policy.
    --yaml                 `values`: emit YAML instead of JSON.
                           `fleet`: also list every constant, not just the count.
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
    let (authority, scope, do_apply, as_yaml, tf_only) =
        (opts.authority, opts.scope, opts.apply, opts.yaml, opts.tf);
    let (pin, emit_pin, positionals) = (opts.pin, opts.emit_pin, opts.positionals);

    // ★ `cr` reads a FILE, so it must not require a device. Connecting first
    // would make judging a render impossible whenever a router is unreachable —
    // exactly when you most want to inspect what was declared.
    if cmd == "cr" {
        return run_cr(positionals.first().map(String::as_str), tf_only);
    }

    // ★ `fleet` reads FILES for the same reason `cr` does, and more so: it
    // compares routers that are in different houses on different continents,
    // so requiring any one of them to be reachable would make the comparison
    // impossible exactly when the fleet is most worth checking.
    if cmd == "fleet" {
        return run_fleet(&positionals, as_yaml, pin.as_deref(), emit_pin);
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
    if cmd == "ready" {
        return run_ready(&adapter, &inv);
    }
    // Regenerates tests/fixtures/. Uses the crate's own catalog, so there is
    // exactly one definition of what is secret. See `capture`'s module docs.
    if cmd == "capture" {
        println!("{}", uci_inventory::capture::fixture(&bodies).render());
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

/// `fleet` — compare N rendered routers to each other.
///
/// Needs no device, like `cr`. The router NAME shown in the report is the
/// manifest's file stem, so `sections-roteador-natal.yaml` reports as
/// `sections-roteador-natal` — readable, and derived from the argument rather
/// than from a flag nobody would keep in step with the paths.
fn run_fleet(paths: &[String], as_yaml: bool, pin: Option<&str>, emit_pin: bool) -> ExitCode {
    use uci_inventory::fleet::{self, Fleet, Router};

    let mut routers = Vec::with_capacity(paths.len());
    for path in paths {
        let manifest = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let name = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(path.as_str())
            .to_owned();
        match Router::from_manifest(name, &manifest) {
            Ok(r) => routers.push(r),
            Err(e) => {
                eprintln!("{path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let fleet = match Fleet::compare(&routers) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if emit_pin {
        print!("{}", fleet::pin_file(&fleet).render());
        return ExitCode::SUCCESS;
    }

    // ★ THE GATE. Exit 1 on a breach, so this is usable as a CI step rather
    // than a report somebody has to read. A breach names the pinned value AND
    // what each router says now — "it changed" without the values sends the
    // reader back to the renders to find out what.
    if let Some(path) = pin {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot read pin {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let pinned = match fleet::read_pin(&text) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        // ★ ANTI-VACUITY. An empty pin file passes every check while checking
        // nothing, and reads in CI exactly like a fleet in perfect agreement.
        if pinned.is_empty() {
            eprintln!(
                "pin {path} is EMPTY — refusing, because an empty pin passes while \
                 asserting nothing and reads as a fleet that agrees on everything"
            );
            return ExitCode::FAILURE;
        }
        let breaches = fleet.breaches(&pinned);
        if breaches.is_empty() {
            println!("fleet holds: {} pinned constants, {} routers", pinned.len(), fleet.routers.len());
            return ExitCode::SUCCESS;
        }
        eprintln!("{} of {} pinned constants no longer hold:", breaches.len(), pinned.len());
        for b in &breaches {
            eprintln!("  {}.{}.{} [{:?}] pinned {:?}", b.config, b.section, b.option, b.kind, b.want);
            for (r, v) in &b.got {
                eprintln!("      {r:<26} {v}");
            }
        }
        return ExitCode::FAILURE;
    }

    let out = if as_yaml { fleet::report_all(&fleet) } else { fleet::report(&fleet) };
    print!("{}", out.render());
    ExitCode::SUCCESS
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
    /// `fleet --pin FILE`: the reviewed constant set to enforce.
    pin: Option<String>,
    /// `fleet --emit-pin`: write the pin file instead of the report.
    emit_pin: bool,
    /// Free arguments, in order.
    ///
    /// A LIST rather than one slot: `fleet` compares N routers, and the single
    /// slot silently kept only the LAST path — so `fleet a.yaml b.yaml c.yaml`
    /// would have compared one router against nothing and been refused as
    /// TooFewRouters, which reads as a bad fleet rather than a dropped argument.
    positionals: Vec<String>,
}

fn parse_flags(args: &[String]) -> Result<Opts, ExitCode> {
    let mut o = Opts {
        authority: "127.0.0.1:9797".to_owned(),
        scope: emit::Scope::StableOnly,
        apply: false,
        yaml: false,
        tf: false,
        pin: None,
        emit_pin: false,
        positionals: Vec::new(),
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
            "--pin" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--pin needs a path to a pin file");
                    return Err(ExitCode::FAILURE);
                };
                o.pin = Some(v.clone());
                i += 2;
            }
            "--emit-pin" => {
                o.emit_pin = true;
                i += 1;
            }
            "--include-positional" => {
                o.scope = emit::Scope::IncludePositional;
                i += 1;
            }
            other if !other.starts_with("--") => {
                o.positionals.push(other.to_owned());
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

/// `ready` — judge whether a router is fit to ship.
///
/// Separate from `main` so the entry point stays a dispatcher; the pedantic
/// line limit has been a fair nudge twice now.
fn run_ready(adapter: &Adapter, inv: &uci_inventory::inventory::Inventory) -> ExitCode {
        // uci.changes is a live query, not part of the inventory.
        let uncommitted = adapter
            .post("/uci/changes", &Json::obj([("config", Json::str("system"))]))
            .ok()
            .and_then(|j| match j {
                Json::Obj(p) => p.iter().find(|(k, _)| k == "changes").map(|(_, v)| v.clone()),
                _ => None,
            })
            .and_then(|c| match c {
                Json::Arr(a) => Some(a.len()),
                _ => None,
            });
        let checks = uci_inventory::readiness::judge(inv, uncommitted);
        let rows: Vec<Json> = checks
            .iter()
            .map(|c| {
                let (v, detail) = match &c.verdict {
                    uci_inventory::readiness::Verdict::Pass => ("pass", String::new()),
                    uci_inventory::readiness::Verdict::Fail(m) => ("FAIL", m.clone()),
                    uci_inventory::readiness::Verdict::Unobservable(m) => {
                        ("unobservable", (*m).to_owned())
                    }
                };
                Json::obj([
                    ("check", Json::str(c.name)),
                    ("verdict", Json::str(v)),
                    ("detail", Json::str(detail)),
                    ("because", Json::str(c.because)),
                ])
            })
            .collect();
        let fit = uci_inventory::readiness::ready(&checks);
        print!(
            "{}",
            Json::obj([
                ("fitToShip", Json::Bool(fit)),
                ("checks", Json::Arr(rows)),
            ])
            .render()
        );
        if fit { ExitCode::SUCCESS } else { ExitCode::FAILURE }
    
}
