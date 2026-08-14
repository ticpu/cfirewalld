//! Build phase for cfirewalld.
//!
//! Reads declarations on fd 3 until EOF, resolves every name once, then submits
//! sets and rules. Nothing reaches the kernel until the whole config has parsed
//! and resolved, so a failure leaves the live ruleset untouched.

mod decl;
mod probe;
mod resolve;
mod rules;
mod sets;

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};

use probe::Prober;
use sets::Family;

/// fd the shell writes declarations to.
const DECL_FD: i32 = 3;

struct Config {
    /// Prefix for chains built by this run; fw_commit renames these.
    prefix: String,
    /// Prefix for sets. Versioned rather than renamed, so a rule must name the
    /// committed set from the start.
    set_prefix: String,
    /// Where to keep a copy of what was submitted.
    cachedir: Option<String>,
    debug: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: cfw-build --prefix PREFIX [--cachedir DIR]\n\
         \n\
         Reads declarations on fd 3 until EOF, then builds the firewall."
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    let mut prefix = None;
    let mut set_prefix = None;
    let mut cachedir = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prefix" => prefix = args.next(),
            "--set-prefix" => set_prefix = args.next(),
            "--cachedir" => cachedir = args.next(),
            _ => usage(),
        }
    }

    // DEBUG is exported by fw_vars and defaults to on.
    let debug = std::env::var("DEBUG").map(|v| v != "0").unwrap_or(true);

    Config {
        prefix: prefix.unwrap_or_else(|| usage()),
        set_prefix: set_prefix.unwrap_or_else(|| usage()),
        cachedir,
        debug,
    }
}

/// Feed text to a command's stdin and wait for it.
fn submit(program: &str, args: &[&str], input: &str) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running {program}: {e}"))?;

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(input.as_bytes())
        .map_err(|e| format!("writing to {program}: {e}"))?;

    let status = child
        .wait()
        .map_err(|e| format!("waiting for {program}: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

/// Keep what was submitted, so a failed run can be read back.
fn record(cachedir: &Option<String>, name: &str, text: &str) {
    let Some(dir) = cachedir else { return };
    let path = format!("{dir}/{name}");
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("cfw-build: recording {path}: {e}");
    }
}

fn die(message: &str) -> ! {
    eprintln!("cfw-build: {message}");
    std::process::exit(1);
}

/// Mirrors the shell's `debug`, which is on by default: without it a reload
/// says nothing about what it did, and the shell path is verbose.
fn debug(enabled: bool, message: &str) {
    if enabled {
        eprintln!("cfw-build » {message}");
    }
}

fn main() {
    let config = parse_args();

    // SAFETY: the shell opens fd 3 before exec; reading it is the contract.
    let mut input = String::new();
    let mut stream = unsafe { std::fs::File::from_raw_fd(DECL_FD) };
    if let Err(e) = stream.read_to_string(&mut input) {
        die(&format!("reading declarations on fd {DECL_FD}: {e}"));
    }

    let decls = match decl::parse(&input) {
        Ok(d) => d,
        Err(e) => die(&format!("parsing declarations: {e}")),
    };
    debug(config.debug, &format!("parsed {} declarations", decls.len()));

    let names = resolve::names_to_resolve(&decls);
    debug(config.debug, &format!("resolving {} name(s)", names.len()));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => die(&format!("starting the resolver: {e}")),
    };
    let resolved = match runtime.block_on(resolve::resolve_all(&names)) {
        Ok(r) => r,
        Err(failures) => {
            for f in &failures {
                eprintln!("cfw-build: {f}");
            }
            die(&format!(
                "{} unresolvable name(s); every one is listed above with its file and line",
                failures.len()
            ));
        }
    };

    let sets = match sets::build(&decls, &resolved) {
        Ok(s) => s,
        Err(e) => die(&e.message),
    };
    debug(config.debug, &format!("built {} set(s)", sets.by_name.len()));

    let mut prober = Prober::new();
    let built = rules::build(
        &decls,
        &sets,
        &resolved,
        &config.prefix,
        &config.set_prefix,
        &mut |table, tail| prober.families_for(table, tail),
    );
    prober.cleanup();

    let built = match built {
        Ok(b) => b,
        Err(e) => die(&e.message),
    };
    for (family, ruleset) in &built {
        let chains: usize = ruleset.tables.values().map(|t| t.chains.len()).sum();
        let count: usize = ruleset.tables.values().flat_map(|t| t.chains.values()).map(Vec::len).sum();
        debug(config.debug, &format!("{family:?}: {count} rule(s) in {chains} chain(s)"));
    }

    // Everything is decided; only now does anything reach the kernel.
    let set_stream = sets::render(&sets, &config.set_prefix);
    record(&config.cachedir, "ipset.restore", &set_stream);
    debug(config.debug, &format!("ipset restore -! ({} lines)", set_stream.lines().count()));
    if let Err(e) = submit("ipset", &["restore", "-!"], &set_stream) {
        die(&format!("loading sets: {e}"));
    }

    for (family, ruleset) in &built {
        let (program, name) = match family {
            Family::V4 => ("iptables-restore", "iptables.restore"),
            Family::V6 => ("ip6tables-restore", "ip6tables.restore"),
        };
        let text = rules::render(ruleset, &config.prefix);
        record(&config.cachedir, name, &text);
        debug(config.debug, &format!("{program} --noflush ({} lines)", text.lines().count()));
        if let Err(e) = submit(program, &["--noflush"], &text) {
            die(&format!("loading rules: {e}"));
        }
    }
}
