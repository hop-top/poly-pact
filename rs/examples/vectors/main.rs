//! Vectors harness entry, run by `make rs-vectors`: prints one NDJSON line,
//! `{"id","kind","result"}`, per entry of the fixture manifest named on the
//! command line, and nothing else on standard output. Every row that is not
//! a pass, with its detail, and a summary line go to standard error.
//!
//! Usage: `cargo run --example vectors -- [--gates FILE] [--capability NAME]... MANIFEST`.
//! Plain argv, no command-line framework. `--gates` names the gates file
//! (tools/parity/gates.json); `--capability` declares an optional capability
//! of the fixtures. This SDK implements no optional capability.
//!
//! Exit status: 0 when no entry fails; 1 when an entry fails, or runs under
//! a gate that is n/a for rs; 2 on a harness error
//! (usage, an unreadable or malformed manifest or gates file, an rs gate
//! other than required or n/a, an unknown
//! kind, scope, capability or in-scope prefix), which prints nothing on
//! standard output. An absent manifest (a package mirror has no fixtures) is
//! a NOTICE on standard error and exit 0, unless `PACT_REQUIRE_VECTORS=1`,
//! which makes it a harness error.

mod core_groups;
mod fixture;
mod harness;
mod jws_groups;
mod manifest;
mod schema_cases;
#[cfg(test)]
mod tests;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use manifest::{Gates, HarnessError};

const EXIT_HARNESS_ERROR: u8 = 2;
const USAGE: &str = "usage: vectors [--gates FILE] [--capability NAME]... MANIFEST";

struct Args {
    manifest: PathBuf,
    gates: Option<PathBuf>,
    capabilities: Vec<String>,
}

fn parse_args(argv: &[String]) -> Option<Args> {
    let mut gates = None;
    let mut capabilities = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--gates" || a == "--capability" {
            let v = argv.get(i + 1)?.clone();
            i += 1;
            if a == "--gates" {
                gates = Some(PathBuf::from(v));
            } else {
                capabilities.push(v);
            }
        } else if a.starts_with('-') {
            return None;
        } else {
            rest.push(a.clone());
        }
        i += 1;
    }
    if rest.len() != 1 {
        return None;
    }
    Some(Args { manifest: PathBuf::from(&rest[0]), gates, capabilities })
}

fn run(argv: &[String]) -> Result<u8, HarnessError> {
    let Some(args) = parse_args(argv) else {
        eprintln!("{USAGE}");
        return Ok(EXIT_HARNESS_ERROR);
    };
    if !args.manifest.exists() {
        if std::env::var("PACT_REQUIRE_VECTORS").as_deref() == Ok("1") {
            return Err(HarnessError(format!("PACT_REQUIRE_VECTORS=1 and {} is absent", args.manifest.display())));
        }
        eprintln!("NOTICE: vectors skipped: {} absent", args.manifest.display());
        return Ok(0);
    }
    let gates = args.gates.as_deref().map(Gates::load).transpose()?;
    let r = harness::run_manifest(&args.manifest, &args.capabilities, gates.as_ref())?;
    let mut out = std::io::stdout().lock();
    for line in &r.lines {
        let text = serde_json::to_string(line).map_err(|e| HarnessError(e.to_string()))?;
        writeln!(out, "{text}").map_err(|e| HarnessError(e.to_string()))?;
    }
    for d in r.details.iter().chain([&r.summary]) {
        eprintln!("{d}");
    }
    Ok(r.status as u8)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("vectors: {e}");
            ExitCode::from(EXIT_HARNESS_ERROR)
        }
    }
}
