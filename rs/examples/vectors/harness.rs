//! The vectors harness (docs/sdk/ports-plan.md sections 5.1 and 5.2): every
//! entry of the fixture manifest gets one result line. Entries of kind
//! vector, key and schema of scope core and adapter run through the crate's
//! modules and are compared with their outcome and expected file. Scope
//! runner entries, the other kinds, and the groups outside this core-only SDK
//! (the HTTP binding vectors) are skipped:out-of-scope. An in-scope entry
//! whose capabilities are not all declared is skipped:capability.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::core_groups::{run_digest, run_jcs, run_schema_vectors, run_strictjson};
use super::fixture::{Fail, Res};
use super::jws_groups::{run_jws, run_key};
use super::manifest::{CAPABILITIES, Entry, Gate, Gates, HarnessError, load_manifest, prefix_of};
use super::schema_cases::run_schema_case;

type Runner = fn(&Path, &Entry) -> Res;

/// The runner of each in-scope (kind, prefix).
const RUNNERS: [(&str, &str, Runner); 9] = [
    ("key", "keys", run_key),
    ("vector", "vectors/digest", run_digest),
    ("vector", "vectors/jcs", run_jcs),
    ("vector", "vectors/jws", run_jws),
    ("vector", "vectors/schema", run_schema_vectors),
    ("vector", "vectors/strictjson", run_strictjson),
    ("schema", "parse", run_schema_case),
    ("schema", "schema", run_schema_case),
    ("vector", "vectors/binding", out_of_scope),
];

fn out_of_scope(_: &Path, _: &Entry) -> Res {
    Err(Fail::Skip {
        reason: "out-of-scope",
        detail: "the HTTP baseline binding is not part of this core-only SDK".into(),
        spec_defects: Vec::new(),
    })
}

const IN_SCOPE_KINDS: [&str; 3] = ["vector", "key", "schema"];

/// Whether the harness runs the entry: kind vector, key or schema, scope core
/// or adapter.
pub fn in_scope(e: &Entry) -> bool {
    IN_SCOPE_KINDS.contains(&e.kind.as_str()) && e.scope != "runner"
}

fn runner_of(e: &Entry) -> Result<Runner, HarnessError> {
    let p = prefix_of(&e.id);
    RUNNERS.iter().find(|(k, pre, _)| *k == e.kind && *pre == p).map(|r| r.2).ok_or_else(|| {
        let known: Vec<String> = RUNNERS.iter().map(|(k, p, _)| format!("{k} {p}")).collect();
        HarnessError(format!("entry {}: no runner for kind {} prefix {p}; runners: {}", e.id, e.kind, known.join(", ")))
    })
}

/// The outcome of one entry.
#[derive(Debug)]
pub enum Outcome {
    Pass,
    Fail(String),
    Skipped { reason: &'static str, detail: String, spec_defects: Vec<Value>, missing: Vec<String> },
}

/// Runs one entry, the fixture directory being `root`.
pub fn run_entry(root: &Path, e: &Entry, capabilities: &[String]) -> Result<Outcome, HarnessError> {
    if !in_scope(e) {
        let detail = if e.scope == "runner" {
            "scope runner: run by the Go conformance runner".to_string()
        } else {
            format!("kind {}: not part of this core-only SDK", e.kind)
        };
        return Ok(Outcome::Skipped { reason: "out-of-scope", detail, spec_defects: Vec::new(), missing: Vec::new() });
    }
    let run = runner_of(e)?;
    let missing: Vec<String> = e.capabilities.iter().filter(|c| !capabilities.contains(c)).cloned().collect();
    if !missing.is_empty() {
        return Ok(Outcome::Skipped {
            reason: "capability",
            detail: format!("optional capability {} not declared (--capability)", missing.join(", ")),
            spec_defects: Vec::new(),
            missing,
        });
    }
    Ok(match run(root, e) {
        Ok(()) => Outcome::Pass,
        Err(Fail::Fail(m)) => Outcome::Fail(m),
        Err(Fail::Skip { reason, detail, spec_defects }) => {
            Outcome::Skipped { reason, detail, spec_defects, missing: Vec::new() }
        }
    })
}

/// One NDJSON line of the result grammar.
#[derive(Debug, Serialize)]
pub struct Line {
    pub id: String,
    pub kind: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_defects: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_capabilities: Option<Vec<String>>,
}

/// The result of a run.
#[derive(Debug)]
pub struct Run {
    pub lines: Vec<Line>,
    /// One row per result that is not a pass: `FAIL id: detail` or
    /// `SKIP id: detail`.
    pub details: Vec<String>,
    pub summary: String,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    /// 1 when an entry fails, or runs under an rs gate that is n/a, else 0.
    pub status: i32,
}

/// An entry that ran although its rs gate is n/a claims coverage the gates
/// file does not declare (ports-plan.md section 5.3, rule 3): the run fails.
fn not_applicable(run: &mut Run, gates: Option<&Gates>, e: &Entry) {
    if gates.and_then(|g| g.of(e)) == Some(Gate::NotApplicable) {
        run.details.push(format!("FAIL {}: ran under an rs gate that is n/a", e.id));
        run.status = 1;
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Runs every entry of the manifest at `path`.
pub fn run_manifest(path: &Path, capabilities: &[String], gates: Option<&Gates>) -> Result<Run, HarnessError> {
    if let Some(c) = capabilities.iter().find(|c| !CAPABILITIES.contains(&c.as_str())) {
        return Err(HarnessError(format!("--capability {c:?} is not one of {}", CAPABILITIES.join(", "))));
    }
    let entries = load_manifest(path)?;
    for e in entries.iter().filter(|e| in_scope(e)) {
        runner_of(e)?;
    }
    let root = path.parent().unwrap_or(Path::new("."));
    let mut run = Run {
        lines: Vec::new(),
        details: Vec::new(),
        summary: String::new(),
        passed: 0,
        failed: 0,
        skipped: 0,
        status: 0,
    };
    for e in &entries {
        let mut line = Line {
            id: e.id.clone(),
            kind: e.kind.clone(),
            result: String::new(),
            spec_defects: None,
            missing_capabilities: None,
        };
        match run_entry(root, e, capabilities)? {
            Outcome::Pass => {
                run.passed += 1;
                line.result = "pass".into();
                not_applicable(&mut run, gates, e);
            }
            Outcome::Fail(detail) => {
                run.failed += 1;
                run.details.push(format!("FAIL {}: {}", e.id, one_line(&detail)));
                line.result = "fail".into();
                run.status = 1;
                not_applicable(&mut run, gates, e);
            }
            Outcome::Skipped { reason, detail, spec_defects, missing } => {
                run.skipped += 1;
                run.details.push(format!("SKIP {}: {}", e.id, one_line(&detail)));
                line.result = format!("skipped:{reason}");
                if !spec_defects.is_empty() {
                    line.spec_defects = Some(spec_defects);
                } else if !missing.is_empty() {
                    line.missing_capabilities = Some(missing);
                }
            }
        }
        run.lines.push(line);
    }
    run.summary = format!("{} passed, {} failed, {} skipped", run.passed, run.failed, run.skipped);
    Ok(run)
}
