//! The harness view of the fixture manifest and of the gates file
//! (tools/parity/gates.json): strict JSON, their top-level rules, and the
//! closed sets of kinds, scopes and capabilities.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use hop_top_pact::core::strictjson::{self, Limits};
use serde_json::Value;

/// The kinds of `go/runner/manifest` (`Kinds()`).
pub const KINDS: [&str; 13] = [
    "key",
    "vector",
    "schema",
    "evaluate",
    "outcomes",
    "learning",
    "adapter-case",
    "adapter-asset",
    "source-case",
    "profile-invalid",
    "transport",
    "mcp",
    "profile",
];

/// The scopes of `go/runner/manifest` (`Scopes()`).
pub const SCOPES: [&str; 3] = ["core", "runner", "adapter"];

/// The optional capabilities of `go/runner/manifest` (`Capabilities()`).
pub const CAPABILITIES: [&str; 1] = ["jws-ed25519"];

/// The manifest, the gates file or the command line prevents a run: exit
/// status 2.
#[derive(Debug)]
pub struct HarnessError(pub String);

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One manifest entry, with the members the harness reads.
#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub id: String,
    pub kind: String,
    pub scope: String,
    pub path: String,
    pub expected: Option<String>,
    pub outcome: Option<String>,
    pub capabilities: Vec<String>,
}

const TWO_SEGMENT_GROUPS: [&str; 3] = ["vectors", "adapters", "sources"];

/// The prefix of an entry id: its first segment, or its first two under
/// vectors/, adapters/ and sources/.
pub fn prefix_of(id: &str) -> String {
    let segs: Vec<&str> = id.split('/').collect();
    let n = if TWO_SEGMENT_GROUPS.contains(&segs[0]) && segs.len() > 2 { 2 } else { 1 };
    segs[..n].join("/")
}

/// Large enough for the manifest and the gates file, which are not wire
/// objects.
const FILE_LIMITS: Limits = Limits { max_bytes: 64 << 20, max_depth: 32 };

fn read(path: &Path) -> Result<Value, HarnessError> {
    let data = std::fs::read(path).map_err(|e| HarnessError(format!("{}: {e}", path.display())))?;
    strictjson::parse(&data, FILE_LIMITS).map_err(|e| HarnessError(format!("{}: {e}", path.display())))
}

fn opt_string(v: Option<&Value>, at: &str, name: &str) -> Result<Option<String>, HarnessError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(HarnessError(format!("{at}: {name} is neither a string nor null"))),
    }
}

/// Reads the manifest at `path`: manifest_version 1 as written, an entries
/// array and no other member; every entry with an id and a path, a known
/// kind, scope and capabilities, and an id of its own.
pub fn load_manifest(path: &Path) -> Result<Vec<Entry>, HarnessError> {
    let at = path.display().to_string();
    let doc = read(path)?;
    let Some(top) = doc.as_object() else { return Err(HarnessError(format!("{at}: not a JSON object"))) };
    if let Some(k) = top.keys().find(|k| *k != "manifest_version" && *k != "entries") {
        return Err(HarnessError(format!("{at}: unknown member {k}")));
    }
    let version = top.get("manifest_version");
    if !version.is_some_and(|v| v.is_u64() && v.as_u64() == Some(1)) {
        return Err(HarnessError(format!("{at}: manifest_version is not 1")));
    }
    let Some(entries) = top.get("entries").and_then(Value::as_array) else {
        return Err(HarnessError(format!("{at}: entries is not an array")));
    };
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let id = e.get("id").and_then(Value::as_str).filter(|s| !s.is_empty());
        let Some(id) = id else {
            return Err(HarnessError(format!("{at}: entries[{i}] is not an object with a string id")));
        };
        let at = format!("{at}: entry {id}");
        let kind = e.get("kind").and_then(Value::as_str).unwrap_or_default();
        if !KINDS.contains(&kind) {
            return Err(HarnessError(format!("{at}: kind {kind:?} is not one of {}", KINDS.join(", "))));
        }
        let scope = e.get("scope").and_then(Value::as_str).unwrap_or_default();
        if !SCOPES.contains(&scope) {
            return Err(HarnessError(format!("{at}: scope {scope:?} is not one of {}", SCOPES.join(", "))));
        }
        let path = e.get("path").and_then(Value::as_str).filter(|s| !s.is_empty());
        let Some(path) = path else { return Err(HarnessError(format!("{at}: path is not a string"))) };
        let capabilities: Vec<String> = match e.get("capabilities") {
            None => Vec::new(),
            Some(Value::Array(a)) if a.iter().all(|c| c.as_str().is_some_and(|c| CAPABILITIES.contains(&c))) => {
                a.iter().filter_map(|c| c.as_str().map(String::from)).collect()
            }
            Some(c) => {
                return Err(HarnessError(format!("{at}: capabilities {c} are not among {}", CAPABILITIES.join(", "))));
            }
        };
        if !seen.insert(id.to_string()) {
            return Err(HarnessError(format!("{at}: id repeated in the manifest")));
        }
        out.push(Entry {
            id: id.to_string(),
            kind: kind.to_string(),
            scope: scope.to_string(),
            path: path.to_string(),
            expected: opt_string(e.get("expected"), &at, "expected")?,
            outcome: opt_string(e.get("outcome"), &at, "outcome")?,
            capabilities,
        });
    }
    Ok(out)
}

/// A gate of the rs column: every row is required or n/a for this SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Required,
    NotApplicable,
}

/// The rs gate of each (scope, kind, prefix) row.
#[derive(Debug, Default)]
pub struct Gates(HashMap<String, Gate>);

impl Gates {
    /// The gate of an entry's row; None without a row.
    pub fn of(&self, e: &Entry) -> Option<Gate> {
        self.0.get(&format!("{} {} {}", e.scope, e.kind, prefix_of(&e.id))).copied()
    }

    /// Reads the gates file at `path`: gates_version 1 and rows with a scope,
    /// a kind, a prefix and an rs gate of `required` or `n/a`.
    pub fn load(path: &Path) -> Result<Gates, HarnessError> {
        let at = format!("gates {}", path.display());
        let doc = read(path)?;
        let rows = match (doc.get("gates_version").and_then(Value::as_u64), doc.get("rows").and_then(Value::as_array)) {
            (Some(1), Some(rows)) => rows,
            _ => return Err(HarnessError(format!("{at}: not an object with gates_version 1 and a rows array"))),
        };
        let mut gates = HashMap::new();
        for (i, r) in rows.iter().enumerate() {
            let s = |k: &str| r.get(k).and_then(Value::as_str);
            let gate = match s("rs") {
                Some("required") => Gate::Required,
                Some("n/a") => Gate::NotApplicable,
                other => {
                    return Err(HarnessError(format!(
                        "{at}: rows[{i}] has rs gate {other:?}; an rs gate is required or n/a"
                    )));
                }
            };
            let (Some(scope), Some(kind), Some(prefix)) = (s("scope"), s("kind"), s("prefix")) else {
                return Err(HarnessError(format!("{at}: rows[{i}] lacks scope, kind, prefix or an rs gate")));
            };
            gates.insert(format!("{scope} {kind} {prefix}"), gate);
        }
        Ok(Gates(gates))
    }
}
