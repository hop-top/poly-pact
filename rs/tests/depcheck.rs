//! Dependency guard: the counterpart of Go's internal/depcheck and of the
//! Python and TypeScript depcheck tests.
//!
//! The vetted set is tests/support/deps.toml; docs/sdk/deps-rs.md of the
//! source repository is its human record. The checks:
//!
//! - the dependency tables of Cargo.toml hold exactly the vetted entries,
//!   each an exact `=x.y.z` pin with the vetted default-features and
//!   features, and no git, path, registry, renamed or optional entry; no
//!   other dependency table, `[patch]`, `[replace]` or `[workspace]`;
//! - Cargo.lock holds exactly the vetted crates.io packages (name, version,
//!   checksum) plus the crate itself;
//! - src/ and examples/ name no dev-only crate, and no source file uses a
//!   private path (a `__` segment) of a dependency;
//! - in the source repository, deps-rs.md agrees with deps.toml.
//!
//! The parser reads the subset of TOML these files use, one entry per line,
//! and reports anything else in a dependency table instead of guessing.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use regex::Regex;

const CRATE: &str = "hop-top-pact";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Bool(bool),
    Array(Vec<Value>),
    Table(Vec<(String, Value)>),
}

/// One `key = value` line of a TOML section.
#[derive(Debug)]
struct Entry {
    key: String,
    value: Result<Value, String>,
    line: usize,
}

#[derive(Debug)]
struct Section {
    header: String,
    entries: Vec<Entry>,
}

/// A dependency entry, normalized.
#[derive(Debug, Clone, PartialEq)]
struct Dep {
    version: String,
    default_features: bool,
    features: BTreeSet<String>,
}

struct Vetted {
    tables: BTreeMap<String, BTreeMap<String, Dep>>,
    /// "name version" -> checksum.
    lock: BTreeMap<String, String>,
}

// --- TOML subset -----------------------------------------------------------

/// The line without a comment that starts outside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            '\\' if in_str && !escaped => {
                escaped = true;
                continue;
            }
            '"' if !escaped => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
        escaped = false;
    }
    line
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] == b' ' || self.s[self.i] == b'\t') {
            self.i += 1;
        }
    }

    fn eat(&mut self, b: u8) -> bool {
        self.ws();
        if self.s.get(self.i) == Some(&b) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn key(&mut self) -> Result<String, String> {
        self.ws();
        if self.s.get(self.i) == Some(&b'"') {
            return self.string();
        }
        let start = self.i;
        while self.i < self.s.len() && (self.s[self.i].is_ascii_alphanumeric() || b"_-".contains(&self.s[self.i])) {
            self.i += 1;
        }
        if start == self.i {
            return Err(format!("expected a key at column {}", start + 1));
        }
        let key = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        self.ws();
        if self.s.get(self.i) == Some(&b'.') {
            return Err(format!("dotted key {key}.… is not supported"));
        }
        Ok(key)
    }

    fn string(&mut self) -> Result<String, String> {
        if !self.eat(b'"') {
            return Err("expected a string".into());
        }
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i] != b'"' {
            if self.s[self.i] == b'\\' {
                return Err("escapes in strings are not supported".into());
            }
            self.i += 1;
        }
        if self.i == self.s.len() {
            return Err("unterminated string".into());
        }
        self.i += 1;
        Ok(String::from_utf8_lossy(&self.s[start..self.i - 1]).into_owned())
    }

    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.s.get(self.i) {
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                if self.eat(b']') {
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    if self.eat(b']') {
                        return Ok(Value::Array(items));
                    }
                    if !self.eat(b',') {
                        return Err("expected , or ] (multi-line arrays are not supported)".into());
                    }
                    if self.eat(b']') {
                        return Ok(Value::Array(items));
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut items = Vec::new();
                if self.eat(b'}') {
                    return Ok(Value::Table(items));
                }
                loop {
                    let k = self.key()?;
                    if !self.eat(b'=') {
                        return Err(format!("expected = after {k}"));
                    }
                    items.push((k, self.value()?));
                    if self.eat(b'}') {
                        return Ok(Value::Table(items));
                    }
                    if !self.eat(b',') {
                        return Err("expected , or }".into());
                    }
                }
            }
            _ if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Value::Bool(true))
            }
            _ if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Value::Bool(false))
            }
            _ => Err(format!("unsupported value at column {}", self.i + 1)),
        }
    }
}

/// The sections of a TOML file. Entries of sections not named in `parse`
/// are kept with their raw line skipped: only the named sections are read.
fn sections(text: &str, parse: impl Fn(&str) -> bool) -> Vec<Section> {
    let mut out: Vec<Section> = vec![Section { header: String::new(), entries: Vec::new() }];
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let inner = line.trim_start_matches('[').trim_end_matches(']').trim();
            out.push(Section { header: inner.to_string(), entries: Vec::new() });
            continue;
        }
        let section = out.last_mut().expect("a section");
        if !parse(&section.header) {
            continue;
        }
        let mut c = Cursor { s: line.as_bytes(), i: 0 };
        let entry = match c.key() {
            Err(e) => Entry { key: line.to_string(), value: Err(e), line: n + 1 },
            Ok(key) => {
                let value = if c.eat(b'=') { c.value() } else { Err(format!("expected = after {key}")) };
                let value = value.and_then(|v| {
                    c.ws();
                    if c.i == c.s.len() { Ok(v) } else { Err(format!("trailing text at column {}", c.i + 1)) }
                });
                Entry { key, value, line: n + 1 }
            }
        };
        section.entries.push(entry);
    }
    out
}

// --- manifest ----------------------------------------------------------------

/// A dependency entry as a Dep, or the reasons it is not in the vetted form.
fn dep(value: &Value) -> Result<Dep, Vec<String>> {
    let mut errs = Vec::new();
    let mut d = Dep { version: String::new(), default_features: true, features: BTreeSet::new() };
    match value {
        Value::Str(v) => d.version = v.clone(),
        Value::Table(items) => {
            for (k, v) in items {
                match (k.as_str(), v) {
                    ("version", Value::Str(s)) => d.version = s.clone(),
                    ("default-features", Value::Bool(b)) => d.default_features = *b,
                    ("features", Value::Array(fs)) => {
                        for f in fs {
                            match f {
                                Value::Str(s) => {
                                    d.features.insert(s.clone());
                                }
                                other => errs.push(format!("feature {other:?} is not a string")),
                            }
                        }
                    }
                    ("version" | "default-features" | "features", other) => {
                        errs.push(format!("`{k}` has the wrong type: {other:?}"))
                    }
                    _ => errs.push(format!("key `{k}` is not allowed (only version, default-features, features)")),
                }
            }
        }
        other => errs.push(format!("unsupported entry {other:?}")),
    }
    let exact = Regex::new(r"^=[0-9]+\.[0-9]+\.[0-9]+$").expect("pin expression");
    if !exact.is_match(&d.version) {
        errs.push(format!("version {:?} is not an exact =x.y.z pin", d.version));
    }
    if errs.is_empty() { Ok(d) } else { Err(errs) }
}

fn is_dep_table(header: &str) -> bool {
    TABLES.contains(&header)
}

/// The three dependency tables of a manifest, plus the problems of its
/// structure: other dependency tables, patch, replace, workspace, entries
/// outside the vetted form.
fn manifest_tables(name: &str, text: &str) -> (BTreeMap<String, BTreeMap<String, Dep>>, Vec<String>) {
    let mut problems = Vec::new();
    let mut tables: BTreeMap<String, BTreeMap<String, Dep>> =
        TABLES.iter().map(|t| (t.to_string(), BTreeMap::new())).collect();
    for s in sections(text, is_dep_table) {
        let h = s.header.as_str();
        let top = h.split('.').next().unwrap_or("").trim_matches('"');
        if is_dep_table(h) {
            for e in &s.entries {
                match &e.value {
                    Err(err) => problems.push(format!("{name}:{}: [{h}] {}: {err}", e.line, e.key)),
                    Ok(v) => match dep(v) {
                        Err(errs) => {
                            for err in errs {
                                problems.push(format!("{name}:{}: [{h}] {}: {err}", e.line, e.key));
                            }
                        }
                        Ok(d) => {
                            if tables.get_mut(h).expect("table").insert(e.key.clone(), d).is_some() {
                                problems.push(format!("{name}:{}: [{h}] {} appears twice", e.line, e.key));
                            }
                        }
                    },
                }
            }
        } else if h.contains("dependencies") {
            problems.push(format!("{name}: table [{h}] is not allowed (only {})", TABLES.join(", ")));
        } else if matches!(top, "patch" | "replace" | "workspace") {
            problems.push(format!("{name}: table [{h}] is not allowed"));
        }
    }
    (tables, problems)
}

fn compare_tables(
    name: &str,
    got: &BTreeMap<String, BTreeMap<String, Dep>>,
    want: &BTreeMap<String, BTreeMap<String, Dep>>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for t in TABLES {
        let (g, w) = (&got[t], &want[t]);
        for (k, d) in g {
            match w.get(k) {
                None => problems.push(format!("{name}: [{t}] {k} is not vetted")),
                Some(v) if v != d => problems.push(format!("{name}: [{t}] {k} is {d:?}, vetted {v:?}")),
                Some(_) => {}
            }
        }
        for k in w.keys() {
            if !g.contains_key(k) {
                problems.push(format!("{name}: [{t}] vetted {k} is missing"));
            }
        }
    }
    problems
}

// --- lock ------------------------------------------------------------------

#[derive(Debug, Default)]
struct Locked {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn lock_packages(text: &str) -> Vec<Locked> {
    let mut out: Vec<Locked> = Vec::new();
    let mut in_pkg = false;
    let field = Regex::new(r#"^(name|version|source|checksum) = "([^"]*)"$"#).expect("lock field");
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_pkg = line == "[[package]]";
            if in_pkg {
                out.push(Locked::default());
            }
            continue;
        }
        let Some(c) = field.captures(line) else { continue };
        if !in_pkg {
            continue;
        }
        let p = out.last_mut().expect("a package");
        let v = c[2].to_string();
        match &c[1] {
            "name" => p.name = v,
            "version" => p.version = v,
            "source" => p.source = Some(v),
            _ => p.checksum = Some(v),
        }
    }
    out
}

fn lock_problems(text: &str, vetted: &Vetted) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    let mut root = 0;
    for p in lock_packages(text) {
        let id = format!("{} {}", p.name, p.version);
        match &p.source {
            None if p.name == CRATE => {
                root += 1;
                continue;
            }
            None => problems.push(format!("Cargo.lock: {id} has no source (a path dependency)")),
            Some(s) if s != CRATES_IO => problems.push(format!("Cargo.lock: {id} comes from {s}, not crates.io")),
            Some(_) => {}
        }
        match vetted.lock.get(&id) {
            None => problems.push(format!("Cargo.lock: {id} is not vetted")),
            Some(sum) if p.checksum.as_deref() != Some(sum.as_str()) => {
                problems.push(format!("Cargo.lock: {id} checksum {:?} != vetted {sum}", p.checksum))
            }
            Some(_) => {}
        }
        seen.insert(id);
    }
    if root != 1 {
        problems.push(format!("Cargo.lock: {root} entries for {CRATE}, want 1"));
    }
    for id in vetted.lock.keys() {
        if !seen.contains(id) {
            problems.push(format!("Cargo.lock: vetted {id} is missing"));
        }
    }
    problems
}

// --- vetted data -----------------------------------------------------------

fn vetted(text: &str) -> Result<Vetted, Vec<String>> {
    let (tables, mut problems) = manifest_tables("deps.toml", text);
    let mut lock = BTreeMap::new();
    for s in sections(text, |h| h == "lock") {
        if s.header != "lock" {
            continue;
        }
        for e in s.entries {
            match e.value {
                Ok(Value::Str(sum)) if e.key.split(' ').count() == 2 => {
                    lock.insert(e.key, sum);
                }
                other => problems.push(format!("deps.toml:{}: [lock] {}: {other:?}", e.line, e.key)),
            }
        }
    }
    let v = Vetted { tables, lock };
    // Every pin is a locked version.
    for t in TABLES {
        for (k, d) in &v.tables[t] {
            let id = format!("{k} {}", d.version.trim_start_matches('='));
            if !v.lock.contains_key(&id) {
                problems.push(format!("deps.toml: [{t}] {k} pins a version not in [lock] ({id})"));
            }
        }
    }
    if problems.is_empty() { Ok(v) } else { Err(problems) }
}

// --- sources ---------------------------------------------------------------

/// Problems of the Rust sources: (relative path, text) pairs.
fn source_problems(files: &[(String, String)], vetted: &Vetted) -> Vec<String> {
    let runtime: BTreeSet<String> = vetted.tables["dependencies"].keys().map(|k| k.replace('-', "_")).collect();
    let dev_only: BTreeSet<String> = TABLES[1..]
        .iter()
        .flat_map(|t| vetted.tables[*t].keys().map(|k| k.replace('-', "_")))
        .filter(|k| !runtime.contains(k))
        .collect();
    let all: Vec<String> = runtime.iter().chain(dev_only.iter()).map(|k| regex::escape(k)).collect();
    let private =
        Regex::new(&format!(r"\b(?:{})(?:\s*::\s*[A-Za-z0-9_]+)*\s*::\s*__", all.join("|"))).expect("private");
    let dev = (!dev_only.is_empty()).then(|| {
        let names: Vec<String> = dev_only.iter().map(|k| regex::escape(k)).collect();
        Regex::new(&format!(r"\b(?:{})\b", names.join("|"))).expect("dev")
    });
    let mut problems = Vec::new();
    for (path, text) in files {
        let shipped = path.starts_with("src/") || path.starts_with("examples/");
        for (n, line) in text.lines().enumerate() {
            if private.is_match(line) {
                problems.push(format!("{path}:{}: private path of a dependency", n + 1));
            }
            if shipped && dev.as_ref().is_some_and(|re| re.is_match(line)) {
                problems.push(format!("{path}:{}: dev-only crate named outside tests", n + 1));
            }
        }
    }
    problems
}

fn rust_files(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut entries: Vec<PathBuf> = rd.map(|e| e.expect("dir entry").path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let rel = p.strip_prefix(root).expect("under root").to_string_lossy().replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&p).expect("read source")));
            }
        }
    }
    let mut out = Vec::new();
    for tree in ["src", "tests", "examples"] {
        walk(&root.join(tree), root, &mut out);
    }
    out
}

// --- the vetting document ----------------------------------------------------

/// Rows of the table under a "## " heading: (crate, version, version cell).
fn doc_rows(doc: &str, heading: &str) -> Vec<(String, String, String)> {
    let tick = Regex::new(r"`([^`]+)`").expect("tick");
    let mut rows = Vec::new();
    let mut inside = false;
    for line in doc.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            inside = h.trim() == heading;
            continue;
        }
        if !inside || !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.split(" | ").collect();
        let name = cells.first().and_then(|c| tick.captures(c)).map(|c| c[1].to_string()).unwrap_or_default();
        let cell = cells.get(2).copied().unwrap_or("").to_string();
        let version = tick.captures(&cell).map(|c| c[1].to_string()).unwrap_or_default();
        rows.push((name, version, cell));
    }
    rows
}

fn doc_problems(doc: &str, vetted: &Vetted) -> Vec<String> {
    let mut problems = Vec::new();
    let runtime = doc_rows(doc, "Vetted dependencies");
    let dev = doc_rows(doc, "Vetted dev-only dependencies");
    let check = |rows: &[(String, String, String)], k: &str, d: &Dep, t: &str, problems: &mut Vec<String>| {
        let Some((_, version, cell)) = rows.iter().find(|r| r.0 == k) else {
            problems.push(format!("deps-rs.md: [{t}] {k} has no row"));
            return;
        };
        let pin = d.version.trim_start_matches('=');
        if version != pin {
            problems.push(format!("deps-rs.md: {k} row is at {version}, pinned {pin}"));
        }
        if cell.contains("default-features = false") == d.default_features {
            problems.push(format!("deps-rs.md: {k} row disagrees on default-features = {}", d.default_features));
        }
        for f in &d.features {
            if !cell.contains(&format!("\"{f}\"")) {
                problems.push(format!("deps-rs.md: {k} row does not name feature {f}"));
            }
        }
    };
    for (k, d) in &vetted.tables["dependencies"] {
        check(&runtime, k, d, "dependencies", &mut problems);
    }
    for (name, _, _) in &runtime {
        if !vetted.tables["dependencies"].contains_key(name) {
            problems.push(format!("deps-rs.md: row {name} is not a vetted runtime dependency"));
        }
    }
    for t in &TABLES[1..] {
        for (k, d) in &vetted.tables[*t] {
            check(&dev, k, d, t, &mut problems);
        }
    }
    let token = Regex::new(r"`([A-Za-z0-9_-]+)@([0-9][^`]*)`").expect("token");
    let mut inside = false;
    let mut listed = BTreeSet::new();
    for line in doc.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            inside = h.trim() == "Locked crate versions";
            continue;
        }
        if inside {
            for c in token.captures_iter(line) {
                listed.insert(format!("{} {}", &c[1], &c[2]));
            }
        }
    }
    let want: BTreeSet<String> = vetted.lock.keys().cloned().collect();
    for id in want.difference(&listed) {
        problems.push(format!("deps-rs.md: locked {id} is not listed"));
    }
    for id in listed.difference(&want) {
        problems.push(format!("deps-rs.md: listed {id} is not in deps.toml [lock]"));
    }
    problems
}

// --- inputs ----------------------------------------------------------------

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A text file with CRLF line ends read as LF, so that the negative controls
/// edits match on any checkout.
fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).replace("\r\n", "\n")
}

/// The manifest as written: a packaged crate carries it as Cargo.toml.orig
/// beside the normalized Cargo.toml.
fn manifest() -> String {
    let orig = root().join("Cargo.toml.orig");
    read(&if orig.is_file() { orig } else { root().join("Cargo.toml") })
}

fn vetted_set() -> Vetted {
    vetted(&read(&root().join("tests/support/deps.toml")))
        .unwrap_or_else(|p| panic!("deps.toml:\n  {}", p.join("\n  ")))
}

/// docs/sdk/deps-rs.md, or None outside the source repository.
fn vetting_doc() -> Option<String> {
    let path = root().join("../docs/sdk/deps-rs.md");
    if path.is_file() {
        return Some(read(&path));
    }
    if std::env::var("PACT_REQUIRE_VECTORS").as_deref() == Ok("1") {
        panic!("PACT_REQUIRE_VECTORS=1 and {} is absent", path.display());
    }
    eprintln!("NOTICE: {} absent; check skipped", path.display());
    None
}

fn problems(manifest: &str, lock: &str, files: &[(String, String)], v: &Vetted) -> Vec<String> {
    let (tables, mut out) = manifest_tables("Cargo.toml", manifest);
    out.extend(compare_tables("Cargo.toml", &tables, &v.tables));
    out.extend(lock_problems(lock, v));
    out.extend(source_problems(files, v));
    out
}

fn assert_clean(what: &str, problems: Vec<String>) {
    assert!(problems.is_empty(), "{what}:\n  {}", problems.join("\n  "));
}

fn assert_reports(problems: &[String], needles: &[&str]) {
    let all = problems.join("\n");
    for n in needles {
        assert!(problems.iter().any(|p| p.contains(n)), "guard missed: {n}\n{all}");
    }
}

#[test]
fn dependencies_are_vetted() {
    let v = vetted_set();
    let lock = read(&root().join("Cargo.lock"));
    assert_clean("dependency problems", problems(&manifest(), &lock, &rust_files(&root()), &v));
}

#[test]
fn vetting_doc_agrees() {
    let Some(doc) = vetting_doc() else { return };
    assert_clean("deps-rs.md and deps.toml disagree", doc_problems(&doc, &vetted_set()));
}

#[test]
fn guard_negative_control() {
    let v = vetted_set();
    let manifest = manifest();
    let lock = read(&root().join("Cargo.lock"));
    let files = rust_files(&root());
    assert_clean("an unmodified copy must pass", problems(&manifest, &lock, &files, &v));

    let bad_manifest = manifest
        .replacen("[dependencies]\n", "[dependencies]\nleft-pad = \"=1.0.0\"\n", 1)
        .replacen("sha2 = \"=0.11.1\"", "sha2 = \"0.11.1\"", 1)
        .replacen("base64 = { version = \"=0.23.1\", default-features = false,", "base64 = { version = \"=0.23.1\",", 1)
        .replacen("features = [\"float_roundtrip\"]", "features = [\"float_roundtrip\", \"arbitrary_precision\"]", 1)
        .replacen("getrandom = { version = \"=0.4.3\",", "getrandom = { version = \"=0.4.3\", optional = true,", 1)
        .replacen(
            "[dev-dependencies]\n",
            "[dev-dependencies]\ntempfile = { git = \"https://example.org/tempfile\" }\nlocal = { path = \"../local\", version = \"=0.1.0\" }\n",
            1,
        )
        + "\n[build-dependencies]\ncc = \"=1.2.0\"\n"
        + "\n[target.'cfg(unix)'.dependencies]\nlibc = \"=0.2.0\"\n"
        + "\n[dependencies.extra]\nversion = \"=1.0.0\"\n"
        + "\n[patch.crates-io]\nserde = { path = \"../serde\" }\n";
    let bad_lock = lock
        .replacen(
            "[[package]]\n",
            "[[package]]\nname = \"left-pad\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"00\"\n\n[[package]]\nname = \"forked\"\nversion = \"0.1.0\"\nsource = \"git+https://example.org/forked#abc\"\n\n[[package]]\n",
            1,
        )
        .replacen("name = \"sha2\"\nversion = \"0.11.1\"", "name = \"sha2\"\nversion = \"0.11.0\"", 1);
    let mut bad_files = files.clone();
    bad_files.push(("src/bad.rs".into(), "use serde_json_canonicalizer::to_vec;\n".into()));
    // Built from pieces, so that this file itself holds no private path.
    bad_files.push(("src/private.rs".into(), concat!("use serde::", "__private::de;\n").into()));
    bad_files.push(("examples/bad.rs".into(), "fn main() { serde_json_canonicalizer::to_vec(&1).ok(); }\n".into()));
    bad_files.push(("tests/private.rs".into(), concat!("let _ = jsonschema :: ", "__internal ();\n").into()));

    let found = problems(&bad_manifest, &bad_lock, &bad_files, &v);
    assert_reports(
        &found,
        &[
            "[dependencies] left-pad is not vetted",
            "[dependencies] sha2: version \"0.11.1\" is not an exact =x.y.z pin",
            "[dependencies] base64 is Dep",
            "[dependencies] serde_json is Dep",
            "[dependencies] getrandom: key `optional` is not allowed",
            "[dev-dependencies] tempfile: key `git` is not allowed",
            "[dev-dependencies] local: key `path` is not allowed",
            "[build-dependencies] cc is not vetted",
            "table [target.'cfg(unix)'.dependencies] is not allowed",
            "table [dependencies.extra] is not allowed",
            "table [patch.crates-io] is not allowed",
            "Cargo.lock: left-pad 1.0.0 is not vetted",
            "Cargo.lock: forked 0.1.0 comes from git+https://example.org/forked#abc",
            "Cargo.lock: sha2 0.11.0 is not vetted",
            "Cargo.lock: vetted sha2 0.11.1 is missing",
            "src/bad.rs:1: dev-only crate",
            "src/private.rs:1: private path",
            "examples/bad.rs:1: dev-only crate",
            "tests/private.rs:1: private path",
        ],
    );
    // A dev-only crate in tests is fine; a missing vetted entry is reported.
    let tests_only = [("tests/ok.rs".to_string(), "use serde_json_canonicalizer::to_vec;\n".to_string())];
    assert_clean("dev crate in tests", source_problems(&tests_only, &v));
    let dropped = manifest.replacen("serde_json_canonicalizer = \"=0.4.1\"\n", "", 1);
    assert_reports(
        &problems(&dropped, &lock, &files, &v),
        &["[dev-dependencies] vetted serde_json_canonicalizer is missing"],
    );
}

#[test]
fn vetting_doc_negative_control() {
    let Some(doc) = vetting_doc() else { return };
    let v = vetted_set();
    assert_clean("an unmodified copy must pass", doc_problems(&doc, &v));
    let bad = doc
        .replacen(
            "| `sha2` (`RustCrypto/hashes`) | SHA-256 for the RFC 7638 thumbprint and `object_digest` | `0.11.1`",
            "| `sha2` (`RustCrypto/hashes`) | SHA-256 | `0.11.0`",
            1,
        )
        .replacen("| `regex` (`rust-lang/regex`)", "| `regex-lite` (`rust-lang/regex`)", 1)
        .replacen("`default-features = false, features = [\"sys_rng\"]`", "`features = [\"sys_rng\"]`", 1)
        .replacen("`features = [\"float_roundtrip\"]`", "`float_roundtrip`", 1)
        .replacen("| `serde_json_canonicalizer` (", "| `serde_json_canon` (", 1)
        .replacen("`zmij@", "`zmij-fork@", 1);
    assert_ne!(bad, doc);
    assert_reports(
        &doc_problems(&bad, &v),
        &[
            "sha2 row is at 0.11.0, pinned 0.11.1",
            "[dependencies] regex has no row",
            "row regex-lite is not a vetted runtime dependency",
            "getrandom row disagrees on default-features = false",
            "serde_json row does not name feature float_roundtrip",
            "[dev-dependencies] serde_json_canonicalizer has no row",
            "locked zmij ",
            "listed zmij-fork ",
        ],
    );
}
