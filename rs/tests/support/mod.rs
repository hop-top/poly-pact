//! Shared test helpers: where the language-neutral fixtures are.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The repository's spec/v1.0 directory, or None in a package mirror, which
/// has no spec tree. With PACT_REQUIRE_VECTORS=1 (the source repository) an
/// absent tree fails the test instead.
pub fn spec_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/v1.0");
    if dir.join("fixtures/manifest.json").is_file() {
        return Some(dir);
    }
    if std::env::var("PACT_REQUIRE_VECTORS").as_deref() == Ok("1") {
        panic!("PACT_REQUIRE_VECTORS=1 and {} is absent", dir.display());
    }
    eprintln!("NOTICE: {} absent; test skipped", dir.display());
    None
}

/// The fixture directory spec/v1.0/fixtures.
pub fn fixtures() -> Option<PathBuf> {
    spec_dir().map(|d| d.join("fixtures"))
}

pub fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&read(path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The manifest entries whose id starts with prefix.
pub fn entries(fixtures: &Path, prefix: &str) -> Vec<serde_json::Value> {
    let m = read_json(&fixtures.join("manifest.json"));
    m["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|e| e["id"].as_str().unwrap_or("").starts_with(prefix))
        .cloned()
        .collect()
}
