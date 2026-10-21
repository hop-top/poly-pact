//! Tests of the harness itself: entry handling, the result grammar and the
//! exit status (docs/sdk/ports-plan.md sections 5.1 to 5.3).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::harness::run_manifest;
use super::manifest::Gates;

/// A fixture directory of its own under the system temporary directory.
struct Tree(PathBuf);

impl Tree {
    fn new() -> Tree {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pact-rs-vectors-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Tree(dir)
    }

    fn write(&self, rel: &str, v: &Value) -> &Tree {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
        self
    }

    fn manifest(&self, entries: Value) -> PathBuf {
        self.write("manifest.json", &json!({"manifest_version": 1, "entries": entries}));
        self.0.join("manifest.json")
    }

    fn gates(&self, rows: Value) -> Gates {
        self.write("gates.json", &json!({"gates_version": 1, "rows": rows}));
        Gates::load(&self.0.join("gates.json")).unwrap()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entry(id: &str, kind: &str, scope: &str, path: &str, outcome: &str) -> Value {
    json!({"id": id, "kind": kind, "scope": scope, "path": path, "expected": path, "outcome": outcome})
}

fn strictjson_vector(t: &Tree, name: &str, expect: &str) -> Value {
    let id = format!("vectors/strictjson/{name}");
    t.write(
        &format!("vectors/strictjson/{name}.json"),
        &json!({"id": id, "input_text": "{\"a\":1,\"a\":2}", "expect": expect, "reason": "r"}),
    );
    let outcome = if expect == "accept" { "ACCEPTED" } else { "REJECTED" };
    entry(&id, "vector", "core", &format!("vectors/strictjson/{name}.json"), outcome)
}

fn results(path: &Path, gates: Option<&Gates>) -> (Vec<String>, i32) {
    let r = run_manifest(path, &[], gates).unwrap();
    (r.lines.iter().map(|l| serde_json::to_string(l).unwrap()).collect(), r.status)
}

#[test]
fn scope_runner_and_other_kinds_are_out_of_scope() {
    let t = Tree::new();
    let m = t.manifest(json!([
        entry("admission/a", "evaluate", "runner", "admission/a", "ACCEPTED"),
        entry("vectors/jws/x", "vector", "runner", "vectors/jws/x.json", "ACCEPTED"),
        entry("adapters/_common/c", "adapter-case", "adapter", "adapters/_common/c.json", "ACCEPTED"),
        entry("vectors/binding/b", "vector", "adapter", "vectors/binding/b.json", "ACCEPTED"),
    ]));
    let (lines, status) = results(&m, None);
    assert_eq!(status, 0);
    for l in &lines {
        assert!(l.ends_with(r#""result":"skipped:out-of-scope"}"#), "{l}");
    }
    assert_eq!(lines[0], r#"{"id":"admission/a","kind":"evaluate","result":"skipped:out-of-scope"}"#);
}

#[test]
fn a_failure_fails_the_run() {
    let t = Tree::new();
    let m = t.manifest(json!([strictjson_vector(&t, "dup", "accept"), strictjson_vector(&t, "dup2", "reject")]));
    let (lines, status) = results(&m, None);
    assert_eq!(lines[0], r#"{"id":"vectors/strictjson/dup","kind":"vector","result":"fail"}"#);
    assert_eq!(lines[1], r#"{"id":"vectors/strictjson/dup2","kind":"vector","result":"pass"}"#);
    assert_eq!(status, 1);
    let row = |gate: &str| json!([{"scope": "core", "kind": "vector", "prefix": "vectors/strictjson", "rs": gate}]);
    assert_eq!(results(&m, Some(&t.gates(row("required")))).1, 1);
    let pass = t.manifest(json!([strictjson_vector(&t, "dup2", "reject")]));
    assert_eq!(results(&pass, Some(&t.gates(row("required")))).1, 0);
    assert_eq!(results(&pass, Some(&t.gates(row("n/a")))).1, 1, "a run under an n/a gate fails");
    t.write("gates.json", &json!({"gates_version": 1, "rows": row("planned")}));
    assert!(Gates::load(&t.0.join("gates.json")).is_err(), "an rs gate is required or n/a");
}

#[test]
fn harness_errors() {
    let t = Tree::new();
    let bad = [
        json!([entry("x/a", "nonsense", "core", "x/a.json", "ACCEPTED")]),
        json!([entry("x/a", "vector", "elsewhere", "x/a.json", "ACCEPTED")]),
        json!([entry("vectors/unknown/a", "vector", "core", "vectors/unknown/a.json", "ACCEPTED")]),
        json!([
            entry("admission/a", "evaluate", "runner", "a", "ACCEPTED"),
            entry("admission/a", "evaluate", "runner", "a", "ACCEPTED")
        ]),
        json!([{"id": "keys/a", "kind": "key", "scope": "core", "path": "keys/a.json", "capabilities": ["bogus"]}]),
        json!([{"kind": "key", "scope": "core", "path": "keys/a.json"}]),
    ];
    for entries in bad {
        let m = t.manifest(entries.clone());
        assert!(run_manifest(&m, &[], None).is_err(), "{entries}");
    }
    t.write("manifest.json", &json!({"manifest_version": 1.0, "entries": []}));
    assert!(run_manifest(&t.0.join("manifest.json"), &[], None).is_err(), "manifest_version 1.0");
    t.write("manifest.json", &json!({"manifest_version": 1, "entries": [], "extra": 1}));
    assert!(run_manifest(&t.0.join("manifest.json"), &[], None).is_err(), "unknown member");
    let m = t.manifest(json!([]));
    assert!(run_manifest(&m, &["jws-ed25519x".into()], None).is_err(), "unknown capability");
    std::fs::write(t.0.join("dup.json"), br#"{"manifest_version":1,"manifest_version":1,"entries":[]}"#).unwrap();
    assert!(run_manifest(&t.0.join("dup.json"), &[], None).is_err(), "duplicate member");
}

#[test]
fn an_entry_needing_an_undeclared_capability_is_skipped() {
    let t = Tree::new();
    let mut e = strictjson_vector(&t, "dup", "reject");
    e["capabilities"] = json!(["jws-ed25519"]);
    let m = t.manifest(json!([e]));
    let (lines, status) = results(&m, None);
    assert_eq!(
        lines[0],
        r#"{"id":"vectors/strictjson/dup","kind":"vector","result":"skipped:capability","missing_capabilities":["jws-ed25519"]}"#
    );
    assert_eq!(status, 0);
}

fn digest_entry(t: &Tree, appendix: Value, defect: bool) -> PathBuf {
    let empty = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    t.write(
        "vectors/digest/d.json",
        &json!([{"id": "empty", "input": "", "input_kind": "bytes", "expected_digest": empty, "appendix_value": appendix, "spec_defect": defect}]),
    );
    t.manifest(json!([entry("vectors/digest/d", "vector", "core", "vectors/digest/d.json", "ACCEPTED")]))
}

#[test]
fn digest_spec_defects() {
    let t = Tree::new();
    let m = digest_entry(&t, json!("AAAA"), true);
    let r = run_manifest(&m, &[], None).unwrap();
    let line = serde_json::to_value(&r.lines[0]).unwrap();
    assert_eq!(line["result"], "skipped:spec-defect");
    assert_eq!(line["spec_defects"][0]["appendix_value"], "AAAA");
    assert_eq!(r.status, 0);
    assert_eq!(
        results(&digest_entry(&t, json!("AAAA"), false), None),
        (vec![r#"{"id":"vectors/digest/d","kind":"vector","result":"fail"}"#.to_string()], 1)
    );
    let ok = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    assert_eq!(results(&digest_entry(&t, json!(ok), true), None).1, 1, "a defect flag on a matching value fails");
    assert_eq!(results(&digest_entry(&t, json!(ok), false), None).1, 0);
}

#[test]
fn a_wrong_jws_reason_fails() {
    let Some(fx) = fixtures() else { return };
    let t = Tree::new();
    let mut v: Value =
        serde_json::from_slice(&std::fs::read(fx.join("vectors/jws/kid-unknown.json")).unwrap()).unwrap();
    v["reject_reason"] = json!("kid-missing");
    t.write("vectors/jws/kid-unknown.json", &v);
    let m = t.manifest(json!([entry(
        "vectors/jws/kid-unknown",
        "vector",
        "core",
        "vectors/jws/kid-unknown.json",
        "REJECTED"
    )]));
    assert_eq!(results(&m, None).1, 1);
}

fn fixtures() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/v1.0/fixtures");
    if dir.join("manifest.json").is_file() {
        return Some(dir);
    }
    assert_ne!(std::env::var("PACT_REQUIRE_VECTORS").as_deref(), Ok("1"), "{} is absent", dir.display());
    None
}

#[test]
fn the_shared_fixtures_pass_under_the_gates() {
    let Some(fx) = fixtures() else { return };
    let gates = Gates::load(&fx.join("../../../tools/parity/gates.json")).ok();
    let r = run_manifest(&fx.join("manifest.json"), &[], gates.as_ref()).unwrap();
    let fails: Vec<&String> = r.details.iter().filter(|d| d.starts_with("FAIL")).collect();
    assert!(fails.is_empty(), "{fails:#?}");
    assert_eq!(r.status, 0);
    assert!(r.passed >= 151, "{}", r.summary);
}

#[test]
fn a_holder_key_must_be_the_appendix_c_key() {
    let t = Tree::new();
    let mut d = [0u8; 32];
    d[31] = 2;
    let k = p256::ecdsa::SigningKey::from_slice(&d).unwrap();
    let jwk = hop_top_pact::core::jws::public_jwk(k.verifying_key());
    let d64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, d);
    t.write("keys/holder.jwk.json", &serde_json::to_value(&jwk).unwrap());
    let record = json!({"role": "holder", "kty": "EC", "crv": "P-256", "scalar": "2", "d": d64, "public_jwk": "holder.jwk.json"});
    t.write("keys/test-private-scalars.json", &json!({"keys": [record]}));
    let key = |path: &str| json!({"id": path.trim_end_matches(".jwk.json").trim_end_matches(".json"), "kind": "key", "scope": "core", "path": path, "expected": null, "outcome": null});
    let m = t.manifest(json!([key("keys/holder.jwk.json"), key("keys/test-private-scalars.json")]));
    let r = run_manifest(&m, &[], None).unwrap();
    assert_eq!((r.failed, r.status), (2, 1), "{:?}", r.details);
    assert!(r.details[0].contains("holder thumbprint"), "{}", r.details[0]);
    let record = json!({"role": "issuer", "kty": "EC", "crv": "P-256", "scalar": "2", "d": d64, "public_jwk": "holder.jwk.json"});
    t.write("keys/test-private-scalars.json", &json!({"keys": [record]}));
    let r = run_manifest(&m, &[], None).unwrap();
    assert_eq!(r.passed, 1, "a non-holder record of scalar 2 passes: {:?}", r.details);
    assert!(r.details.iter().any(|d| d.contains("no P-256 record of role holder")), "{:?}", r.details);
}
