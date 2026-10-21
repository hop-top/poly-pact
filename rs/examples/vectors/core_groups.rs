//! The vectors/jcs, vectors/digest, vectors/strictjson and vectors/schema
//! groups, after the Go runners of cli/pactconf (vectors_core.go,
//! vectors_schema.go) and the formats of spec/v1.0/fixtures/vectors/<group>.

use std::collections::HashSet;
use std::path::Path;

use hop_top_pact::core::strictjson::{self, Limits};
use hop_top_pact::core::{OperationContext, digest, jcs, schema};
use serde_json::{Value, json};

use super::fixture::*;
use super::manifest::Entry;

/// vectors/jcs: an input and output pair whose canonical form is the output
/// byte for byte, or the number list, each binary64 value written as an
/// exponent literal and canonicalized.
pub fn run_jcs(root: &Path, e: &Entry) -> Res {
    let Some(expected) = e.expected.as_deref() else { return fail("expected is null") };
    if e.path == expected {
        return run_jcs_numbers(root, &e.path);
    }
    let input = read_fixture(root, &e.path)?;
    let want = read_fixture(root, expected)?;
    let got = jcs::canonicalize(&input).or_else(|err| fail(format!("canonicalize the input: {err}")))?;
    if got != want {
        return fail(format!(
            "canonical form {:?}, want {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want)
        ));
    }
    if jcs::canonicalize(&want).ok().as_deref() != Some(&want[..]) {
        return fail("the expected output is not canonical");
    }
    Ok(())
}

fn run_jcs_numbers(root: &Path, rel: &str) -> Res {
    let vs = read_json(root, rel)?;
    let Some(rows) = vs.as_array().filter(|a| !a.is_empty()) else { return fail(format!("{rel} has no numbers")) };
    for (i, v) in rows.iter().enumerate() {
        let hex = v.get("ieee754_hex").and_then(Value::as_str).filter(|h| h.len() == 16);
        let want = v.get("expected").and_then(Value::as_str).filter(|w| !w.is_empty());
        let (Some(hex), Some(want)) = (hex, want) else { return fail(format!("number {i} is malformed")) };
        let Ok(bits) = u64::from_str_radix(hex, 16) else { return fail(format!("number {i} is malformed")) };
        let literal = format!("{:e}", f64::from_bits(bits));
        let got = jcs::canonicalize(literal.as_bytes())
            .or_else(|err| fail(format!("{hex}: canonicalize {literal}: {err}, want {want:?}")))?;
        if got != want.as_bytes() {
            return fail(format!("{hex}: canonical form {:?}, want {want:?}", String::from_utf8_lossy(&got)));
        }
    }
    Ok(())
}

const DIGEST_MEMBERS: [&str; 6] = ["appendix_value", "expected_digest", "id", "input", "input_kind", "spec_defect"];

/// vectors/digest: every vector's digest equals expected_digest, and a value
/// the draft prints equals it too unless the vector marks a spec defect,
/// which is skipped:spec-defect with both values.
pub fn run_digest(root: &Path, e: &Entry) -> Res {
    single_file(e)?;
    let vs = read_json(root, &e.path)?;
    let Some(rows) = vs.as_array().filter(|a| !a.is_empty()) else { return fail(format!("{} has no vectors", e.path)) };
    let mut defects = Vec::new();
    let mut seen = HashSet::new();
    for (i, raw) in rows.iter().enumerate() {
        let v = exact_members(raw, &DIGEST_MEMBERS).map_err(|f| prefix(f, &format!("vector {i}")))?;
        let id = v.get("id").and_then(Value::as_str).filter(|id| !id.is_empty() && seen.insert(id.to_string()));
        let Some(id) = id else { return fail(format!("vector {i}: id {:?} is empty or repeated", v.get("id"))) };
        let want = string_of(v.get("expected_digest"), &format!("{id}: expected_digest"))?;
        let appendix = nullable_string_of(v.get("appendix_value"), &format!("{id}: appendix_value"))?;
        let Some(defect) = v.get("spec_defect").and_then(Value::as_bool) else {
            return fail(format!("{id}: spec_defect is not a boolean"));
        };
        let got = compute_digest(id, v)?;
        if got != want {
            return fail(format!("{id}: digest {got}, want expected_digest {want}"));
        }
        match appendix {
            None if defect => return fail(format!("{id}: spec_defect is set but appendix_value is null")),
            None => {}
            Some(a) if a == got && defect => {
                return fail(format!("{id}: spec_defect is set but appendix_value matches"));
            }
            Some(a) if a == got => {}
            Some(a) if defect => defects.push(json!({"vector": id, "appendix_value": a, "expected_digest": got})),
            Some(a) => return fail(format!("{id}: appendix_value {a} differs from {got} and spec_defect is not set")),
        }
    }
    if !defects.is_empty() {
        let what: Vec<String> = defects
            .iter()
            .map(|d| {
                format!("{}: the draft states {}, computed {}", d["vector"], d["appendix_value"], d["expected_digest"])
            })
            .collect();
        return Err(Fail::Skip {
            reason: "spec-defect",
            detail: format!("spec defect: {}", what.join("; ")),
            spec_defects: defects,
        });
    }
    Ok(())
}

fn prefix(f: Fail, p: &str) -> Fail {
    match f {
        Fail::Fail(m) => Fail::Fail(format!("{p}: {m}")),
        other => other,
    }
}

fn compute_digest(id: &str, v: &serde_json::Map<String, Value>) -> Res<String> {
    let r = match v.get("input_kind").and_then(Value::as_str) {
        Some("object") => digest::object_digest(&v["input"]),
        Some("artifact") => digest::artifact_digest(string_of(v.get("input"), &format!("{id}: input"))?),
        Some("bytes") => {
            let hex = string_of(v.get("input"), &format!("{id}: input"))?;
            let ok = hex.len() % 2 == 0 && hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
            if !ok {
                return fail(format!("{id}: input {hex:?} is not lowercase hex"));
            }
            let b: Vec<u8> =
                (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0)).collect();
            Ok(digest::bytes_digest(&b))
        }
        other => return fail(format!("{id}: input_kind {other:?} is not object, artifact or bytes")),
    };
    r.map(|d| d.0).or_else(|err| fail(format!("{id}: {err}")))
}

/// vectors/strictjson: the input is decoded as an OperationContext and
/// accepted, or refused with a strictjson error, as expect says.
pub fn run_strictjson(root: &Path, e: &Entry) -> Res {
    single_file(e)?;
    let raw = read_json(root, &e.path)?;
    let v = only_members(&raw, &["id", "input_text", "input_b64", "expect", "reason"])?;
    let reason_ok = v.get("reason").and_then(Value::as_str).is_some_and(|r| !r.is_empty());
    if v.get("id").and_then(Value::as_str) != Some(e.id.as_str()) || !reason_ok {
        return fail(format!("vector id {:?} (manifest {:?}) or empty reason", v.get("id"), e.id));
    }
    let text = match v.get("input_text") {
        None => "",
        t => string_of(t, "input_text")?,
    };
    let b64 = match v.get("input_b64") {
        None => "",
        t => string_of(t, "input_b64")?,
    };
    let input = match (text.is_empty(), b64.is_empty()) {
        (false, false) => return fail("both input_text and input_b64 are set"),
        (true, false) => base64_std(b64, "input_b64")?,
        (false, true) => text.as_bytes().to_vec(),
        (true, true) => return fail("no input"),
    };
    let expect = v.get("expect").and_then(Value::as_str).unwrap_or_default();
    let want = match expect {
        "accept" => "ACCEPTED",
        "reject" => "REJECTED",
        _ => "",
    };
    if want.is_empty() || Some(want) != e.outcome.as_deref() {
        return fail(format!("expect {expect:?} does not agree with outcome {:?}", e.outcome));
    }
    let r = strictjson::unmarshal::<OperationContext>(&input, Limits::default());
    match (expect, r) {
        ("accept", Err(err)) => fail(format!("rejected ({err}), want accept")),
        ("reject", Ok(_)) => fail("accepted, want reject"),
        _ => Ok(()),
    }
}

const SCHEMA_MEMBERS: [&str; 5] = ["ajv_formats_differs", "expect", "id", "input", "reason"];

/// vectors/schema: each string gets the vector's verdict under the shared
/// checker of the entry's format.
pub fn run_schema_vectors(root: &Path, e: &Entry) -> Res {
    single_file(e)?;
    if e.id != "vectors/schema/uri-format" {
        return fail(format!("no format for {}", e.id));
    }
    if e.outcome.as_deref() != Some("MATCH") {
        return fail(format!("outcome {:?}, want MATCH", e.outcome));
    }
    let vs = read_json(root, &e.path)?;
    let Some(rows) = vs.as_array().filter(|a| !a.is_empty()) else { return fail(format!("{} has no vectors", e.path)) };
    let mut wrong = Vec::new();
    let mut seen = HashSet::new();
    for (i, raw) in rows.iter().enumerate() {
        let v = exact_members(raw, &SCHEMA_MEMBERS).map_err(|f| prefix(f, &format!("vector {i}")))?;
        let id = v.get("id").and_then(Value::as_str).filter(|id| !id.is_empty() && seen.insert(id.to_string()));
        let Some(id) = id else { return fail(format!("vector {i}: id {:?} is empty or repeated", v.get("id"))) };
        let expect = v.get("expect").and_then(Value::as_str).unwrap_or_default();
        if expect != "accept" && expect != "reject" {
            return fail(format!("{id}: expect {expect:?}, want accept or reject"));
        }
        let got =
            if schema::uri_format(string_of(v.get("input"), &format!("{id}: input"))?) { "accept" } else { "reject" };
        if got != expect {
            wrong.push(format!("{id}: {got}ed, want {expect}"));
        }
    }
    if !wrong.is_empty() {
        return fail(format!("format uri: {}", wrong.join("; ")));
    }
    Ok(())
}
