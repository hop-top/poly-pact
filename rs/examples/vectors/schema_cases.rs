//! The schema cases (kind schema, prefixes parse and schema), after
//! spec/v1.0/fixtures/schema/README.md: each document is accepted when it is
//! strict JSON and valid against the definition its type selects, and
//! rejected with INVALID_MESSAGE otherwise.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hop_top_pact::core::schema;
use hop_top_pact::core::strictjson::{self, Limits};
use serde_json::Value;

use super::fixture::*;
use super::manifest::Entry;

const INVALID_MESSAGE: &str = "INVALID_MESSAGE";

/// The definition the `typ` of a signed artifact selects (Appendix A.1).
fn def_of_typ(typ: &str) -> Option<&'static str> {
    Some(match typ {
        "pact-requirements+jwt" => "RequirementContract",
        "pact-evidence+jwt" => "Evidence",
        "pact-presentation+jwt" => "Presentation",
        "pact-admission+jwt" => "AdmissionAttestation",
        "pact-outcome+jwt" => "OutcomeReport",
        "pact-reputation+jwt" => "ReputationSnapshot",
        "pact-learning-policy+jwt" => "LearningPolicy",
        "pact-learning-artifact+jwt" => "LearningArtifact",
        "pact-learning-event+jwt" => "LearningEvent",
        _ => return None,
    })
}

/// The verdict of a compact JWS: why it is rejected, or None.
fn jws_verdict(compact: &str) -> Option<String> {
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 3 {
        return Some("not three segments".into());
    }
    let seg = |s: &str| URL_SAFE_NO_PAD.decode(s).ok().filter(|b| URL_SAFE_NO_PAD.encode(b) == s);
    let (Some(header), Some(payload)) = (seg(parts[0]), seg(parts[1])) else {
        return Some("a segment is not canonical base64url".into());
    };
    let h = match strictjson::parse(&header, Limits::default()) {
        Ok(Value::Object(h)) => h,
        Ok(_) => return Some("the protected header is not an object".into()),
        Err(e) => return Some(format!("protected header: {e}")),
    };
    let Some(def) = h.get("typ").and_then(Value::as_str).and_then(def_of_typ) else {
        return Some(format!("typ {:?} is not in the table", h.get("typ")));
    };
    doc_verdict(def, &payload)
}

/// The verdict of a document's text under its definition.
fn doc_verdict(def: &str, text: &[u8]) -> Option<String> {
    schema::validate(def, text, Limits::default()).err().map(|e| e.to_string())
}

/// One schema entry: every document gets the entry's outcome.
pub fn run_schema_case(root: &Path, e: &Entry) -> Res {
    let mut verdicts: Vec<(String, Option<String>)> = Vec::new();
    if e.path.ends_with(".jws") {
        let b = read_fixture(root, &e.path)?;
        let text = String::from_utf8_lossy(&b);
        verdicts.push(("document".into(), jws_verdict(text.trim_end_matches(['\n', '\r']))));
    } else {
        let raw = read_fixture(root, &e.path)?;
        let doc = strictjson::parse(&raw, Limits { max_bytes: 1 << 20, max_depth: 32 })
            .or_else(|err| fail(format!("{}: {err}", e.path)))?;
        let list = only_members(&doc, &["description", "objects"])?;
        let Some(objects) = list.get("objects").and_then(Value::as_array).filter(|o| !o.is_empty()) else {
            return fail("objects is not a non-empty array");
        };
        for (i, o) in objects.iter().enumerate() {
            let m = only_members(o, &["section", "typ", "def", "object"])?;
            let def = match (m.get("def").and_then(Value::as_str), m.get("typ").and_then(Value::as_str)) {
                (Some(d), None) => d.to_string(),
                (None, Some(t)) => match def_of_typ(t) {
                    Some(d) => d.to_string(),
                    None => return fail(format!("objects[{i}]: typ {t:?} is not in the table")),
                },
                _ => return fail(format!("objects[{i}]: one of typ and def")),
            };
            let text = serde_json::to_vec(&m["object"]).unwrap_or_default();
            verdicts.push((format!("objects[{i}] ({def})"), doc_verdict(&def, &text)));
        }
    }
    match e.outcome.as_deref() {
        Some("ACCEPTED") => {
            if e.expected.as_deref() != Some(e.path.as_str()) {
                return fail("an accepted case names its own path as expected");
            }
            let bad: Vec<String> =
                verdicts.iter().filter_map(|(w, v)| v.as_ref().map(|v| format!("{w}: {v}"))).collect();
            if !bad.is_empty() {
                return fail(format!("rejected, want accept: {}", bad.join("; ")));
            }
        }
        Some("REJECTED") => {
            let Some(exp) = e.expected.as_deref() else { return fail("expected is null") };
            let decision = read_json(root, exp)?;
            let code = decision.get("transport_code").and_then(Value::as_str);
            if code != Some(INVALID_MESSAGE) {
                return fail(format!("{exp}: transport_code {code:?}, want {INVALID_MESSAGE}"));
            }
            let ok: Vec<&String> = verdicts.iter().filter(|(_, v)| v.is_none()).map(|(w, _)| w).collect();
            if !ok.is_empty() {
                return fail(format!("accepted, want reject: {ok:?}"));
            }
        }
        other => return fail(format!("outcome {other:?} is not ACCEPTED or REJECTED")),
    }
    Ok(())
}
