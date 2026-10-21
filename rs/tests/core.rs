//! The wire types, enums, limits and digests of core, after go/core's
//! types_test.go, schema_drift_test.go, limits_test.go and digest tests.

mod support;

use std::collections::BTreeSet;

use hop_top_pact::core::digest::{self, Error as DigestError};
use hop_top_pact::core::strictjson::{self, Kind, Limits as JSONLimits};
use hop_top_pact::core::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The member names a value of T serializes when every optional member is
/// present, read from a default value.
fn members<T: Default + Serialize>() -> BTreeSet<String> {
    let v = serde_json::to_value(T::default()).unwrap();
    v.as_object().unwrap().keys().cloned().collect()
}

fn decode<T: DeserializeOwned>(s: &str) -> Result<T, strictjson::Error> {
    strictjson::unmarshal(s.as_bytes(), JSONLimits::default())
}

macro_rules! drift {
    ($($t:ident),+ $(,)?) => {{
        let mut seen = BTreeSet::new();
        $(
            seen.insert(stringify!($t).to_string());
            check_drift::<$t>(stringify!($t));
        )+
        seen
    }};
}

const OPTIONAL: [&str; 3] = ["extensions", "endpoints", "jwks_uri"];

fn check_drift<T: Default + Serialize + DeserializeOwned + std::fmt::Debug>(name: &str) {
    let schema: serde_json::Value = serde_json::from_str(schema::SCHEMA_JSON).unwrap();
    let def = &schema["$defs"][name];
    let props: BTreeSet<String> = def["properties"].as_object().unwrap().keys().cloned().collect();
    let required: BTreeSet<String> =
        def["required"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect();
    assert_eq!(members::<T>(), required, "{name}: members written by default are the required ones");
    for p in props.difference(&required) {
        assert!(OPTIONAL.contains(&p.as_str()), "{name}: optional member {p} is not one the types know");
        let value = if p == "jwks_uri" { "\"https://x\"" } else { "{}" };
        let doc = format!("{{\"{p}\":{value}}}");
        let got = serde_json::to_value(decode::<T>(&doc).unwrap_or_else(|e| panic!("{name} {doc}: {e}"))).unwrap();
        assert!(got.get(p.as_str()).is_some(), "{name}: present {p} survives");
        let e = decode::<T>(&format!("{{\"{p}\":null}}")).unwrap_err();
        assert_eq!(e.kind, Kind::Null, "{name}: {p} null");
    }
    assert_eq!(decode::<T>(r#"{"bogus":1}"#).unwrap_err().kind, Kind::UnknownField, "{name}");
}

#[test]
fn schema_drift() {
    let seen = drift!(
        AgentProfile,
        Intent,
        OperationContext,
        FieldRule,
        RequirementContract,
        Claim,
        Evidence,
        Presentation,
        CheckResult,
        AdmissionAttestation,
        ReputationContext,
        DimensionStats,
        ReputationValue,
        ReputationSnapshot,
        Attribution,
        OutcomeReport,
        AdaptiveControl,
        DataPolicy,
        MetricBound,
        EvaluationPolicy,
        LearningPolicy,
        LearningArtifact,
        LearningEvent,
        ContractRequest,
        EvaluationRequest,
        ReputationQuery,
        ReceiptQuery,
        Acknowledgment,
        NativeAdapter,
        GatewayMetadata,
        Problem,
    );
    let defs: BTreeSet<String> = schema::defs().into_iter().map(String::from).collect();
    let payload_only: BTreeSet<String> = ["ConformanceDeclaration", "TransportDeclaration"].map(String::from).into();
    let want: BTreeSet<String> = defs.difference(&payload_only).cloned().collect();
    assert_eq!(seen, want, "one type per $defs entry");
}

#[test]
fn nested_helpers_drift() {
    let schema: serde_json::Value = serde_json::from_str(schema::SCHEMA_JSON).unwrap();
    let props = |def: &str, member: &str| -> BTreeSet<String> {
        schema["$defs"][def]["properties"][member]["properties"].as_object().unwrap().keys().cloned().collect()
    };
    assert_eq!(members::<GatewayEndpoints>(), props("GatewayMetadata", "endpoints"));
    assert_eq!(members::<ReputationDimensions>(), props("ReputationValue", "dimensions"));
}

#[test]
fn appendix_b_decodes_and_validates() {
    let Some(fx) = support::fixtures() else { return };
    let doc = support::read_json(&fx.join("schema/appendix-b-valid.json"));
    for o in doc["objects"].as_array().unwrap() {
        let def = match (o.get("def").and_then(|d| d.as_str()), o.get("typ").and_then(|t| t.as_str())) {
            (Some(d), _) => d.to_string(),
            (None, Some(t)) => typ_def(t).to_string(),
            _ => panic!("{o}"),
        };
        let text = serde_json::to_string(&o["object"]).unwrap();
        schema::validate(&def, text.as_bytes(), JSONLimits::default()).unwrap_or_else(|e| panic!("{def}: {e}"));
        round_trip(&def, &text);
    }
}

fn typ_def(typ: &str) -> &'static str {
    match typ {
        "pact-requirements+jwt" => "RequirementContract",
        "pact-evidence+jwt" => "Evidence",
        "pact-presentation+jwt" => "Presentation",
        "pact-admission+jwt" => "AdmissionAttestation",
        "pact-outcome+jwt" => "OutcomeReport",
        "pact-reputation+jwt" => "ReputationSnapshot",
        "pact-learning-policy+jwt" => "LearningPolicy",
        "pact-learning-artifact+jwt" => "LearningArtifact",
        "pact-learning-event+jwt" => "LearningEvent",
        _ => panic!("typ {typ}"),
    }
}

/// Decodes the object as its type and encodes it again: the canonical forms
/// are equal, so no member is lost or added.
fn round_trip(def: &str, text: &str) {
    fn rt<T: Serialize + DeserializeOwned>(text: &str) -> Vec<u8> {
        let v: T = decode(text).unwrap();
        hop_top_pact::core::jcs::canonicalize(&serde_json::to_vec(&v).unwrap()).unwrap()
    }
    let got = match def {
        "AgentProfile" => rt::<AgentProfile>(text),
        "Intent" => rt::<Intent>(text),
        "OperationContext" => rt::<OperationContext>(text),
        "RequirementContract" => rt::<RequirementContract>(text),
        "Evidence" => rt::<Evidence>(text),
        "Presentation" => rt::<Presentation>(text),
        "AdmissionAttestation" => rt::<AdmissionAttestation>(text),
        "OutcomeReport" => rt::<OutcomeReport>(text),
        "ReputationSnapshot" => rt::<ReputationSnapshot>(text),
        "GatewayMetadata" => rt::<GatewayMetadata>(text),
        "ContractRequest" => rt::<ContractRequest>(text),
        "EvaluationRequest" => rt::<EvaluationRequest>(text),
        "LearningPolicy" => rt::<LearningPolicy>(text),
        "LearningArtifact" => rt::<LearningArtifact>(text),
        "LearningEvent" => rt::<LearningEvent>(text),
        "ReputationQuery" => rt::<ReputationQuery>(text),
        "ReceiptQuery" => rt::<ReceiptQuery>(text),
        "Acknowledgment" => rt::<Acknowledgment>(text),
        "Problem" => rt::<Problem>(text),
        other => panic!("no type for {other}"),
    };
    let want = hop_top_pact::core::jcs::canonicalize(text.as_bytes()).unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), String::from_utf8(want).unwrap(), "{def}");
}

#[test]
fn schema_rejects() {
    let e = schema::validate("Intent", br#"{"intent_id":"i"}"#, JSONLimits::default()).unwrap_err();
    assert!(
        matches!(&e, schema::Error::Schema { def, issues } if def == "Intent" && issues.iter().any(|i| i.keyword == "required")),
        "{e}"
    );
    let e = schema::validate("Intent", br#"{"a":1,"a":1}"#, JSONLimits::default()).unwrap_err();
    assert!(matches!(e, schema::Error::Json(ref j) if j.kind == Kind::DuplicateKey), "{e}");
    assert!(matches!(schema::validate("Nope", b"{}", JSONLimits::default()), Err(schema::Error::UnknownDef(_))));
}

#[test]
fn appendix_c_payload_fails_only_its_version() {
    let Some(fx) = support::fixtures() else { return };
    let compact = String::from_utf8(support::read(&fx.join("parse/appendix-c-wrong-version.jws"))).unwrap();
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        compact.trim().split('.').nth(1).unwrap(),
    )
    .unwrap();
    match schema::validate("Evidence", &payload, JSONLimits::default()) {
        Err(schema::Error::Schema { issues, .. }) => {
            assert_eq!(issues.len(), 1, "{issues:?}");
            assert_eq!((issues[0].instance_path.as_str(), issues[0].keyword.as_str()), ("/pact_version", "const"));
        }
        other => panic!("{other:?}"),
    }
    let mut v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    v["pact_version"] = VERSION.into();
    schema::validate("Evidence", v.to_string().as_bytes(), JSONLimits::default()).unwrap();
}

#[test]
fn uri_format_vectors() {
    let Some(fx) = support::fixtures() else { return };
    let rows = support::read_json(&fx.join("vectors/schema/uri-format.json"));
    let rows = rows.as_array().unwrap();
    assert!(rows.len() > 20);
    for r in rows {
        let input = r["input"].as_str().unwrap();
        let want = r["expect"].as_str().unwrap() == "accept";
        assert_eq!(schema::uri_format(input), want, "{}: {input:?}", r["id"]);
    }
    let def_check = schema::validate(
        "NativeAdapter",
        br#"{"protocol":"a","version":"1","mapping_revision":"r"}"#,
        JSONLimits::default(),
    );
    assert!(def_check.is_ok(), "{def_check:?}");
}

#[test]
fn enums_valid() {
    assert!(Mode::OBSERVE.is_valid());
    assert!(!Mode::new("Observe").is_valid());
    assert_eq!(Decision::VALUES.len(), 3);
    assert_eq!(JWSAlgorithm::ED25519.as_str(), "Ed25519");
    let m: Mode = decode(r#""bogus""#).unwrap();
    assert_eq!((m.as_str(), m.is_valid()), ("bogus", false));
    assert_eq!(serde_json::to_string(&RuleSource::SELF).unwrap(), r#""self""#);
    assert_eq!(VERSION, "0.1");
}

#[test]
fn core_integers_are_range_checked() {
    assert_eq!(decode::<Intent>(r#"{"description":"d"}"#).unwrap().description, "d");
    assert_eq!(decode::<Acknowledgment>(r#"{"received_at":-1}"#).unwrap_err().kind, Kind::Integer);
    assert_eq!(decode::<Acknowledgment>(r#"{"received_at":9007199254740992}"#).unwrap_err().kind, Kind::Integer);
    assert_eq!(decode::<Acknowledgment>(r#"{"received_at":2.0}"#).unwrap_err().kind, Kind::Integer);
    assert_eq!(decode::<CheckResult>(r#"{"source_observed_at":null}"#).unwrap().source_observed_at, None);
    assert_eq!(decode::<AgentProfile>(r#"{"attributes":{"x":{"A":1,"a":[null]}}}"#).unwrap().attributes.len(), 1);
    assert_eq!(decode::<AgentProfile>(r#"{"attributes":null}"#).unwrap_err().kind, Kind::Null);
}

#[test]
fn digest_validate() {
    assert!(Digest::from("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M").validate().is_ok());
    assert!(Digest::from("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0").validate().is_err());
    assert!(Digest::from("xx0BcA+wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M").validate().is_err());
    assert_eq!(DIGEST_LEN, 43);
}

#[test]
fn digests() {
    assert_eq!(digest::bytes_digest(b"").as_str(), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    assert_eq!(digest::artifact_digest("a.b.c").unwrap(), digest::bytes_digest(b"a.b.c"));
    assert_eq!(digest::artifact_digest("a.é").unwrap_err(), DigestError::NotAscii { byte: 0xc3, offset: 2 });
    let a = digest::object_digest(&serde_json::json!({"b": [1, 2.5], "a": "x"})).unwrap();
    assert_eq!(a, digest::object_digest_json(br#"{ "a":"x", "b":[1,2.50] }"#).unwrap());
    assert_eq!(a, digest::bytes_digest(br#"{"a":"x","b":[1,2.5]}"#));
    assert_eq!(digest::object_digest(&[1, 2]).unwrap_err(), DigestError::NotObject);
    assert_eq!(digest::object_digest("x").unwrap_err(), DigestError::NotObject);
    let big = serde_json::json!({"n": 9007199254740993u64});
    assert!(matches!(digest::object_digest(&big), Err(DigestError::Canonicalize(_))));
    let intent = Intent { intent_id: "i".into(), ..Default::default() };
    assert_eq!(
        digest::object_digest(&intent).unwrap(),
        digest::object_digest_json(br#"{"intent_id":"i","purpose_id":"","description":"","task_id":""}"#).unwrap()
    );
}

#[test]
fn digest_vectors() {
    let Some(fx) = support::fixtures() else { return };
    let rows = support::read_json(&fx.join("vectors/digest/appendix-b.json"));
    for r in rows.as_array().unwrap() {
        let got = match r["input_kind"].as_str().unwrap() {
            "object" => digest::object_digest(&r["input"]).unwrap(),
            "artifact" => digest::artifact_digest(r["input"].as_str().unwrap()).unwrap(),
            "bytes" => {
                let hex = r["input"].as_str().unwrap();
                let b: Vec<u8> =
                    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
                digest::bytes_digest(&b)
            }
            k => panic!("{k}"),
        };
        assert_eq!(got.as_str(), r["expected_digest"].as_str().unwrap(), "{}", r["id"]);
    }
}

#[test]
fn limits() {
    let d = Limits::default();
    assert_eq!(d, Limits::defaults());
    assert!(d.check().is_ok());
    assert_eq!(
        (d.presentation_bytes, d.artifact_payload_bytes, d.depth, d.description_bytes),
        (262144, 32768, 16, 4096)
    );
    let loose = Limits { depth: 17, ..d };
    assert_eq!(
        loose.check().unwrap_err(),
        LimitError { kind: LimitKind::Invalid, key: KEY_MAX_JSON_DEPTH, max: 16, got: 17 }
    );
    assert_eq!(Limits { resources: 0, ..d }.check().unwrap_err().key, KEY_MAX_RESOURCES);
    let intent = Intent { description: "é".repeat(2049), ..Default::default() };
    let e = d.validate_intent(&intent).unwrap_err();
    assert_eq!((e.kind, e.got, e.max), (LimitKind::Exceeded, 4098, 4096), "bytes, not characters");
    let op = OperationContext { resources: vec![String::new(); 257], ..Default::default() };
    assert_eq!(d.validate_operation(&op).unwrap_err().key, KEY_MAX_RESOURCES);
    let p = Presentation { evidence: vec![String::new(); 33], ..Default::default() };
    assert_eq!(d.validate_presentation(&p, 10).unwrap_err().key, KEY_MAX_EVIDENCE_ARTIFACTS);
    assert_eq!(d.validate_presentation(&p, 262145).unwrap_err().key, KEY_MAX_PRESENTATION_BYTES);
    assert!(d.validate_artifact_size(32768).is_ok() && d.validate_artifact_size(32769).is_err());
    assert!(d.validate_profile_size(32769).is_err());
    let c = RequirementContract { field_rules: vec![FieldRule::default(); 129], ..Default::default() };
    assert_eq!(d.validate_contract(&c).unwrap_err().key, KEY_MAX_FIELD_RULES);
    assert_eq!(d.artifact_json(), JSONLimits { max_bytes: 32768, max_depth: 16 });
    assert_eq!(Limits { depth: 3, ..d }.presentation_json().max_depth, 3);
    assert_eq!(d.profile_json().max_bytes, 32768);
}

#[test]
fn schema_asserts_uri_with_the_shared_matcher() {
    let Some(fx) = support::fixtures() else { return };
    let rows = support::read_json(&fx.join("vectors/schema/uri-format.json"));
    let base = r#"{"intent_id":"i","description":"d","task_id":"t","purpose_id":"#;
    let mut checked = 0;
    for r in rows.as_array().unwrap() {
        let input = r["input"].as_str().unwrap();
        if input.is_empty() || input.len() > 1024 {
            continue;
        }
        let doc = format!("{base}{}}}", serde_json::to_string(input).unwrap());
        let accepted = schema::validate("Intent", doc.as_bytes(), JSONLimits::default()).is_ok();
        assert_eq!(accepted, r["expect"] == "accept", "{}: {input:?}", r["id"]);
        checked += 1;
    }
    assert!(checked > 20);
}
