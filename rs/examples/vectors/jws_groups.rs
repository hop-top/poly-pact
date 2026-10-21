//! The vectors/jws group and the key rule, after cli/pactconf vectors_jws.go
//! and vectors_keys.go, spec/v1.0/fixtures/vectors/jws/README.md and
//! spec/v1.0/fixtures/keys/README.md.

use std::path::Path;

use hop_top_pact::core::jws::{self, JWK, KeySet, Role, StaticResolver, Verifier};
use hop_top_pact::core::strictjson;
use hop_top_pact::core::{Digest, Evidence, Limits, VERSION};
use p256::ecdsa::SigningKey;
use serde_json::Value;

use super::fixture::*;
use super::manifest::Entry;

const VERIFY_MEMBERS: [&str; 12] = [
    "compact",
    "decode_as",
    "description",
    "expect",
    "expected_holder_jkt",
    "expected_payload",
    "expected_typ",
    "id",
    "reject_reason",
    "signature_valid",
    "signer_jwk",
    "trusted_keysets",
];

/// The harness reason of an artifact refused after verification.
pub const PAYLOAD_SCHEMA: &str = "payload-schema";

fn parse_key(v: &Value) -> Result<JWK, jws::Error> {
    jws::parse_jwk(&serde_json::to_vec(v).unwrap_or_default())
}

/// vectors/jws: one verify vector, or one of the three array files.
pub fn run_jws(root: &Path, e: &Entry) -> Res {
    single_file(e)?;
    match e.id.as_str() {
        "vectors/jws/thumbprint" => return run_thumbprints(root, e),
        "vectors/jws/jwk-reject" => return run_jwk_rejects(root, e),
        "vectors/jws/appendix-c-keys" => return run_key_derivations(root, e),
        _ => {}
    }
    let raw = read_json(root, &e.path)?;
    let v = exact_members(&raw, &VERIFY_MEMBERS)?;
    if v.get("id").and_then(Value::as_str) != Some(e.id.as_str()) {
        return fail(format!("vector id {:?}, manifest id {:?}", v.get("id"), e.id));
    }
    let reject_reason = nullable_string_of(v.get("reject_reason"), "reject_reason")?;
    let expect = v.get("expect").and_then(Value::as_str).unwrap_or_default();
    let agree = matches!(
        (expect, reject_reason, e.outcome.as_deref()),
        ("accept", None, Some("ACCEPTED")) | ("reject", Some(_), Some("REJECTED"))
    );
    if !agree {
        return fail(format!("expect {expect:?}, reject_reason and outcome {:?} do not agree", e.outcome));
    }
    let Some(sets) = v.get("trusted_keysets").and_then(Value::as_object) else {
        return fail("trusted_keysets is not an object");
    };
    let mut resolver = StaticResolver::default();
    for (role, keys) in sets {
        let Some(r) = Role::parse(role) else { return fail(format!("trusted_keysets: unknown role {role}")) };
        let Some(keys) = keys.as_array() else { return fail(format!("trusted_keysets.{role} is not an array")) };
        let mut jwks = Vec::new();
        for k in keys {
            jwks.push(parse_key(k).or_else(|err| fail(format!("trusted key for {role}: {err}")))?);
        }
        let set = KeySet::new(jwks).or_else(|err| fail(format!("key sets: {err}")))?;
        resolver.key_sets.insert(r, set);
    }
    resolver.expected_holder_jkt =
        Digest::from(nullable_string_of(v.get("expected_holder_jkt"), "expected_holder_jkt")?.unwrap_or_default());
    let typ = nullable_string_of(v.get("expected_typ"), "expected_typ")?.unwrap_or_default();
    let decode_as = nullable_string_of(v.get("decode_as"), "decode_as")?;
    let compact = string_of(v.get("compact"), "compact")?;

    let verifier = Verifier { keys: Some(&resolver), typ, ..Verifier::default() };
    let (mut reason, payload) = match verifier.verify(compact) {
        Ok(p) => (String::new(), Some(p.payload)),
        Err(err) => (err.reason.as_str().to_string(), None),
    };
    if let (Some(p), Some(t)) = (&payload, decode_as) {
        reason = decode_artifact(t, p)?;
    }
    if expect == "accept" {
        if !reason.is_empty() {
            return fail(format!("rejected ({reason}), want accept"));
        }
        let want = v.get("expected_payload").and_then(Value::as_str);
        if want.map(str::as_bytes) != payload.as_deref() {
            return fail(format!(
                "payload {:?} differs from expected_payload",
                payload.map(|p| String::from_utf8_lossy(&p).into_owned())
            ));
        }
        return Ok(());
    }
    if Some(reason.as_str()) != reject_reason {
        return fail(format!("reason {reason:?}, want {reject_reason:?}"));
    }
    Ok(())
}

/// The artifact layer after verification: a strict typed decode as the named
/// type under the artifact limits, and its pact_version.
fn decode_artifact(typ: &str, payload: &[u8]) -> Res<String> {
    if typ != "Evidence" {
        return fail(format!("decode_as {typ:?} is not handled"));
    }
    match strictjson::unmarshal::<Evidence>(payload, Limits::default().artifact_json()) {
        Ok(ev) if ev.pact_version == VERSION => Ok(String::new()),
        Ok(_) | Err(_) => Ok(PAYLOAD_SCHEMA.into()),
    }
}

fn rows<'a>(vs: &'a Value, e: &Entry, outcome: &str, what: &str) -> Res<Vec<&'a serde_json::Map<String, Value>>> {
    let ok = vs.as_array().is_some_and(|a| !a.is_empty()) && e.outcome.as_deref() == Some(outcome);
    if !ok {
        return fail(format!("no {what} vectors, or outcome {:?} is not {outcome}", e.outcome));
    }
    let mut out = Vec::new();
    for (i, v) in vs.as_array().into_iter().flatten().enumerate() {
        match v.as_object() {
            Some(m) if m.get("id").is_some_and(Value::is_string) => out.push(m),
            _ => return fail(format!("{what} vector {i} is malformed")),
        }
    }
    Ok(out)
}

fn id_of(v: &serde_json::Map<String, Value>) -> &str {
    v.get("id").and_then(Value::as_str).unwrap_or_default()
}

fn run_thumbprints(root: &Path, e: &Entry) -> Res {
    let vs = read_json(root, &e.path)?;
    for v in rows(&vs, e, "ACCEPTED", "thumbprint")? {
        let got = parse_key(&v["jwk"]).and_then(|k| jws::thumbprint(&k));
        let got = got.or_else(|err| fail(format!("{}: {err}", id_of(v))))?;
        if Some(got.as_str()) != v.get("expected_thumbprint").and_then(Value::as_str) {
            return fail(format!("{}: thumbprint {got}, want {:?}", id_of(v), v.get("expected_thumbprint")));
        }
    }
    Ok(())
}

fn run_jwk_rejects(root: &Path, e: &Entry) -> Res {
    let vs = read_json(root, &e.path)?;
    for v in rows(&vs, e, "REJECTED", "jwk-reject")? {
        let (got, detail) = match parse_key(&v["jwk"]).and_then(|k| jws::thumbprint(&k)) {
            Ok(_) => (String::new(), "accepted".to_string()),
            Err(err) => (err.reason.as_str().to_string(), err.to_string()),
        };
        if Some(got.as_str()) != v.get("reject_reason").and_then(Value::as_str) {
            return fail(format!("{}: reason {got:?} ({detail}), want {:?}", id_of(v), v.get("reject_reason")));
        }
    }
    Ok(())
}

/// The public JWK of the P-256 key whose private scalar is `d`.
fn derive(d: &[u8]) -> Res<JWK> {
    let k = SigningKey::from_slice(d).or_else(|err| fail(format!("d is not a P-256 scalar: {err}")))?;
    Ok(jws::public_jwk(k.verifying_key()))
}

fn d_of(v: &serde_json::Map<String, Value>) -> Res<Vec<u8>> {
    let d = v.get("d").and_then(Value::as_str).map(|d| base64_url(d, "d"));
    match d {
        Some(Ok(d)) if d.len() == 32 => Ok(d),
        _ => fail("d is not 32 octets of base64url"),
    }
}

fn run_key_derivations(root: &Path, e: &Entry) -> Res {
    let vs = read_json(root, &e.path)?;
    for v in rows(&vs, e, "ACCEPTED", "key")? {
        let id = id_of(v);
        let k = derive(&d_of(v).map_err(|f| prefix(f, id))?)?;
        let (wx, wy) = (v.get("expected_x").and_then(Value::as_str), v.get("expected_y").and_then(Value::as_str));
        if Some(k.x.as_str()) != wx || Some(k.y.as_str()) != wy {
            return fail(format!("{id}: derived x={} y={}, want x={wx:?} y={wy:?}", k.x, k.y));
        }
        let tp = jws::thumbprint(&k).or_else(|err| fail(format!("{id}: {err}")))?;
        if Some(tp.as_str()) != v.get("expected_thumbprint").and_then(Value::as_str) {
            return fail(format!("{id}: thumbprint {tp}, want {:?}", v.get("expected_thumbprint")));
        }
    }
    Ok(())
}

fn prefix(f: Fail, p: &str) -> Fail {
    match f {
        Fail::Fail(m) => Fail::Fail(format!("{p}: {m}")),
        other => other,
    }
}

/// The file of private test values, relative to the fixture directory.
pub const KEY_SCALARS_PATH: &str = "keys/test-private-scalars.json";

/// The holder_jkt of draft Appendix C: the thumbprint of the P-256 key of
/// scalar 1.
pub const APPENDIX_C_HOLDER_JKT: &str = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M";

fn is_p256(k: &serde_json::Map<String, Value>) -> bool {
    k.get("kty").and_then(Value::as_str) == Some("EC") && k.get("crv").and_then(Value::as_str) == Some("P-256")
}

fn jwk_path(k: &serde_json::Map<String, Value>) -> String {
    format!("keys/{}", k.get("public_jwk").and_then(Value::as_str).unwrap_or_default())
}

/// A key entry: one JWK file, or the scalars file itself.
pub fn run_key(root: &Path, e: &Entry) -> Res {
    let scalars = read_json(root, KEY_SCALARS_PATH)?;
    let records: Vec<&serde_json::Map<String, Value>> = match scalars.get("keys").and_then(Value::as_array) {
        Some(a) if a.iter().all(Value::is_object) => a.iter().filter_map(Value::as_object).collect(),
        _ => return fail(format!("{KEY_SCALARS_PATH}: not an object with a keys array of records")),
    };
    if e.path == KEY_SCALARS_PATH {
        let mut holder = false;
        for k in records.iter().filter(|k| is_p256(k)) {
            let role = k.get("role").and_then(Value::as_str).unwrap_or_default();
            check_key_record(root, k).map_err(|f| prefix(f, &format!("record of role {role}")))?;
            holder |= role == "holder";
        }
        if !holder {
            return fail("no P-256 record of role holder, the key of Appendix C holder_jkt");
        }
        return Ok(());
    }
    let head = read_json(root, &e.path)?;
    if head.get("kty").and_then(Value::as_str) == Some("OKP")
        && head.get("crv").and_then(Value::as_str) == Some("Ed25519")
    {
        return Err(Fail::Skip {
            reason: "out-of-scope",
            detail: "Ed25519 key: the algorithm is optional (draft section 7.2) and not implemented here".into(),
            spec_defects: Vec::new(),
        });
    }
    let Some(k) = records.iter().find(|r| jwk_path(r) == e.path) else {
        return fail(format!(
            "no record in {KEY_SCALARS_PATH} names {}",
            e.path.rsplit('/').next().unwrap_or_default()
        ));
    };
    check_key_record(root, k)
}

/// The decimal digits of a big-endian unsigned integer.
fn decimal(be: &[u8]) -> String {
    let mut n = be.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for b in n.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

/// Derives the public point of a P-256 record from its d, which must be its
/// scalar as 32 big-endian octets, and compares it with the record's JWK.
fn check_key_record(root: &Path, k: &serde_json::Map<String, Value>) -> Res {
    if !is_p256(k) {
        return fail(format!("kty {:?} crv {:?}, want EC P-256", k.get("kty"), k.get("crv")));
    }
    let d = d_of(k)?;
    let scalar =
        k.get("scalar").and_then(Value::as_str).filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()));
    let Some(scalar) = scalar.filter(|s| !s.starts_with('0')) else {
        return fail(format!("scalar {:?} is not a positive decimal integer", k.get("scalar")));
    };
    if decimal(&d) != scalar {
        return fail(format!("d is not scalar {scalar} as 32 big-endian octets"));
    }
    let want = derive(&d)?;
    let path = jwk_path(k);
    let got = jws::parse_jwk(&read_fixture(root, &path)?).or_else(|err| fail(format!("{path}: {err}")))?;
    if got.x != want.x || got.y != want.y {
        return fail(format!(
            "{path}: public point x={} y={}, but scalar {scalar} times G is x={} y={}",
            got.x, got.y, want.x, want.y
        ));
    }
    if k.get("role").and_then(Value::as_str) == Some("holder") {
        let tp = jws::thumbprint(&got).or_else(|err| fail(format!("{path}: {err}")))?;
        if tp != APPENDIX_C_HOLDER_JKT {
            return fail(format!("{path}: holder thumbprint {tp}, want Appendix C holder_jkt {APPENDIX_C_HOLDER_JKT}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn decimal_of_big_endian() {
        assert_eq!(super::decimal(&[0; 32]), "0");
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(super::decimal(&one), "1");
        assert_eq!(super::decimal(&[1, 0]), "256");
        assert_eq!(super::decimal(&[0xff; 8]), "18446744073709551615");
    }
}
