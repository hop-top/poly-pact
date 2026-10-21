//! core::jws: the profile checks, signing, keys and the draft's Appendix C,
//! after go/core/jws/jws_test.go, jwk_test.go and appendix_c_test.go.

mod support;

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hop_top_pact::core::Digest;
use hop_top_pact::core::jws::{
    self, Algorithms, Header, JWK, KeyRequest, KeyResolver, KeySet, Reason, ResolverError, Role, StaticResolver,
    TYP_EVIDENCE, TYP_PRESENTATION, TYP_REQUIREMENTS, Verifier,
};
use p256::ecdsa::SigningKey;

const HOLDER_JKT: &str = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M";

fn key(scalar: u8) -> SigningKey {
    let mut d = [0u8; 32];
    d[31] = scalar;
    SigningKey::from_slice(&d).unwrap()
}

fn with_kid(mut k: JWK, kid: &str) -> JWK {
    k.kid = kid.into();
    k
}

fn issuer_resolver(k: &SigningKey) -> StaticResolver {
    let set = KeySet::new([with_kid(jws::public_jwk(k.verifying_key()), "issuer-1")]).unwrap();
    StaticResolver { key_sets: HashMap::from([(Role::Issuer, set)]), ..Default::default() }
}

fn reason(r: Result<jws::ParsedJWS, jws::Error>) -> Reason {
    match r {
        Ok(p) => panic!("verified: {:?}", String::from_utf8_lossy(&p.payload)),
        Err(e) => e.reason,
    }
}

fn compact(header: &str, payload: &str, sig: &[u8]) -> String {
    format!("{}.{}.{}", B64.encode(header), B64.encode(payload), B64.encode(sig))
}

#[test]
fn sign_verify_round_trip() {
    let k = key(2);
    let payload = br#"{"pact_version":"0.1","jti":"e-1"}"#;
    let c = jws::sign(&Header { typ: TYP_EVIDENCE.into(), kid: "issuer-1".into(), ..Default::default() }, payload, &k)
        .unwrap();
    let header = B64.decode(c.split('.').next().unwrap()).unwrap();
    assert_eq!(header, br#"{"alg":"ES256","typ":"pact-evidence+jwt","kid":"issuer-1"}"#);
    let p = jws::verify(&c, &issuer_resolver(&k)).unwrap();
    assert_eq!((p.role, p.payload.as_slice(), p.header.kid.as_str()), (Role::Issuer, &payload[..], "issuer-1"));
    assert_eq!(p.key_thumbprint, jws::thumbprint(&p.key).unwrap());
    assert_eq!(p.signing_input, c[..c.rfind('.').unwrap()]);
    let again =
        jws::sign(&Header { typ: TYP_EVIDENCE.into(), kid: "issuer-1".into(), ..Default::default() }, payload, &k)
            .unwrap();
    assert_ne!(c, again, "each signature takes a fresh random nonce");
    jws::verify(&again, &issuer_resolver(&k)).unwrap();
    assert_eq!(c[..c.rfind('.').unwrap()], again[..again.rfind('.').unwrap()], "same signing input");
}

#[test]
fn sign_writes_low_s() {
    let half_n = hex(b"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
    for i in 0..64u8 {
        let payload = format!(r#"{{"n":{i}}}"#);
        let c = jws::sign(
            &Header { typ: TYP_EVIDENCE.into(), kid: "k".into(), ..Default::default() },
            payload.as_bytes(),
            &key(3),
        )
        .unwrap();
        let sig = B64.decode(c.rsplit('.').next().unwrap()).unwrap();
        assert!(sig[32..] <= half_n[..], "high S in {c}");
    }
}

fn hex(s: &[u8]) -> Vec<u8> {
    s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}

#[test]
fn verify_accepts_high_s() {
    let n = hex(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let k = key(2);
    let c = jws::sign(&Header { typ: TYP_EVIDENCE.into(), kid: "issuer-1".into(), ..Default::default() }, b"{}", &k)
        .unwrap();
    let mut sig = B64.decode(c.rsplit('.').next().unwrap()).unwrap();
    // s' = n - s, big-endian subtraction.
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = n[i] as i16 - sig[32 + i] as i16 - borrow;
        borrow = i16::from(v < 0);
        sig[32 + i] = v.rem_euclid(256) as u8;
    }
    let twin = format!("{}.{}", &c[..c.rfind('.').unwrap()], B64.encode(&sig));
    assert_ne!(twin, c);
    jws::verify(&twin, &issuer_resolver(&k)).expect("high-S twin verifies");
}

#[test]
fn sign_holder_header() {
    let k = key(1);
    let payload = br#"{"pact_version":"0.1"}"#;
    let c = jws::sign(&Header { typ: TYP_PRESENTATION.into(), ..Default::default() }, payload, &k).unwrap();
    let r = StaticResolver { expected_holder_jkt: Digest::from(HOLDER_JKT), ..Default::default() };
    let p = jws::verify(&c, &r).unwrap();
    assert_eq!((p.role, p.key_thumbprint.as_str()), (Role::Holder, HOLDER_JKT));
    let header = String::from_utf8(p.raw_header).unwrap();
    assert!(
        header.starts_with(r#"{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"#),
        "{header}"
    );
    let wrong = StaticResolver { expected_holder_jkt: Digest::from("A".repeat(43)), ..Default::default() };
    assert_eq!(reason(jws::verify(&c, &wrong)), Reason::HolderJKTMismatch);
    assert_eq!(reason(jws::verify(&c, &StaticResolver::default())), Reason::KeyUnavailable);
}

#[test]
fn sign_rejects() {
    let k = key(2);
    let other = jws::public_jwk(key(3).verifying_key());
    let cases = [
        (
            Header { alg: "RS256".into(), typ: TYP_EVIDENCE.into(), kid: "k".into(), jwk: None },
            &b"{}"[..],
            Reason::AlgUnsupported,
        ),
        (Header { typ: "JWT".into(), kid: "k".into(), ..Default::default() }, b"{}", Reason::TypUnsupported),
        (Header { typ: TYP_EVIDENCE.into(), ..Default::default() }, b"{}", Reason::KidMissing),
        (
            Header { typ: TYP_EVIDENCE.into(), kid: "k".into(), jwk: Some(other.clone()), ..Default::default() },
            b"{}",
            Reason::JWKUnexpected,
        ),
        (Header { typ: TYP_PRESENTATION.into(), jwk: Some(other), ..Default::default() }, b"{}", Reason::SigningKey),
        (Header { typ: TYP_EVIDENCE.into(), kid: "k".into(), ..Default::default() }, b"[]", Reason::PayloadJSON),
        (
            Header { typ: TYP_EVIDENCE.into(), kid: "k".into(), ..Default::default() },
            br#"{"a":1,"a":2}"#,
            Reason::PayloadJSON,
        ),
    ];
    for (h, payload, want) in cases {
        let e = jws::sign(&h, payload, &k).unwrap_err();
        assert_eq!(e.reason, want, "{h:?}: {e}");
    }
}

#[test]
fn verify_rejects_compact_form_and_headers() {
    let k = key(2);
    let r = issuer_resolver(&k);
    let sig = [1u8; 64];
    let ok_header = r#"{"alg":"ES256","typ":"pact-evidence+jwt","kid":"issuer-1"}"#;
    let cases: Vec<(String, Reason)> = vec![
        ("a.b".into(), Reason::CompactForm),
        ("a.b.c.d".into(), Reason::CompactForm),
        (".e30.AA".into(), Reason::CompactForm),
        ("e30=.e30.AA".into(), Reason::Base64URL),
        (compact("[]", "{}", &sig), Reason::HeaderJSON),
        (compact(r#"{"alg":"ES256","alg":"ES256"}"#, "{}", &sig), Reason::HeaderJSON),
        (compact(r#"{"alg":"ES256","typ":"pact-evidence+jwt","kid":7}"#, "{}", &sig), Reason::HeaderJSON),
        (compact(r#"{"alg":"ES256","crit":["exp"]}"#, "{}", &sig), Reason::HeaderCrit),
        (compact(r#"{"alg":"ES256","b64":false}"#, "{}", &sig), Reason::HeaderB64),
        (compact(r#"{"alg":"ES256","jku":"https://x"}"#, "{}", &sig), Reason::HeaderJKU),
        (compact(r#"{"alg":"ES256","x5u":"https://x"}"#, "{}", &sig), Reason::HeaderX5U),
        (compact(r#"{"alg":"ES256","x5c":[]}"#, "{}", &sig), Reason::HeaderX5C),
        (compact(r#"{"alg":"none","typ":"pact-evidence+jwt"}"#, "{}", &sig), Reason::AlgUnsupported),
        (compact(r#"{"alg":"Ed25519","typ":"pact-evidence+jwt"}"#, "{}", &sig), Reason::AlgUnsupported),
        (compact(r#"{"typ":"pact-evidence+jwt"}"#, "{}", &sig), Reason::AlgUnsupported),
        (compact(r#"{"alg":"ES256","typ":"JWT"}"#, "{}", &sig), Reason::TypUnsupported),
        (compact(r#"{"alg":"ES256","typ":"pact-evidence+jwt"}"#, "{}", &sig), Reason::KidMissing),
        (compact(r#"{"alg":"ES256","typ":"pact-presentation+jwt"}"#, "{}", &sig), Reason::JWKMissing),
        (compact(ok_header, "[]", &sig), Reason::PayloadJSON),
        (format!("{}..{}", B64.encode(ok_header), B64.encode(sig)), Reason::PayloadDetached),
        (compact(ok_header, "{}", &sig[..63]), Reason::SignatureLength),
        (compact(ok_header, "{}", &[0u8; 65]), Reason::SignatureLength),
        (compact(ok_header, "{}", &sig), Reason::SignatureInvalid),
        (compact(ok_header, "{}", &[0u8; 64]), Reason::SignatureInvalid),
        (compact(&ok_header.replace("issuer-1", "issuer-2"), "{}", &sig), Reason::KidUnknown),
    ];
    for (c, want) in cases {
        assert_eq!(reason(jws::verify(&c, &r)), want, "{c}");
    }
    let embedded = format!(
        r#"{{"alg":"ES256","typ":"pact-evidence+jwt","kid":"issuer-1","jwk":{}}}"#,
        serde_json::to_string(&jws::public_jwk(k.verifying_key())).unwrap()
    );
    assert_eq!(reason(jws::verify(&compact(&embedded, "{}", &sig), &r)), Reason::JWKUnexpected);
}

#[test]
fn verifier_options() {
    let k = key(2);
    let r = issuer_resolver(&k);
    let c = jws::sign(
        &Header { typ: TYP_EVIDENCE.into(), kid: "issuer-1".into(), ..Default::default() },
        br#"{"a":[[1]]}"#,
        &k,
    )
    .unwrap();
    let v = Verifier { keys: Some(&r), typ: TYP_REQUIREMENTS, ..Default::default() };
    assert_eq!(reason(v.verify(&c)), Reason::TypMismatch);
    let v = Verifier { keys: Some(&r), max_compact_bytes: c.len() - 1, ..Default::default() };
    assert_eq!(reason(v.verify(&c)), Reason::CompactSize);
    let v = Verifier {
        keys: Some(&r),
        limits: hop_top_pact::core::strictjson::Limits { max_bytes: 0, max_depth: 2 },
        ..Default::default()
    };
    assert_eq!(reason(v.verify(&c)), Reason::PayloadJSON);
    assert_eq!(reason(Verifier::default().verify(&c)), Reason::KeyUnavailable);
    let algs = Algorithms::new(["Ed25519"]);
    let v = Verifier { keys: Some(&r), algorithms: Some(&algs), ..Default::default() };
    assert_eq!(reason(v.verify(&c)), Reason::AlgUnsupported, "ES256 is not listed");
}

struct Failing;

impl KeyResolver for Failing {
    fn trusted_keys(&self, _: &KeyRequest<'_>) -> Result<Option<&KeySet>, ResolverError> {
        Err("store down".into())
    }
    fn holder_jkt(&self, req: &KeyRequest<'_>) -> Result<Digest, ResolverError> {
        assert_eq!(req.role, Role::Holder);
        Err("store down".into())
    }
}

#[test]
fn resolver_failures() {
    let k = key(2);
    let c = jws::sign(&Header { typ: TYP_EVIDENCE.into(), kid: "issuer-1".into(), ..Default::default() }, b"{}", &k)
        .unwrap();
    let e = jws::verify(&c, &Failing).unwrap_err();
    assert_eq!(e.reason, Reason::KeyUnavailable);
    assert!(e.to_string().contains("store down"), "{e}");
    assert_eq!(jws::reason_of(&e), Some(Reason::KeyUnavailable));
    let h = jws::sign(&Header { typ: TYP_PRESENTATION.into(), ..Default::default() }, b"{}", &key(1)).unwrap();
    assert_eq!(reason(jws::verify(&h, &Failing)), Reason::KeyUnavailable);
}

#[test]
fn key_set() {
    let a = jws::public_jwk(key(2).verifying_key());
    assert_eq!(KeySet::new([a.clone()]).unwrap_err().reason, Reason::KidMissing);
    assert_eq!(
        KeySet::new([with_kid(a.clone(), "x"), with_kid(a.clone(), "x")]).unwrap_err().reason,
        Reason::KidDuplicate
    );
    let mut bad = with_kid(a.clone(), "y");
    bad.use_ = "enc".into();
    assert_eq!(KeySet::new([bad]).unwrap_err().reason, Reason::JWKUsage);
    let s = KeySet::new([with_kid(a.clone(), "x")]).unwrap();
    assert_eq!(s.lookup("x"), Some(&with_kid(a, "x")));
    assert_eq!((s.lookup(""), s.lookup("z"), s.len()), (None, None, 1));
}

#[test]
fn parse_jwk_rules() {
    let good = jws::public_jwk(key(2).verifying_key());
    let text = |extra: &str| format!(r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"{extra}}}"#, good.x, good.y);
    assert_eq!(jws::parse_jwk(text("").as_bytes()).unwrap(), good);
    assert!(jws::parse_jwk(text(r#","key_ops":["verify"],"ext":true"#).as_bytes()).is_ok());
    for (extra, want) in [
        (r#","d":"AA""#, Reason::JWKPrivate),
        (r#","alg":"RS256""#, Reason::JWKUsage),
        (r#","use":"enc""#, Reason::JWKUsage),
        (r#","key_ops":["sign"]"#, Reason::JWKUsage),
        (r#","key_ops":["verify","verify"]"#, Reason::JWKInvalid),
        (r#","key_ops":"verify""#, Reason::JWKInvalid),
        (r#","kid":1"#, Reason::JWKInvalid),
        (r#","kty":"EC""#, Reason::JWKInvalid),
    ] {
        assert_eq!(jws::parse_jwk(text(extra).as_bytes()).unwrap_err().reason, want, "{extra}");
    }
    let okp = br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    assert_eq!(jws::parse_jwk(okp).unwrap_err().reason, Reason::JWKCurve);
    assert_eq!(Algorithms::new(["ES256", "Ed25519"]).parse_jwk(okp).unwrap_err().reason, Reason::JWKCurve);
}

#[test]
fn public_jwk_keeps_leading_zeros() {
    for s in 1..=200u8 {
        let j = jws::public_jwk(key(s).verifying_key());
        assert_eq!((j.x.len(), j.y.len()), (43, 43));
        assert_eq!(jws::parse_jwk(serde_json::to_string(&j).unwrap().as_bytes()).unwrap(), j);
    }
}

#[test]
fn reasons_are_the_vector_names() {
    assert_eq!(Reason::ALL.len(), 29);
    assert_eq!(Reason::Base64URL.as_str(), "base64url");
    assert_eq!(Reason::HolderJKTMismatch.to_string(), "jws: holder-jkt-mismatch");
    assert_eq!(jws::typs().len(), 9);
    assert_eq!(jws::typ_role("pact-learning-event+jwt"), Some(Role::LearningController));
    assert_eq!(jws::typ_role("application/pact-evidence+jwt"), None);
    assert_eq!(jws::DEFAULT_MAX_COMPACT_BYTES, 360448);
}

#[test]
fn appendix_c() {
    let Some(fx) = support::fixtures() else { return };
    let holder = jws::parse_jwk(&support::read(&fx.join("keys/holder.jwk.json"))).unwrap();
    assert_eq!(jws::thumbprint(&holder).unwrap().as_str(), HOLDER_JKT);
    let issuer = jws::parse_jwk(&support::read(&fx.join("keys/issuer.jwk.json"))).unwrap();
    let compact = String::from_utf8(support::read(&fx.join("parse/appendix-c-wrong-version.jws"))).unwrap();
    let r = StaticResolver {
        key_sets: HashMap::from([(Role::Issuer, KeySet::new([issuer]).unwrap())]),
        ..Default::default()
    };
    let p = jws::verify(compact.trim_end(), &r).unwrap();
    assert_eq!((p.header.typ.as_str(), p.header.kid.as_str()), (TYP_EVIDENCE, "test-issuer-key-1"));
    let ev: hop_top_pact::core::Evidence =
        hop_top_pact::core::strictjson::unmarshal(&p.payload, Default::default()).unwrap();
    assert_eq!(ev.pact_version, "0.2", "the Appendix C example carries the wrong version");
    // Scalar 1 is the holder key of the fixtures.
    assert_eq!(jws::public_jwk(key(1).verifying_key()).x, holder.x);
}
