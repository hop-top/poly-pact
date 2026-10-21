//! core::jcs against the shared vectors and the RFC 8785 samples, after
//! go/core/jcs/jcs_test.go and vectors_test.go.

mod support;

use hop_top_pact::core::jcs::{self, Error};
use hop_top_pact::core::strictjson::Kind;

fn canon(s: &str) -> String {
    String::from_utf8(jcs::canonicalize(s.as_bytes()).unwrap_or_else(|e| panic!("{s}: {e}"))).unwrap()
}

#[test]
fn canonicalize_samples() {
    for (input, want) in [
        (r#"{"b":2,"a":1}"#, r#"{"a":1,"b":2}"#),
        (" [ 1 , 2.50 , -0 , 1E2 , \"\\u00e9\\n\" ] ", r#"[1,2.5,0,100,"é\n"]"#),
        (r#"{"€":1,"😀":2,"דּ":3}"#, "{\"\u{20ac}\":1,\"\u{1f600}\":2,\"\u{fb33}\":3}"),
        (r#""\u007f \u001f\/""#, "\"\u{7f}\u{2028}\\u001f/\""),
        ("1e30", "1e+30"),
        ("null", "null"),
        (r#"{"a":{"d":1,"c":[{"z":1,"y":2}]}}"#, r#"{"a":{"c":[{"y":2,"z":1}],"d":1}}"#),
    ] {
        assert_eq!(canon(input), want, "{input}");
    }
}

#[test]
fn canonicalize_rejects() {
    for (input, kind) in [
        (r#"{"a":1,"a":2}"#, Kind::DuplicateKey),
        ("9007199254740992", Kind::Integer),
        ("NaN", Kind::NonFinite),
        ("1e999", Kind::NonFinite),
        (r#""\ud800""#, Kind::LoneSurrogate),
        ("[1] [2]", Kind::TrailingData),
        ("", Kind::Syntax),
    ] {
        match jcs::canonicalize(input.as_bytes()) {
            Err(Error::Json(e)) => assert_eq!(e.kind, kind, "{input}: {e}"),
            other => panic!("{input}: {other:?}"),
        }
    }
    let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
    assert!(matches!(jcs::canonicalize(deep.as_bytes()), Err(Error::Json(e)) if e.kind == Kind::Depth));
    let ok = format!("{}{}", "[".repeat(16), "]".repeat(16));
    assert_eq!(canon(&ok), ok);
}

#[test]
fn canonicalize_value_matches_text() {
    let v: serde_json::Value = serde_json::from_str(r#"{"b":[1,2.5,{"y":null,"x":true}],"a":"é"}"#).unwrap();
    let got = String::from_utf8(jcs::canonicalize_value(&v).unwrap()).unwrap();
    assert_eq!(got, canon(&v.to_string()));
    let big: serde_json::Value = serde_json::from_str("9007199254740993").unwrap();
    assert!(matches!(jcs::canonicalize_value(&big), Err(Error::Range(_))));
}

#[test]
fn canonicalize_sorts_many_keys() {
    let mut keys: Vec<String> = (0..300).map(|i| format!("k{:03}", (i * 7919) % 300)).collect();
    let input = format!("{{{}}}", keys.iter().map(|k| format!("\"{k}\":0")).collect::<Vec<_>>().join(","));
    keys.sort();
    let want = format!("{{{}}}", keys.iter().map(|k| format!("\"{k}\":0")).collect::<Vec<_>>().join(","));
    assert_eq!(canon(&input), want);
}

#[test]
fn shared_vectors() {
    let Some(fx) = support::fixtures() else { return };
    let entries = support::entries(&fx, "vectors/jcs/");
    assert_eq!(entries.len(), 7, "vectors/jcs entries");
    for e in entries {
        let path = e["path"].as_str().unwrap();
        let expected = e["expected"].as_str().unwrap();
        if path == expected {
            let rows = support::read_json(&fx.join(path));
            let rows = rows.as_array().unwrap();
            assert_eq!(rows.len(), 10000);
            for row in rows {
                let hex = row["ieee754_hex"].as_str().unwrap();
                let f = f64::from_bits(u64::from_str_radix(hex, 16).unwrap());
                let literal = format!("{f:e}");
                let got = String::from_utf8(jcs::canonicalize(literal.as_bytes()).unwrap()).unwrap();
                assert_eq!(got, row["expected"].as_str().unwrap(), "{hex}");
            }
            continue;
        }
        let input = support::read(&fx.join(path));
        let want = support::read(&fx.join(expected));
        let got = jcs::canonicalize(&input).unwrap_or_else(|err| panic!("{path}: {err}"));
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&want), "{path}");
        assert_eq!(jcs::canonicalize(&want).unwrap(), want, "{expected} is canonical");
    }
}

#[test]
fn agrees_with_the_oracle_on_random_documents() {
    let mut x: u64 = 0x2545f4914f6cdd1d;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..2000 {
        let mut members = Vec::new();
        for j in 0..(next() % 8) {
            let f = f64::from_bits(next());
            let v = if f.is_finite() { serde_json::json!(f) } else { serde_json::json!(j) };
            let key: String =
                (0..(next() % 4 + 1)).map(|_| char::from_u32((next() % 0x2fff) as u32 + 0x20).unwrap_or('x')).collect();
            members.push((key, v));
        }
        let doc = serde_json::Value::Object(members.into_iter().collect());
        let text = serde_json::to_string(&doc).unwrap();
        let ours = jcs::canonicalize(text.as_bytes()).unwrap();
        let oracle = serde_json_canonicalizer::to_vec(&doc).unwrap();
        assert_eq!(String::from_utf8_lossy(&ours), String::from_utf8_lossy(&oracle), "{text}");
    }
}
