//! Unit tests of core::strictjson, after go/core/strictjson/strictjson_test.go.

use std::collections::BTreeMap;

use hop_top_pact::core::strictjson::{self, Error, Kind, Limits};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct Inner {
    n: i64,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct Sample {
    name: String,
    count: i64,
    ratio: f64,
    opt: Option<String>,
    opt_count: Option<i64>,
    inner: Option<Inner>,
    items: Vec<Inner>,
    raw: Option<serde_json::Value>,
    headers: BTreeMap<String, String>,
    extensions: BTreeMap<String, serde_json::Value>,
}

fn decode(input: &str, lim: Limits) -> Result<Sample, Error> {
    strictjson::unmarshal(input.as_bytes(), lim)
}

fn deep_arrays(n: usize) -> String {
    format!(r#"{{"extensions":{{"a":{}{}}}}}"#, "[".repeat(n - 2), "]".repeat(n - 2))
}

fn deep_objects(n: usize) -> String {
    format!(r#"{{"extensions":{}{{}}{}}}"#, r#"{"a":"#.repeat(n - 2), "}".repeat(n - 2))
}

#[test]
fn decode_valid() {
    let input = concat!(
        r#"{"name":"a","count":9007199254740991,"ratio":1.5e3,"opt":null,"opt_count":7,"#,
        r#""inner":{"n":0},"items":[{"n":1},{"n":2}],"raw":{"x":[1,2,{"y":null}]},"#,
        r#""headers":{"x-a":"1"},"extensions":{"k":{"deep":[true,false,null]}}}"#
    );
    let got = decode(input, Limits::default()).expect("decode");
    assert_eq!((got.name.as_str(), got.count, got.ratio), ("a", 9007199254740991, 1500.0));
    assert_eq!((got.opt, got.opt_count), (None, Some(7)));
    assert_eq!(got.inner, Some(Inner { n: 0 }));
    assert_eq!(got.items, vec![Inner { n: 1 }, Inner { n: 2 }]);
    assert_eq!(got.raw.unwrap().to_string(), r#"{"x":[1,2,{"y":null}]}"#);
    assert_eq!(got.extensions["k"].to_string(), r#"{"deep":[true,false,null]}"#);
}

#[test]
fn decode_rejects() {
    let d = Limits::default();
    let long = format!(r#"{{"name":"{}"}}"#, "a".repeat(64));
    let cases: Vec<(&str, String, Limits, Kind)> = vec![
        ("duplicate top level", r#"{"name":"a","name":"b"}"#.into(), d, Kind::DuplicateKey),
        ("duplicate same value", r#"{"name":"a","name":"a"}"#.into(), d, Kind::DuplicateKey),
        ("duplicate nested struct", r#"{"inner":{"n":1,"n":2}}"#.into(), d, Kind::DuplicateKey),
        ("duplicate in open map", r#"{"extensions":{"a":{"b":1,"b":2}}}"#.into(), d, Kind::DuplicateKey),
        ("duplicate in headers", r#"{"headers":{"x":"1","x":"2"}}"#.into(), d, Kind::DuplicateKey),
        ("duplicate in raw", r#"{"raw":{"a":1,"a":2}}"#.into(), d, Kind::DuplicateKey),
        ("duplicate in array element", r#"{"items":[{"n":1},{"n":1,"n":1}]}"#.into(), d, Kind::DuplicateKey),
        ("duplicate after unescape", r#"{"name":"a","name":"b"}"#.into(), d, Kind::DuplicateKey),
        ("unknown field", r#"{"name":"a","bogus":1}"#.into(), d, Kind::UnknownField),
        ("unknown nested field", r#"{"inner":{"n":1,"m":2}}"#.into(), d, Kind::UnknownField),
        ("unknown field in array element", r#"{"items":[{"n":1,"m":2}]}"#.into(), d, Kind::UnknownField),
        ("case variant is unknown", r#"{"Name":"a"}"#.into(), d, Kind::UnknownField),
        ("case variant beside real field", r#"{"name":"a","NAME":"b"}"#.into(), d, Kind::UnknownField),
        ("depth 17 objects", deep_objects(17), d, Kind::Depth),
        ("depth 17 arrays", deep_arrays(17), d, Kind::Depth),
        ("custom depth", r#"{"raw":[[1]]}"#.into(), Limits { max_depth: 2, ..d }, Kind::Depth),
        ("1e999", r#"{"ratio":1e999}"#.into(), d, Kind::NonFinite),
        ("-1e999 in raw", r#"{"raw":-1e999}"#.into(), d, Kind::NonFinite),
        ("NaN", r#"{"raw":NaN}"#.into(), d, Kind::NonFinite),
        ("Infinity", r#"{"raw":Infinity}"#.into(), d, Kind::NonFinite),
        ("-Infinity", r#"{"raw":-Infinity}"#.into(), d, Kind::NonFinite),
        ("lone high surrogate", r#"{"name":"\ud800"}"#.into(), d, Kind::LoneSurrogate),
        ("lone low surrogate", r#"{"name":"\udc00"}"#.into(), d, Kind::LoneSurrogate),
        ("high then bmp", r#"{"name":"\ud800A"}"#.into(), d, Kind::LoneSurrogate),
        ("reversed pair", r#"{"name":"\udc00\ud800"}"#.into(), d, Kind::LoneSurrogate),
        ("surrogate in key", r#"{"extensions":{"\ud800":1}}"#.into(), d, Kind::LoneSurrogate),
        ("escaped backslash before a surrogate escape", r#"{"name":"\\\ud800"}"#.into(), d, Kind::LoneSurrogate),
        ("integer 2^53", r#"{"raw":9007199254740992}"#.into(), d, Kind::Integer),
        ("integer -2^53", r#"{"raw":-9007199254740992}"#.into(), d, Kind::Integer),
        ("integer huge", r#"{"raw":123456789012345678901234567890}"#.into(), d, Kind::Integer),
        ("typed integer overflow", r#"{"count":9007199254740992}"#.into(), d, Kind::Integer),
        ("typed integer negative", r#"{"count":-1}"#.into(), d, Kind::Integer),
        ("typed integer fraction", r#"{"count":1.5}"#.into(), d, Kind::Integer),
        ("typed integer exponent form", r#"{"count":1e3}"#.into(), d, Kind::Integer),
        ("typed integer 1.0", r#"{"count":1.0}"#.into(), d, Kind::Integer),
        ("nullable integer negative", r#"{"opt_count":-5}"#.into(), d, Kind::Integer),
        ("trailing text", r#"{"name":"a"} x"#.into(), d, Kind::TrailingData),
        ("trailing value", r#"{"name":"a"}{}"#.into(), d, Kind::TrailingData),
        ("trailing brace", r#"{"name":"a"}}"#.into(), d, Kind::TrailingData),
        ("empty input", "".into(), d, Kind::Syntax),
        ("whitespace only", " \n".into(), d, Kind::Syntax),
        ("truncated", r#"{"name":"a""#.into(), d, Kind::Syntax),
        ("bom", "\u{feff}{}".into(), d, Kind::Syntax),
        ("leading zero", r#"{"raw":01}"#.into(), d, Kind::Syntax),
        ("single quotes", "{'name':'a'}".into(), d, Kind::Syntax),
        ("trailing comma", r#"{"name":"a",}"#.into(), d, Kind::Syntax),
        ("raw control character", "{\"name\":\"a\u{1}\"}".into(), d, Kind::Syntax),
        ("bad escape", r#"{"name":"\x"}"#.into(), d, Kind::Syntax),
        ("too large", long, Limits { max_bytes: 32, ..d }, Kind::Size),
        ("null for string", r#"{"name":null}"#.into(), d, Kind::Null),
        ("null for integer", r#"{"count":null}"#.into(), d, Kind::Null),
        ("null for slice", r#"{"items":null}"#.into(), d, Kind::Null),
        ("null for map", r#"{"headers":null}"#.into(), d, Kind::Null),
        ("null document", "null".into(), d, Kind::Null),
        ("type mismatch", r#"{"name":5}"#.into(), d, Kind::Type),
        ("type mismatch object", r#"{"name":{}}"#.into(), d, Kind::Type),
    ];
    for (name, input, lim, want) in cases {
        match decode(&input, lim) {
            Ok(v) => panic!("{name}: decode({input:?}) = {v:?}, want {want:?}"),
            Err(e) => assert_eq!(e.kind, want, "{name}: decode({input:?}) = {e}"),
        }
    }
}

#[test]
fn decode_rejects_invalid_utf8() {
    for input in [&b"{\"name\":\"\xff\"}"[..], b"{\"na\xc0me\":1}", b"\xed\xa0\x80", b"\xe2\x82"] {
        let e = strictjson::unmarshal::<Sample>(input, Limits::default()).unwrap_err();
        assert_eq!(e.kind, Kind::InvalidUtf8, "{input:?}: {e}");
    }
}

#[test]
fn decode_accepts() {
    let d = Limits::default();
    let cases: Vec<(&str, String, Limits)> = vec![
        ("depth 16 objects", deep_objects(16), d),
        ("depth 16 arrays", deep_arrays(16), d),
        ("max safe integer", r#"{"count":9007199254740991,"raw":9007199254740991}"#.into(), d),
        ("negative max safe in raw", r#"{"raw":-9007199254740991}"#.into(), d),
        ("zero count", r#"{"count":0}"#.into(), d),
        ("negative zero in raw", r#"{"raw":-0}"#.into(), d),
        ("largest finite float", r#"{"ratio":1.7976931348623157e308}"#.into(), d),
        ("negative float", r#"{"ratio":-12.5}"#.into(), d),
        ("float underflow is finite", r#"{"ratio":1e-999}"#.into(), d),
        ("surrogate pair", r#"{"name":"😀"}"#.into(), d),
        ("escaped backslash then u", r#"{"name":"\\ud800"}"#.into(), d),
        ("replacement char literal", "{\"name\":\"\u{fffd}\"}".into(), d),
        ("case distinct keys in open map", r#"{"extensions":{"a":1,"A":2}}"#.into(), d),
        ("same key in sibling objects", r#"{"items":[{"n":1},{"n":2}],"inner":{"n":3}}"#.into(), d),
        ("trailing whitespace", "{\"name\":\"a\"}\n \t\r\n".into(), d),
        ("leading whitespace", " \n{\"name\":\"a\"}".into(), d),
        ("null in raw", r#"{"raw":null}"#.into(), d),
        ("null in nullable", r#"{"opt":null,"opt_count":null}"#.into(), d),
        ("null in nullable struct", r#"{"inner":null}"#.into(), d),
        ("custom depth", r#"{"raw":[[1]]}"#.into(), Limits { max_depth: 3, ..d }),
        ("exact size", r#"{"name":"a"}"#.into(), Limits { max_bytes: 12, ..d }),
        ("empty object", "{}".into(), d),
    ];
    for (name, input, lim) in cases {
        if let Err(e) = decode(&input, lim) {
            panic!("{name}: decode({input:?}): {e}");
        }
    }
}

#[test]
fn decode_free_form_target() {
    strictjson::parse(br#"{"a":[1,{"b":null}],"A":2}"#, Limits::default()).expect("free-form");
    let e = strictjson::parse(br#"{"a":1,"a":2}"#, Limits::default()).unwrap_err();
    assert_eq!(e.kind, Kind::DuplicateKey);
    let e =
        strictjson::unmarshal::<BTreeMap<String, serde_json::Value>>(br#"{"x":9007199254740992}"#, Limits::default())
            .unwrap_err();
    assert_eq!(e.kind, Kind::Integer);
}

#[test]
fn free_form_numbers_keep_their_values() {
    let v = strictjson::parse(br#"[9007199254740991,-9007199254740991,0.1,1e-7,-0]"#, Limits::default()).unwrap();
    assert_eq!(v.to_string(), "[9007199254740991,-9007199254740991,0.1,1e-7,0]");
}

#[test]
fn error_names_path_and_offset() {
    let e = decode(r#"{"items":[{"n":1},{"n":2,"bad":1}]}"#, Limits::default()).unwrap_err();
    assert_eq!((e.kind, e.path.as_str()), (Kind::UnknownField, "/items/1/bad"));
    let e = decode(r#"{"extensions":{"a/b~c":{"x":1,"x":2}}}"#, Limits::default()).unwrap_err();
    assert_eq!((e.kind, e.path.as_str()), (Kind::DuplicateKey, "/extensions/a~1b~0c/x"));
    assert!(e.offset > 0 && e.offset < 40, "offset {}", e.offset);
    let e = decode(r#"{"count":-1}"#, Limits::default()).unwrap_err();
    assert_eq!((e.kind, e.path.as_str(), e.offset), (Kind::Integer, "/count", 9));
    let e = decode(r#"{"name":"a","name":"b"}"#, Limits::default()).unwrap_err();
    assert!(e.to_string().starts_with("strictjson: duplicate member name: \"name\" at /name (offset "), "{e}");
}

#[test]
fn depth_is_checked_before_the_value_is_typed() {
    let e = decode(&format!(r#"{{"name":{}{}}}"#, "[".repeat(40), "]".repeat(40)), Limits::default()).unwrap_err();
    assert_eq!(e.kind, Kind::Depth);
}

#[test]
fn decode_reads_at_most_the_limit() {
    let input = format!(r#"{{"name":"{}"}}"#, "a".repeat(64));
    match strictjson::decode::<Sample, _>(input.as_bytes(), Limits { max_bytes: 32, max_depth: 0 }) {
        Err(strictjson::DecodeError::Json(e)) => assert_eq!(e.kind, Kind::Size),
        other => panic!("decode: {other:?}"),
    }
    let ok: Sample = strictjson::decode(&br#"{"name":"a"}"#[..], Limits::default()).unwrap();
    assert_eq!(ok.name, "a");
}

#[test]
fn limits_default_when_zero() {
    let r = Limits::default().resolved();
    assert_eq!((r.max_bytes, r.max_depth), (strictjson::DEFAULT_MAX_BYTES, strictjson::DEFAULT_MAX_DEPTH));
    assert_eq!((strictjson::DEFAULT_MAX_BYTES, strictjson::DEFAULT_MAX_DEPTH), (262144, 16));
    assert_eq!(strictjson::MAX_SAFE_INTEGER, 9007199254740991);
}
