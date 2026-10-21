// Q3: stock serde_json (from_slice::<Value>) against q3_json::check on the strict-JSON hazards; then raw bytes against str::from_utf8.
use serde_json::{from_slice, Value};
fn show(r: Result<Value, serde_json::Error>) -> String { r.map_or_else(|e| format!("REJECT {e}"), |v| format!("{v}")) }
fn main() {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let text: Vec<(String, String)> = [r#"{"a":1,"a":2}"#, r#"{"a":1,"~u0061":2}"#, "[NaN]", "[Infinity]", "[-Infinity]", "[1e999]", "[-1e999]", "[1e-999]", r#"["~ud800"]"#, r#"["~udc00"]"#, r#"["~ud800~u0041"]"#, r#"["~ud83d~ude00"]"#,
        "[9007199254740991]", "[9007199254740993]", "[18446744073709551615]", "[18446744073709551616]", "[123456789012345678901234567890]", "[9007199254740993.0]", "[0.1,333333333.33333329,5e-324,1e22]", "[-0,-0.0,0.0]",
        r#"{"$serde_json::private::Number":"7"}"#, "{}}", "[1,]", "[1] [2]"].iter().map(|s| (s.replace('~', "\\"), s.replace('~', "\\"))).chain([128, 129, 100000].map(|n| (format!("{n} nested arrays"), deep(n)))).collect();
    let strict = |b: &[u8]| q3_json::check(b).map_or_else(|e| format!("REJECT {e}"), |d| format!("ok depth {d}"));
    for (label, t) in &text { println!("{:<42} stock {:<58} strict {}", label, show(from_slice(t.as_bytes())), strict(t.as_bytes())); }
    let bytes: [(&str, &[u8]); 7] = [("ff", b"\xff"), ("overlong c0 af in string", b"[\"\xc0\xaf\"]"), ("truncated e2 82 in string", b"[\"\xe2\x82\"]"), ("encoded surrogate ed a0 80", b"[\"\xed\xa0\x80\"]"), ("out of range f4 90 80 80", b"[\"\xf4\x90\x80\x80\"]"), ("BOM + {}", b"\xef\xbb\xbf{}"), ("UTF-16LE {}", b"\xff\xfe{\x00}\x00")];
    for (l, b) in bytes { println!("{l:<42} from_slice {} | str::from_utf8 {} | strict {}", show(from_slice(b)), std::str::from_utf8(b).map_or_else(|e| format!("REJECT {e}"), |s| format!("Ok({s:?})")), strict(b)); }
}
