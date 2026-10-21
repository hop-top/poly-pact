// Q4 (domain): integer range, minus zero, non-finite floats, and key order under serde_json's preserve_order, per implementation.
use serde_json::Value;
fn r<E: std::fmt::Display>(x: Result<String, E>) -> String { x.unwrap_or_else(|e| format!("Err({e})")) }
fn main() {
    println!("serde_json preserve_order feature on: {}", cfg!(feature = "po"));
    for t in ["[9007199254740991]", "[9007199254740992]", "[-9007199254740991]", "[-9007199254740992]", "[9007199254740993]", "[18446744073709551615]", "[9007199254740992.0]", "[-0]", "[-0.0]", "[1.0]", "[1E30]", "[0.000001]", "[1e-7]", r#"{"b":1,"a":{"d":1,"c":2}}"#] {
        let v: Value = serde_json::from_str(t).unwrap();
        println!("{t:<26} in-house {:<32} serde_jcs {:<26} serde_json_canonicalizer {}", r(q4_jcs::canonicalize(&v)), r(serde_jcs::to_string(&v)), r(serde_json_canonicalizer::to_string(&v)));
    }
    for (n, x) in [("NaN", f64::NAN), ("Infinity", f64::INFINITY)] {
        println!("{n}: serde_json::to_string {} | to_value {:?} | Number::from_f64 {:?} | serde_jcs {} | serde_json_canonicalizer {}", r(serde_json::to_string(&x)), serde_json::to_value(x).unwrap(), serde_json::Number::from_f64(x), r(serde_jcs::to_string(&x)), r(serde_json_canonicalizer::to_string(&x)));
    }
}
