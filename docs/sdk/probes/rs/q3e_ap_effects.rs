// Q3: arbitrary_precision side effects on typed decoding: untagged enum, flatten, u64/f64 fields, object-vs-number token key.
#![allow(dead_code)]
use serde::Deserialize;
use std::collections::BTreeMap;
#[derive(Deserialize, Debug)] #[serde(untagged)] enum E { N(u64), S(String) }
#[derive(Deserialize, Debug)] struct F { a: u64, #[serde(flatten)] rest: BTreeMap<String, serde_json::Value> }
#[derive(Deserialize, Debug)] struct T { n: u64, f: f64 }
fn main() {
    println!("untagged enum from 5:            {:?}", serde_json::from_str::<E>("5").map_err(|e| e.to_string()));
    println!("untagged enum from \"x\":          {:?}", serde_json::from_str::<E>("\"x\"").map_err(|e| e.to_string()));
    println!("flatten struct:                  {:?}", serde_json::from_str::<F>(r#"{"a":1,"b":2}"#).map_err(|e| e.to_string()));
    println!("plain u64 and f64 fields:        {:?}", serde_json::from_str::<T>(r#"{"n":9007199254740991,"f":1e22}"#).map_err(|e| e.to_string()));
    println!("u64 field from 1.0 / 1e2:        {:?} {:?}", serde_json::from_str::<T>(r#"{"n":1.0,"f":0}"#).map_err(|e| e.to_string()), serde_json::from_str::<T>(r#"{"n":1e2,"f":0}"#).map_err(|e| e.to_string()));
    let v: serde_json::Value = serde_json::from_str(r#"{"k":{"$serde_json::private::Number":"7"}}"#).unwrap();
    println!("object with the private token key: {v} | is_number {} is_object {}", v["k"].is_number(), v["k"].is_object());
}
