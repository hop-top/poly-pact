// Q2 (fixtures): thumbprint of every key in spec/v1.0/fixtures/keys, and the RFC 8037 A.3 Ed25519 vector.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
fn jkt(j: &Value) -> Result<String, String> {
    let names: &[&str] = match j["kty"].as_str() { Some("EC") => &["crv", "kty", "x", "y"], Some("RSA") => &["e", "kty", "n"], Some("OKP") => &["crv", "kty", "x"], k => return Err(format!("unsupported kty {k:?}")) };
    let m: Result<Vec<String>, String> = names.iter().map(|n| j[*n].as_str().map(|v| format!("{}:{}", Value::from(*n), Value::from(v))).ok_or(format!("missing member {n}"))).collect();
    Ok(B.encode(Sha256::digest(format!("{{{}}}", m?.join(",")).as_bytes())))
}
fn main() {
    let dir = format!("{}/spec/v1.0/fixtures/keys", std::env::var("REPO").unwrap());
    let load = |n: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{dir}/{n}")).unwrap()).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).filter(|n| n.ends_with(".jwk.json")).collect(); names.sort();
    for n in &names { println!("  {n} {}", jkt(&load(n)).unwrap()); }
    println!("RFC 8037 A.3 Ed25519 thumbprint matches: {}", jkt(&load("ed25519.jwk.json")).unwrap() == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
}
