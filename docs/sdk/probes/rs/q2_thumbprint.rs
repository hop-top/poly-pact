// Q2: RFC 7638 SHA-256 JWK thumbprint over sha2 + base64 + serde_json: holder fixture, ignored members, RFC 7638 3.1 (RSA), error cases.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use {serde_json::{json, Value}, sha2::{Digest, Sha256}};
fn jkt(j: &Value) -> Result<String, String> {
    let names: &[&str] = match j["kty"].as_str() { Some("EC") => &["crv", "kty", "x", "y"], Some("RSA") => &["e", "kty", "n"], Some("OKP") => &["crv", "kty", "x"], k => return Err(format!("unsupported kty {k:?}")) };
    let m: Result<Vec<String>, String> = names.iter().map(|n| j[*n].as_str().map(|v| format!("{}:{}", Value::from(*n), Value::from(v))).ok_or(format!("missing member {n}"))).collect();
    Ok(B.encode(Sha256::digest(format!("{{{}}}", m?.join(",")).as_bytes())))
}
fn main() {
    let load = |n: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{}/spec/v1.0/fixtures/keys/{n}", std::env::var("REPO").unwrap())).unwrap()).unwrap();
    let holder = load("holder.jwk.json");
    println!("holder {} == expected: {}", jkt(&holder).unwrap(), jkt(&holder).unwrap() == "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M");
    let (mut bare, mut extra) = (holder.clone(), holder.clone());
    bare.as_object_mut().unwrap().retain(|k, _| ["kty", "crv", "x", "y"].contains(&k.as_str())); extra["foo"] = json!("bar");
    println!("kid/alg/use ignored: {} | extra member ignored: {}", jkt(&bare) == jkt(&holder), jkt(&extra) == jkt(&holder));
    let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    let t = jkt(&json!({"kty": "RSA", "n": n, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"})).unwrap();
    println!("RFC 7638 3.1 {t} == expected: {}", t == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    println!("missing required member y -> {:?} | unknown kty -> {:?}", jkt(&json!({"kty": "EC", "crv": "P-256", "x": "AA"})), jkt(&json!({"kty": "oct"})));
}
