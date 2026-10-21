// Q2 (p256 0.13.2, jwk feature): PublicKey::from_jwk_str / to_jwk_string against a hand-built {crv,kty,x,y} string; bad inputs.
use p256::PublicKey;
use serde_json::Value;
fn main() {
    let rd = |p: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{}/spec/v1.0/fixtures/keys/{p}", std::env::var("REPO").unwrap())).unwrap()).unwrap();
    let res = |s: &str| PublicKey::from_jwk_str(s).map(|k| k.to_jwk_string()).map_err(|e| e.to_string());
    for name in ["issuer.jwk.json", "holder.jwk.json"] {
        let v = rd(name);
        let hand = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, v["x"].as_str().unwrap(), v["y"].as_str().unwrap());
        let mut bare = v.clone(); bare.as_object_mut().unwrap().retain(|k, _| ["kty", "crv", "x", "y"].contains(&k.as_str()));
        println!("{name}\n  as shipped (kid, alg, use present): {:?}\n  four members only: {:?}\n  hand-built:        Ok({hand:?})", res(&v.to_string()), res(&bare.to_string()));
    }
    let (i, h) = (rd("issuer.jwk.json"), rd("holder.jwk.json"));
    let (mut off, mut short, mut p384) = (i.clone(), i.clone(), i.clone());
    (off["y"], short["x"], p384["crv"]) = (h["y"].clone(), Value::from(&i["x"].as_str().unwrap()[..42]), "P-384".into());
    for (what, j) in [("foreign y (off-curve)", &off), ("42-char x", &short), ("crv P-384", &p384)] {
        let mut b = j.clone(); b.as_object_mut().unwrap().retain(|k, _| ["kty", "crv", "x", "y"].contains(&k.as_str())); println!("{what}: {:?}", res(&b.to_string()));
    }
}
