// Q1 (fixture): Appendix C compact JWS verifies under issuer.jwk.json; off-curve JWK point rejected on load.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::Value;
fn pubk(j: &Value) -> Result<VerifyingKey, p256::ecdsa::Error> { let c = |k: &str| B.decode(j[k].as_str().unwrap()).unwrap(); VerifyingKey::from_sec1_bytes(&[&[4u8][..], &c("x"), &c("y")].concat()) }
fn main() {
    let r = std::env::var("REPO").unwrap();
    let rd = |p: &str| std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/{p}")).unwrap();
    let jwk = |p: &str| serde_json::from_str::<Value>(&rd(p)).unwrap();
    let (issuer, holder) = (jwk("keys/issuer.jwk.json"), jwk("keys/holder.jwk.json"));
    let jws = rd("parse/appendix-c-wrong-version.jws");
    let (h, p, s) = { let v: Vec<&str> = jws.trim().split('.').collect(); (v[0], v[1], v[2]) };
    let (sig, k) = (B.decode(s).unwrap(), pubk(&issuer).unwrap());
    let ok = |m: String| Signature::from_slice(&sig).map_or(false, |g| k.verify(m.as_bytes(), &g).is_ok());
    println!("header {} sig bytes {} verifies {} other payload {}", String::from_utf8(B.decode(h).unwrap()).unwrap(), sig.len(), ok(format!("{h}.{p}")), ok(format!("{h}.e30")));
    let mut bad = issuer.clone(); bad["y"] = holder["y"].clone();
    println!("off-curve point {}", pubk(&bad).map_or_else(|e| format!("rejected: {e}"), |_| "accepted".into()));
}
