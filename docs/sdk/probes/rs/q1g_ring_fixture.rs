// Q1 (ring, fixture): Appendix C compact JWS verifies under issuer.jwk.json; a key with a foreign y is only rejected at verify.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
fn main() {
    let r = std::env::var("REPO").unwrap();
    let rd = |p: &str| std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/{p}")).unwrap();
    let jwk = |p: &str| serde_json::from_str::<serde_json::Value>(&rd(p)).unwrap();
    let pt = |x: &serde_json::Value, y: &serde_json::Value| [&[4u8][..], &B.decode(x.as_str().unwrap()).unwrap(), &B.decode(y.as_str().unwrap()).unwrap()].concat();
    let (iss, hol, jws) = (jwk("keys/issuer.jwk.json"), jwk("keys/holder.jwk.json"), rd("parse/appendix-c-wrong-version.jws"));
    let (m, s) = jws.trim().rsplit_once('.').unwrap();
    let ver = |pk: Vec<u8>, m: &str| UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk).verify(m.as_bytes(), &B.decode(s).unwrap()).is_ok();
    println!("Appendix C verifies {} other payload {}", ver(pt(&iss["x"], &iss["y"]), m), ver(pt(&iss["x"], &iss["y"]), "x"));
    println!("issuer x with holder y (off-curve) verifies {}", ver(pt(&iss["x"], &hol["y"]), m));
}
