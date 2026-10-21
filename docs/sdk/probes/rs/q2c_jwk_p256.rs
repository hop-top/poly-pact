// Q2 (JWK <-> p256 0.14.0 without a jwk feature): fixture x/y round trip, scalar n to public point, 32-byte coordinates, split-point hazard.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use p256::{ecdsa::{SigningKey, VerifyingKey}, elliptic_curve::Generate};
use serde_json::Value;
fn main() {
    let rd = |p: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{}/spec/v1.0/fixtures/keys/{p}", std::env::var("REPO").unwrap())).unwrap()).unwrap();
    let xy = |k: &VerifyingKey| { let p = k.to_sec1_point(false); let b = p.as_bytes().to_vec(); (B.encode(&b[1..33]), B.encode(&b[33..65])) };
    for e in rd("test-private-scalars.json")["keys"].as_array().unwrap().iter().filter(|e| e["kty"] == "EC") {
        let jwk = rd(e["public_jwk"].as_str().unwrap());
        let sk = SigningKey::from_slice(&B.decode(e["d"].as_str().unwrap()).unwrap()).unwrap();
        println!("  {} scalar {} -> x,y == jwk {}", e["role"].as_str().unwrap(), e["scalar"].as_str().unwrap(), xy(sk.verifying_key()) == (jwk["x"].as_str().unwrap().into(), jwk["y"].as_str().unwrap().into()));
    }
    let lens: std::collections::BTreeSet<(usize, usize)> = (0..5000).map(|_| xy(SigningKey::generate().verifying_key())).map(|(x, y)| (x.len(), y.len())).collect();
    println!("5000 random keys: base64url (x, y) lengths {lens:?} (43 chars = 32 bytes)");
    let (iss, naive) = (rd("issuer.jwk.json"), |x: &[u8], y: &[u8]| VerifyingKey::from_sec1_bytes(&[&[4u8][..], x, y].concat()).is_ok());
    let strict = |x: &[u8], y: &[u8]| x.len() == 32 && y.len() == 32 && naive(x, y);
    let (x, y) = (B.decode(iss["x"].as_str().unwrap()).unwrap(), B.decode(iss["y"].as_str().unwrap()).unwrap());
    let (xs, ys) = (&x[..31], [&x[31..], &y[..]].concat());
    println!("x(32)+y(32): naive {} strict {} | x(31)+y(33), same 64 bytes: naive {} strict {}", naive(&x, &y), strict(&x, &y), naive(xs, &ys), strict(xs, &ys));
}
