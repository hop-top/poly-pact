// Q1: ES256 with p256 0.14.0: 64-byte r||s, RFC 6979 determinism, round trip, tamper and length rejects, RFC 7515 A.3.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use p256::ecdsa::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use std::collections::BTreeSet;
fn pubk(x: &str, y: &str) -> VerifyingKey { VerifyingKey::from_sec1_bytes(&[&[4u8][..], &B.decode(x).unwrap(), &B.decode(y).unwrap()].concat()).unwrap() }
fn ok(k: &VerifyingKey, sig: &[u8], m: &[u8]) -> bool { Signature::from_slice(sig).map_or(false, |s| k.verify(m, &s).is_ok()) }
fn main() {
    let k = SigningKey::generate();
    let msgs: Vec<Vec<u8>> = (0..5000).map(|i| format!("hdr.payload{i}").into_bytes()).collect();
    let sigs: Vec<Signature> = msgs.iter().map(|m| k.sign(m)).collect();
    let (raw, ders): (BTreeSet<usize>, BTreeSet<usize>) = (sigs.iter().map(|s| s.to_bytes().len()).collect(), sigs.iter().map(|s| s.to_der().as_bytes().len()).collect());
    let same: BTreeSet<Vec<u8>> = (0..5000).map(|_| Signer::<Signature>::sign(&k, &msgs[0][..]).to_bytes().to_vec()).collect();
    println!("round trip {} raw lens {raw:?} DER lens {ders:?} | one message signed 5000 times: {} distinct", sigs.iter().zip(&msgs).all(|(s, m)| ok(k.verifying_key(), &s.to_bytes(), m)), same.len());
    let (s0, m0) = (sigs[0].to_bytes(), &msgs[0]);
    println!("tampered msg {} 63 bytes {} 65 bytes {}", ok(k.verifying_key(), &s0, b"hdr.payloaX"), ok(k.verifying_key(), &s0[..63], m0), ok(k.verifying_key(), &[&s0[..], &[0u8]].concat(), m0));
    let a3 = pubk("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
    let (si, sg) = (b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", B.decode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q").unwrap());
    println!("RFC 7515 A.3 verifies {} sig bytes {} tampered input {}", ok(&a3, &sg, si), sg.len(), ok(&a3, &sg, &[&si[..], b"x"].concat()));
}
