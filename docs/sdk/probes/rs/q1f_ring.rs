// Q1 (ring): ECDSA_P256_SHA256_FIXED: 64-byte r||s, nonce randomness, RFC 7515 A.3 verify, bad lengths.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use ring::{rand::SystemRandom, signature::{EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING}};
use std::collections::BTreeSet;
fn main() {
    let u = |s: &str| B.decode(s).unwrap();
    let ver = |pk: &[u8], m: &[u8], s: &[u8]| UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk).verify(m, s).is_ok();
    let a3 = [&[4u8][..], &u("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), &u("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")].concat();
    let si = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    let sg = u("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
    println!("RFC 7515 A.3 verifies {} sig bytes {} tampered input {}", ver(&a3, si, &sg), sg.len(), ver(&a3, &[&si[..], b"x"].concat(), &sg));
    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_FIXED_SIGNING, &u("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"), &a3, &rng).unwrap();
    let sigs: Vec<Vec<u8>> = (0..5000).map(|_| kp.sign(&rng, si).unwrap().as_ref().to_vec()).collect();
    let (lens, distinct): (BTreeSet<usize>, BTreeSet<&Vec<u8>>) = (sigs.iter().map(|s| s.len()).collect(), sigs.iter().collect());
    println!("round trip {} raw lens {lens:?} | one message signed 5000 times: {} distinct", sigs.iter().all(|s| ver(&a3, si, s)), distinct.len());
    println!("63 bytes {} 65 bytes {} tampered msg {}", ver(&a3, si, &sigs[0][..63]), ver(&a3, si, &[&sigs[0][..], &[0u8]].concat()), ver(&a3, b"x", &sigs[0]));
}
