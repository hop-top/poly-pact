// Q1 (ring, malleability): the high-S twin (n - s) of a ring signature verifies under ECDSA_P256_SHA256_FIXED.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use ring::{rand::SystemRandom, signature::{EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING}};
fn main() {
    let u = |s: &str| B.decode(s).unwrap();
    let a3 = [&[4u8][..], &u("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), &u("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")].concat();
    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_FIXED_SIGNING, &u("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"), &a3, &rng).unwrap();
    let sig = kp.sign(&rng, b"m").unwrap().as_ref().to_vec();
    let n: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"[i..i + 2], 16).unwrap()).collect();
    let (mut hi, mut b) = (sig.clone(), 0i16);
    for i in (32..64).rev() { let d = n[i - 32] as i16 - hi[i] as i16 - b; b = (d < 0) as i16; hi[i] = d.rem_euclid(256) as u8; }
    let ver = |s: &[u8]| UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &a3).verify(b"m", s).is_ok();
    println!("original verifies {} | high-S twin (n-s) differs {} verifies {}", ver(&sig), hi != sig, ver(&hi));
}
