// Q1 (ring, malformed signatures): all-zero, r = n, s = n, r = 0, r = 2^256-1 and wrong lengths against ECDSA_P256_SHA256_FIXED; last row is the A.3 signature.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
fn main() {
    let u = |s: &str| B.decode(s).unwrap();
    let k = [&[4u8][..], &u("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), &u("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")].concat();
    let n: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"[i..i + 2], 16).unwrap()).collect();
    let si = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    let good = u("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
    let cases = [("all zero", vec![0u8; 64]), ("r = n", [&n[..], &good[32..]].concat()), ("s = n", [&good[..32], &n[..]].concat()), ("r = 0", [&[0u8; 32][..], &good[32..]].concat()), ("r = 2^256-1", [&[255u8; 32][..], &good[32..]].concat()), ("empty", vec![]), ("good", good.clone())];
    for (l, sig) in cases { println!("{l:<12} verify {:?}", UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &k).verify(si, &sig).map(|_| "Ok").map_err(|e| e.to_string())); }
}
