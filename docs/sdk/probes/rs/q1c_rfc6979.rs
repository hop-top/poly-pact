// Q1 (determinism): RFC 6979 A.2.5 P-256/SHA-256 vectors; Appendix C re-signed with scalar 2; high-S accepted by verify.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use p256::ecdsa::{signature::{Signer, Verifier}, Signature, SigningKey};
fn hx(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn main() {
    let sk = SigningKey::from_slice(&hx("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")).unwrap();
    for (m, rs) in [("sample", "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"), ("test", "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")] {
        let s: Signature = sk.sign(m.as_bytes());
        println!("RFC 6979 A.2.5 SHA-256 {m:?}: r||s matches {}", s.to_bytes()[..] == hx(rs)[..]);
    }
    let r = std::env::var("REPO").unwrap();
    let jws = std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws")).unwrap();
    let (si, fx) = jws.trim().rsplit_once('.').unwrap();
    let d = B.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI").unwrap();
    let k2 = SigningKey::from_slice(&d).unwrap();
    let mine: Signature = k2.sign(si.as_bytes());
    println!("scalar 2 re-sign of Appendix C input == fixture signature {} | verifies {}", mine.to_bytes()[..] == B.decode(fx).unwrap()[..], k2.verifying_key().verify(si.as_bytes(), &mine).is_ok());
    let hi = Signature::from_scalars(mine.r().to_bytes(), (-*mine.s()).to_bytes()).unwrap();
    println!("high-S twin (n-s) differs {} | verifies {} | normalize_s restores {}", hi != mine, k2.verifying_key().verify(si.as_bytes(), &hi).is_ok(), hi.normalize_s() == mine.normalize_s());
}
