// Q1 (base64url): std has no base64. base64 0.23.1 URL_SAFE_NO_PAD strictness, against a 12-line in-house strict decoder on 1,000,000 random strings.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
fn dec(s: &str) -> Option<Vec<u8>> {
    let v: Vec<u8> = s.bytes().map(|c| match c { b'A'..=b'Z' => Some(c - 65), b'a'..=b'z' => Some(c - 71), b'0'..=b'9' => Some(c + 4), b'-' => Some(62), b'_' => Some(63), _ => None }).collect::<Option<_>>()?;
    if v.len() % 4 == 1 { return None; }
    let (mut out, mut acc, mut bits) = (vec![], 0u32, 0);
    for x in &v { acc = acc << 6 | *x as u32; bits += 6; if bits >= 8 { bits -= 8; out.push((acc >> bits) as u8); acc &= (1 << bits) - 1; } }
    if acc != 0 { None } else { Some(out) }
}
fn main() {
    for (l, s) in [("valid 'AAA'", "AAA"), ("padding 'AA=='", "AA=="), ("std alphabet 'A+/A'", "A+/A"), ("newline 'AA\\nA'", "AA\nA"), ("trailing bits 'AB'", "AB"), ("length 5 mod 4 'AAAAA'", "AAAAA"), ("non-ASCII", "AAé")] { println!("{l:<26} crate {:?} in-house {:?}", B.decode(s).ok(), dec(s)); }
    let (mut x, a) = (0x2545F4914F6CDD1Du64, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ ".to_vec());
    let (mut diff, mut valid) = (0, 0);
    for _ in 0..1_000_000 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; let s: String = (0..(x % 12) as usize).map(|i| a[((x >> (8 + 5 * i)) % a.len() as u64) as usize] as char).collect(); valid += B.decode(&s).is_ok() as u32; if B.decode(&s).ok() != dec(&s) { diff += 1; } }
    println!("1000000 random strings, {valid} accepted by the crate; disagreements with the in-house decoder: {diff}");
}
