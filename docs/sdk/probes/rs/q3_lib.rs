// Q3: in-house strict JSON check: a serde Visitor over serde_json::Deserializer. Probe code, not shipped.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{collections::HashSet, fmt};
const MAX_SAFE: u64 = 9_007_199_254_740_991;
pub const MAX_DEPTH: usize = 16;
pub struct Check(pub usize); // nesting depth of the value being visited

pub fn check(bytes: &[u8]) -> Result<usize, String> {
    let s = std::str::from_utf8(bytes).map_err(|e| format!("utf-8: {e}"))?;
    if s.starts_with('\u{feff}') { return Err("byte order mark".into()); }
    let mut de = serde_json::Deserializer::from_str(s);
    let depth = Check(0).deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    #[cfg(not(feature = "ap"))]
    scan_ints(s)?;
    Ok(depth)
}
/// Lexical pass over text serde_json already accepted: an integer literal (no '.', 'e', 'E') must fit +-(2^53-1). Needed because
/// without arbitrary_precision serde_json turns an integer literal above u64::MAX into an f64 before any visitor sees it.
#[cfg(not(feature = "ap"))]
fn scan_ints(s: &str) -> Result<(), String> {
    let (b, mut i, mut in_str) = (s.as_bytes(), 0, false);
    while i < b.len() {
        let c = b[i];
        if in_str { if c == b'\\' { i += 1 } else if c == b'"' { in_str = false } i += 1; continue; }
        if c == b'"' { in_str = true; i += 1; continue; }
        if c == b'-' || c.is_ascii_digit() {
            let st = i;
            i += 1;
            while i < b.len() && matches!(b[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') { i += 1; }
            let t = &s[st..i];
            if !t.contains(['.', 'e', 'E']) && t.trim_start_matches('-').parse::<u64>().map_or(true, |v| v > MAX_SAFE) { return Err(format!("integer literal {t:.24} outside +-(2^53-1)")); }
            continue;
        }
        i += 1;
    }
    Ok(())
}
#[cfg(feature = "ap")]
fn number<E: de::Error>(t: &str, d: usize) -> Result<usize, E> {
    if !t.contains(['.', 'e', 'E']) {
        return match t.trim_start_matches('-').parse::<u64>() { Ok(v) if v <= MAX_SAFE => Ok(d), _ => Err(E::custom("integer above 2^53-1")) };
    }
    match t.parse::<f64>() { Ok(v) if v.is_finite() => Ok(d), _ => Err(E::custom("non-finite number")) }
}
impl<'de> DeserializeSeed<'de> for Check {
    type Value = usize;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<usize, D::Error> { d.deserialize_any(self) }
}
impl<'de> Visitor<'de> for Check {
    type Value = usize;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a JSON value") }
    fn visit_bool<E>(self, _: bool) -> Result<usize, E> { Ok(self.0) }
    fn visit_unit<E>(self) -> Result<usize, E> { Ok(self.0) }
    fn visit_str<E>(self, _: &str) -> Result<usize, E> { Ok(self.0) }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<usize, E> { if v > MAX_SAFE { Err(E::custom("integer above 2^53-1")) } else { Ok(self.0) } }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<usize, E> { if v.unsigned_abs() > MAX_SAFE { Err(E::custom("integer below -(2^53-1)")) } else { Ok(self.0) } }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<usize, E> { if v.is_finite() { Ok(self.0) } else { Err(E::custom("non-finite number")) } }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<usize, A::Error> {
        let d = self.0 + 1;
        if d > MAX_DEPTH { return Err(de::Error::custom("nesting depth above 16")); }
        let mut max = d;
        while let Some(m) = a.next_element_seed(Check(d))? { max = max.max(m); }
        Ok(max)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<usize, A::Error> {
        let d = self.0 + 1;
        if d > MAX_DEPTH { return Err(de::Error::custom("nesting depth above 16")); }
        let (mut seen, mut max) = (HashSet::new(), d);
        while let Some(k) = a.next_key::<String>()? {
            #[cfg(feature = "ap")]
            if k == "$serde_json::private::Number" && seen.is_empty() { return number(&a.next_value::<String>()?, self.0); }
            if !seen.insert(k) { return Err(de::Error::custom("duplicate key")); }
            max = max.max(a.next_value_seed(Check(d))?);
        }
        Ok(max)
    }
}
