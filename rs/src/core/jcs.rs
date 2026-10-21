//! RFC 8785 canonical JSON (JCS), for the object digest of draft section 7.4.
//!
//! [`canonicalize`] reads its input with [`crate::core::strictjson`] under the
//! default limits, so the checks of draft section 7.1 come first. It then
//! writes the value the way ECMAScript `JSON.stringify` does (RFC 8785
//! section 3):
//!
//! - no white space between tokens;
//! - strings: only the quotation mark, the reverse solidus and the control
//!   characters below U+0020 are escaped, in the forms of section 3.2.2.2;
//!   every other character, U+007F, U+2028 and U+2029 included, is written as
//!   is, and no Unicode normalization is applied;
//! - numbers: binary64 values in the ECMAScript `Number::toString` form, with
//!   the shortest digits that round-trip (section 3.2.2.3);
//! - object members sorted by name, recursively, comparing the names as
//!   arrays of UTF-16 code units (section 3.2.3); array order is kept.
//!
//! Integer literals outside ±(2^53-1) are rejected because the strict parser
//! rejects them, while a float written with an exponent, such as `1e30`, is
//! accepted and rounded to binary64.
//!
//! The shortest round-trip digits come from `serde_json`'s float printer; the
//! ECMAScript layout is built here from those digits and the decimal exponent.

use std::fmt;

use super::strictjson::{self, Document, Limits, Node, Number, V};

/// Why canonicalization failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input is not strict JSON.
    Json(strictjson::Error),
    /// A number is `NaN` or an infinity.
    NonFinite,
    /// An integer is outside ±(2^53-1).
    Range(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(e) => write!(f, "jcs: {e}"),
            Error::NonFinite => f.write_str("jcs: non-finite number"),
            Error::Range(n) => write!(f, "jcs: integer {n} is outside ±{}", strictjson::MAX_SAFE_INTEGER),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<strictjson::Error> for Error {
    fn from(e: strictjson::Error) -> Error {
        Error::Json(e)
    }
}

/// Returns the RFC 8785 canonical form of the JSON text in `data`. Any JSON
/// value may be canonicalized, not only an object.
pub fn canonicalize(data: &[u8]) -> Result<Vec<u8>, Error> {
    let doc = Document::read(data, Limits::default().resolved())?;
    if let Some(e) = doc.surrogate {
        return Err(Error::Json(e));
    }
    let mut out = String::with_capacity(data.len());
    write_node(&mut out, &doc.root)?;
    Ok(out.into_bytes())
}

/// Returns the RFC 8785 canonical form of a parsed value. Integers outside
/// ±(2^53-1) are an error, as they are in [`canonicalize`].
pub fn canonicalize_value(v: &serde_json::Value) -> Result<Vec<u8>, Error> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out.into_bytes())
}

fn write_node(out: &mut String, n: &Node) -> Result<(), Error> {
    match &n.v {
        V::Null => out.push_str("null"),
        V::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        V::Number(Number::Int(i)) => write_number(out, *i as f64)?,
        V::Number(Number::Float(f)) => write_number(out, *f)?,
        V::String(s) => write_string(out, s),
        V::Array(items) => {
            out.push('[');
            for (i, e) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_node(out, e)?;
            }
            out.push(']');
        }
        V::Object(members) => {
            let mut sorted: Vec<(Vec<u16>, &(String, Node))> =
                members.iter().map(|m| (m.0.encode_utf16().collect(), m)).collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (_, (name, value))) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, name);
                out.push(':');
                write_node(out, value)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_value(out: &mut String, v: &serde_json::Value) -> Result<(), Error> {
    use serde_json::Value as J;
    match v {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Number(n) => {
            let safe = |i: i64| (-strictjson::MAX_SAFE_INTEGER..=strictjson::MAX_SAFE_INTEGER).contains(&i);
            if let Some(i) = n.as_i64() {
                if !safe(i) {
                    return Err(Error::Range(n.to_string()));
                }
                write_number(out, i as f64)?;
            } else if n.is_u64() {
                return Err(Error::Range(n.to_string()));
            } else {
                write_number(out, n.as_f64().ok_or(Error::NonFinite)?)?;
            }
        }
        J::String(s) => write_string(out, s),
        J::Array(items) => {
            out.push('[');
            for (i, e) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, e)?;
            }
            out.push(']');
        }
        J::Object(m) => {
            let mut sorted: Vec<(Vec<u16>, &String, &serde_json::Value)> =
                m.iter().map(|(k, v)| (k.encode_utf16().collect(), k, v)).collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (_, k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, v)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Writes `s` as a JSON string the way ECMAScript `JSON.stringify` does (RFC
/// 8785 section 3.2.2.2).
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                out.push_str("\\u00");
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The shortest round-trip decimal digits of a finite, positive `f` and the
/// decimal point position `n`: `f` is `0.d1d2...dk` times 10^n.
fn shortest_digits(f: f64) -> (String, i32) {
    let text = serde_json::to_string(&f).unwrap_or_default();
    let (mantissa, exp) = match text.find(['e', 'E']) {
        Some(i) => (&text[..i], text[i + 1..].parse::<i32>().unwrap_or(0)),
        None => (text.as_str(), 0),
    };
    let int_len = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
    let all: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    let lead = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_start_matches('0').trim_end_matches('0').to_string();
    (digits, int_len + exp - lead as i32)
}

/// Writes `f` as ECMAScript `Number::toString` does (RFC 8785 section
/// 3.2.2.3).
fn write_number(out: &mut String, f: f64) -> Result<(), Error> {
    if !f.is_finite() {
        return Err(Error::NonFinite);
    }
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    if f < 0.0 {
        out.push('-');
    }
    let (d, n) = shortest_digits(f.abs());
    let k = d.len() as i32;
    if k <= n && n <= 21 {
        out.push_str(&d);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&d[..n as usize]);
        out.push('.');
        out.push_str(&d[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(&d);
    } else {
        out.push_str(&d[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&d[1..]);
        }
        out.push('e');
        out.push(if n - 1 < 0 { '-' } else { '+' });
        out.push_str(&(n - 1).abs().to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(f: f64) -> String {
        let mut s = String::new();
        write_number(&mut s, f).unwrap();
        s
    }

    #[test]
    fn number_layout() {
        for (f, want) in [
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123e18, "123000000000000000000"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (-0.0, "0"),
            (4.5, "4.5"),
            (1e30, "1e+30"),
            (0.1, "0.1"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (9007199254740992.0, "9007199254740992"),
            (333333333.3333332, "333333333.3333332"),
            (f64::from_bits(0x43143ff3c1cb0959), "1424953923781206.2"),
            (-1.5, "-1.5"),
            (1.0, "1"),
        ] {
            assert_eq!(num(f), want, "{f:e}");
        }
    }

    #[test]
    fn number_non_finite() {
        for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(write_number(&mut String::new(), f), Err(Error::NonFinite));
        }
    }

    #[test]
    fn number_round_trips() {
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..20000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let f = f64::from_bits(x);
            if !f.is_finite() {
                continue;
            }
            let s = num(f);
            assert_eq!(s.parse::<f64>().unwrap(), if f == 0.0 { 0.0 } else { f }, "{s}");
        }
    }
}
