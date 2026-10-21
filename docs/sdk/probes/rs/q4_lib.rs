// Q4: in-house JCS (RFC 8785) over serde_json::Value: std-only number formatter, UTF-16 key order, serde_json string escapes. Probe code.
use serde_json::Value;

/// ECMA-262 7.1.12.1 Number::toString layout for the shortest digits `digits` (no leading or trailing zeros) with decimal point position `n`.
fn layout(neg: bool, digits: &str, n: i32) -> String {
    let k = digits.len() as i32;
    let body = if k <= n && n <= 21 { format!("{digits}{}", "0".repeat((n - k) as usize)) }
        else if 0 < n && n <= 21 { format!("{}.{}", &digits[..n as usize], &digits[n as usize..]) }
        else if -6 < n && n <= 0 { format!("0.{}{digits}", "0".repeat((-n) as usize)) }
        else {
            let (sign, ex) = (if n - 1 < 0 { '-' } else { '+' }, (n - 1).abs());
            if k == 1 { format!("{digits}e{sign}{ex}") } else { format!("{}.{}e{sign}{ex}", &digits[..1], &digits[1..]) }
        };
    if neg { format!("-{body}") } else { body }
}
/// Re-lay out any decimal text of the shortest round-trip digits ("9007199254740992.0", "1e+23", "-1.5e-7") per ECMA-262.
pub fn reflow(t: &str) -> String {
    let (neg, t) = match t.strip_prefix('-') { Some(r) => (true, r), None => (false, t) };
    let (m, e) = t.split_once(['e', 'E']).map_or((t, 0), |(m, e)| (m, e.parse::<i32>().unwrap()));
    let (ip, fp) = m.split_once('.').unwrap_or((m, ""));
    let all = format!("{ip}{fp}");
    let digits = all.trim_start_matches('0').trim_end_matches('0');
    if digits.is_empty() { return "0".into(); }
    layout(neg, digits, ip.len() as i32 - (all.len() - all.trim_start_matches('0').len()) as i32 + e)
}
/// Digits from std `{:e}`.
pub fn es_std(x: f64) -> String { reflow(&format!("{:e}", x)) }
/// Digits from serde_json's own f64 printer (no new dependency).
pub fn es(x: f64) -> String { reflow(&serde_json::to_string(&x).unwrap()) }
/// Digits from the `ryu` crate.
pub fn es_ryu(x: f64) -> String { reflow(ryu::Buffer::new().format_finite(x)) }

pub fn canon(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 { out.push(','); }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                canon(&m[*k], out)?;
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() { if i > 0 { out.push(','); } canon(e, out)?; }
            out.push(']');
        }
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) if i.unsigned_abs() >= 1 << 53 => return Err(format!("integer {i} outside +-(2^53-1)")),
            (_, Some(u), _) if u >= 1 << 53 => return Err(format!("integer {u} outside +-(2^53-1)")),
            (Some(i), _, _) => out.push_str(&i.to_string()),
            (_, Some(u), _) => out.push_str(&u.to_string()),
            (_, _, Some(f)) if f.is_finite() => out.push_str(&es(f)),
            _ => return Err("non-finite number".into()),
        },
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
    Ok(())
}
pub fn canonicalize(v: &Value) -> Result<String, String> { let mut s = String::new(); canon(v, &mut s)?; Ok(s) }

/// Every candidate number formatter for one double: (name, text).
pub fn formatters(x: f64) -> Vec<(&'static str, String)> {
    vec![
        ("ryu", ryu::Buffer::new().format_finite(x).to_string()),
        ("json", serde_json::to_string(&x).unwrap()),
        ("dbg", format!("{x:?}")),
        ("disp", format!("{x}")),
        ("es_std", es_std(x)),
        ("es_json", es(x)),
        ("es_ryu", es_ryu(x)),
        ("jcs", serde_jcs::to_string(&x).unwrap()),
        ("sjc", serde_json_canonicalizer::to_string(&x).unwrap()),
    ]
}
