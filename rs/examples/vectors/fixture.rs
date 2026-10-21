//! Fixture reading and checks shared by the groups of the harness. A group
//! runner returns `Ok` on a pass, [`Fail::Skip`] on a skip and
//! [`Fail::Fail`] on a failure.

use std::path::Path;

use base64::Engine;
use serde_json::{Map, Value};

/// How an entry did not pass.
#[derive(Debug)]
pub enum Fail {
    /// The entry failed, with why.
    Fail(String),
    /// The entry is skipped for a reason of the result grammar.
    Skip { reason: &'static str, detail: String, spec_defects: Vec<Value> },
}

pub type Res<T = ()> = Result<T, Fail>;

/// A failure with a message.
pub fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(Fail::Fail(msg.into()))
}

/// Whether `p` is a slash-separated relative path with no empty, `.` or `..`
/// segment.
pub fn local_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// The bytes of a fixture file named relative to the fixture directory.
pub fn read_fixture(root: &Path, rel: &str) -> Res<Vec<u8>> {
    if !local_path(rel) {
        return fail(format!("path {rel:?} is not inside the fixture directory"));
    }
    std::fs::read(root.join(rel)).or_else(|e| fail(format!("{rel}: {e}")))
}

/// A fixture file parsed as JSON.
pub fn read_json(root: &Path, rel: &str) -> Res<Value> {
    let b = read_fixture(root, rel)?;
    serde_json::from_slice(&b).or_else(|e| fail(format!("{rel}: {e}")))
}

/// Checks that an entry names one JSON file that holds its own expectations.
pub fn single_file(e: &super::manifest::Entry) -> Res {
    if !e.path.ends_with(".json") || e.expected.as_deref() != Some(e.path.as_str()) {
        return fail(format!("path {:?} and expected {:?} must name the same JSON file", e.path, e.expected));
    }
    Ok(())
}

/// The object `v`, whose members are exactly `want`.
pub fn exact_members<'a>(v: &'a Value, want: &[&str]) -> Res<&'a Map<String, Value>> {
    let Some(m) = v.as_object() else { return fail("not a JSON object") };
    let mut got: Vec<&str> = m.keys().map(String::as_str).collect();
    let mut w = want.to_vec();
    got.sort_unstable();
    w.sort_unstable();
    if got != w {
        return fail(format!("members {got:?}, want exactly {w:?}"));
    }
    Ok(m)
}

/// The object `v`, with no member outside `allowed`.
pub fn only_members<'a>(v: &'a Value, allowed: &[&str]) -> Res<&'a Map<String, Value>> {
    let Some(m) = v.as_object() else { return fail("not a JSON object") };
    let extra: Vec<&String> = m.keys().filter(|k| !allowed.contains(&k.as_str())).collect();
    if !extra.is_empty() {
        return fail(format!("unknown members {extra:?}"));
    }
    Ok(m)
}

pub fn string_of<'a>(v: Option<&'a Value>, name: &str) -> Res<&'a str> {
    match v {
        Some(Value::String(s)) => Ok(s),
        _ => fail(format!("{name} is not a string")),
    }
}

pub fn nullable_string_of<'a>(v: Option<&'a Value>, name: &str) -> Res<Option<&'a str>> {
    match v {
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Null) => Ok(None),
        _ => fail(format!("{name} is neither a string nor null")),
    }
}

/// Decodes canonical padded base64 (RFC 4648 section 4).
pub fn base64_std(s: &str, name: &str) -> Res<Vec<u8>> {
    let e = base64::engine::general_purpose::STANDARD;
    match e.decode(s) {
        Ok(b) if e.encode(&b) == s => Ok(b),
        _ => fail(format!("{name} is not canonical base64")),
    }
}

/// Decodes canonical unpadded base64url (RFC 4648 section 5).
pub fn base64_url(s: &str, name: &str) -> Res<Vec<u8>> {
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match e.decode(s) {
        Ok(b) if e.encode(&b) == s => Ok(b),
        _ => fail(format!("{name} is not canonical base64url")),
    }
}
