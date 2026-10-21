//! Validation of PACT objects against the vendored JSON Schema of draft
//! Appendix A.3 (`schema/pact.schema.json`, Draft 2020-12), with format `uri`
//! asserted by the RFC 3986 matcher every PACT SDK shares. An SDK extra: the
//! Go library has no schema module.
//!
//! The validator only ever sees what the strict parser returns: [`validate`]
//! takes JSON text, applies [`strictjson::parse`] first and then the schema.
//! It runs offline; the schema has no remote reference and none is fetched.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use jsonschema::{Draft, Validator};

use super::strictjson::{self, Limits};
pub use super::uri::{URI_PATTERN, uri_format};

/// The vendored schema text.
pub const SCHEMA_JSON: &str = include_str!("../../schema/pact.schema.json");

/// One schema failure of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The JSON Pointer (RFC 6901) of the failing value.
    pub instance_path: String,
    /// The schema keyword that failed.
    pub keyword: String,
    pub message: String,
}

/// Why a document was not validated or is not valid.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The definition is not a `$defs` entry of the schema.
    UnknownDef(String),
    /// The document is not strict JSON.
    Json(strictjson::Error),
    /// The document is strict JSON but fails its definition.
    Schema { def: String, issues: Vec<Issue> },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownDef(d) => write!(f, "schema: {d:?} is not a $defs entry of the schema"),
            Error::Json(e) => e.fmt(f),
            Error::Schema { def, issues } => {
                let all: Vec<String> = issues
                    .iter()
                    .map(|i| {
                        format!("{} {}", if i.instance_path.is_empty() { "/" } else { &i.instance_path }, i.message)
                    })
                    .collect();
                write!(f, "schema: {def}: {}", all.join("; "))
            }
        }
    }
}

impl std::error::Error for Error {}

fn document() -> &'static serde_json::Value {
    static DOC: OnceLock<serde_json::Value> = OnceLock::new();
    DOC.get_or_init(|| serde_json::from_str(SCHEMA_JSON).expect("the vendored schema is JSON"))
}

/// The `$defs` names of the schema, sorted.
pub fn defs() -> Vec<&'static str> {
    document()["$defs"].as_object().map(|m| m.keys().map(String::as_str).collect()).unwrap_or_default()
}

/// The compiled validator of one definition: the whole schema resource with
/// its root `oneOf` replaced by a reference to the definition, so every
/// local reference resolves inside the same resource.
fn validator(def: &str) -> Result<Arc<Validator>, Error> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Validator>>>> = OnceLock::new();
    let doc = document();
    if !doc["$defs"].as_object().is_some_and(|m| m.contains_key(def)) {
        return Err(Error::UnknownDef(def.to_string()));
    }
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(def) {
        return Ok(v.clone());
    }
    let mut root = doc.clone();
    if let Some(m) = root.as_object_mut() {
        m.remove("oneOf");
        m.insert("$ref".into(), serde_json::Value::String(format!("#/$defs/{def}")));
    }
    let v = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_format("uri", uri_format)
        .build(&root)
        .map_err(|e| Error::Schema { def: def.to_string(), issues: vec![issue(&e)] })?;
    let v = Arc::new(v);
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(def.to_string(), v.clone());
    Ok(v)
}

fn issue(e: &jsonschema::ValidationError<'_>) -> Issue {
    Issue {
        instance_path: e.instance_path().to_string(),
        keyword: e.kind().keyword().to_string(),
        message: e.to_string(),
    }
}

/// Strictly parses `input` under `limits` and validates the value against
/// the `$defs` entry `def`. Returns the parsed value.
pub fn validate(def: &str, input: &[u8], limits: Limits) -> Result<serde_json::Value, Error> {
    let v = validator(def)?;
    let value = strictjson::parse(input, limits).map_err(Error::Json)?;
    validate_value(&v, def, &value)?;
    Ok(value)
}

/// Validates a value that came through the strict parser against `def`.
pub fn validate_parsed(def: &str, value: &serde_json::Value) -> Result<(), Error> {
    validate_value(&*validator(def)?, def, value)
}

fn validate_value(v: &Validator, def: &str, value: &serde_json::Value) -> Result<(), Error> {
    let issues: Vec<Issue> = v.iter_errors(value).map(|e| issue(&e)).collect();
    if issues.is_empty() {
        return Ok(());
    }
    Err(Error::Schema { def: def.to_string(), issues })
}
