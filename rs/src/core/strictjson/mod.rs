//! Strict decoding of PACT JSON: the checks of draft section 7.1 that a
//! general JSON parser does not make.
//!
//! [`unmarshal`] and [`decode`] reject, before any value reaches the target:
//!
//! - duplicate member names, compared after unescaping, in any object,
//!   including the open `extensions` and `attributes` objects and free-form
//!   values;
//! - member names that are not an exact, case-sensitive field of the target
//!   type (with `#[serde(deny_unknown_fields)]`, as every PACT wire type has),
//!   except inside maps and free-form values;
//! - nesting deeper than [`Limits::max_depth`] (16 by default);
//! - non-finite numbers: `NaN`, `Infinity` and literals that overflow binary64;
//! - invalid UTF-8 and unpaired surrogate escapes;
//! - integer literals outside ±(2^53-1) anywhere in the document and, for an
//!   integer target, negative or non-integer numbers;
//! - `null` for any target that cannot hold it (only `Option` and free-form
//!   values can);
//! - empty input, text after the JSON value, and input over
//!   [`Limits::max_bytes`].
//!
//! The decoder checks syntax and shape. It does not apply the schema's
//! patterns, lengths, enum sets or required members: a member the input leaves
//! out keeps its default, and a schema validator decides whether it was
//! required (see [`crate::core::schema`]).

mod de;
mod parse;

use std::fmt;
use std::io::Read;

use serde::de::DeserializeOwned;

/// The largest integer a core field may carry: 2^53-1.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// The decoded presentation limit of draft section 20.1.
pub const DEFAULT_MAX_BYTES: usize = 256 << 10;

/// The JSON nesting limit of draft section 20.1. The outermost object or
/// array has depth 1.
pub const DEFAULT_MAX_DEPTH: usize = 16;

/// Bounds one decode. A field that is zero selects its default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The largest input in bytes.
    pub max_bytes: usize,
    /// The deepest nesting of objects and arrays.
    pub max_depth: usize,
}

impl Limits {
    /// The limits with every zero field replaced by its default.
    pub fn resolved(self) -> Limits {
        Limits {
            max_bytes: if self.max_bytes == 0 { DEFAULT_MAX_BYTES } else { self.max_bytes },
            max_depth: if self.max_depth == 0 { DEFAULT_MAX_DEPTH } else { self.max_depth },
        }
    }
}

/// Why a decode failed. An [`Error`] carries exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// The input is larger than [`Limits::max_bytes`].
    Size,
    /// The input is not JSON.
    Syntax,
    /// The input is not UTF-8.
    InvalidUtf8,
    /// A `\u` escape is a surrogate that is not part of a pair.
    LoneSurrogate,
    /// Objects and arrays nest deeper than [`Limits::max_depth`].
    Depth,
    /// An object repeats a member name.
    DuplicateKey,
    /// A member name is not a field of the target type.
    UnknownField,
    /// A number is `NaN`, an infinity, or overflows binary64.
    NonFinite,
    /// An integer is outside ±(2^53-1), or an integer target got a negative
    /// or non-integer number.
    Integer,
    /// A target that cannot hold `null` got one.
    Null,
    /// Text follows the JSON value.
    TrailingData,
    /// A value does not fit the target type.
    Type,
}

impl Kind {
    /// The message of the kind, the text Go's `strictjson` prints.
    pub fn message(self) -> &'static str {
        match self {
            Kind::Size => "strictjson: input too large",
            Kind::Syntax => "strictjson: invalid JSON",
            Kind::InvalidUtf8 => "strictjson: invalid UTF-8",
            Kind::LoneSurrogate => "strictjson: unpaired surrogate escape",
            Kind::Depth => "strictjson: nesting too deep",
            Kind::DuplicateKey => "strictjson: duplicate member name",
            Kind::UnknownField => "strictjson: unknown field",
            Kind::NonFinite => "strictjson: non-finite number",
            Kind::Integer => "strictjson: integer out of range or not an integer",
            Kind::Null => "strictjson: null not allowed",
            Kind::TrailingData => "strictjson: data after the JSON value",
            Kind::Type => "strictjson: value does not fit the target type",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Where and why a decode failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Why the decode failed.
    pub kind: Kind,
    /// The JSON Pointer (RFC 6901) of the offending member, empty for the
    /// document root.
    pub path: String,
    /// The byte offset in the input at which the problem was found.
    pub offset: usize,
    /// Specifics, such as the member name.
    pub detail: String,
}

impl Error {
    pub(crate) fn new(kind: Kind, offset: usize, detail: impl Into<String>) -> Error {
        Error { kind, path: String::new(), offset, detail: detail.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.message())?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        if !self.path.is_empty() {
            write!(f, " at {}", self.path)?;
        }
        write!(f, " (offset {})", self.offset)
    }
}

impl std::error::Error for Error {}

/// Reads one JSON value from `r`, at most [`Limits::max_bytes`] plus one
/// bytes, and decodes it as [`unmarshal`] does.
pub fn decode<T: DeserializeOwned, R: Read>(r: R, limits: Limits) -> Result<T, DecodeError> {
    let lim = limits.resolved();
    let mut data = Vec::new();
    r.take(lim.max_bytes as u64 + 1).read_to_end(&mut data).map_err(DecodeError::Read)?;
    unmarshal(&data, limits).map_err(DecodeError::Json)
}

/// The error of [`decode`]: the reader failed, or the input is not strict
/// JSON for the target.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Reading the input failed.
    Read(std::io::Error),
    /// The input was rejected.
    Json(Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Read(e) => write!(f, "strictjson: read: {e}"),
            DecodeError::Json(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::Read(e) => Some(e),
            DecodeError::Json(e) => Some(e),
        }
    }
}

/// Decodes `data` into a `T` under the rules of the module documentation.
///
/// Every PACT wire type of [`crate::core`] is a valid target. A type of your
/// own gets the unknown-field rule only with `#[serde(deny_unknown_fields)]`.
pub fn unmarshal<T: DeserializeOwned>(data: &[u8], limits: Limits) -> Result<T, Error> {
    let lim = limits.resolved();
    let doc = parse::Document::read(data, lim)?;
    let value = T::deserialize(de::NodeDe::root(&doc.root)).map_err(de::DeError::finish)?;
    if let Some(err) = doc.surrogate {
        return Err(err);
    }
    Ok(value)
}

/// Decodes `data` into a free-form value: [`unmarshal`] into
/// [`serde_json::Value`], which every JSON value fits.
pub fn parse(data: &[u8], limits: Limits) -> Result<serde_json::Value, Error> {
    unmarshal(data, limits)
}

pub(crate) use parse::{Document, Node, Number, V};
