//! The digests of draft section 7.4: `object_digest`, `artifact_digest` and
//! `bytes_digest`, each the unpadded base64url SHA-256 of its input.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::Digest;
use super::jcs;

/// Why a digest could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The value does not encode to a JSON object.
    NotObject,
    /// The value does not encode to JSON.
    Encode(String),
    /// The encoded value is not strict JSON (for example an integer outside
    /// ±(2^53-1), or an object nested deeper than 16).
    Canonicalize(jcs::Error),
    /// An artifact has a byte outside ASCII.
    NotAscii { byte: u8, offset: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotObject => f.write_str("digest: value is not a JSON object"),
            Error::Encode(e) => write!(f, "digest: encode: {e}"),
            Error::Canonicalize(e) => write!(f, "digest: {e}"),
            Error::NotAscii { byte, offset } => {
                write!(f, "digest: artifact has non-ASCII byte 0x{byte:02x} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Returns `object_digest(v)`: the base64url SHA-256 of the RFC 8785
/// canonical form of the JSON encoding of `v`, which must be a JSON object.
///
/// For JSON received from a peer, digest the received text with
/// [`object_digest_json`] instead of a value decoded from it, so that nothing
/// is lost in between. A non-finite `f64` encodes as `null` (serde_json); the
/// PACT wire types hold none.
pub fn object_digest<T: Serialize + ?Sized>(v: &T) -> Result<Digest, Error> {
    let text = serde_json::to_vec(v).map_err(|e| Error::Encode(e.to_string()))?;
    object_digest_json(&text)
}

/// Returns `object_digest` of the JSON text `data`, which must be an object:
/// the base64url SHA-256 of its RFC 8785 canonical form.
pub fn object_digest_json(data: &[u8]) -> Result<Digest, Error> {
    let first = data.iter().find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    if first != Some(&b'{') {
        return Err(Error::NotObject);
    }
    let canonical = jcs::canonicalize(data).map_err(Error::Canonicalize)?;
    Ok(bytes_digest(&canonical))
}

/// Returns `artifact_digest(s)`: the base64url SHA-256 of the ASCII bytes of
/// the compact JWS `s`, exactly as given.
pub fn artifact_digest(s: &str) -> Result<Digest, Error> {
    if let Some((offset, &byte)) = s.as_bytes().iter().enumerate().find(|(_, b)| !b.is_ascii()) {
        return Err(Error::NotAscii { byte, offset });
    }
    Ok(bytes_digest(s.as_bytes()))
}

/// Returns `bytes_digest(b)`: the base64url SHA-256 of `b`, without padding.
pub fn bytes_digest(b: &[u8]) -> Digest {
    Digest(URL_SAFE_NO_PAD.encode(Sha256::digest(b)))
}
