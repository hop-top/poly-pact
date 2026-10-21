//! The PACT core: the wire objects of the protocol and the primitives every
//! implementation shares.
//!
//! - [`strictjson`]: strict decoding (draft section 7.1);
//! - [`jcs`] and [`digest`]: RFC 8785 canonical JSON and the object, artifact
//!   and bytes digests (section 7.4);
//! - [`jws`]: the compact JWS profile with ES256, JWKs, key resolution and
//!   RFC 7638 thumbprints (sections 7.2 and 7.3);
//! - [`clock`]: time windows and lifetimes (section 20.1);
//! - [`schema`]: validation against the vendored PACT JSON Schema.
//!
//! The wire types are re-exported here: [`AgentProfile`], [`Presentation`],
//! [`Evidence`] and the rest, one per `$defs` entry of the schema.

pub mod clock;
pub mod digest;
mod enums;
pub mod jcs;
pub mod jws;
mod limits;
mod reputation;
pub mod schema;
pub mod strictjson;
mod types;
mod uri;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

pub use enums::*;
pub use limits::*;
pub use reputation::*;
pub use types::*;

/// An open JSON object: the `attributes` and `extensions` members, where the
/// schema allows any member.
pub type Object = BTreeMap<String, serde_json::Value>;

/// The length of a base64url SHA-256 value without padding.
pub const DIGEST_LEN: usize = 43;

/// A base64url (RFC 4648, no padding) SHA-256 value, such as an object
/// digest or a JWK thumbprint. The schema pattern is `^[A-Za-z0-9_-]{43}$`.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(pub String);

impl Digest {
    /// The digest text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the digest is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks that the digest is exactly 43 base64url characters.
    pub fn validate(&self) -> Result<(), DigestError> {
        if self.0.len() != DIGEST_LEN {
            return Err(DigestError(format!("core: digest has {} bytes, want {DIGEST_LEN}", self.0.len())));
        }
        if let Some((i, c)) =
            self.0.bytes().enumerate().find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_'))
        {
            return Err(DigestError(format!("core: digest has invalid character {:?} at offset {i}", c as char)));
        }
        Ok(())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for Digest {
    fn from(s: String) -> Digest {
        Digest(s)
    }
}

impl From<&str> for Digest {
    fn from(s: &str) -> Digest {
        Digest(s.to_string())
    }
}

impl PartialEq<str> for Digest {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Digest {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A digest that is not 43 base64url characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestError(String);

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DigestError {}
