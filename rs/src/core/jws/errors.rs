//! The reasons a JWS, a JWK or a key set is rejected.

use std::fmt;

macro_rules! reasons {
    ($($(#[$doc:meta])* $variant:ident = $text:literal,)+) => {
        /// The stable name of why a JWS, a JWK or a key set was rejected. The
        /// same names appear as `reject_reason` in the shared vectors under
        /// `spec/v1.0/fixtures/vectors/jws`, so every SDK reports the same
        /// reason for the same input.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Reason {
            $($(#[$doc])* $variant,)+
        }

        impl Reason {
            /// Every reason, in the order the verifier checks them.
            pub const ALL: &'static [Reason] = &[$(Reason::$variant),+];

            /// The reason's name, as the vectors write it.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Reason::$variant => $text,)+
                }
            }
        }
    };
}

reasons! {
    /// The compact serialization is longer than the limit.
    CompactSize = "compact-size",
    /// Not three segments separated by two periods, or an empty protected
    /// header segment.
    CompactForm = "compact-form",
    /// A segment is not canonical unpadded base64url.
    Base64URL = "base64url",
    /// The protected header is not a strict JSON object, or `kid` is not a
    /// string.
    HeaderJSON = "header-json",
    /// The header has `crit`.
    HeaderCrit = "header-crit",
    /// The header has `b64` (RFC 7797).
    HeaderB64 = "header-b64",
    /// The header has `jku`.
    HeaderJKU = "header-jku",
    /// The header has `x5u`.
    HeaderX5U = "header-x5u",
    /// The header has `x5c`.
    HeaderX5C = "header-x5c",
    /// `alg` is missing or not an algorithm the verifier accepts.
    AlgUnsupported = "alg-unsupported",
    /// `typ` is missing or not in the draft 7.3 table.
    TypUnsupported = "typ-unsupported",
    /// `typ` is in the table but is not the one the caller expects.
    TypMismatch = "typ-mismatch",
    /// A service-signed artifact, or a key of a key set, has no `kid`.
    KidMissing = "kid-missing",
    /// `kid` is not in the key set trusted for the signer role.
    KidUnknown = "kid-unknown",
    /// Two keys of a key set share a `kid`.
    KidDuplicate = "kid-duplicate",
    /// A holder-signed artifact embeds no `jwk`.
    JWKMissing = "jwk-missing",
    /// A service-signed artifact embeds a `jwk`.
    JWKUnexpected = "jwk-unexpected",
    /// A JWK carries a private member.
    JWKPrivate = "jwk-private",
    /// A JWK is not a JSON object, a member has the wrong JSON type, a
    /// coordinate is not the canonical base64url of 32 octets, or `key_ops`
    /// names an operation twice.
    JWKInvalid = "jwk-invalid",
    /// `kty` is not `EC` or `crv` is not `P-256`.
    JWKCurve = "jwk-curve",
    /// `x` and `y` are not a point of P-256.
    JWKOffCurve = "jwk-off-curve",
    /// The JWK's `alg`, `use` or `key_ops` do not allow verification with
    /// the header's algorithm.
    JWKUsage = "jwk-usage",
    /// The thumbprint of the embedded `jwk` is not the expected `holder_jkt`.
    HolderJKTMismatch = "holder-jkt-mismatch",
    /// No resolver, the resolver failed, or it has no expected `holder_jkt`.
    KeyUnavailable = "key-unavailable",
    /// The payload segment is empty.
    PayloadDetached = "payload-detached",
    /// The payload is not a strict JSON object.
    PayloadJSON = "payload-json",
    /// The signature is not 64 octets.
    SignatureLength = "signature-length",
    /// The signature does not verify over the received signing input.
    SignatureInvalid = "signature-invalid",
    /// The signer was given a key that is not the public part of its `jwk`.
    SigningKey = "signing-key",
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jws: {}", self.as_str())
    }
}

/// The error of this module: its [`Reason`], what was found, and the
/// underlying cause when there is one.
#[derive(Debug)]
pub struct Error {
    pub reason: Reason,
    /// What was found, such as the member name or the octet count.
    pub detail: String,
    /// The underlying cause, such as a strictjson error or a resolver error.
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reason.fmt(f)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        if let Some(s) = &self.source {
            write!(f, ": {s}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|s| s as &(dyn std::error::Error + 'static))
    }
}

/// The reason of `err` when it is an [`Error`] of this module.
pub fn reason_of(err: &(dyn std::error::Error + 'static)) -> Option<Reason> {
    err.downcast_ref::<Error>().map(|e| e.reason)
}

pub(crate) fn fail(reason: Reason, detail: impl Into<String>) -> Error {
    Error { reason, detail: detail.into(), source: None }
}

pub(crate) fn fail_by<E: std::error::Error + Send + Sync + 'static>(
    reason: Reason,
    detail: impl Into<String>,
    cause: E,
) -> Error {
    Error { reason, detail: detail.into(), source: Some(Box::new(cause)) }
}
