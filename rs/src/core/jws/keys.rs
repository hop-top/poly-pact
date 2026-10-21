//! Trusted keys: key sets by `kid`, the key request of one verification, and
//! the resolvers that answer it. Keys come only from configuration; the
//! module never fetches them.

use std::collections::HashMap;

use p256::ecdsa::VerifyingKey;

use super::errors::{Error, Reason, fail};
use super::jwk::{Algorithms, JWK, thumbprint};
use super::typ::Role;
use crate::core::Digest;

/// The error of a resolver.
pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;

/// A checked key: the one algorithm it verifies, its key and its thumbprint.
#[derive(Clone, Debug)]
pub(crate) struct TrustedKey {
    pub(crate) jwk: JWK,
    pub(crate) key: VerifyingKey,
    pub(crate) thumbprint: Digest,
}

impl TrustedKey {
    pub(crate) fn new(k: JWK, algs: &Algorithms) -> Result<TrustedKey, Error> {
        k.check(algs)?;
        let key = k.public_key()?;
        let thumbprint = thumbprint(&k)?;
        Ok(TrustedKey { jwk: k, key, thumbprint })
    }
}

/// A set of trusted ES256 public keys, looked up by `kid`. It is built from
/// configuration, never from an artifact; the default set is empty.
#[derive(Clone, Debug, Default)]
pub struct KeySet {
    keys: HashMap<String, TrustedKey>,
}

impl KeySet {
    /// Checks each key as [`super::parse_jwk`] does and requires a non-empty
    /// `kid`, unique within the set.
    pub fn new<I: IntoIterator<Item = JWK>>(keys: I) -> Result<KeySet, Error> {
        KeySet::with_algorithms(&Algorithms::default(), keys)
    }

    pub(crate) fn with_algorithms<I: IntoIterator<Item = JWK>>(algs: &Algorithms, keys: I) -> Result<KeySet, Error> {
        let mut s = KeySet::default();
        for (i, k) in keys.into_iter().enumerate() {
            if k.kid.is_empty() {
                return Err(fail(Reason::KidMissing, format!("key {i} has no kid")));
            }
            if s.keys.contains_key(&k.kid) {
                return Err(fail(Reason::KidDuplicate, format!("kid {:?}", k.kid)));
            }
            let kid = k.kid.clone();
            s.keys.insert(kid, TrustedKey::new(k, algs)?);
        }
        Ok(s)
    }

    /// The key with the given `kid`.
    pub fn lookup(&self, kid: &str) -> Option<&JWK> {
        self.trusted(kid).map(|k| &k.jwk)
    }

    pub(crate) fn trusted(&self, kid: &str) -> Option<&TrustedKey> {
        if kid.is_empty() {
            return None;
        }
        self.keys.get(kid)
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set has no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The key one verification needs. It is built from the protected header and
/// payload after their structural checks and before the signature is
/// checked: nothing in it is authenticated yet. A resolver may use `header`
/// and `payload` only to choose which configured trust record applies, never
/// to obtain key material.
#[derive(Clone, Copy, Debug)]
pub struct KeyRequest<'a> {
    /// The artifact's `typ`.
    pub typ: &'a str,
    /// The signer role the draft 7.3 table requires for `typ`.
    pub role: Role,
    /// The header `kid`, empty when absent.
    pub kid: &'a str,
    /// The decoded protected header, as received.
    pub header: &'a [u8],
    /// The decoded payload, as received.
    pub payload: &'a [u8],
}

/// Supplies the trusted keys of a verification. The verifier calls exactly
/// one method, once: `holder_jkt` for [`Role::Holder`], `trusted_keys` for
/// every other role.
pub trait KeyResolver {
    /// The key set trusted for `req.role`; the header `kid` is looked up in
    /// it and nowhere else. `None` has no keys.
    fn trusted_keys(&self, req: &KeyRequest<'_>) -> Result<Option<&KeySet>, ResolverError>;

    /// The enrolled `holder_jkt` the embedded `jwk` of a holder-signed
    /// artifact must match (draft 6.2, 7.2).
    fn holder_jkt(&self, req: &KeyRequest<'_>) -> Result<Digest, ResolverError>;
}

/// A [`KeyResolver`] over fixed configuration: one key set per role and one
/// expected holder thumbprint.
#[derive(Clone, Debug, Default)]
pub struct StaticResolver {
    pub key_sets: HashMap<Role, KeySet>,
    pub expected_holder_jkt: Digest,
}

impl KeyResolver for StaticResolver {
    fn trusted_keys(&self, req: &KeyRequest<'_>) -> Result<Option<&KeySet>, ResolverError> {
        Ok(self.key_sets.get(&req.role))
    }

    fn holder_jkt(&self, _req: &KeyRequest<'_>) -> Result<Digest, ResolverError> {
        if self.expected_holder_jkt.is_empty() {
            return Err("no expected holder_jkt configured".into());
        }
        Ok(self.expected_holder_jkt.clone())
    }
}
