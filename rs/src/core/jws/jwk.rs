//! JSON Web Keys (RFC 7517) for ES256: parsing, checking, the public JWK of a
//! key, and the RFC 7638 thumbprint.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::base64url::decode_segment;
use super::errors::{Error, Reason, fail, fail_by};
use super::typ::{ALG_ED25519, ALG_ES256};
use crate::core::Digest;
use crate::core::strictjson::{self, Limits};

/// The JOSE algorithms a deployment accepts for its signed artifacts (draft
/// 7.2). Empty is the baseline, ES256 alone. ES256 is the only algorithm this
/// SDK implements: any other entry, Ed25519 included, never matches a header
/// or a key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Algorithms(pub Vec<String>);

impl Algorithms {
    /// The algorithms of a list.
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(algs: I) -> Algorithms {
        Algorithms(algs.into_iter().map(Into::into).collect())
    }

    /// Whether `alg` is accepted: ES256, when the list is empty or names it.
    pub fn accepts(&self, alg: &str) -> bool {
        alg == ALG_ES256 && (self.0.is_empty() || self.0.iter().any(|a| a == alg))
    }

    /// [`parse_jwk`] for these algorithms.
    pub fn parse_jwk(&self, data: &[u8]) -> Result<JWK, Error> {
        parse_jwk_with(data, self)
    }

    /// [`super::KeySet::new`] for these algorithms.
    pub fn new_key_set<I: IntoIterator<Item = JWK>>(&self, keys: I) -> Result<super::KeySet, Error> {
        super::KeySet::with_algorithms(self, keys)
    }
}

/// A public key in JSON Web Key form: an EC P-256 key (RFC 7518 section
/// 6.2.1). `kid`, `alg` and `use` are optional and written only when set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct JWK {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub y: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub alg: String,
    #[serde(rename = "use", skip_serializing_if = "String::is_empty")]
    pub use_: String,
}

/// The private members of RFC 7518 section 6.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Decodes a JWK and checks that it is a usable ES256 public key: a strict
/// JSON object without private members, `kty` `EC`, `crv` `P-256`, `x` and
/// `y` the canonical unpadded base64url of 32 octets each and together a
/// point of the curve, `alg` and `use`, when present, `ES256` and `sig`, and
/// `key_ops`, when present, an array of distinct strings that names
/// `verify`. Other members are ignored (RFC 7517 section 4).
pub fn parse_jwk(data: &[u8]) -> Result<JWK, Error> {
    parse_jwk_with(data, &Algorithms::default())
}

fn parse_jwk_with(data: &[u8], algs: &Algorithms) -> Result<JWK, Error> {
    let m: BTreeMap<String, serde_json::Value> = strictjson::unmarshal(data, Limits::default())
        .map_err(|e| fail_by(Reason::JWKInvalid, "not a strict JSON object", e))?;
    if let Some(name) = PRIVATE_MEMBERS.iter().find(|n| m.contains_key(**n)) {
        return Err(fail(Reason::JWKPrivate, format!("member {name}")));
    }
    let mut k = JWK::default();
    for (name, dst) in [
        ("kty", &mut k.kty),
        ("crv", &mut k.crv),
        ("x", &mut k.x),
        ("y", &mut k.y),
        ("kid", &mut k.kid),
        ("alg", &mut k.alg),
        ("use", &mut k.use_),
    ] {
        match m.get(name) {
            None => {}
            Some(serde_json::Value::String(s)) => *dst = s.clone(),
            Some(_) => return Err(fail(Reason::JWKInvalid, format!("{name} is not a string"))),
        }
    }
    k.check(algs)?;
    if let Some(ops) = m.get("key_ops") {
        check_key_ops(ops)?;
    }
    Ok(k)
}

/// Checks a `key_ops` member (RFC 7517 section 4.3): an array of distinct
/// strings that names `verify`.
fn check_key_ops(v: &serde_json::Value) -> Result<(), Error> {
    let ops: Vec<&str> = match v.as_array() {
        Some(a) if a.iter().all(|o| o.is_string()) => a.iter().filter_map(|o| o.as_str()).collect(),
        _ => return Err(fail(Reason::JWKInvalid, "key_ops is not an array of strings")),
    };
    for (i, op) in ops.iter().enumerate() {
        if ops[..i].contains(op) {
            return Err(fail(Reason::JWKInvalid, format!("key_ops names {op:?} twice")));
        }
    }
    if !ops.contains(&"verify") {
        return Err(fail(Reason::JWKUsage, format!("key_ops {ops:?} does not name verify")));
    }
    Ok(())
}

impl JWK {
    /// The one algorithm the key's `kty` and `crv` serve: ES256 for EC P-256,
    /// Ed25519 for OKP Ed25519. Other key types fail with
    /// [`Reason::JWKCurve`].
    pub fn algorithm(&self) -> Result<&'static str, Error> {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("EC", "P-256") => Ok(ALG_ES256),
            ("OKP", "Ed25519") => Ok(ALG_ED25519),
            _ => Err(fail(
                Reason::JWKCurve,
                format!("kty {:?} crv {:?}, want EC P-256 or, when negotiated, OKP Ed25519", self.kty, self.crv),
            )),
        }
    }

    /// Returns the algorithm of the key after checking that `algs` accepts
    /// it, that the key material is valid, and that `alg` and `use`, when
    /// present, are that algorithm and `sig`.
    pub(crate) fn check(&self, algs: &Algorithms) -> Result<&'static str, Error> {
        let alg = self.algorithm()?;
        if !algs.accepts(alg) {
            return Err(fail(
                Reason::JWKCurve,
                format!("kty {:?} crv {:?}: {alg} is not negotiated", self.kty, self.crv),
            ));
        }
        self.public_key()?;
        self.check_usage(alg)?;
        Ok(alg)
    }

    /// Checks `kty`, `crv`, `x` and `y` and returns the key. It does not look
    /// at `kid`, `alg` or `use`.
    pub fn public_key(&self) -> Result<VerifyingKey, Error> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(fail(Reason::JWKCurve, format!("kty {:?} crv {:?}, want EC P-256", self.kty, self.crv)));
        }
        let x = coordinate("x", &self.x)?;
        let y = coordinate("y", &self.y)?;
        let mut point = Vec::with_capacity(65);
        point.push(4);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&point).map_err(|e| fail_by(Reason::JWKOffCurve, "", e))
    }

    pub(crate) fn check_usage(&self, alg: &str) -> Result<(), Error> {
        if !self.alg.is_empty() && self.alg != alg {
            return Err(fail(Reason::JWKUsage, format!("alg {:?}, want {alg}", self.alg)));
        }
        if !self.use_.is_empty() && self.use_ != "sig" {
            return Err(fail(Reason::JWKUsage, format!("use {:?}, want sig", self.use_)));
        }
        Ok(())
    }
}

fn coordinate(name: &str, s: &str) -> Result<Vec<u8>, Error> {
    let b =
        decode_segment(s).map_err(|e| fail(Reason::JWKInvalid, format!("{name} is not canonical base64url: {e}")))?;
    if b.len() != 32 {
        return Err(fail(Reason::JWKInvalid, format!("{name} has {} octets, want 32", b.len())));
    }
    Ok(b)
}

/// The JWK of a P-256 public key, with `x` and `y` at their full 32 octets
/// (RFC 7518 section 6.2.1.2) and no optional members.
pub fn public_jwk(key: &VerifyingKey) -> JWK {
    let point = key.to_sec1_point(false);
    let b = point.as_bytes();
    JWK {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(&b[1..33]),
        y: URL_SAFE_NO_PAD.encode(&b[33..65]),
        ..JWK::default()
    }
}

/// The RFC 7638 SHA-256 thumbprint of `k`: unpadded base64url of SHA-256
/// over `{"crv":...,"kty":...,"x":...,"y":...}`, the required members in
/// lexicographic order without white space. `k` must be a valid P-256 key;
/// an OKP key fails with [`Reason::JWKCurve`], since this SDK has no Ed25519.
pub fn thumbprint(k: &JWK) -> Result<Digest, Error> {
    if k.algorithm()? != ALG_ES256 {
        return Err(fail(Reason::JWKCurve, "Ed25519 keys are not supported"));
    }
    k.public_key()?;
    // The values are base64url and fixed ASCII names: nothing needs escaping.
    let input = format!(r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#, k.crv, k.kty, k.x, k.y);
    Ok(Digest(URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))))
}
