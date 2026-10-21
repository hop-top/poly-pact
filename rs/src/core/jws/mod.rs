//! The compact JWS of PACT signed artifacts: the profile of draft sections
//! 7.2 and 7.3 over RFC 7515, with ES256 (ECDSA P-256 and SHA-256, RFC 7518
//! section 3.4), the baseline and only algorithm this SDK implements.
//!
//! [`Verifier::verify`] checks a compact JWS in this order and stops at the
//! first failure, whose [`Reason`] it returns inside an [`Error`]:
//!
//! 1. the length bound ([`DEFAULT_MAX_COMPACT_BYTES`]), then three segments
//!    separated by two periods with a non-empty header segment;
//! 2. the header segment is canonical unpadded base64url and a strict JSON
//!    object;
//! 3. no `crit`, `b64`, `jku`, `x5u` or `x5c` member; `alg` is accepted;
//!    `typ` is in the draft 7.3 table and, when [`Verifier::typ`] is set,
//!    equals it; `kid`, if present, is a string; other members are ignored;
//! 4. by the signer role of `typ`: a holder-signed artifact embeds a `jwk`
//!    that [`parse_jwk`] accepts; any other artifact has a `kid` and no `jwk`;
//! 5. the payload segment is not empty, is canonical base64url and a strict
//!    JSON object;
//! 6. the signature segment is canonical base64url of exactly 64 octets;
//! 7. the key: for a holder, the embedded `jwk`'s RFC 7638 thumbprint equals
//!    the `holder_jkt` the [`KeyResolver`] expects; otherwise `kid` is found
//!    in the key set the resolver trusts for the role, and nowhere else;
//! 8. the signature over the received signing input, the compact text up to
//!    its second period. Nothing is decoded and re-encoded to rebuild it.
//!
//! A high S is accepted, since neither RFC 7518 nor the draft has a low-S
//! rule. [`sign`] writes signatures with a random nonce and a low S.
//!
//! `verify` checks the JWS, not the artifact: decode [`ParsedJWS::payload`]
//! with [`crate::core::strictjson`] into its core type and apply the schema,
//! time and authority rules separately.

mod base64url;
mod errors;
mod jwk;
mod keys;
mod typ;

use std::collections::BTreeMap;

use getrandom::SysRng;
use p256::ecdsa::signature::{RandomizedSigner, Verifier as _};
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;

pub use errors::{Error, Reason, reason_of};
pub use jwk::{Algorithms, JWK, parse_jwk, public_jwk, thumbprint};
pub use keys::{KeyRequest, KeyResolver, KeySet, ResolverError, StaticResolver};
/// The P-256 crate the signing and verifying keys come from, re-exported so
/// that a caller names the same version.
pub use p256;
pub use typ::*;

use base64url::{decode_segment, encode};
use errors::{fail, fail_by};
use keys::TrustedKey;

use crate::core::Digest;
use crate::core::strictjson::{self, Limits};

/// The bound of a compact JWS before any decoding: 360448 bytes, the draft
/// 20.1 transport frame minimum.
pub const DEFAULT_MAX_COMPACT_BYTES: usize = 360448;

/// The protected header of a PACT JWS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// `ES256`; [`sign`] accepts it empty.
    pub alg: String,
    /// A `typ` of the draft 7.3 table.
    pub typ: String,
    /// The signing key within the trusted key set of a service-signed
    /// artifact; optional for a holder-signed one.
    pub kid: String,
    /// The embedded public key of a holder-signed artifact.
    pub jwk: Option<JWK>,
}

/// A verified compact JWS.
#[derive(Clone, Debug)]
pub struct ParsedJWS {
    /// The input, unchanged.
    pub compact: String,
    pub header: Header,
    /// The signer role of `header.typ`.
    pub role: Role,
    /// The decoded protected header, exactly as received.
    pub raw_header: Vec<u8>,
    /// The decoded payload, exactly as received. Compute digests over these
    /// bytes or over `compact`, never over a re-encoding.
    pub payload: Vec<u8>,
    /// The received text the signature covers.
    pub signing_input: String,
    /// The 64 octets of the signature, R || S.
    pub signature: Vec<u8>,
    /// The key that verified the signature, and its RFC 7638 thumbprint.
    pub key: JWK,
    pub key_thumbprint: Digest,
}

/// Verifies compact JWS. Zero `max_compact_bytes` and default `limits` select
/// the defaults.
#[derive(Clone, Copy, Default)]
pub struct Verifier<'a> {
    /// Resolves the verification key. Required.
    pub keys: Option<&'a dyn KeyResolver>,
    /// When set, the only `typ` accepted: the one the caller's slot expects.
    pub typ: &'a str,
    /// The bound of the compact serialization.
    pub max_compact_bytes: usize,
    /// The bounds of the strict decoding of the header and payload.
    pub limits: Limits,
    /// The negotiated algorithms; empty is the baseline, ES256 alone.
    pub algorithms: Option<&'a Algorithms>,
}

/// `Verifier { keys: Some(keys), ..Default::default() }.verify(compact)`.
pub fn verify(compact: &str, keys: &dyn KeyResolver) -> Result<ParsedJWS, Error> {
    Verifier { keys: Some(keys), ..Verifier::default() }.verify(compact)
}

type Members = BTreeMap<String, serde_json::Value>;

/// The header members the profile rejects, in the order checked.
const PROHIBITED: [(&str, Reason); 5] = [
    ("crit", Reason::HeaderCrit),
    ("b64", Reason::HeaderB64),
    ("jku", Reason::HeaderJKU),
    ("x5u", Reason::HeaderX5U),
    ("x5c", Reason::HeaderX5C),
];

impl Verifier<'_> {
    /// Checks `compact` against the PACT JWS profile and the signature over
    /// its received signing input; see the module documentation for the
    /// order of the checks.
    pub fn verify(&self, compact: &str) -> Result<ParsedJWS, Error> {
        let default_algs = Algorithms::default();
        let algs = self.algorithms.unwrap_or(&default_algs);
        let limit = if self.max_compact_bytes == 0 { DEFAULT_MAX_COMPACT_BYTES } else { self.max_compact_bytes };
        if compact.len() > limit {
            return Err(fail(Reason::CompactSize, format!("{} bytes, limit {limit}", compact.len())));
        }
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(fail(Reason::CompactForm, "want three segments separated by two periods"));
        }
        let (h64, p64, s64) = (parts[0], parts[1], parts[2]);
        if h64.is_empty() {
            return Err(fail(Reason::CompactForm, "empty protected header"));
        }
        let raw_header = decode_segment(h64).map_err(|e| fail(Reason::Base64URL, format!("protected header: {e}")))?;
        let (mut h, members) = parse_header(&raw_header, self.limits, algs)?;
        if !self.typ.is_empty() && h.typ != self.typ {
            return Err(fail(Reason::TypMismatch, format!("typ {:?}, want {:?}", h.typ, self.typ)));
        }
        let role = typ_role(&h.typ).unwrap_or(Role::Holder);
        match (role, members.get("jwk")) {
            (Role::Holder, None) => {
                return Err(fail(Reason::JWKMissing, "a holder-signed artifact embeds its public jwk"));
            }
            (Role::Holder, Some(raw)) => {
                let text = serde_json::to_vec(raw).unwrap_or_default();
                let k = algs.parse_jwk(&text)?;
                match_alg(&h.alg, &k)?;
                h.jwk = Some(k);
            }
            (_, Some(_)) => {
                return Err(fail(
                    Reason::JWKUnexpected,
                    format!("typ {} is verified by kid, not by an embedded jwk", h.typ),
                ));
            }
            (_, None) if h.kid.is_empty() => return Err(fail(Reason::KidMissing, "")),
            _ => {}
        }
        if p64.is_empty() {
            return Err(fail(Reason::PayloadDetached, ""));
        }
        let payload = decode_segment(p64).map_err(|e| fail(Reason::Base64URL, format!("payload: {e}")))?;
        strictjson::unmarshal::<Members>(&payload, self.limits).map_err(|e| fail_by(Reason::PayloadJSON, "", e))?;
        let sig = decode_segment(s64).map_err(|e| fail(Reason::Base64URL, format!("signature: {e}")))?;
        if sig.len() != 64 {
            return Err(fail(Reason::SignatureLength, format!("{} octets, want 64", sig.len())));
        }
        let req = KeyRequest { typ: &h.typ, role, kid: &h.kid, header: &raw_header, payload: &payload };
        let key = self.resolve(&req, h.jwk.as_ref(), algs)?;
        match_alg(&h.alg, &key.jwk)?;
        let signing_input = &compact[..h64.len() + 1 + p64.len()];
        let valid = Signature::from_slice(&sig).is_ok_and(|s| key.key.verify(signing_input.as_bytes(), &s).is_ok());
        if !valid {
            return Err(fail(Reason::SignatureInvalid, ""));
        }
        Ok(ParsedJWS {
            compact: compact.to_string(),
            header: h,
            role,
            raw_header,
            payload,
            signing_input: signing_input.to_string(),
            signature: sig,
            key: key.jwk,
            key_thumbprint: key.thumbprint,
        })
    }

    fn resolve(&self, req: &KeyRequest<'_>, embedded: Option<&JWK>, algs: &Algorithms) -> Result<TrustedKey, Error> {
        let Some(keys) = self.keys else {
            return Err(fail(Reason::KeyUnavailable, "no key resolver"));
        };
        if req.role == Role::Holder {
            let want = keys.holder_jkt(req).map_err(|e| Error {
                reason: Reason::KeyUnavailable,
                detail: "holder_jkt".into(),
                source: Some(e),
            })?;
            if want.is_empty() {
                return Err(fail(Reason::KeyUnavailable, "no expected holder_jkt"));
            }
            let k = TrustedKey::new(embedded.cloned().unwrap_or_default(), algs)?;
            if k.thumbprint != want {
                return Err(fail(
                    Reason::HolderJKTMismatch,
                    format!("jwk thumbprint {}, expected {want}", k.thumbprint),
                ));
            }
            return Ok(k);
        }
        let set = keys.trusted_keys(req).map_err(|e| Error {
            reason: Reason::KeyUnavailable,
            detail: format!("key set for {}", req.role),
            source: Some(e),
        })?;
        set.and_then(|s| s.trusted(req.kid)).cloned().ok_or_else(|| {
            fail(Reason::KidUnknown, format!("kid {:?} is not in the key set trusted for {}", req.kid, req.role))
        })
    }
}

/// Checks that the header `alg` is the algorithm of the checked key `k`.
fn match_alg(alg: &str, k: &JWK) -> Result<(), Error> {
    let key_alg = k.algorithm()?;
    if key_alg == alg {
        return Ok(());
    }
    let kid = if k.kid.is_empty() { String::new() } else { format!(" (kid {:?})", k.kid) };
    Err(fail(
        Reason::JWKUsage,
        format!("alg {alg}, but the key{kid} is kty {} crv {}, a key for {key_alg}", k.kty, k.crv),
    ))
}

fn describe(name: &str, m: &Members) -> String {
    match m.get(name) {
        None => format!("no {name}"),
        Some(v) => {
            let mut s = v.to_string();
            if s.len() > 64 {
                let mut end = 64;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                s.truncate(end);
            }
            format!("{name} {s}")
        }
    }
}

/// Decodes the protected header strictly and checks the members that do not
/// depend on the signer role.
fn parse_header(raw: &[u8], limits: Limits, algs: &Algorithms) -> Result<(Header, Members), Error> {
    let m: Members = strictjson::unmarshal(raw, limits).map_err(|e| fail_by(Reason::HeaderJSON, "", e))?;
    if let Some((name, reason)) = PROHIBITED.iter().find(|(n, _)| m.contains_key(*n)) {
        return Err(fail(*reason, format!("member {name}")));
    }
    let string = |name: &str| m.get(name).and_then(|v| v.as_str()).map(str::to_string);
    let alg =
        string("alg").filter(|a| algs.accepts(a)).ok_or_else(|| fail(Reason::AlgUnsupported, describe("alg", &m)))?;
    let typ = string("typ")
        .filter(|t| typ_role(t).is_some())
        .ok_or_else(|| fail(Reason::TypUnsupported, describe("typ", &m)))?;
    let kid = match m.get("kid") {
        None => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(_) => return Err(fail(Reason::HeaderJSON, "kid is not a string")),
    };
    Ok((Header { alg, typ, kid, jwk: None }, m))
}

/// The member order [`sign`] writes: `alg`, `typ`, `kid`, `jwk`, as in draft
/// Appendix C.
#[derive(Serialize)]
struct WireHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    kid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<&'a JWK>,
}

/// Returns the compact JWS of `payload` under `key` with the protected
/// header `h`. `h.alg` may be empty and is always written as ES256. For a
/// holder-signed `typ` the header embeds `h.jwk`, or the key's public JWK
/// when it is `None`; `h.jwk` must be that public key. Every other `typ`
/// needs `h.kid` and no `h.jwk`. `payload` must be a strict JSON object and
/// is signed exactly as given. The nonce mixes random bytes from the
/// operating system into the RFC 6979 derivation, so two calls give
/// different signatures; S is always the low value of the pair (S, n-S).
pub fn sign(h: &Header, payload: &[u8], key: &SigningKey) -> Result<String, Error> {
    if !h.alg.is_empty() && h.alg != ALG_ES256 {
        return Err(fail(Reason::AlgUnsupported, format!("alg {}", h.alg)));
    }
    let role = typ_role(&h.typ).ok_or_else(|| fail(Reason::TypUnsupported, format!("typ {}", h.typ)))?;
    let own = public_jwk(key.verifying_key());
    let embedded = match (role, &h.jwk) {
        (Role::Holder, None) => Some(own),
        (Role::Holder, Some(given)) => {
            let given_tp = thumbprint(given)?;
            given.check_usage(ALG_ES256)?;
            if given_tp != thumbprint(&own)? {
                return Err(fail(Reason::SigningKey, "jwk is not the public key of the signing key"));
            }
            Some(given.clone())
        }
        (_, Some(_)) => {
            return Err(fail(
                Reason::JWKUnexpected,
                format!("typ {} is verified by kid, not by an embedded jwk", h.typ),
            ));
        }
        (_, None) if h.kid.is_empty() => return Err(fail(Reason::KidMissing, "")),
        _ => None,
    };
    strictjson::unmarshal::<Members>(payload, Limits::default()).map_err(|e| fail_by(Reason::PayloadJSON, "", e))?;
    let wh = WireHeader { alg: ALG_ES256, typ: &h.typ, kid: &h.kid, jwk: embedded.as_ref() };
    let header = serde_json::to_vec(&wh).map_err(|e| fail_by(Reason::HeaderJSON, "", e))?;
    let signing_input = format!("{}.{}", encode(&header), encode(payload));
    let sig: Signature = key
        .try_sign_with_rng(&mut SysRng, signing_input.as_bytes())
        .map_err(|e| fail_by(Reason::SigningKey, "random nonce", e))?;
    let sig = sig.normalize_s();
    Ok(format!("{signing_input}.{}", encode(&sig.to_bytes())))
}
