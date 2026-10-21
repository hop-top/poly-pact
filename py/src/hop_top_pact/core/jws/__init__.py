"""ES256 compact JWS profile, JWK, key resolution and RFC 7638 thumbprint (draft
sections 7.2 and 7.3 over RFC 7515). Mirrors hop.top/pact-go/core/jws.

ES256 (ECDSA P-256 and SHA-256, RFC 7518 section 3.4) is the baseline and
the only algorithm of this package; Ed25519, which the Go package accepts
where it is negotiated, is not implemented; thumbprint computes the RFC 8037
thumbprint of an OKP Ed25519 key without checking its point.

Verification (verify, Verifier.verify) checks a compact JWS in this order
and stops at the first failure, raising JWSError with its Reason:

1. the length bound (DEFAULT_MAX_COMPACT_BYTES, in UTF-8 octets), then three
   segments separated by two periods with a non-empty header segment;
2. the header segment is canonical unpadded base64url and a strict JSON
   object (core.strictjson: no duplicate members, valid Unicode, bounded
   depth);
3. no crit, b64, jku, x5u or x5c member; alg is ES256; typ is in the draft
   7.3 table and, when Verifier.typ is set, equals it; kid, if present, is a
   string. Other members are ignored (RFC 7515 section 4);
4. by the signer role of typ: a holder-signed artifact embeds a jwk that
   parse_jwk accepts; any other artifact has a kid and no jwk;
5. the payload segment is not empty (no detached payload), is canonical
   base64url and a strict JSON object;
6. the signature segment is canonical base64url of exactly 64 octets;
7. the key: for a holder, the embedded jwk's thumbprint equals the
   holder_jkt the KeyResolver expects; otherwise kid is found in the key set
   the resolver trusts for the role, and nowhere else;
8. the ECDSA signature over the received signing input, the compact text up
   to its second period. Nothing is decoded and re-encoded to rebuild it.
   cryptography's InvalidSignature, and its ValueError for R or S out of
   range, are signature-invalid. A high S is accepted: neither RFC 7518 nor
   the draft has a low-S rule.

verify checks the JWS, not the artifact: decode ParsedJWS.payload with
core.strictjson into its wire type and apply the schema, time and authority
rules separately. sign writes only low-S signatures, and a header text equal
to the one the Go package writes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from hop_top_pact.core import strictjson
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.jws.errors import JWSError, Reason, reason_of
from hop_top_pact.core.jws.jwk import (
    JWK,
    _check_usage,
    _decode_object,
    _jwk_from_object,
    parse_jwk,
    public_jwk,
    public_key_of,
    thumbprint,
)
from hop_top_pact.core.jws.keys import (
    KeyRequest,
    KeyResolver,
    KeySet,
    StaticResolver,
    _trusted_key,
    _TrustedKey,
    new_key_set,
)
from hop_top_pact.core.jws.typ import (
    ALG_ED25519,
    ALG_ES256,
    TYP_ADMISSION,
    TYP_EVIDENCE,
    TYP_LEARNING_ARTIFACT,
    TYP_LEARNING_EVENT,
    TYP_LEARNING_POLICY,
    TYP_OUTCOME,
    TYP_PRESENTATION,
    TYP_REPUTATION,
    TYP_REQUIREMENTS,
    Role,
    typ_role,
    typs,
)
from hop_top_pact.core.types import JSONObject

__all__ = [
    "ALG_ED25519",
    "ALG_ES256",
    "DEFAULT_MAX_COMPACT_BYTES",
    "JWK",
    "TYP_ADMISSION",
    "TYP_EVIDENCE",
    "TYP_LEARNING_ARTIFACT",
    "TYP_LEARNING_EVENT",
    "TYP_LEARNING_POLICY",
    "TYP_OUTCOME",
    "TYP_PRESENTATION",
    "TYP_REPUTATION",
    "TYP_REQUIREMENTS",
    "Header",
    "JWSError",
    "KeyRequest",
    "KeyResolver",
    "KeySet",
    "ParsedJWS",
    "Reason",
    "Role",
    "StaticResolver",
    "Verifier",
    "new_key_set",
    "parse_jwk",
    "public_jwk",
    "public_key_of",
    "reason_of",
    "sign",
    "thumbprint",
    "typ_role",
    "typs",
    "verify",
]

DEFAULT_MAX_COMPACT_BYTES: Final = 360448
"""The bound of a compact JWS before any decoding: the draft 20.1 transport frame
minimum, which holds the base64url of a 256 KiB payload (349526) plus 10922 bytes
for the JOSE header and signature."""

# The order of P-256 (SEC 2, section 2.4.2).
_N: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_SIGNATURE_OCTETS: Final = 64
_COORDINATE_OCTETS: Final = 32
# The header members the profile rejects, in the order checked.
_PROHIBITED: Final = (
    ("crit", Reason.HEADER_CRIT),
    ("b64", Reason.HEADER_B64),
    ("jku", Reason.HEADER_JKU),
    ("x5u", Reason.HEADER_X5U),
    ("x5c", Reason.HEADER_X5C),
)


@dataclass(frozen=True, slots=True)
class Header:
    """The protected header of a PACT JWS. All header members are protected (draft 7.2)."""

    alg: str = ""
    """ES256 (draft 7.2); sign accepts it empty."""
    typ: str = ""
    """A typ of the draft 7.3 table."""
    kid: str = ""
    """The signing key within the trusted key set of a service-signed artifact; for a
    holder-signed artifact optional, and no part of key selection."""
    jwk: JWK | None = None
    """The embedded public key of a holder-signed artifact, None otherwise."""


@dataclass(frozen=True, slots=True)
class ParsedJWS:
    """A verified compact JWS."""

    compact: str
    """The input, unchanged."""
    header: Header
    """The protected header members the profile defines."""
    role: Role
    """The signer role of header.typ."""
    raw_header: bytes
    """The decoded protected header, exactly as received."""
    payload: bytes
    """The decoded payload, exactly as received. Decode it with core.strictjson into the
    artifact type; compute digests over these bytes or over compact, never over a
    re-encoding."""
    signing_input: str
    """The received text the signature covers: compact up to its second period."""
    signature: bytes
    """The 64 octets R || S of the signature."""
    key: JWK
    """The key that verified the signature."""
    key_thumbprint: str
    """The RFC 7638 thumbprint of key."""


@dataclass(frozen=True, slots=True)
class Verifier:
    """Verifies compact JWS under the profile, with keys from keys.

    typ, when set (not None or empty), is the only typ accepted: the typ the
    caller's slot expects (draft 7.2: validators check the artifact-specific
    typ). max_compact_bytes bounds the compact serialization in UTF-8 octets;
    None or a value of 0 or less is DEFAULT_MAX_COMPACT_BYTES. limits bounds
    the strict decoding of the protected header and payload; None is the
    strictjson default.
    """

    keys: KeyResolver | None
    typ: str | None = None
    max_compact_bytes: int | None = None
    limits: strictjson.Limits | None = None

    def verify(self, compact: str) -> ParsedJWS:
        """Run the ordered checks of the profile (see the module documentation); raise
        JWSError on the first that fails."""
        limit = self.max_compact_bytes
        if limit is None or limit <= 0:
            limit = DEFAULT_MAX_COMPACT_BYTES
        size = len(compact) if compact.isascii() else len(compact.encode("utf-8", "surrogatepass"))
        if size > limit:
            raise JWSError(Reason.COMPACT_SIZE, f"{size} bytes, limit {limit}")
        first, last = compact.find("."), compact.rfind(".")
        if first < 0 or first == last or "." in compact[first + 1 : last]:
            raise JWSError(Reason.COMPACT_FORM, "want three segments separated by two periods")
        h64, p64, s64 = compact[:first], compact[first + 1 : last], compact[last + 1 :]
        if not h64:
            raise JWSError(Reason.COMPACT_FORM, "empty protected header")

        raw_header = _segment(h64, "protected header")
        header, role, members = _parse_header(raw_header, self.limits)
        if self.typ and header.typ != self.typ:
            raise JWSError(Reason.TYP_MISMATCH, f"typ {header.typ!r}, want {self.typ!r}")
        if role == Role.HOLDER:
            if "jwk" not in members:
                raise JWSError(Reason.JWK_MISSING, "a holder-signed artifact embeds its public jwk")
            k = _jwk_from_object(members["jwk"])
            _match_alg(header.alg, k)
            header = replace(header, jwk=k)
        else:
            if "jwk" in members:
                raise JWSError(
                    Reason.JWK_UNEXPECTED,
                    f"typ {header.typ} is verified by kid, not by an embedded jwk",
                )
            if not header.kid:
                raise JWSError(Reason.KID_MISSING)

        if not p64:
            raise JWSError(Reason.PAYLOAD_DETACHED)
        payload = _segment(p64, "payload")
        try:
            _decode_object(payload, self.limits)
        except strictjson.StrictJSONError as e:
            raise JWSError(Reason.PAYLOAD_JSON, "", e) from e

        sig = _segment(s64, "signature")
        if len(sig) != _SIGNATURE_OCTETS:
            raise JWSError(Reason.SIGNATURE_LENGTH, f"{len(sig)} octets, want {_SIGNATURE_OCTETS}")

        req = KeyRequest(
            typ=header.typ, role=role, kid=header.kid, header=raw_header, payload=payload
        )
        key = self._resolve(req, header.jwk)
        _match_alg(header.alg, key.jwk)
        signing_input = compact[:last]
        if not _verify_es256(key.pub, signing_input, sig):
            raise JWSError(Reason.SIGNATURE_INVALID)
        return ParsedJWS(
            compact=compact,
            header=header,
            role=role,
            raw_header=raw_header,
            payload=payload,
            signing_input=signing_input,
            signature=sig,
            key=key.jwk,
            key_thumbprint=key.thumbprint,
        )

    def _resolve(self, req: KeyRequest, embedded: JWK | None) -> _TrustedKey:
        if self.keys is None:
            raise JWSError(Reason.KEY_UNAVAILABLE, "no key resolver")
        if req.role == Role.HOLDER:
            if embedded is None:
                raise JWSError(Reason.JWK_MISSING, "a holder-signed artifact embeds its public jwk")
            try:
                want = self.keys.holder_jkt(req)
            except Exception as e:
                raise JWSError(Reason.KEY_UNAVAILABLE, "holder_jkt", e) from e
            if not want:
                raise JWSError(Reason.KEY_UNAVAILABLE, "no expected holder_jkt")
            k = _trusted_key(embedded)
            if k.thumbprint != want:
                raise JWSError(
                    Reason.HOLDER_JKT_MISMATCH,
                    f"jwk thumbprint {k.thumbprint}, expected {want}",
                )
            return k
        try:
            s = self.keys.trusted_keys(req)
        except Exception as e:
            raise JWSError(Reason.KEY_UNAVAILABLE, f"key set for {req.role}", e) from e
        t = s._trusted(req.kid) if s is not None else None
        if t is None:
            raise JWSError(
                Reason.KID_UNKNOWN,
                f"kid {req.kid!r} is not in the key set trusted for {req.role}",
            )
        return t


def verify(compact: str, keys: KeyResolver | None) -> ParsedJWS:
    """Verifier(keys=keys).verify(compact)."""
    return Verifier(keys=keys).verify(compact)


def _segment(s: str, name: str) -> bytes:
    try:
        return base64url.decode(s)
    except ValueError as e:
        raise JWSError(Reason.BASE64_URL, name, e) from e


def _parse_header(raw: bytes, limits: strictjson.Limits | None) -> tuple[Header, Role, JSONObject]:
    """Decode the protected header strictly and check the members that do not depend on
    the signer role. Members the profile does not define are ignored (RFC 7515
    section 4), except the prohibited ones."""
    try:
        m = _decode_object(raw, limits)
    except strictjson.StrictJSONError as e:
        raise JWSError(Reason.HEADER_JSON, "", e) from e
    for name, reason in _PROHIBITED:
        if name in m:
            raise JWSError(reason, "member " + name)
    alg = m.get("alg")
    if alg != ALG_ES256:
        raise JWSError(Reason.ALG_UNSUPPORTED, _describe("alg", m))
    typ = m.get("typ")
    role = typ_role(typ) if isinstance(typ, str) else None
    if not isinstance(typ, str) or role is None:
        raise JWSError(Reason.TYP_UNSUPPORTED, _describe("typ", m))
    kid = m.get("kid", "")
    if not isinstance(kid, str):
        raise JWSError(Reason.HEADER_JSON, "kid is not a string")
    return Header(alg=ALG_ES256, typ=typ, kid=kid), role, m


def _describe(name: str, m: JSONObject) -> str:
    if name not in m:
        return "no " + name
    return f"{name} {json.dumps(m[name], ensure_ascii=False)[:64]}"


def _match_alg(alg: str, k: JWK) -> None:
    """The header alg must be the algorithm of the checked key k: a key serves exactly
    one algorithm (RFC 9864 section 2.2, RFC 8037 section 2)."""
    key_alg = k.algorithm()
    if key_alg != alg:
        kid = f" (kid {k.kid!r})" if k.kid else ""
        raise JWSError(
            Reason.JWK_USAGE,
            f"alg {alg}, but the key{kid} is kty {k.kty} crv {k.crv}, a key for {key_alg}",
        )


def _verify_es256(pub: ec.EllipticCurvePublicKey, signing_input: str, sig: bytes) -> bool:
    """Verify a 64-octet R || S signature (RFC 7518 section 3.4) over the signing input.
    R and S outside [1, n-1] fail; a high S is accepted."""
    if len(sig) != _SIGNATURE_OCTETS:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    try:
        pub.verify(
            encode_dss_signature(r, s),
            signing_input.encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


# Characters Go's encoding/json escapes where json.dumps(ensure_ascii=False) does
# not: U+2028 and U+2029. An unpaired surrogate, which Python text can hold and
# UTF-8 cannot, is written as U+FFFD, as Go writes invalid UTF-8.
_SURROGATE: Final = re.compile("[\ud800-\udfff]")


def _json_string(s: str) -> str:
    """The JSON text of s as Go's encoding/json writes it with SetEscapeHTML(false)."""
    out = json.dumps(_SURROGATE.sub("\ufffd", s), ensure_ascii=False)
    return out.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _header_text(alg: str, typ: str, kid: str, jwk: JWK | None) -> bytes:
    """The protected header in the member order sign writes: alg, typ, kid, jwk, as in
    draft Appendix C; the jwk members kty, crv, x, y, kid, alg, use, the empty ones
    left out."""
    parts = [f'"alg":{_json_string(alg)}', f'"typ":{_json_string(typ)}']
    if kid:
        parts.append(f'"kid":{_json_string(kid)}')
    if jwk is not None:
        members = [
            f'"{name}":{_json_string(value)}'
            for name, value in (
                ("kty", jwk.kty),
                ("crv", jwk.crv),
                ("x", jwk.x),
                ("y", jwk.y),
                ("kid", jwk.kid),
                ("alg", jwk.alg),
                ("use", jwk.use),
            )
            if value or name in ("kty", "crv", "x")
        ]
        parts.append('"jwk":{' + ",".join(members) + "}")
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def sign(header: Header, payload: bytes, key: ec.EllipticCurvePrivateKey | None) -> str:
    """Return the compact JWS of payload under key with the protected header header.

    header.alg may be empty and is always written as ES256. For a
    holder-signed typ the header embeds header.jwk, or the key's public JWK
    when it is None; header.jwk must be that public key. Every other typ
    needs header.kid and no header.jwk. payload must be a strict JSON object
    and is signed exactly as given, never re-encoded. ECDSA signing is
    randomized, so two calls give different signatures; S is always the low
    value of the pair (S, n-S). Raises JWSError.
    """
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise JWSError(Reason.SIGNING_KEY, "no ECDSA private key")
    try:
        own = public_jwk(key.public_key())
    except JWSError as e:
        raise JWSError(Reason.SIGNING_KEY, "not a P-256 key", e) from e
    if header.alg and header.alg != ALG_ES256:
        raise JWSError(Reason.ALG_UNSUPPORTED, "alg " + header.alg)
    role = typ_role(header.typ)
    if role is None:
        raise JWSError(Reason.TYP_UNSUPPORTED, "typ " + header.typ)
    embedded: JWK | None = None
    if role == Role.HOLDER:
        embedded = own
        if header.jwk is not None:
            given = thumbprint(header.jwk)
            _check_usage(header.jwk, ALG_ES256)
            if given != thumbprint(own):
                raise JWSError(Reason.SIGNING_KEY, "jwk is not the public key of the signing key")
            embedded = header.jwk
    else:
        if header.jwk is not None:
            raise JWSError(
                Reason.JWK_UNEXPECTED,
                f"typ {header.typ} is verified by kid, not by an embedded jwk",
            )
        if not header.kid:
            raise JWSError(Reason.KID_MISSING)
    try:
        _decode_object(payload)
    except strictjson.StrictJSONError as e:
        raise JWSError(Reason.PAYLOAD_JSON, "", e) from e

    text = _header_text(ALG_ES256, header.typ, header.kid, embedded)
    signing_input = base64url.encode(text) + "." + base64url.encode(payload)
    r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    if s > _N >> 1:
        s = _N - s
    sig = r.to_bytes(_COORDINATE_OCTETS, "big") + s.to_bytes(_COORDINATE_OCTETS, "big")
    return signing_input + "." + base64url.encode(sig)
