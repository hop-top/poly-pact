"""The reasons and the error of the jws package. Mirrors go/core/jws/errors.go."""

from __future__ import annotations

from enum import StrEnum

from hop_top_pact.errors import PactError

__all__ = ["JWSError", "Reason", "reason_of"]


class Reason(StrEnum):
    """The stable name of why a JWS, a JWK or a key set was rejected.

    The values are the reject_reason names of the shared vectors under
    spec/v1.0/fixtures/vectors/jws, in the order of the Go package, so every SDK
    reports the same reason for the same input. str() of a member is its
    value.
    """

    COMPACT_SIZE = "compact-size"
    """The compact serialization is longer than the limit."""
    COMPACT_FORM = "compact-form"
    """Not three segments separated by two periods, or an empty protected header."""
    BASE64_URL = "base64url"
    """A segment is not canonical unpadded base64url: padding, white space, line
    breaks, the standard alphabet, a length of 1 mod 4 or non-zero spare bits."""
    HEADER_JSON = "header-json"
    """The protected header is not a strict JSON object (draft 7.1), or kid is not a string."""
    HEADER_CRIT = "header-crit"
    """The header has crit; the profile recognizes no critical header (draft 7.2)."""
    HEADER_B64 = "header-b64"
    """The header has b64 (RFC 7797); unencoded payloads are prohibited (draft 7.2)."""
    HEADER_JKU = "header-jku"
    """The header has jku (draft 7.2)."""
    HEADER_X5U = "header-x5u"
    """The header has x5u (draft 7.2)."""
    HEADER_X5C = "header-x5c"
    """The header has x5c; keys come only from the trusted key set or, for a holder,
    from the jwk that matches holder_jkt."""
    ALG_UNSUPPORTED = "alg-unsupported"
    """alg is missing or not an algorithm the verifier accepts (ES256)."""
    TYP_UNSUPPORTED = "typ-unsupported"
    """typ is missing or not in the draft 7.3 table."""
    TYP_MISMATCH = "typ-mismatch"
    """typ is in the table but is not the typ the caller expects (Verifier.typ)."""
    KID_MISSING = "kid-missing"
    """A service-signed artifact, or a key of a key set, has no kid."""
    KID_UNKNOWN = "kid-unknown"
    """kid is not in the key set trusted for the signer role."""
    KID_DUPLICATE = "kid-duplicate"
    """Two keys of a key set share a kid."""
    JWK_MISSING = "jwk-missing"
    """A holder-signed artifact embeds no jwk."""
    JWK_UNEXPECTED = "jwk-unexpected"
    """A service-signed artifact embeds a jwk."""
    JWK_PRIVATE = "jwk-private"
    """A JWK carries a private member (d, p, q, dp, dq, qi, oth or k)."""
    JWK_INVALID = "jwk-invalid"
    """A JWK is not a JSON object, a member has the wrong JSON type, x or y is not the
    canonical base64url of exactly 32 octets, or key_ops names an operation twice."""
    JWK_CURVE = "jwk-curve"
    """kty is not EC or crv is not P-256 (compared exactly)."""
    JWK_OFF_CURVE = "jwk-off-curve"
    """x and y are not a point of P-256."""
    JWK_USAGE = "jwk-usage"
    """The JWK's alg is not ES256, its use is not sig, its key_ops do not name verify,
    or the verifying key is not a key for the header's alg."""
    HOLDER_JKT_MISMATCH = "holder-jkt-mismatch"
    """The RFC 7638 thumbprint of the embedded jwk is not the expected holder_jkt."""
    KEY_UNAVAILABLE = "key-unavailable"
    """There is no resolver, the resolver failed, or it has no expected holder_jkt."""
    PAYLOAD_DETACHED = "payload-detached"
    """The payload segment is empty (draft 7.2)."""
    PAYLOAD_JSON = "payload-json"
    """The payload is not a strict JSON object (draft 7.1)."""
    SIGNATURE_LENGTH = "signature-length"
    """The signature is not 64 octets (RFC 7518 section 3.4)."""
    SIGNATURE_INVALID = "signature-invalid"
    """The signature does not verify over the received signing input under the key."""
    SIGNING_KEY = "signing-key"
    """sign was given no key, a key that is not P-256, or a jwk that is not the key's
    public part."""


class JWSError(PactError):
    """A JWS, a JWK or a key set was rejected for reason.

    detail says what was found, such as the member name or the octet count;
    the underlying cause (a strict JSON error, a resolver's exception) is
    __cause__, also readable as err.
    """

    def __init__(self, reason: Reason, detail: str = "", err: BaseException | None = None) -> None:
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail
        self.__cause__ = err

    @property
    def err(self) -> BaseException | None:
        """The underlying cause, or None."""
        return self.__cause__

    def __str__(self) -> str:
        s = f"jws: {self.reason}"
        if self.detail:
            s += f": {self.detail}"
        if self.__cause__ is not None:
            s += f": {self.__cause__}"
        return s


def reason_of(err: BaseException | None) -> Reason | None:
    """Return the Reason of err or of the first JWSError in its cause chain, or None.

    The chain is followed through __cause__, else __context__, of PactError
    instances only, as the package's other *_of functions do.
    """
    seen: set[int] = set()
    while isinstance(err, PactError) and id(err) not in seen:
        if isinstance(err, JWSError):
            return err.reason
        seen.add(id(err))
        err = err.__cause__ if err.__cause__ is not None else err.__context__
    return None
