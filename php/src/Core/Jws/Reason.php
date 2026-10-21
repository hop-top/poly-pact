<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * The stable name of why a JWS, a JWK or a key set was rejected: the Go
 * sentinels Err* of package jws, in its order.
 *
 * The values are the reject_reason names of the shared vectors under
 * spec/v1.0/fixtures/vectors/jws, so every SDK reports the same reason for
 * the same input.
 */
enum Reason: string
{
    /** The compact serialization is longer than the limit. */
    case COMPACT_SIZE = 'compact-size';
    /** Not three segments separated by two periods, or an empty protected header. */
    case COMPACT_FORM = 'compact-form';
    /**
     * A segment is not canonical unpadded base64url: padding, white space,
     * line breaks, the standard alphabet, a length of 1 mod 4 or non-zero
     * spare bits.
     */
    case BASE64_URL = 'base64url';
    /** The protected header is not a strict JSON object (draft 7.1), or kid is not a string. */
    case HEADER_JSON = 'header-json';
    /** The header has crit; the profile recognizes no critical header (draft 7.2). */
    case HEADER_CRIT = 'header-crit';
    /** The header has b64 (RFC 7797); unencoded payloads are prohibited (draft 7.2). */
    case HEADER_B64 = 'header-b64';
    /** The header has jku (draft 7.2). */
    case HEADER_JKU = 'header-jku';
    /** The header has x5u (draft 7.2). */
    case HEADER_X5U = 'header-x5u';
    /**
     * The header has x5c; keys come only from the trusted key set or, for a
     * holder, from the jwk that matches holder_jkt.
     */
    case HEADER_X5C = 'header-x5c';
    /** alg is missing or not an algorithm the verifier accepts (ES256). */
    case ALG_UNSUPPORTED = 'alg-unsupported';
    /** typ is missing or not in the draft 7.3 table. */
    case TYP_UNSUPPORTED = 'typ-unsupported';
    /** typ is in the table but is not the typ the caller expects (Verifier::$typ). */
    case TYP_MISMATCH = 'typ-mismatch';
    /** A service-signed artifact, or a key of a key set, has no kid. */
    case KID_MISSING = 'kid-missing';
    /** kid is not in the key set trusted for the signer role. */
    case KID_UNKNOWN = 'kid-unknown';
    /** Two keys of a key set share a kid. */
    case KID_DUPLICATE = 'kid-duplicate';
    /** A holder-signed artifact embeds no jwk. */
    case JWK_MISSING = 'jwk-missing';
    /** A service-signed artifact embeds a jwk. */
    case JWK_UNEXPECTED = 'jwk-unexpected';
    /** A JWK carries a private member (d, p, q, dp, dq, qi, oth or k). */
    case JWK_PRIVATE = 'jwk-private';
    /**
     * A JWK is not a JSON object, a member has the wrong JSON type, x or y is
     * not the canonical base64url of exactly 32 octets, or key_ops names an
     * operation twice.
     */
    case JWK_INVALID = 'jwk-invalid';
    /** kty is not EC or crv is not P-256 (compared exactly). */
    case JWK_CURVE = 'jwk-curve';
    /** x and y are not a point of P-256. */
    case JWK_OFF_CURVE = 'jwk-off-curve';
    /**
     * The JWK's alg is not ES256, its use is not sig, its key_ops do not name
     * verify, or the verifying key is not a key for the header's alg.
     */
    case JWK_USAGE = 'jwk-usage';
    /** The RFC 7638 thumbprint of the embedded jwk is not the expected holder_jkt. */
    case HOLDER_JKT_MISMATCH = 'holder-jkt-mismatch';
    /** There is no resolver, the resolver failed, or it has no expected holder_jkt. */
    case KEY_UNAVAILABLE = 'key-unavailable';
    /** The payload segment is empty (draft 7.2). */
    case PAYLOAD_DETACHED = 'payload-detached';
    /** The payload is not a strict JSON object (draft 7.1). */
    case PAYLOAD_JSON = 'payload-json';
    /** The signature is not 64 octets (RFC 7518 section 3.4). */
    case SIGNATURE_LENGTH = 'signature-length';
    /** The signature does not verify over the received signing input under the key. */
    case SIGNATURE_INVALID = 'signature-invalid';
    /**
     * sign was given no key, a key that is not a P-256 private key, or a jwk
     * that is not the key's public part; or a private key could not be built.
     */
    case SIGNING_KEY = 'signing-key';

    /** The text of the Go sentinel error: "jws: " and the value. */
    public function message(): string
    {
        return 'jws: ' . $this->value;
    }
}
