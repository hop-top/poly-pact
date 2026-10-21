<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\PactError;

/**
 * ES256 compact JWS profile, JWK, key resolution and RFC 7638 thumbprint
 * (draft sections 6.2, 7.2 and 7.3 over RFC 7515). Mirrors Go package
 * hop.top/pact-go/core/jws; the package functions are the static methods of
 * this class.
 *
 * ES256 (ECDSA P-256 and SHA-256, RFC 7518 section 3.4) is the baseline and
 * the only algorithm of this package. Ed25519, which the Go package accepts
 * where it is negotiated, is not implemented: an Ed25519 header is
 * ALG_UNSUPPORTED and an OKP Ed25519 key JWK_CURVE, as in a Go deployment
 * that has not negotiated it. thumbprint() computes the RFC 8037 thumbprint
 * of an OKP Ed25519 key without checking its point.
 *
 * See Verifier for the order of the checks. sign() writes only low-S
 * signatures, and a header text equal to the one the Go package writes.
 * Keys are ext-openssl keys (\OpenSSLAsymmetricKey); privateKey() and
 * parsePrivateJwk() build a signing key from a scalar or a private JWK.
 */
final class Jws
{
    /**
     * ES256 (ECDSA P-256 and SHA-256, RFC 7518 section 3.4): the baseline, and
     * the only algorithm this package signs and verifies.
     */
    public const string ALG_ES256 = 'ES256';

    /**
     * The fully specified Ed25519 identifier (RFC 9864 section 2.2), accepted
     * by the Go package only where it is negotiated. Not implemented here.
     */
    public const string ALG_ED25519 = 'Ed25519';

    /**
     * The bound of a compact JWS before any decoding: the draft 20.1
     * transport frame minimum, which holds the base64url of a 256 KiB
     * payload (349526) plus 10922 bytes for the JOSE header and signature.
     */
    public const int DEFAULT_MAX_COMPACT_BYTES = 360448;

    public const string TYP_REQUIREMENTS = 'pact-requirements+jwt';
    public const string TYP_EVIDENCE = 'pact-evidence+jwt';
    public const string TYP_PRESENTATION = 'pact-presentation+jwt';
    public const string TYP_ADMISSION = 'pact-admission+jwt';
    public const string TYP_OUTCOME = 'pact-outcome+jwt';
    public const string TYP_REPUTATION = 'pact-reputation+jwt';
    public const string TYP_LEARNING_POLICY = 'pact-learning-policy+jwt';
    public const string TYP_LEARNING_ARTIFACT = 'pact-learning-artifact+jwt';
    public const string TYP_LEARNING_EVENT = 'pact-learning-event+jwt';

    /** The draft 7.3 table, in its order: typ => Role value. */
    private const TYP_TABLE = [
        self::TYP_REQUIREMENTS => 'requirement-publisher',
        self::TYP_EVIDENCE => 'issuer',
        self::TYP_PRESENTATION => 'holder',
        self::TYP_ADMISSION => 'validator',
        self::TYP_OUTCOME => 'reporter',
        self::TYP_REPUTATION => 'reputation-service',
        self::TYP_LEARNING_POLICY => 'policy-authority',
        self::TYP_LEARNING_ARTIFACT => 'learning-controller',
        self::TYP_LEARNING_EVENT => 'learning-controller',
    ];

    private function __construct() {}

    /**
     * The signer role the draft 7.3 table requires for $typ, or null when
     * $typ is not in the table. $typ is compared exactly: case and an
     * "application/" prefix matter.
     */
    public static function typRole(string $typ): ?Role
    {
        $role = self::TYP_TABLE[$typ] ?? null;

        return $role === null ? null : Role::from($role);
    }

    /**
     * The typ values of the draft 7.3 table, in its order.
     *
     * @return list<string>
     */
    public static function typs(): array
    {
        return array_keys(self::TYP_TABLE);
    }

    /**
     * (new Verifier($keys))->verify($compact).
     *
     * @throws JwsError
     */
    public static function verify(string $compact, ?KeyResolver $keys): ParsedJws
    {
        return (new Verifier($keys))->verify($compact);
    }

    /**
     * The Reason of $err or of the first JwsError in its getPrevious() chain,
     * or null. The chain is followed through PactError instances only.
     */
    public static function reasonOf(?\Throwable $err): ?Reason
    {
        while ($err instanceof PactError) {
            if ($err instanceof JwsError) {
                return $err->reason;
            }
            $err = $err->getPrevious();
        }

        return null;
    }

    /**
     * Strict-parse the JWK text $data and check that it is a usable ES256
     * public key: a strict JSON object (draft 7.1) without private members,
     * kty EC, crv P-256, x and y the canonical unpadded base64url of 32
     * octets each and together a point of the curve, alg and use, when
     * present, ES256 and sig, and key_ops, when present, an array of
     * distinct strings that names verify (RFC 7517 section 4.3). key_ops is
     * checked, not kept. Members RFC 7517 does not define for this use are
     * ignored (RFC 7517 section 4).
     *
     * @throws JwsError
     */
    public static function parseJwk(string $data): Jwk
    {
        try {
            $m = JwkReader::object($data);
        } catch (StrictJsonError $e) {
            throw new JwsError(Reason::JWK_INVALID, 'not a strict JSON object', $e);
        }

        return JwkReader::fromValue($m);
    }

    /**
     * The Jwk of the public part of the P-256 key $key, public or private,
     * with x and y at their full 32 octets (RFC 7518 section 6.2.1.2) and no
     * optional members.
     *
     * @throws JwsError JWK_INVALID for null, JWK_CURVE for a key that is not P-256
     */
    public static function publicJwk(?\OpenSSLAsymmetricKey $key): Jwk
    {
        if ($key === null) {
            throw new JwsError(Reason::JWK_INVALID, 'no public key');
        }
        $c = Es256::coordinates($key);
        if ($c === null) {
            throw new JwsError(Reason::JWK_CURVE, 'not a P-256 key');
        }

        return new Jwk('EC', 'P-256', Base64Url::encode($c['x']), Base64Url::encode($c['y']));
    }

    /**
     * The RFC 7638 SHA-256 thumbprint of $k, unpadded base64url.
     *
     * SHA-256 over the required members in lexicographic order without
     * white space: {"crv":...,"kty":...,"x":...,"y":...} for an EC key and
     * {"crv":...,"kty":...,"x":...} for an OKP key (RFC 8037 Appendix A.3).
     * Optional members do not enter it. $k must be a valid P-256 key (see
     * Jwk::publicKey()) or an OKP Ed25519 key with no y and an x of 32 octets
     * in canonical base64url; the point of an Ed25519 key is not checked.
     * The values are hashed as written: base64url and fixed ASCII names, so
     * nothing needs JSON escaping (RFC 7638 section 3.3).
     *
     * @throws JwsError
     */
    public static function thumbprint(Jwk $k): Digest
    {
        if ($k->algorithm() === self::ALG_ES256) {
            $k->publicKey();
            $text = '{"crv":"' . $k->crv . '","kty":"' . $k->kty . '","x":"' . $k->x . '","y":"' . $k->y . '"}';
        } else {
            self::okpX($k);
            $text = '{"crv":"' . $k->crv . '","kty":"' . $k->kty . '","x":"' . $k->x . '"}';
        }

        return new Digest(Base64Url::encode(hash('sha256', $text, true)));
    }

    /**
     * The P-256 private key of the 32-octet big-endian scalar $d, which
     * must be in [1, n-1]. OpenSSL derives the public point.
     *
     * @throws JwsError SIGNING_KEY
     */
    public static function privateKey(string $d): \OpenSSLAsymmetricKey
    {
        if (\strlen($d) !== Es256::COORDINATE_OCTETS) {
            throw new JwsError(Reason::SIGNING_KEY, \sprintf('scalar of %d octets, want %d', \strlen($d), Es256::COORDINATE_OCTETS));
        }
        $key = Es256::privateKey($d);
        if ($key === null) {
            throw new JwsError(Reason::SIGNING_KEY, 'scalar is not in [1, n-1]');
        }

        return $key;
    }

    /**
     * The P-256 private key of a private JWK: the members of a public key
     * that parseJwk() accepts, plus d, the canonical base64url of the 32
     * octet scalar, whose public point must be x and y.
     *
     * @throws JwsError
     */
    public static function parsePrivateJwk(string $data): \OpenSSLAsymmetricKey
    {
        try {
            $m = JwkReader::object($data);
        } catch (StrictJsonError $e) {
            throw new JwsError(Reason::JWK_INVALID, 'not a strict JSON object', $e);
        }
        $d = $m->get('d');
        if (!\is_string($d)) {
            throw new JwsError(Reason::JWK_INVALID, 'd is missing or not a string');
        }
        $pub = JwkReader::fromValue($m->without('d'));
        try {
            $scalar = Base64Url::decode($d);
        } catch (\UnexpectedValueException $e) {
            throw new JwsError(Reason::JWK_INVALID, 'd is not canonical base64url', $e);
        }
        $key = self::privateKey($scalar);
        $own = self::publicJwk($key);
        if ($own->x !== $pub->x || $own->y !== $pub->y) {
            throw new JwsError(Reason::SIGNING_KEY, 'x and y are not the public point of d');
        }

        return $key;
    }

    /**
     * The compact JWS of $payload under $key with the protected header $h.
     *
     * $h->alg may be empty and is always written as ES256. For a
     * holder-signed typ the header embeds $h->jwk, or the key's public JWK
     * when it is null; $h->jwk must be that public key. Every other typ
     * needs $h->kid and no $h->jwk. $payload must be a strict JSON object and
     * is signed exactly as given, never re-encoded. ECDSA signing is
     * randomized, so two calls give different signatures; S is always the
     * low value of the pair (S, n-S). The header members are written in the
     * order alg, typ, kid, jwk (draft Appendix C), the jwk members kty, crv,
     * x, y, kid, alg, use with the empty optional ones left out, as Go's
     * encoding/json writes them.
     *
     * @throws JwsError
     */
    public static function sign(Header $h, string $payload, ?\OpenSSLAsymmetricKey $key): string
    {
        $c = $key === null ? null : Es256::coordinates($key);
        if ($key === null || $c === null || !$c['private']) {
            throw new JwsError(Reason::SIGNING_KEY, $key === null ? 'no key' : 'not a P-256 private key');
        }
        $own = new Jwk('EC', 'P-256', Base64Url::encode($c['x']), Base64Url::encode($c['y']));
        if ($h->alg !== '' && $h->alg !== self::ALG_ES256) {
            throw new JwsError(Reason::ALG_UNSUPPORTED, 'alg ' . $h->alg);
        }
        $role = self::typRole($h->typ);
        if ($role === null) {
            throw new JwsError(Reason::TYP_UNSUPPORTED, 'typ ' . $h->typ);
        }
        $embedded = null;
        if ($role === Role::HOLDER) {
            $embedded = $own;
            if ($h->jwk !== null) {
                $given = self::thumbprint($h->jwk);
                JwkReader::checkUsage($h->jwk, self::ALG_ES256);
                if ($given->value !== self::thumbprint($own)->value) {
                    throw new JwsError(Reason::SIGNING_KEY, 'jwk is not the public key of the signing key');
                }
                $embedded = $h->jwk;
            }
        } else {
            if ($h->jwk !== null) {
                throw new JwsError(Reason::JWK_UNEXPECTED, \sprintf('typ %s is verified by kid, not by an embedded jwk', $h->typ));
            }
            if ($h->kid === '') {
                throw new JwsError(Reason::KID_MISSING);
            }
        }
        try {
            JwkReader::object($payload);
        } catch (StrictJsonError $e) {
            throw new JwsError(Reason::PAYLOAD_JSON, '', $e);
        }

        $signingInput = Base64Url::encode(self::headerText($h->typ, $h->kid, $embedded)) . '.' . Base64Url::encode($payload);
        $sig = Es256::sign($key, $signingInput);
        if ($sig === null) {
            throw new JwsError(Reason::SIGNING_KEY, 'signing failed');
        }

        return $signingInput . '.' . Base64Url::encode($sig);
    }

    /** The protected header text sign() writes. */
    private static function headerText(string $typ, string $kid, ?Jwk $jwk): string
    {
        $parts = ['"alg":' . Text::quote(self::ALG_ES256), '"typ":' . Text::quote($typ)];
        if ($kid !== '') {
            $parts[] = '"kid":' . Text::quote($kid);
        }
        if ($jwk !== null) {
            $members = [];
            foreach (JwkReader::STRING_MEMBERS as $name) {
                $v = $jwk->{$name};
                if ($v !== '' || \in_array($name, ['kty', 'crv', 'x'], true)) {
                    $members[] = '"' . $name . '":' . Text::quote($v);
                }
            }
            $parts[] = '"jwk":{' . implode(',', $members) . '}';
        }

        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Check the x of an OKP Ed25519 key (RFC 8037 section 2): no y, 32 octets.
     *
     * @throws JwsError JWK_INVALID
     */
    private static function okpX(Jwk $k): void
    {
        if ($k->y !== '') {
            throw new JwsError(Reason::JWK_INVALID, 'an OKP key has no y');
        }
        try {
            $b = Base64Url::decode($k->x);
        } catch (\UnexpectedValueException $e) {
            throw new JwsError(Reason::JWK_INVALID, 'x is not canonical base64url', $e);
        }
        if (\strlen($b) !== Es256::COORDINATE_OCTETS) {
            throw new JwsError(Reason::JWK_INVALID, \sprintf('x has %d octets, want %d', \strlen($b), Es256::COORDINATE_OCTETS));
        }
    }
}
