<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;

/**
 * The checks of Jws::parseJwk() over a strict-parsed value (Go parseJWK,
 * JWK.check, checkKeyOps, JWK.checkUsage).
 *
 * @internal
 */
final class JwkReader
{
    /** The private key members of RFC 7518 section 6: EC d, RSA d, p, q, dp, dq, qi, oth, and the symmetric k. */
    public const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /** The members a Jwk keeps, in the order they are read and written. */
    public const STRING_MEMBERS = ['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use'];

    private function __construct() {}

    /**
     * Strict-decode $data as a JSON object (Go: Unmarshal into
     * map[string]json.RawMessage).
     *
     * @throws StrictJsonError
     */
    public static function object(string $data, ?Limits $limits = null): JsonObject
    {
        return StrictJson::decode($data, JsonObject::class, $limits);
    }

    /**
     * parseJwk() for a value already strict-parsed, such as the jwk member
     * of a header.
     *
     * @throws JwsError
     */
    public static function fromValue(mixed $m): Jwk
    {
        if (!$m instanceof JsonObject) {
            throw new JwsError(Reason::JWK_INVALID, 'not a strict JSON object');
        }
        foreach (self::PRIVATE_MEMBERS as $name) {
            if ($m->has($name)) {
                throw new JwsError(Reason::JWK_PRIVATE, 'member ' . $name);
            }
        }
        $values = [];
        foreach (self::STRING_MEMBERS as $name) {
            if (!$m->has($name)) {
                continue;
            }
            $v = $m->get($name);
            if (!\is_string($v)) {
                throw new JwsError(Reason::JWK_INVALID, $name . ' is not a string');
            }
            $values[$name] = $v;
        }
        $k = new Jwk(...$values);
        self::check($k);
        if ($m->has('key_ops')) {
            self::checkKeyOps($m->get('key_ops'));
        }

        return $k;
    }

    /**
     * Check that $k is a key for ES256 with valid material and fitting alg
     * and use; return its public key. An Ed25519 key is refused as not
     * negotiated.
     *
     * @throws JwsError
     */
    public static function check(Jwk $k): \OpenSSLAsymmetricKey
    {
        $alg = $k->algorithm();
        if ($alg !== Jws::ALG_ES256) {
            throw new JwsError(Reason::JWK_CURVE, \sprintf('kty %s crv %s: %s is not negotiated', Text::quote($k->kty), Text::quote($k->crv), $alg));
        }
        $pub = $k->publicKey();
        self::checkUsage($k, $alg);

        return $pub;
    }

    /**
     * alg and use, when present, must be $alg and sig.
     *
     * @throws JwsError JWK_USAGE
     */
    public static function checkUsage(Jwk $k, string $alg): void
    {
        if ($k->alg !== '' && $k->alg !== $alg) {
            throw new JwsError(Reason::JWK_USAGE, \sprintf('alg %s, want %s', Text::quote($k->alg), $alg));
        }
        if ($k->use !== '' && $k->use !== 'sig') {
            throw new JwsError(Reason::JWK_USAGE, \sprintf('use %s, want sig', Text::quote($k->use)));
        }
    }

    /**
     * A key_ops member (RFC 7517 section 4.3): an array of strings, none
     * twice, that names verify, the operation a trusted public key serves.
     *
     * @throws JwsError
     */
    private static function checkKeyOps(mixed $ops): void
    {
        if (!\is_array($ops) || !array_is_list($ops)) {
            throw new JwsError(Reason::JWK_INVALID, 'key_ops is not an array of strings');
        }
        $seen = [];
        foreach ($ops as $op) {
            if (!\is_string($op)) {
                throw new JwsError(Reason::JWK_INVALID, 'key_ops is not an array of strings');
            }
            if (isset($seen[$op])) {
                throw new JwsError(Reason::JWK_INVALID, \sprintf('key_ops names %s twice', Text::quote($op)));
            }
            $seen[$op] = true;
        }
        if (!isset($seen['verify'])) {
            throw new JwsError(Reason::JWK_USAGE, 'key_ops does not name verify');
        }
    }
}
