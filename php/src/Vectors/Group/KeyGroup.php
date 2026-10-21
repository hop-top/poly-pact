<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;
use HopTop\Pact\Vectors\Skipped;

/**
 * The key rule of docs/sdk/ports-plan.md section 5.2 of the source
 * repository, over spec/v1.0/fixtures/keys (keys/README.md).
 *
 * A P-256 JWK passes when it parses as a public key and its point is its
 * record's scalar times the base point, as OpenSSL derives it from the
 * scalar, and, for the record of role holder, when its thumbprint is the
 * holder_jkt of Appendix C. An Ed25519 JWK is out of scope (optional, draft
 * section 7.2). The entry of the scalars file passes when every P-256 record
 * derives and a holder exists.
 */
final class KeyGroup implements Group
{
    /** The private test values, relative to the fixture directory. */
    public const SCALARS_PATH = 'keys/test-private-scalars.json';

    /** The holder_jkt of draft Appendix C: the RFC 7638 thumbprint of the holder key, P-256 scalar 1. */
    public const APPENDIX_C_HOLDER_JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';

    /** @var list<string> */
    public const RECORD_MEMBERS = ['role', 'kid', 'alg', 'kty', 'crv', 'd', 'public_jwk'];

    public function run(string $root, Entry $e): void
    {
        $doc = Fixtures::obj(Fixtures::readJson($root, self::SCALARS_PATH), self::SCALARS_PATH, ['keys'], ['label', 'warning', 'encoding']);
        $records = [];
        foreach (Fixtures::arr($doc->get('keys'), 'keys') as $i => $r) {
            $records[] = Fixtures::obj($r, \sprintf('keys[%d]', $i), self::RECORD_MEMBERS, ['scalar', 'seed_hex']);
        }
        if ($e->path === self::SCALARS_PATH) {
            $holder = false;
            foreach ($records as $r) {
                if (!self::p256($r)) {
                    continue;
                }
                try {
                    self::checkRecord($root, $r);
                } catch (Fail $f) {
                    throw new Fail(\sprintf('record of role %s: %s', json_encode($r->get('role')), $f->getMessage()), 0, $f);
                }
                $holder = $holder || $r->get('role') === 'holder';
            }
            if (!$holder) {
                throw new Fail('no P-256 record of role holder, the key of Appendix C holder_jkt');
            }

            return;
        }
        $head = Fixtures::readJson($root, $e->path);
        if ($head instanceof JsonObject && $head->get('kty') === 'OKP' && $head->get('crv') === 'Ed25519') {
            throw new Skipped(Skipped::OUT_OF_SCOPE, 'Ed25519 key: the algorithm is optional (draft section 7.2) and not verified here');
        }
        foreach ($records as $r) {
            if (self::jwkPath($r) === $e->path) {
                self::checkRecord($root, $r);

                return;
            }
        }
        throw new Fail(\sprintf('no record in %s names %s', self::SCALARS_PATH, basename($e->path)));
    }

    /** The P-256 private key of the 32-octet scalar $d; a refusal is a Fail. */
    public static function privateKey(string $d, string $where): \OpenSSLAsymmetricKey
    {
        try {
            return Jws::privateKey($d);
        } catch (JwsError $err) {
            throw new Fail($where . ': ' . $err->getMessage(), 0, $err);
        }
    }

    private static function p256(JsonObject $r): bool
    {
        return $r->get('kty') === 'EC' && $r->get('crv') === 'P-256';
    }

    private static function jwkPath(JsonObject $r): string
    {
        $name = $r->get('public_jwk');

        return \dirname(self::SCALARS_PATH) . '/' . (\is_string($name) ? $name : '');
    }

    /** Derive the public point of a P-256 record from d and compare it with its public JWK. */
    private static function checkRecord(string $root, JsonObject $r): void
    {
        if (!self::p256($r)) {
            throw new Fail(\sprintf('kty %s crv %s, want EC P-256', json_encode($r->get('kty')), json_encode($r->get('crv'))));
        }
        $d = Fixtures::b64url(Fixtures::str($r->get('d'), 'd'), 'd');
        if (\strlen($d) !== 32) {
            throw new Fail('d is not 32 octets of base64url');
        }
        $scalar = $r->get('scalar');
        if (!\is_string($scalar) || preg_match('/\A[0-9]+\z/', $scalar) !== 1 || ltrim($scalar, '0') === '' || \strlen(ltrim($scalar, '0')) > 78) {
            throw new Fail(\sprintf('scalar %s is not a positive decimal integer', json_encode($scalar)));
        }
        if (self::decimal($d) !== ltrim($scalar, '0')) {
            throw new Fail(\sprintf('d is not scalar %s as 32 big-endian octets', $scalar));
        }
        $want = Jws::publicJwk(self::privateKey($d, 'scalar ' . $scalar));
        $rel = self::jwkPath($r);
        $raw = Fixtures::read($root, $rel);
        try {
            Fixtures::parseJson($raw);
        } catch (\UnexpectedValueException $err) {
            throw new Fail($rel . ': ' . $err->getMessage(), 0, $err);
        }
        try {
            $got = Jws::parseJwk($raw);
        } catch (JwsError $err) {
            throw new Fail($rel . ': ' . $err->getMessage(), 0, $err);
        }
        if ($got->x !== $want->x || $got->y !== $want->y) {
            throw new Fail(\sprintf('%s: public point x=%s y=%s, but scalar %s times G is x=%s y=%s', $rel, $got->x, $got->y, $scalar, $want->x, $want->y));
        }
        if ($r->get('role') === 'holder') {
            $tp = Jws::thumbprint($got)->value;
            if ($tp !== self::APPENDIX_C_HOLDER_JKT) {
                throw new Fail(\sprintf('%s: holder thumbprint %s, want Appendix C holder_jkt %s', $rel, $tp, self::APPENDIX_C_HOLDER_JKT));
            }
        }
    }

    /** The decimal text of the big-endian unsigned $b, without leading zeros ('' for zero). */
    private static function decimal(string $b): string
    {
        $digits = [];
        $bytes = array_map(\ord(...), str_split($b));
        while ($bytes !== []) {
            $rem = 0;
            $next = [];
            foreach ($bytes as $byte) {
                $cur = $rem * 256 + $byte;
                $q = intdiv($cur, 10);
                $rem = $cur % 10;
                if ($next !== [] || $q !== 0) {
                    $next[] = $q;
                }
            }
            $digits[] = (string) $rem;
            $bytes = $next;
        }

        return ltrim(implode('', array_reverse($digits)), '0');
    }
}
