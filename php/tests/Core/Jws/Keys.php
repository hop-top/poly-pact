<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Reason;
use HopTop\Pact\Core\Jws\Role;
use HopTop\Pact\Core\Jws\StaticResolver;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\Assert;

/**
 * Test keys and signing helpers of the jws tests: the P-256 keys of
 * spec/v1.0/fixtures/keys (scalar 1 holder, 2 issuer, 3 adversarial) and a
 * signer that calls openssl_sign directly, so tests can build inputs
 * Jws::sign() refuses to make and signatures with a high S.
 */
final class Keys
{
    /** The holder_jkt printed in draft Appendix C. */
    public const HOLDER_JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';

    /** The order of P-256 (SEC 2, section 2.4.2), hex. */
    public const N_HEX = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

    public const EVIDENCE_HEADER = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}';

    public const SMALL_PAYLOAD = '{"pact_version":"0.1","jti":"unit"}';

    public static function b64(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    public static function b64d(string $s): string
    {
        $b = base64_decode(strtr($s, '-_', '+/'), false);
        Assert::assertIsString($b);

        return $b;
    }

    public static function n(): string
    {
        return (string) hex2bin(self::N_HEX);
    }

    /** The 32-octet big-endian form of a small scalar. */
    public static function scalar(int $n): string
    {
        return str_pad(pack('J', $n), 32, "\0", \STR_PAD_LEFT);
    }

    public static function scalarKey(int $n): \OpenSSLAsymmetricKey
    {
        return Jws::privateKey(self::scalar($n));
    }

    public static function fixtureJwk(string $name): Jwk
    {
        return Jws::parseJwk(Repo::read('spec/v1.0/fixtures/keys/' . $name . '.jwk.json'));
    }

    /** R || S of a signature made with openssl_sign directly; S may be high. */
    public static function rawSig(string $signingInput, \OpenSSLAsymmetricKey $key): string
    {
        $der = '';
        Assert::assertTrue(openssl_sign($signingInput, $der, $key, \OPENSSL_ALGO_SHA256));
        Assert::assertIsString($der);
        $out = '';
        $o = 2;
        for ($i = 0; $i < 2; ++$i) {
            Assert::assertSame("\x02", $der[$o]);
            $len = \ord($der[$o + 1]);
            $out .= str_pad(ltrim(substr($der, $o + 2, $len), "\0"), 32, "\0", \STR_PAD_LEFT);
            $o += 2 + $len;
        }

        return $out;
    }

    /** Sign header.payload directly. */
    public static function rawCompact(string $header, string $payload, \OpenSSLAsymmetricKey $key): string
    {
        $si = self::b64($header) . '.' . self::b64($payload);

        return $si . '.' . self::b64(self::rawSig($si, $key));
    }

    /** $a - $b for 32-octet big-endian values with $a >= $b. */
    public static function sub(string $a, string $b): string
    {
        $out = '';
        $borrow = 0;
        for ($i = 31; $i >= 0; --$i) {
            $v = \ord($a[$i]) - \ord($b[$i]) - $borrow;
            $borrow = $v < 0 ? 1 : 0;
            $out = \chr($v + 256 * $borrow) . $out;
        }

        return $out;
    }

    /** Call $f and require a JwsError of reason $want. */
    public static function wantReason(callable $f, Reason $want, string $name = ''): JwsError
    {
        try {
            $f();
        } catch (JwsError $e) {
            Assert::assertSame($want, Jws::reasonOf($e), $name . ': ' . $e->getMessage());
            Assert::assertSame($want, $e->reason, $name);

            return $e;
        }
        Assert::fail(\sprintf('%s: no error, want %s', $name, $want->value));
    }

    /** Trusts the issuer test key for the issuer role; expects the Appendix C holder_jkt. */
    public static function issuerResolver(): StaticResolver
    {
        return new StaticResolver([Role::ISSUER->value => new KeySet(self::fixtureJwk('issuer'))], new Digest(self::HOLDER_JKT));
    }

    public static function jwkJson(Jwk $k): string
    {
        return \sprintf('{"kty":"%s","crv":"%s","x":"%s","y":"%s"}', $k->kty, $k->crv, $k->x, $k->y);
    }
}
