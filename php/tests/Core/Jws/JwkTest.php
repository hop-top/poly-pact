<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Reason as R;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\TestCase;

/**
 * JWK parsing, key sets, RFC 7638 thumbprints and key export. Port of
 * go/core/jws/jwk_test.go and the Python port's test_jws_jwk.py.
 */
final class JwkTest extends TestCase
{
    /** The field prime of P-256 (SEC 2, section 2.4.2), hex. */
    private const P_HEX = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';

    /** RFC 8037 Appendix A.3: the Ed25519 public key of Appendix A.2 and its thumbprint. */
    private const RFC8037_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
    private const RFC8037_THUMBPRINT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';

    /**
     * RFC 7638 over crv, kty, x, y in that order gives the Appendix C
     * holder_jkt; optional members and member order in the JWK do not matter.
     */
    public function testThumbprintAppendixC(): void
    {
        foreach ([
            '{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}',
            '{"y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","use":"sig","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","key_ops":["verify"],"crv":"P-256","kid":"k","kty":"EC"}',
        ] as $src) {
            self::assertSame(Keys::HOLDER_JKT, Jws::thumbprint(Jws::parseJwk($src))->value, $src);
        }
    }

    public function testThumbprintRejectsInvalidKeys(): void
    {
        $hj = Keys::fixtureJwk('holder');
        $cases = [
            ['kty RSA', new Jwk('RSA', 'P-256', $hj->x, $hj->y), R::JWK_CURVE],
            ['crv P-384', new Jwk('EC', 'P-384', $hj->x, $hj->y), R::JWK_CURVE],
            ['short x', new Jwk('EC', 'P-256', substr($hj->x, 0, 42), $hj->y), R::JWK_INVALID],
            ['empty y', new Jwk('EC', 'P-256', $hj->x), R::JWK_INVALID],
            ['off curve', new Jwk('EC', 'P-256', $hj->x, Keys::fixtureJwk('issuer')->y), R::JWK_OFF_CURVE],
        ];
        foreach ($cases as [$name, $k, $want]) {
            Keys::wantReason(static fn() => Jws::thumbprint($k), $want, $name);
        }
    }

    /** @return list<array{string, string, R}> */
    private static function parseJwkCases(): array
    {
        $hj = Keys::fixtureJwk('holder');
        $xy = \sprintf('"kty":"EC","crv":"P-256","x":"%s","y":"%s"', $hj->x, $hj->y);
        $x33 = Keys::b64("\0" . Keys::b64d($hj->x));
        $stdY = strtr($hj->y, '-_', '+/');
        $p = Keys::b64((string) hex2bin(self::P_HEX));
        $zero = Keys::b64(str_repeat("\0", 32));
        $iy = Keys::fixtureJwk('issuer')->y;
        $ec = static fn(string $x, string $y): string => \sprintf('{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}', $x, $y);

        return [
            ['d', '{' . $xy . ',"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}', R::JWK_PRIVATE],
            ['RSA private p', '{' . $xy . ',"p":"AQAB"}', R::JWK_PRIVATE],
            ['RSA private q', '{' . $xy . ',"q":"AQAB"}', R::JWK_PRIVATE],
            ['RSA private dp', '{' . $xy . ',"dp":"AQAB"}', R::JWK_PRIVATE],
            ['RSA private dq', '{' . $xy . ',"dq":"AQAB"}', R::JWK_PRIVATE],
            ['RSA private qi', '{' . $xy . ',"qi":"AQAB"}', R::JWK_PRIVATE],
            ['RSA private oth', '{' . $xy . ',"oth":[]}', R::JWK_PRIVATE],
            ['symmetric k', '{' . $xy . ',"k":"AQAB"}', R::JWK_PRIVATE],
            ['d null', '{' . $xy . ',"d":null}', R::JWK_PRIVATE],
            ['not JSON', 'kty=EC', R::JWK_INVALID],
            ['array', '[]', R::JWK_INVALID],
            ['null', 'null', R::JWK_INVALID],
            ['duplicate member', '{' . $xy . ',"x":"' . $hj->x . '"}', R::JWK_INVALID],
            ['x not a string', \sprintf('{"kty":"EC","crv":"P-256","x":1,"y":"%s"}', $hj->y), R::JWK_INVALID],
            ['kid not a string', '{' . $xy . ',"kid":1}', R::JWK_INVALID],
            ['kid null', '{' . $xy . ',"kid":null}', R::JWK_INVALID],
            ['kty missing', \sprintf('{"crv":"P-256","x":"%s","y":"%s"}', $hj->x, $hj->y), R::JWK_CURVE],
            ['kty OKP', '{"kty":"OKP","crv":"Ed25519","x":"' . self::RFC8037_X . '"}', R::JWK_CURVE],
            ['crv lowercase', \sprintf('{"kty":"EC","crv":"p-256","x":"%s","y":"%s"}', $hj->x, $hj->y), R::JWK_CURVE],
            ['y missing', \sprintf('{"kty":"EC","crv":"P-256","x":"%s"}', $hj->x), R::JWK_INVALID],
            ['x padded', $ec($hj->x . '=', $hj->y), R::JWK_INVALID],
            ['y padded', $ec($hj->x, $hj->y . '='), R::JWK_INVALID],
            ['y standard alphabet', $ec($hj->x, $stdY), R::JWK_INVALID],
            ['x 33 octets', $ec($x33, $hj->y), R::JWK_INVALID],
            ['x spare bits', $ec(substr($hj->x, 0, 42) . 'Z', $hj->y), R::JWK_INVALID],
            ['off curve', $ec($hj->x, $iy), R::JWK_OFF_CURVE],
            ['x = p', $ec($p, $hj->y), R::JWK_OFF_CURVE],
            ['x = y = 0', $ec($zero, $zero), R::JWK_OFF_CURVE],
            ['alg RS256', '{' . $xy . ',"alg":"RS256"}', R::JWK_USAGE],
            ['use enc', '{' . $xy . ',"use":"enc"}', R::JWK_USAGE],
            // key_ops (RFC 7517 section 4.3): a verification key names verify, and no operation twice.
            ['key_ops sign', '{' . $xy . ',"key_ops":["sign"]}', R::JWK_USAGE],
            ['key_ops encrypt', '{' . $xy . ',"key_ops":["encrypt"]}', R::JWK_USAGE],
            ['key_ops empty', '{' . $xy . ',"key_ops":[]}', R::JWK_USAGE],
            ['key_ops Verify', '{' . $xy . ',"key_ops":["Verify"]}', R::JWK_USAGE],
            ['key_ops duplicate', '{' . $xy . ',"key_ops":["verify","verify"]}', R::JWK_INVALID],
            ['key_ops a string', '{' . $xy . ',"key_ops":"verify"}', R::JWK_INVALID],
            ['key_ops an object', '{' . $xy . ',"key_ops":{"0":"verify"}}', R::JWK_INVALID],
            ['key_ops not strings', '{' . $xy . ',"key_ops":["verify",5]}', R::JWK_INVALID],
            ['key_ops null', '{' . $xy . ',"key_ops":null}', R::JWK_INVALID],
        ];
    }

    public function testParseJwk(): void
    {
        $hj = Keys::fixtureJwk('holder');
        self::assertSame(['test-holder-key-1', 'ES256', 'sig', 'EC', 'P-256'], [$hj->kid, $hj->alg, $hj->use, $hj->kty, $hj->crv]);
        foreach (self::parseJwkCases() as [$name, $src, $want]) {
            Keys::wantReason(static fn() => Jws::parseJwk($src), $want, $name);
        }
        $xy = \sprintf('"kty":"EC","crv":"P-256","x":"%s","y":"%s"', $hj->x, $hj->y);
        // Members the JWK specification does not define are ignored (RFC 7517 section 4).
        self::assertEquals(new Jwk('EC', 'P-256', $hj->x, $hj->y), Jws::parseJwk('{' . $xy . ',"key_ops":["verify"],"x5t":"abc","ext":true}'));
        // key_ops that name verify, alone or with other operations, are accepted.
        foreach (['["verify"]', '["sign","verify"]', '["verify","encrypt"]'] as $ops) {
            Jws::parseJwk('{' . $xy . ',"key_ops":' . $ops . '}');
        }
    }

    /**
     * A coordinate that is not 43 canonical characters for 32 octets is
     * jwk-invalid even when its value would be a point of the curve, or not.
     */
    public function testCoordinatesCheckedBeforeThePoint(): void
    {
        $hj = Keys::fixtureJwk('holder');
        $iy = Keys::fixtureJwk('issuer')->y;
        foreach ([[$hj->x . '=', $iy], [substr($hj->x, 0, 42), $iy], [Keys::b64("\0" . Keys::b64d($hj->x)), $hj->y]] as [$x, $y]) {
            Keys::wantReason(static fn() => (new Jwk('EC', 'P-256', $x, $y))->publicKey(), R::JWK_INVALID, $x);
        }
        $pub = $hj->publicKey();
        self::assertEquals(new Jwk('EC', 'P-256', $hj->x, $hj->y), Jws::publicJwk($pub));
    }

    /**
     * Coordinates are the full 32 octets (RFC 7518 section 6.2.1.2) even when
     * they start with a zero octet. P-256 scalar 379 is the smallest above 6
     * whose x does; openssl_pkey_get_details() drops that octet.
     */
    public function testPublicJwkKeepsLeadingZeros(): void
    {
        $key = Keys::scalarKey(379);
        $k = Jws::publicJwk($key);
        $x = Keys::b64d($k->x);
        self::assertSame([43, 32, 0], [\strlen($k->x), \strlen($x), \ord($x[0])]);
        self::assertSame(['', '', ''], [$k->kid, $k->alg, $k->use]);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsArray($details['ec']);
        self::assertSame(ltrim($x, "\0"), $details['ec']['x']);
        self::assertEquals($k, Jws::publicJwk($k->publicKey()));
    }

    public function testPublicJwkRejects(): void
    {
        Keys::wantReason(static fn() => Jws::publicJwk(null), R::JWK_INVALID);
        $p384 = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $p384);
        Keys::wantReason(static fn() => Jws::publicJwk($p384), R::JWK_CURVE);
        $rsa = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $rsa);
        Keys::wantReason(static fn() => Jws::publicJwk($rsa), R::JWK_CURVE);
    }

    public function testKeySet(): void
    {
        $iss = Keys::fixtureJwk('issuer');
        $val = Keys::fixtureJwk('validator');
        $s = new KeySet($iss, $val);
        self::assertSame($val, $s->lookup('test-validator-key-1'));
        self::assertNull($s->lookup('test-holder-key-1'));
        self::assertNull((new KeySet())->lookup('test-issuer-key-1'));
        self::assertNull($s->lookup(''));
        self::assertSame('AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE', $s->trusted('test-issuer-key-1')?->thumbprint->value);
        Keys::wantReason(static fn() => new KeySet($iss, $iss), R::KID_DUPLICATE);
        Keys::wantReason(static fn() => new KeySet(new Jwk($iss->kty, $iss->crv, $iss->x, $iss->y)), R::KID_MISSING);
        Keys::wantReason(static fn() => new KeySet(new Jwk($iss->kty, $iss->crv, $iss->x, $val->y, $iss->kid)), R::JWK_OFF_CURVE);
        Keys::wantReason(static fn() => new KeySet(new Jwk($iss->kty, $iss->crv, $iss->x, $iss->y, $iss->kid, '', 'enc')), R::JWK_USAGE);
        Keys::wantReason(static fn() => new KeySet(new Jwk('OKP', 'Ed25519', self::RFC8037_X, '', 'ed')), R::JWK_CURVE);
    }

    /** The thumbprints of the P-256 test keys, as the probe records report them. */
    public function testFixtureThumbprints(): void
    {
        $want = [
            'holder' => Keys::HOLDER_JKT,
            'issuer' => 'AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE',
            'adversarial' => 'B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU',
            'reputation-service' => 'BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ',
            'learning-controller' => 'yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k',
            'validator' => 'uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I',
        ];
        foreach ($want as $name => $w) {
            self::assertSame($w, Jws::thumbprint(Keys::fixtureJwk($name))->value, $name);
        }
    }

    public function testJwkAlgorithm(): void
    {
        self::assertSame(Jws::ALG_ES256, (new Jwk('EC', 'P-256'))->algorithm());
        self::assertSame(Jws::ALG_ED25519, (new Jwk('OKP', 'Ed25519'))->algorithm());
        Keys::wantReason(static fn() => (new Jwk('EC', 'P-384'))->algorithm(), R::JWK_CURVE);
    }

    public function testThumbprintOkpRfc8037(): void
    {
        self::assertSame(self::RFC8037_THUMBPRINT, Jws::thumbprint(new Jwk('OKP', 'Ed25519', self::RFC8037_X))->value);
        // Optional members do not enter it.
        self::assertSame(self::RFC8037_THUMBPRINT, Jws::thumbprint(new Jwk('OKP', 'Ed25519', self::RFC8037_X, '', 'k', 'Ed25519', 'sig'))->value);
        $raw = json_decode(Repo::read('spec/v1.0/fixtures/keys/ed25519.jwk.json'), true, 8, \JSON_THROW_ON_ERROR);
        self::assertIsArray($raw);
        $m = [];
        foreach (['kty', 'crv', 'x', 'kid', 'alg', 'use'] as $name) {
            self::assertIsString($raw[$name] ?? null, $name);
            $m[$name] = $raw[$name];
        }
        $fixture = new Jwk(...$m);
        self::assertSame(self::RFC8037_THUMBPRINT, Jws::thumbprint($fixture)->value);
    }

    /** The OKP checks of Go's Ed25519PublicKey that need no point arithmetic. */
    public function testThumbprintOkpRejects(): void
    {
        $cases = [
            ['y present', new Jwk('OKP', 'Ed25519', self::RFC8037_X, self::RFC8037_X), R::JWK_INVALID],
            ['x padded', new Jwk('OKP', 'Ed25519', self::RFC8037_X . '='), R::JWK_INVALID],
            ['x short', new Jwk('OKP', 'Ed25519', substr(self::RFC8037_X, 0, 42)), R::JWK_INVALID],
            ['x 33 octets', new Jwk('OKP', 'Ed25519', Keys::b64("\0" . Keys::b64d(self::RFC8037_X))), R::JWK_INVALID],
            ['x empty', new Jwk('OKP', 'Ed25519'), R::JWK_INVALID],
            ['crv X25519', new Jwk('OKP', 'X25519', self::RFC8037_X), R::JWK_CURVE],
        ];
        foreach ($cases as [$name, $k, $want]) {
            Keys::wantReason(static fn() => Jws::thumbprint($k), $want, $name);
        }
    }
}
