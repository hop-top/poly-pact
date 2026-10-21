<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Jws\Header;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Reason as R;
use HopTop\Pact\Core\Jws\Role;
use HopTop\Pact\Core\Jws\StaticResolver;
use PHPUnit\Framework\TestCase;

/**
 * Signing and signing keys. Port of go/core/jws/sign_test.go and the Python
 * port's test_jws_sign.py, plus the header text rules of the port.
 *
 * The header text sign() writes is the text Go's encoding/json writes for
 * the same header (SetEscapeHTML(false)): U+2028 and U+2029 escaped, the
 * other non-ASCII characters raw, control characters escaped, and each byte
 * that starts no valid UTF-8 sequence written as \ufffd. The expected texts
 * below are the output of Go 1.26's encoding/json for the same strings.
 */
final class SignTest extends TestCase
{
    private static function headerText(string $compact): string
    {
        return Keys::b64d(explode('.', $compact)[0]);
    }

    public function testSignVerifyRoundTrip(): void
    {
        $holder = Keys::scalarKey(1);
        $issuer = Keys::scalarKey(2);
        $issuerJwk = Keys::fixtureJwk('issuer');
        $sets = [];
        foreach (Jws::typs() as $typ) {
            $role = Jws::typRole($typ);
            if ($role !== null && $role !== Role::HOLDER) {
                $sets[$role->value] = new KeySet($issuerJwk);
            }
        }
        $res = new StaticResolver($sets, new Digest(Keys::HOLDER_JKT));
        $payload = "{\n  \"pact_version\": \"0.1\",\n  \"jti\": \"round-trip\"\n}";
        foreach (Jws::typs() as $typ) {
            $role = Jws::typRole($typ);
            self::assertNotNull($role, $typ);
            if ($role === Role::HOLDER) {
                [$h, $key, $wantKey] = [new Header(typ: $typ), $holder, Keys::fixtureJwk('holder')];
            } else {
                [$h, $key, $wantKey] = [new Header(typ: $typ, kid: 'test-issuer-key-1'), $issuer, $issuerJwk];
            }
            $compact = Jws::sign($h, $payload, $key);
            $p = Jws::verify($compact, $res);
            self::assertSame([$compact, $role, $typ, Jws::ALG_ES256], [$p->compact, $p->role, $p->header->typ, $p->header->alg]);
            self::assertSame($payload, $p->payload);
            self::assertSame(64, \strlen($p->signature));
            self::assertSame([$wantKey->x, $wantKey->y], [$p->key->x, $p->key->y]);
            self::assertSame(Jws::thumbprint($wantKey)->value, $p->keyThumbprint->value);
            if ($role === Role::HOLDER) {
                self::assertNotNull($p->header->jwk);
                self::assertSame('', $p->header->kid);
            } else {
                self::assertNull($p->header->jwk);
                self::assertSame('test-issuer-key-1', $p->header->kid);
            }
        }
    }

    public function testSignHolderHeader(): void
    {
        $compact = Jws::sign(new Header(typ: Jws::TYP_PRESENTATION), Keys::SMALL_PAYLOAD, Keys::scalarKey(1));
        $hj = Keys::fixtureJwk('holder');
        self::assertSame(\sprintf('{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}', $hj->x, $hj->y), self::headerText($compact));
        // A kid next to the holder jwk is written, between typ and jwk.
        $compact = Jws::sign(new Header('ES256', Jws::TYP_PRESENTATION, 'h1'), Keys::SMALL_PAYLOAD, Keys::scalarKey(1));
        self::assertStringStartsWith('{"alg":"ES256","typ":"pact-presentation+jwt","kid":"h1","jwk":{', self::headerText($compact));
    }

    public function testSignRejects(): void
    {
        $issuer = Keys::scalarKey(2);
        $holder = Keys::scalarKey(1);
        $p384 = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $p384);
        $rsa = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $rsa);
        $public = Keys::fixtureJwk('issuer')->publicKey();
        $adv = Keys::fixtureJwk('adversarial');
        $hj = Keys::fixtureJwk('holder');
        $ev = Jws::TYP_EVIDENCE;
        $pres = Jws::TYP_PRESENTATION;
        $cases = [
            ['nil key', new Header(typ: $ev, kid: 'k'), Keys::SMALL_PAYLOAD, null, R::SIGNING_KEY],
            ['P-384 key', new Header(typ: $ev, kid: 'k'), Keys::SMALL_PAYLOAD, $p384, R::SIGNING_KEY],
            ['RSA key', new Header(typ: $ev, kid: 'k'), Keys::SMALL_PAYLOAD, $rsa, R::SIGNING_KEY],
            ['public key', new Header(typ: $ev, kid: 'k'), Keys::SMALL_PAYLOAD, $public, R::SIGNING_KEY],
            ['alg HS256', new Header('HS256', $ev, 'k'), Keys::SMALL_PAYLOAD, $issuer, R::ALG_UNSUPPORTED],
            ['alg Ed25519', new Header('Ed25519', $ev, 'k'), Keys::SMALL_PAYLOAD, $issuer, R::ALG_UNSUPPORTED],
            ['typ unknown', new Header(typ: 'JWT', kid: 'k'), Keys::SMALL_PAYLOAD, $issuer, R::TYP_UNSUPPORTED],
            ['service without kid', new Header(typ: $ev), Keys::SMALL_PAYLOAD, $issuer, R::KID_MISSING],
            ['service with jwk', new Header(typ: $ev, kid: 'k', jwk: $adv), Keys::SMALL_PAYLOAD, $issuer, R::JWK_UNEXPECTED],
            ['holder jwk of another key', new Header(typ: $pres, jwk: $adv), Keys::SMALL_PAYLOAD, $holder, R::SIGNING_KEY],
            ['holder jwk off curve', new Header(typ: $pres, jwk: new Jwk('EC', 'P-256', $hj->x, $adv->y)), Keys::SMALL_PAYLOAD, $holder, R::JWK_OFF_CURVE],
            ['holder jwk use enc', new Header(typ: $pres, jwk: new Jwk('EC', 'P-256', $hj->x, $hj->y, '', '', 'enc')), Keys::SMALL_PAYLOAD, $holder, R::JWK_USAGE],
            ['payload not JSON', new Header(typ: $ev, kid: 'k'), 'hello', $issuer, R::PAYLOAD_JSON],
            ['payload array', new Header(typ: $ev, kid: 'k'), '[]', $issuer, R::PAYLOAD_JSON],
            ['payload duplicate member', new Header(typ: $ev, kid: 'k'), '{"a":1,"a":2}', $issuer, R::PAYLOAD_JSON],
        ];
        foreach ($cases as [$name, $h, $payload, $key, $want]) {
            Keys::wantReason(static fn() => Jws::sign($h, $payload, $key), $want, $name);
        }
    }

    /**
     * S is the low value of (S, n-S); signing is randomized, so the test
     * checks a property of many signatures. A signature is high-S about half
     * the time.
     */
    public function testSignWritesLowS(): void
    {
        $key = Keys::scalarKey(2);
        $res = Keys::issuerResolver();
        $n = Keys::n();
        for ($i = 0; $i < 64; ++$i) {
            $compact = Jws::sign(new Header(typ: Jws::TYP_EVIDENCE, kid: 'test-issuer-key-1'), Keys::SMALL_PAYLOAD, $key);
            $s = substr(Jws::verify($compact, $res)->signature, 32);
            // s <= n >> 1 exactly when n - s >= s.
            self::assertGreaterThanOrEqual(0, strcmp(Keys::sub($n, $s), $s), \sprintf('signature %d has a high S', $i));
        }
    }

    /** @return list<array{string, string}> the kid values of the Go probe and the JSON text Go writes */
    private static function goHeaders(): array
    {
        return [
            ["a\u{2028}b\u{2029}c", '"a\u2028b\u2029c"'],
            ['q"b\s/', '"q\"b\\\\s/"'],
            ["\x00\x01\x08\x09\x0a\x0c\x0d\x1f\x7f", "\"\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f\x7f\""],
            ['<>&', '"<>&"'],
            ["caf\u{e9} \u{1f600}", "\"caf\u{e9} \u{1f600}\""],
            ["bad\xffutf8", '"bad\ufffdutf8"'],
            ["bad\xed\xa0\x80x", '"bad\ufffd\ufffd\ufffdx"'],
            ["\xe2\x82", '"\ufffd\ufffd"'],
            ["\xc0\x80", '"\ufffd\ufffd"'],
            ["\u{feff}", "\"\u{feff}\""],
        ];
    }

    public function testSignHeaderTextMatchesGo(): void
    {
        $key = Keys::scalarKey(2);
        foreach (self::goHeaders() as [$kid, $want]) {
            $compact = Jws::sign(new Header(typ: Jws::TYP_EVIDENCE, kid: $kid), '{"a":1}', $key);
            self::assertSame('{"alg":"ES256","typ":"pact-evidence+jwt","kid":' . $want . '}', self::headerText($compact), (string) json_encode($kid, \JSON_INVALID_UTF8_SUBSTITUTE));
        }
    }

    /** The embedded jwk keeps its optional members, in Go's order, escaped as Go does. */
    public function testSignHolderJwkMembersEscaped(): void
    {
        $hk = Keys::scalarKey(1);
        $pub = Jws::publicJwk($hk);
        $k = new Jwk($pub->kty, $pub->crv, $pub->x, $pub->y, "h\u{2028}", 'ES256', 'sig');
        $compact = Jws::sign(new Header(typ: Jws::TYP_PRESENTATION, jwk: $k), '{"a":1}', $hk);
        // The header segment of the Go probe, byte for byte.
        self::assertSame(
            'eyJhbGciOiJFUzI1NiIsInR5cCI6InBhY3QtcHJlc2VudGF0aW9uK2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNy'
            . 'diI6IlAtMjU2IiwieCI6ImF4ZlI4dUVzUWtmNHZPYmxZNlJBOG5jRGZZRXQ2ek9nOUtFNVJkaVl3cFkiLCJ5Ijoi'
            . 'VC1OQzR2NGFmNXVPNS10S2ZBLWVGaXZPTTFkck1WN095N1pBYURlX1VmVSIsImtpZCI6ImhcdTIwMjgiLCJhbGci'
            . 'OiJFUzI1NiIsInVzZSI6InNpZyJ9fQ',
            explode('.', $compact)[0],
        );
        $p = Jws::verify($compact, new StaticResolver([], new Digest(Keys::HOLDER_JKT)));
        self::assertEquals($k, $p->header->jwk);
    }

    public function testPrivateKey(): void
    {
        $hj = Keys::fixtureJwk('holder');
        $k = Jws::publicJwk(Jws::privateKey(Keys::scalar(1)));
        self::assertSame([$hj->x, $hj->y], [$k->x, $k->y]);
        $n = Keys::n();
        foreach (['empty' => '', 'short' => "\x01", '33 octets' => "\0" . Keys::scalar(1), 'zero' => str_repeat("\0", 32), 'n' => $n, 'n + 1' => substr($n, 0, 31) . "\x52", 'max' => str_repeat("\xff", 32)] as $name => $d) {
            Keys::wantReason(static fn() => Jws::privateKey($d), R::SIGNING_KEY, $name);
        }
        Jws::privateKey(Keys::sub($n, Keys::scalar(1)));
    }

    public function testParsePrivateJwk(): void
    {
        $hj = Keys::fixtureJwk('holder');
        $d1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE';
        $base = \sprintf('"kty":"EC","crv":"P-256","x":"%s","y":"%s","kid":"test-holder-key-1"', $hj->x, $hj->y);
        $key = Jws::parsePrivateJwk('{' . $base . ',"d":"' . $d1 . '"}');
        $compact = Jws::sign(new Header(typ: Jws::TYP_PRESENTATION), Keys::SMALL_PAYLOAD, $key);
        self::assertSame(Keys::HOLDER_JKT, Jws::verify($compact, Keys::issuerResolver())->keyThumbprint->value);
        $cases = [
            ['not JSON', 'd=1', R::JWK_INVALID],
            ['no d', '{' . $base . '}', R::JWK_INVALID],
            ['d not a string', '{' . $base . ',"d":1}', R::JWK_INVALID],
            ['d padded', '{' . $base . ',"d":"' . $d1 . '="}', R::JWK_INVALID],
            ['d short', '{' . $base . ',"d":"AQ"}', R::SIGNING_KEY],
            ['d zero', '{' . $base . ',"d":"' . Keys::b64(str_repeat("\0", 32)) . '"}', R::SIGNING_KEY],
            ['d of another key', '{' . $base . ',"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI"}', R::SIGNING_KEY],
            ['RSA private member', '{' . $base . ',"d":"' . $d1 . '","p":"AQAB"}', R::JWK_PRIVATE],
            ['crv P-384', \sprintf('{"kty":"EC","crv":"P-384","x":"%s","y":"%s","d":"%s"}', $hj->x, $hj->y, $d1), R::JWK_CURVE],
        ];
        foreach ($cases as [$name, $src, $want]) {
            Keys::wantReason(static fn() => Jws::parsePrivateJwk($src), $want, $name);
        }
    }
}
