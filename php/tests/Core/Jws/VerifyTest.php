<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Jws\Header;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\KeyRequest;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Reason as R;
use HopTop\Pact\Core\Jws\Role;
use HopTop\Pact\Core\Jws\StaticResolver;
use HopTop\Pact\Core\Jws\Verifier;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use PHPUnit\Framework\TestCase;

/**
 * Verification of the compact JWS profile. Port of go/core/jws/jws_test.go
 * and the Python port's test_jws.py.
 *
 * The test keys are the P-256 keys of spec/v1.0/fixtures/keys (scalar 1
 * holder, 2 issuer, 3 adversarial). A test that reads them fails when spec/
 * is absent under PACT_REQUIRE_VECTORS=1 and skips otherwise.
 */
final class VerifyTest extends TestCase
{
    /** @return list<array{string, string, int, R}> */
    private static function headerCases(): array
    {
        $hj = Keys::fixtureJwk('holder');
        $xy = \sprintf('"kty":"EC","crv":"P-256","x":"%s","y":"%s"', $hj->x, $hj->y);
        $hjwk = '{' . $xy . '}';
        $ev = '"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"';
        $pres = '"alg":"ES256","typ":"pact-presentation+jwt"';
        $iy = Keys::fixtureJwk('issuer')->y;

        return [
            ['alg none', '{"alg":"none",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg HS256', '{"alg":"HS256",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg HS512', '{"alg":"HS512",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg RS256', '{"alg":"RS256",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg PS256', '{"alg":"PS256",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg EdDSA', '{"alg":"EdDSA",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg Ed25519 not negotiated', '{"alg":"Ed25519",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg es256 lowercase', '{"alg":"es256",' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg missing', '{' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['alg not a string', '{"alg":["ES256"],' . $ev . '}', 2, R::ALG_UNSUPPORTED],
            ['jku', '{"alg":"ES256",' . $ev . ',"jku":"https://trust.example/jwks"}', 2, R::HEADER_JKU],
            ['x5u', '{"alg":"ES256",' . $ev . ',"x5u":"https://trust.example/c.pem"}', 2, R::HEADER_X5U],
            ['x5c', '{"alg":"ES256",' . $ev . ',"x5c":["MIIB"]}', 2, R::HEADER_X5C],
            ['crit', '{"alg":"ES256",' . $ev . ',"crit":["ext"],"ext":1}', 2, R::HEADER_CRIT],
            ['crit empty', '{"alg":"ES256",' . $ev . ',"crit":[]}', 2, R::HEADER_CRIT],
            ['b64 false', '{"alg":"ES256",' . $ev . ',"b64":false}', 2, R::HEADER_B64],
            ['b64 false with crit', '{"alg":"ES256",' . $ev . ',"b64":false,"crit":["b64"]}', 2, R::HEADER_CRIT],
            ['typ missing', '{"alg":"ES256","kid":"test-issuer-key-1"}', 2, R::TYP_UNSUPPORTED],
            ['typ JWT', '{"alg":"ES256","typ":"JWT","kid":"test-issuer-key-1"}', 2, R::TYP_UNSUPPORTED],
            ['typ unlisted', '{"alg":"ES256","typ":"pact-profile+jwt","kid":"test-issuer-key-1"}', 2, R::TYP_UNSUPPORTED],
            ['typ not a string', '{"alg":"ES256","typ":7,"kid":"test-issuer-key-1"}', 2, R::TYP_UNSUPPORTED],
            ['kid missing', '{"alg":"ES256","typ":"pact-evidence+jwt"}', 2, R::KID_MISSING],
            ['kid empty', '{"alg":"ES256","typ":"pact-evidence+jwt","kid":""}', 2, R::KID_MISSING],
            ['kid not a string', '{"alg":"ES256","typ":"pact-evidence+jwt","kid":1}', 2, R::HEADER_JSON],
            ['kid null', '{"alg":"ES256","typ":"pact-evidence+jwt","kid":null}', 2, R::HEADER_JSON],
            ['kid unknown', '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-2"}', 2, R::KID_UNKNOWN],
            ['jwk on a service-signed typ', '{"alg":"ES256",' . $ev . ',"jwk":' . $hjwk . '}', 2, R::JWK_UNEXPECTED],
            ['duplicate member', '{"alg":"ES256",' . $ev . ',"alg":"ES256"}', 2, R::HEADER_JSON],
            ['not an object', '["ES256"]', 2, R::HEADER_JSON],
            ['not JSON', 'alg=ES256', 2, R::HEADER_JSON],
            ['lone surrogate', '{"alg":"ES256",' . $ev . ',"x":"\ud800"}', 2, R::HEADER_JSON],
            ['invalid UTF-8', "{\"alg\":\"ES256\",{$ev},\"x\":\"\xff\"}", 2, R::HEADER_JSON],
            ['holder jwk missing', '{' . $pres . ',"kid":"test-holder-key-1"}', 1, R::JWK_MISSING],
            ['holder jwk not an object', '{' . $pres . ',"jwk":"x"}', 1, R::JWK_INVALID],
            ['holder jwk with d', '{' . $pres . ',"jwk":{' . $xy . ',"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}}', 1, R::JWK_PRIVATE],
            ['holder jwk P-384', '{' . $pres . \sprintf(',"jwk":{"kty":"EC","crv":"P-384","x":"%s","y":"%s"}}', $hj->x, $hj->y), 1, R::JWK_CURVE],
            ['holder jwk RSA', '{' . $pres . ',"jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}', 1, R::JWK_CURVE],
            ['holder jwk Ed25519', '{' . $pres . ',"jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}', 1, R::JWK_CURVE],
            ['holder jwk off curve', '{' . $pres . \sprintf(',"jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}', $hj->x, $iy), 1, R::JWK_OFF_CURVE],
            ['holder jwk short x', '{' . $pres . \sprintf(',"jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}', substr($hj->x, 0, 42), $hj->y), 1, R::JWK_INVALID],
            ['holder jwk of another key', '{' . $pres . ',"jwk":' . Keys::jwkJson(Keys::fixtureJwk('adversarial')) . '}', 3, R::HOLDER_JKT_MISMATCH],
        ];
    }

    /**
     * Each header draft 7.2 prohibits. Every input carries a valid signature
     * over its own signing input, so the rejection comes from the header alone.
     */
    public function testVerifyRejectsHeaders(): void
    {
        $res = Keys::issuerResolver();
        foreach (self::headerCases() as [$name, $header, $scalar, $want]) {
            $compact = Keys::rawCompact($header, Keys::SMALL_PAYLOAD, Keys::scalarKey($scalar));
            Keys::wantReason(static fn() => Jws::verify($compact, $res), $want, $name);
        }
    }

    /** @return list<array{string, string, R}> */
    private static function compactFormCases(): array
    {
        $good = Keys::rawCompact(Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        [$h, $p, $s] = explode('.', $good);
        $si = $h . '.' . $p;
        $std = strtr($s, '-_', '+/') . '+';
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $deep = str_repeat('{"a":', 17) . '1' . str_repeat('}', 17);

        return [
            ['two segments', $si, R::COMPACT_FORM],
            ['four segments', $good . '.AAAA', R::COMPACT_FORM],
            ['five segments (JWE shape)', $h . '..' . $p . '..' . $s, R::COMPACT_FORM],
            ['empty header', '.' . $p . '.' . $s, R::COMPACT_FORM],
            ['empty string', '', R::COMPACT_FORM],
            ['detached payload', $h . '..' . $s, R::PAYLOAD_DETACHED],
            ['empty signature', $si . '.', R::SIGNATURE_LENGTH],
            ['padded header', $h . '=.' . $p . '.' . $s, R::BASE64_URL],
            ['padded signature', $good . '==', R::BASE64_URL],
            ['line feed in payload', $h . '.' . substr($p, 0, 5) . "\n" . substr($p, 5) . '.' . $s, R::BASE64_URL],
            ['carriage return in header', substr($h, 0, 5) . "\r" . substr($h, 5) . '.' . $p . '.' . $s, R::BASE64_URL],
            ['space in signature', $si . '.' . substr($s, 0, 5) . ' ' . substr($s, 5), R::BASE64_URL],
            ['standard alphabet', $si . '.' . $std, R::BASE64_URL],
            ['unencoded payload', $h . '.{"jti":"unit"}.' . $s, R::BASE64_URL],
            ['unencoded payload with a period', $h . '.' . Keys::SMALL_PAYLOAD . '.' . $s, R::COMPACT_FORM],
            ['length 1 mod 4', $si . '.' . $s . 'AAA', R::BASE64_URL],
            ['spare bits', $si . '.' . substr($s, 0, -1) . $alphabet[strpos($alphabet, $s[-1]) ^ 1], R::BASE64_URL],
            ['payload not JSON', $h . '.' . Keys::b64('hello') . '.' . $s, R::PAYLOAD_JSON],
            ['payload array', $h . '.' . Keys::b64('[1]') . '.' . $s, R::PAYLOAD_JSON],
            ['payload duplicate member', $h . '.' . Keys::b64('{"a":1,"a":1}') . '.' . $s, R::PAYLOAD_JSON],
            ['payload invalid UTF-8', $h . '.' . Keys::b64("{\"a\":\"\xff\"}") . '.' . $s, R::PAYLOAD_JSON],
            ['payload too deep', $h . '.' . Keys::b64($deep) . '.' . $s, R::PAYLOAD_JSON],
            ['payload null', $h . '.' . Keys::b64('null') . '.' . $s, R::PAYLOAD_JSON],
        ];
    }

    public function testVerifyRejectsCompactForm(): void
    {
        $res = Keys::issuerResolver();
        foreach (self::compactFormCases() as [$name, $compact, $want]) {
            Keys::wantReason(static fn() => Jws::verify($compact, $res), $want, $name);
        }
    }

    /**
     * RFC 7518 section 3.4: exactly 64 octets, R and S in [1, n-1], over the
     * received signing input.
     */
    public function testVerifyRejectsSignatures(): void
    {
        $issuer = Keys::scalarKey(2);
        $si = Keys::b64(Keys::EVIDENCE_HEADER) . '.' . Keys::b64(Keys::SMALL_PAYLOAD);
        $sig = Keys::rawSig($si, $issuer);
        $r = substr($sig, 0, 32);
        $s = substr($sig, 32);
        $n = Keys::n();
        $zero = str_repeat("\0", 32);
        $enc = static fn(string $r, string $s): string => $si . '.' . Keys::b64($r . $s);
        $flipped = $sig;
        $flipped[10] = \chr(\ord($flipped[10]) ^ 0x80);
        $other = Keys::b64(Keys::EVIDENCE_HEADER) . '.' . Keys::b64('{"pact_version":"0.1","jti":"other"}');
        $cases = [
            ['63 octets', $si . '.' . Keys::b64(substr($sig, 0, 63)), R::SIGNATURE_LENGTH],
            ['65 octets', $si . '.' . Keys::b64($sig . "\0"), R::SIGNATURE_LENGTH],
            ['96 octets', $si . '.' . Keys::b64(str_repeat("\0", 96)), R::SIGNATURE_LENGTH],
            ['r zero', $enc($zero, $s), R::SIGNATURE_INVALID],
            ['s zero', $enc($r, $zero), R::SIGNATURE_INVALID],
            ['all zero', $enc($zero, $zero), R::SIGNATURE_INVALID],
            ['r = n', $enc($n, $s), R::SIGNATURE_INVALID],
            ['s = n', $enc($r, $n), R::SIGNATURE_INVALID],
            ['r = 2^256-1', $enc(str_repeat("\xff", 32), $s), R::SIGNATURE_INVALID],
            ['bit flipped', $si . '.' . Keys::b64($flipped), R::SIGNATURE_INVALID],
            ['other payload', $other . '.' . Keys::b64($sig), R::SIGNATURE_INVALID],
            ['other key', $si . '.' . Keys::b64(Keys::rawSig($si, Keys::scalarKey(3))), R::SIGNATURE_INVALID],
        ];
        $res = Keys::issuerResolver();
        foreach ($cases as [$name, $compact, $want]) {
            Keys::wantReason(static fn() => Jws::verify($compact, $res), $want, $name);
        }
        // Neither RFC 7518 nor the draft has a low-S rule: the high-S twin verifies.
        $p = Jws::verify($enc($r, Keys::sub($n, $s)), $res);
        self::assertSame(Keys::sub($n, $s), substr($p->signature, 32));
        self::assertSame($s, substr(Jws::verify($enc($r, $s), $res)->signature, 32));
    }

    /**
     * The signature covers the received bytes: white space, member order and
     * escapes a serializer would change still verify, and come back unchanged.
     */
    public function testVerifyUsesReceivedSigningInput(): void
    {
        $header = "{ \"kid\" : \"test\\u002dissuer-key-1\",\n\"typ\":\"pact-evidence+jwt\" , \"alg\":\"ES256\" }";
        $payload = "{\n  \"z\": 1.50,\n  \"a\": \"caf\\u00e9 \\/ caf\u{e9}\",\n  \"pact_version\": \"0.1\"\n}";
        $compact = Keys::rawCompact($header, $payload, Keys::scalarKey(2));
        $p = Jws::verify($compact, Keys::issuerResolver());
        self::assertSame($payload, $p->payload);
        self::assertSame($header, $p->rawHeader);
        self::assertSame(substr($compact, 0, (int) strrpos($compact, '.')), $p->signingInput);
        self::assertSame($compact, $p->compact);
        self::assertSame(['test-issuer-key-1', Jws::TYP_EVIDENCE, Jws::ALG_ES256], [$p->header->kid, $p->header->typ, $p->header->alg]);
        self::assertSame(Role::ISSUER, $p->role);
        self::assertNull($p->header->jwk);
        self::assertEquals(Keys::fixtureJwk('issuer'), $p->key);
        self::assertSame('AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE', $p->keyThumbprint->value);
    }

    public function testVerifierExpectedTyp(): void
    {
        $compact = Keys::rawCompact(Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        $v = new Verifier(Keys::issuerResolver(), Jws::TYP_ADMISSION);
        Keys::wantReason(static fn() => $v->verify($compact), R::TYP_MISMATCH);
        (new Verifier(Keys::issuerResolver(), Jws::TYP_EVIDENCE))->verify($compact);
        (new Verifier(Keys::issuerResolver(), ''))->verify($compact);
        $this->addToAssertionCount(2);
    }

    public function testVerifierCompactSize(): void
    {
        $res = Keys::issuerResolver();
        $big = str_repeat('A', Jws::DEFAULT_MAX_COMPACT_BYTES - 1);
        Keys::wantReason(static fn() => Jws::verify($big . '.A.A', $res), R::COMPACT_SIZE);
        Keys::wantReason(static fn() => Jws::verify(substr($big, 4) . '.A.A', $res), R::HEADER_JSON);
        $compact = Keys::rawCompact(Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        $v = new Verifier($res, '', \strlen($compact) - 1);
        Keys::wantReason(static fn() => $v->verify($compact), R::COMPACT_SIZE);
        (new Verifier($res, '', \strlen($compact)))->verify($compact);
        (new Verifier($res, '', -1))->verify($compact);
        // The limit counts UTF-8 octets, as Go's len does.
        $wide = str_repeat("\u{e9}", intdiv(Jws::DEFAULT_MAX_COMPACT_BYTES, 2) - 1) . '.A.A';
        Keys::wantReason(static fn() => Jws::verify($wide, $res), R::COMPACT_SIZE);
    }

    public function testVerifierJsonLimits(): void
    {
        $payload = '{"pact_version":"0.1","pad":"' . str_repeat('x', 100) . '"}';
        $compact = Keys::rawCompact(Keys::EVIDENCE_HEADER, $payload, Keys::scalarKey(2));
        $v = new Verifier(Keys::issuerResolver(), '', 0, new Limits(100));
        $err = Keys::wantReason(static fn() => $v->verify($compact), R::PAYLOAD_JSON);
        $prev = $err->getPrevious();
        self::assertInstanceOf(StrictJsonError::class, $prev);
        self::assertSame(StrictJsonErrorKind::SIZE, $prev->kind);
        // The header is bounded too.
        $v = new Verifier(Keys::issuerResolver(), '', 0, new Limits(20));
        Keys::wantReason(static fn() => $v->verify($compact), R::HEADER_JSON);
    }

    public function testKeyRequest(): void
    {
        $compact = Keys::rawCompact(Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        $rr = new RecordingResolver(new KeySet(Keys::fixtureJwk('issuer')));
        Jws::verify($compact, $rr);
        self::assertCount(1, $rr->reqs);
        $req = $rr->reqs[0];
        self::assertSame([Jws::TYP_EVIDENCE, Role::ISSUER, 'test-issuer-key-1', Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD], [$req->typ, $req->role, $req->kid, $req->header, $req->payload]);
        $holder = Jws::sign(new Header(typ: Jws::TYP_PRESENTATION), Keys::SMALL_PAYLOAD, Keys::scalarKey(1));
        $rr = new RecordingResolver(null, new Digest(Keys::HOLDER_JKT));
        Jws::verify($holder, $rr);
        self::assertSame([[Role::HOLDER, Jws::TYP_PRESENTATION, '']], array_map(static fn(KeyRequest $r): array => [$r->role, $r->typ, $r->kid], $rr->reqs));
        self::assertSame(['holderJkt'], $rr->calls);
    }

    public function testResolverFailures(): void
    {
        $compact = Keys::rawCompact(Keys::EVIDENCE_HEADER, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        $holder = Jws::sign(new Header(typ: Jws::TYP_PRESENTATION), Keys::SMALL_PAYLOAD, Keys::scalarKey(1));
        $cause = new \RuntimeException('deadline exceeded');
        $cases = [
            ['nil resolver', $compact, null, R::KEY_UNAVAILABLE, false],
            ['key set error', $compact, new RecordingResolver(keysErr: $cause), R::KEY_UNAVAILABLE, true],
            ['nil key set', $compact, new RecordingResolver(), R::KID_UNKNOWN, false],
            ['holder jkt error', $holder, new RecordingResolver(holderErr: $cause), R::KEY_UNAVAILABLE, true],
            ['holder jkt empty', $holder, new RecordingResolver(), R::KEY_UNAVAILABLE, false],
            ['static resolver without the role', $compact, new StaticResolver(), R::KID_UNKNOWN, false],
            ['static resolver without holder_jkt', $holder, new StaticResolver(), R::KEY_UNAVAILABLE, false],
            ['static resolver with an empty holder_jkt', $holder, new StaticResolver([], new Digest('')), R::KEY_UNAVAILABLE, false],
            ['static resolver with another holder_jkt', $holder, new StaticResolver([], new Digest('AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE')), R::HOLDER_JKT_MISMATCH, false],
            ['key set of another role', $compact, new StaticResolver([Role::VALIDATOR->value => new KeySet(Keys::fixtureJwk('issuer'))]), R::KID_UNKNOWN, false],
        ];
        foreach ($cases as [$name, $c, $res, $want, $wrapped]) {
            $err = Keys::wantReason(static fn() => Jws::verify($c, $res), $want, $name);
            if ($wrapped) {
                self::assertSame($cause, $err->getPrevious(), $name);
            }
        }
    }

    /**
     * Members the draft does not define are ignored (RFC 7515 section 4), a
     * kid next to a holder jwk plays no part in key selection, and typ is
     * compared exactly.
     */
    public function testHeaderDecisions(): void
    {
        $issuer = Keys::scalarKey(2);
        $res = Keys::issuerResolver();
        $ignored = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","cty":"json","x5t#S256":"abc","pact-note":{"a":1}}';
        Jws::verify(Keys::rawCompact($ignored, Keys::SMALL_PAYLOAD, $issuer), $res);
        $withKid = '{"alg":"ES256","typ":"pact-presentation+jwt","kid":"no-such-key","jwk":' . Keys::jwkJson(Keys::fixtureJwk('holder')) . '}';
        $p = Jws::verify(Keys::rawCompact($withKid, Keys::SMALL_PAYLOAD, Keys::scalarKey(1)), $res);
        self::assertSame('no-such-key', $p->header->kid);
        self::assertSame(Role::HOLDER, $p->role);
        self::assertNotNull($p->header->jwk);
        self::assertSame(Keys::HOLDER_JKT, $p->keyThumbprint->value);
        foreach (['PACT-EVIDENCE+JWT', 'application/pact-evidence+jwt', ' pact-evidence+jwt'] as $typ) {
            $c = Keys::rawCompact(\sprintf('{"alg":"ES256","typ":"%s","kid":"test-issuer-key-1"}', $typ), Keys::SMALL_PAYLOAD, $issuer);
            Keys::wantReason(static fn() => Jws::verify($c, $res), R::TYP_UNSUPPORTED, $typ);
        }
    }
}
