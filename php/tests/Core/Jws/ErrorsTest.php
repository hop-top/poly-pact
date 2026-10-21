<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Jws\Base64Url;
use HopTop\Pact\Core\Jws\Es256;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Core\Jws\Reason;
use HopTop\Pact\Core\Jws\StaticResolver;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use HopTop\Pact\PactError;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\TestCase;

/**
 * Reasons, the error, base64url segments and RFC 7515 Appendix A.3. Port of
 * the rest of go/core/jws/jws_test.go and rfc7515_internal_test.go, and of
 * the Python port's test_jws.py.
 */
final class ErrorsTest extends TestCase
{
    /** RFC 7515 Appendix A.3: ES256 over P-256, copied from the RFC text. */
    private const A3_COMPACT = 'eyJhbGciOiJFUzI1NiJ9'
        . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        . '.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
    private const A3_X = 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU';
    private const A3_Y = 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0';
    private const A3_R = [14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101];
    private const A3_S = [197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213];
    /** UTF-8 of the protected header {"alg":"ES256"}. */
    private const A3_HEADER = [123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125];

    /** The Go sentinels of go/core/jws/errors.go, in their order. */
    public function testReasonsMatchGo(): void
    {
        $src = Repo::read('go/core/jws/errors.go');
        preg_match_all('/^\tErr\w+ Reason = "([a-z0-9-]+)"$/m', $src, $m);
        self::assertCount(29, $m[1]);
        self::assertSame($m[1], array_map(static fn(Reason $r): string => $r->value, Reason::cases()));
        foreach (Reason::cases() as $r) {
            self::assertSame($r->value === 'base64url' ? 'BASE64_URL' : strtoupper(strtr($r->value, '-', '_')), $r->name);
        }
    }

    public function testReasonOf(): void
    {
        self::assertNull(Jws::reasonOf(null));
        self::assertNull(Jws::reasonOf(new \ValueError('x')));
        $h = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}';
        $c = Keys::rawCompact($h, Keys::SMALL_PAYLOAD, Keys::scalarKey(2));
        $err = Keys::wantReason(static fn() => Jws::verify($c, Keys::issuerResolver()), Reason::HEADER_JSON);
        $prev = $err->getPrevious();
        self::assertInstanceOf(StrictJsonError::class, $prev);
        self::assertSame(StrictJsonErrorKind::DUPLICATE_KEY, $prev->kind);
        self::assertStringStartsWith('jws: header-json: strictjson: duplicate member name', $err->getMessage());
        // The reason of a JwsError behind another package error.
        $outer = new PactError('wrapped', 0, $err);
        self::assertSame(Reason::HEADER_JSON, Jws::reasonOf($outer));
        // Not through an exception of another library.
        self::assertNull(Jws::reasonOf(new \RuntimeException('wrapped', 0, $err)));
    }

    public function testJwsErrorIsPactError(): void
    {
        $e = new JwsError(Reason::KID_UNKNOWN, 'kid x', new \ValueError('cause'));
        self::assertInstanceOf(PactError::class, $e);
        self::assertSame([Reason::KID_UNKNOWN, 'kid x'], [$e->reason, $e->detail]);
        self::assertInstanceOf(\ValueError::class, $e->getPrevious());
        self::assertSame('jws: kid-unknown: kid x: cause', $e->getMessage());
        self::assertSame('jws: kid-unknown', (new JwsError(Reason::KID_UNKNOWN))->getMessage());
        self::assertSame('jws: kid-unknown: cause', (new JwsError(Reason::KID_UNKNOWN, '', new \ValueError('cause')))->getMessage());
        self::assertSame('jws: kid-unknown', Reason::KID_UNKNOWN->message());
    }

    /** RFC 7515 base64url: URL-safe alphabet, no padding, no white space, canonical. */
    public function testDecodeSegment(): void
    {
        self::assertSame('', Base64Url::decode(''));
        self::assertSame("\x00", Base64Url::decode('AA'));
        self::assertSame("\x00\x00", Base64Url::decode('AAA'));
        self::assertSame("\xff\xef", Base64Url::decode('_-8'));
        self::assertSame('_-8', Base64Url::encode("\xff\xef"));
        self::assertSame('', Base64Url::encode(''));
        foreach (['AB', 'AAB', 'AA==', 'AAA=', 'A', 'AAAAA', 'A+A', 'A/A', "AA\n", ' AA', "A\u{c0}", "\0AA"] as $bad) {
            try {
                Base64Url::decode($bad);
                self::fail(json_encode($bad) . ' decoded');
            } catch (\UnexpectedValueException $e) {
                self::assertStringStartsWith('base64url: ', $e->getMessage());
            }
        }
        // Every value of 0 to 3 octets round-trips, and its encoding is the only one accepted.
        for ($i = 0; $i < 256; ++$i) {
            foreach ([\chr($i), \chr($i) . "\x5a", "\x01\x02" . \chr($i)] as $b) {
                self::assertSame($b, Base64Url::decode(Base64Url::encode($b)));
            }
        }
    }

    public function testRfc7515A3(): void
    {
        [$h, $p, $s] = explode('.', self::A3_COMPACT);
        self::assertSame(pack('C*', ...self::A3_HEADER), Base64Url::decode($h));
        $sig = Base64Url::decode($s);
        self::assertSame(pack('C*', ...self::A3_R) . pack('C*', ...self::A3_S), $sig);
        $pub = (new Jwk('EC', 'P-256', self::A3_X, self::A3_Y))->publicKey();
        $si = $h . '.' . $p;
        self::assertTrue(Es256::verify($pub, $si, $sig));
        self::assertFalse(Es256::verify($pub, $si . 'A', $sig));
        $flipped = $sig;
        $flipped[63] = \chr(\ord($flipped[63]) ^ 1);
        self::assertFalse(Es256::verify($pub, $si, $flipped));
        // A PACT verifier still rejects the JWS: its header has no typ.
        Keys::wantReason(static fn() => Jws::verify(self::A3_COMPACT, new StaticResolver()), Reason::TYP_UNSUPPORTED);
    }

    /** The scalar arithmetic and the R || S conversion of the ES256 helper. */
    public function testEs256Arithmetic(): void
    {
        $n = Keys::n();
        self::assertSame(Es256::N, $n);
        $one = Keys::scalar(1);
        self::assertSame(Keys::sub($n, $one), Es256::sub($n, $one));
        self::assertSame(Es256::HALF_N, Es256::sub(Es256::sub($n, Es256::HALF_N), $one));
        self::assertTrue(Es256::inRange($one));
        self::assertTrue(Es256::inRange(Keys::sub($n, $one)));
        self::assertFalse(Es256::inRange(str_repeat("\0", 32)));
        self::assertFalse(Es256::inRange($n));
        self::assertFalse(Es256::inRange(str_repeat("\xff", 32)));
        self::assertFalse(Es256::inRange("\x01"));
        self::assertNull(Es256::privateKey(str_repeat("\0", 32)));
        self::assertNull(Es256::privateKey($n));
        self::assertNull(Es256::publicKey('', ''));
    }
}
