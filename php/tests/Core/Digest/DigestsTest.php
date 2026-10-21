<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Digest;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Digest\Digests;
use HopTop\Pact\Core\Digest\NotObjectError;
use HopTop\Pact\Core\Intent;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind as K;
use HopTop\Pact\PactError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Object, artifact and bytes digests. Port of go/core/digest/digest_test.go
 * and the Python port's test_digest.py.
 *
 * Received JSON is a parsed value here, as in Python: the Go cases that pass
 * json.RawMessage run through StrictJson::parse() first.
 */
final class DigestsTest extends TestCase
{
    /** body_digest of draft Appendix B.3, the digest of zero bytes. */
    private const BODY_DIGEST_OF_EMPTY = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
    /** operation_digest and intent_digest of draft Appendix B.4. */
    private const OPERATION_DIGEST_B3 = 'R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0';
    private const INTENT_DIGEST_B2 = 't79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M';
    /** SHA-256("abc"), the FIPS 180-4 example, base64url. */
    private const DIGEST_OF_ABC = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';
    /** A JWS with the payload "{}" and the header {"alg":"ES256"}; SHA-256 over its 29 ASCII bytes. */
    private const SHORT_JWS = 'eyJhbGciOiJFUzI1NiJ9.e30.c2ln';
    private const DIGEST_OF_SHORT_JWS = 'E2ttONh1sD1zwHXFE8fH21SGQ5my65IRYl87KWSpu9o';

    private static function checkShape(Digest $d): void
    {
        $d->validate();
        self::assertSame(\strlen($d->value), strcspn($d->value, '=+/'));
    }

    private static function canonical(string $text): string
    {
        return Digests::bytesDigest($text)->value;
    }

    public function testBytesDigest(): void
    {
        self::assertSame(self::BODY_DIGEST_OF_EMPTY, Digests::bytesDigest('')->value);
        $d = Digests::bytesDigest('abc');
        self::assertSame(self::DIGEST_OF_ABC, $d->value);
        self::checkShape($d);
    }

    public function testArtifactDigest(): void
    {
        $got = Digests::artifactDigest(self::SHORT_JWS);
        self::assertSame(self::DIGEST_OF_SHORT_JWS, $got->value);
        self::checkShape($got);
        self::assertSame(Digests::bytesDigest(self::SHORT_JWS)->value, $got->value);
        // The exact string, no trimming.
        self::assertNotSame($got->value, Digests::artifactDigest(self::SHORT_JWS . "\n")->value);
        self::assertSame(self::BODY_DIGEST_OF_EMPTY, Digests::artifactDigest('')->value);
        foreach (["\u{e9}", self::SHORT_JWS . "\u{e9}", "a\x80b", "\xff", "a\u{2028}b"] as $s) {
            try {
                Digests::artifactDigest($s);
                self::fail('accepted ' . bin2hex($s));
            } catch (PactError $e) {
                self::assertStringContainsString('non-ASCII', $e->getMessage());
            }
        }
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function canonicalForm(): iterable
    {
        yield 'map members sorted' => [new JsonObject(['b' => 2, 'a' => 1]), '{"a":1,"b":2}'];
        yield 'struct members sorted' => [new Intent('i', 'p', 'd', 't'), '{"description":"d","intent_id":"i","purpose_id":"p","task_id":"t"}'];
        yield 'no HTML escaping' => [new JsonObject(['s' => '<a>&b']), '{"s":"<a>&b"}'];
        yield 'line separator is literal' => [new JsonObject(['s' => "\u{2028}"]), "{\"s\":\"\u{2028}\"}"];
        // U+1F600 is the surrogate pair D83D DE00 in UTF-16 and sorts before
        // U+FF5E, while UTF-8 byte order puts it after.
        yield 'member names sort by UTF-16 code units' => [new JsonObject(["\u{ff5e}" => 2, "\u{1f600}" => 1]), "{\"\u{1f600}\":1,\"\u{ff5e}\":2}"];
        yield 'ECMAScript numbers' => [new JsonObject(['n' => [-0.0, 1e21, 4.5, 100.0, 1e-7]]), '{"n":[0,1e+21,4.5,100,1e-7]}'];
        yield 'largest safe integer' => [new JsonObject(['n' => (1 << 53) - 1]), '{"n":9007199254740991}'];
        yield 'empty containers' => [new JsonObject(['b' => [], 'a' => new JsonObject()]), '{"a":{},"b":[]}'];
        yield 'nested objects and null' => [new JsonObject(['z' => null, 'a' => [new JsonObject(['y' => true, 'x' => false])]]), '{"a":[{"x":false,"y":true}],"z":null}'];
        yield 'string escapes' => [new JsonObject(['s' => "q\"\\\n\t\x01\x7f"]), "{\"s\":\"q\\\"\\\\\\n\\t\\u0001\x7f\"}"];
        yield 'raw JSON text is canonicalized, not copied' => [StrictJson::parse(" {\n  \"b\" : [ 1 , 2 ],\r\n  \"a\" : \"x\" }\n"), '{"a":"x","b":[1,2]}'];
        yield 'integer-like member names' => [StrictJson::parse('{"10":1,"9":2,"":3}'), '{"":3,"10":1,"9":2}'];
    }

    #[DataProvider('canonicalForm')]
    public function testObjectDigestCanonicalForm(mixed $value, string $want): void
    {
        $got = Digests::objectDigest($value);
        self::assertSame(self::canonical($want), $got->value);
        self::checkShape($got);
    }

    /** The core types, whose member order is not the sorted order, against the values of the draft. */
    public function testObjectDigestAppendixBStructs(): void
    {
        $op = new OperationContext(
            operation_id: 'invoice-read-operation-0001',
            environment_id: 'https://gateway.example/environments/finance',
            principal_id: 'https://identity.example/principals/alice',
            action: 'invoice.read',
            resources: ['https://invoices.example/invoices/INV-1042'],
            method: 'GET',
            target_uri: 'https://gateway.example/invoices/INV-1042',
            body_digest: self::BODY_DIGEST_OF_EMPTY,
            headers: new JsonObject(),
        );
        self::assertSame(self::OPERATION_DIGEST_B3, Digests::objectDigest($op)->value);
        $intent = new Intent(
            intent_id: 'intent-september-invoices-007',
            purpose_id: 'https://policies.example/purposes/invoice-summary/v1',
            description: 'Read the approved September invoice to prepare the department summary.',
            task_id: 'native-task:september-summary-007',
        );
        self::assertSame(self::INTENT_DIGEST_B2, Digests::objectDigest($intent)->value);
        // An absent optional member is left out, as Go's omitzero does; a
        // wire object nested in a JsonObject and a list is written too.
        self::assertSame(self::canonical('{"x":[{"description":"Read the approved September invoice to prepare the department summary.","intent_id":"intent-september-invoices-007","purpose_id":"https://policies.example/purposes/invoice-summary/v1","task_id":"native-task:september-summary-007"}]}'), Digests::objectDigest(new JsonObject(['x' => [$intent]]))->value);
        // A present optional member is written.
        $with = new Intent('i', 'p', 'd', 't', new JsonObject(['k' => 1]));
        self::assertSame(self::canonical('{"description":"d","extensions":{"k":1},"intent_id":"i","purpose_id":"p","task_id":"t"}'), Digests::objectDigest($with)->value);
        // The decoded wire object digests as its text does.
        $text = '{"operation_id":"invoice-read-operation-0001","environment_id":"https://gateway.example/environments/finance","principal_id":"https://identity.example/principals/alice","action":"invoice.read","resources":["https://invoices.example/invoices/INV-1042"],"method":"GET","target_uri":"https://gateway.example/invoices/INV-1042","body_digest":"' . self::BODY_DIGEST_OF_EMPTY . '","headers":{}}';
        self::assertSame(self::OPERATION_DIGEST_B3, Digests::objectDigest(StrictJson::decode($text, OperationContext::class))->value);
        self::assertSame(self::OPERATION_DIGEST_B3, Digests::objectDigest(StrictJson::parse($text))->value);
    }

    /** @return iterable<string, array{mixed}> */
    public static function nonObjects(): iterable
    {
        yield 'null' => [null];
        yield 'list of objects' => [[new JsonObject(['a' => 1])]];
        yield 'empty list' => [[]];
        yield 'string' => ['x'];
        yield 'int' => [1];
        yield 'bool' => [true];
        yield 'float' => [1.5];
        yield 'JSON text' => ['{"a":1}'];
        yield 'parsed list' => [StrictJson::parse('[{}]')];
        yield 'parsed string' => [StrictJson::parse('"x"')];
        yield 'parsed number' => [StrictJson::parse(' 1 ')];
        yield 'parsed null' => [StrictJson::parse('null')];
    }

    #[DataProvider('nonObjects')]
    public function testObjectDigestRejectsNonObjects(mixed $value): void
    {
        $this->expectException(NotObjectError::class);
        $this->expectExceptionMessage('digest: value is not a JSON object');
        Digests::objectDigest($value);
    }

    private static function nested(int $depth): mixed
    {
        return StrictJson::parse(str_repeat('{"a":', $depth - 1) . '{}' . str_repeat('}', $depth - 1), new Limits(maxDepth: $depth));
    }

    /** @return iterable<string, array{mixed, K}> */
    public static function limits(): iterable
    {
        yield 'NaN' => [new JsonObject(['n' => \NAN]), K::NON_FINITE];
        yield 'Infinity' => [new JsonObject(['n' => \INF]), K::NON_FINITE];
        yield 'integer above 2^53-1' => [new JsonObject(['n' => 1 << 53]), K::INTEGER];
        yield 'integer below -(2^53-1)' => [new JsonObject(['n' => -(1 << 53)]), K::INTEGER];
        yield 'nesting depth 17' => [self::nested(17), K::DEPTH];
        yield 'invalid UTF-8' => [new JsonObject(['a' => "\xed\xa0\x80"]), K::INVALID_UTF8];
        yield 'over 256 KiB' => [new JsonObject(['s' => str_repeat('a', StrictJson::DEFAULT_MAX_BYTES)]), K::SIZE];
    }

    #[DataProvider('limits')]
    public function testObjectDigestLimits(mixed $value, K $want): void
    {
        self::assertKind($want, static fn() => Digests::objectDigest($value));
    }

    public function testObjectDigestLimitsUnsupportedType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Digests::objectDigest(new JsonObject(['c' => new \stdClass()]));
    }

    /** Received text reaches objectDigest only through the strict parse. */
    public function testObjectDigestLimitsReceivedText(): void
    {
        foreach ([
            ['{"a":1,"a":2}', K::DUPLICATE_KEY],
            ['{"a":1,"a":2}', K::DUPLICATE_KEY],
            ["{\"a\":\"\xff\"}", K::INVALID_UTF8],
            ['{"a":"\ud800"}', K::LONE_SURROGATE],
            ['{"a":', K::SYNTAX],
        ] as [$text, $want]) {
            self::assertKind($want, static fn() => Digests::objectDigest(StrictJson::parse($text)));
        }
    }

    /**
     * Go's verdicts (hop.top/pact-go/core/digest.ObjectDigest) for {"n": f}:
     * an integral float above 2^53-1 and below 1e21 is written as an integer
     * literal, which the strict re-parse refuses with ErrInteger.
     *
     * @return iterable<string, array{float, ?string}>
     */
    public static function goFloatVerdicts(): iterable
    {
        yield '2^53' => [(float) (1 << 53), null];
        yield '-2^53' => [-(float) (1 << 53), null];
        yield '2^53-1' => [9007199254740991.0, '4dpIxqYInwbstOCiJZ5ljjeGskIPUrrM35KexkYNe0E'];
        yield '1e20' => [1e20, null];
        yield 'below 1e21' => [9.999999999999999e20, null];
        yield '1e21' => [1e21, '8e4rYO6VoxcP3Aeld-XzUUztJoZ0Q9adomWsrerYEAc'];
        yield '1e16' => [1e16, null];
        yield '1.5e300' => [1.5e300, 'UcmMvoGqYIL71tiCcu99Go78jW8T6xbII3YTkVBnZ2A'];
        yield '1e-7' => [1e-7, 'dH1tI7ZNGy1XmtuDK0TeMckch1u-96jjl_XRg6dGtUs'];
        yield '-0' => [-0.0, '8wE_kzufuAq22ZXnrZ2jb2g4N7odgelQyUPUARHqwvA'];
        yield '123456789012345680000' => [123456789012345680000.0, null];
    }

    #[DataProvider('goFloatVerdicts')]
    public function testObjectDigestLimitsFloatOfIntegerValue(float $f, ?string $want): void
    {
        if ($want !== null) {
            self::assertSame($want, Digests::objectDigest(new JsonObject(['n' => $f]))->value);

            return;
        }
        $e = self::assertKind(K::INTEGER, static fn() => Digests::objectDigest(new JsonObject(['n' => $f])));
        self::assertSame('/n', $e->path);
        // The same float parsed from text is refused too: a digest is never
        // taken over text a receiver's strict parse refuses.
        $e = self::assertKind(K::INTEGER, static fn() => Digests::objectDigest(StrictJson::parse('{"b":1.5e300,"a":[{"n":9007199254740992.0}],"c":1e20}')));
        self::assertSame('/a/0/n', $e->path);
    }

    /**
     * Go's verdicts for the size limit, which applies to Go's JSON encoding
     * of the value: U+2028 and U+2029 are escaped there (6 bytes, 3 in the
     * canonical form), -0.0 is written "-0" ("0" canonical); \b and \f are
     * short in both.
     *
     * @return iterable<string, array{JsonObject, bool}>
     */
    public static function goSizeVerdicts(): iterable
    {
        $pad = StrictJson::DEFAULT_MAX_BYTES - \strlen('{"s":""}');
        yield 'exact a' => [new JsonObject(['s' => str_repeat('a', $pad)]), true];
        yield 'a plus 1' => [new JsonObject(['s' => str_repeat('a', $pad + 1)]), false];
        yield '2028 near limit' => [new JsonObject(['s' => str_repeat('a', $pad - 3) . "\u{2028}"]), false];
        yield '2029 near limit' => [new JsonObject(['s' => str_repeat('a', $pad - 3) . "\u{2029}"]), false];
        yield '2028 within' => [new JsonObject(['s' => str_repeat('a', $pad - 6) . "\u{2028}"]), true];
        yield 'bf near limit' => [new JsonObject(['s' => str_repeat('a', $pad - 2) . "\x08"]), true];
        yield 'negative zero' => [new JsonObject(['z' => -0.0, 's' => str_repeat('a', StrictJson::DEFAULT_MAX_BYTES - \strlen('{"s":"","z":0}'))]), false];
        yield 'positive zero' => [new JsonObject(['z' => 0.0, 's' => str_repeat('a', StrictJson::DEFAULT_MAX_BYTES - \strlen('{"s":"","z":0}'))]), true];
    }

    #[DataProvider('goSizeVerdicts')]
    public function testObjectDigestLimitsSizeOfGoEncoding(JsonObject $value, bool $ok): void
    {
        if ($ok) {
            self::checkShape(Digests::objectDigest($value));

            return;
        }
        self::assertKind(K::SIZE, static fn() => Digests::objectDigest($value));
    }

    /** 100 KiB of '<' is 600 KiB when escaped as <, over the limit, and 100 KiB canonical. */
    public function testObjectDigestLimitsHtmlCharactersDoNotCount(): void
    {
        self::checkShape(Digests::objectDigest(new JsonObject(['s' => str_repeat('<', 100 << 10)])));
    }

    public function testObjectDigestLimitsNestingDepth16IsAccepted(): void
    {
        self::checkShape(Digests::objectDigest(self::nested(16)));
    }

    public function testObjectDigestIgnoresInputShape(): void
    {
        $viaParse = Digests::objectDigest(StrictJson::parse('{"headers":{"x":"1"},"a":[3,2,1],"b":{"d":null,"c":1.5}}'));
        $viaValue = Digests::objectDigest(new JsonObject(['headers' => new JsonObject(['x' => '1']), 'a' => [3, 2, 1], 'b' => new JsonObject(['c' => 1.5, 'd' => null])]));
        $want = self::canonical('{"a":[3,2,1],"b":{"c":1.5,"d":null},"headers":{"x":"1"}}');
        self::assertSame($want, $viaParse->value);
        self::assertSame($want, $viaValue->value);
    }

    public function testErrorsArePactErrors(): void
    {
        foreach ([null, new JsonObject(['n' => \NAN])] as $v) {
            try {
                Digests::objectDigest($v);
                self::fail('accepted');
            } catch (PactError $e) {
                self::assertContains($e::class, [NotObjectError::class, StrictJsonError::class]);
            }
        }
    }

    private static function assertKind(K $want, \Closure $f): StrictJsonError
    {
        try {
            $f();
        } catch (StrictJsonError $e) {
            self::assertSame($want, $e->kind, $e->getMessage());

            return $e;
        }
        self::fail('no StrictJsonError, want ' . $want->value);
    }
}
