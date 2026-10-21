<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Mode;
use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind as K;
use HopTop\Pact\PactError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Strict JSON decoding. Port of go/core/strictjson/strictjson_test.go, with
 * Sample mirroring the Go test's sample struct.
 */
final class StrictJsonTest extends TestCase
{
    private static function decode(string $data, ?Limits $lim = null): Sample
    {
        return StrictJson::decode($data, Sample::class, $lim);
    }

    private static function kindOf(string $data, ?Limits $lim = null): K
    {
        try {
            self::decode($data, $lim);
        } catch (StrictJsonError $e) {
            return $e->kind;
        }
        self::fail('accepted ' . json_encode($data, \JSON_INVALID_UTF8_SUBSTITUTE));
    }

    public function testDecodeValid(): void
    {
        $src = '{"name":"a","count":9007199254740991,"ratio":1.5e3,"opt":null,"opt_count":7,'
            . '"inner":{"n":0},"items":[{"n":1},{"n":2}],"raw":{"x":[1,2,{"y":null}]},'
            . '"headers":{"x-a":"1"},"extensions":{"k":{"deep":[true,false,null]}}}';
        $got = self::decode($src);
        self::assertSame(['a', 9007199254740991, 1500.0], [$got->name, $got->count, $got->ratio]);
        self::assertNull($got->opt);
        self::assertSame(7, $got->opt_count);
        self::assertEquals(new Inner(0), $got->inner);
        self::assertEquals([new Inner(1), new Inner(2)], $got->items);
        self::assertEquals(JsonObject::fromPairs([['x', [1, 2, JsonObject::fromPairs([['y', null]])]]]), $got->raw);
        self::assertSame([['x-a', '1']], $got->headers->pairs());
        self::assertEquals(JsonObject::fromPairs([['k', JsonObject::fromPairs([['deep', [true, false, null]]])]]), $got->extensions);
    }

    private static function deepArrays(int $n): string
    {
        return '{"extensions":{"a":' . str_repeat('[', $n - 2) . str_repeat(']', $n - 2) . '}}';
    }

    /** @return iterable<string, array{string, Limits, K}> */
    public static function rejects(): iterable
    {
        $l = new Limits();
        yield 'duplicate top level' => ['{"name":"a","name":"b"}', $l, K::DUPLICATE_KEY];
        yield 'duplicate same value' => ['{"name":"a","name":"a"}', $l, K::DUPLICATE_KEY];
        yield 'duplicate nested struct' => ['{"inner":{"n":1,"n":2}}', $l, K::DUPLICATE_KEY];
        yield 'duplicate in open map' => ['{"extensions":{"a":{"b":1,"b":2}}}', $l, K::DUPLICATE_KEY];
        yield 'duplicate in headers' => ['{"headers":{"x":"1","x":"2"}}', $l, K::DUPLICATE_KEY];
        yield 'duplicate in raw' => ['{"raw":{"a":1,"a":2}}', $l, K::DUPLICATE_KEY];
        yield 'duplicate in array element' => ['{"items":[{"n":1},{"n":1,"n":1}]}', $l, K::DUPLICATE_KEY];
        yield 'duplicate after unescape' => ['{"name":"a","name":"b"}', $l, K::DUPLICATE_KEY];
        yield 'duplicate integer-like name' => ['{"extensions":{"1":1,"1":2}}', $l, K::DUPLICATE_KEY];
        yield 'unknown field' => ['{"name":"a","bogus":1}', $l, K::UNKNOWN_FIELD];
        yield 'unknown nested field' => ['{"inner":{"n":1,"m":2}}', $l, K::UNKNOWN_FIELD];
        yield 'unknown field in array element' => ['{"items":[{"n":1,"m":2}]}', $l, K::UNKNOWN_FIELD];
        yield 'case variant is unknown' => ['{"Name":"a"}', $l, K::UNKNOWN_FIELD];
        yield 'case variant beside real field' => ['{"name":"a","NAME":"b"}', $l, K::UNKNOWN_FIELD];
        yield 'depth 17 objects' => ['{"extensions":' . str_repeat('{"a":', 15) . '{}' . str_repeat('}', 15) . '}', $l, K::DEPTH];
        yield 'depth 17 arrays' => [self::deepArrays(17), $l, K::DEPTH];
        yield 'custom depth' => ['{"raw":[[1]]}', new Limits(maxDepth: 2), K::DEPTH];
        yield '1e999' => ['{"ratio":1e999}', $l, K::NON_FINITE];
        yield '-1e999 in raw' => ['{"raw":-1e999}', $l, K::NON_FINITE];
        yield 'NaN' => ['{"raw":NaN}', $l, K::NON_FINITE];
        yield 'Infinity' => ['{"raw":Infinity}', $l, K::NON_FINITE];
        yield '-Infinity' => ['{"raw":-Infinity}', $l, K::NON_FINITE];
        yield 'invalid utf8 byte' => ["{\"name\":\"\xff\"}", $l, K::INVALID_UTF8];
        yield 'invalid utf8 in key' => ["{\"na\xc0me\":1}", $l, K::INVALID_UTF8];
        yield 'lone high surrogate' => ['{"name":"\ud800"}', $l, K::LONE_SURROGATE];
        yield 'lone low surrogate' => ['{"name":"\udc00"}', $l, K::LONE_SURROGATE];
        yield 'high then bmp' => ['{"name":"\ud800A"}', $l, K::LONE_SURROGATE];
        yield 'reversed pair' => ['{"name":"\udc00\ud800"}', $l, K::LONE_SURROGATE];
        yield 'lone surrogates replaced before the duplicate check' => ['{"extensions":{"\ud800":1,"\udbff":2}}', $l, K::DUPLICATE_KEY];
        yield 'surrogate in key' => ['{"extensions":{"\ud800":1}}', $l, K::LONE_SURROGATE];
        yield 'escaped backslash is not a surrogate escape guard' => ['{"name":"\\\\\ud800"}', $l, K::LONE_SURROGATE];
        yield 'integer 2^53' => ['{"raw":9007199254740992}', $l, K::INTEGER];
        yield 'integer -2^53' => ['{"raw":-9007199254740992}', $l, K::INTEGER];
        yield 'integer huge' => ['{"raw":123456789012345678901234567890}', $l, K::INTEGER];
        yield 'integer of 5000 digits' => ['{"raw":' . str_repeat('9', 5000) . '}', $l, K::INTEGER];
        yield 'typed integer overflow' => ['{"count":9007199254740992}', $l, K::INTEGER];
        yield 'typed integer negative' => ['{"count":-1}', $l, K::INTEGER];
        yield 'typed integer fraction' => ['{"count":1.5}', $l, K::INTEGER];
        yield 'typed integer exponent form' => ['{"count":1e3}', $l, K::INTEGER];
        yield 'typed integer 1.0' => ['{"count":1.0}', $l, K::INTEGER];
        yield 'nullable integer negative' => ['{"opt_count":-5}', $l, K::INTEGER];
        yield 'trailing text' => ['{"name":"a"} x', $l, K::TRAILING_DATA];
        yield 'trailing value' => ['{"name":"a"}{}', $l, K::TRAILING_DATA];
        yield 'trailing brace' => ['{"name":"a"}}', $l, K::TRAILING_DATA];
        yield 'empty input' => ['', $l, K::SYNTAX];
        yield 'whitespace only' => [" \n", $l, K::SYNTAX];
        yield 'truncated' => ['{"name":"a"', $l, K::SYNTAX];
        yield 'bom' => ["\xef\xbb\xbf{}", $l, K::SYNTAX];
        yield 'leading zero' => ['{"raw":01}', $l, K::SYNTAX];
        yield 'single quotes' => ["{'name':'a'}", $l, K::SYNTAX];
        yield 'trailing comma' => ['{"name":"a",}', $l, K::SYNTAX];
        yield 'too large' => ['{"name":"' . str_repeat('a', 64) . '"}', new Limits(maxBytes: 32), K::SIZE];
        yield 'null for string' => ['{"name":null}', $l, K::NULL];
        yield 'null for integer' => ['{"count":null}', $l, K::NULL];
        yield 'null for slice' => ['{"items":null}', $l, K::NULL];
        yield 'null for map' => ['{"headers":null}', $l, K::NULL];
        yield 'null document' => ['null', $l, K::NULL];
        yield 'type mismatch' => ['{"name":5}', $l, K::TYPE];
        yield 'type mismatch object' => ['{"name":{}}', $l, K::TYPE];
    }

    #[DataProvider('rejects')]
    public function testDecodeRejects(string $data, Limits $lim, K $want): void
    {
        self::assertSame($want, self::kindOf($data, $lim));
    }

    /** @return iterable<string, array{string, Limits}> */
    public static function accepts(): iterable
    {
        $l = new Limits();
        yield 'depth 16 objects' => ['{"extensions":' . str_repeat('{"a":', 14) . '{}' . str_repeat('}', 14) . '}', $l];
        yield 'depth 16 arrays' => [self::deepArrays(16), $l];
        yield 'max safe integer' => ['{"count":9007199254740991,"raw":9007199254740991}', $l];
        yield 'negative max safe in raw' => ['{"raw":-9007199254740991}', $l];
        yield 'zero count' => ['{"count":0}', $l];
        yield 'negative zero in raw' => ['{"raw":-0}', $l];
        yield 'largest finite float' => ['{"ratio":1.7976931348623157e308}', $l];
        yield 'negative float' => ['{"ratio":-12.5}', $l];
        yield 'float underflow is finite' => ['{"ratio":1e-999}', $l];
        yield 'surrogate pair' => ["{\"name\":\"\u{1F600}\"}", $l];
        yield 'escaped surrogate pair' => ['{"name":"😀"}', $l];
        yield 'escaped backslash then u' => ['{"name":"\\\\ud800"}', $l];
        yield 'replacement char literal' => ["{\"name\":\"\u{FFFD}\"}", $l];
        yield 'case distinct keys in open map' => ['{"extensions":{"a":1,"A":2}}', $l];
        yield 'same key in sibling objects' => ['{"items":[{"n":1},{"n":2}],"inner":{"n":3}}', $l];
        yield 'trailing whitespace' => ["{\"name\":\"a\"}\n \t\r\n", $l];
        yield 'leading whitespace' => [" \n{\"name\":\"a\"}", $l];
        yield 'null in raw' => ['{"raw":null}', $l];
        yield 'null in nullable' => ['{"opt":null,"opt_count":null}', $l];
        yield 'null in nullable struct pointer' => ['{"inner":null}', $l];
        yield 'custom depth' => ['{"raw":[[1]]}', new Limits(maxDepth: 3)];
        yield 'exact size' => ['{"name":"a"}', new Limits(maxBytes: 12)];
        yield 'empty object' => ['{}', $l];
        yield 'NUL-leading name' => ['{"extensions":{"\u0000a":1}}', $l];
    }

    #[DataProvider('accepts')]
    public function testDecodeAccepts(string $data, Limits $lim): void
    {
        self::assertInstanceOf(Sample::class, self::decode($data, $lim));
    }

    public function testDecodeFloatEdges(): void
    {
        // Go's ParseFloat returns 0 for 1e-400 without an error and 5e-324
        // for 2.5e-324 (round half to even onto the smallest subnormal).
        self::assertSame(0.0, self::decode('{"ratio":1e-400}')->ratio);
        self::assertSame(5e-324, self::decode('{"ratio":2.5e-324}')->ratio);
        $got = StrictJson::parse('[1e-400,2.5e-324,-0.0,1.0,1E2]');
        self::assertSame('[0.0,5.0e-324,-0.0,1.0,100.0]', json_encode($got, \JSON_PRESERVE_ZERO_FRACTION));
        self::assertSame(1500.0, self::decode('{"ratio":1500}')->ratio, 'an integer literal into a number member');
    }

    public function testValueModel(): void
    {
        $v = StrictJson::parse('{"a":[1,{"b":null}],"A":2,"1":"x","s":"é\n","f":-0,"o":{},"l":[]}');
        self::assertInstanceOf(JsonObject::class, $v);
        self::assertSame(['a', 'A', '1', 's', 'f', 'o', 'l'], $v->names());
        $a = $v->get('a');
        self::assertIsArray($a);
        self::assertSame(1, $a[0]);
        self::assertInstanceOf(JsonObject::class, $a[1]);
        self::assertSame("é\n", $v->get('s'));
        self::assertSame(0, $v->get('f'));
        self::assertEquals(new JsonObject(), $v->get('o'));
        self::assertSame([], $v->get('l'));
        self::assertSame(5, StrictJson::parse(' 5 '));
    }

    public function testDecodeFreeFormTarget(): void
    {
        $v = StrictJson::parse('{"a":[1,{"b":null}],"A":2}');
        self::assertEquals(JsonObject::fromPairs([['a', [1, JsonObject::fromPairs([['b', null]])]], ['A', 2]]), $v);
        foreach ([fn() => StrictJson::parse('{"a":1,"a":2}'), fn() => StrictJson::decode('{"x":9007199254740992}', JsonObject::class)] as $i => $f) {
            try {
                $f();
                self::fail('accepted');
            } catch (StrictJsonError $e) {
                self::assertSame($i === 0 ? K::DUPLICATE_KEY : K::INTEGER, $e->kind);
            }
        }
        self::assertSame([['x', 1]], StrictJson::decode('{"x":1}', JsonObject::class)->pairs());
    }

    public function testDecodeReplacesTarget(): void
    {
        $got = self::decode('{"headers":{"new":"2"}}');
        self::assertSame('', $got->name);
        self::assertSame(0, $got->count);
        self::assertSame(0.0, $got->ratio);
        self::assertNull($got->inner);
        self::assertSame([], $got->items);
        self::assertNull($got->raw);
        self::assertSame([['new', '2']], $got->headers->pairs());
        self::assertCount(0, $got->extensions);
    }

    public function testAbsentRequiredMembersHoldZeroValues(): void
    {
        $op = StrictJson::decode('{}', OperationContext::class);
        self::assertSame('', $op->operation_id);
        self::assertSame([], $op->resources);
        self::assertCount(0, $op->headers);
        self::assertNull($op->extensions, 'an optional member stays absent');
        $op = StrictJson::decode('{"extensions":{}}', OperationContext::class);
        self::assertNotNull($op->extensions);
        self::assertCount(0, $op->extensions);
    }

    public function testEnumMembersHoldTheReceivedString(): void
    {
        // The decoder does not apply enum sets; the schema validator does.
        $c = StrictJson::decode('{"mode":"bogus"}', \HopTop\Pact\Core\RequirementContract::class);
        self::assertSame('bogus', $c->mode);
        self::assertFalse(Mode::isValid($c->mode));
    }

    /** @return iterable<string, array{string}> */
    public static function badTargets(): iterable
    {
        yield 'empty' => [''];
        yield 'missing class' => ['HopTop\Pact\Nope'];
        yield 'no members table' => [\stdClass::class];
        yield 'enum' => [Mode::class];
        yield 'malformed members' => [BadMembers::class];
        yield 'constructor disagrees' => [BadConstructor::class];
        yield 'bad nested ref' => [BadRef::class];
    }

    #[DataProvider('badTargets')]
    public function testDecodeBadTarget(string $target): void
    {
        try {
            // Through reflection: the static type of $class would refuse these.
            (new \ReflectionMethod(StrictJson::class, 'decode'))->invoke(null, '{}', $target);
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame(K::TARGET, $e->kind);
        }
    }

    public function testUnmarshalMatchesDecode(): void
    {
        $data = '{"name":"a","name":"b"}';
        $stream = fopen('php://memory', 'w+');
        self::assertIsResource($stream);
        fwrite($stream, $data);
        rewind($stream);
        foreach ([fn() => StrictJson::decode($data, Sample::class), fn() => StrictJson::parse($data), fn() => StrictJson::parseStream($stream)] as $f) {
            try {
                $f();
                self::fail('accepted');
            } catch (StrictJsonError $e) {
                self::assertSame(K::DUPLICATE_KEY, $e->kind);
            }
        }
    }

    public function testParseStreamReadsAtMostOneByteOverTheLimit(): void
    {
        $src = fopen('php://temp', 'w+');
        self::assertIsResource($src);
        fwrite($src, str_repeat(' ', 10000));
        rewind($src);
        try {
            StrictJson::parseStream($src, new Limits(maxBytes: 100));
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame(K::SIZE, $e->kind);
        }
        self::assertSame(101, ftell($src));
        $ok = fopen('php://memory', 'w+');
        self::assertIsResource($ok);
        fwrite($ok, ' {"a":[1]} ');
        rewind($ok);
        self::assertEquals(JsonObject::fromPairs([['a', [1]]]), StrictJson::parseStream($ok, new Limits(maxBytes: 11)));
    }

    public function testErrorNamesPathAndOffset(): void
    {
        try {
            self::decode('{"inner":{"n":1,"m":2}}');
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertStringContainsString('/inner/m', $e->getMessage());
            self::assertStringContainsString('(offset 19)', $e->getMessage());
        }
    }

    public function testDepthIsCheckedBeforeBodyIsRead(): void
    {
        // A hostile document opens many containers; the walk stops at the limit.
        $this->expectExceptionObject(new StrictJsonError(K::DEPTH, '/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0', 17, 'depth 17 exceeds the limit of 16'));
        StrictJson::parse(str_repeat('[', 100000), new Limits(maxBytes: 1 << 20));
    }

    public function testDepthDoesNotDependOnTheCallStack(): void
    {
        // A configured depth far above the baseline holds. PHP itself frees
        // nested arrays recursively and crashes on about 100000 levels (8 MiB
        // C stack), so the test stays below that.
        $n = 40000;
        $deep = str_repeat('[', $n) . str_repeat(']', $n);
        self::assertNotNull(StrictJson::parse($deep, new Limits(maxBytes: 1 << 20, maxDepth: $n)));
        try {
            StrictJson::parse($deep, new Limits(maxBytes: 1 << 20, maxDepth: $n - 1));
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame(K::DEPTH, $e->kind);
            self::assertSame($n, $e->offset);
        }
    }

    public function testErrorFields(): void
    {
        try {
            self::decode('{"items":[{"n":1},{"n":1,"x~/":2}]}');
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame(K::UNKNOWN_FIELD, $e->kind);
            self::assertSame('/items/1/x~0~1', $e->path);
            self::assertGreaterThan(0, $e->offset);
            self::assertInstanceOf(PactError::class, $e);
        }
    }

    public function testErrorString(): void
    {
        $e = new StrictJsonError(K::DUPLICATE_KEY, '/a', 7, '"a"');
        self::assertSame('strictjson: duplicate member name: "a" at /a (offset 7)', $e->getMessage());
        self::assertSame('strictjson: invalid JSON (offset 0)', (new StrictJsonError(K::SYNTAX))->getMessage());
    }

    public function testDefaults(): void
    {
        self::assertSame(9007199254740991, StrictJson::MAX_SAFE_INTEGER);
        self::assertSame(262144, StrictJson::DEFAULT_MAX_BYTES);
        self::assertSame(16, StrictJson::DEFAULT_MAX_DEPTH);
        self::assertSame(13, \count(K::cases()));
    }
}
