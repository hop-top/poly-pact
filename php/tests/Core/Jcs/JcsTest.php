<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jcs;

use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind as K;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8785 canonicalization. Port of go/core/jcs/jcs_test.go and the Python
 * port's test_jcs.py.
 *
 * Expected values were produced by the RFC 8785 Appendix A reference
 * canonicalizer running on V8 (as in the Go tests), not by this package.
 */
final class JcsTest extends TestCase
{
    /** The cases whose canonical form writes a float beyond 2^53-1 as an integer. */
    private const BEYOND_SAFE_INTEGER = ['numbers'];

    /** @return iterable<string, array{string, string, string}> */
    public static function canonicalizeCases(): iterable
    {
        $cases = [
            ['whitespace dropped', " { \"b\" : [ { \"z\" : 1 , \"y\" : [ ] } , { } ] , \"a\" : { \"d\" : null , \"c\" : true , \"e\" : false } } \n",
                '{"a":{"c":true,"d":null,"e":false},"b":[{"y":[],"z":1},{}]}'],
            ['array order kept', '[3,1,2,"b","a"]', '[3,1,2,"b","a"]'],
            ['empty containers', '[[],{}]', '[[],{}]'],
            ['top-level string', '"x"', '"x"'],
            ['top-level number', '1.50', '1.5'],
            ['top-level null', 'null', 'null'],
            ['top-level true', 'true', 'true'],
            ['top-level false', 'false', 'false'],
            ['top-level minus zero', '-0', '0'],
            // Property names sort by UTF-16 code units. U+10000 is the
            // surrogate pair D800 DC00, which sorts before U+FFFF; by code
            // point or by UTF-8 bytes it would sort after.
            ['keys by UTF-16 units', '{"\uffff":1,"\ud800\udc00":2,"a":3,"ab":4,"":5,"B":6}',
                "{\"\":5,\"B\":6,\"a\":3,\"ab\":4,\"\u{10000}\":2,\"\u{ffff}\":1}"],
            ['keys are compared unescaped', '{"\u0062":1,"a":2}', '{"a":2,"b":1}'],
            ['key escapes follow string rules', '{"\u000a":1,"\"":2,"\\\\":3,"/":4}', '{"\n":1,"\"":2,"/":4,"\\\\":3}'],
            ['string escapes',
                '"\u0000\u0001\u0008\u0009\u000a\u000b\u000c\u000d\u001f \" \\\\ / \u007f \u2028 \u2029 \u00e9 \ud83d\ude02 <>&\'"',
                "\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f \\\" \\\\ / \x7f \u{2028} \u{2029} \u{e9} \u{1F602} <>&'\""],
            ['string literal chars kept', "\"\u{e9}\u{20ac}\u{1F602}\"", "\"\u{e9}\u{20ac}\u{1F602}\""],
            ['no unicode normalization', '"A\u030a"', "\"A\u{30a}\""],
            ['numbers', '[1.0, -0, -0.0, 1E+2, 0.1, 1e21, 1e-7, 1.5e300, 5e-324, 1e-400, 0.000001, 0.0000001, 1e20, 123456789.125, 4.35, 0.30000000000000004, 1e22, 1e23, 12345678901234567890e0, 100e-2, 9007199254740991, -9007199254740991, 1.7976931348623157e308, 2.5e-5]',
                '[1,0,0,100,0.1,1e+21,1e-7,1.5e+300,5e-324,0,0.000001,1e-7,100000000000000000000,123456789.125,4.35,0.30000000000000004,1e+22,1e+23,12345678901234567000,1,9007199254740991,-9007199254740991,1.7976931348623157e+308,0.000025]'],
            // Two float edges: 1e-400 underflows to 0 and
            // 2.5e-324 rounds to the smallest subnormal.
            ['float edges', '[1e-400,2.5e-324,-2.5e-324]', '[0,5e-324,-5e-324]'],
        ];
        foreach ($cases as [$name, $in, $want]) {
            yield $name => [$name, $in, $want];
        }
    }

    #[DataProvider('canonicalizeCases')]
    public function testCanonicalize(string $name, string $in, string $want): void
    {
        $orig = $in;
        $got = Jcs::canonicalize($in);
        self::assertSame($want, $got, $name);
        self::assertSame($orig, $in, 'input was modified');
        // A canonical form is canonical. The one exception: a float such as
        // 1e20 is written without an exponent, and the strict parse rejects
        // an integer literal that large (testCanonicalOutputBeyondSafeInteger).
        if (\in_array($name, self::BEYOND_SAFE_INTEGER, true)) {
            self::assertKind(K::INTEGER, static fn() => Jcs::canonicalize($got));
        } else {
            self::assertSame($got, Jcs::canonicalize($got), 'not idempotent: ' . $name);
        }
        // The parsed tree canonicalizes to the same bytes as the text.
        self::assertSame($got, Jcs::canonicalizeValue(StrictJson::parse($in)), $name);
    }

    /** @return iterable<string, array{string, K}> */
    public static function rejectCases(): iterable
    {
        yield 'empty input' => ['', K::SYNTAX];
        yield 'only whitespace' => [' ', K::SYNTAX];
        yield 'truncated' => ['{"a":', K::SYNTAX];
        yield 'trailing comma' => ['[1,]', K::SYNTAX];
        yield 'duplicate key' => ['{"a":1,"a":2}', K::DUPLICATE_KEY];
        yield 'duplicate key in escaped form' => ['{"a":1,"\u0061":2}', K::DUPLICATE_KEY];
        yield 'duplicate key nested' => ['{"o":{"k":1,"k":1}}', K::DUPLICATE_KEY];
        yield 'NaN' => ['NaN', K::NON_FINITE];
        yield 'Infinity' => ['[Infinity]', K::NON_FINITE];
        yield 'negative Infinity' => ['-Infinity', K::NON_FINITE];
        yield 'overflowing literal' => ['1e999', K::NON_FINITE];
        yield 'negative overflowing literal' => ['{"a":-1e999}', K::NON_FINITE];
        yield 'integer 2^53' => ['9007199254740992', K::INTEGER];
        yield 'integer -2^53' => ['[-9007199254740992]', K::INTEGER];
        yield 'integer far outside' => ['{"a":123456789012345678901234567890}', K::INTEGER];
        yield 'lone high surrogate' => ['"\ud800"', K::LONE_SURROGATE];
        yield 'lone low surrogate' => ['"\udc00"', K::LONE_SURROGATE];
        yield 'invalid UTF-8' => ["\"\xff\"", K::INVALID_UTF8];
        yield 'encoded surrogate' => ["\"\xed\xa0\x80\"", K::INVALID_UTF8];
        yield 'trailing data' => ['{} {}', K::TRAILING_DATA];
        yield 'too deep' => [str_repeat('[', 17) . str_repeat(']', 17), K::DEPTH];
        yield 'too large' => ['"' . str_repeat('a', StrictJson::DEFAULT_MAX_BYTES) . '"', K::SIZE];
    }

    #[DataProvider('rejectCases')]
    public function testCanonicalizeRejects(string $in, K $want): void
    {
        self::assertKind($want, static fn() => Jcs::canonicalize($in));
    }

    /**
     * Integer literals beyond ±(2^53-1) are rejected on input, but a float
     * such as 1e20 is accepted and its canonical form is a plain integer
     * literal, which canonicalize in turn rejects.
     */
    public function testCanonicalOutputBeyondSafeInteger(): void
    {
        $out = Jcs::canonicalize('[1e20,1e21,9007199254740993.0]');
        self::assertSame('[100000000000000000000,1e+21,9007199254740992]', $out);
        self::assertKind(K::INTEGER, static fn() => Jcs::canonicalize($out));
    }

    public function testCanonicalizeAtDepthLimit(): void
    {
        $in = str_repeat('{"a":', 16) . '1' . str_repeat('}', 16);
        self::assertSame($in, Jcs::canonicalize($in));
    }

    public function testCanonicalizeSortsManyKeys(): void
    {
        $n = 200;
        $in = $want = [];
        for ($i = 0; $i < $n; ++$i) {
            // Zero-padded keys: written in descending order, sorted ascending.
            $in[] = \sprintf('"k%03d":%d', $n - 1 - $i, $i);
            $want[] = \sprintf('"k%03d":%d', $i, $n - 1 - $i);
        }
        self::assertSame('{' . implode(',', $want) . '}', Jcs::canonicalize('{' . implode(',', $in) . '}'));
    }

    /** The RFC 8785 section 3.2.3 sample: UTF-16 order differs from UTF-8 byte order. */
    public function testKeyOrderOfTheRfcSample(): void
    {
        $o = new JsonObject([
            "\u{20ac}" => 'Euro Sign',
            "\r" => 'Carriage Return',
            "\u{fb33}" => 'Hebrew Letter Dalet With Dagesh',
            '1' => 'One',
            "\u{1f600}" => 'Emoji: Grinning Face',
            "\u{80}" => 'Control',
            "\u{f6}" => 'Latin Small Letter O With Diaeresis',
        ]);
        self::assertSame(
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}",
            Jcs::canonicalizeValue($o),
        );
    }

    public function testIntegerLikeNamesSortAsStrings(): void
    {
        self::assertSame('{"10":1,"9":2,"a":3}', Jcs::canonicalize('{"a":3,"9":2,"10":1}'));
        self::assertSame('{"":1}', Jcs::canonicalizeValue(new JsonObject(['' => 1])));
    }

    public function testCanonicalizeValueIntegers(): void
    {
        self::assertSame('[0,0,9007199254740991,-9007199254740991]', Jcs::canonicalizeValue([0, -0, 9007199254740991, -9007199254740991]));
        foreach ([1 << 53, -(1 << 53), \PHP_INT_MAX, \PHP_INT_MIN] as $n) {
            $e = self::assertKind(K::INTEGER, static fn() => Jcs::canonicalizeValue(new JsonObject(['n' => $n])));
            self::assertSame('/n', $e->path);
        }
        // bool is not an integer.
        self::assertSame('[true,false]', Jcs::canonicalizeValue([true, false]));
    }

    public function testCanonicalizeValueNonFinite(): void
    {
        foreach ([\NAN, \INF, -\INF] as $f) {
            $e = self::assertKind(K::NON_FINITE, static fn() => Jcs::canonicalizeValue([1, new JsonObject(['x' => $f])]));
            self::assertSame('/1/x', $e->path);
        }
    }

    public function testCanonicalizeValueDepth(): void
    {
        $v = 1;
        for ($i = 0; $i < 16; ++$i) {
            $v = [$v];
        }
        self::assertSame(str_repeat('[', 16) . '1' . str_repeat(']', 16), Jcs::canonicalizeValue($v));
        $e = self::assertKind(K::DEPTH, static fn() => Jcs::canonicalizeValue(new JsonObject(['a' => $v])));
        self::assertSame('/a' . str_repeat('/0', 15), $e->path);
        $o = new JsonObject();
        for ($i = 0; $i < 17; ++$i) {
            $o = new JsonObject(['k' => $o]);
        }
        self::assertKind(K::DEPTH, static fn() => Jcs::canonicalizeValue($o));
    }

    public function testCanonicalizeValueStrings(): void
    {
        self::assertSame("\"\u{1f602}\u{2028}\"", Jcs::canonicalizeValue("\u{1f602}\u{2028}"));
        self::assertSame('"a/b"', Jcs::canonicalizeValue('a/b'));
        // The UTF-8 form of a surrogate is not UTF-8: a parsed value never holds it.
        self::assertKind(K::INVALID_UTF8, static fn() => Jcs::canonicalizeValue("\xed\xa0\xbd\xed\xb8\x82"));
        $e = self::assertKind(K::INVALID_UTF8, static fn() => Jcs::canonicalizeValue(new JsonObject(['k' => ['ok', "a\xff"]])));
        self::assertSame('/k/1', $e->path);
        $e = self::assertKind(K::INVALID_UTF8, static fn() => Jcs::canonicalizeValue(new JsonObject(['a' => new JsonObject(["\xc0" => 1])])));
        self::assertSame("/a/\xc0", $e->path);
        $e = self::assertKind(K::INVALID_UTF8, static fn() => Jcs::canonicalizeValue(new JsonObject(['a/b~' => "\xff"])));
        self::assertSame('/a~1b~0', $e->path);
    }

    /** @return iterable<string, array{mixed}> */
    public static function nonJson(): iterable
    {
        yield 'map array' => [['a' => 1]];
        yield 'sparse list' => [[1 => 1]];
        yield 'nested map array' => [new JsonObject(['a' => ['x' => 1]])];
        yield 'stdClass' => [new \stdClass()];
        yield 'object' => [new \ArrayObject([])];
        yield 'closure' => [static fn() => 1];
        yield 'resource' => [\STDIN];
    }

    #[DataProvider('nonJson')]
    public function testCanonicalizeValueRejectsNonJson(mixed $bad): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Jcs::canonicalizeValue($bad);
    }

    public function testCanonicalizeValueKeepsTheMemberOrderOfTheInputIrrelevant(): void
    {
        $a = JsonObject::fromPairs([['b', [1, new JsonObject(['d' => null])]], ['a', 'x']]);
        self::assertSame('{"a":"x","b":[1,{"d":null}]}', Jcs::canonicalizeValue($a));
    }

    /** The float formatter does not read serialize_precision, precision or the locale. */
    public function testIndependentOfIniAndLocale(): void
    {
        $sp = (string) \ini_get('serialize_precision');
        $p = (string) \ini_get('precision');
        $locale = setlocale(\LC_ALL, '0');
        try {
            ini_set('serialize_precision', '17');
            ini_set('precision', '5');
            setlocale(\LC_ALL, 'de_DE.UTF-8', 'fr_FR.UTF-8', 'de_DE', 'fr_FR');
            self::assertSame('[0.1,1.5,1e+21,1e-7,333333333.3333333]', Jcs::canonicalizeValue([0.1, 1.5, 1e21, 1e-7, 333333333.3333333]));
        } finally {
            ini_set('serialize_precision', $sp);
            ini_set('precision', $p);
            setlocale(\LC_ALL, $locale === false ? 'C' : $locale);
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
