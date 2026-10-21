<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jcs;

use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ECMAScript number text (RFC 8785 section 3.2.2.3). Port of
 * go/core/jcs/number_test.go and the number cases of the Python port, plus
 * every row of spec/v1.0/fixtures/vectors/jcs/numbers.json.
 */
final class JcsNumberTest extends TestCase
{
    /**
     * The number serialization samples of RFC 8785 Appendix B, less NaN and
     * Infinity, which JSON cannot carry.
     */
    private const APPENDIX_B = [
        ['0000000000000000', '0'],
        ['8000000000000000', '0'],
        ['0000000000000001', '5e-324'],
        ['8000000000000001', '-5e-324'],
        ['7fefffffffffffff', '1.7976931348623157e+308'],
        ['ffefffffffffffff', '-1.7976931348623157e+308'],
        ['4340000000000000', '9007199254740992'],
        ['c340000000000000', '-9007199254740992'],
        ['4430000000000000', '295147905179352830000'],
        ['44b52d02c7e14af5', '9.999999999999997e+22'],
        ['44b52d02c7e14af6', '1e+23'],
        ['44b52d02c7e14af7', '1.0000000000000001e+23'],
        ['444b1ae4d6e2ef4e', '999999999999999700000'],
        ['444b1ae4d6e2ef4f', '999999999999999900000'],
        ['444b1ae4d6e2ef50', '1e+21'],
        ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
        ['3eb0c6f7a0b5ed8d', '0.000001'],
        ['41b3de4355555553', '333333333.3333332'],
        ['41b3de4355555554', '333333333.33333325'],
        ['41b3de4355555555', '333333333.3333333'],
        ['41b3de4355555556', '333333333.3333334'],
        ['41b3de4355555557', '333333333.33333343'],
        ['becbf647612f3696', '-0.0000033333333333333333'],
        ['43143ff3c1cb0959', '1424953923781206.2'],
    ];

    public static function bits(string $hex): float
    {
        $b = hex2bin($hex);
        self::assertIsString($b);
        $f = unpack('E', $b);
        self::assertIsArray($f);
        self::assertIsFloat($f[1]);

        return $f[1];
    }

    public function testAppendixB(): void
    {
        foreach (self::APPENDIX_B as [$hex, $want]) {
            self::assertSame($want, Jcs::canonicalizeValue(self::bits($hex)), $hex);
        }
    }

    /**
     * The ES6 layout switches at 10^21 and 10^-6; the exponent form carries
     * an explicit sign and no padding. Expected values come from V8.
     *
     * @return iterable<string, array{float, string}>
     */
    public static function layout(): iterable
    {
        $tenth = 0.1;
        $fifth = 0.2;
        $cases = [
            [1e21, '1e+21'], [-1e21, '-1e+21'], [9.999999999999999e20, '999999999999999900000'],
            [1e20, '100000000000000000000'], [1.23e20, '123000000000000000000'],
            [123456789012345680000.0, '123456789012345680000'], [1.5e25, '1.5e+25'], [1e100, '1e+100'],
            [2.0 ** 70, '1.1805916207174113e+21'], [1e15, '1000000000000000'], [100.0, '100'], [123.0, '123'],
            [22.0, '22'], [12.5, '12.5'], [1234.5678, '1234.5678'], [0.5, '0.5'], [1.0 / 3, '0.3333333333333333'],
            [$tenth + $fifth, '0.30000000000000004'], [1e-6, '0.000001'], [2e-6, '0.000002'], [1.5e-6, '0.0000015'],
            [4.5e-6, '0.0000045'], [0.000123, '0.000123'], [9.999999999999997e-7, '9.999999999999997e-7'],
            [5e-7, '5e-7'], [1e-7, '1e-7'], [1.5e-7, '1.5e-7'], [-1.5e-7, '-1.5e-7'], [1.2345e-100, '1.2345e-100'],
            [2.2250738585072014e-308, '2.2250738585072014e-308'], [5e-324, '5e-324'], [2.0 ** 53, '9007199254740992'],
            [2.0 ** 53 + 2, '9007199254740994'], [\PHP_FLOAT_MAX, '1.7976931348623157e+308'],
            [-\PHP_FLOAT_MAX, '-1.7976931348623157e+308'], [-0.0, '0'], [0.0, '0'],
            // json_encode writes these differently (probe Q4): 1.0e+30, 1.0e-7,
            // -0, 2.9514790517935283e+20 and 1.0e-6.
            [1e30, '1e+30'], [1e16, '10000000000000000'], [2.0 ** 68, '295147905179352830000'], [4.5, '4.5'],
            // The binade boundaries of probe Q4 finding 5: the nearest 16-digit
            // decimal falls outside the interval, its neighbour inside.
            [self::bits('0060000000000000'), '7.120236347223045e-307'],
            [2.0 ** -20, '9.5367431640625e-7'], [2.0 ** 1023, '8.98846567431158e+307'],
        ];
        foreach ($cases as [$f, $want]) {
            yield $want . ' ' . bin2hex(pack('E', $f)) => [$f, $want];
        }
    }

    #[DataProvider('layout')]
    public function testLayout(float $f, string $want): void
    {
        self::assertSame($want, Jcs::canonicalizeValue($f));
    }

    /** The output parses back to the same value: shortest digits never lose information. */
    public function testRoundTrip(): void
    {
        $vals = array_map(static fn(array $r): float => self::bits($r[0]), self::APPENDIX_B);
        for ($e = -330; $e <= 308; ++$e) {
            foreach (['1', '1.5', '9.999999999999998', '7.123456789012345'] as $m) {
                $v = (float) ($m . 'e' . $e);
                if (is_infinite($v)) {
                    continue; // beyond the largest double: not a value to format
                }
                $vals[] = $v;
                $vals[] = -$v;
            }
        }
        foreach ($vals as $f) {
            $s = Jcs::canonicalizeValue($f);
            self::assertSame($f === 0.0 ? 0.0 : $f, (float) $s, $s);
        }
    }

    public function testKeepsPrefix(): void
    {
        self::assertSame('[1.5]', Jcs::canonicalizeValue([1.5]));
    }

    /**
     * Every row of the RFC 8785 number list: the double itself, its negation,
     * and the whole of canonicalize over a 17-digit literal of it.
     */
    public function testNumbersAllRows(): void
    {
        $rows = self::numbers();
        self::assertCount(10000, $rows);
        foreach ($rows as [$hex, $f, $want]) {
            self::assertSame($want, Jcs::canonicalizeValue($f), $hex);
            self::assertSame($f === 0.0 ? '0' : (str_starts_with($want, '-') ? substr($want, 1) : '-' . $want), Jcs::canonicalizeValue(-$f), $hex);
            self::assertSame($want, Jcs::canonicalize(\sprintf('%.16e', $f)), $hex);
        }
    }

    /**
     * Seeded random doubles from 64-bit patterns (subnormals, huge exponents,
     * integral values beyond 2^53): the text parses back to the same double,
     * no shorter digit string does, and the layout is ECMA-262's for the
     * digits and the exponent read back from the text.
     */
    public function testRandomDoubles(): void
    {
        $seed = (int) (getenv('PACT_FUZZ_SEED') ?: 20261019);
        $n = (int) (getenv('PACT_FUZZ_EXAMPLES') ?: 400) * 50;
        $r = new \Random\Randomizer(new \Random\Engine\Mt19937($seed));
        for ($i = 0; $i < $n; ++$i) {
            $f = unpack('E', $r->getBytes(8));
            self::assertIsArray($f);
            $f = $f[1];
            self::assertIsFloat($f);
            if (!is_finite($f)) {
                continue;
            }
            $s = Jcs::canonicalizeValue($f);
            self::assertSame($f === 0.0 ? 0.0 : $f, (float) $s, $s);
            self::checkLayout($f, $s);
        }
    }

    /** $s is the shortest round-trip digits of $f laid out per ECMA-262 Number::toString. */
    private static function checkLayout(float $f, string $s): void
    {
        if ($f === 0.0) {
            self::assertSame('0', $s);

            return;
        }
        self::assertSame($f < 0, str_starts_with($s, '-'), $s);
        if (preg_match('/\A-?0\.(0*)([1-9][0-9]*)\z/', $s, $m) === 1) {
            // 0.000ddd: -6 < n <= 0
            $digits = $m[2];
            $n = -\strlen($m[1]);
            self::assertGreaterThan(-6, $n, $s);
        } elseif (preg_match('/\A-?([1-9])(?:\.([0-9]+))?e([+-][1-9][0-9]*)\z/', $s, $m, \PREG_UNMATCHED_AS_NULL) === 1) {
            $digits = $m[1] . $m[2];
            $n = (int) $m[3] + 1;
            self::assertTrue($n > 21 || $n <= -6, $s);
        } elseif (preg_match('/\A-?([1-9][0-9]*)(?:\.([0-9]+))?\z/', $s, $m, \PREG_UNMATCHED_AS_NULL) === 1) {
            $digits = rtrim($m[1] . $m[2], '0');
            $n = \strlen($m[1]);
            self::assertLessThanOrEqual(21, $n, $s);
        } else {
            self::fail($s . ' is not a Number::toString layout');
        }
        self::assertStringEndsNotWith('0', $digits, $s);
        // No string of fewer significant digits round-trips.
        $k = \strlen($digits);
        if ($k > 1) {
            $a = abs($f);
            $p = $k - 2;
            [$mant, $exp] = explode('e', \sprintf('%.' . $p . 'e', $a));
            $d = (int) str_replace('.', '', $mant);
            $e = (int) $exp - $p;
            foreach ([$d - 1, $d, $d + 1] as $c) {
                self::assertNotSame($a, (float) ($c . 'e' . $e), $s . ' is not the shortest');
            }
        }
    }

    /** @return list<array{string, float, string}> */
    private static function numbers(): array
    {
        $rows = json_decode(Repo::read('spec/v1.0/fixtures/vectors/jcs/numbers.json'), true, 4, \JSON_THROW_ON_ERROR);
        self::assertIsArray($rows);
        $out = [];
        foreach ($rows as $row) {
            self::assertIsArray($row);
            self::assertIsString($row['ieee754_hex']);
            self::assertIsString($row['expected']);
            $out[] = [$row['ieee754_hex'], self::bits($row['ieee754_hex']), $row['expected']];
        }

        return $out;
    }
}
