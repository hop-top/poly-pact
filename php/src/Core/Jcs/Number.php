<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jcs;

/**
 * ECMAScript Number::toString for a finite float (RFC 8785 section
 * 3.2.2.3), the counterpart of Go's appendNumber.
 *
 * The digits are the shortest that round-trip, found with sprintf('%.{p}e'),
 * which reads neither serialize_precision nor precision nor the locale; the
 * nearest p+1-digit decimal is tried first and then, because at a power of
 * two the interval of values that round to the double is asymmetric, its
 * neighbour on the side of the value. json_encode, var_export and strval are
 * not used: their text differs from ECMAScript's and depends on ini settings.
 *
 * @internal
 */
final class Number
{
    /** The largest decimal point position written without an exponent. */
    private const MAX_PLAIN = 21;

    /**
     * Zero of either sign is "0"; otherwise, with k the number of shortest
     * round-trip digits and n the decimal point position (the value is
     * 0.d1d2...dk * 10^n):
     *
     *     k <= n <= 21     the digits, then n-k zeros
     *     0 < n <= 21      the first n digits, ".", the remaining digits
     *     -6 < n <= 0      "0.", then -n zeros, then the digits
     *     otherwise        d1, then "." and d2...dk when k > 1, then "e", a
     *                      sign that is always written, and the exponent n-1
     *
     * @param float $f a finite value
     */
    public static function format(float $f): string
    {
        if ($f === 0.0) {
            return '0'; // also -0.0
        }
        $a = abs($f);
        [$c, $e] = self::shortest($a);
        $d = rtrim((string) $c, '0');
        $k = \strlen($d);
        $n = $e + \strlen((string) $c);
        if ($k <= $n && $n <= self::MAX_PLAIN) {
            $t = $d . str_repeat('0', $n - $k);
        } elseif (0 < $n && $n <= self::MAX_PLAIN) {
            $t = substr($d, 0, $n) . '.' . substr($d, $n);
        } elseif (-6 < $n && $n <= 0) {
            $t = '0.' . str_repeat('0', -$n) . $d;
        } else {
            $t = $d[0] . ($k > 1 ? '.' . substr($d, 1) : '') . 'e' . ($n - 1 < 0 ? '-' : '+') . abs($n - 1);
        }

        return ($f < 0 ? '-' : '') . $t;
    }

    /**
     * The shortest integer $c and exponent $e with (float) "{$c}e{$e}" === $a.
     *
     * @return array{int, int}
     */
    private static function shortest(float $a): array
    {
        for ($p = 0; $p < 16; ++$p) {
            [$d, $e] = self::nearest($a, $p);
            $v = (float) ($d . 'e' . $e);
            if ($v === $a) {
                return [$d, $e];
            }
            $c = $v > $a ? $d - 1 : $d + 1;
            if ((float) ($c . 'e' . $e) === $a) {
                return [$c, $e];
            }
        }

        // 17 significant digits always round-trip.
        return self::nearest($a, 16);
    }

    /**
     * The nearest decimal of p+1 significant digits as digits and exponent.
     *
     * @return array{int, int}
     */
    private static function nearest(float $a, int $p): array
    {
        [$m, $x] = explode('e', \sprintf('%.' . $p . 'e', $a));

        return [(int) str_replace('.', '', $m), (int) $x - $p];
    }
}
