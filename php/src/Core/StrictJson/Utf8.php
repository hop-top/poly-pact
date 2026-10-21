<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * UTF-8 validation with Go's offsets.
 *
 * @internal
 */
final class Utf8
{
    /**
     * The offset of the first byte where Go's utf8.DecodeRune returns
     * RuneError of size 1: a byte that starts no valid sequence (stray
     * continuation, C0, C1, F5 to FF), an overlong form, a surrogate, a value
     * above U+10FFFF or a truncated sequence. The length of $s when valid.
     */
    public static function firstInvalid(string $s): int
    {
        $n = \strlen($s);
        $i = 0;
        while ($i < $n) {
            $i += strspn($s, implode('', array_map('chr', range(0, 0x7F))), $i);
            if ($i >= $n) {
                break;
            }
            $c = \ord($s[$i]);
            [$len, $lo, $hi] = match (true) {
                $c >= 0xC2 && $c <= 0xDF => [2, 0x80, 0xBF],
                $c === 0xE0 => [3, 0xA0, 0xBF],
                $c >= 0xE1 && $c <= 0xEC, $c === 0xEE, $c === 0xEF => [3, 0x80, 0xBF],
                $c === 0xED => [3, 0x80, 0x9F],
                $c === 0xF0 => [4, 0x90, 0xBF],
                $c >= 0xF1 && $c <= 0xF3 => [4, 0x80, 0xBF],
                $c === 0xF4 => [4, 0x80, 0x8F],
                default => [0, 0, 0],
            };
            if ($len === 0 || $i + $len > $n) {
                return $i;
            }
            // The second byte has its own range; the rest are 80 to BF.
            $b = \ord($s[$i + 1]);
            if ($b < $lo || $b > $hi) {
                return $i;
            }
            for ($k = 2; $k < $len; ++$k) {
                $b = \ord($s[$i + $k]);
                if ($b < 0x80 || $b > 0xBF) {
                    return $i;
                }
            }
            $i += $len;
        }

        return $n;
    }
}
