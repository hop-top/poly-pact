<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jcs;

use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use PHPUnit\Framework\TestCase;

/**
 * JCS over seeded random JSON trees: the counterpart of Go's
 * FuzzCanonicalize and the Python port's test_jcs_property.py, without an
 * oracle package (probe Q4: none on Packagist is correct).
 *
 * For every tree: the canonical form of the tree's JSON text (members in
 * insertion order, white space, escaped non-ASCII and slashes, 17-digit
 * exponent numbers) equals that of the tree;
 * the output parses back to the same value and is unchanged by a second
 * pass, except where a float is written as an integer literal beyond
 * 2^53-1, which the strict parse refuses (as in Go). PACT_FUZZ_EXAMPLES
 * sets the number of trees (default 400), PACT_FUZZ_SEED the seed.
 */
final class JcsPropertyTest extends TestCase
{
    /** Characters that stress string and key handling, as in the Python port. */
    private const SPECIAL = ['"', '\\', '/', "\x08", "\f", "\n", "\r", "\t", "\x00", "\x01", "\x1f", "\x7f", "\u{2028}", "\u{2029}", "\u{e9}", "\u{20ac}", "\u{d7ff}", "\u{e000}", "\u{ffff}", "\u{10000}", "\u{1f602}", "\u{10ffff}"];

    private \Random\Randomizer $rng;

    public function testRandomTrees(): void
    {
        $seed = (int) (getenv('PACT_FUZZ_SEED') ?: 20261019);
        $n = (int) (getenv('PACT_FUZZ_EXAMPLES') ?: 400);
        $this->rng = new \Random\Randomizer(new \Random\Engine\Mt19937($seed));
        for ($i = 0; $i < $n; ++$i) {
            self::check($i % 50 === 0 ? $this->deep() : $this->draw(0));
        }
    }

    private static function check(mixed $tree): void
    {
        $out = Jcs::canonicalizeValue($tree);
        $text = self::text($tree);
        self::assertSame($out, Jcs::canonicalize($text), $text);
        if (self::beyondSafeInteger($tree)) {
            try {
                Jcs::canonicalize($out);
                self::fail('accepted ' . $out);
            } catch (StrictJsonError $e) {
                self::assertSame(StrictJsonErrorKind::INTEGER, $e->kind, $out);
            }

            return;
        }
        self::assertSame($out, Jcs::canonicalize($out), $out);
        self::assertTrue(self::same(StrictJson::parse($out), $tree), $out);
    }

    private function draw(int $depth): mixed
    {
        $r = $this->rng->nextFloat();
        if ($depth < StrictJson::DEFAULT_MAX_DEPTH && $r < 0.25) {
            $out = [];
            for ($i = $this->rng->getInt(0, 3); $i > 0; --$i) {
                $out[] = $this->draw($depth + 1);
            }

            return $out;
        }
        if ($depth < StrictJson::DEFAULT_MAX_DEPTH && $r < 0.5) {
            $pairs = [];
            for ($i = $this->rng->getInt(0, 3); $i > 0; --$i) {
                $pairs[$this->string()] = $this->draw($depth + 1);
            }

            return new JsonObject($pairs);
        }

        return match (true) {
            $r < 0.7 => $this->double(),
            $r < 0.8 => $this->int(),
            $r < 0.9 => $this->string(),
            default => [null, true, false][$this->rng->getInt(0, 2)],
        };
    }

    /** A tree at exactly the depth limit. */
    private function deep(): mixed
    {
        $v = $this->double();
        for ($i = 0; $i < StrictJson::DEFAULT_MAX_DEPTH; ++$i) {
            $v = $this->rng->nextFloat() < 0.5 ? [$v] : new JsonObject([$this->string() => $v]);
        }

        return $v;
    }

    private function double(): float
    {
        do {
            $f = unpack('E', $this->rng->getBytes(8));
            self::assertIsArray($f);
            self::assertIsFloat($f[1]);
        } while (!is_finite($f[1]));

        return $f[1];
    }

    private function int(): int
    {
        $bits = [1, 4, 16, 32, 53][$this->rng->getInt(0, 4)];
        $n = $this->rng->getInt(0, (1 << $bits) - 1);
        $n = min($n, StrictJson::MAX_SAFE_INTEGER);

        return $this->rng->nextFloat() < 0.5 ? -$n : $n;
    }

    private function string(): string
    {
        $out = '';
        for ($i = $this->rng->getInt(0, 7); $i > 0; --$i) {
            $r = $this->rng->nextFloat();
            if ($r < 0.4) {
                $out .= self::SPECIAL[$this->rng->getInt(0, \count(self::SPECIAL) - 1)];
            } elseif ($r < 0.7) {
                $out .= \chr($this->rng->getInt(0x20, 0x7E));
            } else {
                $c = $this->rng->getInt(0, 0x110000 - 0x800 - 1);
                $out .= mb_chr($c >= 0xD800 ? $c + 0x800 : $c, 'UTF-8'); // skip the surrogates
            }
        }

        return $out;
    }

    /** $v as non-canonical JSON text. */
    private static function text(mixed $v): string
    {
        if ($v instanceof JsonObject) {
            $out = [];
            foreach ($v->pairs() as [$k, $x]) {
                $out[] = json_encode($k, \JSON_THROW_ON_ERROR) . ' : ' . self::text($x);
            }

            return '{ ' . implode(' , ', $out) . ' }';
        }
        if (\is_array($v)) {
            return '[ ' . implode(' , ', array_map(self::text(...), $v)) . ' ]';
        }
        if (\is_float($v)) {
            return \sprintf('%.16e', $v);
        }

        return json_encode($v, \JSON_THROW_ON_ERROR);
    }

    /** Whether a float of $v is integral, beyond 2^53-1 and below 1e21 (written without exponent). */
    private static function beyondSafeInteger(mixed $v): bool
    {
        if ($v instanceof JsonObject) {
            $v = iterator_to_array($v, false);
        }
        if (\is_array($v)) {
            foreach ($v as $x) {
                if (self::beyondSafeInteger($x)) {
                    return true;
                }
            }

            return false;
        }

        return \is_float($v) && abs($v) > StrictJson::MAX_SAFE_INTEGER && abs($v) < 1e21 && floor($v) === $v;
    }

    /** JSON value equality; numbers by value (JCS writes 1.0 as 1, -0.0 as 0). */
    private static function same(mixed $a, mixed $b): bool
    {
        if ($a instanceof JsonObject && $b instanceof JsonObject) {
            $an = $a->names();
            $bn = $b->names();
            sort($an, \SORT_STRING);
            sort($bn, \SORT_STRING);
            if ($an !== $bn) {
                return false;
            }
            foreach ($an as $k) {
                if (!self::same($a->get($k), $b->get($k))) {
                    return false;
                }
            }

            return true;
        }
        if (\is_array($a) && \is_array($b)) {
            if (\count($a) !== \count($b)) {
                return false;
            }
            foreach ($a as $i => $x) {
                if (!self::same($x, $b[$i])) {
                    return false;
                }
            }

            return true;
        }
        if ((\is_int($a) || \is_float($a)) && (\is_int($b) || \is_float($b))) {
            return (float) $a === (float) $b;
        }

        return $a === $b;
    }
}
