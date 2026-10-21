<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;

/**
 * The walker: a port of go/core/strictjson/walk.go and of the token rules of
 * encoding/json's Decoder (Token, More, InputOffset) it runs on.
 *
 * One pass over the bytes, in step with the target, building the value as it
 * goes. Open containers sit on an explicit stack, so the depth limit does not
 * depend on the PHP call stack. Offsets are byte offsets, as in Go.
 *
 * @internal
 */
final class Walker
{
    private const NON_FINITE = ['NaN', 'Infinity', '-Infinity', '+Infinity'];

    private readonly Tokens $t;
    /** @var list<string> */
    private array $path = [];
    private int $depth = 0;
    /** The first value that does not fit its target. */
    private ?string $mismatch = null;

    private function __construct(string $s, private readonly int $maxDepth)
    {
        $this->t = new Tokens($s);
    }

    /**
     * Strict-decode $data into a value of $top.
     *
     * @throws StrictJsonError
     */
    public static function run(string $data, ?Limits $limits, Target $top): mixed
    {
        $limits ??= new Limits();
        $max = $limits->bytes();
        if (\strlen($data) > $max) {
            throw new StrictJsonError(StrictJsonErrorKind::SIZE, '', $max, \sprintf('limit is %d bytes', $max));
        }
        if (!mb_check_encoding($data, 'UTF-8')) {
            throw new StrictJsonError(StrictJsonErrorKind::INVALID_UTF8, '', Utf8::firstInvalid($data));
        }
        return (new self($data, $limits->depth()))->walk($top);
    }

    // -- reporting --

    private function pointer(): string
    {
        $p = '';
        foreach ($this->path as $seg) {
            $p .= '/' . strtr($seg, ['~' => '~0', '/' => '~1']);
        }

        return $p;
    }

    private function fail(StrictJsonErrorKind $kind, string $detail = ''): StrictJsonError
    {
        return new StrictJsonError($kind, $this->pointer(), $this->t->pos, $detail);
    }

    private function tokenError(Stop $e): StrictJsonError
    {
        if ($e->eof) {
            return $this->fail(StrictJsonErrorKind::SYNTAX, 'unexpected end of input');
        }
        // A failed token leaves the offset at the start of the bad text.
        $at = $this->t->pos + strspn($this->t->s, Tokens::WS, $this->t->pos);
        foreach (self::NON_FINITE as $lit) {
            if (substr($this->t->s, $at, \strlen($lit)) === $lit) {
                return $this->fail(StrictJsonErrorKind::NON_FINITE, $lit . ' is not a JSON number');
            }
        }

        return $this->fail(StrictJsonErrorKind::SYNTAX, $e->getMessage());
    }

    private function doesNotFit(string $what, Target $t): void
    {
        $this->mismatch ??= \sprintf('%s at %s does not fit %s', $what, $this->pointer() === '' ? '/' : $this->pointer(), $t->name());
    }

    // -- values --

    private function scalar(int $kind, mixed $v, Target $t): mixed
    {
        if ($kind === Tokens::NUM) {
            \assert(\is_array($v) && \is_string($v[0]) && \is_bool($v[1]));

            return $this->number($v[0], $v[1], $t);
        }
        if ($kind === Tokens::LIT) {
            if ($v === null) {
                if (!$t->nullable) {
                    throw $this->fail(StrictJsonErrorKind::NULL, \sprintf('target %s cannot hold null', $t->name()));
                }

                return null;
            }
            if ($t->kind !== Target::BOOL && $t->kind !== Target::RAW) {
                $this->doesNotFit('boolean', $t);
            }

            return $v;
        }
        if ($t->kind !== Target::STRING && $t->kind !== Target::RAW) {
            $this->doesNotFit('string', $t);
        }

        return $v;
    }

    private function number(string $lit, bool $integer, Target $t): int|float
    {
        if (!$integer) {
            if ($t->kind === Target::INT) {
                throw $this->fail(StrictJsonErrorKind::INTEGER, $lit . ' is not an integer');
            }
            $value = (float) $lit;
            if (!is_finite($value)) {
                throw $this->fail(StrictJsonErrorKind::NON_FINITE, $lit . ' does not fit binary64');
            }
        } else {
            // The length check first: (int) saturates a literal beyond PHP_INT_MAX.
            $i = \strlen($lit) - ($lit[0] === '-' ? 1 : 0) > 16 ? \PHP_INT_MAX : (int) $lit;
            if (abs($i) > StrictJson::MAX_SAFE_INTEGER) {
                throw $this->fail(StrictJsonErrorKind::INTEGER, \sprintf('%s is outside ±%d', $lit, StrictJson::MAX_SAFE_INTEGER));
            }
            if ($t->kind === Target::INT && $i < 0) {
                throw $this->fail(StrictJsonErrorKind::INTEGER, $lit . ' is negative');
            }
            $value = $t->kind === Target::FLOAT ? (float) $i : $i;
        }
        if ($t->kind !== Target::INT && $t->kind !== Target::FLOAT && $t->kind !== Target::RAW) {
            $this->doesNotFit('number', $t);
        }

        return $value;
    }

    private function open(int $kind, Target $t): Frame
    {
        ++$this->depth;
        if ($this->depth > $this->maxDepth) {
            throw $this->fail(StrictJsonErrorKind::DEPTH, \sprintf('depth %d exceeds the limit of %d', $this->depth, $this->maxDepth));
        }
        $isObject = $kind === Tokens::OPEN_OBJECT;
        $fits = $isObject
            ? $t->kind === Target::STRUCT || $t->kind === Target::MAP || $t->kind === Target::RAW
            : $t->kind === Target::SLICE || $t->kind === Target::RAW;
        if (!$fits) {
            $this->doesNotFit($isObject ? 'object' : 'array', $t);

            return new Frame($isObject, null);
        }

        return new Frame($isObject, $t->kind === Target::RAW ? null : $t);
    }

    private function close(Frame $f): mixed
    {
        --$this->depth;
        if (!$f->isObject) {
            return $f->items;
        }
        $t = $f->target;
        if ($t !== null && $t->kind === Target::STRUCT && $t->class !== null) {
            if ($this->mismatch !== null || $this->t->surrogate !== null) {
                return null; // a failed decode builds nothing
            }
            $values = [];
            foreach ($f->pairs as [$name, $value]) {
                $values[$name] = $value;
            }

            return Target::build($t->class, $values);
        }

        return JsonObject::fromPairs($f->pairs);
    }

    private function walk(Target $top): mixed
    {
        /** @var list<Frame> $stack */
        $stack = [];
        $target = $top;
        $value = null;
        while (true) {
            // A value for $target.
            try {
                [$kind, $v] = $this->t->token();
            } catch (Stop $e) {
                throw $this->tokenError($e);
            }
            if ($kind === Tokens::OPEN_OBJECT || $kind === Tokens::OPEN_ARRAY) {
                $stack[] = $this->open($kind, $target);
                $have = false;
            } else {
                $value = $this->scalar($kind, $v, $target);
                $have = true;
            }
            // The containers: store the value, then read the next member or close.
            while (($f = end($stack)) !== false) {
                if ($have) {
                    $name = (string) array_pop($this->path);
                    if ($f->isObject) {
                        $f->pairs[] = [$name, $value];
                    } else {
                        $f->items[] = $value;
                    }
                    $have = false;
                }
                if ($this->t->more()) {
                    $target = $this->member($f);
                    continue 2;
                }
                try {
                    $this->t->token(); // the closing brace or bracket
                } catch (Stop $e) {
                    throw $this->tokenError($e);
                }
                array_pop($stack);
                $value = $this->close($f);
                $have = true;
            }
            break;
        }
        $end = $this->t->pos;
        $this->trailing();
        if ($this->t->surrogate !== null) {
            throw new StrictJsonError(StrictJsonErrorKind::LONE_SURROGATE, '', $this->t->surrogate[0], $this->t->surrogate[1]);
        }
        if ($this->mismatch !== null) {
            throw new StrictJsonError(StrictJsonErrorKind::TYPE, '', $end, $this->mismatch);
        }

        return $value;
    }

    /**
     * Read the next member name of an object (or open the next array
     * element) and return the target of its value.
     */
    private function member(Frame $f): Target
    {
        if (!$f->isObject) {
            $this->path[] = (string) \count($f->items);

            return $f->elem;
        }
        try {
            [$kind, $key] = $this->t->token();
        } catch (Stop $e) {
            throw $this->tokenError($e);
        }
        if ($kind !== Tokens::KEY || !\is_string($key)) {
            throw $this->fail(StrictJsonErrorKind::SYNTAX, 'object member name is not a string');
        }
        $this->path[] = $key;
        if (isset($f->seen[$key])) {
            throw $this->fail(StrictJsonErrorKind::DUPLICATE_KEY, self::quote($key));
        }
        $f->seen[$key] = true;
        if ($f->fields !== null) {
            $t = $f->fields[$key] ?? null;
            if ($t === null) {
                throw $this->fail(StrictJsonErrorKind::UNKNOWN_FIELD, \sprintf('%s is not a field of %s', self::quote($key), $f->target?->name() ?? 'the target'));
            }

            return $t;
        }

        return $f->elem;
    }

    private function trailing(): void
    {
        try {
            $this->t->token();
        } catch (Stop $e) {
            if ($e->clean) {
                return;
            }
        }
        throw $this->fail(StrictJsonErrorKind::TRAILING_DATA);
    }

    private static function quote(string $s): string
    {
        return (string) json_encode($s, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
