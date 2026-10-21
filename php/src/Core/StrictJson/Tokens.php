<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * The token layer of the walker: a port of the rules of encoding/json's
 * Decoder.Token, More and InputOffset, over bytes.
 *
 * @internal
 */
final class Tokens
{
    // The token states of Go's json.Decoder.
    private const TOP = 0;
    private const ARRAY_START = 1;
    private const ARRAY_VALUE = 2;
    private const ARRAY_COMMA = 3;
    private const OBJECT_START = 4;
    private const OBJECT_KEY = 5;
    private const OBJECT_COLON = 6;
    private const OBJECT_VALUE = 7;
    private const OBJECT_COMMA = 8;
    private const VALUE_STATES = [self::TOP => true, self::ARRAY_START => true, self::ARRAY_VALUE => true, self::OBJECT_VALUE => true];

    // Token kinds.
    public const OPEN_OBJECT = 0;
    public const OPEN_ARRAY = 1;
    public const CLOSE = 2;
    public const KEY = 3;
    public const STR = 4;
    public const NUM = 5;
    public const LIT = 6;

    public const WS = " \t\n\r";
    private const LITERALS = ['t' => ['true', true], 'f' => ['false', false], 'n' => ['null', null]];
    private const ESCAPES = ['"' => '"', '\\' => '\\', '/' => '/', 'b' => "\x08", 'f' => "\f", 'n' => "\n", 'r' => "\r", 't' => "\t"];

    /** The bytes that end a run of plain string content: quote, backslash, controls. */
    private static string $stringStops = '';

    public readonly int $n;

    /** The decoder's input offset. */
    public int $pos = 0;

    private int $state = self::TOP;

    /** @var list<int> */
    private array $states = [];

    /** @var array{int, string}|null the first unpaired surrogate escape: offset, detail */
    public ?array $surrogate = null;

    public function __construct(public readonly string $s)
    {
        $this->n = \strlen($s);
        if (self::$stringStops === '') {
            self::$stringStops = '"\\' . implode('', array_map('chr', range(0, 0x1F)));
        }
    }

    public function peek(): string
    {
        $i = $this->pos;
        if ($i < $this->n) {
            $c = $this->s[$i];
            if ($c !== ' ' && $c !== "\t" && $c !== "\n" && $c !== "\r") {
                return $c;
            }
        }
        $i += strspn($this->s, self::WS, $i);
        if ($i >= $this->n) {
            return ''; // the offset stays before the white space, as in Go
        }
        $this->pos = $i;

        return $this->s[$i];
    }

    public function more(): bool
    {
        $c = $this->peek();

        return $c !== '' && $c !== ']' && $c !== '}';
    }

    private function bad(string $c, string $context): Stop
    {
        // The character as Go quotes it: the whole UTF-8 sequence.
        $len = \ord($c) < 0x80 ? 1 : (\ord($c) < 0xE0 ? 2 : (\ord($c) < 0xF0 ? 3 : 4));

        return new Stop(\sprintf("invalid character '%s' %s", substr($this->s, $this->pos, $len), $context));
    }

    /**
     * The next token: kind and value (a string for KEY and STR, the literal
     * text and whether it is an integer for NUM, the PHP value for LIT).
     *
     * @return array{int, mixed}
     *
     * @throws Stop
     */
    public function token(): array
    {
        while (true) {
            $c = $this->peek();
            if ($c === '') {
                throw new Stop('unexpected end of input', true, true);
            }
            $st = $this->state;
            if ($c === '{' || $c === '[') {
                if (!isset(self::VALUE_STATES[$st])) {
                    throw $this->bad($c, 'looking for beginning of value');
                }
                ++$this->pos;
                $this->states[] = $st;
                $this->state = $c === '{' ? self::OBJECT_START : self::ARRAY_START;

                return [$c === '{' ? self::OPEN_OBJECT : self::OPEN_ARRAY, null];
            }
            if ($c === ']' || $c === '}') {
                $ok = $c === ']' ? [self::ARRAY_START, self::ARRAY_COMMA] : [self::OBJECT_START, self::OBJECT_COMMA];
                if (!\in_array($st, $ok, true)) {
                    throw $this->bad($c, 'looking for beginning of value');
                }
                ++$this->pos;
                $this->state = array_pop($this->states) ?? self::TOP;
                $this->valueEnd();

                return [self::CLOSE, null];
            }
            if ($c === ':') {
                if ($st !== self::OBJECT_COLON) {
                    throw $this->bad($c, 'looking for beginning of value');
                }
                ++$this->pos;
                $this->state = self::OBJECT_VALUE;
                continue;
            }
            if ($c === ',') {
                if ($st === self::ARRAY_COMMA) {
                    $this->state = self::ARRAY_VALUE;
                } elseif ($st === self::OBJECT_COMMA) {
                    $this->state = self::OBJECT_KEY;
                } else {
                    throw $this->bad($c, 'looking for beginning of value');
                }
                ++$this->pos;
                continue;
            }
            if ($c === '"' && ($st === self::OBJECT_START || $st === self::OBJECT_KEY)) {
                $key = $this->readString();
                $this->state = self::OBJECT_COLON;

                return [self::KEY, $key];
            }
            if (!isset(self::VALUE_STATES[$st])) {
                throw $this->bad($c, $st === self::OBJECT_COLON ? 'after object key' : 'after value');
            }
            $tok = $this->readScalar($c);
            $this->valueEnd();

            return $tok;
        }
    }

    private function valueEnd(): void
    {
        if ($this->state === self::ARRAY_START || $this->state === self::ARRAY_VALUE) {
            $this->state = self::ARRAY_COMMA;
        } elseif ($this->state === self::OBJECT_VALUE) {
            $this->state = self::OBJECT_COMMA;
        }
    }

    private function digitAt(int $i): bool
    {
        return $i < $this->n && $this->s[$i] >= '0' && $this->s[$i] <= '9';
    }

    /**
     * @return array{int, mixed}
     *
     * @throws Stop
     */
    private function readScalar(string $c): array
    {
        if ($c === '"') {
            return [self::STR, $this->readString()];
        }
        $s = $this->s;
        $pos = $this->pos;
        if ($c === '-' || ($c >= '0' && $c <= '9')) {
            // -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?
            $i = $c === '-' ? $pos + 1 : $pos;
            if (!$this->digitAt($i)) {
                throw new Stop('invalid number', $pos + 1 >= $this->n);
            }
            $i += $s[$i] === '0' ? 1 : strspn($s, '0123456789', $i);
            $frac = $exp = false;
            if ($i < $this->n && $s[$i] === '.' && $this->digitAt($i + 1)) {
                $i += 1 + strspn($s, '0123456789', $i + 1);
                $frac = true;
            }
            if ($i < $this->n && ($s[$i] === 'e' || $s[$i] === 'E')) {
                $j = $i + 1;
                if ($j < $this->n && ($s[$j] === '+' || $s[$j] === '-')) {
                    ++$j;
                }
                if ($this->digitAt($j)) {
                    $i = $j + strspn($s, '0123456789', $j);
                    $exp = true;
                }
            }
            if ($i < $this->n) {
                $next = $s[$i];
                if ($next === '.' && !$frac && !$exp) {
                    throw new Stop('invalid number', $i + 1 >= $this->n);
                }
                if (($next === 'e' || $next === 'E') && !$exp) {
                    $j = $i + 1;
                    if ($j < $this->n && ($s[$j] === '+' || $s[$j] === '-')) {
                        ++$j;
                    }
                    throw new Stop('invalid number', $j >= $this->n);
                }
            }
            $this->pos = $i;

            return [self::NUM, [substr($s, $pos, $i - $pos), !$frac && !$exp]];
        }
        $lit = self::LITERALS[$c] ?? null;
        if ($lit !== null) {
            [$word, $value] = $lit;
            if (substr($s, $pos, \strlen($word)) === $word) {
                $this->pos = $pos + \strlen($word);

                return [self::LIT, $value];
            }
            throw new Stop('invalid literal, want ' . $word, str_starts_with($word, substr($s, $pos)));
        }
        throw $this->bad($c, 'looking for beginning of value');
    }

    /**
     * The string token at the offset, unescaped. A surrogate escape that is
     * not half of a pair becomes U+FFFD, as Go's decoder writes it, and the
     * first one is noted: Go reports it after the walk.
     *
     * @throws Stop
     */
    private function readString(): string
    {
        $s = $this->s;
        $i = $this->pos + 1;
        $out = '';
        while (true) {
            $k = strcspn($s, self::$stringStops, $i);
            $out .= substr($s, $i, $k);
            $i += $k;
            if ($i >= $this->n) {
                throw new Stop('invalid string', true);
            }
            $c = $s[$i];
            if ($c === '"') {
                $this->pos = $i + 1;

                return $out;
            }
            if ($c !== '\\') {
                throw new Stop('invalid string'); // a control character
            }
            $e = $s[$i + 1] ?? '';
            if (isset(self::ESCAPES[$e])) {
                $out .= self::ESCAPES[$e];
                $i += 2;
                continue;
            }
            $u = $e === 'u' ? self::hex4($s, $i + 2) : -1;
            if ($u < 0) {
                // A valid escape cut off by the end of the input is an early end.
                throw new Stop('invalid string', preg_match('/\G\\\\(?:u[0-9a-fA-F]{0,3})?\z/', $s, $m, 0, $i) === 1);
            }
            if ($u >= 0xD800 && $u <= 0xDBFF && ($s[$i + 6] ?? '') === '\\' && ($s[$i + 7] ?? '') === 'u'
                && ($lo = self::hex4($s, $i + 8)) >= 0xDC00 && $lo <= 0xDFFF) {
                $out .= mb_chr(0x10000 + (($u - 0xD800) << 10) + ($lo - 0xDC00), 'UTF-8');
                $i += 12;
                continue;
            }
            if ($u >= 0xD800 && $u <= 0xDFFF) {
                $this->surrogate ??= [$i, $u >= 0xDC00
                    ? \sprintf('low surrogate \u%04x without a high surrogate before it', $u)
                    : \sprintf('high surrogate \u%04x without a low surrogate after it', $u)];
                $out .= "\u{FFFD}";
            } else {
                $out .= mb_chr($u, 'UTF-8');
            }
            $i += 6;
        }
    }

    /** The value of four hex digits at $at, or -1. */
    private static function hex4(string $s, int $at): int
    {
        $h = substr($s, $at, 4);

        return \strlen($h) === 4 && ctype_xdigit($h) ? (int) hexdec($h) : -1;
    }
}
