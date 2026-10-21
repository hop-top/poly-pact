<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jcs;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;

/**
 * RFC 8785 JSON Canonicalization Scheme. Mirrors Go package
 * hop.top/pact-go/core/jcs.
 *
 * The canonical form is UTF-8 without insignificant white space, object
 * members sorted by name in UTF-16 code units, strings and numbers in the
 * ECMAScript serialization. Number text comes from an in-house formatter, so
 * it does not depend on serialize_precision, precision or the locale.
 */
final class Jcs
{
    private const STRING_FLAGS = \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_LINE_TERMINATORS | \JSON_THROW_ON_ERROR;

    private function __construct() {}

    /**
     * The RFC 8785 canonical form of the JSON text $json.
     *
     * $json is first read by StrictJson::parse() with its default limits, so
     * a document the strict parse rejects is rejected here with the same
     * StrictJsonError: duplicate member names, nesting over 16, input over
     * 256 KiB, invalid UTF-8, unpaired surrogate escapes, text after the
     * value, NaN and Infinity, number literals that overflow binary64, and
     * integer literals outside ±(2^53-1). Any JSON value may be
     * canonicalized, not only an object.
     *
     * @throws StrictJsonError
     */
    public static function canonicalize(string $json): string
    {
        return self::canonicalizeValue(StrictJson::parse($json));
    }

    /**
     * The RFC 8785 canonical form of a value of the package's value model:
     * a JsonObject, a list, a string, an int, a float, a bool or null.
     *
     * For a parsed value the result equals canonicalize() of the text it was
     * parsed from. A value that no strict parse with the default limits
     * yields throws StrictJsonError with the RFC 6901 path of the offending
     * value: nesting over 16 (DEPTH), an int outside ±(2^53-1) (INTEGER),
     * NaN or an infinity (NON_FINITE), a string or member name that is not
     * UTF-8 (INVALID_UTF8). Any other PHP value, such as an array that is not
     * a list, throws \InvalidArgumentException.
     *
     * @throws StrictJsonError
     * @throws \InvalidArgumentException
     */
    public static function canonicalizeValue(mixed $value): string
    {
        $path = [];

        return self::write($value, 0, $path);
    }

    /** @param list<string> $path */
    private static function write(mixed $v, int $depth, array &$path): string
    {
        if ($v === null) {
            return 'null';
        }
        if (\is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (\is_string($v)) {
            return self::string($v, $path);
        }
        if (\is_int($v)) {
            if ($v < -StrictJson::MAX_SAFE_INTEGER || $v > StrictJson::MAX_SAFE_INTEGER) {
                throw self::fail(StrictJsonErrorKind::INTEGER, $path, \sprintf('%d is outside ±%d', $v, StrictJson::MAX_SAFE_INTEGER));
            }

            return (string) $v;
        }
        if (\is_float($v)) {
            if (!is_finite($v)) {
                throw self::fail(StrictJsonErrorKind::NON_FINITE, $path, \sprintf('%F is not a JSON number', $v));
            }

            return Number::format($v);
        }
        if ($v instanceof JsonObject) {
            self::enter($depth, $path);

            return self::object($v, $depth, $path);
        }
        if (\is_array($v) && array_is_list($v)) {
            self::enter($depth, $path);
            $out = [];
            foreach ($v as $i => $x) {
                $path[] = (string) $i;
                $out[] = self::write($x, $depth + 1, $path);
                array_pop($path);
            }

            return '[' . implode(',', $out) . ']';
        }

        throw new \InvalidArgumentException(\sprintf('jcs: %s%s is not a JSON value of the package model', get_debug_type($v), \is_array($v) ? ' that is not a list' : ''));
    }

    /** @param list<string> $path */
    private static function object(JsonObject $o, int $depth, array &$path): string
    {
        // RFC 8785 section 3.2.3 sorts by UTF-16 code units; big-endian
        // UTF-16 bytes compare in that order. A name that is not UTF-8 is
        // refused before it is converted.
        $units = [];
        foreach ($o->names() as $name) {
            $units[$name] = self::utf16($name, $path);
        }
        uasort($units, strcmp(...));
        $out = [];
        foreach (array_keys($units) as $name) {
            $name = (string) $name;
            $path[] = $name;
            $member = self::string($name, $path) . ':' . self::write($o->get($name), $depth + 1, $path);
            array_pop($path);
            $out[] = $member;
        }

        return '{' . implode(',', $out) . '}';
    }

    /** @param list<string> $path */
    private static function enter(int $depth, array $path): void
    {
        if ($depth >= StrictJson::DEFAULT_MAX_DEPTH) {
            throw self::fail(StrictJsonErrorKind::DEPTH, $path, \sprintf('depth exceeds %d', StrictJson::DEFAULT_MAX_DEPTH));
        }
    }

    /** @param list<string> $path the path of the object holding the member $name */
    private static function utf16(string $name, array $path): string
    {
        if (!mb_check_encoding($name, 'UTF-8')) {
            $path[] = $name;
            throw self::fail(StrictJsonErrorKind::INVALID_UTF8, $path, 'member name is not UTF-8');
        }

        return mb_convert_encoding($name, 'UTF-16BE', 'UTF-8');
    }

    /**
     * $s as ECMAScript JSON.stringify writes it (RFC 8785 section 3.2.2.2):
     * the quotation mark and the reverse solidus escaped, \b \t \n \f \r in
     * short form, other controls as lower-case \u00xx, everything else
     * (U+007F, U+2028 and U+2029 included) as is.
     *
     * @param list<string> $path
     */
    private static function string(string $s, array $path): string
    {
        try {
            return json_encode($s, self::STRING_FLAGS);
        } catch (\JsonException) {
            throw self::fail(StrictJsonErrorKind::INVALID_UTF8, $path, 'string is not UTF-8');
        }
    }

    /** @param list<string> $path */
    private static function fail(StrictJsonErrorKind $kind, array $path, string $detail): StrictJsonError
    {
        $pointer = '';
        foreach ($path as $p) {
            $pointer .= '/' . strtr($p, ['~' => '~0', '/' => '~1']);
        }

        return new StrictJsonError($kind, $pointer, 0, $detail);
    }
}
