<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * Strict JSON decoding (draft section 7.1). Mirrors Go package
 * hop.top/pact-go/core/strictjson.
 *
 * parse(), parseStream() and decode() reject, before they build a value:
 *
 * - duplicate member names, compared after unescaping, in any object,
 *   including the open "extensions" and "attributes" objects and free-form
 *   values;
 * - member names that are not an exact, case-sensitive match of a member of
 *   the target class, except inside maps and free-form values such as
 *   extensions, attributes and headers;
 * - nesting deeper than Limits::$maxDepth (16 by default);
 * - non-finite numbers: NaN, Infinity and literals that overflow binary64;
 * - invalid UTF-8 and unpaired surrogate escapes;
 * - integer literals outside ±(2^53-1), anywhere in the document, and, for an
 *   integer member, negative or non-integer numbers;
 * - null for any target that cannot hold it (a nullable member or a
 *   free-form value can);
 * - empty input, text after the JSON value, and input over Limits::$maxBytes.
 *
 * The decoder checks syntax and shape. It does not apply the schema's
 * patterns, lengths, enum sets or required members; a schema validator does.
 * A required member that is absent holds its Go zero value ('', 0, 0.0,
 * false, an empty list or JsonObject, a zero instance); an absent optional
 * member is null.
 *
 * It is a port of the Go package's walker: one pass over the bytes in step
 * with the target, reporting the first violation with the reason, RFC 6901
 * path and byte offset the Go package reports. As there, an unpaired
 * surrogate is reported after every other violation of the walk, and a value
 * that does not fit its target type (TYPE, path empty, offset the end of the
 * value) after that.
 *
 * Values: an object is a JsonObject (a map or an open object too), an array a
 * list, an integer literal an int, any other number a float, a string a UTF-8
 * string. A number member holds a float even when the literal is an integer.
 */
final class StrictJson
{
    /** The largest integer a core field may carry: 2^53-1. */
    public const int MAX_SAFE_INTEGER = 9007199254740991;

    /** The decoded presentation limit of draft section 20.1. */
    public const int DEFAULT_MAX_BYTES = 256 << 10;

    /** The JSON nesting limit of draft section 20.1; the outermost object or array has depth 1. */
    public const int DEFAULT_MAX_DEPTH = 16;

    private function __construct() {}

    /**
     * Strict-parse the JSON text $data into a free-form value (Go: Unmarshal
     * into any).
     *
     * @throws StrictJsonError
     */
    public static function parse(string $data, ?Limits $limits = null): mixed
    {
        return Walker::run($data, $limits, Target::free());
    }

    /**
     * parse() for a stream: reads at most Limits::$maxBytes + 1 bytes (Go:
     * Decode).
     *
     * @param resource $stream
     *
     * @throws StrictJsonError
     * @throws \RuntimeException when the stream cannot be read
     */
    public static function parseStream($stream, ?Limits $limits = null): mixed
    {
        $want = ($limits ?? new Limits())->bytes() + 1;
        $data = '';
        while (\strlen($data) < $want && !feof($stream)) {
            $b = fread($stream, max(1, $want - \strlen($data)));
            if ($b === false) {
                throw new \RuntimeException('strictjson: read failed');
            }
            if ($b === '') {
                break;
            }
            $data .= $b;
        }

        return self::parse($data, $limits);
    }

    /**
     * Strict-decode the JSON text $data into an instance of $class: a wire
     * class of HopTop\Pact\Core, another class with a MEMBERS table of the
     * same form, or JsonObject for an object of free-form values (Go:
     * map[string]any).
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     *
     * @throws StrictJsonError TARGET when $class is none of these, before the input is read
     */
    public static function decode(string $data, string $class, ?Limits $limits = null): object
    {
        $v = Walker::run($data, $limits, Target::of($class));
        if (!$v instanceof $class) {
            throw new StrictJsonError(StrictJsonErrorKind::TARGET, '', 0, 'the decoded value is not a ' . $class);
        }

        return $v;
    }
}
