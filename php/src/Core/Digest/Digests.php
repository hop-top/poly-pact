<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Digest;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use HopTop\Pact\PactError;

/**
 * Object, artifact and bytes digests (draft section 7.4). Mirrors Go package
 * hop.top/pact-go/core/digest.
 *
 * Each digest is the unpadded base64url SHA-256 of its input:
 *
 * - objectDigest($value): of the RFC 8785 canonical form of a JSON object;
 * - artifactDigest($compact): of the ASCII bytes of a compact JWS, exactly
 *   as given;
 * - bytesDigest($data): of the octets.
 *
 * objectDigest() takes a JsonObject (what StrictJson::parse() returns for an
 * object; received JSON reaches it through the strict parse, which refuses
 * duplicate members and the other violations of draft section 7.1) or a wire
 * object of HopTop\Pact\Core (a class with a MEMBERS table), which writes its
 * members and leaves out an absent optional member, as Go's omitzero does.
 * Compare digests with hash_equals().
 */
final class Digests
{
    /**
     * Floats of a magnitude in this range are written without an exponent,
     * as integer literals when integral (ECMAScript Number::toString, and
     * Go's encoding/json).
     */
    private const EXPONENT_FORM = 1e21;

    private function __construct() {}

    /**
     * object_digest($value): the digest of the RFC 8785 canonical form of the
     * JSON object $value.
     *
     * The checks are Go's, whose ObjectDigest JSON-encodes the value and
     * canonicalizes that text with the strict parse: StrictJsonError for
     * what Jcs::canonicalizeValue() refuses; SIZE when Go's encoding of the
     * value is over 256 KiB (the canonical form plus 3 bytes for each U+2028
     * or U+2029, which Go escapes, and 1 for each -0.0, which Go writes
     * "-0"); INTEGER for a float whose canonical form is an integer literal
     * outside ±(2^53-1) (an integral value of magnitude above 2^53-1 and
     * below 10^21), which a receiver's strict parse refuses. NotObjectError
     * for a value that is not an object; \InvalidArgumentException for a
     * value that is not JSON.
     *
     * @throws NotObjectError
     * @throws StrictJsonError
     * @throws \InvalidArgumentException
     */
    public static function objectDigest(mixed $value): Digest
    {
        $v = self::json($value, 0);
        if (!$v instanceof JsonObject) {
            throw new NotObjectError();
        }
        $canonical = Jcs::canonicalizeValue($v);
        $negativeZeros = 0;
        $unsafe = null;
        $path = [];
        self::floats($v, $path, $negativeZeros, $unsafe);
        $size = \strlen($canonical) + 3 * (substr_count($canonical, "\u{2028}") + substr_count($canonical, "\u{2029}")) + $negativeZeros;
        if ($size > StrictJson::DEFAULT_MAX_BYTES) {
            throw new StrictJsonError(StrictJsonErrorKind::SIZE, '', StrictJson::DEFAULT_MAX_BYTES, \sprintf('encoding is %d bytes, limit is %d bytes', $size, StrictJson::DEFAULT_MAX_BYTES));
        }
        if ($unsafe !== null) {
            [$pointer, $f] = $unsafe;
            throw new StrictJsonError(StrictJsonErrorKind::INTEGER, $pointer, 0, \sprintf('%s is written as an integer literal outside ±%d', Jcs::canonicalizeValue($f), StrictJson::MAX_SAFE_INTEGER));
        }

        return self::bytesDigest($canonical);
    }

    /**
     * artifact_digest($compact): the digest of the ASCII bytes of the compact
     * JWS serialization $compact, exactly as given.
     *
     * @throws PactError for a byte outside ASCII
     */
    public static function artifactDigest(string $compact): Digest
    {
        $n = strspn($compact, implode('', array_map(\chr(...), range(0, 0x7F))));
        if ($n !== \strlen($compact)) {
            throw new PactError(\sprintf('digest: artifact has non-ASCII byte 0x%02x at offset %d', \ord($compact[$n]), $n));
        }

        return self::bytesDigest($compact);
    }

    /** bytes_digest($data): the base64url SHA-256 of $data, without padding. */
    public static function bytesDigest(string $data): Digest
    {
        return new Digest(rtrim(strtr(base64_encode(hash('sha256', $data, true)), '+/', '-_'), '='));
    }

    /**
     * $v with its wire objects written as JsonObject. Past the depth limit
     * the value is left as it is, for Jcs::canonicalizeValue() to refuse.
     */
    private static function json(mixed $v, int $depth): mixed
    {
        if ($depth > StrictJson::DEFAULT_MAX_DEPTH) {
            return $v;
        }
        if ($v instanceof JsonObject) {
            $pairs = [];
            foreach ($v->pairs() as [$name, $x]) {
                $pairs[] = [$name, self::json($x, $depth + 1)];
            }

            return JsonObject::fromPairs($pairs);
        }
        if (\is_array($v)) {
            return array_map(static fn(mixed $x): mixed => self::json($x, $depth + 1), $v);
        }
        if (\is_object($v) && \defined($v::class . '::MEMBERS')) {
            $members = \constant($v::class . '::MEMBERS');
            if (!\is_array($members)) {
                return $v;
            }
            $vars = get_object_vars($v);
            $pairs = [];
            foreach ($members as $name => $m) {
                $name = (string) $name;
                $x = $vars[$name] ?? null;
                if ($x === null && \is_array($m) && ($m['required'] ?? false) !== true) {
                    continue;
                }
                $pairs[] = [$name, self::json($x, $depth + 1)];
            }

            return JsonObject::fromPairs($pairs);
        }

        return $v;
    }

    /**
     * Count the -0.0 floats of $v, a value Jcs::canonicalizeValue() accepted
     * (so at most 16 deep), and find the first, in canonical member order,
     * integral float written as an integer literal beyond 2^53-1.
     *
     * @param list<string>               $path
     * @param array{string, float}|null $unsafe the RFC 6901 path and the value
     */
    private static function floats(mixed $v, array &$path, int &$negativeZeros, ?array &$unsafe): void
    {
        if (\is_float($v)) {
            $a = abs($v);
            if ($v === 0.0 && fdiv(1.0, $v) < 0) {
                ++$negativeZeros;
            } elseif ($unsafe === null && $a > StrictJson::MAX_SAFE_INTEGER && $a < self::EXPONENT_FORM && floor($v) === $v) {
                $pointer = '';
                foreach ($path as $p) {
                    $pointer .= '/' . strtr($p, ['~' => '~0', '/' => '~1']);
                }
                $unsafe = [$pointer, $v];
            }
        } elseif ($v instanceof JsonObject) {
            $names = [];
            foreach ($v->names() as $name) {
                $names[$name] = mb_convert_encoding($name, 'UTF-16BE', 'UTF-8');
            }
            uasort($names, strcmp(...));
            foreach (array_keys($names) as $name) {
                $path[] = (string) $name;
                self::floats($v->get((string) $name), $path, $negativeZeros, $unsafe);
                array_pop($path);
            }
        } elseif (\is_array($v)) {
            foreach ($v as $i => $x) {
                $path[] = (string) $i;
                self::floats($x, $path, $negativeZeros, $unsafe);
                array_pop($path);
            }
        }
    }
}
