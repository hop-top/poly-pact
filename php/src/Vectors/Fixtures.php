<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

use HopTop\Pact\Core\JsonObject;

/**
 * Fixture file reading shared by the harness groups.
 *
 * Fixture files are parsed with ext-json, not with the package's strict
 * parser, so that a fixture defect is told apart from a defect of the code
 * under test. Objects become JsonObject and arrays PHP lists, the package's
 * value model.
 */
final class Fixtures
{
    /** The largest fixture file, the RFC 8785 number list, is under 1 MiB. */
    public const MAX_FIXTURE_BYTES = 4 << 20;

    /** Parse UTF-8 JSON text into the package's value model. */
    public static function parseJson(string $data): mixed
    {
        try {
            $v = json_decode($data, false, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \UnexpectedValueException($e->getMessage(), 0, $e);
        }

        return self::model($v);
    }

    /** Write a value of the package's model as compact UTF-8 JSON text. */
    public static function dumpJson(mixed $value): string
    {
        return json_encode(self::plain($value), \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION | \JSON_THROW_ON_ERROR);
    }

    /** Whether $p is a slash-separated relative path with no empty, '.' or '..' segment. */
    public static function localPath(string $p): bool
    {
        if ($p === '') {
            return false;
        }
        foreach (explode('/', $p) as $seg) {
            if ($seg === '' || $seg === '.' || $seg === '..' || str_contains($seg, '\\')) {
                return false;
            }
        }

        return true;
    }

    /** Read the fixture file $rel of the fixture directory $root. */
    public static function read(string $root, string $rel): string
    {
        if (!self::localPath($rel)) {
            throw new Fail(\sprintf('path %s is not inside the fixture directory', json_encode($rel)));
        }
        $file = $root . '/' . $rel;
        $data = is_file($file) ? @file_get_contents($file) : false;
        if ($data === false) {
            throw new Fail(\sprintf('%s: cannot be read', $rel));
        }
        if (\strlen($data) > self::MAX_FIXTURE_BYTES) {
            throw new Fail(\sprintf('%s: larger than %d bytes', $rel, self::MAX_FIXTURE_BYTES));
        }

        return $data;
    }

    /** Read and parse the fixture file $rel. */
    public static function readJson(string $root, string $rel): mixed
    {
        try {
            return self::parseJson(self::read($root, $rel));
        } catch (\UnexpectedValueException $e) {
            throw new Fail(\sprintf('%s: %s', $rel, $e->getMessage()), 0, $e);
        }
    }

    /** Require that the entry names one JSON file holding its own expectations. */
    public static function singleFile(Entry $e): void
    {
        if (!str_ends_with($e->path, '.json') || $e->expected !== $e->path) {
            throw new Fail(\sprintf('path %s and expected %s must name the same JSON file', json_encode($e->path), json_encode($e->expected)));
        }
    }

    /**
     * Require a JSON object with every required member and no member outside both lists.
     *
     * @param list<string> $required
     * @param list<string> $optional
     */
    public static function obj(mixed $v, string $where, array $required, array $optional = []): JsonObject
    {
        if (!$v instanceof JsonObject) {
            throw new Fail(\sprintf('%s: not an object', $where));
        }
        $names = $v->names();
        $missing = array_diff($required, $names);
        $unknown = array_diff($names, $required, $optional);
        if ($missing !== [] || $unknown !== []) {
            sort($names);
            throw new Fail(\sprintf('%s: members [%s], want [%s] (optional [%s])', $where, implode(', ', $names), implode(', ', $required), implode(', ', $optional)));
        }

        return $v;
    }

    /**
     * Require a non-empty JSON array.
     *
     * @return non-empty-list<mixed>
     */
    public static function arr(mixed $v, string $where): array
    {
        if (!\is_array($v) || $v === [] || !array_is_list($v)) {
            throw new Fail(\sprintf('%s: not a non-empty array', $where));
        }

        return $v;
    }

    /** Require a string (or null when $null is set, returned as ''). */
    public static function str(mixed $v, string $where, bool $null = false): string
    {
        if ($v === null && $null) {
            return '';
        }
        if (!\is_string($v)) {
            throw new Fail(\sprintf('%s: not a string', $where));
        }

        return $v;
    }

    /** Decode unpadded base64url, for fixture members only. */
    public static function b64url(string $s, string $where): string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $s) !== 1 || \strlen($s) % 4 === 1) {
            throw new Fail(\sprintf('%s: not unpadded base64url', $where));
        }
        $out = base64_decode(strtr($s, '-_', '+/'), true);
        if ($out === false) {
            throw new Fail(\sprintf('%s: not unpadded base64url', $where));
        }

        return $out;
    }

    private static function model(mixed $v): mixed
    {
        if ($v instanceof \stdClass) {
            $pairs = [];
            foreach (get_object_vars($v) as $k => $x) {
                $pairs[] = [(string) $k, self::model($x)];
            }

            return JsonObject::fromPairs($pairs);
        }
        if (\is_array($v)) {
            return array_map(self::model(...), $v);
        }

        return $v;
    }

    private static function plain(mixed $v): mixed
    {
        if ($v instanceof JsonObject) {
            $o = new \stdClass();
            foreach ($v as $k => $x) {
                $o->{$k} = self::plain($x);
            }

            return $o;
        }
        if (\is_array($v)) {
            return array_map(self::plain(...), $v);
        }

        return $v;
    }
}
