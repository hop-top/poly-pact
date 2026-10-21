<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;

/**
 * A plain reader of the fixture manifest, for the harness alone: strict
 * JSON (duplicate members refused).
 *
 * It checks the members the harness relies on (shape, id, duplicate id,
 * kind, scope, capabilities) and nothing else; the other manifest rules
 * belong to the manifest check. The kind, scope and capability tables are
 * those of the Go package runner/manifest (Kinds, Scopes, Capabilities).
 */
final class Manifest
{
    /** @var list<string> */
    public const KINDS = [
        'key', 'vector', 'schema', 'evaluate', 'outcomes', 'learning',
        'adapter-case', 'adapter-asset', 'source-case', 'profile-invalid',
        'transport', 'mcp', 'profile',
    ];

    /** @var list<string> */
    public const SCOPES = ['core', 'runner', 'adapter'];

    /** @var list<string> */
    public const CAPABILITIES = ['jws-ed25519'];

    /**
     * Read the manifest at $path.
     *
     * @return list<Entry>
     */
    public static function load(string $path): array
    {
        $data = is_file($path) ? @file_get_contents($path) : false;
        if ($data === false) {
            throw new HarnessError(\sprintf('%s: cannot be read', $path));
        }
        try {
            $doc = StrictJson::parse($data, new Limits(Fixtures::MAX_FIXTURE_BYTES, 64));
        } catch (StrictJsonError $e) {
            throw new HarnessError(\sprintf('%s: %s', $path, $e->getMessage()), 0, $e);
        }
        if (!$doc instanceof JsonObject || $doc->get('manifest_version') !== 1 || !\is_array($doc->get('entries'))) {
            throw new HarnessError(\sprintf('%s: not a version 1 manifest with an entries array', $path));
        }
        $out = [];
        $seen = [];
        foreach ($doc->get('entries') as $i => $raw) {
            $out[] = $e = self::entry($raw, \sprintf('%s: entries[%d]', $path, $i));
            if (isset($seen[$e->id])) {
                throw new HarnessError(\sprintf('%s: duplicate id %s', $path, $e->id));
            }
            $seen[$e->id] = true;
        }

        return $out;
    }

    /**
     * The entry of $entries whose id is $id, or null.
     *
     * @param list<Entry> $entries
     */
    public static function lookup(array $entries, string $id): ?Entry
    {
        foreach ($entries as $e) {
            if ($e->id === $id) {
                return $e;
            }
        }

        return null;
    }

    private static function entry(mixed $raw, string $where): Entry
    {
        if (!$raw instanceof JsonObject) {
            throw new HarnessError($where . ': not an object');
        }
        foreach (['id', 'kind', 'scope', 'path'] as $m) {
            if (!\is_string($raw->get($m)) || $raw->get($m) === '') {
                throw new HarnessError(\sprintf('%s: %s is not a non-empty string', $where, $m));
            }
        }
        foreach (['expected', 'outcome'] as $m) {
            if ($raw->get($m) !== null && !\is_string($raw->get($m))) {
                throw new HarnessError(\sprintf('%s: %s is not a string or null', $where, $m));
            }
        }
        /** @var string $id */
        $id = $raw->get('id');
        /** @var string $kind */
        $kind = $raw->get('kind');
        /** @var string $scope */
        $scope = $raw->get('scope');
        if (!\in_array($kind, self::KINDS, true)) {
            throw new HarnessError(\sprintf('entry %s: unknown kind %s', $id, $kind));
        }
        if (!\in_array($scope, self::SCOPES, true)) {
            throw new HarnessError(\sprintf('entry %s: unknown scope %s', $id, $scope));
        }
        $caps = null;
        if ($raw->has('capabilities')) {
            $caps = $raw->get('capabilities');
            if (!\is_array($caps) || $caps === [] || !array_is_list($caps)) {
                throw new HarnessError(\sprintf('entry %s: capabilities is not a non-empty array', $id));
            }
            foreach ($caps as $c) {
                if (!\is_string($c) || !\in_array($c, self::CAPABILITIES, true)) {
                    throw new HarnessError(\sprintf('entry %s: unknown capability %s', $id, json_encode($c)));
                }
            }
        }
        /** @var string $p */
        $p = $raw->get('path');
        /** @var ?string $expected */
        $expected = $raw->get('expected');
        /** @var ?string $outcome */
        $outcome = $raw->get('outcome');

        return new Entry($id, $kind, $scope, $p, $expected, $outcome, $caps);
    }
}
