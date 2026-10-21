<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

use HopTop\Pact\Vectors\Group\DigestGroup;
use HopTop\Pact\Vectors\Group\JcsGroup;
use HopTop\Pact\Vectors\Group\JwsGroup;
use HopTop\Pact\Vectors\Group\KeyGroup;
use HopTop\Pact\Vectors\Group\SchemaCaseGroup;
use HopTop\Pact\Vectors\Group\SchemaGroup;
use HopTop\Pact\Vectors\Group\StrictJsonGroup;

/**
 * The (kind, prefix) groups the harness runs, each with its runner.
 *
 * A runner takes the fixture directory and an entry, calls the package code
 * under test and compares its result with the entry's outcome and expected
 * file. It returns on a pass and throws Fail or Skipped otherwise; any other
 * exception is a fail. The binding vectors have scope adapter and gate n/a
 * for php (the PHP SDK is core-only), so they are not a group here.
 */
final class Groups
{
    /** The kinds the harness runs, in scope core and adapter. */
    public const RUN_KINDS = ['vector', 'key', 'schema'];

    /** The optional capabilities this harness declares: none. */
    public const DECLARED_CAPABILITIES = [];

    /**
     * Runner class by "kind prefix".
     *
     * @var array<string, class-string<Group\Group>>
     */
    public const RUNNERS = [
        'key keys' => KeyGroup::class,
        'schema parse' => SchemaCaseGroup::class,
        'schema schema' => SchemaCaseGroup::class,
        'vector vectors/digest' => DigestGroup::class,
        'vector vectors/jcs' => JcsGroup::class,
        'vector vectors/jws' => JwsGroup::class,
        'vector vectors/schema' => SchemaGroup::class,
        'vector vectors/strictjson' => StrictJsonGroup::class,
    ];

    /**
     * The gate prefix of an entry: the first segment of the id, or the first
     * two under vectors/, adapters/ and sources/.
     */
    public static function prefix(Entry $e): string
    {
        $segs = explode('/', $e->id);
        if (\in_array($segs[0], ['vectors', 'adapters', 'sources'], true) && \count($segs) > 1) {
            return $segs[0] . '/' . $segs[1];
        }

        return $segs[0];
    }

    /**
     * Whether the harness runs an entry: a run kind outside scope runner, in
     * a group of this harness. A run-kind entry of scope adapter outside the
     * groups (the binding vectors) is out of scope for the core-only SDK.
     */
    public static function runs(Entry $e): bool
    {
        if ($e->scope === 'runner' || !\in_array($e->kind, self::RUN_KINDS, true)) {
            return false;
        }

        return $e->scope === 'core' || isset(self::RUNNERS[$e->kind . ' ' . self::prefix($e)]);
    }

    /** The runner of $e, or a harness error for a core entry of an unknown group. */
    public static function runner(Entry $e): Group\Group
    {
        $class = self::RUNNERS[$e->kind . ' ' . self::prefix($e)] ?? null;
        if ($class === null) {
            $groups = [];
            foreach (array_keys(self::RUNNERS) as $k) {
                [$kind, $prefix] = explode(' ', $k, 2);
                if ($kind === $e->kind) {
                    $groups[] = $prefix;
                }
            }
            throw new HarnessError(\sprintf('entry %s: unknown prefix %s for kind %s of scope %s (groups: %s)', $e->id, json_encode(self::prefix($e)), $e->kind, $e->scope, implode(', ', $groups)));
        }

        return new $class();
    }
}
