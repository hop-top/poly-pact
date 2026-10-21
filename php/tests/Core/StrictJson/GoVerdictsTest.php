<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Vectors\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Replays testdata/strictjson-go-verdicts.json: the kind, RFC 6901 path and
 * byte offset that hop.top/pact-go/core/strictjson reports for 142 inputs
 * (every TestDecodeRejects case, the syntax and offset edges), decoded into
 * the Go test's sample struct (Sample), an untyped target (any: parse), a
 * map[string]any (JsonObject) and core.OperationContext.
 */
final class GoVerdictsTest extends TestCase
{
    private const TARGETS = [
        'sample' => Sample::class,
        'any' => null,
        'map' => JsonObject::class,
        'op' => OperationContext::class,
    ];

    /** @return iterable<string, array{JsonObject}> */
    public static function rows(): iterable
    {
        $rows = Fixtures::parseJson((string) file_get_contents(\dirname(__DIR__, 2) . '/testdata/strictjson-go-verdicts.json'));
        self::assertIsArray($rows);
        self::assertCount(142, $rows);
        foreach ($rows as $row) {
            self::assertInstanceOf(JsonObject::class, $row);
            yield (string) Fixtures::str($row->get('name'), 'name') => [$row];
        }
    }

    private static function input(JsonObject $row): string
    {
        if ($row->has('input_b64')) {
            $b = base64_decode(Fixtures::str($row->get('input_b64'), 'input_b64'), true);
            self::assertIsString($b);

            return $b;
        }
        if ($row->has('input_repeat')) {
            $r = $row->get('input_repeat');
            self::assertIsArray($r);
            self::assertIsString($r[0]);
            self::assertIsInt($r[1]);

            return str_repeat($r[0], $r[1]);
        }

        return Fixtures::str($row->get('input_text'), 'input_text');
    }

    #[DataProvider('rows')]
    public function testGoVerdicts(JsonObject $row): void
    {
        $data = self::input($row);
        $maxBytes = $row->get('max_bytes', 0);
        $maxDepth = $row->get('max_depth', 0);
        self::assertIsInt($maxBytes);
        self::assertIsInt($maxDepth);
        $lim = new Limits($maxBytes, $maxDepth);
        $target = $row->get('target');
        self::assertIsString($target);
        self::assertArrayHasKey($target, self::TARGETS);
        $class = self::TARGETS[$target];
        try {
            $class === null ? StrictJson::parse($data, $lim) : StrictJson::decode($data, $class, $lim);
            $got = ['kind' => 'accept'];
        } catch (StrictJsonError $e) {
            $got = ['kind' => $e->kind->value, 'path' => $e->path, 'offset' => $e->offset];
        }
        $want = [];
        foreach (['kind', 'path', 'offset'] as $k) {
            if ($row->has($k)) {
                $want[$k] = $row->get($k);
            }
        }
        self::assertSame($want, $got);
    }
}
