<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Vectors\Fixtures;
use PHPUnit\Framework\TestCase;

/**
 * The seeded counterpart of Go's FuzzUnmarshal: an accepted input is valid
 * JSON and survives a second strict decode of its own re-encoding; no input
 * raises anything but StrictJsonError.
 */
final class FuzzSeedsTest extends TestCase
{
    private const SEEDS = [
        '{}',
        '{"name":"a"}',
        '{"name":"a","name":"b"}',
        '{"count":9007199254740992}',
        '{"raw":[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}',
        '{"name":"\ud800"}',
        "{\"name\":\"\xff\"}",
        '{"ratio":1e999}',
        '{"raw":NaN}',
        '{} x',
        '',
        '[',
        '{"inner":{"n":1}}',
        '{"extensions":{"a":{"a":1}}}',
    ];

    private static function model(mixed $v): mixed
    {
        if ($v instanceof Sample || $v instanceof Inner) {
            $pairs = [];
            $props = get_object_vars($v);
            foreach (array_keys($v::MEMBERS) as $name) {
                $pairs[] = [$name, self::model($props[$name])];
            }

            return JsonObject::fromPairs($pairs);
        }
        if ($v instanceof JsonObject) {
            return JsonObject::fromPairs(array_map(static fn(array $p): array => [$p[0], self::model($p[1])], $v->pairs()));
        }

        return \is_array($v) ? array_map(self::model(...), $v) : $v;
    }

    public function testUnmarshalFuzzSeeds(): void
    {
        mt_srand(20261019);
        $alphabet = '{}[]",:0123456789-+.eEtrufalsn\u ';
        $inputs = self::SEEDS;
        foreach (self::SEEDS as $seed) {
            for ($k = 0; $k < 40; ++$k) {
                $b = $seed;
                for ($m = mt_rand(1, 3); $m > 0; --$m) {
                    $op = mt_rand(0, 2);
                    $i = mt_rand(0, \strlen($b));
                    if ($op === 0) {
                        $b = substr($b, 0, $i) . \chr(mt_rand(0, 255)) . substr($b, $i);
                    } elseif ($b !== '') {
                        $j = min($i, \strlen($b) - 1);
                        $b = substr($b, 0, $j) . ($op === 1 ? '' : $alphabet[mt_rand(0, \strlen($alphabet) - 1)]) . substr($b, $j + 1);
                    }
                }
                $inputs[] = $b;
            }
        }
        $accepted = 0;
        foreach ($inputs as $data) {
            try {
                $s = StrictJson::decode($data, Sample::class);
            } catch (StrictJsonError) {
                continue;
            }
            ++$accepted;
            json_decode($data, true, 512, \JSON_THROW_ON_ERROR);
            $again = StrictJson::decode(Fixtures::dumpJson(self::model($s)), Sample::class);
            self::assertEquals($s, $again, $data);
        }
        self::assertGreaterThan(0, $accepted);
    }
}
