<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\Schema\Schema;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;

/**
 * vectors/schema: validate each string against a Draft 2020-12 schema
 * asserting the entry's format, with the package's validator (the shared
 * uri expression registered), and require each verdict
 * (spec/v1.0/fixtures/vectors/schema/README.md).
 */
final class SchemaGroup implements Group
{
    /** The format each vectors/schema entry tests. */
    public const FORMATS = ['vectors/schema/uri-format' => 'uri'];

    /** @var list<string> */
    public const MEMBERS = ['id', 'input', 'expect', 'reason', 'ajv_formats_differs'];

    public function run(string $root, Entry $e): void
    {
        Fixtures::singleFile($e);
        $format = self::FORMATS[$e->id] ?? null;
        if ($format === null) {
            throw new Fail('no format for ' . $e->id);
        }
        if ($e->outcome !== 'MATCH') {
            throw new Fail(\sprintf('outcome %s, want MATCH', json_encode($e->outcome)));
        }
        $schema = (object) ['type' => 'string', 'format' => $format];
        $validator = Schema::validator();
        $seen = [];
        $wrong = [];
        foreach (Fixtures::arr(Fixtures::readJson($root, $e->path), $e->path) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('vector %d', $i), self::MEMBERS);
            $id = $v->get('id');
            if (!\is_string($id) || $id === '' || isset($seen[$id])) {
                throw new Fail(\sprintf('vector %d: id %s is empty or repeated', $i, json_encode($id)));
            }
            $seen[$id] = true;
            $expect = $v->get('expect');
            if ($expect !== 'accept' && $expect !== 'reject') {
                throw new Fail(\sprintf('%s: expect %s, want accept or reject', $id, json_encode($expect)));
            }
            $got = $validator->validate(Fixtures::str($v->get('input'), $id . ': input'), $schema)->isValid() ? 'accept' : 'reject';
            if ($got !== $expect) {
                $wrong[] = \sprintf('%s: %sed, want %s', $id, $got, $expect);
            }
        }
        if ($wrong !== []) {
            throw new Fail(\sprintf('format %s: %s', $format, implode('; ', $wrong)));
        }
    }
}
