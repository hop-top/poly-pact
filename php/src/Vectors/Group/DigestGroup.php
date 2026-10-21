<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\Digest\Digests;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;
use HopTop\Pact\Vectors\Skipped;

/**
 * vectors/digest: digest every vector of the file with Digests and compare
 * with expected_digest; then compare the draft's appendix_value
 * (spec/v1.0/fixtures/vectors/digest/README.md). A flagged draft value that
 * differs is a spec defect, reported as a skip naming both values.
 */
final class DigestGroup implements Group
{
    /** @var list<string> */
    public const MEMBERS = ['id', 'input_kind', 'input', 'expected_digest', 'spec_defect', 'appendix_value'];

    public function run(string $root, Entry $e): void
    {
        Fixtures::singleFile($e);
        if ($e->outcome !== 'ACCEPTED') {
            throw new Fail(\sprintf('outcome %s, want ACCEPTED', json_encode($e->outcome)));
        }
        $seen = [];
        $notes = [];
        $defects = [];
        foreach (Fixtures::arr(Fixtures::readJson($root, $e->path), $e->path) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('vector %d', $i), self::MEMBERS);
            $id = $v->get('id');
            if (!\is_string($id) || $id === '' || isset($seen[$id])) {
                throw new Fail(\sprintf('vector %d: id %s is empty or repeated', $i, json_encode($id)));
            }
            $seen[$id] = true;
            try {
                $got = self::compute($v);
            } catch (Fail $f) {
                throw new Fail(\sprintf('%s: %s', $id, $f->getMessage()), 0, $f);
            }
            $want = Fixtures::str($v->get('expected_digest'), $id . ': expected_digest');
            if (!hash_equals($want, $got)) {
                throw new Fail(\sprintf('%s: digest %s, want expected_digest %s', $id, $got, $want));
            }
            $flag = $v->get('spec_defect');
            if (!\is_bool($flag)) {
                throw new Fail(\sprintf('%s: spec_defect is not a boolean', $id));
            }
            if ($v->get('appendix_value') === null) {
                if ($flag) {
                    throw new Fail(\sprintf('%s: spec_defect is set but appendix_value is null', $id));
                }
                continue;
            }
            $appendix = Fixtures::str($v->get('appendix_value'), $id . ': appendix_value');
            $match = hash_equals($appendix, $got);
            if ($match && $flag) {
                throw new Fail(\sprintf('%s: spec_defect is set but appendix_value matches', $id));
            }
            if ($match) {
                continue;
            }
            if (!$flag) {
                throw new Fail(\sprintf('%s: appendix_value %s differs from %s and spec_defect is not set', $id, $appendix, $got));
            }
            $notes[] = \sprintf('%s: the draft states %s, computed %s', $id, $appendix, $got);
            $defects[] = ['vector' => $id, 'appendix_value' => $appendix, 'expected_digest' => $got];
        }
        if ($defects !== []) {
            throw new Skipped(Skipped::SPEC_DEFECT, 'spec defect: ' . implode('; ', $notes), $defects);
        }
    }

    private static function compute(JsonObject $v): string
    {
        $kind = $v->get('input_kind');
        $input = $v->get('input');

        return match ($kind) {
            'object' => Digests::objectDigest($input)->value,
            'artifact' => Digests::artifactDigest(Fixtures::str($input, 'input'))->value,
            'bytes' => Digests::bytesDigest(self::hex(Fixtures::str($input, 'input')))->value,
            default => throw new Fail(\sprintf('input_kind %s is not object, artifact or bytes', json_encode($kind))),
        };
    }

    private static function hex(string $s): string
    {
        $b = preg_match('/\A(?:[0-9a-f]{2})*\z/', $s) === 1 ? hex2bin($s) : false;
        if ($b === false) {
            throw new Fail(\sprintf('input %s is not lowercase hex', json_encode($s)));
        }

        return $b;
    }
}
