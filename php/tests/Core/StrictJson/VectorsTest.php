<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind as K;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\TestCase;

/**
 * The strictjson vectors. Port of go/core/strictjson/vectors_test.go: reads
 * spec/v1.0/fixtures/manifest.json of the source repository, failing when it
 * is absent under PACT_REQUIRE_VECTORS=1 and skipping otherwise.
 */
final class VectorsTest extends TestCase
{
    private const FIXTURES = 'spec/v1.0/fixtures/';

    private const PREFIX = 'vectors/strictjson/';

    /** The reason each reject vector fails for; a vector missing here is still run. */
    private const WANT_ERR = [
        'duplicate-key-top-level' => K::DUPLICATE_KEY,
        'duplicate-key-identical-values' => K::DUPLICATE_KEY,
        'duplicate-key-nested' => K::DUPLICATE_KEY,
        'duplicate-key-in-headers' => K::DUPLICATE_KEY,
        'duplicate-key-escaped-form' => K::DUPLICATE_KEY,
        'unknown-core-field' => K::UNKNOWN_FIELD,
        'unknown-core-field-case-variant' => K::UNKNOWN_FIELD,
        'nesting-depth-17-objects' => K::DEPTH,
        'nesting-depth-17-arrays' => K::DEPTH,
        'non-finite-number-1e999' => K::NON_FINITE,
        'non-finite-number-negative-1e999' => K::NON_FINITE,
        'non-finite-number-nan' => K::NON_FINITE,
        'non-finite-number-infinity' => K::NON_FINITE,
        'non-finite-number-negative-infinity' => K::NON_FINITE,
        'invalid-utf8-byte-ff' => K::INVALID_UTF8,
        'invalid-utf8-truncated-sequence' => K::INVALID_UTF8,
        'invalid-utf8-overlong-encoding' => K::INVALID_UTF8,
        'invalid-utf8-encoded-surrogate' => K::INVALID_UTF8,
        'lone-surrogate-high' => K::LONE_SURROGATE,
        'lone-surrogate-low' => K::LONE_SURROGATE,
        'lone-surrogate-high-then-bmp' => K::LONE_SURROGATE,
        'integer-overflow-2-pow-53' => K::INTEGER,
        'integer-overflow-negative' => K::INTEGER,
        'integer-overflow-huge' => K::INTEGER,
        'trailing-garbage-text' => K::TRAILING_DATA,
        'trailing-garbage-second-value' => K::TRAILING_DATA,
        'trailing-garbage-extra-brace' => K::TRAILING_DATA,
    ];

    /** The cases the vector set must contain, whatever else a later change adds. */
    private const REQUIRED_CASES = [
        'duplicate-key-top-level',
        'duplicate-key-nested',
        'unknown-core-field',
        'nesting-depth-17-objects',
        'non-finite-number-1e999',
        'invalid-utf8-byte-ff',
        'lone-surrogate-high',
        'integer-overflow-2-pow-53',
        'trailing-garbage-text',
        'accept-valid-object',
        'accept-depth-16-objects',
        'accept-integer-max-safe',
    ];

    private static function readJson(string $rel): JsonObject
    {
        $v = StrictJson::parse(Repo::read(self::FIXTURES . $rel), new Limits(maxBytes: 1 << 20));
        self::assertInstanceOf(JsonObject::class, $v, $rel);

        return $v;
    }

    private static function str(JsonObject $o, string $name): string
    {
        $v = $o->get($name, '');
        self::assertIsString($v, $name);

        return $v;
    }

    public function testVectorsViaManifest(): void
    {
        $m = self::readJson('manifest.json');
        self::assertSame(1, $m->get('manifest_version'));
        $entries = $m->get('entries');
        self::assertIsArray($entries);
        $ids = [];
        $seen = [];
        foreach ($entries as $e) {
            self::assertInstanceOf(JsonObject::class, $e);
            $id = self::str($e, 'id');
            $ids[] = $id;
            if (str_starts_with($id, self::PREFIX)) {
                $seen[substr($id, \strlen(self::PREFIX))] = $e;
            }
        }
        $sorted = $ids;
        sort($sorted, \SORT_STRING);
        self::assertSame($sorted, $ids, 'manifest entries are not sorted by id');
        self::assertSame(\count($ids), \count(array_unique($ids)), 'manifest ids are not unique');
        self::assertNotSame([], $seen, 'manifest lists no strictjson vectors');
        foreach (self::REQUIRED_CASES as $c) {
            self::assertArrayHasKey($c, $seen, 'manifest lacks required case ' . $c);
        }
        foreach (glob(Repo::root() . '/' . self::FIXTURES . self::PREFIX . '*') ?: [] as $f) {
            self::assertArrayHasKey(basename($f, '.json'), $seen, self::PREFIX . basename($f) . ' is not listed');
        }
        foreach ($seen as $name => $e) {
            $this->runEntry((string) $name, $e);
        }
        self::assertCount(36, $seen);
    }

    private function runEntry(string $name, JsonObject $e): void
    {
        $id = self::str($e, 'id');
        self::assertSame(['vector', 'core'], [$e->get('kind'), $e->get('scope')], $id);
        self::assertSame($id . '.json', $e->get('path'), $id);
        self::assertSame($e->get('path'), $e->get('expected'), $id);
        self::assertNotSame('', self::str($e, 'spec_map_row'), $id);
        self::assertNotSame('', self::str($e, 'draft_section'), $id);
        $v = self::readJson(self::str($e, 'path'));
        self::assertSame($id, $v->get('id'));
        self::assertNotSame('', self::str($v, 'reason'), $id);
        $text = self::str($v, 'input_text');
        $b64 = self::str($v, 'input_b64');
        self::assertFalse($text !== '' && $b64 !== '', $id . ' sets both input_text and input_b64');
        self::assertTrue($text !== '' || $b64 !== '', $id . ' has no input');
        $data = $b64 !== '' ? base64_decode($b64, true) : $text;
        self::assertIsString($data, $id);
        $want = ['reject' => 'REJECTED', 'accept' => 'ACCEPTED'][self::str($v, 'expect')] ?? null;
        self::assertSame($want, $e->get('outcome'), $id);
        // Every vector is decoded as an OperationContext.
        if ($want === 'ACCEPTED') {
            self::assertInstanceOf(OperationContext::class, StrictJson::decode($data, OperationContext::class), $id);

            return;
        }
        try {
            StrictJson::decode($data, OperationContext::class);
            self::fail($id . ': accepted, want reject');
        } catch (StrictJsonError $err) {
            if (isset(self::WANT_ERR[$name])) {
                self::assertSame(self::WANT_ERR[$name], $err->kind, $id . ': ' . $err->getMessage());
            }
        }
    }
}
