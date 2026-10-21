<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;
use HopTop\Pact\Vectors\Group\DigestGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use HopTop\Pact\Vectors\Skipped;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The harness group of vectors/digest (port of go/core/digest/vectors_test.go
 * and the Python port's test_digest_vectors.py): every entry passes, and the
 * spec_defect protocol of the digest README holds.
 */
final class DigestGroupTest extends TestCase
{
    private const A = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
    private const B = 'R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0';
    private const INTENT_DIGEST_B2 = 't79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M';

    private string $dir = '';

    protected function tearDown(): void
    {
        if ($this->dir !== '') {
            @unlink($this->dir . '/d.json');
            rmdir($this->dir);
        }
    }

    /** @return list<Entry> */
    private static function entries(): array
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');

        return array_values(array_filter(Harness::loadManifest(Repo::root() . '/spec/v1.0/fixtures/manifest.json'), static fn(Entry $e): bool => Groups::prefix($e) === 'vectors/digest'));
    }

    public function testEveryDigestVectorPasses(): void
    {
        $entries = self::entries();
        self::assertContains('vectors/digest/appendix-b', array_map(static fn(Entry $e): string => $e->id, $entries));
        foreach ($entries as $e) {
            self::assertSame(['vector', 'core', 'ACCEPTED'], [$e->kind, $e->scope, $e->outcome], $e->id);
            (new DigestGroup())->run(Repo::root() . '/spec/v1.0/fixtures', $e);
        }
    }

    /** Each vector below carries the digest the draft prints, so deleting one or editing its input fails here. */
    public function testVectorsRequiredByTheDraft(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $vs = Fixtures::readJson(Repo::root() . '/spec/v1.0/fixtures', 'vectors/digest/appendix-b.json');
        self::assertIsArray($vs);
        $byId = [];
        $kinds = [];
        foreach ($vs as $v) {
            $v = Fixtures::obj($v, 'vector', DigestGroup::MEMBERS);
            $byId[(string) Fixtures::str($v->get('id'), 'id')] = $v;
            $kinds[] = $v->get('input_kind');
        }
        foreach (['empty-body' => ['bytes', self::A], 'operation-b3' => ['object', self::B], 'intent-b2' => ['object', self::INTENT_DIGEST_B2]] as $id => [$kind, $d]) {
            self::assertArrayHasKey($id, $byId);
            self::assertSame($kind, $byId[$id]->get('input_kind'), $id);
            self::assertSame($d, $byId[$id]->get('appendix_value'), $id);
        }
        foreach (['object', 'artifact', 'bytes'] as $k) {
            self::assertContains($k, $kinds);
        }
    }

    /** @param list<array<string, mixed>> $vectors */
    private function runVectors(array $vectors): void
    {
        if ($this->dir === '') {
            $this->dir = sys_get_temp_dir() . '/pact-php-digest-' . bin2hex(random_bytes(6));
            mkdir($this->dir);
        }
        file_put_contents($this->dir . '/d.json', json_encode($vectors, \JSON_THROW_ON_ERROR));
        (new DigestGroup())->run($this->dir, new Entry('vectors/digest/x', 'vector', 'core', 'd.json', 'd.json', 'ACCEPTED'));
    }

    /** @return array<string, mixed> */
    private static function vector(string $id, ?string $appendix, bool $flag, mixed $input = '', string $expected = self::A, string $kind = 'bytes'): array
    {
        return ['id' => $id, 'input_kind' => $kind, 'input' => $input, 'expected_digest' => $expected, 'spec_defect' => $flag, 'appendix_value' => $appendix];
    }

    public function testMatchAndNoDraftValuePass(): void
    {
        $this->runVectors([self::vector('match', self::A, false), self::vector('none', null, false), self::vector('obj', null, false, new \stdClass(), 'RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o', 'object')]);
        $this->addToAssertionCount(1);
    }

    public function testFlaggedDefectIsASkipNamingBothValues(): void
    {
        try {
            $this->runVectors([self::vector('ok', self::A, false), self::vector('defect', self::B, true)]);
            self::fail('passed');
        } catch (Skipped $s) {
            self::assertSame(Skipped::SPEC_DEFECT, $s->reason);
            self::assertSame([['vector' => 'defect', 'appendix_value' => self::B, 'expected_digest' => self::A]], $s->defects);
            self::assertStringContainsString(self::B, $s->getMessage());
            self::assertStringContainsString(self::A, $s->getMessage());
        }
    }

    /** @return iterable<string, array{list<array<string, mixed>>}> */
    public static function failures(): iterable
    {
        yield 'unflagged mismatch' => [[self::vector('v', self::B, false)]];
        yield 'stale flag' => [[self::vector('v', self::A, true)]];
        yield 'flag without draft value' => [[self::vector('v', null, true)]];
        yield 'wrong expected digest' => [[self::vector('v', null, false, '00')]];
        yield 'repeated id' => [[self::vector('v', null, false), self::vector('v', null, false)]];
        yield 'empty id' => [[self::vector('', null, false)]];
        yield 'upper-case hex' => [[self::vector('v', null, false, 'AB')]];
        yield 'odd hex' => [[self::vector('v', null, false, 'a')]];
        yield 'unknown kind' => [[self::vector('v', null, false, '', self::A, 'text')]];
        yield 'object input not an object' => [[self::vector('v', null, false, '', self::A, 'object')]];
        yield 'missing member' => [[['id' => 'v', 'input_kind' => 'bytes', 'input' => '', 'expected_digest' => self::A, 'spec_defect' => false]]];
        yield 'defect beside a failure' => [[self::vector('d', self::B, true), self::vector('v', self::B, false)]];
    }

    /** @param list<array<string, mixed>> $vectors */
    #[DataProvider('failures')]
    public function testFailures(array $vectors): void
    {
        try {
            $this->runVectors($vectors);
            self::fail('passed');
        } catch (Fail) {
            $this->addToAssertionCount(1);
        } catch (\Throwable $t) {
            // A non-Fail exception is a fail for the harness too.
            self::assertNotInstanceOf(Skipped::class, $t, $t->getMessage());
        }
    }
}
