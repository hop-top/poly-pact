<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Tests\Vectors\SchemaCase\SchemaTree;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\SchemaCaseGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\TestCase;

/** The harness groups parse and schema of kind schema pass every entry, and a contradicted expectation fails. */
final class SchemaCaseGroupTest extends TestCase
{
    protected function tearDown(): void
    {
        SchemaTree::cleanAll();
    }

    public function testEverySchemaCasePasses(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $root = Repo::root() . '/spec/v1.0/fixtures';
        $entries = array_values(array_filter(Harness::loadManifest($root . '/manifest.json'), static fn(Entry $e): bool => $e->kind === 'schema'));
        self::assertCount(25, $entries);
        foreach ($entries as $e) {
            self::assertTrue(Groups::runs($e), $e->id);
            self::assertInstanceOf(SchemaCaseGroup::class, Groups::runner($e), $e->id);
            Groups::runner($e)->run($root, $e);
        }
    }

    public function testContradictedExpectationFails(): void
    {
        [$root, $e] = SchemaTree::rejected(SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, '{"pact_version":"0.2"}'), 'INVALID_PROOF');
        $this->expectException(Fail::class);
        $this->expectExceptionMessage('want INVALID_PROOF');
        (new SchemaCaseGroup())->run($root, $e);
    }
}
