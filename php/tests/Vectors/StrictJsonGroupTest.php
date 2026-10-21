<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\StrictJsonGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\TestCase;

/** The harness group of vectors/strictjson passes every entry of the shared fixtures. */
final class StrictJsonGroupTest extends TestCase
{
    public function testEveryStrictJsonVectorPasses(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $root = Repo::root() . '/spec/v1.0/fixtures';
        $entries = array_values(array_filter(Harness::loadManifest($root . '/manifest.json'), static fn(Entry $e): bool => Groups::prefix($e) === 'vectors/strictjson'));
        self::assertCount(36, $entries);
        foreach ($entries as $e) {
            (new StrictJsonGroup())->run($root, $e);
        }
    }

    public function testAWrongOutcomeFails(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $root = Repo::root() . '/spec/v1.0/fixtures';
        foreach (Harness::loadManifest($root . '/manifest.json') as $e) {
            if (Groups::prefix($e) === 'vectors/strictjson') {
                $flipped = new Entry($e->id, $e->kind, $e->scope, $e->path, $e->expected, $e->outcome === 'ACCEPTED' ? 'REJECTED' : 'ACCEPTED');
                try {
                    (new StrictJsonGroup())->run($root, $flipped);
                    self::fail($e->id . ': passed with the outcome flipped');
                } catch (Fail) {
                    $this->addToAssertionCount(1);
                }
            }
        }
    }
}
