<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\SchemaGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The harness group of vectors/schema passes every entry, and a wrong verdict fails. */
final class SchemaGroupTest extends TestCase
{
    private string $dir = '';

    protected function tearDown(): void
    {
        if ($this->dir !== '') {
            @unlink($this->dir . '/u.json');
            rmdir($this->dir);
        }
    }

    public function testEverySchemaVectorPasses(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $root = Repo::root() . '/spec/v1.0/fixtures';
        $entries = array_values(array_filter(Harness::loadManifest($root . '/manifest.json'), static fn(Entry $e): bool => Groups::prefix($e) === 'vectors/schema'));
        self::assertSame(array_keys(SchemaGroup::FORMATS), array_map(static fn(Entry $e): string => $e->id, $entries));
        foreach ($entries as $e) {
            self::assertSame(['vector', 'core', 'MATCH'], [$e->kind, $e->scope, $e->outcome], $e->id);
            (new SchemaGroup())->run($root, $e);
        }
    }

    /** @return iterable<string, array{list<array<string, mixed>>, bool}> */
    public static function cases(): iterable
    {
        $v = static fn(string $id, string $input, string $expect): array => ['id' => $id, 'input' => $input, 'expect' => $expect, 'reason' => 'r', 'ajv_formats_differs' => false];
        yield 'right verdicts' => [[$v('a', 'https://example.com/', 'accept'), $v('b', "https://example.com/\n", 'reject')], true];
        yield 'line feed accepted' => [[$v('b', "https://example.com/\n", 'accept')], false];
        yield 'uri rejected' => [[$v('a', 'https://example.com/', 'reject')], false];
        yield 'bad expect' => [[$v('a', 'https://example.com/', 'yes')], false];
        yield 'repeated id' => [[$v('a', 'x:', 'accept'), $v('a', 'x:', 'accept')], false];
        yield 'missing member' => [[['id' => 'a', 'input' => 'x:', 'expect' => 'accept']], false];
    }

    /** @param list<array<string, mixed>> $vectors */
    #[DataProvider('cases')]
    public function testVerdicts(array $vectors, bool $ok): void
    {
        $this->dir = sys_get_temp_dir() . '/pact-php-schema-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
        file_put_contents($this->dir . '/u.json', json_encode($vectors, \JSON_THROW_ON_ERROR));
        try {
            (new SchemaGroup())->run($this->dir, new Entry('vectors/schema/uri-format', 'vector', 'core', 'u.json', 'u.json', 'MATCH'));
            self::assertTrue($ok, 'passed');
        } catch (Fail $f) {
            self::assertFalse($ok, $f->getMessage());
        }
    }

    public function testAnUnknownEntryFails(): void
    {
        $this->expectException(Fail::class);
        (new SchemaGroup())->run('/nonexistent', new Entry('vectors/schema/other', 'vector', 'core', 'u.json', 'u.json', 'MATCH'));
    }
}
