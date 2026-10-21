<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\JcsGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\TestCase;

/**
 * The harness group of vectors/jcs passes every entry of the shared fixtures
 * (port of go/core/jcs/vectors_test.go and the Python port's
 * test_jcs_vectors.py).
 */
final class JcsGroupTest extends TestCase
{
    private const PREFIX = 'vectors/jcs/';

    /** The source and license notes of the vendored data: no entry lists them. */
    private const NOTICE_FILES = ['LICENSE-NOTE.md', 'LICENSE.md', 'LICENSE-2.0.md'];

    /** @return list<Entry> */
    private static function entries(): array
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');

        return array_values(array_filter(Harness::loadManifest(self::root() . '/manifest.json'), static fn(Entry $e): bool => Groups::prefix($e) === 'vectors/jcs'));
    }

    private static function root(): string
    {
        return Repo::root() . '/spec/v1.0/fixtures';
    }

    public function testEveryJcsVectorPasses(): void
    {
        $entries = self::entries();
        $ids = array_map(static fn(Entry $e): string => $e->id, $entries);
        foreach (['arrays', 'french', 'structures', 'unicode', 'values', 'weird', 'numbers'] as $n) {
            self::assertContains(self::PREFIX . $n, $ids);
        }
        foreach ($entries as $e) {
            self::assertSame(['vector', 'core', 'ACCEPTED'], [$e->kind, $e->scope, $e->outcome], $e->id);
            (new JcsGroup())->run(self::root(), $e);
        }
    }

    /** Files on disk that the manifest does not list never run: flag them. */
    public function testManifestListsEveryJcsFile(): void
    {
        $listed = [];
        foreach (self::entries() as $e) {
            $listed[] = $e->path;
            $listed[] = (string) $e->expected;
        }
        $dir = self::root() . '/' . self::PREFIX;
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            self::assertInstanceOf(\SplFileInfo::class, $f);
            $rel = self::PREFIX . substr($f->getPathname(), \strlen($dir));
            if (!\in_array($f->getFilename(), self::NOTICE_FILES, true)) {
                self::assertContains($rel, $listed, $rel . ' is not listed in manifest.json');
            }
        }
    }

    public function testAWrongExpectationFails(): void
    {
        foreach (self::entries() as $e) {
            if ($e->path === $e->expected) {
                continue;
            }
            // Another pair's expected output.
            $other = str_contains($e->id, 'arrays') ? 'vectors/jcs/output/french.json' : 'vectors/jcs/output/arrays.json';
            try {
                (new JcsGroup())->run(self::root(), new Entry($e->id, $e->kind, $e->scope, $e->path, $other, $e->outcome));
                self::fail($e->id . ': passed against ' . $other);
            } catch (Fail) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /** A number row whose expected text is not the ECMAScript one fails. */
    public function testAWrongNumberFails(): void
    {
        $dir = sys_get_temp_dir() . '/pact-php-jcs-' . bin2hex(random_bytes(6));
        mkdir($dir);
        try {
            foreach (['1e+21' => true, '1.0e+21' => false, '1000000000000000000000' => false] as $want => $ok) {
                file_put_contents($dir . '/n.json', json_encode([['ieee754_hex' => '444b1ae4d6e2ef50', 'expected' => $want]], \JSON_THROW_ON_ERROR));
                try {
                    (new JcsGroup())->run($dir, new Entry('vectors/jcs/numbers', 'vector', 'core', 'n.json', 'n.json', 'ACCEPTED'));
                    self::assertTrue($ok, $want . ' passed');
                } catch (Fail $f) {
                    self::assertFalse($ok, $want . ': ' . $f->getMessage());
                }
            }
        } finally {
            @unlink($dir . '/n.json');
            rmdir($dir);
        }
    }
}
