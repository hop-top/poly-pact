<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors\SchemaCase;

use HopTop\Pact\Core\Jws\Base64Url;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Manifest;

/** Scratch fixture directories of schema entries, the tree helpers of go/runner/schemaverb_test.go. */
final class SchemaTree
{
    public const string EVIDENCE_HEADER = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"k"}';

    /** @var list<string> */
    private static array $dirs = [];

    private function __construct() {}

    public static function b64(string $s): string
    {
        return Base64Url::encode($s);
    }

    /** A compact JWS of header and payload text; the signature segment is not judged by a schema case. */
    public static function compact(string $header, string $payload): string
    {
        return self::b64($header) . '.' . self::b64($payload) . '.c2ln';
    }

    /** @return array<string, mixed> */
    public static function entry(string $id, string $path, string $outcome, string $expected): array
    {
        return ['id' => $id, 'kind' => 'schema', 'scope' => 'core', 'path' => $path, 'expected' => $expected, 'outcome' => $outcome, 'spec_map_row' => 'CL-A', 'draft_section' => 'A.3'];
    }

    /**
     * A fixture directory with these entries and files.
     *
     * @param list<array<string, mixed>> $entries
     * @param array<string, string>      $files
     */
    public static function tree(array $entries, array $files): string
    {
        $root = sys_get_temp_dir() . '/pact-php-schema-' . bin2hex(random_bytes(6));
        mkdir($root, 0o777, true);
        self::$dirs[] = $root;
        $files['manifest.json'] = json_encode(['manifest_version' => 1, 'entries' => $entries], \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR);
        foreach ($files as $rel => $text) {
            $full = $root . '/' . $rel;
            if (!is_dir(\dirname($full))) {
                mkdir(\dirname($full), 0o777, true);
            }
            file_put_contents($full, $text);
        }

        return $root;
    }

    public static function load(string $root, string $id): Entry
    {
        $e = Manifest::lookup(Manifest::load($root . '/manifest.json'), $id);
        if ($e === null) {
            throw new \LogicException('no entry ' . $id);
        }

        return $e;
    }

    /**
     * A fixture directory with one REJECTED schema entry, parse/p, whose
     * input is the compact JWS text and whose expected code is $code.
     *
     * @return array{string, Entry}
     */
    public static function rejected(string $text, string $code = 'INVALID_MESSAGE'): array
    {
        $root = self::tree([self::entry('parse/p', 'parse/p.jws', 'REJECTED', 'expected/parse/p/decision.json')], [
            'parse/p.jws' => $text,
            'expected/parse/p/decision.json' => '{"transport_code":"' . $code . '","rejected_before_crypto":true,"reason":"test"}',
        ]);

        return [$root, self::load($root, 'parse/p')];
    }

    /**
     * A fixture directory with one schema entry of an object list, schema/s;
     * a REJECTED one expects INVALID_MESSAGE.
     *
     * @return array{string, Entry}
     */
    public static function list(string $list, string $outcome): array
    {
        $exp = 'schema/s.json';
        $files = ['schema/s.json' => $list];
        if ($outcome === 'REJECTED') {
            $exp = 'expected/schema/s/decision.json';
            $files[$exp] = '{"transport_code":"INVALID_MESSAGE"}';
        }
        $root = self::tree([self::entry('schema/s', 'schema/s.json', $outcome, $exp)], $files);

        return [$root, self::load($root, 'schema/s')];
    }

    /** spec/v1.0/fixtures of the source repository, or a skip in a mirror checkout. */
    public static function repoFixtures(): string
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');

        return Repo::root() . '/spec/v1.0/fixtures';
    }

    private static function removeAll(string $dir): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            \assert($f instanceof \SplFileInfo);
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
    }

    public static function cleanAll(): void
    {
        foreach (self::$dirs as $d) {
            self::removeAll($d);
        }
        self::$dirs = [];
    }
}
