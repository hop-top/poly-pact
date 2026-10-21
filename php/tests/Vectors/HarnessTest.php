<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Vectors\Harness;
use HopTop\Pact\Vectors\Manifest;
use PHPUnit\Framework\TestCase;

final class HarnessTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/pact-php-harness-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/spec/v1.0/fixtures', 0o777, true);
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            \assert($f instanceof \SplFileInfo);
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
    }

    /**
     * @param list<array<string, mixed>> $entries
     *
     * @return array{int, string, string}
     */
    private function harness(array $entries): array
    {
        $path = $this->dir . '/spec/v1.0/fixtures/manifest.json';
        file_put_contents($path, json_encode(['manifest_version' => 1, 'entries' => $entries], \JSON_THROW_ON_ERROR));
        $out = fopen('php://memory', 'w+');
        $err = fopen('php://memory', 'w+');
        self::assertIsResource($out);
        self::assertIsResource($err);
        $code = Harness::main([$path], $out, $err);
        rewind($out);
        rewind($err);

        return [$code, (string) stream_get_contents($out), (string) stream_get_contents($err)];
    }

    /** @return array<string, mixed> */
    private static function entry(string $id, string $kind, string $scope): array
    {
        return ['id' => $id, 'kind' => $kind, 'scope' => $scope, 'path' => $id . '.json', 'expected' => $id . '.json', 'outcome' => 'ACCEPTED', 'spec_map_row' => 'X-01', 'draft_section' => '1'];
    }

    public function testRunnerScopeIsOutOfScope(): void
    {
        [$code, $out] = $this->harness([self::entry('admission/valid', 'evaluate', 'runner')]);
        self::assertSame(0, $code);
        self::assertSame('{"id":"admission/valid","kind":"evaluate","result":"skipped:out-of-scope"}' . "\n", $out);
    }

    public function testAdapterScopeIsOutOfScope(): void
    {
        [$code, $out] = $this->harness([self::entry('vectors/binding/bind-01', 'vector', 'adapter')]);
        self::assertSame(0, $code);
        self::assertStringContainsString('"result":"skipped:out-of-scope"', $out);
    }

    public function testUnknownKindIsAHarnessError(): void
    {
        [$code, $out, $err] = $this->harness([self::entry('vectors/jcs/x', 'nope', 'core')]);
        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertStringContainsString('entry vectors/jcs/x: unknown kind nope', $err);
    }

    public function testUnknownCapabilityIsAHarnessError(): void
    {
        [$code, $out, $err] = $this->harness([self::entry('vectors/jws/x', 'vector', 'core') + ['capabilities' => ['ed448']]]);
        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertStringContainsString('entry vectors/jws/x: unknown capability', $err);
    }

    public function testNonStrictManifestIsAHarnessError(): void
    {
        $path = $this->dir . '/spec/v1.0/fixtures/manifest.json';
        file_put_contents($path, '{"manifest_version":1,"entries":[],"entries":[]}');
        $err = fopen('php://memory', 'w+');
        self::assertIsResource($err);
        self::assertSame(2, Harness::main([$path], null, $err));
        rewind($err);
        self::assertStringContainsString('duplicate', (string) stream_get_contents($err));
    }

    /** A rule the harness does not rely on is the manifest check's to report: the run goes on. */
    public function testOtherFieldRulesDoNotStopTheRun(): void
    {
        [$code, $out] = $this->harness([['draft_section' => 'Section 1'] + self::entry('admission/valid', 'evaluate', 'runner')]);
        self::assertSame(0, $code);
        self::assertSame('{"id":"admission/valid","kind":"evaluate","result":"skipped:out-of-scope"}' . "\n", $out);
    }

    public function testUnknownScopeIsAHarnessError(): void
    {
        [$code, $out] = $this->harness([self::entry('vectors/jcs/x', 'vector', 'galaxy')]);
        self::assertSame(2, $code);
        self::assertSame('', $out);
    }

    public function testUnknownCorePrefixIsAHarnessError(): void
    {
        [$code, $out, $err] = $this->harness([self::entry('vectors/nope/x', 'vector', 'core')]);
        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertStringContainsString('unknown prefix', $err);
    }

    public function testDuplicateIdIsAHarnessError(): void
    {
        $e = self::entry('admission/valid', 'evaluate', 'runner');
        [$code, $out] = $this->harness([$e, $e]);
        self::assertSame(2, $code);
        self::assertSame('', $out);
    }

    public function testUndeclaredCapabilityIsSkipped(): void
    {
        $e = self::entry('vectors/jws/x', 'vector', 'core') + ['capabilities' => ['jws-ed25519']];
        [$code, $out] = $this->harness([$e]);
        self::assertSame(0, $code);
        self::assertSame('{"id":"vectors/jws/x","kind":"vector","result":"skipped:capability","missing_capabilities":["jws-ed25519"]}' . "\n", $out);
    }

    public function testFailUnderRequiredGateExitsOne(): void
    {
        mkdir($this->dir . '/tools/parity', 0o777, true);
        file_put_contents($this->dir . '/tools/parity/gates.json', json_encode(['gates_version' => 1, 'rows' => [
            ['scope' => 'core', 'kind' => 'vector', 'prefix' => 'vectors/jcs', 'go' => 'required', 'ts' => 'required', 'py' => 'required', 'rs' => 'planned', 'php' => 'required', 'flipped_by' => 'x'],
        ]], \JSON_THROW_ON_ERROR));
        [$code, $out] = $this->harness([self::entry('vectors/jcs/missing', 'vector', 'core')]);
        self::assertSame(1, $code);
        self::assertStringContainsString('"result":"fail"', $out);
    }

    public function testFailUnderPlannedGateExitsZero(): void
    {
        mkdir($this->dir . '/tools/parity', 0o777, true);
        file_put_contents($this->dir . '/tools/parity/gates.json', json_encode(['gates_version' => 1, 'rows' => [
            ['scope' => 'core', 'kind' => 'vector', 'prefix' => 'vectors/jcs', 'go' => 'required', 'ts' => 'required', 'py' => 'required', 'rs' => 'planned', 'php' => 'planned', 'flipped_by' => 'x'],
        ]], \JSON_THROW_ON_ERROR));
        [$code, $out] = $this->harness([self::entry('vectors/jcs/missing', 'vector', 'core')]);
        self::assertSame(0, $code);
        self::assertStringContainsString('"result":"fail"', $out);
    }

    public function testUsageError(): void
    {
        $err = fopen('php://memory', 'w+');
        self::assertIsResource($err);
        self::assertSame(2, Harness::main(['a', 'b'], null, $err));
        self::assertSame(2, Harness::main(['--x'], null, $err));
    }

    /**
     * The kind, scope and capability tables equal those of the Go package
     * runner/manifest, read from its source in this repository.
     */
    public function testTablesMatchGo(): void
    {
        $src = \dirname(__DIR__, 3) . '/go/runner/manifest/rules.go';
        if (!is_file($src)) {
            if (getenv('PACT_REQUIRE_VECTORS') === '1') {
                self::fail($src . ' absent');
            }
            self::markTestSkipped('go/ is not part of this checkout');
        }
        $go = (string) file_get_contents($src);
        $consts = [];
        preg_match_all('/^\s+(\w+)\s+(?:Kind|Scope)?\s*=\s*"([^"]+)"/m', $go, $m, \PREG_SET_ORDER);
        foreach ($m as [, $name, $value]) {
            $consts[$name] = $value;
        }
        $list = static function (string $var) use ($go, $consts): array {
            self::assertSame(1, preg_match('/var ' . $var . ' = \[\]\w+\{([^}]*)\}/s', $go, $mm));
            $out = [];
            foreach (preg_split('/[\s,]+/', trim($mm[1]), -1, \PREG_SPLIT_NO_EMPTY) ?: [] as $n) {
                $out[] = $consts[$n] ?? $n;
            }

            return $out;
        };
        self::assertSame($list('kinds'), Manifest::KINDS);
        self::assertSame($list('scopes'), Manifest::SCOPES);
        self::assertSame($list('capabilities'), Manifest::CAPABILITIES);
    }
}
