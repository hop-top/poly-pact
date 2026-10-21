<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Tests\Core\Jws\Keys;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\KeyGroup;
use HopTop\Pact\Vectors\Harness;
use HopTop\Pact\Vectors\Skipped;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The key rule of the harness (port of the key cases of the Python port's
 * test_vectors_groups.py): every P-256 key of spec/v1.0/fixtures/keys is
 * its scalar times G, the holder key has the Appendix C holder_jkt, and the
 * Ed25519 key is out of scope.
 */
final class KeyGroupTest extends TestCase
{
    private ?TempTree $tree = null;

    protected function tearDown(): void
    {
        $this->tree?->clean();
    }

    public function testEveryKeyEntryPasses(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $results = [];
        foreach (Harness::loadManifest(Repo::root() . '/spec/v1.0/fixtures/manifest.json') as $e) {
            if ($e->kind !== 'key') {
                continue;
            }
            try {
                (new KeyGroup())->run(Repo::root() . '/spec/v1.0/fixtures', $e);
                $results[$e->id] = 'pass';
            } catch (Skipped $s) {
                $results[$e->id] = 'skipped:' . $s->reason;
            }
        }
        self::assertSame('skipped:out-of-scope', $results['keys/ed25519'] ?? null);
        self::assertSame('pass', $results['keys/holder'] ?? null);
        self::assertSame('pass', $results['keys/test-private-scalars'] ?? null);
        self::assertCount(1, array_filter($results, static fn(string $r): bool => $r !== 'pass'));
        self::assertGreaterThanOrEqual(12, \count($results));
    }

    /**
     * A fixture tree with a holder record (scalar 1) and an issuer record
     * (scalar 2); $holder and $issuer override members of the records.
     *
     * @param array<string, string> $holder
     * @param array<string, string> $issuer
     * @param array<string, mixed>  $holderJwk
     */
    private function keys(array $holder = [], array $issuer = [], array $holderJwk = []): TempTree
    {
        $t = $this->tree = new TempTree('keys');
        $hj = Keys::fixtureJwk('holder');
        $ij = Keys::fixtureJwk('issuer');
        $t->file('keys/holder.jwk.json', $holderJwk + ['kty' => 'EC', 'crv' => 'P-256', 'x' => $hj->x, 'y' => $hj->y, 'kid' => 'h']);
        $t->file('keys/issuer.jwk.json', ['kty' => 'EC', 'crv' => 'P-256', 'x' => $ij->x, 'y' => $ij->y, 'kid' => 'i']);
        $t->file('keys/ed25519.jwk.json', ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo']);
        $rec = static fn(string $role, int $n, string $file): array => ['role' => $role, 'kid' => $role, 'alg' => 'ES256', 'kty' => 'EC', 'crv' => 'P-256', 'scalar' => (string) $n, 'd' => Keys::b64(Keys::scalar($n)), 'public_jwk' => $file];
        $t->file(KeyGroup::SCALARS_PATH, ['label' => 'l', 'keys' => [
            $holder + $rec('holder', 1, 'holder.jwk.json'),
            $issuer + $rec('issuer', 2, 'issuer.jwk.json'),
            ['role' => 'ed', 'kid' => 'e', 'alg' => 'Ed25519', 'kty' => 'OKP', 'crv' => 'Ed25519', 'd' => 'x', 'public_jwk' => 'ed25519.jwk.json', 'seed_hex' => '00'],
        ]]);

        return $t;
    }

    private static function outcome(TempTree $t, string $id, string $path): string
    {
        try {
            (new KeyGroup())->run($t->dir, new Entry($id, 'key', 'core', $path, null, null));
        } catch (Fail $f) {
            return 'fail: ' . $f->getMessage();
        } catch (Skipped $s) {
            return 'skipped:' . $s->reason;
        }

        return 'pass';
    }

    public function testKeyRule(): void
    {
        $t = $this->keys();
        self::assertSame('pass', self::outcome($t, 'keys/holder', 'keys/holder.jwk.json'));
        self::assertSame('pass', self::outcome($t, 'keys/issuer', 'keys/issuer.jwk.json'));
        self::assertSame('pass', self::outcome($t, 'keys/test-private-scalars', KeyGroup::SCALARS_PATH));
        self::assertSame('skipped:out-of-scope', self::outcome($t, 'keys/ed25519', 'keys/ed25519.jwk.json'));
        $t->file('keys/stray.jwk.json', ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'a', 'y' => 'b']);
        self::assertStringStartsWith('fail: no record', self::outcome($t, 'keys/stray', 'keys/stray.jwk.json'));
    }

    /** A holder record whose key is not the Appendix C holder key fails, though it derives. */
    public function testHolderThumbprintChecked(): void
    {
        $t = $this->keys(['d' => Keys::b64(Keys::scalar(2)), 'scalar' => '2', 'public_jwk' => 'issuer.jwk.json']);
        self::assertStringContainsString('holder thumbprint', self::outcome($t, 'keys/issuer', 'keys/issuer.jwk.json'));
        self::assertStringContainsString('holder thumbprint', self::outcome($t, 'keys/test-private-scalars', KeyGroup::SCALARS_PATH));
    }

    /** @return iterable<string, array{array<string, string>, array<string, string>, array<string, mixed>}> */
    public static function mismatches(): iterable
    {
        yield 'x of another key' => [[], [], ['x' => 'fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg']];
        yield 'scalar not d' => [['scalar' => '2'], [], []];
        yield 'scalar negative' => [['scalar' => '-1'], [], []];
        yield 'scalar zero' => [['scalar' => '0'], [], []];
        yield 'd zero' => [['d' => Keys::b64(str_repeat("\0", 32)), 'scalar' => '0'], [], []];
        yield 'd short' => [['d' => 'AQ'], [], []];
        yield 'jwk with d' => [[], [], ['d' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE']];
        yield 'not P-256' => [['crv' => 'P-384'], [], []];
    }

    /**
     * @param array<string, string> $holder
     * @param array<string, string> $issuer
     * @param array<string, mixed>  $holderJwk
     */
    #[DataProvider('mismatches')]
    public function testKeyRuleMismatch(array $holder, array $issuer, array $holderJwk): void
    {
        $t = $this->keys($holder, $issuer, $holderJwk);
        self::assertStringStartsWith('fail', self::outcome($t, 'keys/test-private-scalars', KeyGroup::SCALARS_PATH));
        if (($holder['crv'] ?? '') !== 'P-384') {
            self::assertStringStartsWith('fail', self::outcome($t, 'keys/holder', 'keys/holder.jwk.json'));
        }
        self::assertSame('pass', self::outcome($t, 'keys/issuer', 'keys/issuer.jwk.json'));
    }

    public function testNoHolderRecord(): void
    {
        $t = $this->keys(['role' => 'validator']);
        self::assertStringContainsString('no P-256 record of role holder', self::outcome($t, 'keys/test-private-scalars', KeyGroup::SCALARS_PATH));
    }
}
