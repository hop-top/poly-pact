<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

use HopTop\Pact\Core\Jws\Header;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Core\Jws\Reason;
use HopTop\Pact\Tests\Core\Jws\Keys;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Group\JwsGroup;
use HopTop\Pact\Vectors\Groups;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\TestCase;

/**
 * The harness group of vectors/jws (port of the jws cases of the Python
 * port's test_vectors_groups.py): every entry passes, and a vector whose
 * expectation the package does not meet fails.
 */
final class JwsGroupTest extends TestCase
{
    private ?TempTree $tree = null;

    protected function tearDown(): void
    {
        $this->tree?->clean();
    }

    private function tree(): TempTree
    {
        return $this->tree ??= new TempTree('jws');
    }

    public function testEveryJwsEntryPasses(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $n = 0;
        foreach (Harness::loadManifest(Repo::root() . '/spec/v1.0/fixtures/manifest.json') as $e) {
            if (Groups::prefix($e) === 'vectors/jws') {
                (new JwsGroup())->run(Repo::root() . '/spec/v1.0/fixtures', $e);
                ++$n;
            }
        }
        self::assertGreaterThanOrEqual(43, $n);
    }

    /** @return array<string, mixed> a verify vector of an evidence JWS signed by the issuer test key */
    private static function vector(string $id, ?string $reason, string $payload = Keys::SMALL_PAYLOAD): array
    {
        $issuer = Keys::fixtureJwk('issuer');

        return [
            'id' => $id,
            'description' => 'd',
            'compact' => Jws::sign(new Header(typ: Jws::TYP_EVIDENCE, kid: 'test-issuer-key-1'), $payload, Keys::scalarKey(2)),
            'expected_typ' => null,
            'trusted_keysets' => ['issuer' => [['kty' => 'EC', 'crv' => 'P-256', 'x' => $issuer->x, 'y' => $issuer->y, 'kid' => $issuer->kid]]],
            'expected_holder_jkt' => null,
            'decode_as' => null,
            'expect' => $reason === null ? 'accept' : 'reject',
            'reject_reason' => $reason,
            'signer_jwk' => null,
            'signature_valid' => null,
            'expected_payload' => $reason === null ? $payload : null,
        ];
    }

    /** @param array<string, mixed> $v */
    private function runVector(array $v, ?string $outcome = null, string $id = 'vectors/jws/x'): void
    {
        $rel = $this->tree()->file('vectors/jws/x.json', $v);
        $outcome ??= $v['expect'] === 'accept' ? 'ACCEPTED' : 'REJECTED';
        (new JwsGroup())->run($this->tree()->dir, new Entry($id, 'vector', 'core', $rel, $rel, $outcome));
    }

    /** @param array<string, mixed> $v */
    private function fails(array $v, string $contains, ?string $outcome = null): void
    {
        try {
            $this->runVector($v, $outcome);
        } catch (Fail $f) {
            self::assertStringContainsString($contains, $f->getMessage());

            return;
        }
        self::fail('passed, want a fail: ' . $contains);
    }

    public function testVerifyVectors(): void
    {
        $id = 'vectors/jws/x';
        $this->runVector(self::vector($id, null));
        $this->fails(['expected_payload' => '{"pact_version":"0.1","jti":"other"}'] + self::vector($id, null), 'differs from expected_payload');
        $this->fails(['expected_payload' => null] + self::vector($id, null), 'differs from expected_payload');
        $this->runVector(['expected_typ' => Jws::TYP_ADMISSION] + self::vector($id, 'typ-mismatch'));
        $this->fails(['expected_typ' => Jws::TYP_ADMISSION] + self::vector($id, null), 'rejected (typ-mismatch), want accept');
        $this->fails(self::vector($id, 'kid-unknown'), 'reason null, want "kid-unknown"');
        $this->runVector(['trusted_keysets' => ['validator' => []]] + self::vector($id, 'kid-unknown'));
        $this->fails(self::vector($id, null), 'do not agree', 'REJECTED');
        $this->fails(self::vector($id, 'kid-unknown'), 'do not agree', 'ACCEPTED');
        $this->fails(['id' => 'vectors/jws/y'] + self::vector($id, null), 'manifest id');
        $this->fails(['trusted_keysets' => ['issuer' => [['kty' => 'EC']]]] + self::vector($id, null), 'trusted key for issuer');
    }

    /** decode_as: a strict decode as the type, its schema and its pact_version; payload-schema when refused. */
    public function testDecodeAs(): void
    {
        $id = 'vectors/jws/x';
        $ev = Repo::read('spec/v1.0/fixtures/vectors/jws/appendix-c.json');
        $payload = json_decode($ev, true, 16, \JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        $good = $payload['expected_payload'];
        self::assertIsString($good);
        $this->runVector(['decode_as' => 'Evidence'] + self::vector($id, null, $good));
        $this->runVector(['decode_as' => 'Evidence'] + self::vector($id, 'payload-schema', str_replace('"pact_version": "0.1"', '"pact_version": "0.2"', $good)));
        $this->runVector(['decode_as' => 'Evidence'] + self::vector($id, 'payload-schema'));
        $this->fails(['decode_as' => 'Evidence'] + self::vector($id, null), 'rejected (payload-schema), want accept');
        $this->fails(['decode_as' => 'Outcome'] + self::vector($id, null), 'decode_as "Outcome" is not handled');
        self::assertNull(JwsGroup::decodeArtifact('Evidence', $good));
        self::assertSame('payload-schema', JwsGroup::decodeArtifact('Evidence', str_replace('"pact_version": "0.1"', '"pact_version": "0.2"', $good)));
        self::assertSame('payload-schema', JwsGroup::decodeArtifact('Evidence', '{"pact_version":"0.1"}'));
    }

    public function testReasonRequiresAJwsError(): void
    {
        self::assertSame('kid-unknown', JwsGroup::reason(new JwsError(Reason::KID_UNKNOWN)));
        $this->expectException(Fail::class);
        JwsGroup::reason(new \RuntimeException('kid-unknown'));
    }

    /** @param list<array<string, mixed>> $rows */
    private function runArray(string $id, array $rows, string $outcome): void
    {
        $rel = $this->tree()->file($id . '.json', $rows);
        (new JwsGroup())->run($this->tree()->dir, new Entry($id, 'vector', 'core', $rel, $rel, $outcome));
    }

    public function testArrayFiles(): void
    {
        $hj = Keys::fixtureJwk('holder');
        $holder = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $hj->x, 'y' => $hj->y];
        $d1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE';
        $tp = [['id' => 'h', 'description' => 'd', 'jwk' => $holder, 'expected_thumbprint' => Keys::HOLDER_JKT, 'source' => 's']];
        $rej = [['id' => 'p', 'description' => 'd', 'jwk' => $holder + ['d' => $d1], 'reject_reason' => 'jwk-private']];
        $keys = [['id' => 'h', 'description' => 'd', 'd' => $d1, 'expected_x' => $hj->x, 'expected_y' => $hj->y, 'expected_thumbprint' => Keys::HOLDER_JKT]];
        $this->runArray(JwsGroup::THUMBPRINT_ID, $tp, 'ACCEPTED');
        $this->runArray(JwsGroup::JWK_REJECT_ID, $rej, 'REJECTED');
        $this->runArray(JwsGroup::KEYS_ID, $keys, 'MATCH');
        $cases = [
            [JwsGroup::THUMBPRINT_ID, [['expected_thumbprint' => strrev(Keys::HOLDER_JKT)] + $tp[0]], 'ACCEPTED'],
            [JwsGroup::THUMBPRINT_ID, $tp, 'REJECTED'],
            [JwsGroup::JWK_REJECT_ID, [['reject_reason' => 'jwk-invalid'] + $rej[0]], 'REJECTED'],
            [JwsGroup::JWK_REJECT_ID, [['jwk' => $holder] + $rej[0]], 'REJECTED'],
            [JwsGroup::JWK_REJECT_ID, $rej, 'ACCEPTED'],
            [JwsGroup::KEYS_ID, [['expected_x' => Keys::fixtureJwk('issuer')->x] + $keys[0]], 'MATCH'],
            [JwsGroup::KEYS_ID, [['expected_thumbprint' => strrev(Keys::HOLDER_JKT)] + $keys[0]], 'MATCH'],
            [JwsGroup::KEYS_ID, [['d' => 'AQ'] + $keys[0]], 'MATCH'],
            [JwsGroup::KEYS_ID, [['d' => Keys::b64(str_repeat("\0", 32))] + $keys[0]], 'MATCH'],
        ];
        foreach ($cases as $i => [$id, $rows, $outcome]) {
            try {
                $this->runArray($id, $rows, $outcome);
                self::fail(\sprintf('case %d passed', $i));
            } catch (Fail) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
