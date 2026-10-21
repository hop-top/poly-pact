<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Core\Jws\Reason;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Fixtures;
use HopTop\Pact\Vectors\Group\JwsGroup;
use PHPUnit\Framework\TestCase;

/**
 * The vectors under spec/v1.0/fixtures/vectors/jws. Port of
 * go/core/jws/vectors_test.go and the Python port's test_jws_vectors.py.
 *
 * The verify vectors themselves run through the harness group (JwsGroup,
 * tested in tests/Vectors); here the manifest and the files are checked
 * against the draft's requirements, and signature_valid is recomputed with
 * ext-openssl alone, so a vector rejected for another reason does not also
 * carry a bad signature by accident.
 */
final class VectorsTest extends TestCase
{
    private const PREFIX = 'vectors/jws/';

    /** The vectors the draft requires, with their expected result. */
    private const REQUIRED_VECTORS = [
        'appendix-c' => 'accept',
        'appendix-c-version-mismatch' => 'payload-schema',
        'rfc7515-a3' => 'typ-unsupported',
        'header-alg-none' => 'alg-unsupported',
        'header-alg-hs256' => 'alg-unsupported',
        'header-alg-rs256' => 'alg-unsupported',
        'header-alg-ps256' => 'alg-unsupported',
        'header-alg-eddsa' => 'alg-unsupported',
        'header-jwk-private' => 'jwk-private',
        'header-jku' => 'header-jku',
        'header-x5u' => 'header-x5u',
        'header-x5c' => 'header-x5c',
        'header-crit' => 'header-crit',
        'header-b64-false' => 'header-b64',
        'payload-detached' => 'payload-detached',
        'header-jwk-p384' => 'jwk-curve',
        'header-jwk-off-curve' => 'jwk-off-curve',
        'holder-jkt-mismatch' => 'holder-jkt-mismatch',
        'es256-valid' => 'accept',
        'es256-noncanonical-payload' => 'accept',
        'es256-noncanonical-header' => 'accept',
        'es256-leading-zero-r' => 'accept',
        'es256-signature-63-bytes' => 'signature-length',
        'es256-signature-der' => 'signature-length',
        'es256-signature-padded' => 'base64url',
        'es256-high-s' => 'accept',
        'typ-requirements' => 'accept',
        'typ-evidence' => 'accept',
        'typ-presentation' => 'accept',
        'typ-admission' => 'accept',
        'typ-outcome' => 'accept',
        'typ-reputation' => 'accept',
        'typ-learning-policy' => 'accept',
        'typ-learning-artifact' => 'accept',
        'typ-learning-event' => 'accept',
        'typ-admission-signed-by-issuer' => 'kid-unknown',
    ];

    private static function root(): string
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');

        return Repo::root() . '/spec/v1.0/fixtures';
    }

    /** @return array<string, JsonObject> the manifest entries of vectors/jws by id */
    private static function entries(): array
    {
        $m = Fixtures::readJson(self::root(), 'manifest.json');
        self::assertInstanceOf(JsonObject::class, $m);
        $out = [];
        foreach (Fixtures::arr($m->get('entries'), 'entries') as $e) {
            self::assertInstanceOf(JsonObject::class, $e);
            $id = $e->get('id');
            if (\is_string($id) && str_starts_with($id, self::PREFIX)) {
                $out[$id] = $e;
            }
        }
        self::assertNotEmpty($out, 'manifest lists no vectors/jws entries');

        return $out;
    }

    public function testManifestListsEveryJwsFile(): void
    {
        $listed = [];
        foreach (self::entries() as $id => $e) {
            self::assertSame(['vector', 'core'], [$e->get('kind'), $e->get('scope')], $id);
            self::assertNotEmpty($e->get('spec_map_row'), $id);
            self::assertNotEmpty($e->get('draft_section'), $id);
            self::assertSame($id . '.json', $e->get('path'), $id);
            self::assertSame($id . '.json', $e->get('expected'), $id);
            $listed[$id . '.json'] = true;
        }
        $files = glob(self::root() . '/' . self::PREFIX . '*') ?: [];
        self::assertNotEmpty($files);
        foreach ($files as $f) {
            if (basename($f) !== 'README.md') {
                self::assertArrayHasKey(self::PREFIX . basename($f), $listed, $f);
            }
        }
    }

    public function testRequiredVectors(): void
    {
        $entries = self::entries();
        foreach (self::REQUIRED_VECTORS as $stem => $want) {
            self::assertArrayHasKey(self::PREFIX . $stem, $entries, 'required vector ' . $stem . ' is missing');
            $v = Fixtures::readJson(self::root(), self::PREFIX . $stem . '.json');
            self::assertInstanceOf(JsonObject::class, $v);
            self::assertSame($want, $v->get('reject_reason') ?? $v->get('expect'), $stem);
        }
        // Every typ of the draft 7.3 table has a required accept vector.
        foreach (Jws::typs() as $typ) {
            $stem = 'typ-' . substr($typ, 5, -4);
            self::assertSame('accept', self::REQUIRED_VECTORS[$stem] ?? null, $typ);
        }
    }

    /** Every reject_reason is a Reason value or the harness reason payload-schema. */
    public function testRejectReasonsKnown(): void
    {
        $known = array_map(static fn(Reason $r): string => $r->value, Reason::cases());
        $known[] = JwsGroup::PAYLOAD_SCHEMA;
        $seen = [];
        foreach (glob(self::root() . '/' . self::PREFIX . '*.json') ?: [] as $f) {
            $doc = Fixtures::readJson(self::root(), self::PREFIX . basename($f));
            foreach (\is_array($doc) ? $doc : [$doc] as $v) {
                self::assertInstanceOf(JsonObject::class, $v);
                $r = $v->get('reject_reason');
                if (\is_string($r)) {
                    $seen[$r] = true;
                }
            }
        }
        self::assertNotEmpty($seen);
        self::assertSame([], array_values(array_diff(array_keys($seen), $known)));
        self::assertArrayHasKey(JwsGroup::PAYLOAD_SCHEMA, $seen);
    }

    /** signature_valid, recomputed with a lenient base64 reading of the signature octets. */
    public function testSignatureValid(): void
    {
        $n = 0;
        foreach (self::entries() as $id => $e) {
            if (\in_array($id, [JwsGroup::THUMBPRINT_ID, JwsGroup::JWK_REJECT_ID, JwsGroup::KEYS_ID], true)) {
                continue;
            }
            ++$n;
            $v = Fixtures::obj(Fixtures::readJson(self::root(), $id . '.json'), $id, JwsGroup::VERIFY_MEMBERS);
            $compact = $v->get('compact');
            self::assertIsString($compact);
            $parts = explode('.', $compact);
            $signer = $v->get('signer_jwk');
            $got = null;
            if (\count($parts) === 3 && $signer instanceof JsonObject && $signer->get('kty') === 'EC' && $signer->get('crv') === 'P-256') {
                $pub = Jws::parseJwk(Fixtures::dumpJson($signer))->publicKey();
                $got = self::lenientVerify($pub, $parts[0] . '.' . $parts[1], $parts[2]);
            }
            self::assertSame($v->get('signature_valid'), $got, $id);
        }
        self::assertGreaterThanOrEqual(40, $n);
    }

    private static function lenientVerify(\OpenSSLAsymmetricKey $pub, string $signingInput, string $seg): bool
    {
        $sig = base64_decode(strtr(str_replace(["\r", "\n", '='], '', $seg), '-_', '+/'), false);
        if (!\is_string($sig) || \strlen($sig) !== 64) {
            return false;
        }
        $int = static function (string $b): string {
            $b = ltrim($b, "\0");
            if ($b === '' || \ord($b[0]) >= 0x80) {
                $b = "\0" . $b;
            }

            return "\x02" . \chr(\strlen($b)) . $b;
        };
        $body = $int(substr($sig, 0, 32)) . $int(substr($sig, 32));
        $ok = openssl_verify($signingInput, "\x30" . \chr(\strlen($body)) . $body, $pub, \OPENSSL_ALGO_SHA256);
        while (openssl_error_string() !== false) {
            // drain
        }

        return $ok === 1;
    }

    public function testThumbprintVectors(): void
    {
        $vs = Fixtures::readJson(self::root(), JwsGroup::THUMBPRINT_ID . '.json');
        self::assertIsArray($vs);
        $seen = [];
        foreach ($vs as $v) {
            self::assertInstanceOf(JsonObject::class, $v);
            $id = (string) Fixtures::str($v->get('id'), 'id');
            $seen[] = $id;
            self::assertSame($v->get('expected_thumbprint'), Jws::thumbprint(Jws::parseJwk(Fixtures::dumpJson($v->get('jwk'))))->value, $id);
            if (str_starts_with($id, 'appendix-c-holder')) {
                self::assertSame(Keys::HOLDER_JKT, $v->get('expected_thumbprint'));
            }
        }
        foreach (['appendix-c-holder', 'holder-with-optional-members', 'holder-reordered-extra-member', 'leading-zero-x'] as $want) {
            self::assertContains($want, $seen);
        }
    }

    public function testJwkRejectVectors(): void
    {
        $vs = Fixtures::readJson(self::root(), JwsGroup::JWK_REJECT_ID . '.json');
        self::assertIsArray($vs);
        self::assertGreaterThanOrEqual(10, \count($vs));
        foreach ($vs as $v) {
            self::assertInstanceOf(JsonObject::class, $v);
            $got = null;
            try {
                Jws::thumbprint(Jws::parseJwk(Fixtures::dumpJson($v->get('jwk'))));
            } catch (JwsError $err) {
                $got = Jws::reasonOf($err)?->value;
            }
            self::assertSame($v->get('reject_reason'), $got, (string) json_encode($v->get('id')));
        }
    }

    public function testAppendixCKeyVectors(): void
    {
        $vs = Fixtures::readJson(self::root(), JwsGroup::KEYS_ID . '.json');
        self::assertIsArray($vs);
        self::assertCount(2, $vs, 'want holder and issuer');
        foreach ($vs as $v) {
            self::assertInstanceOf(JsonObject::class, $v);
            $d = Keys::b64d((string) Fixtures::str($v->get('d'), 'd'));
            self::assertSame(32, \strlen($d));
            $k = Jws::publicJwk(Jws::privateKey($d));
            self::assertSame([$v->get('expected_x'), $v->get('expected_y')], [$k->x, $k->y]);
            self::assertSame($v->get('expected_thumbprint'), Jws::thumbprint($k)->value);
        }
        self::assertInstanceOf(JsonObject::class, $vs[0]);
        self::assertSame(Keys::HOLDER_JKT, $vs[0]->get('expected_thumbprint'));
    }
}
