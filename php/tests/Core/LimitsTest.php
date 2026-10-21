<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\FieldRule;
use HopTop\Pact\Core\Intent;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\LimitError;
use HopTop\Pact\Core\LimitErrorKind;
use HopTop\Pact\Core\Limits;
use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\Presentation;
use HopTop\Pact\Core\RequirementContract;
use HopTop\Pact\Core\StrictJson\Limits as JsonLimits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use HopTop\Pact\PactError;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Baseline limits of draft section 20.1. Port of go/core/limits_test.go.
 *
 * testDefaultsMatchTheDraft reads spec/v1.0/draft.md: it fails when the
 * draft is absent under PACT_REQUIRE_VECTORS=1 and skips otherwise. The
 * strict JSON tests check the decode bounds each form hands to the decoder
 * and decode with them: a document of exactly the limit is accepted, one byte
 * or one level more is refused.
 */
final class LimitsTest extends TestCase
{
    /** Every Limits field with its section 20.1 key and baseline, written out from the draft table. */
    private const FIELDS = [
        ['max_presentation_bytes', 262144, 'presentationBytes'],
        ['max_artifact_payload_bytes', 32768, 'artifactPayloadBytes'],
        ['max_profile_bytes', 32768, 'profileBytes'],
        ['max_evidence_artifacts', 32, 'evidenceArtifacts'],
        ['max_field_rules', 128, 'fieldRules'],
        ['max_json_depth', 16, 'depth'],
        ['max_resources', 256, 'resources'],
        ['max_description_bytes', 4096, 'descriptionBytes'],
    ];

    private static function with(Limits $l, string $field, int $value): Limits
    {
        $args = array_map(static fn(mixed $v): int => \is_int($v) ? $v : 0, get_object_vars($l));
        $args[$field] = $value;

        return new Limits(...$args);
    }

    /**
     * A copy of the wire object $o with some members replaced.
     *
     * @template T of object
     *
     * @param T                    $o
     * @param array<string, mixed> $changes
     *
     * @return T
     */
    private static function copy(object $o, array $changes): object
    {
        return new ($o::class)(...[...get_object_vars($o), ...$changes]);
    }

    /**
     * An instance of the wire class $class with every member at its zero value.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private static function zero(string $class): object
    {
        return StrictJson::decode('{}', $class);
    }

    private static function baselineOf(string $key): string
    {
        foreach (self::FIELDS as [$k, , $field]) {
            if ($k === $key) {
                return $field;
            }
        }
        self::fail('no limit field for key ' . $key);
    }

    private static function baseline(string $key): int
    {
        foreach (self::FIELDS as [$k, $b]) {
            if ($k === $key) {
                return $b;
            }
        }
        self::fail('no limit field for key ' . $key);
    }

    public function testDefaults(): void
    {
        $d = Limits::defaults();
        foreach (self::FIELDS as [$key, $baseline, $field]) {
            self::assertSame($baseline, get_object_vars($d)[$field], $key);
        }
        $d->check();
    }

    public function testDefaultsMatchTheDraft(): void
    {
        $draft = Repo::read('spec/v1.0/draft.md');
        $d = get_object_vars(Limits::defaults());
        foreach (self::FIELDS as [$key, , $field]) {
            self::assertSame(1, preg_match('/^\| `' . $key . '` \| (\d+) \|/m', $draft, $m), 'draft 20.1 has no row for ' . $key);
            $want = $m[1] ?? '';
            self::assertSame((int) $want, $d[$field], \sprintf('Limits::defaults()->%s, draft 20.1 says %s', $field, $want));
        }
    }

    public function testKeys(): void
    {
        self::assertSame(array_column(self::FIELDS, 0), [
            Core::KEY_MAX_PRESENTATION_BYTES,
            Core::KEY_MAX_ARTIFACT_PAYLOAD_BYTES,
            Core::KEY_MAX_PROFILE_BYTES,
            Core::KEY_MAX_EVIDENCE_ARTIFACTS,
            Core::KEY_MAX_FIELD_RULES,
            Core::KEY_MAX_JSON_DEPTH,
            Core::KEY_MAX_RESOURCES,
            Core::KEY_MAX_DESCRIPTION_BYTES,
        ]);
        self::assertSame(array_column(self::FIELDS, 2), array_keys(get_object_vars(Limits::defaults())));
    }

    /** @return iterable<string, array{string, int, string}> */
    public static function fields(): iterable
    {
        foreach (self::FIELDS as $f) {
            yield $f[0] => $f;
        }
    }

    #[DataProvider('fields')]
    public function testCheck(string $key, int $baseline, string $field): void
    {
        foreach ([1, $baseline - 1, $baseline] as $v) {
            self::with(Limits::defaults(), $field, $v)->check();
        }
        foreach ([$baseline + 1, 2 * $baseline, 0, -1] as $v) {
            try {
                self::with(Limits::defaults(), $field, $v)->check();
                self::fail(\sprintf('%s = %d passed check()', $field, $v));
            } catch (LimitError $e) {
                self::assertSame([LimitErrorKind::LIMITS_INVALID, $key, $baseline, $v], [$e->kind, $e->key, $e->max, $e->got]);
                self::assertSame(\sprintf('core: invalid limits: %s is %d, must be 1..%d', $key, $v, $baseline), $e->getMessage());
            }
        }
    }

    public function testCheckZeroLimits(): void
    {
        $this->expectException(LimitError::class);
        (new Limits())->check();
    }

    /** @return array<string, array{string, \Closure(Limits, int): void}> how to build and validate exactly n units of one limit */
    public static function boundaries(): array
    {
        $p0 = self::zero(Presentation::class);
        $c0 = self::zero(RequirementContract::class);
        $f0 = self::zero(FieldRule::class);
        $o0 = self::zero(OperationContext::class);
        $i0 = self::zero(Intent::class);

        return [
            'max_presentation_bytes' => ['max_presentation_bytes', static fn(Limits $l, int $n) => $l->validatePresentation($p0, $n)],
            'max_artifact_payload_bytes' => ['max_artifact_payload_bytes', static fn(Limits $l, int $n) => $l->validateArtifactSize($n)],
            'max_profile_bytes' => ['max_profile_bytes', static fn(Limits $l, int $n) => $l->validateProfileSize($n)],
            'max_evidence_artifacts' => ['max_evidence_artifacts', static fn(Limits $l, int $n) => $l->validatePresentation(self::copy($p0, ['evidence' => array_fill(0, $n, '')]), 0)],
            'max_field_rules' => ['max_field_rules', static fn(Limits $l, int $n) => $l->validateContract(self::copy($c0, ['field_rules' => array_fill(0, $n, $f0)]))],
            'max_resources' => ['max_resources', static fn(Limits $l, int $n) => $l->validateOperation(self::copy($o0, ['resources' => array_fill(0, $n, '')]))],
            'max_resources in a presentation' => ['max_resources', static fn(Limits $l, int $n) => $l->validatePresentation(self::copy($p0, ['operation' => self::copy($o0, ['resources' => array_fill(0, $n, '')])]), 0)],
            'max_description_bytes' => ['max_description_bytes', static fn(Limits $l, int $n) => $l->validateIntent(self::copy($i0, ['description' => str_repeat('a', $n)]))],
            'max_description_bytes in a presentation' => ['max_description_bytes', static fn(Limits $l, int $n) => $l->validatePresentation(self::copy($p0, ['intent' => self::copy($i0, ['description' => str_repeat('a', $n)])]), 0)],
        ];
    }

    /** @param \Closure(Limits, int): void $run */
    #[DataProvider('boundaries')]
    public function testBoundaries(string $key, \Closure $run): void
    {
        $baseline = self::baseline($key);
        $d = Limits::defaults();
        // Equal passes, plus one fails.
        $run($d, $baseline);
        $run($d, 0);
        try {
            $run($d, $baseline + 1);
            self::fail('baseline + 1 passed');
        } catch (LimitError $e) {
            self::assertSame([LimitErrorKind::LIMIT_EXCEEDED, $key, $baseline, $baseline + 1], [$e->kind, $e->key, $e->max, $e->got]);
            self::assertStringContainsString($key, $e->getMessage());
        }
        // A tighter configured limit moves the boundary down.
        $tight = self::with($d, self::baselineOf($key), $baseline - 1);
        $run($tight, $baseline - 1);
        try {
            $run($tight, $baseline);
            self::fail('the baseline passed a tighter limit');
        } catch (LimitError $e) {
            self::assertSame(LimitErrorKind::LIMIT_EXCEEDED, $e->kind);
        }
    }

    public function testEachLimitIsIndependent(): void
    {
        // Lowering one limit must not affect the others.
        foreach (self::FIELDS as [$key, , $field]) {
            $lim = self::with(Limits::defaults(), $field, 1);
            foreach (self::boundaries() as [$bkey, $run]) {
                if ($bkey !== $key) {
                    $run($lim, self::baseline($bkey));
                }
            }
        }
        $this->addToAssertionCount(1);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function descriptions(): iterable
    {
        yield '2048 two-byte characters are 4096 bytes' => [str_repeat('é', 2048), true];
        yield '2049 two-byte characters are 4098 bytes' => [str_repeat('é', 2049), false];
        yield '1024 four-byte characters are 4096 bytes' => [str_repeat("\u{1F600}", 1024), true];
        yield '1025 four-byte characters are 4100 bytes' => [str_repeat("\u{1F600}", 1025), false];
        yield '4095 ASCII plus one two-byte character is 4097 bytes' => [str_repeat('a', 4095) . 'é', false];
    }

    #[DataProvider('descriptions')]
    public function testDescriptionLimitCountsBytesNotCharacters(string $desc, bool $ok): void
    {
        $intent = self::copy(self::zero(Intent::class), ['description' => $desc]);
        try {
            Limits::defaults()->validateIntent($intent);
            self::assertTrue($ok, 'accepted');
        } catch (LimitError $e) {
            self::assertFalse($ok, 'refused');
            self::assertSame(LimitErrorKind::LIMIT_EXCEEDED, $e->kind);
        }
    }

    public function testValidateRejectsNil(): void
    {
        $d = Limits::defaults();
        $calls = [
            'presentation' => static fn() => $d->validatePresentation(null, 0),
            'requirement contract' => static fn() => $d->validateContract(null),
            'operation' => static fn() => $d->validateOperation(null),
            'intent' => static fn() => $d->validateIntent(null),
        ];
        foreach ($calls as $name => $call) {
            try {
                $call();
                self::fail($name . ': null accepted');
            } catch (LimitError $e) {
                self::assertSame(LimitErrorKind::NIL_OBJECT, $e->kind, $name);
                self::assertSame('core: nil object: ' . $name, $e->getMessage());
                self::assertInstanceOf(PactError::class, $e);
            }
        }
    }

    public function testValidateOnTheZeroLimitsFailsClosed(): void
    {
        $zero = new Limits();
        foreach ([
            static fn() => $zero->validateContract(self::copy(self::zero(RequirementContract::class), ['field_rules' => [self::zero(FieldRule::class)]])),
            static fn() => $zero->validateArtifactSize(1),
        ] as $call) {
            try {
                $call();
                self::fail('zero limits accepted');
            } catch (LimitError $e) {
                self::assertSame(LimitErrorKind::LIMIT_EXCEEDED, $e->kind);
            }
        }
    }

    private static function decodeObject(string $data, JsonLimits $lim): JsonObject
    {
        return StrictJson::decode($data, JsonObject::class, $lim);
    }

    /** A JSON object of exactly $n bytes. */
    private static function docOfSize(int $n): string
    {
        return '{"a":"' . str_repeat('x', $n - \strlen('{"a":""}')) . '"}';
    }

    /** A JSON document whose nesting depth is exactly $d. */
    private static function docOfDepth(int $d): string
    {
        return '{"a":' . str_repeat('[', $d - 1) . str_repeat(']', $d - 1) . '}';
    }

    private static function refused(\Closure $f, StrictJsonErrorKind $want): void
    {
        try {
            $f();
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame($want, $e->kind);
        }
    }

    /** @return iterable<string, array{string, string, int}> */
    public static function forms(): iterable
    {
        yield 'presentation' => ['presentationJson', 'max_presentation_bytes', 262144];
        yield 'artifact' => ['artifactJson', 'max_artifact_payload_bytes', 32768];
        yield 'profile' => ['profileJson', 'max_profile_bytes', 32768];
    }

    private static function form(Limits $l, string $method): JsonLimits
    {
        return match ($method) {
            'presentationJson' => $l->presentationJson(),
            'artifactJson' => $l->artifactJson(),
            'profileJson' => $l->profileJson(),
            default => self::fail('no form ' . $method),
        };
    }

    #[DataProvider('forms')]
    public function testStrictJsonLimits(string $method, string $key, int $baseline): void
    {
        self::assertEquals(new JsonLimits($baseline, 16), self::form(Limits::defaults(), $method));
        $tight = self::with(Limits::defaults(), self::baselineOf($key), 1000);
        self::assertEquals(new JsonLimits(1000, 16), self::form($tight, $method));

        $o = self::decodeObject(self::docOfSize($baseline), self::form(Limits::defaults(), $method));
        $a = $o->get('a');
        self::assertIsString($a);
        self::assertSame($baseline - 8, \strlen($a));
        self::refused(static fn() => self::decodeObject(self::docOfSize($baseline + 1), self::form(Limits::defaults(), $method)), StrictJsonErrorKind::SIZE);
        self::decodeObject(self::docOfSize(1000), self::form($tight, $method));
        self::refused(static fn() => self::decodeObject(self::docOfSize(1001), self::form($tight, $method)), StrictJsonErrorKind::SIZE);
    }

    #[DataProvider('forms')]
    public function testStrictJsonDepthComesFromLimitsDepth(string $method, string $key, int $baseline): void
    {
        $tight = self::with(Limits::defaults(), 'depth', 3);
        self::assertEquals(new JsonLimits($baseline, 3), self::form($tight, $method));
        self::decodeObject(self::docOfDepth(16), self::form(Limits::defaults(), $method));
        self::refused(static fn() => self::decodeObject(self::docOfDepth(17), self::form(Limits::defaults(), $method)), StrictJsonErrorKind::DEPTH);
        self::decodeObject(self::docOfDepth(3), self::form($tight, $method));
        self::refused(static fn() => self::decodeObject(self::docOfDepth(4), self::form($tight, $method)), StrictJsonErrorKind::DEPTH);
    }

    public function testStrictJsonDefaultsAgree(): void
    {
        // The decoder's own defaults, used when a caller passes no limits, equal the baseline.
        $d = Limits::defaults();
        self::assertSame(StrictJson::DEFAULT_MAX_DEPTH, $d->depth);
        self::assertSame(StrictJson::DEFAULT_MAX_BYTES, $d->presentationBytes);
    }
}
