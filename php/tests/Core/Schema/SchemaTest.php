<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Schema;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Schema\Schema;
use HopTop\Pact\Core\Schema\SchemaError;
use HopTop\Pact\Core\Schema\UriFormat;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Core\StrictJson\StrictJsonErrorKind;
use HopTop\Pact\PactError;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Fixtures;
use HopTop\Pact\Vectors\Harness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The schema module, an SDK extra: the shared RFC 3986 uri matcher against
 * spec/v1.0/fixtures/vectors/schema, and definition validation over the
 * vendored schema with the matcher registered. Port of the TypeScript
 * port's schema.test.ts and the Python port's test_schema.py.
 */
final class SchemaTest extends TestCase
{
    private const ACK = '{"request_id":"r-1","status":"ACCEPTED","artifact_id":"a-1","received_at":1}';

    /** spec/v1.0/fixtures/schema/README.md, definition selection: typ of draft 7.3. */
    private const DEF_OF_TYP = [
        'pact-requirements+jwt' => 'RequirementContract',
        'pact-evidence+jwt' => 'Evidence',
        'pact-presentation+jwt' => 'Presentation',
        'pact-admission+jwt' => 'AdmissionAttestation',
        'pact-outcome+jwt' => 'OutcomeReport',
        'pact-reputation+jwt' => 'ReputationSnapshot',
        'pact-learning-policy+jwt' => 'LearningPolicy',
        'pact-learning-artifact+jwt' => 'LearningArtifact',
        'pact-learning-event+jwt' => 'LearningEvent',
    ];

    /** @return list<JsonObject> */
    private static function uriVectors(): array
    {
        Repo::read('spec/v1.0/fixtures/vectors/schema/uri-format.json');
        $vs = Fixtures::readJson(Repo::root() . '/spec/v1.0/fixtures', 'vectors/schema/uri-format.json');
        self::assertIsArray($vs);
        self::assertGreaterThanOrEqual(50, \count($vs));
        $out = [];
        foreach ($vs as $v) {
            $out[] = Fixtures::obj($v, 'vector', ['id', 'input', 'expect', 'reason', 'ajv_formats_differs']);
        }

        return $out;
    }

    public function testTheUriMatcherGivesEveryVectorItsVerdict(): void
    {
        $wrong = [];
        foreach (self::uriVectors() as $v) {
            $got = UriFormat::matches(Fixtures::str($v->get('input'), 'input')) ? 'accept' : 'reject';
            if ($got !== $v->get('expect')) {
                $wrong[] = $v->get('id');
            }
        }
        self::assertSame([], $wrong);
    }

    /** opis's own checker differs from RFC 3986 (probe Q5): the registered one is the shared matcher. */
    public function testTheRegisteredUriFormatIsTheMatcherInDefinitionValidation(): void
    {
        $wrong = [];
        foreach (self::uriVectors() as $v) {
            $input = Fixtures::str($v->get('input'), 'input');
            $n = mb_strlen($input, 'UTF-8');
            if ($n < 1 || $n > 1024) {
                continue; // Problem.type length bounds
            }
            $verdict = 'accept';
            try {
                Schema::validateValue('Problem', new JsonObject(['type' => $input, 'title' => 't', 'status' => 400, 'code' => 'c', 'request_id' => 'r']));
            } catch (SchemaError) {
                $verdict = 'reject';
            }
            if ($verdict !== $v->get('expect')) {
                $wrong[] = \sprintf('%s: %sed, want %s', (string) json_encode($v->get('id')), $verdict, (string) json_encode($v->get('expect')));
            }
        }
        self::assertSame([], $wrong);
        // And through the validator itself, as the harness uses it.
        $schema = (object) ['type' => 'string', 'format' => 'uri'];
        self::assertFalse(Schema::validator()->validate("https://example.com/\n", $schema)->isValid());
        self::assertTrue(Schema::validator()->validate('https:', $schema)->isValid());
        self::assertTrue(Schema::validator()->validate(5, (object) ['format' => 'uri'])->isValid());
    }

    public function testTheUriExpressionIsTheOneOfTheVectorsReadme(): void
    {
        $readme = Repo::read('spec/v1.0/fixtures/vectors/schema/README.md');
        if (preg_match('/```text\n(\^.*?\$)\n```/s', $readme, $m) !== 1) {
            self::fail('README has no expression block');
        }
        self::assertSame($m[1], UriFormat::URI_EXPRESSION);
    }

    public function testUriMatchesTheWholeStringAsciiOnly(): void
    {
        foreach (['https://example.com/', 'https:', 'urn:x', 'https://[::1]:8080/a?b#c'] as $s) {
            self::assertTrue(UriFormat::matches($s), $s);
        }
        foreach (['', "https://example.com/\n", 'x https://example.com/', 'https://example.com/a b', "https://example.com/\u{212a}", "https://example.com:8\u{661}/", '//example.com/', "https://example.com/\xff"] as $s) {
            self::assertFalse(UriFormat::matches($s), (string) json_encode($s, \JSON_INVALID_UTF8_SUBSTITUTE));
        }
        self::assertTrue((new UriFormat())->validate(5));
        self::assertTrue((new UriFormat())->validate(null));
        self::assertFalse((new UriFormat())->validate('a b'));
    }

    public function testValidateReturnsTheStrictlyParsedDocumentOfAValidObject(): void
    {
        $got = Schema::validate('Acknowledgment', self::ACK);
        self::assertEquals(StrictJson::parse(self::ACK), $got);
        self::assertInstanceOf(JsonObject::class, $got);
        self::assertSame(['request_id', 'status', 'artifact_id', 'received_at'], $got->names());
    }

    public function testValidateRefusesASchemaFailureWithEveryIssue(): void
    {
        try {
            Schema::validate('Acknowledgment', '{"request_id":"r-1","status":"OK","artifact_id":"a-1","received_at":1,"bogus":1}');
            self::fail('accepted');
        } catch (SchemaError $e) {
            self::assertInstanceOf(PactError::class, $e);
            self::assertSame('Acknowledgment', $e->def);
            $keywords = array_map(static fn($i): string => $i->keyword, $e->issues);
            sort($keywords);
            self::assertSame(['additionalProperties', 'enum'], $keywords);
            self::assertContains('/status', array_map(static fn($i): string => $i->instancePath, $e->issues));
            self::assertStringStartsWith('schema: Acknowledgment: ', $e->getMessage());
            self::assertStringNotContainsString('{', $e->getMessage(), 'message placeholders are filled in');
        }
    }

    public function testValidateAppliesTheStrictParseFirst(): void
    {
        foreach ([
            ['{"request_id":"r","request_id":"s"}', StrictJsonErrorKind::DUPLICATE_KEY],
            ['{"request_id":"r-1","status":"ACCEPTED","artifact_id":"a-1","received_at":9007199254740992}', StrictJsonErrorKind::INTEGER],
            ['{"a":NaN}', StrictJsonErrorKind::NON_FINITE],
        ] as [$input, $kind]) {
            try {
                Schema::validate('Acknowledgment', $input);
                self::fail('accepted ' . $input);
            } catch (StrictJsonError $e) {
                self::assertSame($kind, $e->kind, $input);
            }
        }
        try {
            Schema::validate('Acknowledgment', '{}', new Limits(maxBytes: 1));
            self::fail('accepted');
        } catch (StrictJsonError $e) {
            self::assertSame(StrictJsonErrorKind::SIZE, $e->kind);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function notDefs(): iterable
    {
        foreach (['', 'Nope', 'GatewayEndpoints', '__proto__', '#', 'Acknowledgment/properties', 'acknowledgment'] as $name) {
            yield $name === '' ? 'empty' : $name => [$name];
        }
    }

    #[DataProvider('notDefs')]
    public function testValidateRefusesANameThatIsNotADefsEntry(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Schema::validate($name, '{}');
    }

    public function testDefinitions(): void
    {
        $defs = Schema::definitions();
        self::assertContains('Acknowledgment', $defs);
        self::assertContains('Evidence', $defs);
        self::assertSame('urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60', Schema::id());
        $doc = StrictJson::parse((string) file_get_contents(Repo::package() . '/schema/pact.schema.json'), new Limits(4 << 20, 64));
        self::assertInstanceOf(JsonObject::class, $doc);
        $all = $doc->get('$defs');
        self::assertInstanceOf(JsonObject::class, $all);
        self::assertSame($all->names(), $defs);
    }

    /** A member name a stdClass cannot hold fails validation, with a message that says why. */
    public function testANulLeadingNameIsAValidationFailure(): void
    {
        try {
            Schema::validate('Acknowledgment', '{"request_id":"r-1","status":"ACCEPTED","artifact_id":"a-1","received_at":1,"extensions":{"\u0000x":1}}');
            self::fail('accepted');
        } catch (SchemaError $e) {
            self::assertCount(1, $e->issues);
            self::assertSame('/extensions', $e->issues[0]->instancePath);
            self::assertStringContainsString('starts with NUL', $e->issues[0]->message);
        }
        // A NUL inside a name is fine.
        self::assertFalse(Schema::validator()->validate((object) ["a\0" => 1], (object) ['type' => 'object', 'maxProperties' => 0])->isValid());
    }

    public function testValidateValueRefusesValuesOutsideTheModel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Schema::validateValue('Acknowledgment', new JsonObject(['request_id' => new \stdClass()]));
    }

    public function testValidateValueRefusesAMapArray(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Schema::validateValue('Acknowledgment', ['request_id' => 'r']);
    }

    /**
     * Every anchored pattern of the schema gives its valid sample plus a
     * trailing line feed the ECMA-262 verdict: opis compiles patterns with
     * the PCRE D modifier (probe Q5 finding 4), so $ does not match before a
     * final newline. The JSON Pointer pattern accepts it, as in ECMA-262:
     * [^~/] matches a line feed.
     */
    public function testAnchoredPatternsRefuseATrailingLineFeed(): void
    {
        $newlineMatches = ['^(?:/(?:[^~/]|~[01])*)+$'];
        $samples = [
            '^(?:/(?:[^~/]|~[01])*)+$' => '/a/b~0',
            '^[A-Z]+$' => 'GET',
            '^[A-Za-z0-9_-]+$' => 'a_b-1',
            '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' => 'a.b.c',
            '^[A-Za-z0-9_-]{43}$' => str_repeat('A', 43),
            "^[a-z0-9!#$%&'*+.^_`|~-]+$" => 'x-header',
            '^[a-z0-9-]+$' => 'a-1',
            '^pact-[a-z0-9]+(-[a-z0-9]+)*$' => 'pact-transport-profile-v1',
        ];
        $text = (string) file_get_contents(Repo::package() . '/schema/pact.schema.json');
        preg_match_all('/"pattern":\s*("(?:[^"\\\\]|\\\\.)*")/', $text, $m);
        $patterns = array_values(array_unique(array_map(static fn(string $s): string => Fixtures::str(json_decode($s), 'pattern'), $m[1])));
        foreach ($patterns as $p) {
            if (!str_ends_with($p, '$')) {
                continue;
            }
            self::assertArrayHasKey($p, $samples, 'no sample for the anchored pattern ' . $p);
            $schema = (object) ['type' => 'string', 'pattern' => $p];
            self::assertTrue(Schema::validator()->validate($samples[$p], $schema)->isValid(), $p);
            self::assertSame(\in_array($p, $newlineMatches, true), Schema::validator()->validate($samples[$p] . "\n", $schema)->isValid(), $p . ': trailing line feed');
        }
        // Through a definition: body_digest of an operation context.
        $op = '{"operation_id":"o","environment_id":"https://e.example/","principal_id":"https://p.example/","action":"a.b","resources":["https://r.example/"],"method":"GET","target_uri":"https://t.example/","body_digest":"' . str_repeat('A', 43) . '%s","headers":{}}';
        Schema::validate('OperationContext', \sprintf($op, ''));
        try {
            Schema::validate('OperationContext', \sprintf($op, '\n'));
            self::fail('a trailing line feed passed');
        } catch (SchemaError $e) {
            self::assertSame('/body_digest', $e->issues[0]->instancePath);
            self::assertSame('pattern', $e->issues[0]->keyword);
        }
    }

    public function testEveryAppendixBObjectValidatesAgainstItsDefinition(): void
    {
        $list = Fixtures::readJson(Repo::root() . '/spec/v1.0/fixtures', 'schema/appendix-b-valid.json');
        $objects = Fixtures::obj($list, 'list', ['description', 'objects'])->get('objects');
        self::assertIsArray($objects);
        self::assertCount(12, $objects);
        self::checkObjects($objects, true);
    }

    /** Every object-list schema case of the manifest gets its outcome: the cases beyond Appendix B. */
    public function testEverySchemaObjectListCase(): void
    {
        Repo::read('spec/v1.0/fixtures/manifest.json');
        $root = Repo::root() . '/spec/v1.0/fixtures';
        $n = 0;
        foreach (Harness::loadManifest($root . '/manifest.json') as $e) {
            if ($e->kind !== 'schema' || !str_ends_with($e->path, '.json')) {
                continue;
            }
            $objects = Fixtures::obj(Fixtures::readJson($root, $e->path), $e->path, ['description', 'objects'])->get('objects');
            self::assertIsArray($objects, $e->id);
            self::checkObjects($objects, $e->outcome === 'ACCEPTED', $e->id);
            ++$n;
        }
        self::assertGreaterThanOrEqual(20, $n);
    }

    /** @param array<mixed> $objects */
    private static function checkObjects(array $objects, bool $accept, string $where = ''): void
    {
        foreach ($objects as $o) {
            self::assertInstanceOf(JsonObject::class, $o);
            $typ = $o->get('typ');
            $def = $o->get('def') ?? self::DEF_OF_TYP[\is_string($typ) ? $typ : ''] ?? null;
            self::assertIsString($def, $where . ' ' . (string) json_encode($o->get('section')) . ': no definition');
            try {
                Schema::validateValue($def, $o->get('object'));
                self::assertTrue($accept, $where . ' ' . $def . ': accepted, want reject');
            } catch (SchemaError $e) {
                self::assertFalse($accept, $where . ' ' . $e->getMessage());
            }
        }
    }
}
