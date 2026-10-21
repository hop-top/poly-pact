<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors\SchemaCase;

use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Manifest;
use HopTop\Pact\Vectors\SchemaCase\SchemaFixture;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The schema case verdict of spec/v1.0/fixtures/schema/README.md. Port of
 * the verdict tests of go/runner/schemaverb_test.go, with the stub validator
 * of the Go tests and the package's validator.
 */
final class SchemaFixtureTest extends TestCase
{
    protected function tearDown(): void
    {
        SchemaTree::cleanAll();
    }

    /** @param list<string> $problems */
    private static function contains(array $problems, string ...$parts): bool
    {
        $s = implode("\n", $problems);
        foreach ($parts as $p) {
            if (!str_contains($s, $p)) {
                return false;
            }
        }

        return $problems !== [];
    }

    /** The definition of each typ of the draft 7.3 table; typ is compared exactly. */
    public function testTypDef(): void
    {
        $want = [
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
        foreach ($want as $typ => $def) {
            self::assertSame($def, SchemaFixture::typDef($typ), $typ);
        }
        foreach (['', 'JWT', 'jwt', 'PACT-evidence+jwt', 'application/pact-evidence+jwt', 'pact-evidence+jwt ', 'pact-receipt+jwt'] as $typ) {
            self::assertNull(SchemaFixture::typDef($typ), $typ);
        }
    }

    /** @return list<Entry> */
    private static function repoSchemaEntries(): array
    {
        $out = array_values(array_filter(Manifest::load(SchemaTree::repoFixtures() . '/manifest.json'), static fn(Entry $e): bool => $e->kind === 'schema'));
        self::assertCount(25, $out);

        return $out;
    }

    /** The committed schema cases get their expected verdict, each document checked against the definition its type selects. */
    public function testRepoCasesSelectTheirDefinitions(): void
    {
        $root = SchemaTree::repoFixtures();
        $tests = [
            'parse/appendix-c-wrong-version' => ['Evidence'],
            'schema/appendix-b-valid' => ['AgentProfile', 'Intent', 'OperationContext', 'RequirementContract', 'Evidence', 'ReputationSnapshot', 'AdmissionAttestation', 'OutcomeReport', 'LearningPolicy', 'LearningArtifact', 'LearningEvent', 'GatewayMetadata'],
        ];
        foreach ($tests as $id => $defs) {
            $v = new StubValidator();
            $e = Manifest::lookup(Manifest::load($root . '/manifest.json'), $id);
            self::assertNotNull($e);
            self::assertSame([], SchemaFixture::check($root, $e, $v), $id);
            self::assertSame($defs, $v->calls, $id);
        }
    }

    /** Every committed schema entry holds its expectation under the package's validator. */
    public function testEveryRepoCaseHoldsUnderThePackageSchema(): void
    {
        $root = SchemaTree::repoFixtures();
        foreach (self::repoSchemaEntries() as $e) {
            self::assertSame([], SchemaFixture::check($root, $e), $e->id);
        }
    }

    /** The expectation of a committed REJECTED case fails when its documents are taken as ACCEPTED, and the reverse. */
    public function testRepoCasesFailFlipped(): void
    {
        $root = SchemaTree::repoFixtures();
        foreach (self::repoSchemaEntries() as $e) {
            $flip = $e->outcome === 'ACCEPTED' ? 'REJECTED' : 'ACCEPTED';
            $root2 = SchemaTree::tree([SchemaTree::entry($e->id, 'in' . substr($e->path, (int) strrpos($e->path, '.')), $flip, $flip === 'ACCEPTED' ? 'in' . substr($e->path, (int) strrpos($e->path, '.')) : 'd.json')], [
                'in' . substr($e->path, (int) strrpos($e->path, '.')) => (string) file_get_contents($root . '/' . $e->path),
                'd.json' => '{"transport_code":"INVALID_MESSAGE"}',
            ]);
            $p = SchemaFixture::check($root2, SchemaTree::load($root2, $e->id));
            self::assertNotSame([], $p, $e->id);
        }
    }

    /** @return iterable<string, array{string, bool}> */
    public static function rejects(): iterable
    {
        $h = SchemaTree::EVIDENCE_HEADER;
        $c = SchemaTree::compact(...);
        $b = SchemaTree::b64(...);
        $deep = str_repeat('{"a":', 17) . '1' . str_repeat('}', 17);
        yield 'two segments' => [$b($h) . '.' . $b('{}'), false];
        yield 'four segments' => [$c($h, '{}') . '.x', false];
        yield 'padded header' => [$b($h) . '==.' . $b('{}') . '.c2ln', false];
        yield 'standard base64 payload' => [$b($h) . '.' . rtrim(base64_encode("\xfb\xff\xfe"), '=') . '.c2ln', false];
        yield 'header not JSON' => [$c('{"typ":', '{}'), false];
        yield 'header duplicate member' => [$c('{"alg":"ES256","typ":"pact-evidence+jwt","typ":"pact-evidence+jwt"}', '{}'), false];
        yield 'header array' => [$c('["pact-evidence+jwt"]', '{}'), false];
        yield 'header without typ' => [$c('{"alg":"ES256"}', '{}'), false];
        yield 'typ not a string' => [$c('{"typ":7}', '{}'), false];
        yield 'typ JWT' => [$c('{"typ":"JWT"}', '{}'), false];
        yield 'typ with media type prefix' => [$c('{"typ":"application/pact-evidence+jwt"}', '{}'), false];
        yield 'payload duplicate member' => [$c($h, '{"pact_version":"0.1","pact_version":"0.1"}'), false];
        yield 'payload non-finite number' => [$c($h, '{"iat":1e999}'), false];
        yield 'payload integer beyond 2^53-1' => [$c($h, '{"iat":9007199254740992}'), false];
        yield 'payload invalid UTF-8' => [$b($h) . '.' . $b("{\"sub\":\"\xff\"}") . '.c2ln', false];
        yield 'payload lone surrogate' => [$c($h, '{"sub":"\ud800"}'), false];
        yield 'payload nested 17 deep' => [$c($h, $deep), false];
        yield 'payload trailing data' => [$c($h, '{} {}'), false];
        yield 'payload empty' => [$c($h, ''), false];
        yield 'empty file' => ['', false];
        yield 'payload fails the schema' => [$c($h, '{"pact_version":"0.2"}'), true];
        yield 'unknown core field' => [$c($h, '{"pact_version":"0.1","unknown_core_field":1}'), true];
    }

    /**
     * Each input is rejected with INVALID_MESSAGE (draft 13.4). The parse
     * steps come before the schema: an input that is not strict JSON, or
     * whose typ selects no definition, never reaches the validator.
     */
    #[DataProvider('rejects')]
    public function testVerdictRejects(string $text, bool $validate): void
    {
        [$root, $e] = SchemaTree::rejected($text);
        $v = new StubValidator();
        self::assertSame([], SchemaFixture::check($root, $e, $v));
        self::assertSame($validate, $v->calls !== [], implode(', ', $v->calls));
    }

    /** A valid evidence payload is accepted, so a REJECTED expectation fails. */
    public function testVerdictAccepts(): void
    {
        [$root, $e] = SchemaTree::rejected(SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, '{"pact_version":"0.1"}'));
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'accepted, want rejected with INVALID_MESSAGE'));
    }

    /**
     * A document may nest 16 levels deep, not 17 (draft 20.1), counted from
     * the document: in an object list, from the object, not from the file.
     */
    public function testVerdictNesting(): void
    {
        $nest = static fn(int $n): string => str_repeat('{"a":', $n - 1) . '{}' . str_repeat('}', $n - 1);
        $list = static fn(int $n): string => '{"description":"d","objects":[{"section":"B.1","def":"AgentProfile","object":' . $nest($n) . '}]}';
        [$root, $e] = SchemaTree::list($list(16), 'ACCEPTED');
        self::assertSame([], SchemaFixture::check($root, $e, new StubValidator()));
        [$root, $e] = SchemaTree::list($list(17), 'ACCEPTED');
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'rejected', 'deep'));
        [$root, $e] = SchemaTree::rejected(SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, $nest(16)));
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'accepted'));
        [$root, $e] = SchemaTree::rejected(SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, $nest(17)));
        self::assertSame([], SchemaFixture::check($root, $e, new StubValidator()));
    }

    /** An expectation that the verdict does not meet is reported. */
    public function testContradictions(): void
    {
        $good = SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, '{"pact_version":"0.1"}');
        $bad = SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, '{"pact_version":"0.2"}');
        [$root, $e] = SchemaTree::rejected($good);
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'accepted'));
        [$root, $e] = SchemaTree::rejected($bad, 'INVALID_PROOF');
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'INVALID_PROOF'));
        [$root, $e] = SchemaTree::list('{"description":"d","objects":[{"section":"B.5","typ":"pact-evidence+jwt","object":{"pact_version":"0.2"}}]}', 'ACCEPTED');
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), '/pact_version'));
        [$root, $e] = SchemaTree::list('{"description":"d","objects":[{"section":"B.1","def":"NoSuchDef","object":{}}]}', 'ACCEPTED');
        self::assertTrue(self::contains(SchemaFixture::check($root, $e, new StubValidator()), 'NoSuchDef'));
        // The package's validator: an unknown definition is no verdict either.
        self::assertTrue(self::contains(SchemaFixture::check($root, $e), 'NoSuchDef'));
    }

    /** @return iterable<string, array{string}> */
    public static function inputForms(): iterable
    {
        $obj = '{"pact_version":"0.1"}';
        yield 'typ and def' => ['{"description":"d","objects":[{"section":"B.5","typ":"pact-evidence+jwt","def":"Evidence","object":' . $obj . '}]}'];
        yield 'neither typ or def' => ['{"description":"d","objects":[{"section":"B.5","object":' . $obj . '}]}'];
        yield 'unknown typ' => ['{"description":"d","objects":[{"section":"B.5","typ":"pact-receipt+jwt","object":' . $obj . '}]}'];
        yield 'no objects' => ['{"description":"d","objects":[]}'];
        yield 'no description' => ['{"objects":[{"section":"B.5","def":"Evidence","object":' . $obj . '}]}'];
        yield 'no section' => ['{"description":"d","objects":[{"def":"Evidence","object":' . $obj . '}]}'];
        yield 'object not object' => ['{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":[1]}]}'];
        yield 'object missing' => ['{"description":"d","objects":[{"section":"B.5","def":"Evidence"}]}'];
        yield 'unknown member' => ['{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":' . $obj . ',"note":"x"}]}'];
        yield 'unknown top-level member' => ['{"description":"d","note":"x","objects":[{"section":"B.5","def":"Evidence","object":' . $obj . '}]}'];
        yield 'duplicate member' => ['{"description":"d","description":"d","objects":[{"section":"B.5","def":"Evidence","object":' . $obj . '}]}'];
        yield 'def a number' => ['{"description":"d","objects":[{"section":"B.5","def":7,"object":' . $obj . '}]}'];
    }

    /** An input that breaks the format of spec/v1.0/fixtures/schema/README.md is a problem of the case, not a verdict. */
    #[DataProvider('inputForms')]
    public function testInputForm(string $list): void
    {
        [$root, $e] = SchemaTree::list($list, 'ACCEPTED');
        $v = new StubValidator();
        self::assertNotSame([], SchemaFixture::check($root, $e, $v));
        self::assertSame([], $v->calls);
    }

    /** The expectation must fit the outcome. */
    public function testExpectationForm(): void
    {
        $obj = '{"pact_version":"0.1"}';
        $list = '{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":' . $obj . '}]}';
        $bad = SchemaTree::compact(SchemaTree::EVIDENCE_HEADER, '{"pact_version":"0.2"}');
        $root = SchemaTree::tree([
            SchemaTree::entry('schema/a', 'schema/a.json', 'ACCEPTED', 'expected/schema/a/decision.json'),
            SchemaTree::entry('schema/b', 'schema/b.json', 'MATCH', 'schema/b.json'),
            SchemaTree::entry('schema/c', 'schema/c.txt', 'ACCEPTED', 'schema/c.txt'),
            SchemaTree::entry('parse/d', 'parse/d.jws', 'REJECTED', 'expected/parse/d/decision.json'),
            SchemaTree::entry('parse/e', 'parse/e.jws', 'REJECTED', 'expected/parse/e/decision.json'),
            SchemaTree::entry('parse/f', 'parse/f.jws', 'REJECTED', 'expected/parse/f/decision.json'),
        ], [
            'schema/a.json' => $list,
            'expected/schema/a/decision.json' => '{"transport_code":null}',
            'schema/b.json' => $list,
            'schema/c.txt' => $obj,
            'parse/d.jws' => $bad,
            'expected/parse/d/decision.json' => '{"transport_code":null}',
            'parse/e.jws' => $bad,
            'expected/parse/e/decision.json' => '{"transport_code":"INVALID_MESSAGE","decision":"INADMISSIBLE"}',
            'parse/f.jws' => $bad,
        ]);
        foreach (['schema/a', 'schema/b', 'schema/c', 'parse/d', 'parse/e', 'parse/f'] as $id) {
            self::assertNotSame([], SchemaFixture::check($root, SchemaTree::load($root, $id), new StubValidator()), $id);
        }
    }
}
