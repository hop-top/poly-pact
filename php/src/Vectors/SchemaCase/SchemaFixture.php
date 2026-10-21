<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Vectors\Entry;

/**
 * The schema case verdict of spec/v1.0/fixtures/schema/README.md, which every
 * harness applies to the manifest entries of kind schema (Go
 * runner.CheckSchemaFixture and runner.TypDef).
 *
 * A document is accepted when it passes, in order: the form of a compact
 * JWS (three segments, canonical base64url header and payload), a protected
 * header that is a strict JSON object whose typ selects a definition, a
 * payload or object that is strict JSON (draft 7.1, 20.1), and the
 * definition of the Appendix A.3 schema. Otherwise it is rejected with
 * INVALID_MESSAGE (draft 13.4). The signature is never verified.
 */
final class SchemaFixture
{
    /** The definition of each typ of the draft 7.3 table (Appendix A.1: the protected typ selects the definition). */
    public const array TYP_DEFS = [
        Jws::TYP_REQUIREMENTS => 'RequirementContract',
        Jws::TYP_EVIDENCE => 'Evidence',
        Jws::TYP_PRESENTATION => 'Presentation',
        Jws::TYP_ADMISSION => 'AdmissionAttestation',
        Jws::TYP_OUTCOME => 'OutcomeReport',
        Jws::TYP_REPUTATION => 'ReputationSnapshot',
        Jws::TYP_LEARNING_POLICY => 'LearningPolicy',
        Jws::TYP_LEARNING_ARTIFACT => 'LearningArtifact',
        Jws::TYP_LEARNING_EVENT => 'LearningEvent',
    ];

    private function __construct() {}

    /** The $defs definition that the JWS typ selects, null for none; typ is compared exactly. */
    public static function typDef(string $typ): ?string
    {
        return self::TYP_DEFS[$typ] ?? null;
    }

    /**
     * Apply the verdict to the input of the schema entry $e of the fixture
     * directory $root with $v (the package's validator when null) and return
     * how the entry's expectation fails: a document of an ACCEPTED entry that
     * is rejected, or one of a REJECTED entry that is accepted or rejected
     * with another code. A malformed case is a problem too. None means the
     * expectation holds.
     *
     * @return list<string>
     */
    public static function check(string $root, Entry $e, ?SchemaValidator $v = null): array
    {
        try {
            $c = SchemaCase::read($root, $e);
        } catch (SchemaCaseError $err) {
            return [$err->getMessage()];
        }

        return $c->verdicts($v ?? new PackageValidator());
    }
}
