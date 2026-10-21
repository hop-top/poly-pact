<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors\SchemaCase;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Schema\SchemaIssue;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Vectors\SchemaCase\SchemaValidator;

/**
 * The stubValidator of go/runner/schemaverb_test.go: it records the
 * definitions it is asked for and applies two rules of the Appendix A.3
 * schema, pact_version, when present, is the constant "0.1", and no member
 * is named unknown_core_field. An unknown definition is an error.
 */
final class StubValidator implements SchemaValidator
{
    public const array DEFS = [
        'AgentProfile', 'Intent', 'OperationContext', 'RequirementContract', 'Evidence', 'Presentation',
        'AdmissionAttestation', 'OutcomeReport', 'ReputationSnapshot', 'LearningPolicy', 'LearningArtifact',
        'LearningEvent', 'GatewayMetadata',
    ];

    /** @var list<string> */
    public array $calls = [];

    public function validateDef(string $def, string $doc): array
    {
        $this->calls[] = $def;
        if (!\in_array($def, self::DEFS, true)) {
            throw new \InvalidArgumentException(\sprintf('no definition %s', json_encode($def)));
        }
        $m = StrictJson::parse($doc);
        if (!$m instanceof JsonObject) {
            return [new SchemaIssue('', 'type', 'not an object')];
        }
        $out = [];
        if ($m->has('pact_version') && $m->get('pact_version') !== '0.1') {
            $out[] = new SchemaIssue('/pact_version', 'const', "value must be '0.1'");
        }
        if ($m->has('unknown_core_field')) {
            $out[] = new SchemaIssue('', 'additionalProperties', "additional property 'unknown_core_field' not allowed");
        }

        return $out;
    }
}
