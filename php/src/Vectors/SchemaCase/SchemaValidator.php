<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\Core\Schema\SchemaIssue;

/**
 * Validates a document against one definition of the $defs of the Appendix
 * A.3 schema (Go runner.SchemaValidator). PackageValidator is the one of
 * this package; a test may give another.
 */
interface SchemaValidator
{
    /**
     * Validate $doc, one strict JSON text, against #/$defs/$def.
     *
     * @return list<SchemaIssue> the violations, none when $doc is valid
     *
     * @throws \InvalidArgumentException when $def is not a definition of the schema
     * @throws \RuntimeException         when $doc cannot be validated
     */
    public function validateDef(string $def, string $doc): array;
}
