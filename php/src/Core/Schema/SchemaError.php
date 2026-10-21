<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Schema;

use HopTop\Pact\PactError;

/** A document that is strict JSON but fails its definition. */
final class SchemaError extends PactError
{
    /**
     * @param string                  $def    the $defs name the document was validated against
     * @param non-empty-list<SchemaIssue> $issues
     */
    public function __construct(
        public readonly string $def,
        public readonly array $issues,
    ) {
        parent::__construct(\sprintf('schema: %s: %s', $def, implode('; ', array_map(static fn(SchemaIssue $i): string => ($i->instancePath !== '' ? $i->instancePath : '/') . ' ' . $i->message, $issues))));
    }
}
