<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Schema;

/** One schema failure of a document. */
final readonly class SchemaIssue
{
    /**
     * @param string $instancePath the RFC 6901 pointer of the failing value, empty for the document
     * @param string $keyword      the schema keyword that failed
     */
    public function __construct(
        public string $instancePath,
        public string $keyword,
        public string $message,
    ) {}
}
