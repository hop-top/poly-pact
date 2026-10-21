<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

/** The verdict on one document: accepted, or rejected with a draft 13.4 code and why. */
final readonly class Verdict
{
    /** The draft 13.4 code of a document rejected for its form. */
    public const string INVALID_MESSAGE = 'INVALID_MESSAGE';

    private function __construct(
        public bool $accepted,
        public string $code = '',
        public string $why = '',
    ) {}

    public static function accepted(): self
    {
        return new self(true);
    }

    public static function rejected(string $why): self
    {
        return new self(false, self::INVALID_MESSAGE, $why);
    }
}
