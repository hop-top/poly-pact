<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

/** Neither passed nor failed, for a reason: out-of-scope, spec-defect or capability. */
final class Skipped extends \RuntimeException
{
    public const OUT_OF_SCOPE = 'out-of-scope';
    public const SPEC_DEFECT = 'spec-defect';
    public const CAPABILITY = 'capability';

    /**
     * @param list<array<string, string>> $defects the values of a spec-defect vector
     * @param list<string>                $missing the undeclared capabilities
     */
    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly array $defects = [],
        public readonly array $missing = [],
    ) {
        parent::__construct($message);
    }
}
