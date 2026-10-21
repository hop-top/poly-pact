<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

/** One manifest entry, the members the harness reads. */
final readonly class Entry
{
    /**
     * @param list<string>|null $capabilities
     */
    public function __construct(
        public string $id,
        public string $kind,
        public string $scope,
        public string $path,
        public ?string $expected = null,
        public ?string $outcome = null,
        public ?array $capabilities = null,
    ) {}
}
