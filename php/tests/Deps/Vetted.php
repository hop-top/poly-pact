<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Deps;

/** The vetted sets of tests/testdata/deps-vetted.json, typed. */
final readonly class Vetted
{
    /**
     * @param array<string, string> $platform
     * @param list<string> $extensions
     * @param array<string, string> $require
     * @param array<string, string> $requireDev
     * @param array<string, string> $packages
     * @param array<string, string> $packagesDev
     * @param array<string, list<string>> $namespaces
     */
    public function __construct(
        public string $php,
        public array $platform,
        public array $extensions,
        public array $require,
        public array $requireDev,
        public array $packages,
        public array $packagesDev,
        public array $namespaces,
    ) {}

    /** @param array<mixed> $data */
    public static function from(array $data): self
    {
        $extensions = array_values(array_filter(\is_array($data['extensions'] ?? null) ? $data['extensions'] : [], \is_string(...)));
        sort($extensions);
        $namespaces = [];
        foreach (\is_array($data['namespaces'] ?? null) ? $data['namespaces'] : [] as $tree => $list) {
            $namespaces[(string) $tree] = array_values(array_filter(\is_array($list) ? $list : [], \is_string(...)));
        }

        return new self(
            \is_string($data['php'] ?? null) ? $data['php'] : '',
            Depcheck::strings($data['platform'] ?? []),
            $extensions,
            Depcheck::strings($data['require'] ?? []),
            Depcheck::strings($data['require-dev'] ?? []),
            Depcheck::strings($data['packages'] ?? []),
            Depcheck::strings($data['packages-dev'] ?? []),
            $namespaces,
        );
    }
}
