<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Deps;

use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\Assert;

/** What the dependency guard reads, and edited copies of it for the negative control. */
final readonly class Inputs
{
    private const TREES = ['src', 'tests', 'examples', 'scripts'];

    /**
     * @param array<mixed> $composer
     * @param array<mixed> $lock
     * @param array<mixed> $vetted
     * @param array<string, array<string, string>> $trees
     */
    public function __construct(
        public array $composer,
        public array $lock,
        public array $vetted,
        public string $doc,
        public array $trees,
    ) {}

    /** The package as checked out: composer.json, composer.lock, the vetted sets, deps-php.md and the PHP sources. */
    public static function load(): self
    {
        $root = Repo::package();
        $trees = [];
        foreach (self::TREES as $tree) {
            $trees[$tree] = [];
            if (!is_dir($root . '/' . $tree)) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . $tree, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
                    $rel = substr($file->getPathname(), \strlen($root . '/' . $tree . '/'));
                    $trees[$tree][$rel] = (string) file_get_contents($file->getPathname());
                }
            }
        }

        return new self(
            self::json($root . '/composer.json'),
            self::json($root . '/composer.lock'),
            self::json($root . '/tests/testdata/deps-vetted.json'),
            Repo::read('docs/sdk/deps-php.md'),
            $trees,
        );
    }

    /** @return list<string> */
    public function problems(): array
    {
        return Depcheck::problems($this->composer, $this->lock, $this->vetted, $this->doc, $this->trees);
    }

    /** A copy with $value at the dotted $path of composer.json; a package name (vendor/name) is one segment. */
    public function composer(string $path, mixed $value): self
    {
        return new self(self::set($this->composer, $path, $value), $this->lock, $this->vetted, $this->doc, $this->trees);
    }

    /** A copy with $value at the dotted $path of the vetted sets. */
    public function vetted(string $path, mixed $value): self
    {
        return new self($this->composer, $this->lock, self::set($this->vetted, $path, $value), $this->doc, $this->trees);
    }

    /**
     * A copy with $entry added to the lock section $section.
     *
     * @param array<string, mixed> $entry
     */
    public function lockAppend(string $section, array $entry): self
    {
        $lock = $this->lock;
        $entries = \is_array($lock[$section] ?? null) ? $lock[$section] : [];
        $entries[] = $entry;
        $lock[$section] = $entries;

        return new self($this->composer, $lock, $this->vetted, $this->doc, $this->trees);
    }

    /**
     * A copy with $fields merged into the lock entry $name of $section.
     *
     * @param array<string, mixed> $fields
     */
    public function lockEdit(string $section, string $name, array $fields): self
    {
        $lock = $this->lock;
        $entries = \is_array($lock[$section] ?? null) ? $lock[$section] : [];
        $found = false;
        foreach ($entries as $i => $p) {
            if (\is_array($p) && ($p['name'] ?? null) === $name) {
                $entries[$i] = [...$p, ...$fields];
                $found = true;
            }
        }
        Assert::assertTrue($found, $name . ' is in ' . $section);
        $lock[$section] = $entries;

        return new self($this->composer, $lock, $this->vetted, $this->doc, $this->trees);
    }

    /** A copy with the lock entry $name moved from packages-dev to packages. */
    public function lockMove(string $name): self
    {
        $lock = $this->lock;
        $dev = \is_array($lock['packages-dev'] ?? null) ? $lock['packages-dev'] : [];
        $runtime = \is_array($lock['packages'] ?? null) ? $lock['packages'] : [];
        foreach ($dev as $i => $p) {
            if (\is_array($p) && ($p['name'] ?? null) === $name) {
                $runtime[] = $p;
                unset($dev[$i]);
            }
        }
        $lock['packages'] = $runtime;
        $lock['packages-dev'] = array_values($dev);

        return new self($this->composer, $lock, $this->vetted, $this->doc, $this->trees);
    }

    /** A copy of deps-php.md without the one line that starts with $prefix. */
    public function docDrop(string $prefix): self
    {
        $lines = explode("\n", $this->doc);
        $kept = array_filter($lines, static fn(string $l): bool => !str_starts_with($l, $prefix));
        Assert::assertCount(\count($lines) - 1, $kept, 'one line starts with ' . $prefix);

        return new self($this->composer, $this->lock, $this->vetted, implode("\n", $kept), $this->trees);
    }

    /** A copy of deps-php.md with its one $from replaced by $to. */
    public function docReplace(string $from, string $to): self
    {
        Assert::assertSame(1, substr_count($this->doc, $from), $from);

        return new self($this->composer, $this->lock, $this->vetted, str_replace($from, $to, $this->doc), $this->trees);
    }

    /** A copy with the source file $rel of $tree set to $code. */
    public function source(string $tree, string $rel, string $code): self
    {
        $trees = $this->trees;
        $trees[$tree][$rel] = $code;

        return new self($this->composer, $this->lock, $this->vetted, $this->doc, $trees);
    }

    /**
     * @param array<mixed> $data
     *
     * @return array<mixed>
     */
    private static function set(array $data, string $path, mixed $value): array
    {
        $segments = explode('.', $path);
        $key = array_shift($segments);
        if ($segments === []) {
            $data[$key] = $value;

            return $data;
        }
        $child = \is_array($data[$key] ?? null) ? $data[$key] : [];
        $data[$key] = self::set($child, implode('.', $segments), $value);

        return $data;
    }

    /** @return array<mixed> */
    private static function json(string $path): array
    {
        $data = json_decode((string) file_get_contents($path), true, 512, \JSON_THROW_ON_ERROR);
        Assert::assertIsArray($data, $path);

        return $data;
    }
}
