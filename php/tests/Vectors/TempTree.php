<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Vectors;

/** A scratch fixture directory for harness group tests, removed by clean(). */
final class TempTree
{
    public readonly string $dir;

    /** @var list<string> */
    private array $files = [];

    public function __construct(string $name)
    {
        $this->dir = sys_get_temp_dir() . '/pact-php-' . $name . '-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    /** Write $content (a string, or a value written as JSON) to $rel; return $rel. */
    public function file(string $rel, mixed $content): string
    {
        $path = $this->dir . '/' . $rel;
        if (!is_dir(\dirname($path))) {
            mkdir(\dirname($path), 0o777, true);
        }
        file_put_contents($path, \is_string($content) ? $content : json_encode($content, \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR));
        $this->files[] = $path;

        return $rel;
    }

    public function clean(): void
    {
        foreach (array_unique($this->files) as $f) {
            @unlink($f);
        }
        $dirs = [];
        foreach ($this->files as $f) {
            for ($d = \dirname($f); \strlen($d) > \strlen($this->dir); $d = \dirname($d)) {
                $dirs[$d] = true;
            }
        }
        $dirs = array_keys($dirs);
        usort($dirs, static fn(string $a, string $b): int => \strlen($b) <=> \strlen($a));
        foreach ($dirs as $d) {
            @rmdir($d);
        }
        @rmdir($this->dir);
    }
}
