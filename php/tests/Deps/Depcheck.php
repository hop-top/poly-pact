<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Deps;

/**
 * Dependency guard of the package: the counterpart of go/internal/depcheck,
 * py/tests/test_depcheck.py and ts/test/depcheck.test.ts.
 *
 * The vetted sets are tests/testdata/deps-vetted.json; docs/sdk/deps-php.md
 * of the source repository is their human record. A package joins
 * composer.json or composer.lock only after a vet recorded in both.
 *
 * problems() is a pure function of the decoded composer.json, the decoded
 * composer.lock, the decoded vetted sets, the text of deps-php.md and the PHP
 * sources per tree (tree => relative path => code). It returns one line per
 * rule violation, none for a clean package.
 */
final class Depcheck
{
    /** An exact version as composer.json pins it: no range, no prefix, no stability flag. */
    private const EXACT = '/^\d+\.\d+\.\d+$/';

    /** The only dist and source hosts a locked package may come from. */
    private const DIST_URL = 'https://api.github.com/repos/';
    private const SOURCE_URL = 'https://github.com/';

    /**
     * @param array<mixed> $composer
     * @param array<mixed> $lock
     * @param array<mixed> $vetted
     * @param array<string, array<string, string>> $trees
     *
     * @return list<string>
     */
    public static function problems(array $composer, array $lock, array $vetted, string $doc, array $trees): array
    {
        $v = Vetted::from($vetted);

        return [
            ...self::manifest($composer, $v),
            ...self::locked($lock, $composer, $v),
            ...self::record($doc, $v),
            ...self::sources($trees, $v),
        ];
    }

    /**
     * composer.json: require and require-dev are the vetted pins, exact; the php
     * constraint is the floor; the ext-* set is the documented one; no
     * repositories; no plugins; the platform override is the vetted one.
     *
     * @param array<mixed> $composer
     *
     * @return list<string>
     */
    private static function manifest(array $composer, Vetted $v): array
    {
        $out = [];
        $require = self::strings($composer['require'] ?? []);
        $dev = self::strings($composer['require-dev'] ?? []);
        $php = $require['php'] ?? null;
        if ($php !== $v->php) {
            $out[] = sprintf('composer.json: php constraint %s != vetted %s', var_export($php, true), var_export($v->php, true));
        }
        $packages = [];
        $extensions = [];
        foreach ($require as $name => $constraint) {
            if ($name === 'php') {
                continue;
            }
            if (str_starts_with($name, 'ext-')) {
                $extensions[$name] = $constraint;
                continue;
            }
            $packages[$name] = $constraint;
        }
        foreach (self::diff($packages, $v->require) as $d) {
            $out[] = 'composer.json require: ' . $d;
        }
        foreach (self::diff($dev, $v->requireDev) as $d) {
            $out[] = 'composer.json require-dev: ' . $d;
        }
        foreach ([...$packages, ...$dev] as $name => $constraint) {
            if (preg_match(self::EXACT, $constraint) !== 1) {
                $out[] = sprintf('composer.json: %s %s is not an exact version', $name, $constraint);
            }
        }
        $names = array_keys($extensions);
        sort($names);
        if ($names !== $v->extensions) {
            $out[] = sprintf('composer.json: extensions [%s] != vetted [%s]', implode(', ', $names), implode(', ', $v->extensions));
        }
        foreach ($extensions as $name => $constraint) {
            if ($constraint !== '*') {
                $out[] = sprintf('composer.json: %s %s, want *', $name, $constraint);
            }
        }
        foreach (array_keys($dev) as $name) {
            if ($name === 'php' || str_starts_with($name, 'ext-')) {
                $out[] = sprintf('composer.json require-dev: platform requirement %s', $name);
            }
        }
        foreach (['repositories', 'minimum-stability', 'prefer-stable', 'replace', 'provide'] as $key) {
            if (\array_key_exists($key, $composer)) {
                $out[] = sprintf('composer.json: %s is set', $key);
            }
        }
        $config = \is_array($composer['config'] ?? null) ? $composer['config'] : [];
        if (($config['allow-plugins'] ?? null) !== false) {
            $out[] = 'composer.json: config.allow-plugins is not false';
        }
        foreach (self::diff(self::strings($config['platform'] ?? []), $v->platform) as $d) {
            $out[] = 'composer.json config.platform: ' . $d;
        }

        return $out;
    }

    /**
     * composer.lock: each section holds exactly the vetted packages at the
     * vetted versions, each from GitHub and none a plugin; the lock's
     * platform and stability fields match composer.json.
     *
     * @param array<mixed> $lock
     * @param array<mixed> $composer
     *
     * @return list<string>
     */
    private static function locked(array $lock, array $composer, Vetted $v): array
    {
        $out = [];
        foreach (['packages' => $v->packages, 'packages-dev' => $v->packagesDev] as $section => $want) {
            $got = [];
            $entries = \is_array($lock[$section] ?? null) ? $lock[$section] : [];
            foreach ($entries as $i => $p) {
                if (!\is_array($p) || !\is_string($p['name'] ?? null) || !\is_string($p['version'] ?? null)) {
                    $out[] = sprintf('composer.lock %s[%s]: no name or version', $section, $i);
                    continue;
                }
                $name = $p['name'];
                $got[$name] = $p['version'];
                $dist = \is_array($p['dist'] ?? null) ? $p['dist'] : [];
                $url = \is_string($dist['url'] ?? null) ? $dist['url'] : '';
                if (($dist['type'] ?? null) !== 'zip' || !str_starts_with($url, self::DIST_URL)) {
                    $out[] = sprintf('composer.lock %s: %s dist is not a GitHub zip', $section, $name);
                }
                if (\array_key_exists('source', $p)) {
                    $source = \is_array($p['source']) ? $p['source'] : [];
                    $surl = \is_string($source['url'] ?? null) ? $source['url'] : '';
                    if (($source['type'] ?? null) !== 'git' || !str_starts_with($surl, self::SOURCE_URL)) {
                        $out[] = sprintf('composer.lock %s: %s source is not a GitHub git repository', $section, $name);
                    }
                }
                if (($p['type'] ?? 'library') === 'composer-plugin' || \array_key_exists('transport-options', $p)) {
                    $out[] = sprintf('composer.lock %s: %s is a plugin or has transport options', $section, $name);
                }
            }
            foreach (self::diff($got, $want) as $d) {
                $out[] = sprintf('composer.lock %s: %s', $section, $d);
            }
        }
        $locked = self::unprefixed([...$v->packages, ...$v->packagesDev]);
        foreach ([...$v->require, ...$v->requireDev] as $name => $version) {
            if (($locked[$name] ?? null) !== $version) {
                $out[] = sprintf('composer.lock: %s is pinned %s, locked %s', $name, $version, $locked[$name] ?? 'nowhere');
            }
        }
        $require = self::strings($composer['require'] ?? []);
        $platform = array_filter($require, static fn(string $n): bool => $n === 'php' || str_starts_with($n, 'ext-'), \ARRAY_FILTER_USE_KEY);
        foreach (self::diff(self::strings($lock['platform'] ?? []), $platform) as $d) {
            $out[] = 'composer.lock platform: ' . $d;
        }
        foreach (self::diff(self::strings($lock['platform-overrides'] ?? []), $v->platform) as $d) {
            $out[] = 'composer.lock platform-overrides: ' . $d;
        }
        if (($lock['minimum-stability'] ?? null) !== 'stable') {
            $out[] = 'composer.lock: minimum-stability is not stable';
        }
        foreach (['aliases', 'stability-flags', 'platform-dev'] as $key) {
            if (($lock[$key] ?? []) !== []) {
                $out[] = sprintf('composer.lock: %s is not empty', $key);
            }
        }

        return $out;
    }

    /**
     * deps-php.md: the Runtime table lists the locked runtime packages, the
     * Development and Transitive tables the locked development packages, each
     * at the vetted version; the floor and the runtime extension set read as
     * the vetted ones.
     *
     * @return list<string>
     */
    private static function record(string $doc, Vetted $v): array
    {
        $out = [];
        $runtime = self::rows(self::section($doc, '### Runtime', '### Development'), 'Packagist ', 3);
        $development = self::rows(self::section($doc, '### Development', '## Comparisons'), 'Packagist ', 3);
        $transitive = self::rows(self::section($doc, '### Transitive packages', 'Notes on the results'), '', 2);
        foreach (self::diff(self::unprefixed($runtime), self::unprefixed($v->packages)) as $d) {
            $out[] = 'deps-php.md runtime: ' . $d;
        }
        $both = array_intersect_key($development, $transitive);
        if ($both !== []) {
            $out[] = 'deps-php.md: in both the Development and Transitive tables: ' . implode(', ', array_keys($both));
        }
        foreach (self::diff(self::unprefixed([...$transitive, ...$development]), self::unprefixed($v->packagesDev)) as $d) {
            $out[] = 'deps-php.md development: ' . $d;
        }
        foreach ([...$v->require, ...$v->requireDev] as $name => $version) {
            if (!isset($runtime[$name]) && !isset($development[$name])) {
                $out[] = sprintf('deps-php.md: %s has no row in the Runtime or Development table', $name);
            }
        }
        $floor = preg_match('/the floor is ([0-9.]+): `php` `([^`]+)` in `require`, `config\.platform\.php` `([^`]+)`/', $doc, $m) === 1
            ? ['php' => $m[2], 'platform' => $m[3], 'minor' => $m[1]] : null;
        $minor = preg_match('/^>=(\d+\.\d+)$/', $v->php, $fm) === 1 ? $fm[1] : null;
        if ($floor === null || $floor['php'] !== $v->php || $floor['platform'] !== ($v->platform['php'] ?? null) || $floor['minor'] !== $minor) {
            $out[] = sprintf('deps-php.md: the floor line does not read php %s, platform %s', $v->php, $v->platform['php'] ?? '?');
        }
        if (preg_match('/^- Runtime set: (.*?) \(from `php\/composer\.json`\)/m', $doc, $m) === 1) {
            preg_match_all('/`(ext-[a-z0-9_]+)`/', $m[1], $all);
            $ext = $all[1];
            sort($ext);
            if ($ext !== $v->extensions) {
                $out[] = sprintf('deps-php.md: runtime extensions [%s] != vetted [%s]', implode(', ', $ext), implode(', ', $v->extensions));
            }
        } else {
            $out[] = 'deps-php.md: no "Runtime set" line';
        }

        return $out;
    }

    /**
     * Namespaced names each tree imports (use statements) or names fully
     * qualified: its own vetted namespaces and PHP's built-in ones only.
     * Over-matching can only make the guard stricter.
     *
     * @param array<string, array<string, string>> $trees
     *
     * @return list<string>
     */
    private static function sources(array $trees, Vetted $v): array
    {
        $out = [];
        $builtin = self::builtinNamespaces();
        foreach ($trees as $tree => $files) {
            $allowed = $v->namespaces[$tree] ?? null;
            if ($allowed === null) {
                $out[] = sprintf('%s: no vetted namespaces', $tree);
                continue;
            }
            ksort($files);
            foreach ($files as $rel => $code) {
                foreach (self::names($code) as [$name, $line]) {
                    if (\in_array(explode('\\', $name)[0], $builtin, true)) {
                        continue;
                    }
                    $ok = false;
                    foreach ($allowed as $prefix) {
                        if ($name === $prefix || str_starts_with($name, $prefix . '\\')) {
                            $ok = true;
                            break;
                        }
                    }
                    if (!$ok) {
                        $out[] = sprintf('%s/%s:%d: %s outside the vetted namespaces of %s', $tree, $rel, $line, $name, $tree);
                    }
                }
            }
        }

        return $out;
    }

    /**
     * The absolute namespaced names of one file, with their lines: the
     * imports of top-level use statements (group uses expanded, J\{K, L} as
     * J\K and J\L) and every fully qualified name with a namespace part.
     *
     * @return list<array{string, int}>
     */
    public static function names(string $code): array
    {
        $out = [];
        $depth = 0;
        $inUse = false;  // inside a top-level use statement
        $expect = false; // the next name is an import
        $group = null;   // the prefix of the group use being read
        $last = null;    // the import just read, while a \{ may follow
        foreach (token_get_all($code) as $t) {
            if (\is_array($t) && $t[0] === \T_WHITESPACE) {
                continue;
            }
            if (\is_string($t)) {
                if ($inUse && $t === '{' && $last !== null) {
                    $group = $last[0];
                    $last = null;
                    $expect = true;
                    continue;
                }
                if ($last !== null) {
                    self::import($out, $last[0], $last[1]);
                    $last = null;
                }
                if ($t === '{') {
                    ++$depth;
                } elseif ($t === '}') {
                    if ($group !== null) {
                        $group = null;
                    } else {
                        --$depth;
                    }
                } elseif ($t === ';') {
                    $inUse = $expect = false;
                } elseif ($t === ',' && $inUse) {
                    $expect = true;
                }
                continue;
            }
            [$id, $text, $line] = $t;
            if ($id === \T_NS_SEPARATOR && $last !== null) {
                continue; // J\ before {: decided by the next token
            }
            if ($last !== null) {
                self::import($out, $last[0], $last[1]);
                $last = null;
            }
            if ($id === \T_CURLY_OPEN || $id === \T_DOLLAR_OPEN_CURLY_BRACES) {
                ++$depth;
                continue;
            }
            if ($id === \T_USE && $depth === 0) {
                $inUse = $expect = true;
                continue;
            }
            if ($inUse && $expect && ($id === \T_STRING || $id === \T_NAME_QUALIFIED || $id === \T_NAME_FULLY_QUALIFIED)) {
                $name = ltrim($text, '\\');
                $expect = false;
                if ($group !== null) {
                    self::import($out, $group . '\\' . $name, $line);
                } else {
                    $last = [$name, $line];
                }
                continue;
            }
            if ($id === \T_NAME_FULLY_QUALIFIED) {
                self::import($out, ltrim($text, '\\'), $line);
            }
        }
        if ($last !== null) {
            self::import($out, $last[0], $last[1]);
        }

        return $out;
    }

    /**
     * Adds $name to $out when it has a namespace part.
     *
     * @param list<array{string, int}> $out
     */
    private static function import(array &$out, string $name, int $line): void
    {
        if (str_contains($name, '\\')) {
            $out[] = [$name, $line];
        }
    }

    /** @return list<string> the top-level namespaces of PHP's built-in classes, interfaces, traits and functions */
    private static function builtinNamespaces(): array
    {
        $names = [...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()];
        $top = [];
        foreach ($names as $n) {
            if (str_contains($n, '\\') && (new \ReflectionClass($n))->isInternal()) {
                $top[explode('\\', $n)[0]] = true;
            }
        }
        foreach (get_defined_functions()['internal'] as $f) {
            if (str_contains($f, '\\')) {
                $top[explode('\\', $f)[0]] = true;
            }
        }

        return array_keys($top);
    }

    /** The text between the first $from heading and the next $to marker, or "". */
    private static function section(string $doc, string $from, string $to): string
    {
        $start = strpos($doc, "\n" . $from . "\n");
        if ($start === false) {
            return '';
        }
        $end = strpos($doc, $to, $start + \strlen($from) + 2);

        return $end === false ? substr($doc, $start) : substr($doc, $start, $end - $start);
    }

    /**
     * Package => version of the table rows of $text: the package is the first
     * code span of cell 1 after $prefix, the version the first code span of
     * cell $col. Pipes escaped as \| do not split cells.
     *
     * @return array<string, string>
     */
    private static function rows(string $text, string $prefix, int $col): array
    {
        $out = [];
        foreach (explode("\n", $text) as $line) {
            if (!str_starts_with($line, '| ' . $prefix . '`')) {
                continue;
            }
            $cells = preg_split('/(?<!\\\\)\|/', $line);
            if ($cells === false || \count($cells) <= $col) {
                continue;
            }
            if (preg_match('/`([^`]+)`/', $cells[1], $n) === 1 && preg_match('/`([^`]+)`/', $cells[$col], $ver) === 1) {
                $out[$n[1]] = $ver[1];
            }
        }

        return $out;
    }

    /**
     * Differences of two name => version maps, one line per name.
     *
     * @param array<string, string> $got
     * @param array<string, string> $want
     *
     * @return list<string>
     */
    private static function diff(array $got, array $want): array
    {
        $out = [];
        foreach ($got as $name => $version) {
            if (!\array_key_exists($name, $want)) {
                $out[] = sprintf('%s %s is not vetted', $name, $version);
            } elseif ($want[$name] !== $version) {
                $out[] = sprintf('%s %s, vetted %s', $name, $version, $want[$name]);
            }
        }
        foreach ($want as $name => $version) {
            if (!\array_key_exists($name, $got)) {
                $out[] = sprintf('%s %s is missing', $name, $version);
            }
        }
        sort($out);

        return $out;
    }

    /**
     * $map with one leading "v" dropped from each version: Composer reads
     * v3.95.27 and 3.95.27 as the same version.
     *
     * @param array<string, string> $map
     *
     * @return array<string, string>
     */
    private static function unprefixed(array $map): array
    {
        return array_map(static fn(string $ver): string => preg_replace('/^v(?=\\d)/', '', $ver) ?? $ver, $map);
    }

    /**
     * The string => string entries of a decoded JSON object.
     *
     * @return array<string, string>
     */
    public static function strings(mixed $map): array
    {
        $out = [];
        if (\is_array($map)) {
            foreach ($map as $k => $val) {
                $out[(string) $k] = \is_string($val) ? $val : var_export($val, true);
            }
        }

        return $out;
    }
}
