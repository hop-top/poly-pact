<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

use HopTop\Pact\Core\JsonObject;

/**
 * The php column of the parity gates (tools/parity/gates.json of the source
 * repository; docs/sdk/ports-plan.md section 5.3).
 *
 * The harness exits 1 on a fail under a gate required for php; a fail under
 * any other gate value is printed and counted. Without the gates file (a mirror
 * checkout, a copy of the spec tree) no gate is required.
 */
final class Gates
{
    public const LANGUAGE = 'php';

    /** @var list<string> the gate values of the file format, every column */
    public const VALUES = ['required', 'planned', 'n/a'];

    /**
     * @param array<string, array{value: string, exceptions: list<string>}> $rows by "scope kind prefix"
     */
    private function __construct(private readonly array $rows) {}

    /**
     * tools/parity/gates.json of the repository of $manifest, which is
     * ROOT/spec/v1.0/fixtures/manifest.json.
     */
    public static function pathFor(string $manifest): ?string
    {
        $real = realpath($manifest);
        if ($real === false) {
            return null;
        }

        return \dirname($real, 4) . '/tools/parity/gates.json';
    }

    public static function load(string $path): self
    {
        $data = @file_get_contents($path);
        if ($data === false) {
            throw new HarnessError(\sprintf('%s: cannot be read', $path));
        }
        try {
            $doc = Fixtures::parseJson($data);
        } catch (\UnexpectedValueException $e) {
            throw new HarnessError(\sprintf('%s: %s', $path, $e->getMessage()), 0, $e);
        }
        $rows = $doc instanceof JsonObject ? $doc->get('rows') : null;
        if (!\is_array($rows)) {
            throw new HarnessError(\sprintf('%s: rows is not an array', $path));
        }
        $out = [];
        foreach ($rows as $i => $r) {
            $bad = !$r instanceof JsonObject;
            $key = [];
            $exc = [];
            $value = null;
            if ($r instanceof JsonObject) {
                foreach (['scope', 'kind', 'prefix'] as $k) {
                    $key[] = $r->get($k);
                }
                $value = $r->get(self::LANGUAGE);
                $raw = $r->get('exceptions', []);
                $bad = !\is_array($raw);
                foreach (\is_array($raw) ? $raw : [] as $x) {
                    if (!$x instanceof JsonObject || !\is_string($x->get('id'))) {
                        $bad = true;
                        continue;
                    }
                    $exc[] = $x->get('id');
                }
            }
            if ($bad || \count(array_filter($key, 'is_string')) !== 3 || !\in_array($value, self::VALUES, true)) {
                throw new HarnessError(\sprintf('%s: rows[%d] is not a gate row with a %s value', $path, $i, self::LANGUAGE));
            }
            /** @var list<string> $key */
            /** @var string $value */
            /** @var list<string> $exc */
            $out[implode(' ', $key)] = ['value' => $value, 'exceptions' => $exc];
        }

        return new self($out);
    }

    /** Whether a fail of $e blocks the run: its gate is required and lists no exception for it. */
    public function blocks(Entry $e): bool
    {
        $g = $this->rows[$e->scope . ' ' . $e->kind . ' ' . Groups::prefix($e)] ?? null;

        return $g !== null && $g['value'] === 'required' && !\in_array($e->id, $g['exceptions'], true);
    }
}
