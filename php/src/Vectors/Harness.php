<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

/**
 * Shared-vector harness: `php scripts/vectors.php [MANIFEST]`, which
 * `composer run-script vectors` runs.
 *
 * Prints one NDJSON line per manifest entry, {"id","kind","result"}, and
 * nothing else on standard output: the counterpart of `pactconf vectors
 * verify --ndjson`, with the result grammar of tools/parity/README.md
 * of the source repository. Plain argv, no command-line
 * framework: make php-vectors and make parity drive it.
 *
 * MANIFEST defaults to ../spec/v1.0/fixtures/manifest.json beside the
 * package directory. When the default is absent (a mirror checkout) the
 * harness prints a NOTICE on standard error and succeeds, unless
 * PACT_REQUIRE_VECTORS=1 makes the absence an error.
 *
 * Every vector, key and schema entry of scope core runs through the runner of its
 * group (Groups) and is compared with its outcome and expected file: pass
 * or fail. An entry that lists a capability the harness does not declare is
 * skipped:capability; every other entry (scope runner, scope adapter, a kind
 * the harness does not run) is skipped:out-of-scope, and so are the Ed25519
 * key and a spec defect of the digest protocol (skipped:spec-defect).
 *
 * Exit status: 0 when no entry fails under a gate required for php; 1 when
 * one does; 2 on a harness error (usage, unreadable or malformed manifest or
 * gates file, unknown kind, scope, prefix or capability, duplicate id),
 * which prints nothing on standard output.
 */
final class Harness
{
    /**
     * @param list<string>   $argv the arguments after the program name
     * @param resource|null  $out  standard output
     * @param resource|null  $err  standard error
     */
    public static function main(array $argv, $out = null, $err = null): int
    {
        $out ??= \STDOUT;
        $err ??= \STDERR;
        if (\count($argv) > 1 || ($argv !== [] && str_starts_with($argv[0], '-'))) {
            fwrite($err, "usage: php scripts/vectors.php [MANIFEST]\n");

            return 2;
        }
        $path = $argv[0] ?? \dirname(__DIR__, 3) . '/spec/v1.0/fixtures/manifest.json';
        if ($argv === [] && !file_exists($path) && getenv('PACT_REQUIRE_VECTORS') !== '1') {
            fwrite($err, \sprintf("NOTICE: vectors skipped: %s absent\n", $path));

            return 0;
        }
        try {
            return self::run($path, $out, $err);
        } catch (HarnessError $e) {
            fwrite($err, 'vectors: ' . $e->getMessage() . "\n");

            return 2;
        }
    }

    /**
     * @param resource $out
     * @param resource $err
     */
    public static function run(string $path, $out, $err): int
    {
        $entries = self::loadManifest($path);
        $gp = Gates::pathFor($path);
        $gates = $gp !== null && is_file($gp) ? Gates::load($gp) : null;
        if ($gates === null) {
            fwrite($err, \sprintf("NOTICE: no gates file beside %s: no gate is required\n", $path));
        }
        $root = \dirname($path);
        $lines = [];
        $count = ['pass' => 0, 'fail' => 0];
        $skipped = [Skipped::OUT_OF_SCOPE => 0, Skipped::SPEC_DEFECT => 0, Skipped::CAPABILITY => 0];
        $blocking = 0;
        foreach ($entries as $e) {
            [$line, $detail] = self::entry($root, $e);
            $result = $line['result'];
            if (str_starts_with($result, 'skipped:')) {
                $skipped[substr($result, 8)] = ($skipped[substr($result, 8)] ?? 0) + 1;
            } else {
                $count[$result]++;
            }
            if (Groups::runs($e) && $result !== 'pass') {
                fwrite($err, \sprintf("%s %s: %s\n", $result === 'fail' ? 'FAIL' : 'SKIP', $e->id, preg_replace('/\s+/', ' ', trim($detail))));
            }
            if ($result === 'fail' && $gates !== null && $gates->blocks($e)) {
                $blocking++;
            }
            $lines[] = json_encode($line, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR) . "\n";
        }
        fwrite($out, implode('', $lines));
        fwrite($err, \sprintf(
            "vectors: %d passed, %d failed, %d skipped (out-of-scope %d, spec-defect %d, capability %d); %d failed under a required gate\n",
            $count['pass'],
            $count['fail'],
            array_sum($skipped),
            $skipped[Skipped::OUT_OF_SCOPE],
            $skipped[Skipped::SPEC_DEFECT],
            $skipped[Skipped::CAPABILITY],
            $blocking,
        ));

        return $blocking > 0 ? 1 : 0;
    }

    /**
     * Read the manifest at $path through the manifest module and check what
     * the harness relies on: its strict parse, then the rules of the members
     * the harness reads (shape, id, duplicate id, kind, scope, capabilities),
     * and a known group for every core entry it runs. Each is a harness
     * error. The other field rules, completeness and the spec-map checks
     * belong to the Go manifest check (pactfix check manifest).
     *
     * @return list<Entry>
     */
    public static function loadManifest(string $path): array
    {
        $entries = Manifest::load($path);
        foreach ($entries as $e) {
            if ($e->scope === 'core' && Groups::runs($e)) {
                Groups::runner($e);
            }
        }

        return $entries;
    }

    /**
     * The NDJSON line of $e and the detail of a row that is not a pass.
     *
     * @return array{array{id: string, kind: string, result: string, spec_defects?: list<array<string, string>>, missing_capabilities?: list<string>}, string}
     */
    private static function entry(string $root, Entry $e): array
    {
        $line = ['id' => $e->id, 'kind' => $e->kind, 'result' => 'pass'];
        if (!Groups::runs($e)) {
            $line['result'] = 'skipped:' . Skipped::OUT_OF_SCOPE;

            return [$line, ''];
        }
        $missing = array_values(array_diff($e->capabilities ?? [], Groups::DECLARED_CAPABILITIES));
        try {
            if ($missing !== []) {
                throw new Skipped(Skipped::CAPABILITY, \sprintf('optional capability %s not declared: the entry is not run', implode(', ', $missing)), [], $missing);
            }
            Groups::runner($e)->run($root, $e);
        } catch (Skipped $s) {
            $line['result'] = 'skipped:' . $s->reason;
            if ($s->defects !== []) {
                $line['spec_defects'] = $s->defects;
            }
            if ($s->missing !== []) {
                $line['missing_capabilities'] = $s->missing;
            }

            return [$line, $s->getMessage()];
        } catch (HarnessError $h) {
            throw $h;
        } catch (\Throwable $t) {
            $line['result'] = 'fail';

            return [$line, $t->getMessage() !== '' ? $t->getMessage() : $t::class];
        }

        return [$line, ''];
    }
}
