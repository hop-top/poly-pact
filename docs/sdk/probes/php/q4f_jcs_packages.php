<?php // Q4f: three Packagist RFC 8785 packages against the fixtures. Usage: php q4f_jcs_packages.php <root23 dir> <mmccook dir> <kanon dir> (each a composer project dir with vendor/).
foreach (array_slice($argv, 1, 3) as $d) require "$d/vendor/autoload.php";
$P = ['root23 1.0.1' => fn($v) => (new Root23\JsonCanonicalizer\JsonCanonicalizer())->canonicalize($v), 'mmccook 1.0.0' => fn($v) => Mmccook\JsonCanonicalizator\JsonCanonicalizatorFactory::getInstance()->canonicalize($v), 'kanon v1.0.1' => fn($v) => Truschery\Kanon\Json::canonicalize($v)];
$dir = dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/jcs'; $fx = json_decode(file_get_contents("$dir/numbers.json"), true); $out = fn(callable $f, mixed $v) => (function () use ($f, $v) { try { return $f($v); } catch (Throwable $e) { return 'raises ' . get_class($e); } })();
foreach ($P as $name => $f) {
    $ok = 0; $bad = []; foreach (glob("$dir/input/*.json") as $p) { $r = $out($f, json_decode(file_get_contents($p))); $w = file_get_contents(str_replace('/input/', '/output/', $p)); if ($r === $w) $ok++; else $bad[] = basename($p, '.json'); }
    $nb = []; foreach ($fx as $e) { $x = unpack('E', hex2bin($e['ieee754_hex']))[1]; if (($r = $out($f, $x)) !== $e['expected']) $nb[] = "$r (want {$e['expected']})"; }
    echo "$name: RFC pairs $ok of 6", $bad ? ' (fail: ' . implode(', ', $bad) . ')' : '', ' | numbers.json mismatches ', count($nb), ' of ', count($fx), ' e.g. ', implode(' ; ', array_slice($nb, 0, 3)), "\n";
    echo '    edge: 100.0 -> ', $out($f, 100.0), ' | 1e21 -> ', $out($f, 1e21), ' | NAN -> ', $out($f, NAN), ' | INF -> ', $out($f, INF), ' | 2^53 (int) -> ', $out($f, 2 ** 53), ' | PHP_INT_MAX -> ', $out($f, PHP_INT_MAX), ' | "\xff" -> ', $out($f, "\xff"), ' | {} -> ', $out($f, new stdClass), ' | [] -> ', $out($f, []), "\n";
}
