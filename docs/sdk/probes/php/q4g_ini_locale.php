<?php // Q4g: do process-wide settings change number text? numbers.json (10000 rows) with json_encode vs es_num under serialize_precision / precision set at runtime and under a non-C LC_NUMERIC locale.
require __DIR__ . '/esnum.php';
$fx = json_decode(file_get_contents(dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/jcs/numbers.json'), true); $xs = array_map(fn($e) => [unpack('E', hex2bin($e['ieee754_hex']))[1], $e['expected']], $fx);
$bad = fn(callable $f) => count(array_filter($xs, fn($r) => $f($r[0]) !== $r[1]));
$row = fn(string $label) => printf("%-46s json_encode mismatches %5d | var_export %5d | es_num %d | json_encode(0.1) %s | es_num(0.1) %s | sprintf('%%.3e', 1.5) %s\n", $label, $bad('json_encode'), $bad(fn($x) => var_export($x, true)), $bad('es_num'), json_encode(0.1), es_num(0.1), sprintf('%.3e', 1.5));
$row('defaults (' . ini_get('serialize_precision') . ', precision ' . ini_get('precision') . ')');
foreach (['serialize_precision' => ['17', '14', '-1'], 'precision' => ['17', '-1']] as $k => $vs) foreach ($vs as $v) { $old = ini_set($k, $v); $row("ini_set('$k', '$v') (was '$old')"); ini_set($k, $old); }
foreach (['de_DE.UTF-8', 'fr_FR.UTF-8'] as $l) { $got = setlocale(LC_ALL, $l); $row("setlocale(LC_ALL, '$l') => " . var_export($got, true)); }
echo 'locale-dependent in the same process: sprintf("%.1f", 1.5) = ', sprintf('%.1f', 1.5), ' | sprintf("%.1F", 1.5) = ', sprintf('%.1F', 1.5), ' | number_format(1.5, 1) = ', number_format(1.5, 1), "\n";
