<?php // Q3b: json_decode $depth semantics, parser stack limit, the null/error ambiguity without JSON_THROW_ON_ERROR, and the depth vectors at $depth 16, 17, 18.
$try = function (string $t, int $depth) { try { json_decode($t, true, $depth, JSON_THROW_ON_ERROR); return 'ok'; } catch (Throwable $e) { return get_class($e) === 'JsonException' ? $e->getMessage() : get_class($e) . ': ' . $e->getMessage(); } };
$need = function (string $s) use ($try) { for ($d = 1; $d < 9; $d++) if ($try($s, $d) === 'ok') return $d; };
foreach (['1', '[]', '[[]]', '[1]', '{}', '{"a":{}}'] as $s) echo str_pad($s, 10), ' needs $depth ', $need($s), "\n";
foreach ([100, 1000, 5000, 100000] as $n) { $s = str_repeat('[', $n) . str_repeat(']', $n); echo "$n nested arrays: depth 512 -> ", $try($s, 512), ' | depth 2147483647 -> ', $try($s, 2147483647), "\n"; }
echo 'depth 0 -> ', $try('[]', 0), ' | depth PHP_INT_MAX -> ', $try('[]', PHP_INT_MAX), "\n";
foreach (glob(dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/strictjson/*depth*.json') as $f) {
    $v = json_decode(file_get_contents($f), true); echo str_pad(basename($f, '.json'), 28), 'expect ', $v['expect'], ' | depth 16: ', $try($v['input_text'], 16), ' | depth 17: ', $try($v['input_text'], 17), ' | depth 18: ', $try($v['input_text'], 18), "\n";
}
echo 'without THROW: json_decode("null") = ', var_export(json_decode('null'), true), ' json_last_error ', json_last_error(), ' | json_decode("nul") = ', var_export(json_decode('nul'), true), ' json_last_error ', json_last_error(), ' (', json_last_error_msg(), ")\n";
json_decode('{'); json_decode('[]', false, 512, JSON_THROW_ON_ERROR); echo 'json_last_error after a THROW-flag success that follows a failure: ', json_last_error(), "\n";
