<?php // Q4: PHP float text vs RFC 8785 numbers. json_encode, var_export, strval vs in-house es_num: Appendix B rows, the 10000-line fixture, 500k random doubles. Optional argv[1]: dump file for a Node cross-check.
require __DIR__ . '/esnum.php';
$fx = json_decode(file_get_contents(dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/jcs/numbers.json'), true); $want = array_column($fx, 'expected', 'ieee754_hex'); $dbl = fn($h) => unpack('E', hex2bin($h))[1]; // big-endian binary64
$F = ['json_encode' => 'json_encode', 'var_export' => fn($x) => var_export($x, true), 'strval' => 'strval', 'es_num' => 'es_num']; $ini = 'serialize_precision=' . ini_get('serialize_precision') . ' precision=' . ini_get('precision');
$B = explode(' ', '0000000000000000 8000000000000000 0000000000000001 8000000000000001 7fefffffffffffff ffefffffffffffff 4340000000000000 c340000000000000 4430000000000000 44b52d02c7e14af5 44b52d02c7e14af6 44b52d02c7e14af7 444b1ae4d6e2ef4e 444b1ae4d6e2ef4f 444b1ae4d6e2ef50 3eb0c6f7a0b5ed8c 3eb0c6f7a0b5ed8d 41b3de4355555553 41b3de4355555554 41b3de4355555555 41b3de4355555556 41b3de4355555557 becbf647612f3696 43143ff3c1cb0959');
$rows = array_map(fn($h) => [$h, $dbl($h), $want[$h]], $B); foreach ([[1e21, '1e+21'], [1e-7, '1e-7'], [-0.0, '0'], [4.5, '4.5'], [1E30, '1e+30'], [1.0, '1'], [100.0, '100'], [1e16, '10000000000000000']] as [$x, $w]) $rows[] = ['literal', $x, $w];
echo "$ini\n"; foreach ($rows as [$h, $x, $w]) { printf('%-17s want=%-26s', $h, $w); foreach ($F as $n => $f) printf(' %s=%-26s%s', $n, $f($x), $f($x) === $w ? '' : '*'); echo "\n"; }
$fxr = array_map(fn($e) => [$e['ieee754_hex'], $dbl($e['ieee754_hex']), $e['expected']], $fx);
foreach ([['Appendix B rows and literals', $rows], ['numbers.json', $fxr]] as [$name, $set]) { echo "$name: ", count($set), ' rows, mismatches'; foreach ($F as $n => $f) echo " $n ", count(array_filter($set, fn($r) => $f($r[1]) !== $r[2])); echo "\n"; }
mt_srand(0); $r = []; $b = fn() => $dbl(bin2hex(pack('NN', mt_rand(0, 4294967295), mt_rand(0, 4294967295))));
for ($i = 0; $i < 300000; $i++) if (is_finite($x = $b())) $r[] = $x; for ($i = 0; $i < 100000; $i++) { $r[] = mt_rand() / mt_getrandmax() * 2e9 - 1e9; $r[] = (float) mt_rand(-2 ** 53, 2 ** 53); }
$es = array_map('es_num', $r); echo 'random doubles ', count($r), ': float(es_num(x)) === x for ', count(array_filter($r, fn($x, $i) => (float) $es[$i] === $x, ARRAY_FILTER_USE_BOTH));
foreach (['json_encode', 'var_export'] as $n) echo " | $n equals es_num for ", count(array_filter($r, fn($x, $i) => $F[$n]($x) === $es[$i], ARRAY_FILTER_USE_BOTH));
echo "\n"; if (isset($argv[1])) file_put_contents($argv[1], implode("\n", array_map(fn($x, $s) => bin2hex(pack('E', $x)) . ' ' . $s, $r, $es)) . "\n");
