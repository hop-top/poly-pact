<?php // Q4c: es_num at binade boundaries (where the shortest-digits interval is asymmetric): every 2^k, k = -1074..1023, and its two neighbours, both signs. Optional argv[1]: dump file for a Node cross-check.
require __DIR__ . '/esnum.php';
$f = fn(int $bits) => unpack('E', pack('J', $bits))[1]; $bits = fn(float $x) => unpack('J', pack('E', $x))[1]; // pack('J') and pack('E') are big-endian 64-bit
$pw = fn(int $k) => $f($k < -1022 ? 1 << ($k + 1074) : ($k + 1023) << 52); $xs = [];
for ($k = -1074; $k <= 1023; $k++) foreach ([0, 1, -1] as $d) if (is_finite($x = $f($bits($pw($k)) + $d)) && $x > 0) array_push($xs, $x, -$x);
$es = array_map('es_num', $xs);
echo 'values ', count($xs), ' | float(es_num(x)) === x for ', count(array_filter($xs, fn($x, $i) => (float) $es[$i] === $x, ARRAY_FILTER_USE_BOTH)), ' | significant digits histogram: ', json_encode(array_count_values(array_map(fn($s) => strlen(rtrim(preg_replace('/e.*$|[^0-9]/', '', ltrim($s, '-0.')), '0')), $es)), JSON_FORCE_OBJECT), "\n";
echo '2^-1074 ', es_num($pw(-1074)), ' | 2^53 ', es_num($pw(53)), ' | 2^70 ', es_num($pw(70)), ' | 2^-20 ', es_num($pw(-20)), ' | 2^1023 ', es_num($pw(1023)), "\n";
if (isset($argv[1])) file_put_contents($argv[1], implode("\n", array_map(fn($x, $s) => bin2hex(pack('E', $x)) . ' ' . $s, $xs, $es)) . "\n");
