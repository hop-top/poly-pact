<?php // Q3e: cost and failure modes of strict_decode (json_decode + regex token scan) at the 256 KiB presentation limit and 16x larger; pcre.jit is read, not changed.
require __DIR__ . '/strict.php';
$docs = ['one 256 KiB string' => '{"k":"' . str_repeat('a\\"b', 65536) . '"}', 'one 4 MiB string' => '{"k":"' . str_repeat('a\\"b', 1048576) . '"}', '10000 short keys' => '{' . implode(',', array_map(fn($i) => "\"key$i\":$i", range(1, 10000))) . '}',
    '160000 short keys' => '{' . implode(',', array_map(fn($i) => "\"key$i\":$i", range(1, 160000))) . '}', '40000 floats' => '[' . implode(',', array_map(fn($i) => $i . '.5e3', range(1, 40000))) . ']',
    '640000 floats' => '[' . implode(',', array_map(fn($i) => $i . '.5e3', range(1, 640000))) . ']', 'whitespace around {}' => str_repeat(' ', 130000) . '{}' . str_repeat("\n", 130000)];
echo 'pcre.jit=', ini_get('pcre.jit'), ' pcre.backtrack_limit=', ini_get('pcre.backtrack_limit'), ' pcre.jit enabled in this build: ', var_export((bool) preg_match('/a/', 'a') && PCRE_JIT_SUPPORT, true), ' memory_limit=', ini_get('memory_limit'), "\n";
foreach ($docs as $name => $t) {
    memory_reset_peak_usage(); $m0 = memory_get_usage(); $t0 = hrtime(true); $r = 'ok';
    try { json_decode($t, true, 17, JSON_THROW_ON_ERROR); $t1 = hrtime(true); strict_scan($t); } catch (Throwable $e) { $r = get_class($e) . ': ' . $e->getMessage(); $t1 = $t1 ?? hrtime(true); }
    printf("%-34s %8d bytes  json_decode %6.1f ms  scan %7.1f ms  peak +%5.1f MB  %s%s\n", $name, strlen($t), ($t1 - $t0) / 1e6, (hrtime(true) - $t1) / 1e6, (memory_get_peak_usage() - $m0) / 1e6, $r, preg_last_error() ? ' preg: ' . preg_last_error_msg() : '');
}
