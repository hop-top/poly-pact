<?php // Q4b: RFC 8785 input/output pairs through jcs() (json_decode object mode) vs the obvious PHP route (assoc decode, ksort, json_encode); key order for the RFC 8785 3.2.3 sample.
require __DIR__ . '/jcs.php'; $dir = dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/jcs';
function naive(mixed $v): mixed { if (is_array($v)) { ksort($v, SORT_STRING); $v = array_map('naive', $v); } return $v; }
foreach (glob("$dir/input/*.json") as $f) { $in = file_get_contents($f); $want = file_get_contents(str_replace('/input/', '/output/', $f));
    $naive = json_encode(naive(json_decode($in, true)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    printf("%-14s jcs() equals expected bytes: %-5s | obvious route equals: %-5s %s\n", basename($f), var_export(jcs(json_decode($in)) === $want, true), var_export($naive === $want, true), $naive === $want ? '' : $naive); }
$S = '{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}';
$names = fn(array $keys, array $a) => implode(', ', array_map(fn($k) => $a[$k], $keys)); $a = json_decode($S, true);
$utf16 = array_keys($a); usort($utf16, fn($x, $y) => strcmp(mb_convert_encoding((string) $x, 'UTF-16BE', 'UTF-8'), mb_convert_encoding((string) $y, 'UTF-16BE', 'UTF-8')));
$byte = array_keys($a); usort($byte, fn($x, $y) => strcmp((string) $x, (string) $y)); $reg = $a; ksort($reg);
echo "UTF-16 order : ", $names($utf16, $a), "\nUTF-8 bytes  : ", $names($byte, $a), "\nksort default: ", $names(array_keys($reg), $a), "\njcs() output : ", jcs(json_decode($S)), "\n";
