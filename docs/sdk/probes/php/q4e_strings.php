<?php // Q4e: string escaping for JCS. json_encode flags vs RFC 8785 3.2.2.2 over every Unicode scalar value; which code points get escaped. Optional argv[1]: dump file for a Node cross-check.
$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR; $esc = []; $dump = isset($argv[1]) ? fopen($argv[1], 'w') : null;
for ($cp = 0; $cp <= 0x10FFFF; $cp++) {
    if ($cp >= 0xD800 && $cp <= 0xDFFF) continue; // surrogates are not scalar values; PHP strings holding their UTF-8 form are rejected (q4d)
    $c = mb_chr($cp, 'UTF-8'); $a = json_encode($c, $flags); $b = json_encode($c, $flags | JSON_UNESCAPED_LINE_TERMINATORS);
    if (strlen($b) !== strlen($c) + 2 || substr($b, 1, -1) !== $c) $esc[sprintf('U+%04X', $cp)] = substr($b, 1, -1); // escaped even with all unescape flags
    if ($a !== $b) $esc['no LINE_TERMINATORS flag: ' . sprintf('U+%04X', $cp)] = substr($a, 1, -1);
    if ($dump) fwrite($dump, $cp . ' ' . bin2hex($b) . "\n");
}
echo count($esc), " code points differ from the raw character:\n"; foreach ($esc as $k => $v) echo "  $k => $v\n";
