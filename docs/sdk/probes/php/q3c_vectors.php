<?php // Q3c: the 36 strict-json vectors through (a) json_decode alone (depth 17, THROW) and (b) strict_decode (json_decode + token scan); verdict vs the vector's expect.
require __DIR__ . '/strict.php';
$run = function (callable $f, string $in): string { try { $f($in); return 'accept'; } catch (Throwable $e) { return 'reject'; } };
$bare = fn($t) => json_decode($t, true, 17, JSON_THROW_ON_ERROR); $wrong = ['bare' => [], 'strict' => []]; $n = 0;
foreach (glob(dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/strictjson/*.json') as $f) {
    $v = json_decode(file_get_contents($f), true, 512, JSON_THROW_ON_ERROR); $in = $v['input_text'] ?? base64_decode($v['input_b64'], true); $n++;
    foreach (['bare' => $bare, 'strict' => 'strict_decode'] as $name => $fn) if ($run($fn, $in) !== $v['expect']) $wrong[$name][] = basename($f, '.json');
}
foreach ($wrong as $name => $w) echo "$name: ", $n - count($w), " of $n agree with expect; disagree: ", $w ? implode(', ', $w) : '-', "\n";
