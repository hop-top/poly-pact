<?php // Q3d: seld/jsonlint (pure-PHP parser, DETECT_KEY_CONFLICTS) on the 36 strict-json vectors, alone and under json_decode(depth 17) first. Usage: php q3d_jsonlint.php <seld/jsonlint composer dir>
require "$argv[1]/vendor/autoload.php"; use Seld\JsonLint\JsonParser;
$lint = function (string $in): string { try { (new JsonParser())->parse($in, JsonParser::DETECT_KEY_CONFLICTS); return 'accept'; } catch (Throwable $e) { return 'reject'; } };
$pre = fn(string $in) => (function () use ($in) { try { json_decode($in, true, 17, JSON_THROW_ON_ERROR); return 'accept'; } catch (Throwable $e) { return 'reject'; } })() === 'accept' ? $lint($in) : 'reject';
$n = 0; $w = ['jsonlint alone' => [], 'json_decode(depth 17) then jsonlint' => []];
foreach (glob(dirname(__DIR__, 4) . '/spec/v1.0/fixtures/vectors/strictjson/*.json') as $f) { $v = json_decode(file_get_contents($f), true); $in = $v['input_text'] ?? base64_decode($v['input_b64'], true); $n++;
    foreach (array_keys($w) as $i => $name) if (($i ? $pre($in) : $lint($in)) !== $v['expect']) $w[$name][] = basename($f, '.json'); }
foreach ($w as $name => $l) echo "$name: ", $n - count($l), " of $n agree; disagree: ", $l ? implode(', ', $l) : '-', "\n";
$r = (new JsonParser())->parse('{"a":1,"b":[1.5,9223372036854775808,1e999,"\ud800"],"":2,"0":3}', JsonParser::PARSE_TO_ASSOC); echo 'jsonlint parse of numbers and keys: ', var_export($r, true) === '' ? '' : preg_replace('/\s+/', ' ', var_export($r, true)), "\n";
