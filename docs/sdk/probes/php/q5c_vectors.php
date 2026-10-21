<?php // Q5c: the 36 strict-json vectors through strict_decode (object mode) and then opis/json-schema against #/$defs/OperationContext. Usage: php q5c_vectors.php <opis dir>
require "$argv[1]/vendor/autoload.php"; require __DIR__ . '/strict.php';
$root = dirname(__DIR__, 4); $text = file_get_contents("$root/spec/v1.0/schemas/pact.schema.json"); $id = json_decode($text)->{'$id'}; $opis = new Opis\JsonSchema\Validator(); $opis->resolver()->registerRaw($text);
$verdict = function (string $in) use ($opis, $id): string { try { $doc = strict_decode($in, false); } catch (Throwable $e) { return 'reject (json: ' . get_class($e) . ')'; } return $opis->validate($doc, "$id#/\$defs/OperationContext")->isValid() ? 'accept' : 'reject (schema)'; };
$n = 0; $wrong = []; $by = [];
foreach (glob("$root/spec/v1.0/fixtures/vectors/strictjson/*.json") as $f) { $v = json_decode(file_get_contents($f), true); $in = $v['input_text'] ?? base64_decode($v['input_b64'], true); $r = $verdict($in); $n++;
    $by[$r] = ($by[$r] ?? 0) + 1; if (explode(' ', $r)[0] !== $v['expect']) $wrong[] = basename($f, '.json') . " ($r, expect {$v['expect']})"; }
ksort($by); echo "$n vectors; agree with expect: ", $n - count($wrong), '; disagree: ', $wrong ? implode(', ', $wrong) : '-', "\nverdicts: ", json_encode($by), "\n";
