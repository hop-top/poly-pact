<?php // Q5: pact.schema.json (Draft 2020-12, urn:uuid $id, local $refs) offline with opis/json-schema or justinrainbow/json-schema. Usage: php q5_schema.php opis|jr <composer project dir with vendor/>
[$lib, $dir] = [$argv[1], $argv[2]]; require "$dir/vendor/autoload.php"; foreach (['http', 'https', 'ftp'] as $w) stream_wrapper_unregister($w); // no network: a remote $ref or $schema fetch would fail
$root = dirname(__DIR__, 4); $text = file_get_contents("$root/spec/v1.0/schemas/pact.schema.json"); $id = json_decode($text)->{'$id'};
$doc = json_decode(base64_decode(strtr(explode('.', trim(file_get_contents("$root/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws")))[1], '-_', '+/')));
function leaves($e): array { return ($s = $e->subErrors()) ? array_merge(...array_map('leaves', $s)) : [$e]; }
$mk = match ($lib) { // returns fn(object): list of "keyword@/path"; $asis false = a copy with the urn:uuid $id replaced
    'opis' => function (bool $asis) use ($text, $id) { $v = new Opis\JsonSchema\Validator(); $v->setMaxErrors(50); $v->resolver()->registerRaw($text);
        return fn($d) => ($r = $v->validate($d, "$id#/\$defs/Evidence"))->isValid() ? [] : array_map(fn($e) => $e->keyword() . '@/' . implode('/', $e->data()->fullPath()), leaves($r->error())); },
    'jr' => function (bool $asis) use ($text, $id) { $o = json_decode($text); $o->{'$id'} = $u = $asis ? $id : 'https://example.invalid/pact.schema.json'; $st = new JsonSchema\SchemaStorage(); $st->addSchema($u, $o);
        return function ($d) use ($st, $u) { $v = new JsonSchema\Validator(new JsonSchema\Constraints\Factory($st)); $v->validate($d, (object) ['$ref' => "$u#/\$defs/Evidence"]); return array_map(fn($e) => $e['constraint']['name'] . '@/' . $e['property'], $v->getErrors()); }; },
};
$ok = ['pact_version' => '0.1']; $cases = ['payload as published (pact_version 0.2)' => [], 'pact_version 0.1' => $ok, 'iss "not a uri"' => $ok + ['iss' => 'not a uri'], 'iat 2^53' => $ok + ['iat' => 2 ** 53], 'iat 2.0 (float)' => $ok + ['iat' => 2.0], 'iat 1.5' => $ok + ['iat' => 1.5], 'iat "5"' => $ok + ['iat' => '5'], 'extra member' => $ok + ['extra' => 1]];
foreach ($lib === 'jr' ? [true, false] : [true] as $asis) { echo $asis ? "-- schema as published\n" : "-- copy with the urn:uuid \$id replaced by an https URI\n";
    try { $chk = $mk($asis); foreach ($cases as $n => $m) { $d = clone $doc; foreach ($m as $k => $v) $d->$k = $v; printf("  %-40s %s\n", $n, ($e = $chk($d)) ? implode(' ', $e) : 'valid'); } }
    catch (Throwable $e) { echo '  THROWS ', get_class($e), ': ', substr($e->getMessage(), 0, 190), "\n"; } }
