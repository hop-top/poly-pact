<?php // Q4d: jcs() on edge values (guards), and what the assoc-array route does to JSON objects. Each result is the output or the exception class + message.
require __DIR__ . '/jcs.php';
$run = function (string $label, callable $f) { try { $r = $f(); } catch (Throwable $e) { $r = 'raises ' . get_class($e) . ': ' . $e->getMessage(); } printf("%-44s %s\n", $label, $r); };
foreach ([9007199254740991, 9007199254740992, -9007199254740991, -9007199254740992, PHP_INT_MAX, 9007199254740992.0, 1.0, -0.0, INF, NAN, true, null, "\xed\xa0\x80", "a\u{2028}b", "\x7f", "\u{e9}", ['a' => 1, 'b' => [1, 2]]] as $v)
    $run(is_string($v) ? 'string, hex ' . bin2hex($v) : preg_replace('/\s+/', ' ', var_export($v, true)), fn() => jcs($v));
$run('stdClass property "\u0000a" (json_decode obj)', fn() => jcs(json_decode('{"\u0000a":1}', false, 512, JSON_THROW_ON_ERROR)));
$run('{"\u0000a":1} assoc decode, then jcs of object', fn() => jcs((object) json_decode('{"\u0000a":1}', true)));
$run('{} assoc decode then json_encode', fn() => json_encode(json_decode('{}', true)));
$run('{"0":1,"1":2} assoc decode then json_encode', fn() => json_encode(json_decode('{"0":"a","1":"b"}', true)));
$run('{"10":1,"9":2} assoc then ksort() default', fn() => json_encode(array_keys(tap(json_decode('{"10":1,"9":2,"a":3}', true)))));
function tap(array $a) { ksort($a); return $a; }
$run('{"10":1,"9":2,"a":3} jcs() key order', fn() => jcs(json_decode('{"10":1,"9":2,"a":3}')));
$run('object with int-like keys: get_object_vars key types', fn() => json_encode(array_map('gettype', array_keys(get_object_vars(json_decode('{"0":1,"7":2,"x":3}'))))));
$run('jcs(object(a: object())) nested empty object', fn() => jcs(json_decode('{"a":{}}')));
$run('jcs(float 1e400 literal in PHP source)', fn() => jcs(1e400));
$run('jcs of a resource', fn() => jcs(fopen('php://memory', 'r')));
