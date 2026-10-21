<?php // Shared by the Q4 and Q5 probes (probe-only): a JCS writer over json_decode() object-mode output; numbers by es_num().
require __DIR__ . "/esnum.php";
function jcs(mixed $v): string {
    return match (true) {
        $v === null => 'null', is_bool($v) => $v ? 'true' : 'false', is_float($v) => es_num($v),
        is_int($v) => abs($v) <= 9007199254740991 ? (string) $v : throw new DomainException("integer $v outside +-(2^53-1)"),
        is_string($v) => json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR),
        is_array($v) => array_is_list($v) ? '[' . implode(',', array_map('jcs', $v)) . ']' : throw new DomainException('PHP map where a JSON array is expected'),
        is_object($v) => jcs_object(get_object_vars($v)), default => throw new DomainException('unsupported type ' . get_debug_type($v)),
    };
}
function jcs_object(array $a): string { // keys are ordered by UTF-16 code units: compare the UTF-16BE bytes
    $u = []; foreach ($a as $k => $_) $u[$k] = mb_convert_encoding((string) $k, 'UTF-16BE', 'UTF-8'); uasort($u, 'strcmp'); $o = [];
    foreach ($u as $k => $_) $o[] = jcs((string) $k) . ':' . jcs($a[$k]);
    return '{' . implode(',', $o) . '}';
}
