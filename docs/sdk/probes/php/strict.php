<?php // Shared by the Q3 and Q5 probes (probe-only): strict_decode = json_decode (syntax, UTF-8, surrogates, depth) + a token scan for what json_decode hides.
function strict_scan(string $t): void { // $t is already valid JSON; regex tokens, a container stack, a key set per object
    if (preg_match_all('/"(?:[^"\\\\]++|\\\\.)*+"|-?\d++(?:\.\d++)?(?:[eE][+-]?\d++)?|[{}\[\],:]|true|false|null/', $t, $m) === false) throw new RuntimeException('token scan failed: ' . preg_last_error_msg()); // fail closed
    $st = []; $isKey = false;
    foreach ($m[0] as $tok) switch ($tok[0]) {
        case '{': $st[] = []; $isKey = true; break;
        case '[': $st[] = null; break;
        case '}': case ']': array_pop($st); break;
        case ',': $isKey = $st && is_array(end($st)); break;
        case '"': if ($isKey) { $k = json_decode($tok); if (isset($st[array_key_last($st)][$k])) throw new RuntimeException("duplicate key $k"); $st[array_key_last($st)][$k] = 1; $isKey = false; } break;
        default: if ($tok[0] === '-' || ($tok[0] >= '0' && $tok[0] <= '9')) { if (!is_finite((float) $tok)) throw new RuntimeException("non-finite $tok");
            if (preg_match('/^-?\d+$/', $tok)) { $d = ltrim($tok, '-'); if (strlen($d) > 16 || (strlen($d) === 16 && strcmp($d, '9007199254740991') > 0)) throw new RuntimeException("integer out of range $tok"); } }
    }
}
function strict_decode(string $t, bool $assoc = true) { $v = json_decode($t, $assoc, 17, JSON_THROW_ON_ERROR); strict_scan($t); return $v; } // depth 17 = 16 containers
