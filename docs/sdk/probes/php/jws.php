<?php // Shared helpers for the Q1 and Q2 probes (hand-rolled, probe-only): base64url, DER <-> JWS r||s, JWK -> PEM, ES256 verify.
function b64u_enc(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }
function b64u_dec(string $s): string|false { return base64_decode(strtr($s, '-_', '+/'), true); }
function der2raw(string $d): string { // SEQUENCE { INTEGER r, INTEGER s }; short-form lengths (an ES256 DER is at most 72 bytes)
    if ($d[0] !== "\x30" || ord($d[1]) !== strlen($d) - 2) throw new Exception('DER: sequence');
    for ($o = 2, $out = '', $n = 0; $n < 2; $n++, $o += 2 + $l) {
        if ($d[$o] !== "\x02") throw new Exception('DER: integer');
        $l = ord($d[$o + 1]); $out .= str_pad(ltrim(substr($d, $o + 2, $l), "\0"), 32, "\0", STR_PAD_LEFT);
    }
    if ($o !== strlen($d)) throw new Exception('DER: trailing'); return $out;
}
function raw2der(string $r): string {
    $i = fn(string $b) => ($b = ltrim($b, "\0")) === '' ? "\x02\x01\0" : "\x02" . chr(strlen($b) + (ord($b[0]) >> 7)) . (ord($b[0]) >> 7 ? "\0" : '') . $b;
    $body = $i(substr($r, 0, 32)) . $i(substr($r, 32)); return "\x30" . chr(strlen($body)) . $body;
}
function pem(string $label, string $der): string { return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n"; }
function jwk_pub(array $j) { $c = b64u_dec($j['x']) . b64u_dec($j['y']); return strlen($c) === 64 ? openssl_pkey_get_public(pem('PUBLIC KEY', hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $c)) : false; } // SPKI, P-256
function jwk_prv(array $j) { $c = b64u_dec($j['x']) . b64u_dec($j['y']); return strlen($c) === 64 && strlen(b64u_dec($j['d'])) === 32 ? openssl_pkey_get_private(pem('EC PRIVATE KEY', hex2bin('30770201010420') . b64u_dec($j['d']) . hex2bin('a00a06082a8648ce3d030107a144034200') . "\x04" . $c)) : false; } // SEC1
function es256_ok($key, string $sig, string $m): bool { return strlen($sig) === 64 && openssl_verify($m, raw2der($sig), $key, OPENSSL_ALGO_SHA256) === 1; }
