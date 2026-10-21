<?php // Q2: RFC 7638 SHA-256 JWK thumbprint with builtins only (json_encode, hash, base64): fixtures, RFC 7638 3.1, RFC 8037 A.3, missing member.
require __DIR__ . '/jws.php';
const REQ = ['EC' => ['crv', 'kty', 'x', 'y'], 'RSA' => ['e', 'kty', 'n'], 'OKP' => ['crv', 'kty', 'x']];
function jkt(array $jwk, int $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): string {
    $m = []; foreach (REQ[$jwk['kty']] as $k) $m[$k] = $jwk[$k]; ksort($m, SORT_STRING);
    return b64u_enc(hash('sha256', json_encode($m, $flags), true));
}
$keys = dirname(__DIR__, 4) . '/spec/v1.0/fixtures/keys'; $load = fn($n) => json_decode(file_get_contents("$keys/$n"), true);
$holder = $load('holder.jwk.json'); $want = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';
echo 'holder ', jkt($holder), ' == expected: ', var_export(jkt($holder) === $want, true), ' | kid/alg/use ignored: ', var_export(jkt(array_diff_key($holder, ['kid' => 1, 'alg' => 1, 'use' => 1])) === $want, true), ' | extra member ignored: ', var_export(jkt($holder + ['foo' => 'bar']) === $want, true), "\n";
$rsa = ['kty' => 'RSA', 'e' => 'AQAB', 'alg' => 'RS256', 'kid' => '2011-04-29', 'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw'];
echo 'RFC 7638 3.1 ', jkt($rsa), ' == expected: ', var_export(jkt($rsa) === 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', true), ' | default json_encode flags (escaped slashes) same: ', var_export(jkt($rsa, 0) === jkt($rsa), true), "\n";
foreach (glob("$keys/*.jwk.json") as $f) echo '  ', str_pad(basename($f), 30), jkt($load(basename($f))), "\n";
echo 'RFC 8037 A.3 Ed25519 thumbprint matches: ', var_export(jkt($load('ed25519.jwk.json')) === 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k', true), "\n";
set_error_handler(function ($no, $msg) { echo "  [E_WARNING handler] $msg\n"; return true; });
echo 'missing required member y: thumbprint computed anyway = ', jkt(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AA']), "\n";
