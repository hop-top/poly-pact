<?php // Q1c: Appendix C fixture JWS with ext-openssl: verify under issuer.jwk.json, bad-key behavior of the PEM import (off-curve point, wrong-length coordinates).
require __DIR__ . '/jws.php';
$root = dirname(__DIR__, 4); $jwk = fn($n) => json_decode(file_get_contents("$root/spec/v1.0/fixtures/keys/$n.jwk.json"), true);
[$h, $p, $s] = explode('.', trim(file_get_contents("$root/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws"))); [$iss, $hold] = [$jwk('issuer'), $jwk('holder')]; $sig = b64u_dec($s);
echo 'header ', b64u_dec($h), ' signature bytes ', strlen($sig), "\n";
echo 'verifies under issuer ', var_export(es256_ok(jwk_pub($iss), $sig, "$h.$p"), true), ' under holder ', var_export(es256_ok(jwk_pub($hold), $sig, "$h.$p"), true), ' input with one byte appended ', var_export(es256_ok(jwk_pub($iss), $sig, "$h.$p" . 'x'), true), "\n";
$try = function (array $j) { while (openssl_error_string()); $k = jwk_pub($j); return $k ? 'accepted' : 'REJECTED' . (($e = openssl_error_string()) ? ' ' . $e : ' (jwk_pub length check, openssl not called)'); };
echo 'y replaced by 32 x 0x01 (off curve): ', $try(['x' => $iss['x'], 'y' => b64u_enc(str_repeat("\1", 32))]), "\n";
echo "issuer x with holder y (valid coordinates of two different keys): ", $try(['x' => $iss['x'], 'y' => $hold['y']]), "\n";
echo 'x of 31 bytes (leading byte dropped): ', $try(['x' => b64u_enc(substr(b64u_dec($iss['x']), 1)), 'y' => $iss['y']]), ' | x of 33 bytes (0x00 prepended): ', $try(['x' => b64u_enc("\0" . b64u_dec($iss['x'])), 'y' => $iss['y']]), "\n";
$raw = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . substr(b64u_dec($iss['x']), 1) . b64u_dec($iss['y']); // the same 31-byte x written into the SPKI without the helper's check
while (openssl_error_string()); echo 'openssl_pkey_get_public on a PEM whose point is 63 bytes: ', var_export(openssl_pkey_get_public(pem('PUBLIC KEY', $raw)) !== false, true), ' ', openssl_error_string() ?: '', "\n";
