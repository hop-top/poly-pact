<?php // Q1: ES256 with ext-openssl: openssl_sign gives DER; hand-rolled DER <-> 64-byte r||s; round trip, tamper and length rejects.
require __DIR__ . '/jws.php';
$k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']); $m = 'hdr.payload'; $pub = openssl_pkey_get_details($k)['key'];
for ($i = 0, $ders = $raws = []; $i < 5000; $i++) { openssl_sign($m, $der, $k, OPENSSL_ALGO_SHA256); $ders[] = $der; $raws[] = der2raw($der); }
$lens = array_values(array_unique(array_map('strlen', $ders))); sort($lens);
$short = count(array_filter($raws, fn($r) => $r[0] === "\0" || $r[32] === "\0"));
$der2 = array_map('raw2der', $raws);
echo 'DER lens ', json_encode($lens), ' raw lens ', json_encode(array_values(array_unique(array_map('strlen', $raws)))), " raw with a leading 0x00 half: $short of 5000\n";
echo 'round trip ', var_export(array_reduce($raws, fn($a, $s) => $a && es256_ok($pub, $s, $m), true), true), ' DER->raw->DER identical ', var_export($ders === $der2, true), "\n";
$t = $raws[0];
echo 'tampered msg ', var_export(es256_ok($pub, $t, 'hdr.payloaX'), true), ' 63 bytes ', var_export(es256_ok($pub, substr($t, 1), $m), true), ' 65 bytes ', var_export(es256_ok($pub, $t . "\0", $m), true), ' DER as raw ', var_export(es256_ok($pub, $ders[0], $m), true), "\n";
echo 'openssl_verify returns: valid ', openssl_verify($m, $ders[0], $pub, OPENSSL_ALGO_SHA256), ' wrong message ', openssl_verify('x', $ders[0], $pub, OPENSSL_ALGO_SHA256), ' raw 64 bytes ', openssl_verify($m, $t, $pub, OPENSSL_ALGO_SHA256), ' garbage ', openssl_verify($m, 'garbage', $pub, OPENSSL_ALGO_SHA256), ' -1 is truthy: ', var_export((bool) -1, true), "\n";
