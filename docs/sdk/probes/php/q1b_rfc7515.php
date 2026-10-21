<?php // Q1b: RFC 7515 Appendix A.3 (ES256) with ext-openssl. JWK -> key two ways: hand-built PEM (jwk_pub, jwk_prv) and openssl_pkey_new(['ec' => ...]). Verify the RFC signature, sign with the RFC d.
require __DIR__ . '/jws.php';
$jwk = ['x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', 'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', 'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI'];
$si = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
$sg = b64u_dec('DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'); $pub = jwk_pub($jwk); $prv = jwk_prv($jwk);
echo 'PEM import: public ', get_class($pub), ' private ', get_class($prv), ' | public key details have d: ', var_export(isset(openssl_pkey_get_details($pub)['ec']['d']), true), "\n";
echo 'A.3 signature bytes ', strlen($sg), ' verifies ', var_export(es256_ok($pub, $sg, $si), true), ' tampered input ', var_export(es256_ok($pub, $sg, $si . 'x'), true), ' one bit flipped ', var_export(es256_ok($pub, chr(ord($sg[0]) ^ 1) . substr($sg, 1), $si), true), "\n";
openssl_sign($si, $own, $prv, OPENSSL_ALGO_SHA256); $raw = der2raw($own);
echo 'own signature with A.3 d: bytes ', strlen($raw), ' verifies ', var_export(es256_ok($pub, $raw, $si), true), ' equals RFC bytes ', var_export($raw === $sg, true), "\n";
$e = openssl_pkey_get_details($pub); echo 'details of the imported public key: type ', $e['type'], ' (OPENSSL_KEYTYPE_EC=', OPENSSL_KEYTYPE_EC, ') bits ', $e['bits'], ' curve ', $e['ec']['curve_name'], ' x ', b64u_enc($e['ec']['x']) === $jwk['x'] ? 'equals' : 'differs', ' y ', b64u_enc($e['ec']['y']) === $jwk['y'] ? 'equals' : 'differs', " the RFC value\n";
$c = ['curve_name' => 'prime256v1', 'x' => b64u_dec($jwk['x']), 'y' => b64u_dec($jwk['y'])]; $a = openssl_pkey_get_details(openssl_pkey_new(['ec' => $c]))['ec']; $b = openssl_pkey_get_details(openssl_pkey_new(['ec' => $c + ['d' => b64u_dec($jwk['d'])]]))['ec'];
echo 'openssl_pkey_new(ec: x, y): d present ', var_export(isset($a['d']), true), ', x equals input ', var_export(b64u_enc($a['x']) === $jwk['x'], true), ' | openssl_pkey_new(ec: x, y, d): x equals input ', var_export(b64u_enc($b['x']) === $jwk['x'], true), ' d equals input ', var_export(b64u_enc($b['d']) === $jwk['d'], true), "\n";
echo 'A.3 verify with the openssl_pkey_new(ec: x, y) key: ', var_export(openssl_verify($si, raw2der($sg), openssl_pkey_new(['ec' => $c]), OPENSSL_ALGO_SHA256), true), "\n";
