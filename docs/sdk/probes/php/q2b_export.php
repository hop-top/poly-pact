<?php // Q2b: JWK export from openssl_pkey_get_details: x, y, d lengths over 20000 P-256 keys, padding, thumbprint with and without padding.
require __DIR__ . '/jws.php';
$thumb = fn($x, $y) => b64u_enc(hash('sha256', '{"crv":"P-256","kty":"EC","x":"' . b64u_enc($x) . '","y":"' . b64u_enc($y) . '"}', true));
$pad = fn($b) => str_pad($b, 32, "\0", STR_PAD_LEFT); $n = 20000; $lens = ['x' => [], 'y' => [], 'd' => []]; $short = $diff = $lead = 0; $first = null;
for ($i = 0; $i < $n; $i++) {
    $e = openssl_pkey_get_details(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']))['ec'];
    foreach (["x", "y", "d"] as $c) { $lens[$c][strlen($e[$c])] = ($lens[$c][strlen($e[$c])] ?? 0) + 1; $lead += $e[$c][0] === "\0"; }
    if (strlen($e['x']) < 32 || strlen($e['y']) < 32) { $short++; $diff += $thumb($e['x'], $e['y']) !== $thumb($pad($e['x']), $pad($e['y'])); $first ??= $e; }
}
foreach ($lens as $c => $l) { ksort($l); echo "length histogram $c: ", json_encode($l), "\n"; }
echo "keys with a short x or y: $short of $n | unpadded thumbprint differs from padded in $diff of them | exported values starting with a 0x00 byte: $lead\n";
$pem = openssl_pkey_get_details(jwk_pub(['x' => b64u_enc($pad($first['x'])), 'y' => b64u_enc($pad($first['y']))]))['key']; // the public key of the first key with a short coordinate, as PEM
echo "first short key, padded x: ", b64u_enc($pad($first['x'])), " y: ", b64u_enc($pad($first['y'])), " thumbprint: ", $thumb($pad($first['x']), $pad($first['y'])), "\n", $pem;
foreach (['issuer', 'holder', 'validator'] as $f) { $j = json_decode(file_get_contents(dirname(__DIR__, 4) . "/spec/v1.0/fixtures/keys/$f.jwk.json"), true); $ec = openssl_pkey_get_details(jwk_pub($j))['ec'];
    echo "$f export equals file: ", var_export(b64u_enc($pad($ec['x'])) === $j['x'] && b64u_enc($pad($ec['y'])) === $j['y'], true), "\n"; }
