<?php // Q1d: base64url strictness of base64_decode($s, true) after strtr, and a canonical round-trip guard (re-encode and compare).
require __DIR__ . '/jws.php';
$guard = fn(string $s) => preg_match('/\A[A-Za-z0-9_-]*\z/', $s) === 1 && ($b = b64u_dec($s)) !== false && b64u_enc($b) === $s ? bin2hex($b) : 'REJECT';
$cases = ['AA' => 'canonical, 1 byte', 'AB' => 'non-zero trailing bits', 'AAB' => 'non-zero trailing bits, 2 bytes', 'AA==' => 'padded', "AA\n" => 'trailing newline', 'A A' => 'inner space',
    '+/' => 'standard alphabet', '-_-_' => 'url alphabet, 3 bytes', 'A' => 'one character', 'AA=A' => 'pad then data', 'AAAAA' => 'length 5 (1 mod 4)', '' => 'empty'];
foreach ($cases as $s => $d) {
    $dec = b64u_dec((string) $s); // strict flag on, '-_' mapped to '+/' first
    printf("%-9s %-32s base64_decode(strict) after strtr: %-8s guard: %s\n", json_encode((string) $s), $d, $dec === false ? 'false' : bin2hex($dec), $guard((string) $s));
}
$sg = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
$alt = substr($sg, 0, -1) . 'R'; // 86 characters carry 516 bits for 512: the last character's low 4 bits are spare
echo 'RFC A.3 signature: guard ', $guard($sg) === bin2hex(b64u_dec($sg)) ? 'accepts' : 'rejects', '; last char Q -> R (same 64 bytes): decodes equal ', var_export(b64u_dec($alt) === b64u_dec($sg), true), ' guard ', $guard($alt), "\n";
$weak = (function (): string { return base64_decode('A', true); })(); // base64_decode returns false; the declared return type is string
echo 'return type string with a false result, strict_types off: ', var_export($weak, true), ' (coerced; with declare(strict_types=1) it is a TypeError)', "\n";
