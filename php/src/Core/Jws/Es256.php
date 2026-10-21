<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * ES256 over ext-openssl (RFC 7518 section 3.4): keys built from hand-made
 * DER (SubjectPublicKeyInfo for a public key, a SEC1 ECPrivateKey without
 * its public key for a private key, so OpenSSL derives the point), the
 * conversion between OpenSSL's DER ECDSA-Sig-Value and the 64 octets R || S,
 * and the scalar arithmetic the profile needs, on 32-octet big-endian
 * strings (no ext-gmp or ext-bcmath).
 *
 * openssl_verify() returns 1, 0, -1 or false, so only === 1 is a valid
 * signature. OpenSSL's error queue is drained after every call and its text
 * is never passed on.
 *
 * @internal
 */
final class Es256
{
    /** The octets of a P-256 coordinate or scalar (RFC 7518 section 6.2.1.2). */
    public const COORDINATE_OCTETS = 32;

    /** The octets of an ES256 signature, R || S. */
    public const SIGNATURE_OCTETS = 64;

    /** The order n of P-256 (SEC 2, section 2.4.2). */
    public const N = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51";

    /** n >> 1: an S above it is high. */
    public const HALF_N = "\x7F\xFF\xFF\xFF\x80\x00\x00\x00\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xDE\x73\x7D\x56\xD3\x8B\xCF\x42\x79\xDC\xE5\x61\x7E\x31\x92\xA8";

    /** The DER of SubjectPublicKeyInfo { ecPublicKey, prime256v1 } up to the uncompressed point. */
    private const SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04";

    /** The DER of ECPrivateKey { version 1, privateKey } up to the scalar. */
    private const SEC1_PREFIX = "\x30\x31\x02\x01\x01\x04\x20";

    /** The DER of the [0] parameters prime256v1 that follow the scalar. */
    private const SEC1_SUFFIX = "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    private function __construct() {}

    /** The public key of the point (x, y), 32 octets each; null when it is not a point of P-256. */
    public static function publicKey(string $x, string $y): ?\OpenSSLAsymmetricKey
    {
        if (\strlen($x) !== self::COORDINATE_OCTETS || \strlen($y) !== self::COORDINATE_OCTETS) {
            return null;
        }
        $key = openssl_pkey_get_public(self::pem('PUBLIC KEY', self::SPKI_PREFIX . $x . $y));
        self::drain();

        return $key === false ? null : $key;
    }

    /** The private key of the 32-octet scalar $d; null unless 1 <= d < n. */
    public static function privateKey(string $d): ?\OpenSSLAsymmetricKey
    {
        if (!self::inRange($d)) {
            return null;
        }
        $key = openssl_pkey_get_private(self::pem('EC PRIVATE KEY', self::SEC1_PREFIX . $d . self::SEC1_SUFFIX));
        self::drain();

        return $key === false ? null : $key;
    }

    /**
     * The coordinates of a P-256 key, each left-padded to 32 octets
     * (openssl_pkey_get_details() drops leading zero octets), and whether it
     * is a private key; null for any other key.
     *
     * @return array{x: string, y: string, private: bool}|null
     */
    public static function coordinates(\OpenSSLAsymmetricKey $key): ?array
    {
        $d = openssl_pkey_get_details($key);
        self::drain();
        if (!\is_array($d) || ($d['type'] ?? null) !== \OPENSSL_KEYTYPE_EC || !\is_array($d['ec'] ?? null)) {
            return null;
        }
        $ec = $d['ec'];
        $x = $ec['x'] ?? null;
        $y = $ec['y'] ?? null;
        if (($ec['curve_name'] ?? null) !== 'prime256v1' || !\is_string($x) || !\is_string($y) || \strlen($x) > self::COORDINATE_OCTETS || \strlen($y) > self::COORDINATE_OCTETS) {
            return null;
        }
        $priv = $ec['d'] ?? null;

        return [
            'x' => str_pad($x, self::COORDINATE_OCTETS, "\0", \STR_PAD_LEFT),
            'y' => str_pad($y, self::COORDINATE_OCTETS, "\0", \STR_PAD_LEFT),
            'private' => \is_string($priv) && $priv !== '',
        ];
    }

    /**
     * Whether $sig, 64 octets R || S, is a signature of $input under $key.
     * R and S outside [1, n-1] fail; a high S is accepted.
     */
    public static function verify(\OpenSSLAsymmetricKey $key, string $input, string $sig): bool
    {
        if (\strlen($sig) !== self::SIGNATURE_OCTETS) {
            return false;
        }
        $r = substr($sig, 0, self::COORDINATE_OCTETS);
        $s = substr($sig, self::COORDINATE_OCTETS);
        if (!self::inRange($r) || !self::inRange($s)) {
            return false;
        }
        $ok = openssl_verify($input, self::sequence($r, $s), $key, \OPENSSL_ALGO_SHA256);
        self::drain();

        return $ok === 1;
    }

    /**
     * The 64-octet signature R || S of $input under the private key $key,
     * with the low S of the pair (S, n-S); null when OpenSSL fails.
     */
    public static function sign(\OpenSSLAsymmetricKey $key, string $input): ?string
    {
        $der = '';
        $ok = openssl_sign($input, $der, $key, \OPENSSL_ALGO_SHA256);
        self::drain();
        if (!$ok || !\is_string($der)) {
            return null;
        }
        $raw = self::raw($der);
        if ($raw === null) {
            return null;
        }
        [$r, $s] = $raw;
        if (strcmp($s, self::HALF_N) > 0) {
            $s = self::sub(self::N, $s);
        }

        return $r . $s;
    }

    /** Whether the 32-octet big-endian $v is in [1, n-1]. */
    public static function inRange(string $v): bool
    {
        return \strlen($v) === self::COORDINATE_OCTETS && trim($v, "\0") !== '' && strcmp($v, self::N) < 0;
    }

    /** $a - $b for 32-octet big-endian values with $a >= $b. */
    public static function sub(string $a, string $b): string
    {
        $out = '';
        $borrow = 0;
        for ($i = self::COORDINATE_OCTETS - 1; $i >= 0; --$i) {
            $v = \ord($a[$i]) - \ord($b[$i]) - $borrow;
            $borrow = $v < 0 ? 1 : 0;
            $out = \chr($v + 256 * $borrow) . $out;
        }

        return $out;
    }

    /** The DER INTEGER of the non-negative big-endian $v. */
    private static function der(string $v): string
    {
        $v = ltrim($v, "\0");
        if ($v === '' || \ord($v[0]) >= 0x80) {
            $v = "\0" . $v;
        }

        return "\x02" . \chr(\strlen($v)) . $v;
    }

    /** The DER ECDSA-Sig-Value of (r, s); at most 72 octets, so lengths are short form. */
    private static function sequence(string $r, string $s): string
    {
        $body = self::der($r) . self::der($s);

        return "\x30" . \chr(\strlen($body)) . $body;
    }

    /**
     * R and S, 32 octets each, of a DER ECDSA-Sig-Value with short-form
     * lengths; null for anything else.
     *
     * @return array{string, string}|null
     */
    private static function raw(string $der): ?array
    {
        $n = \strlen($der);
        if ($n < 8 || $der[0] !== "\x30" || \ord($der[1]) !== $n - 2) {
            return null;
        }
        $out = [];
        $o = 2;
        for ($k = 0; $k < 2; ++$k) {
            if ($o + 2 > $n || $der[$o] !== "\x02") {
                return null;
            }
            $len = \ord($der[$o + 1]);
            if ($len === 0 || $len > self::COORDINATE_OCTETS + 1 || $o + 2 + $len > $n) {
                return null;
            }
            $v = ltrim(substr($der, $o + 2, $len), "\0");
            if (\strlen($v) > self::COORDINATE_OCTETS) {
                return null;
            }
            $out[] = str_pad($v, self::COORDINATE_OCTETS, "\0", \STR_PAD_LEFT);
            $o += 2 + $len;
        }
        if ($o !== $n) {
            return null;
        }

        return [$out[0], $out[1]];
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN {$label}-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END {$label}-----\n";
    }

    /** Empty OpenSSL's error queue, so no later call reports a stale error. */
    private static function drain(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }
}
