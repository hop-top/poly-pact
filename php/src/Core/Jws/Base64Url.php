<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * RFC 7515 base64url: the URL-safe alphabet without padding (RFC 7515
 * section 2).
 *
 * decode() accepts only the canonical encoding of its octets. base64_decode()
 * in strict mode does not: it accepts padding, white space and non-zero spare
 * bits, and the standard alphabet. So the alphabet and the length are
 * checked first, and the result is re-encoded and compared, which rejects
 * non-zero spare bits.
 */
final class Base64Url
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    private function __construct() {}

    /** The unpadded base64url of $b. */
    public static function encode(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    /**
     * Decode the canonical unpadded base64url $s.
     *
     * The rules, in order: only the 64 characters of the URL-safe alphabet
     * (no padding, white space or line breaks); a length that is not 1 mod
     * 4; zero spare bits in the last character.
     *
     * @throws \UnexpectedValueException
     */
    public static function decode(string $s): string
    {
        $ok = strspn($s, self::ALPHABET);
        if ($ok !== \strlen($s)) {
            throw new \UnexpectedValueException(\sprintf('base64url: character %s at offset %d is not base64url', json_encode($s[$ok], \JSON_INVALID_UTF8_SUBSTITUTE), $ok));
        }
        if (\strlen($s) % 4 === 1) {
            throw new \UnexpectedValueException(\sprintf('base64url: length %d is 1 mod 4', \strlen($s)));
        }
        $b = base64_decode(strtr($s, '-_', '+/'), true);
        if ($b === false || self::encode($b) !== $s) {
            throw new \UnexpectedValueException(\sprintf('base64url: non-zero spare bits at offset %d', \strlen($s) - 1));
        }

        return $b;
    }
}
