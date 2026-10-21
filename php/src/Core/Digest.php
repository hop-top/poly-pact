<?php

declare(strict_types=1);

namespace HopTop\Pact\Core;

use HopTop\Pact\PactError;

/**
 * A base64url (RFC 4648, no padding) SHA-256 value, such as an object digest
 * or a JWK thumbprint. The schema pattern is ^[A-Za-z0-9_-]{43}$.
 *
 * Construction does not check the value, as Go's core.Digest conversion does
 * not; validate() does.
 */
final readonly class Digest implements \Stringable
{
    public function __construct(public string $value) {}

    /** Throw PactError unless the digest is exactly 43 base64url characters. */
    public function validate(): void
    {
        $n = \strlen($this->value);
        if ($n !== Core::DIGEST_LEN) {
            throw new PactError(\sprintf('core: digest has %d bytes, want %d', $n, Core::DIGEST_LEN));
        }
        $ok = strspn($this->value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_');
        if ($ok !== $n) {
            throw new PactError(\sprintf('core: digest has invalid character %s at offset %d', json_encode($this->value[$ok], \JSON_INVALID_UTF8_SUBSTITUTE), $ok));
        }
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
