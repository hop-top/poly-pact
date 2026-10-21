<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * A set of trusted ES256 public keys, looked up by kid (Go KeySet and
 * NewKeySet). It is built from configuration, never from an artifact;
 * new KeySet() is empty.
 */
final class KeySet
{
    /** @var array<string, TrustedKey> */
    private array $keys = [];

    /**
     * Check each key as Jws::parseJwk() checks it and require a non-empty
     * kid, unique within the set.
     *
     * @throws JwsError KID_MISSING, KID_DUPLICATE, or the reason a key fails
     */
    public function __construct(Jwk ...$keys)
    {
        foreach (array_values($keys) as $i => $k) {
            if ($k->kid === '') {
                throw new JwsError(Reason::KID_MISSING, \sprintf('key %d has no kid', $i));
            }
            if (isset($this->keys[$k->kid])) {
                throw new JwsError(Reason::KID_DUPLICATE, 'kid ' . Text::quote($k->kid));
            }
            $this->keys[$k->kid] = TrustedKey::of($k);
        }
    }

    /** The key with the given kid, or null. */
    public function lookup(string $kid): ?Jwk
    {
        return $this->trusted($kid)?->jwk;
    }

    /**
     * The checked key with the given kid, or null; an empty kid finds nothing.
     *
     * @internal
     */
    public function trusted(string $kid): ?TrustedKey
    {
        return $kid === '' ? null : ($this->keys[$kid] ?? null);
    }
}
