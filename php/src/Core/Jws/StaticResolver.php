<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\Digest;

/**
 * A KeyResolver over fixed configuration: one key set per role and one
 * expected holder thumbprint.
 */
final readonly class StaticResolver implements KeyResolver
{
    /**
     * @param array<string, KeySet> $keySets           key sets by Role value
     * @param Digest|null           $expectedHolderJkt the holder_jkt a holder jwk must match
     */
    public function __construct(
        public array $keySets = [],
        public ?Digest $expectedHolderJkt = null,
    ) {}

    /** $keySets[$req->role->value], null when the role has none. */
    public function trustedKeys(KeyRequest $req): ?KeySet
    {
        return $this->keySets[$req->role->value] ?? null;
    }

    /**
     * $expectedHolderJkt.
     *
     * @throws \UnexpectedValueException when it is null or empty
     */
    public function holderJkt(KeyRequest $req): Digest
    {
        if ($this->expectedHolderJkt === null || $this->expectedHolderJkt->value === '') {
            throw new \UnexpectedValueException('no expected holder_jkt configured');
        }

        return $this->expectedHolderJkt;
    }
}
