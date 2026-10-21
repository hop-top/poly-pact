<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\Digest;

/**
 * Supplies the trusted keys of a verification. Verification calls exactly
 * one method, once: holderJkt() for Role::HOLDER, trustedKeys() for every
 * other role. An \Exception either throws becomes JwsError KEY_UNAVAILABLE
 * with the exception as previous. The package never fetches keys.
 */
interface KeyResolver
{
    /**
     * The key set trusted for $req->role; null has no keys. The header kid
     * is looked up in it and nowhere else.
     */
    public function trustedKeys(KeyRequest $req): ?KeySet;

    /**
     * The enrolled holder_jkt the embedded jwk of a holder-signed artifact
     * must match (draft 6.2, 7.2).
     */
    public function holderJkt(KeyRequest $req): Digest;
}
