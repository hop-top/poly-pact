<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * The key one verification needs, built from the protected header and
 * payload after their structural checks and before the signature is
 * checked: nothing in it is authenticated yet. A resolver may use header and
 * payload only to choose which configured trust record or enrollment applies
 * (draft 7.3: iss selects a trust record), never to obtain key material.
 */
final readonly class KeyRequest
{
    /**
     * @param string $typ     the artifact's typ
     * @param Role   $role    the signer role the draft 7.3 table requires for typ
     * @param string $kid     the header kid, empty when absent
     * @param string $header  the decoded protected header, as received
     * @param string $payload the decoded payload, as received
     */
    public function __construct(
        public string $typ,
        public Role $role,
        public string $kid,
        public string $header,
        public string $payload,
    ) {}
}
