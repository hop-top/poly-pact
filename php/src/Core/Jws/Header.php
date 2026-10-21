<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/** The protected header of a PACT JWS. All header members are protected (draft 7.2). */
final readonly class Header
{
    /**
     * @param string   $alg ES256 (draft 7.2); Jws::sign() accepts it empty
     * @param string   $typ a typ of the draft 7.3 table
     * @param string   $kid the signing key within the trusted key set of a
     *                      service-signed artifact; for a holder-signed
     *                      artifact optional, and no part of key selection
     * @param Jwk|null $jwk the embedded public key of a holder-signed artifact, null otherwise
     */
    public function __construct(
        public string $alg = '',
        public string $typ = '',
        public string $kid = '',
        public ?Jwk $jwk = null,
    ) {}
}
