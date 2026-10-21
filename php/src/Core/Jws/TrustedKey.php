<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\Digest;

/**
 * A checked key: the one algorithm it verifies, its OpenSSL public key and
 * its RFC 7638 thumbprint.
 *
 * @internal
 */
final readonly class TrustedKey
{
    private function __construct(
        public Jwk $jwk,
        public string $alg,
        public \OpenSSLAsymmetricKey $pub,
        public Digest $thumbprint,
    ) {}

    /**
     * Check $k as Jws::parseJwk() does and keep its public key and thumbprint.
     *
     * @throws JwsError
     */
    public static function of(Jwk $k): self
    {
        $pub = JwkReader::check($k);

        return new self($k, Jws::ALG_ES256, $pub, Jws::thumbprint($k));
    }
}
