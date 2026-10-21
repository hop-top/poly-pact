<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\Digest;

/** A verified compact JWS. */
final readonly class ParsedJws
{
    /**
     * @param string $compact       the input, unchanged
     * @param Header $header        the protected header members the profile defines
     * @param Role   $role          the signer role of header->typ
     * @param string $rawHeader     the decoded protected header, exactly as received
     * @param string $payload       the decoded payload, exactly as received; decode it with
     *                              StrictJson into the artifact type, and compute digests
     *                              over these bytes or over compact, never over a re-encoding
     * @param string $signingInput  the received text the signature covers: compact up to its second period
     * @param string $signature     the 64 octets R || S
     * @param Jwk    $key           the key that verified the signature
     * @param Digest $keyThumbprint the RFC 7638 thumbprint of key
     */
    public function __construct(
        public string $compact,
        public Header $header,
        public Role $role,
        public string $rawHeader,
        public string $payload,
        public string $signingInput,
        public string $signature,
        public Jwk $key,
        public Digest $keyThumbprint,
    ) {}
}
