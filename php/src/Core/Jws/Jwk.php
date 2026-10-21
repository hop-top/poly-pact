<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * A public key in JSON Web Key form (RFC 7517): an EC P-256 key (RFC 7518
 * section 6.2.1). An empty string is an absent member; kid, alg and use are
 * optional.
 *
 * A Jwk built in PHP is checked when it is used: by publicKey(),
 * Jws::thumbprint(), new KeySet() and Jws::sign().
 */
final readonly class Jwk
{
    public function __construct(
        public string $kty = '',
        public string $crv = '',
        public string $x = '',
        public string $y = '',
        public string $kid = '',
        public string $alg = '',
        public string $use = '',
    ) {}

    /**
     * The one algorithm the key's kty and crv serve: ES256 for EC P-256,
     * Ed25519 for OKP Ed25519 (RFC 9864 section 2.2, RFC 8037 section 2).
     * The key material is not checked, nor whether the algorithm is
     * negotiated.
     *
     * @throws JwsError JWK_CURVE for any other key type
     */
    public function algorithm(): string
    {
        if ($this->kty === 'EC' && $this->crv === 'P-256') {
            return Jws::ALG_ES256;
        }
        if ($this->kty === 'OKP' && $this->crv === 'Ed25519') {
            return Jws::ALG_ED25519;
        }

        throw new JwsError(Reason::JWK_CURVE, \sprintf('kty %s crv %s, want EC P-256 or, when negotiated, OKP Ed25519', Text::quote($this->kty), Text::quote($this->crv)));
    }

    /**
     * Check kty, crv, x and y and return the OpenSSL public key; kid, alg and
     * use are not looked at (Go JWK.PublicKey).
     *
     * Each coordinate must be the canonical unpadded base64url of exactly 32
     * octets before the point is built, so a malformed coordinate is
     * JWK_INVALID even where its value is not a point of the curve; a
     * well-formed pair that is not a point (a coordinate not below p
     * included) is JWK_OFF_CURVE.
     *
     * @throws JwsError
     */
    public function publicKey(): \OpenSSLAsymmetricKey
    {
        if ($this->kty !== 'EC' || $this->crv !== 'P-256') {
            throw new JwsError(Reason::JWK_CURVE, \sprintf('kty %s crv %s, want EC P-256', Text::quote($this->kty), Text::quote($this->crv)));
        }
        $x = self::coordinate('x', $this->x);
        $y = self::coordinate('y', $this->y);
        $key = Es256::publicKey($x, $y);
        if ($key === null) {
            throw new JwsError(Reason::JWK_OFF_CURVE, 'not a point of P-256');
        }

        return $key;
    }

    /**
     * The 32 octets of the coordinate $name.
     *
     * @throws JwsError JWK_INVALID
     */
    private static function coordinate(string $name, string $s): string
    {
        try {
            $b = Base64Url::decode($s);
        } catch (\UnexpectedValueException $e) {
            throw new JwsError(Reason::JWK_INVALID, $name . ' is not canonical base64url', $e);
        }
        if (\strlen($b) !== Es256::COORDINATE_OCTETS) {
            throw new JwsError(Reason::JWK_INVALID, \sprintf('%s has %d octets, want %d', $name, \strlen($b), Es256::COORDINATE_OCTETS));
        }

        return $b;
    }
}
