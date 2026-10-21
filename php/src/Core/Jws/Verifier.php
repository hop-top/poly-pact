<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJsonError;

/**
 * Verifies compact JWS under the profile (Go Verifier).
 *
 * Verification checks a compact JWS in this order and stops at the first
 * failure, throwing JwsError with its Reason:
 *
 * 1. the length bound (maxCompactBytes, in bytes), then three segments
 *    separated by two periods with a non-empty header segment;
 * 2. the header segment is canonical unpadded base64url and a strict JSON
 *    object (no duplicate members, valid Unicode, bounded depth);
 * 3. no crit, b64, jku, x5u or x5c member; alg is ES256; typ is in the
 *    draft 7.3 table and, when $typ is set, equals it; kid, if present, is a
 *    string. Other members are ignored (RFC 7515 section 4);
 * 4. by the signer role of typ: a holder-signed artifact embeds a jwk that
 *    Jws::parseJwk() accepts; any other artifact has a kid and no jwk;
 * 5. the payload segment is not empty (no detached payload), is canonical
 *    base64url and a strict JSON object;
 * 6. the signature segment is canonical base64url of exactly 64 octets;
 * 7. the key: for a holder, the embedded jwk's thumbprint equals the
 *    holder_jkt the KeyResolver expects; otherwise kid is found in the key
 *    set the resolver trusts for the role, and nowhere else;
 * 8. the ECDSA signature over the received signing input, the compact text
 *    up to its second period. Nothing is decoded and re-encoded to rebuild
 *    it. R or S outside [1, n-1] is signature-invalid; a high S is
 *    accepted: neither RFC 7518 nor the draft has a low-S rule.
 *
 * verify() checks the JWS, not the artifact: decode ParsedJws::$payload with
 * StrictJson into its wire type and apply the schema, time and authority
 * rules separately.
 */
final readonly class Verifier
{
    /** The header members the profile rejects, in the order checked. */
    private const PROHIBITED = [
        'crit' => Reason::HEADER_CRIT,
        'b64' => Reason::HEADER_B64,
        'jku' => Reason::HEADER_JKU,
        'x5u' => Reason::HEADER_X5U,
        'x5c' => Reason::HEADER_X5C,
    ];

    /**
     * @param KeyResolver|null $keys            resolves the verification key; required
     * @param string           $typ             when not empty, the only typ accepted: the typ the
     *                                          caller's slot expects (draft 7.2: validators check
     *                                          the artifact-specific typ)
     * @param int              $maxCompactBytes bounds the compact serialization in bytes; 0 or
     *                                          less is Jws::DEFAULT_MAX_COMPACT_BYTES
     * @param Limits|null      $limits          bounds the strict decoding of the protected header
     *                                          and payload; null is the StrictJson default
     */
    public function __construct(
        public ?KeyResolver $keys,
        public string $typ = '',
        public int $maxCompactBytes = 0,
        public ?Limits $limits = null,
    ) {}

    /**
     * Run the ordered checks of the profile.
     *
     * @throws JwsError on the first that fails
     */
    public function verify(string $compact): ParsedJws
    {
        $limit = $this->maxCompactBytes > 0 ? $this->maxCompactBytes : Jws::DEFAULT_MAX_COMPACT_BYTES;
        if (\strlen($compact) > $limit) {
            throw new JwsError(Reason::COMPACT_SIZE, \sprintf('%d bytes, limit %d', \strlen($compact), $limit));
        }
        $first = strpos($compact, '.');
        $last = strrpos($compact, '.');
        if ($first === false || $last === false || $first === $last || str_contains(substr($compact, $first + 1, $last - $first - 1), '.')) {
            throw new JwsError(Reason::COMPACT_FORM, 'want three segments separated by two periods');
        }
        $h64 = substr($compact, 0, $first);
        $p64 = substr($compact, $first + 1, $last - $first - 1);
        $s64 = substr($compact, $last + 1);
        if ($h64 === '') {
            throw new JwsError(Reason::COMPACT_FORM, 'empty protected header');
        }

        $rawHeader = self::segment($h64, 'protected header');
        [$header, $role, $members] = $this->parseHeader($rawHeader);
        if ($this->typ !== '' && $header->typ !== $this->typ) {
            throw new JwsError(Reason::TYP_MISMATCH, \sprintf('typ %s, want %s', Text::quote($header->typ), Text::quote($this->typ)));
        }
        if ($role === Role::HOLDER) {
            if (!$members->has('jwk')) {
                throw new JwsError(Reason::JWK_MISSING, 'a holder-signed artifact embeds its public jwk');
            }
            $k = JwkReader::fromValue($members->get('jwk'));
            self::matchAlg($header->alg, $k);
            $header = new Header($header->alg, $header->typ, $header->kid, $k);
        } else {
            if ($members->has('jwk')) {
                throw new JwsError(Reason::JWK_UNEXPECTED, \sprintf('typ %s is verified by kid, not by an embedded jwk', $header->typ));
            }
            if ($header->kid === '') {
                throw new JwsError(Reason::KID_MISSING);
            }
        }

        if ($p64 === '') {
            throw new JwsError(Reason::PAYLOAD_DETACHED);
        }
        $payload = self::segment($p64, 'payload');
        try {
            JwkReader::object($payload, $this->limits);
        } catch (StrictJsonError $e) {
            throw new JwsError(Reason::PAYLOAD_JSON, '', $e);
        }

        $sig = self::segment($s64, 'signature');
        if (\strlen($sig) !== Es256::SIGNATURE_OCTETS) {
            throw new JwsError(Reason::SIGNATURE_LENGTH, \sprintf('%d octets, want %d', \strlen($sig), Es256::SIGNATURE_OCTETS));
        }

        $key = $this->resolve(new KeyRequest($header->typ, $role, $header->kid, $rawHeader, $payload), $header->jwk);
        self::matchAlg($header->alg, $key->jwk);
        $signingInput = substr($compact, 0, $last);
        if (!Es256::verify($key->pub, $signingInput, $sig)) {
            throw new JwsError(Reason::SIGNATURE_INVALID);
        }

        return new ParsedJws($compact, $header, $role, $rawHeader, $payload, $signingInput, $sig, $key->jwk, $key->thumbprint);
    }

    /** @throws JwsError BASE64_URL */
    private static function segment(string $s, string $name): string
    {
        try {
            return Base64Url::decode($s);
        } catch (\UnexpectedValueException $e) {
            throw new JwsError(Reason::BASE64_URL, $name, $e);
        }
    }

    /**
     * Decode the protected header strictly and check the members that do
     * not depend on the signer role.
     *
     * @return array{Header, Role, JsonObject}
     *
     * @throws JwsError
     */
    private function parseHeader(string $raw): array
    {
        try {
            $m = JwkReader::object($raw, $this->limits);
        } catch (StrictJsonError $e) {
            throw new JwsError(Reason::HEADER_JSON, '', $e);
        }
        foreach (self::PROHIBITED as $name => $reason) {
            if ($m->has($name)) {
                throw new JwsError($reason, 'member ' . $name);
            }
        }
        if ($m->get('alg') !== Jws::ALG_ES256) {
            throw new JwsError(Reason::ALG_UNSUPPORTED, self::describe('alg', $m));
        }
        $typ = $m->get('typ');
        $role = \is_string($typ) ? Jws::typRole($typ) : null;
        if (!\is_string($typ) || $role === null) {
            throw new JwsError(Reason::TYP_UNSUPPORTED, self::describe('typ', $m));
        }
        $kid = $m->get('kid', '');
        if (!\is_string($kid)) {
            throw new JwsError(Reason::HEADER_JSON, 'kid is not a string');
        }

        return [new Header(Jws::ALG_ES256, $typ, $kid), $role, $m];
    }

    private static function describe(string $name, JsonObject $m): string
    {
        if (!$m->has($name)) {
            return 'no ' . $name;
        }
        $v = $m->get($name);

        return $name . ' ' . (\is_string($v) ? substr(Text::quote($v), 0, 64) : get_debug_type($v));
    }

    /**
     * The header alg must be the algorithm of the checked key $k: a key
     * serves exactly one algorithm (RFC 9864 section 2.2, RFC 8037 section 2).
     *
     * @throws JwsError JWK_USAGE
     */
    private static function matchAlg(string $alg, Jwk $k): void
    {
        $keyAlg = $k->algorithm();
        if ($keyAlg !== $alg) {
            $kid = $k->kid !== '' ? ' (kid ' . Text::quote($k->kid) . ')' : '';
            throw new JwsError(Reason::JWK_USAGE, \sprintf('alg %s, but the key%s is kty %s crv %s, a key for %s', $alg, $kid, $k->kty, $k->crv, $keyAlg));
        }
    }

    /** @throws JwsError */
    private function resolve(KeyRequest $req, ?Jwk $embedded): TrustedKey
    {
        if ($this->keys === null) {
            throw new JwsError(Reason::KEY_UNAVAILABLE, 'no key resolver');
        }
        if ($req->role === Role::HOLDER) {
            if ($embedded === null) {
                throw new JwsError(Reason::JWK_MISSING, 'a holder-signed artifact embeds its public jwk');
            }
            try {
                $want = $this->keys->holderJkt($req);
            } catch (\Exception $e) {
                throw new JwsError(Reason::KEY_UNAVAILABLE, 'holder_jkt', $e);
            }
            if ($want->value === '') {
                throw new JwsError(Reason::KEY_UNAVAILABLE, 'no expected holder_jkt');
            }
            $k = TrustedKey::of($embedded);
            if (!hash_equals($want->value, $k->thumbprint->value)) {
                throw new JwsError(Reason::HOLDER_JKT_MISMATCH, \sprintf('jwk thumbprint %s, expected %s', $k->thumbprint->value, $want->value));
            }

            return $k;
        }
        try {
            $set = $this->keys->trustedKeys($req);
        } catch (\Exception $e) {
            throw new JwsError(Reason::KEY_UNAVAILABLE, 'key set for ' . $req->role->value, $e);
        }
        $k = $set?->trusted($req->kid);
        if ($k === null) {
            throw new JwsError(Reason::KID_UNKNOWN, \sprintf('kid %s is not in the key set trusted for %s', Text::quote($req->kid), $req->role->value));
        }

        return $k;
    }
}
