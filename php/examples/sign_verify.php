<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use HopTop\Pact\Core\Digest\Digests;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Header;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Role;
use HopTop\Pact\Core\Jws\StaticResolver;

// A requirement publisher signs a payload with its P-256 key (ES256).
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($key === false) {
    throw new RuntimeException('no P-256 key');
}
$payload = '{"pact_version":"0.1","jti":"contract-1"}';
$compact = Jws::sign(new Header(typ: Jws::TYP_REQUIREMENTS, kid: 'publisher-1'), $payload, $key);

// A gateway that trusts the publisher's public key verifies the compact JWS.
$public = Jws::publicJwk($key);
$publisher = new Jwk($public->kty, $public->crv, $public->x, $public->y, kid: 'publisher-1');
$trusted = new StaticResolver([Role::REQUIREMENT_PUBLISHER->value => new KeySet($publisher)]);
$parsed = Jws::verify($compact, $trusted);
echo $parsed->role->value, ' ', $parsed->header->kid, ' ', $parsed->payload, "\n";

// Object digest: unpadded base64url SHA-256 of the RFC 8785 canonical form.
echo Digests::objectDigest(new JsonObject(['jti' => 'contract-1', 'pact_version' => '0.1'])), "\n";
