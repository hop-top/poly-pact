# PACT (PHP SDK)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

PHP SDK: wire types, strict JSON, JCS, digests, ES256 JWS and schema validation.

Read-only mirror of `php/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) (component
`pact-php`); open issues and pull requests there.

Status: prerelease. The protocol is a [draft](https://github.com/hop-top/spec-pact), and the API
may change between prerelease versions.

[![Packagist](https://img.shields.io/packagist/v/hop-top/pact)](https://packagist.org/packages/hop-top/pact)
[![ci-php](https://github.com/hop-top/poly-pact/actions/workflows/ci-php.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-php.yml)

## Table of contents

- [Install](https://github.com/hop-top/pact-php#install)
- [Usage](https://github.com/hop-top/pact-php#usage)
- [Limitations](https://github.com/hop-top/pact-php#limitations)
- [API](https://github.com/hop-top/pact-php#api)
- [Conformance](https://github.com/hop-top/pact-php#conformance)
- [Contributing](https://github.com/hop-top/pact-php#contributing)
- [Security](https://github.com/hop-top/pact-php#security)
- [License](https://github.com/hop-top/pact-php#license)

[PACT](https://github.com/hop-top/spec-pact) is a protocol
for agent profiles, intent, reputation and adaptive admission: a gateway admits an agent's
signed, purpose-bound request, and native authorization stays final. This package is its PHP
SDK for the core of the protocol: the wire objects and the primitives every party needs to read,
sign and check them. Its namespaces follow the packages of the Go reference implementation,
[pact-go](https://github.com/hop-top/pact-go), and read the same conformance fixtures.

## Install

```sh
composer require hop-top/pact
```

The namespace is `HopTop\Pact`.

Requirements: PHP 8.4 or later with the `openssl`, `mbstring`, `json`, `hash`, `pcre` and `iconv`
extensions; CI tests 8.4 and 8.5 on Linux. One dependency: `opis/json-schema`, for schema
validation.

## Usage

Sign a payload as a requirement publisher, verify it as a gateway that trusts the publisher's
key, and compute an object digest:

```php
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
```

```text
requirement-publisher publisher-1 {"pact_version":"0.1","jti":"contract-1"}
J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4
```

The program is
[examples/sign_verify.php](https://github.com/hop-top/pact-php/blob/main/examples/sign_verify.php);
run it with `php examples/sign_verify.php` after `composer install`.

## Limitations

- The protocol is a draft. Its specification claims no interoperability suite and no
  independent security assessment.
- ES256 is the only signature algorithm. Ed25519, optional in the draft, is not implemented:
  `Core\Jws` rejects Ed25519 keys and signatures.
- The package covers the core of the protocol. It has no native adapter contract, no HTTP
  binding, no requirement contracts, holder, validator or gateway middleware, no reputation
  service, no fixture-manifest checker and no evaluation-case loader. Use [pact-go](https://github.com/hop-top/pact-go) for those.
- JSON objects are `HopTop\Pact\Core\JsonObject` values, never PHP arrays or `stdClass`: a
  PHP array cannot tell `{}` from `[]` and turns a member name such as `"1"` into an integer
  key.
- Instants are `DateTimeImmutable` values with microsecond precision; durations are integer
  microseconds.

## API

Every class carries its reference in its doc comments. Each namespace mirrors the Go package of
the same path, documented at [pkg.go.dev/hop.top/pact-go](https://pkg.go.dev/hop.top/pact-go).

| Namespace | What it gives |
|---|---|
| `HopTop\Pact\Core` | classes of the wire objects, enums, `Digest`, `Limits` and `JsonObject` |
| `Core\StrictJson`, `Core\Jcs`, `Core\Digest`, `Core\Clock` | strict JSON decoding, RFC 8785 canonicalization, the object, artifact and bytes digests, and the time rules of the draft |
| `Core\Schema` | validation against the PACT JSON Schema, with the RFC 3986 `uri` format |
| `Core\Jws` | compact JWS signing and verification under the PACT profile (ES256), JWKs, key resolution and RFC 7638 thumbprints |
| `PactError` | the root of the package's exceptions |

## Conformance

The language-neutral fixtures of the [specification](https://github.com/hop-top/spec-pact)
(`v1.0/fixtures`, indexed by `v1.0/fixtures/manifest.json`) run against this package in the
source repository, through the harness `php scripts/vectors.php`. A failure fails CI for:

- the shared vectors of `strictjson`, `jcs`, `digest`, `jws` and `schema`;
- the key fixtures, except the Ed25519 key;
- the schema cases (`parse`, `schema`).

The evaluation, outcome and learning cases judge an implementation under test, and are run
with `pactc` of [hop-top/pact](https://github.com/hop-top/pact).

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `php/`; this
mirror accepts no issues or pull requests. See
[CONTRIBUTING.md](https://github.com/hop-top/poly-pact/blob/next/CONTRIBUTING.md) and the
[code of conduct](https://github.com/hop-top/poly-pact/blob/next/CODE_OF_CONDUCT.md).

PHP and Composer come from your system, not from the repository's toolchain pins. From `php/`:

```sh
composer install
composer test
composer lint
```

`composer.json` holds the exact versions of the dependencies and `composer.lock` the resolved
set. From the repository root, `make php-lint php-test php-vectors php-check-schema php-build`
runs the checks CI runs.

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](https://github.com/hop-top/poly-pact/blob/next/SECURITY.md).

## License

MIT, © 2026 Idea Crafters LLC and Jad Bitar. See
[LICENSE](https://github.com/hop-top/pact-php/blob/main/LICENSE).
