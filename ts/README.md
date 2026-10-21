# PACT (TypeScript SDK)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

TypeScript SDK.

Read-only mirror of [hop-top/poly-pact](https://github.com/hop-top/poly-pact) (component `pact-ts`, directory `ts/`); open issues and pull requests there.

Status: pre-1.0; any minor release can change the API.

[![npm](https://img.shields.io/npm/v/@hop-top/pact)](https://www.npmjs.com/package/@hop-top/pact)

[PACT](https://github.com/hop-top/spec-pact) is a draft protocol in which a gateway admits an agent's signed, purpose-bound request while native authorization stays final; its [draft](https://github.com/hop-top/spec-pact/blob/main/v1.0/draft.md) is the authority on behavior. This package implements its wire types, the JSON, digest, JWS, clock and HTTP binding rules, the native adapter contract with its conformance suite, and an in-memory reference adapter.

## Install

```sh
npm install @hop-top/pact
```

Requirements: Node.js 22.18 or later. The package is ESM only and ships its own type declarations. Its one runtime dependency is [ajv](https://ajv.js.org), used by `@hop-top/pact/core/schema`.

## Usage

Sign a payload as a requirement publisher, verify it with the publisher's trusted key, and compute an object digest:

```ts
import { generateKeyPairSync } from 'node:crypto';
import { objectDigest } from '@hop-top/pact/core/digest';
import {
  KeySet,
  publicJWK,
  Role,
  StaticResolver,
  sign,
  TYP_REQUIREMENTS,
  verify,
} from '@hop-top/pact/core/jws';

// A requirement publisher signs a payload with its P-256 key.
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const payload = new TextEncoder().encode('{"pact_version":"0.1","jti":"contract-1"}');
const compact = sign({ typ: TYP_REQUIREMENTS, kid: 'publisher-1' }, payload, privateKey);

// A verifier that trusts the publisher's public key for that role checks it.
const publisher = new KeySet({ ...publicJWK(privateKey), kid: 'publisher-1' });
const trusted = new StaticResolver(new Map([[Role.REQUIREMENT_PUBLISHER, publisher]]));
const parsed = verify(compact, trusted);
console.log(parsed.role, parsed.header.kid, new TextDecoder().decode(parsed.payload));

// The object digest: SHA-256 over the RFC 8785 form, base64url.
console.log(objectDigest({ jti: 'contract-1', pact_version: '0.1' }));
```

```text
requirement-publisher publisher-1 {"pact_version":"0.1","jti":"contract-1"}
J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4
```

The runnable program is [`test/readme-example.ts`](test/readme-example.ts).

## Limitations

- Ed25519 keys, optional in the draft, are not supported: checking one throws `NotImplementedError`. ES256 is the only signature algorithm.
- The package has no gateway, validator, holder, reputation service or conformance runner, and no native adapter other than the in-memory one. Those are in the Go reference implementation, [hop.top/pact-go](https://github.com/hop-top/pact-go).

## API

Each entry point is a subpath export. Its module comment states what it covers and the draft sections it implements; every export carries TSDoc in the shipped `.d.ts` files, which editors show inline. The sources are in [`src/`](src/).

| Import | Contents |
|---|---|
| `@hop-top/pact` | wire object types, enums, member shapes, limits and constants |
| `@hop-top/pact/core/strictjson` | strict JSON decoding: size, depth, duplicate names and the other checks `JSON.parse` does not make |
| `@hop-top/pact/core/jcs` | RFC 8785 JSON canonicalization |
| `@hop-top/pact/core/digest` | object, artifact and bytes digests (SHA-256, base64url) |
| `@hop-top/pact/core/jws` | compact JWS signing and verification (ES256), JWKs, key sets and resolvers |
| `@hop-top/pact/core/clock` | time windows, skew and baseline lifetimes |
| `@hop-top/pact/core/binding` | operation context of the baseline HTTP request binding |
| `@hop-top/pact/core/schema` | JSON Schema validation against the bundled `schema/pact.schema.json` |
| `@hop-top/pact/adapter` | native adapter contract: the seven functions, their value types and errors |
| `@hop-top/pact/adapter/enroll` | enrollment registry contract and binding resolver |
| `@hop-top/pact/adapter/enroll/memory` | in-memory enrollment registry |
| `@hop-top/pact/adapter/freshness` | age limits of a field rule against a native claim |
| `@hop-top/pact/adapter/adaptertest` | adapter conformance suite: `runConformance` for `node:test`, `evaluateConformance` for any runner |
| `@hop-top/pact/adapters/memory` | in-memory reference adapter |
| `@hop-top/pact/runner/manifest` | fixture manifest reading and checks |
| `@hop-top/pact/conformance` | evaluation-case loader for the conformance fixtures |

## Conformance

The package is tested against the language-neutral [conformance fixtures](https://github.com/hop-top/spec-pact/tree/main/v1.0/fixtures) of the specification. It passes the shared vectors for strict JSON, JCS, digests, JWS, schema and the HTTP binding, and the fixture key set; the in-memory adapter passes every common adapter case (`adapters/_common`) of the conformance suite.

## Contributing

Questions, bug reports and pull requests go to [hop-top/poly-pact](https://github.com/hop-top/poly-pact), under `ts/`; see its [contributing guide](https://github.com/hop-top/poly-pact/blob/HEAD/CONTRIBUTING.md) and [code of conduct](https://github.com/hop-top/poly-pact/blob/HEAD/CODE_OF_CONDUCT.md). From the repository root, `make ts-lint ts-test ts-build` runs this package's checks. Report vulnerabilities by email to security@hop.top, not in a public issue; see the [security policy](https://github.com/hop-top/poly-pact/blob/HEAD/SECURITY.md).

## License

MIT, copyright Idea Crafters LLC and jadb. See [LICENSE](LICENSE).
