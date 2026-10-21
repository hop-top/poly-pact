import { generateKeyPairSync } from 'node:crypto';
import { objectDigest } from '../src/core/digest.ts';
import {
  KeySet,
  publicJWK,
  Role,
  StaticResolver,
  sign,
  TYP_REQUIREMENTS,
  verify,
} from '../src/core/jws/index.ts';

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
