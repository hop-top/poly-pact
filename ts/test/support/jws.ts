// Helpers of the ported go/core/jws tests (helpers_test.go): the P-256 test
// keys of spec/v1.0/fixtures/keys by scalar, compact JWS signed with node:crypto
// directly (so a test can build inputs the package's sign refuses to make),
// and the reason assertion.

import assert from 'node:assert/strict';
import { createECDH, createPrivateKey, type KeyObject, sign } from 'node:crypto';
import {
  type JWK,
  JWSError,
  KeySet,
  parseJWK,
  type Reason,
  Role,
  reasonOf,
  StaticResolver,
} from '../../src/core/jws/index.ts';
import { readFixture } from './fixtures.ts';

/** The holder_jkt printed in draft Appendix C. */
export const HOLDER_JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';

/** The order n of the P-256 base point (SEC 2 section 2.4.2). */
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** The field prime p of P-256 (SEC 2 section 2.4.2). */
export const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

export const EVIDENCE_HEADER =
  '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}';

export const SMALL_PAYLOAD = '{"pact_version":"0.1","jti":"unit"}';

const utf8 = new TextEncoder();

/** Unpadded base64url of a string's UTF-8 bytes or of raw octets. */
export function b64(v: string | Uint8Array): string {
  return Buffer.from(typeof v === 'string' ? utf8.encode(v) : v).toString('base64url');
}

/** The 32 big-endian octets of n. */
export function octets32(n: bigint): Uint8Array {
  return new Uint8Array(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
}

/** The unsigned integer of big-endian octets. */
export function int(b: Uint8Array): bigint {
  return b.length === 0 ? 0n : BigInt(`0x${Buffer.from(b).toString('hex')}`);
}

/** The public point of the P-256 scalar n, as base64url coordinates. */
export function scalarPoint(n: bigint): { x: string; y: string; d: string } {
  const d = Buffer.from(octets32(n));
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const p = ecdh.getPublicKey();
  return {
    x: p.subarray(1, 33).toString('base64url'),
    y: p.subarray(33).toString('base64url'),
    d: d.toString('base64url'),
  };
}

/** The P-256 private key whose scalar is n, as the test keys of spec/v1.0/fixtures/keys define them. */
export function scalarKey(n: bigint | number): KeyObject {
  const { x, y, d } = scalarPoint(BigInt(n));
  return createPrivateKey({ key: { kty: 'EC', crv: 'P-256', x, y, d }, format: 'jwk' });
}

/** spec/v1.0/fixtures/keys/NAME.jwk.json, parsed by the package. */
export function fixtureJWK(name: string): JWK {
  return parseJWK(readFixture(`keys/${name}.jwk.json`));
}

/** A copy of k with another kid. */
export function withKid(k: JWK, kid: string): JWK {
  return { ...k, kid };
}

/** The 64-octet R || S of signingInput under key, from node:crypto alone. */
export function rawSig(signingInput: string, key: KeyObject): Uint8Array {
  return new Uint8Array(
    sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }),
  );
}

/** header.payload signed with node:crypto directly. */
export function rawCompact(header: string, payload: string, key: KeyObject): string {
  const si = `${b64(header)}.${b64(payload)}`;
  return `${si}.${b64(rawSig(si, key))}`;
}

/** The error f throws, or undefined. */
export function errorOf(f: () => unknown): unknown {
  try {
    f();
  } catch (err) {
    return err;
  }
  return undefined;
}

/** f throws a JWSError of reason want; returns it. */
export function wantReason(f: () => unknown, want: Reason): JWSError {
  const err = errorOf(f);
  assert.ok(err !== undefined, `got no error, want ${want}`);
  assert.equal(reasonOf(err), want, `reason of ${String(err)}`);
  assert.ok(err instanceof JWSError, `${String(err)} is not a JWSError`);
  return err;
}

/**
 * Trusts the issuer test key for the issuer role and expects the Appendix C
 * holder thumbprint for holder-signed artifacts.
 */
export function issuerResolver(): StaticResolver {
  return new StaticResolver(new Map([[Role.ISSUER, new KeySet(fixtureJWK('issuer'))]]), HOLDER_JKT);
}
