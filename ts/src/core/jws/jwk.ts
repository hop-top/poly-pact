/**
 * Public JWKs of the profile (Go go/core/jws/jwk.go): EC P-256 keys (RFC
 * 7518 section 6.2.1) and their RFC 7638 thumbprint.
 *
 * Node's JWK import accepts padded, non-canonical, 31- and 33-octet
 * coordinates, so `x` and `y` go
 * through the canonical base64url decoder and must be 32 octets each before
 * `createPublicKey`; an import failure is `jwk-off-curve`.
 *
 * @module
 */
import { createHash, createPublicKey, KeyObject } from 'node:crypto';
import { notImplemented } from '../../internal/notimplemented.ts';
import type { Digest } from '../values.ts';
import { decodeSegment } from './base64url.ts';
import { fail, Reason } from './errors.ts';
import { strictObject } from './json.ts';
import { ALG_ED25519, ALG_ES256 } from './typ.ts';

/**
 * A public key in JSON Web Key form (RFC 7517): an EC P-256 key (RFC 7518
 * section 6.2.1). `kid`, `alg` and `use` are optional. A JWK built in code
 * is checked when it is used: by {@link publicKeyOf}, {@link thumbprint},
 * `new KeySet` and `sign`.
 */
export interface JWK {
  readonly kty: string;
  readonly crv: string;
  readonly x: string;
  readonly y?: string;
  readonly kid?: string;
  readonly alg?: string;
  readonly use?: string;
}

// The private key members of RFC 7518 section 6: EC d, RSA d, p, q, dp, dq,
// qi, oth, and the symmetric k.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

// The string members of a JWK, in the order Go reads them.
const STRING_MEMBERS = ['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use'] as const;

const q = (s: unknown) => JSON.stringify(s ?? '');

/**
 * Whether `alg` is an algorithm of `names` (Go Algorithms.Accepts): ES256
 * or Ed25519, and listed in `names`, or ES256 when `names` is empty.
 */
export function accepts(names: readonly string[], alg: string): boolean {
  if (alg !== ALG_ES256 && alg !== ALG_ED25519) return false;
  return names.length === 0 ? alg === ALG_ES256 : names.includes(alg);
}

/**
 * Strictly parses a JWK and checks that it is a usable ES256 public key: a
 * strict JSON object (draft 7.1) without private members, kty EC, crv
 * P-256, x and y the canonical unpadded base64url of 32 octets each and
 * together a point of the curve, alg and use, when present, ES256 and sig,
 * and key_ops, when present, an array of distinct strings that names verify
 * (RFC 7517 section 4.3). key_ops is checked, not kept. Members RFC 7517
 * does not define for this use are ignored (RFC 7517 section 4). Throws a
 * `JWSError`.
 */
export function parseJWK(raw: Uint8Array | string): JWK {
  return parseJWKFor(raw, []);
}

/** {@link parseJWK} for the negotiated algorithms `names`. */
export function parseJWKFor(raw: Uint8Array | string, names: readonly string[]): JWK {
  let m: Record<string, unknown>;
  try {
    m = strictObject(raw);
  } catch (err) {
    throw fail(Reason.JWK_INVALID, 'not a strict JSON object', err);
  }
  for (const name of PRIVATE_MEMBERS) {
    if (Object.hasOwn(m, name)) throw fail(Reason.JWK_PRIVATE, `member ${name}`);
  }
  const k: Record<string, string> = {};
  for (const name of STRING_MEMBERS) {
    if (!Object.hasOwn(m, name)) continue;
    const v = m[name];
    if (typeof v !== 'string') throw fail(Reason.JWK_INVALID, `${name} is not a string`);
    k[name] = v;
  }
  const jwk = Object.freeze({ kty: '', crv: '', x: '', ...k }) as JWK;
  checkKey(jwk, names);
  if (Object.hasOwn(m, 'key_ops')) checkKeyOps(m.key_ops);
  return jwk;
}

// A key_ops member (RFC 7517 section 4.3): an array of strings, none twice
// ("Duplicate key operation values MUST NOT be present"), that names
// verify, the operation a trusted public key serves.
function checkKeyOps(v: unknown): void {
  if (!Array.isArray(v) || !v.every((op) => typeof op === 'string')) {
    throw fail(Reason.JWK_INVALID, 'key_ops is not an array of strings');
  }
  for (const [i, op] of v.entries()) {
    if (v.indexOf(op) !== i) throw fail(Reason.JWK_INVALID, `key_ops names ${q(op)} twice`);
  }
  if (!v.includes('verify')) {
    throw fail(Reason.JWK_USAGE, `key_ops ${JSON.stringify(v)} does not name verify`);
  }
}

/**
 * The algorithm of the checked key `k` after checking that `names` accepts
 * it, that the key material is valid for it, and that alg and use, when
 * present, are that algorithm and sig; and the platform key.
 */
export function checkKey(
  k: JWK,
  names: readonly string[],
): { readonly alg: string; readonly key: KeyObject } {
  const alg = algorithmOf(k);
  if (!accepts(names, alg)) {
    throw fail(Reason.JWK_CURVE, `kty ${q(k.kty)} crv ${q(k.crv)}: ${alg} is not negotiated`);
  }
  const key = alg === ALG_ES256 ? publicKeyOf(k) : notImplemented('jws.ed25519PublicKeyOf');
  checkUsage(k, alg);
  return { alg, key };
}

/** Throws `jwk-usage` unless alg and use, when present, are `alg` and sig. */
export function checkUsage(k: JWK, alg: string): void {
  if ((k.alg ?? '') !== '' && k.alg !== alg) {
    throw fail(Reason.JWK_USAGE, `alg ${q(k.alg)}, want ${alg}`);
  }
  if ((k.use ?? '') !== '' && k.use !== 'sig') {
    throw fail(Reason.JWK_USAGE, `use ${q(k.use)}, want sig`);
  }
}

/**
 * The one algorithm the key's kty and crv serve: ES256 for EC P-256,
 * Ed25519 for OKP Ed25519 (RFC 9864 section 2.2, RFC 8037 section 2).
 * Other key types are `jwk-curve`. It does not check the key material, nor
 * whether the algorithm is negotiated.
 */
export function algorithmOf(k: JWK): string {
  if (k.kty === 'EC' && k.crv === 'P-256') return ALG_ES256;
  if (k.kty === 'OKP' && k.crv === 'Ed25519') return ALG_ED25519;
  throw fail(
    Reason.JWK_CURVE,
    `kty ${q(k.kty)} crv ${q(k.crv)}, want EC P-256 or, when negotiated, OKP Ed25519`,
  );
}

function coordinate(name: string, s: unknown): Uint8Array {
  let b: Uint8Array;
  try {
    if (typeof s !== 'string') throw new Error(`a ${typeof s}, not a string`);
    b = decodeSegment(s);
  } catch (err) {
    throw fail(Reason.JWK_INVALID, `${name} is not canonical base64url`, err);
  }
  if (b.length !== 32) throw fail(Reason.JWK_INVALID, `${name} has ${b.length} octets, want 32`);
  return b;
}

/**
 * Checks kty, crv, x and y and returns the platform public key: `jwk-curve`
 * unless EC P-256, `jwk-invalid` unless x and y are the canonical base64url
 * of 32 octets each, `jwk-off-curve` when the point is not on the curve. It
 * does not look at kid, alg or use.
 */
export function publicKeyOf(k: JWK): KeyObject {
  if (k.kty !== 'EC' || k.crv !== 'P-256') {
    throw fail(Reason.JWK_CURVE, `kty ${q(k.kty)} crv ${q(k.crv)}, want EC P-256`);
  }
  coordinate('x', k.x);
  coordinate('y', k.y ?? '');
  try {
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y ?? '' },
      format: 'jwk',
    });
  } catch (err) {
    throw fail(Reason.JWK_OFF_CURVE, 'not a point of P-256', err);
  }
}

/**
 * The JWK of a P-256 key, with x and y at their full 32 octets (RFC 7518
 * section 6.2.1.2) and no optional members. A private key gives the JWK of
 * its public part.
 */
export function publicJWK(key: KeyObject): JWK {
  if (!(key instanceof KeyObject)) throw fail(Reason.JWK_INVALID, 'not a KeyObject');
  if (key.type === 'secret') throw fail(Reason.JWK_INVALID, 'a secret key has no public JWK');
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw fail(Reason.JWK_CURVE, 'not a P-256 key');
  }
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  const j = pub.export({ format: 'jwk' });
  coordinate('x', j.x);
  coordinate('y', j.y);
  return Object.freeze({ kty: 'EC', crv: 'P-256', x: j.x as string, y: j.y as string });
}

/**
 * The RFC 7638 SHA-256 thumbprint of `k`: base64url, without padding, of
 * SHA-256 over the required members in lexicographic order without white
 * space, `{"crv":...,"kty":...,"x":...,"y":...}`. Optional members do not
 * enter it. `k` must be a valid P-256 key (see {@link publicKeyOf}); the
 * coordinates are hashed as written, which for a valid key is their
 * canonical 43-character form.
 */
export function thumbprint(k: JWK): Digest {
  if (algorithmOf(k) !== ALG_ES256) return notImplemented('jws.thumbprint(Ed25519)');
  publicKeyOf(k);
  // The values are base64url and fixed ASCII names, so nothing needs JSON
  // escaping (RFC 7638 section 3.3).
  const input = `{"crv":"${k.crv}","kty":"${k.kty}","x":"${k.x}","y":"${k.y}"}`;
  return createHash('sha256').update(input).digest('base64url') as Digest;
}
