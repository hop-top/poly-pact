/**
 * Trusted keys and key resolution (Go go/core/jws/keys.go). Keys come only
 * from configuration: a {@link KeySet} holds trusted public keys by kid; a
 * {@link KeyResolver} returns the set for a signer role, or the holder_jkt
 * enrolled for the agent. The package never fetches keys.
 *
 * @module
 */
import type { KeyObject } from 'node:crypto';
import type { Digest } from '../values.ts';
import { fail, Reason } from './errors.ts';
import { checkKey, type JWK, thumbprint } from './jwk.ts';
import type { Role } from './typ.ts';

/** A checked key: the one algorithm it verifies, its platform key and thumbprint. */
export interface TrustedKey {
  readonly jwk: JWK;
  readonly alg: string;
  readonly key: KeyObject;
  readonly thumbprint: Digest;
}

/** Checks `k` for the algorithms `names`, as `parseJWK` does. */
export function trustedKey(k: JWK, names: readonly string[]): TrustedKey {
  const jwk = Object.freeze({ ...k });
  const { alg, key } = checkKey(jwk, names);
  return Object.freeze({ jwk, alg, key, thumbprint: thumbprint(jwk) });
}

function build(keys: readonly JWK[], names: readonly string[]): Map<string, TrustedKey> {
  const out = new Map<string, TrustedKey>();
  for (const [i, k] of keys.entries()) {
    const kid = k.kid ?? '';
    if (kid === '') throw fail(Reason.KID_MISSING, `key ${i} has no kid`);
    if (out.has(kid)) throw fail(Reason.KID_DUPLICATE, `kid ${JSON.stringify(kid)}`);
    out.set(kid, trustedKey(k, names));
  }
  return out;
}

let keysOf: (s: KeySet) => ReadonlyMap<string, TrustedKey>;
let setKeys: (s: KeySet, keys: Map<string, TrustedKey>) => void;

/**
 * A set of trusted public keys, looked up by kid. It is built from
 * configuration, never from an artifact. `new KeySet(...keys)` checks each
 * key as `parseJWK` does and requires a non-empty kid, unique within the
 * set; it is the baseline, ES256 keys alone (see `Algorithms.newKeySet`).
 * Throws a `JWSError`.
 */
export class KeySet {
  #keys: ReadonlyMap<string, TrustedKey>;

  constructor(...keys: JWK[]) {
    this.#keys = build(keys, []);
  }

  /** The key with the given kid, or `undefined`. */
  lookup(kid: string): JWK | undefined {
    return lookupTrusted(this, kid)?.jwk;
  }

  static {
    keysOf = (s) => s.#keys;
    setKeys = (s, keys) => {
      s.#keys = keys;
    };
  }
}

/** A {@link KeySet} of `keys` checked for the algorithms `names`. */
export function newKeySetFor(names: readonly string[], keys: readonly JWK[]): KeySet {
  const s = new KeySet();
  setKeys(s, build(keys, names));
  return s;
}

/** The checked key of `kid` in `set`; `undefined` for no set, an empty kid or an unknown one. */
export function lookupTrusted(set: KeySet | null | undefined, kid: string): TrustedKey | undefined {
  if (!(set instanceof KeySet) || kid === '') return undefined;
  return keysOf(set).get(kid);
}

/**
 * The key one verification needs. It is built from the protected header and
 * payload after their structural checks and before the signature is
 * checked: nothing in it is authenticated yet. A resolver may use `header`
 * and `payload` only to choose which configured trust record or enrollment
 * binding applies (draft 7.3: iss selects a trust record), never to obtain
 * key material.
 */
export interface KeyRequest {
  /** The artifact's typ. */
  readonly typ: string;
  /** The signer role the draft 7.3 table requires for typ. */
  readonly role: Role;
  /** The header kid, `''` when absent. */
  readonly kid: string;
  /** The decoded protected header, as received. */
  readonly header: Uint8Array;
  /** The decoded payload, as received. */
  readonly payload: Uint8Array;
}

/**
 * The trusted keys of a verification. `verify` calls exactly one method,
 * once: `holderJKT` for the holder role, `trustedKeys` for every other
 * role. A thrown error is `key-unavailable`, with the error as its cause.
 */
export interface KeyResolver {
  /**
   * The key set trusted for `req.role`. The header kid is looked up in it
   * and nowhere else; `null` or `undefined` has no keys.
   */
  trustedKeys(req: KeyRequest): KeySet | null | undefined;
  /**
   * The enrolled holder_jkt the embedded jwk of a holder-signed artifact
   * must match (draft 6.2, 7.2).
   */
  holderJKT(req: KeyRequest): string;
}

/** A {@link KeyResolver} over fixed configuration: one key set per role and one expected holder thumbprint. */
export class StaticResolver implements KeyResolver {
  readonly keySets: ReadonlyMap<string, KeySet>;
  readonly expectedHolderJKT: string;

  constructor(keySets: ReadonlyMap<string, KeySet> = new Map(), expectedHolderJKT = '') {
    this.keySets = keySets;
    this.expectedHolderJKT = expectedHolderJKT;
  }

  /** `keySets.get(req.role)`, `undefined` when the role has none. */
  trustedKeys(req: KeyRequest): KeySet | undefined {
    return this.keySets.get(req.role);
  }

  /** `expectedHolderJKT`; throws when it is empty. */
  holderJKT(_req: KeyRequest): string {
    if (this.expectedHolderJKT === '') throw new Error('no expected holder_jkt configured');
    return this.expectedHolderJKT;
  }
}
