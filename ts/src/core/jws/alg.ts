/**
 * The negotiated algorithms (Go go/core/jws/alg.go, type Algorithms).
 *
 * @module
 */
import { accepts, type JWK, parseJWKFor } from './jwk.ts';
import { type KeySet, newKeySetFor } from './keys.ts';

/**
 * The JOSE algorithms a deployment accepts for its signed artifacts (draft
 * 7.2). Empty is the baseline, ES256 alone. Ed25519 (RFC 9864 section 2.2)
 * is accepted only when it is listed, that is, when it has been negotiated
 * explicitly. ES256 and Ed25519 are the only algorithms of the profile: any
 * other entry, the ambiguous EdDSA included, never matches a header or a
 * key.
 *
 * Ed25519 keys are not ported yet: checking one throws `NotImplementedError`.
 */
export class Algorithms {
  readonly names: readonly string[];

  constructor(names: readonly string[] = []) {
    this.names = Object.freeze([...names]);
  }

  /** Whether `alg` is ES256 or Ed25519 and listed, or ES256 when the list is empty. */
  accepts(alg: string): boolean {
    return accepts(this.names, alg);
  }

  /** `parseJWK` for these algorithms. */
  parseJWK(raw: Uint8Array | string): JWK {
    return parseJWKFor(raw, this.names);
  }

  /** `new KeySet` for these algorithms: each key is checked as {@link parseJWK} checks it. */
  newKeySet(...keys: JWK[]): KeySet {
    return newKeySetFor(this.names, keys);
  }
}
