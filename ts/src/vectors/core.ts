/**
 * The functions of the SDK that the vectors harness calls, behind one
 * interface so that the harness tests can run each group against a fake.
 * {@link defaultCore} wires the package's own modules.
 *
 * @module
 */
import type { KeyObject } from 'node:crypto';
import { Config, fromRequest, type RawRequest } from '../core/binding/index.ts';
import { artifactDigest, bytesDigest, objectDigest } from '../core/digest.ts';
import { canonicalize } from '../core/jcs.ts';
import {
  Algorithms,
  type JWK,
  type KeySet,
  parseJWK,
  publicJWK,
  reasonOf,
  StaticResolver,
  thumbprint,
  Verifier,
} from '../core/jws/index.ts';
import { artifactJSON, defaultLimits } from '../core/limits.ts';
import { uriFormat } from '../core/schema.ts';
import { shapes } from '../core/shapes.ts';
import { decode } from '../core/strictjson.ts';

export interface Core {
  /** jcs: the RFC 8785 form of a JSON text. */
  canonicalize(input: Uint8Array): Uint8Array;
  /** digest: object_digest of a parsed JSON object. */
  objectDigest(value: unknown): string;
  artifactDigest(compact: string): string;
  bytesDigest(bytes: Uint8Array): string;
  /** strictjson: strict typed decode as an OperationContext. */
  decodeOperationContext(input: Uint8Array): unknown;
  /** strictjson: strict typed decode of a signed payload as Evidence, under the artifact limits. */
  decodeEvidence(payload: Uint8Array): unknown;
  /** jws: strict parse of a public JWK; empty algorithms are the baseline, ES256 alone. */
  parseJWK(raw: Uint8Array, algorithms: readonly string[]): JWK;
  publicJWK(key: KeyObject): JWK;
  thumbprint(jwk: JWK): string;
  /** jws: a key resolver over the trusted key sets by role and the expected holder thumbprint. */
  keyResolver(
    keySets: ReadonlyMap<string, readonly JWK[]>,
    expectedHolderJKT: string,
    algorithms: readonly string[],
  ): unknown;
  /** jws: verify a compact JWS; an empty typ expects none. */
  verify(
    compact: string,
    resolver: unknown,
    typ: string,
    algorithms: readonly string[],
  ): { readonly payload: Uint8Array };
  reasonOf(err: unknown): string;
  /** binding: the OperationContext of a raw request, without operation_id and environment_id. */
  fromRequest(
    cfg: Config,
    req: RawRequest,
    principalId: string,
    action: string,
    resources: readonly string[],
  ): Record<string, unknown>;
  /** binding: the configuration check; throws a RequestError of kind INVALID_CONFIG. */
  validateConfig(cfg: Config): void;
  /** schema: the shared checker of format uri. */
  uriFormat(value: string): boolean;
}

/** The package's own modules. */
export const defaultCore: Core = {
  canonicalize: (input) => canonicalize(input),
  objectDigest: (value) => objectDigest(value),
  artifactDigest: (compact) => artifactDigest(compact),
  bytesDigest: (bytes) => bytesDigest(bytes),
  decodeOperationContext: (input) => decode(input, shapes.OperationContext),
  decodeEvidence: (payload) => decode(payload, shapes.Evidence, artifactJSON(defaultLimits())),
  parseJWK: (raw, algorithms) =>
    algorithms.length === 0 ? parseJWK(raw) : new Algorithms(algorithms).parseJWK(raw),
  publicJWK: (key) => publicJWK(key),
  thumbprint: (jwk) => thumbprint(jwk),
  keyResolver: (keySets, expectedHolderJKT, algorithms) => {
    const algs = new Algorithms(algorithms);
    const sets = new Map<string, KeySet>();
    for (const [role, keys] of keySets) sets.set(role, algs.newKeySet(...keys));
    return new StaticResolver(sets, expectedHolderJKT);
  },
  verify: (compact, resolver, typ, algorithms) =>
    new Verifier({
      keys: resolver as StaticResolver,
      typ,
      algorithms: new Algorithms(algorithms),
    }).verify(compact),
  reasonOf: (err) => reasonOf(err),
  fromRequest: (cfg, req, principalId, action, resources) => ({
    ...fromRequest(cfg, req, principalId, action, resources),
  }),
  validateConfig: (cfg) => Config.validate(cfg),
  uriFormat: (value) => uriFormat(value),
};
