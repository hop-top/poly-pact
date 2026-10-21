/**
 * The committed signed files of a directory, checked against the generator
 * contract and verified against the directory's trust records (Go
 * hop.top/pact-go/runner/evalcase, verify.go).
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { Verifier } from '../core/jws/index.ts';
import { type JWK, parseJWK } from '../core/jws/jwk.ts';
import { KeySet, StaticResolver } from '../core/jws/keys.ts';
import { Role, typRole } from '../core/jws/typ.ts';
import { parse } from '../core/strictjson.ts';
import { AUTHENTICATED_MEMBER, readMember, TRUST_MEMBER } from './decode.ts';
import { type Dir, under } from './dirs.ts';
import { CaseError, messageOf, wrap } from './errors.ts';
import type { Key } from './keys.ts';
import type { Authenticated, TrustRecord } from './types.ts';
import { walk } from './walk.ts';

/** A committed signed file of a directory, in signing.json order: the artifacts, then the presentations. */
export interface Signed {
  /** The signed file, relative to the directory. */
  readonly path: string;
  readonly typ: string;
  readonly compact: string;
  /** The decoded payload the compact JWS carries. */
  readonly payload: Uint8Array;
  /**
   * null when the compact JWS verifies against the directory's trust
   * records: for a service-signed artifact, under a key of a trust record of
   * the typ's signer role whose iss is the payload's iss; for a
   * presentation, by the embedded key whose thumbprint is the authenticated
   * holder_jkt of native_context.json. Otherwise the failure, a `JWSError`
   * whose reason `reasonOf` returns. A case may fail it by design, as a
   * payload_signed entry always does.
   */
  readonly trust: Error | null;
}

/**
 * Checks the committed signed files of the directory d against the
 * generator contract and returns them, each with its trust result. The
 * trust records are the trust member of the directory's config.json; the
 * holder_jkt, read when the directory has a presentation, is the
 * authenticated member's of its native_context.json. Throws a
 * {@link CaseError} when a signed file is stale, that is not what the
 * generator keeps (`File.check`), or when a decoded file's digests are not
 * those the generator sets.
 */
export function verify(fixtures: string, d: Dir, keys: ReadonlyMap<string, Key>): Signed[] {
  const dir = under(fixtures, d.path);
  let trust: readonly TrustRecord[];
  try {
    trust = (readMember(under(dir, 'config.json'), 'trust', TRUST_MEMBER) as TrustRecord[]) ?? [];
  } catch (err) {
    throw wrap(`${d.id}/config.json`, err);
  }
  let jkt = '';
  if (d.signing.presentations.length > 0) {
    let auth: Authenticated | null | undefined;
    try {
      auth = readMember(under(dir, 'native_context.json'), 'authenticated', AUTHENTICATED_MEMBER) as
        | Authenticated
        | null
        | undefined;
    } catch (err) {
      throw wrap(`${d.id}/native_context.json`, err);
    }
    jkt = auth?.holder_jkt ?? '';
  }
  return verifyDir(fixtures, d, keys, trust, jkt);
}

/** {@link verify} with the trust records and the enrolled holder_jkt given. */
export function verifyDir(
  fixtures: string,
  d: Dir,
  keys: ReadonlyMap<string, Key>,
  trust: readonly TrustRecord[],
  holderJKT: string,
): Signed[] {
  const dir = under(fixtures, d.path);
  const out: Signed[] = [];
  try {
    walk(fixtures, d, keys, (f) => {
      if (f.digestsChanged) {
        throw new CaseError(
          `stale: the digests of ${f.decoded} are not the artifact_digest values of the files they name; run pactfix generate`,
        );
      }
      const compact = readFileSync(under(dir, f.signed), 'utf8');
      f.check(compact);
      out.push({
        path: f.signed,
        typ: f.typ,
        compact,
        payload: f.payload,
        trust: trusted(fixtures, compact, f.typ, f.payload, trust, holderJKT),
      });
      return compact;
    });
  } catch (err) {
    throw wrap(d.id, err);
  }
  return out;
}

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(messageOf(err));
}

// Verifies compact as typ against the trust records and the enrolled
// holder_jkt; the failure, or null.
function trusted(
  fixtures: string,
  compact: string,
  typ: string,
  payload: Uint8Array,
  trust: readonly TrustRecord[],
  holderJKT: string,
): Error | null {
  try {
    const role = typRole(typ) as Role;
    let res: StaticResolver;
    if (role === Role.HOLDER) {
      res = new StaticResolver(new Map(), holderJKT);
    } else {
      const claims = parse(payload) as Record<string, unknown>;
      const iss = typeof claims.iss === 'string' ? claims.iss : '';
      const set: JWK[] = [];
      for (const r of trust) {
        if (r.role !== role || r.iss !== iss) continue;
        for (const k of r.keys) {
          const b = new Uint8Array(readFileSync(under(fixtures, k)));
          let jwk: JWK;
          try {
            jwk = parseJWK(b);
          } catch (err) {
            return new Error(`${k}: ${messageOf(err)}`, { cause: err });
          }
          // Two records of one role and iss may name the same key file.
          if (!set.some((s) => s.kid === jwk.kid && s.x === jwk.x && s.y === jwk.y)) set.push(jwk);
        }
      }
      res = new StaticResolver(new Map([[role, new KeySet(...set)]]));
    }
    new Verifier({ keys: res, typ }).verify(compact);
    return null;
  } catch (err) {
    return asError(err);
  }
}
