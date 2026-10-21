/**
 * signing.json, the generator contract of a signed directory (Go
 * hop.top/pact-go/runner/evalcase, signing.go; spec/v1.0/fixtures/README.md, section
 * Generator contract: signing.json).
 *
 * @module
 */
import { TYP_PRESENTATION, typRole } from '../core/jws/typ.ts';
import type { RawJSON } from '../core/values.ts';
import { pathRE } from '../runner/manifest/rules.ts';
import { decodeAs } from './decode.ts';
import { CaseError, q } from './errors.ts';

/**
 * The default iat, and so nbf, of every generated artifact: the sample time
 * of draft Appendix B, 2026-10-15T16:00:00Z.
 */
export const FIXED_TIME = 1792080000;

/** The default exp - iat of a generated presentation, the most draft Section 7.5 allows. */
export const PRESENTATION_LIFETIME = 60;

/** A directory's signing.json: the artifacts the generator signs, in order, then the presentations it builds and signs. */
export interface Signing {
  readonly artifacts: readonly Artifact[];
  readonly presentations: readonly Presentation[];
}

/**
 * One service-signed artifact: its decoded payload, the signed file, its
 * typ, the role of its signing key in the test keys file, and the claims its
 * payload must carry.
 */
export interface Artifact {
  readonly decoded: string;
  readonly signed: string;
  readonly typ: string;
  readonly signer: string;
  readonly jti: string;
  /** iat defaults to {@link FIXED_TIME}, nbf to the iat; exp is checked only when set. */
  readonly iat: number | null;
  readonly nbf: number | null;
  readonly exp: number | null;
  /**
   * An RFC 6901 pointer into the decoded payload to the signed file of an
   * earlier entry whose artifact_digest the member gets.
   */
  readonly digests: Readonly<Record<string, string>>;
  /**
   * When set, the decoded file the signature covers; the compact JWS still
   * carries decoded, so it does not verify by design.
   */
  readonly payload_signed: string | null;
}

/** A presentation, which has no decoded file: the generator builds its payload from the case files. */
export interface Presentation {
  readonly signed: string;
  readonly signer: string;
  readonly jti: string;
  /** iat defaults to {@link FIXED_TIME}, nbf to the iat, exp to iat + {@link PRESENTATION_LIFETIME}. */
  readonly iat: number | null;
  readonly nbf: number | null;
  readonly exp: number | null;
  /** Defaults to signed/contract.jws. */
  readonly contract: string | null;
  /** Defaults to the evidence artifacts in order. */
  readonly evidence: readonly string[] | null;
  /**
   * null when absent: the reputation artifact, or null when there is none;
   * otherwise the member as written, null or a path.
   */
  readonly reputation: RawJSON | null;
  readonly profile: string | null;
  readonly intent: string | null;
  readonly operation: string | null;
}

/** Reports whether p is a relative path inside a case (the manifest path pattern). */
export function relPath(p: string): boolean {
  return pathRE.test(p);
}

/** Reads a signing.json strictly and checks it; throws a {@link CaseError} or a `StrictJSONError`. */
export function parseSigning(b: Uint8Array): Signing {
  const raw = decodeAs<{ artifacts: Artifact[] | null; presentations: Presentation[] }>(
    b,
    'SigningFile',
  );
  if (raw.artifacts === null) throw new CaseError('artifacts is required');
  const s: Signing = { artifacts: raw.artifacts, presentations: raw.presentations };
  validate(s);
  return s;
}

function validate(s: Signing): void {
  const paths = (where: string, ...ps: string[]) => {
    for (const p of ps) {
      if (!relPath(p))
        throw new CaseError(`${where}: ${q(p)} is not a relative path inside the case`);
    }
  };
  const seen = new Set<string>();
  for (const [i, a] of s.artifacts.entries()) {
    const where = `artifacts[${i}]`;
    if (a.decoded === '' || a.signed === '' || a.typ === '' || a.signer === '' || a.jti === '') {
      throw new CaseError(`${where}: decoded, signed, typ, signer and jti are required`);
    }
    paths(where, a.decoded, a.signed);
    if (a.payload_signed !== null) paths(where, a.payload_signed);
    if (typRole(a.typ) === undefined || a.typ === TYP_PRESENTATION) {
      throw new CaseError(
        `${where}: typ ${q(a.typ)} is not a typ of draft Section 7.3 for a service-signed artifact`,
      );
    }
    for (const [ptr, p] of Object.entries(a.digests)) {
      if (!ptr.startsWith('/')) {
        throw new CaseError(`${where}: digests: ${q(ptr)} is not a JSON Pointer to a member`);
      }
      if (!seen.has(p)) {
        throw new CaseError(
          `${where}: digests ${ptr}: ${p} is not the signed file of an earlier entry`,
        );
      }
    }
    if (seen.has(a.signed)) throw new CaseError(`${where}: signed file ${a.signed} is named twice`);
    seen.add(a.signed);
  }
  for (const [i, p] of s.presentations.entries()) {
    const where = `presentations[${i}]`;
    if (p.signed === '' || p.signer === '' || p.jti === '') {
      throw new CaseError(`${where}: signed, signer and jti are required`);
    }
    paths(where, p.signed);
    if (seen.has(p.signed)) throw new CaseError(`${where}: signed file ${p.signed} is named twice`);
    seen.add(p.signed);
  }
}
