/**
 * The compact JWS of PACT signed artifacts (Go package
 * hop.top/pact-go/core/jws): the profile of draft sections 7.2 and 7.3 over
 * RFC 7515. ES256 (ECDSA P-256 and SHA-256, RFC 7518 section 3.4) is the
 * baseline and the only algorithm accepted by default.
 *
 * {@link Verifier.verify} checks a compact JWS in this order and stops at
 * the first failure, whose {@link Reason} it throws inside a
 * {@link JWSError}:
 *
 * 1. the length bound in UTF-8 bytes ({@link DEFAULT_MAX_COMPACT_BYTES}),
 *    then three segments separated by two periods with a non-empty header
 *    segment;
 * 2. the header segment is canonical unpadded base64url and a strict JSON
 *    object (draft 7.1);
 * 3. no crit, b64, jku, x5u or x5c member; alg is one of the verifier's
 *    algorithms (ES256 when none are given); typ is in the draft 7.3 table
 *    and, when the verifier's typ is set, equals it; kid, if present, is a
 *    string. Other members are ignored (RFC 7515 section 4);
 * 4. by the signer role of typ: a holder-signed artifact embeds a jwk that
 *    `parseJWK` accepts and that is a key for alg; any other artifact has a
 *    kid and no jwk;
 * 5. the payload segment is not empty (no detached payload), is canonical
 *    base64url and a strict JSON object;
 * 6. the signature segment is canonical base64url of exactly 64 octets;
 * 7. the key: for a holder, the embedded jwk's RFC 7638 thumbprint equals
 *    the holder_jkt the {@link KeyResolver} expects; otherwise kid is found
 *    in the key set the resolver trusts for the role, and nowhere else, and
 *    that key is a key for alg;
 * 8. the ES256 signature over the received signing input, the compact text
 *    up to its second period. Nothing is decoded and re-encoded to rebuild
 *    it.
 *
 * A high S is accepted, since neither RFC 7518 nor the draft has a low-S
 * rule; {@link sign} writes only low-S signatures. Verification checks the
 * JWS, not the artifact: decode {@link ParsedJWS.payload} with strictjson
 * into its core type and apply the schema, time and authority rules
 * separately.
 *
 * Ed25519, optional in draft 7.2, is not ported: {@link Algorithms} accepts
 * the name where it is listed, and checking an Ed25519 key throws
 * `NotImplementedError`.
 *
 * @module
 */
import { KeyObject, timingSafeEqual } from 'node:crypto';
import { notImplemented } from '../../internal/notimplemented.ts';
import type { Limits } from '../strictjson.ts';
import type { Digest } from '../values.ts';
import { Algorithms } from './alg.ts';
import { decodeSegment, encodeSegment } from './base64url.ts';
import { fail, Reason } from './errors.ts';
import { signES256, verifyES256 } from './es256.ts';
import { jsonString, rawMember, strictObject } from './json.ts';
import { algorithmOf, checkUsage, type JWK, publicJWK, thumbprint } from './jwk.ts';
import {
  type KeyRequest,
  type KeyResolver,
  lookupTrusted,
  type TrustedKey,
  trustedKey,
} from './keys.ts';
import { ALG_ES256, Role, typRole } from './typ.ts';

export { Algorithms } from './alg.ts';
export { JWSError, Reason, reasonOf } from './errors.ts';
export { algorithmOf, type JWK, parseJWK, publicJWK, publicKeyOf, thumbprint } from './jwk.ts';
export { type KeyRequest, type KeyResolver, KeySet, StaticResolver } from './keys.ts';
export {
  ALG_ED25519,
  ALG_ES256,
  Role,
  TYP_ADMISSION,
  TYP_EVIDENCE,
  TYP_LEARNING_ARTIFACT,
  TYP_LEARNING_EVENT,
  TYP_LEARNING_POLICY,
  TYP_OUTCOME,
  TYP_PRESENTATION,
  TYP_REPUTATION,
  TYP_REQUIREMENTS,
  typRole,
  typs,
} from './typ.ts';

/**
 * The bound of a compact JWS before any decoding: 360448 bytes, the draft
 * 20.1 transport frame minimum, which holds the base64url of a 256 KiB
 * payload (349526) plus 10922 bytes for the JOSE header and signature.
 */
export const DEFAULT_MAX_COMPACT_BYTES = 360448;

/** The protected header of a PACT JWS. All header members are protected (draft 7.2). */
export interface Header {
  /** ES256 (draft 7.2); {@link sign} accepts it absent or empty. */
  readonly alg?: string;
  /** A typ of the draft 7.3 table. */
  readonly typ: string;
  /**
   * The signing key within the trusted key set of a service-signed
   * artifact. For a holder-signed artifact it is optional and plays no part
   * in key selection. A verified header has `''` when the JWS has none.
   */
  readonly kid?: string;
  /** The embedded public key of a holder-signed artifact, absent otherwise. */
  readonly jwk?: JWK;
}

/** A verified compact JWS. */
export interface ParsedJWS {
  /** The input, unchanged. */
  readonly compact: string;
  /** The protected header members the profile defines. */
  readonly header: Header;
  /** The signer role of `header.typ`. */
  readonly role: Role;
  /**
   * The decoded protected header exactly as received. Compute digests over
   * these bytes or over `compact`, never over a re-encoding.
   */
  readonly rawHeader: Uint8Array;
  /** The decoded payload exactly as received; decode it with strictjson into the artifact type. */
  readonly payload: Uint8Array;
  /** The received text the signature covers: the compact serialization up to its second period. */
  readonly signingInput: string;
  /** The 64 octets R || S of the signature. */
  readonly signature: Uint8Array;
  /** The key that verified the signature. */
  readonly key: JWK;
  /** The RFC 7638 thumbprint of `key`. */
  readonly keyThumbprint: Digest;
}

/** The options of a {@link Verifier}. */
export interface VerifierOptions {
  /** Resolves the verification key. Required: without it every JWS is `key-unavailable`. */
  readonly keys?: KeyResolver | null;
  /**
   * When set, the only typ accepted: the typ the caller's slot expects
   * (draft 7.2: validators check the artifact-specific typ).
   */
  readonly typ?: string;
  /** The bound of the compact serialization in UTF-8 bytes; zero or absent is {@link DEFAULT_MAX_COMPACT_BYTES}. */
  readonly maxCompactBytes?: number;
  /** The bounds of the strict decoding of the protected header and payload. */
  readonly limits?: Limits;
  /** The negotiated algorithms; absent is the baseline, ES256 alone. */
  readonly algorithms?: Algorithms;
}

// The header members the profile rejects, in the order checked.
const PROHIBITED: readonly (readonly [string, Reason])[] = [
  ['crit', Reason.HEADER_CRIT],
  ['b64', Reason.HEADER_B64],
  ['jku', Reason.HEADER_JKU],
  ['x5u', Reason.HEADER_X5U],
  ['x5c', Reason.HEADER_X5C],
];

function segment(s: string, what: string): Uint8Array {
  try {
    return decodeSegment(s);
  } catch (err) {
    throw fail(Reason.BASE64_URL, what, err);
  }
}

function describe(name: string, m: Readonly<Record<string, unknown>>): string {
  if (!Object.hasOwn(m, name)) return `no ${name}`;
  return `${name} ${JSON.stringify(m[name]).slice(0, 64)}`;
}

// The header alg is the algorithm of the checked key k: a key serves
// exactly one algorithm (RFC 9864 section 2.2, RFC 8037 section 2).
function matchAlg(alg: string, k: JWK): void {
  const keyAlg = algorithmOf(k);
  if (keyAlg === alg) return;
  const kid = (k.kid ?? '') === '' ? '' : ` (kid ${JSON.stringify(k.kid)})`;
  throw fail(
    Reason.JWK_USAGE,
    `alg ${alg}, but the key${kid} is kty ${k.kty} crv ${k.crv}, a key for ${keyAlg}`,
  );
}

function sameDigest(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Verifies compact JWS under the profile; see the module documentation for the order of the checks. */
export class Verifier {
  readonly keys: KeyResolver | null;
  readonly typ: string;
  readonly maxCompactBytes: number;
  readonly limits: Limits;
  readonly algorithms: Algorithms;

  constructor(options: VerifierOptions = {}) {
    this.keys = options.keys ?? null;
    this.typ = options.typ ?? '';
    this.maxCompactBytes = options.maxCompactBytes ?? 0;
    this.limits = options.limits ?? {};
    this.algorithms = options.algorithms ?? new Algorithms();
  }

  /** Checks `compact` and its signature; throws a {@link JWSError}. */
  verify(compact: string): ParsedJWS {
    const limit = this.maxCompactBytes > 0 ? this.maxCompactBytes : DEFAULT_MAX_COMPACT_BYTES;
    const size = Buffer.byteLength(compact, 'utf8');
    if (size > limit) throw fail(Reason.COMPACT_SIZE, `${size} bytes, limit ${limit}`);
    const first = compact.indexOf('.');
    const last = compact.lastIndexOf('.');
    if (first < 0 || first === last || compact.slice(first + 1, last).includes('.')) {
      throw fail(Reason.COMPACT_FORM, 'want three segments separated by two periods');
    }
    const h64 = compact.slice(0, first);
    const p64 = compact.slice(first + 1, last);
    const s64 = compact.slice(last + 1);
    if (h64 === '') throw fail(Reason.COMPACT_FORM, 'empty protected header');

    const rawHeader = segment(h64, 'protected header');
    const { alg, typ, kid, members } = this.#parseHeader(rawHeader);
    if (this.typ !== '' && typ !== this.typ) {
      throw fail(
        Reason.TYP_MISMATCH,
        `typ ${JSON.stringify(typ)}, want ${JSON.stringify(this.typ)}`,
      );
    }
    const role = typRole(typ) as Role;
    const hasJWK = Object.hasOwn(members, 'jwk');
    let embedded: JWK | undefined;
    if (role === Role.HOLDER) {
      if (!hasJWK) {
        throw fail(Reason.JWK_MISSING, 'a holder-signed artifact embeds its public jwk');
      }
      embedded = this.algorithms.parseJWK(rawMember(rawHeader, this.limits, members, 'jwk'));
      matchAlg(alg, embedded);
    } else {
      if (hasJWK) {
        throw fail(Reason.JWK_UNEXPECTED, `typ ${typ} is verified by kid, not by an embedded jwk`);
      }
      if (kid === '') throw fail(Reason.KID_MISSING);
    }

    if (p64 === '') throw fail(Reason.PAYLOAD_DETACHED);
    const payload = segment(p64, 'payload');
    try {
      strictObject(payload, this.limits);
    } catch (err) {
      throw fail(Reason.PAYLOAD_JSON, '', err);
    }

    const sig = segment(s64, 'signature');
    if (sig.length !== 64) throw fail(Reason.SIGNATURE_LENGTH, `${sig.length} octets, want 64`);

    const key = this.#resolve({ typ, role, kid, header: rawHeader, payload }, embedded);
    matchAlg(alg, key.jwk);
    const signingInput = compact.slice(0, last);
    const valid =
      key.alg === ALG_ES256
        ? verifyES256(key.key, signingInput, sig)
        : notImplemented('jws.verifyEd25519');
    if (!valid) throw fail(Reason.SIGNATURE_INVALID);
    const header: Header =
      embedded === undefined ? { alg, typ, kid } : { alg, typ, kid, jwk: embedded };
    return Object.freeze({
      compact,
      header: Object.freeze(header),
      role,
      rawHeader,
      payload,
      signingInput,
      signature: sig,
      key: key.jwk,
      keyThumbprint: key.thumbprint,
    });
  }

  // Decodes the protected header strictly and checks the members that do
  // not depend on the signer role.
  #parseHeader(raw: Uint8Array): {
    alg: string;
    typ: string;
    kid: string;
    members: Record<string, unknown>;
  } {
    let m: Record<string, unknown>;
    try {
      m = strictObject(raw, this.limits);
    } catch (err) {
      throw fail(Reason.HEADER_JSON, '', err);
    }
    for (const [name, reason] of PROHIBITED) {
      if (Object.hasOwn(m, name)) throw fail(reason, `member ${name}`);
    }
    const alg = Object.hasOwn(m, 'alg') ? m.alg : undefined;
    if (typeof alg !== 'string' || !this.algorithms.accepts(alg)) {
      throw fail(Reason.ALG_UNSUPPORTED, describe('alg', m));
    }
    const typ = Object.hasOwn(m, 'typ') ? m.typ : undefined;
    if (typeof typ !== 'string' || typRole(typ) === undefined) {
      throw fail(Reason.TYP_UNSUPPORTED, describe('typ', m));
    }
    let kid = '';
    if (Object.hasOwn(m, 'kid')) {
      if (typeof m.kid !== 'string') throw fail(Reason.HEADER_JSON, 'kid is not a string');
      kid = m.kid;
    }
    return { alg, typ, kid, members: m };
  }

  #resolve(req: KeyRequest, embedded: JWK | undefined): TrustedKey {
    const keys = this.keys;
    if (keys === null) throw fail(Reason.KEY_UNAVAILABLE, 'no key resolver');
    if (req.role === Role.HOLDER) {
      if (embedded === undefined) throw fail(Reason.JWK_MISSING);
      let want: unknown;
      try {
        want = keys.holderJKT(req);
      } catch (err) {
        throw fail(Reason.KEY_UNAVAILABLE, 'holder_jkt', err);
      }
      if (typeof want !== 'string' || want === '') {
        throw fail(Reason.KEY_UNAVAILABLE, 'no expected holder_jkt');
      }
      const k = trustedKey(embedded, this.algorithms.names);
      if (!sameDigest(k.thumbprint, want)) {
        throw fail(Reason.HOLDER_JKT_MISMATCH, `jwk thumbprint ${k.thumbprint}, expected ${want}`);
      }
      return k;
    }
    let set: ReturnType<KeyResolver['trustedKeys']>;
    try {
      set = keys.trustedKeys(req);
    } catch (err) {
      throw fail(Reason.KEY_UNAVAILABLE, `key set for ${req.role}`, err);
    }
    const k = lookupTrusted(set, req.kid);
    if (k === undefined) {
      throw fail(
        Reason.KID_UNKNOWN,
        `kid ${JSON.stringify(req.kid)} is not in the key set trusted for ${req.role}`,
      );
    }
    return k;
  }
}

/** `new Verifier({keys}).verify(compact)`. */
export function verify(compact: string, keys: KeyResolver | null | undefined): ParsedJWS {
  return new Verifier({ keys }).verify(compact);
}

function jwkText(k: JWK): string {
  let out = `{"kty":${jsonString(k.kty)},"crv":${jsonString(k.crv)},"x":${jsonString(k.x)}`;
  for (const name of ['y', 'kid', 'alg', 'use'] as const) {
    const v = k[name] ?? '';
    if (v !== '') out += `,"${name}":${jsonString(v)}`;
  }
  return `${out}}`;
}

/**
 * The compact JWS of `payload` under the P-256 private `key` with the
 * protected header `header`. `alg` may be absent and is always written as
 * ES256. For a holder-signed typ the header embeds `header.jwk`, or the
 * key's public JWK when absent; `header.jwk` must be that public key. Every
 * other typ needs `header.kid` and no `header.jwk`. `payload` must be a
 * strict JSON object and is signed exactly as given, never re-encoded. The
 * header members are written in the order alg, typ, kid, jwk, as in draft
 * Appendix C. ECDSA signing is randomized, so two calls give different
 * signatures; S is always the low value of the pair (S, n-S). Throws a
 * {@link JWSError}.
 */
export function sign(header: Header, payload: Uint8Array, key: KeyObject): string {
  if (!(key instanceof KeyObject)) throw fail(Reason.SIGNING_KEY, 'no key');
  if (key.type !== 'private')
    throw fail(Reason.SIGNING_KEY, `a ${key.type} key, want a private key`);
  let own: JWK;
  try {
    own = publicJWK(key);
  } catch (err) {
    throw fail(Reason.SIGNING_KEY, 'not a P-256 key', err);
  }
  if ((header.alg ?? '') !== '' && header.alg !== ALG_ES256) {
    throw fail(Reason.ALG_UNSUPPORTED, `alg ${header.alg}`);
  }
  const role = typRole(header.typ);
  if (role === undefined) throw fail(Reason.TYP_UNSUPPORTED, `typ ${header.typ}`);
  const kid = header.kid ?? '';
  let embedded: JWK | undefined;
  if (role === Role.HOLDER) {
    embedded = own;
    if (header.jwk !== undefined) {
      const given = thumbprint(header.jwk);
      checkUsage(header.jwk, ALG_ES256);
      if (given !== thumbprint(own)) {
        throw fail(Reason.SIGNING_KEY, 'jwk is not the public key of the signing key');
      }
      embedded = header.jwk;
    }
  } else {
    if (header.jwk !== undefined) {
      throw fail(
        Reason.JWK_UNEXPECTED,
        `typ ${header.typ} is verified by kid, not by an embedded jwk`,
      );
    }
    if (kid === '') throw fail(Reason.KID_MISSING);
  }
  try {
    strictObject(payload);
  } catch (err) {
    throw fail(Reason.PAYLOAD_JSON, '', err);
  }

  let text = `{"alg":${jsonString(ALG_ES256)},"typ":${jsonString(header.typ)}`;
  if (kid !== '') text += `,"kid":${jsonString(kid)}`;
  if (embedded !== undefined) text += `,"jwk":${jwkText(embedded)}`;
  text += '}';
  const signingInput = `${encodeSegment(new TextEncoder().encode(text))}.${encodeSegment(payload)}`;
  let sig: Uint8Array;
  try {
    sig = signES256(key, signingInput);
  } catch (err) {
    throw fail(Reason.SIGNING_KEY, '', err);
  }
  return `${signingInput}.${encodeSegment(sig)}`;
}
