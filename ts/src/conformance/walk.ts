/**
 * The generator contract applied to a signed directory (Go
 * hop.top/pact-go/runner/evalcase, walk.go and digests.go): what each signed
 * file must carry, which key signs it, and the check of a committed file
 * against it (spec/v1.0/fixtures/README.md, sections Signed artifacts and
 * Generator contract: signing.json).
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { artifactDigest } from '../core/digest.ts';
import { canonicalize } from '../core/jcs.ts';
import { encodeSegment } from '../core/jws/base64url.ts';
import { type Header, sign as signJWS, Verifier } from '../core/jws/index.ts';
import { type JWK, thumbprint } from '../core/jws/jwk.ts';
import { KeySet, StaticResolver } from '../core/jws/keys.ts';
import { Role, TYP_EVIDENCE, TYP_PRESENTATION, TYP_REPUTATION, typRole } from '../core/jws/typ.ts';
import { parse } from '../core/strictjson.ts';
import { type Dir, under } from './dirs.ts';
import { CaseError, q, wrap } from './errors.ts';
import type { Key } from './keys.ts';
import { type Artifact, FIXED_TIME, PRESENTATION_LIFETIME, type Presentation } from './signing.ts';

const utf8 = new TextEncoder();
const text = new TextDecoder();

/** The members of a {@link File}. */
export interface FileInit {
  readonly signed: string;
  readonly typ: string;
  readonly key: Key;
  readonly payload: Uint8Array;
  readonly over: Uint8Array;
  readonly decoded: string;
  readonly digested: boolean;
  readonly digestsChanged: boolean;
}

/**
 * One signed file of a directory as the generator contract defines it: what
 * its compact JWS must carry and which key signs it.
 */
export class File {
  /** The signed file, relative to the directory. */
  readonly signed: string;
  readonly typ: string;
  readonly key: Key;
  /**
   * What the compact JWS carries: the decoded file, with its digests set, or
   * the presentation payload built from the case files.
   */
  readonly payload: Uint8Array;
  /** What the signature covers: payload, or the payload_signed file. */
  readonly over: Uint8Array;
  /** The artifact's decoded file, '' for a presentation. */
  readonly decoded: string;
  /** The artifact entry has digests: payload is the decoded file with them set. */
  readonly digested: boolean;
  /** payload differs from the decoded file read. */
  readonly digestsChanged: boolean;

  constructor(init: FileInit) {
    this.signed = init.signed;
    this.typ = init.typ;
    this.key = init.key;
    this.payload = init.payload;
    this.over = init.over;
    this.decoded = init.decoded;
    this.digested = init.digested;
    this.digestsChanged = init.digestsChanged;
  }

  // The protected header the generator writes: typ, and the kid of the
  // signing key unless a holder signs (the key is then embedded).
  #header(): Header {
    return { typ: this.typ, kid: typRole(this.typ) === Role.HOLDER ? '' : this.key.public.kid };
  }

  /**
   * A fresh compact JWS: the protected header, payload, and an ES256
   * signature over the header and over. ES256 signatures are randomized, so
   * two calls differ in the signature only. Throws a `JWSError`.
   */
  sign(): string {
    const seg = signJWS(this.#header(), this.over, this.key.private).split('.');
    return `${seg[0]}.${encodeSegment(this.payload)}.${seg[2]}`;
  }

  /**
   * Checks that compact is a signed file the generator keeps: its protected
   * header and payload are those {@link sign} writes, and its signature
   * verifies over them, over `over` for a payload_signed entry, under the
   * key. Throws a {@link CaseError} that says what is stale.
   */
  check(compact: string): void {
    if (signingInput(compact) !== signingInput(this.sign())) {
      throw new CaseError(
        'stale: its protected header or payload is not the one the generator writes',
      );
    }
    if (!verifies(resigned(compact, this.over), this.typ, this.key.public)) {
      throw new CaseError(`stale: its signature does not verify under the ${this.key.role} key`);
    }
  }
}

// compact with its payload segment replaced by over, so that its signature
// can be checked over the payload it was computed on.
function resigned(compact: string, over: Uint8Array): string {
  const seg = compact.split('.');
  if (seg.length !== 3) return compact;
  return `${seg[0]}.${encodeSegment(over)}.${seg[2]}`;
}

function signingInput(compact: string): string {
  const i = compact.lastIndexOf('.');
  return i < 0 ? '' : compact.slice(0, i);
}

// Whether compact verifies as typ under the public key jwk: by kid in a key
// set of the typ's role, or, for a holder, by the thumbprint of the embedded
// key.
function verifies(compact: string, typ: string, jwk: JWK): boolean {
  try {
    const role = typRole(typ);
    const res =
      role === Role.HOLDER
        ? new StaticResolver(new Map(), thumbprint(jwk))
        : new StaticResolver(new Map([[role as string, new KeySet(jwk)]]));
    new Verifier({ keys: res, typ }).verify(compact);
    return true;
  } catch {
    return false;
  }
}

interface SignedArtifact {
  readonly compact: string;
  readonly payload: Uint8Array;
  readonly typ: string;
}

/**
 * Applies the generator contract to the directory d of the fixture
 * directory: for each entry of its signing.json, in order, it reads the
 * decoded file ({@link readDecoded}), sets its digests, checks its jti and
 * times, or builds the presentation payload (draft Section 11.2), and calls
 * sign with the resulting {@link File}. sign returns the compact JWS that
 * later entries embed or digest: the committed file or a fresh one. Throws a
 * {@link CaseError}.
 */
export function walk(
  fixtures: string,
  d: Dir,
  keys: ReadonlyMap<string, Key>,
  sign: (f: File) => string,
): void {
  const dir = under(fixtures, d.path);
  const signed = new Map<string, SignedArtifact>();
  const order: string[] = [];
  for (const a of d.signing.artifacts) {
    let payload = readDecoded(dir, a.decoded);
    if (text.decode(payload) === 'null') {
      throw new CaseError(
        `${a.decoded} is null: a decoded file whose content is null has no artifact entry`,
      );
    }
    let digested = false;
    let digestsChanged = false;
    if (Object.keys(a.digests).length > 0) {
      let filled: Uint8Array;
      try {
        filled = fillDigests(payload, a.digests, signed);
      } catch (err) {
        throw wrap(a.decoded, err);
      }
      digested = true;
      digestsChanged = !Buffer.from(filled).equals(Buffer.from(payload));
      payload = filled;
    }
    checkClaims(a, payload);
    const over = a.payload_signed === null ? payload : readDecoded(dir, a.payload_signed);
    const key = keys.get(a.signer);
    if (key === undefined) throw new CaseError(`${a.decoded}: no test key for role ${a.signer}`);
    const f = new File({
      signed: a.signed,
      typ: a.typ,
      key,
      payload,
      over,
      decoded: a.decoded,
      digested,
      digestsChanged,
    });
    let compact: string;
    try {
      compact = sign(f);
    } catch (err) {
      throw wrap(a.signed, err);
    }
    signed.set(a.signed, { compact, payload, typ: a.typ });
    order.push(a.signed);
  }
  for (const p of d.signing.presentations) {
    try {
      sign(presentation(dir, p, signed, order, keys));
    } catch (err) {
      throw wrap(p.signed, err);
    }
  }
}

// The JSON object payload, parsed.
function object(payload: Uint8Array): Record<string, unknown> {
  const v = parse(payload);
  if (typeof v !== 'object' || v === null || Array.isArray(v))
    throw new CaseError('not a JSON object');
  return v as Record<string, unknown>;
}

// The string member name of o, '' when absent.
function stringMember(o: Record<string, unknown>, name: string): string {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string') throw new CaseError(`${name} is not a string`);
  return v;
}

// The integer member name of o, null when absent or null.
function intMember(o: Record<string, unknown>, name: string): number | null {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (v === undefined || v === null) return null;
  if (typeof v !== 'number' || !Number.isInteger(v))
    throw new CaseError(`${name} is not an integer`);
  return v;
}

// Builds the presentation p from the case files and the artifacts signed
// before it (draft Section 11.2).
function presentation(
  dir: string,
  p: Presentation,
  signed: ReadonlyMap<string, SignedArtifact>,
  order: readonly string[],
  keys: ReadonlyMap<string, Key>,
): File {
  const embedded = (what: string, rel: string): SignedArtifact => {
    const a = signed.get(rel);
    if (a === undefined)
      throw new CaseError(`${what}: ${rel} is not the signed file of an artifact entry`);
    return a;
  };
  const contractPath = p.contract ?? 'signed/contract.jws';
  const contract = embedded('contract', contractPath);
  let claims: Record<string, string>;
  try {
    const c = object(contract.payload);
    claims = Object.fromEntries(
      ['pact_version', 'aud', 'nonce'].map((n) => [n, stringMember(c, n)]),
    );
  } catch (err) {
    throw wrap(`contract ${contractPath}`, err);
  }
  const evidence: string[] = [];
  const reps: string[] = [];
  for (const rel of order) {
    const a = signed.get(rel) as SignedArtifact;
    if (a.typ === TYP_EVIDENCE && p.evidence === null) evidence.push(a.compact);
    if (a.typ === TYP_REPUTATION) reps.push(rel);
  }
  for (const rel of p.evidence ?? []) evidence.push(embedded('evidence', rel).compact);
  let reputation: string | null = null;
  if (p.reputation === null) {
    if (reps.length > 1)
      throw new CaseError(`reputation: ${reps.length} snapshot artifacts; name one`);
    if (reps.length === 1) reputation = (signed.get(reps[0] as string) as SignedArtifact).compact;
  } else if (p.reputation.text !== 'null') {
    const rel: unknown = parse(p.reputation.text);
    if (typeof rel !== 'string') throw new CaseError('reputation: not a path or null');
    reputation = embedded('reputation', rel).compact;
  }

  const parts = new Map<string, unknown>();
  for (const name of ['profile', 'intent', 'operation'] as const) {
    parts.set(name, parse(readDecoded(dir, p[name] ?? `${name}.json`)));
  }
  let agentId: string;
  let tenantId: string;
  try {
    const profile = parts.get('profile');
    if (typeof profile !== 'object' || profile === null || Array.isArray(profile)) {
      throw new CaseError('not a JSON object');
    }
    agentId = stringMember(profile as Record<string, unknown>, 'agent_id');
    tenantId = stringMember(profile as Record<string, unknown>, 'tenant_id');
  } catch (err) {
    throw wrap('profile', err);
  }
  const iat = p.iat ?? FIXED_TIME;
  const nbf = p.nbf ?? iat;
  const exp = p.exp ?? iat + PRESENTATION_LIFETIME;
  const payload = canonicalize(
    JSON.stringify({
      pact_version: claims.pact_version,
      iss: agentId,
      sub: agentId,
      aud: claims.aud,
      jti: p.jti,
      iat,
      nbf,
      exp,
      tenant_id: tenantId,
      contract: contract.compact,
      profile: parts.get('profile'),
      intent: parts.get('intent'),
      operation: parts.get('operation'),
      evidence,
      reputation,
      nonce: claims.nonce,
    }),
  );
  const key = keys.get(p.signer);
  if (key === undefined) throw new CaseError(`no test key for role ${p.signer}`);
  return new File({
    signed: p.signed,
    typ: TYP_PRESENTATION,
    key,
    payload,
    over: payload,
    decoded: '',
    digested: false,
    digestsChanged: false,
  });
}

/**
 * The decoded file rel of the directory dir, which must be RFC 8785
 * canonical with no trailing newline: it is the payload byte for byte.
 * Throws a {@link CaseError}, or the file system error.
 */
export function readDecoded(dir: string, rel: string): Uint8Array {
  const b = new Uint8Array(readFileSync(under(dir, rel)));
  let canon: Uint8Array;
  try {
    canon = canonicalize(b);
  } catch (err) {
    throw wrap(rel, err);
  }
  if (!Buffer.from(canon).equals(Buffer.from(b))) {
    throw new CaseError(
      `${rel} is not in RFC 8785 canonical form (no white space, sorted members, no trailing newline)`,
    );
  }
  return b;
}

// Requires the entry's jti, iat, nbf and, when the entry states one, exp in
// a decoded artifact. iat defaults to FIXED_TIME and nbf to the iat.
function checkClaims(a: Artifact, payload: Uint8Array): void {
  let jti: string;
  let got: Record<'iat' | 'nbf' | 'exp', number | null>;
  try {
    const o = object(payload);
    jti = stringMember(o, 'jti');
    got = { iat: intMember(o, 'iat'), nbf: intMember(o, 'nbf'), exp: intMember(o, 'exp') };
  } catch (err) {
    throw wrap(a.decoded, err);
  }
  const iat = a.iat ?? FIXED_TIME;
  const nbf = a.nbf ?? iat;
  const show = (v: number | null) => (v === null ? 'absent' : String(v));
  const fixed = (name: 'iat' | 'nbf' | 'exp', want: number) => {
    if (got[name] !== want) {
      throw new CaseError(`${a.decoded}: ${name} ${show(got[name])}, want the fixed ${want}`);
    }
  };
  if (jti !== a.jti) throw new CaseError(`${a.decoded}: jti ${q(jti)}, want the fixed ${q(a.jti)}`);
  fixed('iat', iat);
  fixed('nbf', nbf);
  if (a.exp !== null) fixed('exp', a.exp);
}

// Sets, in the decoded payload, the member that each RFC 6901 pointer of
// digests names to the artifact_digest (draft Section 7.4) of the signed file
// its path names, which an earlier entry signed, and returns the payload in
// RFC 8785 canonical form.
function fillDigests(
  payload: Uint8Array,
  digests: Readonly<Record<string, string>>,
  signed: ReadonlyMap<string, SignedArtifact>,
): Uint8Array {
  const doc = parse(payload);
  for (const ptr of Object.keys(digests).sort()) {
    const rel = digests[ptr] as string;
    const a = signed.get(rel);
    if (a === undefined) {
      throw new CaseError(`digests ${ptr}: ${rel} is not the signed file of an earlier entry`);
    }
    try {
      setPointer(doc, ptr, artifactDigest(a.compact));
    } catch (err) {
      throw wrap(`digests ${ptr}`, err);
    }
  }
  return canonicalize(utf8.encode(JSON.stringify(doc)));
}

const INDEX = /^(?:0|[1-9][0-9]*)$/;

// Sets the member or array element that the RFC 6901 pointer ptr names in
// doc to v. Every step but the last must exist; the last may add a member to
// an object, but only replace an element of an array.
function setPointer(doc: unknown, ptr: string, v: string): void {
  if (!ptr.startsWith('/')) throw new CaseError(`${q(ptr)} does not name a member`);
  const tokens = ptr.slice(1).split('/');
  let cur = doc;
  for (const [i, raw] of tokens.entries()) {
    const tok = raw.replaceAll('~1', '/').replaceAll('~0', '~');
    const last = i === tokens.length - 1;
    if (Array.isArray(cur)) {
      const n = INDEX.test(tok) ? Number(tok) : -1;
      if (n < 0 || n >= cur.length) throw new CaseError(`no array element ${q(tok)}`);
      if (last) {
        cur[n] = v;
        return;
      }
      cur = cur[n];
    } else if (typeof cur === 'object' && cur !== null) {
      const o = cur as Record<string, unknown>;
      if (last) {
        Object.defineProperty(o, tok, {
          value: v,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        return;
      }
      if (!Object.hasOwn(o, tok)) throw new CaseError(`no member ${q(tok)}`);
      cur = o[tok];
    } else {
      throw new CaseError(`${q(tok)} is inside a value that is not an object or array`);
    }
  }
}
