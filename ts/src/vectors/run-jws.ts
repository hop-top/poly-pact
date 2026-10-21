/**
 * The vectors/jws group of the harness, after cli/pactconf vectors_jws.go
 * and spec/v1.0/fixtures/vectors/jws/README.md.
 *
 * @module
 */
import { createECDH, createPublicKey } from 'node:crypto';
import { ALG_ED25519, ALG_ES256, type JWK } from '../core/jws/index.ts';
import { VERSION } from '../core/limits.ts';
import { StrictJSONError } from '../core/strictjson.ts';
import type { Core } from './core.ts';
import {
  base64URL,
  bytes,
  equal,
  exactMembers,
  isObject,
  messageOf,
  nullableStringOf,
  readJSON,
  rethrowStub,
  singleFile,
  str,
  stringOf,
} from './fixture.ts';
import type { Entry } from './manifest.ts';

const VERIFY_MEMBERS = [
  'compact',
  'decode_as',
  'description',
  'expect',
  'expected_holder_jkt',
  'expected_payload',
  'expected_typ',
  'id',
  'reject_reason',
  'signature_valid',
  'signer_jwk',
  'trusted_keysets',
];

/** The harness reason of an artifact refused after verification (strict typed decode, pact_version). */
export const PAYLOAD_SCHEMA = 'payload-schema';

/**
 * The algorithms an entry runs with: ES256 and Ed25519 when it lists the
 * capability jws-ed25519, otherwise the baseline (empty: ES256 alone).
 */
export function algorithmsOf(e: Entry): readonly string[] {
  return e.capabilities.includes('jws-ed25519') ? [ALG_ES256, ALG_ED25519] : [];
}

function parseKey(core: Core, raw: unknown, algorithms: readonly string[]): JWK {
  return core.parseJWK(bytes(JSON.stringify(raw)), algorithms);
}

/** vectors/jws: one verify vector, or one of the three array files. */
export function runJWS(root: string, e: Entry, core: Core): void {
  singleFile(e);
  switch (e.id) {
    case 'vectors/jws/thumbprint':
      runThumbprints(root, e, core);
      return;
    case 'vectors/jws/jwk-reject':
      runJWKRejects(root, e, core);
      return;
    case 'vectors/jws/appendix-c-keys':
      runKeyDerivations(root, e, core);
      return;
  }
  const v = exactMembers(readJSON(root, e.path), ...VERIFY_MEMBERS);
  if (v.id !== e.id)
    throw new Error(`vector id ${JSON.stringify(v.id)}, manifest id ${JSON.stringify(e.id)}`);
  const rejectReason = nullableStringOf(v.reject_reason, 'reject_reason');
  const agree =
    (v.expect === 'accept' && rejectReason === null && e.outcome === 'ACCEPTED') ||
    (v.expect === 'reject' && rejectReason !== null && e.outcome === 'REJECTED');
  if (!agree) {
    throw new Error(
      `expect ${JSON.stringify(v.expect)}, reject_reason and outcome ${JSON.stringify(e.outcome)} do not agree`,
    );
  }

  const algs = algorithmsOf(e);
  if (!isObject(v.trusted_keysets)) throw new Error('trusted_keysets is not an object');
  const sets = new Map<string, JWK[]>();
  for (const [role, keys] of Object.entries(v.trusted_keysets)) {
    if (!Array.isArray(keys)) throw new Error(`trusted_keysets.${role} is not an array`);
    sets.set(
      role,
      keys.map((k) => {
        try {
          return parseKey(core, k, algs);
        } catch (err) {
          rethrowStub(err);
          throw new Error(`trusted key for ${role}: ${messageOf(err)}`);
        }
      }),
    );
  }
  const holderJKT = nullableStringOf(v.expected_holder_jkt, 'expected_holder_jkt') ?? '';
  let resolver: unknown;
  try {
    resolver = core.keyResolver(sets, holderJKT, algs);
  } catch (err) {
    rethrowStub(err);
    throw new Error(`key sets: ${messageOf(err)}`);
  }
  const typ = nullableStringOf(v.expected_typ, 'expected_typ') ?? '';
  const decodeAs = nullableStringOf(v.decode_as, 'decode_as');

  let reason = '';
  let payload: Uint8Array | undefined;
  try {
    payload = core.verify(stringOf(v.compact, 'compact'), resolver, typ, algs).payload;
  } catch (err) {
    rethrowStub(err);
    reason = core.reasonOf(err);
    if (reason === '') throw new Error(`error without a reason: ${messageOf(err)}`);
  }
  if (payload !== undefined && decodeAs !== null) reason = decodeArtifact(decodeAs, payload, core);

  if (v.expect === 'accept') {
    if (reason !== '') throw new Error(`rejected (${reason}), want accept`);
    const want = v.expected_payload;
    if (typeof want !== 'string' || payload === undefined || !equal(payload, bytes(want))) {
      throw new Error(
        `payload ${JSON.stringify(payload === undefined ? null : str(payload))} differs from expected_payload`,
      );
    }
    return;
  }
  if (reason !== rejectReason)
    throw new Error(`reason ${JSON.stringify(reason)}, want ${JSON.stringify(rejectReason)}`);
}

/**
 * The artifact layer after verification: a strict typed decode as the named
 * type and its pact_version. Returns payload-schema when the artifact is
 * refused, '' when it is accepted.
 */
function decodeArtifact(typ: string, payload: Uint8Array, core: Core): string {
  if (typ !== 'Evidence') throw new Error(`decode_as ${JSON.stringify(typ)} is not handled`);
  let ev: unknown;
  try {
    ev = core.decodeEvidence(payload);
  } catch (err) {
    rethrowStub(err);
    if (err instanceof StrictJSONError) return PAYLOAD_SCHEMA;
    throw new Error(`decode as Evidence: ${messageOf(err)}`);
  }
  return isObject(ev) && ev.pact_version === VERSION ? '' : PAYLOAD_SCHEMA;
}

function rows(root: string, e: Entry, outcome: string, what: string): Record<string, unknown>[] {
  const vs = readJSON(root, e.path);
  if (!Array.isArray(vs) || vs.length === 0 || e.outcome !== outcome) {
    throw new Error(
      `no ${what} vectors, or outcome ${JSON.stringify(e.outcome)} is not ${outcome}`,
    );
  }
  return vs.map((v, i) => {
    if (!isObject(v) || typeof v.id !== 'string')
      throw new Error(`${what} vector ${i} is malformed`);
    return v;
  });
}

function runThumbprints(root: string, e: Entry, core: Core): void {
  for (const v of rows(root, e, 'ACCEPTED', 'thumbprint')) {
    let got: string;
    try {
      got = core.thumbprint(parseKey(core, v.jwk, algorithmsOf(e)));
    } catch (err) {
      rethrowStub(err);
      throw new Error(`${v.id}: ${messageOf(err)}`);
    }
    if (got !== v.expected_thumbprint)
      throw new Error(`${v.id}: thumbprint ${got}, want ${String(v.expected_thumbprint)}`);
  }
}

function runJWKRejects(root: string, e: Entry, core: Core): void {
  for (const v of rows(root, e, 'REJECTED', 'jwk-reject')) {
    let got = '';
    let detail = 'accepted';
    try {
      core.thumbprint(parseKey(core, v.jwk, algorithmsOf(e)));
    } catch (err) {
      rethrowStub(err);
      got = core.reasonOf(err);
      detail = messageOf(err);
    }
    if (got !== v.reject_reason) {
      throw new Error(
        `${v.id}: reason ${JSON.stringify(got)} (${detail}), want ${JSON.stringify(v.reject_reason)}`,
      );
    }
  }
}

/** The P-256 public point of the 32-octet scalar d, by the platform's ECDH. */
export function derivePoint(d: Uint8Array): { x: string; y: string } {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const p = ecdh.getPublicKey();
  return { x: p.subarray(1, 33).toString('base64url'), y: p.subarray(33).toString('base64url') };
}

/** The platform public key of a P-256 point. */
export function publicKeyOf(point: { x: string; y: string }) {
  return createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: point.x, y: point.y },
    format: 'jwk',
  });
}

function runKeyDerivations(root: string, e: Entry, core: Core): void {
  for (const v of rows(root, e, 'ACCEPTED', 'key')) {
    let d: Uint8Array;
    try {
      d = base64URL(stringOf(v.d, 'd'), 'd');
    } catch {
      d = new Uint8Array();
    }
    if (d.length !== 32) throw new Error(`${v.id}: d is not 32 octets of base64url`);
    const k = core.publicJWK(publicKeyOf(derivePoint(d)));
    if (k.x !== v.expected_x || k.y !== v.expected_y) {
      throw new Error(
        `${v.id}: derived x=${k.x} y=${k.y}, want x=${String(v.expected_x)} y=${String(v.expected_y)}`,
      );
    }
    const tp = core.thumbprint(k);
    if (tp !== v.expected_thumbprint)
      throw new Error(`${v.id}: thumbprint ${tp}, want ${String(v.expected_thumbprint)}`);
  }
}
