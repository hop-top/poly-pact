/**
 * The key rule of the harness (docs/sdk/ports-plan.md section 5.2), after
 * cli/pactconf vectors_keys.go and spec/v1.0/fixtures/keys/README.md: every
 * P-256 JWK under keys/ parses, and its point is the scalar of its record in
 * keys/test-private-scalars.json times the base point; the holder key's
 * RFC 7638 thumbprint is the holder_jkt of draft Appendix C.
 *
 * @module
 */
import type { Core } from './core.ts';
import {
  base64URL,
  isObject,
  messageOf,
  readFixture,
  readJSON,
  rethrowStub,
  Skipped,
  str,
} from './fixture.ts';
import type { Entry } from './manifest.ts';
import { derivePoint, publicKeyOf } from './run-jws.ts';

/** The file of private test values, relative to the fixture directory. */
export const KEY_SCALARS_PATH = 'keys/test-private-scalars.json';

/** The holder_jkt of draft Appendix C: the thumbprint of the P-256 key of scalar 1. */
export const APPENDIX_C_HOLDER_JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';

type KeyRecord = Record<string, unknown>;

function p256(k: KeyRecord): boolean {
  return k.kty === 'EC' && k.crv === 'P-256';
}

function jwkPath(k: KeyRecord): string {
  return `keys/${String(k.public_jwk)}`;
}

/** A key entry: one JWK file, or the scalars file itself. */
export function runKey(root: string, e: Entry, core: Core): void {
  const scalars = readJSON(root, KEY_SCALARS_PATH);
  if (!isObject(scalars) || !Array.isArray(scalars.keys) || !scalars.keys.every(isObject)) {
    throw new Error(`${KEY_SCALARS_PATH}: not an object with a keys array of records`);
  }
  const records = scalars.keys as KeyRecord[];
  if (e.path === KEY_SCALARS_PATH) {
    let holder = false;
    for (const k of records.filter(p256)) {
      try {
        checkKeyRecord(root, k, core);
      } catch (err) {
        rethrowStub(err);
        throw new Error(`record of role ${String(k.role)}: ${messageOf(err)}`);
      }
      holder ||= k.role === 'holder';
    }
    if (!holder)
      throw new Error('no P-256 record of role holder, the key of Appendix C holder_jkt');
    return;
  }
  const head: unknown = JSON.parse(str(readFixture(root, e.path)));
  if (isObject(head) && head.kty === 'OKP' && head.crv === 'Ed25519') {
    throw new Skipped(
      'out-of-scope',
      'Ed25519 key: the algorithm is optional (draft section 7.2) and not verified here',
    );
  }
  const k = records.find((r) => jwkPath(r) === e.path);
  if (k === undefined)
    throw new Error(`no record in ${KEY_SCALARS_PATH} names ${e.path.split('/').at(-1)}`);
  checkKeyRecord(root, k, core);
}

/**
 * Derives the public point of a P-256 record from its d, which must be its
 * scalar as 32 big-endian octets, and compares it with the record's JWK.
 */
function checkKeyRecord(root: string, k: KeyRecord, core: Core): void {
  if (!p256(k))
    throw new Error(`kty ${JSON.stringify(k.kty)} crv ${JSON.stringify(k.crv)}, want EC P-256`);
  let d: Uint8Array;
  try {
    d = base64URL(String(k.d), 'd');
  } catch {
    d = new Uint8Array();
  }
  if (d.length !== 32) throw new Error('d is not 32 octets of base64url');
  const scalar = typeof k.scalar === 'string' && /^[0-9]+$/.test(k.scalar) ? BigInt(k.scalar) : 0n;
  if (scalar <= 0n || scalar >= 1n << 256n) {
    throw new Error(`scalar ${JSON.stringify(k.scalar)} is not a positive decimal integer`);
  }
  if (BigInt(`0x${Buffer.from(d).toString('hex')}`) !== scalar) {
    throw new Error(`d is not scalar ${scalar} as 32 big-endian octets`);
  }
  const want = core.publicJWK(publicKeyOf(derivePoint(d)));
  const path = jwkPath(k);
  const got = core.parseJWK(readFixture(root, path), []);
  if (got.x !== want.x || got.y !== want.y) {
    throw new Error(
      `${path}: public point x=${got.x} y=${got.y}, but scalar ${scalar} times G is x=${want.x} y=${want.y}`,
    );
  }
  if (k.role === 'holder') {
    const tp = core.thumbprint(got);
    if (tp !== APPENDIX_C_HOLDER_JKT) {
      throw new Error(
        `${path}: holder thumbprint ${tp}, want Appendix C holder_jkt ${APPENDIX_C_HOLDER_JKT}`,
      );
    }
  }
}
