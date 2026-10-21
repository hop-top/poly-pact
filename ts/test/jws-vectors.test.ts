// Port of go/core/jws/vectors_test.go: the language-neutral vectors under
// spec/v1.0/fixtures/vectors/jws (format in their README), listed in
// spec/v1.0/fixtures/manifest.json. The expected results come from the vector
// files; signature_valid is recomputed with node:crypto alone.

import assert from 'node:assert/strict';
import { verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { test } from 'node:test';
import {
  type JWK,
  KeySet,
  parseJWK,
  publicJWK,
  publicKeyOf,
  reasonOf,
  StaticResolver,
  thumbprint,
  typs,
  Verifier,
} from '../src/core/jws/index.ts';
import { artifactJSON, defaultLimits, VERSION } from '../src/core/limits.ts';
import { shapes } from '../src/core/shapes.ts';
import { decode } from '../src/core/strictjson.ts';
import {
  bytes,
  filesUnder,
  fixturesPresent,
  type ManifestEntry,
  manifestEntries,
  readFixtureJSON,
  str,
} from './support/fixtures.ts';
import { HOLDER_JKT, int, scalarKey } from './support/jws.ts';

const PREFIX = 'vectors/jws/';

// The array files; every other file under vectors/jws holds one verify vector.
const THUMBPRINT_ID = `${PREFIX}thumbprint`;
const JWK_REJECT_ID = `${PREFIX}jwk-reject`;
const KEYS_ID = `${PREFIX}appendix-c-keys`;

const VERIFY_FIELDS = [
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

interface VerifyVector {
  readonly id: string;
  readonly description: string;
  readonly compact: string;
  readonly expected_typ: string | null;
  readonly trusted_keysets: Readonly<Record<string, readonly unknown[]>>;
  readonly expected_holder_jkt: string | null;
  readonly decode_as: string | null;
  readonly expect: string;
  readonly reject_reason: string | null;
  readonly signer_jwk: Record<string, unknown> | null;
  readonly signature_valid: boolean | null;
  readonly expected_payload: string | null;
}

function jwsEntries(): Map<string, ManifestEntry> {
  const out = new Map(manifestEntries(PREFIX).map((e) => [e.id, e]));
  assert.ok(out.size > 0, 'manifest lists no vectors/jws entries');
  return out;
}

const jwkOf = (v: unknown): JWK => parseJWK(bytes(JSON.stringify(v)));

test('TestManifestListsEveryJWSFile', (t) => {
  if (!fixturesPresent(t)) return;
  const listed = new Set<string>();
  for (const [id, e] of jwsEntries()) {
    assert.ok(
      e.kind === 'vector' && e.scope === 'core' && e.spec_map_row !== '' && e.draft_section !== '',
      `${id}: kind/scope/row/section = ${e.kind}/${e.scope}/${e.spec_map_row}/${e.draft_section}`,
    );
    assert.equal(e.path, `${id}.json`, `${id}: path`);
    assert.equal(e.expected, e.path, `${id}: expected`);
    listed.add(e.path);
  }
  for (const rel of filesUnder(PREFIX.slice(0, -1))) {
    if (rel.split('/').at(-1) === 'README.md') continue;
    assert.ok(listed.has(rel), `${rel} is not listed in manifest.json`);
  }
});

// The vectors the task and the draft require, with their expected result,
// so deleting one or changing its expectation fails here.
const REQUIRED_VECTORS: Readonly<Record<string, string>> = {
  'appendix-c': 'accept',
  'appendix-c-version-mismatch': 'payload-schema',
  'rfc7515-a3': 'typ-unsupported',
  'header-alg-none': 'alg-unsupported',
  'header-alg-hs256': 'alg-unsupported',
  'header-alg-rs256': 'alg-unsupported',
  'header-alg-ps256': 'alg-unsupported',
  'header-alg-eddsa': 'alg-unsupported',
  'header-jwk-private': 'jwk-private',
  'header-jku': 'header-jku',
  'header-x5u': 'header-x5u',
  'header-x5c': 'header-x5c',
  'header-crit': 'header-crit',
  'header-b64-false': 'header-b64',
  'payload-detached': 'payload-detached',
  'header-jwk-p384': 'jwk-curve',
  'header-jwk-off-curve': 'jwk-off-curve',
  'holder-jkt-mismatch': 'holder-jkt-mismatch',
  'es256-valid': 'accept',
  'es256-noncanonical-payload': 'accept',
  'es256-noncanonical-header': 'accept',
  'es256-leading-zero-r': 'accept',
  'es256-signature-63-bytes': 'signature-length',
  'es256-signature-der': 'signature-length',
  'es256-signature-padded': 'base64url',
  'es256-high-s': 'accept',
  'typ-requirements': 'accept',
  'typ-evidence': 'accept',
  'typ-presentation': 'accept',
  'typ-admission': 'accept',
  'typ-outcome': 'accept',
  'typ-reputation': 'accept',
  'typ-learning-policy': 'accept',
  'typ-learning-artifact': 'accept',
  'typ-learning-event': 'accept',
  'typ-admission-signed-by-issuer': 'kid-unknown',
};

test('TestRequiredVectors', (t) => {
  if (!fixturesPresent(t)) return;
  const entries = jwsEntries();
  for (const [stem, want] of Object.entries(REQUIRED_VECTORS)) {
    const e = entries.get(PREFIX + stem);
    assert.ok(e, `required vector ${stem} is missing`);
    const v = readFixtureJSON(e.path) as VerifyVector;
    assert.equal(v.reject_reason ?? v.expect, want, stem);
  }
  // Every typ of the draft 7.3 table has a required accept vector.
  for (const typ of typs()) {
    const stem = `typ-${typ.replace(/^pact-/, '').replace(/\+jwt$/, '')}`;
    assert.equal(
      REQUIRED_VECTORS[stem],
      'accept',
      `no required accept vector ${stem} for typ ${typ}`,
    );
  }
});

test('TestVerifyVectors', async (t) => {
  if (!fixturesPresent(t)) return;
  let n = 0;
  for (const [id, e] of jwsEntries()) {
    if (id === THUMBPRINT_ID || id === JWK_REJECT_ID || id === KEYS_ID) continue;
    n++;
    await t.test(id.slice(PREFIX.length), () => {
      const v = readFixtureJSON(e.path) as VerifyVector;
      assert.deepEqual(Object.keys(v).sort(), VERIFY_FIELDS, 'members');
      assert.equal(v.id, id);
      runVerifyVector(v, e);
    });
  }
  assert.ok(n >= 40, `only ${n} verify vectors`);
});

function runVerifyVector(v: VerifyVector, e: ManifestEntry): void {
  const agree =
    (v.expect === 'accept' && v.reject_reason === null && e.outcome === 'ACCEPTED') ||
    (v.expect === 'reject' && v.reject_reason !== null && e.outcome === 'REJECTED');
  assert.ok(agree, `expect ${v.expect}, reject_reason ${v.reject_reason}, outcome ${e.outcome}`);
  const sets = new Map<string, KeySet>();
  for (const [role, keys] of Object.entries(v.trusted_keysets)) {
    sets.set(role, new KeySet(...keys.map(jwkOf)));
  }
  const res = new StaticResolver(sets, v.expected_holder_jkt ?? '');
  const verifier = new Verifier({ keys: res, typ: v.expected_typ ?? '' });
  checkSignatureValid(v);

  let reason = '';
  let payload: Uint8Array | undefined;
  try {
    payload = verifier.verify(v.compact).payload;
  } catch (err) {
    reason = reasonOf(err);
    assert.notEqual(reason, '', `error without a reason: ${String(err)}`);
  }
  if (payload !== undefined && v.decode_as !== null) reason = decodeAs(v.decode_as, payload);
  if (v.expect === 'accept') {
    assert.equal(reason, '', 'rejected, want accept');
    assert.equal(payload === undefined ? undefined : str(payload), v.expected_payload);
    return;
  }
  assert.equal(reason, v.reject_reason);
}

// The artifact layer after a successful verification: a strict decode as
// the named type and the pact_version constant of the schema;
// payload-schema when the artifact is rejected.
function decodeAs(typ: string, payload: Uint8Array): string {
  assert.equal(typ, 'Evidence', `decode_as ${typ} is not handled`);
  try {
    const ev = decode<{ pact_version: string }>(
      payload,
      shapes.Evidence,
      artifactJSON(defaultLimits()),
    );
    return ev.pact_version === VERSION ? '' : 'payload-schema';
  } catch {
    return 'payload-schema';
  }
}

// Recomputes signature_valid with node:crypto alone: the signature octets,
// decoded leniently, over the received signing input under signer_jwk. It
// shows that a vector rejected for another reason does not also carry a bad
// signature by accident.
function checkSignatureValid(v: VerifyVector): void {
  const parts = v.compact.split('.');
  let got: boolean | null = null;
  if (parts.length === 3 && v.signer_jwk !== null) {
    if (v.signer_jwk.kty === 'EC' && v.signer_jwk.crv === 'P-256') {
      const pub = publicKeyOf(jwkOf(v.signer_jwk));
      got = lenientVerify(pub, `${parts[0]}.${parts[1]}`, parts[2] ?? '');
    }
  }
  assert.equal(got, v.signature_valid, 'signature_valid, recomputed');
}

function lenientVerify(pub: KeyObject, signingInput: string, seg: string): boolean {
  const s = seg
    .replace(/[\r\n=]/g, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_');
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return false;
  const sig = Buffer.from(s, 'base64url');
  if (sig.length !== 64) return false;
  return cryptoVerify(
    'sha256',
    Buffer.from(signingInput),
    { key: pub, dsaEncoding: 'ieee-p1363' },
    sig,
  );
}

function entry(id: string): ManifestEntry {
  const e = jwsEntries().get(id);
  assert.ok(e, `manifest lacks ${id}`);
  return e;
}

interface Row {
  readonly id: string;
  readonly jwk: unknown;
  readonly [k: string]: unknown;
}

test('TestThumbprintVectors', async (t) => {
  if (!fixturesPresent(t)) return;
  const e = entry(THUMBPRINT_ID);
  assert.equal(e.outcome, 'ACCEPTED');
  const vs = readFixtureJSON(e.path) as Row[];
  const seen = new Set<string>();
  for (const v of vs) {
    await t.test(v.id, () => {
      seen.add(v.id);
      assert.equal(thumbprint(jwkOf(v.jwk)), v.expected_thumbprint);
    });
  }
  for (const id of [
    'appendix-c-holder',
    'holder-with-optional-members',
    'holder-reordered-extra-member',
    'leading-zero-x',
  ]) {
    assert.ok(seen.has(id), `thumbprint vector ${id} missing`);
  }
  for (const v of vs) {
    if (v.id.startsWith('appendix-c-holder')) assert.equal(v.expected_thumbprint, HOLDER_JKT, v.id);
  }
});

test('TestJWKRejectVectors', async (t) => {
  if (!fixturesPresent(t)) return;
  const e = entry(JWK_REJECT_ID);
  assert.equal(e.outcome, 'REJECTED');
  const vs = readFixtureJSON(e.path) as Row[];
  assert.ok(vs.length >= 10, `only ${vs.length} jwk-reject vectors`);
  for (const v of vs) {
    await t.test(v.id, () => {
      let got = '';
      try {
        thumbprint(jwkOf(v.jwk));
      } catch (err) {
        got = reasonOf(err);
      }
      assert.equal(got, v.reject_reason);
    });
  }
});

test('TestAppendixCKeyVectors', async (t) => {
  if (!fixturesPresent(t)) return;
  const e = entry(KEYS_ID);
  const vs = readFixtureJSON(e.path) as Row[];
  assert.equal(vs.length, 2, 'holder and issuer');
  for (const v of vs) {
    await t.test(v.id, () => {
      const d = Buffer.from(String(v.d), 'base64url');
      assert.equal(d.length, 32);
      const k = publicJWK(scalarKey(int(d)));
      assert.equal(k.x, v.expected_x);
      assert.equal(k.y, v.expected_y);
      assert.equal(thumbprint(k), v.expected_thumbprint);
    });
  }
  assert.equal(vs[0]?.expected_thumbprint, HOLDER_JKT, 'the Appendix C holder_jkt');
});
