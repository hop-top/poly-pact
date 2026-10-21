// Port of go/core/jws/sign_test.go. Signing is randomized, so the tests check
// properties of signatures and the exact header and payload segments, never
// signature bytes. The low-S rule is the one Go applies (S is the low value
// of the pair S, n-S); Node's signer writes a high S about half the time
// (docs/sdk/probes/ts.md), so 64 signatures without normalization have a
// high S with probability 1 - 2^-64.

import assert from 'node:assert/strict';
import { createSecretKey, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import {
  ALG_ES256,
  type Header,
  KeySet,
  Reason,
  Role,
  StaticResolver,
  sign,
  TYP_EVIDENCE,
  TYP_PRESENTATION,
  thumbprint,
  typRole,
  typs,
  verify,
} from '../src/core/jws/index.ts';
import { appendixB5, appendixCCompact } from './support/draft.ts';
import { bytes, fixturesPresent, str } from './support/fixtures.ts';
import {
  fixtureJWK,
  HOLDER_JKT,
  int,
  issuerResolver,
  N,
  SMALL_PAYLOAD,
  scalarKey,
  wantReason,
} from './support/jws.ts';
import { DRAFT, specText } from './support/repo.ts';

test('TestSignVerifyRoundTrip', async (t) => {
  if (!fixturesPresent(t)) return;
  const holder = scalarKey(1);
  const issuer = scalarKey(2);
  const issuerJWK = fixtureJWK('issuer');
  const sets = new Map<string, KeySet>();
  for (const typ of typs()) {
    const role = typRole(typ);
    if (role !== Role.HOLDER && role !== undefined) sets.set(role, new KeySet(issuerJWK));
  }
  const res = new StaticResolver(sets, HOLDER_JKT);
  const payload = '{\n  "pact_version": "0.1",\n  "jti": "round-trip"\n}';
  for (const typ of typs()) {
    await t.test(typ, () => {
      const role = typRole(typ);
      assert.ok(role !== undefined, `typRole(${typ})`);
      let h: Header = { typ, kid: 'test-issuer-key-1' };
      let key = issuer;
      let wantKey = issuerJWK;
      if (role === Role.HOLDER) {
        h = { typ };
        key = holder;
        wantKey = fixtureJWK('holder');
      }
      const compact = sign(h, bytes(payload), key);
      const p = verify(compact, res);
      assert.equal(p.compact, compact);
      assert.equal(p.role, role);
      assert.equal(p.header.typ, typ);
      assert.equal(p.header.alg, ALG_ES256);
      assert.equal(str(p.payload), payload);
      assert.equal(p.signature.length, 64);
      assert.equal(p.key.x, wantKey.x);
      assert.equal(p.key.y, wantKey.y);
      assert.equal(p.keyThumbprint, thumbprint(wantKey));
      if (role === Role.HOLDER) {
        assert.ok(p.header.jwk !== undefined, 'holder header embeds a jwk');
        assert.equal(p.header.kid ?? '', '');
      } else {
        assert.equal(p.header.jwk, undefined);
        assert.equal(p.header.kid, 'test-issuer-key-1');
      }
    });
  }
});

// The header sign writes for an evidence artifact is the protected header of
// the draft's Appendix C JWS, byte for byte, and the payload is signed as
// given.
test('TestSignMatchesAppendixCHeader', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const appc = appendixCCompact(draft);
  const compact = sign(
    { typ: TYP_EVIDENCE, kid: 'test-issuer-key-1' },
    bytes(appendixB5(draft)),
    scalarKey(2),
  );
  const [gh, gp] = compact.split('.');
  const [wh, wp] = appc.split('.');
  assert.equal(gh, wh, 'header segment of Appendix C');
  assert.equal(gp, wp, 'payload segment of Appendix C: the payload bytes were changed');
});

test('TestSignHolderHeader', (t) => {
  if (!fixturesPresent(t)) return;
  const compact = sign({ typ: TYP_PRESENTATION }, bytes(SMALL_PAYLOAD), scalarKey(1));
  const hdr = Buffer.from(compact.split('.')[0] ?? '', 'base64url').toString();
  const hj = fixtureJWK('holder');
  assert.equal(
    hdr,
    `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"${hj.x}","y":"${hj.y}"}}`,
  );
});

// The header is written as Go's encoder writes it (SetEscapeHTML false): <, >
// and & as they are, U+2028 and U+2029 escaped, control characters as \b, \f,
// \n, \r, \t or \u00XX.
test('TestSignHeaderEscapes', () => {
  const kid = 'a b <&>\x01\b\f"\\é';
  const compact = sign({ typ: TYP_EVIDENCE, kid }, bytes('{}'), scalarKey(2));
  assert.equal(
    Buffer.from(compact.split('.')[0] ?? '', 'base64url').toString(),
    '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"a\\u2028b\\u2029<&>\\u0001\\b\\f\\"\\\\é"}',
  );
});

test('TestSignRejects', async (t) => {
  if (!fixturesPresent(t)) return;
  const issuer = scalarKey(2);
  const holder = scalarKey(1);
  const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
  const ed = generateKeyPairSync('ed25519').privateKey;
  const adv = fixtureJWK('adversarial');
  const kid = { typ: TYP_EVIDENCE, kid: 'k' };
  const cases: [string, Header, string, unknown, Reason][] = [
    ['nil key', kid, SMALL_PAYLOAD, undefined, Reason.SIGNING_KEY],
    ['P-384 key', kid, SMALL_PAYLOAD, p384, Reason.SIGNING_KEY],
    ['Ed25519 key', kid, SMALL_PAYLOAD, ed, Reason.SIGNING_KEY],
    [
      'public key',
      kid,
      SMALL_PAYLOAD,
      generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey,
      Reason.SIGNING_KEY,
    ],
    ['secret key', kid, SMALL_PAYLOAD, createSecretKey(new Uint8Array(32)), Reason.SIGNING_KEY],
    ['not a key', kid, SMALL_PAYLOAD, { kty: 'EC' }, Reason.SIGNING_KEY],
    ['alg HS256', { ...kid, alg: 'HS256' }, SMALL_PAYLOAD, issuer, Reason.ALG_UNSUPPORTED],
    ['typ unknown', { typ: 'JWT', kid: 'k' }, SMALL_PAYLOAD, issuer, Reason.TYP_UNSUPPORTED],
    ['service without kid', { typ: TYP_EVIDENCE }, SMALL_PAYLOAD, issuer, Reason.KID_MISSING],
    ['service with jwk', { ...kid, jwk: adv }, SMALL_PAYLOAD, issuer, Reason.JWK_UNEXPECTED],
    [
      'holder jwk of another key',
      { typ: TYP_PRESENTATION, jwk: adv },
      SMALL_PAYLOAD,
      holder,
      Reason.SIGNING_KEY,
    ],
    ['payload not JSON', kid, 'hello', issuer, Reason.PAYLOAD_JSON],
    ['payload array', kid, '[]', issuer, Reason.PAYLOAD_JSON],
    ['payload null', kid, 'null', issuer, Reason.PAYLOAD_JSON],
    ['payload duplicate member', kid, '{"a":1,"a":2}', issuer, Reason.PAYLOAD_JSON],
  ];
  for (const [name, h, payload, key, want] of cases) {
    await t.test(name, () => {
      wantReason(() => sign(h, bytes(payload), key as never), want);
    });
  }
  await t.test('alg ES256 and holder jwk of the key are accepted', () => {
    assert.doesNotThrow(() => sign({ ...kid, alg: ALG_ES256 }, bytes(SMALL_PAYLOAD), issuer));
    const hj = fixtureJWK('holder');
    const compact = sign({ typ: TYP_PRESENTATION, jwk: hj }, bytes(SMALL_PAYLOAD), holder);
    assert.equal(
      Buffer.from(compact.split('.')[0] ?? '', 'base64url').toString(),
      `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"${hj.x}","y":"${hj.y}","kid":"test-holder-key-1","alg":"ES256","use":"sig"}}`,
    );
  });
});

test('TestSignWritesLowS', (t) => {
  if (!fixturesPresent(t)) return;
  const key = scalarKey(2);
  const half = N >> 1n;
  const res = issuerResolver();
  for (let i = 0; i < 64; i++) {
    const compact = sign(
      { typ: TYP_EVIDENCE, kid: 'test-issuer-key-1' },
      bytes(SMALL_PAYLOAD),
      key,
    );
    const p = verify(compact, res);
    assert.ok(int(p.signature.subarray(32)) <= half, `signature ${i} has a high S`);
  }
});
