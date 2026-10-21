// Port of go/core/jws/jwk_test.go. Expected thumbprints are the Appendix C
// holder_jkt and the RFC 7638 values computed independently for the P-256
// test keys; expected reasons follow RFC 7517, RFC 7518 section 6.2.1 and
// draft 7.2. The coordinate cases beyond Go's (31 and 33 octets, padding,
// spare bits, the standard alphabet) are the inputs Node's JWK import
// accepts: the profile refuses each one
// before the import.

import assert from 'node:assert/strict';
import { createPublicKey, createSecretKey, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import {
  ALG_ES256,
  Algorithms,
  algorithmOf,
  type JWK,
  KeySet,
  parseJWK,
  publicJWK,
  publicKeyOf,
  Reason,
  thumbprint,
} from '../src/core/jws/index.ts';
import { bytes, fixturesPresent } from './support/fixtures.ts';
import {
  b64,
  fixtureJWK,
  HOLDER_JKT,
  octets32,
  P,
  scalarKey,
  scalarPoint,
  wantReason,
} from './support/jws.ts';

const HOLDER_X = 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY';
const HOLDER_Y = 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU';

const stdAlphabet = (s: string) => s.replaceAll('-', '+').replaceAll('_', '/');
const decode = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

// RFC 7638 over crv, kty, x, y in that order gives the holder_jkt printed in
// draft Appendix C; optional members and member order in the JWK do not
// matter.
test('TestThumbprintAppendixC', () => {
  for (const src of [
    `{"kty":"EC","crv":"P-256","x":"${HOLDER_X}","y":"${HOLDER_Y}"}`,
    `{"y":"${HOLDER_Y}","use":"sig","x":"${HOLDER_X}","key_ops":["verify"],"crv":"P-256","kid":"k","kty":"EC"}`,
  ]) {
    assert.equal(thumbprint(parseJWK(bytes(src))), HOLDER_JKT, src);
    assert.equal(thumbprint(parseJWK(src)), HOLDER_JKT, `${src} as a string`);
  }
});

test('TestThumbprintRejectsInvalidKeys', async (t) => {
  if (!fixturesPresent(t)) return;
  const hj = fixtureJWK('holder');
  const cases: [string, JWK, Reason][] = [
    ['kty RSA', { kty: 'RSA', crv: 'P-256', x: hj.x, y: hj.y ?? '' }, Reason.JWK_CURVE],
    ['crv P-384', { kty: 'EC', crv: 'P-384', x: hj.x, y: hj.y ?? '' }, Reason.JWK_CURVE],
    [
      'short x',
      { kty: 'EC', crv: 'P-256', x: hj.x.slice(0, 42), y: hj.y ?? '' },
      Reason.JWK_INVALID,
    ],
    ['empty y', { kty: 'EC', crv: 'P-256', x: hj.x }, Reason.JWK_INVALID],
    [
      'off curve',
      { kty: 'EC', crv: 'P-256', x: hj.x, y: fixtureJWK('issuer').y ?? '' },
      Reason.JWK_OFF_CURVE,
    ],
    ['padded x', { kty: 'EC', crv: 'P-256', x: `${hj.x}=`, y: hj.y ?? '' }, Reason.JWK_INVALID],
  ];
  for (const [name, k, want] of cases) {
    await t.test(name, () => {
      wantReason(() => thumbprint(k), want);
    });
  }
});

test('TestParseJWK', async (t) => {
  if (!fixturesPresent(t)) return;
  const hj = fixtureJWK('holder');
  assert.equal(hj.kid, 'test-holder-key-1');
  assert.equal(hj.alg, 'ES256');
  assert.equal(hj.use, 'sig');
  assert.equal(hj.kty, 'EC');
  assert.equal(hj.crv, 'P-256');
  const hx = hj.x;
  const hy = hj.y ?? '';
  const xy = `"kty":"EC","crv":"P-256","x":"${hx}","y":"${hy}"`;
  // A P-256 point whose x starts with a zero octet: scalar 379 (see
  // TestPublicJWKKeepsLeadingZeros), the 31-octet form Node imports.
  const lz = scalarPoint(379n);
  const cases: [string, string, Reason][] = [
    ['d', `{${xy},"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}`, Reason.JWK_PRIVATE],
    ['RSA private p', `{${xy},"p":"AQAB"}`, Reason.JWK_PRIVATE],
    ['RSA private q', `{${xy},"q":"AQAB"}`, Reason.JWK_PRIVATE],
    ['RSA private dp', `{${xy},"dp":"AQAB"}`, Reason.JWK_PRIVATE],
    ['RSA private dq', `{${xy},"dq":"AQAB"}`, Reason.JWK_PRIVATE],
    ['RSA private qi', `{${xy},"qi":"AQAB"}`, Reason.JWK_PRIVATE],
    ['RSA private oth', `{${xy},"oth":[]}`, Reason.JWK_PRIVATE],
    ['symmetric k', `{${xy},"k":"AQAB"}`, Reason.JWK_PRIVATE],
    ['d null', `{${xy},"d":null}`, Reason.JWK_PRIVATE],
    ['not JSON', 'kty=EC', Reason.JWK_INVALID],
    ['array', '[]', Reason.JWK_INVALID],
    ['null', 'null', Reason.JWK_INVALID],
    ['duplicate member', `{${xy},"x":"${hx}"}`, Reason.JWK_INVALID],
    ['x not a string', `{"kty":"EC","crv":"P-256","x":1,"y":"${hy}"}`, Reason.JWK_INVALID],
    ['kid not a string', `{${xy},"kid":1}`, Reason.JWK_INVALID],
    ['kid null', `{${xy},"kid":null}`, Reason.JWK_INVALID],
    ['use null', `{${xy},"use":null}`, Reason.JWK_INVALID],
    ['x not a string before kty', '{"kty":"RSA","crv":"P-256","x":1}', Reason.JWK_INVALID],
    ['kty missing', `{"crv":"P-256","x":"${hx}","y":"${hy}"}`, Reason.JWK_CURVE],
    [
      'kty OKP',
      '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
      Reason.JWK_CURVE,
    ],
    ['crv lowercase', `{"kty":"EC","crv":"p-256","x":"${hx}","y":"${hy}"}`, Reason.JWK_CURVE],
    ['y missing', `{"kty":"EC","crv":"P-256","x":"${hx}"}`, Reason.JWK_INVALID],
    ['x padded', `{"kty":"EC","crv":"P-256","x":"${hx}=","y":"${hy}"}`, Reason.JWK_INVALID],
    ['x and y padded', `{"kty":"EC","crv":"P-256","x":"${hx}=","y":"${hy}="}`, Reason.JWK_INVALID],
    [
      'y standard alphabet',
      `{"kty":"EC","crv":"P-256","x":"${hx}","y":"${stdAlphabet(hy)}"}`,
      Reason.JWK_INVALID,
    ],
    [
      'x 33 octets',
      `{"kty":"EC","crv":"P-256","x":"${b64(new Uint8Array([0, ...decode(hx)]))}","y":"${hy}"}`,
      Reason.JWK_INVALID,
    ],
    [
      'x 31 octets',
      `{"kty":"EC","crv":"P-256","x":"${b64(decode(lz.x).subarray(1))}","y":"${lz.y}"}`,
      Reason.JWK_INVALID,
    ],
    [
      'x spare bits',
      `{"kty":"EC","crv":"P-256","x":"${hx.slice(0, 42)}Z","y":"${hy}"}`,
      Reason.JWK_INVALID,
    ],
    [
      'x with a line feed',
      `{"kty":"EC","crv":"P-256","x":"${hx.slice(0, 20)}\\n${hx.slice(20)}","y":"${hy}"}`,
      Reason.JWK_INVALID,
    ],
    [
      'off curve',
      `{"kty":"EC","crv":"P-256","x":"${hx}","y":"${fixtureJWK('issuer').y}"}`,
      Reason.JWK_OFF_CURVE,
    ],
    [
      'x = p',
      `{"kty":"EC","crv":"P-256","x":"${b64(octets32(P))}","y":"${hy}"}`,
      Reason.JWK_OFF_CURVE,
    ],
    [
      'point at zero',
      `{"kty":"EC","crv":"P-256","x":"${b64(new Uint8Array(32))}","y":"${b64(new Uint8Array(32))}"}`,
      Reason.JWK_OFF_CURVE,
    ],
    ['alg RS256', `{${xy},"alg":"RS256"}`, Reason.JWK_USAGE],
    ['use enc', `{${xy},"use":"enc"}`, Reason.JWK_USAGE],
    // key_ops (RFC 7517 section 4.3): a verification key names verify, and
    // no operation twice.
    ['key_ops sign', `{${xy},"key_ops":["sign"]}`, Reason.JWK_USAGE],
    ['key_ops encrypt', `{${xy},"key_ops":["encrypt"]}`, Reason.JWK_USAGE],
    ['key_ops empty', `{${xy},"key_ops":[]}`, Reason.JWK_USAGE],
    ['key_ops Verify', `{${xy},"key_ops":["Verify"]}`, Reason.JWK_USAGE],
    ['key_ops duplicate', `{${xy},"key_ops":["verify","verify"]}`, Reason.JWK_INVALID],
    ['key_ops a string', `{${xy},"key_ops":"verify"}`, Reason.JWK_INVALID],
    ['key_ops not strings', `{${xy},"key_ops":["verify",5]}`, Reason.JWK_INVALID],
    ['key_ops null', `{${xy},"key_ops":null}`, Reason.JWK_INVALID],
    ['alg checked before key_ops', `{${xy},"alg":"RS256","key_ops":[]}`, Reason.JWK_USAGE],
  ];
  for (const [name, src, want] of cases) {
    await t.test(name, () => {
      wantReason(() => parseJWK(bytes(src)), want);
    });
  }
  await t.test('accepted', () => {
    // Members the JWK specification does not define are ignored (RFC 7517
    // section 4).
    assert.doesNotThrow(() =>
      parseJWK(bytes(`{${xy},"key_ops":["verify"],"x5t":"abc","ext":true}`)),
    );
    // key_ops that name verify, alone or with other operations, are accepted.
    for (const ops of ['["verify"]', '["sign","verify"]', '["verify","encrypt"]']) {
      assert.doesNotThrow(() => parseJWK(bytes(`{${xy},"key_ops":${ops}}`)), ops);
    }
    // The 32-octet form of the leading-zero coordinate is accepted.
    assert.doesNotThrow(() => parseJWK(`{"kty":"EC","crv":"P-256","x":"${lz.x}","y":"${lz.y}"}`));
  });
  await t.test(
    'the negotiated Ed25519 parser applies the same rule',
    { skip: 'Ed25519 is optional (draft section 7.2) and not ported' },
    () => {},
  );
});

test('algorithmOf: the algorithm of kty and crv', (t) => {
  if (!fixturesPresent(t)) return;
  assert.equal(algorithmOf(fixtureJWK('holder')), ALG_ES256);
  wantReason(() => algorithmOf({ kty: 'EC', crv: 'P-384', x: '' }), Reason.JWK_CURVE);
  wantReason(() => algorithmOf({ kty: 'RSA', crv: '', x: '' }), Reason.JWK_CURVE);
});

test('Algorithms: the baseline accepts ES256 alone', (t) => {
  if (!fixturesPresent(t)) return;
  const base = new Algorithms();
  assert.equal(base.accepts(ALG_ES256), true);
  for (const alg of ['Ed25519', 'EdDSA', 'es256', 'HS256', 'none', '']) {
    assert.equal(base.accepts(alg), false, alg);
  }
  const ed = new Algorithms(['Ed25519']);
  assert.equal(ed.accepts('Ed25519'), true);
  assert.equal(ed.accepts(ALG_ES256), false, 'a list without ES256 does not accept it');
  assert.equal(new Algorithms(['EdDSA', 'RS256']).accepts('EdDSA'), false, 'not implemented');
  // ES256 keys need ES256 in the list.
  wantReason(
    () => ed.parseJWK(`{"kty":"EC","crv":"P-256","x":"${HOLDER_X}","y":"${HOLDER_Y}"}`),
    Reason.JWK_CURVE,
  );
  assert.equal(
    thumbprint(
      new Algorithms([ALG_ES256]).parseJWK(
        `{"kty":"EC","crv":"P-256","x":"${HOLDER_X}","y":"${HOLDER_Y}"}`,
      ),
    ),
    HOLDER_JKT,
  );
  wantReason(() => ed.newKeySet(fixtureJWK('issuer')), Reason.JWK_CURVE);
  assert.ok(
    new Algorithms([ALG_ES256]).newKeySet(fixtureJWK('issuer')).lookup('test-issuer-key-1'),
  );
});

// Coordinates are the full 32 octets (RFC 7518 section 6.2.1.2) even when
// they start with a zero octet. P-256 scalar 379 is the smallest above 6
// whose x does.
test('TestPublicJWKKeepsLeadingZeros', () => {
  const key = scalarKey(379);
  const k = publicJWK(createPublicKey(key));
  const x = decode(k.x);
  assert.equal(k.x.length, 43);
  assert.equal(x.length, 32);
  assert.equal(x[0], 0);
  assert.deepEqual(k, { kty: 'EC', crv: 'P-256', x: k.x, y: k.y });
  const pub = publicKeyOf(k);
  assert.ok(pub.equals(createPublicKey(key)), 'round trip');
  // The public JWK of the private key is the same.
  assert.deepEqual(publicJWK(key), k);
});

test('TestPublicJWKRejects', () => {
  wantReason(() => publicJWK(undefined as never), Reason.JWK_INVALID);
  wantReason(() => publicJWK({} as never), Reason.JWK_INVALID);
  wantReason(() => publicJWK(createSecretKey(new Uint8Array(32))), Reason.JWK_INVALID);
  const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey;
  wantReason(() => publicJWK(p384), Reason.JWK_CURVE);
  wantReason(() => publicJWK(generateKeyPairSync('ed25519').publicKey), Reason.JWK_CURVE);
});

test('publicKeyOf checks the coordinates before the import', async (t) => {
  if (!fixturesPresent(t)) return;
  const hj = fixtureJWK('holder');
  assert.ok(
    publicKeyOf(hj).equals(
      createPublicKey({
        key: { kty: 'EC', crv: 'P-256', x: HOLDER_X, y: HOLDER_Y },
        format: 'jwk',
      }),
    ),
  );
  const cases: [string, JWK, Reason][] = [
    ['P-384', { ...hj, crv: 'P-384' }, Reason.JWK_CURVE],
    ['padded x', { ...hj, x: `${hj.x}=` }, Reason.JWK_INVALID],
    ['33-octet x', { ...hj, x: b64(new Uint8Array([0, ...decode(hj.x)])) }, Reason.JWK_INVALID],
    ['off curve', { ...hj, y: fixtureJWK('issuer').y }, Reason.JWK_OFF_CURVE],
  ];
  for (const [name, k, want] of cases) {
    await t.test(name, () => {
      const err = wantReason(() => publicKeyOf(k), want);
      if (want === Reason.JWK_OFF_CURVE)
        assert.ok(err.cause !== undefined, 'wraps the import error');
    });
  }
});

test('TestKeySet', (t) => {
  if (!fixturesPresent(t)) return;
  const iss = fixtureJWK('issuer');
  const val = fixtureJWK('validator');
  const s = new KeySet(iss, val);
  assert.equal(s.lookup('test-validator-key-1')?.x, val.x);
  assert.equal(s.lookup('test-holder-key-1'), undefined, 'a key that is not in the set');
  assert.equal(new KeySet().lookup('test-issuer-key-1'), undefined, 'empty set');
  assert.equal(s.lookup(''), undefined, 'empty kid');

  wantReason(() => new KeySet(iss, iss), Reason.KID_DUPLICATE);
  wantReason(() => new KeySet({ ...iss, kid: '' }), Reason.KID_MISSING);
  const { kid: _, ...noKid } = iss;
  wantReason(() => new KeySet(noKid), Reason.KID_MISSING);
  wantReason(() => new KeySet({ ...iss, y: val.y }), Reason.JWK_OFF_CURVE);
  wantReason(() => new KeySet({ ...iss, use: 'enc' }), Reason.JWK_USAGE);
});

// The thumbprints of the P-256 test keys, as computed independently in
// TypeScript, Python, Rust and PHP.
test('TestFixtureThumbprints', (t) => {
  if (!fixturesPresent(t)) return;
  const want: Record<string, string> = {
    holder: HOLDER_JKT,
    issuer: 'AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE',
    adversarial: 'B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU',
    'reputation-service': 'BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ',
    'learning-controller': 'yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k',
    validator: 'uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I',
  };
  for (const [name, w] of Object.entries(want)) assert.equal(thumbprint(fixtureJWK(name)), w, name);
});
