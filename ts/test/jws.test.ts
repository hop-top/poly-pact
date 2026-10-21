// Port of go/core/jws/jws_test.go. Expected reasons follow draft sections
// 7.1 and 7.2, RFC 7515 and RFC 7518 section 3.4, as in the Go tests; every
// input that should fail on its header carries a valid ES256 signature, so
// the refusal comes from the header alone.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ALG_ES256,
  DEFAULT_MAX_COMPACT_BYTES,
  type JWK,
  type KeyRequest,
  type KeyResolver,
  KeySet,
  Reason,
  Role,
  reasonOf,
  StaticResolver,
  sign,
  TYP_ADMISSION,
  TYP_EVIDENCE,
  TYP_PRESENTATION,
  Verifier,
  verify,
} from '../src/core/jws/index.ts';
import { StrictJSONError } from '../src/core/strictjson.ts';
import { bytes, fixturesPresent, str } from './support/fixtures.ts';
import {
  b64,
  EVIDENCE_HEADER,
  errorOf,
  fixtureJWK,
  HOLDER_JKT,
  int,
  issuerResolver,
  N,
  octets32,
  rawCompact,
  rawSig,
  SMALL_PAYLOAD,
  scalarKey,
  wantReason,
} from './support/jws.ts';

function jwkJSON(k: JWK): string {
  return `{"kty":"${k.kty}","crv":"${k.crv}","x":"${k.x}","y":"${k.y}"}`;
}

const stdAlphabet = (s: string) => s.replaceAll('-', '+').replaceAll('_', '/');

test('TestVerifyRejectsHeaders', async (t) => {
  if (!fixturesPresent(t)) return;
  const issuer = scalarKey(2);
  const holder = scalarKey(1);
  const cases = (): [string, string, typeof issuer, Reason][] => {
    const hj = fixtureJWK('holder');
    const hjwk = jwkJSON(hj);
    const iy = fixtureJWK('issuer').y;
    return [
      [
        'alg none',
        '{"alg":"none","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg HS256',
        '{"alg":"HS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg HS512',
        '{"alg":"HS512","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg RS256',
        '{"alg":"RS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg PS256',
        '{"alg":"PS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg EdDSA',
        '{"alg":"EdDSA","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg Ed25519 not in phase 1',
        '{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg es256 lowercase',
        '{"alg":"es256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg missing',
        '{"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'alg not a string',
        '{"alg":["ES256"],"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.ALG_UNSUPPORTED,
      ],
      [
        'jku',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","jku":"https://trust.example/jwks"}',
        issuer,
        Reason.HEADER_JKU,
      ],
      [
        'x5u',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x5u":"https://trust.example/c.pem"}',
        issuer,
        Reason.HEADER_X5U,
      ],
      [
        'x5c',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x5c":["MIIB"]}',
        issuer,
        Reason.HEADER_X5C,
      ],
      [
        'crit',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","crit":["ext"],"ext":1}',
        issuer,
        Reason.HEADER_CRIT,
      ],
      [
        'crit empty',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","crit":[]}',
        issuer,
        Reason.HEADER_CRIT,
      ],
      [
        'b64 false',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","b64":false}',
        issuer,
        Reason.HEADER_B64,
      ],
      [
        'b64 false with crit',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","b64":false,"crit":["b64"]}',
        issuer,
        Reason.HEADER_CRIT,
      ],
      ['typ missing', '{"alg":"ES256","kid":"test-issuer-key-1"}', issuer, Reason.TYP_UNSUPPORTED],
      [
        'typ JWT',
        '{"alg":"ES256","typ":"JWT","kid":"test-issuer-key-1"}',
        issuer,
        Reason.TYP_UNSUPPORTED,
      ],
      [
        'typ unlisted',
        '{"alg":"ES256","typ":"pact-profile+jwt","kid":"test-issuer-key-1"}',
        issuer,
        Reason.TYP_UNSUPPORTED,
      ],
      [
        'typ not a string',
        '{"alg":"ES256","typ":7,"kid":"test-issuer-key-1"}',
        issuer,
        Reason.TYP_UNSUPPORTED,
      ],
      ['kid missing', '{"alg":"ES256","typ":"pact-evidence+jwt"}', issuer, Reason.KID_MISSING],
      [
        'kid empty',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":""}',
        issuer,
        Reason.KID_MISSING,
      ],
      [
        'kid not a string',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":1}',
        issuer,
        Reason.HEADER_JSON,
      ],
      [
        'kid unknown',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-2"}',
        issuer,
        Reason.KID_UNKNOWN,
      ],
      [
        'jwk on a service-signed typ',
        `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","jwk":${hjwk}}`,
        issuer,
        Reason.JWK_UNEXPECTED,
      ],
      [
        'duplicate member',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}',
        issuer,
        Reason.HEADER_JSON,
      ],
      ['not an object', '["ES256"]', issuer, Reason.HEADER_JSON],
      ['not JSON', 'alg=ES256', issuer, Reason.HEADER_JSON],
      [
        'lone surrogate',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x":"\\ud800"}',
        issuer,
        Reason.HEADER_JSON,
      ],
      [
        'holder jwk missing',
        '{"alg":"ES256","typ":"pact-presentation+jwt","kid":"test-holder-key-1"}',
        holder,
        Reason.JWK_MISSING,
      ],
      [
        'holder jwk not an object',
        '{"alg":"ES256","typ":"pact-presentation+jwt","jwk":"x"}',
        holder,
        Reason.JWK_INVALID,
      ],
      [
        'holder jwk with d',
        `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"${hj.x}","y":"${hj.y}","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}}`,
        holder,
        Reason.JWK_PRIVATE,
      ],
      [
        'holder jwk P-384',
        `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-384","x":"${hj.x}","y":"${hj.y}"}}`,
        holder,
        Reason.JWK_CURVE,
      ],
      [
        'holder jwk RSA',
        '{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}',
        holder,
        Reason.JWK_CURVE,
      ],
      [
        'holder jwk off curve',
        `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"${hj.x}","y":"${iy}"}}`,
        holder,
        Reason.JWK_OFF_CURVE,
      ],
      [
        'holder jwk short x',
        `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"${hj.x.slice(0, 42)}","y":"${hj.y}"}}`,
        holder,
        Reason.JWK_INVALID,
      ],
      [
        'holder jwk null',
        '{"alg":"ES256","typ":"pact-presentation+jwt","jwk":null}',
        holder,
        Reason.JWK_INVALID,
      ],
      [
        'holder jwk of another key',
        `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":${jwkJSON(fixtureJWK('adversarial'))}}`,
        scalarKey(3),
        Reason.HOLDER_JKT_MISMATCH,
      ],
      [
        'kid null',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":null}',
        issuer,
        Reason.HEADER_JSON,
      ],
      [
        'crit null',
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","crit":null}',
        issuer,
        Reason.HEADER_CRIT,
      ],
      ['header null', 'null', issuer, Reason.HEADER_JSON],
    ];
  };
  const res = issuerResolver();
  for (const [name, header, key, want] of cases()) {
    await t.test(name, () => {
      wantReason(() => verify(rawCompact(header, SMALL_PAYLOAD, key), res), want);
    });
  }
});

test('TestVerifyRejectsCompactForm', async (t) => {
  if (!fixturesPresent(t)) return;
  const issuer = scalarKey(2);
  const good = rawCompact(EVIDENCE_HEADER, SMALL_PAYLOAD, issuer);
  const [h, p, s] = good.split('.') as [string, string, string];
  const si = `${h}.${p}`;
  const cases: [string, string, Reason][] = [
    ['two segments', si, Reason.COMPACT_FORM],
    ['four segments', `${good}.AAAA`, Reason.COMPACT_FORM],
    ['five segments (JWE shape)', `${h}..${p}..${s}`, Reason.COMPACT_FORM],
    ['empty header', `.${p}.${s}`, Reason.COMPACT_FORM],
    ['empty string', '', Reason.COMPACT_FORM],
    ['detached payload', `${h}..${s}`, Reason.PAYLOAD_DETACHED],
    ['empty signature', `${si}.`, Reason.SIGNATURE_LENGTH],
    ['padded header', `${h}=.${p}.${s}`, Reason.BASE64_URL],
    ['padded signature', `${good}==`, Reason.BASE64_URL],
    ['line feed in payload', `${h}.${p.slice(0, 5)}\n${p.slice(5)}.${s}`, Reason.BASE64_URL],
    ['carriage return in header', `${h.slice(0, 5)}\r${h.slice(5)}.${p}.${s}`, Reason.BASE64_URL],
    ['space in signature', `${si}.${s.slice(0, 5)} ${s.slice(5)}`, Reason.BASE64_URL],
    ['standard alphabet', `${si}.${stdAlphabet(s)}+`, Reason.BASE64_URL],
    ['unencoded payload', `${h}.{"jti":"unit"}.${s}`, Reason.BASE64_URL],
    ['unencoded payload with a period', `${h}.${SMALL_PAYLOAD}.${s}`, Reason.COMPACT_FORM],
    ['length 1 mod 4', `${si}.${s}AAA`, Reason.BASE64_URL],
    ['non-ASCII in signature', `${si}.${s.slice(0, 5)}é${s.slice(5)}`, Reason.BASE64_URL],
    ['payload not JSON', `${h}.${b64('hello')}.${s}`, Reason.PAYLOAD_JSON],
    ['payload array', `${h}.${b64('[1]')}.${s}`, Reason.PAYLOAD_JSON],
    ['payload null', `${h}.${b64('null')}.${s}`, Reason.PAYLOAD_JSON],
    ['payload duplicate member', `${h}.${b64('{"a":1,"a":1}')}.${s}`, Reason.PAYLOAD_JSON],
    [
      'payload invalid UTF-8',
      `${h}.${b64(new Uint8Array([...bytes('{"a":"'), 0xff, ...bytes('"}')]))}.${s}`,
      Reason.PAYLOAD_JSON,
    ],
    [
      'payload too deep',
      `${h}.${b64(`${'{"a":'.repeat(17)}1${'}'.repeat(17)}`)}.${s}`,
      Reason.PAYLOAD_JSON,
    ],
  ];
  const res = issuerResolver();
  for (const [name, compact, want] of cases) {
    await t.test(name, () => {
      wantReason(() => verify(compact, res), want);
    });
  }
});

// The ES256 signature rules of RFC 7518 section 3.4: exactly 64 octets, R
// and S in [1, n-1], over the received signing input.
test('TestVerifyRejectsSignatures', async (t) => {
  if (!fixturesPresent(t)) return;
  const issuer = scalarKey(2);
  const si = `${b64(EVIDENCE_HEADER)}.${b64(SMALL_PAYLOAD)}`;
  const sig = rawSig(si, issuer);
  const r = int(sig.subarray(0, 32));
  const s = int(sig.subarray(32));
  const enc = (r: bigint, s: bigint) =>
    `${si}.${b64(new Uint8Array([...octets32(r), ...octets32(s)]))}`;
  const flipped = sig.slice();
  flipped[10] = (flipped[10] ?? 0) ^ 0x80;
  const max = (1n << 256n) - 1n;
  const cases: [string, string, Reason][] = [
    ['63 octets', `${si}.${b64(sig.subarray(0, 63))}`, Reason.SIGNATURE_LENGTH],
    ['65 octets', `${si}.${b64(new Uint8Array([...sig, 0]))}`, Reason.SIGNATURE_LENGTH],
    ['96 octets', `${si}.${b64(new Uint8Array(96))}`, Reason.SIGNATURE_LENGTH],
    ['r zero', enc(0n, s), Reason.SIGNATURE_INVALID],
    ['s zero', enc(r, 0n), Reason.SIGNATURE_INVALID],
    ['all zero', enc(0n, 0n), Reason.SIGNATURE_INVALID],
    ['r = n', enc(N, s), Reason.SIGNATURE_INVALID],
    ['s = n', enc(r, N), Reason.SIGNATURE_INVALID],
    ['r = 2^256-1', enc(max, s), Reason.SIGNATURE_INVALID],
    ['s = 2^256-1', enc(r, max), Reason.SIGNATURE_INVALID],
    ['bit flipped', `${si}.${b64(flipped)}`, Reason.SIGNATURE_INVALID],
    [
      'other payload',
      `${b64(EVIDENCE_HEADER)}.${b64('{"pact_version":"0.1","jti":"other"}')}.${b64(sig)}`,
      Reason.SIGNATURE_INVALID,
    ],
    ['other key', `${si}.${b64(rawSig(si, scalarKey(3)))}`, Reason.SIGNATURE_INVALID],
  ];
  const res = issuerResolver();
  for (const [name, compact, want] of cases) {
    await t.test(name, () => {
      wantReason(() => verify(compact, res), want);
    });
  }
  // As in Go, an open question for the draft: the high-S twin of a valid
  // signature verifies; no low-S rule applies.
  await t.test('high S accepted', () => {
    const p = verify(enc(r, N - s), res);
    assert.equal(int(p.signature.subarray(32)), N - s);
  });
});

// The signature covers the received bytes, so a header and payload with
// white space, member order and escapes a serializer would change still
// verify, and come back unchanged.
test('TestVerifyUsesReceivedSigningInput', (t) => {
  if (!fixturesPresent(t)) return;
  const header =
    '{ "kid" : "test\\u002dissuer-key-1",\n"typ":"pact-evidence+jwt" , "alg":"ES256" }';
  const payload = '{\n  "z": 1.50,\n  "a": "caf\\u00e9 \\/ café",\n  "pact_version": "0.1"\n}';
  const compact = rawCompact(header, payload, scalarKey(2));
  const p = verify(compact, issuerResolver());
  assert.equal(str(p.payload), payload);
  assert.equal(str(p.rawHeader), header);
  assert.equal(p.signingInput, compact.slice(0, compact.lastIndexOf('.')));
  assert.equal(p.compact, compact);
  assert.equal(p.header.kid, 'test-issuer-key-1');
  assert.equal(p.header.typ, TYP_EVIDENCE);
  assert.equal(p.header.alg, ALG_ES256);
  assert.equal(p.header.jwk, undefined);
  assert.equal(p.role, Role.ISSUER);
  assert.equal(p.signature.length, 64);
});

test('TestVerifierExpectedTyp', (t) => {
  if (!fixturesPresent(t)) return;
  const compact = rawCompact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalarKey(2));
  wantReason(
    () => new Verifier({ keys: issuerResolver(), typ: TYP_ADMISSION }).verify(compact),
    Reason.TYP_MISMATCH,
  );
  assert.doesNotThrow(() =>
    new Verifier({ keys: issuerResolver(), typ: TYP_EVIDENCE }).verify(compact),
  );
});

test('TestVerifierCompactSize', (t) => {
  if (!fixturesPresent(t)) return;
  const res = issuerResolver();
  const big = 'A'.repeat(DEFAULT_MAX_COMPACT_BYTES - 1);
  wantReason(() => verify(`${big}.A.A`, res), Reason.COMPACT_SIZE);
  // The bound is in UTF-8 bytes, as in Go: 2 bytes per é.
  wantReason(
    () => verify(`${'é'.repeat(DEFAULT_MAX_COMPACT_BYTES / 2)}.A.A`, res),
    Reason.COMPACT_SIZE,
  );

  const compact = rawCompact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalarKey(2));
  wantReason(
    () => new Verifier({ keys: res, maxCompactBytes: compact.length - 1 }).verify(compact),
    Reason.COMPACT_SIZE,
  );
  assert.doesNotThrow(() =>
    new Verifier({ keys: res, maxCompactBytes: compact.length }).verify(compact),
  );
});

test('TestVerifierJSONLimits', (t) => {
  if (!fixturesPresent(t)) return;
  const payload = `{"pact_version":"0.1","pad":"${'x'.repeat(100)}"}`;
  const compact = rawCompact(EVIDENCE_HEADER, payload, scalarKey(2));
  const err = wantReason(
    () => new Verifier({ keys: issuerResolver(), limits: { maxBytes: 100 } }).verify(compact),
    Reason.PAYLOAD_JSON,
  );
  assert.ok(err.cause instanceof StrictJSONError, 'wraps a strictjson error');
  assert.equal(err.cause.kind, 'SIZE');
});

class RecordingResolver implements KeyResolver {
  readonly reqs: KeyRequest[] = [];
  readonly keys: KeySet | undefined;
  readonly jkt: string;
  readonly keysErr: Error | undefined;
  readonly holderErr: Error | undefined;

  constructor(keys?: KeySet, jkt = '', keysErr?: Error, holderErr?: Error) {
    this.keys = keys;
    this.jkt = jkt;
    this.keysErr = keysErr;
    this.holderErr = holderErr;
  }

  trustedKeys(req: KeyRequest): KeySet | undefined {
    this.reqs.push(req);
    if (this.keysErr) throw this.keysErr;
    return this.keys;
  }

  holderJKT(req: KeyRequest): string {
    this.reqs.push(req);
    if (this.holderErr) throw this.holderErr;
    return this.jkt;
  }
}

test('TestKeyRequest', (t) => {
  if (!fixturesPresent(t)) return;
  const compact = rawCompact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalarKey(2));
  let rr = new RecordingResolver(new KeySet(fixtureJWK('issuer')));
  verify(compact, rr);
  assert.equal(rr.reqs.length, 1);
  const req = rr.reqs[0];
  assert.ok(req);
  assert.equal(req.typ, TYP_EVIDENCE);
  assert.equal(req.role, Role.ISSUER);
  assert.equal(req.kid, 'test-issuer-key-1');
  assert.equal(str(req.header), EVIDENCE_HEADER);
  assert.equal(str(req.payload), SMALL_PAYLOAD);

  const holderCompact = sign({ typ: TYP_PRESENTATION }, bytes(SMALL_PAYLOAD), scalarKey(1));
  rr = new RecordingResolver(undefined, HOLDER_JKT);
  verify(holderCompact, rr);
  assert.equal(rr.reqs.length, 1);
  assert.equal(rr.reqs[0]?.role, Role.HOLDER);
  assert.equal(rr.reqs[0]?.typ, TYP_PRESENTATION);
});

test('TestResolverFailures', async (t) => {
  const compact = rawCompact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalarKey(2));
  const holderCompact = sign({ typ: TYP_PRESENTATION }, bytes(SMALL_PAYLOAD), scalarKey(1));
  const cause = new Error('deadline exceeded');
  const cases: [string, string, KeyResolver | null, Reason, Error | undefined][] = [
    ['nil resolver', compact, null, Reason.KEY_UNAVAILABLE, undefined],
    [
      'key set error',
      compact,
      new RecordingResolver(undefined, '', cause),
      Reason.KEY_UNAVAILABLE,
      cause,
    ],
    ['nil key set', compact, new RecordingResolver(), Reason.KID_UNKNOWN, undefined],
    [
      'holder jkt error',
      holderCompact,
      new RecordingResolver(undefined, '', undefined, cause),
      Reason.KEY_UNAVAILABLE,
      cause,
    ],
    ['holder jkt empty', holderCompact, new RecordingResolver(), Reason.KEY_UNAVAILABLE, undefined],
    [
      'static resolver without the role',
      compact,
      new StaticResolver(),
      Reason.KID_UNKNOWN,
      undefined,
    ],
    [
      'static resolver without holder_jkt',
      holderCompact,
      new StaticResolver(),
      Reason.KEY_UNAVAILABLE,
      undefined,
    ],
  ];
  for (const [name, c, res, want, wantCause] of cases) {
    await t.test(name, () => {
      const err = wantReason(() => verify(c, res), want);
      if (wantCause !== undefined) assert.equal(err.cause, wantCause, 'wraps the cause');
    });
  }
});

// Behaviour the draft leaves to RFC 7515: header members it does not define
// are ignored (RFC 7515 section 4), a kid next to the jwk of a holder-signed
// artifact plays no part in key selection, and typ is compared exactly.
test('TestHeaderDecisions', (t) => {
  if (!fixturesPresent(t)) return;
  const issuer = scalarKey(2);
  const res = issuerResolver();
  const ignored =
    '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","cty":"json","x5t#S256":"abc","pact-note":{"a":1}}';
  assert.doesNotThrow(() => verify(rawCompact(ignored, SMALL_PAYLOAD, issuer), res));
  const withKid = `{"alg":"ES256","typ":"pact-presentation+jwt","kid":"no-such-key","jwk":${jwkJSON(fixtureJWK('holder'))}}`;
  const p = verify(rawCompact(withKid, SMALL_PAYLOAD, scalarKey(1)), res);
  assert.equal(p.role, Role.HOLDER);
  assert.equal(p.header.kid, 'no-such-key');
  assert.equal(p.header.jwk?.x, fixtureJWK('holder').x);
  assert.equal(p.keyThumbprint, HOLDER_JKT);
  for (const typ of ['PACT-EVIDENCE+JWT', 'application/pact-evidence+jwt', ' pact-evidence+jwt']) {
    const h = `{"alg":"ES256","typ":"${typ}","kid":"test-issuer-key-1"}`;
    wantReason(() => verify(rawCompact(h, SMALL_PAYLOAD, issuer), res), Reason.TYP_UNSUPPORTED);
  }
});

test('TestReasonOf', (t) => {
  if (!fixturesPresent(t)) return;
  assert.equal(reasonOf(null), '');
  assert.equal(reasonOf(undefined), '');
  assert.equal(reasonOf(new Error('x')), '');
  const dup = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}';
  const err = wantReason(
    () => verify(rawCompact(dup, SMALL_PAYLOAD, scalarKey(2)), issuerResolver()),
    Reason.HEADER_JSON,
  );
  assert.ok(err.cause instanceof StrictJSONError);
  assert.equal(err.cause.kind, 'DUPLICATE_KEY');
  assert.ok(err.message.startsWith('jws: header-json'), err.message);
  // The reason of a JWSError further down the cause chain.
  assert.equal(reasonOf(new Error('wrapped', { cause: err })), Reason.HEADER_JSON);
  assert.equal(reasonOf(errorOf(() => verify('', null))), Reason.COMPACT_FORM);
});
