// The JWS and key groups of the harness (src/vectors/run-jws.ts,
// run-keys.ts) against fake cores. Expectations follow
// spec/v1.0/fixtures/vectors/jws/README.md, spec/v1.0/fixtures/keys/README.md and the
// key rule of docs/sdk/ports-plan.md section 5.2; the Appendix C holder_jkt
// is the thumbprint of the P-256 key of scalar 1.

import assert from 'node:assert/strict';
import { createECDH, type KeyObject } from 'node:crypto';
import { after, describe, test } from 'node:test';
import { type JWK, JWSError, Reason } from '../src/core/jws/index.ts';
import { StrictJSONError } from '../src/core/strictjson.ts';
import { NotImplementedError } from '../src/internal/notimplemented.ts';
import { type Core, defaultCore } from '../src/vectors/core.ts';
import { type Outcome, runEntry } from '../src/vectors/harness.ts';
import { bytes, cleanup, entry, fake, rfc7638, str, stubbed, tree } from './vectors/tree.ts';

after(cleanup);

const HOLDER_JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';

function passes(o: Outcome): void {
  assert.deepEqual(o, { result: 'pass' });
}

function fails(o: Outcome, detail?: RegExp): void {
  assert.equal(o.result, 'fail', JSON.stringify(o));
  if (detail && o.result === 'fail') assert.match(o.detail, detail);
}

function point(scalar: number): { x: string; y: string; d: string } {
  const d = Buffer.alloc(32);
  d.writeUInt32BE(scalar, 28);
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const p = ecdh.getPublicKey();
  return {
    x: p.subarray(1, 33).toString('base64url'),
    y: p.subarray(33).toString('base64url'),
    d: d.toString('base64url'),
  };
}

const parseJWK = (raw: Uint8Array): JWK => JSON.parse(str(raw)) as JWK;
const publicJWK = (k: KeyObject): JWK => k.export({ format: 'jwk' }) as JWK;
const keyCore = fake({ parseJWK, publicJWK, thumbprint: rfc7638 });

describe('jws verify vectors', () => {
  const vec = (over: Record<string, unknown> = {}) => ({
    id: 'vectors/jws/a',
    description: 'd',
    compact: 'h.p.s',
    expected_typ: 'pact-evidence+jwt',
    trusted_keysets: { issuer: [{ kty: 'EC', crv: 'P-256', x: 'X', y: 'Y', kid: 'k' }] },
    expected_holder_jkt: null,
    decode_as: null,
    expect: 'accept',
    reject_reason: null,
    signer_jwk: null,
    signature_valid: true,
    expected_payload: '{"a":1}',
    ...over,
  });
  const file = (v: unknown) => tree({ 'vectors/jws/a.json': v });
  const acc = entry('vectors/jws/a', 'vector', 'core', 'vectors/jws/a.json');
  const rej = { ...acc, outcome: 'REJECTED' };
  const seen: unknown[] = [];
  const verifying = (payload: string, over: Partial<Core> = {}) =>
    fake({
      parseJWK: (raw, algs) => {
        seen.push(['parseJWK', JSON.parse(str(raw)), algs]);
        return parseJWK(raw);
      },
      keyResolver: (sets, jkt, algs) => {
        seen.push(['keyResolver', [...sets.keys()], jkt, algs]);
        return 'resolver';
      },
      verify: (compact, resolver, typ, algs) => {
        seen.push(['verify', compact, resolver, typ, algs]);
        return { payload: bytes(payload) };
      },
      reasonOf: (err) => (err instanceof JWSError ? err.reason : ''),
      ...over,
    });
  const refusing = (reason: Reason) =>
    verifying('', {
      verify: () => {
        throw new JWSError(reason, 'refused');
      },
    });

  test('accept passes on the expected payload, with the keys, typ and holder thumbprint given', () => {
    seen.length = 0;
    passes(runEntry(file(vec({ expected_holder_jkt: HOLDER_JKT })), acc, verifying('{"a":1}')));
    assert.deepEqual(seen, [
      ['parseJWK', { kty: 'EC', crv: 'P-256', x: 'X', y: 'Y', kid: 'k' }, []],
      ['keyResolver', ['issuer'], HOLDER_JKT, []],
      ['verify', 'h.p.s', 'resolver', 'pact-evidence+jwt', []],
    ]);
  });
  test('accept fails on another payload or a refusal', () => {
    fails(runEntry(file(vec()), acc, verifying('{"a":2}')), /expected_payload/);
    fails(runEntry(file(vec()), acc, refusing(Reason.SIGNATURE_INVALID)), /signature-invalid/);
  });
  test('reject passes on the expected reason only', () => {
    const f = file(vec({ expect: 'reject', reject_reason: 'kid-unknown' }));
    passes(runEntry(f, rej, refusing(Reason.KID_UNKNOWN)));
    fails(runEntry(f, rej, refusing(Reason.KID_MISSING)), /kid-missing/);
    fails(runEntry(f, rej, verifying('{"a":1}')));
    fails(
      runEntry(
        f,
        rej,
        verifying('', {
          verify: () => {
            throw new Error('boom');
          },
        }),
      ),
      /without a reason/,
    );
  });
  test('a trusted key that does not parse fails the entry, whatever the expected reason', () => {
    const f = file(vec({ expect: 'reject', reject_reason: 'jwk-invalid' }));
    const core = verifying('', {
      parseJWK: () => {
        throw new JWSError(Reason.JWK_INVALID, 'bad key');
      },
    });
    fails(runEntry(f, rej, core), /trusted key/);
  });
  test('decode_as Evidence refuses a wrong pact_version or a strict decode failure as payload-schema', () => {
    const f = file(
      vec({ decode_as: 'Evidence', expect: 'reject', reject_reason: 'payload-schema' }),
    );
    passes(runEntry(f, rej, verifying('{}', { decodeEvidence: () => ({ pact_version: '0.2' }) })));
    passes(
      runEntry(
        f,
        rej,
        verifying('{}', {
          decodeEvidence: () => {
            throw new StrictJSONError('UNKNOWN_FIELD', '/x', 1, 'x');
          },
        }),
      ),
    );
    fails(runEntry(f, rej, verifying('{}', { decodeEvidence: () => ({ pact_version: '0.1' }) })));
    fails(
      runEntry(
        f,
        rej,
        verifying('{}', {
          decodeEvidence: () => {
            throw new Error('boom');
          },
        }),
      ),
      /boom/,
    );
    const ok = file(vec({ decode_as: 'Evidence', expected_payload: '{}' }));
    passes(runEntry(ok, acc, verifying('{}', { decodeEvidence: () => ({ pact_version: '0.1' }) })));
    const other = file(vec({ decode_as: 'Presentation', expected_payload: '{}' }));
    fails(
      runEntry(other, acc, verifying('{}', { decodeEvidence: () => ({ pact_version: '0.1' }) })),
      /decode_as/,
    );
  });
  test('an entry that lists jws-ed25519 runs with Ed25519 negotiated besides ES256', () => {
    seen.length = 0;
    const ed = { ...acc, capabilities: ['jws-ed25519'] };
    passes(runEntry(file(vec()), ed, verifying('{"a":1}'), ['jws-ed25519']));
    assert.deepEqual(seen.at(-1), [
      'verify',
      'h.p.s',
      'resolver',
      'pact-evidence+jwt',
      ['ES256', 'Ed25519'],
    ]);
  });
  test('expect, reject_reason and outcome must agree; members are exact', () => {
    fails(runEntry(file(vec()), rej, verifying('{"a":1}')));
    fails(runEntry(file(vec({ reject_reason: 'kid-unknown' })), acc, verifying('{"a":1}')));
    const { signer_jwk: _, ...short } = vec();
    fails(runEntry(file(short), acc, verifying('{"a":1}')), /members/);
    fails(runEntry(file(vec({ id: 'vectors/jws/b' })), acc, verifying('{"a":1}')));
  });
  test('the stubs fail', () => {
    fails(runEntry(file(vec()), acc, stubbed), /not implemented/);
    fails(
      runEntry(file(vec({ expect: 'reject', reject_reason: 'kid-unknown' })), rej, stubbed),
      /not implemented/,
    );
  });
});

test('a stub is never the refusal a vector expects, whatever reasonOf says', () => {
  const anyReason = (reason: string) =>
    fake({
      parseJWK: (raw) => parseJWK(raw),
      keyResolver: () => 'resolver',
      verify: () => {
        throw new NotImplementedError('jws.Verifier.verify');
      },
      thumbprint: () => {
        throw new NotImplementedError('jws.thumbprint');
      },
      reasonOf: () => reason,
    });
  const verifyVector = {
    id: 'vectors/jws/a',
    description: 'd',
    compact: 'h.p.s',
    expected_typ: null,
    trusted_keysets: {},
    expected_holder_jkt: null,
    decode_as: null,
    expect: 'reject',
    reject_reason: 'kid-unknown',
    signer_jwk: null,
    signature_valid: null,
    expected_payload: null,
  };
  const e = entry('vectors/jws/a', 'vector', 'core', 'vectors/jws/a.json', { outcome: 'REJECTED' });
  fails(
    runEntry(tree({ 'vectors/jws/a.json': verifyVector }), e, anyReason('kid-unknown')),
    /not implemented/,
  );
  const rejects = [{ id: 'a', description: 'd', jwk: {}, reject_reason: 'jwk-invalid' }];
  const r = entry('vectors/jws/jwk-reject', 'vector', 'core', 'vectors/jws/jwk-reject.json', {
    outcome: 'REJECTED',
  });
  fails(
    runEntry(tree({ 'vectors/jws/jwk-reject.json': rejects }), r, anyReason('jwk-invalid')),
    /not implemented/,
  );
});

describe('jws array files', () => {
  const holder = point(1);
  const jwk = { kty: 'EC', crv: 'P-256', x: holder.x, y: holder.y };

  test('thumbprint: each JWK gets its expected thumbprint', () => {
    const e = entry('vectors/jws/thumbprint', 'vector', 'core', 'vectors/jws/thumbprint.json');
    const row = { id: 'h', description: 'd', jwk, expected_thumbprint: HOLDER_JKT, source: 's' };
    passes(runEntry(tree({ 'vectors/jws/thumbprint.json': [row] }), e, keyCore));
    const bad = { ...row, expected_thumbprint: 'other' };
    fails(runEntry(tree({ 'vectors/jws/thumbprint.json': [bad] }), e, keyCore), /h: thumbprint/);
    fails(runEntry(tree({ 'vectors/jws/thumbprint.json': [row] }), e, stubbed), /not implemented/);
  });
  test('jwk-reject: each JWK is refused with its reason, at parse or thumbprint', () => {
    const e = entry('vectors/jws/jwk-reject', 'vector', 'core', 'vectors/jws/jwk-reject.json', {
      outcome: 'REJECTED',
    });
    const rows = [
      { id: 'a', description: 'd', jwk: { kty: 'RSA' }, reject_reason: 'jwk-curve' },
      { id: 'b', description: 'd', jwk, reject_reason: 'jwk-invalid' },
    ];
    const core = fake({
      parseJWK: (raw) => {
        const k = parseJWK(raw);
        if (k.kty !== 'EC') throw new JWSError(Reason.JWK_CURVE, 'kty');
        return k;
      },
      thumbprint: () => {
        throw new JWSError(Reason.JWK_INVALID, 'x');
      },
      reasonOf: (err) => (err instanceof JWSError ? err.reason : ''),
    });
    passes(runEntry(tree({ 'vectors/jws/jwk-reject.json': rows }), e, core));
    fails(
      runEntry(
        tree({ 'vectors/jws/jwk-reject.json': [{ ...rows[0], reject_reason: 'jwk-usage' }] }),
        e,
        core,
      ),
      /a: reason/,
    );
    fails(runEntry(tree({ 'vectors/jws/jwk-reject.json': rows }), e, stubbed), /not implemented/);
  });
  test('appendix-c-keys: d derives the expected point and thumbprint', () => {
    const e = entry(
      'vectors/jws/appendix-c-keys',
      'vector',
      'core',
      'vectors/jws/appendix-c-keys.json',
    );
    const row = {
      id: 'holder',
      description: 'd',
      d: holder.d,
      expected_x: holder.x,
      expected_y: holder.y,
      expected_thumbprint: HOLDER_JKT,
    };
    passes(runEntry(tree({ 'vectors/jws/appendix-c-keys.json': [row] }), e, keyCore));
    const two = point(2);
    fails(
      runEntry(
        tree({ 'vectors/jws/appendix-c-keys.json': [{ ...row, expected_x: two.x }] }),
        e,
        keyCore,
      ),
      /derived/,
    );
    fails(
      runEntry(tree({ 'vectors/jws/appendix-c-keys.json': [{ ...row, d: 'AA' }] }), e, keyCore),
      /32 octets/,
    );
    fails(
      runEntry(tree({ 'vectors/jws/appendix-c-keys.json': [row] }), e, stubbed),
      /not implemented/,
    );
  });
});

describe('key rule', () => {
  const rec = (role: string, scalar: number, file: string) => ({
    role,
    kid: `test-${role}-key-1`,
    alg: 'ES256',
    kty: 'EC',
    crv: 'P-256',
    scalar: String(scalar),
    d: point(scalar).d,
    public_jwk: file,
  });
  const pub = (scalar: number) => ({ kty: 'EC', crv: 'P-256', ...point(scalar), d: undefined });
  const scalars = (keys: unknown[]) => ({ label: 'l', warning: 'w', encoding: 'e', keys });
  const ed = {
    role: 'executor',
    kid: 'test-ed',
    alg: 'Ed25519',
    kty: 'OKP',
    crv: 'Ed25519',
    seed_hex: '00',
    d: 'AA',
    public_jwk: 'ed25519.jwk.json',
  };
  const fixtures = (over: Record<string, unknown> = {}) =>
    tree({
      'keys/test-private-scalars.json': scalars([
        rec('holder', 1, 'holder.jwk.json'),
        rec('issuer', 2, 'issuer.jwk.json'),
        ed,
      ]),
      'keys/holder.jwk.json': pub(1),
      'keys/issuer.jwk.json': pub(2),
      'keys/ed25519.jwk.json': { kty: 'OKP', crv: 'Ed25519', x: 'AA' },
      ...over,
    });
  const key = (name: string) =>
    entry(`keys/${name}`, 'key', 'core', `keys/${name}.jwk.json`, {
      expected: null,
      outcome: null,
    });
  const all = entry('keys/test-private-scalars', 'key', 'core', 'keys/test-private-scalars.json', {
    expected: null,
    outcome: null,
  });

  test('a P-256 key passes when its point is scalar times G; the holder also needs the Appendix C thumbprint', () => {
    passes(runEntry(fixtures(), key('issuer'), keyCore));
    passes(runEntry(fixtures(), key('holder'), keyCore));
    passes(runEntry(fixtures(), all, keyCore));
  });
  test('a point that is not scalar times G fails', () => {
    fails(
      runEntry(fixtures({ 'keys/issuer.jwk.json': pub(3) }), key('issuer'), keyCore),
      /scalar 2 times G/,
    );
    fails(runEntry(fixtures({ 'keys/issuer.jwk.json': pub(3) }), all, keyCore), /issuer/);
  });
  test('d must be the scalar as 32 big-endian octets', () => {
    const bad = { ...rec('issuer', 2, 'issuer.jwk.json'), d: point(3).d };
    const f = fixtures({
      'keys/test-private-scalars.json': scalars([rec('holder', 1, 'holder.jwk.json'), bad]),
    });
    fails(runEntry(f, key('issuer'), keyCore), /scalar 2/);
  });
  test('a holder key with another thumbprint fails', () => {
    const f = fixtures({
      'keys/test-private-scalars.json': scalars([rec('holder', 2, 'issuer.jwk.json')]),
    });
    fails(runEntry(f, key('issuer'), keyCore), /holder_jkt/);
  });
  test('the scalars entry needs a P-256 holder record', () => {
    const f = fixtures({
      'keys/test-private-scalars.json': scalars([rec('issuer', 2, 'issuer.jwk.json')]),
    });
    fails(runEntry(f, all, keyCore), /holder/);
  });
  test('a key no record names fails; the Ed25519 key is skipped:out-of-scope without a call', () => {
    fails(
      runEntry(fixtures({ 'keys/other.jwk.json': pub(5) }), key('other'), keyCore),
      /no record/,
    );
    const o = runEntry(fixtures(), key('ed25519'), defaultCore);
    assert.equal(o.result, 'skipped');
    if (o.result === 'skipped') assert.equal(o.reason, 'out-of-scope');
  });
  test('the stubs fail', () => {
    fails(runEntry(fixtures(), key('issuer'), stubbed), /not implemented/);
    fails(runEntry(fixtures(), all, stubbed), /not implemented/);
  });
});
