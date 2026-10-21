// Port of go/core/jws/draft_test.go: the draft 7.3 typ table, the draft 20.1
// compact bound, and the keys and JWS of draft Appendix C, read from
// spec/v1.0/draft.md at test time.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_MAX_COMPACT_BYTES,
  KeySet,
  parseJWK,
  publicJWK,
  Reason,
  Role,
  StaticResolver,
  TYP_EVIDENCE,
  thumbprint,
  typRole,
  typs,
  Verifier,
  verify,
} from '../src/core/jws/index.ts';
import { artifactJSON, defaultLimits, VERSION } from '../src/core/limits.ts';
import { shapes } from '../src/core/shapes.ts';
import { decode, parse } from '../src/core/strictjson.ts';
import type { Evidence } from '../src/core/types.ts';
import { appendixB5, appendixC, appendixCCompact, fenced, section } from './support/draft.ts';
import { fixturesPresent, readFixture, str } from './support/fixtures.ts';
import {
  fixtureJWK,
  HOLDER_JKT,
  issuerResolver,
  scalarKey,
  wantReason,
  withKid,
} from './support/jws.ts';
import { DRAFT, specText } from './support/repo.ts';

// The "Required signer" cells of the draft 7.3 table, mapped to roles. A
// changed cell fails TestTypTableMatchesDraft until it is mapped.
const SIGNER_ROLES: Readonly<Record<string, Role>> = {
  'Gateway-authorized requirement publisher': Role.REQUIREMENT_PUBLISHER,
  'Issuer authorized for its claim paths and scope': Role.ISSUER,
  'Enrolled agent holder key': Role.HOLDER,
  'Gateway-authorized validator': Role.VALIDATOR,
  'Authorized reporter for the observation type': Role.REPORTER,
  'Authorized reputation service': Role.REPUTATION_SERVICE,
  'Native administrator or delegated policy authority': Role.POLICY_AUTHORITY,
  'Authorized learning controller': Role.LEARNING_CONTROLLER,
  'Controller authorized for that transition': Role.LEARNING_CONTROLLER,
};

test('TestTypTableMatchesDraft', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const table = section(draft, '### 7.3 Artifact types and claims', '### 7.4');
  const rows = [...table.matchAll(/^\| ([^|]+?) \| `([^`]+)` \| ([^|]+?) \|$/gm)];
  assert.ok(rows.length > 0, 'no typ rows found in draft 7.3');
  const want: string[] = [];
  for (const [, , typ, signer] of rows) {
    assert.ok(typ !== undefined && signer !== undefined);
    want.push(typ);
    const role = SIGNER_ROLES[signer];
    assert.ok(
      role !== undefined,
      `draft 7.3 signer ${JSON.stringify(signer)} (typ ${typ}) has no role mapping`,
    );
    assert.equal(typRole(typ), role, `typRole(${typ}); draft 7.3 requires ${signer}`);
  }
  assert.deepEqual(typs(), want, 'typs() in the draft 7.3 order');
  for (const typ of ['', 'JWT', 'pact-profile+jwt', 'pact-evidence+JWT', 'toString', '__proto__']) {
    assert.equal(typRole(typ), undefined, JSON.stringify(typ));
  }
  // typs() returns a copy.
  typs().pop();
  assert.equal(typs().length, want.length);
});

test('TestDefaultMaxCompactBytesMatchesDraft', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  // Section 20.1: the frame minimum covers an encoded 256 KiB payload plus
  // the JOSE header and signature.
  assert.ok(draft.includes('349526 + 10922 = 360448'));
  assert.equal(DEFAULT_MAX_COMPACT_BYTES, 360448);
});

// Derives the public keys of P-256 scalars 1 (holder) and 2 (issuer) and
// compares them with the JWKs printed in Appendix C, and the holder
// thumbprint with the printed holder_jkt.
test('TestAppendixCKeys', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const c = appendixC(draft);
  const issuerPrinted = fenced(c, 'Issuer public JWK', 'json');
  const hp = parse(fenced(c, 'Holder public JWK and thumbprint', 'json')) as {
    jwk: Record<string, string>;
    holder_jkt: string;
  };
  const ip = parseJWK(issuerPrinted);
  for (const [scalar, x, y] of [
    [1, hp.jwk.x, hp.jwk.y],
    [2, ip.x, ip.y],
  ] as const) {
    const k = publicJWK(scalarKey(scalar));
    assert.equal(k.x, x, `scalar ${scalar} x`);
    assert.equal(k.y, y, `scalar ${scalar} y`);
    if (scalar === 1) {
      assert.equal(thumbprint(k), hp.holder_jkt);
      assert.equal(hp.holder_jkt, HOLDER_JKT);
    }
  }
  assert.equal(ip.kid, 'test-issuer-key-1');
});

// Verifies the exact compact evidence JWS of Appendix C under the printed
// issuer JWK and checks every expectation the appendix states.
test('TestAppendixCJWS', (t) => {
  if (!fixturesPresent(t)) return;
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const c = appendixC(draft);
  const issuer = parseJWK(fenced(c, 'Issuer public JWK', 'json'));
  const res = new StaticResolver(new Map([[Role.ISSUER, new KeySet(issuer)]]));
  const p = new Verifier({ keys: res, typ: TYP_EVIDENCE }).verify(appendixCCompact(draft));
  assert.equal(p.header.typ, 'pact-evidence+jwt');
  assert.equal(p.role, Role.ISSUER);
  assert.equal(str(p.payload), appendixB5(draft), 'payload is byte for byte the B.5 block');
  const ev = decode<Evidence>(p.payload, shapes.Evidence, artifactJSON(defaultLimits()));
  assert.equal(ev.pact_version, VERSION);
  assert.equal(ev.sub, 'https://identity.example/agents/invoice-assistant');
  assert.equal(ev.claims.length, 1);
  assert.equal(ev.claims[0]?.path, '/attributes/runtime/isolation');
  assert.equal(ev.claims[0]?.value.text, '"managed"');
  assert.equal(ev.holder_jkt, HOLDER_JKT);
  // Not under the holder key.
  const wrong = new StaticResolver(
    new Map([[Role.ISSUER, new KeySet(withKid(fixtureJWK('holder'), 'test-issuer-key-1'))]]),
  );
  wantReason(() => verify(appendixCCompact(draft), wrong), Reason.SIGNATURE_INVALID);
});

// The earlier Appendix C JWS has a valid signature but carries pact_version
// 0.2, which the schema constant (0.1) rejects.
test('TestAppendixCVersionMismatch', (t) => {
  if (!fixturesPresent(t)) return;
  const compact = str(readFixture('parse/appendix-c-wrong-version.jws')).trim();
  const p = new Verifier({ keys: issuerResolver(), typ: TYP_EVIDENCE }).verify(compact);
  const ev = decode<Evidence>(p.payload, shapes.Evidence, artifactJSON(defaultLimits()));
  assert.equal(ev.pact_version, '0.2', 'the 0.2 of the old fixture');
  assert.notEqual(ev.pact_version, VERSION, 'the schema constant check would accept this payload');
});
