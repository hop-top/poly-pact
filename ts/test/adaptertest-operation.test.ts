// Port of go/adapter/adaptertest/checks_operation_test.go: the
// map_operation checks. The Go row of an operation returned together with
// an error has no counterpart: a rejected promise carries no value.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ExpectOperation } from '../src/adapter/adaptertest/index.ts';
import { AdapterError, type Principal } from '../src/adapter/index.ts';
import type { RawRequest } from '../src/core/binding/index.ts';
import type { OperationContext } from '../src/core/types.ts';
import type { Digest } from '../src/core/values.ts';
import {
  acme,
  fake,
  goodOp,
  header,
  mapCase,
  mapFake,
  NOW,
  type Row,
  runFake,
  runRows,
  wantClean,
} from './support/adaptertest.ts';

const loose: ExpectOperation = {
  environment_id: '',
  principal_id: '',
  action: '',
  resources: null,
  method: '',
  target_uri: '',
  body_digest: '',
  headers: null,
};
const expectOp = (m: Partial<ExpectOperation>) => ({ operation: { ...loose, ...m } });

test('TestMapOperationChecks', async (t) => {
  const good = goodOp();
  const w = (m: Partial<OperationContext> | Record<string, unknown>): OperationContext =>
    ({ ...good, headers: {}, ...m }) as OperationContext;
  const rows: Row[] = [
    [
      'mapped',
      mapFake(good),
      mapCase(
        'mapped',
        expectOp({
          environment_id: good.environment_id,
          principal_id: good.principal_id,
          action: 'invoice.read',
          resources: ['https://invoices.example/invoices/1'],
          method: 'GET',
          target_uri: good.target_uri,
          body_digest: good.body_digest,
          headers: {},
        }),
      ),
      null,
    ],
    [
      'mapped but rejects',
      mapFake({}, AdapterError.contextMismatch()),
      mapCase('mapped', expectOp({})),
      ['want an operation context'],
    ],
    [
      'no operation id',
      mapFake(w({ operation_id: '' })),
      mapCase('mapped', expectOp({})),
      ['operation_id is empty'],
    ],
    [
      'principal from elsewhere',
      mapFake(w({ principal_id: 'https://idp.example/mallory' })),
      mapCase('mapped', expectOp({})),
      ['never from the request'],
    ],
    [
      'lowercase method',
      mapFake(w({ method: 'get' })),
      mapCase('mapped', expectOp({})),
      ['not uppercase'],
    ],
    [
      'http target',
      mapFake(w({ target_uri: 'http://gateway.example/x' })),
      mapCase('mapped', expectOp({})),
      ['not an https URI'],
    ],
    [
      'fragment in target',
      mapFake(w({ target_uri: 'https://gateway.example/x#f' })),
      mapCase('mapped', expectOp({})),
      ['carries a fragment'],
    ],
    [
      'bad body digest',
      mapFake(w({ body_digest: 'abc' as Digest })),
      mapCase('mapped', expectOp({})),
      ['body_digest'],
    ],
    [
      'no resources',
      mapFake(w({ resources: null })),
      mapCase('mapped', expectOp({})),
      ['resources is null'],
    ],
    [
      'no headers',
      mapFake(w({ headers: null })),
      mapCase('mapped', expectOp({})),
      ['headers is null'],
    ],
    [
      'uppercase header name',
      mapFake(w({ headers: { 'X-Kind': 'a' } })),
      mapCase('mapped', expectOp({})),
      ['not lowercase'],
    ],
    [
      'wrong environment',
      mapFake(good),
      mapCase('mapped', expectOp({ environment_id: 'other' })),
      ['environment_id is'],
    ],
    [
      'wrong principal expectation',
      mapFake(good),
      mapCase('mapped', expectOp({ principal_id: 'other' })),
      ['principal_id is'],
    ],
    [
      'wrong action',
      mapFake(good),
      mapCase('mapped', expectOp({ action: 'invoice.approve' })),
      ['action is'],
    ],
    [
      'wrong resources',
      mapFake(good),
      mapCase('mapped', expectOp({ resources: ['https://invoices.example/invoices/2'] })),
      ['resources are'],
    ],
    ['wrong method', mapFake(good), mapCase('mapped', expectOp({ method: 'POST' })), ['method is']],
    [
      'wrong target',
      mapFake(good),
      mapCase('mapped', expectOp({ target_uri: 'https://x.example/' })),
      ['target_uri is'],
    ],
    [
      'wrong digest',
      mapFake(good),
      mapCase('mapped', expectOp({ body_digest: 'yy' })),
      ['body_digest is'],
    ],
    [
      'wrong headers',
      mapFake(good),
      mapCase('mapped', expectOp({ headers: { 'x-request-kind': 'approval' } })),
      ['headers are'],
    ],

    [
      'error',
      mapFake({}, AdapterError.contextMismatch()),
      mapCase('error', { reason_code: 'CONTEXT_MISMATCH' }),
      null,
    ],
    ['error expected, mapped', mapFake(good), mapCase('error', {}), ['want an error']],
  ];
  await runRows(t, rows);
});

// The code a rejected malformed request reports, INVALID_MESSAGE (draft
// 13.4), is checked against the case. A code is carried by an AdapterError
// in the cause chain; an error that only has a `code` member carries none.
test('TestMapOperationMalformedRequestCode', async (t) => {
  const want = { reason_code: 'INVALID_MESSAGE' };
  const codedOnly = Object.assign(new Error('coded only'), { code: 'INVALID_MESSAGE' });
  const rows: Row[] = [
    ['the code', mapFake({}, AdapterError.invalidMessage()), mapCase('error', want), null],
    [
      'wrapped',
      mapFake(
        {},
        new Error('target', {
          cause: new Error('map', { cause: AdapterError.invalidMessage('fragment') }),
        }),
      ),
      mapCase('error', want),
      null,
    ],
    [
      'another code',
      mapFake({}, AdapterError.unsupportedRequirement()),
      mapCase('error', want),
      ['code is UNSUPPORTED_REQUIREMENT, want INVALID_MESSAGE'],
    ],
    [
      'no code',
      mapFake({}, new Error('cannot map')),
      mapCase('error', want),
      ['carries no draft 13.4 code, want INVALID_MESSAGE'],
    ],
    [
      'the code without an AdapterError',
      mapFake({}, codedOnly),
      mapCase('error', want),
      ['carries no draft 13.4 code'],
    ],
  ];
  await runRows(t, rows);
});

// The adapter must leave the body it reads: the digest covers the exact
// bytes, and the request must still be forwardable (draft 10.2). The suite
// hands over a frozen RawRequest, so the adapter can only change it by
// writing into its body; the Go rows of a body taken away have no
// counterpart.
test('TestMapOperationRestoresTheBody', async (t) => {
  const req = { method: 'POST', body_b64: Buffer.from('{"amount":"1"}').toString('base64') };
  const read = (after: (r: RawRequest) => void) =>
    fake({
      mapOp: async (r) => {
        after(r);
        return goodOp();
      },
    });
  const rows: Row[] = [
    [
      'read and left',
      read((r) => void Buffer.from(r.body).toString()),
      mapCase('mapped', expectOp({}), req),
      null,
    ],
    [
      'overwritten',
      read((r) => r.body.fill(0)),
      mapCase('mapped', expectOp({}), req),
      ['must leave what it reads'],
    ],
    [
      'partly overwritten',
      read((r) => r.body.fill(0x20, 3)),
      mapCase('mapped', expectOp({}), req),
      ['differ from the original'],
    ],
  ];
  await runRows(t, rows);
});

test('TestMapOperationReceivesTheCase', async () => {
  let got: [RawRequest, Principal, string] | undefined;
  const f = fake({
    mapOp: async (r, p, v) => {
      got = [r, p, v];
      return goodOp();
    },
  });
  const c = mapCase('mapped', expectOp({}), {
    method: 'POST',
    url: 'https://svc:pw@gateway.example/invoices/1?a=%2f&b=2#frag',
    headers: { 'X-One': '1', Host: 'attacker.example' },
    native_state_ref: 'alice',
  });
  wantClean(await runFake(f, c));
  assert.ok(got !== undefined);
  const [r, p, v] = got;
  assert.equal(r.method, 'POST');
  assert.equal(
    r.rawRequestURI,
    'https://svc:pw@gateway.example/invoices/1?a=%2f&b=2#frag',
    'the adapter gets the URL exactly as the case states it',
  );
  assert.equal(header(r, 'X-One'), '1');
  assert.equal(header(r, 'Host'), 'attacker.example');
  assert.equal(header(r, 'Authorization'), 'Bearer tok-alice', 'the credential hook ran');
  assert.equal(p.id, 'https://idp.example/alice');
  assert.deepEqual(p.realm, acme);
  assert.equal(p.mechanism, 'test');
  assert.equal(p.authenticatedAt, NOW);
  assert.equal(v, 'map-1');
});
