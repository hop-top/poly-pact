// Port of go/core/binding/appendix_test.go.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fromRequest } from '../src/core/binding/index.ts';
import { objectDigest } from '../src/core/digest.ts';
import { canonicalize } from '../src/core/jcs.ts';
import { bind, config, get } from './support/binding.ts';
import { FIXTURES, fixturesPresent } from './support/fixtures.ts';

/** The operation_digest of draft Appendix B.4 and B.7, object_digest of B.3. */
const OPERATION_DIGEST_B3 = 'R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0';

const utf8 = new TextEncoder();

// The request of the Appendix B example, sent to a real server with
// credentials and a presentation header, binds to the B.3 operation context
// and its digest once the caller sets operation_id and environment_id.
test('TestAppendixB3', async (t) => {
  if (!fixturesPresent(t)) return;
  const vectors = JSON.parse(
    readFileSync(join(FIXTURES, 'vectors', 'digest', 'appendix-b.json'), 'utf8'),
  ) as { id: string; input: unknown; expected_digest: string }[];
  const b3 = vectors.find((v) => v.id === 'operation-b3');
  assert.ok(b3, 'appendix-b.json has no vector operation-b3');
  assert.equal(b3.expected_digest, OPERATION_DIGEST_B3, 'vector digest against draft B.4');

  const { operation } = await bind(
    config(),
    'GET /invoices/INV-1042 HTTP/1.1\r\n' +
      'Host: gateway.example\r\n' +
      'Authorization: Bearer native-token\r\n' +
      'PACT-Presentation: eyJhbGciOiJFUzI1NiJ9.e30.c2ln\r\n' +
      'Accept: application/json\r\n\r\n',
  );
  assert.equal(operation.operation_id, '', 'the caller owns operation_id');
  assert.equal(operation.environment_id, '', 'the caller owns environment_id');
  const op = {
    ...operation,
    operation_id: 'invoice-read-operation-0001',
    environment_id: 'https://gateway.example/environments/finance',
  };
  assert.equal(
    new TextDecoder().decode(canonicalize(utf8.encode(JSON.stringify(op)))),
    new TextDecoder().decode(canonicalize(utf8.encode(JSON.stringify(b3.input)))),
  );
  assert.equal(objectDigest(op), OPERATION_DIGEST_B3);
});

// Principal, action and resources are the caller's, and the resources are
// copied.
test('TestCallerValues', () => {
  const res = ['https://invoices.example/invoices/1', 'https://invoices.example/invoices/2'];
  const op = fromRequest(
    config(),
    get('/x'),
    'https://identity.example/principals/bob',
    'invoice.list',
    res,
  );
  assert.equal(op.principal_id, 'https://identity.example/principals/bob');
  assert.equal(op.action, 'invoice.list');
  res[0] = 'changed';
  assert.deepEqual(op.resources, [
    'https://invoices.example/invoices/1',
    'https://invoices.example/invoices/2',
  ]);
});
