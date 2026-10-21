// Port of go/runner/evalcase/transport_test.go: a submission's transport.

import assert from 'node:assert/strict';
import { type TestContext, test } from 'node:test';
import { load } from '../src/conformance/case.ts';
import { at, caseTree, REPO_FIXTURES, wantThrows, writeFile } from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

const ID = 'admission/valid';
const PRES = '"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"';

// A submission's transport is the transport profile the presentation arrives
// over, https or stdio-ipc, by default https (spec/v1.0/fixtures/README.md,
// exchange.json; draft 13.3.1).
test('TestSubmissionTransport', async (t) => {
  if (!fixturesPresent(t)) return;
  for (const [body, want] of [
    ['', 'https'],
    [`{"presentations":[{${PRES}}]}`, 'https'],
    [`{"presentations":[{${PRES},"transport":"https"}]}`, 'https'],
    [`{"presentations":[{${PRES},"transport":"stdio-ipc"}]}`, 'stdio-ipc'],
  ]) {
    await t.test(body === '' ? 'no exchange.json' : body, (t: TestContext) => {
      const root = caseTree(t, ID);
      if (body !== '') writeFile(at(root, `${ID}/exchange.json`), body);
      assert.equal(load(root, ID).exchanges[0]?.submissions[0]?.transport, want);
    });
  }
  for (const body of [
    `{"presentations":[{${PRES},"transport":"http"}]}`,
    `{"presentations":[{${PRES},"transport":""}]}`,
    `{"presentations":[{${PRES},"transport":"HTTPS"}]}`,
  ]) {
    await t.test(body, (t: TestContext) => {
      const root = caseTree(t, ID);
      writeFile(at(root, `${ID}/exchange.json`), body);
      wantThrows(() => load(root, ID), 'exchange.json', 'transport');
    });
  }
  for (const [id, want] of [
    ['transport/https-contract-over-stdio-ipc', 'stdio-ipc'],
    ['transport/stdio-ipc-contract-over-https', 'https'],
  ]) {
    assert.equal(load(REPO_FIXTURES, id).exchanges[0]?.submissions[0]?.transport, want, id);
  }
});
