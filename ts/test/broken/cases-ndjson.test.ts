// Port of TestCaseResultsNDJSONBroken of go/adapters/memory/cases_ndjson_test.go,
// the adapter-case leg of the cross-language parity check against a broken
// adapter: the leg's results, by manifest id, run against an adapter that
// resolves a shared workload to its first agent.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { commonCaseId, evaluateModes } from '../../src/vectors/run-adapter-cases.ts';
import { FIXTURES, fixturesPresent, manifestEntries } from '../support/fixtures.ts';
import { factory, sharedFactory } from './broken.ts';
import { Defect } from './defects.ts';

// The results still cover every common case of the manifest, and the
// shared-workload cases that the defect breaks are fail; they run only in
// the shared mode.
test('TestCaseResultsNDJSONBroken', async (t) => {
  if (!fixturesPresent(t)) return;
  const want = manifestEntries('adapters/_common/')
    .filter((e) => e.kind === 'adapter-case')
    .map((e) => e.id)
    .sort();
  const cases = await evaluateModes(FIXTURES, [
    { name: 'dedicated', factory: factory(Defect.FIRST_OF_SHARED), options: {} },
    {
      name: 'shared',
      factory: sharedFactory(Defect.FIRST_OF_SHARED),
      options: { sharedWorkloads: true },
    },
  ]);
  assert.equal(cases.loadError, '');
  assert.deepEqual([...cases.results.keys()], want, "the manifest's common adapter cases");
  for (const id of [
    'IDENT-09.shared-workload',
    'IDENT-09.other-agent',
    'IDENT-09.unenrolled-agent',
  ]) {
    assert.equal(cases.results.get(commonCaseId(id))?.passed, false, `${id}: want fail`);
  }
  assert.equal(
    cases.results.get(commonCaseId('COMMON-01.credential-wins'))?.passed,
    true,
    'COMMON-01.credential-wins: want pass',
  );
});
