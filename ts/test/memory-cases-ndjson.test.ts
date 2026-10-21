// Port of go/adapters/memory/cases_ndjson_test.go: the adapter-case leg of
// the cross-language parity check. The harness runs the common cases against
// the memory adapter in both workload modes and prints one line per case,
// {"id","kind","result"}, under the case's manifest id. The Go test of the
// leg against a broken adapter belongs to the broken catalogue.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { type TestContext, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Result } from '../src/adapter/adaptertest/index.ts';
import {
  commonCaseId,
  evaluateAdapterCases,
  mergeCaseResults,
} from '../src/vectors/run-adapter-cases.ts';
import { FIXTURES, fixturesPresent, manifestEntries } from './support/fixtures.ts';

const MAIN = fileURLToPath(new URL('../src/vectors/main.ts', import.meta.url));

// The ids of the adapter-case entries of the manifest whose files are common cases.
function manifestCaseIds(t: TestContext): string[] | undefined {
  if (!fixturesPresent(t)) return undefined;
  return manifestEntries('adapters/_common/')
    .filter((e) => e.kind === 'adapter-case')
    .map((e) => e.id)
    .sort();
}

// One result per common adapter-case entry of the manifest, and every one
// passes, as TestSuite requires.
test('TestCaseResultsNDJSON', async (t) => {
  const want = manifestCaseIds(t);
  if (want === undefined) return;
  const cases = await evaluateAdapterCases(FIXTURES);
  assert.equal(cases.loadError, '');
  assert.deepEqual([...cases.results.keys()], want, "the manifest's common adapter cases");
  for (const [id, r] of cases.results) assert.ok(r.passed, `${id}: ${r.failures.join('; ')}`);
});

// A case passes only when it passed in every mode that ran it; a case that
// ran in one mode takes that mode's result; the failures name their mode.
test('TestMergeCaseResults', () => {
  const fail = ['wrong outcome'];
  const got = mergeCaseResults(
    ['dedicated', 'shared'],
    [
      [
        new Result('COMMON-02.b', []),
        new Result('IDENT-10.a', fail),
        new Result('COMMON-01.a', []),
        new Result('COMMON-03.c', fail),
      ],
      [
        new Result('COMMON-02.b', fail),
        new Result('IDENT-09.a', []),
        new Result('COMMON-01.a', []),
        new Result('IDENT-09.b', fail),
        new Result('COMMON-03.c', []),
      ],
    ],
  );
  assert.deepEqual(
    [...got.entries()],
    [
      ['adapters/_common/common-01.a', { passed: true, failures: [] }],
      ['adapters/_common/common-02.b', { passed: false, failures: ['shared: wrong outcome'] }],
      ['adapters/_common/common-03.c', { passed: false, failures: ['dedicated: wrong outcome'] }],
      ['adapters/_common/ident-09.a', { passed: true, failures: [] }],
      ['adapters/_common/ident-09.b', { passed: false, failures: ['shared: wrong outcome'] }],
      ['adapters/_common/ident-10.a', { passed: false, failures: ['dedicated: wrong outcome'] }],
    ],
  );
  assert.equal(
    commonCaseId('COMMON-01.credential-wins'),
    'adapters/_common/common-01.credential-wins',
  );
});

// The harness entry, run as make ts-vectors runs it: standard output holds
// one JSON line per manifest entry, and the line of every common adapter case
// is a pass.
test('TestCaseResultsNDJSONBinary', (t) => {
  const want = manifestCaseIds(t);
  if (want === undefined) return;
  const r = spawnSync(process.execPath, [MAIN, join(FIXTURES, 'manifest.json')], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout
    .trimEnd()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, string>);
  const cases = lines.filter(
    (l) => l.kind === 'adapter-case' && l.id?.startsWith('adapters/_common/'),
  );
  assert.deepEqual(cases.map((l) => l.id).sort(), want);
  for (const l of cases) {
    assert.deepEqual(Object.keys(l), ['id', 'kind', 'result'], l.id);
    assert.equal(l.result, 'pass', l.id);
  }
});
