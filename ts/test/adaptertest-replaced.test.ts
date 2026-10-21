// Port of go/adapter/adaptertest/replaced_test.go: the declarations of
// common cases replaced by an adapter's own cases (draft 22.2), the verdict
// of a replaced case, and a run with a declaration.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  evaluateConformance,
  loadCases,
  runConformance,
} from '../src/adapter/adaptertest/index.ts';
import { checkReplaced, verdict } from '../src/adapter/adaptertest/suite.ts';
import { DenialReason, NativeDenial } from '../src/adapter/index.ts';
import {
  authFake,
  factoryFor,
  minimalCase,
  treeOf,
  ZERO_PRINCIPAL,
} from './support/adaptertest.ts';

// minimalCase, an authenticate_native case that expects a denial, with
// another id and outcome.
const caseWith = (id: string, outcome: string): string =>
  minimalCase.replace('COMMON-01.one', id).replace('"denied"', `"${outcome}"`);

// A resolve_agent_binding case that expects UNKNOWN.
const bindingCaseJSON = (id: string): string => `{
  "case_version": 1,
  "id": "${id}",
  "title": "A binding case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "call": {
    "realm": {"tenant_id": "acme", "environment_id": "https://gateway.example/environments/finance"},
    "workload": "w-1",
    "agent_id": "https://identity.example/agents/a"
  },
  "expect": {"function": "resolve_agent_binding", "outcome": "unknown"}
}`;

// The principal and operation of the authorize_native, check_context and
// read_native_claim cases below.
const callPrincipal =
  '"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}';
const callOperation =
  '"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a", "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "", "headers": {}}';

// A case of the function fn with the call members call that expects outcome.
const callCaseJSON = (id: string, fn: string, outcome: string, call: string): string => `{
  "case_version": 1,
  "id": "${id}",
  "title": "A ${fn} case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "call": {${call}},
  "expect": {"function": "${fn}", "outcome": "${outcome}"}
}`;

const authorizeCaseJSON = (id: string, outcome: string): string =>
  callCaseJSON(id, 'authorize_native', outcome, `${callPrincipal}, ${callOperation}`);

// Common cases of four functions and the cases of the adapter "mech".
function replacedTree(): Record<string, string> {
  return {
    'adapters/_common/a.json': caseWith('COMMON-01.one', 'error'),
    'adapters/_common/b.json': bindingCaseJSON('COMMON-08.one'),
    'adapters/_common/c.json': authorizeCaseJSON('COMMON-06.one', 'ALLOW'),
    'adapters/_common/d.json': callCaseJSON(
      'COMMON-04.one',
      'read_native_claim',
      'error',
      `${callPrincipal}, "native_path": "/x"`,
    ),
    'adapters/mech/mech-01.json': caseWith('MECH-01.denied', 'denied'),
    'adapters/mech/mech-02.json': caseWith('MECH-02.authenticated', 'authenticated'),
    'adapters/mech/mech-03.json': bindingCaseJSON('MECH-03.binding'),
    'adapters/mech/mech-04.json': caseWith('MECH-04.error', 'error'),
    'adapters/mech/mech-05.json': authorizeCaseJSON('MECH-05.allow', 'ALLOW'),
    'adapters/mech/mech-06.json': authorizeCaseJSON('MECH-06.deny', 'DENY'),
    'adapters/mech/mech-07.json': callCaseJSON(
      'MECH-07.check',
      'check_context',
      'PASS',
      `${callPrincipal}, ${callOperation}, "check_id": "c"`,
    ),
    'adapters/mech/mech-08.json': callCaseJSON(
      'MECH-08.claim',
      'read_native_claim',
      'error',
      `${callPrincipal}, "native_path": "/x"`,
    ),
    'adapters/other/other-01.json': caseWith('OTHER-01.denied', 'denied'),
  };
}

test('TestCheckReplaced', async (t) => {
  const tree = replacedTree();
  // MECH-02 expects a principal, so its case needs one.
  tree['adapters/mech/mech-02.json'] = (tree['adapters/mech/mech-02.json'] as string).replace(
    '"outcome": "authenticated"}',
    '"outcome": "authenticated", "principal": {"id": "p"}}',
  );
  const cases = loadCases(treeOf(tree), 'mech');
  const ok = { by: 'MECH-01.denied', reason: 'the mechanism has no bearer token' };
  const valid = (replaced: Record<string, { by: string; reason: string }>, what: string) =>
    assert.doesNotThrow(() => checkReplaced(cases, { adapter: 'mech', replaced }), what);
  valid({ 'COMMON-01.one': ok }, 'a valid declaration');
  valid(
    { 'COMMON-01.one': { by: 'MECH-04.error', reason: 'r' } },
    'a replacement with another rejected outcome',
  );
  // An authorize_native case may be replaced as well, under the same rules
  // (spec/v1.0/fixtures/adapters/README.md, "Replaced common cases").
  valid(
    {
      'COMMON-06.one': {
        by: 'MECH-05.allow',
        reason: 'the decision answer carries no decision time',
      },
    },
    'an authorize_native declaration',
  );
  valid(
    { 'COMMON-01.one': ok, 'COMMON-06.one': { by: 'MECH-05.allow', reason: 'r' } },
    'declarations of both functions',
  );
  const tests: [string, string, { by: string; reason: string }, string][] = [
    ['unknown id', 'COMMON-01.none', ok, 'is not a common case'],
    ['adapter case as the original', 'MECH-04.error', ok, 'is not a common case'],
    [
      'original of another function',
      'COMMON-08.one',
      { by: 'MECH-03.binding', reason: 'r' },
      'only authenticate_native and authorize_native cases',
    ],
    [
      'read_native_claim original',
      'COMMON-04.one',
      { by: 'MECH-08.claim', reason: 'r' },
      'only authenticate_native and authorize_native cases',
    ],
    [
      'authorize_native replaced by check_context',
      'COMMON-06.one',
      { by: 'MECH-07.check', reason: 'r' },
      'is a check_context case',
    ],
    [
      'authorize_native replaced by authenticate_native',
      'COMMON-06.one',
      { by: 'MECH-02.authenticated', reason: 'r' },
      'is a authenticate_native case',
    ],
    [
      'authorize_native replaced by the other outcome class',
      'COMMON-06.one',
      { by: 'MECH-06.deny', reason: 'r' },
      'other outcome class',
    ],
    [
      'authorize_native with an empty reason',
      'COMMON-06.one',
      { by: 'MECH-05.allow', reason: '' },
      'gives no reason',
    ],
    ['no replacement', 'COMMON-01.one', { by: '', reason: 'r' }, 'names no replacement'],
    [
      'unknown replacement',
      'COMMON-01.one',
      { by: 'MECH-09.none', reason: 'r' },
      'not a case of adapters/mech',
    ],
    [
      'common case as the replacement',
      'COMMON-01.one',
      { by: 'COMMON-01.one', reason: 'r' },
      'not a case of adapters/mech',
    ],
    [
      'replacement of another function',
      'COMMON-01.one',
      { by: 'MECH-03.binding', reason: 'r' },
      'is a resolve_agent_binding case',
    ],
    [
      'replacement of the other outcome class',
      'COMMON-01.one',
      { by: 'MECH-02.authenticated', reason: 'r' },
      'other outcome class',
    ],
    ['empty reason', 'COMMON-01.one', { by: 'MECH-01.denied', reason: ' ' }, 'gives no reason'],
  ];
  for (const [name, id, rep, want] of tests) {
    await t.test(name, () => {
      assert.throws(
        () => checkReplaced(cases, { adapter: 'mech', replaced: { [id]: rep } }),
        (err: Error) => err.message.includes(want),
      );
    });
  }
  await t.test("another adapter's case is no replacement", () => {
    const other = loadCases(treeOf(tree), 'other');
    assert.throws(
      () => checkReplaced(other, { adapter: 'other', replaced: { 'COMMON-01.one': ok } }),
      /not a case of adapters\/other/,
    );
  });
});

test('TestVerdict', () => {
  const rep = { by: 'MECH-01.denied', reason: 'no bearer token' };
  const fails = ['principal id is "x"'];
  let v = verdict('COMMON-01.one', fails, undefined);
  assert.deepEqual(
    v,
    { errors: fails, logs: [] },
    'undeclared failing case: its failures as errors',
  );
  v = verdict('COMMON-01.one', [], undefined);
  assert.deepEqual(v, { errors: [], logs: [] }, 'undeclared passing case');
  v = verdict('COMMON-01.one', [], rep);
  assert.equal(v.errors.length, 1);
  assert.match(v.errors[0] as string, /declared replaced by MECH-01\.denied but passes/);
  v = verdict('COMMON-01.one', fails, rep);
  assert.deepEqual(v.errors, []);
  assert.ok(v.logs.includes(fails[0] as string));
  assert.match(v.logs[0] as string, /no bearer token/);
});

test('TestRunReplaced', async (t) => {
  const denying = authFake(ZERO_PRINCIPAL, new NativeDenial(DenialReason.NO_CREDENTIAL));
  const fixtures = treeOf({
    'adapters/_common/a.json': caseWith('COMMON-01.one', 'error').replace(
      '"outcome": "error"',
      '"outcome": "error", "reason_code": "DEPENDENCY_UNAVAILABLE"',
    ),
    'adapters/mech/mech-01.json': caseWith('MECH-01.denied', 'denied'),
  });
  const opts = {
    fixtures,
    adapter: 'mech',
    replaced: {
      'COMMON-01.one': { by: 'MECH-01.denied', reason: 'the mechanism cannot produce this error' },
    },
  };

  await t.test('declared, failing, valid replacement', async (t) => {
    await runConformance(t, factoryFor(denying), opts);
  });

  await t.test('evaluate ignores the declaration', async () => {
    const res = await evaluateConformance(factoryFor(denying), opts);
    assert.equal(res.length, 2);
    assert.equal(res[0]?.id, 'COMMON-01.one');
    assert.ok(!res[0]?.passed(), 'the replaced case is reported as run and failed');
    assert.ok(res[1]?.passed());
  });

  await t.test('a replaced case that passes fails its test', async () => {
    const passing = treeOf({
      'adapters/_common/a.json': caseWith('COMMON-01.one', 'denied'),
      'adapters/mech/mech-01.json': caseWith('MECH-01.denied', 'denied'),
    });
    const recorded: { name: string; error?: unknown }[] = [];
    const ctx = {
      test: async (
        name: string,
        fn: (st: { diagnostic: (m: string) => void }) => Promise<void>,
      ) => {
        try {
          await fn({ diagnostic: () => {} });
          recorded.push({ name });
        } catch (error) {
          recorded.push({ name, error });
        }
      },
    };
    await runConformance(ctx as never, factoryFor(denying), { ...opts, fixtures: passing });
    assert.equal(recorded.length, 2);
    assert.match(
      String((recorded[0]?.error as Error)?.message),
      /declared replaced by MECH-01\.denied but passes/,
    );
    assert.equal(recorded[1]?.error, undefined);
  });
});
