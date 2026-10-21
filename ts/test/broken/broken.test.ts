// Port of go/adapters/internal/broken/broken_test.go: the proof that the
// adapter conformance suite can fail. With no defect on, the broken adapter
// is the memory adapter and passes every case; with one defect on, the cases
// that defect targets fail; with every defect on, every case fails; every
// case is targeted by some defect; and runConformance itself, not only
// evaluateConformance, reports a failure for every case.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { type TestContext, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { evaluateConformance, type Result } from '../../src/adapter/adaptertest/index.ts';
import { fixturesPresent } from '../support/fixtures.ts';
import { defects } from './broken.ts';
import { CATALOGUE } from './catalogue.ts';
import type { Defect } from './defects.ts';
import { MODES, type Mode } from './modes.ts';

const RUN_AGAINST_BROKEN = fileURLToPath(new URL('./run-against-broken.ts', import.meta.url));

// Runs the suite against the broken adapter with the given defects on, in
// mode m, and returns the results by case id.
async function evaluate(m: Mode, ...on: Defect[]): Promise<Map<string, Result>> {
  const results = await evaluateConformance(m.factory(...on), m.options);
  assert.ok(results.length > 0, 'the suite has no cases');
  return new Map(results.map((r) => [r.id, r]));
}

function caseIds(res: ReadonlyMap<string, Result>): string[] {
  return [...res.keys()].sort();
}

// With every defect off, the wrapper is the memory adapter and passes every
// case of each mode, so a failure below is the defect's doing.
test('TestNoDefectsPassesTheSuite', async (t) => {
  if (!fixturesPresent(t)) return;
  const errors: string[] = [];
  for (const m of MODES) {
    for (const [id, r] of await evaluate(m)) {
      if (!r.passed())
        errors.push(`${m.name}: ${id} fails with no defect on: ${r.failures.join('; ')}`);
    }
  }
  assert.deepEqual(errors, []);
});

// Defects are unique, each one has a description and a target, and every
// target is a case that exists in a mode. A case that no defect targets
// cannot be shown to catch anything, so it fails.
test('TestCatalogueIsConsistent', async (t) => {
  if (!fixturesPresent(t)) return;
  const res = new Map<string, Result>();
  for (const m of MODES) for (const [id, r] of await evaluate(m)) res.set(id, r);
  const errors: string[] = [];
  const seen = new Set<Defect>();
  const targeted = new Set<string>();
  for (const s of CATALOGUE) {
    if (seen.has(s.defect)) errors.push(`defect ${JSON.stringify(s.defect)} is listed twice`);
    seen.add(s.defect);
    if (s.what === '' || s.targets.length === 0) {
      errors.push(`defect ${JSON.stringify(s.defect)} has no description or no target`);
    }
    for (const id of s.targets) {
      if (!res.has(id)) {
        errors.push(
          `defect ${JSON.stringify(s.defect)} targets ${JSON.stringify(id)}, which is not a case`,
        );
      }
      targeted.add(id);
    }
  }
  for (const id of caseIds(res)) {
    if (!targeted.has(id))
      errors.push(`no defect targets case ${id}: add a mutant that it catches`);
  }
  assert.deepEqual(errors, []);
});

// The mutation proof, one defect at a time. The cases a defect targets must
// fail with only that defect on, in every mode that runs them, so no defect
// passes the whole suite. Other cases that fail with it are reported as
// diagnostics, not required: some defects spoil several cases.
test('TestEachDefectFailsItsCases', async (t) => {
  if (!fixturesPresent(t)) return;
  for (const s of CATALOGUE) {
    await t.test(s.defect, async (st: TestContext) => {
      const errors: string[] = [];
      const ran = new Set<string>();
      for (const m of MODES) {
        const res = await evaluate(m, s.defect);
        for (const id of s.targets) {
          const r = res.get(id);
          if (r === undefined) continue;
          ran.add(id);
          if (r.passed()) {
            errors.push(
              `${m.name}: case ${id} passes although ${JSON.stringify(s.defect)} (${s.what}) is on`,
            );
          }
        }
        const collateral = caseIds(res).filter(
          (id) => !(res.get(id) as Result).passed() && !s.targets.includes(id),
        );
        if (collateral.length > 0) st.diagnostic(`${m.name}: also fails: ${collateral.join(', ')}`);
      }
      for (const id of s.targets) if (!ran.has(id)) errors.push(`no case ${id} in any mode`);
      assert.deepEqual(errors, []);
    });
  }
});

// The adapter with every defect on fails every case of the suite, in each
// mode.
test('TestAllDefectsFailEveryCase', async (t) => {
  if (!fixturesPresent(t)) return;
  const errors: string[] = [];
  for (const m of MODES) {
    const res = await evaluate(m, ...defects());
    for (const id of caseIds(res)) {
      if ((res.get(id) as Result).passed()) {
        errors.push(`${m.name}: case ${id} passes against the adapter with every defect on`);
      }
    }
  }
  assert.deepEqual(errors, []);
});

// The environment of a subprocess that runs tests of its own: without the
// variable by which the node:test runner tells a child process to report to
// it in its own serialized format instead of the reporter given.
function childEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return env;
}

// runConformance itself, not only evaluateConformance, reports a failure for
// every case of each mode when the adapter is broken. run-against-broken.ts
// runs in a subprocess with the TAP reporter, and its output is read: a
// top-level test per mode, a subtest per case.
test('TestRunFailsEveryCase', async (t) => {
  if (!fixturesPresent(t)) return;
  const out = spawnSync(process.execPath, ['--test-reporter=tap', RUN_AGAINST_BROKEN], {
    encoding: 'utf8',
    env: { ...childEnv(), PACT_RUN_BROKEN: '1' },
    maxBuffer: 64 << 20,
  });
  const text = `${out.stdout}${out.stderr}`;
  assert.notEqual(
    out.status,
    0,
    `runConformance against the broken adapter exited successfully:\n${text}`,
  );

  const errors: string[] = [];
  const failed = new Map<string, Set<string>>();
  let mode = '';
  for (const line of out.stdout.split('\n')) {
    const top = /^# Subtest: (\S+)$/.exec(line);
    if (top !== null) {
      mode = top[1] as string;
      continue;
    }
    const sub = /^ {4}(ok|not ok) \d+ - (\S+)(.*)$/.exec(line);
    if (sub === null) continue;
    const [, status, id, rest] = sub as unknown as [string, string, string, string];
    if (status !== 'not ok' || /#\s*(SKIP|TODO)/i.test(rest)) {
      errors.push(`${mode}: case ${id} is reported ${status}${rest}`);
    }
    let set = failed.get(mode);
    if (set === undefined) {
      set = new Set();
      failed.set(mode, set);
    }
    set.add(id);
  }
  for (const m of MODES) {
    const want = caseIds(await evaluate(m));
    const got = failed.get(m.name) ?? new Set<string>();
    for (const id of want)
      if (!got.has(id)) errors.push(`${m.name}: runConformance reports no failure for case ${id}`);
    if (got.size !== want.length) {
      errors.push(
        `${m.name}: runConformance reported ${got.size} cases, the suite has ${want.length}`,
      );
    }
  }
  assert.deepEqual(errors, [], errors.length > 0 && text.length < 4000 ? text : errors.join('\n'));
});
