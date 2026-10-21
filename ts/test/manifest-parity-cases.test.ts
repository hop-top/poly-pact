// The shared manifest case table, tools/spec/manifest-parity-cases.json
// (tools/spec/README.md, Manifest parity cases), against this module: each
// case's mutation is applied to a scratch copy of the spec tree, and check
// must report the case's rule (or nothing, for a control), never a rule of
// its forbid list, and never the rule of a gap case. The table and the Go
// rule list sit outside the package: where one is absent (package mirror,
// mutation copy) the test is skipped.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { type TestContext, test } from 'node:test';
import * as manifest from '../src/runner/manifest/index.ts';
import { check } from '../src/runner/manifest/index.ts';
import { tempDir } from './support/manifest.ts';
import { loadCases, type ParityCase } from './support/paritycases.ts';
import { ParityCopy } from './support/paritycopy.ts';
import { goSource, REPO } from './support/repo.ts';

const CASES_FILE = join(REPO, 'tools', 'spec', 'manifest-parity-cases.json');
const GO_RULES = join(REPO, 'go', 'runner', 'manifest', 'problem.go');
const SPEC = join(REPO, 'spec');

// The rule ids of this module: the values of its RULE_* exports.
const RULES = Object.entries(manifest)
  .filter(([k]) => k.startsWith('RULE_'))
  .map(([, v]) => v as string);

function table(t: TestContext): ParityCase[] | undefined {
  if (!existsSync(CASES_FILE) || !existsSync(join(SPEC, 'fixtures', 'manifest.json'))) {
    t.skip(`${CASES_FILE} or spec/v1.0/fixtures absent`);
    return undefined;
  }
  return loadCases(readFileSync(CASES_FILE, 'utf8'), 'tools/spec/manifest-parity-cases.json');
}

test('the rule ids are those of go/runner/manifest/problem.go', (t) => {
  const src = goSource(t, GO_RULES);
  if (src === undefined) return;
  const goRules = [...src.matchAll(/^\s*Rule\w+\s*=\s*"([a-z][a-z-]*)"/gm)].map((m) => m[1]);
  assert.ok(goRules.length > 0);
  assert.deepEqual([...RULES].sort(), [...goRules].sort());
});

test('every rule has a case in the shared table, and every case names a rule', (t) => {
  const cases = table(t);
  if (cases === undefined) return;
  const named = new Set(cases.flatMap((c) => (c.rule === null ? [] : [c.rule])));
  assert.deepEqual(
    [...named].filter((r) => !RULES.includes(r)),
    [],
    'cases name unknown rules',
  );
  const covered = new Set(cases.flatMap((c) => (c.rule === null || c.gap ? [] : [c.rule])));
  assert.deepEqual(
    RULES.filter((r) => !covered.has(r)),
    [],
    'rules without a case',
  );
  assert.ok(
    cases.some((c) => c.rule === null),
    'no control case',
  );
});

test('every case of the shared table yields its expected rule', async (t) => {
  const cases = table(t);
  if (cases === undefined) return;
  const copy = new ParityCopy(SPEC, tempDir());
  const run = () => check(copy.fixtures, copy.mapPath);

  await t.test('(unmodified)', () => {
    const ps = run();
    assert.equal(ps.length, 0, ps.message);
  });
  for (const c of cases) {
    const symlinks = c.mutation.some((s) => s.op === 'symlink');
    const skip =
      symlinks && process.platform === 'win32'
        ? 'symbolic links need privileges on windows'
        : false;
    await t.test(`${c.rule ?? '(control)'} ${c.name}`, { skip }, () => {
      copy.apply(c.mutation);
      try {
        const ps = run();
        const found = new Set(ps.map((p) => p.rule));
        if (c.rule === null) assert.equal(ps.length, 0, `the control fails:\n${ps.message}`);
        else if (c.gap)
          assert.ok(!found.has(c.rule), `reports [${c.rule}] now: remove the gap mark`);
        else assert.ok(found.has(c.rule), `does not report [${c.rule}]; got:\n${ps.message}`);
        for (const f of c.forbid) {
          assert.ok(!found.has(f), `reports [${f}], which this copy must not trigger`);
        }
      } finally {
        copy.restore();
      }
    });
  }
  // The copy is back to the unmodified tree.
  await t.test('(restored)', () => {
    const ps = run();
    assert.equal(ps.length, 0, ps.message);
  });
});
