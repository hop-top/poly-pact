// Tests of the evaluate skeleton, src/conformance/main.ts, run as a child
// process the way pactc runs an evaluate command ("tool evaluate {dir}
// {state}", go/runner package documentation): one response line per
// submission and per handoff attempt of each exchange, each an RFC 9457
// Problem (draft 13.4) with the code UNSUPPORTED_REQUIREMENT and status 422;
// a usage or case error prints nothing on standard output and exits 2.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { at, REPO_FIXTURES } from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

const MAIN = fileURLToPath(new URL('../src/conformance/main.ts', import.meta.url));

function run(args: string[]) {
  const r = spawnSync(process.execPath, [MAIN, ...args], { encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function json(rel: string): Record<string, unknown> {
  return JSON.parse(readFileSync(at(REPO_FIXTURES, rel), 'utf8')) as Record<string, unknown>;
}

// The response lines a case asks for, counted from its files: per exchange,
// the expected responses (the top level as one, or responses) and the
// expected handoff results (spec/v1.0/fixtures/README.md, decision.json).
function wantLines(id: string): number {
  const seq = existsSync(at(REPO_FIXTURES, `${id}/sequence.json`))
    ? (json(`${id}/sequence.json`).exchanges as string[])
    : [''];
  let n = 0;
  for (const x of seq) {
    const d = json(`expected/${id}/${x === '' ? '' : `${x}/`}decision.json`);
    n += Array.isArray(d.responses) ? d.responses.length : 1;
    n += Array.isArray(d.handoff) ? d.handoff.length : 0;
  }
  return n;
}

test('TestSkeletonPrintsUnsupportedRequirement', async (t) => {
  if (!fixturesPresent(t)) return;
  const state = mkdtempSync(join(tmpdir(), 'pact-skeleton-'));
  t.after(() => rmSync(state, { recursive: true, force: true }));
  for (const id of [
    'admission/valid',
    'admission/attestation-reuse',
    'admission/replay-same-nonce-two-replicas',
    'approval/approved-fresh-exchange',
  ]) {
    await t.test(id, () => {
      const r = run(['evaluate', at(REPO_FIXTURES, id), join(state, id.replaceAll('/', '_'))]);
      assert.equal(r.status, 0, r.stderr);
      const lines = r.stdout.split('\n');
      assert.equal(lines.pop(), '', 'output ends with a newline');
      assert.equal(lines.length, wantLines(id));
      for (const [i, line] of lines.entries()) {
        const p = JSON.parse(line) as Record<string, unknown>;
        assert.deepEqual(Object.keys(p).sort(), ['code', 'request_id', 'status', 'title', 'type']);
        assert.equal(p.code, 'UNSUPPORTED_REQUIREMENT', `line ${i}`);
        assert.equal(p.status, 422, `line ${i}`);
        assert.equal(typeof p.request_id, 'string');
        assert.notEqual(p.request_id, '');
      }
    });
  }
});

test('TestSkeletonUsage', async (t) => {
  for (const args of [[], ['evaluate'], ['receipt', '/tmp', 'x'], ['evaluate', 'a', 'b', 'c']]) {
    await t.test(JSON.stringify(args), () => {
      const r = run(args);
      assert.equal(r.status, 2);
      assert.equal(r.stdout, '');
      assert.match(r.stderr, /usage: /);
    });
  }
  await t.test('not a case directory', (t) => {
    if (!fixturesPresent(t)) return;
    const r = run(['evaluate', at(REPO_FIXTURES, 'keys')]);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /keys/);
  });
});
