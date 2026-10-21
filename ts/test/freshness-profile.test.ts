// Port of go/adapter/freshness/profile_test.go: the vocabulary, the worked
// evaluations and the clock cross-references of spec/v1.0/profiles/freshness.md,
// read at test time.

import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { evaluate, ReasonCode } from '../src/adapter/freshness.ts';
import type { NativeClaim } from '../src/adapter/index.ts';
import { Artifact, BASELINE_SKEW_MS, maxLifetime } from '../src/core/clock.ts';
import { at, base, rule } from './support/freshness.ts';
import { REPO, specText } from './support/repo.ts';

const PROFILE = join(REPO, 'spec', 'v1.0', 'profiles', 'freshness.md');

// The text under the heading line head, up to the next heading of the same
// or a higher level.
function section(doc: string, head: string): string {
  const level = head.indexOf(' ');
  const start = doc.indexOf(`\n${head}\n`);
  assert.ok(start >= 0, `profile has no heading ${JSON.stringify(head)}`);
  const body = doc.slice(start + head.length + 2);
  let pos = 0;
  for (const line of body.split(/(?<=\n)/)) {
    const n = line.length - line.replace(/^#+/, '').length;
    if (n >= 1 && n <= level && line.slice(n).startsWith(' ')) return body.slice(0, pos);
    pos += line.length;
  }
  return body;
}

// A worked-evaluation time: seconds relative to now, or none.
function offset(cell: string, now: number): number | null {
  const c = cell.replace(/^[` ]+|[` ]+$/g, '');
  if (c === 'none') return null;
  assert.match(c, /^[-+]?\d+$/, `time cell ${JSON.stringify(cell)} is neither an offset nor none`);
  return now + Number(c) * 1000;
}

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|+|\|+$/g, '')
    .split('|')
    .map((c) => c.trim());
}

// Every row of the profile's table of worked evaluations through evaluate:
// the document and the code say the same.
test('TestProfileWorkedEvaluations', (t) => {
  const doc = specText(t, PROFILE);
  if (doc === undefined) return;
  const table = section(doc, '### 3.3 Worked evaluations');
  const now = at(base);
  let rows = 0;
  for (const line of table.split('\n')) {
    if (!/^\| `([-+]?\d+|none)` \|/.test(line)) continue;
    const c = cells(line);
    assert.equal(c.length, 7, `row ${line}`);
    const [observed, status, maxAge, statusAge, result, code] = c as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    assert.match(maxAge, /^\d+$/, `row ${line}: limits are integers`);
    assert.match(statusAge, /^\d+$/, `row ${line}: limits are integers`);
    const got: NativeClaim = {
      value: null,
      observedAt: offset(observed, now),
      statusCheckedAt: offset(status, now),
      sourceId: '',
      sourceRef: '',
    };
    assert.deepEqual(
      evaluate(rule(Number(maxAge), Number(statusAge)), got, now),
      [result, code.replace(/`/g, '')],
      `row ${line}`,
    );
    rows++;
  }
  assert.ok(rows >= 10, `found ${rows} worked evaluations, want at least 10`);
});

// The results and decisions the profile gives each reason code.
test('TestProfileReasonCodes', (t) => {
  const doc = specText(t, PROFILE);
  if (doc === undefined) return;
  const table = section(doc, '### 3.2 Results and reason codes');
  const want = new Map<string, readonly [string, string]>([
    [ReasonCode.SATISFIED, ['PASS', 'Contributes to `ADMISSIBLE`']],
    [ReasonCode.STALE_EVIDENCE, ['FAIL', '`INADMISSIBLE`']],
    [ReasonCode.CLOCK_AHEAD, ['FAIL', '`INADMISSIBLE`']],
    [ReasonCode.RESTAMPED, ['FAIL', '`INADMISSIBLE`']],
    [ReasonCode.UNSUPPORTED_REQUIREMENT, ['UNKNOWN', '`DEFERRED`']],
    [ReasonCode.DEPENDENCY_UNAVAILABLE, ['UNKNOWN', '`DEFERRED`']],
  ]);
  const got = new Map<string, readonly [string, string]>();
  for (const line of table.split('\n')) {
    if (!line.startsWith('| `')) continue;
    const c = cells(line);
    assert.equal(c.length, 5, `row ${line}`);
    got.set((c[0] ?? '').replace(/`/g, ''), [(c[1] ?? '').replace(/`/g, ''), c[2] ?? '']);
  }
  for (const [code, w] of want) assert.deepEqual(got.get(code), w, code);
  assert.equal(got.size, want.size, 'the profile lists the reason codes of the module');
});

// The clock constants the profile names carry the values it quotes.
test('TestProfileClockCrossReferences', (t) => {
  const doc = specText(t, PROFILE);
  if (doc === undefined) return;
  const table = section(doc, '## 8. Reference implementation (informative)');
  const re = /^\| `clock\.(BaselineSkew|MaxLifetime\(clock\.(\w+)\))` \| (\d+) seconds? \|/;
  const want = new Map<string, number>([
    ['BaselineSkew', BASELINE_SKEW_MS],
    ['Contract', maxLifetime(Artifact.CONTRACT)],
    ['Presentation', maxLifetime(Artifact.PRESENTATION)],
    ['Evidence', maxLifetime(Artifact.EVIDENCE)],
    ['Snapshot', maxLifetime(Artifact.SNAPSHOT)],
    ['Outcome', maxLifetime(Artifact.OUTCOME)],
    ['Profile', maxLifetime(Artifact.PROFILE)],
  ]);
  const seen = new Set<string>();
  for (const line of table.split('\n')) {
    const m = re.exec(line);
    if (m === null) continue;
    const key = m[1] === 'BaselineSkew' ? 'BaselineSkew' : (m[2] ?? '');
    const w = want.get(key);
    assert.ok(w !== undefined, `profile names clock constant ${key}, which the test does not know`);
    assert.equal(Number(m[3]) * 1000, w, key);
    seen.add(key);
  }
  for (const key of want.keys())
    assert.ok(seen.has(key), `profile does not cross-reference ${key}`);
});
