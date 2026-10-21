// Tests of the vectors harness entry, src/vectors/main.ts, run as a child
// process the way make ts-vectors runs it. Expected lines follow the result
// grammar of tools/parity/README.md in the source repository: one
// {"id","kind","result"} object per manifest entry on standard output and
// nothing else; the rows that are not a pass and a summary go to standard
// error. Exit status 0, 1 on a fail under a gate other than planned for ts,
// 2 on a harness error, which prints nothing on standard output.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { prefixOf } from '../src/vectors/manifest.ts';
import { cleanup, entry, tree } from './vectors/tree.ts';

after(cleanup);

const MAIN = fileURLToPath(new URL('../src/vectors/main.ts', import.meta.url));
const REPO = fileURLToPath(new URL('../..', import.meta.url));
const REPO_MANIFEST = join(REPO, 'spec', 'v1.0', 'fixtures', 'manifest.json');
const REPO_GATES = join(REPO, 'tools', 'parity', 'gates.json');

function run(args: string[], env: Record<string, string> = {}) {
  const childEnv: Record<string, string | undefined> = { ...process.env, ...env };
  if (!('PACT_REQUIRE_VECTORS' in env)) delete childEnv.PACT_REQUIRE_VECTORS;
  const r = spawnSync(process.execPath, [MAIN, ...args], { encoding: 'utf8', env: childEnv });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function manifestFile(doc: unknown, files: Record<string, unknown> = {}): string {
  return join(tree({ 'manifest.json': doc, ...files }), 'manifest.json');
}

const jcsBad = entry('vectors/jcs/a', 'vector', 'core', 'vectors/jcs/in.json', {
  expected: 'vectors/jcs/out.json',
});
const jcsFiles = {
  'vectors/jcs/in.json': '{"b":1,"a":2}',
  'vectors/jcs/out.json': 'not the canonical form',
};

test('prints one line per entry in manifest order, nothing else, and a summary on stderr', () => {
  const path = manifestFile(
    {
      manifest_version: 1,
      entries: [
        jcsBad,
        entry('adapters/_common/common-01.credential-wins', 'adapter-case', 'adapter', 'c.json'),
        entry('admission/a-01', 'evaluate', 'runner', 'admission/a-01'),
      ],
    },
    jcsFiles,
  );
  const r = run([path]);
  assert.equal(r.status, 1, r.stderr);
  assert.equal(
    r.stdout,
    '{"id":"vectors/jcs/a","kind":"vector","result":"fail"}\n' +
      '{"id":"adapters/_common/common-01.credential-wins","kind":"adapter-case","result":"fail"}\n' +
      '{"id":"admission/a-01","kind":"evaluate","result":"skipped:out-of-scope"}\n',
  );
  assert.match(r.stderr, /^FAIL vectors\/jcs\/a: /m);
  // The tree has no common case files, so the common adapter case fails.
  assert.match(
    r.stderr,
    /^FAIL adapters\/_common\/common-01\.credential-wins: the common cases do not load/m,
  );
  assert.match(r.stderr, /^0 passed, 2 failed, 1 skipped$/m);
});

test('--gates: a fail under a planned gate exits 0, under a required gate 1', () => {
  const path = manifestFile({ manifest_version: 1, entries: [jcsBad] }, jcsFiles);
  const gates = (ts: string) =>
    join(
      tree({
        'gates.json': {
          gates_version: 1,
          rows: [
            {
              scope: 'core',
              kind: 'vector',
              prefix: 'vectors/jcs',
              go: 'required',
              ts,
              py: 'planned',
              rs: 'planned',
              php: 'planned',
              flipped_by: 'x',
            },
          ],
        },
      }),
      'gates.json',
    );
  const planned = run(['--gates', gates('planned'), path]);
  assert.equal(planned.status, 0, planned.stderr);
  assert.equal(planned.stdout, '{"id":"vectors/jcs/a","kind":"vector","result":"fail"}\n');
  assert.equal(run(['--gates', gates('required'), path]).status, 1);
});

for (const [name, doc] of [
  ['an unknown kind', { manifest_version: 1, entries: [entry('a/b', 'vectr', 'core', 'a')] }],
  ['an unknown scope', { manifest_version: 1, entries: [entry('a/b', 'vector', 'cor', 'a')] }],
  [
    'an unknown prefix of an in-scope vector',
    { manifest_version: 1, entries: [entry('vectors/nope/b', 'vector', 'core', 'a')] },
  ],
  [
    'an unknown capability',
    {
      manifest_version: 1,
      entries: [entry('a/b', 'evaluate', 'runner', 'a', { capabilities: ['x'] })],
    },
  ],
  ['a missing kind', { manifest_version: 1, entries: [{ id: 'a/b', scope: 'core' }] }],
  ['a non-string id', { manifest_version: 1, entries: [{ id: 7, kind: 'vector', scope: 'core' }] }],
  ['an unknown manifest_version', { manifest_version: 2, entries: [] }],
  ['entries that are not an array', { manifest_version: 1, entries: {} }],
  ['a document that is not JSON', '{"manifest_version": 1, "entries": ['],
] as const) {
  test(`exits 2 with nothing on standard output on ${name}`, () => {
    const good = entry('admission/ok', 'evaluate', 'runner', 'ok');
    const withGood =
      typeof doc === 'string' || !Array.isArray(doc.entries)
        ? doc
        : { ...doc, entries: [good, ...doc.entries] };
    const r = run([manifestFile(withGood)]);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, '');
    assert.notEqual(r.stderr, '');
  });
}

test('usage errors exit 2 with nothing on standard output', () => {
  const path = manifestFile({ manifest_version: 1, entries: [] });
  for (const args of [
    [],
    [path, path],
    ['--gates'],
    ['--capability'],
    ['--capability', 'jws-rsa', path],
    ['--frob', path],
  ]) {
    const r = run(args);
    assert.equal(r.status, 2, args.join(' '));
    assert.equal(r.stdout, '');
  }
  assert.equal(run(['--capability', 'jws-ed25519', path]).status, 0);
  assert.equal(run(['--gates', join(tree({}), 'absent.json'), path]).status, 2);
});

test('an absent manifest is a notice unless PACT_REQUIRE_VECTORS=1', () => {
  const absent = join(tree({}), 'absent', 'manifest.json');
  const lenient = run([absent]);
  assert.equal(lenient.status, 0, lenient.stderr);
  assert.equal(lenient.stdout, '');
  assert.match(lenient.stderr, /NOTICE/);
  const strict = run([absent], { PACT_REQUIRE_VECTORS: '1' });
  assert.equal(strict.status, 2);
  assert.equal(strict.stdout, '');
});

test('repository manifest and gates: one valid line per entry; status 1 only on a fail under a non-planned ts gate', (t) => {
  if (!existsSync(REPO_MANIFEST) || !existsSync(REPO_GATES)) {
    if (process.env.PACT_REQUIRE_VECTORS === '1' && !existsSync(REPO_MANIFEST)) {
      assert.fail(`PACT_REQUIRE_VECTORS=1 and ${REPO_MANIFEST} is absent`);
    }
    t.skip('NOTICE: spec/v1.0/fixtures/manifest.json or tools/parity/gates.json absent');
    return;
  }
  const doc = JSON.parse(readFileSync(REPO_MANIFEST, 'utf8')) as {
    entries: { id: string; kind: string; scope: string }[];
  };
  const gates = JSON.parse(readFileSync(REPO_GATES, 'utf8')) as {
    rows: { scope: string; kind: string; prefix: string; ts: string }[];
  };
  const r = run(['--gates', REPO_GATES, REPO_MANIFEST]);
  const lines = r.stdout
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { id: string; kind: string; result: string });
  assert.deepEqual(
    lines.map((l) => [l.id, l.kind]),
    doc.entries.map((e) => [e.id, e.kind]),
  );
  const grammar = /^(?:pass|fail|skipped:(?:out-of-scope|spec-defect|os-layer|capability))$/;
  for (const l of lines) assert.match(l.result, grammar, l.id);
  const gate = new Map(gates.rows.map((g) => [`${g.scope} ${g.kind} ${g.prefix}`, g.ts]));
  const redUnderGate = doc.entries.some(
    (e, i) =>
      lines[i]?.result === 'fail' &&
      gate.get(`${e.scope} ${e.kind} ${prefixOf(e.id)}`) !== 'planned',
  );
  assert.equal(r.status, redUnderGate ? 1 : 0, r.stderr.split('\n').slice(-3).join('\n'));
  assert.match(r.stderr, /^\d+ passed, \d+ failed, \d+ skipped$/m);
});
