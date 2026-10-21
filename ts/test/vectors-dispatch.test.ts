// Entry handling of the vectors harness (tools/parity/README.md, Result
// grammar and Entry handling): which entries run, the skipped reasons, the closed sets, the
// line shape and the exit status under the gates file. Run in process with
// runManifest; vectors-main.test.ts covers the command line.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../src/core/jcs.ts';
import { NotImplementedError } from '../src/internal/notimplemented.ts';
import { type Core, defaultCore } from '../src/vectors/core.ts';
import { loadGates } from '../src/vectors/gates.ts';
import { type Line, runManifest } from '../src/vectors/harness.ts';
import { HarnessError, prefixOf } from '../src/vectors/manifest.ts';
import { evaluateAdapterCases } from '../src/vectors/run-adapter-cases.ts';
import { cleanup, entry, fake, poisoned, tree } from './vectors/tree.ts';

after(cleanup);

const REPO_MANIFEST = fileURLToPath(
  new URL('../../spec/v1.0/fixtures/manifest.json', import.meta.url),
);

function manifest(entries: unknown[], files: Record<string, unknown> = {}): string {
  const root = tree({ 'manifest.json': { manifest_version: 1, entries }, ...files });
  return join(root, 'manifest.json');
}

function results(lines: readonly Line[]): string[] {
  return lines.map((l) => `${l.id} ${l.result}`);
}

const outOfScope = [
  entry('admission/a-01', 'evaluate', 'runner', 'admission/a-01'),
  entry('reputation/beta', 'vector', 'runner', 'reputation/beta.json'),
  entry('vectors/nope/x', 'vector', 'runner', 'x.json'),
  entry('adapters/basic/c-01', 'adapter-case', 'adapter', 'c.json'),
  entry('adapters/aws/asset', 'adapter-asset', 'adapter', 'a.json', {
    expected: null,
    outcome: null,
  }),
  entry('sources/scim/s-01', 'source-case', 'adapter', 's.json', { expected: null, outcome: null }),
  entry('schema/appendix-b', 'schema', 'core', 'schema/b.json'),
  entry('parse/x', 'schema', 'core', 'parse/x.json'),
  entry('profiles/p', 'profile-invalid', 'runner', 'p.json'),
  entry('transport/t', 'transport', 'runner', 't.json'),
  entry('mcp/m', 'mcp', 'adapter', 'm.json'),
  entry('profile/p', 'profile', 'runner', 'p.json'),
  entry('admission/ed', 'evaluate', 'runner', 'ed', { capabilities: ['jws-ed25519'] }),
];

test('runner-scope entries and kinds other than vector and key are skipped:out-of-scope, never run', () => {
  const run = runManifest(manifest(outOfScope), { core: poisoned });
  assert.deepEqual(
    run.lines,
    outOfScope.map((e) => ({ id: e.id, kind: e.kind, result: 'skipped:out-of-scope' })),
  );
  assert.equal(run.status, 0);
  assert.deepEqual([run.passed, run.failed, run.skipped], [0, 0, outOfScope.length]);
});

// The common adapter cases take the result of the adapter-case leg
// (run-adapter-cases.ts); a case the leg did not run, or could not load,
// fails and never passes or skips.
test('a common adapter case takes the result of the adapter-case leg', () => {
  const ids = ['adapters/_common/c-01.a', 'adapters/_common/c-02.b', 'adapters/_common/c-03.c'];
  const entries = ids.map((id) => entry(id, 'adapter-case', 'adapter', `${id}.json`));
  const byId = new Map([
    [ids[0] as string, { passed: true, failures: [] }],
    [ids[1] as string, { passed: false, failures: ['dedicated: wrong outcome'] }],
  ]);
  const run = runManifest(manifest(entries), {
    core: poisoned,
    adapterCases: { results: byId, loadError: '' },
  });
  assert.deepEqual(results(run.lines), [`${ids[0]} pass`, `${ids[1]} fail`, `${ids[2]} fail`]);
  assert.match(run.details[0] ?? '', /dedicated: wrong outcome/);
  assert.match(run.details[1] ?? '', /no common case of the fixture tree has this id/);
  const none = runManifest(manifest(entries), { core: poisoned });
  assert.deepEqual(
    results(none.lines),
    ids.map((id) => `${id} fail`),
    'without the leg',
  );
  const broken = runManifest(manifest(entries), {
    core: poisoned,
    adapterCases: { results: new Map(), loadError: 'no case files' },
  });
  assert.match(broken.details[0] ?? '', /do not load: no case files/);
});

test('an in-scope entry whose capabilities are not declared is skipped:capability, naming them', () => {
  const e = entry('vectors/jws/ed', 'vector', 'core', 'vectors/jws/ed.json', {
    capabilities: ['jws-ed25519'],
  });
  const run = runManifest(manifest([e]), { core: poisoned });
  assert.deepEqual(run.lines, [
    {
      id: e.id,
      kind: 'vector',
      result: 'skipped:capability',
      missing_capabilities: ['jws-ed25519'],
    },
  ]);
  const declared = runManifest(manifest([e]), { core: poisoned, capabilities: ['jws-ed25519'] });
  assert.deepEqual(results(declared.lines), [`${e.id} fail`]);
});

test('an unknown kind, scope, capability or in-scope prefix, or a repeated id, is a harness error', () => {
  const bad = [
    [entry('vectors/jcs/a', 'vectr', 'core', 'a.json')],
    [entry('vectors/jcs/a', 'vector', 'cor', 'a.json')],
    [entry('vectors/jcs/a', 'vector', 'core', 'a.json', { capabilities: ['jws-rsa'] })],
    [entry('vectors/nope/a', 'vector', 'core', 'a.json')],
    [entry('vectors/nope/a', 'vector', 'adapter', 'a.json')],
    [entry('vectors/a', 'vector', 'core', 'a.json')],
    [entry('jcs/a', 'vector', 'core', 'a.json')],
    [entry('notkeys/holder', 'key', 'core', 'h.json')],
    [
      entry('admission/a', 'evaluate', 'runner', 'a'),
      entry('admission/a', 'evaluate', 'runner', 'a'),
    ],
  ];
  for (const entries of bad) {
    assert.throws(
      () => runManifest(manifest(entries), { core: poisoned }),
      HarnessError,
      JSON.stringify(entries),
    );
  }
  assert.throws(
    () => runManifest(manifest([]), { core: poisoned, capabilities: ['jws-rsa'] }),
    HarnessError,
  );
});

test('a malformed manifest is a harness error', () => {
  for (const doc of [
    [],
    { manifest_version: 2, entries: [] },
    { manifest_version: 1, entries: {} },
    { manifest_version: 1, entries: [7] },
    { manifest_version: 1, entries: [{ id: 'a/b', kind: 'vector' }] },
    { manifest_version: 1, entries: [{ id: 7, kind: 'vector', scope: 'core', path: 'a' }] },
    { manifest_version: 1, entries: [{ id: 'a/b', kind: 'evaluate', scope: 'runner' }] },
  ]) {
    const root = tree({ 'manifest.json': doc });
    assert.throws(
      () => runManifest(join(root, 'manifest.json'), { core: poisoned }),
      HarnessError,
      JSON.stringify(doc),
    );
  }
  const root = tree({ 'manifest.json': '{"manifest_version": 1, "entries": [' });
  assert.throws(() => runManifest(join(root, 'manifest.json'), { core: poisoned }), HarnessError);
});

// The harness reads the manifest through runner/manifest: the strict parse
// of draft section 7.1 and manifest_version as written.
test('a manifest that is not strict JSON or not version 1 as written is a harness error', () => {
  for (const text of [
    '{"manifest_version": 1, "entries": [], "entries": []}',
    '{"manifest_version": 1, "entries": [{"id": "a/b", "id": "a/c"}]}',
    '{"manifest_version": 1.0, "entries": []}',
    '{"manifest_version": 1e0, "entries": []}',
    '{"manifest_version": 1, "entries": [], "generated": true}',
  ]) {
    const root = tree({ 'manifest.json': text });
    assert.throws(
      () => runManifest(join(root, 'manifest.json'), { core: poisoned }),
      HarnessError,
      text,
    );
  }
});

const jcsBad = entry('vectors/jcs/a', 'vector', 'core', 'vectors/jcs/in.json', {
  expected: 'vectors/jcs/out.json',
});
const jcsFiles = { 'vectors/jcs/in.json': '{}', 'vectors/jcs/out.json': 'not canonical' };
const identity: Core = fake({ canonicalize: (b) => b });

function gatesFile(rows: unknown[]): string {
  const root = tree({ 'gates.json': { gates_version: 1, rows } });
  return join(root, 'gates.json');
}

function row(ts: string, more: Record<string, unknown> = {}) {
  return {
    scope: 'core',
    kind: 'vector',
    prefix: 'vectors/jcs',
    go: 'required',
    ts,
    py: 'planned',
    rs: 'planned',
    php: 'planned',
    flipped_by: 'x',
    ...more,
  };
}

test('a fail makes the status 1, unless its gate is planned for ts', () => {
  const path = manifest([jcsBad], jcsFiles);
  const bare = runManifest(path, { core: identity });
  assert.deepEqual(results(bare.lines), ['vectors/jcs/a fail']);
  assert.equal(bare.status, 1, 'no gates file: every gate counts as required');
  assert.equal(
    runManifest(path, { core: identity, gates: loadGates(gatesFile([row('planned')])) }).status,
    0,
  );
  assert.equal(
    runManifest(path, { core: identity, gates: loadGates(gatesFile([row('required')])) }).status,
    1,
  );
  assert.equal(
    runManifest(path, { core: identity, gates: loadGates(gatesFile([row('n/a')])) }).status,
    1,
  );
  assert.equal(
    runManifest(path, {
      core: identity,
      gates: loadGates(gatesFile([row('planned', { prefix: 'vectors/jws' })])),
    }).status,
    1,
    'a fail without a gate row counts as required',
  );
});

test('a malformed gates file is a harness error', () => {
  for (const doc of [
    [],
    { gates_version: 2, rows: [] },
    { gates_version: 1, rows: {} },
    { gates_version: 1, rows: [row('maybe')] },
    { gates_version: 1, rows: [{ scope: 'core' }] },
  ]) {
    const root = tree({ 'gates.json': doc });
    assert.throws(() => loadGates(join(root, 'gates.json')), HarnessError, JSON.stringify(doc));
  }
  assert.throws(() => loadGates(join(tree({}), 'absent.json')), HarnessError);
});

test('every row that is not a pass goes to the detail list, then a summary', () => {
  const ok = entry('vectors/jcs/b', 'vector', 'core', 'vectors/jcs/in.json', {
    expected: 'vectors/jcs/in.json',
  });
  const run = runManifest(manifest([jcsBad, ok, outOfScope[0]], jcsFiles), {
    core: fake({ canonicalize: (b) => b }),
  });
  assert.deepEqual(results(run.lines), [
    'vectors/jcs/a fail',
    'vectors/jcs/b fail',
    'admission/a-01 skipped:out-of-scope',
  ]);
  assert.equal(run.details.length, 3);
  assert.match(run.details[0] ?? '', /^FAIL vectors\/jcs\/a: /);
  assert.match(run.details[2] ?? '', /^SKIP admission\/a-01: /);
  assert.equal(run.summary, '0 passed, 2 failed, 1 skipped');
});

// The RED evidence: on the repository manifest, every in-scope entry of a
// group whose module is still a stub fails with a not-implemented detail,
// and every other entry is classified as tools/parity/README.md says.
test('repository manifest: classification, and every entry of a stubbed group fails', async (t) => {
  if (!existsSync(REPO_MANIFEST)) {
    if (process.env.PACT_REQUIRE_VECTORS === '1')
      assert.fail(`PACT_REQUIRE_VECTORS=1 and ${REPO_MANIFEST} is absent`);
    t.skip('NOTICE: spec/v1.0/fixtures/manifest.json absent (package mirror)');
    return;
  }
  const doc = JSON.parse(readFileSync(REPO_MANIFEST, 'utf8')) as {
    entries: { id: string; kind: string; scope: string; capabilities?: string[] }[];
  };
  const adapterCases = await evaluateAdapterCases(dirname(REPO_MANIFEST));
  const run = runManifest(REPO_MANIFEST, { core: defaultCore, adapterCases });
  assert.deepEqual(
    run.lines.map((l) => l.id),
    doc.entries.map((e) => e.id),
  );
  const stubbed = (f: () => unknown): boolean => {
    try {
      f();
      return false;
    } catch (err) {
      return err instanceof NotImplementedError;
    }
  };
  const stubGroups = new Set(
    Object.entries({
      'vectors/jcs': () => canonicalize('{}'),
      'vectors/digest': () => defaultCore.bytesDigest(new Uint8Array()),
      'vectors/strictjson': () => defaultCore.decodeOperationContext(new Uint8Array()),
      'vectors/jws': () => defaultCore.thumbprint({ kty: 'EC', crv: 'P-256', x: '', y: '' }),
      'vectors/schema': () => defaultCore.uriFormat(''),
      'vectors/binding': () =>
        defaultCore.fromRequest(
          {
            origin: '',
            headerAllowlist: [],
            headerNormalizationId: '',
            mappingVersion: '',
            maxBody: 0,
          },
          { method: 'GET', rawRequestURI: '/', headers: [], body: new Uint8Array() },
          '',
          '',
          [],
        ),
      keys: () => defaultCore.parseJWK(new Uint8Array(), []),
    })
      .filter(([, f]) => stubbed(f))
      .map(([g]) => g),
  );
  const details = new Map(run.details.map((d) => [d.split(': ')[0]?.split(' ')[1], d]));
  let red = 0;
  let inScopeCount = 0;
  for (const [i, e] of doc.entries.entries()) {
    const line = run.lines[i];
    assert.ok(line);
    // The common adapter cases pass against the memory adapter.
    if (e.kind === 'adapter-case' && prefixOf(e.id) === 'adapters/_common') {
      assert.equal(line.result, 'pass', `${e.id}: ${details.get(e.id) ?? ''}`);
      continue;
    }
    const inScope =
      (e.kind === 'vector' || e.kind === 'key') && e.scope !== 'runner' && e.id !== 'keys/ed25519';
    if (!inScope) {
      assert.equal(line.result, 'skipped:out-of-scope', e.id);
      continue;
    }
    inScopeCount += 1;
    assert.ok(
      ['pass', 'fail', 'skipped:spec-defect', 'skipped:capability'].includes(line.result),
      e.id,
    );
    if (stubGroups.has(prefixOf(e.id))) {
      assert.equal(line.result, 'fail', e.id);
      assert.match(details.get(e.id) ?? '', /not implemented/, e.id);
      red += 1;
    }
  }
  assert.ok(inScopeCount > 0);
  if (stubGroups.size === 7)
    assert.equal(red, inScopeCount, 'every in-scope entry is red on stubs');
});
