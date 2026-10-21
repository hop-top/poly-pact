// Tables of the vectors harness against their sources: the kinds, scopes and
// capabilities of the manifest format, which the harness reads from the
// runner/manifest module (Go runner/manifest Kinds(), Scopes(),
// Capabilities(), spec/v1.0/fixtures/README.md), the JWS reasons (Go
// core/jws/errors.go), and the repository manifest and vectors that use
// them. The Go sources sit outside the package: a check that needs one is
// skipped where it is absent (package mirror, mutation copy).

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { type TestContext, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Reason } from '../src/core/jws/index.ts';
import { capabilities, kinds, scopes } from '../src/runner/manifest/index.ts';
import { RUNNERS } from '../src/vectors/harness.ts';
import { prefixOf } from '../src/vectors/manifest.ts';

const REPO = fileURLToPath(new URL('../..', import.meta.url));
const MANIFEST = join(REPO, 'spec', 'v1.0', 'fixtures', 'manifest.json');
const GO_RULES = join(REPO, 'go', 'runner', 'manifest', 'rules.go');
const GO_JWS_ERRORS = join(REPO, 'go', 'core', 'jws', 'errors.go');
const JWS_VECTORS = join(REPO, 'spec', 'v1.0', 'fixtures', 'vectors', 'jws');

function needSpec(t: TestContext, path: string): boolean {
  if (existsSync(path)) return true;
  if (process.env.PACT_REQUIRE_VECTORS === '1')
    assert.fail(`PACT_REQUIRE_VECTORS=1 and ${path} is absent`);
  t.skip(`NOTICE: ${path} absent (package mirror)`);
  return false;
}

function goSource(t: TestContext, path: string): string | undefined {
  if (existsSync(path)) return readFileSync(path, 'utf8');
  t.skip(`${path} absent`);
  return undefined;
}

// The string constants of a Go const block whose type is typ, in source order.
function goConstants(source: string, typ: string): string[] {
  const re = new RegExp(`^\\s*\\w+\\s+${typ}\\s*=\\s*"([^"]+)"`, 'gm');
  return [...source.matchAll(re)].map((m) => m[1] ?? '');
}

// The names listed by a Go slice literal `var name = []T{A, B, ...}`.
function goList(source: string, name: string): string[] {
  const m = new RegExp(`var ${name} = \\[\\]\\w+\\{([^}]*)\\}`).exec(source);
  assert.ok(m, `var ${name} not found`);
  return (m[1] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function goNamedConstants(source: string): Map<string, string> {
  const re = /^\s*(\w+)\s+(?:\w+\s+)?=\s*"([^"]+)"/gm;
  return new Map([...source.matchAll(re)].map((m) => [m[1] ?? '', m[2] ?? '']));
}

interface ManifestDoc {
  entries: { id: string; kind: string; scope: string }[];
}

test('the kind table is the closed set of the manifest format, in Go order', () => {
  const KINDS = kinds();
  // 13 kinds, transport, mcp, profile and source-case among them.
  assert.deepEqual(KINDS, [
    'key',
    'vector',
    'schema',
    'evaluate',
    'outcomes',
    'learning',
    'adapter-case',
    'adapter-asset',
    'source-case',
    'profile-invalid',
    'transport',
    'mcp',
    'profile',
  ]);
  assert.deepEqual(scopes(), ['core', 'runner', 'adapter']);
  assert.deepEqual(capabilities(), ['jws-ed25519']);
});

test('the kind, scope and capability tables equal Go runner/manifest', (t) => {
  const src = goSource(t, GO_RULES);
  if (src === undefined) return;
  const named = goNamedConstants(src);
  const resolve = (names: string[]) => names.map((n) => named.get(n) ?? `<${n}>`);
  assert.deepEqual(resolve(goList(src, 'kinds')), kinds());
  assert.deepEqual(resolve(goList(src, 'scopes')), scopes());
  assert.deepEqual(resolve(goList(src, 'capabilities')), capabilities());
});

test("the repository manifest's kinds and scopes are a subset of the tables", (t) => {
  if (!needSpec(t, MANIFEST)) return;
  const doc = JSON.parse(readFileSync(MANIFEST, 'utf8')) as ManifestDoc;
  const used = new Set(doc.entries.map((e) => e.kind));
  const usedScopes = new Set(doc.entries.map((e) => e.scope));
  assert.deepEqual(
    [...used].filter((k) => !kinds().includes(k)),
    [],
  );
  assert.deepEqual(
    [...usedScopes].filter((s) => !scopes().includes(s)),
    [],
  );
});

test('every vector and key prefix of scope core or adapter in the manifest has a runner', (t) => {
  if (!needSpec(t, MANIFEST)) return;
  const doc = JSON.parse(readFileSync(MANIFEST, 'utf8')) as ManifestDoc;
  const prefixes = new Set(
    doc.entries
      .filter((e) => (e.kind === 'vector' || e.kind === 'key') && e.scope !== 'runner')
      .map((e) => `${e.kind} ${prefixOf(e.id)}`),
  );
  assert.deepEqual(
    [...prefixes].filter((p) => !Object.hasOwn(RUNNERS, p)),
    [],
  );
  assert.deepEqual(Object.keys(RUNNERS).sort(), [...prefixes].sort(), 'no runner without entries');
});

test('the JWS reason table equals go/core/jws/errors.go, in order', (t) => {
  const src = goSource(t, GO_JWS_ERRORS);
  if (src === undefined) return;
  assert.deepEqual(Object.values(Reason), goConstants(src, 'Reason'));
});

test('every reject_reason of the JWS vectors is a Reason or the harness reason payload-schema', (t) => {
  if (!needSpec(t, JWS_VECTORS)) return;
  const known = new Set<string>([...Object.values(Reason), 'payload-schema']);
  const seen = new Set<string>();
  const visit = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(visit);
    else if (typeof v === 'object' && v !== null) {
      for (const [k, x] of Object.entries(v)) {
        if (k === 'reject_reason' && typeof x === 'string') seen.add(x);
        else visit(x);
      }
    }
  };
  for (const f of readdirSync(JWS_VECTORS).filter((n) => n.endsWith('.json'))) {
    visit(JSON.parse(readFileSync(join(JWS_VECTORS, f), 'utf8')));
  }
  assert.ok(seen.size > 0);
  assert.deepEqual(
    [...seen].filter((r) => !known.has(r)),
    [],
  );
});

test('prefixOf takes two segments under vectors/, adapters/ and sources/', () => {
  assert.equal(prefixOf('vectors/jcs/numbers'), 'vectors/jcs');
  assert.equal(prefixOf('adapters/_common/c-01'), 'adapters/_common');
  assert.equal(prefixOf('sources/scim/a'), 'sources/scim');
  assert.equal(prefixOf('keys/holder'), 'keys');
  assert.equal(prefixOf('admission/a-01'), 'admission');
  assert.equal(prefixOf('vectors/x'), 'vectors');
});
