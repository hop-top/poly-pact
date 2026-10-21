// Helpers of the runner/manifest tests, ported from
// go/runner/manifest/helpers_test.go: the base manifest, tree and spec map,
// and the rule assertions. Not a test file (the test glob is *.test.ts).

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after } from 'node:test';
import { load, type Manifest, type Problems } from '../../src/runner/manifest/index.ts';
import { REPO } from './repo.ts';

/** spec/v1.0/fixtures of the source repository. */
export const REPO_FIXTURES = join(REPO, 'spec', 'v1.0', 'fixtures');
/** spec/v1.0/spec-map.md of the source repository. */
export const REPO_SPEC_MAP = join(REPO, 'spec', 'v1.0', 'spec-map.md');

/** One manifest entry as written, so a test can break any member. */
export type RawEntry = Record<string, unknown>;

/** A valid manifest: one entry of each shape the tests need, sorted by id. */
export function baseEntries(): RawEntry[] {
  return [
    {
      id: 'adapters/db/schema',
      kind: 'adapter-asset',
      scope: 'adapter',
      path: 'adapters/db/assets',
      expected: null,
      outcome: null,
      spec_map_row: 'CL-C',
      draft_section: '17.1',
    },
    {
      id: 'admission/valid',
      kind: 'evaluate',
      scope: 'runner',
      path: 'admission/valid',
      expected: 'expected/admission/valid/decision.json',
      outcome: 'ADMISSIBLE',
      spec_map_row: 'CL-11.3',
      draft_section: '11.3',
    },
    {
      id: 'keys/holder',
      kind: 'key',
      scope: 'core',
      path: 'keys/holder.jwk.json',
      expected: null,
      outcome: null,
      spec_map_row: 'CL-C',
      draft_section: 'C',
    },
    {
      id: 'vectors/jcs/arrays',
      kind: 'vector',
      scope: 'core',
      path: 'vectors/jcs/input/arrays.json',
      expected: 'vectors/jcs/output/arrays.json',
      outcome: 'ACCEPTED',
      spec_map_row: 'CL-C',
      draft_section: '7.4',
    },
  ];
}

/** The files of the base tree, other than manifest.json. */
export const BASE_FILES = [
  'README.md',
  'manifest.schema.json',
  'adapters/README.md',
  'adapters/db/assets/schema.sql',
  'admission/valid/config.json',
  'admission/valid/signed/contract.jws',
  'expected/admission/valid/decision.json',
  'keys/README.md',
  'keys/holder.jwk.json',
  'vectors/jcs/input/arrays.json',
  'vectors/jcs/output/arrays.json',
];

/**
 * Cites every base entry's row. Every group of the base entries and rows has
 * a status: admission is partial (admission/valid is registered,
 * admission/wrong-tenant is reserved), approval and parse are planned, and
 * adapters, keys and vectors are landed.
 */
export const BASE_SPEC_MAP =
  '# Spec map\n\n' +
  '## Fixture groups\n\n' +
  '| Group | Directory | Covers | Status |\n' +
  '|---|---|---|---|\n' +
  '| admission | `fixtures/admission/` | Positive control | partial |\n' +
  '| approval | `fixtures/approval/` | Approval states | planned |\n' +
  '| parse | `fixtures/parse/` | Strict parse \\| JWS | planned |\n' +
  '| adapters | `fixtures/adapters/` | Adapter cases | landed |\n' +
  '| keys | `fixtures/keys/` | Test keys | landed |\n' +
  '| vectors | `fixtures/vectors/` | Vectors | landed |\n\n' +
  '## Conformance map\n\n' +
  '| ID | Check | Draft section | Finding | Fixture(s) |\n' +
  '|----|-------|---------------|---------|------------|\n' +
  '| CL-11.3 | Positive control | 11.3 | G13 | admission/valid, admission/wrong-tenant |\n' +
  '| CL-C | Test keys | C | G13 | keys/holder |\n' +
  '| CL-17.3.1 | Approval | 17.3 | G06 | approval/pending, parse/alg-none |\n\n' +
  '```\n## Not a section\n```\n';

/** entries as a manifest document. */
export function encode(entries: readonly RawEntry[]): string {
  return JSON.stringify({ manifest_version: 1, entries }, null, 2);
}

const dirs: string[] = [];
after(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A new scratch directory, removed after the file's tests. */
export function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'pact-manifest-'));
  dirs.push(d);
  return d;
}

/** A temporary fixtures directory with a spec map beside it. */
export class Tree {
  /** The parent of fixtures/ and spec-map.md. */
  readonly dir: string;
  /** The fixtures directory. */
  readonly root: string;
  readonly specMap: string;

  constructor(entries: readonly RawEntry[]) {
    this.dir = tempDir();
    this.root = join(this.dir, 'fixtures');
    this.specMap = join(this.dir, 'spec-map.md');
    for (const f of BASE_FILES) this.write(f, '{}');
    this.write('manifest.json', encode(entries));
    writeFileSync(this.specMap, BASE_SPEC_MAP);
  }

  write(rel: string, content: string): void {
    const full = join(this.root, ...rel.split('/'));
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }

  remove(rel: string): void {
    rmSync(join(this.root, ...rel.split('/')), { recursive: true, force: true });
  }

  setSpecMap(text: string): void {
    writeFileSync(this.specMap, text);
  }

  manifest(): Manifest {
    return load(this.root);
  }
}

/** The distinct rules of ps, sorted. */
export function rules(ps: Problems): string[] {
  return [...new Set(ps.map((p) => p.rule))].sort();
}

/**
 * Fails unless ps has a problem of rule whose where is where (any where when
 * where is empty), and no problem of another rule.
 */
export function wantRule(ps: Problems, rule: string, where: string): void {
  const unexpected = ps.filter((p) => p.rule !== rule).map(String);
  assert.deepEqual(unexpected, [], `unexpected problems besides ${rule}`);
  assert.ok(
    ps.some((p) => where === '' || p.where === where),
    `no ${rule} problem at ${JSON.stringify(where)}; got:\n${ps.message}`,
  );
}

/** Fails unless ps has a problem of rule at where; other problems are allowed. */
export function wantWhere(ps: Problems, rule: string, where: string): void {
  assert.ok(
    ps.some((p) => p.rule === rule && p.where === where),
    `no ${rule} problem at ${where}:\n${ps.message}`,
  );
}

export function wantClean(ps: Problems): void {
  assert.equal(ps.length, 0, `want no problems, got:\n${ps.message}`);
}

/** Fails unless s contains every part. */
export function mustContain(s: string, ...parts: string[]): void {
  for (const p of parts) assert.ok(s.includes(p), `${JSON.stringify(s)} does not contain ${p}`);
}
