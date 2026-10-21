// The shared fixture tree, spec/v1.0/fixtures, for the ported vector tests of the
// core primitives: the manifest entries of one group and the files they
// name, read strictly as the Go tests read them (strictjson, 2 MiB). Absent
// in the package mirror: a NOTICE skip there, a failure under
// PACT_REQUIRE_VECTORS=1.

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { TestContext } from 'node:test';
import { parse } from '../../src/core/strictjson.ts';
import { REPO } from './repo.ts';

export const FIXTURES = join(REPO, 'spec', 'v1.0', 'fixtures');

const LIMITS = { maxBytes: 2 << 20 };

/** One manifest entry, the members every language reads. */
export interface ManifestEntry {
  readonly id: string;
  readonly kind: string;
  readonly scope: string;
  readonly path: string;
  readonly expected: string | null;
  readonly outcome: string | null;
  readonly spec_map_row: string;
  readonly draft_section: string;
  readonly capabilities?: readonly string[];
}

/** False after a NOTICE skip when spec/v1.0/fixtures is absent (package mirror). */
export function fixturesPresent(t: TestContext): boolean {
  if (existsSync(join(FIXTURES, 'manifest.json'))) return true;
  if (process.env.PACT_REQUIRE_VECTORS === '1')
    assert.fail(`PACT_REQUIRE_VECTORS=1 and ${FIXTURES} is absent`);
  t.skip(`NOTICE: ${FIXTURES} absent (package mirror)`);
  return false;
}

/** The bytes of a fixture, by its manifest path. */
export function readFixture(rel: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES, ...rel.split('/'))));
}

/** A fixture strictly parsed. */
export function readFixtureJSON(rel: string): unknown {
  return parse(readFixture(rel), LIMITS);
}

/** The manifest entries whose id starts with prefix, in manifest order. */
export function manifestEntries(prefix: string): ManifestEntry[] {
  const m = readFixtureJSON('manifest.json') as {
    manifest_version: number;
    entries: ManifestEntry[];
  };
  assert.equal(m.manifest_version, 1, 'manifest_version');
  return m.entries.filter((e) => e.id.startsWith(prefix));
}

/** Every file under the fixture directory dir, as a manifest path. */
export function filesUnder(dir: string): string[] {
  const root = join(FIXTURES, ...dir.split('/'));
  return readdirSync(root, { withFileTypes: true, recursive: true })
    .filter((d) => d.isFile())
    .map((d) => relative(FIXTURES, join(d.parentPath, d.name)).split(sep).join('/'))
    .sort();
}

const utf8 = new TextEncoder();
const text = new TextDecoder();

export function bytes(s: string): Uint8Array {
  return utf8.encode(s);
}

export function str(b: Uint8Array): string {
  return text.decode(b);
}
