/**
 * The case-file loader of the adapter conformance suite (Go
 * hop.top/pact-go/adapter/adaptertest, casefile.go: Load and DefaultFixtures):
 * the case files of a fixture tree, the workload mode of a case, and the
 * fixture trees the suite reads.
 *
 * @module
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCase } from './casedecode.ts';
import type { Case } from './casefile.ts';
import type { FixtureTree } from './harness.ts';
import { COMMON_DIR, WORKLOADS_DEDICATED, WORKLOADS_SHARED } from './names.ts';

export { parseCase } from './casedecode.ts';
export {
  ARRIVAL_DIRECT,
  CASE_VERSION,
  COMMON_DIR,
  FN,
  FUNCTION_OUTCOMES,
  MAX_CASE_BYTES,
  OUT,
  WORKLOADS_DEDICATED,
  WORKLOADS_SHARED,
} from './names.ts';

const ADAPTER_NAME_PATTERN = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

// The cases of adapters/_common, as Load marked them (Go Case.common).
const COMMON = new WeakSet<Case>();

/** Whether `c` is a case of adapters/_common as {@link loadCases} read it. */
export function isCommon(c: Case): boolean {
  return COMMON.has(c);
}

function loadDir(fixtures: FixtureTree, dir: string): Case[] {
  let names: readonly string[];
  try {
    names = fixtures.list(dir);
  } catch (err) {
    throw new Error(`adaptertest: read ${dir}: ${(err as Error).message}`);
  }
  const cases: Case[] = [];
  for (const name of [...names].sort()) {
    if (!name.endsWith('.json')) continue;
    const file = `${dir}/${name}`;
    let data: Uint8Array;
    try {
      data = fixtures.read(file);
    } catch (err) {
      throw new Error(`adaptertest: read ${file}: ${(err as Error).message}`);
    }
    try {
      cases.push(parseCase(data));
    } catch (err) {
      throw new Error(`adaptertest: ${file}: ${(err as Error).message}`);
    }
  }
  return cases;
}

/**
 * Reads the common cases and, when `adapter` is not empty, the cases in
 * adapters/<adapter>, from `fixtures` (Go `Load`). An adapter's case files
 * sit directly in its directory, as the common cases do; a subdirectory is
 * not read. A case file that does not strict-parse, or breaks a rule of the
 * format, throws.
 */
export function loadCases(fixtures: FixtureTree, adapter = ''): Case[] {
  const cases = loadDir(fixtures, COMMON_DIR);
  if (cases.length === 0) throw new Error(`adaptertest: no case files in ${COMMON_DIR}`);
  for (const c of cases) COMMON.add(c);
  if (adapter !== '') {
    if (!ADAPTER_NAME_PATTERN.test(adapter)) {
      throw new Error(
        `adaptertest: adapter name ${JSON.stringify(adapter)} is not a lowercase hyphenated name`,
      );
    }
    const own = loadDir(fixtures, `adapters/${adapter}`);
    if (own.length === 0) throw new Error(`adaptertest: no case files in adapters/${adapter}`);
    cases.push(...own);
  }
  const seen = new Set<string>();
  for (const c of cases) {
    if (seen.has(c.id)) throw new Error(`adaptertest: case id ${c.id} is used twice`);
    seen.add(c.id);
  }
  return cases;
}

/**
 * Whether the case runs against an adapter whose profile supports
 * workloads shared by several agents (`shared` true) or does not.
 */
export function appliesTo(c: Case, shared: boolean): boolean {
  if (c.workloads === WORKLOADS_SHARED) return shared;
  if (c.workloads === WORKLOADS_DEDICATED) return !shared;
  return true;
}

/**
 * The fixture tree rooted at the directory `root`: `read` returns the bytes
 * of a file, `list` the names of the regular files directly in a directory.
 * A module that uses this package from the published package, without the
 * source repository, passes the v1.0/fixtures directory of the spec
 * mirror.
 */
export function fixturesAt(root: string): FixtureTree {
  const at = (p: string) => join(root, ...p.split('/'));
  return Object.freeze({
    read(path: string): Uint8Array {
      return new Uint8Array(readFileSync(at(path)));
    },
    list(dir: string): readonly string[] {
      return readdirSync(at(dir), { withFileTypes: true })
        .filter((d) => d.isFile())
        .map((d) => d.name)
        .sort();
    },
  });
}

/**
 * The fixture tree of the source repository: the spec/v1.0/fixtures directory of
 * the repository this module sits in (Go `DefaultFixtures`). Throws when it
 * is absent, as in the published package.
 */
export function defaultFixtures(): FixtureTree {
  // src/adapter/adaptertest/ and dist/adapter/adaptertest/ are both four
  // levels below the repository root.
  const root = fileURLToPath(new URL('../../../../spec/v1.0/fixtures', import.meta.url));
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new Error(
      `adaptertest: no fixture directory at ${root}; set options.fixtures to the spec mirror's v1.0/fixtures`,
    );
  }
  return fixturesAt(root);
}
