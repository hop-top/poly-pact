/**
 * The adapter-case leg of the vectors harness (Go: the test binary of
 * go/adapters/memory run with -ndjson): the common adapter cases of the
 * fixture tree, run by the conformance suite against the memory adapter in
 * both workload modes, one result per case under its manifest id.
 *
 * @module
 */
import {
  evaluateConformance,
  type Factory,
  fixturesAt,
  type Options,
  type Result,
} from '../adapter/adaptertest/index.ts';
import { factory, factoryWith, withSharedWorkloads } from '../adapters/memory/index.ts';

/** The result of one common adapter case, merged over the workload modes that ran it. */
export interface AdapterCaseResult {
  readonly passed: boolean;
  /** Every failure, prefixed with the mode it occurred in. */
  readonly failures: readonly string[];
}

/** The results of the leg, by manifest id, or why the cases could not be loaded. */
export interface AdapterCases {
  readonly results: ReadonlyMap<string, AdapterCaseResult>;
  /** `''` when the cases loaded. */
  readonly loadError: string;
}

/**
 * The manifest id of the common case `id`: its file,
 * adapters/_common/<id in lowercase>.json, without .json
 * (spec/v1.0/fixtures/adapters/README.md).
 */
export function commonCaseId(id: string): string {
  return `adapters/_common/${id.toLowerCase()}`;
}

/**
 * The results of each mode, `runs[i]` being those of `modes[i]`, as one
 * result per case, sorted by manifest id. A case passes when it passed in
 * every mode that ran it, and fails otherwise; the failures name their mode.
 */
export function mergeCaseResults(
  modes: readonly string[],
  runs: readonly (readonly Result[])[],
): Map<string, AdapterCaseResult> {
  const byId = new Map<string, { passed: boolean; failures: string[] }>();
  for (const [i, rs] of runs.entries()) {
    for (const r of rs) {
      const id = commonCaseId(r.id);
      const merged = byId.get(id) ?? { passed: true, failures: [] };
      if (!r.passed()) {
        merged.passed = false;
        for (const f of r.failures) merged.failures.push(`${modes[i]}: ${f}`);
      }
      byId.set(id, merged);
    }
  }
  return new Map([...byId.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** One workload mode the suite runs an adapter in. */
export interface CaseMode {
  readonly name: string;
  readonly factory: Factory;
  /** The suite options of the mode; the fixture tree is set by {@link evaluateModes}. */
  readonly options: Options;
}

/**
 * The modes of the memory adapter: dedicated workloads, the default of every
 * profile, and workloads shared by several agents (identity mapping IM-19).
 * Each runs the cases that apply to it, so every common case runs in at
 * least one.
 */
export const MEMORY_MODES: readonly CaseMode[] = Object.freeze([
  { name: 'dedicated', factory, options: {} },
  {
    name: 'shared',
    factory: factoryWith(withSharedWorkloads()),
    options: { sharedWorkloads: true },
  },
]);

/**
 * Runs the common cases of the fixture tree at `root` in every mode of
 * `modes` and merges the results with {@link mergeCaseResults}.
 */
export async function evaluateModes(
  root: string,
  modes: readonly CaseMode[],
): Promise<AdapterCases> {
  const fixtures = fixturesAt(root);
  try {
    const runs: Result[][] = [];
    for (const m of modes)
      runs.push(await evaluateConformance(m.factory, { ...m.options, fixtures }));
    return {
      results: mergeCaseResults(
        modes.map((m) => m.name),
        runs,
      ),
      loadError: '',
    };
  } catch (err) {
    return { results: new Map(), loadError: (err as Error).message };
  }
}

/**
 * Runs the common cases of the fixture tree at `root` against the memory
 * adapter in both of its modes, {@link MEMORY_MODES}.
 */
export function evaluateAdapterCases(root: string): Promise<AdapterCases> {
  return evaluateModes(root, MEMORY_MODES);
}
