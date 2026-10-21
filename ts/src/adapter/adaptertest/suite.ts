/**
 * The entry points of the adapter conformance suite (Go
 * hop.top/pact-go/adapter/adaptertest, suite.go): {@link runConformance} for a
 * `node:test` test, and {@link evaluateConformance}, which imports no test
 * framework, for any other runner and for the proof that a broken adapter
 * fails.
 *
 * @module
 */
import type { TestContext } from 'node:test';
import type { Case } from './casefile.ts';
import type { Factory, Options, Replacement } from './harness.ts';
import { appliesTo, defaultFixtures, FN, isCommon, loadCases, OUT } from './load.ts';
import { runCase } from './run.ts';

/** The outcome of one case. */
export class Result {
  /** The case id. */
  readonly id: string;
  /** Every assertion the adapter failed, one line each; empty when it passed. */
  readonly failures: readonly string[];

  constructor(id: string, failures: readonly string[]) {
    this.id = id;
    this.failures = Object.freeze([...failures]);
    Object.freeze(this);
  }

  /** Whether the adapter passed the case. */
  passed(): boolean {
    return this.failures.length === 0;
  }
}

// The cases of every workload mode.
function loadAll(o: Options): Case[] {
  return loadCases(o.fixtures ?? defaultFixtures(), o.adapter ?? '');
}

// The cases of the workload mode of o.
function applicable(o: Options, cases: readonly Case[]): Case[] {
  return cases.filter((c) => appliesTo(c, o.sharedWorkloads === true));
}

/**
 * Whether an outcome lets the stimulus through, the outcome class ACCEPTED
 * of the fixture manifest; every other outcome is REJECTED.
 */
export function accepted(outcome: string): boolean {
  const yes: readonly string[] = [
    OUT.authenticated,
    OUT.bound,
    OUT.mapped,
    OUT.claim,
    OUT.signed,
    OUT.allow,
    OUT.pass,
  ];
  return yes.includes(outcome);
}

/**
 * Checks every declaration of `o.replaced` against the loaded cases, the
 * common cases and the adapter's own cases of every workload mode; throws
 * an `Error` naming the rule a declaration breaks.
 */
export function checkReplaced(cases: readonly Case[], o: Options): void {
  const replaced = o.replaced ?? {};
  const byId = new Map(cases.map((c) => [c.id, c]));
  for (const id of Object.keys(replaced).sort()) {
    const rep = replaced[id] as Replacement;
    const orig = byId.get(id);
    if (orig === undefined || !isCommon(orig)) {
      throw new Error(`adaptertest: replaced: ${id} is not a common case`);
    }
    const fn = orig.expect.function;
    if (fn !== FN.authenticate && fn !== FN.authorize) {
      throw new Error(
        `adaptertest: replaced: ${id} is a ${fn} case; only ${FN.authenticate} and ${FN.authorize} cases may be replaced`,
      );
    }
    if (rep.reason.trim() === '') throw new Error(`adaptertest: replaced: ${id} gives no reason`);
    if (rep.by === '') throw new Error(`adaptertest: replaced: ${id} names no replacement case`);
    const by = byId.get(rep.by);
    if (by === undefined || isCommon(by)) {
      throw new Error(
        `adaptertest: replaced: ${id} is replaced by ${rep.by}, which is not a case of adapters/${o.adapter ?? ''}`,
      );
    }
    if (by.expect.function !== fn) {
      throw new Error(
        `adaptertest: replaced: ${id} is a ${fn} case, but its replacement ${rep.by} is a ${by.expect.function} case`,
      );
    }
    if (accepted(by.expect.outcome) !== accepted(orig.expect.outcome)) {
      throw new Error(
        `adaptertest: replaced: ${id} expects ${orig.expect.outcome}, but its replacement ${rep.by} expects ${by.expect.outcome}, of the other outcome class`,
      );
    }
  }
}

/**
 * The errors and the log lines of a case's test from its failures. A case
 * that is not replaced fails with its failures. A replaced case is expected
 * to fail: its failures are logged, and a pass is the error, because the
 * declaration is no longer needed.
 */
export function verdict(
  id: string,
  fails: readonly string[],
  rep: Replacement | undefined,
): { errors: string[]; logs: string[] } {
  if (rep === undefined) return { errors: [...fails], logs: [] };
  if (fails.length === 0) {
    return {
      errors: [`${id} is declared replaced by ${rep.by} but passes; drop the declaration`],
      logs: [],
    };
  }
  return {
    errors: [],
    logs: [`${id} is replaced by ${rep.by} (${rep.reason}); it fails here as declared:`, ...fails],
  };
}

/**
 * Runs the common cases, and the adapter's own cases when `options.adapter`
 * is set, as one subtest of `t` per case (Go `Run`). A case that names a
 * workload mode other than the one of `options.sharedWorkloads` is not run.
 * `factory` builds the adapter afresh for each case. A failed assertion
 * fails the subtest of its case, with every failure in its message. A common
 * case that `options.replaced` declares replaced is run as well, and its
 * subtest fails when the case passes. A declaration that breaks a rule of
 * {@link Options.replaced}, or a fixture tree that does not load, rejects
 * before any case runs.
 *
 * `t` is the context of a `node:test` test; the module imports its type
 * only, so nothing of `node:test` loads unless the caller's test does.
 */
export async function runConformance(
  t: TestContext,
  factory: Factory,
  options: Options = {},
): Promise<void> {
  const all = loadAll(options);
  checkReplaced(all, options);
  for (const c of applicable(options, all)) {
    const rep = options.replaced?.[c.id];
    await t.test(c.id, async (st) => {
      const { errors, logs } = verdict(c.id, await runCase(factory, c), rep);
      for (const line of logs) st.diagnostic(line);
      if (errors.length > 0) throw new Error(errors.join('\n'));
    });
  }
}

/**
 * Runs the same cases as {@link runConformance} and returns their results
 * instead of failing a test (Go `Evaluate`). It is how a test proves that a
 * deliberately broken adapter fails the suite, and how a runner other than
 * `node:test` runs it: it imports no test framework. It ignores
 * `options.replaced` and reports every case as run. It rejects when the
 * cases cannot be loaded.
 */
export async function evaluateConformance(
  factory: Factory,
  options: Options = {},
): Promise<Result[]> {
  const cases = applicable(options, loadAll(options));
  const out: Result[] = [];
  for (const c of cases) out.push(new Result(c.id, await runCase(factory, c)));
  return out;
}
