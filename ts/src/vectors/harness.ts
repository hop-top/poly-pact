/**
 * The vectors harness (tools/parity/README.md, Result grammar and Entry
 * handling): every
 * entry of the fixture manifest gets one result line. Entries of kind vector
 * and key of scope core and adapter run through the package's modules and
 * are compared with their outcome and expected file. Entries of kind
 * adapter-case under adapters/_common take the result of the adapter-case
 * leg, the conformance suite run against the memory adapter
 * (run-adapter-cases.ts). Scope runner entries and every other kind are
 * skipped:out-of-scope. An in-scope entry whose capabilities are not all
 * declared is skipped:capability.
 *
 * @module
 */
import { dirname } from 'node:path';
import { capabilities as knownCapabilities } from '../runner/manifest/index.ts';
import { type Core, defaultCore } from './core.ts';
import { messageOf, Skipped, type SpecDefect } from './fixture.ts';
import type { Gates } from './gates.ts';
import { type Entry, HarnessError, loadManifest, prefixOf } from './manifest.ts';
import type { AdapterCases } from './run-adapter-cases.ts';
import { runBinding } from './run-binding.ts';
import { runDigest, runJCS, runSchema, runStrictJSON } from './run-core.ts';
import { runJWS } from './run-jws.ts';
import { runKey } from './run-keys.ts';

/** A group runner: returns on a pass, throws {@link Skipped} on a skip, any other error on a failure. */
export type Runner = (root: string, e: Entry, core: Core) => void;

/**
 * The runner of each in-scope (kind, prefix). An in-scope entry whose
 * prefix has no runner is a harness error.
 */
export const RUNNERS: Readonly<Record<string, Runner>> = {
  'key keys': runKey,
  'vector vectors/binding': runBinding,
  'vector vectors/digest': runDigest,
  'vector vectors/jcs': runJCS,
  'vector vectors/jws': runJWS,
  'vector vectors/schema': runSchema,
  'vector vectors/strictjson': runStrictJSON,
};

const IN_SCOPE_KINDS = ['vector', 'key'];

/** Whether the harness runs the entry: kind vector or key, scope core or adapter. */
export function inScope(e: Entry): boolean {
  return IN_SCOPE_KINDS.includes(e.kind) && e.scope !== 'runner';
}

/**
 * Whether the entry is a common adapter case, which the adapter-case leg
 * runs against the memory adapter (run-adapter-cases.ts).
 */
export function isCommonAdapterCase(e: Entry): boolean {
  return e.kind === 'adapter-case' && prefixOf(e.id) === 'adapters/_common';
}

// The outcome of a common adapter case: the result of the adapter-case leg.
// A case the leg did not run fails.
function adapterCaseOutcome(e: Entry, cases: AdapterCases | undefined): Outcome {
  const r = cases?.results.get(e.id);
  if (r === undefined) {
    let why = 'the adapter-case leg did not run';
    if (cases !== undefined) {
      why =
        cases.loadError === ''
          ? 'no common case of the fixture tree has this id'
          : `the common cases do not load: ${cases.loadError}`;
    }
    return { result: 'fail', detail: why };
  }
  return r.passed ? { result: 'pass' } : { result: 'fail', detail: r.failures.join('; ') };
}

function runnerOf(e: Entry): Runner {
  const r = RUNNERS[`${e.kind} ${prefixOf(e.id)}`];
  if (r === undefined) {
    throw new HarnessError(
      `entry ${e.id}: no runner for kind ${e.kind} prefix ${prefixOf(e.id)}; runners: ${Object.keys(RUNNERS).join(', ')}`,
    );
  }
  return r;
}

export type Outcome =
  | { readonly result: 'pass' }
  | { readonly result: 'fail'; readonly detail: string }
  | {
      readonly result: 'skipped';
      readonly reason: 'out-of-scope' | 'spec-defect' | 'capability';
      readonly detail: string;
      readonly specDefects?: readonly SpecDefect[];
      readonly missingCapabilities?: readonly string[];
    };

/**
 * Runs one entry against core, the fixture directory being root. Throws a
 * {@link HarnessError} for an in-scope entry of an unknown prefix.
 */
export function runEntry(
  root: string,
  e: Entry,
  core: Core = defaultCore,
  capabilities: readonly string[] = [],
  adapterCases?: AdapterCases,
): Outcome {
  if (isCommonAdapterCase(e)) return adapterCaseOutcome(e, adapterCases);
  if (!inScope(e)) {
    const why =
      e.scope === 'runner'
        ? 'scope runner: run by the Go conformance runner'
        : `kind ${e.kind}: no runner in this harness`;
    return { result: 'skipped', reason: 'out-of-scope', detail: why };
  }
  const run = runnerOf(e);
  const missing = e.capabilities.filter((c) => !capabilities.includes(c));
  if (missing.length > 0) {
    return {
      result: 'skipped',
      reason: 'capability',
      detail: `optional capability ${missing.join(', ')} not declared (--capability)`,
      missingCapabilities: missing,
    };
  }
  try {
    run(root, e, core);
    return { result: 'pass' };
  } catch (err) {
    if (err instanceof Skipped) {
      return err.reason === 'spec-defect'
        ? {
            result: 'skipped',
            reason: err.reason,
            detail: err.message,
            specDefects: err.specDefects,
          }
        : { result: 'skipped', reason: err.reason, detail: err.message };
    }
    if (err instanceof HarnessError) throw err;
    return { result: 'fail', detail: messageOf(err) };
  }
}

/** One NDJSON line of the result grammar. */
export interface Line {
  readonly id: string;
  readonly kind: string;
  readonly result: string;
  readonly spec_defects?: readonly SpecDefect[];
  readonly missing_capabilities?: readonly string[];
}

export interface RunOptions {
  readonly core?: Core;
  /** The declared optional capabilities. */
  readonly capabilities?: readonly string[];
  /** The ts gates; without them every gate counts as required. */
  readonly gates?: Gates;
  /**
   * The results of the adapter-case leg (evaluateAdapterCases); without
   * them every common adapter case fails as not run.
   */
  readonly adapterCases?: AdapterCases;
}

export interface Run {
  readonly lines: readonly Line[];
  /** One row per result that is not a pass: `FAIL id: detail` or `SKIP id: detail`. */
  readonly details: readonly string[];
  readonly summary: string;
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  /** 1 when an entry fails under a ts gate other than planned, else 0. */
  readonly status: 0 | 1;
}

function oneLine(s: string): string {
  return s.split(/\s+/).filter(Boolean).join(' ');
}

/** Runs every entry of the manifest at path; throws a {@link HarnessError}. */
export function runManifest(path: string, options: RunOptions = {}): Run {
  const core = options.core ?? defaultCore;
  const caps = options.capabilities ?? [];
  const known = knownCapabilities();
  for (const c of caps) {
    if (!known.includes(c)) {
      throw new HarnessError(`--capability ${JSON.stringify(c)} is not one of ${known.join(', ')}`);
    }
  }
  const entries = loadManifest(path);
  for (const e of entries) if (inScope(e)) runnerOf(e);
  const root = dirname(path);
  const lines: Line[] = [];
  const details: string[] = [];
  let passed = 0;
  let failed = 0;
  let skipped = 0;
  let status: 0 | 1 = 0;
  for (const e of entries) {
    const o = runEntry(root, e, core, caps, options.adapterCases);
    if (o.result === 'pass') {
      passed += 1;
      lines.push({ id: e.id, kind: e.kind, result: 'pass' });
      continue;
    }
    if (o.result === 'fail') {
      failed += 1;
      details.push(`FAIL ${e.id}: ${oneLine(o.detail)}`);
      lines.push({ id: e.id, kind: e.kind, result: 'fail' });
      if (options.gates?.(e) !== 'planned') status = 1;
      continue;
    }
    skipped += 1;
    details.push(`SKIP ${e.id}: ${oneLine(o.detail)}`);
    const line: Line = { id: e.id, kind: e.kind, result: `skipped:${o.reason}` };
    if (o.specDefects !== undefined) lines.push({ ...line, spec_defects: o.specDefects });
    else if (o.missingCapabilities !== undefined)
      lines.push({ ...line, missing_capabilities: o.missingCapabilities });
    else lines.push(line);
  }
  const summary = `${passed} passed, ${failed} failed, ${skipped} skipped`;
  return { lines, details, summary, passed, failed, skipped, status };
}
