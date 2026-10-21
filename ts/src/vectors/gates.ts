/**
 * The ts column of the gates file, tools/parity/gates.json
 * (docs/sdk/ports-plan.md section 5.3), for the exit status of the harness.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { type Entry, HarnessError, prefixOf } from './manifest.ts';

export type Gate = 'required' | 'planned' | 'n/a';

/** The ts gate of an entry's (scope, kind, prefix) row; undefined without a row. */
export type Gates = (e: Entry) => Gate | undefined;

const GATES: readonly string[] = ['required', 'planned', 'n/a'];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Reads the gates file at path; throws a {@link HarnessError}. */
export function loadGates(path: string): Gates {
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new HarnessError(`gates ${path}: ${(err as Error).message}`);
  }
  if (!isObject(doc) || doc.gates_version !== 1 || !Array.isArray(doc.rows)) {
    throw new HarnessError(`gates ${path}: not an object with gates_version 1 and a rows array`);
  }
  const rows = new Map<string, Gate>();
  for (const [i, r] of doc.rows.entries()) {
    const ok =
      isObject(r) &&
      typeof r.scope === 'string' &&
      typeof r.kind === 'string' &&
      typeof r.prefix === 'string' &&
      typeof r.ts === 'string' &&
      GATES.includes(r.ts);
    if (!ok)
      throw new HarnessError(`gates ${path}: rows[${i}] lacks scope, kind, prefix or a ts gate`);
    rows.set(`${r.scope} ${r.kind} ${r.prefix}`, r.ts as Gate);
  }
  return (e) => rows.get(`${e.scope} ${e.kind} ${prefixOf(e.id)}`);
}
