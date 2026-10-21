/**
 * The harness view of the fixture manifest, read through the runner/manifest
 * module: its strict parse (draft section 7.1), its top-level rules, and its
 * closed sets of kinds, scopes and capabilities.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import {
  capabilities,
  FILE_NAME,
  Kind,
  kinds,
  type Manifest,
  Problems,
  parse,
  RULE_SHAPE,
  Scope,
  scopes,
} from '../runner/manifest/index.ts';

/** The manifest, the gates file or the command line prevents a run: exit status 2. */
export class HarnessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HarnessError';
  }
}

/** One manifest entry, with the members the harness reads. */
export interface Entry {
  readonly id: string;
  readonly kind: string;
  readonly scope: string;
  readonly path: string;
  readonly expected: string | null;
  readonly outcome: string | null;
  readonly capabilities: readonly string[];
}

const TWO_SEGMENT_GROUPS = ['vectors', 'adapters', 'sources'];

/**
 * The prefix of an entry id (docs/sdk/ports-plan.md section 5.3): its first
 * segment, or its first two under vectors/, adapters/ and sources/.
 */
export function prefixOf(id: string): string {
  const segs = id.split('/');
  const n = TWO_SEGMENT_GROUPS.includes(segs[0] ?? '') && segs.length > 2 ? 2 : 1;
  return segs.slice(0, n).join('/');
}

function read(path: string): Manifest {
  let data: Uint8Array;
  try {
    data = readFileSync(path);
  } catch (err) {
    throw new HarnessError(`${path}: ${(err as Error).message}`);
  }
  try {
    return parse(data);
  } catch (err) {
    if (err instanceof Problems) throw new HarnessError(`${path}: ${err.message}`);
    throw err;
  }
}

/**
 * Reads the manifest at path; throws a {@link HarnessError} when it is not
 * strict JSON, breaks a top-level rule (manifest_version 1 as written, an
 * entries array, no other member), or has an entry without an id or a path,
 * of an unknown kind, scope or capability, or with a repeated id.
 */
export function loadManifest(path: string): Entry[] {
  const m = read(path);
  const top = m.validate().filter((p) => p.rule === RULE_SHAPE && p.where === FILE_NAME);
  if (top.length > 0) throw new HarnessError(`${path}: ${top.map(String).join('; ')}`);
  const seen = new Set<string>();
  const known = capabilities();
  return m.entries.map((e, i): Entry => {
    if (e.id === '') {
      throw new HarnessError(`${path}: entries[${i}] is not an object with a string id`);
    }
    const at = `${path}: entry ${e.id}`;
    if (!Kind.known(e.kind)) {
      throw new HarnessError(
        `${at}: kind ${JSON.stringify(e.kind)} is not one of ${kinds().join(', ')}`,
      );
    }
    if (!Scope.known(e.scope)) {
      throw new HarnessError(
        `${at}: scope ${JSON.stringify(e.scope)} is not one of ${scopes().join(', ')}`,
      );
    }
    if (e.path === '') throw new HarnessError(`${at}: path is not a string`);
    const caps = e.capabilities ?? [];
    if (!caps.every((c) => known.includes(c))) {
      throw new HarnessError(
        `${at}: capabilities ${JSON.stringify(caps)} are not among ${known.join(', ')}`,
      );
    }
    if (seen.has(e.id)) throw new HarnessError(`${at}: id repeated in the manifest`);
    seen.add(e.id);
    return {
      id: e.id,
      kind: e.kind,
      scope: e.scope,
      path: e.path,
      expected: e.expected,
      outcome: e.outcome,
      capabilities: caps,
    };
  });
}
