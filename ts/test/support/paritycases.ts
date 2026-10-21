// The shared manifest case table, tools/spec/manifest-parity-cases.json, as
// tools/spec/README.md (Manifest parity cases) defines it: loadCases reads
// and checks the table, transform applies the string transforms of a step
// (paritycopy.ts applies the steps). A port of scripts/paritycases.py. Not
// a test file (the test glob is *.test.ts).

import { parse as strictParse } from '../../src/core/strictjson.ts';

/** The table is malformed, or a mutation does not fit the current tree. */
export class CaseError extends Error {
  override name = 'CaseError';
}

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type Obj = { [k: string]: Json };
export type Step = Readonly<Obj> & { readonly op: string };

/** One case of the table. */
export interface ParityCase {
  readonly name: string;
  /** The rule id the copy triggers, or null for a control. */
  readonly rule: string | null;
  /** Rule ids the copy must not trigger. */
  readonly forbid: readonly string[];
  /** A rule only the Python oracle enforces: a ported checker must not report it. */
  readonly gap: boolean;
  readonly mutation: readonly Step[];
}

const CASE_ID = /^[a-z0-9][a-z0-9.-]*$/;
const STATUSES = ['planned', 'partial', 'landed'];
const CHECKERS = ['manifest', 'map'];

// The members of each step and their kinds; OPTIONAL members may be left out.
const STEPS: Record<string, Record<string, string>> = {
  add: { path: 'pointer', value: 'json' },
  remove: { path: 'pointer' },
  replace: { path: 'pointer', value: 'json' },
  move: { from: 'pointer', path: 'pointer' },
  copy: { from: 'pointer', path: 'pointer', apply: 'apply' },
  'insert-entry': { like: 'pointer', set: 'members' },
  text: { apply: 'apply' },
  write: { file: 'expr', text: 'str' },
  'copy-file': { source: 'expr', file: 'expr' },
  delete: { file: 'expr' },
  symlink: { file: 'expr', target: 'str' },
  'map-group': { group: 'expr', status: 'status', set_status: 'status', drop: 'true' },
  'map-line': { line: 'str', text: 'str' },
};
const OPTIONAL: Record<string, string[]> = {
  copy: ['apply'],
  'insert-entry': ['like'],
  'map-group': ['group', 'status', 'set_status', 'drop'],
};
// Each transform with the types of its arguments.
const TRANSFORMS: Record<string, readonly ('str' | 'int')[]> = {
  prepend: ['str'],
  append: ['str'],
  replace: ['str', 'str'],
  'replace-first': ['str', 'str'],
  upper: [],
  lower: [],
  dirname: [],
  segment: ['int'],
};

export function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function members(
  v: unknown,
  required: string[],
  optional: string[],
  where: string,
): asserts v is Obj {
  if (!isObj(v)) throw new CaseError(`${where}: not a JSON object`);
  const missing = required.filter((k) => !Object.hasOwn(v, k)).sort();
  if (missing.length > 0) throw new CaseError(`${where}: missing ${missing.join(', ')}`);
  const unknown = Object.keys(v)
    .filter((k) => !required.includes(k) && !optional.includes(k))
    .sort();
  if (unknown.length > 0) throw new CaseError(`${where}: unknown ${unknown.join(', ')}`);
}

function checkApply(steps: unknown, where: string): void {
  if (!Array.isArray(steps)) throw new CaseError(`${where}: apply is not an array`);
  for (const step of steps) {
    const name = Array.isArray(step) ? step[0] : undefined;
    const types = typeof name === 'string' ? TRANSFORMS[name] : undefined;
    if (!Array.isArray(step) || types === undefined) {
      throw new CaseError(`${where}: ${JSON.stringify(step)} is not a transform`);
    }
    const args = step.slice(1);
    const ok =
      args.length === types.length &&
      args.every((a, i) =>
        types[i] === 'str' ? typeof a === 'string' : Number.isInteger(a) && (a as number) >= 0,
      );
    if (!ok) throw new CaseError(`${where}: wrong arguments for ${name}`);
    if (name.startsWith('replace') && args[0] === '') {
      throw new CaseError(`${where}: ${name} of the empty string`);
    }
  }
}

function checkExpr(v: unknown, where: string): void {
  if (typeof v === 'string') return;
  members(v, ['from'], ['apply'], where);
  checkMember('pointer', v.from, where);
  checkApply(v.apply ?? [], where);
}

function checkMember(kind: string, v: unknown, where: string): void {
  switch (kind) {
    case 'pointer':
      if (typeof v !== 'string' || (v !== '' && !v.startsWith('/'))) {
        throw new CaseError(`${where}: ${JSON.stringify(v)} is not a JSON pointer`);
      }
      return;
    case 'apply':
      checkApply(v, where);
      return;
    case 'expr':
      checkExpr(v, where);
      return;
    case 'members':
      if (!isObj(v)) throw new CaseError(`${where}: set is not a JSON object`);
      for (const item of Object.values(v)) {
        if (typeof item === 'object' && item !== null) checkExpr(item, where);
      }
      return;
    case 'str':
      if (typeof v !== 'string')
        throw new CaseError(`${where}: ${JSON.stringify(v)} is not a string`);
      return;
    case 'status':
      if (!STATUSES.includes(v as string)) {
        throw new CaseError(`${where}: ${JSON.stringify(v)} is not a group status`);
      }
      return;
    case 'true':
      if (v !== true) throw new CaseError(`${where}: drop is not true`);
      return;
  }
}

function checkStep(step: unknown, where: string): asserts step is Step {
  const op = isObj(step) ? step.op : undefined;
  const fields = typeof op === 'string' ? STEPS[op] : undefined;
  if (!isObj(step) || typeof op !== 'string' || fields === undefined) {
    throw new CaseError(`${where}: ${JSON.stringify(step)} is not a step`);
  }
  const optional = OPTIONAL[op] ?? [];
  members(
    step,
    ['op', ...Object.keys(fields).filter((f) => !optional.includes(f))],
    optional,
    where,
  );
  for (const [name, v] of Object.entries(step)) {
    if (name !== 'op') checkMember(fields[name] as string, v, `${where}: ${name}`);
  }
  if (op === 'map-group') {
    if (Object.hasOwn(step, 'set_status') === Object.hasOwn(step, 'drop')) {
      throw new CaseError(`${where}: map-group needs one of set_status and drop`);
    }
    if (!Object.hasOwn(step, 'group') && !Object.hasOwn(step, 'status')) {
      throw new CaseError(`${where}: map-group needs group or status`);
    }
  }
}

/** The cases of the table text, checked; name is the table's name in messages. */
export function loadCases(text: string, name: string): ParityCase[] {
  let table: unknown;
  try {
    table = strictParse(text);
  } catch (err) {
    throw new CaseError(`${name}: ${(err as Error).message}`);
  }
  members(table, ['version', 'cases'], [], name);
  if (table.version !== 1) throw new CaseError(`${name}: version is not 1`);
  if (!Array.isArray(table.cases) || table.cases.length === 0) {
    throw new CaseError(`${name}: cases is not a non-empty array`);
  }
  const cases: ParityCase[] = [];
  const seen = new Set<string>();
  for (const [i, item] of table.cases.entries()) {
    const id = isObj(item) ? item.id : undefined;
    if (typeof id !== 'string' || !CASE_ID.test(id) || seen.has(id)) {
      throw new CaseError(`${name}: case ${i + 1}: id ${JSON.stringify(id)} is not a new case id`);
    }
    seen.add(id);
    const where = `${name}: case ${id}`;
    const rule = (item as Obj).rule;
    const extra = rule !== null && rule !== undefined ? ['checker', 'label', 'forbid', 'gap'] : [];
    members(item, ['id', 'rule', 'mutation'], [...extra, 'note'], where);
    if (rule !== null && (typeof rule !== 'string' || rule === '')) {
      throw new CaseError(`${where}: rule is not a rule id or null`);
    }
    const checker = item.checker ?? 'manifest';
    if (!CHECKERS.includes(checker as string)) {
      throw new CaseError(`${where}: checker is not manifest or map`);
    }
    if (Object.hasOwn(item, 'label') !== (checker === 'map')) {
      throw new CaseError(`${where}: label goes with checker map, and only there`);
    }
    if (item.label !== undefined && item.label !== null && typeof item.label !== 'string') {
      throw new CaseError(`${where}: label is not a string or null`);
    }
    const forbid = item.forbid ?? [];
    if (!Array.isArray(forbid) || !forbid.every((f) => typeof f === 'string')) {
      throw new CaseError(`${where}: forbid is not an array of rule ids`);
    }
    const gap = item.gap ?? false;
    if (typeof gap !== 'boolean') throw new CaseError(`${where}: gap is not true or false`);
    if (item.note !== undefined && typeof item.note !== 'string') {
      throw new CaseError(`${where}: note is not a string`);
    }
    const mutation = item.mutation;
    if (!Array.isArray(mutation) || mutation.length === 0) {
      throw new CaseError(`${where}: mutation is not a non-empty array`);
    }
    for (const [j, step] of mutation.entries()) checkStep(step, `${where}: step ${j + 1}`);
    cases.push({
      name: id,
      rule: rule as string | null,
      forbid: forbid as string[],
      gap,
      mutation: mutation as Step[],
    });
  }
  return cases;
}

const UPPER = (s: string): string => s.replace(/[a-z]/g, (c) => c.toUpperCase());
const LOWER = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** Applies the transforms of an apply array to text. */
export function transform(text: string, steps: readonly Json[]): string {
  let out = text;
  for (const step of steps as (string | number)[][]) {
    const [name, ...args] = step;
    switch (name) {
      case 'prepend':
        out = (args[0] as string) + out;
        break;
      case 'append':
        out += args[0] as string;
        break;
      case 'replace':
      case 'replace-first': {
        const [old, repl] = args as [string, string];
        if (!out.includes(old))
          throw new CaseError(`${name}: ${JSON.stringify(old)} does not occur`);
        out = name === 'replace' ? out.split(old).join(repl) : out.replace(old, () => repl);
        break;
      }
      case 'upper':
        out = UPPER(out);
        break;
      case 'lower':
        out = LOWER(out);
        break;
      case 'dirname': {
        const i = out.lastIndexOf('/');
        if (i < 0) throw new CaseError(`dirname: ${JSON.stringify(out)} has no /`);
        out = out.slice(0, i);
        break;
      }
      default: {
        const parts = out.split('/');
        const n = args[0] as number;
        if (n >= parts.length) {
          throw new CaseError(`segment: ${JSON.stringify(out)} has no segment ${n}`);
        }
        out = parts[n] as string;
      }
    }
  }
  return out;
}
