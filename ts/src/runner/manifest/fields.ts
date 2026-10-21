/**
 * The field rules of one manifest entry (Go runner/manifest manifest.go,
 * Entry.validate): the members, the id, kind, scope, path, expected,
 * outcome, spec_map_row and draft_section forms, the optional members
 * capabilities, conformance_profile, transport and layer, and the layout of
 * adapter and source cases.
 *
 * @module
 */
import type { Entry, RawEntry } from './manifest.ts';
import {
  add,
  type Problems,
  RULE_ADAPTER_CASE_PATH,
  RULE_CAPABILITIES,
  RULE_CONFORMANCE_PROFILE,
  RULE_DRAFT_SECTION,
  RULE_EXPECTED,
  RULE_ID,
  RULE_KIND,
  RULE_LAYER,
  RULE_OUTCOME,
  RULE_PATH,
  RULE_SCOPE,
  RULE_SHAPE,
  RULE_SOURCE_CASE_PATH,
  RULE_SPEC_MAP_ROW,
  RULE_TRANSPORT,
} from './problem.ts';
import {
  adapterCaseIdRE,
  DEFAULT_CONFORMANCE_PROFILE,
  DEFAULT_TRANSPORT,
  draftSectionRE,
  fileIdRE,
  idRE,
  Kind,
  KNOWN,
  kinds,
  listOf,
  pathRE,
  quote,
  Scope,
  scopes,
  sortedKeys,
  sourceCaseIdRE,
  specMapRowRE,
  TRANSPORT_STDIO_IPC,
} from './rules.ts';

// The members every entry has, all required, and the members it may have.
const ENTRY_MEMBERS = [
  'id',
  'kind',
  'scope',
  'path',
  'expected',
  'outcome',
  'spec_map_row',
  'draft_section',
];
const OPTIONAL_MEMBERS = ['capabilities', 'conformance_profile', 'transport', 'layer'];

export type JSONType = 'object' | 'array' | 'string' | 'null' | 'boolean' | 'number';

// The JSON type of a parsed value.
export function jsonType(v: unknown): JSONType {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  switch (typeof v) {
    case 'object':
      return 'object';
    case 'string':
      return 'string';
    case 'boolean':
      return 'boolean';
  }
  return 'number';
}

export function isObject(v: unknown): v is Readonly<Record<string, unknown>> {
  return jsonType(v) === 'object';
}

// The members of each entry as read, for the field rules.
const raws = new WeakMap<Entry, RawEntry>();

/** Keeps the members of `e` as read, for {@link validateEntry}. */
export function remember(e: Entry, raw: RawEntry): void {
  raws.set(e, raw);
}

/** Applies the field rules to entries[i], `e`. */
export function validateEntry(e: Entry, i: number, ps: Problems): void {
  const raw = raws.get(e) ?? null;
  const where = e.id === '' ? `entries[${i}]` : e.id;
  if (raw === null) {
    add(ps, RULE_SHAPE, where, 'not an object');
    return;
  }
  for (const k of sortedKeys(raw)) {
    if (!ENTRY_MEMBERS.includes(k) && !OPTIONAL_MEMBERS.includes(k)) {
      add(ps, RULE_SHAPE, where, `unknown member ${quote(k)}`);
    }
  }
  for (const k of ENTRY_MEMBERS) {
    if (!Object.hasOwn(raw, k)) add(ps, RULE_SHAPE, where, `no ${k}`);
  }

  const v = new Checker(raw, where, ps);
  v.check('id', RULE_ID, false, (s) => {
    if (!fileIdRE.test(s)) {
      return 'is not two or three id segments: lowercase letters, digits and hyphens';
    }
    if (
      Kind.known(e.kind) &&
      e.kind !== Kind.ADAPTER_CASE &&
      e.kind !== Kind.SOURCE_CASE &&
      !idRE.test(s)
    ) {
      return `starts a segment with _ or has a . in one; only ${Kind.ADAPTER_CASE} and ${Kind.SOURCE_CASE} ids may`;
    }
    return '';
  });
  v.check('kind', RULE_KIND, false, (s) =>
    Kind.known(s) ? '' : `is not one of ${listOf(kinds())}`,
  );
  v.check('scope', RULE_SCOPE, false, (s) => {
    if (!Scope.known(s)) return `is not one of ${listOf(scopes())}`;
    const want = Kind.requiredScope(e.kind);
    if (want !== undefined && s !== want) {
      return `is not ${want}, the scope of every ${e.kind} entry`;
    }
    return '';
  });
  v.check('path', RULE_PATH, false, pathProblem);
  v.check('spec_map_row', RULE_SPEC_MAP_ROW, false, (s) =>
    specMapRowRE.test(s) ? '' : 'is not a spec-map row id such as R01 or CL-11.3',
  );
  v.check('draft_section', RULE_DRAFT_SECTION, false, (s) =>
    draftSectionRE.test(s)
      ? ''
      : 'is not a section number or appendix letter such as "11.3" or "C"',
  );

  if (e.kind === Kind.ADAPTER_CASE) {
    caseLayout(e, where, ps, adapterCaseIdRE, RULE_ADAPTER_CASE_PATH, 'adapters/<adapter>/<case>');
  } else if (e.kind === Kind.SOURCE_CASE) {
    caseLayout(e, where, ps, sourceCaseIdRE, RULE_SOURCE_CASE_PATH, 'sources/<source>/<case>');
  }
  v.tokens(
    'capabilities',
    RULE_CAPABILITIES,
    KNOWN.capabilities,
    'leave the member out for an entry every implementation must pass',
  );
  v.tokens(
    'conformance_profile',
    RULE_CONFORMANCE_PROFILE,
    KNOWN.conformanceProfiles,
    `leave the member out for an entry of the default profile ${DEFAULT_CONFORMANCE_PROFILE}`,
  );
  v.tokens(
    'transport',
    RULE_TRANSPORT,
    KNOWN.transports,
    `leave the member out for an entry of the default transport ${DEFAULT_TRANSPORT}`,
  );
  checkLayer(e, raw, v, where, ps);

  // expected and outcome are null exactly for the kinds without them.
  const known = Kind.known(e.kind);
  const needs = Kind.hasExpected(e.kind);
  v.check('expected', RULE_EXPECTED, true, pathProblem);
  v.check('outcome', RULE_OUTCOME, true, (s) =>
    KNOWN.outcomes.includes(s) ? '' : `is not one of ${listOf(KNOWN.outcomes)}`,
  );
  for (const [name, rule, value] of [
    ['expected', RULE_EXPECTED, e.expected],
    ['outcome', RULE_OUTCOME, e.outcome],
  ] as const) {
    if (!known || !Object.hasOwn(raw, name)) continue;
    const t = jsonType(raw[name]);
    if (t !== 'null' && t !== 'string') continue;
    if (needs && value === null) {
      add(ps, rule, where, `${name} is null, but kind ${e.kind} needs one`);
    } else if (!needs && value !== null) {
      add(ps, rule, where, `${name} is ${quote(value)}, but kind ${e.kind} has none: write null`);
    }
  }
}

// The adapter-case and source-case layout: the file <prefix>/<x>/<case>.json
// with the id <prefix>/<x>/<case>. An id or path that breaks its own field
// rule is left to that rule.
function caseLayout(
  e: Entry,
  where: string,
  ps: Problems,
  re: RegExp,
  rule: string,
  form: string,
): void {
  if (!fileIdRE.test(e.id) || !pathRE.test(e.path)) return;
  const want = `${e.id}.json`;
  if (!re.test(e.id)) {
    add(ps, rule, where, `id ${quote(e.id)} is not ${form}, the id of the case file ${form}.json`);
  } else if (e.path !== want) {
    add(
      ps,
      rule,
      where,
      `path ${quote(e.path)} is not the case file ${quote(want)}, the id followed by .json`,
    );
  }
}

// The layer rule: transcript or os, only on an entry whose transport, as
// written or by default, has stdio-ipc, and required on an entry of kind
// transport. A transport that breaks its own rule is left to that rule.
function checkLayer(
  e: Entry,
  raw: Readonly<Record<string, unknown>>,
  v: Checker,
  where: string,
  ps: Problems,
): void {
  if (!Object.hasOwn(raw, 'layer') && e.kind === Kind.TRANSPORT) {
    add(
      ps,
      RULE_LAYER,
      where,
      `names no layer: an entry of kind ${Kind.TRANSPORT} says who executes it, ${listOf(KNOWN.layers)}`,
    );
  }
  v.check('layer', RULE_LAYER, false, (s) => {
    if (!KNOWN.layers.includes(s)) return `is not one of ${listOf(KNOWN.layers)}`;
    if (Object.hasOwn(raw, 'transport') && e.transport === null) return '';
    if (!e.transports().includes(TRANSPORT_STDIO_IPC)) {
      return `is set, but transport ${listOf(e.transports())} has no ${TRANSPORT_STDIO_IPC}: a layer applies only to the local transport profile`;
    }
    return '';
  });
}

function pathProblem(s: string): string {
  return pathRE.test(s)
    ? ''
    : 'is not a relative path: / separated ASCII segments, none empty or starting with .';
}

// The checks of one entry's members.
class Checker {
  readonly #raw: Readonly<Record<string, unknown>>;
  readonly #where: string;
  readonly #ps: Problems;

  constructor(raw: Readonly<Record<string, unknown>>, where: string, ps: Problems) {
    this.#raw = raw;
    this.#where = where;
    this.#ps = ps;
  }

  // Applies test to the string member name. A missing member is reported by
  // validateEntry; a member of the wrong JSON type is a manifest-shape
  // problem; null is accepted only when nullable, and then not tested.
  check(name: string, rule: string, nullable: boolean, test: (v: string) => string): void {
    if (!Object.hasOwn(this.#raw, name)) return;
    const v = this.#raw[name];
    const t = jsonType(v);
    if (t === 'null' && nullable) return;
    if (t !== 'string') {
      add(this.#ps, RULE_SHAPE, this.#where, `${name} is ${t}, not a string`);
      return;
    }
    const msg = test(v as string);
    if (msg !== '') add(this.#ps, rule, this.#where, `${name} ${quote(v as string)} ${msg}`);
  }

  // Applies rule to the optional member name: an array of one or more
  // distinct tokens of known. A member of the wrong JSON type, or an item
  // that is not a string, is a manifest-shape problem; empty says what to
  // write instead of an empty array.
  tokens(name: string, rule: string, known: readonly string[], empty: string): void {
    if (!Object.hasOwn(this.#raw, name)) return;
    const v = this.#raw[name];
    const t = jsonType(v);
    if (t !== 'array') {
      add(this.#ps, RULE_SHAPE, this.#where, `${name} is ${t}, not an array`);
      return;
    }
    const items = v as readonly unknown[];
    if (items.length === 0) {
      add(this.#ps, rule, this.#where, `${name} is empty: ${empty}`);
      return;
    }
    const seen: string[] = [];
    for (const [i, item] of items.entries()) {
      const it = jsonType(item);
      if (it !== 'string') {
        add(this.#ps, RULE_SHAPE, this.#where, `${name}[${i}] is ${it}, not a string`);
        continue;
      }
      const c = item as string;
      if (!known.includes(c)) {
        add(
          this.#ps,
          rule,
          this.#where,
          `${name}[${i}] ${quote(c)} is not one of ${listOf(known)}`,
        );
      } else if (seen.includes(c)) {
        add(this.#ps, rule, this.#where, `${name}[${i}] ${quote(c)} repeats a token`);
      }
      seen.push(c);
    }
  }
}
