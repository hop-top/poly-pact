/**
 * The cross-references between the manifest and spec/v1.0/spec-map.md (Go
 * runner/manifest specmap.go), read as scripts/check-spec-map.py reads
 * them.
 *
 * @module
 */
import { statSync } from 'node:fs';
import { join } from 'node:path';
import type { Manifest } from './manifest.ts';
import {
  add,
  Problems,
  RULE_FIXTURE_MISSING,
  RULE_GROUP_LANDED,
  RULE_GROUP_PARTIAL_COMPLETE,
  RULE_GROUP_PARTIAL_EMPTY,
  RULE_GROUP_PLANNED,
  RULE_GROUP_UNLISTED,
  RULE_ROW_UNKNOWN,
  RULE_SPEC_MAP,
} from './problem.ts';
import { compareCodePoints, fileIdRE, NEUTRAL_EXTENSIONS, quote } from './rules.ts';

/**
 * No fixture of the group is committed. The ids the map lists for it are
 * reserved, and the manifest has no entry under it.
 */
export const STATUS_PLANNED = 'planned';
/**
 * Some fixtures of the group are committed. A listed id whose fixture
 * exists is registered; the others stay reserved. Once every listed id
 * exists, the group is landed.
 */
export const STATUS_PARTIAL = 'partial';
/** Every id the map lists for the group exists and is registered. */
export const STATUS_LANDED = 'landed';

// The values of the Status column, in the order of the map.
const STATUSES = [STATUS_PLANNED, STATUS_PARTIAL, STATUS_LANDED];

/** One row of the spec map's Conformance map table. */
export interface Row {
  readonly id: string;
  /** The ids of the Fixture(s) cell, in order. */
  readonly fixtures: readonly string[];
}

/** What the checks read from spec/v1.0/spec-map.md. */
export interface SpecMap {
  readonly rows: readonly Row[];
  /** The status of each group of the Fixture groups table. */
  readonly groups: ReadonlyMap<string, string>;
}

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/;
const SEPARATOR_RE = /^:?-+:?$/;

// The white space of Go strings.TrimSpace (Unicode White_Space).
const SPACE =
  '\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const TRIM_SPACE_RE = new RegExp(`^[${SPACE}]+|[${SPACE}]+$`, 'g');

function trimSpace(s: string): string {
  return s.replace(TRIM_SPACE_RE, '');
}

// s without leading and trailing characters of cut (Go strings.Trim).
function trimChars(s: string, cut: string): string {
  let i = 0;
  let j = s.length;
  while (i < j && cut.includes(s.charAt(i))) i++;
  while (j > i && cut.includes(s.charAt(j - 1))) j--;
  return s.slice(i, j);
}

const utf8 = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * Reads the Conformance map and Fixture groups tables of a spec map, as
 * scripts/check-spec-map.py does. A missing section, table or column gives
 * no spec map; a malformed row, a duplicate row id or group, and a status
 * other than planned, partial or landed are reported beside a usable one.
 * Every problem has the rule `spec-map`.
 */
export function parseSpecMap(text: Uint8Array | string): [SpecMap | undefined, Problems] {
  const ps = new Problems();
  let s = typeof text === 'string' ? text : utf8.decode(text);
  if (s.startsWith('﻿')) s = s.slice(1);
  const sections = splitSections(s.replaceAll('\r\n', '\n').replaceAll('\r', '\n'));

  const groups = new Map<string, string>();
  let t = table(sections, 'Fixture groups');
  let err = t.problem;
  if (err === '') {
    const [groupCol, e1] = column(t.header, 'Group', false);
    const [statusCol, e2] = column(t.header, 'Status', false);
    err = e1 + e2;
    for (const cells of err === '' ? t.rows : []) {
      if (cells.length !== t.header.length) {
        add(
          ps,
          RULE_SPEC_MAP,
          'Fixture groups',
          `row ${quote(cells[0] ?? '')} has ${cells.length} cells, the header has ${t.header.length}`,
        );
        continue;
      }
      const group = trimChars(cells[groupCol] ?? '', '` ');
      const status = trimChars(cells[statusCol] ?? '', '` ');
      if (groups.has(group)) {
        add(ps, RULE_SPEC_MAP, group, 'duplicate group in the Fixture groups table');
      } else if (!STATUSES.includes(status)) {
        add(
          ps,
          RULE_SPEC_MAP,
          group,
          `status ${quote(status)} is not one of ${STATUSES.join(', ')}`,
        );
      } else {
        groups.set(group, status);
      }
    }
  }
  if (err !== '') {
    add(ps, RULE_SPEC_MAP, 'Fixture groups', err);
    return [undefined, ps];
  }

  const rows: Row[] = [];
  t = table(sections, 'Conformance map');
  err = t.problem;
  if (err === '') {
    const [idCol, e1] = column(t.header, 'ID', false);
    const [fixCol, e2] = column(t.header, 'Fixture(s)', true);
    err = e1 + e2;
    const seen = new Set<string>();
    for (const cells of err === '' ? t.rows : []) {
      if (cells.length !== t.header.length) {
        add(
          ps,
          RULE_SPEC_MAP,
          cells[0] ?? '',
          `row has ${cells.length} cells, the header has ${t.header.length}`,
        );
        continue;
      }
      const id = trimChars(cells[idCol] ?? '', '` ');
      if (seen.has(id)) add(ps, RULE_SPEC_MAP, id, 'duplicate row id');
      seen.add(id);
      const fixtures: string[] = [];
      for (const f of (cells[fixCol] ?? '').split(',')) {
        const x = trimChars(f, ' `');
        if (x !== '') fixtures.push(x);
      }
      rows.push({ id, fixtures });
    }
  }
  if (err !== '') {
    add(ps, RULE_SPEC_MAP, 'Conformance map', err);
    return [undefined, ps];
  }
  return [{ rows, groups }, ps];
}

/**
 * Checks the cross-references between `m` and `sm`. `root` is the fixture
 * directory, where {@link fixtureExists} looks for the fixture of a listed
 * id that has no entry.
 *
 * - `row-unknown`: an entry's spec_map_row is not a row of sm;
 * - `group-unlisted`: an entry or a row names a group that the Fixture
 *   groups table does not list. The ids of such a group are not checked
 *   further;
 * - `fixture-id-missing`: a fixture id of a row is not a manifest id, and its
 *   group is landed or its fixture exists;
 * - `group-planned-has-entries`: a planned group has manifest entries;
 * - `group-partial-empty`: a partial group has none;
 * - `group-partial-complete`: the fixture of every id the rows list for a
 *   partial group exists, registered or not;
 * - `group-landed-empty`: a landed group has no manifest entries.
 */
export function checkSpecMap(root: string, m: Manifest, sm: SpecMap): Problems {
  const ps = new Problems();
  const rowIds = new Set(sm.rows.map((r) => r.id));
  const ids = new Set<string>();
  const byGroup = new Map<string, string[]>();
  const uncited = new Map<string, string[]>();
  for (const e of m.entries) {
    if (e.id === '') continue;
    ids.add(e.id);
    push(byGroup, groupOf(e.id), e.id);
    if (e.specMapRow !== '' && !rowIds.has(e.specMapRow)) push(uncited, e.specMapRow, e.id);
  }
  for (const row of sortedMapKeys(uncited)) {
    add(
      ps,
      RULE_ROW_UNKNOWN,
      row,
      `not a row of the spec map, but cited by ${list(uncited.get(row) ?? [])}`,
    );
  }

  const order: string[] = [];
  const citedBy = new Map<string, string[]>();
  const listed = new Map<string, string[]>();
  for (const r of sm.rows) {
    for (const f of r.fixtures) {
      if (!citedBy.has(f)) {
        order.push(f);
        citedBy.set(f, []);
        push(listed, groupOf(f), f);
      }
      const by = citedBy.get(f) as string[];
      if (!by.includes(r.id)) by.push(r.id);
    }
  }

  const unlisted = new Set<string>();
  for (const g of [...byGroup.keys(), ...listed.keys()]) {
    if (!sm.groups.has(g)) unlisted.add(g);
  }
  for (const g of [...unlisted].sort(compareCodePoints)) {
    const names = [...(byGroup.get(g) ?? [])];
    for (const f of listed.get(g) ?? []) if (!names.includes(f)) names.push(f);
    add(
      ps,
      RULE_GROUP_UNLISTED,
      g,
      `named by ${list(names)}, but the Fixture groups table has no row for it`,
    );
  }

  const exists = new Map<string, boolean>();
  for (const f of order) {
    const status = sm.groups.get(groupOf(f));
    if (status === undefined) continue;
    const there = ids.has(f) || fixtureExists(root, f);
    exists.set(f, there);
    const by = (citedBy.get(f) ?? []).join(', ');
    if (ids.has(f)) continue;
    if (status === STATUS_LANDED) {
      add(
        ps,
        RULE_FIXTURE_MISSING,
        f,
        `named by ${by} but not in the manifest: group ${groupOf(f)} is landed, so every id it lists is registered`,
      );
    } else if (there) {
      add(
        ps,
        RULE_FIXTURE_MISSING,
        f,
        `named by ${by} and present in the fixture directory, but not in the manifest: register it`,
      );
    }
  }

  for (const g of sortedMapKeys(sm.groups)) {
    const found = byGroup.get(g) ?? [];
    switch (sm.groups.get(g)) {
      case STATUS_PLANNED:
        if (found.length > 0) {
          add(
            ps,
            RULE_GROUP_PLANNED,
            g,
            `marked planned, but the manifest has entries: ${list(found)}; mark it partial`,
          );
        }
        break;
      case STATUS_PARTIAL: {
        const all = listed.get(g) ?? [];
        if (found.length === 0) {
          add(
            ps,
            RULE_GROUP_PARTIAL_EMPTY,
            g,
            'marked partial, but the manifest has no entries under it; mark it planned',
          );
        } else if (all.every((f) => exists.get(f) === true)) {
          add(
            ps,
            RULE_GROUP_PARTIAL_COMPLETE,
            g,
            `marked partial, but every id the spec map lists for it exists (${all.length}); mark it landed`,
          );
        }
        break;
      }
      case STATUS_LANDED:
        if (found.length === 0) {
          add(ps, RULE_GROUP_LANDED, g, 'marked landed, but the manifest has no entries under it');
        }
        break;
    }
  }
  return ps;
}

/**
 * Reports whether the fixture of `id` is in the fixture directory `root`:
 * root/<id> is a file or a directory, or root/<id> followed by a neutral
 * extension (.json, .yaml, .md, .jws) is a file. An id that does not have
 * the id form exists only through its manifest entry, which this function
 * does not consult.
 */
export function fixtureExists(root: string, id: string): boolean {
  if (!fileIdRE.test(id)) return false;
  const full = join(root, ...id.split('/'));
  if (stat(full) !== undefined) return true;
  return NEUTRAL_EXTENSIONS.some((ext) => stat(full + ext)?.isFile() === true);
}

function stat(path: string): ReturnType<typeof statSync> | undefined {
  try {
    return statSync(path, { throwIfNoEntry: false });
  } catch {
    return undefined;
  }
}

function push(m: Map<string, string[]>, k: string, v: string): void {
  const xs = m.get(k);
  if (xs === undefined) m.set(k, [v]);
  else xs.push(v);
}

function groupOf(id: string): string {
  const i = id.indexOf('/');
  return i < 0 ? id : id.slice(0, i);
}

// Shortens a list of ids for a message.
function list(ids: readonly string[]): string {
  return ids.length > 5 ? `${ids.slice(0, 5).join(', ')}, ...` : ids.join(', ');
}

function sortedMapKeys(m: ReadonlyMap<string, unknown>): string[] {
  return [...m.keys()].sort(compareCodePoints);
}

// Maps each H2 title to the lines under it that are outside fenced code
// blocks. An H2 inside a fence starts no section.
function splitSections(text: string): Map<string, string[]> {
  const sections = new Map<string, string[]>();
  let current = '';
  let fence = '';
  for (const line of text.split('\n')) {
    const mark = FENCE_RE.exec(line);
    if (mark) {
      const m = mark[1] as string;
      if (fence === '') fence = m;
      else if (m[0] === fence[0] && m.length >= fence.length) fence = '';
      continue;
    }
    if (fence !== '') continue;
    if (line.startsWith('## ')) {
      current = trimSpace(line.slice(3));
      sections.set(current, []);
      continue;
    }
    if (current !== '') sections.get(current)?.push(line);
  }
  return sections;
}

interface Table {
  readonly header: string[];
  readonly rows: string[][];
  readonly problem: string;
}

// The header and rows of the first pipe table of a section, or why there is
// none.
function table(sections: ReadonlyMap<string, string[]>, name: string): Table {
  const lines = sections.get(name);
  if (lines === undefined)
    return { header: [], rows: [], problem: `the spec map has no '${name}' section` };
  let header: string[] | undefined;
  const rows: string[][] = [];
  for (const line of lines) {
    if (!line.replace(/^[ \t]+/, '').startsWith('|')) {
      if (header !== undefined) break;
      continue;
    }
    const cells = splitRow(line);
    if (cells === undefined)
      return { header: [], rows: [], problem: `malformed table line: ${line}` };
    if (header === undefined) header = cells;
    else if (!cells.every((c) => SEPARATOR_RE.test(c))) rows.push(cells);
  }
  if (header === undefined) {
    return { header: [], rows: [], problem: `the '${name}' section has no table` };
  }
  return { header, rows, problem: '' };
}

// Splits a table line on pipes not escaped with a backslash. The line must
// start and end with a pipe.
function splitRow(raw: string): string[] | undefined {
  const line = trimSpace(raw);
  const cells: string[] = [];
  let cell = '';
  for (let i = 0; i < line.length; i++) {
    const c = line.charAt(i);
    if (c === '\\' && line.charAt(i + 1) === '|') {
      cell += '|';
      i++;
    } else if (c === '|') {
      cells.push(cell);
      cell = '';
    } else {
      cell += c;
    }
  }
  cells.push(cell);
  if (
    cells.length < 2 ||
    trimSpace(cells[0] as string) !== '' ||
    trimSpace(cells[cells.length - 1] as string) !== ''
  ) {
    return undefined;
  }
  return cells.slice(1, -1).map(trimSpace);
}

// The index of a header cell, compared after trimming backticks and spaces;
// with prefix, a cell that starts with label matches too.
function column(header: readonly string[], label: string, prefix: boolean): [number, string] {
  for (const [i, raw] of header.entries()) {
    const c = trimChars(raw, '` ');
    if (c === label || (prefix && c.startsWith(label))) return [i, ''];
  }
  return [0, `the table has no ${label} column`];
}
