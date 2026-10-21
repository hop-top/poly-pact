/**
 * Reading manifest.json and its field rules (Go runner/manifest
 * manifest.go): {@link load} and {@link parse} read the manifest with the
 * strict parse rules of draft section 7.1, and {@link Manifest.validate}
 * applies the field rules of spec/v1.0/fixtures/README.md.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decode, StrictJSONError, parse as strictParse } from '../../core/strictjson.ts';
import type { RawJSON } from '../../core/values.ts';
import { isObject, jsonType, remember, validateEntry } from './fields.ts';
import { add, Problems, RULE_ID_DUPLICATE, RULE_JSON, RULE_ORDER, RULE_SHAPE } from './problem.ts';
import {
  compareCodePoints,
  DEFAULT_CONFORMANCE_PROFILE,
  DEFAULT_TRANSPORT,
  quote,
  sortedKeys,
} from './rules.ts';

/** The manifest's file name in the fixture directory. */
export const FILE_NAME = 'manifest.json';
/** The JSON Schema of the manifest, beside it. */
export const SCHEMA_FILE_NAME = 'manifest.schema.json';
/** The format version, manifest_version. */
export const VERSION = 1;

// Bounds manifest.json. It is an index, not a protocol object, so the
// presentation limit of draft section 20.1 does not apply.
const MAX_BYTES = 16 << 20;

/** The members of an entry as parsed: a plain JSON object, or null for another value. */
export type RawEntry = Readonly<Record<string, unknown>> | null;

function member(raw: RawEntry, name: string): unknown {
  return raw !== null && Object.hasOwn(raw, name) ? raw[name] : undefined;
}

function str(raw: RawEntry, name: string): string {
  const v = member(raw, name);
  return typeof v === 'string' ? v : '';
}

function optStr(raw: RawEntry, name: string): string | null {
  const v = member(raw, name);
  return typeof v === 'string' ? v : null;
}

// The member when it is an array of strings, else null.
function strs(raw: RawEntry, name: string): readonly string[] | null {
  const v = member(raw, name);
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) return null;
  return Object.freeze([...v]);
}

/** One fixture of the manifest. */
export class Entry {
  readonly id: string;
  /** The kind as written; a `Kind` once {@link Manifest.validate} reports nothing. */
  readonly kind: string;
  /** The scope as written; a `Scope` once {@link Manifest.validate} reports nothing. */
  readonly scope: string;
  /** The case directory or single file, relative to the fixture directory. */
  readonly path: string;
  /** The expected-result file; null for key, adapter-asset and source-case entries. */
  readonly expected: string | null;
  /** The one-token result summary; null for key, adapter-asset and source-case entries. */
  readonly outcome: string | null;
  readonly specMapRow: string;
  readonly draftSection: string;
  /**
   * The optional capabilities the entry tests; null for an entry without
   * the member (or with a malformed one), which every implementation must
   * pass. A harness judges an entry only for an implementation that
   * declares each of them (spec/v1.0/fixtures/README.md, Optional capabilities).
   */
  readonly capabilities: readonly string[] | null;
  /**
   * The member conformance_profile as written, null when the entry has none;
   * {@link conformanceProfiles} applies the default.
   */
  readonly conformanceProfile: readonly string[] | null;
  /** The member transport as written, null when absent; {@link transports} applies the default. */
  readonly transport: readonly string[] | null;
  /**
   * The member layer, '' when the entry has none, which applies to every
   * layer. It is set only on an entry whose transport has stdio-ipc.
   */
  readonly layer: string;

  /** An entry of the members `raw` as parsed; null for an element that is not an object. */
  constructor(raw: RawEntry) {
    remember(this, raw);
    this.id = str(raw, 'id');
    this.kind = str(raw, 'kind');
    this.scope = str(raw, 'scope');
    this.path = str(raw, 'path');
    this.expected = optStr(raw, 'expected');
    this.outcome = optStr(raw, 'outcome');
    this.specMapRow = str(raw, 'spec_map_row');
    this.draftSection = str(raw, 'draft_section');
    this.capabilities = strs(raw, 'capabilities');
    this.conformanceProfile = strs(raw, 'conformance_profile');
    this.transport = strs(raw, 'transport');
    this.layer = str(raw, 'layer');
    Object.freeze(this);
  }

  /**
   * The conformance profiles the entry runs under: its conformance_profile,
   * or [full] when it has none. A run under a profile executes only the
   * entries that list it.
   */
  conformanceProfiles(): string[] {
    return this.conformanceProfile === null
      ? [DEFAULT_CONFORMANCE_PROFILE]
      : [...this.conformanceProfile];
  }

  /** The transports the entry exercises: its transport, or [https] when it has none. */
  transports(): string[] {
    return this.transport === null ? [DEFAULT_TRANSPORT] : [...this.transport];
  }
}

/**
 * A parsed manifest.json. Call {@link Manifest.validate} before relying on
 * it: {@link parse} accepts any strict JSON object, and a member that has the
 * wrong JSON type reads as its zero value.
 */
export class Manifest {
  /** manifest_version, 0 when it is absent or not an integer. */
  readonly version: number;
  /** The entries in file order, one per element of entries. */
  readonly entries: readonly Entry[];
  readonly #top: Readonly<Record<string, unknown>>;
  // The text of manifest_version as received, undefined when absent.
  readonly #versionText: string | undefined;

  /**
   * @internal The manifest of a parsed top-level object; `versionText` is
   * the text of manifest_version as received. Use {@link parse}.
   */
  constructor(top: Readonly<Record<string, unknown>>, versionText: string | undefined) {
    this.#top = top;
    this.#versionText = versionText;
    this.version =
      versionText !== undefined && /^-?(?:0|[1-9][0-9]*)$/.test(versionText)
        ? Number(versionText)
        : 0;
    const elems = top.entries;
    this.entries = Object.freeze(
      Array.isArray(elems) ? elems.map((el) => new Entry(isObject(el) ? el : null)) : [],
    );
  }

  /** The entry with the given id, or undefined. */
  lookup(id: string): Entry | undefined {
    return this.entries.find((e) => e.id === id);
  }

  /** Applies the field rules of spec/v1.0/fixtures/README.md; every violation, in file order. */
  validate(): Problems {
    const ps = new Problems();
    for (const k of sortedKeys(this.#top)) {
      if (k !== 'manifest_version' && k !== 'entries') {
        add(ps, RULE_SHAPE, FILE_NAME, `unknown top-level member ${quote(k)}`);
      }
    }
    if (this.#versionText === undefined) add(ps, RULE_SHAPE, FILE_NAME, 'no manifest_version');
    else if (this.#versionText !== '1') {
      add(ps, RULE_SHAPE, FILE_NAME, `manifest_version is ${this.#versionText}, want ${VERSION}`);
    }
    if (!Object.hasOwn(this.#top, 'entries')) {
      add(ps, RULE_SHAPE, FILE_NAME, 'no entries');
      return ps;
    }
    const t = jsonType(this.#top.entries);
    if (t !== 'array') {
      add(ps, RULE_SHAPE, FILE_NAME, `entries is ${t}, not an array`);
      return ps;
    }

    const first = new Map<string, number>();
    for (const [i, e] of this.entries.entries()) {
      validateEntry(e, i, ps);
      if (e.id === '') continue;
      const j = first.get(e.id);
      if (j !== undefined) {
        add(ps, RULE_ID_DUPLICATE, e.id, `entries[${i}] repeats the id of entries[${j}]`);
      } else {
        first.set(e.id, i);
      }
      const prev = this.entries[i - 1];
      if (prev !== undefined && compareCodePoints(prev.id, e.id) > 0) {
        add(
          ps,
          RULE_ORDER,
          e.id,
          `entries[${i}] sorts before entries[${i - 1}] ${prev.id}; sort the entries by id`,
        );
      }
    }
    return ps;
  }
}

/** Reads and parses manifest.json in the fixture directory `root`; throws {@link Problems}. */
export function load(root: string): Manifest {
  let data: Uint8Array;
  try {
    data = readFileSync(join(root, FILE_NAME));
  } catch (err) {
    throw jsonProblem(err);
  }
  return parse(data);
}

/**
 * Reads a manifest with the strict parse rules of draft section 7.1:
 * duplicate member names, non-finite numbers, invalid UTF-8, unpaired
 * surrogates, a byte order mark and trailing data are errors, and so is a
 * value other than an object. Throws {@link Problems} with one
 * `manifest-json` problem whose cause is the {@link StrictJSONError}.
 */
export function parse(data: Uint8Array | string): Manifest {
  const limits = { maxBytes: MAX_BYTES };
  let top: unknown;
  try {
    top = strictParse(data, limits);
  } catch (err) {
    throw jsonProblem(err);
  }
  if (!isObject(top)) {
    const kind = top === null ? 'NULL' : 'TYPE';
    throw jsonProblem(
      new StrictJSONError(kind, '', 0, `the manifest is ${jsonType(top)}, not an object`),
    );
  }
  let versionText: string | undefined;
  if (Object.hasOwn(top, 'manifest_version')) {
    // The member as written: 1.0 and 1e0 are not the version 1.
    const keys = Object.keys(top);
    const raw = decode<Record<string, RawJSON>>(
      data,
      {
        required: [],
        optional: keys,
        members: Object.fromEntries(keys.map((k) => [k, { type: 'raw' as const }])),
      },
      limits,
    );
    versionText = raw.manifest_version?.text;
  }
  return new Manifest(top, versionText);
}

function jsonProblem(err: unknown): Problems {
  const e = err instanceof Error ? err : new Error(String(err));
  const ps = new Problems();
  add(ps, RULE_JSON, FILE_NAME, e.message, e);
  return ps;
}
