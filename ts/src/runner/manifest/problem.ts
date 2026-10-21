/**
 * The rule ids of the manifest checks and the problems that name them (Go
 * runner/manifest problem.go). A {@link Problem} names exactly one rule.
 *
 * @module
 */

/** manifest.json is unreadable or not strict JSON (draft section 7.1). */
export const RULE_JSON = 'manifest-json';
/** A top-level member, an entry member or a JSON type is wrong or missing. */
export const RULE_SHAPE = 'manifest-shape';
/** An id is not two or three id segments. */
export const RULE_ID = 'entry-id';
/** Two entries share an id. */
export const RULE_ID_DUPLICATE = 'entry-id-duplicate';
/** The entries are not sorted by id. */
export const RULE_ORDER = 'entry-order';
/** kind is not a known kind. */
export const RULE_KIND = 'entry-kind';
/** scope is not a known scope, or not the one scope of a kind that has one. */
export const RULE_SCOPE = 'entry-scope';
/** path is not a relative slash-separated path. */
export const RULE_PATH = 'entry-path';
/** expected is malformed, or null where a file is needed, or set where the kind has none. */
export const RULE_EXPECTED = 'entry-expected';
/** outcome is not a known token, or null where one is needed, or set where the kind has none. */
export const RULE_OUTCOME = 'entry-outcome';
/** spec_map_row is not a row id. */
export const RULE_SPEC_MAP_ROW = 'entry-spec-map-row';
/** draft_section is not a section number or letter. */
export const RULE_DRAFT_SECTION = 'entry-draft-section';
/** capabilities is empty, or names a capability twice or one that is not a capability token. */
export const RULE_CAPABILITIES = 'entry-capabilities';
/** conformance_profile is empty, or names a profile twice or one that is not a profile id. */
export const RULE_CONFORMANCE_PROFILE = 'entry-conformance-profile';
/** transport is empty, or names a transport profile twice or one that is not https or stdio-ipc. */
export const RULE_TRANSPORT = 'entry-transport';
/**
 * layer is not transcript or os, is set on an entry whose transport has no
 * stdio-ipc, or is absent from an entry of kind transport.
 */
export const RULE_LAYER = 'entry-layer';
/** An adapter-case entry is not the file adapters/<adapter>/<case>.json with the id adapters/<adapter>/<case>. */
export const RULE_ADAPTER_CASE_PATH = 'adapter-case-path';
/** A source-case entry is not the file sources/<source>/<case>.json with the id sources/<source>/<case>. */
export const RULE_SOURCE_CASE_PATH = 'source-case-path';
/** An entry path does not exist, is a dangling symbolic link, or resolves outside the fixture directory. */
export const RULE_PATH_MISSING = 'path-missing';
/** An expected file does not exist, resolves outside the fixture directory, or is not a file. */
export const RULE_EXPECTED_MISSING = 'expected-missing';
/** A fixture file is in no entry's path, is no entry's expected file, and is not under expected/<id>/. */
export const RULE_UNCOVERED = 'file-uncovered';
/** A fixture file has an extension outside the neutral list, or a native one outside an adapter-asset entry. */
export const RULE_EXTENSION = 'file-extension';
/** An entry cites a spec_map_row the spec map lacks. */
export const RULE_ROW_UNKNOWN = 'row-unknown';
/** A fixture id named in the spec map is not in the manifest, although its group is landed or its fixture exists. */
export const RULE_FIXTURE_MISSING = 'fixture-id-missing';
/** A group marked planned has manifest entries. */
export const RULE_GROUP_PLANNED = 'group-planned-has-entries';
/** A group marked partial has no manifest entries. */
export const RULE_GROUP_PARTIAL_EMPTY = 'group-partial-empty';
/** Every fixture id the spec map names in a group marked partial exists. */
export const RULE_GROUP_PARTIAL_COMPLETE = 'group-partial-complete';
/** A group marked landed has no manifest entries. */
export const RULE_GROUP_LANDED = 'group-landed-empty';
/** A manifest entry or a spec-map row names a group that has no row in the Fixture groups table. */
export const RULE_GROUP_UNLISTED = 'group-unlisted';
/** The spec map is unreadable or lacks a table, a column or a well-formed row the checks read. */
export const RULE_SPEC_MAP = 'spec-map';

/** One violation of a rule. */
export class Problem {
  /** One of the `RULE_*` ids. */
  readonly rule: string;
  /**
   * The entry id (or entries[i] when the entry has no usable id), the
   * fixture file, the spec-map row, group or fixture id, or the file name
   * of manifest.json or the spec map.
   */
  readonly where: string;
  /** What is wrong. */
  readonly msg: string;
  /** The underlying cause, or undefined. */
  readonly err: Error | undefined;

  constructor(rule: string, where: string, msg: string, err?: Error) {
    this.rule = rule;
    this.where = where;
    this.msg = msg;
    this.err = err;
  }

  /** `[rule] where: msg` (Go `Problem.String`). */
  toString(): string {
    return `[${this.rule}] ${this.where}: ${this.msg}`;
  }
}

/**
 * A list of problems (Go `Problems`). As an error it prints one problem per
 * line: {@link load} and {@link parse} throw one.
 */
export class Problems extends Array<Problem> {
  /** map, filter and the other derived arrays are plain arrays. */
  static override get [Symbol.species](): ArrayConstructor {
    return Array;
  }

  /** One problem per line (Go `Problems.Error`). */
  get message(): string {
    return this.map((p) => p.toString()).join('\n');
  }

  /** The underlying causes, in order (Go `Problems.Unwrap`). */
  get cause(): Error[] {
    return this.flatMap((p) => (p.err === undefined ? [] : [p.err]));
  }

  /** This list, or undefined when it is empty (Go `Problems.Err`). */
  err(): Problems | undefined {
    return this.length === 0 ? undefined : this;
  }

  /** The same as {@link message}. */
  override toString(): string {
    return this.message;
  }
}

/** Appends a problem to `ps`. Internal to the package. */
export function add(ps: Problem[], rule: string, where: string, msg: string, err?: Error): void {
  ps.push(new Problem(rule, where, msg, err));
}
