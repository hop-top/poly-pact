/**
 * The closed sets and field patterns of the manifest format
 * (spec/v1.0/fixtures/README.md; Go runner/manifest rules.go). The schema
 * spec/v1.0/fixtures/manifest.schema.json states the same patterns and enums.
 *
 * @module
 */

/**
 * The id of every entry that is not an adapter or source case: two or three
 * segments, each lowercase letters and digits joined by hyphens.
 */
export const ID_PATTERN =
  '^[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)?$';

/**
 * The id of an adapter-case entry, adapters/<adapter>/<case>. It follows the
 * file name adapters/<adapter>/<case>.json, so its last two segments may
 * also start with "_" and join with ".", as in
 * adapters/_common/common-03.fragment.
 */
export const ADAPTER_CASE_ID_PATTERN =
  '^adapters/_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*$';

/**
 * The id of a source-case entry, sources/<source>/<case>. Its case segment
 * may also join with ".", as in sources/scim/scim-01.join; no segment
 * starts with "_".
 */
export const SOURCE_CASE_ID_PATTERN =
  '^sources/[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:[-.][a-z0-9]+)*$';

/**
 * A relative, slash-separated path: a segment is ASCII letters, digits, ".",
 * "_" and "-", and does not start with ".", so there is no leading "/", no
 * empty segment and no "." or ".." segment.
 */
export const PATH_PATTERN = '^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$';

/** A row id of spec/v1.0/spec-map.md, such as R01, CL-11.3, CL-C or COMMON-01. */
export const SPEC_MAP_ROW_PATTERN = '^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+(?:\\.[0-9]+)*)?$';

/**
 * A draft section number such as 11.3, or an appendix letter with an
 * optional subsection, such as C or B.7.
 */
export const DRAFT_SECTION_PATTERN = '^(?:[1-9][0-9]*|[A-Z])(?:\\.[1-9][0-9]*)*$';

// Two or three segments that may each start with "_" and join with ".", the
// widest id form. An id of another form is malformed whatever the kind; a
// spec-map fixture id of this form can name a file.
const FILE_ID_PATTERN =
  '^_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*(?:/_?[a-z0-9]+(?:[-.][a-z0-9]+)*)?$';

export const idRE = new RegExp(ID_PATTERN);
export const adapterCaseIdRE = new RegExp(ADAPTER_CASE_ID_PATTERN);
export const sourceCaseIdRE = new RegExp(SOURCE_CASE_ID_PATTERN);
export const fileIdRE = new RegExp(FILE_ID_PATTERN);
export const pathRE = new RegExp(PATH_PATTERN);
export const specMapRowRE = new RegExp(SPEC_MAP_ROW_PATTERN);
export const draftSectionRE = new RegExp(DRAFT_SECTION_PATTERN);

const KIND_VALUES = {
  KEY: 'key',
  VECTOR: 'vector',
  SCHEMA: 'schema',
  EVALUATE: 'evaluate',
  OUTCOMES: 'outcomes',
  LEARNING: 'learning',
  ADAPTER_CASE: 'adapter-case',
  ADAPTER_ASSET: 'adapter-asset',
  /**
   * A case of a membership or status source that is not an adapter, scope
   * adapter, with its expectations inline and neither an expected file nor
   * an outcome.
   */
  SOURCE_CASE: 'source-case',
  PROFILE_INVALID: 'profile-invalid',
  /** A transport transcript, scope runner. */
  TRANSPORT: 'transport',
  /** An MCP adapter vector or case, scope adapter. */
  MCP: 'mcp',
  /** A conformance-profile case, scope runner. */
  PROFILE: 'profile',
} as const;

/** What an entry is: the harness verb that runs it or the role of the asset. */
export type Kind = (typeof KIND_VALUES)[keyof typeof KIND_VALUES];

const SCOPE_VALUES = {
  /** Every language harness. */
  CORE: 'core',
  /** Only the Go conformance runner. */
  RUNNER: 'runner',
  /** The adapter conformance harnesses. */
  ADAPTER: 'adapter',
} as const;

/** Who must pass an entry. */
export type Scope = (typeof SCOPE_VALUES)[keyof typeof SCOPE_VALUES];

const KINDS: readonly Kind[] = Object.freeze(Object.values(KIND_VALUES));
const SCOPES: readonly Scope[] = Object.freeze(Object.values(SCOPE_VALUES));

/** The kinds, and the rules that depend on the kind (Go `Kind` methods). */
export const Kind = Object.freeze({
  ...KIND_VALUES,
  /** Reports whether `k` is a kind of the manifest format (Go `Kind.Known`). */
  known(k: string): k is Kind {
    return (KINDS as readonly string[]).includes(k);
  },
  /**
   * Reports whether entries of kind `k` name an expected file and an
   * outcome. Key, adapter-asset and source-case entries have neither: both
   * are null (Go `Kind.HasExpected`).
   */
  hasExpected(k: string): boolean {
    return (
      k !== KIND_VALUES.KEY && k !== KIND_VALUES.ADAPTER_ASSET && k !== KIND_VALUES.SOURCE_CASE
    );
  },
  /**
   * The one scope an entry of kind `k` must have: runner for transport
   * transcripts and conformance-profile cases, adapter for MCP vectors and
   * cases and for source cases, never core; undefined for a kind that takes
   * any scope (Go `Kind.RequiredScope`).
   */
  requiredScope(k: string): Scope | undefined {
    switch (k) {
      case KIND_VALUES.TRANSPORT:
      case KIND_VALUES.PROFILE:
        return SCOPE_VALUES.RUNNER;
      case KIND_VALUES.MCP:
      case KIND_VALUES.SOURCE_CASE:
        return SCOPE_VALUES.ADAPTER;
    }
    return undefined;
  },
});

/** The scopes (Go `Scope` constants and `Scope.Known`). */
export const Scope = Object.freeze({
  ...SCOPE_VALUES,
  /** Reports whether `s` is a scope of the manifest format. */
  known(s: string): s is Scope {
    return (SCOPES as readonly string[]).includes(s);
  },
});

/** The kinds in the order of the README. */
export function kinds(): string[] {
  return [...KINDS];
}

/** The scopes in the order of the README. */
export function scopes(): string[] {
  return [...SCOPES];
}

/**
 * The conformance profiles: the entries of kind conformance in
 * spec/v1.0/profiles/registry.json (draft section 22.1).
 */
export const CONFORMANCE_PROFILE_FULL = 'full';
export const CONFORMANCE_PROFILE_SINGLE_OWNER = 'single-owner';
/** The conformance profile of an entry without conformance_profile. */
export const DEFAULT_CONFORMANCE_PROFILE = CONFORMANCE_PROFILE_FULL;

const CONFORMANCE_PROFILES = [CONFORMANCE_PROFILE_FULL, CONFORMANCE_PROFILE_SINGLE_OWNER];

/** The conformance profile ids in registry order. */
export function conformanceProfiles(): string[] {
  return [...CONFORMANCE_PROFILES];
}

/**
 * The transport profiles an entry exercises: https, the baseline HTTPS
 * binding of draft section 13, and stdio-ipc, the local IPC and stdio
 * profile of draft section 13.3.
 */
export const TRANSPORT_HTTPS = 'https';
export const TRANSPORT_STDIO_IPC = 'stdio-ipc';
/** The transport of an entry without transport. */
export const DEFAULT_TRANSPORT = TRANSPORT_HTTPS;

const TRANSPORTS = [TRANSPORT_HTTPS, TRANSPORT_STDIO_IPC];

/** The transport profile ids in the order of the README. */
export function transports(): string[] {
  return [...TRANSPORTS];
}

/**
 * How an entry over stdio-ipc is executed: a transcript entry is a
 * language-neutral frame sequence the runner executes; an os entry needs
 * real operating-system facilities.
 */
export const LAYER_TRANSCRIPT = 'transcript';
export const LAYER_OS = 'os';

const LAYERS = [LAYER_TRANSCRIPT, LAYER_OS];

/** The layer tokens in the order of the README. */
export function layers(): string[] {
  return [...LAYERS];
}

/**
 * Ed25519 (RFC 9864) negotiated explicitly for signed artifacts, with RFC
 * 8037 keys (draft section 7.2, MAY): an optional capability.
 */
export const CAPABILITY_JWS_ED25519 = 'jws-ed25519';

const CAPABILITIES = [CAPABILITY_JWS_ED25519];

/** The optional capability tokens in the order of the README. */
export function capabilities(): string[] {
  return [...CAPABILITIES];
}

// The decisions of draft section 11.4, then the other one-token summaries,
// among them the qualification results of draft section 14.3.
const OUTCOMES = [
  'ADMISSIBLE',
  'INADMISSIBLE',
  'DEFERRED',
  'ACCEPTED',
  'REJECTED',
  'QUALIFIED',
  'UNQUALIFIED',
  'DISPUTED',
  'MATCH',
];

/** The outcome tokens in the order of the README. */
export function outcomes(): string[] {
  return [...OUTCOMES];
}

export const KNOWN = Object.freeze({
  conformanceProfiles: CONFORMANCE_PROFILES as readonly string[],
  transports: TRANSPORTS as readonly string[],
  layers: LAYERS as readonly string[],
  capabilities: CAPABILITIES as readonly string[],
  outcomes: OUTCOMES as readonly string[],
});

// Neutral extensions may appear anywhere under the fixture directory, native
// ones only inside the path of an adapter-asset entry. Both are lowercase and
// compared as written: .JSON is on neither list.
export const NEUTRAL_EXTENSIONS: readonly string[] = ['.json', '.yaml', '.md', '.jws'];
export const NATIVE_EXTENSIONS: readonly string[] = ['.sql', '.rego', '.fga', '.ldif'];

/**
 * The directory at the top of the fixture directory that holds the test
 * inputs of the manifest checks themselves; its files are not fixtures.
 */
export const TESTDATA_DIR = 'testdata';

/** Whether `rel` is `p` or lies inside the directory `p`. */
export function within(rel: string, p: string): boolean {
  return rel === p || rel.startsWith(`${p}/`);
}

/** The last segment of a slash-separated path (Go `path.Base`). */
export function baseName(rel: string): string {
  return rel.slice(rel.lastIndexOf('/') + 1);
}

/** The extension of the last segment, from its final dot (Go `path.Ext`). */
export function extName(rel: string): string {
  const name = baseName(rel);
  const i = name.lastIndexOf('.');
  return i < 0 ? '' : name.slice(i);
}

// Moves the surrogates above the rest of the BMP, so that code units compare
// in code point order.
function codePointOrder(u: number): number {
  if (u >= 0xe000) return u - 0x800;
  if (u >= 0xd800) return u + 0x2000;
  return u;
}

/**
 * Compares two strings in code point order, which is the byte order of
 * their UTF-8 forms (Go string comparison).
 */
export function compareCodePoints(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x !== y) return codePointOrder(x) - codePointOrder(y);
  }
  return a.length - b.length;
}

/** The keys of `o` in code point order. */
export function sortedKeys(o: object): string[] {
  return Object.keys(o).sort(compareCodePoints);
}

/** A string as Go `%q` writes it, close enough for messages. */
export function quote(s: string): string {
  return JSON.stringify(s);
}

/** A list as Go `%v` writes a slice of strings. */
export function listOf(xs: readonly string[]): string {
  return `[${xs.join(' ')}]`;
}
