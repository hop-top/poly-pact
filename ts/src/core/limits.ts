/**
 * Protocol version and size limits (Go package hop.top/pact-go/core: Version,
 * Limits, Defaults, LimitError).
 *
 * The nesting depth is enforced while decoding, by core/strictjson: the
 * functions presentationJSON, artifactJSON and profileJSON give the decoder
 * the matching bounds. The validate functions check the rest on decoded
 * objects; a size is the length in bytes of the received input, not of a
 * re-encoding. Section 20.1 also fixes lifetimes, the clock skew and the
 * evaluation time; those are in core/clock.
 *
 * @module
 */
import type { Limits as JSONLimits } from './strictjson.ts';
import type { Intent, OperationContext, Presentation, RequirementContract } from './types.ts';

/** The protocol version every artifact carries in `pact_version`. */
export const VERSION = '0.1';

// The keys of the baseline limits that section 20.1 of the draft names in
// GatewayMetadata.limits. A LimitError carries one of them.
export const KEY_MAX_PRESENTATION_BYTES = 'max_presentation_bytes';
export const KEY_MAX_ARTIFACT_PAYLOAD_BYTES = 'max_artifact_payload_bytes';
export const KEY_MAX_PROFILE_BYTES = 'max_profile_bytes';
export const KEY_MAX_EVIDENCE_ARTIFACTS = 'max_evidence_artifacts';
export const KEY_MAX_FIELD_RULES = 'max_field_rules';
export const KEY_MAX_JSON_DEPTH = 'max_json_depth';
export const KEY_MAX_RESOURCES = 'max_resources';
export const KEY_MAX_DESCRIPTION_BYTES = 'max_description_bytes';

/**
 * The size and count limits of draft section 20.1 that a validator enforces
 * on untrusted input. {@link defaultLimits} returns the baseline; a
 * deployment may configure tighter values, and {@link checkLimits} rejects
 * larger ones.
 */
export interface Limits {
  /** The largest decoded presentation, embedded artifacts included (`max_presentation_bytes`). */
  readonly presentationBytes: number;
  /** The largest decoded payload of one signed evidence or reputation artifact (`max_artifact_payload_bytes`). */
  readonly artifactPayloadBytes: number;
  /** The largest profile JSON (`max_profile_bytes`). */
  readonly profileBytes: number;
  /** The most evidence artifacts in a presentation (`max_evidence_artifacts`). */
  readonly evidenceArtifacts: number;
  /** The most field rules in a contract (`max_field_rules`). */
  readonly fieldRules: number;
  /** The deepest JSON nesting; the outermost object or array has depth 1 (`max_json_depth`). */
  readonly depth: number;
  /** The most resources in an operation (`max_resources`). */
  readonly resources: number;
  /** The longest human-readable description in UTF-8 bytes (`max_description_bytes`). */
  readonly descriptionBytes: number;
}

/** The kinds of a limit failure, one per Go sentinel error. */
export type LimitErrorKind = 'LIMIT_EXCEEDED' | 'LIMITS_INVALID' | 'NIL_OBJECT';

/**
 * A limit check failure. `key` is the section 20.1 metadata key of the limit
 * (empty for `NIL_OBJECT`); `max` is what the limit allows (the configured
 * value for `LIMIT_EXCEEDED`, the baseline for `LIMITS_INVALID`); `got` is
 * the offending value.
 */
export class LimitError extends Error {
  readonly kind: LimitErrorKind;
  readonly key: string;
  readonly max: number;
  readonly got: number;

  constructor(kind: LimitErrorKind, key: string, max: number, got: number, detail = '') {
    super(message(kind, key, max, got, detail));
    this.name = 'LimitError';
    this.kind = kind;
    this.key = key;
    this.max = max;
    this.got = got;
  }
}

function message(kind: LimitErrorKind, key: string, max: number, got: number, detail: string) {
  switch (kind) {
    case 'LIMITS_INVALID':
      return `core: invalid limits: ${key} is ${got}, must be 1..${max}`;
    case 'LIMIT_EXCEEDED':
      return `core: limit exceeded: ${key} is ${got}, at most ${max}`;
    case 'NIL_OBJECT':
      return `core: nil object: ${detail}`;
  }
}

// The baseline values of section 20.1.
const BASELINE: Limits = Object.freeze({
  presentationBytes: 256 * 1024,
  artifactPayloadBytes: 32 * 1024,
  profileBytes: 32 * 1024,
  evidenceArtifacts: 32,
  fieldRules: 128,
  depth: 16,
  resources: 256,
  descriptionBytes: 4096,
});

// Each limit with its metadata key, in the order of the section 20.1 table.
const KEYS: readonly (readonly [keyof Limits, string])[] = [
  ['presentationBytes', KEY_MAX_PRESENTATION_BYTES],
  ['artifactPayloadBytes', KEY_MAX_ARTIFACT_PAYLOAD_BYTES],
  ['profileBytes', KEY_MAX_PROFILE_BYTES],
  ['evidenceArtifacts', KEY_MAX_EVIDENCE_ARTIFACTS],
  ['fieldRules', KEY_MAX_FIELD_RULES],
  ['depth', KEY_MAX_JSON_DEPTH],
  ['resources', KEY_MAX_RESOURCES],
  ['descriptionBytes', KEY_MAX_DESCRIPTION_BYTES],
];

/** The baseline limits of draft section 20.1. */
export function defaultLimits(): Limits {
  return { ...BASELINE };
}

/**
 * Throws a `LIMITS_INVALID` {@link LimitError} unless every limit is an
 * integer from 1 to its baseline. Equal and tighter values pass; zero does
 * not, so a forgotten member is an error and not an unlimited input.
 */
export function checkLimits(l: Limits): void {
  for (const [field, key] of KEYS) {
    const value = l[field];
    const ceiling = BASELINE[field];
    if (!Number.isInteger(value) || value < 1 || value > ceiling) {
      throw new LimitError('LIMITS_INVALID', key, ceiling, value);
    }
  }
}

// Fails closed: a limit that is not a number never admits anything.
function exceeds(key: string, got: number, max: number): void {
  if (!(got <= max)) throw new LimitError('LIMIT_EXCEEDED', key, max, got);
}

function nil(what: string): LimitError {
  return new LimitError('NIL_OBJECT', '', 0, 0, what);
}

/**
 * Checks a decoded presentation of `size` received bytes, embedded artifacts
 * included: the size, the number of evidence artifacts, and through
 * {@link validateOperation} and {@link validateIntent} the resources and the
 * description. Throws on the first limit exceeded. The profile inside a
 * presentation has its own limit: check it with {@link validateProfileSize}
 * on the bytes it was decoded from.
 */
export function validatePresentation(
  l: Limits,
  p: Presentation | null | undefined,
  size: number,
): void {
  if (p == null) throw nil('presentation');
  exceeds(KEY_MAX_PRESENTATION_BYTES, size, l.presentationBytes);
  exceeds(KEY_MAX_EVIDENCE_ARTIFACTS, p.evidence.length, l.evidenceArtifacts);
  validateOperation(l, p.operation);
  validateIntent(l, p.intent);
}

/** Checks the number of field rules of a decoded contract. */
export function validateContract(l: Limits, c: RequirementContract | null | undefined): void {
  if (c == null) throw nil('requirement contract');
  exceeds(KEY_MAX_FIELD_RULES, c.field_rules.length, l.fieldRules);
}

/** Checks the number of resources of a decoded operation. */
export function validateOperation(l: Limits, op: OperationContext | null | undefined): void {
  if (op == null) throw nil('operation');
  exceeds(KEY_MAX_RESOURCES, op.resources.length, l.resources);
}

/**
 * Checks the length of a decoded intent's description in UTF-8 bytes, not in
 * UTF-16 code units. core/strictjson has already rejected lone surrogates;
 * one would count as the three bytes of U+FFFD.
 */
export function validateIntent(l: Limits, intent: Intent | null | undefined): void {
  if (intent == null) throw nil('intent');
  exceeds(KEY_MAX_DESCRIPTION_BYTES, utf8Length(intent.description), l.descriptionBytes);
}

function utf8Length(s: string): number {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    n += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }
  return n;
}

/** Checks the decoded payload size in bytes of one signed evidence or reputation artifact. */
export function validateArtifactSize(l: Limits, size: number): void {
  exceeds(KEY_MAX_ARTIFACT_PAYLOAD_BYTES, size, l.artifactPayloadBytes);
}

/** Checks the size in bytes of a profile's JSON. */
export function validateProfileSize(l: Limits, size: number): void {
  exceeds(KEY_MAX_PROFILE_BYTES, size, l.profileBytes);
}

/** The strict decode limits of a presentation: `presentationBytes` bytes and `depth` levels. */
export function presentationJSON(l: Limits): JSONLimits {
  return { maxBytes: l.presentationBytes, maxDepth: l.depth };
}

/** The strict decode limits of one signed artifact payload: `artifactPayloadBytes` bytes and `depth` levels. */
export function artifactJSON(l: Limits): JSONLimits {
  return { maxBytes: l.artifactPayloadBytes, maxDepth: l.depth };
}

/** The strict decode limits of a profile: `profileBytes` bytes and `depth` levels. */
export function profileJSON(l: Limits): JSONLimits {
  return { maxBytes: l.profileBytes, maxDepth: l.depth };
}
