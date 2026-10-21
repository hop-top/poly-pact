/**
 * Strict reading of the case files: the member tables the strict decoder
 * checks them against (Go: the struct types of evalcase and strictjson's
 * walk over them), the zero values of absent members, and the rules of
 * config.json and native_context.json the decoder does not make.
 *
 * As in Go, a member that may be null in the file is `nullable`; every
 * other member rejects null, and integers are 0 to 2^53-1. A member absent
 * from the file reads as its zero value.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { ALG_ED25519, ALG_ES256 } from '../core/jws/typ.ts';
import type { Member, Shape } from '../core/shapes.ts';
import { shapes } from '../core/shapes.ts';
import { decode, parse } from '../core/strictjson.ts';
import type { RawJSON } from '../core/values.ts';
import { CaseError, messageOf, notExist, q } from './errors.ts';
import {
  type Authenticated,
  BINDING_ACTIVE,
  BINDING_COMPROMISED,
  BINDING_REVOKED,
  BINDING_UNKNOWN,
  type Config,
  type Gateway,
  type NativeContext,
  type NativeSource,
} from './types.ts';

const S: Member = { type: 'string' };
const I: Member = { type: 'integer' };
const B: Member = { type: 'boolean' };
const R: Member = { type: 'raw' };
const arr = (items: Member): Member => ({ type: 'array', items });
const map = (values: Member): Member => ({ type: 'map', values });
const nul = (of: Member): Member => ({ type: 'nullable', of });
const ref = (name: string): Member => ({ type: 'shape', name: P + name });

// The prefix of the case shapes among the core shapes.
const P = 'evalcase.';

function shape(members: Record<string, Member>): Shape {
  return { required: [], optional: Object.keys(members), members };
}

const nullableStrings = (...names: string[]) => Object.fromEntries(names.map((n) => [n, nul(S)]));
const strings = (...names: string[]) => Object.fromEntries(names.map((n) => [n, S]));

const response = {
  transport_code: nul(S),
  decision: nul(S),
  checks: arr(ref('ExpectedCheck')),
  receipt: nul(ref('Receipt')),
  executed: nul(B),
  absent_checks: arr(S),
  rejected_before_crypto: nul(B),
  reason: nul(S),
};

const caseShapes: Record<string, Shape> = {
  Config: shape({
    mode: S,
    now: I,
    clock_skew_seconds: I,
    gateway: ref('Gateway'),
    trust: arr(ref('TrustRecord')),
    validator: ref('Validator'),
    native_mappings: arr(ref('NativeMapping')),
    installed_checks: arr(S),
    active_policy: ref('ActivePolicy'),
    limits: map(I),
    executor_classes: arr(ref('ExecutorClass')),
    check_freshness: map(I),
    selection: nul(ref('Selection')),
  }),
  Gateway: shape({
    ...strings('gateway_id', 'environment_id', 'tenant_id', 'operation_mapping_version'),
    extensions_supported: arr(S),
    jws_algorithms: arr(S),
  }),
  TrustRecord: shape({
    iss: S,
    role: S,
    keys: arr(S),
    claim_paths: arr(S),
    reporter_role: nul(S),
  }),
  Validator: shape(strings('iss', 'source_id', 'key')),
  // source is read by readNativeSource, as Go's NativeSource.UnmarshalJSON.
  NativeMapping: shape({ path: S, native_path: S, source: R }),
  ActivePolicy: shape(
    strings('base_revision', 'selected_set', 'learning_policy_digest', 'learning_artifact_digest'),
  ),
  ExecutorClass: shape({
    ...strings('principal_id', 'task_id', 'operation_id', 'class'),
    executor_id: nul(S),
  }),
  Selection: shape({
    selector: ref('Selector'),
    current_snapshot: nul(S),
    record: ref('SelectionRecord'),
  }),
  Selector: shape({
    implementation_id: S,
    learning_artifact_digest: S,
    order: arr(S),
    sets: map(arr({ type: 'shape', name: 'FieldRule' })),
    thresholds: map(ref('Threshold')),
  }),
  Threshold: shape({ dimensions: map(ref('Minimums')), security_status: S }),
  Minimums: shape({ score_bps: I, confidence_bps: I, independent_tasks: I }),
  SelectionRecord: shape({
    ...strings('record_ref', 'learning_policy_digest', 'learning_artifact_digest'),
    snapshot_jti: nul(S),
    hold_refs: arr(S),
    base_revision: S,
  }),
  NativeContext: shape({
    authenticated: nul(ref('Authenticated')),
    native_claims: arr(ref('NativeClaim')),
    approval: nul(ref('Approval')),
    delegation: nul(ref('Delegation')),
    executor: nul(ref('Executor')),
    evidence_status: map(ref('EvidenceStatus')),
    security_holds: arr(S),
    authorize: B,
  }),
  Authenticated: shape({
    principal_id: S,
    agent_id: nul(S),
    operator_id: nul(S),
    tenant_id: S,
    holder_jkt: nul({ type: 'digest' }),
    binding_status: S,
    authenticated_at: I,
    enrolled_elsewhere: B,
    binding_error: nul(S),
  }),
  NativeClaim: shape({
    native_path: S,
    value: R,
    observed_at: I,
    status_checked_at: I,
    source_id: S,
  }),
  Approval: shape({
    ...strings('ref', 'state', 'agent_id', 'principal_id', 'purpose_id', 'task_id'),
    status_checked_at: nul(I),
    approver_id: nul(S),
    approver_authority: nul(ref('ApproverAuthority')),
    amount: nul(ref('Amount')),
    resources: arr(S),
  }),
  ApproverAuthority: shape({ required_role: S, approver_roles: arr(S) }),
  Amount: shape(strings('approved', 'requested', 'currency')),
  Delegation: shape({
    ...strings('authority_ref', 'principal_id', 'task_id', 'state'),
    observed_at: I,
  }),
  Executor: shape(strings('class', 'principal_id')),
  EvidenceStatus: shape({ status: S, checked_at: I }),
  Decision: shape({
    ...response,
    responses: arr(ref('Response')),
    handoff: arr(ref('Handoff')),
    subject: nul(S),
  }),
  Response: shape(response),
  ExpectedCheck: shape({
    ...strings('check_id', 'result', 'reason_code'),
    evidence_ids_include: arr(S),
    source_ref: nul(S),
  }),
  Receipt: shape({ typ: S, signer: S, claims: map(R), exp_max: I }),
  Handoff: shape({ transport_code: nul(S) }),
  // exchange.json, as the harness reads it before its defaults.
  ExchangeFile: shape({
    presentations: nul(arr(ref('ExchangePresentation'))),
    availability: nul(ref('ExchangeAvailability')),
    handoff: arr(ref('ExchangeHandoff')),
  }),
  ExchangePresentation: shape({
    signed: S,
    jti: S,
    replica: nul(S),
    concurrent: nul(B),
    evict_replay_records: nul(B),
    actual_operation: nul(S),
    transport: nul(S),
    evaluation: nul(ref('ExchangeEvaluation')),
  }),
  ExchangeEvaluation: shape({
    started_at: nul(I),
    native_reads_at: nul(I),
    cancelled_at: nul(I),
  }),
  ExchangeAvailability: shape({
    sources: arr(S),
    ...nullableStrings('replay_store', 'enrollment_source'),
  }),
  ExchangeHandoff: shape({
    ...nullableStrings('presentation', 'actual_operation'),
    at: nul(I),
  }),
  Sequence: shape({ exchanges: arr(S), subject: S }),
  SigningFile: shape({
    artifacts: nul(arr(ref('Artifact'))),
    presentations: arr(ref('Presentation')),
  }),
  Artifact: shape({
    ...strings('decoded', 'signed', 'typ', 'signer', 'jti'),
    iat: nul(I),
    nbf: nul(I),
    exp: nul(I),
    digests: map(S),
    payload_signed: nul(S),
  }),
  Presentation: shape({
    ...strings('signed', 'signer', 'jti'),
    iat: nul(I),
    nbf: nul(I),
    exp: nul(I),
    contract: nul(S),
    evidence: nul(arr(S)),
    reputation: R,
    ...nullableStrings('profile', 'intent', 'operation'),
  }),
  KeysFile: shape({
    ...strings('label', 'warning', 'encoding'),
    keys: arr(ref('KeyEntry')),
  }),
  KeyEntry: shape(
    strings('role', 'kid', 'alg', 'kty', 'crv', 'scalar', 'seed_hex', 'd', 'public_jwk'),
  ),
};

/** The case shapes, under their prefixed names, with the core shapes they reach. */
const DEFS: Readonly<Record<string, Shape>> = Object.freeze({
  ...shapes,
  ...Object.fromEntries(Object.entries(caseShapes).map(([k, v]) => [P + k, v])),
});

// Members whose absence Go keeps apart from an empty array (a nil slice):
// they read as null when absent.
const NIL_WHEN_ABSENT = new Set([`${P}Gateway.jws_algorithms`, `${P}Decision.responses`]);

// An object of the entries of o mapped through f, "__proto__" included.
function mapValues(o: object, f: (v: unknown) => unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    Object.defineProperty(out, k, {
      value: f(v),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

function zero(m: Member): unknown {
  switch (m.type) {
    case 'string':
    case 'digest':
    case 'enum':
      return '';
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    case 'array':
      return [];
    case 'map':
    case 'object':
      return {};
    case 'shape':
      return m.name.startsWith(P) ? fill(m.name, {}) : {};
    default:
      return null; // nullable, raw
  }
}

function convert(m: Member, v: unknown): unknown {
  switch (m.type) {
    case 'nullable':
      return v === null ? null : convert(m.of, v);
    case 'array':
      return (v as unknown[]).map((x) => convert(m.items, x));
    case 'map':
      return mapValues(v as object, (x) => convert(m.values, x));
    case 'shape':
      return m.name.startsWith(P) ? fill(m.name, v as Record<string, unknown>) : v;
    default:
      return v;
  }
}

// The decoded object v of the case shape name with every absent member at
// its zero value.
function fill(name: string, v: Record<string, unknown>): Record<string, unknown> {
  const s = DEFS[name] as Shape;
  const out: Record<string, unknown> = {};
  for (const [k, m] of Object.entries(s.members)) {
    if (Object.hasOwn(v, k)) out[k] = convert(m, v[k]);
    else out[k] = NIL_WHEN_ABSENT.has(`${name}.${k}`) ? null : zero(m);
  }
  return out;
}

/** The strict JSON text b as the case shape name, absent members at their zero value. */
export function decodeAs<T>(b: Uint8Array | string, name: string): T {
  return fill(P + name, decode(b, DEFS[P + name] as Shape, undefined, DEFS)) as T;
}

/** {@link decodeAs} of the file p; a missing file throws the file system error. */
export function readAs<T>(p: string, name: string): T {
  return decodeAs<T>(new Uint8Array(readFileSync(p)), name);
}

/**
 * The member name of the strict JSON object file p, read as m; undefined
 * when the file or the member is absent.
 */
export function readMember(p: string, name: string, m: Member): unknown {
  let b: Uint8Array;
  try {
    b = new Uint8Array(readFileSync(p));
  } catch (err) {
    if (notExist(err)) return undefined;
    throw err;
  }
  const top = parse(b);
  const keys =
    typeof top === 'object' && top !== null && !Array.isArray(top) ? Object.keys(top) : [];
  const members: Record<string, Member> = Object.fromEntries(keys.map((k) => [k, R]));
  if (keys.includes(name)) members[name] = m;
  const v = decode<Record<string, unknown>>(b, shape(members), undefined, DEFS);
  return Object.hasOwn(v, name) ? convert(m, v[name]) : undefined;
}

/** The member tables a {@link readMember} of trust and authenticated names. */
export const TRUST_MEMBER: Member = arr(ref('TrustRecord'));
export const AUTHENTICATED_MEMBER: Member = nul(ref('Authenticated'));

// The largest limit with a wire form, 2^53-1 (draft 7.1).
const MAX_SECONDS = 9007199254740991;
const INTEGER_TEXT = /^-?(?:0|[1-9][0-9]*)$/;

const SOURCE_MEMBERS = [
  'source_id',
  'best_max_age_seconds',
  'best_status_max_age_seconds',
  'live_check',
  'change_feed',
] as const;

// Reads a declared source strictly, as Go's NativeSource.UnmarshalJSON: each
// member once and present, no other member, bounds from 0 to 2^53-1, a
// change feed of none, poll_delta or push, and, for a source with no live
// check, a status bound of at least 1 (freshness profile, section 4.2).
function readNativeSource(raw: RawJSON): NativeSource {
  const fail = (detail: string, cause?: unknown) =>
    new CaseError(`native_mappings source: ${detail}`, { cause });
  let v: Record<string, RawJSON>;
  try {
    v = decode(
      raw.text,
      shape(Object.fromEntries(SOURCE_MEMBERS.map((n) => [n, R]))),
      undefined,
      DEFS,
    );
  } catch (err) {
    throw fail(messageOf(err), err);
  }
  // A null member is an absent one, as for Go's pointer members.
  const text = (n: string): string | undefined => {
    const t = v[n]?.text;
    return t === 'null' ? undefined : t;
  };
  const str = (n: string): string | undefined => {
    const t = text(n);
    if (t !== undefined && !t.startsWith('"')) throw fail(`${n} is not a string`);
    return t === undefined ? undefined : (JSON.parse(t) as string);
  };
  const int = (n: string): number | undefined => {
    const t = text(n);
    if (t !== undefined && !INTEGER_TEXT.test(t)) throw fail(`${n} is not an integer`);
    return t === undefined ? undefined : Number(t);
  };
  const bool = (n: string): boolean | undefined => {
    const t = text(n);
    if (t !== undefined && t !== 'true' && t !== 'false') throw fail(`${n} is not a boolean`);
    return t === undefined ? undefined : t === 'true';
  };
  const sourceId = str('source_id');
  const best = int('best_max_age_seconds');
  const bestStatus = int('best_status_max_age_seconds');
  const liveCheck = bool('live_check');
  const changeFeed = str('change_feed');
  if (sourceId === undefined || sourceId === '') throw fail('no source_id');
  if (best === undefined) throw fail('no best_max_age_seconds');
  if (bestStatus === undefined) throw fail('no best_status_max_age_seconds');
  if (liveCheck === undefined) throw fail('no live_check');
  if (changeFeed === undefined) throw fail('no change_feed');
  for (const [n, x] of [
    ['best_max_age_seconds', best],
    ['best_status_max_age_seconds', bestStatus],
  ] as const) {
    if (x < 0 || x > MAX_SECONDS) throw fail(`${n} ${x} is not from 0 to 2^53-1`);
  }
  if (changeFeed !== 'none' && changeFeed !== 'poll_delta' && changeFeed !== 'push') {
    throw fail(`change_feed ${q(changeFeed)} is not none, poll_delta or push`);
  }
  if (!liveCheck && bestStatus < 1) {
    throw fail('a source with no live check has a best_status_max_age_seconds of at least 1');
  }
  return {
    sourceId,
    bestMaxAgeSeconds: best,
    bestStatusMaxAgeSeconds: bestStatus,
    liveCheck,
    changeFeed,
  };
}

/** config.json read strictly, with the declared sources of its native mappings. */
export function readConfig(p: string): Config {
  const c = readAs<Record<string, unknown> & { native_mappings: Record<string, unknown>[] }>(
    p,
    'Config',
  );
  c.native_mappings = c.native_mappings.map((m) => {
    const raw = m.source as RawJSON | null;
    return { ...m, source: raw === null || raw.text === 'null' ? null : readNativeSource(raw) };
  });
  return c as unknown as Config;
}

/**
 * Checks jws_algorithms against the type of GatewayMetadata.jws_algorithms
 * (draft A.3): when present, one or two distinct algorithms out of ES256
 * and Ed25519. EdDSA, none and HMAC algorithms are never accepted (draft
 * 7.2).
 */
export function checkAlgorithms(g: Gateway): void {
  const algs = g.jws_algorithms;
  if (algs === null) return;
  if (algs.length === 0) {
    throw new CaseError('gateway.jws_algorithms is empty; leave it out for the baseline ["ES256"]');
  }
  for (const [i, alg] of algs.entries()) {
    if (alg !== ALG_ES256 && alg !== ALG_ED25519) {
      throw new CaseError(
        `gateway.jws_algorithms[${i}] ${q(alg)} is not ES256 or Ed25519 (draft 7.2, A.3)`,
      );
    }
    if (algs.indexOf(alg) !== i) {
      throw new CaseError(`gateway.jws_algorithms[${i}] ${q(alg)} repeats an algorithm`);
    }
  }
}

/**
 * The rules of the authenticated member that the decoder does not make: the
 * status set, the null members of an unknown binding, and the members that
 * only an unknown binding may carry.
 */
export function checkAuthenticated(a: Authenticated | null): void {
  if (a === null) return;
  const s = a.binding_status;
  if (![BINDING_ACTIVE, BINDING_REVOKED, BINDING_COMPROMISED, BINDING_UNKNOWN].includes(s)) {
    throw new CaseError(
      `authenticated.binding_status ${q(s)} is not active, revoked, compromised or unknown`,
    );
  }
  const unknown = s === BINDING_UNKNOWN;
  for (const [name, v] of [
    ['agent_id', a.agent_id],
    ['operator_id', a.operator_id],
    ['holder_jkt', a.holder_jkt],
  ] as const) {
    if (unknown && v !== null) {
      throw new CaseError(
        `authenticated.${name} is set, but binding_status unknown has no agent, operator or key (null)`,
      );
    }
    if (!unknown && (v === null || v === '')) {
      throw new CaseError(
        `authenticated.${name} is null or empty, but binding_status ${s} names a binding`,
      );
    }
  }
  if (a.enrolled_elsewhere && !unknown) {
    throw new CaseError(
      `authenticated.enrolled_elsewhere is true with binding_status ${s}; it reports only for unknown`,
    );
  }
  if (a.binding_error !== null) {
    if (a.binding_error !== 'UNSUPPORTED_REQUIREMENT') {
      throw new CaseError(
        `authenticated.binding_error ${q(a.binding_error)} is not UNSUPPORTED_REQUIREMENT or null`,
      );
    }
    if (!unknown) {
      throw new CaseError(
        `authenticated.binding_error is set with binding_status ${s}; it comes with unknown`,
      );
    }
  }
}

/** Checks that every native claim at the native path of a mapping that declares a source names that source's source_id. */
export function checkSources(c: Config, nc: NativeContext): void {
  for (const [i, m] of c.native_mappings.entries()) {
    if (m.source === null) continue;
    for (const cl of nc.native_claims) {
      if (cl.native_path === m.native_path && cl.source_id !== m.source.sourceId) {
        throw new CaseError(
          `native_mappings[${i}] source source_id ${q(m.source.sourceId)}, but the native claim at ${m.native_path} names ${q(cl.source_id)}`,
        );
      }
    }
  }
}
