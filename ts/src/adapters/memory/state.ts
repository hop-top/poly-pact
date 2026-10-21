/**
 * The native state of the memory adapter, the neutral common/1 model of the
 * common conformance cases (Go hop.top/pact-go/adapters/memory, state.go and the
 * freshness members of freshness.go). Every member keeps its JSON member
 * name; a time is Unix seconds, `null` when the source gives none.
 *
 * @module
 */

import { isBindingStatus, isEffect, isVerdict } from '../../adapter/types.ts';
import { equalFoldASCII, lowerASCII } from '../../core/binding/chars.ts';
import { Digest, type RawJSON } from '../../core/values.ts';

/** The value of `State.model`: the neutral native state the common cases use. */
export const MODEL = 'common/1';

/** A tenant in one environment. */
export interface Realm {
  readonly tenant_id: string;
  readonly environment_id: string;
}

/** The trusted configuration of draft 4.2 that the adapter needs. */
export interface Gateway {
  readonly tenant_id: string;
  readonly environment_id: string;
  /** The public HTTPS origin, the only source of the scheme, host and port of a target URI. */
  readonly origin: string;
  /** The application headers the operation context covers, besides content-type. */
  readonly header_allowlist: readonly string[];
}

/**
 * Maps a method and a path template to an action and a resource template. A
 * `{name}` segment of the path matches one path segment, and the same
 * placeholder in `resource` is replaced by it.
 */
export interface Route {
  readonly method: string;
  readonly path: string;
  readonly action: string;
  readonly resource: string;
}

/** One installed version of the operation mapping. */
export interface Mapping {
  readonly version: string;
  readonly routes: readonly Route[];
}

/** An authenticated principal and the secret that proves it. */
export interface Identity {
  /** The name by which a case refers to the identity. */
  readonly ref: string;
  /** The principal id, namespaced by issuer. */
  readonly id: string;
  readonly realm: Realm;
  readonly workload: string;
  /** The bearer token that authenticates the identity. */
  readonly secret: string;
  readonly attributes: Readonly<Record<string, unknown>> | null;
}

/** An agent/key binding of a workload. */
export interface Enrollment {
  readonly realm: Realm;
  readonly workload: string;
  readonly agent_id: string;
  readonly operator_id: string;
  readonly holder_jkt: string;
  readonly status: string;
  readonly observed_at: number | null;
  readonly status_checked_at: number | null;
  readonly source_id: string;
  readonly source_ref: string;
}

/** One authoritative value of a principal. */
export interface ClaimRecord {
  readonly realm: Realm;
  readonly principal: string;
  readonly path: string;
  /** When set, the record is a fact of that resource, read only for an operation that lists it. */
  readonly resource: string;
  /** When set, the record is a fact of that task, read only for an intent of that task_id. */
  readonly task_id: string;
  /** The value as JSON; JSON null is a value, `null` is none. */
  readonly value: RawJSON | null;
  readonly observed_at: number | null;
  readonly status_checked_at: number | null;
  readonly source_id: string;
  readonly source_ref: string;
}

/**
 * The age limits of draft 9.2 that an installed check applies to the record
 * it consults. Both are required.
 */
export interface CheckFreshness {
  readonly max_age_seconds: number | null;
  readonly status_max_age_seconds: number | null;
}

/** An installed check and the verdict of its native state. */
export interface CheckRecord {
  readonly id: string;
  /** When set, the record applies only in a call whose authenticated principal has this id. */
  readonly principal: string;
  /** When set, the record applies only in a call whose agent binding names this agent. */
  readonly agent_id: string;
  readonly result: string;
  readonly reason_code: string;
  readonly source_id: string;
  readonly source_ref: string;
  readonly observed_at: number | null;
  readonly status_checked_at: number | null;
  /** When set, the age limits the check requires of the record it consults. */
  readonly freshness: CheckFreshness | null;
  /** When set, the revision of the source the check is pinned to. */
  readonly pinned_revision: string;
  /** The revision the source reports now. */
  readonly revision: string;
}

/** An obligation of a policy rule. */
export interface Obligation {
  readonly id: string;
  readonly attributes: Readonly<Record<string, unknown>> | null;
}

/**
 * One rule of the native policy. It applies to the principal of the realm it
 * names, for the action, and for the resource when it names one.
 */
export interface PolicyRule {
  readonly realm: Realm;
  readonly principal: string;
  readonly action: string;
  readonly resource: string;
  readonly effect: string;
  readonly obligations: readonly Obligation[];
  readonly reason: string;
  /** The policy source that holds the rule; `''`: the adapter's own store, POLICY_SOURCE_ID. */
  readonly source_id: string;
  readonly source_ref: string;
  readonly decided_at: number | null;
  readonly policy_revision: string;
}

/** The issuer, audience and key of outcome reports. */
export interface Reporting {
  readonly issuer: string;
  readonly audience: string;
  readonly kid: string;
}

/** An observation time the guard against re-stamping already holds for one source record. */
export interface Sighting {
  readonly source_id: string;
  readonly source_ref: string;
  readonly observed_at: number | null;
}

/** The native state of the memory adapter: the stores it reads. */
export interface State {
  readonly model: string;
  readonly gateway: Gateway;
  readonly mappings: readonly Mapping[];
  readonly identities: readonly Identity[];
  readonly enrollments: readonly Enrollment[];
  /** The native paths an administrator approved for readNativeClaim. */
  readonly approved_paths: readonly string[];
  readonly claims: readonly ClaimRecord[];
  readonly checks: readonly CheckRecord[];
  readonly policy: readonly PolicyRule[];
  /** `execution` when the adapter observes executions; `none` or `''` when it does not. */
  readonly visibility: string;
  /** The signer of outcome reports; `null`: recordOutcome is unavailable. */
  readonly reporting: Reporting | null;
  /** The observation times the guard against re-stamping starts with. */
  readonly sightings: readonly Sighting[];
  /** The ids of configured sources that cannot currently answer. */
  readonly unavailable_sources: readonly string[];
}

/**
 * The headers that never belong to an operation context (draft 10.2, 19):
 * credentials, presentations, hop-by-hop headers and signatures.
 */
const FORBIDDEN_HEADERS: readonly string[] = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'pact-presentation',
  'pact-admission',
  'connection',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'signature',
  'signature-input',
  'content-digest',
  'digest',
];

const q = JSON.stringify;

// Whether s is an absolute URI: a scheme, and no space, control or
// malformed escape.
export function isAbsoluteURI(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(s) && !/%(?![0-9A-Fa-f]{2})/.test(s);
}

function digestProblem(d: string): string | undefined {
  const validate: (d: string) => void = Digest.validate;
  try {
    validate(d);
    return undefined;
  } catch (err) {
    return (err as Error).message;
  }
}

/** Operations on {@link State} values. */
export const State = Object.freeze({
  /** Throws an `Error` naming the first problem in the state (Go `State.Validate`). */
  validate(st: State): void {
    if (st.model !== MODEL) throw new Error(`model is ${q(st.model)}, want ${q(MODEL)}`);
    const g = st.gateway;
    if (g.tenant_id === '' || g.environment_id === '') {
      throw new Error('gateway needs a tenant_id and an environment_id');
    }
    try {
      normalizeOrigin(g.origin);
    } catch (err) {
      throw new Error(`gateway origin: ${(err as Error).message}`);
    }
    for (const h of g.header_allowlist) {
      if (h !== h.toLowerCase() || FORBIDDEN_HEADERS.includes(h)) {
        throw new Error(
          `gateway header_allowlist: ${q(h)} must be a lowercase application header; credentials, presentations, hop-by-hop headers and signatures never belong to an operation`,
        );
      }
    }
    for (const m of st.mappings) {
      if (m.version === '') throw new Error('a mapping has no version');
      for (const rt of m.routes) {
        if (
          rt.method === '' ||
          !rt.path.startsWith('/') ||
          rt.action === '' ||
          rt.resource === ''
        ) {
          throw new Error(`mapping ${q(m.version)} has an incomplete route`);
        }
      }
    }
    const refs = new Set<string>();
    for (const i of st.identities) {
      if (
        i.ref === '' ||
        i.id === '' ||
        i.secret === '' ||
        (i.realm.tenant_id === '' && i.realm.environment_id === '')
      ) {
        throw new Error(`identity ${q(i.ref)} needs a ref, an id, a realm and a secret`);
      }
      if (refs.has(i.ref)) throw new Error(`identity ref ${q(i.ref)} is used twice`);
      refs.add(i.ref);
    }
    for (const e of st.enrollments) {
      if (!isBindingStatus(e.status)) {
        throw new Error(`enrollment of ${q(e.workload)} has status ${q(e.status)}`);
      }
      if (e.holder_jkt !== '') {
        const bad = digestProblem(e.holder_jkt);
        if (bad !== undefined) throw new Error(`enrollment of ${q(e.workload)}: ${bad}`);
      }
      if (e.source_id === '') throw new Error(`enrollment of ${q(e.workload)} names no source_id`);
      if (!isAbsoluteURI(e.agent_id)) {
        throw new Error(
          `enrollment of ${q(e.workload)}: agent_id ${q(e.agent_id)} is not an absolute URI`,
        );
      }
    }
    for (const c of st.claims) {
      if (!st.approved_paths.includes(c.path)) {
        throw new Error(`claim ${q(c.path)} is not under an approved path`);
      }
      if (c.value === null || c.value.text === '')
        throw new Error(`claim ${q(c.path)} has no value`);
      if (c.source_id === '') throw new Error(`claim ${q(c.path)} names no source_id`);
    }
    for (const c of st.checks) {
      if (c.id === '' || !isVerdict(c.result) || c.reason_code === '') {
        throw new Error(`check ${q(c.id)} needs an id, a result and a reason_code`);
      }
    }
    for (const p of st.policy) {
      if (!isEffect(p.effect) || p.principal === '' || p.action === '') {
        throw new Error(
          `a policy rule for ${q(p.principal)} needs a principal, an action and an effect`,
        );
      }
    }
    validateFreshness(st);
    if (st.visibility !== '' && st.visibility !== 'execution' && st.visibility !== 'none') {
      throw new Error(`visibility is ${q(st.visibility)}, want "execution" or "none"`);
    }
    const r = st.reporting;
    if (r !== null && (r.issuer === '' || r.audience === '' || r.kid === '')) {
      throw new Error('reporting needs an issuer, an audience and a kid');
    }
  },
});

// The members of the state that the freshness rules read.
function validateFreshness(st: State): void {
  for (const c of st.checks) {
    const f = c.freshness;
    if (f !== null && (f.max_age_seconds === null || f.status_max_age_seconds === null)) {
      throw new Error(
        `check ${q(c.id)}: freshness needs max_age_seconds and status_max_age_seconds`,
      );
    }
  }
  for (const s of st.sightings) {
    if (s.source_id === '' || s.source_ref === '' || s.observed_at === null) {
      throw new Error('a sighting needs a source_id, a source_ref and an observed_at');
    }
  }
  for (const id of st.unavailable_sources) {
    if (id === '') throw new Error('unavailable_sources lists an empty source id');
  }
}

/**
 * The origin in the form a target URI uses: the scheme and host lowercase,
 * the default port omitted (draft 10.2). Only an HTTPS origin without
 * userinfo, path, query or fragment is valid; throws an `Error` otherwise.
 */
export function normalizeOrigin(origin: string): string {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s.exec(origin);
  if (m === null || !equalFoldASCII(m[1] as string, 'https')) {
    throw new Error(`${q(origin)} is not an https origin`);
  }
  const rest = m[2] as string;
  if (!rest.startsWith('//')) throw new Error(`${q(origin)} is not a bare origin`);
  const after = rest.slice(2);
  const end = after.search(/[/?#]/);
  const authority = end < 0 ? after : after.slice(0, end);
  const tail = end < 0 ? '' : after.slice(end);
  if (authority === '' || authority.includes('@') || (tail !== '' && tail !== '/')) {
    throw new Error(`${q(origin)} is not a bare origin`);
  }
  let host: string;
  let port = '';
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) throw new Error(`${q(origin)} is not a bare origin`);
    host = authority.slice(1, close);
    const p = authority.slice(close + 1);
    if (p !== '' && !p.startsWith(':')) throw new Error(`${q(origin)} is not a bare origin`);
    port = p.slice(1);
  } else {
    const colon = authority.lastIndexOf(':');
    host = colon < 0 ? authority : authority.slice(0, colon);
    port = colon < 0 ? '' : authority.slice(colon + 1);
  }
  if (!/^[0-9]*$/.test(port)) throw new Error(`${q(origin)} is not a bare origin`);
  host = lowerASCII(host);
  if (host === '') throw new Error(`${q(origin)} has no host`);
  if (host.includes(':')) host = `[${host}]`;
  if (port !== '' && port !== '443') host += `:${port}`;
  return `https://${host}`;
}
