/**
 * authenticate_native and resolve_agent_binding of the memory adapter, and
 * the enforcement-point mark (Go hop.top/pact-go/adapters/memory, identity.go
 * and Arrive, Credential and bearer of memory.go).
 *
 * @module
 */
import { timingSafeEqual } from 'node:crypto';
import { AdapterError, DenialReason, NativeDenial } from '../../adapter/errors.ts';
import {
  type AgentBinding,
  BindingStatus,
  type Principal,
  type Realm,
} from '../../adapter/types.ts';
import { equalFoldASCII } from '../../core/binding/chars.ts';
import type { RawRequest } from '../../core/binding/index.ts';
import type { Digest } from '../../core/values.ts';
import { type Core, checkSourceTimes, live, outage, sourceTime, unavailable } from './core.ts';
import type { Enrollment, Identity } from './state.ts';

// The requests that came through the enforcement point. Module-private, so
// no client-supplied value can carry the mark.
const ARRIVED = new WeakSet<RawRequest>();

/**
 * Marks `req` as having arrived through the enforcement point and returns the
 * request to use: a frozen copy that carries the mark. A real enforcement
 * point calls it after it has taken the request off the wire; a request that
 * did not pass through it carries no mark, and authenticateNative refuses it.
 */
export function arrive(req: RawRequest): RawRequest {
  const marked: RawRequest = Object.freeze({ ...req });
  ARRIVED.add(marked);
  return marked;
}

/** Whether `req` carries the mark that {@link arrive} sets. */
export function arrived(req: RawRequest): boolean {
  return ARRIVED.has(req);
}

/** The value of the first `name` field line of req, without regard to case; `''` when none. */
export function headerValue(req: RawRequest, name: string): string {
  for (const [k, v] of req.headers) if (equalFoldASCII(k, name)) return v;
  return '';
}

/**
 * `req` with the bearer token of the identity named `ref`, unless it
 * already carries an Authorization header. Throws for an unknown ref.
 */
export function credentialOf(c: Core, req: RawRequest, ref: string): RawRequest {
  const i = c.st.identities.find((x) => x.ref === ref);
  if (i === undefined) throw new Error(`memory: no identity ${JSON.stringify(ref)}`);
  if (headerValue(req, 'Authorization') !== '') return req;
  return { ...req, headers: [...req.headers, ['Authorization', `Bearer ${i.secret}`]] };
}

// The bearer token of req and whether req carries an Authorization header at all.
function bearer(req: RawRequest): { token: string; presented: boolean } {
  const h = headerValue(req, 'Authorization').trim();
  if (h === '') return { token: '', presented: false };
  const sp = h.indexOf(' ');
  if (sp < 0 || !equalFoldASCII(h.slice(0, sp), 'Bearer')) return { token: '', presented: true };
  return { token: h.slice(sp + 1).trim(), presented: true };
}

/** The bearer token of req, `''` when none. */
export function bearerToken(req: RawRequest): string {
  return bearer(req).token;
}

// Whether a and b are equal, in time that does not depend on where they differ.
function sameSecret(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * The identity that `token` authenticates. It compares against every
 * identity, so that the time taken does not depend on which one matches.
 */
export function identityBySecret(c: Core, token: string): Identity | undefined {
  let found: Identity | undefined;
  for (const i of c.st.identities) {
    if (sameSecret(i.secret, token) && token !== '') found = i;
  }
  return found;
}

/**
 * authenticate_native: the bearer token of the Authorization header and
 * nothing else. A header such as X-User or X-Forwarded-User, which any client
 * can send, names no one (draft 8.5). A request that did not pass through the
 * enforcement point is refused whatever it carries.
 */
export function authenticate(c: Core, req: RawRequest, signal?: AbortSignal): Principal {
  live('authenticate', signal);
  const { token, presented } = bearer(req);
  if (!presented) throw new NativeDenial(DenialReason.NO_CREDENTIAL);
  if (!arrived(req)) throw new NativeDenial(DenialReason.CREDENTIAL_REJECTED);
  const id = identityBySecret(c, token);
  if (id === undefined) throw new NativeDenial(DenialReason.CREDENTIAL_REJECTED);
  return {
    id: id.id,
    realm: { tenantId: id.realm.tenant_id, environmentId: id.realm.environment_id },
    workload: id.workload,
    mechanism: 'bearer',
    authenticatedAt: c.clock.now(),
    attributes: structuredClone(id.attributes ?? {}),
  };
}

const inRealm = (e: Enrollment, realm: Realm): boolean =>
  e.realm.tenant_id === realm.tenantId && e.realm.environment_id === realm.environmentId;

/**
 * resolve_agent_binding: the records are selected by realm, workload and
 * agent ID together, so the agent ID selects among the records of the
 * workload only. An agent with no such record has status UNKNOWN; the
 * workload alone names no agent. When the source holds several records of
 * the agent on the workload, {@link current} picks the answer. A binding the
 * source holds as revoked or compromised is returned as that status, with
 * the agent, operator and holder key of the record and no error (identity
 * mapping IM-11, IM-29).
 *
 * Unless the adapter supports shared workloads, a workload serves one agent,
 * and a workload with more than one enrollment in force in the realm is a
 * configuration error: whichever agent ID the request names, the call rejects
 * with UNSUPPORTED_REQUIREMENT (draft 17.1, identity mapping IM-19). A record
 * is in force unless it is REVOKED. Counting needs every record of the
 * workload, so a record of the workload whose source cannot answer fails the
 * call as a source that cannot answer.
 *
 * An UNKNOWN answer reports, in `enrolledElsewhere`, whether the agent has a
 * record, in any status, on another workload of the realm (draft 17.1). A
 * record in another realm never sets it. A record of the agent on another
 * workload whose source cannot answer leaves that report unknown, so the
 * call fails as a source that cannot answer.
 */
export function resolveBinding(
  c: Core,
  realm: Realm,
  workload: string,
  agent: string,
  signal?: AbortSignal,
): AgentBinding {
  live('resolve binding', signal);
  if (!c.shared) dedicated(c, realm, workload);
  const rows: Enrollment[] = [];
  const elsewhere: Enrollment[] = [];
  for (const e of c.st.enrollments) {
    if (!inRealm(e, realm) || e.agent_id !== agent) continue;
    if (e.workload !== workload) {
      elsewhere.push(e);
      continue;
    }
    if (unavailable(c, e.source_id)) throw outage('resolve binding', e.source_id);
    rows.push(e);
  }
  const e = current(rows);
  if (
    e !== undefined &&
    (e.status === BindingStatus.ACTIVE ||
      e.status === BindingStatus.REVOKED ||
      e.status === BindingStatus.COMPROMISED)
  ) {
    const observed = sourceTime(e.observed_at);
    const checked = sourceTime(e.status_checked_at);
    checkSourceTimes(c, observed, checked);
    return {
      agentId: e.agent_id,
      operatorId: e.operator_id,
      holderJKT: e.holder_jkt as Digest | '',
      status: e.status,
      observedAt: observed,
      statusCheckedAt: checked,
      sourceId: e.source_id,
      sourceRef: e.source_ref,
      enrolledElsewhere: false,
    };
  }
  for (const x of elsewhere) {
    if (unavailable(c, x.source_id)) throw outage('resolve binding', x.source_id);
  }
  return {
    agentId: '',
    operatorId: '',
    holderJKT: '',
    status: BindingStatus.UNKNOWN,
    observedAt: null,
    statusCheckedAt: null,
    sourceId: '',
    sourceRef: '',
    enrolledElsewhere: elsewhere.length > 0,
  };
}

// Throws when workload has more than one enrollment in force in realm: the
// configuration error of a workload that serves one agent (identity mapping
// IM-19).
function dedicated(c: Core, realm: Realm, workload: string): void {
  let inForce = 0;
  for (const e of c.st.enrollments) {
    if (!inRealm(e, realm) || e.workload !== workload) continue;
    if (unavailable(c, e.source_id)) throw outage('resolve binding', e.source_id);
    if (e.status !== BindingStatus.REVOKED) inForce++;
  }
  if (inForce > 1) {
    throw AdapterError.unsupportedRequirement(
      `memory: resolve binding: workload ${JSON.stringify(workload)} has ${inForce} enrollments in force and serves one agent, a configuration error for the administrators of the enrollment source`,
    );
  }
}

/**
 * The enrollment that answers for an agent on a workload, given all the
 * records of that agent on that workload in the realm; `undefined` when none
 * does.
 *
 * One record in force, one that is not REVOKED, is the answer. A COMPROMISED
 * record stays in force, so that a compromise is never hidden behind another
 * record of the agent. When no record is in force, a single revoked record is
 * the answer. Several records, in force or revoked, answer nothing, never the
 * first or the most recent (identity mapping IM-18).
 */
function current(rows: readonly Enrollment[]): Enrollment | undefined {
  let inForce = rows.filter((e) => e.status !== BindingStatus.REVOKED);
  if (inForce.length === 0) inForce = [...rows];
  return inForce.length === 1 ? inForce[0] : undefined;
}
