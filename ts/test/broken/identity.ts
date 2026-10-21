/**
 * authenticate_native and resolve_agent_binding of the broken adapter, with
 * their defects (Go hop.top/pact-go/adapters/internal/broken, identity.go).
 *
 * @module
 */
import { AdapterError, DenialReason, NativeDenial } from '../../src/adapter/errors.ts';
import {
  type AgentBinding,
  BindingStatus,
  type Principal,
  type Realm,
} from '../../src/adapter/types.ts';
import {
  arrive,
  arrived,
  type Enrollment,
  type Identity,
} from '../../src/adapters/memory/index.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import type { Digest } from '../../src/core/values.ts';
import type { Adapter } from './broken.ts';
import { Defect } from './defects.ts';
import { revokedWithinContract } from './freshness.ts';
import { header, sameRealm } from './native.ts';

/** The principal of a stored identity. */
function principalOf(b: Adapter, i: Identity): Principal {
  return {
    id: i.id,
    realm: { tenantId: i.realm.tenant_id, environmentId: i.realm.environment_id },
    workload: i.workload,
    mechanism: 'bearer',
    authenticatedAt: b.now(),
    attributes: {},
  };
}

/**
 * The last element of a slash-separated path, as Go's `path.Base`: trailing
 * slashes are dropped, an empty path is `.` and a path of slashes only `/`.
 */
export function base(p: string): string {
  if (p === '') return '.';
  const trimmed = p.replace(/\/+$/, '');
  if (trimmed === '') return '/';
  return trimmed.slice(trimmed.lastIndexOf('/') + 1);
}

/**
 * The stored identity that a client-supplied identity header names, by id,
 * by local name, or by certificate subject.
 */
function identityFromHeaders(b: Adapter, req: RawRequest): Identity | undefined {
  for (const name of [
    'X-User',
    'X-Principal',
    'X-Forwarded-User',
    'X-Client-Cert',
    'X-Acme-Identity',
  ]) {
    let v = header(req, name);
    if (v === '') continue;
    v = (v.split(',', 1)[0] as string).replace(/^CN=/, '');
    for (const i of b.state().identities) {
      if (i.id === v || base(i.id) === v) return i;
    }
  }
  return undefined;
}

/** authenticateNative of the memory adapter, with the authentication defects. */
export async function authenticate(
  b: Adapter,
  req: RawRequest,
  signal?: AbortSignal,
): Promise<Principal> {
  try {
    return await authenticateWith(b, req, signal);
  } catch (err) {
    if (!b.has(Defect.LEAK_TOKEN_IN_DENIAL)) throw err;
    const token = header(req, 'Authorization').replace(/^Bearer /, '');
    throw new Error(
      `authentication failed for token ${token} (cookie ${header(req, 'Cookie')}): ${(err as Error).message}`,
      { cause: err },
    );
  }
}

async function authenticateWith(
  b: Adapter,
  req: RawRequest,
  signal?: AbortSignal,
): Promise<Principal> {
  if (b.has(Defect.REJECT_ENFORCEMENT_POINT) && arrived(req)) {
    throw new NativeDenial(DenialReason.CREDENTIAL_REJECTED);
  }
  const r = b.has(Defect.ACCEPT_BYPASS) ? arrive(req) : req;
  let p: Principal;
  try {
    p = await b.base.authenticateNative(r, signal);
  } catch (err) {
    if (
      b.has(Defect.TRUST_HEADER_IDENTITY) &&
      err instanceof NativeDenial &&
      err.reason === DenialReason.NO_CREDENTIAL
    ) {
      const id = identityFromHeaders(b, r);
      if (id !== undefined) return principalOf(b, id);
    }
    throw err;
  }
  if (b.has(Defect.HEADER_OVERRIDES_CREDENTIAL)) {
    const id = identityFromHeaders(b, r);
    if (id !== undefined) return principalOf(b, id);
  }
  if (b.has(Defect.CONFLATE_ISSUERS)) {
    const local = base(p.id);
    for (const i of b.state().identities) {
      if (base(i.id) === local) return principalOf(b, i);
    }
  }
  return misattribute(b, p);
}

/**
 * The defects that give an authenticated principal the identity or the
 * workload of someone else.
 */
function misattribute(b: Adapter, p: Principal): Principal {
  const ids = b.state().identities;
  if (b.has(Defect.CONFLATE_TENANTS)) {
    for (const i of ids) {
      if (lastComponent(i.id) === lastComponent(p.id)) return principalOf(b, i);
    }
  }
  const name = p.attributes.display_name;
  if (typeof name === 'string' && b.has(Defect.IDENTITY_BY_DISPLAY_NAME)) {
    for (const i of ids) {
      if (i.attributes?.display_name === name) return principalOf(b, i);
    }
  }
  let out = p;
  if (b.has(Defect.USER_WORKLOAD)) {
    const i = ids.find((x) => x.id === p.id);
    if (i !== undefined) out = { ...out, workload: i.workload };
  }
  if (b.has(Defect.REALM_WORKLOAD)) {
    const e = b.state().enrollments.find((x) => sameRealm(x.realm, out.realm));
    if (e !== undefined) out = { ...out, workload: e.workload };
  }
  return out;
}

/**
 * What follows the last colon of a namespaced identifier, or the whole
 * identifier when it has none.
 */
export function lastComponent(id: string): string {
  return id.slice(id.lastIndexOf(':') + 1);
}

/** The identifier without its last component, or `''` when it has a single one. */
export function dropLast(id: string): string {
  const i = id.lastIndexOf(':');
  return i < 0 ? '' : id.slice(0, i);
}

/** The enrollment of agent on workload in realm, whatever its status. */
function enrollmentOf(
  b: Adapter,
  realm: Realm,
  workload: string,
  agent: string,
): Enrollment | undefined {
  return recordsOf(b, realm, workload).find((e) => e.agent_id === agent);
}

/** The enrollments of workload in realm, of every agent. */
function recordsOf(b: Adapter, realm: Realm, workload: string): Enrollment[] {
  return b.state().enrollments.filter((e) => sameRealm(e.realm, realm) && e.workload === workload);
}

/** The binding an enrollment would have if it were active. */
function activeOf(b: Adapter, e: Enrollment): AgentBinding {
  return {
    agentId: e.agent_id,
    operatorId: e.operator_id,
    holderJKT: e.holder_jkt as Digest | '',
    status: BindingStatus.ACTIVE,
    observedAt: b.now(),
    statusCheckedAt: b.now(),
    sourceId: e.source_id,
    sourceRef: e.source_ref,
    enrolledElsewhere: false,
  };
}

const sameAdapterRealm = (a: Realm, c: Realm): boolean =>
  a.tenantId === c.tenantId && a.environmentId === c.environmentId;

/**
 * resolveAgentBinding of the memory adapter, with the binding defects. The
 * defects of the lookup choose the realm, the workload and the agent that the
 * memory adapter resolves; the defects of the result then change its answer.
 */
export async function resolveBinding(
  b: Adapter,
  realm: Realm,
  workload: string,
  agent: string,
  signal?: AbortSignal,
): Promise<AgentBinding> {
  // RevokedCountsAsInForce miscounts for the rule of a dedicated workload;
  // SelectDespiteDedicated does not apply that rule at all.
  if (
    b.has(Defect.REVOKED_COUNTS_AS_IN_FORCE) &&
    !b.shared &&
    !b.has(Defect.SELECT_DESPITE_DEDICATED) &&
    recordsOf(b, realm, workload).length > 1
  ) {
    throw AdapterError.unsupportedRequirement(
      `broken: workload ${JSON.stringify(workload)} has more than one enrollment`,
    );
  }
  let lookup = realm;
  if (b.has(Defect.CONFLATE_BINDING_REALMS)) {
    const e = b.state().enrollments.find((x) => x.workload === workload);
    if (e !== undefined) {
      lookup = { tenantId: e.realm.tenant_id, environmentId: e.realm.environment_id };
    }
  }
  const asked = workload;
  const askedAgent = agent;
  let w = looseWorkload(b, lookup, workload);
  w = crossWorkload(b, lookup, w, agent);
  const a = selectAgent(b, lookup, w, agent);
  const got = await b.base.resolveAgentBinding(lookup, w, a, signal);

  if (got.status === BindingStatus.REVOKED || got.status === BindingStatus.COMPROMISED) {
    const e = enrollmentOf(b, lookup, w, a);
    if (e !== undefined) {
      const compromised = got.status === BindingStatus.COMPROMISED;
      const k = credentialKey(b, lookup, w);
      if (
        (b.has(Defect.REVIVE_REVOKED_BINDING) && !compromised) ||
        (b.has(Defect.REVIVE_COMPROMISED_BINDING) && compromised) ||
        (b.has(Defect.RECOVER_BY_OLD_KEY) && compromised && k !== '' && k === e.holder_jkt)
      ) {
        return activeOf(b, e);
      }
      if (b.has(Defect.CACHE_BINDING_FOR_CONTRACT) && revokedWithinContract(b, e)) {
        return activeOf(b, e);
      }
    }
    if (b.has(Defect.UNUSABLE_AS_ERROR)) {
      throw AdapterError.invalidProof('broken: the enrolled binding is not in force');
    }
    if (b.has(Defect.STATUS_WITHOUT_RECORD)) {
      return {
        agentId: '',
        operatorId: '',
        holderJKT: '',
        status: got.status,
        observedAt: got.observedAt,
        statusCheckedAt: got.statusCheckedAt,
        sourceId: got.sourceId,
        sourceRef: got.sourceRef,
        enrolledElsewhere: false,
      };
    }
    return got;
  }
  let out = got;
  const k = credentialKey(b, lookup, w);
  if (b.has(Defect.HOLDER_KEY_FROM_CREDENTIAL) && k !== '' && got.status === BindingStatus.ACTIVE) {
    out = { ...got, holderJKT: k as Digest };
  }
  // Only the caller's own realm, workload and agent lose their binding; a
  // binding found through the defects of the lookup is a different defect.
  if (
    b.has(Defect.LOSE_ACTIVE_BINDING) &&
    got.status === BindingStatus.ACTIVE &&
    sameAdapterRealm(lookup, realm) &&
    w === asked &&
    a === askedAgent
  ) {
    return {
      agentId: '',
      operatorId: '',
      holderJKT: '',
      status: BindingStatus.UNKNOWN,
      observedAt: null,
      statusCheckedAt: null,
      sourceId: '',
      sourceRef: '',
      enrolledElsewhere: false,
    };
  }
  if (b.has(Defect.TRUST_UNENROLLED) && got.status === BindingStatus.UNKNOWN) {
    return {
      agentId: `urn:workload:${w}`,
      operatorId: '',
      holderJKT: 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M' as Digest,
      status: BindingStatus.ACTIVE,
      observedAt: b.now(),
      statusCheckedAt: b.now(),
      sourceId: 'synthetic',
      sourceRef: '',
      enrolledElsewhere: false,
    };
  }
  if (got.status === BindingStatus.UNKNOWN) {
    return { ...out, enrolledElsewhere: elsewhere(b, lookup, a, got.enrolledElsewhere) };
  }
  return out;
}

/**
 * The defects that misreport whether the agent ID is enrolled for another
 * workload of the realm, given the memory adapter's report. Only an UNKNOWN
 * answer carries the report, defects or not.
 */
function elsewhere(b: Adapter, realm: Realm, agent: string, reported: boolean): boolean {
  if (b.has(Defect.NEVER_SET_ELSEWHERE)) return false;
  if (b.has(Defect.ELSEWHERE_ACROSS_REALMS)) {
    for (const e of b.state().enrollments) {
      if (e.agent_id === agent && !sameRealm(e.realm, realm)) return true;
    }
  }
  return reported;
}

/**
 * The defects that match a workload with no enrollment to an enrolled one by
 * a comparison looser than octet equality.
 */
function looseWorkload(b: Adapter, realm: Realm, workload: string): string {
  if (recordsOf(b, realm, workload).length > 0) return workload;
  for (const e of b.state().enrollments) {
    if (!sameRealm(e.realm, realm)) continue;
    if (
      b.has(Defect.BINDING_BY_REALM) ||
      (b.has(Defect.MATCH_LOCAL_PART) && lastComponent(e.workload) === lastComponent(workload)) ||
      (b.has(Defect.DROP_LAST_COMPONENT) &&
        dropLast(workload) !== '' &&
        dropLast(e.workload) === dropLast(workload))
    ) {
      return e.workload;
    }
  }
  return workload;
}

/**
 * CrossWorkloadAgent: an agent with no record on the workload is looked up on
 * the first other workload of the realm that enrolls it.
 */
function crossWorkload(b: Adapter, realm: Realm, workload: string, agent: string): string {
  if (!b.has(Defect.CROSS_WORKLOAD_AGENT)) return workload;
  if (enrollmentOf(b, realm, workload, agent) !== undefined) return workload;
  const e = b.state().enrollments.find((x) => sameRealm(x.realm, realm) && x.agent_id === agent);
  return e === undefined ? workload : e.workload;
}

/**
 * The defects that resolve a workload without the agent ID the request names:
 * they return the agent they resolve instead, and `''` for none, which no
 * record names.
 */
function selectAgent(b: Adapter, realm: Realm, workload: string, agent: string): string {
  const rows = recordsOf(b, realm, workload);
  let a = agent;
  if (b.has(Defect.IGNORE_AGENT_ID)) a = soleInForce(rows);
  if (rows.length < 2) return a;
  if (b.has(Defect.FIRST_OF_SHARED)) return (rows[0] as Enrollment).agent_id;
  // Every record counts as in force, so two or more name no agent.
  if (b.has(Defect.REVOKED_IN_FORCE)) return '';
  if (b.has(Defect.COMPROMISED_NOT_IN_FORCE)) {
    const kept = rows.filter((e) => e.status !== BindingStatus.COMPROMISED);
    if (kept.length === 1) return (kept[0] as Enrollment).agent_id;
  }
  return a;
}

/**
 * The rule of the memory adapter applied to every record of a workload
 * instead of the records of one agent: the agent of the single record in
 * force, or of the single revoked record when none is in force, and `''`
 * otherwise.
 */
function soleInForce(rows: readonly Enrollment[]): string {
  let inForce = rows.filter((e) => e.status !== BindingStatus.REVOKED);
  if (inForce.length === 0) inForce = [...rows];
  return inForce.length === 1 ? (inForce[0] as Enrollment).agent_id : '';
}

/**
 * The thumbprint of the key that the credential of the workload's identity is
 * bound to, the jkt member of its cnf attribute, and `''` when it names none.
 */
function credentialKey(b: Adapter, realm: Realm, workload: string): string {
  for (const i of b.state().identities) {
    if (!sameRealm(i.realm, realm) || i.workload !== workload) continue;
    const cnf = i.attributes?.cnf;
    if (typeof cnf === 'object' && cnf !== null && !Array.isArray(cnf)) {
      const k = (cnf as Record<string, unknown>).jkt;
      if (typeof k === 'string') return k;
    }
  }
  return '';
}
