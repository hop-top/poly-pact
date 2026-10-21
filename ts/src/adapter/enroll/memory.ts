/**
 * An in-memory enrollment registry for tests, examples and single-process
 * gateways (Go package hop.top/pact-go/adapter/enroll/memory). It keeps no state
 * across restarts and its audit log grows with every attempt, denied ones
 * included, so it is not a production store.
 *
 * @module
 */
import { type Clock, SystemClock } from '../../core/clock.ts';
import { Digest } from '../../core/values.ts';
import {
  Actor,
  AuditAction,
  type AuditEntry,
  AuditResult,
  EnrollError,
  type Registry,
} from '../enroll.ts';
import {
  AdapterError,
  type AgentBinding,
  type AgentID,
  BindingStatus,
  type Realm,
  type Workload,
} from '../index.ts';

// Digest.validate, callable where an assertion signature is not.
const validateDigest: (d: string) => void = Digest.validate;

/** The `sourceId` of a registry built without the `sourceId` option. */
export const DEFAULT_SOURCE_ID = 'enroll-memory';

/**
 * The native fact an administrator records: this agent runs as this
 * workload, belongs to this operator and holds this key. The realm is the
 * realm of the enrolling actor.
 */
export interface Enrollment {
  /** The stable agent_id, an absolute URI without a fragment. */
  readonly agentId: string;
  /** The accountable operator. It is required. */
  readonly operatorId: string;
  /**
   * The authenticated workload the agent runs as. Several agents may share
   * one workload only in a registry built with `sharedWorkloads`; each then
   * has its own enrollment.
   */
  readonly workload: Workload;
  /** The RFC 7638 thumbprint of the agent's public key. */
  readonly holderJKT: Digest;
}

/**
 * Options of a {@link MemoryRegistry}. Several are applied in order, a later
 * member overriding an earlier one.
 */
export interface Option {
  /** The clock that stamps observations; the system clock by default. */
  readonly clock?: Clock;
  /** The `sourceId` that `lookup` reports; {@link DEFAULT_SOURCE_ID} by default. */
  readonly sourceId?: string;
  /**
   * Makes the registry that of a profile that supports workloads shared by
   * several agents (spec/v1.0/profiles/identity-mapping.md, IM-19): `enroll`
   * accepts any number of agents for a workload, and `lookup` selects among
   * them by the agent ID. Without it a workload serves one agent.
   */
  readonly sharedWorkloads?: boolean;
}

/** The option that sets the clock (Go `WithClock`). */
export function withClock(c: Clock): Option {
  return { clock: c };
}

/** The option that sets the source id (Go `WithSourceID`). */
export function withSourceId(id: string): Option {
  return { sourceId: id };
}

/** The option of a registry with shared workloads (Go `WithSharedWorkloads`). */
export function withSharedWorkloads(): Option {
  return { sharedWorkloads: true };
}

/**
 * The in-memory backend of {@link Registry}. Every method runs to its end
 * before another starts, so it is safe for concurrent use.
 */
export class MemoryRegistry implements Registry {
  readonly #clock: Clock;
  readonly #sourceId: string;
  readonly #shared: boolean;

  // The record of each (realm, agent_id), the records of each (realm,
  // workload) in enrollment order, every key ever enrolled in each realm,
  // and the audit log.
  readonly #agents = new Map<string, Row>();
  readonly #byWork = new Map<string, Row[]>();
  readonly #usedKeys = new Set<string>();
  readonly #audit: AuditEntry[] = [];

  /** An empty registry (Go `New`). */
  constructor(...opts: readonly Option[]) {
    let clock: Clock = new SystemClock();
    let sourceId = DEFAULT_SOURCE_ID;
    let shared = false;
    for (const o of opts) {
      if (o.clock !== undefined) clock = o.clock;
      if (o.sourceId !== undefined) sourceId = o.sourceId;
      if (o.sharedWorkloads !== undefined) shared = o.sharedWorkloads;
    }
    this.#clock = clock;
    this.#sourceId = sourceId;
    this.#shared = shared;
  }

  /**
   * Implements `Registry.lookup`. The registry is the enrollment source, so a
   * read confirms the status as of now (`statusCheckedAt`) while
   * `observedAt` stays the time of the last change to the binding.
   *
   * The agent_id selects the record: a realm holds one record per agent_id
   * (`enroll` refuses a second), and `lookup` returns it, in any status, when
   * it names exactly this workload. A record of another workload is never the
   * answer, and neither is a record of another agent of a workload that
   * several agents share; both answer UNKNOWN. When the agent's record names
   * another workload, the UNKNOWN answer reports it in `enrolledElsewhere`
   * (draft 17.1); a record in another realm is never consulted.
   *
   * Unless the registry was built with `sharedWorkloads`, a workload with more
   * than one record in force, which `enroll` refuses to create but a
   * compromise mark on a revoked record can bring about, is the configuration
   * error of IM-19: the call rejects with code `UNSUPPORTED_REQUIREMENT`,
   * whichever agent ID it is given.
   */
  async lookup(
    realm: Realm,
    workload: Workload,
    agentId: AgentID,
    signal?: AbortSignal,
  ): Promise<AgentBinding> {
    unavailable(signal);
    const n = this.#inForce(realm, workload);
    if (!this.#shared && n > 1) {
      throw AdapterError.unsupportedRequirement(
        `enroll memory: workload ${JSON.stringify(workload)} has ${n} enrollments in force and serves one agent, a configuration error for the administrators of the registry`,
      );
    }
    const row = this.#agents.get(agentKey(realm, agentId));
    if (row !== undefined && row.workload !== workload) {
      return { ...this.#read(undefined), enrolledElsewhere: true };
    }
    return this.#read(row);
  }

  /**
   * Records the binding of `e` in the realm of `actor`. The binding starts
   * ACTIVE. It rejects with an `EnrollError` of kind `NOT_AUTHORIZED` unless
   * the actor is trusted, `INVALID` for a malformed member,
   * `ALREADY_ENROLLED` when the agent_id is enrolled in the realm in any
   * status, `KEY_REUSE` when the key was ever enrolled in the realm, and,
   * unless the registry was built with `sharedWorkloads`, `WORKLOAD_IN_USE`
   * when a record in force of the realm already names the workload (identity
   * mapping IM-19).
   */
  async enroll(actor: Actor, e: Enrollment, signal?: AbortSignal): Promise<void> {
    unavailable(signal);
    const entry = this.#begin(AuditAction.ENROLL, actor, e.agentId);
    entry.workload = e.workload;
    entry.newJKT = e.holderJKT;
    this.#authorize(entry);
    try {
      validateEnrollment(e);
    } catch (err) {
      this.#refuse(entry, err as EnrollError);
    }
    const ak = agentKey(actor.realm, e.agentId);
    if (this.#agents.has(ak)) {
      this.#refuse(entry, new EnrollError('ALREADY_ENROLLED', JSON.stringify(e.agentId)));
    }
    const kk = keyKey(actor.realm, e.holderJKT);
    if (this.#usedKeys.has(kk)) {
      this.#refuse(entry, new EnrollError('KEY_REUSE', JSON.stringify(e.holderJKT)));
    }
    if (!this.#shared && this.#inForce(actor.realm, e.workload) > 0) {
      this.#refuse(
        entry,
        new EnrollError('WORKLOAD_IN_USE', `${JSON.stringify(e.workload)} serves one agent`),
      );
    }

    const row: Row = {
      workload: e.workload,
      binding: {
        agentId: e.agentId,
        operatorId: e.operatorId,
        holderJKT: e.holderJKT,
        status: BindingStatus.ACTIVE,
        observedAt: entry.at,
        statusCheckedAt: null,
        sourceId: this.#sourceId,
        sourceRef: `enrollment/${this.#agents.size + 1}`,
        enrolledElsewhere: false,
      },
    };
    const wk = workKey(actor.realm, e.workload);
    this.#agents.set(ak, row);
    this.#byWork.set(wk, [...(this.#byWork.get(wk) ?? []), row]);
    this.#usedKeys.add(kk);
    this.#commit(entry, AuditResult.APPLIED);
  }

  /**
   * Implements `Registry.rotate`. The rotation takes effect for the next
   * `lookup`: the registry has no cache, so its propagation bound is zero.
   */
  async rotate(admin: Actor, agentId: string, newJKT: Digest, signal?: AbortSignal): Promise<void> {
    unavailable(signal);
    const entry = this.#begin(AuditAction.ROTATE, admin, agentId);
    entry.newJKT = newJKT;
    this.#authorize(entry);
    try {
      validateDigest(newJKT);
    } catch (err) {
      this.#refuse(entry, new EnrollError('INVALID', (err as Error).message, { cause: err }));
    }
    const row = this.#agents.get(agentKey(admin.realm, agentId));
    if (row === undefined) {
      this.#refuse(entry, new EnrollError('NOT_FOUND', JSON.stringify(agentId)));
    }
    entry.oldJKT = row.binding.holderJKT;
    if (row.binding.status === BindingStatus.COMPROMISED) {
      this.#refuse(entry, new EnrollError('COMPROMISED', JSON.stringify(agentId)));
    }
    if (row.binding.status === BindingStatus.REVOKED) {
      this.#refuse(entry, new EnrollError('REVOKED', JSON.stringify(agentId)));
    }
    const kk = keyKey(admin.realm, newJKT);
    if (this.#usedKeys.has(kk)) {
      this.#refuse(entry, new EnrollError('KEY_REUSE', JSON.stringify(newJKT)));
    }

    row.binding = { ...row.binding, holderJKT: newJKT, observedAt: entry.at };
    this.#usedKeys.add(kk);
    this.#commit(entry, AuditResult.APPLIED);
  }

  /**
   * Implements `Registry.markCompromised`. Compromised is terminal: a later
   * `rotate`, `revoke` or `enroll` of the same agent_id fails, and `lookup`
   * keeps reporting COMPROMISED. A revoked binding can be marked compromised.
   */
  async markCompromised(authority: Actor, agentId: string, signal?: AbortSignal): Promise<void> {
    unavailable(signal);
    const entry = this.#begin(AuditAction.MARK_COMPROMISED, authority, agentId);
    this.#authorize(entry);
    const row = this.#agents.get(agentKey(authority.realm, agentId));
    if (row === undefined) {
      this.#refuse(entry, new EnrollError('NOT_FOUND', JSON.stringify(agentId)));
    }
    if (row.binding.status === BindingStatus.COMPROMISED) {
      this.#commit(entry, AuditResult.UNCHANGED);
      return;
    }
    row.binding = { ...row.binding, status: BindingStatus.COMPROMISED, observedAt: entry.at };
    this.#commit(entry, AuditResult.APPLIED);
  }

  /**
   * Withdraws the binding of the agent in the actor's realm; the actor must
   * be trusted. A revoked binding is not rotated or enrolled back to life.
   * Revoking again is a no-op, and a compromised binding cannot be revoked:
   * it rejects with kind `COMPROMISED`, so the compromise mark is never
   * downgraded.
   */
  async revoke(actor: Actor, agentId: string, signal?: AbortSignal): Promise<void> {
    unavailable(signal);
    const entry = this.#begin(AuditAction.REVOKE, actor, agentId);
    this.#authorize(entry);
    const row = this.#agents.get(agentKey(actor.realm, agentId));
    if (row === undefined) {
      this.#refuse(entry, new EnrollError('NOT_FOUND', JSON.stringify(agentId)));
    }
    if (row.binding.status === BindingStatus.COMPROMISED) {
      this.#refuse(entry, new EnrollError('COMPROMISED', JSON.stringify(agentId)));
    }
    if (row.binding.status === BindingStatus.REVOKED) {
      this.#commit(entry, AuditResult.UNCHANGED);
      return;
    }
    row.binding = { ...row.binding, status: BindingStatus.REVOKED, observedAt: entry.at };
    this.#commit(entry, AuditResult.APPLIED);
  }

  /** A copy of the audit log, oldest entry first. */
  audit(): AuditEntry[] {
    return this.#audit.map(copyEntry);
  }

  // The number of records of workload in realm that are in force: every
  // record that is not REVOKED, a COMPROMISED one included (IM-18).
  #inForce(realm: Realm, workload: Workload): number {
    const rows = this.#byWork.get(workKey(realm, workload)) ?? [];
    return rows.filter((r) => r.binding.status !== BindingStatus.REVOKED).length;
  }

  // The binding of row confirmed as of now, or the UNKNOWN binding for no row.
  #read(row: Row | undefined): AgentBinding {
    const b: AgentBinding = row?.binding ?? {
      agentId: '',
      operatorId: '',
      holderJKT: '',
      status: BindingStatus.UNKNOWN,
      observedAt: null,
      statusCheckedAt: null,
      sourceId: this.#sourceId,
      sourceRef: '',
      enrolledElsewhere: false,
    };
    return { ...b, statusCheckedAt: this.#clock.now() };
  }

  // The audit entry of a request, with a copy of the actor as stated.
  #begin(action: AuditAction, actor: Actor, agentId: string): Draft {
    return {
      at: this.#clock.now(),
      action,
      actor: copyActor(actor),
      agentId,
      workload: '',
      oldJKT: '',
      newJKT: '',
      reason: '',
    };
  }

  // Appends the entry with its result.
  #commit(e: Draft, result: AuditResult): void {
    this.#audit.push(Object.freeze({ ...e, seq: this.#audit.length + 1, result }));
  }

  // Checks the actor of the entry, and audits and throws a denial.
  #authorize(e: Draft): void {
    try {
      Actor.checkAuthority(e.actor);
    } catch (err) {
      e.reason = (err as Error).message;
      this.#commit(e, AuditResult.DENIED);
      throw err;
    }
  }

  // Audits a request an authorized actor made and throws err.
  #refuse(e: Draft, err: EnrollError): never {
    e.reason = err.message;
    this.#commit(e, AuditResult.REJECTED);
    throw err;
  }
}

// One enrollment. The workload and the agent never change; the key, the
// status and the observation time do, by replacing the binding.
// binding.statusCheckedAt stays null here and is set on each read.
interface Row {
  readonly workload: Workload;
  binding: AgentBinding;
}

// An audit entry being built: every member but its number and result.
type Draft = { -readonly [K in Exclude<keyof AuditEntry, 'seq' | 'result'>]: AuditEntry[K] };

// The map keys. JSON arrays keep the parts apart whatever they contain.
function agentKey(realm: Realm, agentId: string): string {
  return JSON.stringify([realm.tenantId, realm.environmentId, agentId]);
}

function workKey(realm: Realm, workload: Workload): string {
  return JSON.stringify([realm.tenantId, realm.environmentId, workload]);
}

function keyKey(realm: Realm, jkt: string): string {
  return JSON.stringify([realm.tenantId, realm.environmentId, jkt]);
}

function copyActor(a: Actor): Actor {
  return Object.freeze({
    kind: a.kind,
    id: a.id,
    realm: Object.freeze({ tenantId: a.realm.tenantId, environmentId: a.realm.environmentId }),
  });
}

function copyEntry(e: AuditEntry): AuditEntry {
  return { ...e, actor: { ...e.actor, realm: { ...e.actor.realm } } };
}

// Throws for an aborted call: a source that cannot answer, with the abort
// reason as the cause.
function unavailable(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw AdapterError.dependencyUnavailable('the call was aborted', { cause: signal.reason });
  }
}

function validateEnrollment(e: Enrollment): void {
  if (!absoluteURI(e.agentId)) {
    throw new EnrollError(
      'INVALID',
      `agent_id ${JSON.stringify(e.agentId)} is not an absolute URI (RFC 3986)`,
    );
  }
  if (e.operatorId === '') throw new EnrollError('INVALID', 'operator_id is empty');
  if (e.workload === '') throw new EnrollError('INVALID', 'workload is empty');
  try {
    validateDigest(e.holderJKT);
  } catch (err) {
    throw new EnrollError('INVALID', (err as Error).message, { cause: err });
  }
}

const URI_CHARS = "-._~:/?[]@!$&'()*+,;=";

// Reports whether s is an absolute-URI of RFC 3986 section 4.3: a scheme, a
// colon and a non-empty remainder of URI characters, with no fragment.
// Non-ASCII text must already be percent-encoded.
function absoluteURI(s: string): boolean {
  const colon = s.indexOf(':');
  if (colon <= 0 || colon === s.length - 1 || !isAlpha(s.charCodeAt(0))) return false;
  for (let i = 1; i < colon; i++) {
    const c = s.charCodeAt(i);
    if (!isAlpha(c) && !isDigit(c) && c !== 0x2b && c !== 0x2d && c !== 0x2e) return false;
  }
  for (let i = colon + 1; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (isAlpha(c) || isDigit(c) || URI_CHARS.includes(s.charAt(i))) continue;
    if (
      c === 0x25 &&
      i + 2 < s.length &&
      isHex(s.charCodeAt(i + 1)) &&
      isHex(s.charCodeAt(i + 2))
    ) {
      i += 2;
      continue;
    }
    return false;
  }
  return true;
}

function isAlpha(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a);
}

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

function isHex(c: number): boolean {
  return isDigit(c) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46);
}
