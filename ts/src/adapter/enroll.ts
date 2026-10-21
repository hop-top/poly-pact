/**
 * The enrollment registry behind the draft 17.1 function
 * resolve_agent_binding (Go package hop.top/pact-go/adapter/enroll): the record
 * that binds a stable agent_id to an authenticated workload in a realm, with
 * its operator and its holder key (draft 6.1, 6.2), and the lifecycle
 * operations on that record (draft 6.4).
 *
 * The module holds the {@link Registry} contract, the {@link Actor} that may
 * change a binding, the {@link EnrollError}, the {@link AuditEntry} every
 * change leaves, and {@link Resolver}, which exposes a Registry as the
 * `BindingResolver` an adapter needs. The in-memory backend is
 * `./adapter/enroll/memory`.
 *
 * ## Who may change a binding
 *
 * Enrollment, rotation and the compromise mark are native administrative
 * operations (draft 6.1). The only trusted actors are `ADMIN`, a native
 * authenticated administrative workflow, and `AUTHORIZED_ISSUER`, an
 * identity-binding or rotation issuer the gateway's administrators
 * configured. The agent holding the old key is an `AGENT` actor and has no
 * authority: proof by the old key alone never rotates a key and never
 * recovers a compromised identity. An actor's authority is scoped to the one
 * realm named in `Actor.realm`.
 *
 * ## Binding status
 *
 * `lookup` selects the record by the agent_id the request names, among the
 * records of the authenticated workload in the realm, and reports the status
 * of its binding:
 *
 * - ACTIVE: enrolled and in force.
 * - REVOKED: withdrawn. It is not rotated or enrolled back to life.
 * - COMPROMISED: marked by an authority. It is terminal: no Registry method
 *   returns it to ACTIVE or REVOKED. The remediated agent is enrolled under a
 *   new agent_id.
 * - UNKNOWN: no current binding can be established. It covers an agent_id
 *   with no record on the workload, including one enrolled only for another
 *   workload, so that a workload alone, or a credential that several agents
 *   share, never selects an agent. `enrolledElsewhere` then says whether the
 *   agent_id is enrolled for another workload of the realm (draft 17.1).
 *
 * ## Dedicated workloads
 *
 * By default a workload serves one agent (identity mapping IM-19): a registry
 * refuses to enroll an agent for a workload that an enrollment in force
 * already names (`WORKLOAD_IN_USE`), and `lookup` reports a workload with
 * more than one enrollment in force as a configuration error, an
 * `AdapterError` with code `UNSUPPORTED_REQUIREMENT` and no binding (draft
 * 17.1). An enrollment is in force unless it is revoked; a compromised one is
 * in force, so that a compromise is never hidden behind a newer record. A
 * backend may support workloads shared by several agents as an option, for a
 * profile that supports them.
 *
 * The mapping rules these types implement are in
 * spec/v1.0/profiles/identity-mapping.md.
 *
 * @module
 */
import type { Digest } from '../core/values.ts';
import type { AgentBinding, AgentID, BindingResolver, Realm, Workload } from './index.ts';

/** The values of {@link ActorKind}. */
const ACTOR_KIND = {
  /**
   * A native authenticated administrative workflow: an administrator of the
   * realm acting through the environment's existing admin controls (draft
   * 6.1, 6.4). A trusted enrollment actor.
   */
  ADMIN: 'ADMIN',
  /**
   * An identity-binding or rotation issuer that the gateway's administrators
   * configured for the realm (draft 4.2, 6.1, 6.4). A trusted enrollment
   * actor.
   */
  AUTHORIZED_ISSUER: 'AUTHORIZED_ISSUER',
  /**
   * The agent itself, or anyone presenting its key. Self-registration proves
   * neither organizational identity nor entitlement (draft 6.1), so an agent
   * has no authority over any binding.
   */
  AGENT: 'AGENT',
} as const;

/** The capacity in which an {@link Actor} acts on an enrollment. */
export const ActorKind = Object.freeze(ACTOR_KIND);

/** The capacity in which an {@link Actor} acts on an enrollment. */
export type ActorKind = (typeof ACTOR_KIND)[keyof typeof ACTOR_KIND];

/** Reports whether `x` is an {@link ActorKind} value (Go `ActorKind.Valid`). */
export function isActorKind(x: unknown): x is ActorKind {
  return typeof x === 'string' && Object.hasOwn(ACTOR_KIND, x);
}

/** The kinds of an {@link EnrollError}, one per Go sentinel error. */
export type EnrollErrorKind =
  | 'NOT_AUTHORIZED'
  | 'NOT_FOUND'
  | 'ALREADY_ENROLLED'
  | 'COMPROMISED'
  | 'REVOKED'
  | 'KEY_REUSE'
  | 'INVALID'
  | 'WORKLOAD_IN_USE';

// The text of each Go sentinel error, after "enroll: ".
const TEXT: Readonly<Record<EnrollErrorKind, string>> = {
  NOT_AUTHORIZED: 'actor is not a trusted enrollment actor',
  NOT_FOUND: 'agent is not enrolled in the realm',
  ALREADY_ENROLLED: 'agent_id is already enrolled in the realm',
  COMPROMISED: 'binding is marked compromised',
  REVOKED: 'binding is revoked',
  KEY_REUSE: 'holder key was already enrolled in the realm',
  INVALID: 'invalid argument',
  WORKLOAD_IN_USE: 'workload already has an enrollment in force',
};

/**
 * A change to a binding that a registry refuses:
 *
 * - `NOT_AUTHORIZED`: the actor is not a trusted enrollment actor for its
 *   realm. It is reported before the registry looks at the target, so it
 *   never reveals whether an agent is enrolled.
 * - `NOT_FOUND`: the agent_id is not enrolled in the actor's realm.
 * - `ALREADY_ENROLLED`: the agent_id is already enrolled in the realm, in any
 *   status. An agent_id is enrolled once; a replacement identity is a new
 *   agent_id.
 * - `COMPROMISED`: the binding is marked compromised and cannot be changed by
 *   rotation or revocation (draft 6.4).
 * - `REVOKED`: the binding is revoked and cannot be rotated.
 * - `KEY_REUSE`: the holder key is, or ever was, enrolled in the realm. A key
 *   is enrolled at most once, so rotation cannot restore a retired key and
 *   two agents never share one.
 * - `INVALID`: an argument is malformed, such as a thumbprint that is not 43
 *   base64url characters or an agent_id that is not an absolute URI.
 * - `WORKLOAD_IN_USE`: the workload already has an enrollment in force in the
 *   realm, and the registry does not support workloads shared by several
 *   agents (spec/v1.0/profiles/identity-mapping.md, IM-18, IM-19).
 *
 * The message is `enroll: <the Go sentinel text>[: <detail>]`.
 */
export class EnrollError extends Error {
  readonly kind: EnrollErrorKind;
  readonly detail: string;

  constructor(kind: EnrollErrorKind, detail = '', options?: { readonly cause?: unknown }) {
    super(
      `enroll: ${TEXT[kind]}${detail === '' ? '' : `: ${detail}`}`,
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = 'EnrollError';
    this.kind = kind;
    this.detail = detail;
  }
}

/** Who asks a {@link Registry} to change a binding. */
export interface Actor {
  /** The capacity in which the actor acts. */
  readonly kind: ActorKind;
  /**
   * Identifies the actor for the audit log: an administrator account, an
   * issuer identifier. It is never interpreted.
   */
  readonly id: string;
  /**
   * The realm the actor's authority covers, and so the realm whose bindings
   * the call addresses. An actor has no authority outside it.
   */
  readonly realm: Realm;
}

/** Operations on {@link Actor} values. */
export const Actor = Object.freeze({
  /**
   * Returns when `a` is a trusted enrollment actor for its realm: its kind is
   * `ADMIN` or `AUTHORIZED_ISSUER`, its id is set so that the change is
   * attributable, and its realm names a tenant and an environment. Otherwise
   * it throws an {@link EnrollError} of kind `NOT_AUTHORIZED` (Go
   * `Actor.CheckAuthority`).
   */
  checkAuthority(a: Actor): void {
    if (a.kind !== ACTOR_KIND.ADMIN && a.kind !== ACTOR_KIND.AUTHORIZED_ISSUER) {
      throw new EnrollError(
        'NOT_AUTHORIZED',
        `actor kind ${JSON.stringify(a.kind)} is not a trusted enrollment actor`,
      );
    }
    if (a.id === '') throw new EnrollError('NOT_AUTHORIZED', 'the actor is not attributable');
    if (a.realm.tenantId === '' || a.realm.environmentId === '') {
      throw new EnrollError('NOT_AUTHORIZED', 'the actor has no realm');
    }
  },
});

/**
 * The enrollment registry of draft 6.1 and 6.4: it answers whether an agent
 * is bound to a workload and with which holder key, and it applies rotation
 * and the compromise mark. Enrolling an agent is a native administrative
 * operation that each backend exposes in its own terms.
 */
export interface Registry {
  /**
   * Resolves to the binding of the agent to the workload in the realm, with
   * the semantics of `BindingResolver.resolveAgentBinding`: the agent ID
   * selects among the records of the workload only. A binding in state
   * COMPROMISED or REVOKED is returned in that state; it is never reported as
   * active. Status UNKNOWN, with no identity, is the answer when the agent
   * has no record on the workload in the realm, which includes an agent
   * enrolled only for another workload; `enrolledElsewhere` then reports
   * whether the agent is enrolled for another workload of the realm, and an
   * enrollment in another realm never sets it. A source that cannot answer
   * rejects with code `DEPENDENCY_UNAVAILABLE`.
   *
   * Unless the registry supports workloads shared by several agents, a
   * workload with more than one enrollment in force in the realm is a
   * configuration error: the call rejects with code
   * `UNSUPPORTED_REQUIREMENT`, whichever agent ID it is given (draft 17.1,
   * identity mapping IM-19).
   */
  lookup(
    realm: Realm,
    workload: Workload,
    agentId: AgentID,
    signal?: AbortSignal,
  ): Promise<AgentBinding>;

  /**
   * Replaces the holder key of the agent with `newJKT`, in `admin.realm`.
   * `admin` must be a trusted enrollment actor ({@link Actor.checkAuthority});
   * proof by the old key never suffices. The old key stops being the
   * enrolled key at once. It rejects with kind `COMPROMISED` or `REVOKED` for
   * a binding in that state, `KEY_REUSE` for a key that was ever enrolled in
   * the realm, `INVALID` for a malformed thumbprint and `NOT_FOUND` for an
   * agent that is not enrolled.
   */
  rotate(admin: Actor, agentId: string, newJKT: Digest, signal?: AbortSignal): Promise<void>;

  /**
   * Marks the binding of the agent compromised, in `authority.realm`.
   * `authority` must be a trusted enrollment actor. The mark is terminal and
   * a repeat is a no-op. It rejects with kind `NOT_FOUND` for an agent that
   * is not enrolled.
   */
  markCompromised(authority: Actor, agentId: string, signal?: AbortSignal): Promise<void>;
}

/** Exposes a {@link Registry} as the `BindingResolver` of draft 17.1. */
export class Resolver implements BindingResolver {
  readonly registry: Registry;

  constructor(registry: Registry) {
    this.registry = registry;
  }

  /** `registry.lookup` for the realm, workload and agent. */
  resolveAgentBinding(
    realm: Realm,
    workload: Workload,
    agent: AgentID,
    signal?: AbortSignal,
  ): Promise<AgentBinding> {
    return this.registry.lookup(realm, workload, agent, signal);
  }
}

/** The values of {@link AuditAction}. */
const AUDIT_ACTION = {
  ENROLL: 'ENROLL',
  ROTATE: 'ROTATE',
  REVOKE: 'REVOKE',
  MARK_COMPROMISED: 'MARK_COMPROMISED',
} as const;

/** The change an {@link AuditEntry} records. */
export const AuditAction = Object.freeze(AUDIT_ACTION);

/** The change an {@link AuditEntry} records. */
export type AuditAction = (typeof AUDIT_ACTION)[keyof typeof AUDIT_ACTION];

/** The values of {@link AuditResult}. */
const AUDIT_RESULT = {
  /** The change was made. */
  APPLIED: 'APPLIED',
  /** The binding was already in the requested state. */
  UNCHANGED: 'UNCHANGED',
  /** The actor has no authority, and nothing else was examined. */
  DENIED: 'DENIED',
  /**
   * The actor has authority and the request was refused, for example for an
   * unknown agent, a compromised binding or a reused key.
   */
  REJECTED: 'REJECTED',
} as const;

/** What became of the request an {@link AuditEntry} records. */
export const AuditResult = Object.freeze(AUDIT_RESULT);

/** What became of the request an {@link AuditEntry} records. */
export type AuditResult = (typeof AUDIT_RESULT)[keyof typeof AUDIT_RESULT];

/**
 * One attempt to change a binding. A registry appends an entry for every
 * attempt, including denied and rejected ones, and never edits or removes
 * one; a rotation entry is the retained rotation event of draft 6.4.
 */
export interface AuditEntry {
  /** Numbers the entries of one registry from 1, without gaps. */
  readonly seq: number;
  /** When the registry handled the request, Unix milliseconds. */
  readonly at: number;
  /** The requested change. */
  readonly action: AuditAction;
  /** Who asked, as the caller stated it. For a denied entry it is unverified. */
  readonly actor: Actor;
  /** The agent the request addressed. */
  readonly agentId: string;
  /** The enrolled workload; set for `ENROLL` only. */
  readonly workload: Workload;
  /**
   * The enrolled key before a rotation, when the registry got as far as
   * reading it; `''` otherwise.
   */
  readonly oldJKT: Digest | '';
  /** The key the request enrolls: set for `ENROLL` and `ROTATE`. */
  readonly newJKT: Digest | '';
  /** What became of the request. */
  readonly result: AuditResult;
  /** The refusal for a denied or rejected entry; `''` otherwise. */
  readonly reason: string;
}
