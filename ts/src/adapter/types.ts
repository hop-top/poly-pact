/**
 * The value types the seven adapter functions exchange (Go
 * hop.top/pact-go/adapter: adapter.go, auth.go, binding.go, claim.go, check.go,
 * authorize.go, outcome.go).
 *
 * Instants are Unix milliseconds, and `null` stands for the Go zero time: the
 * source gives no such time.
 *
 * @module
 */
import {
  CheckStatus,
  type Dimension,
  type EventKind,
  type OutcomeResult,
  type Severity,
} from '../core/enums.ts';
import type {
  Attribution,
  Intent,
  NativeAdapter,
  OperationContext,
  ReputationContext,
} from '../core/types.ts';
import type { Digest } from '../core/values.ts';

/** The trust realm a principal and a binding belong to: one tenant in one environment. */
export interface Realm {
  readonly tenantId: string;
  readonly environmentId: string;
}

/**
 * The namespaced identifier of the authenticated workload, such as a native
 * client, service account, certificate subject or local process identity. It
 * is opaque to PACT and compared for exact equality.
 */
export type Workload = string;

/**
 * How the native system authenticated the request, for example a mutual-TLS
 * client certificate or a bearer token. The set is open; PACT records the
 * value and does not interpret it.
 */
export type Mechanism = string;

/**
 * The authenticated principal and workload context that
 * `authenticateNative` produces. It comes only from the native system's
 * authenticated context, never from the request's own claims (draft 8.5).
 */
export interface Principal {
  /**
   * Identifies the principal. It is namespaced by issuer and tenant so that
   * two same-spelled identities of different issuers never compare equal.
   */
  readonly id: string;
  /** The tenant and environment the principal authenticated in. */
  readonly realm: Realm;
  /** The authenticated workload the request came from. */
  readonly workload: Workload;
  /** How the principal authenticated. */
  readonly mechanism: Mechanism;
  /** When native authentication of this request completed; `null` for none. */
  readonly authenticatedAt: number | null;
  /**
   * Further authenticated attributes the native system supplied, such as
   * groups. Each value is JSON data.
   */
  readonly attributes: Readonly<Record<string, unknown>>;
}

/**
 * The agent_id that a request names, an absolute URI (draft 6.1). It is
 * opaque to the adapter and compared for exact equality.
 */
export type AgentID = string;

/** The values of {@link BindingStatus}. */
const BINDING_STATUS = {
  /** The binding is enrolled and in force. */
  ACTIVE: 'ACTIVE',
  /** The binding was withdrawn, for example after a key rotation (draft 6.4). */
  REVOKED: 'REVOKED',
  /** The identity is marked compromised; the old key alone cannot recover it (draft 6.4). */
  COMPROMISED: 'COMPROMISED',
  /**
   * No current binding can be established, including the case of a workload
   * that is not enrolled (draft 6.1). It is never treated as active.
   */
  UNKNOWN: 'UNKNOWN',
} as const;

/** The current status of an agent/key binding. */
export const BindingStatus = Object.freeze(BINDING_STATUS);

/** The current status of an agent/key binding. */
export type BindingStatus = (typeof BINDING_STATUS)[keyof typeof BINDING_STATUS];

/** Reports whether `x` is a {@link BindingStatus} value (Go `BindingStatus.Valid`). */
export function isBindingStatus(x: unknown): x is BindingStatus {
  return typeof x === 'string' && Object.hasOwn(BINDING_STATUS, x);
}

/** The enrolled binding of a workload to an agent and its holder key. */
export interface AgentBinding {
  /** The enrolled agent_id, an absolute URI (draft 6.1); `''` when unknown. */
  readonly agentId: string;
  /** The operator the agent is bound to. */
  readonly operatorId: string;
  /** The RFC 7638 thumbprint of the enrolled public key (draft 6.2); `''` when unknown. */
  readonly holderJKT: Digest | '';
  /** The current status of the binding. */
  readonly status: BindingStatus;
  /** When the enrollment source recorded the binding; `null` for none. */
  readonly observedAt: number | null;
  /** When the status was last confirmed against the source; `null` for none. */
  readonly statusCheckedAt: number | null;
  /** Identifies the configured enrollment source. */
  readonly sourceId: string;
  /** An opaque reference into that source; `''` when none. */
  readonly sourceRef: string;
  /**
   * Reports that the agent ID the request names is enrolled for another
   * workload of the same realm, the same tenant and environment (draft
   * 17.1). It is meaningful only with status `UNKNOWN`: it is false whenever
   * a binding on the authenticated workload is returned, and an enrollment in
   * another realm never sets it. It lets a validator tell an agent ID the
   * authenticated workload has no record of (INVALID_PROOF) from an agent
   * enrolled for a different workload (CONTEXT_MISMATCH);
   * spec/v1.0/profiles/identity-mapping.md, IM-11 and section 8.
   */
  readonly enrolledElsewhere: boolean;
}

/** The values of {@link Verdict}. */
const VERDICT = { PASS: 'PASS', FAIL: 'FAIL', UNKNOWN: 'UNKNOWN' } as const;

/** The result of a context check. */
export type Verdict = (typeof VERDICT)[keyof typeof VERDICT];

/** The values of the result of a context check, and its mapping to a check status. */
export const Verdict = Object.freeze({
  ...VERDICT,
  /**
   * The check status with the same name as `v` (Go `Verdict.CheckStatus`). A
   * value that is not a verdict maps to `UNKNOWN`: a check that reported
   * nothing valid established nothing.
   */
  checkStatus(v: string): CheckStatus {
    switch (v) {
      case VERDICT.PASS:
        return CheckStatus.PASS;
      case VERDICT.FAIL:
        return CheckStatus.FAIL;
      default:
        return CheckStatus.UNKNOWN;
    }
  },
});

/** Reports whether `x` is a {@link Verdict} value (Go `Verdict.Valid`). */
export function isVerdict(x: unknown): x is Verdict {
  return typeof x === 'string' && Object.hasOwn(VERDICT, x);
}

/** The result of one installed context check. */
export interface CheckOutcome {
  /** PASS, FAIL or UNKNOWN. */
  readonly result: Verdict;
  /**
   * A stable code for the result, such as a draft 13.4 code or a
   * check-specific code of draft 17.3.1.
   */
  readonly reasonCode: string;
  /** Identifies the configured source the check consulted. */
  readonly sourceId: string;
  /** An opaque reference into that source; `''` when none. */
  readonly sourceRef: string;
  /** The original source observation time (draft 8.3); `null` for none. */
  readonly observedAt: number | null;
}

/**
 * What an installed check is evaluated on: the inputs of the draft 17.1 row
 * for check_context. The validator fills it from what it has already
 * established for this evaluation and from nothing a client sent.
 */
export interface CheckInput {
  /**
   * The authenticated principal and workload context, as
   * `authenticateNative` returned it, attributes included (draft 12.1: the
   * principal of the receipt). A check that compares a principal, or reads an
   * authenticated attribute such as device_id or peer_address, reads it here
   * and never from `operation.principal_id` alone.
   */
  readonly principal: Principal;
  /**
   * The enrolled binding of the agent the request names, as
   * `resolveAgentBinding` returned it and the validator verified it (draft
   * 11.3 step 2). A check that compares the agent reads `agentId` (and
   * `operatorId` when its source binds an operator) and never re-judges
   * `status`, which the validator decided. `null` means the caller
   * established no agent (Go: the zero binding); a check that compares the
   * agent then fails its scope comparison and never reports PASS.
   */
  readonly binding: AgentBinding | null;
  /** The declared intent. */
  readonly intent: Intent;
  /** The actual operation. */
  readonly operation: OperationContext;
  /** The evidence references the contract names (draft 9.3): names, never evidence content. */
  readonly evidenceRefs: readonly string[];
}

/**
 * The evaluation context a native claim is read in (draft 17.1: "approved
 * native path and context"). The approved mapping of a native path decides
 * which part of the context the read uses: a subject path uses `principal`,
 * a resource path uses the resources of `operation`, and a task path uses
 * the task of `intent`. An adapter reads nothing else from the request.
 */
export interface ClaimContext {
  /** The authenticated principal. */
  readonly principal: Principal;
  /** The declared intent; `intent.task_id` scopes task facts. */
  readonly intent: Intent;
  /** The actual operation; `operation.resources` scopes resource facts. */
  readonly operation: OperationContext;
}

/** An authoritative value read from a native source together with its provenance. */
export interface NativeClaim {
  /** The authoritative value as JSON data, compared as JSON data (draft 8.4); `null` is JSON null. */
  readonly value: unknown;
  /**
   * The original source observation time (draft 8.3), not the time of the
   * read; `null` when the source gives none.
   */
  readonly observedAt: number | null;
  /**
   * When the source last confirmed the value is still in force; `null` when
   * no status check took place.
   */
  readonly statusCheckedAt: number | null;
  /** Identifies the configured authoritative source. */
  readonly sourceId: string;
  /** An opaque reference into that source; `''` when none. */
  readonly sourceRef: string;
}

/** The values of {@link Effect}. */
const EFFECT = { ALLOW: 'ALLOW', DENY: 'DENY', UNKNOWN: 'UNKNOWN' } as const;

/** The effect of a native authorization decision. */
export const Effect = Object.freeze(EFFECT);

/** The effect of a native authorization decision. */
export type Effect = (typeof EFFECT)[keyof typeof EFFECT];

/** Reports whether `x` is an {@link Effect} value (Go `Effect.Valid`). */
export function isEffect(x: unknown): x is Effect {
  return typeof x === 'string' && Object.hasOwn(EFFECT, x);
}

/**
 * A condition the native policy attaches to a decision. PACT defines no
 * obligation types and never interprets one: it carries the obligation to
 * the enforcement point, and the gateway enforces it (draft 17.3). A profile
 * that relies on particular obligation types names them.
 */
export interface Obligation {
  /** The obligation type, as the native policy names it. */
  readonly id: string;
  /** The obligation's parameters as JSON data. */
  readonly attributes: Readonly<Record<string, unknown>>;
}

/**
 * The native policy's decision for the original principal and the actual
 * operation, with its provenance. It has no member with which a caller could
 * turn a denial into an allow: a denial is final by construction.
 */
export interface Decision {
  readonly effect: Effect;
  readonly obligations: readonly Obligation[];
  /**
   * The native policy's own explanation. It is untrusted text and may name
   * private resources, so it does not go into a public error.
   */
  readonly reason: string;
  /** Identifies the configured native policy source that decided; every decision names one. */
  readonly sourceId: string;
  /**
   * An opaque reference to the source's immutable record of the decision
   * (draft A.2), such as a decision log id; `''` when the source gives none.
   */
  readonly sourceRef: string;
  /**
   * When the source decided; `null` when the source gives none. It is never
   * later than now plus the baseline clock skew of draft 7.5.
   */
  readonly decidedAt: number | null;
  /** The revision of the native policy, as the source reports it; `''` when none. */
  readonly policyRevision: string;
}

/** Operations on {@link Decision} values. */
export const Decision = Object.freeze({
  /**
   * Reports whether the decision allows the operation (Go
   * `Decision.Permits`). Only an explicit `ALLOW` does; a deny, an unknown
   * and an undefined effect do not.
   */
  permits(d: Decision): boolean {
    return d.effect === EFFECT.ALLOW;
  },
});

/**
 * An attributable decision or execution observation, the content of an
 * outcome report (draft 14.1) that the observed system determines. The
 * signing claims and the reporter role belong to the recorder, which reports
 * under the role it is authorized for (draft 14.2).
 */
export interface Observation {
  /** The stable identifier of this observation; a retry carries the same one. */
  readonly eventId: string;
  readonly eventKind: EventKind;
  /** The agent, realm and reputation context of the event. */
  readonly context: ReputationContext;
  /** The authoritative native task. */
  readonly taskId: string;
  /** The operation the event concerns. */
  readonly operationId: string;
  /** The admission receipt, when one exists. */
  readonly admissionReceiptId: string | null;
  /** When the adapter observed the event at its source; `null` for none. */
  readonly observedAt: number | null;
  /** The result the observation supports. */
  readonly result: OutcomeResult;
  /** The reputation dimension the event counts toward. */
  readonly dimension: Dimension;
  readonly severity: Severity;
  /** References to the evidence behind the observation. */
  readonly evidenceRefs: readonly string[];
  /** Ties the event to a native task and a cause. */
  readonly attribution: Attribution;
  /** The events a correction replaces. */
  readonly supersedes: readonly string[];
  /** Untrusted free text. */
  readonly details: string;
}

/**
 * A recorded outcome: the compact JWS of an outcome report (typ
 * pact-outcome+jwt). A variant of {@link Recorded}.
 */
export class Signed {
  // The private member makes the class nominal, so no other value is a Signed.
  readonly #jws: string;

  constructor(jws: string) {
    this.#jws = jws;
    Object.freeze(this);
  }

  /** The compact JWS. */
  get jws(): string {
    return this.#jws;
  }

  /**
   * Throws unless `jws` has the three non-empty dot-separated segments of a
   * compact JWS (RFC 7515). It does not verify the signature.
   */
  validate(): void {
    const parts = this.jws.split('.');
    if (parts.length !== 3 || parts.some((p) => p === '')) {
      throw new Error('adapter: signed outcome is not a compact JWS');
    }
  }
}

// A string of Go unicode.IsSpace characters only, as strings.TrimSpace
// leaves empty: JavaScript's \s differs (it has U+FEFF and lacks U+0085).
const GO_SPACE = /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;

/**
 * A declared absence of execution visibility (draft 14.1). It is never filled
 * with an assumed success. A variant of {@link Recorded}.
 */
export class NoVisibility {
  readonly #reason: string;

  constructor(reason: string) {
    this.#reason = reason;
    Object.freeze(this);
  }

  /** Why the adapter cannot observe the execution. */
  get reason(): string {
    return this.#reason;
  }

  /** Throws when the reason is blank: an absence must be declared with its reason. */
  validate(): void {
    if (GO_SPACE.test(this.reason)) {
      throw new Error('adapter: no-visibility declaration has no reason');
    }
  }
}

/**
 * The result of recording an outcome: exactly one of {@link Signed} and
 * {@link NoVisibility}. Both are classes with a private member, so no other
 * value has this type, and `instanceof` over the two is exhaustive.
 */
export type Recorded = Signed | NoVisibility;

/**
 * The native protocol an adapter implements and the revision of its
 * operation mapping (draft 13.3).
 */
export interface Descriptor {
  /** The native protocol, such as "mcp". */
  readonly protocol: string;
  /** The exact protocol version the adapter implements. */
  readonly version: string;
  /** The revision of the adapter's operation mapping. */
  readonly mappingRevision: string;
}

/** Operations on {@link Descriptor} values. */
export const Descriptor = Object.freeze({
  /**
   * The descriptor as the entry a gateway publishes in its metadata (Go
   * `Descriptor.NativeAdapter`).
   */
  nativeAdapter(d: Descriptor): NativeAdapter {
    return { protocol: d.protocol, version: d.version, mapping_revision: d.mappingRevision };
  },
});
