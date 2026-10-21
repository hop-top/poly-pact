/**
 * The case model of the adapter conformance suite (Go
 * hop.top/pact-go/adapter/adaptertest, casefile.go): one case file is a
 * stimulus for one of the seven draft 17.1 functions and the behavior the
 * draft requires of it.
 *
 * Every member keeps the case-file member name, which
 * spec/v1.0/fixtures/adapters/README.md documents, except `Request.tlsPeer`
 * (case-file member `tls_peer`), whose value is the `TLSPeer` of
 * `RawRequest`. A Go pointer member is `null` when absent, a Go string `''`,
 * a Go slice or map `null` when absent where the format tells absent from
 * empty, and a Go `json.RawMessage` the {@link RawJSON} text of the member.
 *
 * @module
 */
import type { TLSPeer } from '../../core/binding/index.ts';
import type { Dimension, EventKind, OutcomeResult, Severity } from '../../core/enums.ts';
import type { Attribution, Intent, OperationContext, ReputationContext } from '../../core/types.ts';
import type { RawJSON } from '../../core/values.ts';

export type { TLSPeer };

/** One case file. */
export interface Case {
  readonly case_version: number;
  readonly id: string;
  readonly title: string;
  /** The draft sections the case rests on. */
  readonly draft: readonly string[];
  /**
   * Limits the case to the adapters whose profile supports workloads shared
   * by several agents, `shared`, or to those whose profile does not,
   * `dedicated`. `''`: the case applies to every adapter.
   */
  readonly workloads: string;
  /** The case's current time in Unix seconds; `null` when absent (the suite's default). */
  readonly now: number | null;
  /** Handed to the adapter's factory verbatim. */
  readonly native_state: RawJSON;
  readonly request: Request | null;
  readonly call: Call;
  readonly expect: Expect;
}

/** The HTTP request of an authenticate_native or map_operation case. */
export interface Request {
  readonly method: string;
  /** The request-target as the gateway received it. */
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  /** The request body, standard base64 with padding; `''` for none. */
  readonly body_b64: string;
  /** The client certificate of a mutual-TLS connection; `null` when none. */
  readonly tlsPeer: TLSPeer | null;
  /**
   * The native identity whose credential the request presents; the
   * subject's `credential` hook attaches it. `''` when none.
   */
  readonly native_state_ref: string;
  /** `enforcement_point` (the default, also `''`) or `direct`. */
  readonly arrival: string;
}

/** A realm in a case file. */
export interface RealmJSON {
  readonly tenant_id: string;
  readonly environment_id: string;
}

/** An authenticated principal handed to a function directly. */
export interface PrincipalJSON {
  readonly id: string;
  readonly realm: RealmJSON;
  readonly workload: string;
  /** `''` stands for the default, `test`. */
  readonly mechanism: string;
  /** Unix seconds; `null` when absent (the case's now). */
  readonly authenticated_at: number | null;
  readonly attributes: Readonly<Record<string, unknown>> | null;
}

/**
 * An agent binding handed to check_context: the binding of the agent the
 * request names, as resolve_agent_binding returned it and the validator
 * verified it (draft 11.3 step 2, 17.1).
 */
export interface BindingJSON {
  readonly agent_id: string;
  readonly operator_id: string;
  readonly holder_jkt: string;
  /** `''` stands for ACTIVE. */
  readonly status: string;
}

/** An observation in a case file, with the member names of the outcome report (draft 14.1). */
export interface ObservationJSON {
  readonly event_id: string;
  readonly event_kind: EventKind;
  readonly context: ReputationContext;
  readonly task_id: string;
  readonly operation_id: string;
  readonly admission_receipt_id: string | null;
  /** Unix seconds. */
  readonly observed_at: number;
  readonly result: OutcomeResult;
  readonly dimension: Dimension;
  readonly severity: Severity;
  readonly evidence_refs: readonly string[] | null;
  readonly attribution: Attribution;
  readonly supersedes: readonly string[] | null;
  readonly details: string;
}

/**
 * The arguments of the function under test other than the HTTP request.
 * Which members a case may set depends on `expect.function`.
 */
export interface Call {
  readonly realm: RealmJSON | null;
  readonly workload: string;
  /** The agent ID the request names, the third input of resolve_agent_binding (draft 17.1). */
  readonly agent_id: string;
  readonly mapping_version: string;
  readonly principal: PrincipalJSON | null;
  /**
   * The agent binding of a check_context call; `null`: the call establishes
   * no agent and the check receives no binding.
   */
  readonly binding: BindingJSON | null;
  readonly native_path: string;
  readonly check_id: string | null;
  readonly intent: Intent | null;
  readonly operation: OperationContext | null;
  readonly evidence_refs: readonly string[] | null;
  readonly observation: ObservationJSON | null;
}

/**
 * What the case requires. `function`, `outcome` and the member that belongs
 * to the outcome carry the assertions; the rest are optional.
 */
export interface Expect {
  /** One of the seven draft 17.1 function names. */
  readonly function: string;
  /** One of the outcomes defined for the function. */
  readonly outcome: string;
  /**
   * The stable code the function reports: the public denial reason, the
   * draft 13.4 code of an error, or the reason code of a check.
   */
  readonly reason_code: string;
  /** Native hooks that must not have fired by the end of the case. */
  readonly must_not_call: readonly string[];
  /** When set, no credential may appear in the values and errors the function returns. */
  readonly leak_scan: LeakScan | null;
  readonly principal: ExpectPrincipal | null;
  readonly binding: ExpectBinding | null;
  readonly operation: ExpectOperation | null;
  readonly claim: ExpectClaim | null;
  readonly decision: ExpectDecision | null;
}

/** The credential scan of draft 19. */
export interface LeakScan {
  /** Literal credential values that must not appear anywhere. */
  readonly secrets: readonly string[];
}

/** The members of the authenticated principal to check; an empty member is not checked. */
export interface ExpectPrincipal {
  readonly id: string;
  readonly realm: RealmJSON | null;
  readonly workload: string;
  readonly mechanism: string;
  /**
   * A JSON object when set: each of its members must equal, as JSON data,
   * the principal's attribute of the same name.
   */
  readonly attributes: RawJSON | null;
}

/** The members of the agent binding to check; an empty member is not checked. */
export interface ExpectBinding {
  readonly agent_id: string;
  readonly operator_id: string;
  readonly holder_jkt: string;
  readonly status: string;
  /**
   * When set, the required `enrolledElsewhere`: whether the agent ID is
   * enrolled for another workload of the realm (draft 17.1). It may be true
   * only for the outcome `unknown`, and it is the only member that outcome
   * accepts.
   */
  readonly enrolled_elsewhere: boolean | null;
}

/** The members of the operation context to check; `''` or `null` is not checked. */
export interface ExpectOperation {
  readonly environment_id: string;
  readonly principal_id: string;
  readonly action: string;
  readonly resources: readonly string[] | null;
  readonly method: string;
  readonly target_uri: string;
  readonly body_digest: string;
  readonly headers: Readonly<Record<string, string>> | null;
}

/**
 * The members of the native claim to check. `null` is not checked; a JSON
 * null in a time member requires no time.
 */
export interface ExpectClaim {
  readonly value: RawJSON | null;
  readonly observed_at: RawJSON | null;
  readonly status_checked_at: RawJSON | null;
  readonly source_id: string;
  readonly source_ref: string;
}

/**
 * The members of the native decision to check. `null` or `''` is not
 * checked; a JSON null in `decided_at` requires no decision time, and a JSON
 * null in `source_ref` requires an empty source reference: the source keeps
 * no record of the decision.
 */
export interface ExpectDecision {
  /** When set, must equal the decision's obligations exactly, in order. */
  readonly obligations: readonly ObligationJSON[] | null;
  readonly source_id: string;
  readonly source_ref: RawJSON | null;
  /** Unix seconds, or JSON null. */
  readonly decided_at: RawJSON | null;
  readonly policy_revision: string;
}

/** An obligation in a case file. */
export interface ObligationJSON {
  readonly id: string;
  readonly attributes: Readonly<Record<string, unknown>> | null;
}
