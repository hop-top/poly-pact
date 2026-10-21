/**
 * The values of an evaluation case (Go hop.top/pact-go/runner/evalcase,
 * files.go): config.json, native_context.json and the expected
 * decision.json (spec/v1.0/fixtures/README.md, sections config.json,
 * native_context.json, decision.json and their additions), and exchange.json
 * with its defaults applied.
 *
 * The members of the case files keep their JSON names, as the generated
 * core types do. An absent member reads as the zero value of its type (`''`,
 * `0`, `false`, `[]`, `{}`); a member that may be null in the file reads as
 * `null` when it is null or absent.
 *
 * @module
 */
import { Algorithms } from '../core/jws/alg.ts';
import { ALG_ES256 } from '../core/jws/typ.ts';
import type { FieldRule } from '../core/types.ts';
import type { RawJSON } from '../core/values.ts';

/** config.json: the trusted configuration of the gateway. */
export interface Config {
  readonly mode: string;
  readonly now: number;
  readonly clock_skew_seconds: number;
  readonly gateway: Gateway;
  readonly trust: readonly TrustRecord[];
  readonly validator: Validator;
  readonly native_mappings: readonly NativeMapping[];
  readonly installed_checks: readonly string[];
  readonly active_policy: ActivePolicy;
  /** The limits of draft Section 20.1 by their metadata keys. */
  readonly limits: Readonly<Record<string, number>>;
  readonly executor_classes: readonly ExecutorClass[];
  readonly check_freshness: Readonly<Record<string, number>>;
  /** null when the contract's set is the conservative set. */
  readonly selection: Selection | null;
}

/** config.json's gateway. */
export interface Gateway {
  readonly gateway_id: string;
  readonly environment_id: string;
  readonly tenant_id: string;
  readonly operation_mapping_version: string;
  readonly extensions_supported: readonly string[];
  /**
   * The GatewayMetadata.jws_algorithms the gateway publishes (draft 13.1,
   * A.3); null when config.json does not name it. See {@link Gateway.algorithms}.
   */
  readonly jws_algorithms: readonly string[] | null;
}

/** Operations on {@link Gateway} values (Go `Gateway` methods). */
export const Gateway = Object.freeze({
  /**
   * The JOSE algorithms the gateway publishes: its jws_algorithms, or the
   * baseline ES256 alone when config.json does not name them (draft 7.2).
   */
  algorithms(g: Gateway): Algorithms {
    return new Algorithms(g.jws_algorithms ?? [ALG_ES256]);
  },
});

/**
 * One trust record: an issuer, the signer role it is trusted for, its public
 * JWK files (paths under the fixture directory) and, for evidence issuers
 * and reputation services, the claim paths it may assert. reporter_role is
 * set in the trust records of outcome cases.
 */
export interface TrustRecord {
  readonly iss: string;
  readonly role: string;
  readonly keys: readonly string[];
  readonly claim_paths: readonly string[];
  readonly reporter_role: string | null;
}

/** The validator that signs the admission attestation. */
export interface Validator {
  readonly iss: string;
  readonly source_id: string;
  readonly key: string;
}

/**
 * The native path that is authoritative for a profile path (draft Section
 * 17.2). source is the declared capability of the mapping's native source;
 * null when config.json declares none (absent or null).
 */
export interface NativeMapping {
  readonly path: string;
  readonly native_path: string;
  readonly source: NativeSource | null;
}

/**
 * The declared capability of a native source (spec/v1.0/fixtures/README.md,
 * config.json additions; freshness profile, section 4.2). Every member is
 * required in the file.
 */
export interface NativeSource {
  /** The source_id of the native claims the source answers. */
  readonly sourceId: string;
  readonly bestMaxAgeSeconds: number;
  readonly bestStatusMaxAgeSeconds: number;
  readonly liveCheck: boolean;
  /** none, poll_delta or push. */
  readonly changeFeed: string;
}

/** The active requirement and learning versions. */
export interface ActivePolicy {
  readonly base_revision: string;
  readonly selected_set: string;
  readonly learning_policy_digest: string;
  readonly learning_artifact_digest: string;
}

/** One entry of the installed execution-identity mapping; executor_id is null when only the class is compared. */
export interface ExecutorClass {
  readonly principal_id: string;
  readonly task_id: string;
  readonly operation_id: string;
  readonly class: string;
  readonly executor_id: string | null;
}

/** The requirement-set selection the gateway performed. */
export interface Selection {
  readonly selector: Selector;
  /** The path of a decoded snapshot; null when the current input is the presented snapshot. */
  readonly current_snapshot: string | null;
  readonly record: SelectionRecord;
}

/** The selector a contract pins. */
export interface Selector {
  readonly implementation_id: string;
  readonly learning_artifact_digest: string;
  readonly order: readonly string[];
  readonly sets: Readonly<Record<string, readonly FieldRule[]>>;
  readonly thresholds: Readonly<Record<string, Threshold>>;
}

/** What a snapshot must meet for a set. */
export interface Threshold {
  readonly dimensions: Readonly<Record<string, Minimums>>;
  readonly security_status: string;
}

/** The minimums of one reputation dimension. */
export interface Minimums {
  readonly score_bps: number;
  readonly confidence_bps: number;
  readonly independent_tasks: number;
}

/** The selection record. */
export interface SelectionRecord {
  readonly record_ref: string;
  readonly learning_policy_digest: string;
  readonly learning_artifact_digest: string;
  readonly snapshot_jti: string | null;
  readonly hold_refs: readonly string[];
  readonly base_revision: string;
}

/** native_context.json: what the native environment establishes. */
export interface NativeContext {
  readonly authenticated: Authenticated | null;
  readonly native_claims: readonly NativeClaim[];
  readonly approval: Approval | null;
  readonly delegation: Delegation | null;
  readonly executor: Executor | null;
  readonly evidence_status: Readonly<Record<string, EvidenceStatus>>;
  readonly security_holds: readonly string[];
  readonly authorize: boolean;
}

/**
 * The result of authenticate_native and resolve_agent_binding for the
 * presented agent. agent_id, operator_id and holder_jkt are null exactly
 * when binding_status is unknown: the agent has no record on the
 * authenticated workload in the realm (identity mapping IM-11).
 */
export interface Authenticated {
  readonly principal_id: string;
  readonly agent_id: string | null;
  readonly operator_id: string | null;
  readonly tenant_id: string;
  readonly holder_jkt: string | null;
  /** active, revoked, compromised or unknown (draft 17.1, in lower case). */
  readonly binding_status: string;
  readonly authenticated_at: number;
  /** The realm holds a record of the presented agent ID for another workload; only with unknown. */
  readonly enrolled_elsewhere: boolean;
  /**
   * null, or UNSUPPORTED_REQUIREMENT when the workload holds more than one
   * enrollment in force under a profile without shared workloads (identity
   * mapping IM-19); binding_status is then unknown.
   */
  readonly binding_error: string | null;
}

/** The binding status of an agent with an active binding. */
export const BINDING_ACTIVE = 'active';
/** The binding status of a revoked binding. */
export const BINDING_REVOKED = 'revoked';
/** The binding status of a compromised binding. */
export const BINDING_COMPROMISED = 'compromised';
/** The binding status of an agent with no record on the authenticated workload. */
export const BINDING_UNKNOWN = 'unknown';

/** What read_native_claim returns for a native path. */
export interface NativeClaim {
  readonly native_path: string;
  /** The value as written; null when the member is absent. */
  readonly value: RawJSON | null;
  readonly observed_at: number;
  readonly status_checked_at: number;
  readonly source_id: string;
}

/** The native approval state; the format v2 members are null when absent or null. */
export interface Approval {
  readonly ref: string;
  readonly state: string;
  readonly agent_id: string;
  readonly principal_id: string;
  readonly purpose_id: string;
  readonly task_id: string;
  readonly status_checked_at: number | null;
  readonly approver_id: string | null;
  readonly approver_authority: ApproverAuthority | null;
  readonly amount: Amount | null;
  readonly resources: readonly string[];
}

/** What the native environment establishes about the approver's authority. */
export interface ApproverAuthority {
  readonly required_role: string;
  readonly approver_roles: readonly string[];
}

/** The amount an approval covers and the amount requested, as decimal strings. */
export interface Amount {
  readonly approved: string;
  readonly requested: string;
  readonly currency: string;
}

/** The native delegation state. */
export interface Delegation {
  readonly authority_ref: string;
  readonly principal_id: string;
  readonly task_id: string;
  readonly state: string;
  readonly observed_at: number;
}

/** The executor identity (draft Section 17.5). */
export interface Executor {
  readonly class: string;
  readonly principal_id: string;
}

/** The status of an evidence status reference. */
export interface EvidenceStatus {
  readonly status: string;
  readonly checked_at: number;
}

/** One presentation the harness submits (README section exchange.json), with the defaults applied. */
export interface Submission {
  readonly signed: string;
  readonly jti: string;
  readonly replica: string;
  readonly concurrent: boolean;
  readonly evictReplayRecords: boolean;
  readonly actualOperation: string;
  /** The transport profile the presentation arrives over, as the gateway established it: https or stdio-ipc (draft 13.3.1, 17.1). */
  readonly transport: string;
  readonly evaluation: Evaluation;
}

/** The timing of an evaluation: startedAt defaults to the config's now; a null time is null. */
export interface Evaluation {
  readonly startedAt: number;
  readonly nativeReadsAt: number | null;
  readonly cancelledAt: number | null;
}

/** What does not answer during the case. */
export interface Availability {
  readonly sources: readonly string[];
  /** available, unavailable or full. */
  readonly replayStore: string;
  /** available or unavailable: the enrollment source behind resolve_agent_binding (draft 17.1). */
  readonly enrollmentSource: string;
}

/** A sidecar handoff of an issued attestation, with the defaults applied: presentation is a submission's jti. */
export interface HandoffAttempt {
  readonly presentation: string;
  readonly actualOperation: string;
  readonly at: number;
}

/**
 * An expected decision.json: one response at the top level, or, in format
 * v2, one per submission under responses, then one entry per handoff attempt
 * (README sections decision.json and decision.json additions).
 */
export interface Decision {
  readonly transport_code: string | null;
  readonly decision: string | null;
  readonly checks: readonly ExpectedCheck[];
  readonly receipt: Receipt | null;
  readonly executed: boolean | null;
  readonly absent_checks: readonly string[];
  readonly rejected_before_crypto: boolean | null;
  readonly reason: string | null;
  /** null when the file has no responses member. */
  readonly responses: readonly Response[] | null;
  readonly handoff: readonly Handoff[];
  /** The RFC 6901 pointer to the response the manifest outcome summarizes; null means "". */
  readonly subject: string | null;
}

/** Operations on {@link Decision} values (Go `Decision` methods). */
export const Decision = Object.freeze({
  /** The expected responses in submission order: the top level as one response, or responses. */
  expectedResponses(d: Decision): readonly Response[] {
    if (d.responses !== null) return d.responses;
    return [
      {
        transport_code: d.transport_code,
        decision: d.decision,
        checks: d.checks,
        receipt: d.receipt,
        executed: d.executed,
        absent_checks: d.absent_checks,
        rejected_before_crypto: d.rejected_before_crypto,
        reason: d.reason,
      },
    ];
  },
});

/** One expected response: a transport rejection, when transport_code is set, or a receipt. */
export interface Response {
  readonly transport_code: string | null;
  readonly decision: string | null;
  readonly checks: readonly ExpectedCheck[];
  readonly receipt: Receipt | null;
  readonly executed: boolean | null;
  readonly absent_checks: readonly string[];
  readonly rejected_before_crypto: boolean | null;
  readonly reason: string | null;
}

/** A check result the receipt must carry. */
export interface ExpectedCheck {
  readonly check_id: string;
  readonly result: string;
  readonly reason_code: string;
  readonly evidence_ids_include: readonly string[];
  readonly source_ref: string | null;
}

/**
 * What the expected receipt must be: its typ, the public JWK file of its
 * signer, the payload members it must carry with exactly these values, and
 * the latest permitted exp.
 */
export interface Receipt {
  readonly typ: string;
  readonly signer: string;
  readonly claims: Readonly<Record<string, RawJSON>>;
  readonly exp_max: number;
}

/** The expected result of a handoff attempt: transport_code is null when the gateway accepts it. */
export interface Handoff {
  readonly transport_code: string | null;
}
