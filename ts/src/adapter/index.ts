/**
 * The native adapter contract of PACT draft section 17.1 (Go package
 * hop.top/pact-go/adapter): the seven logical functions an enforced gateway
 * adapter exposes, the value types they exchange, and the errors they
 * report.
 *
 * The module holds interfaces, types and errors only. An implementation
 * lives in its own module; the validator and the conformance harness compile
 * against the interfaces here. The contracts are behavioral, not new REST
 * APIs (draft 17.1): an existing gateway plugin, policy hook, middleware,
 * directory lookup or native claim can satisfy them. Each of the seven
 * returns a `Promise` and takes an optional `AbortSignal` last.
 *
 * ## The seven functions
 *
 * One interface per row of the draft 17.1 table, and the composite
 * {@link Adapter} that extends all seven. Each row below gives the draft
 * function name, the interface and method, and the draft's own Input and
 * Output / requirement cells.
 *
 * ```text
 * authenticate_native    NativeAuthenticator.authenticateNative
 *     Input:  Actual request
 *     Output: Authenticated principal and workload context, or native denial.
 *
 * resolve_agent_binding  BindingResolver.resolveAgentBinding
 *     Input:  Realm, authenticated workload, and the agent ID the request names
 *     Output: The enrolled binding of that agent ID to that workload in that realm:
 *             operator binding, holder key, and current binding status; `UNKNOWN` when
 *             no such enrollment exists, together with whether that agent ID is
 *             enrolled for another workload of the realm.
 *
 * map_operation          OperationMapper.mapOperation
 *     Input:  Actual request and mapping version
 *     Output: Authoritative `OperationContext`; all consequential request data is covered.
 *
 * read_native_claim      ClaimReader.readNativeClaim
 *     Input:  Approved native path and context
 *     Output: Authoritative value, original observation time, status time, and source ID.
 *
 * check_context          ContextChecker.checkContext
 *     Input:  Installed check ID; the authenticated principal and workload context that
 *             `authenticate_native` returned, with its authenticated attributes; the agent
 *             binding that `resolve_agent_binding` returned; intent; operation; evidence references
 *     Output: `PASS`, `FAIL`, or `UNKNOWN`, with a reason.
 *
 * authorize_native       NativeAuthorizer.authorizeNative
 *     Input:  Original principal and actual operation
 *     Output: Existing policy decision; PACT cannot rewrite a denial.
 *
 * record_outcome         OutcomeRecorder.recordOutcome
 *     Input:  Attributable decision/execution observation
 *     Output: Signed outcome or declared absence of execution visibility.
 * ```
 *
 * ## Invariants
 *
 * Every implementation holds two invariants, whatever the native system:
 *
 * 1. Values come only from authenticated context or configured authoritative
 *    lookups. A client-supplied header, profile text, URL parameter or model
 *    output is never native context, and identities keep their issuer and
 *    tenant namespace so that similarly named users or roles are not
 *    conflated (draft 8.5, 17.2).
 * 2. `observedAt` is the original source observation. An adapter never
 *    refreshes a stale upstream fact by stamping it with the time of the
 *    read, and it never reports a check or a freshness it did not perform
 *    (draft 8.3, 17.2). A `null` time means the source gives no such time;
 *    the validator cannot establish freshness from it.
 *
 * ## Errors
 *
 * Every error is an {@link AdapterError} whose {@link Code} is one of the
 * draft 13.4 table, and {@link codeOf} recovers the code from a `cause`
 * chain:
 *
 * ```text
 * INVALID_MESSAGE  INVALID_PROOF  CONTEXT_MISMATCH  DEPENDENCY_UNAVAILABLE
 * UNSUPPORTED_REQUIREMENT  UNSUPPORTED_PURPOSE  MISSING_FIELD
 * ```
 *
 * A function that cannot reach its source rejects with an error whose code
 * is `DEPENDENCY_UNAVAILABLE`; the validator records the affected check as
 * UNKNOWN and the admission decision as DEFERRED (draft 11.4, 17.3.1).
 * `checkContext` does not reject: it reports the same conditions as a
 * {@link CheckOutcome} with the verdict UNKNOWN and the code as
 * `reasonCode`.
 *
 * ## Times
 *
 * Instants are Unix milliseconds, `null` for none. On the wire they are
 * integer Unix seconds; a conversion truncates to the second and maps `null`
 * to an absent (null) member.
 *
 * The interfaces are the contract that implementations and the conformance
 * harness share, frozen with the Go package (docs/sdk/adapter-contract-freeze.md
 * of the source repository).
 *
 * @module
 */
import type { RawRequest } from '../core/binding/index.ts';
import type { OperationContext } from '../core/types.ts';
import type {
  AgentBinding,
  AgentID,
  CheckInput,
  CheckOutcome,
  ClaimContext,
  Decision,
  Descriptor,
  NativeClaim,
  Observation,
  Principal,
  Realm,
  Recorded,
  Workload,
} from './types.ts';

export {
  AdapterError,
  type AdapterErrorOptions,
  Code,
  codeOf,
  DenialReason,
  isDenialReason,
  NativeDenial,
} from './errors.ts';
export {
  type AgentBinding,
  type AgentID,
  BindingStatus,
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  Decision,
  Descriptor,
  Effect,
  isBindingStatus,
  isEffect,
  isVerdict,
  type Mechanism,
  type NativeClaim,
  NoVisibility,
  type Obligation,
  type Observation,
  type Principal,
  type Realm,
  type Recorded,
  Signed,
  Verdict,
  type Workload,
} from './types.ts';

/** The draft 17.1 function authenticate_native. */
export interface NativeAuthenticator {
  /**
   * Authenticates the actual request with the environment's existing
   * identity system and resolves to the principal and workload context.
   *
   * It rejects with a {@link NativeDenial} when authentication was evaluated
   * and failed, and with an {@link AdapterError} of code
   * `DEPENDENCY_UNAVAILABLE` when it could not be evaluated.
   */
  authenticateNative(req: RawRequest, signal?: AbortSignal): Promise<Principal>;
}

/** The draft 17.1 function resolve_agent_binding. */
export interface BindingResolver {
  /**
   * Resolves to the enrolled binding of `agent` to the authenticated
   * `workload` in `realm`, from the configured enrollment source. The realm
   * and workload are those of the authenticated {@link Principal}; `agent` is
   * the agent ID the request names.
   *
   * The agent ID only selects among the enrollments of the workload: it
   * never selects an enrollment of another workload, and a workload alone
   * never names an agent. The holder-key proof then binds the request to the
   * selected enrollment (draft 6.2). When the profile in use does not support
   * workloads shared by several agents, a workload with more than one
   * enrollment in force is a configuration error: the call rejects with code
   * `UNSUPPORTED_REQUIREMENT`, whichever agent ID it is given. An enrollment
   * is in force unless it is revoked; a compromised one is in force
   * (spec/v1.0/profiles/identity-mapping.md, IM-18, IM-19).
   *
   * A binding the source holds as revoked or compromised resolves with
   * status `REVOKED` or `COMPROMISED` and the agent, operator and holder key
   * of its record, so that a caller can state the reason
   * (spec/v1.0/profiles/identity-mapping.md, IM-11); it is never reported as
   * active. A source that cannot answer rejects with code
   * `DEPENDENCY_UNAVAILABLE`. A source that answers that no such enrollment
   * exists resolves with status `UNKNOWN`, not an error, with
   * `enrolledElsewhere` set when the agent ID is enrolled for another
   * workload of the realm.
   */
  resolveAgentBinding(
    realm: Realm,
    workload: Workload,
    agent: AgentID,
    signal?: AbortSignal,
  ): Promise<AgentBinding>;
}

/** The draft 17.1 function map_operation. */
export interface OperationMapper {
  /**
   * Derives the authoritative operation context from the actual
   * authenticated request and the installed mapping named by
   * `mappingVersion` (draft 10.2). Action, resources and principal come from
   * the request and `p`, never from a client-supplied resource list, and
   * every consequential part of the request (path, query, body, headers) is
   * covered.
   *
   * It rejects with code `INVALID_MESSAGE` when `req` violates a rule of the
   * baseline HTTP mapping (draft 10.2, 13.4), such as a fragment or userinfo
   * in the target, an ambiguous encoding as draft 10.2 defines and lists
   * them, or an HTTP content encoding; `UNSUPPORTED_REQUIREMENT` when
   * `mappingVersion` is not installed; `CONTEXT_MISMATCH` when the request
   * and `p` disagree; and `DEPENDENCY_UNAVAILABLE` when a lookup the mapping
   * needs cannot be completed.
   */
  mapOperation(
    req: RawRequest,
    p: Principal,
    mappingVersion: string,
    signal?: AbortSignal,
  ): Promise<OperationContext>;
}

/** The draft 17.1 function read_native_claim. */
export interface ClaimReader {
  /**
   * Reads the value at `nativePath` in the context `c` from the configured
   * authoritative source. `nativePath` is a path an administrator approved in
   * the versioned mapping (draft 17.2); any other path rejects with code
   * `UNSUPPORTED_REQUIREMENT`. A fact of a resource is read only for a
   * resource that `c.operation` lists, and a fact of a task only for the task
   * of `c.intent`.
   *
   * The adapter reports the timestamps the source gives and no others: it
   * does not claim a freshness it cannot establish, and it does not restamp a
   * cached snapshot with the time of the read (draft 8.3, 17.2). A source
   * that cannot be reached rejects with code `DEPENDENCY_UNAVAILABLE`, which
   * the validator maps to DEFERRED.
   */
  readNativeClaim(nativePath: string, c: ClaimContext, signal?: AbortSignal): Promise<NativeClaim>;
}

/** The draft 17.1 function check_context. */
export interface ContextChecker {
  /**
   * Runs the installed, versioned check named by `checkId` on `input`: the
   * authenticated principal, the agent binding, the declared intent, the
   * actual operation and the evidence references, which are the inputs draft
   * 17.1 lists. A check compares an agent or a principal against
   * `input.binding` and `input.principal`, never against a value the
   * presentation, the profile or an evidence artifact carries; a check that
   * needs neither ignores them.
   *
   * It does not reject. A check it did not perform resolves to UNKNOWN,
   * never PASS (draft 17.2): an unknown `checkId` with reason code
   * UNSUPPORTED_REQUIREMENT, a source that cannot answer with reason code
   * DEPENDENCY_UNAVAILABLE. The validator records UNKNOWN as DEFERRED.
   */
  checkContext(checkId: string, input: CheckInput, signal?: AbortSignal): Promise<CheckOutcome>;
}

/** The draft 17.1 function authorize_native. */
export interface NativeAuthorizer {
  /**
   * Resolves to the environment's existing policy decision for the original
   * authenticated principal `p` and the actual operation. It never
   * substitutes a connector or service identity for `p` (draft 4.3). A native
   * exception changes only this result (draft 17.3); PACT evidence of an
   * exception neither grants nor implies one.
   *
   * Native authorization never sees the PACT contract: draft 17.1 gives it
   * the original principal and the actual operation only. A caller whose
   * contract pins a policy version compares `Decision.policyRevision` with
   * the installed check version the contract names; on a mismatch it does
   * not use the decision and answers REQUIREMENTS_CHANGED (draft 13.4).
   *
   * A policy that cannot decide rejects with code `DEPENDENCY_UNAVAILABLE`,
   * or resolves to a decision with effect `UNKNOWN`.
   */
  authorizeNative(p: Principal, op: OperationContext, signal?: AbortSignal): Promise<Decision>;
}

/** The draft 17.1 function record_outcome. */
export interface OutcomeRecorder {
  /**
   * Records the observation as a signed outcome report and resolves to a
   * {@link Signed}, or to a {@link NoVisibility} when the adapter has no
   * visibility of the event. Missing visibility is declared, never assumed to
   * be success (draft 14.1). A recorder that cannot reach its signer or store
   * rejects with code `DEPENDENCY_UNAVAILABLE`.
   */
  recordOutcome(o: Observation, signal?: AbortSignal): Promise<Recorded>;
}

/**
 * The composite an enforced adapter implements: the seven draft 17.1
 * functions and its descriptor.
 */
export interface Adapter
  extends NativeAuthenticator,
    BindingResolver,
    OperationMapper,
    ClaimReader,
    ContextChecker,
    NativeAuthorizer,
    OutcomeRecorder {
  /** The adapter's descriptor; for a {@link MultiDescriber}, the primary form. */
  describe(): Descriptor;
}

/**
 * Implemented by an adapter that serves more than one native protocol form
 * and must publish one GatewayMetadata.adapters entry per form (draft 13.3).
 * `describe` then returns the primary form.
 */
export interface MultiDescriber {
  /** One descriptor per form, the primary form first. */
  descriptors(): readonly Descriptor[];
}

/**
 * Every descriptor an adapter publishes: `descriptors()` when it is a
 * {@link MultiDescriber}, otherwise the one `describe` returns. The result
 * and its descriptors are new values, the caller's to change.
 */
export function descriptorsOf(a: Adapter): Descriptor[] {
  const m = a as Adapter & Partial<MultiDescriber>;
  const ds = typeof m.descriptors === 'function' ? m.descriptors() : [a.describe()];
  return ds.map((d) => ({ ...d }));
}
