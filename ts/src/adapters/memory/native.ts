/**
 * read_native_claim, check_context and authorize_native of the memory
 * adapter (Go hop.top/pact-go/adapters/memory, native.go).
 *
 * @module
 */
import { AdapterError, Code } from '../../adapter/errors.ts';
import {
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  type Decision,
  Effect,
  type NativeClaim,
  type Principal,
  Verdict,
} from '../../adapter/types.ts';
import { BASELINE_SKEW_MS } from '../../core/clock.ts';
import type { OperationContext } from '../../core/types.ts';
import { type Core, checkSourceTimes, live, outage, sourceTime, unavailable } from './core.ts';
import { CODE_APPROVAL_SCOPE_MISMATCH, runCheck } from './freshness.ts';
import type {
  CheckRecord as CheckRecordT,
  ClaimRecord as ClaimRecordT,
  PolicyRule,
} from './state.ts';

/**
 * The source a decision names when the rule that decided names no source of
 * its own, and when no rule applies: the adapter's own policy store.
 */
export const POLICY_SOURCE_ID = 'memory-policy';

/** Operations on check records. */
export const CheckRecord = Object.freeze({
  /**
   * Whether the record is the check's native state in the call `input`
   * (Go `CheckRecord.Applies`): its principal, when it names one, is the
   * authenticated principal of `input`, and its agent, when it names one, is
   * the agent of `input`'s binding. A call with no binding has no agent, so
   * it never matches a record that names one.
   */
  applies(c: CheckRecordT, input: CheckInput): boolean {
    if (c.principal !== '' && c.principal !== input.principal?.id) return false;
    if (c.agent_id !== '' && c.agent_id !== (input.binding?.agentId ?? '')) return false;
    return true;
  },
});

/** Operations on claim records. */
export const ClaimRecord = Object.freeze({
  /**
   * Whether the record is the value at `nativePath` in the context `cc` (Go
   * `ClaimRecord.Applies`): the path, the principal and its realm are those
   * of `cc`, and the resource and the task, when the record names them, are
   * those of the operation and the intent of `cc`.
   */
  applies(c: ClaimRecordT, nativePath: string, cc: ClaimContext): boolean {
    const p = cc.principal;
    if (
      c.path !== nativePath ||
      c.principal !== p.id ||
      c.realm.tenant_id !== p.realm.tenantId ||
      c.realm.environment_id !== p.realm.environmentId
    ) {
      return false;
    }
    if (c.resource !== '' && !(cc.operation?.resources ?? []).includes(c.resource)) return false;
    if (c.task_id !== '' && c.task_id !== (cc.intent?.task_id ?? '')) return false;
    return true;
  },
});

/**
 * read_native_claim: only a path in the approved list is readable. The
 * record is looked up by realm, principal and path together, so a
 * same-spelled principal of another realm has its own value. A record that
 * names a resource is read only when `cc.operation` lists that resource, and
 * a record that names a task only when `cc.intent` carries that task. The
 * times are what the source recorded and nothing else: a source that gives
 * no time yields none, and the time of the read is never substituted.
 */
export function readClaim(
  core: Core,
  nativePath: string,
  cc: ClaimContext,
  signal?: AbortSignal,
): NativeClaim {
  live('read claim', signal);
  if (!core.st.approved_paths.includes(nativePath)) {
    throw AdapterError.unsupportedRequirement(
      `memory: ${JSON.stringify(nativePath)} is not an approved native path`,
    );
  }
  for (const c of core.st.claims) {
    if (!ClaimRecord.applies(c, nativePath, cc)) continue;
    if (unavailable(core, c.source_id)) throw outage('read claim', c.source_id);
    const observed = sourceTime(c.observed_at);
    const checked = sourceTime(c.status_checked_at);
    checkSourceTimes(core, observed, checked);
    let value: unknown;
    try {
      value = JSON.parse(c.value?.text ?? '');
    } catch {
      throw AdapterError.dependencyUnavailable(
        `memory: the value at ${JSON.stringify(nativePath)} is not JSON`,
      );
    }
    return {
      value,
      observedAt: observed,
      statusCheckedAt: checked,
      sourceId: c.source_id,
      sourceRef: c.source_ref,
    };
  }
  throw new Error(
    `memory: the source holds no value at ${JSON.stringify(nativePath)} in this context`,
  );
}

/**
 * check_context: the installed check whose id equals `checkId` exactly. A
 * check that is not installed is UNKNOWN with UNSUPPORTED_REQUIREMENT: the
 * adapter did not perform it, so it cannot report that it passed (draft
 * 17.2). An installed check is the record of that id that applies to the
 * principal and the agent binding of `input`; when the check is installed
 * and no record of it applies, it is FAIL with APPROVAL_SCOPE_MISMATCH, never
 * PASS, and the outcome names the source without the record's reference
 * (draft 17.1, 17.3.1).
 */
export function checkContext(
  core: Core,
  checkId: string,
  input: CheckInput,
  signal?: AbortSignal,
): CheckOutcome {
  const none = { sourceId: '', sourceRef: '', observedAt: null };
  if (signal?.aborted) {
    return { ...none, result: Verdict.UNKNOWN, reasonCode: Code.DEPENDENCY_UNAVAILABLE };
  }
  let other: CheckRecordT | undefined;
  for (const c of core.st.checks) {
    if (c.id !== checkId) continue;
    if (CheckRecord.applies(c, input)) return runCheck(core, c);
    other ??= c;
  }
  if (other !== undefined) {
    return {
      ...none,
      sourceId: other.source_id,
      result: Verdict.FAIL,
      reasonCode: CODE_APPROVAL_SCOPE_MISMATCH,
    };
  }
  return { ...none, result: Verdict.UNKNOWN, reasonCode: Code.UNSUPPORTED_REQUIREMENT };
}

/**
 * authorize_native: the rules that name `p`, in `p`'s realm, and the
 * operation's action (and its resource, when the rule names one) apply. A
 * deny wins over an unknown, and an unknown over an allow. When no rule
 * applies the decision is a deny, so an absent rule is never an allow. The
 * decision carries the provenance of the rule that decided as the rule gives
 * it; the deny of no rule comes from POLICY_SOURCE_ID and has no record,
 * time or revision. A decision time later than now plus the skew did not
 * happen yet, so the decision is not passed on: the call rejects with
 * DEPENDENCY_UNAVAILABLE.
 */
export function authorize(
  core: Core,
  p: Principal,
  op: OperationContext,
  signal?: AbortSignal,
): Decision {
  live('authorize', signal);
  let allow: PolicyRule | undefined;
  let unknown: PolicyRule | undefined;
  let deny: PolicyRule | undefined;
  for (const r of core.st.policy) {
    if (
      r.principal !== p.id ||
      r.realm.tenant_id !== p.realm.tenantId ||
      r.realm.environment_id !== p.realm.environmentId ||
      r.action !== op.action ||
      (r.resource !== '' && !(op.resources ?? []).includes(r.resource))
    ) {
      continue;
    }
    if (r.effect === Effect.DENY) deny ??= r;
    else if (r.effect === Effect.UNKNOWN) unknown ??= r;
    else if (r.effect === Effect.ALLOW) allow ??= r;
  }
  const decided = deny ?? unknown ?? allow;
  if (decided === undefined) {
    return {
      effect: Effect.DENY,
      obligations: [],
      reason: 'no rule of the policy allows this principal',
      sourceId: POLICY_SOURCE_ID,
      sourceRef: '',
      decidedAt: null,
      policyRevision: '',
    };
  }
  const d = decisionOf(decided);
  if (d.decidedAt !== null && d.decidedAt > core.clock.now() + BASELINE_SKEW_MS) {
    throw AdapterError.dependencyUnavailable(
      'memory: the policy source reports a decision after now',
    );
  }
  return d;
}

function decisionOf(r: PolicyRule): Decision {
  return {
    effect: r.effect as Effect,
    obligations: r.obligations.map((o) => ({
      id: o.id,
      attributes: structuredClone(o.attributes ?? {}),
    })),
    reason: r.reason,
    sourceId: r.source_id === '' ? POLICY_SOURCE_ID : r.source_id,
    sourceRef: r.source_ref,
    decidedAt: sourceTime(r.decided_at),
    policyRevision: r.policy_revision,
  };
}
