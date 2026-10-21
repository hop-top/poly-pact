/**
 * read_native_claim, check_context and authorize_native of the broken
 * adapter, with their defects (Go hop.top/pact-go/adapters/internal/broken,
 * native.go).
 *
 * @module
 */
import { AdapterError } from '../../src/adapter/errors.ts';
import {
  type AgentBinding,
  BindingStatus,
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  type Decision,
  Effect,
  type NativeClaim,
  type Principal,
  type Realm,
  Verdict,
} from '../../src/adapter/types.ts';
import { ClaimRecord, type Realm as StateRealm } from '../../src/adapters/memory/index.ts';
import type { CheckRecord } from '../../src/adapters/memory/state.ts';
import { equalFoldASCII } from '../../src/core/binding/chars.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import { BASELINE_SKEW_MS } from '../../src/core/clock.ts';
import type { OperationContext } from '../../src/core/types.ts';
import type { Adapter } from './broken.ts';
import { Defect } from './defects.ts';
import { checkFreshness } from './freshness.ts';

/** Whether the realm of a stored record is `b`. */
export function sameRealm(a: StateRealm, b: Realm): boolean {
  return a.tenant_id === b.tenantId && a.environment_id === b.environmentId;
}

/** The value of the first `name` field line of req, without regard to case; `''` when none. */
export function header(req: RawRequest, name: string): string {
  for (const [k, v] of req.headers) if (equalFoldASCII(k, name)) return v;
  return '';
}

/** The instant of a Unix-seconds member of a source record, `null` for none. */
function sourceTime(sec: number | null): number | null {
  return sec === null ? null : sec * 1000;
}

/**
 * The record behind a claim as the source stores it, with no check of the
 * times; `undefined` when no record applies or its value is not JSON.
 */
function rawClaim(b: Adapter, nativePath: string, cc: ClaimContext): NativeClaim | undefined {
  for (const c of b.state().claims) {
    if (!ClaimRecord.applies(c, nativePath, cc)) continue;
    let value: unknown;
    try {
      value = JSON.parse(c.value?.text ?? '');
    } catch {
      return undefined;
    }
    return {
      value,
      observedAt: sourceTime(c.observed_at),
      statusCheckedAt: sourceTime(c.status_checked_at),
      sourceId: c.source_id,
      sourceRef: c.source_ref,
    };
  }
  return undefined;
}

/** readNativeClaim of the memory adapter, with the claim defects. */
export async function readClaim(
  b: Adapter,
  nativePath: string,
  context: ClaimContext,
  signal?: AbortSignal,
): Promise<NativeClaim> {
  let cc = context;
  if (b.has(Defect.CONFLATE_CLAIM_REALMS)) {
    // Look the principal up in the realm of the first record that names it.
    const rec = b
      .state()
      .claims.find((x) => x.path === nativePath && x.principal === cc.principal.id);
    if (rec !== undefined) {
      cc = {
        ...cc,
        principal: {
          ...cc.principal,
          realm: { tenantId: rec.realm.tenant_id, environmentId: rec.realm.environment_id },
        },
      };
    }
  }
  if (b.has(Defect.IGNORE_CLAIM_RESOURCE)) {
    // Take the first record of the path whatever resource it names, by
    // making its resource the one the operation lists.
    for (const rec of b.state().claims) {
      if (rec.resource !== '' && ClaimRecord.applies({ ...rec, resource: '' }, nativePath, cc)) {
        cc = { ...cc, operation: { ...cc.operation, resources: [rec.resource] } };
        break;
      }
    }
  }
  if (b.has(Defect.IGNORE_CLAIM_TASK)) {
    // Take the first record of the path whatever task it names, by making
    // its task the task of the intent.
    for (const rec of b.state().claims) {
      if (rec.task_id !== '' && ClaimRecord.applies({ ...rec, task_id: '' }, nativePath, cc)) {
        cc = { ...cc, intent: { ...cc.intent, task_id: rec.task_id } };
        break;
      }
    }
  }
  let c: NativeClaim;
  try {
    c = await b.base.readNativeClaim(nativePath, cc, signal);
  } catch (err) {
    return passFutureTimes(b, nativePath, cc, err);
  }
  if (
    b.has(Defect.NO_STATUS_SKEW_ALLOWANCE) &&
    c.statusCheckedAt !== null &&
    c.statusCheckedAt > b.now()
  ) {
    throw AdapterError.dependencyUnavailable('broken: the source reports a status check after now');
  }
  if (b.has(Defect.RESTAMP_OBSERVED_AT)) c = { ...c, observedAt: b.now() };
  if (b.has(Defect.STAMP_MISSING_TIMES)) {
    c = {
      ...c,
      observedAt: c.observedAt ?? b.now(),
      statusCheckedAt: c.statusCheckedAt ?? b.now(),
    };
  }
  return c;
}

// The memory adapter refused the claim with err; the defects that pass on a
// time later than now plus the skew return the record instead.
function passFutureTimes(
  b: Adapter,
  nativePath: string,
  cc: ClaimContext,
  err: unknown,
): NativeClaim {
  const raw = rawClaim(b, nativePath, cc);
  if (raw === undefined) throw err;
  const limit = b.now() + BASELINE_SKEW_MS;
  const futureObserved = raw.observedAt !== null && raw.observedAt > limit;
  const futureChecked = raw.statusCheckedAt !== null && raw.statusCheckedAt > limit;
  if (
    (b.has(Defect.PASS_FUTURE_OBSERVED_AT) && futureObserved && !futureChecked) ||
    (b.has(Defect.PASS_FUTURE_STATUS_CHECKED) && futureChecked && !futureObserved)
  ) {
    return raw;
  }
  if (b.has(Defect.CLAMP_FUTURE_CLAIM_TIMES) && (futureObserved || futureChecked)) {
    return {
      ...raw,
      observedAt: futureObserved ? limit : raw.observedAt,
      statusCheckedAt: futureChecked ? limit : raw.statusCheckedAt,
    };
  }
  throw err;
}

/** The binding of a call that established none. */
const NO_BINDING: AgentBinding = Object.freeze({
  agentId: '',
  operatorId: '',
  holderJKT: '',
  status: BindingStatus.UNKNOWN,
  observedAt: null,
  statusCheckedAt: null,
  sourceId: '',
  sourceRef: '',
  enrolledElsewhere: false,
});

/** checkContext of the memory adapter, with the check defects. */
export async function checkContext(
  b: Adapter,
  checkId: string,
  input: CheckInput,
  signal?: AbortSignal,
): Promise<CheckOutcome> {
  const installed = b.state().checks;
  const verdict = (c: CheckRecord): CheckOutcome => ({
    result: c.result as Verdict,
    reasonCode: c.reason_code,
    sourceId: c.source_id,
    sourceRef: c.source_ref,
    observedAt: null,
  });
  let inp = input;
  if (
    b.has(Defect.IGNORE_CHECK_SCOPE) ||
    (b.has(Defect.TRUST_EMPTY_BINDING) && inp.binding === null)
  ) {
    // Take the first record of the id whatever agent or principal it is
    // for, by making the call the record's own.
    const rec = installed.find((x) => x.id === checkId);
    if (rec !== undefined) {
      if (b.has(Defect.IGNORE_CHECK_SCOPE) && rec.principal !== '') {
        inp = { ...inp, principal: { ...inp.principal, id: rec.principal } };
      }
      if (rec.agent_id !== '') {
        inp = { ...inp, binding: { ...(inp.binding ?? NO_BINDING), agentId: rec.agent_id } };
      }
    }
  }
  let out = checkFreshness(b, checkId, await b.base.checkContext(checkId, inp, signal));

  if (b.has(Defect.NEVER_EVALUATE_CHECKS) && out.result !== Verdict.UNKNOWN) {
    return {
      result: Verdict.FAIL,
      reasonCode: 'CHECK_FAILED',
      sourceId: out.sourceId,
      sourceRef: '',
      observedAt: null,
    };
  }
  if (b.has(Defect.PREFIX_MATCH_CHECK)) {
    const c = installed.find((x) => x.id.startsWith(checkId));
    if (c !== undefined) return verdict(c);
  }
  if (b.has(Defect.FOLD_CASE_CHECK)) {
    const c = installed.find((x) => x.id.toLowerCase() === checkId.toLowerCase());
    if (c !== undefined) return verdict(c);
  }
  if (b.has(Defect.FAIL_OPEN_UNKNOWN_CHECK) && out.result === Verdict.UNKNOWN) {
    return {
      result: Verdict.PASS,
      reasonCode: 'REQUIREMENT_SATISFIED',
      sourceId: '',
      sourceRef: '',
      observedAt: null,
    };
  }
  if (b.has(Defect.ECHO_REFS_IN_SOURCE)) out = { ...out, sourceRef: inp.evidenceRefs.join(' ') };
  return out;
}

/** authorizeNative of the memory adapter, with the authorization defects. */
export async function authorize(
  b: Adapter,
  p: Principal,
  op: OperationContext,
  signal?: AbortSignal,
): Promise<Decision> {
  let evaluated = p;
  if (b.has(Defect.CONNECTOR_SUBSTITUTION)) {
    const r = b
      .state()
      .policy.find(
        (x) => x.effect === Effect.ALLOW && x.action === op.action && x.principal !== p.id,
      );
    if (r !== undefined) evaluated = { ...evaluated, id: r.principal };
  }
  if (b.has(Defect.CONFLATE_POLICY_REALMS)) {
    const r = b
      .state()
      .policy.find(
        (x) => x.principal === p.id && x.action === op.action && !sameRealm(x.realm, p.realm),
      );
    if (r !== undefined) {
      evaluated = {
        ...evaluated,
        realm: { tenantId: r.realm.tenant_id, environmentId: r.realm.environment_id },
      };
    }
  }
  let d = await b.base.authorizeNative(evaluated, op, signal);

  if (b.has(Defect.DEFAULT_ALLOW) && !ruleMentions(b, p.id, op.action)) {
    d = { ...d, effect: Effect.ALLOW };
  }
  if (b.has(Defect.REWRITE_READ_DENY) && d.effect === Effect.DENY && op.method === 'GET') {
    d = { ...d, effect: Effect.ALLOW };
  }
  if (b.has(Defect.DROP_OBLIGATIONS)) d = { ...d, obligations: [] };
  if (b.has(Defect.DECISION_WITHOUT_SOURCE)) d = { ...d, sourceId: '' };
  if (b.has(Defect.FUTURE_DECIDED_AT)) d = { ...d, decidedAt: b.now() + 3_600_000 };
  if (
    (b.has(Defect.EXECUTE_ON_DENY) && d.effect === Effect.DENY) ||
    (b.has(Defect.EXECUTE_ON_ALLOW) && d.effect === Effect.ALLOW)
  ) {
    b.fire('execute');
  }
  return d;
}

/** Whether any rule of any realm names the principal for the action. */
function ruleMentions(b: Adapter, principal: string, action: string): boolean {
  return b.state().policy.some((r) => r.principal === principal && r.action === action);
}
