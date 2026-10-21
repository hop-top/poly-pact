/**
 * The read_native_claim, check_context and authorize_native checks of the
 * suite (Go hop.top/pact-go/adapter/adaptertest, checks_native.go).
 *
 * @module
 */
import { shapes } from '../../core/shapes.ts';
import type { Intent, OperationContext } from '../../core/types.ts';
import { encode } from '../../internal/encode.ts';
import {
  type AgentBinding,
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  Decision,
  isEffect,
  isVerdict,
  type NativeClaim,
  type Obligation,
} from '../types.ts';
import type { ExpectClaim, ExpectDecision, ObligationJSON } from './casefile.ts';
import { errorText, jsonText } from './leak.ts';
import { OUT } from './load.ts';
import { jsonEqual, type Run, SKEW_MS } from './run.ts';

// The zero intent and operation, which a call without them passes (Go: the
// zero values of the structs).
function zeroOf(shape: { readonly required: readonly string[] }): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of shape.required) out[name] = '';
  return out;
}

/** The intent a claim or a check receives when the case gives none. */
export const ZERO_INTENT: Intent = Object.freeze(zeroOf(shapes.Intent)) as unknown as Intent;

/** The operation a claim receives when the case gives none. */
export const ZERO_OPERATION: OperationContext = Object.freeze({
  ...zeroOf(shapes.OperationContext),
  resources: Object.freeze([]),
  headers: Object.freeze({}),
}) as unknown as OperationContext;

/** Runs a read_native_claim case. */
export async function claim(r: Run): Promise<void> {
  const k = r.c.call;
  const cc: ClaimContext = Object.freeze({
    principal: r.principal(),
    intent: k.intent ?? ZERO_INTENT,
    operation: k.operation ?? ZERO_OPERATION,
  });
  const s = await r.call('readNativeClaim', () =>
    r.subj.adapter.readNativeClaim(k.native_path, cc, r.signal),
  );
  if (s === undefined) return;
  if (!s.ok) r.scanError('readNativeClaim', s.error);
  else r.scanValue('readNativeClaim claim', s.value);

  const e = r.c.expect;
  switch (e.outcome) {
    case OUT.claim:
      if (!s.ok) {
        r.failf(`readNativeClaim rejected with ${errorText(s.error)}, want a claim`);
        return;
      }
      checkClaimInvariants(r, s.value);
      checkClaim(r, s.value, e.claim);
      break;
    case OUT.error:
      if (s.ok) {
        r.failf('readNativeClaim resolved to a claim, want an error');
        return;
      }
      r.wantReason('readNativeClaim', s.error);
      break;
  }
}

// What holds for every claim an adapter returns: observedAt is the original
// observation and statusCheckedAt a check that took place, and neither lies
// beyond the allowed skew in the future ("No source observation or
// status-check time may be later than now + clock_skew", draft A.2); and the
// source is named (draft 8.3, 17.1, 17.2).
function checkClaimInvariants(r: Run, c: NativeClaim): void {
  r.notAfter('observedAt', c?.observedAt, r.now + SKEW_MS);
  r.notAfter('statusCheckedAt', c?.statusCheckedAt, r.now + SKEW_MS);
  if ((c?.sourceId ?? '') === '') r.failf('claim names no source');
}

function checkClaim(r: Run, c: NativeClaim, want: ExpectClaim | null): void {
  if (want === null) return;
  if (want.value !== null) {
    let got: string | undefined;
    try {
      got = encode(c?.value);
    } catch (err) {
      r.failf(`claim value does not encode as JSON: ${(err as Error).message}`);
    }
    if (got !== undefined) {
      try {
        if (!jsonEqual(want.value.text, got)) {
          r.failf(`claim value is ${got}, want ${want.value.text}`);
        }
      } catch (err) {
        r.failf(`claim value: ${(err as Error).message}`);
      }
    }
  }
  r.wantTime('observedAt', want.observed_at, c?.observedAt ?? null);
  r.wantTime('statusCheckedAt', want.status_checked_at, c?.statusCheckedAt ?? null);
  if (want.source_id !== '' && c?.sourceId !== want.source_id) {
    r.failf(`source id is ${JSON.stringify(c?.sourceId)}, want ${JSON.stringify(want.source_id)}`);
  }
  if (want.source_ref !== '' && c?.sourceRef !== want.source_ref) {
    r.failf(
      `source ref is ${JSON.stringify(c?.sourceRef)}, want ${JSON.stringify(want.source_ref)}`,
    );
  }
}

/** Runs a check_context case. */
export async function check(r: Run): Promise<void> {
  const k = r.c.call;
  const b = k.binding;
  const bound: AgentBinding | null =
    b === null
      ? null
      : Object.freeze({
          agentId: b.agent_id,
          operatorId: b.operator_id,
          holderJKT: b.holder_jkt as AgentBinding['holderJKT'],
          status: (b.status === '' ? 'ACTIVE' : b.status) as AgentBinding['status'],
          observedAt: null,
          statusCheckedAt: null,
          sourceId: '',
          sourceRef: '',
          enrolledElsewhere: false,
        });
  const input: CheckInput = Object.freeze({
    principal: r.principal(),
    binding: bound,
    intent: k.intent ?? ZERO_INTENT,
    operation: k.operation ?? ZERO_OPERATION,
    evidenceRefs: Object.freeze([...(k.evidence_refs ?? [])]),
  });
  const id = k.check_id ?? '';
  const s = await r.call('checkContext', () => r.subj.adapter.checkContext(id, input, r.signal));
  if (s === undefined) return;
  if (!s.ok) {
    r.scanError('checkContext', s.error);
    r.failf(
      `checkContext rejected with ${errorText(s.error)}; a check reports UNKNOWN with a reason code, it does not reject`,
    );
    return;
  }
  const out = s.value as CheckOutcome;
  r.scanValue('checkContext outcome', out);

  const e = r.c.expect;
  if (!isVerdict(out?.result)) {
    r.failf(`check result ${JSON.stringify(out?.result)} is not PASS, FAIL or UNKNOWN`);
  } else if (out.result !== e.outcome) {
    r.failf(
      `check ${JSON.stringify(id)} returned ${out.result} (${out.reasonCode}), want ${e.outcome}: a check the adapter did not perform is never PASS`,
    );
  }
  if ((out?.reasonCode ?? '') === '') r.failf('check returned no reason code');
  if (e.reason_code !== '' && out?.reasonCode !== e.reason_code) {
    r.failf(
      `check reason code is ${JSON.stringify(out?.reasonCode)}, want ${JSON.stringify(e.reason_code)}`,
    );
  }
  r.notAfter('check observedAt', out?.observedAt, r.now + SKEW_MS);
}

/** Runs an authorize_native case. */
export async function authorize(r: Run): Promise<void> {
  const k = r.c.call;
  const p = r.principal();
  const op = k.operation ?? ZERO_OPERATION;
  const s = await r.call('authorizeNative', () => r.subj.adapter.authorizeNative(p, op, r.signal));
  if (s === undefined) return;
  if (!s.ok) r.scanError('authorizeNative', s.error);
  else r.scanValue('authorizeNative decision', s.value);
  const d = s.ok ? (s.value as Decision) : undefined;
  if (d !== undefined) checkDecisionInvariants(r, d);

  const e = r.c.expect;
  switch (e.outcome) {
    case OUT.allow:
    case OUT.deny:
    case OUT.unknown:
      if (d === undefined) {
        r.failf(
          `authorizeNative rejected with ${errorText(s.ok ? '' : s.error)}, want effect ${e.outcome}`,
        );
        return;
      }
      if (d?.effect !== e.outcome) {
        r.failf(
          `decision effect is ${d?.effect}, want ${e.outcome}: a native decision is returned as it is, and PACT cannot rewrite a denial`,
        );
      }
      checkDecision(r, d, e.decision);
      break;
    case OUT.notAllowed:
      if (d !== undefined && Decision.permits(d)) {
        r.failf(
          `decision is ${d.effect}, want anything but ALLOW: the policy holds no rule that allows this principal`,
        );
      }
      break;
    case OUT.error:
      if (d !== undefined) {
        r.failf(`authorizeNative resolved to ${d?.effect}, want an error`);
        return;
      }
      if (!s.ok) r.wantReason('authorizeNative', s.error);
      break;
  }
}

// What holds for every decision an adapter returns: the effect is one of the
// three, the policy source that decided is named, and the decision time
// cannot lie beyond the allowed skew in the future (draft 7.5, 17.1, A.2).
function checkDecisionInvariants(r: Run, d: Decision): void {
  if (!isEffect(d?.effect)) {
    r.failf(`decision effect ${JSON.stringify(d?.effect)} is not ALLOW, DENY or UNKNOWN`);
  }
  if ((d?.sourceId ?? '') === '') {
    r.failf('decision names no source: every native decision names the policy source that decided');
  }
  r.notAfter('decidedAt', d?.decidedAt, r.now + SKEW_MS);
}

function checkDecision(r: Run, d: Decision, want: ExpectDecision | null): void {
  if (want === null) return;
  if (want.source_id !== '' && d.sourceId !== want.source_id) {
    r.failf(
      `decision source id is ${JSON.stringify(d.sourceId)}, want ${JSON.stringify(want.source_id)}`,
    );
  }
  wantRecord(r, want.source_ref, d.sourceRef ?? '');
  r.wantTime('decidedAt', want.decided_at, d.decidedAt ?? null);
  if (want.policy_revision !== '' && d.policyRevision !== want.policy_revision) {
    r.failf(
      `policy revision is ${JSON.stringify(d.policyRevision)}, want ${JSON.stringify(want.policy_revision)}: the revision is reported as the source gave it`,
    );
  }
  if (want.obligations === null) return;
  const wantObs = want.obligations.map(
    (o: ObligationJSON): Obligation => ({ id: o.id, attributes: o.attributes ?? {} }),
  );
  if (!sameObligations(d.obligations ?? [], wantObs)) {
    r.failf(`obligations are ${jsonText(d.obligations ?? [])}, want ${jsonText(wantObs)}`);
  }
}

// Obligations compared as JSON data, in order; no and empty attributes are
// the same.
function sameObligations(a: readonly Obligation[], b: readonly Obligation[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    const y = b[i] as Obligation;
    if (x?.id !== y.id) return false;
    const xa = x.attributes ?? {};
    const ya = y.attributes ?? {};
    if (Object.keys(xa).length === 0 && Object.keys(ya).length === 0) return true;
    try {
      return jsonEqual(encode(xa), encode(ya));
    } catch {
      return false;
    }
  });
}

// The decision record of a decision against the expected source_ref: absent
// or an empty string is not checked, JSON null requires an empty record, since
// the source keeps none, and any other string must be equal.
function wantRecord(r: Run, want: { readonly text: string } | null, got: string): void {
  if (want === null) return;
  const text = want.text.trim();
  if (text === 'null') {
    if (got !== '') {
      r.failf(
        `decision source ref is ${JSON.stringify(got)}, want none: the source keeps no record of the decision and the adapter must not supply one`,
      );
    }
    return;
  }
  let ref: unknown;
  try {
    ref = JSON.parse(text);
  } catch {
    ref = undefined;
  }
  if (typeof ref !== 'string') {
    r.failf(`source_ref: expected value ${text} is not a string or null`);
    return;
  }
  if (ref !== '' && got !== ref) {
    r.failf(`decision source ref is ${JSON.stringify(got)}, want ${JSON.stringify(ref)}`);
  }
}
