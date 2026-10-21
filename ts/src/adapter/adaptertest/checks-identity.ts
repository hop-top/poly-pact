/**
 * The authenticate_native and resolve_agent_binding checks of the suite (Go
 * hop.top/pact-go/adapter/adaptertest, checks_identity.go).
 *
 * @module
 */
import { Code, codeOf, NativeDenial } from '../errors.ts';
import { type AgentBinding, BindingStatus, isBindingStatus, type Principal } from '../types.ts';
import type { ExpectBinding, ExpectPrincipal } from './casefile.ts';
import { errorText, jsonText, typeName } from './leak.ts';
import { OUT } from './load.ts';
import { digestProblem, jsonEqual, type Run, SKEW_MS } from './run.ts';

/** Whether a principal carries nothing: no id, no workload, no realm. */
export function principalEmpty(p: Partial<Principal> | null | undefined): boolean {
  return (
    (p?.id ?? '') === '' &&
    (p?.workload ?? '') === '' &&
    (p?.realm?.tenantId ?? '') === '' &&
    (p?.realm?.environmentId ?? '') === ''
  );
}

/** Whether a binding names no record: no agent, operator or holder key. */
export function bindingEmpty(b: Partial<AgentBinding> | null | undefined): boolean {
  return (b?.agentId ?? '') === '' && (b?.operatorId ?? '') === '' && (b?.holderJKT ?? '') === '';
}

// The first NativeDenial of the cause chain of err, err included.
function denialOf(err: unknown): NativeDenial | undefined {
  const seen = new Set<unknown>();
  for (let e = err; e instanceof Error && !seen.has(e); e = e.cause) {
    if (e instanceof NativeDenial) return e;
    seen.add(e);
  }
  return undefined;
}

// Whether s is an absolute URI: a scheme, then no space, control or
// malformed escape (draft 6.1).
function isAbsoluteURI(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(s) && !/%(?![0-9A-Fa-f]{2})/.test(s);
}

/** Runs an authenticate_native case. */
export async function authenticate(r: Run): Promise<void> {
  const built = r.request();
  if (built === undefined) return;
  const s = await r.call('authenticateNative', () =>
    r.subj.adapter.authenticateNative(built.req, r.signal),
  );
  if (s === undefined) return;
  const err = s.ok ? undefined : s.error;
  const p = s.ok ? s.value : undefined;
  if (!s.ok) r.scanError('authenticateNative', err);
  else r.scanValue('authenticateNative principal', p);

  const e = r.c.expect;
  switch (e.outcome) {
    case OUT.authenticated:
      if (!s.ok) {
        r.failf(
          `authenticateNative rejected with ${errorText(err)}, want an authenticated principal`,
        );
        return;
      }
      checkPrincipal(r, p as Principal, e.principal as ExpectPrincipal);
      break;
    case OUT.denied:
      wantDenial(r, s.ok ? p : undefined, s.ok, err);
      break;
    case OUT.error:
      if (s.ok) {
        r.failf(`authenticateNative authenticated ${JSON.stringify(p?.id)}, want an error`);
        return;
      }
      r.wantReason('authenticateNative', err);
      break;
  }
  if (s.ok && principalEmpty(p)) {
    r.failf('authenticateNative resolved to a zero principal with no error');
  }
}

// A native denial: a NativeDenial that is an INVALID_PROOF and carries no
// principal. A rejected promise carries no value, so no principal can come
// back with it.
function wantDenial(r: Run, p: Principal | undefined, ok: boolean, err: unknown): void {
  if (ok) {
    r.failf(`authenticateNative authenticated ${JSON.stringify(p?.id)}, want a native denial`);
    return;
  }
  const d = denialOf(err);
  if (d === undefined) {
    r.failf(
      `authenticateNative rejected with ${typeName(err)} (${errorText(err)}), want a NativeDenial`,
    );
    return;
  }
  const code = codeOf(err);
  if (code !== Code.INVALID_PROOF) {
    r.failf(`denial code is ${JSON.stringify(code)}, want ${Code.INVALID_PROOF}`);
  }
  const want = r.c.expect.reason_code;
  if (want !== '' && d.publicReason() !== want) {
    r.failf(`denial reason is ${d.publicReason()}, want ${want}`);
  }
}

// An authenticated principal against the case.
function checkPrincipal(r: Run, p: Principal, want: ExpectPrincipal): void {
  if (principalEmpty(p)) return;
  if (want.id !== '' && p.id !== want.id) {
    r.failf(`principal id is ${JSON.stringify(p.id)}, want ${JSON.stringify(want.id)}`);
  }
  if (want.realm !== null) {
    const got = { tenant_id: p.realm?.tenantId, environment_id: p.realm?.environmentId };
    if (
      got.tenant_id !== want.realm.tenant_id ||
      got.environment_id !== want.realm.environment_id
    ) {
      r.failf(`principal realm is ${jsonText(got)}, want ${jsonText(want.realm)}`);
    }
  }
  if (want.workload !== '' && p.workload !== want.workload) {
    r.failf(
      `principal workload is ${JSON.stringify(p.workload)}, want ${JSON.stringify(want.workload)}`,
    );
  }
  if (want.mechanism !== '' && p.mechanism !== want.mechanism) {
    r.failf(
      `principal mechanism is ${JSON.stringify(p.mechanism)}, want ${JSON.stringify(want.mechanism)}`,
    );
  }
  checkAttributes(r, p.attributes, want.attributes);
  r.notAfter('principal authenticatedAt', p.authenticatedAt, r.now + SKEW_MS);
}

/**
 * Compares the authenticated attributes the case names with those of the
 * principal, each as JSON data: object member order is ignored, array order
 * is not (draft 8.4). An attribute the case does not name is not checked.
 */
export function checkAttributes(
  r: Run,
  got: Readonly<Record<string, unknown>> | null | undefined,
  want: { readonly text: string } | null,
): void {
  if (want === null || want.text === '') return;
  const members = JSON.parse(want.text) as Record<string, unknown>;
  for (const name of Object.keys(members).sort()) {
    const wantText = JSON.stringify(members[name]);
    if (got == null || !Object.hasOwn(got, name)) {
      r.failf(`principal has no attribute ${JSON.stringify(name)}, want ${wantText}`);
      continue;
    }
    const raw = JSON.stringify(got[name]);
    if (raw === undefined) {
      r.failf(`principal attribute ${JSON.stringify(name)} does not encode as JSON`);
      continue;
    }
    try {
      if (!jsonEqual(wantText, raw)) {
        r.failf(`principal attribute ${JSON.stringify(name)} is ${raw}, want ${wantText}`);
      }
    } catch (err) {
      r.failf(`principal attribute ${JSON.stringify(name)}: ${(err as Error).message}`);
    }
  }
}

/** Runs a resolve_agent_binding case. */
export async function binding(r: Run): Promise<void> {
  const k = r.c.call;
  const realm = Object.freeze({
    tenantId: k.realm?.tenant_id ?? '',
    environmentId: k.realm?.environment_id ?? '',
  });
  const s = await r.call('resolveAgentBinding', () =>
    r.subj.adapter.resolveAgentBinding(realm, k.workload, k.agent_id, r.signal),
  );
  if (s === undefined) return;
  const err = s.ok ? undefined : s.error;
  const b = s.ok ? s.value : undefined;
  if (!s.ok) r.scanError('resolveAgentBinding', err);

  const e = r.c.expect;
  if (s.ok && !isBindingStatus(b?.status)) {
    r.failf(`binding status ${JSON.stringify(b?.status)} is not a defined status`);
  }
  if (s.ok && b?.enrolledElsewhere === true && b.status !== BindingStatus.UNKNOWN) {
    r.failf(
      `binding of status ${b.status} reports the agent ID enrolled for another workload; only an UNKNOWN result carries that report (draft 17.1)`,
    );
  }
  switch (e.outcome) {
    case OUT.bound:
      if (!s.ok) {
        r.failf(`resolveAgentBinding rejected with ${errorText(err)}, want an active binding`);
        return;
      }
      if (b?.status !== BindingStatus.ACTIVE) {
        r.failf(`binding status is ${b?.status}, want ACTIVE`);
      }
      checkRecord(r, b as AgentBinding, e.binding);
      break;
    case OUT.notEnrolled:
      if (!s.ok) {
        r.failf(
          `resolveAgentBinding rejected with ${errorText(err)}, want status UNKNOWN with no error`,
        );
      } else if (b?.status !== BindingStatus.UNKNOWN) {
        r.failf(`binding status is ${b?.status}, want UNKNOWN: no binding exists in this realm`);
      } else if (!bindingEmpty(b)) {
        r.failf(
          `binding of status UNKNOWN names agent ${JSON.stringify(b.agentId)} and a holder key; it must name none`,
        );
      } else {
        checkElsewhere(r, b, e.binding);
      }
      break;
    case OUT.unusable:
      checkUnusable(r, b, s.ok, err);
      break;
    case OUT.error:
      if (s.ok) {
        r.failf(`resolveAgentBinding resolved to a ${b?.status} binding, want an error`);
        return;
      }
      r.wantReason('resolveAgentBinding', err);
      break;
  }
}

// The report that the agent ID is enrolled for another workload of the
// realm, against the case, when the case requires a value.
function checkElsewhere(r: Run, b: AgentBinding, want: ExpectBinding | null): void {
  if (want === null || want.enrolled_elsewhere === null) return;
  if (b.enrolledElsewhere !== want.enrolled_elsewhere) {
    r.failf(
      `agent ID enrolled for another workload is ${b.enrolledElsewhere === true}, want ${want.enrolled_elsewhere} (draft 17.1)`,
    );
  }
}

// A binding that names an enrollment record, active, revoked or compromised,
// against the case: the record's agent, operator and holder key, a named
// source, and times within the skew.
function checkRecord(r: Run, b: AgentBinding, want: ExpectBinding | null): void {
  if (!isAbsoluteURI(b.agentId ?? '')) {
    r.failf(`agent id ${JSON.stringify(b.agentId)} is not an absolute URI (draft 6.1)`);
  }
  const bad = digestProblem(b.holderJKT);
  if (bad !== undefined) r.failf(`holder key thumbprint: ${bad}`);
  if ((b.sourceId ?? '') === '') r.failf('binding names no source');
  // Draft A.2: no source observation or status-check time may be later than
  // now plus the skew.
  r.notAfter('binding observedAt', b.observedAt, r.now + SKEW_MS);
  r.notAfter('binding statusCheckedAt', b.statusCheckedAt, r.now + SKEW_MS);
  if (want === null) return;
  if (want.agent_id !== '' && b.agentId !== want.agent_id) {
    r.failf(`agent id is ${JSON.stringify(b.agentId)}, want ${JSON.stringify(want.agent_id)}`);
  }
  if (want.operator_id !== '' && b.operatorId !== want.operator_id) {
    r.failf(
      `operator id is ${JSON.stringify(b.operatorId)}, want ${JSON.stringify(want.operator_id)}`,
    );
  }
  if (want.holder_jkt !== '' && b.holderJKT !== want.holder_jkt) {
    r.failf(
      `holder key thumbprint is ${JSON.stringify(b.holderJKT)}, want ${JSON.stringify(want.holder_jkt)}`,
    );
  }
  if (want.status !== '' && b.status !== want.status) {
    r.failf(`binding status is ${b.status}, want ${want.status}`);
  }
  checkElsewhere(r, b, want);
}

// The result for a binding the source holds as revoked or compromised: no
// result that a caller can use as an active binding.
//
// Identity mapping IM-11 fixes the form: resolve_agent_binding returns the
// record's status, REVOKED or COMPROMISED, with the agent, operator and
// holder key, and no error, so that a validator can state the reason (IM-29)
// and tell a revocation from a compromise. An error is not accepted: it hides
// the status, and an unavailable source would defer a request that must be
// refused. The call must never return an ACTIVE binding.
function checkUnusable(r: Run, b: AgentBinding | undefined, ok: boolean, err: unknown): void {
  const want = r.c.expect.binding;
  if (!ok) {
    const status = want !== null && want.status !== '' ? want.status : 'REVOKED or COMPROMISED';
    if (codeOf(err) === Code.DEPENDENCY_UNAVAILABLE) {
      r.failf(
        `a revoked or compromised binding was reported as an unavailable source (${errorText(err)}); that defers instead of refusing`,
      );
    }
    r.failf(
      `resolveAgentBinding rejected with ${errorText(err)}, want the binding with status ${status}, its agent, operator and holder key, and no error (identity mapping IM-11)`,
    );
    return;
  }
  switch (b?.status) {
    case BindingStatus.REVOKED:
    case BindingStatus.COMPROMISED:
      checkRecord(r, b, want);
      break;
    case BindingStatus.ACTIVE:
      r.failf(
        `resolveAgentBinding returned an ACTIVE binding for agent ${JSON.stringify(b.agentId)} whose binding the source holds as revoked or compromised`,
      );
      break;
    default:
      r.failf(
        `binding status is ${b?.status}, want REVOKED or COMPROMISED with the agent, operator and holder key of the record (identity mapping IM-11)`,
      );
  }
}
