/**
 * The record_outcome checks of the suite (Go
 * hop.top/pact-go/adapter/adaptertest, checks_record.go).
 *
 * @module
 */
import { Artifact, checkLifetime, checkWindow } from '../../core/clock.ts';
import { EventKind, isReporterRole, OutcomeResult } from '../../core/enums.ts';
import { decodeSegment } from '../../core/jws/base64url.ts';
import { defaultLimits, VERSION } from '../../core/limits.ts';
import { shapes } from '../../core/shapes.ts';
import { decode, parse } from '../../core/strictjson.ts';
import type { OutcomeReport } from '../../core/types.ts';
import { encode } from '../../internal/encode.ts';
import { NoVisibility, type Observation, type Recorded, Signed } from '../types.ts';
import { errorText, jsonText, typeName } from './leak.ts';
import { OUT } from './load.ts';
import { jsonEqual, type Run, SKEW_MS, sec } from './run.ts';

/** The JWS typ of an outcome report (draft 7.3). */
const OUTCOME_TYP = 'pact-outcome+jwt';

/** The case's observation argument as the adapter type. */
export function observationOf(r: Run): Observation {
  const o = r.c.call.observation;
  if (o === null) throw new Error('the case has no observation');
  return Object.freeze({
    eventId: o.event_id,
    eventKind: o.event_kind,
    context: o.context,
    taskId: o.task_id,
    operationId: o.operation_id,
    admissionReceiptId: o.admission_receipt_id,
    observedAt: o.observed_at * 1000,
    result: o.result,
    dimension: o.dimension,
    severity: o.severity,
    evidenceRefs: Object.freeze([...(o.evidence_refs ?? [])]),
    attribution: o.attribution,
    supersedes: Object.freeze([...(o.supersedes ?? [])]),
    details: o.details,
  });
}

/** Runs a record_outcome case. */
export async function record(r: Run): Promise<void> {
  const obs = observationOf(r);
  const s = await r.call('recordOutcome', () => r.subj.adapter.recordOutcome(obs, r.signal));
  if (s === undefined) return;
  if (!s.ok) r.scanError('recordOutcome', s.error);

  const e = r.c.expect;
  if (e.outcome === OUT.error) {
    if (s.ok) {
      r.failf('recordOutcome recorded the observation, want an error');
      return;
    }
    r.wantReason('recordOutcome', s.error);
    return;
  }
  if (!s.ok) {
    r.failf(`recordOutcome rejected with ${errorText(s.error)}, want ${e.outcome}`);
    return;
  }
  const rec: Recorded | null | undefined = s.value;
  if (rec === null || rec === undefined) {
    r.failf(`recordOutcome resolved to ${String(rec)}: no result with no error`);
  } else if (rec instanceof Signed) {
    signed(r, rec, obs);
  } else if (rec instanceof NoVisibility) {
    noVisibility(r, rec);
  } else {
    r.failf(
      `recordOutcome resolved to a ${typeName(rec)}; return a Signed or a NoVisibility, not another value`,
    );
  }
}

function noVisibility(r: Run, n: NoVisibility): void {
  r.scanText('recordOutcome declaration', n.reason);
  try {
    n.validate();
  } catch (err) {
    r.failf(`no-visibility declaration: ${(err as Error).message}`);
  }
  if (r.c.expect.outcome === OUT.signed) {
    r.failf(
      `recordOutcome declared no visibility (${JSON.stringify(n.reason)}), want a signed outcome`,
    );
  }
}

function signed(r: Run, s: Signed, obs: Observation): void {
  const e = r.c.expect;
  if (e.outcome === OUT.noVisibility) {
    r.failf('recordOutcome returned a signed outcome, want a declared absence of visibility');
    return;
  }
  try {
    s.validate();
  } catch (err) {
    r.failf(`signed outcome: ${(err as Error).message}`);
    return;
  }
  r.scanJWS('signed outcome', s.jws);
  const verify = r.subj.verifyOutcome;
  if (typeof verify === 'function') {
    try {
      verify(s.jws);
    } catch (err) {
      r.failf(`signature of the outcome does not verify: ${errorText(err)}`);
    }
  }
  const rep = checkOutcomeJWS(r, s.jws, obs);
  if (rep === undefined) return;
  if (
    e.outcome === OUT.noExecSuccess &&
    rep.event_kind === EventKind.EXECUTION &&
    rep.result === OutcomeResult.SUCCESS
  ) {
    r.failf(
      'recordOutcome signed an EXECUTION report with result SUCCESS although the case gives the adapter no execution visibility (draft 14.1: missing visibility is declared, never assumed to be success)',
    );
  }
}

// The value of a header member for a message, as Go's %v prints it.
function v(x: unknown): string {
  if (x === undefined) return '<nil>';
  return typeof x === 'string' ? x : jsonText(x);
}

/**
 * Decodes a compact JWS and checks it as an outcome report of the
 * observation: the JOSE header of draft 7.2, a payload that strict-decodes
 * as an outcome report with every required member, the members the adapter
 * does not choose, and the time rules of draft 7.5 and 14.3. Returns the
 * report, or `undefined` when it cannot be read.
 */
function checkOutcomeJWS(r: Run, jws: string, obs: Observation): OutcomeReport | undefined {
  const [h, p] = jws.split('.');
  let hdrRaw: Uint8Array;
  let payRaw: Uint8Array;
  try {
    hdrRaw = decodeSegment(h ?? '');
  } catch (err) {
    r.failf(`JWS header is not unpadded base64url: ${(err as Error).message}`);
    return undefined;
  }
  try {
    payRaw = decodeSegment(p ?? '');
  } catch (err) {
    r.failf(`JWS payload is not unpadded base64url: ${(err as Error).message}`);
    return undefined;
  }

  let hdr: Record<string, unknown>;
  try {
    const parsed = parse(hdrRaw, { maxBytes: 4 << 10 });
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('not a JSON object');
    }
    hdr = parsed as Record<string, unknown>;
  } catch (err) {
    r.failf(`JWS header: ${(err as Error).message}`);
    return undefined;
  }
  if (hdr.typ !== OUTCOME_TYP) r.failf(`JWS typ is ${v(hdr.typ)}, want ${OUTCOME_TYP}`);
  if (hdr.alg !== 'ES256' && hdr.alg !== 'Ed25519') {
    r.failf(`JWS alg is ${v(hdr.alg)}, want ES256 or Ed25519 (draft 7.2)`);
  }
  if (typeof hdr.kid !== 'string' || hdr.kid === '') {
    r.failf('JWS header has no kid: a service-signed artifact names its key');
  }
  for (const banned of ['jku', 'x5u', 'jwk', 'crit']) {
    if (Object.hasOwn(hdr, banned)) {
      r.failf(
        `JWS header carries ${JSON.stringify(banned)}, which an outcome report must not (draft 7.2)`,
      );
    }
  }

  let rep: OutcomeReport;
  try {
    rep = decode<OutcomeReport>(payRaw, shapes.OutcomeReport, {
      maxBytes: defaultLimits().artifactPayloadBytes,
    });
  } catch (err) {
    r.failf(`JWS payload is not an outcome report: ${(err as Error).message}`);
    return undefined;
  }
  // The strict decode refuses a null where the schema wants an array or an
  // object, but it does not require members to be present.
  for (const name of shapes.OutcomeReport.required) {
    if (!Object.hasOwn(rep, name)) {
      r.failf(`outcome report lacks the required member ${JSON.stringify(name)}`);
    }
  }
  checkReport(r, rep, obs);
  return rep;
}

// The members of the report that the adapter does not choose, against the
// observation, and the validity window.
function checkReport(r: Run, rep: OutcomeReport, obs: Observation): void {
  if (rep.pact_version !== VERSION) {
    r.failf(`pact_version is ${JSON.stringify(rep.pact_version)}, want ${JSON.stringify(VERSION)}`);
  }
  const pairs: [string, unknown, string][] = [
    ['event_id', rep.event_id, obs.eventId],
    ['operation_id', rep.operation_id, obs.operationId],
    ['task_id', rep.task_id, obs.taskId],
    ['event_kind', rep.event_kind, obs.eventKind],
    ['result', rep.result, obs.result],
    ['dimension', rep.dimension, obs.dimension],
    ['severity', rep.severity, obs.severity],
    ['tenant_id', rep.tenant_id, obs.context.tenant_id],
    ['environment_id', rep.environment_id, obs.context.environment_id],
    ['sub', rep.sub, obs.context.agent_id],
  ];
  for (const [name, got, want] of pairs) {
    if (got !== want) {
      r.failf(
        `outcome report ${name} is ${JSON.stringify(got ?? '')}, want ${JSON.stringify(want)} from the observation`,
      );
    }
  }
  const observed = obs.observedAt === null ? null : sec(obs.observedAt);
  if (rep.observed_at !== observed) {
    r.failf(
      `outcome report observed_at is ${rep.observed_at}, want ${observed}: the original observation time`,
    );
  }
  let sameContext = false;
  try {
    sameContext = jsonEqual(encode(rep.context), encode(obs.context));
  } catch {
    sameContext = false;
  }
  if (!sameContext) {
    r.failf(
      `outcome report context is ${jsonText(rep.context)}, want the observation's ${jsonText(obs.context)}`,
    );
  }
  if (!isReporterRole(rep.reporter_role)) {
    r.failf(`reporter_role ${JSON.stringify(rep.reporter_role)} is not a defined role`);
  }
  const jti = Buffer.byteLength(rep.jti ?? '', 'utf8');
  if (jti < 22 || jti > 128) r.failf(`jti has ${jti} characters, want 22 to 128`);
  try {
    checkWindow(rep.iat, rep.nbf, rep.exp, r.now, SKEW_MS);
  } catch (err) {
    r.failf(`outcome report validity: ${(err as Error).message}`);
  }
  try {
    checkLifetime(Artifact.OUTCOME, rep.iat, rep.exp);
  } catch (err) {
    r.failf(`outcome report lifetime: ${(err as Error).message}`);
  }
  for (const [name, value] of [
    ['iss', rep.iss],
    ['aud', rep.aud],
  ] as const) {
    if ((value ?? '') === '') r.failf(`outcome report ${name} is empty`);
  }
}
