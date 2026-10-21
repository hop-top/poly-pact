/**
 * record_outcome of the memory adapter and the verification of what it
 * signs (Go hop.top/pact-go/adapters/memory, outcome.go).
 *
 * @module
 */
import { createHash } from 'node:crypto';
import { AdapterError } from '../../adapter/errors.ts';
import { NoVisibility, type Observation, type Recorded, Signed } from '../../adapter/types.ts';
import { EventKind, ReporterRole } from '../../core/enums.ts';
import { decodeSegment } from '../../core/jws/base64url.ts';
import { verifyES256 } from '../../core/jws/es256.ts';
import { sign } from '../../core/jws/index.ts';
import { VERSION } from '../../core/limits.ts';
import type { OutcomeReport } from '../../core/types.ts';
import { encode } from '../../internal/encode.ts';
import { type Core, live } from './core.ts';

/** The validity of a signed outcome report: the baseline maximum of draft 14.3, in seconds. */
const OUTCOME_VALIDITY = 300;

/**
 * record_outcome: the observation as an outcome report signed with ES256 by
 * the ephemeral key of the instance.
 *
 * What the adapter cannot see it does not claim. An EXECUTION observation
 * with no execution visibility resolves to a NoVisibility whatever result
 * the observation carries, and never to an assumed success (draft 14.1). The
 * adapter signs only the events it observes itself: admission and
 * authorization decisions as the gateway and, with visibility, executions as
 * the executor. Free text and evidence references are cleaned of credential
 * material first (draft 19).
 */
export function recordOutcome(c: Core, o: Observation, signal?: AbortSignal): Recorded {
  live('record outcome', signal);
  const reporting = c.st.reporting;
  if (c.key === null || reporting === null) {
    throw AdapterError.unsupportedRequirement('memory: no reporting key is configured');
  }
  if (o.eventId === '') throw new Error('memory: the observation has no event id');
  if (
    o.context.tenant_id !== c.st.gateway.tenant_id ||
    o.context.environment_id !== c.st.gateway.environment_id
  ) {
    throw AdapterError.contextMismatch('memory: the observation belongs to another realm');
  }
  let role: ReporterRole;
  switch (o.eventKind) {
    case EventKind.ADMISSION:
    case EventKind.AUTHORIZATION:
      role = ReporterRole.GATEWAY;
      break;
    case EventKind.EXECUTION:
      if (c.st.visibility !== 'execution') {
        return new NoVisibility(
          'the adapter does not observe the execution of operations; execution is reported by the system that runs them',
        );
      }
      role = ReporterRole.EXECUTOR;
      break;
    default:
      throw AdapterError.unsupportedRequirement(
        `memory: the adapter does not report ${o.eventKind} events`,
      );
  }

  const now = Math.floor(c.clock.now() / 1000);
  const rep: OutcomeReport = {
    pact_version: VERSION,
    iss: reporting.issuer,
    sub: o.context.agent_id,
    aud: reporting.audience,
    jti: jti(reporting.issuer, o.eventId),
    iat: now,
    nbf: now,
    exp: now + OUTCOME_VALIDITY,
    tenant_id: o.context.tenant_id,
    event_id: o.eventId,
    environment_id: o.context.environment_id,
    task_id: o.taskId,
    operation_id: o.operationId,
    admission_receipt_id: o.admissionReceiptId,
    observed_at: o.observedAt === null ? 0 : Math.floor(o.observedAt / 1000),
    reporter_role: role,
    context: o.context,
    event_kind: o.eventKind,
    result: o.result,
    dimension: o.dimension,
    severity: o.severity,
    evidence_refs: o.evidenceRefs.map((r) => redact(c, r)),
    attribution: o.attribution,
    supersedes: [...o.supersedes],
    details: redact(c, o.details),
  };
  let jws: string;
  try {
    jws = sign(
      { alg: 'ES256', typ: 'pact-outcome+jwt', kid: reporting.kid },
      new TextEncoder().encode(encode(rep)),
      c.key,
    );
  } catch (err) {
    throw AdapterError.dependencyUnavailable('memory: signing', { cause: err });
  }
  return new Signed(jws);
}

// Stable per event, so a retry of the same observation carries the same
// identifier and the receiver deduplicates it (draft 7.5).
function jti(issuer: string, eventId: string): string {
  return createHash('sha256')
    .update(`${issuer}\u0000${eventId}`, 'utf8')
    .digest('base64url')
    .slice(0, 22);
}

/**
 * Verifies the ES256 signature of a compact JWS this adapter signed; throws
 * an `Error` when it does not verify.
 */
export function verifyOutcome(c: Core, jws: string): void {
  if (c.publicKey === null) throw new Error('memory: no reporting key is configured');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('memory: not a compact JWS');
  let sig: Uint8Array;
  try {
    sig = decodeSegment(parts[2] as string);
  } catch {
    throw new Error('memory: malformed signature');
  }
  if (sig.length !== 64) throw new Error('memory: malformed signature');
  if (!verifyES256(c.publicKey, `${parts[0]}.${parts[1]}`, sig)) {
    throw new Error('memory: the signature does not verify');
  }
}

// The shapes of credential material that draft 19 keeps out of receipts,
// outcome reports and logs.
const HEADER_LINE =
  /\b(authorization|proxy-authorization|cookie|set-cookie|pact-presentation|pact-admission)\s*:[^\r\n]*/gi;
const AUTH_VALUE = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi;
const JWS_LIKE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const ASSIGNMENT =
  /\b(access_token|refresh_token|id_token|api_?key|password|passwd|secret|session(?:_?id)?|sid|token)=[^\s&;"']+/gi;

const REDACTED = '[redacted]';

/**
 * `s` without credential material: every secret the adapter holds, header
 * lines that carry credentials, bearer and basic values, compact JWS
 * strings, and name=value pairs with a credential name.
 */
function redact(c: Core, s: string): string {
  let out = s;
  for (const id of c.st.identities) {
    if (id.secret !== '') out = out.replaceAll(id.secret, REDACTED);
  }
  out = out.replace(HEADER_LINE, `$1: ${REDACTED}`);
  out = out.replace(AUTH_VALUE, `$1 ${REDACTED}`);
  out = out.replace(JWS_LIKE, REDACTED);
  return out.replace(ASSIGNMENT, `$1=${REDACTED}`);
}
