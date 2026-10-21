/**
 * The strict decode of one adapter case file into the case model (Go
 * hop.top/pact-go/adapter/adaptertest, casefile.go: the json tags of Case and
 * the members it reaches).
 *
 * @module
 */

import type { Dimension, EventKind, OutcomeResult, Severity } from '../../core/enums.ts';
import { type Member, type Shape, shapes } from '../../core/shapes.ts';
import { decode } from '../../core/strictjson.ts';
import { RawJSON } from '../../core/values.ts';
import type {
  BindingJSON,
  Call,
  Case,
  Expect,
  ExpectPrincipal,
  ObligationJSON,
  ObservationJSON,
  PrincipalJSON,
} from './casefile.ts';
import { validateCall, validateExpect, validateRequest, validateTop, within } from './caserules.ts';
import { MAX_CASE_BYTES } from './names.ts';

// The member tables of a case file. A Go pointer member is nullable; a Go
// slice or map is not (the strict decoder refuses null for both).
const str: Member = { type: 'string' };
const num: Member = { type: 'number' };
const strs: Member = { type: 'array', items: str };
const raw: Member = { type: 'raw' };
const rawMap: Member = { type: 'map', values: raw };
const nullable = (of: Member): Member => ({ type: 'nullable', of });
const ref = (name: string): Member => ({ type: 'shape', name });
const shapeOf = (members: Record<string, Member>): Shape => ({
  required: [],
  optional: Object.keys(members),
  members,
});

const CASE_DEFS: Readonly<Record<string, Shape>> = {
  ...shapes,
  Case: shapeOf({
    case_version: num,
    id: str,
    title: str,
    draft: strs,
    workloads: str,
    now: nullable(num),
    native_state: raw,
    request: nullable(ref('Request')),
    call: ref('Call'),
    expect: ref('Expect'),
  }),
  Request: shapeOf({
    method: str,
    url: str,
    headers: { type: 'map', values: str },
    body_b64: str,
    tls_peer: nullable(ref('TLSPeer')),
    native_state_ref: str,
    arrival: str,
  }),
  TLSPeer: shapeOf({ subject_cn: str, issuer_cn: str, dns_names: strs, uris: strs }),
  RealmJSON: shapeOf({ tenant_id: str, environment_id: str }),
  PrincipalJSON: shapeOf({
    id: str,
    realm: ref('RealmJSON'),
    workload: str,
    mechanism: str,
    authenticated_at: nullable(num),
    attributes: rawMap,
  }),
  BindingJSON: shapeOf({ agent_id: str, operator_id: str, holder_jkt: str, status: str }),
  ObservationJSON: shapeOf({
    event_id: str,
    event_kind: { type: 'enum', name: 'EventKind' },
    context: ref('ReputationContext'),
    task_id: str,
    operation_id: str,
    admission_receipt_id: nullable(str),
    observed_at: num,
    result: { type: 'enum', name: 'OutcomeResult' },
    dimension: { type: 'enum', name: 'Dimension' },
    severity: { type: 'enum', name: 'Severity' },
    evidence_refs: strs,
    attribution: ref('Attribution'),
    supersedes: strs,
    details: str,
  }),
  Call: shapeOf({
    realm: nullable(ref('RealmJSON')),
    workload: str,
    agent_id: str,
    mapping_version: str,
    principal: nullable(ref('PrincipalJSON')),
    binding: nullable(ref('BindingJSON')),
    native_path: str,
    check_id: nullable(str),
    intent: nullable(ref('Intent')),
    operation: nullable(ref('OperationContext')),
    evidence_refs: strs,
    observation: nullable(ref('ObservationJSON')),
  }),
  Expect: shapeOf({
    function: str,
    outcome: str,
    reason_code: str,
    must_not_call: strs,
    leak_scan: nullable(ref('LeakScan')),
    principal: nullable(ref('ExpectPrincipal')),
    binding: nullable(ref('ExpectBinding')),
    operation: nullable(ref('ExpectOperation')),
    claim: nullable(ref('ExpectClaim')),
    decision: nullable(ref('ExpectDecision')),
  }),
  LeakScan: shapeOf({ secrets: strs }),
  ExpectPrincipal: shapeOf({
    id: str,
    realm: nullable(ref('RealmJSON')),
    workload: str,
    mechanism: str,
    attributes: raw,
  }),
  ExpectBinding: shapeOf({
    agent_id: str,
    operator_id: str,
    holder_jkt: str,
    status: str,
    enrolled_elsewhere: nullable({ type: 'boolean' }),
  }),
  ExpectOperation: shapeOf({
    environment_id: str,
    principal_id: str,
    action: str,
    resources: nullable(strs),
    method: str,
    target_uri: str,
    body_digest: str,
    headers: nullable({ type: 'map', values: str }),
  }),
  ExpectClaim: shapeOf({
    value: raw,
    observed_at: raw,
    status_checked_at: raw,
    source_id: str,
    source_ref: str,
  }),
  ExpectDecision: shapeOf({
    obligations: nullable({ type: 'array', items: ref('ObligationJSON') }),
    source_id: str,
    source_ref: raw,
    decided_at: raw,
    policy_revision: str,
  }),
  ObligationJSON: shapeOf({ id: str, attributes: rawMap }),
};

type Obj = Record<string, unknown>;

function isObject(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// The JSON value of a raw member, for a Go `any` (numbers as numbers).
function plain(v: RawJSON): unknown {
  return JSON.parse(v.text);
}

function plainMap(v: unknown): Record<string, unknown> | null {
  if (!isObject(v)) return null;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) out[k] = x instanceof RawJSON ? plain(x) : x;
  return out;
}

// A value of a generated shape with every required member present: an absent
// one gets the Go zero value of its type, as Go's decoder leaves it.
function zeroOf(m: Member): unknown {
  switch (m.type) {
    case 'string':
    case 'digest':
    case 'enum':
      return '';
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    case 'array':
      return [];
    case 'map':
    case 'object':
      return {};
    case 'raw':
      return new RawJSON('null');
    case 'nullable':
      return null;
    case 'shape':
      return filled({}, m.name);
  }
}

function filled(v: Obj, shapeName: string): Obj {
  const s = CASE_DEFS[shapeName] as Shape;
  const out: Obj = { ...v };
  for (const name of s.required) {
    const m = s.members[name] as Member;
    if (out[name] === undefined) out[name] = zeroOf(m);
    else if (m.type === 'shape' && isObject(out[name]))
      out[name] = filled(out[name] as Obj, m.name);
  }
  return out;
}

const s = (v: unknown): string => (typeof v === 'string' ? v : '');

function realmOf(v: unknown) {
  const r = isObject(v) ? v : {};
  return Object.freeze({ tenant_id: s(r.tenant_id), environment_id: s(r.environment_id) });
}

function principalOf(v: Obj): PrincipalJSON {
  return Object.freeze({
    id: s(v.id),
    realm: realmOf(v.realm),
    workload: s(v.workload),
    mechanism: s(v.mechanism),
    authenticated_at: typeof v.authenticated_at === 'number' ? v.authenticated_at : null,
    attributes: plainMap(v.attributes),
  });
}

function bindingOf(v: Obj): BindingJSON {
  return Object.freeze({
    agent_id: s(v.agent_id),
    operator_id: s(v.operator_id),
    holder_jkt: s(v.holder_jkt),
    status: s(v.status),
  });
}

function observationOf(v: Obj): ObservationJSON {
  return Object.freeze({
    event_id: s(v.event_id),
    event_kind: s(v.event_kind) as EventKind,
    context: filled(isObject(v.context) ? v.context : {}, 'ReputationContext') as never,
    task_id: s(v.task_id),
    operation_id: s(v.operation_id),
    admission_receipt_id:
      typeof v.admission_receipt_id === 'string' ? v.admission_receipt_id : null,
    observed_at: typeof v.observed_at === 'number' ? v.observed_at : 0,
    result: s(v.result) as OutcomeResult,
    dimension: s(v.dimension) as Dimension,
    severity: s(v.severity) as Severity,
    evidence_refs: Array.isArray(v.evidence_refs) ? (v.evidence_refs as string[]) : null,
    attribution: filled(isObject(v.attribution) ? v.attribution : {}, 'Attribution') as never,
    supersedes: Array.isArray(v.supersedes) ? (v.supersedes as string[]) : null,
    details: s(v.details),
  });
}

function callOf(v: Obj): Call {
  return Object.freeze({
    realm: isObject(v.realm) ? realmOf(v.realm) : null,
    workload: s(v.workload),
    agent_id: s(v.agent_id),
    mapping_version: s(v.mapping_version),
    principal: isObject(v.principal) ? principalOf(v.principal) : null,
    binding: isObject(v.binding) ? bindingOf(v.binding) : null,
    native_path: s(v.native_path),
    check_id: typeof v.check_id === 'string' ? v.check_id : null,
    intent: isObject(v.intent) ? (filled(v.intent, 'Intent') as never) : null,
    operation: isObject(v.operation) ? (filled(v.operation, 'OperationContext') as never) : null,
    evidence_refs: Array.isArray(v.evidence_refs) ? (v.evidence_refs as string[]) : null,
    observation: isObject(v.observation) ? observationOf(v.observation) : null,
  });
}

const rawOrNull = (v: unknown): RawJSON | null => (v instanceof RawJSON ? v : null);

function expectOf(v: Obj): Expect {
  const p = isObject(v.principal) ? v.principal : null;
  const b = isObject(v.binding) ? v.binding : null;
  const op = isObject(v.operation) ? v.operation : null;
  const c = isObject(v.claim) ? v.claim : null;
  const d = isObject(v.decision) ? v.decision : null;
  const principal: ExpectPrincipal | null =
    p === null
      ? null
      : Object.freeze({
          id: s(p.id),
          realm: isObject(p.realm) ? realmOf(p.realm) : null,
          workload: s(p.workload),
          mechanism: s(p.mechanism),
          attributes: rawOrNull(p.attributes),
        });
  return Object.freeze({
    function: s(v.function),
    outcome: s(v.outcome),
    reason_code: s(v.reason_code),
    must_not_call: Array.isArray(v.must_not_call) ? (v.must_not_call as string[]) : [],
    leak_scan: isObject(v.leak_scan)
      ? Object.freeze({
          secrets: Array.isArray(v.leak_scan.secrets) ? (v.leak_scan.secrets as string[]) : [],
        })
      : null,
    principal,
    binding:
      b === null
        ? null
        : Object.freeze({
            ...bindingOf(b),
            enrolled_elsewhere:
              typeof b.enrolled_elsewhere === 'boolean' ? b.enrolled_elsewhere : null,
          }),
    operation:
      op === null
        ? null
        : Object.freeze({
            environment_id: s(op.environment_id),
            principal_id: s(op.principal_id),
            action: s(op.action),
            resources: Array.isArray(op.resources) ? (op.resources as string[]) : null,
            method: s(op.method),
            target_uri: s(op.target_uri),
            body_digest: s(op.body_digest),
            headers: isObject(op.headers) ? (op.headers as Record<string, string>) : null,
          }),
    claim:
      c === null
        ? null
        : Object.freeze({
            value: rawOrNull(c.value),
            observed_at: rawOrNull(c.observed_at),
            status_checked_at: rawOrNull(c.status_checked_at),
            source_id: s(c.source_id),
            source_ref: s(c.source_ref),
          }),
    decision:
      d === null
        ? null
        : Object.freeze({
            obligations: Array.isArray(d.obligations)
              ? (d.obligations as Obj[]).map(
                  (o): ObligationJSON =>
                    Object.freeze({ id: s(o.id), attributes: plainMap(o.attributes) }),
                )
              : null,
            source_id: s(d.source_id),
            source_ref: rawOrNull(d.source_ref),
            decided_at: rawOrNull(d.decided_at),
            policy_revision: s(d.policy_revision),
          }),
  });
}

/**
 * Decodes one case file strictly and checks the rules of the format; throws
 * an `Error` naming the rule.
 */
export function parseCase(data: Uint8Array | string): Case {
  const v = decode<Obj>(data, CASE_DEFS.Case as Shape, { maxBytes: MAX_CASE_BYTES }, CASE_DEFS);
  const top = {
    case_version: typeof v.case_version === 'number' ? v.case_version : 0,
    id: s(v.id),
    title: s(v.title),
    draft: Array.isArray(v.draft) ? (v.draft as string[]) : [],
    workloads: s(v.workloads),
    now: typeof v.now === 'number' ? v.now : null,
    native_state: v.native_state instanceof RawJSON ? v.native_state : new RawJSON(''),
    call: callOf(isObject(v.call) ? v.call : {}),
    expect: expectOf(isObject(v.expect) ? v.expect : {}),
  };
  validateTop(top);
  const f = top.expect.function;
  const c: Case = Object.freeze({
    ...top,
    request: within(top.id, () => validateRequest(f, isObject(v.request) ? v.request : null)),
  });
  within(c.id, () => validateCall(c, f));
  within(c.id, () => validateExpect(c, f));
  return c;
}
