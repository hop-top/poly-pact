/**
 * The rules of the adapter case-file format (Go
 * hop.top/pact-go/adapter/adaptertest, casefile.go: Case.validate and the rules
 * it applies), as spec/v1.0/fixtures/adapters/README.md states them.
 *
 * @module
 */
import { MAX_SAFE_INTEGER } from '../../core/strictjson.ts';
import { decodeRequest } from '../../internal/request.ts';
import { isBindingStatus } from '../types.ts';
import type { Call, Case, Expect, PrincipalJSON, Request } from './casefile.ts';
import {
  CASE_VERSION,
  FN,
  FUNCTION_OUTCOMES,
  OUT,
  WORKLOADS_DEDICATED,
  WORKLOADS_SHARED,
} from './names.ts';

const ID_PATTERN = /^[A-Z][A-Z0-9]*-[0-9]{2,}(\.[a-z0-9]+(-[a-z0-9]+)*)?$/;

type Obj = Record<string, unknown>;

const s = (v: unknown): string => (typeof v === 'string' ? v : '');

// The request of a case, after the rules of the format: a method and a url,
// then the shared request decoder (arrival, header names, body_b64).
function requestOf(v: Obj): Request {
  if (s(v.method) === '' || s(v.url) === '') throw new Error('request needs a method and a url');
  const d = decodeRequest(v);
  const headers: Record<string, string> = {};
  for (const [name, value] of d.request.headers) headers[name] = value;
  return Object.freeze({
    method: d.request.method,
    url: d.request.rawRequestURI,
    headers,
    body_b64: s(v.body_b64),
    tlsPeer: d.request.tlsPeer ?? null,
    native_state_ref: d.nativeStateRef,
    arrival: d.arrival,
  });
}

// Runs check and prefixes the message of an error it throws with the case id.
export function within<T>(id: string, check: () => T): T {
  try {
    return check();
  } catch (err) {
    throw new Error(`${id}: ${(err as Error).message}`);
  }
}

export function validateTop(c: Omit<Case, 'request'>): void {
  if (c.case_version !== CASE_VERSION) {
    throw new Error(`case_version is ${c.case_version}, want ${CASE_VERSION}`);
  }
  if (!ID_PATTERN.test(c.id)) {
    throw new Error(`id ${JSON.stringify(c.id)} does not match ${ID_PATTERN.source}`);
  }
  if (c.title.trim() === '') throw new Error(`${c.id}: title is empty`);
  if (
    c.workloads !== '' &&
    c.workloads !== WORKLOADS_SHARED &&
    c.workloads !== WORKLOADS_DEDICATED
  ) {
    throw new Error(
      `${c.id}: workloads ${JSON.stringify(c.workloads)} is not "${WORKLOADS_SHARED}" or "${WORKLOADS_DEDICATED}"`,
    );
  }
  if (c.now !== null && (!Number.isInteger(c.now) || c.now < 0 || c.now > MAX_SAFE_INTEGER)) {
    throw new Error(`${c.id}: now is outside 0..2^53-1`);
  }
  if (!isJSONObject(c.native_state.text)) {
    throw new Error(`${c.id}: native_state is not a JSON object`);
  }
  const f = c.expect.function;
  const outcomes = FUNCTION_OUTCOMES[f];
  if (outcomes === undefined) {
    throw new Error(
      `${c.id}: expect.function ${JSON.stringify(f)} is not one of the seven functions`,
    );
  }
  if (!outcomes.includes(c.expect.outcome)) {
    throw new Error(
      `${c.id}: outcome ${JSON.stringify(c.expect.outcome)} is not defined for ${f} (want one of [${outcomes.join(' ')}])`,
    );
  }
}

function isJSONObject(text: string): boolean {
  const t = text.trim();
  return t.startsWith('{') && t.endsWith('}');
}

export function validateRequest(f: string, r: Obj | null): Request | null {
  const takesRequest = f === FN.authenticate || f === FN.mapOperation;
  if (takesRequest && r === null) throw new Error(`${f} needs a request`);
  if (!takesRequest && r !== null) throw new Error(`${f} takes no request`);
  return r === null ? null : requestOf(r);
}

// The members of the call that are set.
function presentCall(k: Call): string[] {
  const set: [boolean, string][] = [
    [k.realm !== null, 'realm'],
    [k.workload !== '', 'workload'],
    [k.agent_id !== '', 'agent_id'],
    [k.mapping_version !== '', 'mapping_version'],
    [k.principal !== null, 'principal'],
    [k.binding !== null, 'binding'],
    [k.native_path !== '', 'native_path'],
    [k.check_id !== null, 'check_id'],
    [k.intent !== null, 'intent'],
    [k.operation !== null, 'operation'],
    [k.evidence_refs !== null, 'evidence_refs'],
    [k.observation !== null, 'observation'],
  ];
  return set.filter(([on]) => on).map(([, name]) => name);
}

// The required and the optional members of the call, per function.
const CALL_MEMBERS: Readonly<Record<string, { required: string[]; optional: string[] }>> = {
  [FN.authenticate]: { required: [], optional: [] },
  [FN.binding]: { required: ['realm', 'workload', 'agent_id'], optional: [] },
  [FN.mapOperation]: { required: ['principal', 'mapping_version'], optional: [] },
  [FN.claim]: { required: ['principal', 'native_path'], optional: ['intent', 'operation'] },
  [FN.check]: {
    required: ['check_id', 'principal', 'operation'],
    optional: ['binding', 'intent', 'evidence_refs'],
  },
  [FN.authorize]: { required: ['principal', 'operation'], optional: [] },
  [FN.record]: { required: ['observation'], optional: [] },
};

export function validateCall(c: Case, f: string): void {
  const m = CALL_MEMBERS[f] as { required: string[]; optional: string[] };
  const set = presentCall(c.call);
  for (const name of m.required) {
    if (!set.includes(name)) throw new Error(`call.${name} is required for ${f}`);
  }
  for (const name of set) {
    if (!m.required.includes(name) && !m.optional.includes(name)) {
      throw new Error(`call.${name} is not an argument of ${f}`);
    }
  }
  if (f === FN.check) validateCheckCall(c.call);
}

// The principal of a check_context call is the one the operation names
// (draft 12.1), and a binding has a defined status.
function validateCheckCall(k: Call): void {
  const p = k.principal as PrincipalJSON;
  const pid = k.operation?.principal_id ?? '';
  if (p.id !== pid) {
    throw new Error(
      `call.principal.id ${JSON.stringify(p.id)} is not call.operation.principal_id ${JSON.stringify(pid)}: the principal is the one of the operation (draft 12.1)`,
    );
  }
  const b = k.binding;
  if (b !== null && b.status !== '' && !isBindingStatus(b.status)) {
    throw new Error(`call.binding.status ${JSON.stringify(b.status)} is not a binding status`);
  }
}

// The Expect member an outcome must come with.
const EXPECT_MEMBER: Readonly<Record<string, string>> = {
  [OUT.authenticated]: 'principal',
  [OUT.bound]: 'binding',
  [OUT.unusable]: 'binding',
};

// The outcome-specific Expect members a function accepts.
const FUNCTION_EXPECT: Readonly<Record<string, readonly string[]>> = {
  [FN.authenticate]: ['principal'],
  [FN.binding]: ['binding'],
  [FN.mapOperation]: ['operation'],
  [FN.claim]: ['claim'],
  [FN.authorize]: ['decision'],
};

function presentExpect(e: Expect): string[] {
  const set: [boolean, string][] = [
    [e.principal !== null, 'principal'],
    [e.binding !== null, 'binding'],
    [e.operation !== null, 'operation'],
    [e.claim !== null, 'claim'],
    [e.decision !== null, 'decision'],
  ];
  return set.filter(([on]) => on).map(([, name]) => name);
}

// Only an UNKNOWN result reports the agent ID enrolled for another workload
// (draft 17.1): the member may be true only for the outcome unknown, and that
// outcome, which names no record, accepts no other binding member.
function validateElsewhere(e: Expect): void {
  const b = e.binding;
  if (b === null) return;
  if (e.outcome === OUT.notEnrolled) {
    if (b.agent_id !== '' || b.operator_id !== '' || b.holder_jkt !== '' || b.status !== '') {
      throw new Error(
        `outcome ${JSON.stringify(e.outcome)} accepts only enrolled_elsewhere in expect.binding`,
      );
    }
    return;
  }
  if (b.enrolled_elsewhere === true) {
    throw new Error(
      `expect.binding.enrolled_elsewhere true applies only to outcome "${OUT.notEnrolled}", not ${JSON.stringify(e.outcome)}`,
    );
  }
}

export function validateExpect(c: Case, f: string): void {
  const e = c.expect;
  const present = presentExpect(e);
  for (const name of present) {
    if (!(FUNCTION_EXPECT[f] ?? []).includes(name)) {
      throw new Error(`expect.${name} does not apply to ${f}`);
    }
  }
  const want = EXPECT_MEMBER[e.outcome];
  if (want !== undefined && !present.includes(want)) {
    throw new Error(`outcome ${JSON.stringify(e.outcome)} needs expect.${want}`);
  }
  validateElsewhere(e);
  const attrs = e.principal?.attributes;
  if (attrs != null && attrs.text.length > 0 && !isJSONObject(attrs.text)) {
    throw new Error('expect.principal.attributes is not a JSON object');
  }
  for (const h of e.must_not_call) {
    if (h.trim() === '') throw new Error('expect.must_not_call has an empty hook name');
  }
}
