// Port of go/adapter/adaptertest/fake_test.go and the case builders of the
// adaptertest tests: an adapter whose behavior each test scripts, a factory
// for it, case builders for the seven functions, and the row runner.

import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import type {
  Call,
  Case,
  Expect,
  Factory,
  RealmJSON,
  Request,
  Subject,
} from '../../src/adapter/adaptertest/index.ts';
import { runCase } from '../../src/adapter/adaptertest/run.ts';
import type {
  Adapter,
  AgentBinding,
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
} from '../../src/adapter/index.ts';
import { Signed } from '../../src/adapter/index.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import type { EventKind, OutcomeResult } from '../../src/core/enums.ts';
import type { OperationContext, OutcomeReport } from '../../src/core/types.ts';
import { type Digest, RawJSON } from '../../src/core/values.ts';

type Fn<A extends unknown[], R> = (...args: A) => Promise<R>;

/**
 * The scripted behavior of a fake adapter. A function that is not set
 * resolves to the zero value, which the suite treats as a wrong answer.
 */
export interface Script {
  auth?: Fn<[RawRequest], Principal>;
  bind?: Fn<[Realm, string, string], AgentBinding>;
  mapOp?: Fn<[RawRequest, Principal, string], OperationContext>;
  claim?: Fn<[string, ClaimContext], NativeClaim>;
  check?: Fn<[string, CheckInput], Partial<CheckOutcome>>;
  authz?: Fn<[Principal, OperationContext], Decision>;
  record?: Fn<[Observation], Recorded | null>;
}

export const ZERO_PRINCIPAL: Principal = Object.freeze({
  id: '',
  realm: Object.freeze({ tenantId: '', environmentId: '' }),
  workload: '',
  mechanism: '',
  authenticatedAt: null,
  attributes: Object.freeze({}),
});

export const ZERO_BINDING = Object.freeze({
  agentId: '',
  operatorId: '',
  holderJKT: '',
  status: '',
  observedAt: null,
  statusCheckedAt: null,
  sourceId: '',
  sourceRef: '',
  enrolledElsewhere: false,
}) as unknown as AgentBinding;

/** A fake adapter with the script s. */
export function fake(s: Script = {}): Adapter {
  return {
    describe: (): Descriptor => ({ protocol: 'fake', version: '', mappingRevision: '' }),
    authenticateNative: async (req) => (s.auth ? s.auth(req) : ZERO_PRINCIPAL),
    resolveAgentBinding: async (realm, w, a) => (s.bind ? s.bind(realm, w, a) : ZERO_BINDING),
    mapOperation: async (req, p, v) =>
      s.mapOp ? s.mapOp(req, p, v) : ({} as unknown as OperationContext),
    readNativeClaim: async (path, c) =>
      s.claim ? s.claim(path, c) : ({} as unknown as NativeClaim),
    checkContext: async (id, input) => (s.check ? await s.check(id, input) : {}) as CheckOutcome,
    authorizeNative: async (p, op) => (s.authz ? s.authz(p, op) : ({} as unknown as Decision)),
    recordOutcome: async (o) => (s.record ? s.record(o) : null) as unknown as Recorded,
  };
}

/** The request with one more header line, `name: value`, replacing any of that name. */
export function withHeader(req: RawRequest, name: string, value: string): RawRequest {
  const rest = req.headers.filter(([n]) => n.toLowerCase() !== name.toLowerCase());
  return { ...req, headers: [...rest, [name, value]] };
}

/** The value of the header `name` of req, `''` when absent. */
export function header(req: RawRequest, name: string): string {
  const line = req.headers.find(([n]) => n.toLowerCase() === name.toLowerCase());
  return line === undefined ? '' : line[1];
}

/**
 * A factory that hands out the adapter with an arrive hook that marks
 * nothing and a credential hook that sets a bearer token.
 */
export function factoryFor(a: Adapter): Factory {
  return (): Subject => ({
    adapter: a,
    arrive: (r) => r,
    credential: (r, ref) => withHeader(r, 'Authorization', `Bearer tok-${ref}`),
  });
}

/** The current time of a case that states none, in milliseconds. */
export const NOW = 1792080000 * 1000;
export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const SKEW = 5 * SECOND;

export const acme: Realm = Object.freeze({
  tenantId: 'acme',
  environmentId: 'https://gateway.example/environments/finance',
});
export const acmeJS: RealmJSON = Object.freeze({
  tenant_id: 'acme',
  environment_id: 'https://gateway.example/environments/finance',
});

/** An authenticated principal that satisfies every invariant. */
export function goodPrincipal(): Principal {
  return {
    id: 'https://idp.example/alice',
    realm: acme,
    workload: 'w-1',
    mechanism: 'bearer',
    authenticatedAt: NOW,
    attributes: {},
  };
}

/** An operation context that satisfies every invariant. */
export function goodOp(): OperationContext {
  return {
    operation_id: 'op-1',
    environment_id: acme.environmentId,
    principal_id: 'https://idp.example/alice',
    action: 'invoice.read',
    resources: ['https://invoices.example/invoices/1'],
    method: 'GET',
    target_uri: 'https://gateway.example/invoices/1',
    body_digest: '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU' as Digest,
    headers: {},
  };
}

export function emptyCall(): Call {
  return {
    realm: null,
    workload: '',
    agent_id: '',
    mapping_version: '',
    principal: null,
    binding: null,
    native_path: '',
    check_id: null,
    intent: null,
    operation: null,
    evidence_refs: null,
    observation: null,
  };
}

/** An expectation of `fn` and `outcome` with the members of e. */
export function expect(fn: string, outcome: string, e: Partial<Expect> = {}): Expect {
  return {
    reason_code: '',
    must_not_call: [],
    leak_scan: null,
    principal: null,
    binding: null,
    operation: null,
    claim: null,
    decision: null,
    ...e,
    function: fn,
    outcome,
  };
}

type Writable<T> = { -readonly [K in keyof T]: T[K] };

/** A case whose members and call members a test may change, as the Go tests change a *Case. */
export type TestCase = Omit<Writable<Case>, 'call'> & { call: Writable<Call> };

/** A case with the defaults of runFake: id T-01, native state {}. */
export function makeCase(c: Partial<Case>): TestCase {
  return {
    case_version: 1,
    id: 'T-01',
    title: 't',
    draft: [],
    workloads: '',
    now: null,
    native_state: new RawJSON('{}'),
    request: null,
    call: emptyCall(),
    ...(c as object),
    expect: c.expect ?? expect('authenticate_native', 'denied'),
  } as TestCase;
}

export function request(r: Partial<Request> = {}): Request {
  return {
    method: 'GET',
    url: 'https://gateway.example/invoices/1',
    headers: {},
    body_b64: '',
    tlsPeer: null,
    native_state_ref: '',
    arrival: '',
    ...r,
  };
}

export function authCase(outcome: string, e: Partial<Expect> = {}): TestCase {
  return makeCase({
    request: request({ native_state_ref: 'alice' }),
    expect: expect('authenticate_native', outcome, e),
  });
}

export function authFake(p: Principal, err?: unknown): Adapter {
  return fake({
    auth: async () => {
      if (err !== undefined) throw err;
      return p;
    },
  });
}

export function bindCase(outcome: string, e: Partial<Expect> = {}): TestCase {
  return makeCase({
    call: {
      ...emptyCall(),
      realm: acmeJS,
      workload: 'w-1',
      agent_id: 'https://identity.example/agents/a',
    },
    expect: expect('resolve_agent_binding', outcome, e),
  });
}

export function bindFake(b: Partial<AgentBinding>, err?: unknown): Adapter {
  return fake({
    bind: async () => {
      if (err !== undefined) throw err;
      return { ...ZERO_BINDING, ...b };
    },
  });
}

function callPrincipal() {
  return {
    id: goodPrincipal().id,
    realm: acmeJS,
    workload: 'w-1',
    mechanism: '',
    authenticated_at: null,
    attributes: null,
  };
}

export function mapCase(outcome: string, e: Partial<Expect>, req: Partial<Request> = {}): TestCase {
  return makeCase({
    request: request(req),
    call: { ...emptyCall(), mapping_version: 'map-1', principal: callPrincipal() },
    expect: expect('map_operation', outcome, e),
  });
}

export function mapFake(op: Partial<OperationContext>, err?: unknown): Adapter {
  return fake({
    mapOp: async () => {
      if (err !== undefined) throw err;
      return op as OperationContext;
    },
  });
}

export function claimCase(outcome: string, e: Partial<Expect> = {}): TestCase {
  return makeCase({
    call: {
      ...emptyCall(),
      native_path: '/attributes/environment/roles',
      principal: callPrincipal(),
    },
    expect: expect('read_native_claim', outcome, e),
  });
}

export function claimFake(c: Partial<NativeClaim>, err?: unknown): Adapter {
  return fake({
    claim: async () => {
      if (err !== undefined) throw err;
      return c as NativeClaim;
    },
  });
}

export function checkCase(id: string, outcome: string, e: Partial<Expect> = {}): TestCase {
  return makeCase({
    call: { ...emptyCall(), check_id: id, principal: callPrincipal(), operation: goodOp() },
    expect: expect('check_context', outcome, e),
  });
}

export function checkFake(out: Partial<CheckOutcome>): Adapter {
  return fake({ check: async () => out as CheckOutcome });
}

export function authzCase(outcome: string, e: Partial<Expect> = {}): TestCase {
  return makeCase({
    call: { ...emptyCall(), principal: callPrincipal(), operation: goodOp() },
    expect: expect('authorize_native', outcome, e),
  });
}

export function authzFake(d: Partial<Decision>, err?: unknown): Adapter {
  return fake({
    authz: async () => {
      if (err !== undefined) throw err;
      return d as Decision;
    },
  });
}

export function recordCase(
  outcome: string,
  e: Partial<Expect>,
  kind: EventKind,
  result: OutcomeResult,
): TestCase {
  return makeCase({
    call: {
      ...emptyCall(),
      observation: {
        event_id: 'event-1',
        event_kind: kind,
        context: {
          tenant_id: 'acme',
          environment_id: acme.environmentId,
          agent_id: 'https://identity.example/agents/a',
          purpose_id: 'p',
          action_class: 'a',
          resource_class: 'r',
          runtime_class: 'managed',
        },
        task_id: 'task-1',
        operation_id: 'op-1',
        admission_receipt_id: null,
        observed_at: NOW / 1000 - 5,
        result,
        dimension: 'reliability',
        severity: 'info',
        evidence_refs: ['native-record:1'],
        attribution: {
          native_task_ref: 'task-1',
          independence_group: 'g',
          causal_assessment: 'UNKNOWN',
          assessment_ref: null,
        },
        supersedes: [],
        details: '',
      },
    },
    expect: expect('record_outcome', outcome, e),
  } as Partial<Case>);
}

export function recordFake(rec: unknown, err?: unknown): Adapter {
  return fake({
    record: async () => {
      if (err !== undefined) throw err;
      return rec as Recorded;
    },
  });
}

/** Runs one case against the adapter and returns the failures. */
export function runFake(a: Adapter, c: TestCase): Promise<string[]> {
  return runCase(factoryFor(a), c as Case);
}

/** Fails unless the case produced no failure. */
export function wantClean(fails: readonly string[]): void {
  assert.deepEqual(fails, [], `unexpected failures: ${JSON.stringify(fails)}`);
}

/** Fails unless there is a failure, and some failure contains each substring. */
export function wantFails(fails: readonly string[], ...subs: string[]): void {
  assert.ok(fails.length > 0, `the case passed, want failures containing ${JSON.stringify(subs)}`);
  for (const s of subs) {
    assert.ok(
      fails.some((f) => f.includes(s)),
      `no failure contains ${JSON.stringify(s)}; failures: ${JSON.stringify(fails)}`,
    );
  }
}

/** One row of scripted behaviors: the fake, the case, and the failures expected (none for a pass). */
export type Row = readonly [
  name: string,
  adapter: Adapter,
  c: TestCase,
  fails: readonly string[] | null,
];

/** Runs each row as a subtest and compares its failures with the expectation. */
export async function runRows(t: TestContext, rows: readonly Row[]): Promise<void> {
  for (const [name, a, c, fails] of rows) {
    await t.test(name, async () => {
      const got = await runFake(a, c);
      if (fails === null || fails.length === 0) wantClean(got);
      else wantFails(got, ...fails);
    });
  }
}

/** A fixture tree over in-memory files, keyed by their path. */
export function treeOf(files: Readonly<Record<string, string>>) {
  const enc = new TextEncoder();
  return {
    read(path: string): Uint8Array {
      const f = files[path];
      if (f === undefined) throw new Error(`open ${path}: file does not exist`);
      return enc.encode(f);
    },
    list(dir: string): readonly string[] {
      const prefix = `${dir}/`;
      const under = Object.keys(files).filter((p) => p.startsWith(prefix));
      if (under.length === 0) throw new Error(`open ${dir}: file does not exist`);
      return under
        .map((p) => p.slice(prefix.length))
        .filter((rest) => !rest.includes('/'))
        .sort();
    },
  };
}

/** minimalCase: a valid authenticate_native case. */
export const minimalCase = `{
  "case_version": 1,
  "id": "COMMON-01.one",
  "title": "A case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "request": {"method": "GET", "url": "https://gateway.example/x"},
  "expect": {"function": "authenticate_native", "outcome": "denied"}
}`;

const enc = (s: string) => Buffer.from(s).toString('base64url');
const nowSec = NOW / 1000;

/** The pieces of a signed outcome that a test changes before they are put together. */
export interface Parts {
  hdr: Record<string, unknown>;
  rep: Writable<OutcomeReport> & Record<string, unknown>;
  /** When set, replaces the encoded report. */
  payload?: string;
}

export function reportOf(o: Observation): Writable<OutcomeReport> & Record<string, unknown> {
  return {
    pact_version: '0.1',
    iss: 'https://gateway.example/reporters/finance',
    sub: o.context.agent_id,
    aud: 'https://reputation.example/service',
    jti: 'AAAAAAAAAAAAAAAAAAAAAA',
    iat: nowSec,
    nbf: nowSec,
    exp: nowSec + 300,
    tenant_id: o.context.tenant_id,
    event_id: o.eventId,
    environment_id: o.context.environment_id,
    task_id: o.taskId,
    operation_id: o.operationId,
    admission_receipt_id: o.admissionReceiptId,
    observed_at: Math.floor((o.observedAt ?? 0) / 1000),
    reporter_role: 'executor',
    context: { ...o.context },
    event_kind: o.eventKind,
    result: o.result,
    dimension: o.dimension,
    severity: o.severity,
    evidence_refs: [...o.evidenceRefs],
    attribution: o.attribution,
    supersedes: [...o.supersedes],
    details: o.details,
  };
}

function jwsOf(p: Parts): string {
  return `${enc(JSON.stringify(p.hdr))}.${enc(p.payload ?? JSON.stringify(p.rep))}.${enc('signature')}`;
}

/** A fake that signs the observation it gets, after mod has changed the pieces. */
export function signedFake(mod?: (p: Parts) => void) {
  return fake({
    record: async (o) => {
      const p: Parts = {
        hdr: { alg: 'ES256', kid: 'reporter-key-1', typ: 'pact-outcome+jwt' },
        rep: reportOf(o),
      };
      mod?.(p);
      return new Signed(jwsOf(p));
    },
  });
}
