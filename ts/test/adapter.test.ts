// Port of go/adapter/adapter_test.go: the seven interfaces of the draft 17.1
// table, the composite Adapter, and the module documentation that
// reproduces the table. The Go tests check the method signatures by
// reflection; here the compiler checks them (assertType) and the run checks
// the names.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  type Adapter,
  type AgentBinding,
  type AgentID,
  type BindingResolver,
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  type ClaimReader,
  type ContextChecker,
  type Decision,
  type Descriptor,
  type NativeAuthenticator,
  type NativeAuthorizer,
  type NativeClaim,
  NoVisibility,
  type Observation,
  type OperationMapper,
  type OutcomeRecorder,
  type Principal,
  type Realm,
  type Recorded,
  type Workload,
} from '../src/adapter/index.ts';
import type { RawRequest } from '../src/core/binding/index.ts';
import type { OperationContext } from '../src/core/types.ts';
import { headingSection } from './support/draft.ts';
import { DRAFT, PACKAGE, specText } from './support/repo.ts';
import { assertType, type Equal } from './support/types.ts';

// One row of the draft 17.1 table with the interface and method the module
// gives it, written from the 17.1 table and the contract, not derived from
// the module under test.
interface Fn {
  readonly draft: string;
  readonly iface: string;
  readonly method: keyof Adapter;
}

const FUNCTIONS: readonly Fn[] = [
  { draft: 'authenticate_native', iface: 'NativeAuthenticator', method: 'authenticateNative' },
  { draft: 'resolve_agent_binding', iface: 'BindingResolver', method: 'resolveAgentBinding' },
  { draft: 'map_operation', iface: 'OperationMapper', method: 'mapOperation' },
  { draft: 'read_native_claim', iface: 'ClaimReader', method: 'readNativeClaim' },
  { draft: 'check_context', iface: 'ContextChecker', method: 'checkContext' },
  { draft: 'authorize_native', iface: 'NativeAuthorizer', method: 'authorizeNative' },
  { draft: 'record_outcome', iface: 'OutcomeRecorder', method: 'recordOutcome' },
];

// The signatures, without the receiver, of the seven methods.
type Sig<I, M extends keyof I> = I[M] extends (...a: infer A) => infer R ? [A, R] : never;
assertType<
  Equal<
    Sig<NativeAuthenticator, 'authenticateNative'>,
    [[req: RawRequest, signal?: AbortSignal], Promise<Principal>]
  >
>();
assertType<
  Equal<
    Sig<BindingResolver, 'resolveAgentBinding'>,
    [
      [realm: Realm, workload: Workload, agent: AgentID, signal?: AbortSignal],
      Promise<AgentBinding>,
    ]
  >
>();
assertType<
  Equal<
    Sig<OperationMapper, 'mapOperation'>,
    [
      [req: RawRequest, p: Principal, mappingVersion: string, signal?: AbortSignal],
      Promise<OperationContext>,
    ]
  >
>();
assertType<
  Equal<
    Sig<ClaimReader, 'readNativeClaim'>,
    [[nativePath: string, c: ClaimContext, signal?: AbortSignal], Promise<NativeClaim>]
  >
>();
assertType<
  Equal<
    Sig<ContextChecker, 'checkContext'>,
    [[checkId: string, input: CheckInput, signal?: AbortSignal], Promise<CheckOutcome>]
  >
>();
assertType<
  Equal<
    Sig<NativeAuthorizer, 'authorizeNative'>,
    [[p: Principal, op: OperationContext, signal?: AbortSignal], Promise<Decision>]
  >
>();
assertType<
  Equal<
    Sig<OutcomeRecorder, 'recordOutcome'>,
    [[o: Observation, signal?: AbortSignal], Promise<Recorded>]
  >
>();
// One method per interface.
assertType<Equal<keyof NativeAuthenticator, 'authenticateNative'>>();
assertType<Equal<keyof BindingResolver, 'resolveAgentBinding'>>();
assertType<Equal<keyof OperationMapper, 'mapOperation'>>();
assertType<Equal<keyof ClaimReader, 'readNativeClaim'>>();
assertType<Equal<keyof ContextChecker, 'checkContext'>>();
assertType<Equal<keyof NativeAuthorizer, 'authorizeNative'>>();
assertType<Equal<keyof OutcomeRecorder, 'recordOutcome'>>();
// The composite: the seven and describe, nothing else.
assertType<
  Equal<
    keyof Adapter,
    | 'authenticateNative'
    | 'resolveAgentBinding'
    | 'mapOperation'
    | 'readNativeClaim'
    | 'checkContext'
    | 'authorizeNative'
    | 'recordOutcome'
    | 'describe'
  >
>();
assertType<Equal<Sig<Adapter, 'describe'>, [[], Descriptor]>>();

interface DraftRow {
  readonly fn: string;
  readonly input: string;
  readonly output: string;
}

// The rows of the draft 17.1 table.
function draftRows(draft: string): DraftRow[] {
  const sec = headingSection(draft, '### 17.1 Required adapter capabilities');
  return [...sec.matchAll(/^\| `([a-z_]+)` \| (.+?) \| (.+?) \|$/gm)].map((m) => ({
    fn: m[1] ?? '',
    input: m[2] ?? '',
    output: m[3] ?? '',
  }));
}

// The stub proves the composite is satisfiable; the module ships no
// implementation.
const stub: Adapter = {
  authenticateNative: async () => ({
    id: '',
    realm: { tenantId: '', environmentId: '' },
    workload: '',
    mechanism: '',
    authenticatedAt: null,
    attributes: {},
  }),
  resolveAgentBinding: async () => ({
    agentId: '',
    operatorId: '',
    holderJKT: '',
    status: 'UNKNOWN',
    observedAt: null,
    statusCheckedAt: null,
    sourceId: '',
    sourceRef: '',
    enrolledElsewhere: false,
  }),
  mapOperation: async () => ({
    operation_id: '',
    environment_id: '',
    principal_id: '',
    action: '',
    resources: [],
    method: 'GET',
    target_uri: '',
    body_digest: '' as OperationContext['body_digest'],
    headers: {},
  }),
  readNativeClaim: async () => ({
    value: null,
    observedAt: null,
    statusCheckedAt: null,
    sourceId: '',
    sourceRef: '',
  }),
  checkContext: async () => ({
    result: 'UNKNOWN',
    reasonCode: '',
    sourceId: '',
    sourceRef: '',
    observedAt: null,
  }),
  authorizeNative: async () => ({
    effect: 'UNKNOWN',
    obligations: [],
    reason: '',
    sourceId: '',
    sourceRef: '',
    decidedAt: null,
    policyRevision: '',
  }),
  recordOutcome: async () => new NoVisibility('stub'),
  describe: () => ({ protocol: '', version: '', mappingRevision: '' }),
};

test('TestDraftTableHasSevenFunctions', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const rows = draftRows(draft);
  assert.equal(rows.length, FUNCTIONS.length, 'draft 17.1 rows against the functions mapped');
  rows.forEach((r, i) => {
    assert.equal(r.fn, FUNCTIONS[i]?.draft, `row ${i}`);
  });
});

test('TestOneInterfacePerFunction', async (t) => {
  for (const f of FUNCTIONS) {
    await t.test(f.draft, () => {
      // The interface's single method and its signature are checked at
      // compile time above; the stub implements it under that name.
      assert.equal(typeof stub[f.method], 'function', `${f.iface}.${f.method}`);
    });
  }
});

test('TestCompositeExposesAllSeven', async () => {
  const want = [...FUNCTIONS.map((f) => f.method), 'describe'].sort();
  assert.deepEqual(Object.keys(stub).sort(), want);
  assert.ok((await stub.recordOutcome({} as Observation)) instanceof NoVisibility);
});

// The module comment of src/adapter/index.ts with the comment markers removed.
function docText(): string {
  const src = readFileSync(join(PACKAGE, 'src', 'adapter', 'index.ts'), 'utf8');
  const end = src.indexOf('*/');
  assert.ok(src.startsWith('/**') && end > 0, 'src/adapter/index.ts starts with a module comment');
  return src
    .slice(3, end)
    .split('\n')
    .map((line) => line.replace(/^\s*\* ?/, ''))
    .join('\n');
}

// Collapses whitespace runs, so a wrapped comment line matches the
// single-line draft cell.
function normalize(s: string): string {
  return s.split(/\s+/).filter(Boolean).join(' ');
}

test('TestDocReproducesDraftTableRowByRow', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const doc = normalize(docText());
  draftRows(draft).forEach((r, i) => {
    const f = FUNCTIONS[i];
    assert.ok(f, `row ${i}`);
    for (const want of [r.fn, `${f.iface}.${f.method}`, r.input, r.output]) {
      assert.ok(doc.includes(normalize(want)), `index.ts row ${i} (${r.fn}) lacks ${want}`);
    }
  });
});

test('TestDocStatesTheTwoInvariants', () => {
  const doc = normalize(docText());
  for (const want of [
    'authenticated context',
    'configured authoritative lookup',
    'draft 8.5',
    'original source observation',
    'draft 8.3',
  ]) {
    assert.ok(doc.includes(want), `index.ts lacks ${JSON.stringify(want)}`);
  }
});
