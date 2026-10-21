// Port of the claim, check and policy tests of
// go/adapters/memory/memory_unit_test.go: readNativeClaim with its times and
// scope, checkContext with its exact ids and scope, authorizeNative with its
// precedence and provenance.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type CheckInput,
  type ClaimContext,
  Code,
  codeOf,
  Decision,
  type Principal,
} from '../src/adapter/index.ts';
import {
  CODE_APPROVAL_SCOPE_MISMATCH,
  type MemoryAdapter,
  POLICY_SOURCE_ID,
} from '../src/adapters/memory/index.ts';
import type { Intent, OperationContext } from '../src/core/types.ts';
import { RawJSON } from '../src/core/values.ts';
import { alice, check, claim, ENV, newAdapter, rule, SEC } from './support/memory.ts';

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  return undefined;
}

const intent = (task_id = ''): Intent => ({
  intent_id: '',
  purpose_id: '',
  description: '',
  task_id,
});
const operation = (m: Partial<OperationContext> = {}): OperationContext =>
  ({
    operation_id: '',
    environment_id: '',
    principal_id: '',
    action: '',
    resources: [],
    method: '',
    target_uri: '',
    body_digest: '',
    headers: {},
    ...m,
  }) as OperationContext;
const ctx = (principal: Principal, m: Partial<ClaimContext> = {}): ClaimContext => ({
  principal,
  intent: intent(),
  operation: operation(),
  ...m,
});
const raw = (s: string) => new RawJSON(s);

test('TestReadNativeClaim', async () => {
  const past = SEC - 120;
  const future = SEC + 3600;
  const { a } = newAdapter((st) => {
    st.approved_paths = [
      '/roles',
      '/null',
      '/future',
      '/checked',
      '/edge',
      '/checked-edge',
      '/checked-past',
      '/number',
    ];
    const rec = (path: string, value: string, o: number | null, c: number | null) =>
      claim({
        path,
        value: raw(value),
        observed_at: o,
        status_checked_at: c,
        source_id: 'dir',
        source_ref: `r-${path}`,
      });
    st.claims = [
      rec('/roles', '["approver","viewer"]', past, past),
      rec('/null', 'null', null, null),
      rec('/future', '["x"]', future, null),
      rec('/checked', '["x"]', past, future),
      rec('/edge', '["x"]', SEC + 5, null),
      rec('/checked-edge', '["x"]', past, SEC + 5),
      rec('/checked-past', '["x"]', past, SEC + 6),
      rec('/number', '12345678901234567890', null, null),
    ];
  });
  const read = (path: string, p: Principal = alice()) => a.readNativeClaim(path, ctx(p));

  const c = await read('/roles');
  assert.deepEqual(c, {
    value: ['approver', 'viewer'],
    observedAt: past * 1000,
    statusCheckedAt: past * 1000,
    sourceId: 'dir',
    sourceRef: 'r-/roles',
  });
  const n = await read('/null');
  assert.deepEqual(
    [n.value, n.observedAt, n.statusCheckedAt],
    [null, null, null],
    'a null value and no times',
  );
  assert.equal((await read('/edge')).observedAt, (SEC + 5) * 1000, 'observation at now+skew');
  // Draft A.2: no status-check time may be later than now plus the skew.
  assert.equal(
    (await read('/checked-edge')).statusCheckedAt,
    (SEC + 5) * 1000,
    'status check at now+skew',
  );
  for (const path of ['/future', '/checked', '/checked-past']) {
    assert.equal(codeOf(await rejection(read(path))), Code.DEPENDENCY_UNAVAILABLE, path);
  }
  assert.equal(codeOf(await rejection(read('/not-approved'))), Code.UNSUPPORTED_REQUIREMENT);
  assert.equal(codeOf(await rejection(read(''))), Code.UNSUPPORTED_REQUIREMENT, 'empty path');
  for (const [name, p] of Object.entries({
    'another principal': { ...alice(), id: 'https://idp.example/bob' },
    'another tenant': { ...alice(), realm: { tenantId: 'globex', environmentId: ENV } },
    'another env': { ...alice(), realm: { tenantId: 'acme', environmentId: 'other' } },
  })) {
    const err = await rejection(read('/roles', p));
    assert.ok(err !== undefined, `${name}: read a value`);
    assert.equal(codeOf(err), '', `${name}: a missing value is not ${codeOf(err)}`);
  }
});

test('TestReadNativeClaimFollowsTheClock', async () => {
  const { a, clock } = newAdapter((st) => {
    (st.claims[0] as { observed_at: number }).observed_at = SEC + 600;
  });
  assert.ok(
    (await rejection(a.readNativeClaim('/roles', ctx(alice())))) !== undefined,
    'a claim observed ten minutes ahead was passed on',
  );
  clock.advance(10 * 60 * 1000);
  const c = await a.readNativeClaim('/roles', ctx(alice()));
  assert.equal(c.observedAt, (SEC + 600) * 1000, 'after the clock passed the observation');
});

// A record that names a resource is read only for an operation that lists
// the resource, and a record that names a task only for an intent that
// carries the task (draft 17.1: "approved native path and context").
test('TestReadNativeClaimScope', async (t) => {
  const doc1 = 'https://docs.example/d/1';
  const doc2 = 'https://docs.example/d/2';
  const { a } = newAdapter((st) => {
    st.approved_paths = ['/roles', '/classification', '/grant', '/both'];
    const rec = (path: string, value: string, resource: string, task: string) =>
      claim({ path, value: raw(value), source_id: 'src', resource, task_id: task });
    st.claims = [
      rec('/roles', '["approver"]', '', ''),
      rec('/classification', '"restricted"', doc1, ''),
      rec('/classification', '"internal"', doc2, ''),
      rec('/grant', '"grant-a"', '', 'task-a'),
      rec('/grant', '"grant-b"', '', 'task-b'),
      rec('/both', '"doc1-task-a"', doc1, 'task-a'),
    ];
  });
  const ops = (...resources: string[]) => operation({ principal_id: alice().id, resources });
  const none = operation();
  const tests: [string, string, Intent, OperationContext, unknown][] = [
    ['unscoped, no context', '/roles', intent(), none, ['approver']],
    ['unscoped, any context', '/roles', intent('task-a'), ops(doc1), ['approver']],
    ['the first resource', '/classification', intent(), ops(doc1), 'restricted'],
    ['the second resource', '/classification', intent(), ops(doc2), 'internal'],
    [
      'a resource among several',
      '/classification',
      intent(),
      ops('https://docs.example/d/9', doc2),
      'internal',
    ],
    [
      'a resource the operation does not list',
      '/classification',
      intent(),
      ops('https://docs.example/d/9'),
      undefined,
    ],
    ['a resource fact with no operation', '/classification', intent(), none, undefined],
    [
      'a resource fact is not read from the intent',
      '/classification',
      intent(doc1),
      none,
      undefined,
    ],
    ['the first task', '/grant', intent('task-a'), none, 'grant-a'],
    ['the second task', '/grant', intent('task-b'), ops(doc1), 'grant-b'],
    ['another task', '/grant', intent('task-c'), none, undefined],
    ['a task fact with no intent', '/grant', intent(), none, undefined],
    ['a task fact is not read from the resources', '/grant', intent(), ops('task-a'), undefined],
    ['a task is matched exactly', '/grant', intent('TASK-A'), none, undefined],
    ['both scopes', '/both', intent('task-a'), ops(doc1), 'doc1-task-a'],
    ['both scopes, task missing', '/both', intent(), ops(doc1), undefined],
    ['both scopes, resource missing', '/both', intent('task-a'), none, undefined],
  ];
  for (const [name, path, i, op, want] of tests) {
    await t.test(name, async () => {
      const p = a.readNativeClaim(path, { principal: alice(), intent: i, operation: op });
      if (want === undefined) {
        const err = await rejection(p);
        assert.ok(err !== undefined, 'read a value, want none');
        assert.equal(codeOf(err), '', `a value out of scope is missing, not ${codeOf(err)}`);
        return;
      }
      assert.deepEqual((await p).value, want);
    });
  }
  await t.test('the realm still applies', async () => {
    const other = { ...alice(), realm: { tenantId: 'globex', environmentId: ENV } };
    const err = await rejection(
      a.readNativeClaim('/classification', {
        principal: other,
        intent: intent(),
        operation: ops(doc1),
      }),
    );
    assert.ok(err !== undefined, 'read a value for a same-spelled principal of another realm');
  });
});

const NO_INPUT: CheckInput = {
  principal: { ...alice(), id: '' },
  binding: null,
  intent: intent(),
  operation: operation(),
  evidenceRefs: [],
};
const runCheck = (
  a: MemoryAdapter,
  id: string,
  input: CheckInput = NO_INPUT,
  signal?: AbortSignal,
) => a.checkContext(id, input, signal);

test('TestCheckContext', async () => {
  const { a } = newAdapter((st) => {
    st.checks.push(
      check({
        id: 'failing-v1',
        result: 'FAIL',
        reason_code: 'APPROVAL_REJECTED',
        source_id: 'approvals',
        source_ref: 'a-1',
      }),
      check({
        id: 'pending-v1',
        result: 'UNKNOWN',
        reason_code: 'APPROVAL_PENDING',
        source_id: 'approvals',
      }),
      check({
        id: 'future-v1',
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
        observed_at: SEC + 3600,
      }),
    );
  });
  for (const [id, want] of Object.entries({
    'approval-v1': 'PASS',
    'failing-v1': 'FAIL',
    'pending-v1': 'UNKNOWN',
    '': 'UNKNOWN',
    approval: 'UNKNOWN',
    'approval-v10': 'UNKNOWN',
    'APPROVAL-V1': 'UNKNOWN',
    ' approval-v1': 'UNKNOWN',
    'approval-v1 ': 'UNKNOWN',
  })) {
    const got = await runCheck(a, id);
    assert.equal(got.result, want, JSON.stringify(id));
    assert.notEqual(got.reasonCode, '', `${JSON.stringify(id)} with a reason`);
  }
  const none = await runCheck(a, 'nothing');
  assert.deepEqual([none.reasonCode, none.sourceId], ['UNSUPPORTED_REQUIREMENT', ''], 'unknown id');
  const failing = await runCheck(a, 'failing-v1');
  assert.deepEqual([failing.reasonCode, failing.sourceRef], ['APPROVAL_REJECTED', 'a-1']);
  const future = await runCheck(a, 'future-v1');
  assert.deepEqual(
    [future.result, future.reasonCode],
    ['UNKNOWN', 'DEPENDENCY_UNAVAILABLE'],
    'a check observed in the future must not pass',
  );
  assert.equal(
    (await runCheck(a, 'approval-v1', NO_INPUT, AbortSignal.abort())).result,
    'UNKNOWN',
    'aborted call',
  );
});

// A check whose record names a principal or an agent applies only in a call
// from that principal and that agent's binding; an installed check no record
// applies to is FAIL with APPROVAL_SCOPE_MISMATCH, never PASS (draft 17.1,
// 17.3.1).
test('TestCheckContextScope', async (t) => {
  const ALICE = 'https://idp.example/alice';
  const BOB = 'https://idp.example/bob';
  const agentA = 'https://agents.example/a';
  const agentB = 'https://agents.example/b';
  const { a } = newAdapter((st) => {
    st.checks.push(
      check({
        id: 'scoped-v1',
        principal: ALICE,
        agent_id: agentA,
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
        source_ref: 'appr-1',
      }),
      check({
        id: 'principal-only-v1',
        principal: ALICE,
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
      }),
      check({
        id: 'agent-only-v1',
        agent_id: agentA,
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
      }),
      check({
        id: 'two-v1',
        principal: BOB,
        result: 'FAIL',
        reason_code: 'APPROVAL_REJECTED',
        source_id: 'approvals',
      }),
      check({
        id: 'two-v1',
        principal: ALICE,
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
      }),
    );
  });
  const input = (principal: string, agent: string): CheckInput => ({
    ...NO_INPUT,
    principal: { ...alice(), id: principal },
    binding:
      agent === ''
        ? null
        : {
            agentId: agent,
            operatorId: '',
            holderJKT: '',
            status: 'ACTIVE',
            observedAt: null,
            statusCheckedAt: null,
            sourceId: '',
            sourceRef: '',
            enrolledElsewhere: false,
          },
  });
  const MISMATCH = CODE_APPROVAL_SCOPE_MISMATCH;
  for (const [name, id, inp, want, code] of [
    ['both match', 'scoped-v1', input(ALICE, agentA), 'PASS', 'REQUIREMENT_SATISFIED'],
    ['other agent', 'scoped-v1', input(ALICE, agentB), 'FAIL', MISMATCH],
    ['other principal', 'scoped-v1', input(BOB, agentA), 'FAIL', MISMATCH],
    ['no binding', 'scoped-v1', input(ALICE, ''), 'FAIL', MISMATCH],
    ['no input at all', 'scoped-v1', NO_INPUT, 'FAIL', MISMATCH],
    [
      'principal only, match',
      'principal-only-v1',
      input(ALICE, ''),
      'PASS',
      'REQUIREMENT_SATISFIED',
    ],
    ['principal only, other', 'principal-only-v1', input(BOB, agentA), 'FAIL', MISMATCH],
    ['agent only, match', 'agent-only-v1', input('', agentA), 'PASS', 'REQUIREMENT_SATISFIED'],
    ['agent only, none', 'agent-only-v1', input(ALICE, ''), 'FAIL', MISMATCH],
    [
      'the record that applies is used',
      'two-v1',
      input(ALICE, ''),
      'PASS',
      'REQUIREMENT_SATISFIED',
    ],
    [
      'the other record that applies is used',
      'two-v1',
      input(BOB, ''),
      'FAIL',
      'APPROVAL_REJECTED',
    ],
    [
      'no record applies to a third principal',
      'two-v1',
      input('https://idp.example/carol', ''),
      'FAIL',
      MISMATCH,
    ],
    [
      'not installed stays unknown',
      'absent-v1',
      input(ALICE, agentA),
      'UNKNOWN',
      'UNSUPPORTED_REQUIREMENT',
    ],
  ] as const) {
    await t.test(name, async () => {
      const got = await runCheck(a, id, inp);
      assert.deepEqual([got.result, got.reasonCode], [want, code]);
    });
  }
  await t.test('a mismatch names no record of the approval', async () => {
    assert.equal((await runCheck(a, 'scoped-v1', input(ALICE, agentB))).sourceRef, '');
  });
});

test('TestAuthorizeNative', async () => {
  const RES = 'https://invoices.example/invoices/1';
  const r = (
    principal: string,
    action: string,
    resource: string,
    effect: string,
    reason: string,
    obligations: { id: string; attributes: Record<string, unknown> | null }[] = [],
  ) => rule({ principal, action, resource, effect, reason, obligations });
  const { a } = newAdapter((st) => {
    st.policy = [
      r('https://idp.example/alice', 'invoice.read', RES, 'ALLOW', 'r1', [
        { id: 'mask', attributes: { f: 'iban' } },
      ]),
      r('https://idp.example/alice', 'invoice.read', '', 'ALLOW', 'r2'),
      r('https://idp.example/alice', 'invoice.write', '', 'ALLOW', 'w1'),
      r('https://idp.example/alice', 'invoice.write', RES, 'DENY', 'w2'),
      r('https://idp.example/alice', 'invoice.pay', '', 'UNKNOWN', 'p1'),
      r('https://idp.example/alice', 'invoice.pay', '', 'ALLOW', 'p2'),
      r('https://idp.example/bob', 'invoice.read', '', 'DENY', 'b1'),
    ];
  });
  const op = (action: string, ...resources: string[]) => operation({ action, resources });
  const decide = (p: Principal, o: OperationContext) => a.authorizeNative(p, o);

  const d = await decide(alice(), op('invoice.read', RES));
  assert.deepEqual(
    [d.effect, d.reason, d.obligations],
    ['ALLOW', 'r1', [{ id: 'mask', attributes: { f: 'iban' } }]],
    'read of the named resource',
  );
  assert.deepEqual(
    [(await decide(alice(), op('invoice.read', 'https://invoices.example/invoices/2'))).reason],
    ['r2'],
  );
  const w = await decide(alice(), op('invoice.write', RES));
  assert.deepEqual([w.effect, w.reason], ['DENY', 'w2'], 'a deny wins over an allow');
  assert.equal(
    (await decide(alice(), op('invoice.write', 'https://invoices.example/invoices/2'))).effect,
    'ALLOW',
    'the deny names another resource',
  );
  const pay = await decide(alice(), op('invoice.pay'));
  assert.deepEqual([pay.effect, pay.reason], ['UNKNOWN', 'p1'], 'an unknown wins over an allow');
  for (const [name, p, o] of [
    ['no rule for the action', alice(), op('invoice.delete', RES)],
    ['another principal', { ...alice(), id: 'https://idp.example/carol' }, op('invoice.read', RES)],
    [
      'another realm',
      { ...alice(), realm: { tenantId: 'globex', environmentId: ENV } },
      op('invoice.read', RES),
    ],
    ['a denied principal', { ...alice(), id: 'https://idp.example/bob' }, op('invoice.read', RES)],
    ['the empty principal', { ...alice(), id: '' }, op('invoice.read', RES)],
    ['an operation with no data', alice(), operation()],
  ] as const) {
    assert.ok(!Decision.permits(await decide(p, o)), name);
  }
});

// A decision carries the source, the record, the time and the policy
// revision of the rule that decided, as the rule gives them, and names a
// source even when the rule names none or no rule applies. A decision time
// later than now plus the skew is not passed on.
test('TestAuthorizeNativeProvenance', async () => {
  const decided = SEC - 2;
  const future = SEC + 3600;
  const edge = SEC + 5;
  const ALICE = 'https://idp.example/alice';
  const { a, clock } = newAdapter((st) => {
    st.policy = [
      rule({
        principal: ALICE,
        action: 'invoice.read',
        effect: 'ALLOW',
        source_id: 'pdp-1',
        source_ref: 'decision-8f0d',
        decided_at: decided,
        policy_revision: 'policy-2026-10-01',
      }),
      rule({ principal: ALICE, action: 'invoice.list', effect: 'DENY' }),
      rule({
        principal: ALICE,
        action: 'invoice.pay',
        effect: 'ALLOW',
        source_id: 'pdp-1',
        decided_at: future,
      }),
      rule({
        principal: ALICE,
        action: 'invoice.void',
        effect: 'DENY',
        source_id: 'pdp-1',
        decided_at: future,
      }),
      rule({
        principal: ALICE,
        action: 'invoice.edge',
        effect: 'ALLOW',
        source_id: 'pdp-1',
        decided_at: edge,
      }),
    ];
  });
  const decide = (action: string) => a.authorizeNative(alice(), operation({ action }));

  const d = await decide('invoice.read');
  assert.deepEqual(
    [d.effect, d.sourceId, d.sourceRef, d.decidedAt, d.policyRevision],
    ['ALLOW', 'pdp-1', 'decision-8f0d', decided * 1000, 'policy-2026-10-01'],
    "the rule's provenance unchanged",
  );
  const list = await decide('invoice.list');
  assert.deepEqual(
    [list.effect, list.sourceId, list.sourceRef, list.decidedAt, list.policyRevision],
    ['DENY', POLICY_SOURCE_ID, '', null, ''],
    "a rule without provenance: the adapter's policy source and nothing else",
  );
  const del = await decide('invoice.delete');
  assert.deepEqual(
    [del.effect, del.sourceId, del.decidedAt],
    ['DENY', POLICY_SOURCE_ID, null],
    'no rule applies',
  );
  assert.notEqual(POLICY_SOURCE_ID, '');
  for (const action of ['invoice.pay', 'invoice.void']) {
    assert.equal(
      codeOf(await rejection(decide(action))),
      Code.DEPENDENCY_UNAVAILABLE,
      `${action} decided an hour ahead`,
    );
  }
  assert.equal(
    (await decide('invoice.edge')).decidedAt,
    edge * 1000,
    'decided at now plus the skew',
  );
  clock.advance(60 * 60 * 1000);
  const pay = await decide('invoice.pay');
  assert.ok(Decision.permits(pay), 'after the clock passed the decision time');
  assert.equal(pay.decidedAt, future * 1000);
});
