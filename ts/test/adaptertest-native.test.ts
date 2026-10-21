// Port of go/adapter/adaptertest/checks_native_test.go: the
// read_native_claim, check_context and authorize_native checks.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ExpectClaim, ExpectDecision } from '../src/adapter/adaptertest/index.ts';
import {
  AdapterError,
  type CheckInput,
  type ClaimContext,
  type Decision,
  type NativeClaim,
} from '../src/adapter/index.ts';
import { RawJSON } from '../src/core/values.ts';
import {
  acme,
  authzCase,
  authzFake,
  checkCase,
  checkFake,
  claimCase,
  claimFake,
  fake,
  goodOp,
  goodPrincipal,
  HOUR,
  MINUTE,
  NOW,
  type Row,
  runFake,
  runRows,
  SECOND,
  SKEW,
  wantClean,
} from './support/adaptertest.ts';

const raw = (s: string) => new RawJSON(s);
const sec = (ms: number) => String(Math.floor(ms / 1000));

function goodClaim(): NativeClaim {
  return {
    value: ['approver'],
    observedAt: NOW - HOUR,
    statusCheckedAt: NOW - 30 * SECOND,
    sourceId: 'directory-1',
    sourceRef: 'entry-17',
  };
}

const noClaim: ExpectClaim = {
  value: null,
  observed_at: null,
  status_checked_at: null,
  source_id: '',
  source_ref: '',
};
const expectClaim = (m: Partial<ExpectClaim>) => ({ claim: { ...noClaim, ...m } });

test('TestClaimChecks', async (t) => {
  const good = goodClaim();
  const w = (m: Partial<NativeClaim>): NativeClaim => ({ ...good, ...m });
  const full = expectClaim({
    value: raw('["approver"]'),
    observed_at: raw(sec(NOW - HOUR)),
    status_checked_at: raw(sec(NOW - 30 * SECOND)),
    source_id: 'directory-1',
    source_ref: 'entry-17',
  });
  const cyclic: unknown[] = [];
  cyclic.push(cyclic);
  const rows: Row[] = [
    ['claim', claimFake(good), claimCase('claim', full), null],
    [
      'claim but rejects',
      claimFake({}, AdapterError.unsupportedRequirement()),
      claimCase('claim', full),
      ['want a claim'],
    ],
    [
      'value in another order',
      claimFake(w({ value: ['a', 'b'] })),
      claimCase('claim', expectClaim({ value: raw('["b","a"]') })),
      ['claim value is'],
    ],
    [
      'object members in another order',
      claimFake(w({ value: { b: 1, a: 2 } })),
      claimCase('claim', expectClaim({ value: raw('{"b": 1,  "a": 2}') })),
      null,
    ],
    [
      'null value',
      claimFake(w({ value: null })),
      claimCase('claim', expectClaim({ value: raw('null') })),
      null,
    ],
    [
      'value that does not encode',
      claimFake(w({ value: cyclic })),
      claimCase('claim', expectClaim({ value: raw('null') })),
      ['does not encode'],
    ],
    [
      'undefined value',
      claimFake(w({ value: undefined })),
      claimCase('claim', expectClaim({ value: raw('null') })),
      ['does not encode'],
    ],
    [
      'restamped observation',
      claimFake(w({ observedAt: NOW })),
      claimCase('claim', full),
      ['observedAt is', 'not the time of the read'],
    ],
    [
      'restamped status check',
      claimFake(w({ statusCheckedAt: NOW })),
      claimCase('claim', full),
      ['statusCheckedAt is'],
    ],
    [
      'observation supplied where the source gives none',
      claimFake(w({ observedAt: NOW })),
      claimCase('claim', expectClaim({ observed_at: raw('null') })),
      ['want none'],
    ],
    [
      'no time where the source gives one',
      claimFake(w({ observedAt: null })),
      claimCase('claim', full),
      ['observedAt is none'],
    ],
    [
      'no times as the source gives none',
      claimFake(w({ observedAt: null, statusCheckedAt: null })),
      claimCase('claim', expectClaim({ observed_at: raw('null'), status_checked_at: raw('null') })),
      null,
    ],
    [
      'observation in the future',
      claimFake(w({ observedAt: NOW + HOUR })),
      claimCase('claim', expectClaim({})),
      ['observedAt is', 'later than the allowed'],
    ],
    [
      'observation at the skew edge',
      claimFake(w({ observedAt: NOW + SKEW })),
      claimCase('claim', expectClaim({})),
      null,
    ],
    [
      'observation past the skew',
      claimFake(w({ observedAt: NOW + SKEW + SECOND })),
      claimCase('claim', expectClaim({})),
      ['later than the allowed'],
    ],
    // Draft A.2: no status-check time may be later than now plus the skew.
    [
      'status check past the skew',
      claimFake(w({ statusCheckedAt: NOW + SKEW + SECOND })),
      claimCase('claim', expectClaim({})),
      ['statusCheckedAt is', 'later than the allowed'],
    ],
    [
      'status check at the skew edge',
      claimFake(w({ statusCheckedAt: NOW + SKEW })),
      claimCase('claim', expectClaim({})),
      null,
    ],
    [
      'status check at now',
      claimFake(w({ statusCheckedAt: NOW })),
      claimCase('claim', expectClaim({})),
      null,
    ],
    [
      'no source',
      claimFake(w({ sourceId: '' })),
      claimCase('claim', expectClaim({})),
      ['names no source'],
    ],
    [
      'wrong source',
      claimFake(good),
      claimCase('claim', expectClaim({ source_id: 'other' })),
      ['source id is'],
    ],
    [
      'wrong source ref',
      claimFake(good),
      claimCase('claim', expectClaim({ source_ref: 'other' })),
      ['source ref is'],
    ],

    [
      'error',
      claimFake({}, new Error('x', { cause: AdapterError.unsupportedRequirement() })),
      claimCase('error', { reason_code: 'UNSUPPORTED_REQUIREMENT' }),
      null,
    ],
    ['error expected, claim returned', claimFake(good), claimCase('error'), ['want an error']],
  ];
  await runRows(t, rows);

  // The claim context of draft 17.1 is the principal, the declared intent and
  // the actual operation of the case, passed as they are.
  await t.test('the context reaches the adapter', async () => {
    let got: [string, ClaimContext] | undefined;
    const f = fake({
      claim: async (path, c) => {
        got = [path, c];
        return good;
      },
    });
    const c = claimCase('claim');
    const op = goodOp();
    c.call.intent = { intent_id: 'i-1', purpose_id: 'p-1', description: '', task_id: 'task-7' };
    c.call.operation = op as never;
    wantClean(await runFake(f, c));
    assert.ok(got !== undefined);
    assert.equal(got[0], '/attributes/environment/roles');
    assert.equal(got[1].principal.id, goodPrincipal().id);
    assert.deepEqual(got[1].principal.realm, acme);
    assert.equal(got[1].principal.workload, 'w-1');
    assert.deepEqual(got[1].intent, {
      intent_id: 'i-1',
      purpose_id: 'p-1',
      description: '',
      task_id: 'task-7',
    });
    assert.deepEqual(got[1].operation, op);
  });

  await t.test('a case without intent or operation passes neither', async () => {
    let got: ClaimContext | undefined;
    const f = fake({
      claim: async (_, c) => {
        got = c;
        return good;
      },
    });
    wantClean(await runFake(f, claimCase('claim')));
    assert.equal(got?.principal.id, goodPrincipal().id);
    assert.deepEqual(got?.intent, { intent_id: '', purpose_id: '', description: '', task_id: '' });
    assert.equal(got?.operation.operation_id, '');
    assert.deepEqual(got?.operation.resources, []);
    assert.equal(got?.operation.principal_id, '');
  });
});

test('TestCheckChecks', async (t) => {
  const unknown = { result: 'UNKNOWN', reasonCode: 'UNSUPPORTED_REQUIREMENT' } as const;
  const pass = {
    result: 'PASS',
    reasonCode: 'REQUIREMENT_SATISFIED',
    sourceId: 'approvals',
    observedAt: NOW - MINUTE,
  } as const;
  const rows: Row[] = [
    [
      'unknown',
      checkFake(unknown),
      checkCase('x', 'UNKNOWN', { reason_code: 'UNSUPPORTED_REQUIREMENT' }),
      null,
    ],
    ['unknown but pass', checkFake(pass), checkCase('x', 'UNKNOWN'), ['never PASS']],
    [
      'pass',
      checkFake(pass),
      checkCase('x', 'PASS', { reason_code: 'REQUIREMENT_SATISFIED' }),
      null,
    ],
    [
      'pass expected, unknown returned',
      checkFake(unknown),
      checkCase('x', 'PASS'),
      ['returned UNKNOWN'],
    ],
    [
      'fail',
      checkFake({ result: 'FAIL', reasonCode: 'APPROVAL_REJECTED' }),
      checkCase('x', 'FAIL', { reason_code: 'APPROVAL_REJECTED' }),
      null,
    ],
    [
      'wrong reason',
      checkFake(unknown),
      checkCase('x', 'UNKNOWN', { reason_code: 'DEPENDENCY_UNAVAILABLE' }),
      ['reason code is'],
    ],
    ['no reason', checkFake({ result: 'UNKNOWN' }), checkCase('x', 'UNKNOWN'), ['no reason code']],
    [
      'undefined verdict',
      checkFake({ result: 'OK' as never, reasonCode: 'X' }),
      checkCase('x', 'UNKNOWN'),
      ['not PASS, FAIL or UNKNOWN'],
    ],
    [
      'observation in the future',
      checkFake({ result: 'PASS', reasonCode: 'X', observedAt: NOW + HOUR }),
      checkCase('x', 'PASS'),
      ['check observedAt'],
    ],
    // A check reports what it could not perform as UNKNOWN; it never rejects.
    [
      'rejects',
      fake({
        check: async () => {
          throw AdapterError.dependencyUnavailable();
        },
      }),
      checkCase('x', 'UNKNOWN'),
      ['checkContext rejected', 'it does not reject'],
    ],
  ];
  await runRows(t, rows);

  await t.test('arguments reach the adapter', async () => {
    let got: [string, CheckInput] | undefined;
    const f = fake({
      check: async (id, input) => {
        got = [id, input];
        return unknown;
      },
    });
    const c = checkCase('', 'UNKNOWN');
    c.call.intent = { intent_id: 'i-1', purpose_id: '', description: '', task_id: '' };
    c.call.evidence_refs = ['ref-1'];
    (c.call.principal as { attributes: unknown }).attributes = { device_id: 'dev-1' };
    c.call.binding = {
      agent_id: 'https://agents.example/a',
      operator_id: 'https://ops.example/o',
      holder_jkt: 'thumb-1',
      status: '',
    };
    wantClean(await runFake(f, c));
    assert.ok(got !== undefined);
    const [id, input] = got;
    assert.equal(id, '');
    assert.equal(input.intent.intent_id, 'i-1');
    assert.deepEqual(input.evidenceRefs, ['ref-1']);
    assert.equal(input.principal.id, goodPrincipal().id);
    assert.deepEqual(input.principal.realm, acme);
    assert.equal(input.principal.workload, 'w-1');
    assert.equal(
      input.principal.attributes.device_id,
      'dev-1',
      'the principal with its attributes',
    );
    assert.equal(input.operation.operation_id, 'op-1');
    assert.deepEqual(
      input.binding,
      {
        agentId: 'https://agents.example/a',
        operatorId: 'https://ops.example/o',
        holderJKT: 'thumb-1',
        status: 'ACTIVE',
        observedAt: null,
        statusCheckedAt: null,
        sourceId: '',
        sourceRef: '',
        enrolledElsewhere: false,
      },
      'a binding without status is ACTIVE',
    );
  });

  await t.test('a stated status reaches the adapter', async () => {
    let got: CheckInput | undefined;
    const f = fake({
      check: async (_, input) => {
        got = input;
        return unknown;
      },
    });
    const c = checkCase('x', 'UNKNOWN');
    c.call.binding = {
      agent_id: 'https://agents.example/a',
      operator_id: '',
      holder_jkt: '',
      status: 'REVOKED',
    };
    wantClean(await runFake(f, c));
    assert.equal(got?.binding?.status, 'REVOKED');
  });

  await t.test('a case without a binding passes none', async () => {
    let got: CheckInput | undefined;
    const f = fake({
      check: async (_, input) => {
        got = input;
        return unknown;
      },
    });
    wantClean(await runFake(f, checkCase('x', 'UNKNOWN')));
    assert.equal(got?.binding, null, 'the caller established no agent');
  });
});

const noDecision: ExpectDecision = {
  obligations: null,
  source_id: '',
  source_ref: null,
  decided_at: null,
  policy_revision: '',
};
const pinned = (m: Partial<ExpectDecision>) => ({ decision: { ...noDecision, ...m } });

test('TestAuthorizeChecks', async (t) => {
  // A decision with effect e that names its source, as every decision must.
  const decision = (effect: string, m: Partial<Decision> = {}): Decision =>
    ({ effect, sourceId: 'policy-1', ...m }) as Decision;
  const deny = decision('DENY', { reason: 'policy 7' });
  const allow = decision('ALLOW');
  const unknown = decision('UNKNOWN');
  const audit = { id: 'audit', attributes: { level: 'high' } };
  const wantAudit = [{ id: 'audit', attributes: { level: 'high' } }];
  const withObligations = (
    effect: string,
    ...o: { id: string; attributes: Record<string, unknown> }[]
  ) => decision(effect, { obligations: o });
  const rows: Row[] = [
    ['deny', authzFake(deny), authzCase('DENY'), null],
    ['deny rewritten to allow', authzFake(allow), authzCase('DENY'), ['cannot rewrite a denial']],
    [
      'deny rewritten to unknown',
      authzFake(unknown),
      authzCase('DENY'),
      ['decision effect is UNKNOWN'],
    ],
    [
      'deny but rejects',
      authzFake({}, AdapterError.dependencyUnavailable()),
      authzCase('DENY'),
      ['want effect DENY'],
    ],
    ['allow', authzFake(allow), authzCase('ALLOW'), null],
    ['unknown', authzFake(unknown), authzCase('UNKNOWN'), null],
    [
      'obligations kept',
      authzFake(withObligations('DENY', audit)),
      authzCase('DENY', pinned({ obligations: wantAudit })),
      null,
    ],
    [
      'obligations dropped',
      authzFake(deny),
      authzCase('DENY', pinned({ obligations: wantAudit })),
      ['obligations are'],
    ],
    [
      'obligation attributes changed',
      authzFake(withObligations('DENY', { id: 'audit', attributes: { level: 'low' } })),
      authzCase('DENY', pinned({ obligations: wantAudit })),
      ['obligations are'],
    ],
    [
      'obligation added',
      authzFake(withObligations('DENY', audit)),
      authzCase('DENY', pinned({ obligations: [] })),
      ['obligations are'],
    ],
    [
      'no and empty attributes are the same',
      authzFake(withObligations('DENY', { id: 'x', attributes: {} })),
      authzCase('DENY', pinned({ obligations: [{ id: 'x', attributes: null }] })),
      null,
    ],
    [
      'undefined effect',
      authzFake(decision('PERMIT')),
      authzCase('not_allowed'),
      ['not ALLOW, DENY or UNKNOWN'],
    ],

    ['not allowed by a denial', authzFake(deny), authzCase('not_allowed'), null],
    ['not allowed by an unknown', authzFake(unknown), authzCase('not_allowed'), null],
    ['not allowed by an error', authzFake({}, new Error('x')), authzCase('not_allowed'), null],
    ['not allowed but allowed', authzFake(allow), authzCase('not_allowed'), ['anything but ALLOW']],

    [
      'error',
      authzFake({}, AdapterError.dependencyUnavailable()),
      authzCase('error', { reason_code: 'DEPENDENCY_UNAVAILABLE' }),
      null,
    ],
    ['error expected, decision returned', authzFake(deny), authzCase('error'), ['want an error']],
  ];
  await runRows(t, rows);
});

// Every decision names the policy source that decided and a decision time
// that is not in the future beyond the skew, whatever the outcome the case
// expects; a case may pin the source, the record, the time and the policy
// revision the native source gave.
test('TestDecisionProvenance', async (t) => {
  const decidedAt = NOW - 2 * SECOND;
  const full: Decision = {
    effect: 'ALLOW',
    obligations: [],
    reason: '',
    sourceId: 'pdp-1',
    sourceRef: 'decision-8f0d',
    decidedAt,
    policyRevision: 'policy-2026-10-01',
  };
  const w = (m: Partial<Decision>): Decision => ({ ...full, ...m });
  const all = pinned({
    source_id: 'pdp-1',
    source_ref: raw('"decision-8f0d"'),
    decided_at: raw(sec(decidedAt)),
    policy_revision: 'policy-2026-10-01',
  });
  const rows: Row[] = [
    ['provenance as the source gave it', authzFake(full), authzCase('ALLOW', all), null],
    ['only a source', authzFake({ effect: 'DENY', sourceId: 'pdp-1' }), authzCase('DENY'), null],

    ['no source', authzFake(w({ sourceId: '' })), authzCase('ALLOW'), ['decision names no source']],
    [
      'no source on a denial',
      authzFake({ effect: 'DENY' }),
      authzCase('DENY'),
      ['decision names no source'],
    ],
    [
      'no source where only not allowed is required',
      authzFake({ effect: 'DENY' }),
      authzCase('not_allowed'),
      ['decision names no source'],
    ],
    [
      'no source on an unknown',
      authzFake({ effect: 'UNKNOWN' }),
      authzCase('UNKNOWN'),
      ['decision names no source'],
    ],
    [
      'an error carries no decision',
      authzFake({}, AdapterError.dependencyUnavailable()),
      authzCase('not_allowed'),
      null,
    ],

    [
      'decided in the future',
      authzFake(w({ decidedAt: NOW + HOUR })),
      authzCase('ALLOW'),
      ['decidedAt is', 'later than the allowed'],
    ],
    [
      'decided in the future, not allowed',
      authzFake({ effect: 'DENY', sourceId: 'pdp-1', decidedAt: NOW + HOUR }),
      authzCase('not_allowed'),
      ['decidedAt is', 'later than the allowed'],
    ],
    ['decided at the skew edge', authzFake(w({ decidedAt: NOW + SKEW })), authzCase('ALLOW'), null],
    [
      'decided past the skew',
      authzFake(w({ decidedAt: NOW + SKEW + SECOND })),
      authzCase('ALLOW'),
      ['later than the allowed'],
    ],
    ['no decision time', authzFake(w({ decidedAt: null })), authzCase('ALLOW'), null],

    [
      'another source',
      authzFake(w({ sourceId: 'pdp-2' })),
      authzCase('ALLOW', all),
      ['decision source id is "pdp-2", want "pdp-1"'],
    ],
    [
      'record dropped',
      authzFake(w({ sourceRef: '' })),
      authzCase('ALLOW', all),
      ['decision source ref is "", want "decision-8f0d"'],
    ],
    [
      'revision rewritten',
      authzFake(w({ policyRevision: 'policy-2026-09-01' })),
      authzCase('ALLOW', all),
      ['policy revision is "policy-2026-09-01", want "policy-2026-10-01"'],
    ],
    [
      'revision dropped',
      authzFake(w({ policyRevision: '' })),
      authzCase('ALLOW', all),
      ['policy revision is'],
    ],
    [
      'decision restamped',
      authzFake(w({ decidedAt: NOW })),
      authzCase('ALLOW', all),
      ['decidedAt is', 'not the time of the read'],
    ],
    [
      'decision time dropped',
      authzFake(w({ decidedAt: null })),
      authzCase('ALLOW', all),
      ['decidedAt is none'],
    ],
    [
      'decision time supplied where the source gives none',
      authzFake(full),
      authzCase('ALLOW', pinned({ decided_at: raw('null') })),
      ['want none'],
    ],
    [
      'record supplied where the source keeps none',
      authzFake(full),
      authzCase('ALLOW', pinned({ source_ref: raw('null') })),
      ['decision source ref is "decision-8f0d", want none'],
    ],
    [
      'no record where the source keeps none',
      authzFake(w({ sourceRef: '' })),
      authzCase('ALLOW', pinned({ source_ref: raw(' null ') })),
      null,
    ],
    [
      'an empty record is not checked',
      authzFake(full),
      authzCase('ALLOW', pinned({ source_ref: raw('""') })),
      null,
    ],
    [
      'a record that is not a string',
      authzFake(full),
      authzCase('ALLOW', pinned({ source_ref: raw('7') })),
      ['source_ref: expected value 7 is not a string or null'],
    ],
    [
      'provenance is checked with the effect',
      authzFake(w({ sourceId: 'pdp-2' })),
      authzCase('ALLOW', pinned({ source_id: 'pdp-1', obligations: [] })),
      ['decision source id is'],
    ],
  ];
  await runRows(t, rows);
});
