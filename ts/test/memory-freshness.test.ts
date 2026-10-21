// Port of go/adapters/memory/freshness_unit_test.go: the freshness rules of
// the installed checks (spec/v1.0/profiles/freshness.md), the guard against
// re-stamping, unavailable sources, pinned revisions and the state members
// they read.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { type CheckInput, type CheckOutcome, Code, codeOf } from '../src/adapter/index.ts';
import { type MemoryAdapter, parseState, State } from '../src/adapters/memory/index.ts';
import { RawJSON } from '../src/core/values.ts';
import {
  alice,
  at,
  baseState,
  check,
  claim,
  ENV,
  enrollment,
  limits,
  type MState,
  newAdapter,
  newSharedAdapter,
} from './support/memory.ts';

const NO_INPUT: CheckInput = {
  principal: { ...alice(), id: '' },
  binding: null,
  intent: { intent_id: '', purpose_id: '', description: '', task_id: '' },
  operation: {
    operation_id: '',
    environment_id: '',
    principal_id: '',
    action: '',
    resources: [],
    method: '',
    target_uri: '',
    body_digest: '',
    headers: {},
  } as never,
  evidenceRefs: [],
};

const runCheck = (a: MemoryAdapter, id: string): Promise<CheckOutcome> =>
  a.checkContext(id, NO_INPUT);

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  return undefined;
}

// A check with freshness limits applies them to the record it consults
// before it reports the native verdict. The rows are the worked evaluations
// of section 3.3 of the freshness profile, with the baseline skew of 5
// seconds; times are seconds relative to now, and null is a time the source
// does not give.
test('TestBoundedCheckEvaluation', async () => {
  const rows: [number | null, number | null, number, number, string, string][] = [
    [-10, 0, 30, 0, 'PASS', 'REQUIREMENT_SATISFIED'],
    [-30, 0, 30, 0, 'PASS', 'REQUIREMENT_SATISFIED'],
    [-31, 0, 30, 0, 'FAIL', 'STALE_EVIDENCE'],
    [-5, -1, 30, 0, 'FAIL', 'STALE_EVIDENCE'],
    [-5, -25, 30, 30, 'PASS', 'REQUIREMENT_SATISFIED'],
    [-5, -31, 30, 30, 'FAIL', 'STALE_EVIDENCE'],
    [5, 0, 30, 0, 'PASS', 'REQUIREMENT_SATISFIED'],
    [6, 0, 30, 0, 'FAIL', 'CLOCK_AHEAD'],
    [0, 6, 30, 0, 'FAIL', 'CLOCK_AHEAD'],
    [6, -31, 30, 30, 'FAIL', 'CLOCK_AHEAD'],
    [null, 0, 30, 0, 'UNKNOWN', 'UNSUPPORTED_REQUIREMENT'],
    [-5, null, 30, 30, 'UNKNOWN', 'UNSUPPORTED_REQUIREMENT'],
    [-31, null, 30, 30, 'FAIL', 'STALE_EVIDENCE'],
    [-5, 0, 0, 0, 'FAIL', 'STALE_EVIDENCE'],
    [0, 0, 0, 0, 'PASS', 'REQUIREMENT_SATISFIED'],
  ];
  for (const [i, [observed, checked, maxAge, statusMaxAge, result, code]] of rows.entries()) {
    const { a } = newAdapter((st) => {
      st.checks = [
        check({
          id: 'bounded-v1',
          result: 'PASS',
          reason_code: 'REQUIREMENT_SATISFIED',
          source_id: 'delegation',
          source_ref: 'd-1',
          observed_at: observed === null ? null : at(observed),
          status_checked_at: checked === null ? null : at(checked),
          freshness: limits(maxAge, statusMaxAge),
        }),
      ];
    });
    const got = await runCheck(a, 'bounded-v1');
    assert.deepEqual([got.result, got.reasonCode], [result, code], `row ${i}`);
    assert.equal(got.sourceId, 'delegation', `row ${i}: the check's source`);
    if (code === 'CLOCK_AHEAD') {
      assert.equal(got.observedAt, null, `row ${i}: a time ahead of the clock is passed on`);
    } else if (observed !== null) {
      assert.equal(got.observedAt, at(observed) * 1000, `row ${i}: the record's own time`);
    }
  }
});

// A record within its limits reports the native verdict, a failure
// included; the limits only ever take a PASS away.
test('TestBoundedCheckKeepsANativeFailure', async () => {
  const { a } = newAdapter((st) => {
    st.checks = [
      check({
        id: 'bounded-v1',
        result: 'FAIL',
        reason_code: 'REVOKED_EVIDENCE',
        source_id: 'delegation',
        observed_at: at(-5),
        status_checked_at: at(-1),
        freshness: limits(30, 30),
      }),
    ];
  });
  const got = await runCheck(a, 'bounded-v1');
  assert.deepEqual([got.result, got.reasonCode], ['FAIL', 'REVOKED_EVIDENCE']);
});

// Without limits a check is not evaluated for age, but a time it cannot pass
// on still defers it, as for a claim (draft A.2).
test('TestUnboundedCheckTimes', async () => {
  const pass = (id: string, observed: number, checked: number) =>
    check({
      id,
      result: 'PASS',
      reason_code: 'REQUIREMENT_SATISFIED',
      source_id: 's',
      observed_at: at(observed),
      status_checked_at: at(checked),
    });
  const { a } = newAdapter((st) => {
    st.checks = [
      pass('old-v1', -86400, -86400),
      pass('status-at-skew-v1', -5, 5),
      pass('status-ahead-v1', -5, 6),
    ];
  });
  assert.equal((await runCheck(a, 'old-v1')).result, 'PASS', 'old record without limits');
  assert.equal(
    (await runCheck(a, 'status-at-skew-v1')).result,
    'PASS',
    'status check at now plus the skew',
  );
  const ahead = await runCheck(a, 'status-ahead-v1');
  assert.deepEqual([ahead.result, ahead.reasonCode], ['UNKNOWN', 'DEPENDENCY_UNAVAILABLE']);
});

// A check pinned to a revision of its source fails with REQUIREMENTS_CHANGED
// when the source reports any other, or none.
test('TestPinnedRevision', async () => {
  const pin = (id: string, pinned: string, revision: string) =>
    check({
      id,
      result: 'PASS',
      reason_code: 'REQUIREMENT_SATISFIED',
      source_id: 'pdp',
      source_ref: `dec-${id}`,
      pinned_revision: pinned,
      revision,
    });
  const { a } = newAdapter((st) => {
    st.checks = [
      pin('same-v1', 'policy-7', 'policy-7'),
      pin('changed-v1', 'policy-7', 'policy-8'),
      pin('case-v1', 'policy-7', 'Policy-7'),
      pin('absent-v1', 'policy-7', ''),
      pin('unpinned-v1', '', 'policy-8'),
    ];
  });
  for (const [id, want] of Object.entries({
    'same-v1': 'REQUIREMENT_SATISFIED',
    'unpinned-v1': 'REQUIREMENT_SATISFIED',
    'changed-v1': 'REQUIREMENTS_CHANGED',
    'case-v1': 'REQUIREMENTS_CHANGED',
    'absent-v1': 'REQUIREMENTS_CHANGED',
  })) {
    const got = await runCheck(a, id);
    const result = want === 'REQUIREMENTS_CHANGED' ? 'FAIL' : 'PASS';
    assert.deepEqual([got.result, got.reasonCode, got.sourceRef], [result, want, `dec-${id}`], id);
  }
});

// The guard against re-stamping starts with the sightings of the state and
// records every record a bounded check consults, keyed by source and
// reference together.
test('TestSightings', async () => {
  const bounded = (id: string, source: string, ref: string, observed: number) =>
    check({
      id,
      result: 'PASS',
      reason_code: 'REQUIREMENT_SATISFIED',
      source_id: source,
      source_ref: ref,
      observed_at: at(observed),
      status_checked_at: at(-1),
      freshness: limits(300, 30),
    });
  const { a } = newAdapter((st) => {
    st.checks = [
      bounded('restamped-v1', 'delegation', 'd-1', -10),
      bounded('same-time-v1', 'delegation', 'd-2', -100),
      bounded('earlier-v1', 'delegation', 'd-3', -200),
      bounded('other-source-v1', 'directory', 'd-1', -10),
      bounded('first-v1', 'delegation', 'd-4', -100),
      bounded('later-v1', 'delegation', 'd-4', -10),
      bounded('unguarded-v1', 'delegation', '', -10),
    ];
    st.sightings = [
      { source_id: 'delegation', source_ref: 'd-1', observed_at: at(-3600) },
      { source_id: 'delegation', source_ref: 'd-2', observed_at: at(-100) },
      { source_id: 'delegation', source_ref: 'd-3', observed_at: at(-150) },
    ];
  });
  for (const [id, code] of [
    ['restamped-v1', 'RESTAMPED'],
    ['same-time-v1', 'REQUIREMENT_SATISFIED'],
    ['earlier-v1', 'REQUIREMENT_SATISFIED'],
    ['other-source-v1', 'REQUIREMENT_SATISFIED'],
    ['first-v1', 'REQUIREMENT_SATISFIED'],
    ['later-v1', 'RESTAMPED'],
    ['unguarded-v1', 'REQUIREMENT_SATISFIED'],
    ['restamped-v1', 'RESTAMPED'],
  ]) {
    const got = await runCheck(a, id as string);
    assert.deepEqual(
      [got.result, got.reasonCode],
      [code === 'RESTAMPED' ? 'FAIL' : 'PASS', code],
      id,
    );
  }
});

// A record of a source that cannot answer is not read: the binding and the
// claim fail with DEPENDENCY_UNAVAILABLE, and the check is UNKNOWN. Other
// sources still answer.
test('TestUnavailableSources', async () => {
  const JKT = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';
  const enr = (workload: string, agent: string, status: string, source: string) =>
    enrollment({
      workload,
      agent_id: `https://identity.example/agents/${agent}`,
      holder_jkt: JKT,
      status,
      observed_at: at(-60),
      status_checked_at: at(-60),
      source_id: source,
    });
  // Workload "up" is shared by two agents, so the adapter supports shared
  // workloads; TestResolveAgentBindingDedicatedWorkload has the default.
  const { a } = newSharedAdapter((st) => {
    st.enrollments = [
      enr('down', 'down', 'ACTIVE', 'registry-down'),
      enr('revoked-down', 'revoked', 'REVOKED', 'registry-down'),
      enr('up', 'up', 'ACTIVE', 'registry'),
      // Another agent of the same workload, held by the source that is down.
      enr('up', 'up-other', 'ACTIVE', 'registry-down'),
    ];
    st.approved_paths = ['/roles', '/dept'];
    st.claims = [
      claim({
        path: '/roles',
        value: new RawJSON('["approver"]'),
        source_id: 'directory-down',
        observed_at: at(-60),
        status_checked_at: at(-30),
      }),
      claim({
        path: '/dept',
        value: new RawJSON('"finance"'),
        source_id: 'directory',
        observed_at: at(-60),
        status_checked_at: at(-30),
      }),
    ];
    st.checks = [
      check({
        id: 'down-v1',
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'checks-down',
        source_ref: 'c-1',
      }),
      check({
        id: 'bounded-down-v1',
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'checks-down',
        observed_at: at(-5),
        status_checked_at: at(-1),
        freshness: limits(300, 30),
      }),
      check({
        id: 'up-v1',
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'checks',
      }),
    ];
    st.unavailable_sources = ['registry-down', 'directory-down', 'checks-down'];
  });
  const ar = { tenantId: 'acme', environmentId: ENV };
  for (const [w, agent] of [
    ['down', 'down'],
    ['revoked-down', 'revoked'],
  ]) {
    const err = await rejection(
      a.resolveAgentBinding(ar, w as string, `https://identity.example/agents/${agent}`),
    );
    assert.equal(codeOf(err), Code.DEPENDENCY_UNAVAILABLE, `binding ${w}`);
  }
  // On a shared workload the agent's own records decide.
  assert.equal(
    (await a.resolveAgentBinding(ar, 'up', 'https://identity.example/agents/up')).status,
    'ACTIVE',
  );
  const other = await rejection(
    a.resolveAgentBinding(ar, 'up', 'https://identity.example/agents/up-other'),
  );
  assert.equal(
    codeOf(other),
    Code.DEPENDENCY_UNAVAILABLE,
    'the other agent, from the source that is down',
  );
  const intent = NO_INPUT.intent;
  const op = NO_INPUT.operation;
  const err = await rejection(
    a.readNativeClaim('/roles', { principal: alice(), intent, operation: op }),
  );
  assert.equal(codeOf(err), Code.DEPENDENCY_UNAVAILABLE, 'claim');
  assert.match((err as Error).message, /directory-down/, 'the claim error names the source');
  assert.equal(
    (await a.readNativeClaim('/dept', { principal: alice(), intent, operation: op })).value,
    'finance',
  );
  for (const id of ['down-v1', 'bounded-down-v1']) {
    const got = await runCheck(a, id);
    assert.deepEqual(
      [got.result, got.reasonCode, got.sourceId],
      ['UNKNOWN', 'DEPENDENCY_UNAVAILABLE', 'checks-down'],
      id,
    );
  }
  assert.equal((await runCheck(a, 'up-v1')).result, 'PASS');
});

// The members the freshness rules read are complete.
test('TestFreshnessStateRules', () => {
  for (const [name, mutate] of Object.entries({
    'freshness without a status limit': (st: MState) => {
      (st.checks[0] as { freshness: unknown }).freshness = {
        max_age_seconds: 30,
        status_max_age_seconds: null,
      };
    },
    'freshness without an age limit': (st: MState) => {
      (st.checks[0] as { freshness: unknown }).freshness = {
        max_age_seconds: null,
        status_max_age_seconds: 30,
      };
    },
    'sighting without a reference': (st: MState) => {
      st.sightings = [{ source_id: 's', source_ref: '', observed_at: at(0) }];
    },
    'sighting without a source': (st: MState) => {
      st.sightings = [{ source_id: '', source_ref: 'r', observed_at: at(0) }];
    },
    'sighting without a time': (st: MState) => {
      st.sightings = [{ source_id: 's', source_ref: 'r', observed_at: null }];
    },
    'empty unavailable source': (st: MState) => {
      st.unavailable_sources = [''];
    },
  })) {
    const st = baseState();
    mutate(st);
    assert.throws(() => State.validate(st as State), Error, `${name}: state accepted`);
  }

  const doc = `{"model": "common/1",
    "gateway": {"tenant_id": "acme", "environment_id": "https://gateway.example/environments/finance",
      "origin": "https://gateway.example"},
    "checks": [{"id": "c", "result": "PASS", "reason_code": "REQUIREMENT_SATISFIED", "source_id": "s",
      "source_ref": "r", "observed_at": 1, "status_checked_at": 2,
      "freshness": {"max_age_seconds": 3, "status_max_age_seconds": 4},
      "pinned_revision": "p", "revision": "q"}],
    "sightings": [{"source_id": "s", "source_ref": "r", "observed_at": 1}],
    "unavailable_sources": ["t"]}`;
  const st = parseState(doc);
  const c = st.checks[0];
  assert.deepEqual(
    [
      c?.status_checked_at,
      c?.freshness,
      c?.pinned_revision,
      c?.revision,
      st.sightings.length,
      st.unavailable_sources[0],
    ],
    [2, { max_age_seconds: 3, status_max_age_seconds: 4 }, 'p', 'q', 1, 't'],
  );
});
