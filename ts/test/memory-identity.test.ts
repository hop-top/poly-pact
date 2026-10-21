// Port of the identity tests of go/adapters/memory/memory_unit_test.go:
// authenticateNative, the credential hook, the enforcement-point mark and
// resolveAgentBinding in both workload modes (draft 17.1, identity mapping
// IM-11, IM-16, IM-18, IM-19).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type AgentBinding,
  BindingStatus,
  Code,
  codeOf,
  DenialReason,
  NativeDenial,
  type Realm,
} from '../src/adapter/index.ts';
import { arrive, arrived, type MemoryAdapter } from '../src/adapters/memory/index.ts';
import type { RawRequest } from '../src/core/binding/index.ts';
import {
  ENV,
  enrollment,
  get,
  type MState,
  newAdapter,
  newSharedAdapter,
  SEC,
  setHeader,
  T0,
} from './support/memory.ts';

const AR: Realm = { tenantId: 'acme', environmentId: ENV };
const KA = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';
const KB = 'lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU';
const KD = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
const AG = 'https://identity.example/agents/';
const OPERATOR = 'https://identity.example/operators/o';

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  return undefined;
}

const isDependency = (err: unknown) => codeOf(err) === Code.DEPENDENCY_UNAVAILABLE;

test('TestAuthenticate', async (t) => {
  const { a } = newAdapter();
  const req = (authz: string, through: boolean): RawRequest => {
    let r = get('https://gateway.example/invoices/1');
    if (authz !== '') r = setHeader(r, 'Authorization', authz);
    return through ? arrive(r) : r;
  };

  const p = await a.authenticateNative(req('Bearer tok-alice-secret-1', true));
  assert.equal(p.id, 'https://idp.example/alice');
  assert.equal(p.workload, 'w-alice');
  assert.equal(p.mechanism, 'bearer');
  assert.equal(p.authenticatedAt, T0);
  const bob = await a.authenticateNative(req('bearer tok-bob-secret-2', true));
  assert.equal(bob.id, 'https://idp.example/bob', 'a lowercase scheme');

  for (const [name, r, reason] of [
    ['no header', req('', true), DenialReason.NO_CREDENTIAL],
    ['no header, direct', req('', false), DenialReason.NO_CREDENTIAL],
    ['unknown token', req('Bearer tok-nobody', true), DenialReason.CREDENTIAL_REJECTED],
    ['basic scheme', req('Basic dXNlcjpwdw==', true), DenialReason.CREDENTIAL_REJECTED],
    ['empty token', req('Bearer ', true), DenialReason.CREDENTIAL_REJECTED],
    ['direct, valid', req('Bearer tok-alice-secret-1', false), DenialReason.CREDENTIAL_REJECTED],
    ['token prefix only', req('Bearer tok-alice', true), DenialReason.CREDENTIAL_REJECTED],
    [
      'token plus suffix',
      req('Bearer tok-alice-secret-1x', true),
      DenialReason.CREDENTIAL_REJECTED,
    ],
    [
      'token in lowercase',
      req('Bearer TOK-ALICE-SECRET-1', true),
      DenialReason.CREDENTIAL_REJECTED,
    ],
    // The auth-scheme is compared with ASCII case folding only (RFC 9110 11.1).
    [
      'a scheme that folds to bearer only outside ASCII',
      req('BearerK tok-alice-secret-1', true),
      DenialReason.CREDENTIAL_REJECTED,
    ],
  ] as const) {
    const err = await rejection(a.authenticateNative(r));
    assert.ok(err instanceof NativeDenial, `${name}: ${String(err)}, want a NativeDenial`);
    assert.equal(err.reason, reason, name);
    assert.equal(codeOf(err), Code.INVALID_PROOF, `${name}: not an INVALID_PROOF`);
  }

  await t.test('a header cannot carry the mark', async () => {
    let r = req('Bearer tok-alice-secret-1', false);
    r = setHeader(setHeader(r, 'X-Arrived', 'true'), 'Arrived', 'true');
    assert.ok(
      (await rejection(a.authenticateNative(r))) !== undefined,
      'authenticated a request marked by a header',
    );
    assert.ok(!arrived(r), 'arrived is true for an unmarked request');
    assert.ok(arrived(arrive(r)), 'arrived is false for a marked request');
    assert.ok(!arrived({ ...arrive(r) }), 'a copy of a marked request carries no mark');
  });

  await t.test('attributes are copied', async () => {
    const { a } = newAdapter((st) => {
      (st.identities[0] as { attributes: unknown }).attributes = { groups: ['finance'] };
    });
    const p = await a.authenticateNative(req('Bearer tok-alice-secret-1', true));
    (p.attributes as Record<string, unknown>).groups = 'changed';
    const p2 = await a.authenticateNative(req('Bearer tok-alice-secret-1', true));
    assert.deepEqual(
      p2.attributes.groups,
      ['finance'],
      'the store changed through a returned principal',
    );
  });

  await t.test('aborted call', async () => {
    const err = await rejection(
      a.authenticateNative(req('Bearer tok-alice-secret-1', true), AbortSignal.abort()),
    );
    assert.ok(isDependency(err), `err = ${String(err)}, want a dependency error`);
  });
});

test('TestCredentialHook', () => {
  const { a } = newAdapter();
  let r = a.credential(get('https://gateway.example/'), 'bob');
  assert.deepEqual(r.headers, [['Authorization', 'Bearer tok-bob-secret-2']]);
  r = setHeader(r, 'Authorization', 'Bearer explicit');
  assert.deepEqual(
    a.credential(r, 'alice').headers,
    [['Authorization', 'Bearer explicit']],
    'an explicit header was replaced',
  );
  assert.throws(() => a.credential(r, 'nobody'), /no identity "nobody"/);
});

const binding = (a: MemoryAdapter, w: string, agent: string, realm: Realm = AR) =>
  a.resolveAgentBinding(realm, w, agent);

async function settled(p: Promise<AgentBinding>): Promise<{ b?: AgentBinding; err?: unknown }> {
  try {
    return { b: await p };
  } catch (err) {
    return { err };
  }
}

test('TestResolveAgentBinding', async () => {
  const other = { tenant_id: 'globex', environment_id: ENV };
  const rec = (
    w: string,
    status: string,
    realm?: typeof other,
    observed: number | null = null,
    checked: number | null = null,
  ) =>
    enrollment({
      ...(realm === undefined ? {} : { realm }),
      workload: w,
      agent_id: AG + w,
      operator_id: OPERATOR,
      holder_jkt: KA,
      status,
      observed_at: observed,
      status_checked_at: checked,
      source_id: 'registry',
      source_ref: `ref-${w}`,
    });
  const past = SEC - 60;
  const { a } = newAdapter((st) => {
    st.enrollments = [
      rec('active', 'ACTIVE', undefined, past, past),
      rec('checked-edge', 'ACTIVE', undefined, past, SEC + 5),
      rec('checked-past', 'ACTIVE', undefined, past, SEC + 6),
      rec('revoked', 'REVOKED'),
      rec('compromised', 'COMPROMISED'),
      rec('unknown', 'UNKNOWN'),
      rec('future', 'ACTIVE', undefined, SEC + 3600),
      rec('globex-only', 'ACTIVE', other),
    ];
  });
  // resolve names the agent enrolled for w, so that only the realm and the
  // workload decide; TestResolveAgentBindingSelectsTheAgent varies the agent.
  const resolve = (w: string, realm: Realm = AR) => settled(binding(a, w, AG + w, realm));

  const active = await resolve('active');
  assert.deepEqual(active.b, {
    agentId: `${AG}active`,
    operatorId: OPERATOR,
    holderJKT: KA,
    status: 'ACTIVE',
    observedAt: past * 1000,
    statusCheckedAt: past * 1000,
    sourceId: 'registry',
    sourceRef: 'ref-active',
    enrolledElsewhere: false,
  });
  // Identity mapping IM-11: a revoked or compromised binding is returned as
  // its status, with the agent, operator and holder key, and no error.
  for (const [w, status] of [
    ['revoked', BindingStatus.REVOKED],
    ['compromised', BindingStatus.COMPROMISED],
  ] as const) {
    assert.deepEqual((await resolve(w)).b, {
      agentId: AG + w,
      operatorId: OPERATOR,
      holderJKT: KA,
      status,
      observedAt: null,
      statusCheckedAt: null,
      sourceId: 'registry',
      sourceRef: `ref-${w}`,
      enrolledElsewhere: false,
    });
  }
  for (const w of ['unknown', 'no-such-workload', 'globex-only']) {
    const { b, err } = await resolve(w);
    assert.equal(err, undefined, w);
    assert.equal(b?.status, BindingStatus.UNKNOWN, w);
    assert.equal(b?.agentId, '', w);
    assert.equal(b?.holderJKT, '', w);
  }
  assert.equal(
    (await resolve('globex-only', { tenantId: 'globex', environmentId: ENV })).b?.status,
    'ACTIVE',
  );
  assert.ok(isDependency((await resolve('future')).err), 'future observation');
  // Draft A.2: no status-check time may be later than now plus the skew.
  const edge = await resolve('checked-edge');
  assert.equal(edge.b?.statusCheckedAt, (SEC + 5) * 1000, 'status checked at now+skew');
  assert.ok(isDependency((await resolve('checked-past')).err), 'status checked past now+skew');
});

// The agent ID the request names selects among the records of the
// authenticated workload in the realm, and only there (draft 17.1).
test('TestResolveAgentBindingSelectsTheAgent', async () => {
  const other = { tenant_id: 'globex', environment_id: ENV };
  const rec = (w: string, agent: string, jkt: string, realm?: typeof other) =>
    enrollment({
      ...(realm === undefined ? {} : { realm }),
      workload: w,
      agent_id: AG + agent,
      operator_id: OPERATOR,
      holder_jkt: jkt,
      source_ref: `ref-${agent}`,
    });
  const { a } = newSharedAdapter((st) => {
    st.enrollments = [
      rec('shared', 'a', KA),
      rec('shared', 'b', KB),
      rec('dedicated', 'd', KD),
      rec('shared', 'g', KD, other),
    ];
  });
  for (const [w, agent, jkt] of [
    ['shared', `${AG}a`, KA],
    ['shared', `${AG}b`, KB],
    ['dedicated', `${AG}d`, KD],
    ['shared', `${AG}c`, ''],
    ['shared', `${AG}d`, ''],
    ['dedicated', `${AG}a`, ''],
    ['shared', `${AG}g`, ''],
    ['shared', `${AG}A`, ''],
    ['shared', `${AG}a/`, ''],
    ['shared', '', ''],
    ['dedicated', '', ''],
  ]) {
    const b = await binding(a, w as string, agent as string);
    if (jkt === '') {
      assert.deepEqual([b.status, b.agentId, b.holderJKT], ['UNKNOWN', '', ''], `(${w}, ${agent})`);
    } else {
      assert.deepEqual(
        [b.status, b.agentId, b.holderJKT],
        ['ACTIVE', agent, jkt],
        `(${w}, ${agent})`,
      );
    }
  }
});

// An UNKNOWN answer reports whether the agent ID is enrolled for another
// workload of the realm, in any status (draft 17.1).
test('TestResolveAgentBindingEnrolledElsewhere', async () => {
  const otherTenant = { tenant_id: 'globex', environment_id: ENV };
  const otherEnv = { tenant_id: 'acme', environment_id: `${ENV}-staging` };
  const rec = (
    w: string,
    agent: string,
    jkt: string,
    status: string,
    source: string,
    realm?: typeof otherEnv,
  ) =>
    enrollment({
      ...(realm === undefined ? {} : { realm }),
      workload: w,
      agent_id: AG + agent,
      operator_id: OPERATOR,
      holder_jkt: jkt,
      status,
      source_id: source,
      source_ref: `ref-${agent}`,
    });
  const { a } = newSharedAdapter((st) => {
    st.enrollments = [
      rec('shared', 'a', KA, 'ACTIVE', 'registry'),
      rec('shared', 'b', KB, 'ACTIVE', 'registry'),
      rec('dedicated', 'd', KD, 'ACTIVE', 'registry'),
      rec('retired', 'r', KA, 'REVOKED', 'registry'),
      rec('quarantine', 'q', KB, 'COMPROMISED', 'registry'),
      rec('dedicated', 'both', KD, 'ACTIVE', 'registry'),
      rec('shared', 'both', KA, 'REVOKED', 'registry'),
      rec('shared', 'g', KD, 'ACTIVE', 'registry', otherTenant),
      rec('elsewhere', 'x', KD, 'ACTIVE', 'registry', otherEnv),
      rec('far', 'down', KD, 'ACTIVE', 'registry-down'),
    ];
    st.unavailable_sources = ['registry-down'];
  });
  for (const [w, agent, status, elsewhere] of [
    ['shared', 'a', 'ACTIVE', false],
    ['shared', 'both', 'REVOKED', false],
    ['dedicated', 'both', 'ACTIVE', false],
    ['shared', 'd', 'UNKNOWN', true],
    ['dedicated', 'a', 'UNKNOWN', true],
    ['shared', 'r', 'UNKNOWN', true],
    ['shared', 'q', 'UNKNOWN', true],
    ['shared', 'c', 'UNKNOWN', false],
    ['shared', 'g', 'UNKNOWN', false],
    ['shared', 'x', 'UNKNOWN', false],
    ['elsewhere', 'x', 'UNKNOWN', false],
    ['shared', '', 'UNKNOWN', false],
  ] as const) {
    const id = agent === '' ? '' : AG + agent;
    const b = await binding(a, w, id);
    assert.deepEqual([b.status, b.enrolledElsewhere], [status, elsewhere], `(${w}, ${id})`);
  }
  assert.ok(
    isDependency(await rejection(binding(a, 'shared', `${AG}down`))),
    'a record elsewhere in a source that cannot answer',
  );
  const far = await binding(a, 'far', `${AG}a`);
  assert.deepEqual(
    [far.status, far.enrolledElsewhere],
    ['UNKNOWN', true],
    'unavailable source of another agent',
  );
});

const SHARED = 'k8s:prod-eu-1:system:serviceaccount:payments:agent-runner';
const agentA = 'https://identity.example/agents/a';
const agentB = 'https://identity.example/agents/b';

// On a workload that two agents share, each agent ID resolves to that agent's
// own record, whatever the status of the other agent's record and the order
// of the records (identity mapping IM-16, IM-18).
test('TestResolveAgentBindingSharedWorkload', async (t) => {
  const rec = (agent: string, jkt: string, status: string) =>
    enrollment({
      workload: SHARED,
      agent_id: agent,
      operator_id: OPERATOR,
      holder_jkt: jkt,
      status,
    });
  const statuses = ['ACTIVE', 'REVOKED', 'COMPROMISED', 'UNKNOWN'];
  for (const sa of statuses) {
    for (const sb of statuses) {
      for (const order of ['a first', 'b first']) {
        await t.test(`${sa} and ${sb}, ${order}`, async () => {
          const rows = [rec(agentA, KA, sa), rec(agentB, KB, sb)];
          if (order === 'b first') rows.reverse();
          const { a } = newSharedAdapter((st) => {
            st.enrollments = rows;
          });
          for (const [agent, jkt, status] of [
            [agentA, KA, sa],
            [agentB, KB, sb],
          ] as const) {
            const b = await binding(a, SHARED, agent);
            if (status === 'UNKNOWN')
              assert.deepEqual([b.status, b.agentId, b.holderJKT], ['UNKNOWN', '', ''], agent);
            else assert.deepEqual([b.status, b.agentId, b.holderJKT], [status, agent, jkt], agent);
          }
        });
      }
    }
  }
});

// When the source holds more than one record of the named agent on the
// workload, the rule of IM-18 applies among those records only.
test('TestResolveAgentBindingSeveralRecordsOfTheAgent', async (t) => {
  const K1 = KA;
  const K2 = KD;
  const rec = (agent: string, jkt: string, status: string) =>
    enrollment({
      workload: SHARED,
      agent_id: agent,
      operator_id: OPERATOR,
      holder_jkt: jkt,
      status,
    });
  for (const [name, s1, s2, status, jkt] of [
    ['both active', 'ACTIVE', 'ACTIVE', 'UNKNOWN', ''],
    ['one revoked', 'ACTIVE', 'REVOKED', 'ACTIVE', K1],
    ['one compromised', 'ACTIVE', 'COMPROMISED', 'UNKNOWN', ''],
    ['one unknown', 'ACTIVE', 'UNKNOWN', 'UNKNOWN', ''],
    ['both revoked', 'REVOKED', 'REVOKED', 'UNKNOWN', ''],
    // The single record in force is COMPROMISED: it is the answer, as its
    // status with its own key (identity mapping IM-11, IM-18).
    ['compromised and revoked', 'COMPROMISED', 'REVOKED', 'COMPROMISED', K1],
    ['both compromised', 'COMPROMISED', 'COMPROMISED', 'UNKNOWN', ''],
  ] as const) {
    for (const order of ['first', 'second']) {
      await t.test(`${name}, ${order} first`, async () => {
        // Agent B's ACTIVE record sits between agent A's two records; it is
        // never part of A's answer.
        const rows = [rec(agentA, K1, s1), rec(agentB, KB, 'ACTIVE'), rec(agentA, K2, s2)];
        if (order === 'second') [rows[0], rows[2]] = [rows[2] as never, rows[0] as never];
        const { a } = newSharedAdapter((st) => {
          st.enrollments = rows;
        });
        const b = await binding(a, SHARED, agentA);
        const wantAgent = status === 'UNKNOWN' ? '' : agentA;
        assert.deepEqual([b.status, b.agentId, b.holderJKT], [status, wantAgent, jkt]);
        assert.equal(
          (await binding(a, SHARED, agentB)).holderJKT,
          KB,
          'agent B: its own ACTIVE record',
        );
      });
    }
  }
});

// By default a workload serves one agent, and a workload with more than one
// enrollment in force is a configuration error: whichever agent ID the
// request names, UNSUPPORTED_REQUIREMENT (draft 17.1, identity mapping
// IM-19). A REVOKED record does not count, a COMPROMISED one does.
test('TestResolveAgentBindingDedicatedWorkload', async (t) => {
  const W = SHARED;
  const other = { tenant_id: 'globex', environment_id: ENV };
  const rec = (
    workload: string,
    agent: string,
    jkt: string,
    status: string,
    source: string,
    realm?: typeof other,
  ) =>
    enrollment({
      ...(realm === undefined ? {} : { realm }),
      workload,
      agent_id: AG + agent,
      operator_id: OPERATOR,
      holder_jkt: jkt,
      status,
      source_id: source,
      source_ref: `ref-${agent}`,
    });
  const configError = async (a: MemoryAdapter) => {
    for (const agent of [`${AG}a`, `${AG}b`, `${AG}c`, '']) {
      const err = await rejection(binding(a, W, agent));
      assert.equal(
        codeOf(err),
        Code.UNSUPPORTED_REQUIREMENT,
        `${agent}: want UNSUPPORTED_REQUIREMENT`,
      );
    }
  };
  const selects = async (a: MemoryAdapter, want: Record<string, string>) => {
    for (const [agent, status] of Object.entries(want)) {
      const b = await binding(a, W, AG + agent);
      assert.deepEqual(
        [b.status, b.agentId],
        [status, status === 'UNKNOWN' ? '' : AG + agent],
        agent,
      );
    }
  };
  type Rows = MState['enrollments'];
  const cases: [string, Rows, boolean, Record<string, string>][] = [
    ['two active', [rec(W, 'a', KA, 'ACTIVE', 'r'), rec(W, 'b', KB, 'ACTIVE', 'r')], true, {}],
    [
      'compromised and active',
      [rec(W, 'a', KA, 'COMPROMISED', 'r'), rec(W, 'b', KB, 'ACTIVE', 'r')],
      true,
      {},
    ],
    [
      'two compromised',
      [rec(W, 'a', KA, 'COMPROMISED', 'r'), rec(W, 'b', KB, 'COMPROMISED', 'r')],
      true,
      {},
    ],
    [
      'unknown status and active',
      [rec(W, 'a', KA, 'UNKNOWN', 'r'), rec(W, 'b', KB, 'ACTIVE', 'r')],
      true,
      {},
    ],
    [
      'two active and a revoked',
      [
        rec(W, 'd', KD, 'REVOKED', 'r'),
        rec(W, 'a', KA, 'ACTIVE', 'r'),
        rec(W, 'b', KB, 'ACTIVE', 'r'),
      ],
      true,
      {},
    ],
    [
      'revoked and active',
      [rec(W, 'a', KA, 'REVOKED', 'r'), rec(W, 'b', KB, 'ACTIVE', 'r')],
      false,
      { a: 'REVOKED', b: 'ACTIVE', c: 'UNKNOWN' },
    ],
    [
      'revoked and compromised',
      [rec(W, 'a', KA, 'REVOKED', 'r'), rec(W, 'b', KB, 'COMPROMISED', 'r')],
      false,
      { a: 'REVOKED', b: 'COMPROMISED' },
    ],
    [
      'two revoked',
      [rec(W, 'a', KA, 'REVOKED', 'r'), rec(W, 'b', KB, 'REVOKED', 'r')],
      false,
      { a: 'REVOKED', b: 'REVOKED' },
    ],
    [
      'another realm',
      [rec(W, 'a', KA, 'ACTIVE', 'r'), rec(W, 'b', KB, 'ACTIVE', 'r', other)],
      false,
      { a: 'ACTIVE', b: 'UNKNOWN' },
    ],
    [
      'another workload',
      [rec(W, 'a', KA, 'ACTIVE', 'r'), rec(`${W}-2`, 'b', KB, 'ACTIVE', 'r')],
      false,
      { a: 'ACTIVE', b: 'UNKNOWN' },
    ],
  ];
  for (const [name, rows, inError, want] of cases) {
    for (const order of ['as listed', 'reversed']) {
      await t.test(`${name}, ${order}`, async () => {
        const list = order === 'reversed' ? [...rows].reverse() : rows;
        const { a } = newAdapter((st) => {
          st.enrollments = list;
        });
        if (inError) await configError(a);
        else await selects(a, want);
      });
    }
  }

  await t.test('a record of the workload that cannot be read', async () => {
    const { a } = newAdapter((st) => {
      st.enrollments = [rec(W, 'a', KA, 'ACTIVE', 'r'), rec(W, 'b', KB, 'REVOKED', 'down')];
      st.unavailable_sources = ['down'];
    });
    assert.ok(
      isDependency(await rejection(binding(a, W, `${AG}a`))),
      'whether the workload is in error cannot be established',
    );
  });

  await t.test('shared workloads select by the agent ID', async () => {
    const { a } = newSharedAdapter((st) => {
      st.enrollments = [rec(W, 'a', KA, 'ACTIVE', 'r'), rec(W, 'b', KB, 'COMPROMISED', 'r')];
    });
    await selects(a, { a: 'ACTIVE', b: 'COMPROMISED', c: 'UNKNOWN' });
  });
});

// After construction the adapter only reads its state, so calls that
// interleave are independent (Go: from several goroutines, under -race).
test('TestConcurrentUse', async () => {
  const { a } = newAdapter();
  const one = async () => {
    for (let i = 0; i < 50; i++) {
      const r = arrive(
        setHeader(
          get('https://gateway.example/invoices/1'),
          'Authorization',
          'Bearer tok-alice-secret-1',
        ),
      );
      const p = await a.authenticateNative(r);
      const op = await a.mapOperation(r, p, 'map-1');
      assert.equal(op.resources[0], 'https://invoices.example/invoices/1');
      const intent = { intent_id: '', purpose_id: '', description: '', task_id: '' };
      await a.readNativeClaim('/roles', { principal: p, intent, operation: op });
      await a.checkContext('approval-v1', {
        principal: p,
        binding: null,
        intent,
        operation: op,
        evidenceRefs: [],
      });
    }
  };
  await Promise.all(Array.from({ length: 8 }, one));
});
