// Port of go/adapter/enroll/memory/registry_test.go: the registry rules of
// spec/v1.0/profiles/identity-mapping.md (IM-11 resolution results, IM-18
// selection by the presented agent, IM-19 dedicated workloads) and the
// lifecycle of draft 6.4.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  DEFAULT_SOURCE_ID,
  type Enrollment,
  MemoryRegistry,
  type Option,
  withClock,
  withSharedWorkloads,
  withSourceId,
} from '../src/adapter/enroll/memory.ts';
import {
  type Actor,
  ActorKind,
  AuditAction,
  AuditResult,
  EnrollError,
  type EnrollErrorKind,
  type Registry,
  Resolver,
} from '../src/adapter/enroll.ts';
import {
  type AgentBinding,
  type BindingResolver,
  BindingStatus,
  Code,
  codeOf,
  type Realm,
  type Workload,
} from '../src/adapter/index.ts';
import { FakeClock } from '../src/core/clock.ts';
import type { Digest } from '../src/core/values.ts';

const registry: Registry = new MemoryRegistry();
const resolver: BindingResolver = new Resolver(registry);
assert.ok(resolver);

const realm: Realm = { tenantId: 'tenant-1', environmentId: 'prod' };
const otherTenant: Realm = { tenantId: 'tenant-2', environmentId: 'prod' };
const otherEnv: Realm = { tenantId: 'tenant-1', environmentId: 'staging' };

const admin: Actor = { kind: ActorKind.ADMIN, id: 'admin-1', realm };
const issuer: Actor = { kind: ActorKind.AUTHORIZED_ISSUER, id: 'issuer-1', realm };
const agentActor: Actor = { kind: ActorKind.AGENT, id: 'https://agents.example/a', realm };

const agentA = 'https://agents.example/a';
const agentB = 'https://agents.example/b';
const agentC = 'https://agents.example/c';
const agentD = 'https://agents.example/d';

const workloadA: Workload = 'acct:1001';
const workloadB: Workload = 'acct:1002';
const shared: Workload = 'acct:shared';

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const start = 1_700_000_000 * SECOND;

// A valid 43-character thumbprint derived from label.
function jkt(label: string): Digest {
  return createHash('sha256').update(label).digest('base64url') as Digest;
}

function actorOf(kind: string, id: string, r?: Partial<Realm>): Actor {
  return {
    kind: kind as ActorKind,
    id,
    realm: { tenantId: r?.tenantId ?? '', environmentId: r?.environmentId ?? '' },
  };
}

class Fixture {
  readonly clk = new FakeClock(start);
  readonly reg: MemoryRegistry;

  constructor(...opts: Option[]) {
    this.reg = new MemoryRegistry(withClock(this.clk), withSourceId('test-source'), ...opts);
  }

  async enroll(agent: string, wl: Workload, key: Digest): Promise<void> {
    await this.reg.enroll(admin, {
      agentId: agent,
      operatorId: 'op-1',
      workload: wl,
      holderJKT: key,
    });
  }

  lookup(r: Realm, wl: Workload, agent: string): Promise<AgentBinding> {
    return this.reg.lookup(r, wl, agent);
  }

  // Fails unless lookup of the agent on the workload reports status and key.
  async wantBinding(
    wl: Workload,
    agent: string,
    status: BindingStatus,
    key: Digest,
  ): Promise<void> {
    const b = await this.lookup(realm, wl, agent);
    assert.equal(b.status, status, `lookup(${wl}, ${agent}) status`);
    assert.equal(b.holderJKT, key, `lookup(${wl}, ${agent}) key`);
  }
}

function isKind(kind: EnrollErrorKind): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof EnrollError, `want an EnrollError ${kind}, got ${String(e)}`);
    assert.equal(e.kind, kind, e.message);
    return true;
  };
}

test('TestLookupActive', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));

  const got = await f.lookup(realm, workloadA, agentA);
  assert.equal(got.agentId, agentA);
  assert.equal(got.operatorId, 'op-1');
  assert.equal(got.holderJKT, jkt('a1'));
  assert.equal(got.status, BindingStatus.ACTIVE);
  assert.equal(got.observedAt, start);
  assert.equal(got.statusCheckedAt, start);
  assert.equal(got.sourceId, 'test-source');
  assert.notEqual(got.sourceRef, '', 'an opaque row reference');
  assert.equal(got.enrolledElsewhere, false);
});

test('a registry without options reports the default source id', async () => {
  const reg = new MemoryRegistry();
  assert.equal(DEFAULT_SOURCE_ID, 'enroll-memory');
  assert.equal((await reg.lookup(realm, workloadA, agentA)).sourceId, DEFAULT_SOURCE_ID);
  const options = new MemoryRegistry({ sourceId: 'a' }, { sourceId: 'b' });
  assert.equal((await options.lookup(realm, workloadA, agentA)).sourceId, 'b', 'later wins');
});

// Draft 17.1 invariant 2: a read confirms the status now; it never restamps
// the original observation.
test('TestLookupKeepsObservationTime', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  f.clk.advance(90 * SECOND);

  const got = await f.lookup(realm, workloadA, agentA);
  assert.equal(got.observedAt, start, 'the enrollment time');
  assert.equal(got.statusCheckedAt, start + 90 * SECOND, 'the read time');
});

test('TestSourceRefIsStablePerEnrollment', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  await f.enroll(agentB, workloadB, jkt('b1'));

  const before = (await f.lookup(realm, workloadA, agentA)).sourceRef;
  await f.reg.rotate(admin, agentA, jkt('a2'));
  assert.equal((await f.lookup(realm, workloadA, agentA)).sourceRef, before, 'across rotation');
  assert.notEqual((await f.lookup(realm, workloadB, agentB)).sourceRef, before, 'two enrollments');
});

test('TestLookupNotEnrolled', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  f.clk.advance(MINUTE);

  // An absent binding is UNKNOWN, not an error.
  const got = await f.lookup(realm, 'acct:9999', agentA);
  assert.equal(got.status, BindingStatus.UNKNOWN);
  assert.equal(got.agentId, '');
  assert.equal(got.operatorId, '');
  assert.equal(got.holderJKT, '');
  assert.equal(got.observedAt, null, 'nothing was observed');
  assert.equal(got.statusCheckedAt, f.clk.now());
  assert.equal(got.sourceId, 'test-source');
});

// The same workload text in another tenant or environment, and a near-miss
// spelling of the workload or of the agent ID, is another identity (draft
// 8.5, 17.2).
test('TestLookupDistinguishesRealmAndWorkload', async (t) => {
  const f = new Fixture();
  await f.enroll(agentA, 'User:Alice', jkt('a1'));

  const rows: readonly [string, Realm, Workload, string][] = [
    ['other tenant', otherTenant, 'User:Alice', agentA],
    ['other environment', otherEnv, 'User:Alice', agentA],
    ['zero realm', { tenantId: '', environmentId: '' }, 'User:Alice', agentA],
    ['other case', realm, 'user:alice', agentA],
    ['trailing space', realm, 'User:Alice ', agentA],
    ['empty workload', realm, '', agentA],
    ['agent in other case', realm, 'User:Alice', 'https://agents.example/A'],
    ['agent with trailing slash', realm, 'User:Alice', `${agentA}/`],
    ['empty agent', realm, 'User:Alice', ''],
  ];
  for (const [name, r, wl, agent] of rows) {
    await t.test(name, async () => {
      const got = await f.lookup(r, wl, agent);
      assert.equal(got.status, BindingStatus.UNKNOWN);
      assert.equal(got.agentId, '');
    });
  }
  await f.wantBinding('User:Alice', agentA, BindingStatus.ACTIVE, jkt('a1'));
});

// An UNKNOWN answer reports whether the agent ID is enrolled for another
// workload of the realm, in any status (draft 17.1, IM-11). A binding on the
// workload never carries the report, and an enrollment in another tenant or
// environment never sets it.
test('TestLookupEnrolledElsewhere', async (t) => {
  const f = new Fixture();
  await f.enroll(agentA, shared, jkt('a1'));
  await f.enroll(agentB, workloadB, jkt('b1'));
  await f.reg.revoke(admin, agentB);
  const other: Actor = { kind: ActorKind.ADMIN, id: 'admin-2', realm: otherEnv };
  await f.reg.enroll(other, {
    agentId: agentD,
    operatorId: 'op-1',
    workload: workloadA,
    holderJKT: jkt('d1'),
  });

  const rows: readonly [string, Realm, Workload, string, BindingStatus, boolean][] = [
    ['binding on the workload', realm, shared, agentA, 'ACTIVE', false],
    ['revoked binding on the workload', realm, workloadB, agentB, 'REVOKED', false],
    ['agent of another workload', realm, workloadA, agentA, 'UNKNOWN', true],
    ['revoked agent of another workload', realm, shared, agentB, 'UNKNOWN', true],
    ['agent not enrolled', realm, shared, agentC, 'UNKNOWN', false],
    ['agent of another environment only', realm, shared, agentD, 'UNKNOWN', false],
    [
      'agent of another environment, same workload text',
      realm,
      workloadA,
      agentD,
      'UNKNOWN',
      false,
    ],
    [
      'agent of the realm, asked in another tenant',
      otherTenant,
      workloadA,
      agentA,
      'UNKNOWN',
      false,
    ],
    ['no agent named', realm, shared, '', 'UNKNOWN', false],
  ];
  for (const [name, r, wl, agent, status, elsewhere] of rows) {
    await t.test(name, async () => {
      const got = await f.lookup(r, wl, agent);
      assert.equal(got.status, status);
      assert.equal(got.enrolledElsewhere, elsewhere);
      if (status === 'UNKNOWN') assert.equal(got.agentId, '', 'UNKNOWN names no agent');
    });
  }
  await f.reg.markCompromised(admin, agentA);
  const got = await f.lookup(realm, workloadA, agentA);
  assert.equal(got.status, BindingStatus.UNKNOWN, 'compromised agent of another workload');
  assert.equal(got.enrolledElsewhere, true);
});

test('TestEnrollRequiresAuthorityAndValidInput', async (t) => {
  const good: Enrollment = {
    agentId: agentA,
    operatorId: 'op-1',
    workload: workloadA,
    holderJKT: jkt('a1'),
  };
  const rows: readonly [string, Actor, Enrollment, EnrollErrorKind][] = [
    ['agent enrolling itself', agentActor, good, 'NOT_AUTHORIZED'],
    ['empty actor', actorOf('', ''), good, 'NOT_AUTHORIZED'],
    ['relative agent id', admin, { ...good, agentId: 'agent-a' }, 'INVALID'],
    ['empty agent id', admin, { ...good, agentId: '' }, 'INVALID'],
    ['agent id with fragment', admin, { ...good, agentId: `${agentA}#x` }, 'INVALID'],
    ['agent id with empty fragment', admin, { ...good, agentId: `${agentA}#` }, 'INVALID'],
    ['agent id with space', admin, { ...good, agentId: 'https://agents.example/a b' }, 'INVALID'],
    ['empty operator', admin, { ...good, operatorId: '' }, 'INVALID'],
    ['empty workload', admin, { ...good, workload: '' }, 'INVALID'],
    ['short key', admin, { ...good, holderJKT: 'abc' as Digest }, 'INVALID'],
    ['padded key', admin, { ...good, holderJKT: `${jkt('a1')}=` as Digest }, 'INVALID'],
  ];
  for (const [name, a, e, kind] of rows) {
    await t.test(name, async () => {
      const f = new Fixture();
      await assert.rejects(f.reg.enroll(a, e), isKind(kind));
      const got = await f.lookup(realm, workloadA, agentA);
      assert.equal(got.status, BindingStatus.UNKNOWN, 'a failed enrollment left a binding');
    });
  }
});

test('TestEnrollConflicts', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));

  // Same agent_id again, even with a new key and workload.
  await assert.rejects(
    f.reg.enroll(admin, {
      agentId: agentA,
      operatorId: 'op-2',
      workload: workloadB,
      holderJKT: jkt('a9'),
    }),
    isKind('ALREADY_ENROLLED'),
  );
  // A holder key already bound to another agent of the realm.
  await assert.rejects(
    f.reg.enroll(admin, {
      agentId: agentB,
      operatorId: 'op-1',
      workload: workloadB,
      holderJKT: jkt('a1'),
    }),
    isKind('KEY_REUSE'),
  );

  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
  assert.equal((await f.lookup(realm, workloadB, agentB)).status, BindingStatus.UNKNOWN);
});

// The same agent_id and the same key in another realm are separate
// enrollments, and an admin acts only in its own realm.
test('TestEnrollIsRealmScoped', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  const other: Actor = { kind: ActorKind.ADMIN, id: 'admin-2', realm: otherTenant };
  await f.reg.enroll(other, {
    agentId: agentA,
    operatorId: 'op-9',
    workload: workloadA,
    holderJKT: jkt('a1'),
  });
  const there = await f.lookup(otherTenant, workloadA, agentA);
  assert.equal(there.operatorId, 'op-9');
  assert.equal(there.status, BindingStatus.ACTIVE);
  assert.equal((await f.lookup(realm, workloadA, agentA)).operatorId, 'op-1');
});

// Rotation by a non-admin is rejected and leaves the binding untouched
// (draft 6.4).
test('TestRotateRequiresAdminOrIssuer', async (t) => {
  const rows: readonly [string, Actor][] = [
    ['agent with the old key', agentActor],
    ['agent claiming admin id', actorOf('AGENT', 'admin-1', realm)],
    ['zero actor', actorOf('', '')],
    ['undefined kind', actorOf('OPERATOR', 'op-1', realm)],
    ['admin without id', actorOf('ADMIN', '', realm)],
    ['admin without realm', actorOf('ADMIN', 'admin-1')],
  ];
  for (const [name, a] of rows) {
    await t.test(name, async () => {
      const f = new Fixture();
      await f.enroll(agentA, workloadA, jkt('a1'));
      await assert.rejects(f.reg.rotate(a, agentA, jkt('a2')), isKind('NOT_AUTHORIZED'));
      await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
    });
  }
});

test('TestRotateByAdminAndIssuer', async (t) => {
  for (const [name, a] of [
    ['admin', admin],
    ['authorized issuer', issuer],
  ] as const) {
    await t.test(name, async () => {
      const f = new Fixture();
      await f.enroll(agentA, workloadA, jkt('a1'));
      f.clk.advance(HOUR + MINUTE);

      await f.reg.rotate(a, agentA, jkt('a2'));
      const got = await f.lookup(realm, workloadA, agentA);
      assert.equal(got.holderJKT, jkt('a2'));
      assert.equal(got.status, BindingStatus.ACTIVE);
      assert.equal(got.agentId, agentA);
      assert.equal(got.operatorId, 'op-1');
      assert.equal(got.observedAt, start + HOUR + MINUTE, 'the rotation time');
    });
  }
});

test('TestRotateRejectsBadKeys', async (t) => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  await f.enroll(agentB, workloadB, jkt('b1'));
  await f.reg.rotate(admin, agentA, jkt('a2'));

  const rows: readonly [string, Digest, EnrollErrorKind][] = [
    ['malformed', 'not-a-thumbprint' as Digest, 'INVALID'],
    ['empty', '' as Digest, 'INVALID'],
    ['current key', jkt('a2'), 'KEY_REUSE'],
    ['retired key', jkt('a1'), 'KEY_REUSE'],
    ["another agent's key", jkt('b1'), 'KEY_REUSE'],
  ];
  for (const [name, key, kind] of rows) {
    await t.test(name, async () => {
      await assert.rejects(f.reg.rotate(admin, agentA, key), isKind(kind));
      await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a2'));
    });
  }
});

test('TestRotateUnknownAgent', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));

  await assert.rejects(f.reg.rotate(admin, agentB, jkt('b1')), isKind('NOT_FOUND'));
  // An admin of another tenant has no authority over this realm's agent.
  const foreign: Actor = { kind: ActorKind.ADMIN, id: 'admin-2', realm: otherTenant };
  await assert.rejects(f.reg.rotate(foreign, agentA, jkt('a2')), isKind('NOT_FOUND'));
  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
});

test('TestMarkCompromised', async (t) => {
  for (const [name, a] of [
    ['admin', admin],
    ['authorized issuer', issuer],
  ] as const) {
    await t.test(name, async () => {
      const f = new Fixture();
      await f.enroll(agentA, workloadA, jkt('a1'));
      f.clk.advance(HOUR);

      await f.reg.markCompromised(a, agentA);
      const got = await f.lookup(realm, workloadA, agentA);
      assert.equal(got.status, BindingStatus.COMPROMISED);
      // A compromised binding still names the agent and key.
      assert.equal(got.agentId, agentA);
      assert.equal(got.holderJKT, jkt('a1'));
      assert.equal(got.observedAt, start + HOUR, 'the marking time');
    });
  }
});

test('TestMarkCompromisedRequiresAuthority', async (t) => {
  const rows: readonly [string, Actor][] = [
    ['agent', agentActor],
    ['zero', actorOf('', '')],
    ['admin no id', actorOf('ADMIN', '', realm)],
    ['admin no realm', actorOf('ADMIN', 'admin-1')],
  ];
  for (const [name, a] of rows) {
    await t.test(name, async () => {
      const f = new Fixture();
      await f.enroll(agentA, workloadA, jkt('a1'));
      await assert.rejects(f.reg.markCompromised(a, agentA), isKind('NOT_AUTHORIZED'));
      await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
    });
  }
});

test('TestMarkCompromisedUnknownAgent', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  const foreign: Actor = { kind: ActorKind.ADMIN, id: 'admin-2', realm: otherTenant };
  for (const [name, a, agent] of [
    ['unknown agent', admin, agentB],
    ['admin of another tenant', foreign, agentA],
  ] as const) {
    await assert.rejects(f.reg.markCompromised(a, agent), isKind('NOT_FOUND'), name);
  }
  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
});

// No call sequence, whoever makes it, returns a compromised binding to ACTIVE
// through lookup, and the original observation time of the marking survives
// (draft 6.4).
test('TestCompromisedNeverRecovers', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  f.clk.advance(HOUR);
  const markedAt = f.clk.now();
  await f.reg.markCompromised(admin, agentA);
  f.clk.advance(HOUR);

  const enrollment = (key: Digest): Enrollment => ({
    agentId: agentA,
    operatorId: 'op-1',
    workload: workloadA,
    holderJKT: key,
  });
  const steps: readonly [string, () => Promise<void>, EnrollErrorKind | null][] = [
    ['rotate by admin', () => f.reg.rotate(admin, agentA, jkt('a2')), 'COMPROMISED'],
    ['rotate by issuer', () => f.reg.rotate(issuer, agentA, jkt('a3')), 'COMPROMISED'],
    ['rotate by the agent', () => f.reg.rotate(agentActor, agentA, jkt('a4')), 'NOT_AUTHORIZED'],
    ['revoke', () => f.reg.revoke(admin, agentA), 'COMPROMISED'],
    ['enroll again, new key', () => f.reg.enroll(admin, enrollment(jkt('a5'))), 'ALREADY_ENROLLED'],
    [
      'enroll again, same key',
      () => f.reg.enroll(admin, enrollment(jkt('a1'))),
      'ALREADY_ENROLLED',
    ],
    ['mark again', () => f.reg.markCompromised(admin, agentA), null],
  ];
  for (const [name, call, kind] of steps) {
    if (kind === null) await call();
    else await assert.rejects(call(), isKind(kind), name);
    const got = await f.lookup(realm, workloadA, agentA);
    assert.equal(got.status, BindingStatus.COMPROMISED, `after ${name}`);
    assert.equal(got.holderJKT, jkt('a1'), `after ${name}`);
    assert.equal(got.agentId, agentA, `after ${name}`);
    assert.equal(got.observedAt, markedAt, `after ${name}: the first marking time`);
  }
});

test('TestRevoke', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  f.clk.advance(HOUR);

  await assert.rejects(f.reg.revoke(agentActor, agentA), isKind('NOT_AUTHORIZED'));
  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));

  await f.reg.revoke(admin, agentA);
  const got = await f.lookup(realm, workloadA, agentA);
  assert.equal(got.status, BindingStatus.REVOKED);
  assert.equal(got.agentId, agentA, 'REVOKED names the agent');
  assert.equal(got.holderJKT, jkt('a1'), 'and the key');

  // A revoked binding is not rotated back to life, and revoking again is a no-op.
  await assert.rejects(f.reg.rotate(admin, agentA, jkt('a2')), isKind('REVOKED'));
  await f.reg.revoke(admin, agentA);
  await assert.rejects(
    f.reg.enroll(admin, {
      agentId: agentA,
      operatorId: 'op-1',
      workload: workloadA,
      holderJKT: jkt('a3'),
    }),
    isKind('ALREADY_ENROLLED'),
  );
  await f.wantBinding(workloadA, agentA, BindingStatus.REVOKED, jkt('a1'));

  // A revoked binding can still be found compromised, and then stays so.
  await f.reg.markCompromised(admin, agentA);
  await f.wantBinding(workloadA, agentA, BindingStatus.COMPROMISED, jkt('a1'));
});

test('TestRevokeUnknownAgent', async () => {
  const f = new Fixture();
  await assert.rejects(f.reg.revoke(admin, agentA), isKind('NOT_FOUND'));
});

// Draft 5 invariant 3, 6.1 and 17.1, IM-18. A credential shared by two
// agents names the account, never an agent; each agent has its own record,
// and lookup selects the record of the agent the request names among the
// records of the workload, never a record of another workload or of another
// agent.
test('TestSharedWorkload', async () => {
  const f = new Fixture(withSharedWorkloads());
  await f.enroll(agentA, shared, jkt('a1'));
  await f.enroll(agentB, shared, jkt('b1'));
  await f.enroll(agentD, workloadA, jkt('d1'));

  for (const [agent, key] of [
    [agentA, jkt('a1')],
    [agentB, jkt('b1')],
  ] as const) {
    const got = await f.lookup(realm, shared, agent);
    assert.equal(got.status, BindingStatus.ACTIVE, agent);
    assert.equal(got.agentId, agent);
    assert.equal(got.holderJKT, key, 'its own key');
  }

  // The agent ID selects only among the records of the workload; the
  // workload alone names no agent.
  for (const [name, wl, agent] of [
    ['agent enrolled only on another workload', shared, agentD],
    ['agent of the shared workload, other one', workloadA, agentA],
    ['agent not enrolled', shared, agentC],
    ['no agent named', shared, ''],
  ] as const) {
    const got = await f.lookup(realm, wl, agent);
    assert.equal(got.status, BindingStatus.UNKNOWN, name);
    assert.equal(got.agentId, '', name);
    assert.equal(got.holderJKT, '', name);
  }

  // Compromise of one agent does not touch the other.
  await f.reg.markCompromised(admin, agentA);
  await f.wantBinding(shared, agentA, BindingStatus.COMPROMISED, jkt('a1'));
  await f.wantBinding(shared, agentB, BindingStatus.ACTIVE, jkt('b1'));

  // Revoking B answers REVOKED for B, and A stays COMPROMISED.
  await f.reg.revoke(admin, agentB);
  await f.wantBinding(shared, agentB, BindingStatus.REVOKED, jkt('b1'));
  await f.wantBinding(shared, agentA, BindingStatus.COMPROMISED, jkt('a1'));
});

// On an account whose first agent was revoked, the agent enrolled after it
// resolves ACTIVE and the revoked agent stays REVOKED; neither answers for
// the other.
test('TestRevokedRowsDoNotShadowTheBinding', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  await f.reg.revoke(admin, agentA);
  await f.enroll(agentB, workloadA, jkt('b1'));

  const b = await f.lookup(realm, workloadA, agentB);
  assert.equal(b.agentId, agentB);
  assert.equal(b.status, BindingStatus.ACTIVE);
  assert.equal(b.holderJKT, jkt('b1'));
  const a = await f.lookup(realm, workloadA, agentA);
  assert.equal(a.agentId, agentA);
  assert.equal(a.status, BindingStatus.REVOKED);
  assert.equal(a.holderJKT, jkt('a1'));
});

// By default a workload serves one agent, so enroll refuses a record for a
// workload that a record in force already names (IM-19). Only records in
// force count: a revoked record does not, a compromised one does. The
// refusal is audited, and the workload of another realm is another workload.
test('TestDedicatedWorkloadRefusesASecondEnrollment', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));

  await assert.rejects(
    f.reg.enroll(admin, {
      agentId: agentB,
      operatorId: 'op-1',
      workload: workloadA,
      holderJKT: jkt('b1'),
    }),
    isKind('WORKLOAD_IN_USE'),
  );
  const audit = f.reg.audit();
  const last = audit[audit.length - 1];
  assert.equal(last?.result, AuditResult.REJECTED);
  assert.equal(last?.agentId, agentB);
  assert.equal(last?.workload, workloadA);
  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
  const refused = await f.lookup(realm, workloadA, agentB);
  assert.equal(refused.status, BindingStatus.UNKNOWN, 'a refused enrollment left a binding');
  assert.equal(refused.agentId, '');

  // The key of the refused request was not used, so a later enrollment may
  // take it; another workload of the realm is free.
  await f.enroll(agentB, workloadB, jkt('b1'));
  // The same workload text in another realm is another workload.
  const other: Actor = { kind: ActorKind.ADMIN, id: 'admin-2', realm: otherEnv };
  await f.reg.enroll(other, {
    agentId: agentC,
    operatorId: 'op-1',
    workload: workloadA,
    holderJKT: jkt('c1'),
  });

  // A compromised record stays in force.
  await f.reg.markCompromised(admin, agentA);
  await assert.rejects(
    f.reg.enroll(admin, {
      agentId: agentC,
      operatorId: 'op-1',
      workload: workloadA,
      holderJKT: jkt('c2'),
    }),
    isKind('WORKLOAD_IN_USE'),
  );

  // A revoked record does not count.
  await f.reg.revoke(admin, agentB);
  await f.enroll(agentC, workloadB, jkt('c3'));
  await f.wantBinding(workloadB, agentC, BindingStatus.ACTIVE, jkt('c3'));
});

// A workload whose agent was revoked takes a new agent, and the old record
// becomes in force again when it is marked compromised. The workload then
// has two records in force, the configuration error of IM-19: whichever
// agent ID the request names, lookup rejects with UNSUPPORTED_REQUIREMENT and
// no binding (draft 17.1). A registry that supports shared workloads selects
// instead.
test('TestDedicatedWorkloadConfigurationError', async (t) => {
  for (const [name, opts, isShared] of [
    ['dedicated', [], false],
    ['shared', [withSharedWorkloads()], true],
  ] as const) {
    await t.test(name, async () => {
      const f = new Fixture(...opts);
      await f.enroll(agentA, workloadA, jkt('a1'));
      await f.reg.revoke(admin, agentA);
      await f.enroll(agentB, workloadA, jkt('b1'));
      await f.wantBinding(workloadA, agentB, BindingStatus.ACTIVE, jkt('b1'));
      await f.wantBinding(workloadA, agentA, BindingStatus.REVOKED, jkt('a1'));

      await f.reg.markCompromised(admin, agentA);
      if (isShared) {
        await f.wantBinding(workloadA, agentB, BindingStatus.ACTIVE, jkt('b1'));
        await f.wantBinding(workloadA, agentA, BindingStatus.COMPROMISED, jkt('a1'));
        return;
      }
      const r: BindingResolver = new Resolver(f.reg);
      for (const agent of [agentA, agentB, agentC, '']) {
        await assert.rejects(
          r.resolveAgentBinding(realm, workloadA, agent),
          (e: unknown) => codeOf(e) === Code.UNSUPPORTED_REQUIREMENT,
          JSON.stringify(agent),
        );
      }
      // Another workload of the realm is not affected.
      await f.enroll(agentC, workloadB, jkt('c1'));
      await f.wantBinding(workloadB, agentC, BindingStatus.ACTIVE, jkt('c1'));
    });
  }
});

test('TestAuditLog', async () => {
  const f = new Fixture();
  assert.equal(f.reg.audit().length, 0, 'a new registry');
  const swallow = (p: Promise<void>) => p.catch(() => undefined);

  await f.enroll(agentA, workloadA, jkt('a1')); // 1 applied
  f.clk.advance(MINUTE);
  await swallow(f.reg.rotate(agentActor, agentA, jkt('a2'))); // 2 denied: no authority
  await swallow(f.reg.rotate(admin, agentA, jkt('a2'))); // 3 applied
  await swallow(f.reg.rotate(issuer, agentA, jkt('a1'))); // 4 rejected: retired key
  await swallow(f.reg.markCompromised(issuer, agentA)); // 5 applied
  await swallow(f.reg.markCompromised(admin, agentA)); // 6 unchanged: already compromised
  await swallow(f.reg.rotate(admin, agentA, jkt('a3'))); // 7 rejected: compromised
  await swallow(f.reg.revoke(admin, agentB)); // 8 rejected: not enrolled

  const log = f.reg.audit();
  const want: readonly [AuditAction, ActorKind, AuditResult][] = [
    [AuditAction.ENROLL, ActorKind.ADMIN, AuditResult.APPLIED],
    [AuditAction.ROTATE, ActorKind.AGENT, AuditResult.DENIED],
    [AuditAction.ROTATE, ActorKind.ADMIN, AuditResult.APPLIED],
    [AuditAction.ROTATE, ActorKind.AUTHORIZED_ISSUER, AuditResult.REJECTED],
    [AuditAction.MARK_COMPROMISED, ActorKind.AUTHORIZED_ISSUER, AuditResult.APPLIED],
    [AuditAction.MARK_COMPROMISED, ActorKind.ADMIN, AuditResult.UNCHANGED],
    [AuditAction.ROTATE, ActorKind.ADMIN, AuditResult.REJECTED],
    [AuditAction.REVOKE, ActorKind.ADMIN, AuditResult.REJECTED],
  ];
  assert.equal(log.length, want.length, JSON.stringify(log));
  want.forEach(([action, kind, result], i) => {
    const e = log[i];
    assert.ok(e);
    assert.equal(e.seq, i + 1, `entry ${i} seq`);
    assert.deepEqual([e.action, e.actor.kind, e.result], [action, kind, result], `entry ${i}`);
    assert.deepEqual(e.actor.realm, realm, `entry ${i} realm`);
    const refused = e.result === AuditResult.DENIED || e.result === AuditResult.REJECTED;
    assert.equal(refused, e.reason !== '', `entry ${i}: ${e.result} with reason ${e.reason}`);
  });

  // Details of the entries that carry a key.
  const [enrolled, denied, rotated] = log;
  assert.equal(enrolled?.agentId, agentA);
  assert.equal(enrolled?.workload, workloadA);
  assert.equal(enrolled?.newJKT, jkt('a1'));
  assert.equal(enrolled?.oldJKT, '');
  assert.equal(enrolled?.at, start);
  assert.equal(rotated?.agentId, agentA);
  assert.equal(rotated?.oldJKT, jkt('a1'));
  assert.equal(rotated?.newJKT, jkt('a2'));
  assert.equal(rotated?.actor.id, 'admin-1');
  assert.equal(rotated?.at, start + MINUTE);
  // A denied rotation records what was asked for, not what the binding held.
  assert.equal(denied?.oldJKT, '');
  assert.equal(denied?.newJKT, jkt('a2'));

  // The returned log is a copy.
  (log[0] as { agentId: string }).agentId = 'tampered';
  (log[0]?.actor.realm as { tenantId: string }).tenantId = 'tampered';
  log.pop();
  const again = f.reg.audit();
  assert.equal(again[0]?.agentId, agentA);
  assert.equal(again[0]?.actor.realm.tenantId, realm.tenantId);
  assert.equal(again.length, want.length);
});

test('TestAuditLogRecordsNothingForReads', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  await f.lookup(realm, workloadA, agentA);
  await f.lookup(realm, workloadA, agentB);
  assert.equal(f.reg.audit().length, 1, 'only the enrollment');
});

// A canceled call is a source that cannot answer: DEPENDENCY_UNAVAILABLE
// with the abort reason as its cause (Go: context.Canceled).
test('TestCanceledContext', async (t) => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a1'));
  const ctl = new AbortController();
  ctl.abort();
  const signal = ctl.signal;

  const calls: Readonly<Record<string, () => Promise<unknown>>> = {
    lookup: () => f.reg.lookup(realm, workloadA, agentA, signal),
    rotate: () => f.reg.rotate(admin, agentA, jkt('a2'), signal),
    markCompromised: () => f.reg.markCompromised(admin, agentA, signal),
    revoke: () => f.reg.revoke(admin, agentA, signal),
    enroll: () =>
      f.reg.enroll(
        admin,
        { agentId: agentB, operatorId: 'op-1', workload: workloadB, holderJKT: jkt('b1') },
        signal,
      ),
  };
  for (const [name, call] of Object.entries(calls)) {
    await t.test(name, async () => {
      await assert.rejects(call(), (e: unknown) => {
        assert.equal(codeOf(e), Code.DEPENDENCY_UNAVAILABLE);
        assert.equal((e as Error).cause, signal.reason, 'the abort reason');
        return true;
      });
    });
  }
  await f.wantBinding(workloadA, agentA, BindingStatus.ACTIVE, jkt('a1'));
  assert.equal(f.reg.audit().length, 1, 'a canceled call was audited');
});

test('TestConcurrentUse', async () => {
  const f = new Fixture();
  await f.enroll(agentA, workloadA, jkt('a0'));

  const rotations = 40;
  const calls: Promise<unknown>[] = [];
  for (let i = 0; i < rotations; i++) {
    calls.push(
      f.reg.rotate(admin, agentA, jkt(`a-${i}`)).catch((e: unknown) => {
        if (!(e instanceof EnrollError && e.kind === 'COMPROMISED')) throw e;
      }),
      f.reg.lookup(realm, workloadA, agentA),
    );
    if (i === rotations / 2) calls.push(f.reg.markCompromised(issuer, agentA));
  }
  await Promise.all(calls);

  // Whatever the interleaving, the end state is COMPROMISED, and every
  // attempt is in the log.
  assert.equal((await f.lookup(realm, workloadA, agentA)).status, BindingStatus.COMPROMISED);
  assert.equal(f.reg.audit().length, 1 + rotations + 1);
});

// agent_id is an absolute URI (draft 6.1); a native workload identifier, a
// gateway-assigned URI and a DID are all valid.
test('TestEnrollAgentIDForms', async (t) => {
  const rows: readonly [string, boolean][] = [
    ['https://agents.example/a', true],
    ['https://agents.example/a%20b?x=1', true],
    ['urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66', true],
    ['did:web:example.com', true],
    ['spiffe://example.org/ns/prod/sa/runner', true],
    ['agent-a', false],
    ['/agents/a', false],
    ['1http://agents.example/a', false],
    ['://agents.example/a', false],
    ['https:', false],
    ['https://agents.example/a%2', false],
    ['https://agents.example/a%zz', false],
    ['https://agents.example/é', false],
    ['https://agents.example/a b', false],
    ['https://agents.example/a#frag', false],
    [' https://agents.example/a', false],
  ];
  for (const [id, ok] of rows) {
    await t.test(id, async () => {
      const f = new Fixture();
      const call = f.reg.enroll(admin, {
        agentId: id,
        operatorId: 'op-1',
        workload: workloadA,
        holderJKT: jkt('k'),
      });
      if (ok) await call;
      else await assert.rejects(call, isKind('INVALID'));
    });
  }
});
