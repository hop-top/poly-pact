// Port of go/adapter/enroll/enroll_test.go.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Actor,
  ActorKind,
  EnrollError,
  isActorKind,
  type Registry,
  Resolver,
} from '../src/adapter/enroll.ts';
import {
  AdapterError,
  type AgentBinding,
  type BindingResolver,
  Code,
  codeOf,
  type Realm,
} from '../src/adapter/index.ts';
import type { Digest } from '../src/core/values.ts';

const realm: Realm = { tenantId: 'tenant-1', environmentId: 'prod' };

test('TestActorKindValid', () => {
  const rows: readonly [unknown, boolean][] = [
    [ActorKind.ADMIN, true],
    [ActorKind.AUTHORIZED_ISSUER, true],
    [ActorKind.AGENT, true],
    ['', false],
    ['admin', false],
    ['ROOT', false],
    [undefined, false],
  ];
  for (const [kind, want] of rows) assert.equal(isActorKind(kind), want, String(kind));
  assert.deepEqual(Object.values(ActorKind), ['ADMIN', 'AUTHORIZED_ISSUER', 'AGENT']);
});

function actor(kind: string, id: string, r: Partial<Realm> = realm): Actor {
  return {
    kind: kind as ActorKind,
    id,
    realm: { tenantId: r.tenantId ?? '', environmentId: r.environmentId ?? '' },
  };
}

// Who may change an enrollment: the draft 6.1 and 6.4 actors (a native
// authenticated administrative workflow and an authorized identity-binding
// or rotation issuer), scoped to one realm and attributable.
test('TestCheckAuthority', async (t) => {
  const rows: readonly [string, Actor, boolean][] = [
    ['admin', actor('ADMIN', 'a1'), true],
    ['authorized issuer', actor('AUTHORIZED_ISSUER', 'i1'), true],
    ['agent itself', actor('AGENT', 'https://agents.example/a'), false],
    ['empty kind', actor('', 'a1'), false],
    ['undefined kind', actor('OWNER', 'a1'), false],
    ['lower-case kind', actor('admin', 'a1'), false],
    ['admin without id', actor('ADMIN', ''), false],
    ['admin without realm', actor('ADMIN', 'a1', {}), false],
    ['admin without tenant', actor('ADMIN', 'a1', { environmentId: 'prod' }), false],
    ['admin without environment', actor('ADMIN', 'a1', { tenantId: 'tenant-1' }), false],
  ];
  for (const [name, a, ok] of rows) {
    await t.test(name, () => {
      if (ok) assert.doesNotThrow(() => Actor.checkAuthority(a));
      else
        assert.throws(
          () => Actor.checkAuthority(a),
          (e: unknown) => e instanceof EnrollError && e.kind === 'NOT_AUTHORIZED',
        );
    });
  }
});

// Records the arguments of lookup and returns canned results.
class StubRegistry implements Registry {
  got: unknown[] = [];
  binding: AgentBinding | undefined;
  err: unknown;

  async lookup(...args: unknown[]): Promise<AgentBinding> {
    this.got = args;
    if (this.err !== undefined) throw this.err;
    return this.binding as AgentBinding;
  }

  async rotate(): Promise<void> {}

  async markCompromised(): Promise<void> {}
}

test('TestResolverDelegatesToLookup', async () => {
  const want: AgentBinding = {
    agentId: 'https://agents.example/a',
    operatorId: 'op-1',
    holderJKT: '0123456789012345678901234567890123456789012' as Digest,
    status: 'COMPROMISED',
    observedAt: null,
    statusCheckedAt: null,
    sourceId: '',
    sourceRef: '',
    enrolledElsewhere: false,
  };
  const stub = new StubRegistry();
  stub.binding = want;
  const r: BindingResolver = new Resolver(stub);
  const signal = new AbortController().signal;

  const got = await r.resolveAgentBinding(realm, 'acct:1', 'https://agents.example/a', signal);
  assert.deepEqual(got, want);
  assert.deepEqual(stub.got, [realm, 'acct:1', 'https://agents.example/a', signal]);
  assert.equal(new Resolver(stub).registry, stub);
});

test('TestResolverKeepsDependencyError', async () => {
  const stub = new StubRegistry();
  stub.err = new Error('store down', { cause: AdapterError.dependencyUnavailable() });
  await assert.rejects(
    new Resolver(stub).resolveAgentBinding(realm, 'acct:1', 'https://agents.example/a'),
    (e: unknown) => codeOf(e) === Code.DEPENDENCY_UNAVAILABLE,
  );
});
