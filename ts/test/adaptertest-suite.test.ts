// Port of go/adapter/adaptertest/suite_test.go: the request a case builds,
// the harness around the factory and the hooks, runConformance and
// evaluateConformance, the workload modes and the default fixture tree;
// plus the two properties of the TypeScript entry points: a stub adapter
// fails every common case, and the module loads no test framework.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  type Case,
  defaultFixtures,
  type Env,
  evaluateConformance,
  type Factory,
  type Hooks,
  loadCases,
  runConformance,
  type Subject,
} from '../src/adapter/adaptertest/index.ts';
import { buildRequest } from '../src/adapter/adaptertest/request.ts';
import { runCase } from '../src/adapter/adaptertest/run.ts';
import { type Adapter, DenialReason, NativeDenial } from '../src/adapter/index.ts';
import { FakeClock } from '../src/core/clock.ts';
import { RawJSON } from '../src/core/values.ts';
import {
  authCase,
  authFake,
  authzCase,
  authzFake,
  factoryFor,
  fake,
  goodPrincipal,
  header,
  minimalCase,
  NOW,
  request,
  type TestCase,
  treeOf,
  wantClean,
  wantFails,
  withHeader,
  ZERO_PRINCIPAL,
} from './support/adaptertest.ts';
import { fixturesPresent } from './support/fixtures.ts';
import { PACKAGE } from './support/repo.ts';

test('TestBuildRequest', async (t) => {
  await t.test('url is kept as stated', () => {
    const { req, body } = buildRequest(
      request({
        method: 'POST',
        url: 'https://svc:pw@internal.local:8443/a%2Fb/c?x=%2f&y=1#frag',
        headers: { 'X-One': '1', host: 'front.example' },
        body_b64: 'aGVsbG8=',
      }),
    );
    assert.equal(req.method, 'POST');
    // The request is the one a server took off the wire: its request-target
    // is the url, in absolute-form, octet for octet.
    assert.equal(req.rawRequestURI, 'https://svc:pw@internal.local:8443/a%2Fb/c?x=%2f&y=1#frag');
    assert.equal(header(req, 'X-One'), '1');
    assert.equal(header(req, 'host'), 'front.example', 'the Host field line reaches the adapter');
    assert.equal(Buffer.from(req.body).toString(), 'hello');
    assert.equal(Buffer.from(body).toString(), 'hello');
  });

  await t.test('no body', () => {
    const { req, body } = buildRequest(request({ url: 'https://gateway.example/' }));
    assert.equal(body.length, 0);
    assert.equal(req.body.length, 0);
    assert.equal(req.tlsPeer, undefined);
  });

  await t.test('tls peer', () => {
    const { req } = buildRequest(
      request({
        url: 'https://gateway.example/',
        tlsPeer: {
          subjectCN: 'alice',
          issuerCN: 'Test CA',
          dnsNames: ['alice.example'],
          uris: ['spiffe://example/alice'],
        },
      }),
    );
    assert.deepEqual(req.tlsPeer, {
      subjectCN: 'alice',
      issuerCN: 'Test CA',
      dnsNames: ['alice.example'],
      uris: ['spiffe://example/alice'],
    });
  });

  await t.test('errors', () => {
    for (const [name, r] of Object.entries({
      'bad body': request({ url: 'https://x.example/', body_b64: '***' }),
      'bad url': request({ url: 'https://x.example/%zz' }),
      'bad method': request({ method: 'G ET', url: 'https://x.example/' }),
      'bad peer': request({
        url: 'https://x.example/',
        tlsPeer: { subjectCN: '', issuerCN: '', dnsNames: [], uris: ['%zz'] },
      }),
    })) {
      assert.throws(() => buildRequest(r), Error, name);
    }
  });
});

// A case any denying fake passes.
function authDenied(): TestCase {
  return authCase('denied');
}

const asCase = (c: TestCase): Case => c as Case;

test('TestRunCaseHarness', async (t) => {
  const denial = new NativeDenial(DenialReason.NO_CREDENTIAL);
  const denying = authFake(ZERO_PRINCIPAL, denial);

  await t.test('factory error', async () => {
    const got = await runCase(async () => {
      throw new Error('no such state');
    }, asCase(authDenied()));
    wantFails(got, 'factory: no such state');
  });

  await t.test('factory panic', async () => {
    const got = await runCase(() => {
      throw new Error('boom');
    }, asCase(authDenied()));
    wantFails(got, 'factory panicked: boom');
  });

  await t.test('no adapter', async () => {
    const got = await runCase(() => ({}) as Subject, asCase(authDenied()));
    wantFails(got, 'no adapter');
  });

  await t.test('no arrive hook', async () => {
    const got = await runCase(() => ({ adapter: denying }) as Subject, asCase(authDenied()));
    wantFails(got, 'no arrive hook');
  });

  await t.test('no credential hook', async () => {
    const got = await runCase(() => ({ adapter: denying, arrive: (r) => r }), asCase(authDenied()));
    wantFails(got, 'no credential hook', '"alice"');
  });

  await t.test('credential error', async () => {
    const got = await runCase(
      () => ({
        adapter: denying,
        arrive: (r) => r,
        credential: () => {
          throw new Error('unknown ref');
        },
      }),
      asCase(authDenied()),
    );
    wantFails(got, 'unknown ref');
  });

  await t.test('arrive returns no request', async () => {
    const got = await runCase(
      () => ({
        adapter: denying,
        arrive: () => null as never,
        credential: (r) => r,
      }),
      asCase(authDenied()),
    );
    wantFails(got, 'the arrive hook returned no request');
  });

  await t.test('adapter panic', async () => {
    // A function that throws instead of returning a promise breaks the
    // contract, as a Go panic does.
    const a: Adapter = {
      ...fake(),
      authenticateNative: () => {
        throw new TypeError('nil map');
      },
    };
    wantFails(
      await runCase(factoryFor(a), asCase(authDenied())),
      'authenticateNative panicked: nil map',
    );
  });

  await t.test('arrive runs, unless the request is direct', async () => {
    const marked: boolean[] = [];
    const a = fake({
      auth: async (r) => {
        marked.push(header(r, 'X-Arrived') === '1');
        throw denial;
      },
    });
    const factory: Factory = () => ({
      adapter: a,
      arrive: (r) => withHeader(r, 'X-Arrived', '1'),
      credential: (r) => r,
    });
    const via = authDenied();
    const direct = authDenied();
    (direct.request as { arrival: string }).arrival = 'direct';
    for (const c of [via, direct]) wantClean(await runCase(factory, asCase(c)));
    assert.deepEqual(marked, [true, false]);
  });

  await t.test('env: state, clock, hooks', async () => {
    let env: Env | undefined;
    const factory: Factory = (e) => {
      env = e;
      return factoryFor(denying)(e);
    };
    const c = authDenied();
    c.native_state = new RawJSON('{"model":"x"}');
    wantClean(await runCase(factory, asCase(c)));
    assert.equal(env?.state.text, '{"model":"x"}');
    assert.equal(env?.clock.now(), NOW, 'the default now');
    assert.ok(env?.hooks !== undefined, 'hooks');

    const at = 1_900_000_000;
    c.now = at;
    wantClean(await runCase(factory, asCase(c)));
    assert.equal(env?.clock.now(), at * 1000);
    assert.ok(env?.clock instanceof FakeClock, 'the clock is a fake clock the suite holds');
  });

  await t.test('each case gets a fresh adapter and fresh hooks', async () => {
    const seen: Hooks[] = [];
    const factory: Factory = (e) => {
      seen.push(e.hooks);
      e.hooks.fire('execute');
      return factoryFor(denying)(e);
    };
    for (let i = 0; i < 2; i++) await runCase(factory, asCase(authDenied()));
    assert.equal(seen.length, 2);
    assert.notEqual(seen[0], seen[1]);
    assert.equal(seen[1]?.fired().length, 1);
  });

  await t.test('a call that never settles fails the case', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const a = fake({ auth: () => new Promise(() => {}) });
    const pending = runCase(factoryFor(a), asCase(authDenied()));
    await new Promise((resolve) => setImmediate(resolve));
    t.mock.timers.tick(10_000);
    wantFails(await pending, 'authenticateNative did not settle within 10 s');
  });
});

test('TestMustNotCall', async () => {
  const deny = authzFake({ effect: 'DENY', sourceId: 'policy-1' });
  const fires =
    (...names: string[]): Factory =>
    (e) => {
      for (const n of names) e.hooks.fire(n);
      return factoryFor(deny)(e);
    };
  const c = (...forbidden: string[]) => asCase(authzCase('DENY', { must_not_call: forbidden }));
  wantClean(await runCase(fires(), c('execute')));
  wantClean(await runCase(fires('audit'), c('execute')));
  wantClean(await runCase(fires('execute'), c()));
  wantFails(await runCase(fires('execute'), c('execute')), 'hook "execute" fired');
  wantFails(
    await runCase(fires('audit', 'execute'), c('grant', 'execute')),
    'hook "execute" fired',
  );
});

test('TestRunAndEvaluate', async (t) => {
  const fixtures = treeOf({
    'adapters/_common/a.json': minimalCase,
    'adapters/_common/b.json': minimalCase
      .replace('COMMON-01.one', 'COMMON-01.two')
      .replace('"denied"', '"error"'),
  });
  const denying = authFake(ZERO_PRINCIPAL, new NativeDenial(DenialReason.NO_CREDENTIAL));

  await t.test('evaluate', async () => {
    let res = await evaluateConformance(factoryFor(denying), { fixtures });
    assert.equal(res.length, 2);
    assert.equal(res[0]?.id, 'COMMON-01.one');
    assert.ok(res[0]?.passed());
    res = await evaluateConformance(factoryFor(authFake(goodPrincipal())), { fixtures });
    for (const r of res)
      assert.ok(!r.passed(), `${r.id} passes against an adapter that authenticates everyone`);
  });

  await t.test('evaluate reports a load error', async () => {
    await assert.rejects(evaluateConformance(factoryFor(denying), { fixtures: treeOf({}) }));
  });

  await t.test('run passes when the adapter does', async (t) => {
    await runConformance(t, factoryFor(denying), {
      fixtures: treeOf({ 'adapters/_common/a.json': minimalCase }),
    });
  });
});

// A case marked "shared" runs only when the adapter's profile supports
// workloads shared by several agents, one marked "dedicated" only when it
// does not, and an unmarked case in both runs.
test('TestWorkloadModes', async (t) => {
  const mark = (id: string, mode: string, outcome: string): string => {
    let s = minimalCase.replace('COMMON-01.one', id).replace('"denied"', `"${outcome}"`);
    if (mode !== '')
      s = s.replace('"title": "A case",', `"title": "A case", "workloads": "${mode}",`);
    return s;
  };
  // The denying adapter fails the cases that expect an error, so a case that
  // runs in the wrong mode fails the run below.
  const fixtures = treeOf({
    'adapters/_common/a.json': mark('COMMON-01.both', '', 'denied'),
    'adapters/_common/b.json': mark('COMMON-01.shared', 'shared', 'error'),
    'adapters/_common/c.json': mark('COMMON-01.dedicated', 'dedicated', 'error'),
    'adapters/_common/d.json': mark('COMMON-01.shared-denied', 'shared', 'denied'),
    'adapters/_common/e.json': mark('COMMON-01.dedicated-denied', 'dedicated', 'denied'),
  });
  const denying = authFake(ZERO_PRINCIPAL, new NativeDenial(DenialReason.NO_CREDENTIAL));
  for (const [name, shared, want] of [
    [
      'dedicated by default',
      false,
      ['COMMON-01.both', 'COMMON-01.dedicated', 'COMMON-01.dedicated-denied'],
    ],
    ['shared', true, ['COMMON-01.both', 'COMMON-01.shared', 'COMMON-01.shared-denied']],
  ] as const) {
    await t.test(name, async () => {
      const res = await evaluateConformance(factoryFor(denying), {
        fixtures,
        sharedWorkloads: shared,
      });
      assert.deepEqual(res.map((r) => r.id).sort(), want);
    });
  }
  await t.test('run skips the cases of the other mode', async (t) => {
    await runConformance(t, factoryFor(denying), {
      fixtures: treeOf({
        'adapters/_common/a.json': mark('COMMON-01.both', '', 'denied'),
        'adapters/_common/b.json': mark('COMMON-01.shared', 'shared', 'error'),
        'adapters/_common/d.json': mark('COMMON-01.dedicated-denied', 'dedicated', 'denied'),
      }),
    });
    await runConformance(t, factoryFor(denying), {
      fixtures: treeOf({
        'adapters/_common/a.json': mark('COMMON-01.both', '', 'denied'),
        'adapters/_common/c.json': mark('COMMON-01.dedicated', 'dedicated', 'error'),
        'adapters/_common/e.json': mark('COMMON-01.shared-denied', 'shared', 'denied'),
      }),
      sharedWorkloads: true,
    });
  });
});

test('TestDefaultFixtures', (t) => {
  if (!fixturesPresent(t)) return;
  const cases = loadCases(defaultFixtures());
  assert.ok(cases.length > 0, 'the default fixture tree has no common cases');
});

// The zero-value stub of every function (Go: a fake with nothing set) fails
// every common case in both workload modes: no case passes an adapter that
// answers nothing.
test('a stub adapter fails every common case', async (t) => {
  if (!fixturesPresent(t)) return;
  const all = loadCases(defaultFixtures());
  for (const shared of [false, true]) {
    const res = await evaluateConformance(factoryFor(fake()), { sharedWorkloads: shared });
    const want = all.filter((c) => c.workloads !== (shared ? 'dedicated' : 'shared')).length;
    assert.equal(res.length, want, `cases run with sharedWorkloads ${shared}`);
    const passing = res.filter((r) => r.passed()).map((r) => r.id);
    assert.deepEqual(passing, [], `cases the stub passes with sharedWorkloads ${shared}`);
  }
});

// The published module imports node:test as a type only: no runtime import
// of a test framework anywhere under src/adapter/adaptertest.
test('the adaptertest module loads no test framework', () => {
  const dir = join(PACKAGE, 'src', 'adapter', 'adaptertest');
  for (const f of readdirSync(dir)) {
    const text = readFileSync(join(dir, f), 'utf8');
    for (const m of text.matchAll(/^import\s+(type\s+)?[^;]*?from\s+'([^']+)'/gms)) {
      const typeOnly = m[1] !== undefined;
      const spec = m[2] as string;
      if (spec === 'node:test' || spec === 'node:assert' || spec.startsWith('node:assert/')) {
        assert.ok(typeOnly, `${f} imports ${spec} at run time`);
      }
    }
    assert.doesNotMatch(text, /import\(\s*'node:test'\s*\)|require\(\s*'node:test'\s*\)/, f);
  }
});

test('a replaced case of an invalid declaration rejects before any case runs', async (t) => {
  let built = 0;
  await assert.rejects(
    runConformance(
      t,
      () => {
        built++;
        return factoryFor(fake())(undefined as never);
      },
      {
        fixtures: treeOf({ 'adapters/_common/a.json': minimalCase }),
        replaced: { 'COMMON-01.none': { by: 'X-01', reason: 'r' } },
      },
    ),
    /is not a common case/,
  );
  assert.equal(built, 0);
});
