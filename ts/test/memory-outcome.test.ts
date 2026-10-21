// Port of TestRecordOutcome of go/adapters/memory/memory_unit_test.go:
// recordOutcome signs outcome reports with the ephemeral ES256 key of the
// instance, under the role of what it observes, declares no visibility for
// executions it does not see, and removes credentials.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Code,
  codeOf,
  NoVisibility,
  type Observation,
  type Recorded,
  Signed,
} from '../src/adapter/index.ts';
import type { MemoryAdapter } from '../src/adapters/memory/index.ts';
import type { EventKind } from '../src/core/enums.ts';
import type { OutcomeReport, ReputationContext } from '../src/core/types.ts';
import { ENV, newAdapter, SEC, T0 } from './support/memory.ts';

const CTXT: ReputationContext = {
  tenant_id: 'acme',
  environment_id: ENV,
  agent_id: 'https://identity.example/agents/a',
  purpose_id: 'p',
  action_class: 'a',
  resource_class: 'r',
  runtime_class: 'managed',
};

function obs(kind: EventKind, m: Partial<Observation> = {}): Observation {
  return {
    eventId: 'event-1',
    eventKind: kind,
    context: CTXT,
    taskId: 'task-1',
    operationId: 'op-1',
    admissionReceiptId: null,
    observedAt: T0 - 5000,
    result: 'SUCCESS',
    dimension: 'reliability',
    severity: 'info',
    evidenceRefs: [],
    attribution: {
      native_task_ref: 'task-1',
      independence_group: 'g',
      causal_assessment: 'UNKNOWN',
      assessment_ref: null,
    },
    supersedes: [],
    details: '',
    ...m,
  };
}

const segment = (s: string) => Buffer.from(s, 'base64url');

function payload(r: Recorded): OutcomeReport {
  assert.ok(r instanceof Signed, `recorded ${String(r)}, want Signed`);
  return JSON.parse(segment(r.jws.split('.')[1] as string).toString('utf8')) as OutcomeReport;
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  return undefined;
}

test('TestRecordOutcome', async (t) => {
  const { a, clock } = newAdapter();
  const rec = (adapter: MemoryAdapter, o: Observation, signal?: AbortSignal) =>
    adapter.recordOutcome(o, signal);

  await t.test('roles by kind', async () => {
    for (const [kind, role] of [
      ['ADMISSION', 'gateway'],
      ['AUTHORIZATION', 'gateway'],
      ['EXECUTION', 'executor'],
    ] as const) {
      const r = await rec(a, obs(kind));
      const rep = payload(r);
      assert.deepEqual([rep.reporter_role, rep.event_kind], [role, kind]);
      assert.doesNotThrow(() => a.verifyOutcome((r as Signed).jws), kind);
    }
  });

  await t.test('report fields', async () => {
    const rep = payload(await rec(a, obs('EXECUTION')));
    assert.deepEqual([rep.iat, rep.nbf, rep.exp, rep.observed_at], [SEC, SEC, SEC + 300, SEC - 5]);
    assert.deepEqual(
      [rep.iss, rep.aud, rep.sub, rep.tenant_id],
      [
        'https://gateway.example/reporters/finance',
        'https://reputation.example/',
        CTXT.agent_id,
        'acme',
      ],
    );
    assert.deepEqual([rep.evidence_refs, rep.supersedes, rep.jti.length], [[], [], 22]);
    clock.advance(60 * 60 * 1000);
    assert.equal(payload(await rec(a, obs('EXECUTION'))).iat, SEC + 3600, 'iat follows the clock');
    clock.advance(-60 * 60 * 1000);
  });

  await t.test('a retry carries the same jti', async () => {
    const j1 = payload(await rec(a, obs('ADMISSION'))).jti;
    const j2 = payload(await rec(a, obs('ADMISSION'))).jti;
    const j3 = payload(await rec(a, obs('ADMISSION', { eventId: 'event-2' }))).jti;
    assert.equal(j1, j2);
    assert.notEqual(j1, j3, 'jti is a function of the event id');
  });

  await t.test('no execution visibility', async () => {
    for (const vis of ['none', '']) {
      const { a } = newAdapter((st) => {
        st.visibility = vis;
      });
      for (const result of ['SUCCESS', 'FAILURE', 'UNKNOWN'] as const) {
        const r = await rec(a, obs('EXECUTION', { result }));
        assert.ok(r instanceof NoVisibility, `visibility ${JSON.stringify(vis)}, result ${result}`);
        assert.doesNotThrow(() => r.validate());
      }
    }
    const { a: blind } = newAdapter((st) => {
      st.visibility = 'none';
    });
    assert.ok(
      (await rec(blind, obs('ADMISSION'))) instanceof Signed,
      'admission without execution visibility',
    );
  });

  await t.test('refusals', async () => {
    const other = obs('ADMISSION', { context: { ...CTXT, tenant_id: 'globex' } });
    assert.equal(codeOf(await rejection(rec(a, other))), Code.CONTEXT_MISMATCH, 'another tenant');
    const env = obs('ADMISSION', { context: { ...CTXT, environment_id: 'other' } });
    assert.equal(
      codeOf(await rejection(rec(a, env))),
      Code.CONTEXT_MISMATCH,
      'another environment',
    );
    assert.ok(
      (await rejection(rec(a, obs('ADMISSION', { eventId: '' })))) !== undefined,
      'no event id',
    );
    for (const kind of ['QUALITY', 'SECURITY', 'FEEDBACK', 'CORRECTION', 'REMEDIATION'] as const) {
      assert.equal(codeOf(await rejection(rec(a, obs(kind)))), Code.UNSUPPORTED_REQUIREMENT, kind);
    }
    const { a: unsigned } = newAdapter((st) => {
      st.reporting = null;
    });
    assert.equal(
      codeOf(await rejection(rec(unsigned, obs('ADMISSION')))),
      Code.UNSUPPORTED_REQUIREMENT,
      'no reporting key',
    );
    assert.throws(() => unsigned.verifyOutcome('a.b.c'), Error, 'verifyOutcome with no key');
    assert.equal(
      codeOf(await rejection(rec(a, obs('ADMISSION'), AbortSignal.abort()))),
      Code.DEPENDENCY_UNAVAILABLE,
      'aborted',
    );
  });

  await t.test('credentials are removed', async () => {
    const o = obs('EXECUTION', {
      details:
        'rejected: Authorization: Bearer tok-alice-secret-1 and tok-bob-secret-2 inline\n' +
        'Cookie: session=abcdef123456; other=1\nset-cookie: sid=zzzzzzzz\nCookie: sc=cookievalue9999; plain=1\n' +
        'pact-presentation: eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln\nbasic dXNlcjpwYXNzd29yZA==\n' +
        'token eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln and password=hunter22 api_key=abcdef12',
      evidenceRefs: [
        'native-record:1',
        'https://e.example/x?access_token=abc123456&keep=1',
        'tok-alice-secret-1',
      ],
    });
    const rep = payload(await rec(a, o));
    const text = `${rep.details}\n${rep.evidence_refs.join('\n')}`;
    for (const secret of [
      'tok-alice-secret-1',
      'tok-bob-secret-2',
      'abcdef123456',
      'zzzzzzzz',
      'cookievalue9999',
      'eyJhbGci',
      'dXNlcjpwYXNzd29yZA',
      'hunter22',
      'abcdef12',
      'abc123456',
    ]) {
      assert.ok(!text.includes(secret), `${secret} survived in ${text}`);
    }
    assert.equal(
      rep.evidence_refs[0],
      'native-record:1',
      'a reference without a credential was changed',
    );
    assert.match(rep.evidence_refs[1] as string, /keep=1/);
    assert.match(rep.details, /rejected:/, 'the free text was dropped');
  });

  await t.test('signature', async () => {
    const r = (await rec(a, obs('ADMISSION'))) as Signed;
    const parts = r.jws.split('.');
    const tamper = (i: number) => {
      const p = [...parts];
      const raw = segment(p[i] as string);
      raw[Math.floor(raw.length / 2)] = (raw[Math.floor(raw.length / 2)] as number) ^ 1;
      p[i] = raw.toString('base64url');
      return p.join('.');
    };
    assert.doesNotThrow(() => a.verifyOutcome(r.jws));
    for (const bad of [
      tamper(0),
      tamper(1),
      tamper(2),
      'a.b',
      'a.b.c',
      `${parts[0]}.${parts[1]}.`,
      `${parts.slice(0, 2).join('.')}.${Buffer.alloc(64).toString('base64url')}`,
    ]) {
      assert.throws(
        () => a.verifyOutcome(bad),
        Error,
        `verifyOutcome accepted ${bad.slice(0, 40)}`,
      );
    }
    const { a: other } = newAdapter();
    assert.throws(
      () => other.verifyOutcome(r.jws),
      Error,
      "a report verifies under another adapter's key",
    );
    const hdr = JSON.parse(segment(parts[0] as string).toString('utf8')) as Record<string, string>;
    assert.deepEqual(hdr, { alg: 'ES256', typ: 'pact-outcome+jwt', kid: 'k1' });
    assert.equal(segment(parts[2] as string).length, 64, 'the 64 octets of an ES256 R||S');
  });
});
