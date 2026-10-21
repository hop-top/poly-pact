// Port of go/adapter/adaptertest/checks_identity_test.go and
// attributes_test.go: the authenticate_native and resolve_agent_binding
// checks. The Go rows of a value returned together with an error have no
// counterpart: a rejected promise carries no value.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  AdapterError,
  type AgentBinding,
  BindingStatus,
  DenialReason,
  NativeDenial,
  type Principal,
  type Realm,
} from '../src/adapter/index.ts';
import type { Digest } from '../src/core/values.ts';
import { RawJSON } from '../src/core/values.ts';
import {
  acme,
  acmeJS,
  authCase,
  authFake,
  bindCase,
  bindFake,
  fake,
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
  ZERO_PRINCIPAL,
} from './support/adaptertest.ts';

const wrap = (msg: string, cause: unknown) => new Error(msg, { cause });

test('TestAuthenticateChecks', async (t) => {
  const good = goodPrincipal();
  const want = {
    id: good.id,
    realm: acmeJS,
    workload: 'w-1',
    mechanism: 'bearer',
    attributes: null,
  };
  const principal = { principal: want };
  const w = (f: (p: { -readonly [K in keyof Principal]: Principal[K] }) => void): Principal => {
    const p = { ...good, realm: { ...good.realm } };
    f(p);
    return p;
  };
  const denial = new NativeDenial(DenialReason.NO_CREDENTIAL);
  const rows: Row[] = [
    ['authenticated', authFake(good), authCase('authenticated', principal), null],
    [
      'authenticated but rejects',
      authFake(ZERO_PRINCIPAL, denial),
      authCase('authenticated', principal),
      ['want an authenticated principal'],
    ],
    [
      'wrong id',
      authFake(
        w((p) => {
          p.id = 'other';
        }),
      ),
      authCase('authenticated', principal),
      ['principal id'],
    ],
    [
      'wrong tenant',
      authFake({ ...good, realm: { ...acme, tenantId: 'globex' } }),
      authCase('authenticated', principal),
      ['principal realm'],
    ],
    [
      'wrong environment',
      authFake({ ...good, realm: { ...acme, environmentId: 'other' } }),
      authCase('authenticated', principal),
      ['principal realm'],
    ],
    [
      'wrong workload',
      authFake(
        w((p) => {
          p.workload = 'w-2';
        }),
      ),
      authCase('authenticated', principal),
      ['principal workload'],
    ],
    [
      'wrong mechanism',
      authFake(
        w((p) => {
          p.mechanism = 'mtls';
        }),
      ),
      authCase('authenticated', principal),
      ['principal mechanism'],
    ],
    [
      'authenticated in the future',
      authFake(
        w((p) => {
          p.authenticatedAt = NOW + MINUTE;
        }),
      ),
      authCase('authenticated', principal),
      ['authenticatedAt'],
    ],
    [
      'authenticated at the skew edge',
      authFake(
        w((p) => {
          p.authenticatedAt = NOW + SKEW;
        }),
      ),
      authCase('authenticated', principal),
      null,
    ],
    [
      'zero principal without error',
      authFake(ZERO_PRINCIPAL),
      authCase('authenticated', {
        principal: { ...want, id: '', realm: null, workload: '', mechanism: '' },
      }),
      ['zero principal'],
    ],

    [
      'denied',
      authFake(ZERO_PRINCIPAL, denial),
      authCase('denied', { reason_code: 'NO_CREDENTIAL' }),
      null,
    ],
    [
      'denied through wrapping',
      authFake(ZERO_PRINCIPAL, wrap('authn', denial)),
      authCase('denied', { reason_code: 'NO_CREDENTIAL' }),
      null,
    ],
    ['denied but authenticated', authFake(good), authCase('denied'), ['want a native denial']],
    [
      'denied with a plain error',
      authFake(ZERO_PRINCIPAL, new Error('no')),
      authCase('denied'),
      ['want a NativeDenial'],
    ],
    [
      'denied with the wrong reason',
      authFake(ZERO_PRINCIPAL, new NativeDenial(DenialReason.CREDENTIAL_REJECTED)),
      authCase('denied', { reason_code: 'NO_CREDENTIAL' }),
      ['denial reason is CREDENTIAL_REJECTED'],
    ],
    [
      'denied with free text is a rejection',
      authFake(ZERO_PRINCIPAL, new NativeDenial('user alice unknown')),
      authCase('denied', { reason_code: 'NO_CREDENTIAL' }),
      ['denial reason is CREDENTIAL_REJECTED'],
    ],
    [
      'denial inside an error of another code',
      authFake(ZERO_PRINCIPAL, AdapterError.contextMismatch('x', { cause: denial })),
      authCase('denied'),
      ['denial code is "CONTEXT_MISMATCH"'],
    ],

    [
      'error with a code',
      authFake(ZERO_PRINCIPAL, wrap('x', AdapterError.dependencyUnavailable())),
      authCase('error', { reason_code: 'DEPENDENCY_UNAVAILABLE' }),
      null,
    ],
    ['error expected, none returned', authFake(good), authCase('error'), ['want an error']],
    [
      'error with the wrong code',
      authFake(ZERO_PRINCIPAL, AdapterError.contextMismatch()),
      authCase('error', { reason_code: 'DEPENDENCY_UNAVAILABLE' }),
      ['error code is CONTEXT_MISMATCH'],
    ],
    [
      'error without a code',
      authFake(ZERO_PRINCIPAL, new Error('boom')),
      authCase('error', { reason_code: 'DEPENDENCY_UNAVAILABLE' }),
      ['carries no draft 13.4 code'],
    ],
  ];
  await runRows(t, rows);
});

const AGENT = 'https://identity.example/agents/a';

// The suite hands resolveAgentBinding the realm, the workload and the agent
// ID of the call, unchanged (draft 17.1).
test('TestBindingCallArguments', async () => {
  let got: [Realm, string, string] | undefined;
  let calls = 0;
  const f = fake({
    bind: async (r, w, a) => {
      got = [r, w, a];
      calls++;
      return { ...goodBinding(), agentId: '', operatorId: '', holderJKT: '', status: 'UNKNOWN' };
    },
  });
  const c = bindCase('unknown');
  c.call.workload = 'k8s:prod-eu-1:system:serviceaccount:payments:agent-runner';
  c.call.agent_id = 'https://identity.example/agents/payments-runner-b';
  wantClean(await runFake(f, c));
  assert.equal(calls, 1);
  assert.deepEqual(got, [
    acme,
    'k8s:prod-eu-1:system:serviceaccount:payments:agent-runner',
    'https://identity.example/agents/payments-runner-b',
  ]);
});

function goodBinding(): AgentBinding {
  return {
    agentId: AGENT,
    operatorId: 'https://identity.example/operators/o',
    holderJKT: 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M' as Digest,
    status: BindingStatus.ACTIVE,
    observedAt: NOW - HOUR,
    statusCheckedAt: NOW - MINUTE,
    sourceId: 'registry',
    sourceRef: '',
    enrolledElsewhere: false,
  };
}

const UNKNOWN = { status: BindingStatus.UNKNOWN } as const;

test('TestBindingChecks', async (t) => {
  const good = goodBinding();
  const rec = (status: string) => ({
    agent_id: good.agentId,
    operator_id: good.operatorId,
    holder_jkt: good.holderJKT,
    status,
    enrolled_elsewhere: null,
  });
  const loose = {
    binding: {
      agent_id: '',
      operator_id: '',
      holder_jkt: '',
      status: '',
      enrolled_elsewhere: null,
    },
  };
  const only = (m: Record<string, string>) => ({ binding: { ...loose.binding, ...m } });
  const wantBound = { binding: rec('ACTIVE') };
  const wantRevoked = { binding: rec('REVOKED') };
  const wantCompromised = { binding: rec('COMPROMISED') };
  const w = (m: Partial<AgentBinding>): AgentBinding => ({ ...good, ...m });
  const revoked = w({ status: BindingStatus.REVOKED });
  const compromised = w({ status: BindingStatus.COMPROMISED });
  const boundErr = wrap('binding', AdapterError.invalidProof());

  const rows: Row[] = [
    ['bound', bindFake(good), bindCase('bound', wantBound), null],
    [
      'bound but rejects',
      bindFake({}, boundErr),
      bindCase('bound', wantBound),
      ['want an active binding'],
    ],
    ['bound but revoked', bindFake(revoked), bindCase('bound', wantBound), ['want ACTIVE']],
    // The status alone, with no status pinned by the case.
    [
      'bound but revoked, status not pinned',
      bindFake(revoked),
      bindCase('bound', loose),
      ['want ACTIVE'],
    ],
    [
      'agent id is not a URI',
      bindFake(w({ agentId: 'agent-1' })),
      bindCase('bound', loose),
      ['not an absolute URI'],
    ],
    [
      'holder key is not a thumbprint',
      bindFake(w({ holderJKT: 'short' as Digest })),
      bindCase('bound', loose),
      ['holder key thumbprint'],
    ],
    ['no source', bindFake(w({ sourceId: '' })), bindCase('bound', loose), ['names no source']],
    [
      'observed in the future',
      bindFake(w({ observedAt: NOW + HOUR })),
      bindCase('bound', loose),
      ['binding observedAt'],
    ],
    // Draft A.2: no status-check time may be later than now plus the skew.
    [
      'status checked past the skew',
      bindFake(w({ statusCheckedAt: NOW + SKEW + SECOND })),
      bindCase('bound', loose),
      ['binding statusCheckedAt'],
    ],
    [
      'status checked at the skew edge',
      bindFake(w({ statusCheckedAt: NOW + SKEW })),
      bindCase('bound', loose),
      null,
    ],
    [
      'wrong agent',
      bindFake(good),
      bindCase('bound', only({ agent_id: 'https://other.example/a' })),
      ['agent id is'],
    ],
    [
      'wrong operator',
      bindFake(good),
      bindCase('bound', only({ operator_id: 'https://other.example/o' })),
      ['operator id is'],
    ],
    [
      'wrong holder key',
      bindFake(good),
      bindCase('bound', only({ holder_jkt: 'yy0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M' })),
      ['holder key thumbprint is'],
    ],
    [
      'undefined status',
      bindFake(w({ status: 'SUSPENDED' as BindingStatus })),
      bindCase('bound', loose),
      ['not a defined status'],
    ],

    ['not enrolled', bindFake(UNKNOWN), bindCase('unknown'), null],
    ['not enrolled but active', bindFake(good), bindCase('unknown'), ['want UNKNOWN']],
    [
      'not enrolled but rejects',
      bindFake({}, boundErr),
      bindCase('unknown'),
      ['status UNKNOWN with no error'],
    ],
    [
      'not enrolled but names an agent',
      bindFake(w({ status: BindingStatus.UNKNOWN })),
      bindCase('unknown'),
      ['names agent'],
    ],

    // Identity mapping IM-11: a REVOKED or COMPROMISED binding comes back as
    // its status, with the agent, operator and holder key of the record, and
    // no error.
    ['unusable as REVOKED', bindFake(revoked), bindCase('unusable', wantRevoked), null],
    ['unusable as COMPROMISED', bindFake(compromised), bindCase('unusable', wantCompromised), null],
    [
      'unusable as an error',
      bindFake({}, boundErr),
      bindCase('unusable', wantRevoked),
      ['want the binding with status REVOKED', 'IM-11'],
    ],
    [
      'unusable but ACTIVE',
      bindFake(good),
      bindCase('unusable', wantRevoked),
      ['returned an ACTIVE binding'],
    ],
    [
      'unusable but UNKNOWN',
      bindFake(UNKNOWN),
      bindCase('unusable', wantRevoked),
      ['want REVOKED or COMPROMISED'],
    ],
    [
      'unusable as unavailable',
      bindFake({}, wrap('x', AdapterError.dependencyUnavailable())),
      bindCase('unusable', wantRevoked),
      ['unavailable source'],
    ],
    [
      'unusable with the wrong status',
      bindFake(revoked),
      bindCase('unusable', wantCompromised),
      ['binding status is REVOKED, want COMPROMISED'],
    ],
    [
      'unusable status without the agent',
      bindFake(w({ status: BindingStatus.REVOKED, agentId: '' })),
      bindCase('unusable', only({ status: 'REVOKED' })),
      ['not an absolute URI'],
    ],
    [
      'unusable status without the holder key',
      bindFake(w({ status: BindingStatus.REVOKED, holderJKT: '' })),
      bindCase('unusable', only({ status: 'REVOKED' })),
      ['holder key thumbprint'],
    ],
    [
      'unusable status that names no source',
      bindFake(w({ status: BindingStatus.REVOKED, sourceId: '' })),
      bindCase('unusable', only({ status: 'REVOKED' })),
      ['names no source'],
    ],
    [
      'unusable status checked past the skew',
      bindFake(w({ status: BindingStatus.REVOKED, statusCheckedAt: NOW + SKEW + SECOND })),
      bindCase('unusable', only({ status: 'REVOKED' })),
      ['binding statusCheckedAt'],
    ],
    [
      'unusable status of another agent',
      bindFake(w({ status: BindingStatus.REVOKED, agentId: 'https://identity.example/agents/b' })),
      bindCase('unusable', wantRevoked),
      ['agent id is'],
    ],
    [
      'unusable status with another operator',
      bindFake(
        w({ status: BindingStatus.REVOKED, operatorId: 'https://identity.example/operators/p' }),
      ),
      bindCase('unusable', wantRevoked),
      ['operator id is'],
    ],
    [
      'unusable status with another key',
      bindFake(
        w({
          status: BindingStatus.REVOKED,
          holderJKT: 'lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU' as Digest,
        }),
      ),
      bindCase('unusable', wantRevoked),
      ['holder key thumbprint is'],
    ],

    ['error', bindFake({}, boundErr), bindCase('error', { reason_code: 'INVALID_PROOF' }), null],
    ['error expected, binding returned', bindFake(good), bindCase('error'), ['want an error']],
  ];
  await runRows(t, rows);
});

// Draft 17.1 has UNKNOWN come with whether the agent ID is enrolled for
// another workload of the realm. A case can require the value; the suite
// requires it false for every result that is not an UNKNOWN.
test('TestBindingEnrolledElsewhere', async (t) => {
  const elsewhere = { status: BindingStatus.UNKNOWN, enrolledElsewhere: true };
  const good = goodBinding();
  const revoked = { ...good, status: BindingStatus.REVOKED };
  const want = (v: boolean | null) => ({
    binding: { agent_id: '', operator_id: '', holder_jkt: '', status: '', enrolled_elsewhere: v },
  });
  const wantRecord = (status: string, v: boolean | null) => ({
    binding: {
      agent_id: good.agentId,
      operator_id: good.operatorId,
      holder_jkt: good.holderJKT,
      status,
      enrolled_elsewhere: v,
    },
  });
  const rows: Row[] = [
    [
      'unknown, enrolled elsewhere as required',
      bindFake(elsewhere),
      bindCase('unknown', want(true)),
      null,
    ],
    [
      'unknown, not enrolled elsewhere as required',
      bindFake(UNKNOWN),
      bindCase('unknown', want(false)),
      null,
    ],
    [
      'unknown, enrolled elsewhere not reported',
      bindFake(UNKNOWN),
      bindCase('unknown', want(true)),
      ['enrolled for another workload is false, want true'],
    ],
    [
      'unknown, enrolled elsewhere reported wrongly',
      bindFake(elsewhere),
      bindCase('unknown', want(false)),
      ['enrolled for another workload is true, want false'],
    ],
    ['unknown, not required either way', bindFake(elsewhere), bindCase('unknown'), null],
    [
      'bound, false as required',
      bindFake(good),
      bindCase('bound', wantRecord('ACTIVE', false)),
      null,
    ],
    [
      'bound with the flag',
      bindFake({ ...good, enrolledElsewhere: true }),
      bindCase('bound', wantRecord('ACTIVE', null)),
      ['status ACTIVE reports the agent ID enrolled for another workload'],
    ],
    [
      'unusable with the flag',
      bindFake({ ...revoked, enrolledElsewhere: true }),
      bindCase('unusable', wantRecord('REVOKED', null)),
      ['status REVOKED reports the agent ID enrolled for another workload'],
    ],
  ];
  await runRows(t, rows);
});

test('TestPrincipalAttributes', async (t) => {
  const w = (attributes: Record<string, unknown>): Principal => ({
    ...goodPrincipal(),
    attributes,
  });
  const want = (raw: string | null) => ({
    principal: {
      id: goodPrincipal().id,
      realm: null,
      workload: '',
      mechanism: '',
      attributes: raw === null ? null : new RawJSON(raw),
    },
  });
  const cnf = { jkt: 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M' };
  const wantCnf = '{"cnf": {"jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}';
  const rows: Row[] = [
    ['equal', authFake(w({ cnf })), authCase('authenticated', want(wantCnf)), null],
    [
      'unnamed attribute not checked',
      authFake(w({ cnf, groups: ['a'] })),
      authCase('authenticated', want(wantCnf)),
      null,
    ],
    [
      'member order ignored',
      authFake(w({ x: { a: 1, b: 2 } })),
      authCase('authenticated', want('{"x": {"b": 2, "a": 1}}')),
      null,
    ],
    [
      'other value',
      authFake(w({ cnf: { jkt: 'other' } })),
      authCase('authenticated', want(wantCnf)),
      ['principal attribute "cnf"'],
    ],
    [
      'missing attribute',
      authFake(w({})),
      authCase('authenticated', want('{"cnf": {"jkt": "a"}}')),
      ['principal has no attribute "cnf"'],
    ],
    [
      'array order kept',
      authFake(w({ groups: ['b', 'a'] })),
      authCase('authenticated', want('{"groups": ["a", "b"]}')),
      ['principal attribute "groups"'],
    ],
    [
      'absent member not checked',
      authFake(w({ cnf })),
      authCase('authenticated', want(null)),
      null,
    ],
  ];
  await runRows(t, rows);
});
