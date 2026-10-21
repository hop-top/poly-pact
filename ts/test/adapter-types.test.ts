// Port of go/adapter/types_test.go. The Go tests pin the fields of every
// value type by reflection; here the compiler pins the members and their
// types (assertType), and the run pins the enum values and the methods.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type AgentBinding,
  BindingStatus,
  type CheckInput,
  type CheckOutcome,
  type ClaimContext,
  Decision,
  DenialReason,
  type Descriptor,
  Effect,
  isBindingStatus,
  isDenialReason,
  isEffect,
  isVerdict,
  type NativeClaim,
  type NativeDenial,
  type NoVisibility,
  type Obligation,
  type Observation,
  type Principal,
  type Realm,
  type Signed,
  Verdict,
} from '../src/adapter/index.ts';
import { CheckStatus } from '../src/core/enums.ts';
import type { Digest } from '../src/core/values.ts';
import type {
  Attribution,
  Dimension,
  EventKind,
  Intent,
  OperationContext,
  OutcomeResult,
  ReputationContext,
  Severity,
} from '../src/index.ts';
import { assertType, type Equal } from './support/types.ts';

// The shape of every exported value type, written from the contract of the
// section 17.1 functions: adding, dropping or retyping a member is a
// contract change and must change this table.
assertType<Equal<Realm, { readonly tenantId: string; readonly environmentId: string }>>();
assertType<
  Equal<
    Principal,
    {
      readonly id: string;
      readonly realm: Realm;
      readonly workload: string;
      readonly mechanism: string;
      readonly authenticatedAt: number | null;
      readonly attributes: Readonly<Record<string, unknown>>;
    }
  >
>();
assertType<Equal<NativeDenial['reason'], string>>();
assertType<
  Equal<
    AgentBinding,
    {
      readonly agentId: string;
      readonly operatorId: string;
      readonly holderJKT: Digest | '';
      readonly status: BindingStatus;
      readonly observedAt: number | null;
      readonly statusCheckedAt: number | null;
      readonly sourceId: string;
      readonly sourceRef: string;
      readonly enrolledElsewhere: boolean;
    }
  >
>();
assertType<
  Equal<
    NativeClaim,
    {
      readonly value: unknown;
      readonly observedAt: number | null;
      readonly statusCheckedAt: number | null;
      readonly sourceId: string;
      readonly sourceRef: string;
    }
  >
>();
assertType<
  Equal<
    CheckOutcome,
    {
      readonly result: Verdict;
      readonly reasonCode: string;
      readonly sourceId: string;
      readonly sourceRef: string;
      readonly observedAt: number | null;
    }
  >
>();
assertType<
  Equal<
    ClaimContext,
    { readonly principal: Principal; readonly intent: Intent; readonly operation: OperationContext }
  >
>();
assertType<
  Equal<
    CheckInput,
    {
      readonly principal: Principal;
      readonly binding: AgentBinding | null;
      readonly intent: Intent;
      readonly operation: OperationContext;
      readonly evidenceRefs: readonly string[];
    }
  >
>();
assertType<
  Equal<
    Decision,
    {
      readonly effect: Effect;
      readonly obligations: readonly Obligation[];
      readonly reason: string;
      readonly sourceId: string;
      readonly sourceRef: string;
      readonly decidedAt: number | null;
      readonly policyRevision: string;
    }
  >
>();
assertType<
  Equal<Obligation, { readonly id: string; readonly attributes: Readonly<Record<string, unknown>> }>
>();
assertType<
  Equal<
    Observation,
    {
      readonly eventId: string;
      readonly eventKind: EventKind;
      readonly context: ReputationContext;
      readonly taskId: string;
      readonly operationId: string;
      readonly admissionReceiptId: string | null;
      readonly observedAt: number | null;
      readonly result: OutcomeResult;
      readonly dimension: Dimension;
      readonly severity: Severity;
      readonly evidenceRefs: readonly string[];
      readonly attribution: Attribution;
      readonly supersedes: readonly string[];
      readonly details: string;
    }
  >
>();
assertType<Equal<Signed['jws'], string>>();
assertType<Equal<NoVisibility['reason'], string>>();
assertType<
  Equal<
    Descriptor,
    { readonly protocol: string; readonly version: string; readonly mappingRevision: string }
  >
>();

test('TestStructFields', () => {
  // The members are pinned at compile time above; a value of each type with
  // every member compiles only with exactly these members.
  const realm: Realm = { tenantId: 't', environmentId: 'e' };
  const d: Descriptor = { protocol: 'mcp', version: 'v', mappingRevision: 'r' };
  assert.deepEqual(Object.keys(realm), ['tenantId', 'environmentId']);
  assert.deepEqual(Object.keys(d), ['protocol', 'version', 'mappingRevision']);
});

// A denial is final by construction: besides the effect, the obligations and
// the reason, a decision carries only its provenance.
test('TestDecisionHasNoOverride', () => {
  assertType<
    Equal<
      keyof Decision,
      | 'effect'
      | 'obligations'
      | 'reason'
      | 'sourceId'
      | 'sourceRef'
      | 'decidedAt'
      | 'policyRevision'
    >
  >();
  assert.deepEqual(Object.keys(Decision), ['permits']);
});

test('TestEnums', async (t) => {
  const rows: readonly {
    name: string;
    table: Readonly<Record<string, unknown>>;
    valid: Readonly<Record<string, string>>;
    guard: (x: unknown) => boolean;
    bogus: readonly unknown[];
  }[] = [
    {
      name: 'BindingStatus',
      table: BindingStatus,
      valid: {
        ACTIVE: 'ACTIVE',
        REVOKED: 'REVOKED',
        COMPROMISED: 'COMPROMISED',
        UNKNOWN: 'UNKNOWN',
      },
      guard: isBindingStatus,
      bogus: ['', 'active', 'SUSPENDED', undefined, 1],
    },
    {
      name: 'Verdict',
      table: Verdict,
      valid: { PASS: 'PASS', FAIL: 'FAIL', UNKNOWN: 'UNKNOWN' },
      guard: isVerdict,
      bogus: ['', 'pass', 'NOT_APPLICABLE', 'checkStatus', null],
    },
    {
      name: 'Effect',
      table: Effect,
      valid: { ALLOW: 'ALLOW', DENY: 'DENY', UNKNOWN: 'UNKNOWN' },
      guard: isEffect,
      bogus: ['', 'allow', 'PERMIT'],
    },
    {
      name: 'DenialReason',
      table: DenialReason,
      valid: { NO_CREDENTIAL: 'NO_CREDENTIAL', CREDENTIAL_REJECTED: 'CREDENTIAL_REJECTED' },
      guard: isDenialReason,
      bogus: ['', 'user alice not found'],
    },
  ];
  for (const r of rows) {
    await t.test(r.name, () => {
      for (const [member, lit] of Object.entries(r.valid)) {
        assert.equal(r.table[member], lit, `${r.name}.${member}`);
        assert.ok(r.guard(lit), `${lit} is valid`);
      }
      const values = Object.values(r.table).filter((v) => typeof v === 'string');
      assert.deepEqual(values, Object.values(r.valid), 'no other values');
      for (const v of r.bogus) assert.ok(!r.guard(v), `${String(v)} is not valid`);
    });
  }
});

// 17.1 names exactly PASS, FAIL and UNKNOWN for check_context, and each maps
// to the CheckResult status of the same name.
test('TestVerdictMatchesDraftAndCore', () => {
  const rows: readonly [string, CheckStatus][] = [
    [Verdict.PASS, CheckStatus.PASS],
    [Verdict.FAIL, CheckStatus.FAIL],
    [Verdict.UNKNOWN, CheckStatus.UNKNOWN],
    // A check that reported nothing valid established nothing.
    ['', CheckStatus.UNKNOWN],
    ['NOT_APPLICABLE', CheckStatus.UNKNOWN],
  ];
  for (const [v, want] of rows) assert.equal(Verdict.checkStatus(v), want, `Verdict(${v})`);
});

// Only an explicit allow permits. A deny, an unknown, an empty and a
// mis-spelled effect all fail closed.
test('TestDecisionPermits', () => {
  const base: Decision = {
    effect: Effect.ALLOW,
    obligations: [],
    reason: '',
    sourceId: 'policy',
    sourceRef: '',
    decidedAt: null,
    policyRevision: '',
  };
  const rows: readonly [Partial<Record<keyof Decision, unknown>>, boolean][] = [
    [{ effect: Effect.ALLOW }, true],
    [{ effect: Effect.ALLOW, obligations: [{ id: 'redact', attributes: {} }] }, true],
    [{ effect: Effect.DENY }, false],
    [{ effect: Effect.DENY, reason: 'allow' }, false],
    [{ effect: Effect.UNKNOWN }, false],
    [{ effect: '' }, false],
    [{ effect: 'allow' }, false],
  ];
  for (const [mod, want] of rows) {
    const d = { ...base, ...mod } as Decision;
    assert.equal(Decision.permits(d), want, JSON.stringify(mod));
  }
});
