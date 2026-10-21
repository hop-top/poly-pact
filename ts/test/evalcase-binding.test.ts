// Port of go/runner/evalcase/binding_test.go: the binding results of
// native_context.json and availability.enrollment_source.

import assert from 'node:assert/strict';
import { type TestContext, test } from 'node:test';
import { type Authenticated, load, read } from '../src/conformance/case.ts';
import {
  at,
  caseTree,
  editJSON,
  type JSONObject,
  REPO_FIXTURES,
  wantThrows,
  writeFile,
} from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

const ID = 'admission/valid';

// Edits the authenticated member of native_context.json into the result of
// resolve_agent_binding for an agent with no record on the authenticated
// workload (identity mapping IM-11): binding_status unknown and no agent,
// operator or key.
function unknownBinding(a: JSONObject): void {
  a.binding_status = 'unknown';
  a.agent_id = null;
  a.operator_id = null;
  a.holder_jkt = null;
}

function editAuthenticated(root: string, f: (a: JSONObject) => void): void {
  editJSON(root, `${ID}/native_context.json`, (n) => f(n.authenticated));
}

// native_context.json's authenticated member carries the binding results of
// identity mapping section 8 (spec/v1.0/fixtures/README.md, native_context.json):
// a status of the four, enrolled_elsewhere and binding_error with their
// defaults, and null agent, operator and key exactly when the status is
// unknown.
test('TestBindingResult', async (t) => {
  if (!fixturesPresent(t)) return;
  await t.test('defaults', () => {
    const c = load(REPO_FIXTURES, ID);
    const a = c.exchanges[0]?.nativeContext.authenticated;
    assert.equal(a?.agent_id, 'https://identity.example/agents/invoice-assistant');
    assert.equal(a?.operator_id, 'https://identity.example/operators/acme');
    assert.equal(a?.holder_jkt, 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M');
    assert.equal(a?.binding_status, 'active');
    assert.equal(a?.enrolled_elsewhere, false);
    assert.equal(a?.binding_error, null);
    assert.equal(c.exchanges[0]?.availability.enrollmentSource, 'available');
  });

  const accepted: [string, (a: JSONObject) => void, (a: Authenticated) => void][] = [
    [
      'unknown, not enrolled elsewhere',
      unknownBinding,
      (a) => {
        assert.deepEqual(
          [a.agent_id, a.operator_id, a.holder_jkt, a.enrolled_elsewhere, a.binding_error],
          [null, null, null, false, null],
        );
      },
    ],
    [
      'unknown, enrolled elsewhere',
      (a) => {
        unknownBinding(a);
        a.enrolled_elsewhere = true;
      },
      (a) => assert.equal(a.enrolled_elsewhere, true),
    ],
    [
      'unknown, two enrollments',
      (a) => {
        unknownBinding(a);
        a.binding_error = 'UNSUPPORTED_REQUIREMENT';
      },
      (a) => assert.equal(a.binding_error, 'UNSUPPORTED_REQUIREMENT'),
    ],
    [
      'explicit defaults',
      (a) => {
        a.enrolled_elsewhere = false;
        a.binding_error = null;
      },
      (a) => {
        assert.deepEqual([a.enrolled_elsewhere, a.binding_error], [false, null]);
        assert.notEqual(a.agent_id, null);
      },
    ],
    [
      'compromised',
      (a) => {
        a.binding_status = 'compromised';
      },
      (a) => {
        assert.equal(a.binding_status, 'compromised');
        assert.notEqual(a.holder_jkt, null);
      },
    ],
    [
      'revoked',
      (a) => {
        a.binding_status = 'revoked';
      },
      (a) => assert.equal(a.binding_status, 'revoked'),
    ],
  ];
  for (const [name, f, check] of accepted) {
    await t.test(`accepts ${name}`, (t: TestContext) => {
      const root = caseTree(t, ID);
      editAuthenticated(root, f);
      const a = load(root, ID).exchanges[0]?.nativeContext.authenticated;
      assert.ok(a !== null && a !== undefined);
      check(a);
    });
  }

  const rejected: [string, (a: JSONObject) => void, string][] = [
    [
      'a status outside the four',
      (a) => {
        a.binding_status = 'suspended';
      },
      'binding_status',
    ],
    [
      'an upper-case status',
      (a) => {
        a.binding_status = 'ACTIVE';
      },
      'binding_status',
    ],
    [
      'unknown with an agent',
      (a) => {
        unknownBinding(a);
        a.agent_id = 'https://identity.example/agents/invoice-assistant';
      },
      'agent_id',
    ],
    [
      'unknown with an operator',
      (a) => {
        unknownBinding(a);
        a.operator_id = 'https://identity.example/operators/acme';
      },
      'operator_id',
    ],
    [
      'unknown with a key',
      (a) => {
        unknownBinding(a);
        a.holder_jkt = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M';
      },
      'holder_jkt',
    ],
    [
      'active with no agent',
      (a) => {
        a.agent_id = null;
      },
      'agent_id',
    ],
    [
      'active with no operator',
      (a) => {
        a.operator_id = null;
      },
      'operator_id',
    ],
    [
      'compromised with no key',
      (a) => {
        a.binding_status = 'compromised';
        a.holder_jkt = null;
      },
      'holder_jkt',
    ],
    [
      'active with an empty agent',
      (a) => {
        a.agent_id = '';
      },
      'agent_id',
    ],
    [
      'enrolled elsewhere with an active binding',
      (a) => {
        a.enrolled_elsewhere = true;
      },
      'enrolled_elsewhere',
    ],
    [
      'enrolled elsewhere null',
      (a) => {
        unknownBinding(a);
        a.enrolled_elsewhere = null;
      },
      'enrolled_elsewhere',
    ],
    [
      'binding error with an active binding',
      (a) => {
        a.binding_error = 'UNSUPPORTED_REQUIREMENT';
      },
      'binding_error',
    ],
    [
      'binding error of another code',
      (a) => {
        unknownBinding(a);
        a.binding_error = 'CONTEXT_MISMATCH';
      },
      'binding_error',
    ],
    [
      'a renamed member',
      (a) => {
        unknownBinding(a);
        a.enrolled_for_another_workload = true;
      },
      'enrolled_for_another_workload',
    ],
  ];
  for (const [name, f, want] of rejected) {
    await t.test(`rejects ${name}`, (t: TestContext) => {
      const root = caseTree(t, ID);
      editAuthenticated(root, f);
      wantThrows(() => load(root, ID), 'native_context.json', want);
      wantThrows(() => read(root, ID), 'native_context.json', want);
    });
  }
});

// exchange.json's availability.enrollment_source is available or
// unavailable (spec/v1.0/fixtures/README.md, availability).
test('TestEnrollmentSource', async (t) => {
  if (!fixturesPresent(t)) return;
  for (const [body, want] of [
    ['{"availability":{"enrollment_source":"unavailable"}}', 'unavailable'],
    ['{"availability":{"enrollment_source":"available"}}', 'available'],
    ['{"availability":{"replay_store":"unavailable"}}', 'available'],
    ['{"availability":{}}', 'available'],
  ]) {
    await t.test(body, (t: TestContext) => {
      const root = caseTree(t, ID);
      writeFile(at(root, `${ID}/exchange.json`), body);
      assert.equal(load(root, ID).exchanges[0]?.availability.enrollmentSource, want);
    });
  }
  for (const body of [
    '{"availability":{"enrollment_source":"down"}}',
    '{"availability":{"enrollment_source":"full"}}',
  ]) {
    await t.test(body, (t: TestContext) => {
      const root = caseTree(t, ID);
      writeFile(at(root, `${ID}/exchange.json`), body);
      wantThrows(() => load(root, ID), 'exchange.json', 'enrollment_source');
    });
  }
});
