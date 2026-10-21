// Port of go/adapter/adaptertest/casefile_test.go and the attributes rule
// of attributes_test.go: the case loader, the strict decode of a case file
// and each rule of the format (spec/v1.0/fixtures/adapters/README.md).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadCases } from '../src/adapter/adaptertest/index.ts';
import { minimalCase, treeOf } from './support/adaptertest.ts';

function loadErr(tree: Record<string, string>, adapter = ''): string {
  try {
    loadCases(treeOf(tree), adapter);
  } catch (err) {
    return (err as Error).message;
  }
  return '';
}

test('TestLoad', async (t) => {
  await t.test('common cases', () => {
    const cases = loadCases(
      treeOf({
        'adapters/_common/a.json': minimalCase,
        'adapters/_common/b.json': minimalCase.replace('COMMON-01.one', 'COMMON-01.two'),
        'adapters/_common/notes.txt': 'ignored',
      }),
    );
    assert.deepEqual(
      cases.map((c) => c.id),
      ['COMMON-01.one', 'COMMON-01.two'],
    );
  });

  await t.test('adapter cases follow the common cases', () => {
    const cases = loadCases(
      treeOf({
        'adapters/_common/a.json': minimalCase,
        'adapters/basic/basic-01.json': minimalCase.replace('COMMON-01.one', 'BASIC-01'),
        'adapters/basic/basic-02.json': minimalCase.replace('COMMON-01.one', 'BASIC-02'),
        'adapters/other/other-01.json': minimalCase.replace('COMMON-01.one', 'OTHER-01'),
        'adapters/basic/notes/x.json': minimalCase.replace('COMMON-01.one', 'BASIC-99'),
        'adapters/basic/cases/old.json': minimalCase.replace('COMMON-01.one', 'BASIC-98'),
      }),
      'basic',
    );
    assert.deepEqual(
      cases.map((c) => c.id),
      ['COMMON-01.one', 'BASIC-01', 'BASIC-02'],
      'the adapter cases are the files of adapters/<name>, with no subdirectory',
    );
  });

  await t.test('adapter name without cases', () => {
    const trees: Record<string, Record<string, string>> = {
      'no directory': { 'adapters/_common/a.json': minimalCase },
      'only a cases subdirectory': {
        'adapters/_common/a.json': minimalCase,
        'adapters/basic/cases/own.json': minimalCase.replace('COMMON-01.one', 'BASIC-01'),
      },
    };
    for (const [name, tree] of Object.entries(trees)) {
      const err = loadErr(tree, 'basic');
      assert.ok(
        err.includes('adapters/basic') && !err.includes('adapters/basic/cases'),
        `${name}: err = ${err}, want no case files in adapters/basic`,
      );
    }
  });

  await t.test('bad adapter name', () => {
    for (const name of ['../x', 'Basic', 'a/b', '-x']) {
      const err = loadErr({ 'adapters/_common/a.json': minimalCase }, name);
      assert.ok(err.includes('adapter name'), `loadCases(${name}) = ${err}`);
    }
  });

  await t.test('no common cases', () => {
    assert.notEqual(loadErr({ 'adapters/_common/readme.txt': 'x' }), '');
    assert.notEqual(loadErr({ 'other/a.json': minimalCase }), '');
  });

  await t.test('duplicate id across directories', () => {
    const err = loadErr(
      { 'adapters/_common/a.json': minimalCase, 'adapters/basic/basic-01.json': minimalCase },
      'basic',
    );
    assert.ok(err.includes('used twice'), err);
  });
});

// Each mutation of the minimal case breaks one rule of the format, and the
// loader names it.
test('TestCaseFileRules', async (t) => {
  const sub = (old: string, neu: string): string => {
    assert.ok(minimalCase.includes(old), `minimalCase lacks ${old}`);
    return minimalCase.replace(old, neu);
  };
  const replaceAll = (pairs: [string, string][]): string =>
    pairs.reduce((s, [a, b]) => s.replace(a, b), minimalCase);
  const tests: [string, string, string | RegExp][] = [
    ['unknown member', sub('"title": "A case",', '"title": "A case", "surprise": 1,'), 'surprise'],
    // The strict decoder names the kind of the failure, DUPLICATE_KEY.
    [
      'duplicate member',
      sub('"title": "A case",', '"title": "A case", "title": "B",'),
      /duplicate/i,
    ],
    ['case version', sub('"case_version": 1', '"case_version": 2'), 'case_version'],
    ['id shape', sub('COMMON-01.one', 'common-01'), 'does not match'],
    ['id suffix shape', sub('COMMON-01.one', 'COMMON-01.One'), 'does not match'],
    ['empty title', sub('"A case"', '" "'), 'title is empty'],
    ['native state is not an object', sub('{"model": "common/1"}', '[1]'), 'native_state'],
    ['native state missing', sub('"native_state": {"model": "common/1"},', ''), 'native_state'],
    ['negative now', sub('"title"', '"now": -1, "title"'), 'now'],
    ['unknown function', sub('authenticate_native', 'authenticate'), 'seven functions'],
    [
      'outcome of another function',
      sub('"denied"', '"mapped"'),
      'not defined for authenticate_native',
    ],
    // A clock-ahead claim is refused (freshness profile); no outcome accepts
    // a claim with its times clamped instead.
    [
      'retired bounded outcome',
      replaceAll([
        ['authenticate_native', 'read_native_claim'],
        ['"denied"', '"bounded"'],
        [
          '"request": {"method": "GET", "url": "https://gateway.example/x"},',
          '"call": {"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}}, "native_path": "/x"},',
        ],
      ]),
      'outcome "bounded" is not defined for read_native_claim',
    ],
    [
      'authenticated without a principal',
      sub('"denied"', '"authenticated"'),
      'needs expect.principal',
    ],
    [
      'missing request',
      sub('"request": {"method": "GET", "url": "https://gateway.example/x"},', ''),
      'needs a request',
    ],
    [
      'request without a url',
      sub('"url": "https://gateway.example/x"', '"url": ""'),
      'method and a url',
    ],
    ['bad arrival', sub('"method": "GET"', '"method": "GET", "arrival": "sideways"'), 'arrival'],
    [
      'bad header name',
      sub('"method": "GET"', '"method": "GET", "headers": {"X Bad": "1"}'),
      'header name',
    ],
    ['bad body', sub('"method": "GET"', '"method": "GET", "body_b64": "***"'), 'base64'],
    [
      'call argument that does not apply',
      sub('"expect"', '"call": {"native_path": "/x"}, "expect"'),
      'not an argument of authenticate_native',
    ],
    [
      'expectation that does not apply',
      sub('"outcome": "denied"', '"outcome": "denied", "claim": {}'),
      'does not apply',
    ],
    [
      'empty hook name',
      sub('"outcome": "denied"', '"outcome": "denied", "must_not_call": [" "]'),
      'empty hook name',
    ],
    [
      'unknown workload mode',
      sub('"title": "A case",', '"title": "A case", "workloads": "Shared",'),
      'workloads',
    ],
    [
      'workload mode of no profile',
      sub('"title": "A case",', '"title": "A case", "workloads": "any",'),
      'workloads',
    ],
    ['not json', '{', 'strictjson'],
  ];
  for (const [name, body, want] of tests) {
    await t.test(name, () => {
      const err = loadErr({ 'adapters/_common/a.json': body });
      assert.notEqual(err, '', 'the loader accepted the file');
      if (typeof want === 'string') assert.ok(err.includes(want), `err = ${err}, want ${want}`);
      else assert.match(err, want);
      assert.ok(err.includes('adapters/_common/a.json'), `err = ${err}, want it to name the file`);
    });
  }
});

// A case may say which adapters it applies to, by whether the adapter's
// profile supports workloads shared by several agents. "shared" and
// "dedicated" are the two values; absent, the case applies to every adapter.
test('TestWorkloadsMember', () => {
  for (const [member, want] of [
    ['', ''],
    ['"workloads": "shared",', 'shared'],
    ['"workloads": "dedicated",', 'dedicated'],
  ] as const) {
    const body = minimalCase.replace('"title": "A case",', `"title": "A case", ${member}`);
    const cases = loadCases(treeOf({ 'adapters/_common/a.json': body }));
    assert.equal(cases[0]?.workloads, want, member);
  }
});

// expect.binding.enrolled_elsewhere may be true only for the outcome
// unknown, which accepts no other binding member.
test('TestEnrolledElsewhereExpectation', async (t) => {
  const record =
    '"agent_id": "https://a.example/a", "operator_id": "https://o.example/o", "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", "status": "ACTIVE"';
  const tests: [string, string, string][] = [
    ['unknown', '"enrolled_elsewhere": true', ''],
    ['unknown', '"enrolled_elsewhere": false', ''],
    [
      'unknown',
      '"enrolled_elsewhere": true, "agent_id": "https://a.example/a"',
      'only enrolled_elsewhere',
    ],
    ['unknown', '"status": "UNKNOWN"', 'only enrolled_elsewhere'],
    ['bound', `${record}, "enrolled_elsewhere": false`, ''],
    ['bound', `${record}, "enrolled_elsewhere": true`, 'enrolled_elsewhere true'],
    ['unusable', `${record}, "enrolled_elsewhere": true`, 'enrolled_elsewhere true'],
    ['error', '"enrolled_elsewhere": true', 'enrolled_elsewhere true'],
  ];
  for (const [outcome, binding, want] of tests) {
    await t.test(`${outcome}/${binding}`, () => {
      const body = `{"case_version": 1, "id": "CASE-01", "title": "t", "native_state": {}, "call": {"realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w", "agent_id": "https://a.example/a"}, "expect": {"function": "resolve_agent_binding", "outcome": "${outcome}", "binding": {${binding}}}}`;
      const err = loadErr({ 'adapters/_common/a.json': body });
      if (want === '') assert.equal(err, '', 'the loader rejected a valid case');
      else assert.ok(err.includes(want), `err = ${err}, want ${want}`);
    });
  }
});

// Each function requires its arguments and rejects the others.
test('TestCallArgumentsPerFunction', async (t) => {
  const realm = '"realm": {"tenant_id": "t", "environment_id": "e"}';
  const prin =
    '"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}';
  const op =
    '"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a", "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "", "headers": {}}';
  const binding =
    '"binding": {"agent_id": "https://a.example/a", "operator_id": "https://o.example/o", "holder_jkt": "k"}';
  const otherPrin =
    '"principal": {"id": "q", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}';
  const obs =
    '"observation": {"event_id": "e", "event_kind": "ADMISSION", "task_id": "t", "operation_id": "o", "observed_at": 1}';
  const intent =
    '"intent": {"intent_id": "i", "purpose_id": "p", "description": "", "task_id": "t"}';
  const agent = '"agent_id": "https://a.example/a"';
  const tests: [string, string, string, boolean, string][] = [
    ['resolve_agent_binding', 'unknown', `${realm}, "workload": "w", ${agent}`, false, ''],
    ['resolve_agent_binding', 'unknown', `${realm}, ${agent}`, false, 'call.workload is required'],
    [
      'resolve_agent_binding',
      'unknown',
      `${realm}, "workload": "w"`,
      false,
      'call.agent_id is required',
    ],
    [
      'resolve_agent_binding',
      'unknown',
      `"workload": "w", ${agent}`,
      false,
      'call.realm is required',
    ],
    [
      'resolve_agent_binding',
      'unknown',
      `${realm}, "workload": "w", ${agent}, "native_path": "/x"`,
      false,
      'not an argument',
    ],
    [
      'resolve_agent_binding',
      'unusable',
      `${realm}, "workload": "w", ${agent}`,
      false,
      'needs expect.binding',
    ],
    ['map_operation', 'error', `${prin}, "mapping_version": "m"`, true, ''],
    ['map_operation', 'error', prin, true, 'call.mapping_version is required'],
    [
      'map_operation',
      'error',
      `${prin}, "mapping_version": "m", ${agent}`,
      true,
      'not an argument',
    ],
    ['map_operation', 'error', `${prin}, "mapping_version": "m"`, false, 'needs a request'],
    ['read_native_claim', 'error', `${prin}, "native_path": "/x"`, false, ''],
    ['read_native_claim', 'error', `${prin}, "native_path": "/x"`, true, 'takes no request'],
    ['read_native_claim', 'error', `${prin}, "native_path": "/x", ${op}`, false, ''],
    ['read_native_claim', 'error', `${prin}, "native_path": "/x", ${intent}`, false, ''],
    ['read_native_claim', 'error', `${prin}, "native_path": "/x", ${intent}, ${op}`, false, ''],
    [
      'read_native_claim',
      'error',
      `"native_path": "/x", ${op}`,
      false,
      'call.principal is required',
    ],
    [
      'read_native_claim',
      'error',
      `${prin}, "native_path": "/x", "evidence_refs": ["r"]`,
      false,
      'not an argument',
    ],
    [
      'read_native_claim',
      'error',
      `${prin}, "native_path": "/x", "check_id": "c"`,
      false,
      'not an argument',
    ],
    ['check_context', 'UNKNOWN', `${prin}, ${op}, "check_id": ""`, false, ''],
    ['check_context', 'UNKNOWN', `${prin}, ${op}`, false, 'call.check_id is required'],
    ['check_context', 'UNKNOWN', `"check_id": "c", ${op}`, false, 'call.principal is required'],
    ['check_context', 'UNKNOWN', `"check_id": "c", ${prin}`, false, 'call.operation is required'],
    [
      'check_context',
      'UNKNOWN',
      `"check_id": "c", ${prin}, ${op}, "evidence_refs": ["r"]`,
      false,
      '',
    ],
    ['check_context', 'UNKNOWN', `"check_id": "c", ${prin}, ${op}, ${binding}`, false, ''],
    [
      'check_context',
      'UNKNOWN',
      `"check_id": "c", ${prin}, ${op}, "binding": {"agent_id": "https://a.example/a", "status": "ACTIVE"}`,
      false,
      '',
    ],
    [
      'check_context',
      'UNKNOWN',
      `"check_id": "c", ${prin}, ${op}, "binding": {"agent_id": "https://a.example/a", "status": "LIVE"}`,
      false,
      'not a binding status',
    ],
    [
      'check_context',
      'UNKNOWN',
      `"check_id": "c", ${otherPrin}, ${op}`,
      false,
      'is not call.operation.principal_id',
    ],
    [
      'read_native_claim',
      'error',
      `${prin}, "native_path": "/x", ${binding}`,
      false,
      'call.binding is not an argument',
    ],
    [
      'authorize_native',
      'DENY',
      `${prin}, ${op}, ${binding}`,
      false,
      'call.binding is not an argument',
    ],
    [
      'resolve_agent_binding',
      'unknown',
      `${realm}, "workload": "w", ${agent}, ${binding}`,
      false,
      'call.binding is not an argument',
    ],
    [
      'map_operation',
      'error',
      `${prin}, "mapping_version": "m", ${binding}`,
      true,
      'call.binding is not an argument',
    ],
    ['authorize_native', 'DENY', `${prin}, ${op}`, false, ''],
    ['authorize_native', 'DENY', prin, false, 'call.operation is required'],
    ['record_outcome', 'error', obs, false, ''],
    ['record_outcome', 'error', '', false, 'call.observation is required'],
  ];
  for (const [i, [fn, outcome, call, withRequest, want]] of tests.entries()) {
    await t.test(`${i} ${fn}/${want}`, () => {
      const req = withRequest
        ? '"request": {"method": "GET", "url": "https://gateway.example/x"},'
        : '';
      const callMember = call === '' ? '' : `"call": {${call}},`;
      const body = `{"case_version": 1, "id": "T-01", "title": "t", "native_state": {}, ${req}${callMember}"expect": {"function": "${fn}", "outcome": "${outcome}"}}`;
      const err = loadErr({ 'adapters/_common/a.json': body });
      if (want === '') assert.equal(err, '', 'the loader rejected a valid case');
      else assert.ok(err.includes(want), `err = ${err}, want ${want}`);
    });
  }
});

test('TestPrincipalAttributesMustBeAnObject', () => {
  const c = minimalCase.replace(
    '"outcome": "denied"}',
    '"outcome": "authenticated", "principal": {"id": "p", "attributes": ["cnf"]}}',
  );
  const err = loadErr({ 'adapters/_common/a.json': c });
  assert.ok(err.includes('attributes is not a JSON object'), err);
});

test('a loaded case is the case model of the file', () => {
  const body = `{
    "case_version": 1, "id": "CASE-01", "title": "t", "draft": ["17.1"], "now": 1792080001,
    "native_state": {"model": "common/1", "x": [1, 2]},
    "call": {"check_id": "c", "principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "attributes": {"n": 1}},
             "operation": {"principal_id": "p", "action": "a"}, "evidence_refs": [],
             "binding": {"agent_id": "https://a.example/a"}},
    "expect": {"function": "check_context", "outcome": "PASS", "reason_code": "R", "leak_scan": {"secrets": ["s"]}}
  }`;
  const [c] = loadCases(treeOf({ 'adapters/_common/a.json': body }));
  assert.ok(c !== undefined);
  assert.equal(c.now, 1792080001);
  assert.equal(c.native_state.text, '{"model": "common/1", "x": [1, 2]}', 'native_state verbatim');
  assert.equal(c.request, null);
  assert.deepEqual(c.call.principal?.attributes, { n: 1 });
  assert.equal(c.call.principal?.mechanism, '');
  assert.equal(c.call.principal?.authenticated_at, null);
  assert.deepEqual(c.call.evidence_refs, []);
  assert.equal(c.call.operation?.principal_id, 'p');
  assert.deepEqual(c.call.operation?.resources, [], 'an absent member is the Go zero value');
  assert.deepEqual(c.call.operation?.headers, {});
  assert.equal(c.call.binding?.status, '');
  assert.deepEqual(c.expect.leak_scan, { secrets: ['s'] });
  assert.deepEqual(c.expect.must_not_call, []);
  assert.ok(Object.isFrozen(c));
});
