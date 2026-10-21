// The comparison of each vector group of the harness (src/vectors/run-*.ts)
// against a fake core over scratch fixtures: the right answer passes, a
// wrong answer, a wrong error or a stub fails. Expectations follow the
// fixture formats of spec/v1.0/fixtures/vectors/*/README.md and the Go runners
// of cli/pactconf (vectors_core.go, vectors_schema.go).

import assert from 'node:assert/strict';
import { after, describe, test } from 'node:test';
import { RequestError } from '../src/core/binding/index.ts';
import { StrictJSONError } from '../src/core/strictjson.ts';
import { NotImplementedError } from '../src/internal/notimplemented.ts';
import { type Outcome, runEntry } from '../src/vectors/harness.ts';
import {
  bytes,
  cleanup,
  entry,
  fake,
  str,
  stubbed,
  toyCanonicalize,
  tree,
} from './vectors/tree.ts';

after(cleanup);

function passes(o: Outcome): void {
  assert.deepEqual(o, { result: 'pass' });
}

function fails(o: Outcome, detail?: RegExp): void {
  assert.equal(o.result, 'fail', JSON.stringify(o));
  if (detail && o.result === 'fail') assert.match(o.detail, detail);
}

function notImplemented(o: Outcome): void {
  fails(o, /not implemented/);
}

describe('jcs', () => {
  const pair = (output: string) =>
    tree({
      'vectors/jcs/input/a.json': '{"b": 1, "a": [true, null]}',
      'vectors/jcs/output/a.json': output,
    });
  const e = entry('vectors/jcs/a', 'vector', 'core', 'vectors/jcs/input/a.json', {
    expected: 'vectors/jcs/output/a.json',
  });
  const canon = fake({ canonicalize: toyCanonicalize });

  test('a pair passes when the canonical form is the output byte for byte', () => {
    passes(runEntry(pair('{"a":[true,null],"b":1}'), e, canon));
  });
  test('a pair fails on any other output', () => {
    fails(runEntry(pair('{"a":[true,null],"b":1}\n'), e, canon), /canonical form/);
    fails(runEntry(pair('{"b":1,"a":[true,null]}'), e, canon));
  });
  test('a pair fails when the expected output is not canonical', () => {
    // The input maps to the output, but the output does not map to itself.
    const lax = fake({
      canonicalize: (b) => (str(b).startsWith('{"b"') ? toyCanonicalize(b) : bytes('{}')),
    });
    fails(runEntry(pair('{"a":[true,null],"b":1}'), e, lax), /not canonical/);
  });
  test('a null expected fails', () => {
    fails(runEntry(pair('{}'), { ...e, expected: null }, canon));
  });
  test('the stub fails', () => {
    notImplemented(runEntry(pair('{"a":[true,null],"b":1}'), e, stubbed));
  });

  const numbers = (rows: unknown) => tree({ 'vectors/jcs/numbers.json': rows });
  const n = entry('vectors/jcs/numbers', 'vector', 'core', 'vectors/jcs/numbers.json');
  const seen: string[] = [];
  // ECMAScript Number-to-String is the RFC 8785 number form (section 3.2.2.3).
  const ecma = fake({
    canonicalize: (b) => {
      seen.push(str(b));
      return bytes(String(Number(str(b))));
    },
  });
  const rows = [
    { ieee754_hex: '3ff0000000000000', expected: '1' },
    { ieee754_hex: '8000000000000000', expected: '0' },
    { ieee754_hex: '0000000000000001', expected: '5e-324' },
    { ieee754_hex: '444b1ae4d6e2ef50', expected: '1e+21' },
  ];
  test('the number list passes, each value given as an exponent literal', () => {
    seen.length = 0;
    passes(runEntry(numbers(rows), n, ecma));
    assert.deepEqual(seen, ['1e+0', '-0e+0', '5e-324', '1e+21']);
  });
  test('the number list fails on one wrong row, a malformed row or no rows', () => {
    fails(
      runEntry(numbers([...rows, { ieee754_hex: '3ff8000000000000', expected: '1.6' }]), n, ecma),
      /3ff8/,
    );
    fails(runEntry(numbers([{ ieee754_hex: '3ff', expected: '1' }]), n, ecma), /malformed/);
    fails(runEntry(numbers([]), n, ecma));
  });
});

describe('digest', () => {
  const vec = (over: Record<string, unknown> = {}) => ({
    id: 'v',
    input_kind: 'bytes',
    input: '00ff',
    expected_digest: 'D-bytes',
    spec_defect: false,
    appendix_value: null,
    ...over,
  });
  const file = (vs: unknown[]) => tree({ 'vectors/digest/a.json': vs });
  const e = entry('vectors/digest/a', 'vector', 'core', 'vectors/digest/a.json');
  const got: unknown[] = [];
  const core = fake({
    bytesDigest: (b) => {
      got.push([...b]);
      return 'D-bytes';
    },
    objectDigest: (v) => {
      got.push(v);
      return 'D-object';
    },
    artifactDigest: (s) => {
      got.push(s);
      return 'D-artifact';
    },
  });

  test('each input kind goes to its function and passes on the expected digest', () => {
    got.length = 0;
    const vs = [
      vec(),
      vec({ id: 'o', input_kind: 'object', input: { a: 1 }, expected_digest: 'D-object' }),
      vec({
        id: 'j',
        input_kind: 'artifact',
        input: 'h.p.s',
        expected_digest: 'D-artifact',
        appendix_value: 'D-artifact',
      }),
    ];
    passes(runEntry(file(vs), e, core));
    assert.deepEqual(got, [[0, 255], { a: 1 }, 'h.p.s']);
  });
  test('a digest other than expected_digest fails', () => {
    fails(runEntry(file([vec({ expected_digest: 'other' })]), e, core), /expected_digest/);
  });
  test('bytes that are not lowercase hex fail', () => {
    fails(runEntry(file([vec({ input: '00FF' })]), e, core));
    fails(runEntry(file([vec({ input: '0' })]), e, core));
  });
  test('a flagged appendix difference is skipped:spec-defect with both values', () => {
    const o = runEntry(file([vec({ spec_defect: true, appendix_value: 'D-draft' })]), e, core);
    assert.equal(o.result, 'skipped');
    if (o.result !== 'skipped') return;
    assert.equal(o.reason, 'spec-defect');
    assert.deepEqual(o.specDefects, [
      { vector: 'v', appendix_value: 'D-draft', expected_digest: 'D-bytes' },
    ]);
  });
  test('an unflagged difference, a flag without difference or without value fails', () => {
    fails(runEntry(file([vec({ appendix_value: 'D-draft' })]), e, core));
    fails(runEntry(file([vec({ spec_defect: true, appendix_value: 'D-bytes' })]), e, core));
    fails(runEntry(file([vec({ spec_defect: true })]), e, core));
  });
  test('a missing or unknown member, a repeated id or no vectors fails', () => {
    const { spec_defect: _, ...short } = vec();
    fails(runEntry(file([short]), e, core), /members/);
    fails(runEntry(file([vec({ extra: 1 })]), e, core), /members/);
    fails(runEntry(file([vec(), vec()]), e, core), /repeated/);
    fails(runEntry(file([]), e, core));
    fails(runEntry(file([vec({ input_kind: 'text' })]), e, core));
  });
  test('the stub fails', () => {
    notImplemented(runEntry(file([vec()]), e, stubbed));
  });
});

describe('strictjson', () => {
  const file = (v: Record<string, unknown>) =>
    tree({ 'vectors/strictjson/a.json': { id: 'vectors/strictjson/a', reason: 'r', ...v } });
  const acc = entry('vectors/strictjson/a', 'vector', 'core', 'vectors/strictjson/a.json');
  const rej = { ...acc, outcome: 'REJECTED' };
  const accepting = fake({ decodeOperationContext: () => ({}) });
  const refusing = fake({
    decodeOperationContext: () => {
      throw new StrictJSONError('DUPLICATE_KEY', '/a', 7, 'duplicate');
    },
  });
  const crashing = fake({
    decodeOperationContext: () => {
      throw new TypeError('boom');
    },
  });

  test('accept passes when the decode succeeds, and fails otherwise', () => {
    passes(runEntry(file({ input_text: '{}', expect: 'accept' }), acc, accepting));
    fails(runEntry(file({ input_text: '{}', expect: 'accept' }), acc, refusing));
  });
  test('reject passes only on a StrictJSONError', () => {
    const f = file({ input_text: '{"a":1,"a":2}', expect: 'reject' });
    passes(runEntry(f, rej, refusing));
    fails(runEntry(f, rej, accepting));
    fails(runEntry(f, rej, crashing), /boom/);
    notImplemented(runEntry(f, rej, stubbed));
  });
  test('the decoder gets input_text as UTF-8 and input_b64 decoded', () => {
    const inputs: number[][] = [];
    const rec = fake({
      decodeOperationContext: (b) => {
        inputs.push([...b]);
        return {};
      },
    });
    passes(runEntry(file({ input_text: 'é', expect: 'accept' }), acc, rec));
    passes(runEntry(file({ input_b64: '/w==', expect: 'accept' }), acc, rec));
    assert.deepEqual(inputs, [[0xc3, 0xa9], [0xff]]);
  });
  test('expect against outcome, the inputs and the id are checked', () => {
    fails(runEntry(file({ input_text: '{}', expect: 'reject' }), acc, refusing));
    fails(
      runEntry(file({ input_text: '{}', input_b64: 'e30=', expect: 'accept' }), acc, accepting),
    );
    fails(runEntry(file({ expect: 'accept' }), acc, accepting));
    fails(runEntry(file({ input_b64: 'e30', expect: 'accept' }), acc, accepting));
    fails(
      runEntry(
        file({ input_text: '{}', expect: 'accept' }),
        { ...acc, id: 'vectors/strictjson/b' },
        accepting,
      ),
    );
  });
});

describe('schema', () => {
  const file = (vs: unknown[]) => tree({ 'vectors/schema/uri-format.json': vs });
  const e = entry('vectors/schema/uri-format', 'vector', 'core', 'vectors/schema/uri-format.json', {
    outcome: 'MATCH',
  });
  const v = (id: string, input: string, expect: string) => ({
    id,
    input,
    expect,
    reason: 'r',
    ajv_formats_differs: false,
  });
  const vs = [v('a', 'https://example.com/', 'accept'), v('b', 'not a uri', 'reject')];
  const core = fake({ uriFormat: (s) => s.startsWith('https:') });

  test('passes when every verdict matches', () => {
    passes(runEntry(file(vs), e, core));
  });
  test('fails on a wrong verdict, naming it', () => {
    fails(runEntry(file(vs), e, fake({ uriFormat: () => true })), /b: accepted, want reject/);
  });
  test('fails on an unknown format entry, an outcome other than MATCH or a bad vector', () => {
    fails(runEntry(file(vs), { ...e, id: 'vectors/schema/email-format' }, core));
    fails(runEntry(file(vs), { ...e, outcome: 'ACCEPTED' }, core));
    fails(runEntry(file([v('a', 'x', 'maybe')]), e, core));
    fails(runEntry(file([{ id: 'a', input: 'x', expect: 'accept' }]), e, core), /members/);
  });
  test('the stub fails', () => {
    notImplemented(runEntry(file(vs), e, stubbed));
  });
});

describe('binding', () => {
  const base = {
    id: 'vectors/binding/a',
    description: 'd',
    config: {
      origin: 'https://gw.example',
      header_allowlist: ['if-match'],
      normalization_id: 'n-1',
      mapping_version: 'm-1',
      environment_id: 'https://gw.example/env',
    },
    request: {
      method: 'POST',
      raw_request_uri: '/a?b=1',
      headers: [
        { name: 'Host', value: 'gw.example' },
        { name: 'If-Match', value: ' "x" ' },
      ],
      body_b64: 'e30=',
    },
    operation_id: 'op-1',
    principal_id: 'p',
    action: 'a.read',
    resources: ['r'],
  };
  const context = { method: 'POST', target_uri: 'https://gw.example/a?b=1' };
  const accept = {
    ...base,
    expect: {
      operation_context: {
        ...context,
        operation_id: 'op-1',
        environment_id: 'https://gw.example/env',
      },
    },
    expect_operation_digest: 'D-op',
  };
  const reject = {
    ...base,
    expect: { reject_reason: 'INVALID_MESSAGE' },
    expect_operation_digest: null,
  };
  const file = (v: unknown) => tree({ 'vectors/binding/a.json': v });
  const acc = entry('vectors/binding/a', 'vector', 'adapter', 'vectors/binding/a.json');
  const rej = { ...acc, outcome: 'REJECTED' };
  const calls: unknown[] = [];
  const binder = (digest = 'D-op') =>
    fake({
      canonicalize: toyCanonicalize,
      objectDigest: (v) => {
        calls.push(v);
        return digest;
      },
      fromRequest: (cfg, req, principalId, action, resources) => {
        calls.push({ cfg, req: { ...req, body: [...req.body] }, principalId, action, resources });
        return { ...context };
      },
    });
  const refusing = (kind: 'INVALID_REQUEST' | 'INVALID_CONFIG') =>
    fake({
      fromRequest: () => {
        throw new RequestError(kind, 'fragment', 'refused');
      },
    });

  test('an accepted request passes, with the request as received and the context completed', () => {
    calls.length = 0;
    passes(runEntry(file(accept), acc, binder()));
    assert.deepEqual(calls[0], {
      cfg: {
        origin: 'https://gw.example',
        headerAllowlist: ['if-match'],
        headerNormalizationId: 'n-1',
        mappingVersion: 'm-1',
        maxBody: 1 << 20,
      },
      req: {
        method: 'POST',
        rawRequestURI: '/a?b=1',
        headers: [
          ['Host', 'gw.example'],
          ['If-Match', ' "x" '],
        ],
        body: [0x7b, 0x7d],
      },
      principalId: 'p',
      action: 'a.read',
      resources: ['r'],
    });
    assert.deepEqual(calls[1], accept.expect.operation_context);
  });
  test('an accepted request fails on another context, digest or a refusal', () => {
    fails(
      runEntry(file({ ...accept, expect: { operation_context: context } }), acc, binder()),
      /operation context/,
    );
    fails(runEntry(file(accept), acc, binder('D-other')), /object_digest/);
    fails(runEntry(file(accept), acc, refusing('INVALID_REQUEST')));
  });
  test('a refused request passes only on RequestError INVALID_REQUEST', () => {
    passes(runEntry(file(reject), rej, refusing('INVALID_REQUEST')));
    fails(runEntry(file(reject), rej, refusing('INVALID_CONFIG')));
    fails(runEntry(file(reject), rej, binder()));
    fails(
      runEntry(
        file(reject),
        rej,
        fake({
          fromRequest: () => {
            throw new Error('boom');
          },
        }),
      ),
      /boom/,
    );
    notImplemented(runEntry(file(reject), rej, stubbed));
  });
  const configError = { ...base, expect: { config_error: true }, expect_operation_digest: null };
  const validating = (kind?: 'INVALID_REQUEST' | 'INVALID_CONFIG') =>
    fake({
      validateConfig: () => {
        if (kind !== undefined) throw new RequestError(kind, '', 'refused');
      },
    });
  test('a configuration error passes only on RequestError INVALID_CONFIG from validateConfig', () => {
    passes(runEntry(file(configError), rej, validating('INVALID_CONFIG')));
    fails(runEntry(file(configError), rej, validating()), /configuration/);
    fails(runEntry(file(configError), rej, validating('INVALID_REQUEST')));
    fails(runEntry(file(configError), acc, validating('INVALID_CONFIG')));
    fails(
      runEntry(
        file({ ...configError, expect: { config_error: false } }),
        rej,
        validating('INVALID_CONFIG'),
      ),
    );
    fails(
      runEntry(
        file({ ...configError, expect_operation_digest: 'D-op' }),
        rej,
        validating('INVALID_CONFIG'),
      ),
    );
    notImplemented(runEntry(file(configError), rej, stubbed));
  });
  test('expect, expect_operation_digest and outcome must agree; members are exact', () => {
    fails(runEntry(file(accept), rej, binder()));
    fails(runEntry(file({ ...accept, expect_operation_digest: null }), acc, binder()));
    fails(
      runEntry(
        file({ ...reject, expect: { reject_reason: 'OTHER' } }),
        rej,
        refusing('INVALID_REQUEST'),
      ),
    );
    fails(runEntry(file({ ...accept, extra: true }), acc, binder()), /members/);
    fails(runEntry(file({ ...accept, id: 'vectors/binding/b' }), acc, binder()));
  });
  test('the stub fails', () => {
    notImplemented(runEntry(file(accept), acc, stubbed));
  });
});

test('a NotImplementedError is a failure even where a refusal is expected', () => {
  const core = fake({
    decodeOperationContext: () => {
      throw new NotImplementedError('strictjson.decode');
    },
  });
  const root = tree({
    'vectors/strictjson/a.json': {
      id: 'vectors/strictjson/a',
      input_text: '[',
      expect: 'reject',
      reason: 'r',
    },
  });
  notImplemented(
    runEntry(
      root,
      entry('vectors/strictjson/a', 'vector', 'core', 'vectors/strictjson/a.json', {
        outcome: 'REJECTED',
      }),
      core,
    ),
  );
});
