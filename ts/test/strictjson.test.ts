// Port of go/core/strictjson/strictjson_test.go. The Go test struct `sample`
// is the shape SAMPLE below; a Go pointer field is a nullable member, a
// json.RawMessage field a raw member and map[string]json.RawMessage an
// object member. Expected kinds come from the Go tests and draft section
// 7.1.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Shape } from '../src/core/shapes.ts';
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH,
  decode,
  type Limits,
  MAX_SAFE_INTEGER,
  parse,
  StrictJSONError,
  type StrictJSONErrorKind,
} from '../src/core/strictjson.ts';
import { RawJSON } from '../src/core/values.ts';

const INNER: Shape = { required: [], optional: ['n'], members: { n: { type: 'integer' } } };

const SAMPLE: Shape = {
  required: [],
  optional: [
    'name',
    'count',
    'ratio',
    'opt',
    'opt_count',
    'inner',
    'items',
    'raw',
    'headers',
    'extensions',
  ],
  members: {
    name: { type: 'string' },
    count: { type: 'integer' },
    ratio: { type: 'number' },
    opt: { type: 'nullable', of: { type: 'string' } },
    opt_count: { type: 'nullable', of: { type: 'integer' } },
    inner: { type: 'nullable', of: { type: 'shape', name: 'Inner' } },
    items: { type: 'array', items: { type: 'shape', name: 'Inner' } },
    raw: { type: 'raw' },
    headers: { type: 'map', values: { type: 'string' } },
    extensions: { type: 'object' },
  },
};

const DEFS: Readonly<Record<string, Shape>> = { Inner: INNER };

interface Sample {
  name?: string;
  count?: number;
  ratio?: number;
  opt?: string | null;
  opt_count?: number | null;
  inner?: { n?: number } | null;
  items?: { n?: number }[];
  raw?: RawJSON;
  headers?: Record<string, string>;
  extensions?: Record<string, RawJSON>;
}

function decodeSample(input: string | Uint8Array, lim: Limits = {}): Sample {
  return decode<Sample>(input, SAMPLE, lim, DEFS);
}

function errorOf(f: () => unknown): unknown {
  try {
    f();
  } catch (err) {
    return err;
  }
  return undefined;
}

function assertKind(
  err: unknown,
  kind: StrictJSONErrorKind,
  what: string,
): asserts err is StrictJSONError {
  assert.ok(err instanceof StrictJSONError, `${what}: got ${String(err)}, want ${kind}`);
  assert.equal(err.kind, kind, `${what}: ${err.message}`);
}

test('constants', () => {
  assert.equal(MAX_SAFE_INTEGER, 2 ** 53 - 1);
  assert.equal(DEFAULT_MAX_BYTES, 256 * 1024);
  assert.equal(DEFAULT_MAX_DEPTH, 16);
});

test('TestDecodeValid', () => {
  const input =
    '{"name":"a","count":9007199254740991,"ratio":1.5e3,"opt":null,"opt_count":7,' +
    '"inner":{"n":0},"items":[{"n":1},{"n":2}],"raw":{"x":[1,2,{"y":null}]},' +
    '"headers":{"x-a":"1"},"extensions":{"k":{"deep":[true,false,null]}}}';
  const got = decodeSample(input);
  assert.equal(got.name, 'a');
  assert.equal(got.count, 9007199254740991);
  assert.equal(got.ratio, 1500);
  assert.equal(got.opt, null);
  assert.equal(got.opt_count, 7);
  assert.deepEqual(got.inner, { n: 0 });
  assert.deepEqual(got.items, [{ n: 1 }, { n: 2 }]);
  assert.ok(got.raw instanceof RawJSON);
  assert.equal(got.raw.text, '{"x":[1,2,{"y":null}]}');
  assert.deepEqual(got.headers, { 'x-a': '1' });
  assert.ok(got.extensions?.k instanceof RawJSON);
  assert.equal(got.extensions.k.text, '{"deep":[true,false,null]}');
});

test('TestDecodeRejects', async (t) => {
  const deep = (n: number) => `{"extensions":{"a":${'['.repeat(n - 2)}${']'.repeat(n - 2)}}}`;
  const tests: [string, string | Uint8Array, Limits, StrictJSONErrorKind][] = [
    ['duplicate top level', '{"name":"a","name":"b"}', {}, 'DUPLICATE_KEY'],
    ['duplicate same value', '{"name":"a","name":"a"}', {}, 'DUPLICATE_KEY'],
    ['duplicate nested struct', '{"inner":{"n":1,"n":2}}', {}, 'DUPLICATE_KEY'],
    ['duplicate in open map', '{"extensions":{"a":{"b":1,"b":2}}}', {}, 'DUPLICATE_KEY'],
    ['duplicate in headers', '{"headers":{"x":"1","x":"2"}}', {}, 'DUPLICATE_KEY'],
    ['duplicate in raw', '{"raw":{"a":1,"a":2}}', {}, 'DUPLICATE_KEY'],
    ['duplicate in array element', '{"items":[{"n":1},{"n":1,"n":1}]}', {}, 'DUPLICATE_KEY'],
    ['duplicate after unescape', '{"name":"a","\\u006eame":"b"}', {}, 'DUPLICATE_KEY'],
    ['unknown field', '{"name":"a","bogus":1}', {}, 'UNKNOWN_FIELD'],
    ['unknown nested field', '{"inner":{"n":1,"m":2}}', {}, 'UNKNOWN_FIELD'],
    ['unknown field in array element', '{"items":[{"n":1,"m":2}]}', {}, 'UNKNOWN_FIELD'],
    ['case variant is unknown', '{"Name":"a"}', {}, 'UNKNOWN_FIELD'],
    ['case variant beside real field', '{"name":"a","NAME":"b"}', {}, 'UNKNOWN_FIELD'],
    ['depth 17 objects', `{"extensions":${'{"a":'.repeat(15)}{}${'}'.repeat(15)}}`, {}, 'DEPTH'],
    ['depth 17 arrays', deep(17), {}, 'DEPTH'],
    ['custom depth', '{"raw":[[1]]}', { maxDepth: 2 }, 'DEPTH'],
    ['1e999', '{"ratio":1e999}', {}, 'NON_FINITE'],
    ['-1e999 in raw', '{"raw":-1e999}', {}, 'NON_FINITE'],
    ['NaN', '{"raw":NaN}', {}, 'NON_FINITE'],
    ['Infinity', '{"raw":Infinity}', {}, 'NON_FINITE'],
    ['-Infinity', '{"raw":-Infinity}', {}, 'NON_FINITE'],
    [
      'invalid utf8 byte',
      Uint8Array.from([...bytesOf('{"name":"'), 0xff, ...bytesOf('"}')]),
      {},
      'INVALID_UTF8',
    ],
    [
      'invalid utf8 in key',
      Uint8Array.from([...bytesOf('{"na'), 0xc0, ...bytesOf('me":1}')]),
      {},
      'INVALID_UTF8',
    ],
    ['lone high surrogate', '{"name":"\\ud800"}', {}, 'LONE_SURROGATE'],
    ['lone low surrogate', '{"name":"\\udc00"}', {}, 'LONE_SURROGATE'],
    ['high then bmp', '{"name":"\\ud800A"}', {}, 'LONE_SURROGATE'],
    ['reversed pair', '{"name":"\\udc00\\ud800"}', {}, 'LONE_SURROGATE'],
    ['surrogate in key', '{"extensions":{"\\ud800":1}}', {}, 'LONE_SURROGATE'],
    [
      'escaped backslash is not a surrogate escape guard',
      '{"name":"\\\\\\ud800"}',
      {},
      'LONE_SURROGATE',
    ],
    ['integer 2^53', '{"raw":9007199254740992}', {}, 'INTEGER'],
    ['integer -2^53', '{"raw":-9007199254740992}', {}, 'INTEGER'],
    ['integer huge', '{"raw":123456789012345678901234567890}', {}, 'INTEGER'],
    ['typed integer overflow', '{"count":9007199254740992}', {}, 'INTEGER'],
    ['typed integer negative', '{"count":-1}', {}, 'INTEGER'],
    ['typed integer fraction', '{"count":1.5}', {}, 'INTEGER'],
    ['typed integer exponent form', '{"count":1e3}', {}, 'INTEGER'],
    ['typed integer 1.0', '{"count":1.0}', {}, 'INTEGER'],
    ['nullable integer negative', '{"opt_count":-5}', {}, 'INTEGER'],
    ['trailing text', '{"name":"a"} x', {}, 'TRAILING_DATA'],
    ['trailing value', '{"name":"a"}{}', {}, 'TRAILING_DATA'],
    ['trailing brace', '{"name":"a"}}', {}, 'TRAILING_DATA'],
    ['empty input', '', {}, 'SYNTAX'],
    ['whitespace only', ' \n', {}, 'SYNTAX'],
    ['truncated', '{"name":"a"', {}, 'SYNTAX'],
    ['bom', Uint8Array.from([0xef, 0xbb, 0xbf, ...bytesOf('{}')]), {}, 'SYNTAX'],
    ['leading zero', '{"raw":01}', {}, 'SYNTAX'],
    ['single quotes', "{'name':'a'}", {}, 'SYNTAX'],
    ['trailing comma', '{"name":"a",}', {}, 'SYNTAX'],
    ['too large', `{"name":"${'a'.repeat(64)}"}`, { maxBytes: 32 }, 'SIZE'],
    ['null for string', '{"name":null}', {}, 'NULL'],
    ['null for integer', '{"count":null}', {}, 'NULL'],
    ['null for slice', '{"items":null}', {}, 'NULL'],
    ['null for map', '{"headers":null}', {}, 'NULL'],
    ['null document', 'null', {}, 'NULL'],
    ['type mismatch', '{"name":5}', {}, 'TYPE'],
    ['type mismatch object', '{"name":{}}', {}, 'TYPE'],
  ];
  for (const [name, input, lim, want] of tests) {
    await t.test(name, () => {
      assertKind(
        errorOf(() => decodeSample(input, lim)),
        want,
        `decode(${JSON.stringify(typeof input === 'string' ? input : [...input])})`,
      );
    });
  }
});

test('TestDecodeAccepts', async (t) => {
  const arrays = (n: number) => `{"extensions":{"a":${'['.repeat(n - 2)}${']'.repeat(n - 2)}}}`;
  const tests: [string, string, Limits][] = [
    ['depth 16 objects', `{"extensions":${'{"a":'.repeat(14)}{}${'}'.repeat(14)}}`, {}],
    ['depth 16 arrays', arrays(16), {}],
    ['max safe integer', '{"count":9007199254740991,"raw":9007199254740991}', {}],
    ['negative max safe in raw', '{"raw":-9007199254740991}', {}],
    ['zero count', '{"count":0}', {}],
    ['negative zero in raw', '{"raw":-0}', {}],
    ['largest finite float', '{"ratio":1.7976931348623157e308}', {}],
    ['negative float', '{"ratio":-12.5}', {}],
    ['float underflow is finite', '{"ratio":1e-999}', {}],
    ['surrogate pair', '{"name":"😀"}', {}],
    ['escaped backslash then u', '{"name":"\\\\ud800"}', {}],
    ['replacement char literal', '{"name":"�"}', {}],
    ['case distinct keys in open map', '{"extensions":{"a":1,"A":2}}', {}],
    ['same key in sibling objects', '{"items":[{"n":1},{"n":2}],"inner":{"n":3}}', {}],
    ['trailing whitespace', '{"name":"a"}\n \t\r\n', {}],
    ['leading whitespace', ' \n{"name":"a"}', {}],
    ['null in raw', '{"raw":null}', {}],
    ['null in nullable', '{"opt":null,"opt_count":null}', {}],
    ['null in nullable struct pointer', '{"inner":null}', {}],
    ['custom depth', '{"raw":[[1]]}', { maxDepth: 3 }],
    ['exact size', '{"name":"a"}', { maxBytes: 12 }],
    ['empty object', '{}', {}],
  ];
  for (const [name, input, lim] of tests) {
    await t.test(name, () => {
      decodeSample(input, lim);
    });
  }
});

test('TestDecodeFreeFormTarget', () => {
  assert.deepEqual(parse('{"a":[1,{"b":null}],"A":2}'), { a: [1, { b: null }], A: 2 });
  assertKind(
    errorOf(() => parse('{"a":1,"a":2}')),
    'DUPLICATE_KEY',
    'duplicate into any',
  );
  assertKind(
    errorOf(() => decode('{"x":9007199254740992}', { required: [], optional: [], members: {} })),
    'UNKNOWN_FIELD',
    'unknown member of an empty shape',
  );
  const open: Shape = {
    required: [],
    optional: ['m'],
    members: { m: { type: 'map', values: { type: 'raw' } } },
  };
  assertKind(
    errorOf(() => decode('{"m":{"x":9007199254740992}}', open)),
    'INTEGER',
    'overflow into map',
  );
});

// Go fills a target only on success; a TypeScript decode returns a fresh
// value, so the port checks that a failure returns nothing and that the
// input is untouched.
test('TestDecodeDoesNotFillTargetOnFailure', async (t) => {
  for (const [name, input] of [
    ['walk failure', '{"name":"new","count":-1}'],
    ['decode failure', '{"name":"new","count":"x"}'],
  ] as const) {
    await t.test(name, () => {
      const b = bytesOf(input);
      const copy = b.slice();
      let got: Sample | undefined;
      assert.ok(
        errorOf(() => {
          got = decodeSample(b);
        }) instanceof StrictJSONError,
      );
      assert.equal(got, undefined);
      assert.deepEqual(b, copy);
    });
  }
});

test('TestDecodeReplacesTarget', () => {
  const got = decodeSample('{"headers":{"new":"2"}}');
  assert.deepEqual(Object.keys(got), ['headers']);
  assert.deepEqual(got.headers, { new: '2' });
});

test('TestDecodeBadTarget', () => {
  for (const shape of [undefined, null, {}, { required: [], optional: [] }, 'Intent']) {
    assertKind(
      errorOf(() => decode('{}', shape as unknown as Shape)),
      'TARGET',
      `decode into ${JSON.stringify(shape)}`,
    );
  }
  assertKind(
    errorOf(() =>
      decode('{"inner":{}}', {
        required: [],
        optional: ['inner'],
        members: { inner: { type: 'shape', name: 'Missing' } },
      }),
    ),
    'TARGET',
    'a shape member naming no shape',
  );
});

test('TestUnmarshalMatchesDecode', () => {
  const input = bytesOf('{"name":"a","name":"b"}');
  assertKind(
    errorOf(() => decodeSample(input)),
    'DUPLICATE_KEY',
    'decode',
  );
  assertKind(
    errorOf(() => parse(input)),
    'DUPLICATE_KEY',
    'parse',
  );
  assertKind(
    errorOf(() => decodeSample('{"name":"a","name":"b"}')),
    'DUPLICATE_KEY',
    'string',
  );
});

test('TestErrorNamesPathAndOffset', () => {
  const err = errorOf(() => decodeSample('{"inner":{"n":1,"m":2}}'));
  assert.ok(err instanceof StrictJSONError && err.message.includes('/inner/m'), String(err));
});

test('TestDepthIsCheckedBeforeBodyIsRead', () => {
  assertKind(
    errorOf(() => parse('['.repeat(100000), { maxBytes: 1 << 20 })),
    'DEPTH',
    'hostile depth',
  );
});

test('ExampleDecode', () => {
  const err = errorOf(() =>
    decode('{"name":"a","name":"b"}', {
      required: [],
      optional: ['name'],
      members: { name: { type: 'string' } },
    }),
  );
  assert.ok(err instanceof StrictJSONError && err.kind === 'DUPLICATE_KEY');
});

test('the message names the path, except for the document root', () => {
  const root = errorOf(() => parse('{} x'));
  assertKind(root, 'TRAILING_DATA', 'trailing data');
  assert.equal(root.path, '');
  assert.ok(!root.message.includes(' at '), root.message);
  assert.match(root.message, /^strictjson: TRAILING_DATA \(offset 3\): /);
  const empty = errorOf(() => parse('{"":1,"":2}'));
  assertKind(empty, 'DUPLICATE_KEY', 'duplicate member named ""');
  assert.equal(empty.path, '/');
  assert.match(empty.message, /^strictjson: DUPLICATE_KEY at \/ \(offset \d+\): /);
  const member = errorOf(() => decodeSample('{"inner":{"n":1,"m":2}}'));
  assertKind(member, 'UNKNOWN_FIELD', 'unknown nested field');
  assert.match(member.message, /^strictjson: UNKNOWN_FIELD at \/inner\/m \(offset \d+\): /);
});

test('TestErrorFields', () => {
  const err = errorOf(() => decodeSample('{"items":[{"n":1},{"n":1,"x~/":2}]}'));
  assertKind(err, 'UNKNOWN_FIELD', 'unknown field in an array element');
  assert.equal(err.path, '/items/1/x~0~1');
  assert.ok(err.offset > 0, `offset ${err.offset}`);
});

// Additions of the port: the value types parse returns, the raw text kept
// as received, the input forms and the limits defaults.
test('parse returns plain JSON values, members in input order', () => {
  const v = parse('{"b":[1,-0,2.5,"x",true,false,null],"a":{},"__proto__":1}') as Record<
    string,
    unknown
  >;
  assert.deepEqual(Object.keys(v), ['b', 'a', '__proto__']);
  assert.equal(Object.getPrototypeOf(v), Object.prototype);
  assert.ok(Object.hasOwn(v, '__proto__'));
  assert.equal(Object.getOwnPropertyDescriptor(v, '__proto__')?.value, 1);
  assert.deepEqual(v.b, [1, -0, 2.5, 'x', true, false, null]);
  assert.ok(Object.is((v.b as number[])[1], -0));
  assert.equal(parse('"\\ud83d\\ude00\\n\\u00e9"'), '😀\né');
});

test('raw members keep the text of the value as received', () => {
  const got = decodeSample('{"raw" : [ 1.50 , "\\u0041" ] ,"extensions":{"k": 1e2 }}');
  assert.equal(got.raw?.text, '[ 1.50 , "\\u0041" ]');
  assert.equal(got.extensions?.k?.text, '1e2');
  assert.equal(decodeSample('{"raw":null}').raw?.text, 'null');
});

test('a string input is read as its UTF-8 bytes', () => {
  assertKind(
    errorOf(() => parse('"\ud800"')),
    'INVALID_UTF8',
    'lone surrogate code unit',
  );
  assertKind(
    errorOf(() => parse(`"${'é'.repeat(6)}"`, { maxBytes: 13 })),
    'SIZE',
    'bytes, not code units',
  );
  assert.equal(parse(`"${'é'.repeat(6)}"`, { maxBytes: 14 }), 'é'.repeat(6));
});

test('a zero or negative limit selects the default', () => {
  const big = `"${'a'.repeat(DEFAULT_MAX_BYTES - 2)}"`;
  for (const lim of [{}, { maxBytes: 0 }, { maxBytes: -1 }]) {
    assert.equal((parse(big, lim) as string).length, DEFAULT_MAX_BYTES - 2);
    assertKind(
      errorOf(() => parse(`${big} `, lim)),
      'SIZE',
      JSON.stringify(lim),
    );
  }
  const deepest = `${'['.repeat(16)}${']'.repeat(16)}`;
  for (const lim of [{}, { maxDepth: 0 }, { maxDepth: -3 }]) {
    parse(deepest, lim);
    assertKind(
      errorOf(() => parse(`[${deepest}]`, lim)),
      'DEPTH',
      JSON.stringify(lim),
    );
  }
});

test('control characters and bad escapes in strings are syntax errors', () => {
  for (const input of ['"a\nb"', '"\t"', '"\\x41"', '"\\u12"', '"\\u12G4"', '"abc']) {
    assertKind(
      errorOf(() => parse(input)),
      'SYNTAX',
      JSON.stringify(input),
    );
  }
  for (const input of [
    '01',
    '1.',
    '.5',
    '-',
    '1e',
    '+1',
    '- 1',
    'tru',
    'nul',
    '[1 2]',
    '{"a" 1}',
  ]) {
    assertKind(
      errorOf(() => parse(input)),
      'SYNTAX',
      JSON.stringify(input),
    );
  }
});

function bytesOf(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
