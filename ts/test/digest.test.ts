// Port of go/core/digest/digest_test.go and vectors_test.go. Expected
// digests are the draft's Appendix B values, the FIPS 180-4 "abc" example
// and digests of hand-written RFC 8785 texts, as in the Go tests.
//
// Deviation of the port (docs/sdk/ports-plan-ts.md section 3): a Uint8Array
// passed to objectDigest is received JSON text, hashed in its canonical
// form, where Go's ObjectDigest encodes a []byte as a base64 string. Go's
// json.RawMessage maps to Uint8Array or RawJSON.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { artifactDigest, bytesDigest, NotObjectError, objectDigest } from '../src/core/digest.ts';
import { shapes } from '../src/core/shapes.ts';
import {
  DEFAULT_MAX_BYTES,
  decode,
  parse,
  StrictJSONError,
  type StrictJSONErrorKind,
} from '../src/core/strictjson.ts';
import { Digest, RawJSON } from '../src/core/values.ts';
import {
  bytes,
  filesUnder,
  fixturesPresent,
  manifestEntries,
  readFixtureJSON,
} from './support/fixtures.ts';

// The body_digest of Appendix B.3, the digest of zero bytes.
const BODY_DIGEST_OF_EMPTY = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
// The operation_digest and intent_digest of Appendix B.4: the digests of
// the B.3 and B.2 objects.
const OPERATION_DIGEST_B3 = 'R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0';
const INTENT_DIGEST_B2 = 't79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M';
// SHA-256("abc") (FIPS 180-4, hex ba7816bf...15ad) as base64url.
const DIGEST_OF_ABC = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';
// Payload "{}" (e30), header {"alg":"ES256"}; SHA-256 over its 29 ASCII bytes.
const SHORT_JWS = 'eyJhbGciOiJFUzI1NiJ9.e30.c2ln';
const DIGEST_OF_SHORT_JWS = 'E2ttONh1sD1zwHXFE8fH21SGQ5my65IRYl87KWSpu9o';

function checkShape(d: string): void {
  assert.doesNotThrow(() => Digest.validate(d), d);
  assert.ok(!/[=+/]/.test(d), `digest ${d} uses padding or the standard alphabet`);
}

function errorOf(f: () => unknown): unknown {
  try {
    f();
  } catch (err) {
    return err;
  }
  return undefined;
}

// The digest of a hand-written RFC 8785 text.
const canonical = (text: string) => bytesDigest(bytes(text));

test('TestBytesDigest', () => {
  const tests: [string, Uint8Array, string][] = [
    ['empty', new Uint8Array(), BODY_DIGEST_OF_EMPTY],
    ['abc', bytes('abc'), DIGEST_OF_ABC],
  ];
  for (const [name, input, want] of tests) {
    const got = bytesDigest(input);
    assert.equal(got, want, name);
    checkShape(got);
  }
});

test('TestArtifactDigest', async (t) => {
  await t.test('hashes the ASCII bytes of the string', () => {
    const got = artifactDigest(SHORT_JWS);
    assert.equal(got, DIGEST_OF_SHORT_JWS);
    checkShape(got);
    assert.equal(got, bytesDigest(bytes(SHORT_JWS)));
  });
  await t.test('exact string, no trimming', () => {
    assert.notEqual(artifactDigest(SHORT_JWS), artifactDigest(`${SHORT_JWS}\n`));
  });
  await t.test('empty string is the empty input', () => {
    assert.equal(artifactDigest(''), BODY_DIGEST_OF_EMPTY);
  });
  await t.test('non-ASCII is rejected', () => {
    for (const s of ['é', `${SHORT_JWS}é`, 'a\x80b', '\xff', 'a b', '\ud800']) {
      assert.throws(() => artifactDigest(s), /non-ASCII/, JSON.stringify(s));
    }
  });
});

test('TestObjectDigestCanonicalForm', async (t) => {
  class Unsorted {
    z = 1;
    a = 'x';
  }
  const tests: [string, unknown, string][] = [
    ['map members sorted', { b: 2, a: 1 }, '{"a":1,"b":2}'],
    ['object members sorted', { z: 1, a: 'x' }, '{"a":"x","z":1}'],
    ['no HTML escaping', { s: '<a>&b' }, '{"s":"<a>&b"}'],
    ['line separator is literal', { s: ' ' }, '{"s":" "}'],
    [
      // U+1F600 is the surrogate pair D83D DE00 and sorts before U+FF5E.
      'member names sort by UTF-16 code units',
      { '～': 2, '\u{1F600}': 1 },
      '{"\u{1F600}":1,"～":2}',
    ],
    ['ECMAScript numbers', { n: [-0, 1e21, 4.5, 100, 1e-7] }, '{"n":[0,1e+21,4.5,100,1e-7]}'],
    ['largest safe integer', { n: 2 ** 53 - 1 }, '{"n":9007199254740991}'],
    ['bigint in range', { n: 2n ** 53n - 1n, m: -7n }, '{"m":-7,"n":9007199254740991}'],
    ['empty containers', { b: [], a: {} }, '{"a":{},"b":[]}'],
    [
      'nested objects and null',
      { z: null, a: [{ y: true, x: false }] },
      '{"a":[{"x":false,"y":true}],"z":null}',
    ],
    ['string escapes', { s: 'q"\\\n\t\x01\x7f' }, '{"s":"q\\"\\\\\\n\\t\\u0001\x7f"}'],
    ['undefined members are absent', { a: 1, b: undefined }, '{"a":1}'],
    [
      'raw JSON text is canonicalized, not copied',
      bytes(' {\n  "b" : [ 1 , 2 ],\r\n  "a" : "x" }\n'),
      '{"a":"x","b":[1,2]}',
    ],
    ['a RawJSON is its text', new RawJSON('{"b":[1,2],"a":"x"}'), '{"a":"x","b":[1,2]}'],
    [
      'RawJSON members keep their value',
      { e: { k: new RawJSON(' [1.50, {"y":1,"x":2}] ') } },
      '{"e":{"k":[1.5,{"x":2,"y":1}]}}',
    ],
    [
      'a null-prototype object',
      Object.assign(Object.create(null), { b: 1, a: 2 }),
      '{"a":2,"b":1}',
    ],
  ];
  for (const [name, input, want] of tests) {
    await t.test(name, () => {
      const got = objectDigest(input);
      assert.equal(got, canonical(want), `want the digest of ${want}`);
      checkShape(got);
    });
  }
  await t.test('class instances are refused', () => {
    assert.throws(() => objectDigest(new Unsorted()), TypeError);
  });
});

test('TestObjectDigestAppendixBStructs', () => {
  const op = {
    operation_id: 'invoice-read-operation-0001',
    environment_id: 'https://gateway.example/environments/finance',
    principal_id: 'https://identity.example/principals/alice',
    action: 'invoice.read',
    resources: ['https://invoices.example/invoices/INV-1042'],
    method: 'GET',
    target_uri: 'https://gateway.example/invoices/INV-1042',
    body_digest: BODY_DIGEST_OF_EMPTY,
    headers: {},
  };
  assert.equal(objectDigest(op), OPERATION_DIGEST_B3);
  // The same object through the typed strict decode, raw members included.
  assert.equal(
    objectDigest(decode(JSON.stringify(op), shapes.OperationContext)),
    OPERATION_DIGEST_B3,
  );
  const intent = {
    intent_id: 'intent-september-invoices-007',
    purpose_id: 'https://policies.example/purposes/invoice-summary/v1',
    description: 'Read the approved September invoice to prepare the department summary.',
    task_id: 'native-task:september-summary-007',
  };
  assert.equal(objectDigest(intent), INTENT_DIGEST_B2);
});

test('TestObjectDigestRejectsNonObjects', async (t) => {
  const tests: [string, unknown][] = [
    ['null', null],
    ['undefined', undefined],
    ['array', [{ a: 1 }]],
    ['empty array', []],
    ['string', 'x'],
    ['JSON text in a string', '{"a":1}'],
    ['number', 1],
    ['boolean', true],
    ['raw array', bytes('[{}]')],
    ['raw string', bytes('"x"')],
    ['raw number', bytes('1')],
    ['raw null', bytes('null')],
    ['padded scalar', bytes(' 1 ')],
    ['RawJSON array', new RawJSON('[{}]')],
    ['object in list', [new RawJSON('{}')]],
  ];
  for (const [name, input] of tests) {
    await t.test(name, () => {
      let got: string | undefined;
      const err = errorOf(() => {
        got = objectDigest(input);
      });
      assert.ok(err instanceof NotObjectError, `${name}: ${String(err)}`);
      assert.equal(got, undefined);
    });
  }
});

function nested(depth: number): Uint8Array {
  return bytes(`${'{"a":'.repeat(depth - 1)}{}${'}'.repeat(depth - 1)}`);
}

test('TestObjectDigestLimits', async (t) => {
  const deepValue = (depth: number): unknown => {
    let v: unknown = {};
    for (let i = 1; i < depth; i++) v = { a: v };
    return v;
  };
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const tests: [string, unknown, StrictJSONErrorKind | null][] = [
    ['NaN', { n: Number.NaN }, null],
    ['Infinity', { n: Number.POSITIVE_INFINITY }, null],
    ['unsupported type', { f: () => 1 }, null],
    ['a Map', { m: new Map() }, null],
    ['a nested Uint8Array', { b: new Uint8Array(1) }, null],
    ['undefined in an array', { a: [undefined] }, null],
    ['duplicate member', bytes('{"a":1,"a":2}'), 'DUPLICATE_KEY'],
    ['duplicate member, escaped', bytes('{"a":1,"\\u0061":2}'), 'DUPLICATE_KEY'],
    ['duplicate member in RawJSON', { r: new RawJSON('{"a":1,"a":2}') }, 'DUPLICATE_KEY'],
    ['integer above 2^53-1', { n: 2n ** 53n }, 'INTEGER'],
    ['integer below -(2^53-1)', { n: -(2n ** 53n) }, 'INTEGER'],
    ['nesting depth 17', nested(17), 'DEPTH'],
    ['nesting depth 17, value', deepValue(17), 'DEPTH'],
    ['a cycle', cyclic, 'DEPTH'],
    ['invalid UTF-8', Uint8Array.of(...bytes('{"a":"'), 0xff, ...bytes('"}')), 'INVALID_UTF8'],
    ['lone surrogate escape', bytes('{"a":"\\ud800"}'), 'LONE_SURROGATE'],
    ['lone surrogate code unit', { a: '\ud800' }, 'LONE_SURROGATE'],
    ['float of integer value 2^53', { n: 2 ** 53 }, 'INTEGER'],
    ['over 256 KiB', { s: 'a'.repeat(DEFAULT_MAX_BYTES) }, 'SIZE'],
    ['malformed raw JSON', bytes('{"a":'), 'SYNTAX'],
  ];
  for (const [name, input, want] of tests) {
    await t.test(name, () => {
      let got: string | undefined;
      const err = errorOf(() => {
        got = objectDigest(input);
      });
      assert.ok(err !== undefined, `want an error, got ${got}`);
      assert.ok(!(err instanceof NotObjectError), String(err));
      if (want !== null) {
        assert.ok(err instanceof StrictJSONError, String(err));
        assert.equal(err.kind, want, err.message);
      }
      assert.equal(got, undefined);
    });
  }
  await t.test('HTML characters do not count against the size limit', () => {
    assert.ok(objectDigest({ s: '<'.repeat(100 << 10) }) !== '');
  });
  await t.test('nesting depth 16 is accepted', () => {
    checkShape(objectDigest(nested(16)));
    checkShape(objectDigest(deepValue(16)));
  });
});

test('TestObjectDigestIgnoresInputShape', () => {
  const text = '{"headers":{"x":"1"},"a":[3,2,1],"b":{"d":null,"c":1.5}}';
  const want = canonical('{"a":[3,2,1],"b":{"c":1.5,"d":null},"headers":{"x":"1"}}');
  assert.equal(objectDigest(parse(text)), want);
  assert.equal(objectDigest(bytes(text)), want);
  assert.equal(objectDigest(new RawJSON(text)), want);
});

// vectors_test.go

const PREFIX = 'vectors/digest/';
const APPENDIX_ID = 'vectors/digest/appendix-b';
const VECTOR_FIELDS = [
  'appendix_value',
  'expected_digest',
  'id',
  'input',
  'input_kind',
  'spec_defect',
];

interface Vector {
  id: string;
  input_kind: string;
  input: unknown;
  expected_digest: string;
  spec_defect: boolean;
  appendix_value: string | null;
}

test('TestManifestListsEveryDigestFile', (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  assert.ok(
    entries.some((e) => e.id === APPENDIX_ID),
    `manifest lacks ${APPENDIX_ID}`,
  );
  const listed = new Set(entries.flatMap((e) => [e.path, e.expected]));
  for (const f of filesUnder(PREFIX.slice(0, -1))) {
    if (f.endsWith('/README.md')) continue;
    assert.ok(listed.has(f), `${f} is not listed in manifest.json`);
  }
});

function appendixVectors(): Vector[] {
  const e = manifestEntries(PREFIX).find((x) => x.id === APPENDIX_ID);
  assert.ok(e, `manifest lacks ${APPENDIX_ID}`);
  return readFixtureJSON(e.path) as Vector[];
}

test('TestVectorsRequiredByTheDraft', (t) => {
  if (!fixturesPresent(t)) return;
  const vs = appendixVectors();
  const byId = new Map(vs.map((v) => [v.id, v]));
  const want: Record<string, [string, string]> = {
    'empty-body': ['bytes', BODY_DIGEST_OF_EMPTY],
    'operation-b3': ['object', OPERATION_DIGEST_B3],
    'intent-b2': ['object', INTENT_DIGEST_B2],
  };
  for (const [id, [kind, d]] of Object.entries(want)) {
    const v = byId.get(id);
    assert.ok(v, `vector ${id} is missing`);
    assert.equal(v.input_kind, kind, id);
    assert.equal(v.appendix_value, d, `${id}: appendix_value is not the digest the draft prints`);
  }
  const kinds = new Set(vs.map((v) => v.input_kind));
  for (const k of ['object', 'artifact', 'bytes']) assert.ok(kinds.has(k), `no ${k} vector`);
});

type AppendixStatus = 'none' | 'match' | 'defect';

function classifyAppendix(
  v: Pick<Vector, 'id' | 'expected_digest' | 'spec_defect' | 'appendix_value'>,
): AppendixStatus {
  if (v.appendix_value === null && v.spec_defect)
    throw new Error(`vector ${v.id}: spec_defect is set but appendix_value is null`);
  if (v.appendix_value === null) return 'none';
  if (v.appendix_value === v.expected_digest && v.spec_defect)
    throw new Error(`vector ${v.id}: spec_defect is set but appendix_value matches`);
  if (v.appendix_value === v.expected_digest) return 'match';
  if (v.spec_defect) return 'defect';
  throw new Error(`vector ${v.id}: appendix_value differs and spec_defect is not set`);
}

test('TestVectorsViaManifest', async (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  assert.ok(entries.length > 0, 'manifest lists no digest vectors');
  for (const e of entries) {
    await t.test(e.id.slice(PREFIX.length), async (t) => {
      assert.equal(e.kind, 'vector');
      assert.equal(e.scope, 'core');
      assert.equal(e.outcome, 'ACCEPTED');
      assert.ok(e.spec_map_row !== '');
      assert.equal(e.draft_section, '7.4');
      assert.ok(e.path.endsWith('.json') && e.path === e.expected);
      const vs = readFixtureJSON(e.path) as Vector[];
      assert.ok(Array.isArray(vs) && vs.length > 0, `${e.path} has no vectors`);
      const seen = new Set<string>();
      for (const [i, v] of vs.entries()) {
        assert.deepEqual(Object.keys(v).sort(), VECTOR_FIELDS, `vector ${i} members`);
        assert.ok(v.id !== '' && !seen.has(v.id), `vector ${i}: id ${v.id} is empty or repeated`);
        seen.add(v.id);
      }
      for (const v of vs) {
        await t.test(v.id, (t) => {
          assert.doesNotThrow(() => Digest.validate(v.expected_digest), 'expected_digest');
          const got = computeDigest(v);
          assert.equal(got, v.expected_digest);
          const status = classifyAppendix(v);
          if (status === 'defect') {
            t.skip(`spec defect: draft Appendix B states ${v.appendix_value}, computed ${got}`);
          } else if (status === 'match') {
            assert.equal(v.appendix_value, got);
          }
        });
      }
    });
  }
});

// Both ways a caller can hold an object: the parsed value, and JSON text.
function computeDigest(v: Vector): string {
  const input = v.input;
  switch (v.input_kind) {
    case 'object': {
      const viaValue = objectDigest(input);
      const viaText = objectDigest(bytes(JSON.stringify(input)));
      assert.equal(viaValue, viaText, 'objectDigest(value) and objectDigest(text) differ');
      return viaValue;
    }
    case 'artifact':
      assert.equal(typeof v.input, 'string');
      return artifactDigest(v.input as string);
    case 'bytes': {
      const s = v.input as string;
      assert.ok(
        typeof s === 'string' && /^(?:[0-9a-f]{2})*$/.test(s),
        `input ${s} is not lowercase hex`,
      );
      return bytesDigest(new Uint8Array(Buffer.from(s, 'hex')));
    }
    default:
      throw new Error(`input_kind ${v.input_kind} is not object, artifact or bytes`);
  }
}

test('TestClassifyAppendix', () => {
  const a = BODY_DIGEST_OF_EMPTY;
  const b = OPERATION_DIGEST_B3;
  const v = (expected_digest: string, appendix_value: string | null, spec_defect = false) => ({
    id: 'v',
    expected_digest,
    appendix_value,
    spec_defect,
  });
  assert.equal(classifyAppendix(v(a, a)), 'match');
  assert.equal(classifyAppendix(v(a, null)), 'none');
  assert.equal(classifyAppendix(v(a, b, true)), 'defect');
  assert.throws(() => classifyAppendix(v(a, b)));
  assert.throws(() => classifyAppendix(v(a, a, true)));
  assert.throws(() => classifyAppendix(v(a, null, true)));
});
