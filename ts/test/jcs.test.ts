// Port of go/core/jcs/jcs_test.go and number_test.go, plus the JCS property
// test of the plan (section 6, item 5). Expected texts are those of the Go
// tests, produced there by the RFC 8785 Appendix A reference canonicalizer
// on V8, and the RFC 8785 Appendix B table.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalize } from '../src/core/jcs.ts';
import {
  DEFAULT_MAX_BYTES,
  parse,
  StrictJSONError,
  type StrictJSONErrorKind,
} from '../src/core/strictjson.ts';
import { numberText } from '../src/internal/numbers.ts';
import { bytes, str } from './support/fixtures.ts';

function canon(input: string | Uint8Array): string {
  return str(canonicalize(input));
}

function errorOf(f: () => unknown): unknown {
  try {
    f();
  } catch (err) {
    return err;
  }
  return undefined;
}

test('TestCanonicalize', async (t) => {
  const tests: [string, string, string][] = [
    [
      'whitespace dropped',
      ' { "b" : [ { "z" : 1 , "y" : [ ] } , { } ] , "a" : { "d" : null , "c" : true , "e" : false } } \n',
      '{"a":{"c":true,"d":null,"e":false},"b":[{"y":[],"z":1},{}]}',
    ],
    ['array order kept', '[3,1,2,"b","a"]', '[3,1,2,"b","a"]'],
    ['empty containers', '[[],{}]', '[[],{}]'],
    ['top-level string', '"x"', '"x"'],
    ['top-level number', '1.50', '1.5'],
    ['top-level null', 'null', 'null'],
    ['top-level true', 'true', 'true'],
    ['top-level false', 'false', 'false'],
    ['top-level minus zero', '-0', '0'],
    // U+10000 is the surrogate pair D800 DC00, which sorts before U+FFFF by
    // UTF-16 code units; by code point or by UTF-8 bytes it sorts after.
    [
      'keys by UTF-16 units',
      '{"\\uffff":1,"\\ud800\\udc00":2,"a":3,"ab":4,"":5,"B":6}',
      '{"":5,"B":6,"a":3,"ab":4,"\u{10000}":2,"\uffff":1}',
    ],
    ['keys are compared unescaped', '{"\\u0062":1,"a":2}', '{"a":2,"b":1}'],
    [
      'key escapes follow string rules',
      '{"\\u000a":1,"\\"":2,"\\\\":3,"/":4}',
      '{"\\n":1,"\\"":2,"/":4,"\\\\":3}',
    ],
    [
      'string escapes',
      '"\\u0000\\u0001\\u0008\\u0009\\u000a\\u000b\\u000c\\u000d\\u001f \\" \\\\ / \\u007f \\u2028 \\u2029 \\u00e9 \\ud83d\\ude02 <>&\'"',
      '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f \\" \\\\ / \x7f \u2028 \u2029 \u00e9 \u{1F602} <>&\'"',
    ],
    ['string literal chars kept', '"\u00e9\u20ac\u{1F602}"', '"\u00e9\u20ac\u{1F602}"'],
    ['no unicode normalization', '"A\\u030a"', '"A\u030a"'],
    [
      'numbers',
      '[1.0, -0, -0.0, 1E+2, 0.1, 1e21, 1e-7, 1.5e300, 5e-324, 1e-400, 0.000001, 0.0000001, 1e20, 123456789.125, 4.35, 0.30000000000000004, 1e22, 1e23, 12345678901234567890e0, 100e-2, 9007199254740991, -9007199254740991, 1.7976931348623157e308, 2.5e-5]',
      '[1,0,0,100,0.1,1e+21,1e-7,1.5e+300,5e-324,0,0.000001,1e-7,100000000000000000000,123456789.125,4.35,0.30000000000000004,1e+22,1e+23,12345678901234567000,1,9007199254740991,-9007199254740991,1.7976931348623157e+308,0.000025]',
    ],
  ];
  for (const [name, input, want] of tests) {
    await t.test(name, () => {
      const b = bytes(input);
      const orig = b.slice();
      const got = canonicalize(b);
      assert.equal(str(got), want);
      assert.deepEqual(b, orig, 'input was modified');
      // A canonical form is canonical, except a float such as 1e20, written
      // without an exponent, which the strict parse refuses as an integer.
      const again = errorOf(() => assert.equal(canon(got), want));
      if (again !== undefined) {
        assert.ok(again instanceof StrictJSONError && again.kind === 'INTEGER', String(again));
      }
    });
  }
});

test('TestCanonicalizeRejects', async (t) => {
  const tests: [string, string | Uint8Array, StrictJSONErrorKind][] = [
    ['empty input', '', 'SYNTAX'],
    ['only whitespace', ' ', 'SYNTAX'],
    ['truncated', '{"a":', 'SYNTAX'],
    ['trailing comma', '[1,]', 'SYNTAX'],
    ['duplicate key', '{"a":1,"a":2}', 'DUPLICATE_KEY'],
    ['duplicate key in escaped form', '{"a":1,"\\u0061":2}', 'DUPLICATE_KEY'],
    ['duplicate key nested', '{"o":{"k":1,"k":1}}', 'DUPLICATE_KEY'],
    ['NaN', 'NaN', 'NON_FINITE'],
    ['Infinity', '[Infinity]', 'NON_FINITE'],
    ['negative Infinity', '-Infinity', 'NON_FINITE'],
    ['overflowing literal', '1e999', 'NON_FINITE'],
    ['negative overflowing literal', '{"a":-1e999}', 'NON_FINITE'],
    ['integer 2^53', '9007199254740992', 'INTEGER'],
    ['integer -2^53', '[-9007199254740992]', 'INTEGER'],
    ['integer far outside', '{"a":123456789012345678901234567890}', 'INTEGER'],
    ['lone high surrogate', '"\\ud800"', 'LONE_SURROGATE'],
    ['lone low surrogate', '"\\udc00"', 'LONE_SURROGATE'],
    ['invalid UTF-8', Uint8Array.of(0x22, 0xff, 0x22), 'INVALID_UTF8'],
    ['encoded surrogate', Uint8Array.of(0x22, 0xed, 0xa0, 0x80, 0x22), 'INVALID_UTF8'],
    ['trailing data', '{} {}', 'TRAILING_DATA'],
    ['too deep', `${'['.repeat(17)}${']'.repeat(17)}`, 'DEPTH'],
    ['too large', `"${'a'.repeat(DEFAULT_MAX_BYTES)}"`, 'SIZE'],
  ];
  for (const [name, input, want] of tests) {
    await t.test(name, () => {
      let got: Uint8Array | undefined;
      const err = errorOf(() => {
        got = canonicalize(input);
      });
      assert.equal(got, undefined, 'result alongside an error');
      assert.ok(err instanceof StrictJSONError, `want ${want}, got ${String(err)}`);
      assert.equal(err.kind, want, err.message);
    });
  }
});

test('TestCanonicalOutputBeyondSafeInteger', () => {
  const out = canon('[1e20,1e21,9007199254740993.0]');
  assert.equal(out, '[100000000000000000000,1e+21,9007199254740992]');
  const err = errorOf(() => canonicalize(out));
  assert.ok(err instanceof StrictJSONError && err.kind === 'INTEGER', String(err));
});

test('TestCanonicalizeAtDepthLimit', () => {
  const input = `${'{"a":'.repeat(16)}1${'}'.repeat(16)}`;
  assert.equal(canon(input), input);
});

test('TestCanonicalizeSortsManyKeys', () => {
  const n = 200;
  const pad = (i: number) => String(i).padStart(3, '0');
  const input = Array.from({ length: n }, (_, i) => `"k${pad(n - 1 - i)}":${i}`).join(',');
  const want = Array.from({ length: n }, (_, i) => `"k${pad(i)}":${n - 1 - i}`).join(',');
  assert.equal(canon(`{${input}}`), `{${want}}`);
});

// RFC 8785 Appendix B, less NaN and Infinity, which JSON cannot carry.
const APPENDIX_B: readonly [string, string][] = [
  ['0000000000000000', '0'],
  ['8000000000000000', '0'],
  ['0000000000000001', '5e-324'],
  ['8000000000000001', '-5e-324'],
  ['7fefffffffffffff', '1.7976931348623157e+308'],
  ['ffefffffffffffff', '-1.7976931348623157e+308'],
  ['4340000000000000', '9007199254740992'],
  ['c340000000000000', '-9007199254740992'],
  ['4430000000000000', '295147905179352830000'],
  ['44b52d02c7e14af5', '9.999999999999997e+22'],
  ['44b52d02c7e14af6', '1e+23'],
  ['44b52d02c7e14af7', '1.0000000000000001e+23'],
  ['444b1ae4d6e2ef4e', '999999999999999700000'],
  ['444b1ae4d6e2ef4f', '999999999999999900000'],
  ['444b1ae4d6e2ef50', '1e+21'],
  ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
  ['3eb0c6f7a0b5ed8d', '0.000001'],
  ['41b3de4355555553', '333333333.3333332'],
  ['41b3de4355555554', '333333333.33333325'],
  ['41b3de4355555555', '333333333.3333333'],
  ['41b3de4355555556', '333333333.3333334'],
  ['41b3de4355555557', '333333333.33333343'],
  ['becbf647612f3696', '-0.0000033333333333333333'],
  ['43143ff3c1cb0959', '1424953923781206.2'],
];

function fromBits(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

// The exponent-form literal of f, valid JSON at any magnitude, sign of zero kept.
function literal(f: number): string {
  return (Object.is(f, -0) ? '-' : '') + f.toExponential();
}

test('TestAppendNumberAppendixB', () => {
  for (const [hex, want] of APPENDIX_B) {
    const f = fromBits(hex);
    assert.equal(numberText(f), want, hex);
    assert.equal(canon(literal(f)), want, `${hex} through canonicalize`);
  }
});

// The ECMAScript layout switches at 10^21 and 10^-6; the exponent carries an
// explicit sign and no padding. Expected values come from V8 (JSON.stringify)
// as recorded in the Go test.
test('TestAppendNumberLayout', () => {
  const tests: [number, string][] = [
    [1e21, '1e+21'],
    [-1e21, '-1e+21'],
    [9.999999999999999e20, '999999999999999900000'],
    [1e20, '100000000000000000000'],
    [1.23e20, '123000000000000000000'],
    [123456789012345680000, '123456789012345680000'],
    [1.5e25, '1.5e+25'],
    [1e100, '1e+100'],
    [2 ** 70, '1.1805916207174113e+21'],
    [1e15, '1000000000000000'],
    [100, '100'],
    [123, '123'],
    [22, '22'],
    [12.5, '12.5'],
    [1234.5678, '1234.5678'],
    [0.5, '0.5'],
    [1 / 3, '0.3333333333333333'],
    [0.1 + 0.2, '0.30000000000000004'],
    [1e-6, '0.000001'],
    [2e-6, '0.000002'],
    [1.5e-6, '0.0000015'],
    [4.5e-6, '0.0000045'],
    [0.000123, '0.000123'],
    [9.999999999999997e-7, '9.999999999999997e-7'],
    [5e-7, '5e-7'],
    [1e-7, '1e-7'],
    [1.5e-7, '1.5e-7'],
    [-1.5e-7, '-1.5e-7'],
    [1.2345e-100, '1.2345e-100'],
    [2.2250738585072014e-308, '2.2250738585072014e-308'],
    [5e-324, '5e-324'],
    [2 ** 53, '9007199254740992'],
    [2 ** 53 + 2, '9007199254740994'],
    [Number.MAX_VALUE, '1.7976931348623157e+308'],
    [-Number.MAX_VALUE, '-1.7976931348623157e+308'],
    [-0, '0'],
    [0, '0'],
  ];
  for (const [f, want] of tests) {
    assert.equal(numberText(f), want, String(f));
    assert.equal(canon(literal(f)), want, `${f} through canonicalize`);
  }
});

test('TestAppendNumberRoundTrip', () => {
  const vals = APPENDIX_B.map(([hex]) => fromBits(hex));
  for (let e = -330; e <= 308; e++) {
    for (const m of ['1', '1.5', '9.999999999999998', '7.123456789012345']) {
      const v = Number(`${m}e${e}`);
      if (!Number.isFinite(v)) continue;
      vals.push(v, -v);
    }
  }
  for (const f of vals) {
    const s = numberText(f);
    assert.ok(Object.is(Number(s), f === 0 ? 0 : f), `${f} -> ${s} -> ${Number(s)}`);
  }
});

test('TestAppendNumberNonFinite', () => {
  for (const f of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(() => numberText(f), RangeError, String(f));
  }
});

// Property test: random JSON trees, written with random white space and
// member order, canonicalize to a text that (1) is canonical (idempotent),
// (2) strictly parses to the same value, and (3) has every object's members
// in UTF-16 code unit order. Deterministic: a fixed seed per run.

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Tree = null | boolean | number | string | Tree[] | { [k: string]: Tree };

const CODE_POINTS = [
  0x00, 0x01, 0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x1f, 0x20, 0x22, 0x2f, 0x41, 0x42, 0x5c, 0x61, 0x7e,
  0x7f, 0xe9, 0x20ac, 0x2028, 0x2029, 0xfb33, 0xfeff, 0xff5e, 0xffff, 0x10000, 0x1f600, 0x10ffff,
];

function generator(rand: () => number) {
  const int = (n: number) => Math.floor(rand() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const string = (): string => {
    const n = int(6);
    let s = '';
    for (let i = 0; i < n; i++) s += String.fromCodePoint(pick(CODE_POINTS));
    return s;
  };
  // Finite, and outside [2^53, 1e21), where a double is written as an
  // integer literal that the strict parse refuses (TestCanonicalOutputBeyondSafeInteger).
  const usable = (f: number): number =>
    Number.isFinite(f) && !(Math.abs(f) >= 2 ** 53 && Math.abs(f) < 1e21) ? f : 0.5;
  const anyNumber = (): number => {
    switch (int(5)) {
      case 0:
        return int(2001) - 1000;
      case 1:
        return (rand() - 0.5) * 10 ** (int(40) - 20);
      case 2: {
        // Any bit pattern.
        const view = new DataView(new ArrayBuffer(8));
        view.setUint32(0, int(2 ** 32));
        view.setUint32(4, int(2 ** 32));
        return view.getFloat64(0);
      }
      case 3:
        return pick([0, -0, 2 ** 53 - 1, -(2 ** 53 - 1), 1e21, 5e-324, 1e-7, Number.MAX_VALUE]);
      default:
        return rand();
    }
  };
  const number = (): number => usable(anyNumber());
  const tree = (depth: number): Tree => {
    const k = depth >= 6 ? int(4) : int(6);
    switch (k) {
      case 0:
        return pick([null, true, false]);
      case 1:
        return number();
      case 2:
      case 3:
        return string();
      case 4:
        return Array.from({ length: int(4) }, () => tree(depth + 1));
      default: {
        const o: { [k: string]: Tree } = {};
        for (let i = int(5); i > 0; i--) {
          Object.defineProperty(o, string(), {
            value: tree(depth + 1),
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
        return o;
      }
    }
  };
  const ws = () => pick(['', '', ' ', '\n', '\t', '\r\n ']);
  // A JSON text of v with random white space, members in random order and
  // numbers in exponent form half the time.
  const text = (v: Tree): string => {
    if (Array.isArray(v)) return `[${ws()}${v.map(text).join(`${ws()},${ws()}`)}${ws()}]`;
    if (typeof v === 'number') return rand() < 0.5 ? literal(v) : JSON.stringify(v);
    if (v !== null && typeof v === 'object') {
      const keys = Object.keys(v).sort(() => rand() - 0.5);
      const members = keys.map(
        (k) => `${ws()}${JSON.stringify(k)}${ws()}:${ws()}${text(v[k] as Tree)}`,
      );
      return `{${members.join(',')}${ws()}}`;
    }
    return JSON.stringify(v);
  };
  return { tree, text };
}

// The member names of every object of a canonical text, in text order (an
// object's enumeration order puts integer-like names first, so the parsed
// value cannot show the order).
function memberNameLists(text: string): string[][] {
  const lists: string[][] = [];
  const stack: (string[] | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') {
      const names: string[] = [];
      lists.push(names);
      stack.push(names);
    } else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (text[j + 1] === ':' && top) top.push(JSON.parse(text.slice(i, j + 1)) as string);
      i = j;
    }
  }
  return lists;
}

function compareUnits(a: string, b: string): number {
  for (let j = 0; j < Math.min(a.length, b.length); j++) {
    const c = a.charCodeAt(j) - b.charCodeAt(j);
    if (c !== 0) return c;
  }
  return a.length - b.length;
}

function checkSorted(text: string): void {
  for (const names of memberNameLists(text)) {
    for (let i = 1; i < names.length; i++) {
      const a = names[i - 1] as string;
      const b = names[i] as string;
      assert.ok(
        compareUnits(a, b) < 0,
        `members ${JSON.stringify(a)}, ${JSON.stringify(b)} out of order`,
      );
    }
  }
}

// -0 is written 0 (RFC 8785 section 3.2.2.3): compare values with zeros unsigned.
function unsignedZeros(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(unsignedZeros);
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).map(([k, e]) => [k, unsignedZeros(e)]));
  }
  return Object.is(v, -0) ? 0 : v;
}

test('TestCanonicalizeProperties', () => {
  const seed = 0x5eed;
  const rand = mulberry32(seed);
  const { tree, text } = generator(rand);
  for (let i = 0; i < 2000; i++) {
    const v = tree(0);
    const input = text(v);
    const out = canonicalize(input);
    const outText = str(out);
    assert.equal(canon(out), outText, `seed ${seed} case ${i}: not idempotent: ${input}`);
    assert.deepEqual(
      parse(out),
      unsignedZeros(parse(input)),
      `seed ${seed} case ${i}: value changed: ${input}`,
    );
    checkSorted(outText);
    assert.ok(
      !/[\s]/.test(outText.replace(/"(?:[^"\\]|\\.)*"/g, '')),
      `white space left: ${outText}`,
    );
  }
});

test('the key order is the UTF-16 code unit order of RFC 8785 section 3.2.3', () => {
  // RFC 8785 section 3.2.3 sample: CR, One, Control, o-umlaut, Euro, Emoji, Dalet.
  const input =
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}';
  assert.equal(
    canon(input),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\u{1F600}":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
  );
  // U+1F600 (D83D DE00) sorts before U+FF5E by code units, after it by code point.
  assert.equal(canon('{"\\uff5e":2,"\\ud83d\\ude00":1}'), '{"\u{1F600}":1,"\uff5e":2}');
});
