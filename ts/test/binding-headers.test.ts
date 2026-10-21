// Port of go/core/binding/headers_test.go. An octet that is not UTF-8 is the
// lone surrogate of its value (U+DC80 to U+DCFF), as fromIncomingMessage
// gives it. The Go rule header-key-collision needs a header map, which loses
// the order of field lines that differ only in the case of their name; a
// RawRequest keeps every line in order, so such lines are joined instead.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { Rule } from '../src/core/binding/index.ts';
import {
  bindRefused,
  config,
  from,
  mustBind,
  parse,
  request,
  wantRefused,
} from './support/binding.ts';

const HOST: readonly [string, string] = ['Host', 'gateway.example'];

// Names are lowercase and come from the allowlist only; values are trimmed
// and field lines of one name are joined with ", " in order (RFC 9110 5.2,
// 5.3, 5.5); content-type is added when a body is present (draft 10.2).
describe('TestHeaders', () => {
  const tests: [name: string, allow: string[], raw: string, want: Record<string, string>][] = [
    ['none', [], '\r\n', {}],
    ['allowlisted only', ['x-dry-run'], 'X-Dry-Run: 1\r\nX-Other: 2\r\n\r\n', { 'x-dry-run': '1' }],
    ['allowlist name lowercased', ['If-Match'], 'IF-MATCH: "v1"\r\n\r\n', { 'if-match': '"v1"' }],
    [
      'field lines joined in order',
      ['x-dry-run'],
      'X-Dry-Run: b\r\nX-Other: 1\r\nx-dry-run: a\r\n\r\n',
      { 'x-dry-run': 'b, a' },
    ],
    ['list value kept', ['x-dry-run'], 'X-Dry-Run: a,b ,  c\r\n\r\n', { 'x-dry-run': 'a,b ,  c' }],
    [
      'surrounding whitespace dropped',
      ['x-dry-run'],
      'X-Dry-Run: \t a \t\r\n\r\n',
      { 'x-dry-run': 'a' },
    ],
    ['empty value kept', ['x-dry-run'], 'X-Dry-Run:\r\n\r\n', { 'x-dry-run': '' }],
    [
      'obs-text that is UTF-8 kept',
      ['x-dry-run'],
      'X-Dry-Run: café\r\n\r\n',
      { 'x-dry-run': 'café' },
    ],
    [
      'credentials and signatures not covered',
      ['x-dry-run'],
      'Authorization: Bearer t\r\nPACT-Presentation: a.b.c\r\nSignature: sig1=:AA==:\r\n' +
        'Signature-Input: sig1=()\r\nProxy-Authorization: Basic x\r\nCookie: s=1\r\n\r\n',
      {},
    ],
    [
      'content-type with body',
      ['x-dry-run'],
      'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      { 'content-type': 'application/json' },
    ],
    [
      'no content-type without body',
      ['x-dry-run'],
      'Content-Type: application/json\r\nContent-Length: 0\r\n\r\n',
      {},
    ],
    ['body without content-type', ['x-dry-run'], 'Content-Length: 2\r\n\r\n{}', {}],
    [
      'allowlisted content-type without body',
      ['content-type'],
      'Content-Type: text/plain\r\n\r\n',
      { 'content-type': 'text/plain' },
    ],
    [
      'connection-listed excluded',
      ['x-dry-run', 'if-match'],
      'Connection: keep-alive, X-Dry-Run\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n',
      { 'if-match': '*' },
    ],
    [
      'connection-listed across field lines',
      ['x-dry-run', 'if-match'],
      'Connection: close\r\nConnection:\tif-match ,\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n',
      { 'x-dry-run': '1' },
    ],
    [
      'connection-listed content-type excluded',
      ['x-dry-run'],
      'Connection: Content-Type\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\na',
      {},
    ],
    [
      'name that is an object property',
      ['__proto__', 'constructor'],
      '__proto__: a\r\nconstructor: b\r\n\r\n',
      { ['__proto__']: 'a', constructor: 'b' },
    ],
  ];
  for (const [name, allow, raw, want] of tests) {
    test(name, () => {
      const cfg = config();
      cfg.headerAllowlist = allow;
      const op = mustBind(cfg, parse(`POST /x HTTP/1.1\r\nHost: gateway.example\r\n${raw}`));
      assert.deepEqual(
        Object.entries(op.headers),
        Object.entries(want),
        `headers ${JSON.stringify(op.headers)}`,
      );
      assert.equal(Object.getPrototypeOf(op.headers), Object.prototype);
    });
  }
});

// A request a program builds can carry whitespace a server would have
// removed; the binding trims it itself.
test('TestHeadersTrimmedWhenBuilt', () => {
  const r = request('GET', '/x', [
    [...HOST],
    ['X-Dry-Run', ' a\t'],
    ['X-Dry-Run', '\t b '],
    ['X-Dry-Run', ''],
  ]);
  assert.equal(mustBind(config(), r).headers['x-dry-run'], 'a, b, ');
});

// Header values have maxLength 8192 in the schema; the limit applies to the
// joined value, in characters.
test('TestHeaderValueLength', () => {
  const one = (...values: string[]) =>
    request('GET', '/x', [[...HOST], ...values.map((v) => ['X-Dry-Run', v] as const)]);
  assert.equal(mustBind(config(), one('a'.repeat(8192))).headers['x-dry-run']?.length, 8192);
  wantRefused(() => from(config(), one('a'.repeat(8193))), Rule.HEADER_TOO_LONG);
  wantRefused(() => from(config(), one('a'.repeat(4095), 'b'.repeat(4096))), Rule.HEADER_TOO_LONG);
  // 8192 characters outside the BMP: 16384 UTF-16 code units.
  assert.ok(mustBind(config(), one('\u{1F600}'.repeat(8192))).headers['x-dry-run']);
  wantRefused(() => from(config(), one('\u{1F600}'.repeat(8193))), Rule.HEADER_TOO_LONG);
});

// One failing input per header rule.
describe('TestRejectHeaders', () => {
  const tests: [rule: Rule, name: string, lines: [string, string][]][] = [
    [Rule.HEADER_VALUE, 'NUL', [['X-Dry-Run', 'a\x00b']]],
    [Rule.HEADER_VALUE, 'CR', [['X-Dry-Run', 'a\rb']]],
    [Rule.HEADER_VALUE, 'LF', [['X-Dry-Run', 'a\nb']]],
    [Rule.HEADER_VALUE, 'other control', [['X-Dry-Run', 'a\x01b']]],
    [Rule.HEADER_VALUE, 'DEL', [['X-Dry-Run', 'a\x7fb']]],
    [Rule.HEADER_VALUE, 'invalid UTF-8', [['X-Dry-Run', '\udcff\udcfe']]],
    [Rule.HEADER_VALUE, 'lone surrogate', [['X-Dry-Run', 'a\ud800']]],
    [
      Rule.HEADER_VALUE,
      'second field line',
      [
        ['X-Dry-Run', 'ok'],
        ['X-Dry-Run', '\udcc0\udcaf'],
      ],
    ],
    [Rule.HEADER_VALUE, 'content-type with body', [['Content-Type', 'text/\x01plain']]],
  ];
  for (const [rule, name, lines] of tests) {
    test(`${rule}/${name}`, () => {
      const hasType = lines.some(([n]) => n === 'Content-Type');
      const r = request('POST', '/x', [[...HOST], ...lines], hasType ? 'a' : '');
      wantRefused(() => from(config(), r), rule);
    });
  }
  test('two spellings of one name are joined in order', () => {
    const r = request('POST', '/x', [[...HOST], ['X-Dry-Run', '1'], ['x-dry-run', '2']]);
    assert.equal(mustBind(config(), r).headers['x-dry-run'], '1, 2');
  });
});

// More than one Host field line is refused (RFC 9112 3.2; request-binding.md
// RB-65), with names in any case and even when the values are equal; one
// Host line is not covered.
describe('TestRejectDuplicateHost', () => {
  const tests: [name: string, lines: [string, string][]][] = [
    [
      'same value',
      [
        ['Host', 'gateway.example'],
        ['Host', 'gateway.example'],
      ],
    ],
    [
      'other value',
      [
        ['Host', 'gateway.example'],
        ['Host', 'evil.example'],
      ],
    ],
    [
      'two spellings',
      [
        ['Host', 'gateway.example'],
        ['host', 'gateway.example'],
      ],
    ],
    [
      'with an allowlisted header',
      [
        ['Host', 'a'],
        ['If-Match', '"v1"'],
        ['HOST', 'b'],
      ],
    ],
  ];
  for (const [name, lines] of tests) {
    test(name, () => {
      wantRefused(() => from(config(), request('GET', '/x', lines)), Rule.DUPLICATE_HOST);
    });
  }
  test('one Host line', () => {
    const op = mustBind(config(), request('GET', '/x', [['Host', 'evil.example']]));
    assert.deepEqual(op.headers, {});
    assert.equal(op.target_uri, 'https://gateway.example/x');
  });
});

// node:http accepts a second Host field line (docs/sdk/probes/ts.md, P1), so
// the binding refuses it from the wire.
test('TestRejectDuplicateHostOverWire', async () => {
  await bindRefused(
    config(),
    'GET /x HTTP/1.1\r\nHost: gateway.example\r\nHost: gateway.example\r\n\r\n',
    Rule.DUPLICATE_HOST,
  );
});

// Host values that are, and are not, uri-host [ ":" port ] with a non-empty
// host (RFC 9110 4.2.2, 7.2; RFC 3986 3.2.2, 3.2.3; request-binding.md RB-66).
const VALID_HOSTS = [
  'gateway.example',
  'GATEWAY.example:443',
  'gateway.example:',
  '192.0.2.1:8443',
  '[::1]',
  '[2001:db8::1]:443',
  '[v1.x]',
  'g%41teway.example',
  ' gateway.example\t',
];
const INVALID_HOSTS = [
  '',
  'gate way.example',
  'gateway.example/x',
  'a@b',
  '[::1',
  '[fe80::1%25en0]',
  '[192.0.2.1]',
  'gateway.example:abc',
  'caf\u00e9.example',
  '%zz.example',
  ':443',
  'a:1:2',
  '[::1]x',
];

describe('TestHostValues', () => {
  test('valid', () => {
    for (const v of VALID_HOSTS) mustBind(config(), request('GET', '/x', [['Host', v]]));
  });
  test('invalid', () => {
    for (const v of INVALID_HOSTS) {
      wantRefused(() => from(config(), request('GET', '/x', [['Host', v]])), Rule.INVALID_HOST);
    }
  });
  test('an absolute-form target is checked too', () => {
    const r = request('GET', 'https://gateway.example/x', [['Host', 'a@b']]);
    wantRefused(() => from(config(), r), Rule.INVALID_HOST);
  });
});

// An origin-form request without Host has no authority and is refused; an
// absolute-form target carries its own (RFC 9112 3.2.2).
describe('TestMissingHost', () => {
  test('origin-form', () => {
    wantRefused(() => from(config(), request('GET', '/x', [])), Rule.MISSING_HOST);
  });
  test('absolute-form', () => {
    const op = mustBind(config(), request('GET', 'https://gateway.example/x', []));
    assert.equal(op.target_uri, 'https://gateway.example/x');
  });
});

// node:http passes a port that is not digits on to the handler.
test('TestInvalidHostOverWire', async () => {
  await bindRefused(
    config(),
    'GET /x HTTP/1.1\r\nHost: gateway.example:abc\r\n\r\n',
    Rule.INVALID_HOST,
  );
});

// node:http passes obs-text through, so a header that is not UTF-8 reaches
// the binding from the wire.
test('TestRejectHeaderValueOverWire', async () => {
  await bindRefused(
    config(),
    'GET /x HTTP/1.1\r\nHost: gateway.example\r\nX-Dry-Run: \xff\xfe\r\n\r\n',
    Rule.HEADER_VALUE,
  );
});

// Without a body, content-type is not part of the operation context unless
// allowlisted, so its value is not examined.
test('TestContentTypeIgnoredWithoutBody', () => {
  const r = request('GET', '/x', [[...HOST], ['Content-Type', '\udcff']]);
  assert.deepEqual(mustBind(config(), r).headers, {});
});
