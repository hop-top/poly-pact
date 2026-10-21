// Port of go/core/binding/target_test.go. A Go request parsed by net/http or
// built by hand is a RawRequest here; an octet that is not UTF-8 is the lone
// surrogate of its value (U+DC80 to U+DCFF), as fromIncomingMessage gives
// it. TestRejectProgrammaticURL has no counterpart: a RawRequest has no
// parsed URL that could carry a fragment or userinfo its target does not
// show; its last case, userinfo in the target alone, is a TestRejectTarget
// row.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { fromIncomingMessage, Rule } from '../src/core/binding/index.ts';
import {
  ACTION,
  config,
  from,
  get,
  mustBind,
  ORIGIN,
  overWire,
  PRINCIPAL,
  parse,
  RESOURCE,
  request,
  wantRefused,
  wantRule,
} from './support/binding.ts';

// target_uri is the configured origin plus the exact path and query of the
// request target; octets, percent encoding and query order are kept (draft
// 10.2).
describe('TestTargetURIPreserved', () => {
  const tests: [name: string, target: string, want: string][] = [
    ['appendix B.3', '/invoices/INV-1042', `${ORIGIN}/invoices/INV-1042`],
    ['root', '/', `${ORIGIN}/`],
    ['query order', '/s?b=2&a=1&b=1', `${ORIGIN}/s?b=2&a=1&b=1`],
    ['uppercase escapes kept', '/files/a%20b?q=%C3%A9', `${ORIGIN}/files/a%20b?q=%C3%A9`],
    ['sub-delims colon at', "/a:b@c!$&'()*+,;=?x=/?:@", `${ORIGIN}/a:b@c!$&'()*+,;=?x=/?:@`],
    ['empty query kept', '/a?', `${ORIGIN}/a?`],
    ['dots inside a segment', '/a..b', `${ORIGIN}/a..b`],
    ['three dots', '/.../', `${ORIGIN}/.../`],
    ['dot in a segment', '/a.b/', `${ORIGIN}/a.b/`],
    ['dot prefix and suffix', '/.a/b./..c/', `${ORIGIN}/.a/b./..c/`],
    ['dot segments in the query', '/a?x=./..&y=/../.', `${ORIGIN}/a?x=./..&y=/../.`],
    ['double slash kept', '//a//b', `${ORIGIN}//a//b`],
    ['encoded slash in query', '/a?u=%2F%3F%23', `${ORIGIN}/a?u=%2F%3F%23`],
    ['encoded question mark in path', '/a%3Fb', `${ORIGIN}/a%3Fb`],
    ['encoded percent in path', '/a%25b', `${ORIGIN}/a%25b`],
    ['encoded backslash in path', '/a%5Cb', `${ORIGIN}/a%5Cb`],
    ['encoded NUL in path', '/a%00b', `${ORIGIN}/a%00b`],
    ['encoded space plus', '/a?q=a+b%20c', `${ORIGIN}/a?q=a+b%20c`],
    ['absolute-form', 'https://gateway.example/x?y=1', `${ORIGIN}/x?y=1`],
    ['absolute-form other authority', 'http://Other.Example:8080/x', `${ORIGIN}/x`],
  ];
  for (const [name, target, want] of tests) {
    test(name, () => {
      assert.equal(mustBind(config(), get(target)).target_uri, want);
    });
  }
});

// The origin comes from trusted configuration; Host and forwarding headers
// cannot select it (draft 10.2).
test('TestTargetURIIgnoresForwardingHeaders', () => {
  const r = parse(
    'GET /x HTTP/1.1\r\nHost: evil.example\r\n' +
      'X-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: http\r\n' +
      'Forwarded: host=evil.example;proto=http\r\n\r\n',
  );
  assert.equal(mustBind(config(), r).target_uri, `${ORIGIN}/x`);
});

// target_uri has maxLength 1024 in the schema.
test('TestTargetURILength', () => {
  const path = `/${'a'.repeat(1024 - ORIGIN.length - 1)}`;
  assert.equal(mustBind(config(), get(path)).target_uri.length, 1024);
  wantRefused(() => from(config(), get(`${path}a`)), Rule.TARGET_TOO_LONG);
});

// method is the uppercase HTTP method (draft 10.2).
describe('TestMethodUppercased', () => {
  for (const [m, want] of [
    ['GET', 'GET'],
    ['get', 'GET'],
    ['Patch', 'PATCH'],
    ['DELETE', 'DELETE'],
  ] as const) {
    test(m, () => {
      const op = mustBind(config(), parse(`${m} /x HTTP/1.1\r\nHost: gateway.example\r\n\r\n`));
      assert.equal(op.method, want);
    });
  }
});

// The schema pattern for method is ^[A-Z]+$, and only ASCII letters are
// uppercased, so a Unicode case mapping cannot make one.
describe('TestRejectMethod', () => {
  for (const m of ['', 'M-SEARCH', 'GET1', 'ſet', 'GİT']) {
    test(JSON.stringify(m), () => {
      wantRefused(() => from(config(), request(m, '/x')), Rule.METHOD);
    });
  }
});

// Failing inputs for every target rule. The ambiguous encodings are those of
// draft 10.2: an encoded unreserved character, a lowercase hex digit in an
// escape, invalid or overlong UTF-8 in the decoded octets, an encoded slash
// in the path, and a dot segment, which the path segment normalization of
// RFC 3986 6.2.2.3 would remove. An encoded dot segment such as %2E%2E is
// refused as an encoded unreserved character.
describe('TestRejectTarget', () => {
  const tests: [rule: Rule, name: string, target: string][] = [
    [Rule.FRAGMENT, 'path', '/a#b'],
    [Rule.FRAGMENT, 'query', '/a?b#c'],
    [Rule.FRAGMENT, 'empty', '/a#'],
    [Rule.FRAGMENT, 'absolute-form', 'https://gateway.example/a#b'],

    [Rule.USERINFO, 'user and password', 'https://u:p@gateway.example/x'],
    [Rule.USERINFO, 'user', 'https://u@gateway.example/x'],
    [Rule.USERINFO, 'empty', 'https://@gateway.example/x'],
    [Rule.USERINFO, 'other scheme', 'ftp://u@gateway.example/x'],

    [Rule.NON_ASCII_HOST, 'raw UTF-8', 'https://bücher.example/x'],
    [Rule.NON_ASCII_HOST, 'percent-encoded', 'https://b%C3%BCcher.example/x'],
    [Rule.NON_ASCII_HOST, 'raw byte', 'https://b\udcfccher.example/x'],

    [Rule.ENCODED_UNRESERVED, 'ALPHA', '/%41'],
    [Rule.ENCODED_UNRESERVED, 'alpha', '/a%7A'],
    [Rule.ENCODED_UNRESERVED, 'DIGIT', '/%30'],
    [Rule.ENCODED_UNRESERVED, 'hyphen', '/a%2Db'],
    [Rule.ENCODED_UNRESERVED, 'dot segment', '/%2E%2E/secret'],
    [Rule.ENCODED_UNRESERVED, 'underscore', '/a%5F'],
    [Rule.ENCODED_UNRESERVED, 'tilde in query', '/a?x=%7E'],

    [Rule.LOWERCASE_HEX, 'encoded slash', '/a%2fb'],
    [Rule.LOWERCASE_HEX, 'UTF-8', '/caf%c3%a9'],
    [Rule.LOWERCASE_HEX, 'query', '/a?x=%3d'],
    [Rule.LOWERCASE_HEX, 'mixed case', '/a?x=%aB'],
    [Rule.LOWERCASE_HEX, 'second digit', '/%3a'],

    [Rule.INVALID_UTF8, 'overlong slash', '/%C0%AF'],
    [Rule.INVALID_UTF8, 'overlong three octets', '/%E0%80%AF'],
    [Rule.INVALID_UTF8, 'overlong NUL in query', '/a?x=%C0%80'],
    [Rule.INVALID_UTF8, 'surrogate', '/%ED%A0%80'],
    [Rule.INVALID_UTF8, 'above U+10FFFF', '/%F4%90%80%80'],
    [Rule.INVALID_UTF8, 'FF', '/%FF'],
    [Rule.INVALID_UTF8, 'truncated', '/%C3'],
    [Rule.INVALID_UTF8, 'split by a slash', '/%C3/%A9'],

    [Rule.DOT_SEGMENT, 'single dot', '/a/./b'],
    [Rule.DOT_SEGMENT, 'double dot', '/a/../b'],
    [Rule.DOT_SEGMENT, 'root single dot', '/.'],
    [Rule.DOT_SEGMENT, 'root double dot', '/..'],
    [Rule.DOT_SEGMENT, 'trailing single dot', '/a/.'],
    [Rule.DOT_SEGMENT, 'trailing double dot', '/a/..'],
    [Rule.DOT_SEGMENT, 'before a query', '/a/..?x=1'],
    [Rule.DOT_SEGMENT, 'after an empty segment', '//../a'],
    [Rule.DOT_SEGMENT, 'absolute-form', 'https://gateway.example/a/../b'],

    [Rule.ENCODED_SLASH, 'inside a segment', '/a%2Fb'],
    [Rule.ENCODED_SLASH, 'alone', '/%2F'],

    [Rule.MALFORMED_ESCAPE, 'non-hex in query', '/a?x=%zz'],
    [Rule.MALFORMED_ESCAPE, 'one digit at end of query', '/a?x=%4'],
    [Rule.MALFORMED_ESCAPE, 'bare percent in path', '/a%'],
    [Rule.MALFORMED_ESCAPE, 'non-hex in path', '/a%G1'],

    [Rule.INVALID_CHARACTER, 'raw UTF-8 in path', '/café'],
    [Rule.INVALID_CHARACTER, 'raw byte in query', '/a?x=\udcff'],
    [Rule.INVALID_CHARACTER, 'lone surrogate in path', '/a\ud800'],
    [Rule.INVALID_CHARACTER, 'brackets in query', '/a?x[]=1'],
    [Rule.INVALID_CHARACTER, 'brace', '/a{b}'],
    [Rule.INVALID_CHARACTER, 'pipe', '/a|b'],
    [Rule.INVALID_CHARACTER, 'backslash', '/a\\b'],
    [Rule.INVALID_CHARACTER, 'quote', '/a"b'],
    [Rule.INVALID_CHARACTER, 'caret and backtick', '/a^`'],
    [Rule.INVALID_CHARACTER, 'angle brackets', '/a<b>'],
    [Rule.INVALID_CHARACTER, 'space', '/a b'],
    [Rule.INVALID_CHARACTER, 'tab', '/a\tb'],
    [Rule.INVALID_CHARACTER, 'DEL', '/a\x7fb'],

    [Rule.TARGET_FORM, 'asterisk-form', '*'],
    [Rule.TARGET_FORM, 'authority-form', 'gateway.example:443'],
    [Rule.TARGET_FORM, 'opaque URI', 'foo:bar'],
    [Rule.TARGET_FORM, 'other scheme', 'ftp://gateway.example/x'],
    [Rule.TARGET_FORM, 'empty host', 'https:///x'],
    [Rule.TARGET_FORM, 'absolute-form without path', 'https://gateway.example'],
    [Rule.TARGET_FORM, 'absolute-form query without path', 'https://gateway.example?x'],
    [Rule.TARGET_FORM, 'empty', ''],
  ];
  for (const [rule, name, target] of tests) {
    test(`${rule}/${name}`, () => {
      wantRefused(() => from(config(), get(target)), rule);
    });
  }
});

// The target rules that matter most, through a real node:http server, so the
// inputs are what a gateway receives. The parser answers 400 itself to a raw
// non-ASCII octet in the target (docs/sdk/probes/ts.md, P1), so that row
// never reaches the binding over node:http.
describe('TestRejectTargetOverWire', () => {
  const tests: [rule: Rule, target: string, parser400?: boolean][] = [
    [Rule.FRAGMENT, '/a#b'],
    [Rule.USERINFO, 'https://u:p@gateway.example/x'],
    [Rule.NON_ASCII_HOST, 'https://bÃ¼cher.example/x', true],
    [Rule.ENCODED_UNRESERVED, '/%41'],
    [Rule.LOWERCASE_HEX, '/a%2fb'],
    [Rule.INVALID_UTF8, '/%C0%AF'],
    [Rule.ENCODED_SLASH, '/a%2Fb'],
    [Rule.DOT_SEGMENT, '/a/../b'],
  ];
  for (const [rule, target, parser400] of tests) {
    test(rule, async () => {
      const w = await overWire(`GET ${target} HTTP/1.1\r\nHost: gateway.example\r\n\r\n`, (msg) =>
        fromIncomingMessage(config(), msg, PRINCIPAL, ACTION, [RESOURCE]),
      );
      if (parser400) {
        assert.equal(w.called, false);
        assert.equal(w.status, 'HTTP/1.1 400 Bad Request');
        return;
      }
      assert.ok(w.called, w.status);
      wantRule(w.error, rule);
    });
  }
});

// A missing request has nothing to bind.
test('TestRejectNoRequest', () => {
  wantRefused(() => from(config(), null), Rule.NO_REQUEST);
  wantRefused(() => from(config(), undefined), Rule.NO_REQUEST);
});

// Scheme and host are lowercase and a default port is omitted (draft 10.2;
// RFC 3986 6.2.2.1 and 6.2.3; RFC 9110 4.2.2 and 4.2.3).
describe('TestOriginNormalized', () => {
  const tests: [origin: string, want: string][] = [
    ['https://gateway.example', 'https://gateway.example'],
    ['HTTPS://Gateway.EXAMPLE', 'https://gateway.example'],
    ['https://gateway.example:443', 'https://gateway.example'],
    ['https://gateway.example:', 'https://gateway.example'],
    ['https://gateway.example:8443', 'https://gateway.example:8443'],
    ['https://GATEWAY.example:8443', 'https://gateway.example:8443'],
    ['https://192.0.2.1:443', 'https://192.0.2.1'],
    ['https://[2001:DB8::1]:443', 'https://[2001:db8::1]'],
    ['https://[2001:db8::1]:8443', 'https://[2001:db8::1]:8443'],
  ];
  for (const [origin, want] of tests) {
    test(origin, () => {
      const cfg = config();
      cfg.origin = origin;
      assert.equal(mustBind(cfg, get('/A%20B?Q')).target_uri, `${want}/A%20B?Q`);
    });
  }
});
