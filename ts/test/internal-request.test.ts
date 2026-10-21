// The shared request decoder, src/internal/request.ts: the request object of
// a binding vector (spec/v1.0/fixtures/vectors/README.md) and of an adapter
// conformance case (Go adapter/adaptertest casefile.go Request and
// validateRequest, request.go decodeBody).

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { decodeRequest } from '../src/internal/request.ts';

const bytes = (s: string) => [...new TextEncoder().encode(s)];

describe('binding vector request', () => {
  test('field lines in order with names as sent, body decoded', () => {
    const d = decodeRequest({
      method: 'POST',
      raw_request_uri: '/a?b=1',
      headers: [
        { name: 'Host', value: 'gw.example' },
        { name: 'If-Match', value: ' "x" ' },
        { name: 'if-match', value: 'y' },
      ],
      body_b64: 'e30=',
    });
    assert.deepEqual(
      { ...d.request, body: [...d.request.body] },
      {
        method: 'POST',
        rawRequestURI: '/a?b=1',
        headers: [
          ['Host', 'gw.example'],
          ['If-Match', ' "x" '],
          ['if-match', 'y'],
        ],
        body: bytes('{}'),
      },
    );
    assert.equal(d.nativeStateRef, '');
    assert.equal(d.arrival, '');
    assert.equal('tlsPeer' in d.request, false);
  });
  test('an empty body_b64 is no body', () => {
    const d = decodeRequest({ method: 'GET', raw_request_uri: '/', headers: [], body_b64: '' });
    assert.equal(d.request.body.length, 0);
  });
});

describe('case request', () => {
  test('url is the request-target; headers an object; tls_peer and directives', () => {
    const d = decodeRequest({
      method: 'GET',
      url: 'https://gateway.example/x#f',
      headers: { Authorization: 'Basic YTpi', 'X-A': '1' },
      body_b64: 'YWJj',
      tls_peer: {
        subject_cn: 'agent',
        issuer_cn: 'ca',
        dns_names: ['a.example'],
        uris: ['spiffe://t/a'],
      },
      native_state_ref: 'alice',
      arrival: 'direct',
    });
    assert.deepEqual(
      { ...d.request, body: [...d.request.body] },
      {
        method: 'GET',
        rawRequestURI: 'https://gateway.example/x#f',
        headers: [
          ['Authorization', 'Basic YTpi'],
          ['X-A', '1'],
        ],
        body: bytes('abc'),
        tlsPeer: {
          subjectCN: 'agent',
          issuerCN: 'ca',
          dnsNames: ['a.example'],
          uris: ['spiffe://t/a'],
        },
      },
    );
    assert.equal(d.nativeStateRef, 'alice');
    assert.equal(d.arrival, 'direct');
  });
  test('optional members absent', () => {
    const d = decodeRequest({ method: 'GET', url: '/x' });
    assert.deepEqual(d.request.headers, []);
    assert.equal(d.request.body.length, 0);
    assert.equal('tlsPeer' in d.request, false);
    assert.equal(d.arrival, '');
  });
  test('a null tls_peer is no peer; absent peer members are empty', () => {
    assert.equal(
      'tlsPeer' in decodeRequest({ method: 'GET', url: '/x', tls_peer: null }).request,
      false,
    );
    const d = decodeRequest({ method: 'GET', url: '/x', tls_peer: { subject_cn: 'a' } });
    assert.deepEqual(d.request.tlsPeer, { subjectCN: 'a', issuerCN: '', dnsNames: [], uris: [] });
  });
  test('arrival enforcement_point', () => {
    assert.equal(
      decodeRequest({ method: 'GET', url: '/x', arrival: 'enforcement_point' }).arrival,
      'enforcement_point',
    );
  });
});

describe('refused request objects', () => {
  const bad: [name: string, v: unknown, detail: RegExp][] = [
    ['not an object', [], /request is not a JSON object/],
    ['unknown member', { method: 'GET', url: '/x', extra: 1 }, /extra/],
    ['no method', { url: '/x' }, /method/],
    ['empty method', { method: '', url: '/x' }, /method/],
    ['no target', { method: 'GET' }, /url|raw_request_uri/],
    ['empty url', { method: 'GET', url: '' }, /url/],
    ['both targets', { method: 'GET', url: '/x', raw_request_uri: '/x' }, /url|raw_request_uri/],
    ['headers not a list or object', { method: 'GET', url: '/x', headers: 'h' }, /headers/],
    [
      'field line with another member',
      { method: 'GET', url: '/x', headers: [{ name: 'a', value: 'b', c: 1 }] },
      /headers\[0\]/,
    ],
    [
      'field line value not a string',
      { method: 'GET', url: '/x', headers: [{ name: 'a', value: 1 }] },
      /headers\[0\]/,
    ],
    ['header value not a string', { method: 'GET', url: '/x', headers: { a: 1 } }, /headers/],
    ['empty header name', { method: 'GET', url: '/x', headers: { '': 'v' } }, /header name/],
    [
      'header name with a colon',
      { method: 'GET', url: '/x', headers: [{ name: 'a:b', value: 'v' }] },
      /header name/,
    ],
    [
      'header name with a space',
      { method: 'GET', url: '/x', headers: { 'a b': 'v' } },
      /header name/,
    ],
    ['body not padded', { method: 'GET', url: '/x', body_b64: 'YWJjZA' }, /body_b64/],
    ['body base64url', { method: 'GET', url: '/x', body_b64: '-_8=' }, /body_b64/],
    ['body with a newline', { method: 'GET', url: '/x', body_b64: 'YW\nJj' }, /body_b64/],
    ['arrival unknown', { method: 'GET', url: '/x', arrival: 'side' }, /arrival/],
    [
      'native_state_ref not a string',
      { method: 'GET', url: '/x', native_state_ref: 1 },
      /native_state_ref/,
    ],
    ['tls_peer unknown member', { method: 'GET', url: '/x', tls_peer: { cn: 'a' } }, /tls_peer/],
    [
      'tls_peer uris not strings',
      { method: 'GET', url: '/x', tls_peer: { uris: [1] } },
      /tls_peer/,
    ],
  ];
  for (const [name, v, detail] of bad) {
    test(name, () => {
      assert.throws(() => decodeRequest(v), detail);
    });
  }
});
