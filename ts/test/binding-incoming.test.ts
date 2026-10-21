// fromIncomingMessage and readIncomingMessage over a node:http server: what
// the request looks like once read (docs/sdk/probes/ts.md, P1), and what
// node:http accepts that the binding then decides.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { fromIncomingMessage, Rule, readIncomingMessage } from '../src/core/binding/index.ts';
import {
  ACTION,
  bind,
  bindRefused,
  config,
  overWire,
  PRINCIPAL,
  RESOURCE,
  wantKind,
} from './support/binding.ts';

describe('readIncomingMessage', () => {
  test('field lines in order, names as sent, every duplicate kept', async () => {
    const w = await overWire(
      'POST /h?q=1 HTTP/1.1\r\nHost: x\r\nX-B: 1\r\nx-a: first\r\nX-A: second\r\nContent-Length: 2\r\n\r\nhi',
      (msg) => readIncomingMessage(msg, 1 << 20),
    );
    assert.ok(w.value, String(w.error ?? w.status));
    assert.equal(w.value.method, 'POST');
    assert.equal(w.value.rawRequestURI, '/h?q=1');
    assert.deepEqual(w.value.headers, [
      ['Host', 'x'],
      ['X-B', '1'],
      ['x-a', 'first'],
      ['X-A', 'second'],
      ['Content-Length', '2'],
    ]);
    assert.equal(Buffer.from(w.value.body).toString('latin1'), 'hi');
    assert.equal('tlsPeer' in w.value, false);
  });
  test('field values are decoded as UTF-8; other octets become lone surrogates', async () => {
    const w = await overWire(
      'GET /x HTTP/1.1\r\nHost: x\r\nX-A: caf\xc3\xa9\r\nX-B: \xff\xc3\r\n\r\n',
      (msg) => readIncomingMessage(msg, 0),
    );
    assert.ok(w.value, String(w.error ?? w.status));
    assert.deepEqual(w.value.headers.slice(1), [
      ['X-A', 'café'],
      ['X-B', '\udcff\udcc3'],
    ]);
  });
  test('a negative or fractional maxBody is a configuration error', async () => {
    for (const max of [-1, 0.5]) {
      const w = await overWire('GET /x HTTP/1.1\r\nHost: x\r\n\r\n', (msg) =>
        readIncomingMessage(msg, max),
      );
      wantKind(w.error, 'INVALID_CONFIG');
    }
  });
});

describe('fromIncomingMessage', () => {
  test('a trailer field is not bound', async () => {
    const cfg = config();
    const { operation } = await bind(
      cfg,
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nTransfer-Encoding: chunked\r\n\r\n' +
        '3\r\nabc\r\n0\r\nX-Dry-Run: 1\r\n\r\n',
    );
    assert.deepEqual(operation.headers, {});
  });
  test('two Host field lines are accepted by node:http and refused by the binding', async () => {
    await bindRefused(
      config(),
      'GET /dh HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n',
      Rule.DUPLICATE_HOST,
    );
  });
  test('a covered field value keeps its inner whitespace', async () => {
    const { operation } = await bind(
      config(),
      'GET /x HTTP/1.1\r\nHost: gateway.example\r\nX-Dry-Run:   a  b \t\r\n\r\n',
    );
    assert.deepEqual(operation.headers, { 'x-dry-run': 'a  b' });
  });
  test('an invalid configuration is refused before the body is read', async () => {
    const cfg = { ...config(), origin: 'http://gateway.example' };
    const w = await overWire(
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 3\r\n\r\nabc',
      async (msg) => {
        let err: unknown;
        try {
          await fromIncomingMessage(cfg, msg, PRINCIPAL, ACTION, [RESOURCE]);
        } catch (e) {
          err = e;
        }
        return { err, read: msg.readableDidRead };
      },
    );
    assert.ok(w.value, w.status);
    wantKind(w.value.err, 'INVALID_CONFIG');
    assert.equal(w.value.read, false);
  });
  test('a refused request is refused under its rule', async () => {
    const w = await overWire('GET /a#b HTTP/1.1\r\nHost: gateway.example\r\n\r\n', (msg) =>
      fromIncomingMessage(config(), msg, PRINCIPAL, ACTION, [RESOURCE]),
    );
    assert.ok(w.called, w.status);
    assert.equal((w.error as { rule?: string }).rule, Rule.FRAGMENT);
  });
});
