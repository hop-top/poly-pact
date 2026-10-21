// Port of go/core/binding/body_test.go. A RawRequest carries its body after
// transfer decoding, so a declared Content-Length is a field line and the
// body is the bytes given; reading a body, and keeping it for the native
// error path, is readIncomingMessage's part, tested over a node:http server.
// The "nil body" subtest is a RawRequest with an empty body; node:http has
// no counterpart of http.MaxBytesReader, so "server byte limit" has none.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { Rule, readIncomingMessage } from '../src/core/binding/index.ts';
import {
  ABC_DIGEST,
  bind,
  bindRefused,
  config,
  EMPTY_BODY_DIGEST,
  from,
  get,
  mustBind,
  overWire,
  parse,
  request,
  utf8,
  wantKind,
  wantRefused,
  wantRule,
} from './support/binding.ts';

const HOST: readonly [string, string] = ['Host', 'gateway.example'];

/** A POST /x with a body and its Content-Length. */
function withBody(s: string, contentLength: string | null = String(utf8(s).length)) {
  const headers: [string, string][] = [[...HOST]];
  if (contentLength !== null) headers.push(['Content-Length', contentLength]);
  return request('POST', '/x', headers, s);
}

async function drain(msg: AsyncIterable<Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of msg) chunks.push(c);
  return Buffer.concat(chunks).toString('latin1');
}

// body_digest hashes the exact body bytes after transfer decoding; an empty
// body hashes the empty byte string (draft 10.2).
describe('TestBodyDigest', () => {
  test('empty', () => {
    assert.equal(mustBind(config(), get('/x')).body_digest, EMPTY_BODY_DIGEST);
  });
  test('nil body', () => {
    const op = mustBind(config(), request('GET', '/x', [[...HOST]], new Uint8Array(0)));
    assert.equal(op.body_digest, EMPTY_BODY_DIGEST);
  });
  test('content-length', () => {
    const op = mustBind(
      config(),
      parse('POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 3\r\n\r\nabc'),
    );
    assert.equal(op.body_digest, ABC_DIGEST);
  });
  test('chunked over the wire', async () => {
    const { operation } = await bind(
      config(),
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\n' +
        'Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\n\r\n',
    );
    assert.equal(operation.body_digest, ABC_DIGEST, 'the transfer-decoded bytes');
  });
  test('largest MaxBody', () => {
    const cfg = config();
    cfg.maxBody = Number.MAX_SAFE_INTEGER;
    assert.equal(mustBind(cfg, withBody('abc')).body_digest, ABC_DIGEST);
  });
  test('exactly MaxBody', () => {
    const cfg = config();
    cfg.maxBody = 3;
    assert.equal(mustBind(cfg, withBody('abc')).body_digest, ABC_DIGEST);
  });
});

// The body can be used again after the binding: fromRequest leaves the
// request's bytes alone, and fromIncomingMessage returns the body it read,
// the only copy once the stream is consumed.
describe('TestBodyRestored', () => {
  test('RawRequest', () => {
    const r = withBody('abc');
    mustBind(config(), r);
    assert.deepEqual([...r.body], [...utf8('abc')]);
  });
  test('IncomingMessage', async () => {
    const { request: r } = await bind(
      config(),
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 3\r\n\r\nabc',
    );
    assert.equal(Buffer.from(r.body).toString('latin1'), 'abc');
  });
});

// The baseline forbids HTTP content encodings on protected requests (draft
// 10.2), so any Content-Encoding field is refused.
test('TestRejectContentEncoding', async () => {
  for (const lines of [
    [['Content-Encoding', 'gzip']],
    [['Content-Encoding', 'identity']],
    [['Content-Encoding', '']],
    [
      ['Content-Encoding', 'gzip'],
      ['Content-Encoding', 'br'],
    ],
    [['content-encoding', 'gzip']],
  ] as [string, string][][]) {
    const r = request('POST', '/x', [[...HOST], ['Content-Length', '3'], ...lines], 'abc');
    wantRefused(() => from(config(), r), Rule.CONTENT_ENCODING);
  }
  await bindRefused(
    config(),
    'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc',
    Rule.CONTENT_ENCODING,
  );
});

// Chunked is the only transfer coding the server decodes; a request that
// names another has a body the binding cannot know to be decoded.
test('TestRejectTransferCoding', () => {
  const coded = (...te: string[]) =>
    request('POST', '/x', [[...HOST], ...te.map((v) => ['Transfer-Encoding', v] as const)], 'abc');
  wantRefused(() => from(config(), coded('gzip, chunked')), Rule.TRANSFER_CODING);
  wantRefused(() => from(config(), coded('gzip')), Rule.TRANSFER_CODING);
  wantRefused(() => from(config(), coded('chunked', 'br')), Rule.TRANSFER_CODING);
  mustBind(config(), coded('chunked'));
  mustBind(config(), coded(' Chunked\t'));
});

// A body over maxBody is refused, whether the length is declared or found,
// and the request keeps its body.
describe('TestRejectBodyTooLarge', () => {
  const cfg = config();
  cfg.maxBody = 3;

  test('declared length', () => {
    const r = withBody('abcd');
    wantRefused(() => from(cfg, r), Rule.BODY_TOO_LARGE);
    assert.equal(Buffer.from(r.body).toString('latin1'), 'abcd', 'body after rejection');
  });
  test('declared length over a short body', () => {
    wantRefused(() => from(cfg, withBody('ab', '4')), Rule.BODY_TOO_LARGE);
  });
  test('declared length is not read', async () => {
    const w = await overWire(
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 4\r\n\r\nabcd',
      async (msg) => {
        let err: unknown;
        try {
          await readIncomingMessage(msg, cfg.maxBody);
        } catch (e) {
          err = e;
        }
        return { err, rest: await drain(msg) };
      },
    );
    assert.ok(w.value, w.status);
    wantRule(w.value.err, Rule.BODY_TOO_LARGE);
    assert.equal(w.value.rest, 'abcd', 'body after rejection');
  });
  test('unknown length', () => {
    const r = withBody('abcdef', null);
    wantRefused(() => from(cfg, r), Rule.BODY_TOO_LARGE);
    assert.equal(Buffer.from(r.body).toString('latin1'), 'abcdef', 'body after rejection');
  });
  test('understated length', () => {
    wantRefused(() => from(cfg, withBody('abcd', '1')), Rule.BODY_TOO_LARGE);
  });
  test('chunked over the wire', async () => {
    const w = await overWire(
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\n' +
        'Transfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n',
      async (msg) => {
        let err: unknown;
        try {
          await readIncomingMessage(msg, cfg.maxBody);
        } catch (e) {
          err = e;
        }
        return { err, rest: await drain(msg) };
      },
    );
    assert.ok(w.value, w.status);
    wantRule(w.value.err, Rule.BODY_TOO_LARGE);
    assert.equal(w.value.rest, 'abcd', 'body after rejection');
  });
  test('zero MaxBody', () => {
    const zero = config();
    zero.maxBody = 0;
    wantRefused(() => from(zero, withBody('a')), Rule.BODY_TOO_LARGE);
    mustBind(zero, request('POST', '/x'));
  });
});

// A body that cannot be read is not a malformed request.
describe('TestBodyReadError', () => {
  test('connection closed before the body ends', async () => {
    const w = await overWire(
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 10\r\n\r\nabc',
      (msg) => readIncomingMessage(msg, 1 << 20),
      { abort: true },
    );
    assert.ok(w.called, w.status);
    wantKind(w.error, 'BODY_READ');
  });
  test('message already read', async () => {
    const w = await overWire(
      'POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 3\r\n\r\nabc',
      async (msg) => {
        await drain(msg);
        return readIncomingMessage(msg, 1 << 20);
      },
    );
    assert.ok(w.called, w.status);
    wantKind(w.error, 'BODY_READ');
  });
});
