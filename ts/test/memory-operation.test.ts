// Port of TestMapOperationRules of go/adapters/memory/memory_unit_test.go:
// mapOperation over the baseline HTTP mapping of draft 10.2 and the
// installed routes. A RawRequest is the request as received, so the Go rows
// of a parsed URL that differs from the request-target, of a header under two
// map keys, and of a body that cannot be read have no counterpart; the body
// is never consumed, so it needs no restoring.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AdapterError, Code, codeOf } from '../src/adapter/index.ts';
import type { MemoryAdapter } from '../src/adapters/memory/index.ts';
import { type RawRequest, RequestError, Rule } from '../src/core/binding/index.ts';
import type { OperationContext } from '../src/core/types.ts';
import { addHeader, alice, ENV, get, newAdapter, received, setHeader } from './support/memory.ts';

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  return undefined;
}

// The first RequestError of the cause chain of err.
function requestErrorOf(err: unknown): RequestError | undefined {
  for (let e = err; e instanceof Error; e = e.cause) if (e instanceof RequestError) return e;
  return undefined;
}

const withRoute = (method: string) => (st: Parameters<Parameters<typeof newAdapter>[0]>[0]) => {
  st.mappings[0]?.routes.push({
    method,
    path: '/invoices/{id}',
    action: 'invoice.write',
    resource: 'https://invoices.example/invoices/{id}',
  });
};

test('TestMapOperationRules', async (t) => {
  const { a } = newAdapter();
  const p = alice();
  const map = (r: RawRequest, adapter: MemoryAdapter = a, pr = p, v = 'map-1') =>
    adapter.mapOperation(r, pr, v);

  await t.test('mapping version', async () => {
    const err = await rejection(map(get('https://gateway.example/invoices/1'), a, p, 'map-9'));
    assert.equal(codeOf(err), Code.UNSUPPORTED_REQUIREMENT);
  });

  await t.test('no route', async () => {
    for (const target of [
      'https://gateway.example/invoices',
      'https://gateway.example/invoices/1/approve',
      'https://gateway.example/other/1',
      'https://gateway.example/invoices/a%20b',
    ]) {
      assert.equal(codeOf(await rejection(map(get(target)))), Code.UNSUPPORTED_REQUIREMENT, target);
    }
    const del = received('DELETE', 'https://gateway.example/invoices/1');
    assert.equal(codeOf(await rejection(map(del))), Code.UNSUPPORTED_REQUIREMENT, 'DELETE');
  });

  await t.test('realm and credential', async () => {
    const r = get('https://gateway.example/invoices/1');
    const other = { ...p, realm: { ...p.realm, tenantId: 'globex' } };
    assert.equal(codeOf(await rejection(map(r, a, other))), Code.CONTEXT_MISMATCH, 'other realm');
    assert.equal(
      codeOf(await rejection(map(r, a, { ...p, id: '' }))),
      Code.CONTEXT_MISMATCH,
      'no principal id',
    );
    const bob = setHeader(r, 'Authorization', 'Bearer tok-bob-secret-2');
    assert.equal(
      codeOf(await rejection(map(bob))),
      Code.CONTEXT_MISMATCH,
      "bob's token with alice as principal",
    );
    await map(setHeader(r, 'Authorization', 'Bearer tok-alice-secret-1'));
    // An unknown token says nothing about the sender.
    await map(setHeader(r, 'Authorization', 'Bearer tok-unknown-to-the-store'));
  });

  // Every request the baseline mapping refuses is an INVALID_MESSAGE (draft
  // 10.2, 13.4), and nothing else. Where the baseline mapping names the rule,
  // the error's cause carries it.
  const wantInvalid = async (name: string, r: RawRequest | null, rule: string) => {
    const err = await rejection(map(r as RawRequest));
    assert.ok(err instanceof AdapterError, `${name}: ${String(err)}, want an AdapterError`);
    assert.equal(codeOf(err), Code.INVALID_MESSAGE, `${name}: ${String(err)}`);
    if (rule !== '') assert.equal(requestErrorOf(err)?.rule, rule, `${name}: ${String(err)}`);
  };

  await t.test('rejected forms', async () => {
    const base = get('https://gateway.example/invoices/1');
    const withTarget = (target: string): RawRequest => get(target);
    const withMethod = (method: string): RawRequest => ({ ...base, method });
    const rows: [string, RawRequest | null, string][] = [
      ['fragment', get('https://gateway.example/invoices/1#f'), Rule.FRAGMENT],
      ['request-target fragment', withTarget('/invoices/1#f'), Rule.FRAGMENT],
      ['userinfo', get('https://u:p@gateway.example/invoices/1'), Rule.USERINFO],
      ['content encoding', setHeader(base, 'Content-Encoding', 'gzip'), Rule.CONTENT_ENCODING],
      ['identity encoding', setHeader(base, 'Content-Encoding', 'identity'), Rule.CONTENT_ENCODING],
      ['blank content encoding', setHeader(base, 'Content-Encoding', ' '), Rule.CONTENT_ENCODING],
      [
        'transfer coding other than chunked',
        setHeader(base, 'Transfer-Encoding', 'gzip, chunked'),
        Rule.TRANSFER_CODING,
      ],
      ['method with a digit', withMethod('GET1'), Rule.METHOD],
      ['method with a hyphen', withMethod('M-SEARCH'), Rule.METHOD],
      ['no request-target', withTarget(''), Rule.TARGET_FORM],
      ['asterisk-form', withTarget('*'), Rule.TARGET_FORM],
      ['authority-form', withTarget('gateway.example:443'), Rule.TARGET_FORM],
      ['absolute-form without a path', withTarget('https://gateway.example?x=1'), Rule.TARGET_FORM],
      ['non-ASCII host', withTarget('https://gatéway.example/invoices/1'), Rule.NON_ASCII_HOST],
      ['space in the query', withTarget('/invoices/1?q=a b'), Rule.INVALID_CHARACTER],
      ['raw non-ASCII in the path', withTarget('/invoices/é'), Rule.INVALID_CHARACTER],
      ['malformed escape', withTarget('/invoices/1?q=%zz'), Rule.MALFORMED_ESCAPE],
      ['target too long', withTarget(`/invoices/1?q=${'x'.repeat(1024)}`), Rule.TARGET_TOO_LONG],
      [
        'control octet in a covered header',
        setHeader(base, 'X-Request-Kind', 'a\u0001b'),
        Rule.HEADER_VALUE,
      ],
      [
        'covered header not UTF-8',
        setHeader(base, 'X-Request-Kind', 'a\ud800b'),
        Rule.HEADER_VALUE,
      ],
      [
        'covered header too long',
        setHeader(base, 'X-Request-Kind', 'k'.repeat(8193)),
        Rule.HEADER_TOO_LONG,
      ],
      ['no request', null, ''],
    ];
    for (const [name, r, rule] of rows) await wantInvalid(name, r, rule);
  });

  // Draft 10.2: an encoding is ambiguous when RFC 3986 syntax-based
  // normalization would change it, or when it hides structure. It is
  // rejected, never normalized.
  await t.test('ambiguous encodings', async () => {
    for (const [name, target, rule] of [
      [
        'encoded unreserved tilde',
        'https://gateway.example/invoices/INV%7E1',
        Rule.ENCODED_UNRESERVED,
      ],
      [
        'encoded unreserved letter',
        'https://gateway.example/invoices/%41',
        Rule.ENCODED_UNRESERVED,
      ],
      ['encoded dot segment', 'https://gateway.example/invoices/%2E%2E/1', Rule.ENCODED_UNRESERVED],
      [
        'encoded unreserved in the query',
        'https://gateway.example/invoices/1?r=%7E',
        Rule.ENCODED_UNRESERVED,
      ],
      [
        'lowercase hex in the query',
        'https://gateway.example/invoices/1?a=%2f',
        Rule.LOWERCASE_HEX,
      ],
      ['lowercase hex in the path', 'https://gateway.example/invoices/%c3%a9', Rule.LOWERCASE_HEX],
      ['encoded slash', 'https://gateway.example/invoices/a%2Fb', Rule.ENCODED_SLASH],
      ['encoded slash lowercase', 'https://gateway.example/invoices/a%2fb', Rule.LOWERCASE_HEX],
      ['overlong slash', 'https://gateway.example/invoices/1%C0%AF', Rule.INVALID_UTF8],
      ['stray octet in the query', 'https://gateway.example/invoices/1?q=%FF', Rule.INVALID_UTF8],
      ['surrogate', 'https://gateway.example/invoices/%ED%A0%80', Rule.INVALID_UTF8],
      ['dot segment', 'https://gateway.example/invoices/../admin', Rule.DOT_SEGMENT],
    ]) {
      await wantInvalid(name as string, get(target as string), rule as string);
    }
  });

  // Other escapes are not ambiguous: they are bound as sent, and the mapping
  // decides whether a route takes them.
  await t.test('other escapes reach the mapping', async () => {
    for (const target of [
      'https://gateway.example/invoices/a%5Cb',
      'https://gateway.example/invoices/a%00b',
      'https://gateway.example/invoices/a%25b',
    ]) {
      assert.equal(codeOf(await rejection(map(get(target)))), Code.UNSUPPORTED_REQUIREMENT, target);
    }
  });

  await t.test('target uri', async () => {
    for (const [target, want] of Object.entries({
      'https://internal.local:8443/invoices/1': 'https://gateway.example/invoices/1',
      'https://internal.local/invoices/1?': 'https://gateway.example/invoices/1?',
      'https://internal.local/invoices/1?b=2&a=%2F&a=1':
        'https://gateway.example/invoices/1?b=2&a=%2F&a=1',
      'https://internal.local/invoices/1?q=%C3%A9+%20&q=&z':
        'https://gateway.example/invoices/1?q=%C3%A9+%20&q=&z',
      'https://internal.local/invoices/INV~1?q=a+b%20c&r=~':
        'https://gateway.example/invoices/INV~1?q=a+b%20c&r=~',
      'http://Other.Example:8080/invoices/1?x=%3D%26&x=%2F%3F/?':
        'https://gateway.example/invoices/1?x=%3D%26&x=%2F%3F/?',
    })) {
      assert.equal((await map(get(target))).target_uri, want, target);
    }
    // An origin-form request-target is the path and query as sent.
    const origin = await map(get('/invoices/INV~1?z=%2F&a=1'));
    assert.equal(origin.target_uri, 'https://gateway.example/invoices/INV~1?z=%2F&a=1');
    // The method is uppercased; the route is matched on the bound path.
    const op = await map({ ...get('https://gateway.example/invoices/7'), method: 'get' });
    assert.equal(op.method, 'GET');
    assert.equal(op.action, 'invoice.read');
    assert.deepEqual(op.resources, ['https://invoices.example/invoices/7']);
  });

  await t.test('operation id and environment', async () => {
    const id = async (target: string, pr = p) => {
      const op = await map(get(target), a, pr);
      assert.equal(op.environment_id, ENV);
      return op.operation_id;
    };
    const u = 'https://gateway.example/invoices/1';
    const first = await id(u);
    assert.notEqual(first, '');
    assert.equal(await id(u), first, 'the same request has the same operation id');
    assert.notEqual(await id(`${u}?x=1`), first, 'specific to the request');
    assert.notEqual(
      await id(u, { ...p, id: 'https://idp.example/bob' }),
      first,
      'specific to the principal',
    );
  });

  await t.test('headers', async () => {
    const post = async (body: string, hdr: [string, string][]): Promise<OperationContext> => {
      const { a } = newAdapter(withRoute('POST'));
      let r = received(
        'POST',
        'https://gateway.example/invoices/1',
        new TextEncoder().encode(body),
      );
      for (const [k, v] of hdr) r = addHeader(r, k, v);
      return a.mapOperation(r, p, 'map-1');
    };
    let op = await post('x', [
      ['Content-Type', 'text/plain'],
      ['X-Request-Kind', '  bulk\t'],
      ['Authorization', 'Bearer t'],
    ]);
    assert.deepEqual(op.headers, { 'content-type': 'text/plain', 'x-request-kind': 'bulk' });
    // Content-type is covered when there is a body, and only then.
    op = await post('', [['Content-Type', 'text/plain']]);
    assert.deepEqual(op.headers, {});
    // A header the request names in Connection is hop-by-hop for it (RFC 9110
    // 7.6.1), so it is not covered even when allowlisted.
    op = await post('', [
      ['X-Request-Kind', 'bulk'],
      ['Connection', 'x-request-kind'],
    ]);
    assert.deepEqual(op.headers, {});
    // Repeated headers are joined.
    const r = addHeader(
      addHeader(get('https://gateway.example/invoices/1'), 'X-Request-Kind', 'a'),
      'X-Request-Kind',
      'b',
    );
    assert.equal((await map(r)).headers['x-request-kind'], 'a, b');
  });

  await t.test('body', async () => {
    const body = new Uint8Array([
      ...new TextEncoder().encode('exact bytes '),
      0x00,
      0xff,
      0x0d,
      0x0a,
    ]);
    const { a } = newAdapter(withRoute('PUT'));
    const r = received('PUT', 'https://gateway.example/invoices/1', body);
    const op = await a.mapOperation(r, p, 'map-1');
    assert.equal(op.body_digest, 'M24hzpYZfgDraiT_FZmtqZmmKetxRFnz_tSjno0bnXQ');
    assert.deepEqual(r.body, body, 'the body after the call');
    // A second mapping of the same request gives the same digest.
    assert.equal((await a.mapOperation(r, p, 'map-1')).body_digest, op.body_digest);
  });

  await t.test('body too large', async () => {
    const { a } = newAdapter(withRoute('PUT'));
    const size = 9 << 20;
    const r = received('PUT', 'https://gateway.example/invoices/1', new Uint8Array(size));
    const err = await rejection(a.mapOperation(r, p, 'map-1'));
    assert.equal(codeOf(err), Code.INVALID_MESSAGE, String(err));
    assert.equal(requestErrorOf(err)?.rule, Rule.BODY_TOO_LARGE);
    assert.equal(r.body.length, size, 'the request keeps its whole body');
  });

  await t.test('aborted call', async () => {
    const err = await rejection(
      a.mapOperation(get('https://gateway.example/invoices/1'), p, 'map-1', AbortSignal.abort()),
    );
    assert.equal(codeOf(err), Code.DEPENDENCY_UNAVAILABLE);
  });
});
