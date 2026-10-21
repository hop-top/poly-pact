// Port of go/core/binding/vectors_test.go: every binding vector bound twice,
// "built" from the vector's request object by the shared request decoder,
// and "parsed": sent as HTTP/1.1 text to a node:http server whose handler
// runs fromIncomingMessage. The parser answers 400 itself to a raw non-ASCII
// octet in the target; that is allowed only for
// a vector that expects a refusal.

import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import {
  Config,
  fromIncomingMessage,
  fromRequest,
  type RawRequest,
  RequestError,
  Rule,
} from '../src/core/binding/index.ts';
import { objectDigest } from '../src/core/digest.ts';
import { canonicalize } from '../src/core/jcs.ts';
import type { OperationContext } from '../src/core/types.ts';
import { decodeRequest } from '../src/internal/request.ts';
import { overWire } from './support/binding.ts';
import {
  FIXTURES,
  fixturesPresent,
  type ManifestEntry,
  manifestEntries,
  readFixtureJSON,
} from './support/fixtures.ts';

const PREFIX = 'vectors/binding/';

/** The vectors the set must hold, with the outcome each expects. */
const REQUIRED: Readonly<Record<string, string>> = {
  'bind-01-appendix-b3': 'ACCEPTED',
  'bind-02-query-order-ab': 'ACCEPTED',
  'bind-02-query-order-ba': 'ACCEPTED',
  'bind-03-space-percent-20': 'ACCEPTED',
  'bind-03-space-plus': 'ACCEPTED',
  'bind-04-duplicate-key': 'ACCEPTED',
  'bind-05-fragment': 'REJECTED',
  'bind-06-userinfo': 'REJECTED',
  'bind-07-content-encoding-gzip': 'REJECTED',
  'bind-08-body-compact': 'ACCEPTED',
  'bind-08-body-spaced': 'ACCEPTED',
  'bind-09-header-plain': 'ACCEPTED',
  'bind-09-header-case-and-whitespace': 'ACCEPTED',
  'bind-10-header-not-allowlisted': 'ACCEPTED',
  'bind-11-forwarding-headers': 'ACCEPTED',
  'bind-12-default-port': 'ACCEPTED',
  'bind-13-encoded-unreserved': 'REJECTED',
  'bind-14-encoded-slash-path': 'REJECTED',
  'bind-15-non-ascii-host': 'REJECTED',
  'bind-16-repeated-header': 'ACCEPTED',
  'bind-17-lowercase-hex-path': 'REJECTED',
  'bind-17-lowercase-hex-query': 'REJECTED',
  'bind-18-overlong-utf8': 'REJECTED',
  'bind-18-invalid-utf8-query': 'REJECTED',
  'bind-19-normal-form-query': 'ACCEPTED',
  'bind-20-dot-segment': 'REJECTED',
  'bind-20-dots-in-segment': 'ACCEPTED',
  'bind-21-duplicate-host': 'REJECTED',
  'bind-22-host-allowlisted': 'REJECTED',
  'bind-23-missing-host': 'REJECTED',
  'bind-24-invalid-host': 'REJECTED',
};

/** The rule pinned for each refused vector; the files carry only INVALID_MESSAGE. */
const VECTOR_RULE: Readonly<Record<string, Rule>> = {
  'bind-05-fragment': Rule.FRAGMENT,
  'bind-06-userinfo': Rule.USERINFO,
  'bind-07-content-encoding-gzip': Rule.CONTENT_ENCODING,
  'bind-13-encoded-unreserved': Rule.ENCODED_UNRESERVED,
  'bind-14-encoded-slash-path': Rule.ENCODED_SLASH,
  'bind-15-non-ascii-host': Rule.NON_ASCII_HOST,
  'bind-17-lowercase-hex-path': Rule.LOWERCASE_HEX,
  'bind-17-lowercase-hex-query': Rule.LOWERCASE_HEX,
  'bind-18-overlong-utf8': Rule.INVALID_UTF8,
  'bind-18-invalid-utf8-query': Rule.INVALID_UTF8,
  'bind-20-dot-segment': Rule.DOT_SEGMENT,
  'bind-21-duplicate-host': Rule.DUPLICATE_HOST,
  'bind-23-missing-host': Rule.MISSING_HOST,
  'bind-24-invalid-host': Rule.INVALID_HOST,
};

interface Vector {
  id: string;
  config: {
    origin: string;
    header_allowlist: string[];
    normalization_id: string;
    mapping_version: string;
    environment_id: string;
  };
  request: { method: string; raw_request_uri: string; headers: { name: string; value: string }[] };
  operation_id: string;
  principal_id: string;
  action: string;
  resources: string[];
  expect: { operation_context?: unknown; reject_reason?: string; config_error?: boolean };
  expect_operation_digest: string | null;
}

const stem = (id: string): string => id.slice(PREFIX.length);
const text = new TextDecoder();
const utf8 = new TextEncoder();

// Every file under vectors/binding is in the manifest, every required vector
// is there with its outcome, and each entry has the form of the vectors
// README.
test('TestBindingVectorsListed', (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  assert.ok(entries.length > 0, 'manifest lists no binding vectors');
  const listed = new Set<string>();
  for (const e of entries) {
    listed.add(stem(e.id));
    assert.equal(`${e.kind}/${e.scope}`, 'vector/adapter', e.id);
    assert.equal(e.path, `${e.id}.json`, e.id);
    assert.equal(e.expected, e.path, e.id);
    assert.match(e.spec_map_row, /^BIND-[0-9]{2}$/, e.id);
    assert.equal(e.draft_section, '10.2', e.id);
    const want = REQUIRED[stem(e.id)];
    if (want !== undefined) assert.equal(e.outcome, want, e.id);
  }
  for (const s of Object.keys(REQUIRED)) assert.ok(listed.has(s), `required vector ${s} missing`);
  for (const f of readdirSync(join(FIXTURES, ...PREFIX.split('/')))) {
    if (f.endsWith('.json'))
      assert.ok(listed.has(f.slice(0, -5)), `${PREFIX}${f} is not in manifest.json`);
  }
});

function vectorConfig(v: Vector): Config {
  return {
    origin: v.config.origin,
    headerAllowlist: v.config.header_allowlist,
    headerNormalizationId: v.config.normalization_id,
    mappingVersion: v.config.mapping_version,
    maxBody: 1 << 20,
  };
}

/** The request of v as HTTP/1.1 text in UTF-8, each header as "name: value". */
function wireText(v: Vector, body: Uint8Array): Uint8Array {
  const head =
    `${v.request.method} ${v.request.raw_request_uri} HTTP/1.1\r\n` +
    v.request.headers.map((h) => `${h.name}: ${h.value}\r\n`).join('') +
    '\r\n';
  return new Uint8Array(Buffer.concat([utf8.encode(head), body]));
}

function check(e: ManifestEntry, v: Vector, op: OperationContext | undefined, err: unknown): void {
  const accept = v.expect.operation_context !== undefined;
  if (v.expect.config_error === true) {
    // A configuration error, never a refused request (INVALID_MESSAGE).
    assert.throws(
      () => Config.validate(vectorConfig(v)),
      (x) => x instanceof RequestError && x.kind === 'INVALID_CONFIG',
    );
    assert.ok(err instanceof RequestError, `got ${String(err)}, want a configuration error`);
    assert.equal(err.kind, 'INVALID_CONFIG', err.message);
    return;
  }
  if (!accept) {
    assert.ok(err instanceof RequestError, `got ${String(err)}, want a refusal`);
    assert.equal(err.kind, 'INVALID_REQUEST', err.message);
    const want = VECTOR_RULE[stem(e.id)];
    if (want !== undefined) assert.equal(err.rule, want, err.message);
    return;
  }
  if (err !== undefined) throw err;
  assert.ok(op);
  const done = { ...op, operation_id: v.operation_id, environment_id: v.config.environment_id };
  const got = text.decode(canonicalize(utf8.encode(JSON.stringify(done))));
  const want = text.decode(canonicalize(utf8.encode(JSON.stringify(v.expect.operation_context))));
  assert.equal(got, want, 'operation context');
  assert.equal(objectDigest(done), v.expect_operation_digest, 'object_digest');
}

function agree(e: ManifestEntry, v: Vector): void {
  const accept = v.expect.operation_context !== undefined;
  const ok = accept
    ? v.expect.reject_reason === undefined &&
      e.outcome === 'ACCEPTED' &&
      typeof v.expect_operation_digest === 'string'
    : (v.expect.config_error === true
        ? v.expect.reject_reason === undefined
        : v.expect.reject_reason === 'INVALID_MESSAGE' && v.expect.config_error === undefined) &&
      e.outcome === 'REJECTED' &&
      v.expect_operation_digest === null;
  assert.ok(ok, 'expect, expect_operation_digest and outcome do not agree');
}

describe('TestBindingVectors', () => {
  const present = (() => {
    try {
      return manifestEntries(PREFIX);
    } catch {
      return [];
    }
  })();
  test('vectors present', (t) => {
    if (!fixturesPresent(t)) return;
    assert.ok(present.length > 0);
  });
  for (const e of present) {
    describe(stem(e.id), () => {
      const v = readFixtureJSON(e.path) as Vector;
      test('built', () => {
        assert.equal(v.id, e.id);
        agree(e, v);
        const req: RawRequest = decodeRequest(v.request).request;
        let op: OperationContext | undefined;
        let err: unknown;
        try {
          op = fromRequest(vectorConfig(v), req, v.principal_id, v.action, v.resources);
        } catch (x) {
          err = x;
        }
        check(e, v, op, err);
      });
      test('parsed', async () => {
        const body = decodeRequest(v.request).request.body;
        const w = await overWire(wireText(v, body), (msg) =>
          fromIncomingMessage(vectorConfig(v), msg, v.principal_id, v.action, v.resources),
        );
        if (!w.called) {
          assert.equal(e.outcome, 'REJECTED', `server answered ${w.status}`);
          assert.equal(w.status, 'HTTP/1.1 400 Bad Request');
          return;
        }
        check(e, v, w.value?.operation, w.error);
      });
    });
  }
});
