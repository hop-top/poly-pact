// Port of go/core/strictjson/vectors_test.go: every manifest entry under
// vectors/strictjson/ decoded as an OperationContext, accepted or rejected
// as the vector says, with the rejection kind pinned where Go pins it.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { shapes } from '../src/core/shapes.ts';
import { decode, StrictJSONError, type StrictJSONErrorKind } from '../src/core/strictjson.ts';
import {
  bytes,
  filesUnder,
  fixturesPresent,
  type ManifestEntry,
  manifestEntries,
  readFixtureJSON,
} from './support/fixtures.ts';

const PREFIX = 'vectors/strictjson/';

const WANT_KIND: Readonly<Record<string, StrictJSONErrorKind>> = {
  'duplicate-key-top-level': 'DUPLICATE_KEY',
  'duplicate-key-identical-values': 'DUPLICATE_KEY',
  'duplicate-key-nested': 'DUPLICATE_KEY',
  'duplicate-key-in-headers': 'DUPLICATE_KEY',
  'duplicate-key-escaped-form': 'DUPLICATE_KEY',
  'unknown-core-field': 'UNKNOWN_FIELD',
  'unknown-core-field-case-variant': 'UNKNOWN_FIELD',
  'nesting-depth-17-objects': 'DEPTH',
  'nesting-depth-17-arrays': 'DEPTH',
  'non-finite-number-1e999': 'NON_FINITE',
  'non-finite-number-negative-1e999': 'NON_FINITE',
  'non-finite-number-nan': 'NON_FINITE',
  'non-finite-number-infinity': 'NON_FINITE',
  'non-finite-number-negative-infinity': 'NON_FINITE',
  'invalid-utf8-byte-ff': 'INVALID_UTF8',
  'invalid-utf8-truncated-sequence': 'INVALID_UTF8',
  'invalid-utf8-overlong-encoding': 'INVALID_UTF8',
  'invalid-utf8-encoded-surrogate': 'INVALID_UTF8',
  'lone-surrogate-high': 'LONE_SURROGATE',
  'lone-surrogate-low': 'LONE_SURROGATE',
  'lone-surrogate-high-then-bmp': 'LONE_SURROGATE',
  'integer-overflow-2-pow-53': 'INTEGER',
  'integer-overflow-negative': 'INTEGER',
  'integer-overflow-huge': 'INTEGER',
  'trailing-garbage-text': 'TRAILING_DATA',
  'trailing-garbage-second-value': 'TRAILING_DATA',
  'trailing-garbage-extra-brace': 'TRAILING_DATA',
};

const REQUIRED_CASES = [
  'duplicate-key-top-level',
  'duplicate-key-nested',
  'unknown-core-field',
  'nesting-depth-17-objects',
  'non-finite-number-1e999',
  'invalid-utf8-byte-ff',
  'lone-surrogate-high',
  'integer-overflow-2-pow-53',
  'trailing-garbage-text',
  'accept-valid-object',
  'accept-depth-16-objects',
  'accept-integer-max-safe',
];

interface VectorFile {
  id: string;
  input_text?: string;
  input_b64?: string;
  expect: string;
  reason: string;
}

test('TestVectorsViaManifest', async (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  assert.ok(entries.length > 0, 'manifest lists no strictjson vectors');
  const seen = new Set<string>();
  for (const e of entries) {
    const name = e.id.slice(PREFIX.length);
    seen.add(name);
    await t.test(name, () => runEntry(e));
  }
  for (const c of REQUIRED_CASES) assert.ok(seen.has(c), `manifest lacks required case ${c}`);
  for (const f of filesUnder(PREFIX.slice(0, -1))) {
    const name = f.slice(PREFIX.length).replace(/\.json$/, '');
    assert.ok(seen.has(name), `${f} is not listed in manifest.json`);
  }
});

function runEntry(e: ManifestEntry): void {
  assert.equal(e.kind, 'vector');
  assert.equal(e.scope, 'core');
  assert.equal(e.path, `${e.id}.json`);
  assert.equal(e.expected, e.path);
  assert.ok(e.spec_map_row !== '' && e.draft_section !== '');

  const v = readFixtureJSON(e.path) as VectorFile;
  assert.equal(v.id, e.id);
  assert.ok(v.reason !== '', 'vector has no reason');
  const text = v.input_text ?? '';
  const b64 = v.input_b64 ?? '';
  assert.ok(!(text !== '' && b64 !== ''), 'vector sets both input_text and input_b64');
  assert.ok(text !== '' || b64 !== '', 'vector has no input');
  const input = b64 !== '' ? new Uint8Array(Buffer.from(b64, 'base64')) : bytes(text);
  const wantOutcome = { reject: 'REJECTED', accept: 'ACCEPTED' }[v.expect];
  assert.ok(wantOutcome !== undefined && wantOutcome === e.outcome, `expect ${v.expect}`);

  let err: unknown;
  try {
    decode(input, shapes.OperationContext);
  } catch (caught) {
    err = caught;
  }
  if (v.expect === 'accept') {
    assert.equal(err, undefined, `want accepted, got ${String(err)}`);
    return;
  }
  assert.ok(
    err instanceof StrictJSONError,
    `want rejected with a StrictJSONError, got ${String(err)}`,
  );
  const want = WANT_KIND[e.id.slice(PREFIX.length)];
  if (want !== undefined) assert.equal(err.kind, want, err.message);
}
