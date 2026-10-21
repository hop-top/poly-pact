// Port of go/adapter/outcome_test.go.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Descriptor, NoVisibility, type Recorded, Signed } from '../src/adapter/index.ts';
import { parse } from '../src/core/strictjson.ts';
import { fenced, headingSection } from './support/draft.ts';
import { DRAFT, specText } from './support/repo.ts';

test('TestSignedValidate', async (t) => {
  const rows: readonly [string, string, boolean][] = [
    ['three segments', 'eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln', true],
    ['empty', '', false],
    ['two segments', 'aaa.bbb', false],
    ['four segments', 'aaa.bbb.ccc.ddd', false],
    ['empty header', '.bbb.ccc', false],
    ['empty payload', 'aaa..ccc', false],
    ['empty signature', 'aaa.bbb.', false],
  ];
  for (const [name, jws, ok] of rows) {
    await t.test(name, () => {
      if (ok) assert.doesNotThrow(() => new Signed(jws).validate());
      else assert.throws(() => new Signed(jws).validate(), /not a compact JWS/);
    });
  }
});

test('TestNoVisibilityValidate', () => {
  const rows: readonly [string, boolean][] = [
    ['execution happens in a system the adapter cannot observe', true],
    ['', false],
    ['   \t', false],
    // The blank set is Go's unicode.IsSpace, which strings.TrimSpace uses:
    // U+0085 is space there, U+FEFF is not.
    ['\u0085  　', false],
    ['﻿', true],
  ];
  for (const [reason, ok] of rows) {
    const label = JSON.stringify(reason);
    if (ok) assert.doesNotThrow(() => new NoVisibility(reason).validate(), label);
    else assert.throws(() => new NoVisibility(reason).validate(), /no reason/, label);
  }
});

// The exhaustive switch a consumer writes over the sum type.
function kind(r: Recorded): string {
  if (r instanceof Signed) return 'signed';
  if (r instanceof NoVisibility) return 'no-visibility';
  return 'unknown';
}

test('TestRecordedHoldsExactlyOne', () => {
  assert.equal(kind(new Signed('a.b.c')), 'signed');
  assert.equal(kind(new NoVisibility('r')), 'no-visibility');
  assert.equal(new Signed('a.b.c').jws, 'a.b.c');
  assert.equal(new NoVisibility('r').reason, 'r');
});

// Both variants carry a private member, so no value but theirs has the type:
// a third variant does not compile, and a look-alike is neither.
test('TestRecordedIsSealed', () => {
  const lookAlike = { jws: 'a.b.c', validate(): void {} };
  // @ts-expect-error a structural copy of Signed is not a Recorded
  const r: Recorded = lookAlike;
  assert.equal(kind(r), 'unknown');
  for (const v of [new Signed('a.b.c'), new NoVisibility('r')]) {
    assert.equal(typeof v.validate, 'function');
    assert.ok(Object.isFrozen(v));
  }
});

// The conversion against the adapters entry of the draft's gateway metadata
// example (B.13).
test('TestDescriptorConvertsToNativeAdapter', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const sec = headingSection(draft, '### B.13 Gateway metadata with baseline limits');
  const md = parse(fenced(sec, '', 'json')) as { adapters: unknown[] };
  assert.equal(md.adapters.length, 1, 'B.13 adapters');
  const d: Descriptor = {
    protocol: 'mcp',
    version: '2025-11-25',
    mappingRevision: 'finance-mcp-1',
  };
  assert.deepEqual(Descriptor.nativeAdapter(d), md.adapters[0]);
});
