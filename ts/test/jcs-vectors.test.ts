// Port of go/core/jcs/vectors_test.go: the RFC 8785 reference pairs and the
// full ECMAScript number list of spec/v1.0/fixtures/vectors/jcs, through the
// manifest.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalize } from '../src/core/jcs.ts';
import {
  filesUnder,
  fixturesPresent,
  type ManifestEntry,
  manifestEntries,
  readFixture,
  readFixtureJSON,
  str,
} from './support/fixtures.ts';

const PREFIX = 'vectors/jcs/';
const NUMBERS_ID = `${PREFIX}numbers`;
const REQUIRED_PAIRS = ['arrays', 'french', 'structures', 'unicode', 'values', 'weird'];
// spec/v1.0/fixtures/vectors/jcs/LICENSE-NOTE.md: the first 10000 lines of the
// RFC 8785 ECMAScript number list.
const NUMBER_ROWS = 10000;

// The source and license notes of the vendored data: no manifest entry lists
// them, as for every file named LICENSE*.
const NOTICE_FILES = [`${PREFIX}LICENSE-NOTE.md`, `${PREFIX}LICENSE.md`, `${PREFIX}LICENSE-2.0.md`];

test('TestManifestListsEveryJCSFile', (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  const ids = new Set(entries.map((e) => e.id));
  for (const n of [...REQUIRED_PAIRS, 'numbers']) {
    assert.ok(ids.has(PREFIX + n), `manifest lacks required entry ${PREFIX}${n}`);
  }
  const listed = new Set(entries.flatMap((e) => [e.path, e.expected]));
  for (const f of filesUnder(PREFIX.slice(0, -1))) {
    if (NOTICE_FILES.includes(f) || f === `${PREFIX}README.md`) continue;
    assert.ok(listed.has(f), `${f} is not listed in manifest.json`);
  }
});

test('TestVectorsViaManifest', async (t) => {
  if (!fixturesPresent(t)) return;
  const entries = manifestEntries(PREFIX);
  assert.ok(entries.length > 0, 'manifest lists no jcs vectors');
  for (const e of entries) {
    await t.test(e.id.slice(PREFIX.length), () => {
      assert.equal(e.kind, 'vector');
      assert.equal(e.scope, 'core');
      assert.equal(e.outcome, 'ACCEPTED');
      assert.ok(e.spec_map_row !== '' && e.draft_section !== '');
      assert.ok(e.path.endsWith('.json') && e.expected?.endsWith('.json'));
      if (e.id === NUMBERS_ID) {
        assert.equal(e.path, e.expected);
        runNumbers(e.path);
        return;
      }
      runPair(e);
    });
  }
});

function runPair(e: ManifestEntry): void {
  assert.ok(e.expected !== null && e.path !== e.expected, 'a pair names two files');
  const want = readFixture(e.expected);
  assert.equal(str(canonicalize(readFixture(e.path))), str(want));
  assert.deepEqual(canonicalize(want), want, 'the expected output is canonical');
}

function literal(hex: string): string {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  const f = view.getFloat64(0);
  return (Object.is(f, -0) ? '-' : '') + f.toExponential();
}

// Every number of the list, written as an exponent-form literal (valid JSON
// at any magnitude), through the whole of canonicalize.
function runNumbers(rel: string): void {
  const vs = readFixtureJSON(rel) as { ieee754_hex: string; expected: string }[];
  assert.equal(vs.length, NUMBER_ROWS);
  const wrong: string[] = [];
  for (const [i, v] of vs.entries()) {
    assert.ok(/^[0-9A-Fa-f]{16}$/.test(v.ieee754_hex) && v.expected !== '', `entry ${i} malformed`);
    const lit = literal(v.ieee754_hex);
    let got: string;
    try {
      got = str(canonicalize(lit));
    } catch (err) {
      got = String(err);
    }
    if (
      got !== v.expected &&
      wrong.push(`${v.ieee754_hex}: ${lit} -> ${got}, want ${v.expected}`) >= 20
    )
      break;
  }
  assert.deepEqual(wrong, []);
}
