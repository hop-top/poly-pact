// Port of go/runner/evalcase/source_test.go: the declared native source of
// config.json.

import assert from 'node:assert/strict';
import { type TestContext, test } from 'node:test';
import { load } from '../src/conformance/case.ts';
import {
  caseTree,
  editJSON,
  type JSONObject,
  REPO_FIXTURES,
  wantThrows,
} from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

const ID = 'admission/valid';

// A declared capability for the roles mapping of admission/valid, whose
// native claim names configured-finance-validator-v1.
function rolesSource(): JSONObject {
  return {
    source_id: 'configured-finance-validator-v1',
    best_max_age_seconds: 60,
    best_status_max_age_seconds: 30,
    live_check: false,
    change_feed: 'poll_delta',
  };
}

// Sets the source of the roles mapping of admission/valid,
// native_mappings[1], through f.
function withSource(root: string, f: (src: JSONObject) => unknown): void {
  editJSON(root, `${ID}/config.json`, (c) => {
    c.native_mappings[1].source = f(rolesSource());
  });
}

// native_mappings[].source is optional, null or an object with exactly its
// five members (spec/v1.0/fixtures/README.md, config.json additions), parsed
// strictly.
test('TestNativeMappingSource', async (t) => {
  if (!fixturesPresent(t)) return;
  let c = load(REPO_FIXTURES, ID);
  for (const m of c.exchanges[0]?.config.native_mappings ?? []) {
    assert.equal(m.source, null, `${m.native_path}: source, want none`);
  }

  let root = caseTree(t, ID);
  withSource(root, (src) => src);
  c = load(root, ID);
  assert.deepEqual(c.exchanges[0]?.config.native_mappings[1]?.source, {
    sourceId: 'configured-finance-validator-v1',
    bestMaxAgeSeconds: 60,
    bestStatusMaxAgeSeconds: 30,
    liveCheck: false,
    changeFeed: 'poll_delta',
  });

  root = caseTree(t, ID);
  withSource(root, () => null);
  c = load(root, ID);
  assert.equal(c.exchanges[0]?.config.native_mappings[1]?.source, null, 'null source');

  const rejected: [string, (s: JSONObject) => unknown, string][] = [
    ['unknown member', (s) => ({ ...s, cache_seconds: 1 }), 'config.json'],
    ['no source_id', ({ source_id: _, ...s }) => s, 'source_id'],
    ['empty source_id', (s) => ({ ...s, source_id: '' }), 'source_id'],
    ['no best_max_age', ({ best_max_age_seconds: _, ...s }) => s, 'best_max_age_seconds'],
    [
      'no best_status',
      ({ best_status_max_age_seconds: _, ...s }) => s,
      'best_status_max_age_seconds',
    ],
    ['no live_check', ({ live_check: _, ...s }) => s, 'live_check'],
    ['no change_feed', ({ change_feed: _, ...s }) => s, 'change_feed'],
    ['negative bound', (s) => ({ ...s, best_max_age_seconds: -1 }), 'best_max_age_seconds'],
    ['unknown change feed', (s) => ({ ...s, change_feed: 'webhook' }), 'change_feed'],
    ['live_check a string', (s) => ({ ...s, live_check: 'false' }), 'config.json'],
    ['no live check, bound 0', (s) => ({ ...s, best_status_max_age_seconds: 0 }), 'at least 1'],
    ['other source_id', (s) => ({ ...s, source_id: 'scim-northstar' }), 'source_id'],
    ['an array', (s) => [s], 'config.json'],
  ];
  for (const [name, f, want] of rejected) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, ID);
      withSource(root, f);
      wantThrows(() => load(root, ID), want);
    });
  }

  // A live source may declare a status bound of zero.
  root = caseTree(t, ID);
  withSource(root, (s) => ({ ...s, live_check: true, best_status_max_age_seconds: 0 }));
  load(root, ID);
});
