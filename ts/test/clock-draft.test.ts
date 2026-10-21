// Port of go/core/clock/draft_test.go: the lifetimes, skew and replay
// retention against the section 20.1 tables and the section 7.5 prose of
// spec/v1.0/draft.md, read at test time.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Artifact, BASELINE_SKEW_MS, maxLifetime, replayRetention } from '../src/core/clock.ts';
import { DRAFT, specText } from './support/repo.ts';

function quote(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// The "At most N seconds|hour|hours" value, in ms, of the section 20.1
// baseline-limit row labelled item.
function draftDuration(draft: string, item: string): number {
  const m = new RegExp(`^\\| ${quote(item)} \\| At most (\\d+) (second|hour)s?\\b`, 'm').exec(
    draft,
  );
  assert.ok(m, `draft has no 20.1 row "${item}" of the form "At most N seconds|hours"`);
  const n = Number(m[1]);
  return m[2] === 'hour' ? n * 3_600_000 : n * 1000;
}

// The value cell of the section 20.1 metadata row for key.
function draftKey(draft: string, key: string): string {
  const m = new RegExp(`^\\| \`${quote(key)}\` \\| ([^|]+?) \\|`, 'm').exec(draft);
  assert.ok(m, `draft has no 20.1 metadata row for ${key}`);
  return m[1] ?? '';
}

function draftSeconds(draft: string, key: string): number {
  const cell = draftKey(draft, key);
  assert.match(cell, /^\d+$/, `metadata row ${key}`);
  return Number(cell) * 1000;
}

test('TestLifetimesMatchTheDraft', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const rows: readonly [string, Artifact][] = [
    ['Contract validity', Artifact.CONTRACT],
    ['Presentation validity', Artifact.PRESENTATION],
    ['Profile lifetime', Artifact.PROFILE],
    ['Evidence artifact lifetime', Artifact.EVIDENCE],
    ['Reputation snapshot lifetime', Artifact.SNAPSHOT],
    ['Outcome report validity', Artifact.OUTCOME],
  ];
  for (const [item, a] of rows) {
    assert.equal(maxLifetime(a), draftDuration(draft, item), `${item}: maxLifetime(${a})`);
  }
});

test('TestSkewAndRetentionMatchTheDraft', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;

  assert.equal(BASELINE_SKEW_MS, draftDuration(draft, 'Clock skew'), '20.1 table');
  assert.equal(BASELINE_SKEW_MS, draftSeconds(draft, 'clock_skew_seconds'), 'clock_skew_seconds');
  for (const [key, a] of [
    ['contract_validity_seconds', Artifact.CONTRACT],
    ['presentation_validity_seconds', Artifact.PRESENTATION],
  ] as const) {
    assert.equal(maxLifetime(a), draftSeconds(draft, key), `maxLifetime(${a}), ${key}`);
  }

  // replay_retention_seconds is "At least 65": iat+60+skew with the baseline
  // skew, for a presentation that lives its full 60 seconds.
  const cell = draftKey(draft, 'replay_retention_seconds');
  const m = /^At least (\d+)$/.exec(cell);
  assert.ok(m, `replay_retention_seconds cell "${cell}" is not "At least N"`);
  const iat = 1_700_000_000;
  const got = replayRetention(iat + 60, iat, BASELINE_SKEW_MS) - iat * 1000;
  assert.equal(got, Number(m[1]) * 1000, 'baseline replay retention');

  // 7.5 states the same formula in prose.
  assert.match(
    draft,
    /later of the artifact expiry and `iat \+ 60 \+ clock_skew`/,
    'draft 7.5 no longer states the replay retention formula; revisit replayRetention',
  );
});
