// Port of go/adapter/freshness/freshness_test.go. Instants are Unix
// milliseconds here (the time-precision deviation of the parity ledger), so
// a Go row one nanosecond past a bound is one millisecond past it here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { type AgeLimits, Evaluator, evaluate, ReasonCode } from '../src/adapter/freshness.ts';
import type { NativeClaim } from '../src/adapter/index.ts';
import { BASELINE_SKEW_MS, FakeClock } from '../src/core/clock.ts';
import {
  ahead,
  at,
  badLimit,
  base,
  noTime,
  type Outcome,
  pass,
  rule,
  stale,
} from './support/freshness.ts';

function claim(observed: number | null, status: number | null): NativeClaim {
  return {
    value: 'alice',
    observedAt: observed,
    statusCheckedAt: status,
    sourceId: 'directory',
    sourceRef: 'entry-1',
  };
}

test('TestBaselineSkewIsTheClockPackageBaseline', () => {
  // Section 7.5 gives 5 seconds; the clock module owns the constant and the
  // evaluator takes it from there, so a change reaches both.
  assert.equal(BASELINE_SKEW_MS, 5000, 'the tables below assume 5 s');
});

test('TestReasonCodes', () => {
  // The spelling of every code is part of the wire contract: it lands in
  // CheckResult.reason_code. STALE_EVIDENCE is the section 13.4 code,
  // DEPENDENCY_UNAVAILABLE and UNSUPPORTED_REQUIREMENT are the section 13.4
  // and 17.1 codes, REQUIREMENT_SATISFIED is the section 17.3.1 code, and
  // CLOCK_AHEAD and RESTAMPED are the freshness profile's own.
  const rows: readonly [string, string][] = [
    [ReasonCode.SATISFIED, 'REQUIREMENT_SATISFIED'],
    [ReasonCode.STALE_EVIDENCE, 'STALE_EVIDENCE'],
    [ReasonCode.CLOCK_AHEAD, 'CLOCK_AHEAD'],
    [ReasonCode.RESTAMPED, 'RESTAMPED'],
    [ReasonCode.UNSUPPORTED_REQUIREMENT, 'UNSUPPORTED_REQUIREMENT'],
    [ReasonCode.DEPENDENCY_UNAVAILABLE, 'DEPENDENCY_UNAVAILABLE'],
  ];
  for (const [got, want] of rows) assert.equal(got, want);
  assert.equal(ReasonCode.treatedAs(ReasonCode.RESTAMPED), ReasonCode.STALE_EVIDENCE);
  for (const c of [
    ReasonCode.SATISFIED,
    ReasonCode.STALE_EVIDENCE,
    ReasonCode.CLOCK_AHEAD,
    ReasonCode.UNSUPPORTED_REQUIREMENT,
    ReasonCode.DEPENDENCY_UNAVAILABLE,
  ]) {
    assert.equal(ReasonCode.treatedAs(c), c, `${c} is treated as itself`);
  }
});

test('TestEvaluate', async (t) => {
  const now = at(base);
  const rows: readonly [string, AgeLimits, NativeClaim, number, Outcome][] = [
    // max_age_seconds against observedAt: the age may equal the limit and not
    // exceed it (section 7.5 phrases its own bounds as "at most").
    ['observed 10s ago, status now', rule(30, 0), claim(at(base - 10), now), now, pass],
    ['observed exactly at the limit', rule(30, 0), claim(at(base - 30), now), now, pass],
    [
      'observed one millisecond past the limit',
      rule(30, 0),
      claim(at(base - 31, 999), now),
      now,
      stale,
    ],
    ['observed one second past the limit', rule(30, 0), claim(at(base - 31), now), now, stale],
    ['observed long ago', rule(30, 0), claim(at(base - 86400), now), now, stale],
    ['observed now', rule(30, 0), claim(now, now), now, pass],

    // status_max_age_seconds against statusCheckedAt.
    ['status exactly at a 30s limit', rule(30, 30), claim(at(base - 5), at(base - 30)), now, pass],
    [
      'status one second past a 30s limit',
      rule(30, 30),
      claim(at(base - 5), at(base - 31)),
      now,
      stale,
    ],
    ['status fresh but observation stale', rule(30, 30), claim(at(base - 31), now), now, stale],
    ['observation fresh but status stale', rule(30, 30), claim(now, at(base - 31)), now, stale],

    // A zero status limit means a check in this evaluation: the start is now,
    // so the status time must not precede now.
    ['zero status limit, checked at now', rule(30, 0), claim(at(base - 5), now), now, pass],
    [
      'zero status limit, checked one millisecond ago',
      rule(30, 0),
      claim(at(base - 5), at(base - 1, 999)),
      now,
      stale,
    ],
    [
      'zero status limit, checked one second ago',
      rule(30, 0),
      claim(at(base - 5), at(base - 1)),
      now,
      stale,
    ],
    [
      'zero status limit, cached status',
      rule(30, 0),
      claim(at(base - 5), at(base - 25)),
      now,
      stale,
    ],
    [
      'zero status limit, checked within skew ahead',
      rule(30, 0),
      claim(at(base - 5), at(base + 2)),
      now,
      pass,
    ],
    ['zero observation limit, observed at now', rule(0, 0), claim(now, now), now, pass],
    [
      'zero observation limit, observed one second ago',
      rule(0, 0),
      claim(at(base - 1), now),
      now,
      stale,
    ],

    // Fractional now: the comparison is exact, never rounded in the claim's
    // favour (core/clock does the same for window checks).
    [
      'fractional now, age equals limit',
      rule(30, 30),
      claim(at(base - 30, 500), at(base)),
      at(base, 500),
      pass,
    ],
    [
      'fractional now, age one millisecond over',
      rule(30, 30),
      claim(at(base - 30, 499), at(base)),
      at(base, 500),
      stale,
    ],
    [
      'fractional now, status one millisecond over',
      rule(30, 30),
      claim(at(base), at(base - 30, 499)),
      at(base, 500),
      stale,
    ],

    // Source clock ahead: a time later than now+skew is rejected, however
    // fresh it looks (Appendix A.2).
    ['observed at now+skew', rule(30, 0), claim(at(base + 5), now), now, pass],
    [
      'observed one millisecond past now+skew',
      rule(30, 0),
      claim(at(base + 5, 1), now),
      now,
      ahead,
    ],
    ['observed one second past now+skew', rule(30, 0), claim(at(base + 6), now), now, ahead],
    ['observed far in the future', rule(30, 0), claim(at(base + 3600), now), now, ahead],
    ['status at now+skew', rule(30, 0), claim(now, at(base + 5)), now, pass],
    ['status one second past now+skew', rule(30, 0), claim(now, at(base + 6)), now, ahead],
    ['status far in the future', rule(30, 0), claim(now, at(base + 3600)), now, ahead],
    ['observed beyond 2^53-1 seconds', rule(30, 0), claim(at(2 ** 53), now), now, ahead],

    // Missing times: a source that gives none cannot establish freshness, and
    // unknown status is not evidence of validity (sections 8.3, 17.2).
    ['no observation time', rule(30, 0), claim(null, now), now, noTime],
    ['no status time', rule(30, 0), claim(now, null), now, noTime],
    ['no status time, positive status limit', rule(30, 30), claim(now, null), now, noTime],
    ['neither time', rule(30, 30), claim(null, null), now, noTime],
    [
      'observation before the epoch is no usable time',
      rule(30, 30),
      claim(at(-1), now),
      now,
      noTime,
    ],
    ['status before the epoch is no usable time', rule(30, 30), claim(now, at(-1)), now, noTime],
    ['observation one millisecond before the epoch', rule(30, 30), claim(-1, now), now, noTime],
    ['observation that is not a number', rule(30, 30), claim(Number.NaN, now), now, noTime],
    ['observation at the epoch is a time', rule(2147483647 * 2, 30), claim(at(0), now), now, pass],

    // A demonstrable failure outranks a missing time, and a source clock
    // ahead outranks staleness.
    ['stale observation, no status time', rule(30, 30), claim(at(base - 31), null), now, stale],
    ['observation ahead, no status time', rule(30, 30), claim(at(base + 6), null), now, ahead],
    ['no observation time, stale status', rule(30, 30), claim(null, at(base - 31)), now, stale],
    [
      'observation ahead, status stale',
      rule(30, 30),
      claim(at(base + 6), at(base - 31)),
      now,
      ahead,
    ],
    [
      'observation stale, status ahead',
      rule(30, 30),
      claim(at(base - 31), at(base + 6)),
      now,
      ahead,
    ],

    // The limits are integers in 0..2^53-1 (Appendix A schema); anything else
    // is a rule no source can satisfy.
    ['negative observation limit', rule(-1, 0), claim(now, now), now, badLimit],
    ['negative status limit', rule(30, -1), claim(now, now), now, badLimit],
    ['observation limit above 2^53-1', rule(2 ** 53, 0), claim(now, now), now, badLimit],
    ['status limit above 2^53-1', rule(30, 2 ** 53), claim(now, now), now, badLimit],
    [
      'observation limit int64 max',
      rule(Number(2n ** 63n - 1n), 0),
      claim(now, now),
      now,
      badLimit,
    ],
    ['fractional observation limit', rule(30.5, 0), claim(now, now), now, badLimit],
    ['status limit that is not a number', rule(30, Number.NaN), claim(now, now), now, badLimit],

    // A limit as large as the schema allows must not overflow.
    [
      'largest observation limit',
      rule(2 ** 53 - 1, 0),
      claim(at(base - 86400 * 365), now),
      now,
      pass,
    ],
    ['largest status limit', rule(30, 2 ** 53 - 1), claim(now, at(base - 86400 * 365)), now, pass],
    [
      'largest limit, claim at the epoch',
      rule(2 ** 53 - 1, 2 ** 53 - 1),
      claim(at(0), at(0)),
      now,
      pass,
    ],
    [
      'limit of 292 years in seconds, one year old',
      rule(9_223_372_037, 0),
      claim(at(base - 86400 * 365), now),
      now,
      pass,
    ],
    [
      'limit past 292 years, claim at the epoch',
      rule(9_223_372_037, 9_223_372_037),
      claim(at(0), at(0)),
      now,
      pass,
    ],
  ];
  for (const [name, r, c, n, want] of rows) {
    await t.test(name, () => {
      assert.deepEqual(evaluate(r, c, n), want);
    });
  }
});

test('TestEvaluateIgnoresTheClaimValue', () => {
  // Freshness says nothing about the value; a null value is JSON null and
  // evaluates like any other.
  const c = { ...claim(at(base - 1), at(base)), value: null };
  assert.deepEqual(evaluate(rule(30, 0), c, at(base)), pass);
});

test('TestEvaluator', async (t) => {
  const now = at(base);
  const skewed = (skew: number) => new Evaluator({ skew });
  const started = (start: number) => new Evaluator({ skew: BASELINE_SKEW_MS, start });
  const rows: readonly [string, Evaluator, AgeLimits, NativeClaim, Outcome][] = [
    // Skew may be tightened (section 7.5: deployments MAY tighten).
    ['zero skew, observed at now', new Evaluator(), rule(30, 0), claim(now, now), pass],
    [
      'zero skew, observed one millisecond ahead',
      new Evaluator(),
      rule(30, 0),
      claim(at(base, 1), now),
      ahead,
    ],
    [
      'zero skew, status one millisecond ahead',
      new Evaluator(),
      rule(30, 0),
      claim(now, at(base, 1)),
      ahead,
    ],
    ['2s skew, observed at now+2s', skewed(2000), rule(30, 0), claim(at(base + 2), now), pass],
    ['2s skew, observed at now+3s', skewed(2000), rule(30, 0), claim(at(base + 3), now), ahead],
    [
      '5s skew is the baseline',
      skewed(BASELINE_SKEW_MS),
      rule(30, 0),
      claim(at(base + 5), now),
      pass,
    ],

    // Skew above the baseline is not honoured, and a negative skew counts as
    // zero, the way core/clock treats it in replayRetention.
    [
      '6s skew is held to the baseline, at now+5s',
      skewed(6000),
      rule(30, 0),
      claim(at(base + 5), now),
      pass,
    ],
    [
      '6s skew is held to the baseline, at now+6s',
      skewed(6000),
      rule(30, 0),
      claim(at(base + 6), now),
      ahead,
    ],
    [
      'hour skew is held to the baseline',
      skewed(3_600_000),
      rule(30, 0),
      claim(at(base + 3600), now),
      ahead,
    ],
    ['negative skew counts as zero, at now', skewed(-1000), rule(30, 0), claim(now, now), pass],
    [
      'negative skew counts as zero, one millisecond ahead',
      skewed(-1000),
      rule(30, 0),
      claim(at(base, 1), now),
      ahead,
    ],
    [
      'a skew that is not a number counts as zero',
      skewed(Number.NaN),
      rule(30, 0),
      claim(at(base, 1), now),
      ahead,
    ],

    // The start is when this evaluation began. A zero limit asks for a time
    // not before it, and a positive limit is measured from now regardless.
    [
      'start 10s ago, status 5s ago',
      started(at(base - 10)),
      rule(30, 0),
      claim(at(base - 5), at(base - 5)),
      pass,
    ],
    [
      'start 10s ago, status at start',
      started(at(base - 10)),
      rule(30, 0),
      claim(at(base - 5), at(base - 10)),
      pass,
    ],
    [
      'start 10s ago, status before start',
      started(at(base - 10)),
      rule(30, 0),
      claim(at(base - 5), at(base - 11, 999)),
      stale,
    ],
    [
      'start 10s ago, observed before start, zero observation limit',
      started(at(base - 10)),
      rule(0, 0),
      claim(at(base - 11), now),
      stale,
    ],
    [
      'start 100s ago does not loosen a positive status limit',
      started(at(base - 100)),
      rule(30, 30),
      claim(at(base - 5), at(base - 31)),
      stale,
    ],
    [
      'start 100s ago does not loosen a positive observation limit',
      started(at(base - 100)),
      rule(30, 30),
      claim(at(base - 31), now),
      stale,
    ],
    [
      'no start means now',
      new Evaluator({ skew: BASELINE_SKEW_MS }),
      rule(30, 0),
      claim(at(base - 5), at(base - 1)),
      stale,
    ],
  ];
  for (const [name, ev, r, c, want] of rows) {
    await t.test(name, () => {
      assert.deepEqual(ev.evaluate(r, c, now), want);
    });
  }
  const zero = new Evaluator();
  assert.deepEqual([zero.skew, zero.start, zero.guard], [0, null, null], 'the zero value');
});

test('TestEvaluateIsTheBaselineEvaluator', () => {
  const now = at(base);
  const cases = [
    claim(now, now),
    claim(at(base - 31), now),
    claim(at(base + 5), now),
    claim(at(base + 6), now),
    claim(null, now),
    claim(now, at(base - 1)),
  ];
  cases.forEach((c, i) => {
    assert.deepEqual(
      evaluate(rule(30, 0), c, now),
      new Evaluator({ skew: BASELINE_SKEW_MS }).evaluate(rule(30, 0), c, now),
      `case ${i}`,
    );
  });
});

test('TestEvaluateWithAFakeClock', () => {
  // The evaluator takes the instant as an argument, so a test moves it with
  // the fake clock of core/clock and never reads the wall clock.
  const clk = new FakeClock(at(base));
  const c = claim(clk.now(), clk.now());
  assert.deepEqual(evaluate(rule(30, 30), c, clk.now()), pass, 'at issue');
  clk.advance(30_000);
  assert.deepEqual(evaluate(rule(30, 30), c, clk.now()), pass, '30 s later');
  clk.advance(1000);
  assert.deepEqual(evaluate(rule(30, 30), c, clk.now()), stale, '31 s later');
  // A validator clock 30 s behind the source puts the claim in the future.
  clk.advance(-61_000);
  assert.deepEqual(evaluate(rule(30, 30), c, clk.now()), ahead, 'validator clock 30 s behind');
});
