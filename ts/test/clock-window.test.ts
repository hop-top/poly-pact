// Port of go/core/clock/window_test.go. Expected values come from draft
// sections 7.5 (nbf <= now + skew, iat <= now + skew, now < exp with no
// grace, now - iat <= 60 s, replay retention the later of exp and
// iat + 60 + skew) and 20.1 (lifetimes, skew at most 5 s).
//
// Instants are Unix milliseconds and wire claims integer seconds. A Go
// instant at or near 2^53-1 seconds has no millisecond counterpart (it
// exceeds 2^53-1 ms); those rows keep their Go names, their claims, and a
// `now` that a millisecond clock can hold, and say so.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Artifact,
  BASELINE_SKEW_MS,
  ClockError,
  type ClockErrorKind,
  checkLifetime,
  checkPresentation,
  checkPresentationAge,
  checkWindow,
  maxLifetime,
  replayRetention,
} from '../src/core/clock.ts';

// The instant every table below measures against, in seconds.
const base = 1_000_000;
// The largest core integer, 2^53-1 (draft section 7.1).
const top = 9007199254740991;
// Go math.MaxInt64 and math.MinInt64 as JavaScript numbers.
const maxInt64 = 2 ** 63;
const minInt64 = -(2 ** 63);
// The latest instant a millisecond clock holds exactly: 2^53-1 ms.
const latestMs = Number.MAX_SAFE_INTEGER;

/** The instant `sec` whole seconds after the epoch, in ms. */
function at(sec: number): number {
  return sec * 1000;
}

function check(fn: () => void, want: ClockErrorKind | undefined, what = ''): void {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  if (want === undefined) {
    assert.equal(err, undefined, `${what} unexpected error: ${String(err)}`);
    return;
  }
  assert.ok(err instanceof ClockError, `${what} got ${String(err)}, want ClockError ${want}`);
  assert.equal(err.kind, want, `${what} ${err.message}`);
}

test('TestBaselineSkew', () => {
  assert.equal(BASELINE_SKEW_MS, 5000);
});

test('TestCheckWindow', async (t) => {
  const skew = BASELINE_SKEW_MS;
  const subsecond = at(base) + 999;

  const tests: readonly [string, number, number, number, number, number, ClockErrorKind?][] = [
    // name, iat, nbf, exp, now, skew, want
    ['inside the window', base - 10, base - 10, base + 50, at(base), skew],
    ['all claims at now', base, base, base + 1, at(base), skew],

    // nbf <= now + skew
    ['nbf equals now+skew', base, base + 5, base + 60, at(base), skew],
    ['nbf one second past now+skew', base, base + 6, base + 60, at(base), skew, 'NOT_YET_VALID'],
    ['nbf far in the future', base, base + 3600, base + 7200, at(base), skew, 'NOT_YET_VALID'],
    ['nbf in the past', base, base - 3600, base + 60, at(base), skew],
    ['nbf vs fractional now, equal bound', base, base + 5, base + 60, subsecond, skew],
    [
      'nbf vs fractional now, past bound',
      base,
      base + 6,
      base + 60,
      subsecond,
      skew,
      'NOT_YET_VALID',
    ],

    // iat <= now + skew
    ['iat equals now+skew', base + 5, base, base + 60, at(base), skew],
    ['iat one second past now+skew', base + 6, base, base + 60, at(base), skew, 'ISSUED_IN_FUTURE'],
    ['iat far in the future', base + 3600, base, base + 7200, at(base), skew, 'ISSUED_IN_FUTURE'],
    ['iat vs fractional now, equal bound', base + 5, base, base + 60, subsecond, skew],
    [
      'iat vs fractional now, past bound',
      base + 6,
      base,
      base + 60,
      subsecond,
      skew,
      'ISSUED_IN_FUTURE',
    ],

    // now < exp, with no grace period
    ['exp one second after now', base - 10, base - 10, base + 1, at(base), skew],
    ['exp equals now', base - 10, base - 10, base, at(base), skew, 'EXPIRED'],
    ['exp one second before now', base - 10, base - 10, base - 1, at(base), skew, 'EXPIRED'],
    [
      'exp within skew of now gets no grace',
      base - 10,
      base - 10,
      base - 5,
      at(base),
      skew,
      'EXPIRED',
    ],
    ['exp long past', base - 7200, base - 7200, base - 3600, at(base), skew, 'EXPIRED'],
    ['fractional now before exp', base - 10, base - 10, base + 1, subsecond, skew],
    ['fractional now past exp', base - 10, base - 10, base, subsecond, skew, 'EXPIRED'],
    ['now half a second past exp', base - 10, base - 10, base, at(base) + 500, skew, 'EXPIRED'],
    ['now half a second before exp', base - 10, base - 10, base + 1, at(base) + 500, skew],

    // tighter skew is allowed
    ['zero skew, nbf equals now', base, base, base + 60, at(base), 0],
    ['zero skew, nbf one second ahead', base, base + 1, base + 60, at(base), 0, 'NOT_YET_VALID'],
    ['zero skew, iat one second ahead', base + 1, base, base + 60, at(base), 0, 'ISSUED_IN_FUTURE'],
    ['2s skew, nbf equals now+2', base, base + 2, base + 60, at(base), 2000],
    ['2s skew, nbf at now+3', base, base + 3, base + 60, at(base), 2000, 'NOT_YET_VALID'],
    // now + skew = base + 0.6 s + 2.5 s = base + 3.1 s: the remainder of now
    // and of the skew add up past a whole second.
    [
      '2.5s skew, fractional now, nbf at the carried second',
      base,
      base + 3,
      base + 60,
      at(base) + 600,
      2500,
    ],
    [
      '2.5s skew, fractional now, nbf one second later',
      base,
      base + 4,
      base + 60,
      at(base) + 600,
      2500,
      'NOT_YET_VALID',
    ],
    [
      '2.5s skew, fractional now, iat at the carried second',
      base + 3,
      base,
      base + 60,
      at(base) + 600,
      2500,
    ],

    // claims outside the core integer range 0..2^53-1 are rejected
    ['iat negative', -1, base, base + 60, at(base), skew, 'TIMESTAMP'],
    ['nbf negative', base, -1, base + 60, at(base), skew, 'TIMESTAMP'],
    ['exp negative', base, base, -1, at(base), skew, 'TIMESTAMP'],
    ['iat above 2^53-1', 2 ** 53, base, base + 60, at(base), skew, 'TIMESTAMP'],
    ['nbf above 2^53-1', base, 2 ** 53, base + 60, at(base), skew, 'TIMESTAMP'],
    ['exp above 2^53-1', base, base, 2 ** 53, at(base), skew, 'TIMESTAMP'],
    [
      'nbf int64 max must not wrap into the past',
      base,
      maxInt64,
      base + 60,
      at(base),
      skew,
      'TIMESTAMP',
    ],
    ['exp int64 max', base, base, maxInt64, at(base), skew, 'TIMESTAMP'],
    ['claims at the epoch are in range', 0, 0, 1, at(0), skew],
    // Go: now at 2^53-1 s, EXPIRED. The latest millisecond instant is earlier
    // than 2^53-1 s, so claims at 2^53-1 are in range and not yet valid.
    ['all claims at 2^53-1', top, top, top, latestMs, skew, 'NOT_YET_VALID'],
    // Go: iat = nbf = 2^53-3, now 2^53-2 s. Here iat = nbf = base.
    ['exp at 2^53-1 is still ahead', base, base, top, at(base), skew],
    ['exp at 2^53-1 is ahead of the latest millisecond instant', 0, 0, top, latestMs, skew],

    // a claim that is not an integer is outside the core integer range
    ['iat fractional', base + 0.5, base, base + 60, at(base), skew, 'TIMESTAMP'],
    ['exp NaN', base, base, Number.NaN, at(base), skew, 'TIMESTAMP'],
    ['nbf -Infinity', base, Number.NEGATIVE_INFINITY, base + 60, at(base), skew, 'TIMESTAMP'],

    // skew above the baseline or negative is rejected
    ['skew one nanosecond over baseline', base, base, base + 60, at(base), skew + 1e-6, 'SKEW'],
    ['skew 6s', base, base, base + 60, at(base), 6000, 'SKEW'],
    ['negative skew', base, base, base + 60, at(base), -1000, 'SKEW'],
    ['NaN skew', base, base, base + 60, at(base), Number.NaN, 'SKEW'],
  ];
  for (const [name, iat, nbf, exp, now, s, want] of tests) {
    await t.test(name, () => check(() => checkWindow(iat, nbf, exp, now, s), want));
  }
});

test('TestCheckWindowErrorsAreDistinct', () => {
  const all: readonly ClockErrorKind[] = [
    'NOT_YET_VALID',
    'ISSUED_IN_FUTURE',
    'EXPIRED',
    'SKEW',
    'TIMESTAMP',
  ];
  const cases: readonly [string, number, number, number, ClockErrorKind][] = [
    ['nbf', base, base + 100, base + 200, 'NOT_YET_VALID'],
    ['iat', base + 100, base, base + 200, 'ISSUED_IN_FUTURE'],
    ['exp', base - 10, base - 10, base - 1, 'EXPIRED'],
  ];
  for (const [name, iat, nbf, exp, want] of cases) {
    let err: unknown;
    try {
      checkWindow(iat, nbf, exp, at(base), BASELINE_SKEW_MS);
    } catch (e) {
      err = e;
    }
    assert.ok(err instanceof ClockError, `${name}: ${String(err)}`);
    for (const k of all) {
      assert.equal(err.kind === k, k === want, `${name}: kind ${err.kind}, checking ${k}`);
    }
  }
});

test('TestMaxLifetime', () => {
  const tests: readonly [Artifact, number][] = [
    [Artifact.PRESENTATION, 60_000],
    [Artifact.CONTRACT, 60_000],
    [Artifact.EVIDENCE, 3_600_000],
    [Artifact.SNAPSHOT, 300_000],
    [Artifact.OUTCOME, 300_000],
    [Artifact.PROFILE, 86_400_000],
  ];
  for (const [a, want] of tests) {
    assert.equal(maxLifetime(a), want, `maxLifetime(${a})`);
  }
  const zero = { code: 0 } as unknown as Artifact;
  const ninetyNine = { code: 99 } as unknown as Artifact;
  check(() => maxLifetime(zero), 'UNKNOWN_ARTIFACT', 'maxLifetime(zero)');
  check(() => maxLifetime(ninetyNine), 'UNKNOWN_ARTIFACT', 'maxLifetime(99)');
});

test('TestCheckLifetime', async (t) => {
  const limits: readonly [Artifact, number][] = [
    [Artifact.PRESENTATION, 60],
    [Artifact.CONTRACT, 60],
    [Artifact.EVIDENCE, 3600],
    [Artifact.SNAPSHOT, 300],
    [Artifact.OUTCOME, 300],
    [Artifact.PROFILE, 86400],
  ];
  const iat = 1_700_000_000;
  for (const [a, max] of limits) {
    await t.test(String(a), () => {
      check(() => checkLifetime(a, iat, iat + max), undefined);
      check(() => checkLifetime(a, iat, iat + max + 1), 'LIFETIME');
      check(() => checkLifetime(a, iat, iat + max - 1), undefined);
      check(() => checkLifetime(a, iat, iat + 1), undefined);
      // A.2: iat < exp, so an empty or negative lifetime is malformed.
      check(() => checkLifetime(a, iat, iat), 'LIFETIME');
      check(() => checkLifetime(a, iat, iat - 1), 'LIFETIME');
    });
  }

  await t.test('unknown artifact', () => {
    const zero = { code: 0 } as unknown as Artifact;
    check(() => checkLifetime(zero, iat, iat + 1), 'UNKNOWN_ARTIFACT');
  });
  await t.test('range extremes do not wrap', () => {
    check(() => checkLifetime(Artifact.PROFILE, minInt64, maxInt64), 'LIFETIME');
    check(() => checkLifetime(Artifact.PROFILE, -1, maxInt64), 'LIFETIME');
    check(() => checkLifetime(Artifact.PRESENTATION, 0, maxInt64), 'LIFETIME');
  });
  await t.test('largest core integers', () => {
    check(() => checkLifetime(Artifact.PRESENTATION, top - 60, top), undefined);
    check(() => checkLifetime(Artifact.PRESENTATION, top - 61, top), 'LIFETIME');
  });
  await t.test('claims that are not integers', () => {
    check(() => checkLifetime(Artifact.PROFILE, iat, iat + 0.5), 'TIMESTAMP');
    check(() => checkLifetime(Artifact.PROFILE, Number.NaN, iat), 'TIMESTAMP');
    check(() => checkLifetime(Artifact.PROFILE, iat, Number.POSITIVE_INFINITY), 'TIMESTAMP');
  });
});

test('TestCheckPresentationAge', async (t) => {
  const tests: readonly [string, number, number, ClockErrorKind?][] = [
    ['age 0', base, at(base)],
    ['age 60 equals the bound', base - 60, at(base)],
    ['age 61', base - 61, at(base), 'TOO_OLD'],
    ['age 60s + 1ns', base - 60, at(base) + 1e-6, 'TOO_OLD'],
    ['age 60s - 1ns', base - 60, at(base) - 1e-6],
    ['age 60s + 1ms', base - 60, at(base) + 1, 'TOO_OLD'],
    ['age 60s - 1ms', base - 60, at(base) - 1],
    ['age 60.5s', base - 60, at(base) + 500, 'TOO_OLD'],
    ['age 59.5s', base - 59, at(base) + 500],
    ['issued in the future is not too old', base + 5, at(base)],
    ['long ago', base - 86400, at(base), 'TOO_OLD'],
    ['iat at the epoch', 0, at(0)],
    ['negative iat', -1, at(base), 'TIMESTAMP'],
    ['iat above 2^53-1', 2 ** 53, at(base), 'TIMESTAMP'],
    ['iat at 2^53-1 is in range', top, latestMs],
    ['fractional iat', base - 0.5, at(base), 'TIMESTAMP'],
  ];
  for (const [name, iat, now, want] of tests) {
    await t.test(name, () => check(() => checkPresentationAge(iat, now), want));
  }
});

test('TestCheckPresentation', async (t) => {
  const skew = BASELINE_SKEW_MS;
  const tests: readonly [string, number, number, number, number, ClockErrorKind?][] = [
    ['fresh presentation', base - 10, base - 10, base + 50, at(base)],
    ['issued now, full lifetime', base, base, base + 60, at(base)],
    ['issued within skew of the future', base + 5, base + 5, base + 65, at(base)],
    ['exp - iat is 61', base - 10, base - 10, base + 51, at(base), 'LIFETIME'],
    ['exp - iat is 60', base - 10, base - 10, base + 50, at(base)],
    ['last second of validity', base - 59, base - 59, base + 1, at(base)],
    ['expired', base - 60, base - 60, base, at(base), 'EXPIRED'],
    ['iat too far ahead', base + 6, base, base + 66, at(base), 'ISSUED_IN_FUTURE'],
    ['nbf too far ahead', base, base + 6, base + 60, at(base), 'NOT_YET_VALID'],
    ['expiry before issue', base + 4, base, base + 2, at(base), 'LIFETIME'],
  ];
  for (const [name, iat, nbf, exp, now, want] of tests) {
    await t.test(name, () => check(() => checkPresentation(iat, nbf, exp, now, skew), want));
  }

  await t.test('skew is validated', () => {
    check(() => checkPresentation(base, base, base + 60, at(base), 6000), 'SKEW');
  });
  await t.test('tighter skew applies', () => {
    check(() => checkPresentation(base + 3, base, base + 63, at(base), 2000), 'ISSUED_IN_FUTURE');
  });
});

// replayRetention returns an instant in ms. A retention later than the
// latest millisecond instant, 2^53-1 ms, is Infinity: it is never shortened
// by rounding and no clock reading reaches it.
test('TestReplayRetention', async (t) => {
  const iat = 1_700_000_000;
  const tests: readonly [string, number, number, number][] = [
    ['60s presentation, baseline skew', iat + 60, BASELINE_SKEW_MS, at(iat + 65)],
    ['short presentation is held for iat+60+skew', iat + 10, BASELINE_SKEW_MS, at(iat + 65)],
    ['exp equals iat+60+skew', iat + 65, BASELINE_SKEW_MS, at(iat + 65)],
    ['exp one second past iat+60+skew', iat + 66, BASELINE_SKEW_MS, at(iat + 66)],
    ['expiry later than the window', iat + 600, BASELINE_SKEW_MS, at(iat + 600)],
    ['zero skew', iat + 60, 0, at(iat + 60)],
    ['2s skew', iat + 30, 2000, at(iat + 62)],
    ['fractional skew', iat + 30, 1500, at(iat + 61) + 500],
    ['negative skew counts as zero', iat + 30, -1000, at(iat + 60)],
    ['exp before iat', iat - 5, BASELINE_SKEW_MS, at(iat + 65)],
  ];
  for (const [name, exp, skew, want] of tests) {
    await t.test(name, () => assert.equal(replayRetention(exp, iat, skew), want));
  }

  await t.test('out-of-range claims never shorten retention', () => {
    // Go: 2^53-1 + 65 s.
    assert.equal(replayRetention(maxInt64, maxInt64, BASELINE_SKEW_MS), Infinity);
  });
  await t.test('an out-of-range expiry is clamped, not wrapped', () => {
    // Go: 2^53-1 s.
    assert.equal(replayRetention(maxInt64, base, BASELINE_SKEW_MS), Infinity);
    assert.equal(replayRetention(minInt64, base, BASELINE_SKEW_MS), at(base + 65));
  });
  await t.test('largest core integers do not wrap', () => {
    // Go: 2^53-1 - 30 + 65 s and 2^53-1 + 65 s.
    assert.equal(replayRetention(top, top - 30, BASELINE_SKEW_MS), Infinity);
    assert.equal(replayRetention(top - 100, top, BASELINE_SKEW_MS), Infinity);
  });
  await t.test('the latest millisecond instant is exact', () => {
    // floor((2^53-1) / 1000) = 9007199254740 s is the last whole second
    // below 2^53-1 ms; one second later is past it.
    const lastSec = 9007199254740;
    assert.equal(replayRetention(lastSec, 0, BASELINE_SKEW_MS), 9007199254740000);
    assert.equal(replayRetention(lastSec + 1, 0, BASELINE_SKEW_MS), Infinity);
    assert.equal(replayRetention(0, lastSec - 65, BASELINE_SKEW_MS), 9007199254740000);
    assert.equal(replayRetention(0, lastSec - 64, BASELINE_SKEW_MS), Infinity);
  });
});
