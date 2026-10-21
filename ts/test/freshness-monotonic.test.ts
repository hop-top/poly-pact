// Port of go/adapter/freshness/monotonic_test.go: the re-stamp guard of
// spec/v1.0/profiles/freshness.md section 7 and its place in the order of the
// findings.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Evaluator,
  evaluate,
  Monotonic,
  ReasonCode,
  type Result,
} from '../src/adapter/freshness.ts';
import type { NativeClaim } from '../src/adapter/index.ts';
import { BASELINE_SKEW_MS } from '../src/core/clock.ts';
import { CheckStatus } from '../src/core/enums.ts';
import { at, badLimit, base, noTime, pass, rule, stale } from './support/freshness.ts';

// A claim for (source, ref) observed at the given instant.
function seen(source: string, ref: string, observed: number | null): NativeClaim {
  return {
    value: 'alice',
    observedAt: observed,
    statusCheckedAt: at(base),
    sourceId: source,
    sourceRef: ref,
  };
}

type CheckOutcome = readonly [Result, ReasonCode | ''];

const notApplicable: CheckOutcome = [CheckStatus.NOT_APPLICABLE, ''];
const restamped: CheckOutcome = [CheckStatus.FAIL, ReasonCode.RESTAMPED];
const deferred: CheckOutcome = [CheckStatus.UNKNOWN, ReasonCode.DEPENDENCY_UNAVAILABLE];

test('TestMonotonicCheck', async (t) => {
  // Each step runs against one guard, in order. The observation time of a
  // source record never changes (draft 8.3): a later one for the same record
  // is a re-stamp, and a new time needs a new sourceRef.
  const rows: readonly [string, readonly [string, NativeClaim, CheckOutcome][]][] = [
    ['first sighting passes', [['first', seen('dir', 'e1', at(100)), pass]]],
    [
      'the same time again passes',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['again', seen('dir', 'e1', at(100)), pass],
        ['and again', seen('dir', 'e1', at(100)), pass],
      ],
    ],
    [
      'a later time for the same record is a re-stamp',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['later', seen('dir', 'e1', at(101)), restamped],
      ],
    ],
    [
      'a re-stamp does not become the new baseline',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['later', seen('dir', 'e1', at(500)), restamped],
        ['later again', seen('dir', 'e1', at(500)), restamped],
        ['original', seen('dir', 'e1', at(100)), pass],
      ],
    ],
    [
      'an earlier time lowers the baseline',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['earlier', seen('dir', 'e1', at(90)), pass],
        ['the first time is now later than the baseline', seen('dir', 'e1', at(100)), restamped],
        ['earlier again', seen('dir', 'e1', at(90)), pass],
      ],
    ],
    [
      'a re-stamp is caught however stale the first sighting was',
      [
        ['stale original', seen('dir', 'e1', at(base - 86400)), pass],
        ['laundered', seen('dir', 'e1', at(base)), restamped],
      ],
    ],
    [
      'records are independent',
      [
        ['e1', seen('dir', 'e1', at(100)), pass],
        ['e2', seen('dir', 'e2', at(200)), pass],
        ['e1 later', seen('dir', 'e1', at(101)), restamped],
        ['e2 same', seen('dir', 'e2', at(200)), pass],
        ['e2 later', seen('dir', 'e2', at(201)), restamped],
      ],
    ],
    [
      'a reference is scoped to its source',
      [
        ['dir', seen('dir', 'e1', at(100)), pass],
        ['idp', seen('idp', 'e1', at(300)), pass],
        ['dir later', seen('dir', 'e1', at(101)), restamped],
        ['idp later', seen('idp', 'e1', at(301)), restamped],
        ['idp same', seen('idp', 'e1', at(300)), pass],
      ],
    ],
    [
      'the wire carries whole seconds',
      [
        ['first', seen('dir', 'e1', at(100, 1)), pass],
        ['same second, later fraction', seen('dir', 'e1', at(100, 900)), pass],
        ['next second', seen('dir', 'e1', at(101)), restamped],
        ['same second, earlier fraction', seen('dir', 'e1', at(100)), pass],
      ],
    ],
    [
      'no reference is nothing to compare',
      [
        ['first', seen('dir', '', at(100)), notApplicable],
        ['later', seen('dir', '', at(200)), notApplicable],
      ],
    ],
    [
      'no observation time is nothing to compare',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['none', seen('dir', 'e1', null), notApplicable],
        ['later', seen('dir', 'e1', at(101)), restamped],
      ],
    ],
    [
      'a time before the epoch is nothing to compare',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['before the epoch', seen('dir', 'e1', at(-5)), notApplicable],
        ['same', seen('dir', 'e1', at(100)), pass],
      ],
    ],
    [
      'a claim with no reference leaves the others alone',
      [
        ['first', seen('dir', 'e1', at(100)), pass],
        ['no ref', seen('dir', '', at(900)), notApplicable],
        ['e1 same', seen('dir', 'e1', at(100)), pass],
      ],
    ],
    [
      // The key of a record is the pair, not a joined string.
      'the source and the reference do not run together',
      [
        ['a + bc', seen('a', 'bc', at(100)), pass],
        ['ab + c', seen('ab', 'c', at(200)), pass],
        ['a + bc later', seen('a', 'bc', at(101)), restamped],
      ],
    ],
  ];
  for (const [name, steps] of rows) {
    await t.test(name, () => {
      const m = new Monotonic(16);
      for (const [step, c, want] of steps) assert.deepEqual(m.check(c), want, step);
    });
  }
});

test('TestMonotonicCapacity', () => {
  // A full store defers (draft 7.5 and 18: a full or unavailable state store
  // causes deferral, never a pass), and never evicts to make room.
  const m = new Monotonic(2);
  assert.deepEqual(m.check(seen('dir', 'e1', at(100))), pass, 'e1');
  assert.deepEqual(m.check(seen('dir', 'e2', at(100))), pass, 'e2');
  assert.equal(m.len(), 2);

  assert.deepEqual(m.check(seen('dir', 'e3', at(100))), deferred, 'e3 in a full store');
  assert.equal(m.len(), 2, 'after a refused record');
  // Known records are still guarded, and an old record was not evicted.
  assert.deepEqual(m.check(seen('dir', 'e1', at(101))), restamped, 'e1 re-stamp in a full store');
  assert.deepEqual(m.check(seen('dir', 'e2', at(100))), pass, 'e2 again in a full store');

  // forget frees one slot, and only that one.
  m.forget('dir', 'e1');
  assert.equal(m.len(), 1, 'after forget');
  assert.deepEqual(m.check(seen('dir', 'e3', at(100))), pass, 'e3 after forget');
  assert.deepEqual(m.check(seen('dir', 'e1', at(100))), deferred, 'e1 after its slot went');
  m.forget('dir', 'never-seen'); // no effect
  m.forget('other', 'e2'); // another source: no effect
  assert.equal(m.len(), 2, 'after forgetting nothing');
});

test('TestMonotonicForgetStartsTheRecordAfresh', () => {
  const m = new Monotonic(4);
  m.check(seen('dir', 'e1', at(100)));
  m.forget('dir', 'e1');
  assert.deepEqual(m.check(seen('dir', 'e1', at(500))), pass, 'a first sighting after forget');
  assert.deepEqual(m.check(seen('dir', 'e1', at(501))), restamped, 'and is then guarded');
});

test('TestMonotonicWithNoCapacityDefersEveryReference', () => {
  for (const limit of [0, -1, Number.NaN]) {
    const m = new Monotonic(limit);
    assert.deepEqual(m.check(seen('dir', 'e1', at(100))), deferred, `limit ${limit}`);
    // A claim the guard cannot compare is not refused for want of room.
    assert.deepEqual(m.check(seen('dir', '', at(100))), notApplicable, `limit ${limit}, no ref`);
    assert.equal(m.len(), 0);
  }
});

test('TestMonotonicIsSafeForConcurrentUse', async () => {
  // Every worker reports the same record at a different time, interleaved
  // through the event loop. Whatever the order, the lowest time recorded is
  // the baseline, and no time above it passes once it is set.
  const m = new Monotonic(8);
  await Promise.all(
    Array.from({ length: 16 }, async (_, i) => {
      for (let n = 0; n < 50; n++) {
        await null;
        m.check(seen('dir', 'e1', at(1000 + i)));
      }
    }),
  );
  assert.deepEqual(m.check(seen('dir', 'e1', at(1000))), pass, 'lowest time');
  assert.deepEqual(m.check(seen('dir', 'e1', at(1001))), restamped, 'a higher time');
  assert.equal(m.len(), 1);
});

function guarded(m: Monotonic): Evaluator {
  return new Evaluator({ skew: BASELINE_SKEW_MS, guard: m });
}

test('TestEvaluatorGuard', async (t) => {
  const now = at(base);

  await t.test('a refreshed time for a known record is a re-stamp', () => {
    const ev = guarded(new Monotonic(4));
    // The source saw the fact 20 s ago.
    assert.deepEqual(
      ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 20)), now),
      pass,
      'first',
    );
    // Ten seconds on, the same record comes back stamped "now", fresh enough
    // on its face. Age alone passes it; the guard does not.
    const later = at(base + 10);
    const relaundered = { ...seen('dir', 'e1', later), statusCheckedAt: later };
    assert.deepEqual(ev.evaluate(rule(30, 0), relaundered, later), restamped, 'guarded');
    assert.deepEqual(
      evaluate(rule(30, 0), relaundered, later),
      pass,
      'the guard is what catches it',
    );
  });

  await t.test('a stale first sighting still sets the baseline', () => {
    // The stale fact is refused, and then the same record re-stamped as fresh
    // must not get through: re-signing never launders an old observation.
    const ev = guarded(new Monotonic(4));
    assert.deepEqual(ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 3600)), now), stale);
    const fresh = { ...seen('dir', 'e1', now), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), fresh, now), restamped, 'laundered');
  });

  await t.test('a new record with a new reference is a new observation', () => {
    const ev = guarded(new Monotonic(4));
    ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 3600)), now);
    const fresh = { ...seen('dir', 'e2', now), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), fresh, now), pass);
  });

  await t.test('a re-stamp that is also stale reports the re-stamp', () => {
    const ev = guarded(new Monotonic(4));
    ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 7200)), now);
    const stillStale = { ...seen('dir', 'e1', at(base - 3600)), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), stillStale, now), restamped);
  });

  await t.test('a source clock ahead is reported as that and is not recorded', () => {
    const m = new Monotonic(4);
    const ev = guarded(m);
    const future = seen('dir', 'e1', at(base + 3600));
    assert.deepEqual(ev.evaluate(rule(30, 0), future, now), [
      CheckStatus.FAIL,
      ReasonCode.CLOCK_AHEAD,
    ]);
    assert.equal(m.len(), 0, 'an implausible time must not become a baseline');
  });

  await t.test('a source clock ahead outranks a re-stamp', () => {
    const m = new Monotonic(4);
    const ev = guarded(m);
    ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 20)), now);
    const later = { ...seen('dir', 'e1', at(base + 3600)), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), later, now), [
      CheckStatus.FAIL,
      ReasonCode.CLOCK_AHEAD,
    ]);
    assert.deepEqual(m.check(seen('dir', 'e1', at(base - 20))), pass, 'the baseline did not move');
  });

  await t.test('a full store defers a claim that otherwise passes', () => {
    const ev = guarded(new Monotonic(0));
    const fresh = { ...seen('dir', 'e1', now), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), fresh, now), deferred);
  });

  await t.test('a demonstrable failure outranks a full store', () => {
    const ev = guarded(new Monotonic(0));
    assert.deepEqual(ev.evaluate(rule(30, 0), seen('dir', 'e1', at(base - 3600)), now), stale);
  });

  await t.test('a claim with no reference passes on age alone', () => {
    const ev = guarded(new Monotonic(0));
    const fresh = { ...seen('dir', '', now), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), fresh, now), pass);
  });

  await t.test('a rule no source can satisfy is refused before the guard', () => {
    const m = new Monotonic(4);
    assert.deepEqual(guarded(m).evaluate(rule(-1, 0), seen('dir', 'e1', now), now), badLimit);
    assert.equal(m.len(), 0);
  });

  await t.test('a missing status time is reported once the guard has passed', () => {
    const m = new Monotonic(4);
    const c = { ...seen('dir', 'e1', now), statusCheckedAt: null };
    assert.deepEqual(guarded(m).evaluate(rule(30, 0), c, now), noTime);
    assert.equal(m.len(), 1, 'the observation was plausible and is recorded');
  });
});

test('TestEvaluatorGuardAcrossManyRecords', () => {
  const ev = guarded(new Monotonic(64));
  const now = at(base);
  for (let i = 0; i < 64; i++) {
    const c = { ...seen('dir', `e${i}`, now), statusCheckedAt: now };
    assert.deepEqual(ev.evaluate(rule(30, 0), c, now), pass, `e${i}`);
  }
  const later = at(base + 1);
  for (let i = 0; i < 64; i++) {
    const c = { ...seen('dir', `e${i}`, later), statusCheckedAt: later };
    assert.deepEqual(ev.evaluate(rule(30, 0), c, later), restamped, `e${i} re-stamped`);
  }
});
