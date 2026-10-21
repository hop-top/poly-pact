// Port of go/core/clock/clock_test.go. Instants are Unix milliseconds, so a
// Go time.Unix(s, ns) is s * 1000 + ns / 1e6 here.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { type Clock, FakeClock, SystemClock } from '../src/core/clock.ts';

const _system: Clock = new SystemClock();
const _fake: Clock = new FakeClock(0);
void _system;
void _fake;

test('TestSystemClockTracksWallTime', () => {
  const before = Date.now();
  const got = new SystemClock().now();
  const after = Date.now();
  assert.ok(got >= before && got <= after, `now() = ${got}, want within [${before}, ${after}]`);
});

test('TestFake', () => {
  const start = 1_000_000_000;
  const f = new FakeClock(start);
  assert.equal(f.now(), start);
  assert.equal(f.now(), start, 'a fake clock moved on its own');

  f.advance(90_000);
  assert.equal(f.now(), start + 90_000, 'after advance');
  f.advance(-30_000);
  assert.equal(f.now(), start + 60_000, 'after negative advance');

  const reset = 5_000.5;
  f.set(reset);
  assert.equal(f.now(), reset, 'after set');
});

// Go runs eight goroutines; JavaScript interleaves eight async tasks that
// yield between steps, so an advance computed from a stale reading would be
// lost the same way.
test('TestFakeIsSafeForConcurrentUse', async () => {
  const f = new FakeClock(0);
  await Promise.all(
    Array.from({ length: 8 }, async () => {
      for (let i = 0; i < 100; i++) {
        f.advance(1000);
        await Promise.resolve();
        f.now();
      }
    }),
  );
  assert.equal(f.now(), 800_000, 'an advance was lost');
});
