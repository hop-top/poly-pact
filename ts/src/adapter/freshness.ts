/**
 * The two age limits of a field rule, evaluated against a native claim, and
 * the guard against re-stamping (Go package hop.top/pact-go/adapter/freshness;
 * PACT draft sections 8.3, 9.2, 17.2 and 18).
 *
 * A field rule bounds two different ages (section 9.2):
 *
 * - `max_age_seconds` bounds the original source observation,
 *   `NativeClaim.observedAt`. It is the time the source gave, never an
 *   intermediary's receipt time;
 * - `status_max_age_seconds` bounds the last confirmation that the value is
 *   still in force, `NativeClaim.statusCheckedAt`. Zero requires a check made
 *   in this evaluation.
 *
 * The module is one function, {@link evaluate}; one class that carries its
 * parameters, {@link Evaluator}; and the guard against re-stamping,
 * {@link Monotonic}. `evaluate` uses the baseline clock skew. An Evaluator
 * tightens it, says when the evaluation began, and attaches a Monotonic
 * guard. The freshness profile (spec/v1.0/profiles/freshness.md) defines the
 * vocabulary, the source classes, and the check points these rules serve.
 *
 * ## Rules
 *
 * With `now` the instant of the evaluation, `skew` the clock skew allowance
 * (at most `BASELINE_SKEW_MS`, section 7.5), and each limit read as whole
 * seconds:
 *
 * - A time later than now+skew is a source clock that runs ahead. The claim
 *   fails with `CLOCK_AHEAD` (Appendix A.2: no observation or status-check
 *   time may be later than now+skew). This outranks every finding but an
 *   invalid limit, because a time that cannot be true says nothing about
 *   age.
 * - A source that gives no time cannot establish freshness (section 17.2),
 *   and unknown status is not evidence of validity (section 8.3). The result
 *   is UNKNOWN with `UNSUPPORTED_REQUIREMENT`. A time before the epoch counts
 *   as no time, because it has no wire form.
 * - An age above its limit fails with `STALE_EVIDENCE`. The age may equal
 *   the limit: now-observedAt <= max_age_seconds, the way section 7.5
 *   phrases its own bounds. The comparison is exact, to the millisecond, and
 *   is not rounded in the claim's favour.
 * - A limit of zero means the time must not precede the start of this
 *   evaluation ({@link Evaluator.start}). The draft defines zero only for
 *   `status_max_age_seconds` (section 9.2); this module reads
 *   `max_age_seconds` = 0 the same way, which fails closed.
 * - A limit outside 0..2^53-1 cannot come from a valid contract and no
 *   source can satisfy it. The result is UNKNOWN with
 *   `UNSUPPORTED_REQUIREMENT`.
 * - With a {@link Monotonic} guard, a later `observedAt` for a source record
 *   already seen is a re-stamp and fails with `RESTAMPED`, which is treated
 *   as `STALE_EVIDENCE`.
 *
 * A demonstrable failure outranks a missing time: a claim already known to
 * be stale is FAIL, not UNKNOWN. After an invalid limit, the order of the
 * findings is `CLOCK_AHEAD`, `RESTAMPED`, `STALE_EVIDENCE`, then the UNKNOWN
 * findings: no usable time (`UNSUPPORTED_REQUIREMENT`) and a guard that
 * cannot record (`DEPENDENCY_UNAVAILABLE`).
 *
 * ## Calling it
 *
 * The evaluator does not read a clock. The caller passes `now`, Unix
 * milliseconds, normally from a `Clock`, so a test drives it with a
 * `FakeClock`. To honour a zero limit the caller also gives the instant the
 * evaluation began, taken before any source was read for it. Without a
 * start, the instant `now` stands in for it.
 *
 * The evaluation reads only the two age limits. A self rule has none
 * (Appendix A.2) and is not evaluated here.
 *
 * @module
 */
import { BASELINE_SKEW_MS } from '../core/clock.ts';
import { CheckStatus } from '../core/enums.ts';
import type { FieldRule } from '../core/types.ts';
import { Code, type NativeClaim } from './index.ts';

/**
 * The outcome of a freshness check, the type of `CheckResult.result`.
 * {@link evaluate} returns PASS, FAIL or UNKNOWN; {@link Monotonic.check}
 * can also return NOT_APPLICABLE.
 */
export type Result = CheckStatus;

/** The values of {@link ReasonCode}. */
const REASON_CODE = {
  /** Every age is within its limit (section 17.3.1). */
  SATISFIED: 'REQUIREMENT_SATISFIED',
  /** An age is above its limit (section 13.4). */
  STALE_EVIDENCE: 'STALE_EVIDENCE',
  /**
   * A source time is later than now plus the clock skew, so the source clock
   * runs ahead of the validator's.
   */
  CLOCK_AHEAD: 'CLOCK_AHEAD',
  /**
   * A source record came back with a later observation time than the first
   * one seen for it. It is treated as `STALE_EVIDENCE`.
   */
  RESTAMPED: 'RESTAMPED',
  /**
   * The source gives no usable time, or the rule's limit is not a valid one,
   * so the demanded freshness cannot be established (sections 13.4 and
   * 17.2). The result is UNKNOWN.
   */
  UNSUPPORTED_REQUIREMENT: Code.UNSUPPORTED_REQUIREMENT,
  /**
   * The guard cannot record the observation, so the check cannot be
   * completed now (sections 13.4 and 18). The result is UNKNOWN.
   */
  DEPENDENCY_UNAVAILABLE: Code.DEPENDENCY_UNAVAILABLE,
} as const;

/** A stable reason code for a freshness result, the value of `CheckResult.reason_code`. */
export type ReasonCode = (typeof REASON_CODE)[keyof typeof REASON_CODE];

/** The reason codes of a freshness check, and the handling they share. */
export const ReasonCode = Object.freeze({
  ...REASON_CODE,
  /**
   * The code whose handling `c` shares (Go `ReasonCode.TreatedAs`):
   * `RESTAMPED` is treated as `STALE_EVIDENCE`, an INADMISSIBLE check with
   * the same transport error. Any other code is its own.
   */
  treatedAs(c: ReasonCode): ReasonCode {
    return c === REASON_CODE.RESTAMPED ? REASON_CODE.STALE_EVIDENCE : c;
  },
});

/** The age limits an evaluation reads from a field rule. */
export type AgeLimits = Pick<FieldRule, 'max_age_seconds' | 'status_max_age_seconds'>;

/** The parameters of an {@link Evaluator}; every member is optional. */
export interface EvaluatorInit {
  readonly skew?: number;
  readonly start?: number | null;
  readonly guard?: Monotonic | null;
}

/**
 * The parameters of a freshness evaluation. `new Evaluator()` is the Go zero
 * value: no skew allowance, an evaluation that began at `now`, and no guard.
 */
export class Evaluator {
  /**
   * The clock skew allowance in milliseconds (section 7.5). A value above
   * `BASELINE_SKEW_MS` counts as the baseline, and a negative one or one that
   * is not a number as zero, so the evaluator is never more lenient than the
   * baseline. {@link evaluate} uses the baseline.
   */
  readonly skew: number;
  /**
   * The instant this evaluation began, taken before any source was read for
   * it. A limit of zero seconds requires the time not to precede it. `null`
   * means the instant `now` of the call.
   */
  readonly start: number | null;
  /**
   * When set, records the observation time of each source record and
   * reports a later one as `RESTAMPED`. One guard serves every evaluation
   * that must see the same records.
   */
  readonly guard: Monotonic | null;

  constructor(init: EvaluatorInit = {}) {
    this.skew = init.skew ?? 0;
    this.start = init.start ?? null;
    this.guard = init.guard ?? null;
    Object.freeze(this);
  }

  /**
   * Checks `claim` against `rule.max_age_seconds` and
   * `rule.status_max_age_seconds` at `now`. See the module documentation for
   * the rules and their order.
   */
  evaluate(rule: AgeLimits, claim: NativeClaim, now: number): readonly [Result, ReasonCode] {
    if (!validLimit(rule.max_age_seconds) || !validLimit(rule.status_max_age_seconds)) {
      return [CheckStatus.UNKNOWN, REASON_CODE.UNSUPPORTED_REQUIREMENT];
    }
    const skew = Number.isNaN(this.skew) ? 0 : Math.min(Math.max(this.skew, 0), BASELINE_SKEW_MS);
    const start = this.start ?? now;
    const observed = usable(claim.observedAt) ? claim.observedAt : null;
    const checked = usable(claim.statusCheckedAt) ? claim.statusCheckedAt : null;

    // A source clock ahead outranks everything, and an implausible time is
    // never recorded as the baseline of a source record.
    const latest = now + skew;
    if ((observed !== null && observed > latest) || (checked !== null && checked > latest)) {
      return [CheckStatus.FAIL, REASON_CODE.CLOCK_AHEAD];
    }

    const guard = this.guard === null ? CheckStatus.NOT_APPLICABLE : this.guard.check(claim)[0];
    if (guard === CheckStatus.FAIL) return [CheckStatus.FAIL, REASON_CODE.RESTAMPED];

    if (
      (observed !== null && tooOld(observed, now, start, rule.max_age_seconds)) ||
      (checked !== null && tooOld(checked, now, start, rule.status_max_age_seconds))
    ) {
      return [CheckStatus.FAIL, REASON_CODE.STALE_EVIDENCE];
    }

    if (observed === null || checked === null) {
      return [CheckStatus.UNKNOWN, REASON_CODE.UNSUPPORTED_REQUIREMENT];
    }
    if (guard === CheckStatus.UNKNOWN) {
      return [CheckStatus.UNKNOWN, REASON_CODE.DEPENDENCY_UNAVAILABLE];
    }
    return [CheckStatus.PASS, REASON_CODE.SATISFIED];
  }
}

/**
 * Checks `claim` against the age limits of `rule` at `now`, with the
 * baseline clock skew, no guard, and an evaluation that began at `now`. It is
 * {@link Evaluator.evaluate} for the common case.
 */
export function evaluate(
  rule: AgeLimits,
  claim: NativeClaim,
  now: number,
): readonly [Result, ReasonCode] {
  return new Evaluator({ skew: BASELINE_SKEW_MS }).evaluate(rule, claim, now);
}

/**
 * The guard against re-stamping. The observation time of a source record
 * never changes (draft section 8.3): an adapter or an issuer that refreshes a
 * stale upstream fact must not give it a new time, and a new `observedAt`
 * requires a new `sourceRef`. The guard remembers the first observation time
 * it sees for each (`sourceId`, `sourceRef`) and reports a later one as
 * `RESTAMPED`.
 *
 * The guard compares whole seconds, which is all the wire carries. It keeps
 * the lowest time seen for a record, so the baseline never moves up: a
 * re-stamped time does not become the new baseline, and an earlier time seen
 * later lowers it. A claim seen once, however stale, still sets the
 * baseline, which is what stops a refused fact from coming back with a fresh
 * time.
 *
 * The store is bounded. At the limit it refuses a record it has not seen and
 * returns UNKNOWN with `DEPENDENCY_UNAVAILABLE`, the deferral sections 7.5
 * and 18 require of a full state store, and it never evicts.
 * {@link Monotonic.forget} ends the life of a record the source has retired.
 * The store is in memory and local to one process: a deployment with several
 * replicas that must catch a re-stamp across replicas shares the store
 * between them, as it shares replay state (section 7.5), or accepts that
 * each replica guards only what it has seen itself.
 */
export class Monotonic {
  readonly #limit: number;
  // The lowest whole second seen for each record, keyed by the JSON array
  // [sourceId, sourceRef]: a reference is scoped to its source.
  readonly #seen = new Map<string, number>();

  /**
   * A guard that records at most `limit` source records (Go
   * `NewMonotonic`). A limit below 1 records none, so every claim with a
   * reference is deferred.
   */
  constructor(limit: number) {
    this.#limit = limit;
  }

  /**
   * Records the observation time of `claim` for its source record and
   * reports whether it contradicts an earlier one: FAIL with `RESTAMPED`
   * when the record was seen with an earlier time; UNKNOWN with
   * `DEPENDENCY_UNAVAILABLE` when the record is new and the store is full;
   * PASS with `REQUIREMENT_SATISFIED` otherwise; and NOT_APPLICABLE with the
   * empty reason code when the claim has no `sourceRef` or no usable
   * `observedAt`, so that there is nothing to compare and no check took
   * place. A caller does not record NOT_APPLICABLE as a pass.
   */
  check(claim: NativeClaim): readonly [Result, ReasonCode | ''] {
    if (claim.sourceRef === '' || !usable(claim.observedAt)) {
      return [CheckStatus.NOT_APPLICABLE, ''];
    }
    const key = recordKey(claim.sourceId, claim.sourceRef);
    const sec = Math.floor(claim.observedAt / 1000);
    const first = this.#seen.get(key);
    // Written so that a limit that is not a number, like one below 1, records
    // nothing.
    if (first === undefined && !(this.#seen.size < this.#limit)) {
      return [CheckStatus.UNKNOWN, REASON_CODE.DEPENDENCY_UNAVAILABLE];
    }
    if (first !== undefined && sec > first) return [CheckStatus.FAIL, REASON_CODE.RESTAMPED];
    this.#seen.set(key, sec);
    return [CheckStatus.PASS, REASON_CODE.SATISFIED];
  }

  /**
   * Drops the record of (`sourceId`, `sourceRef`), which ends its guard: a
   * later sighting is a first one. Call it when the source retires the
   * record, such as a token that has expired. It does nothing for a record
   * never seen.
   */
  forget(sourceId: string, sourceRef: string): void {
    this.#seen.delete(recordKey(sourceId, sourceRef));
  }

  /** The number of source records the guard holds. */
  len(): number {
    return this.#seen.size;
  }
}

function recordKey(sourceId: string, sourceRef: string): string {
  return JSON.stringify([sourceId, sourceRef]);
}

// Reports whether n is a limit a valid contract can carry: an integer in the
// core range 0..2^53-1 (draft section 7.1).
function validLimit(n: number): boolean {
  return Number.isSafeInteger(n) && n >= 0;
}

// Reports whether t is a time a source gave and the wire can carry: not null,
// which means none, not before the epoch, and a number.
function usable(t: number | null): t is number {
  return typeof t === 'number' && t >= 0;
}

// Reports whether t is older than limit seconds at now. A limit of zero asks
// for a time not before start. A positive limit is compared as whole seconds
// plus the millisecond remainder, so that a limit as large as 2^53-1 seconds
// is never scaled to milliseconds and a fractional now is not rounded.
function tooOld(t: number, now: number, start: number, limit: number): boolean {
  if (limit === 0) return t < start;
  const nowSec = Math.floor(now / 1000);
  const tSec = Math.floor(t / 1000);
  const whole = nowSec - tSec;
  if (whole !== limit) return whole > limit;
  return now - nowSec * 1000 > t - tSec * 1000;
}
