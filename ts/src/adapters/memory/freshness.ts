/**
 * The freshness rules of the installed checks of the memory adapter (Go
 * hop.top/pact-go/adapters/memory, freshness.go): age limits, the guard against
 * re-stamping, unavailable sources and pinned revisions.
 *
 * @module
 */
import { Code } from '../../adapter/errors.ts';
import { Evaluator, Monotonic, ReasonCode } from '../../adapter/freshness.ts';
import { type CheckOutcome, Verdict } from '../../adapter/types.ts';
import { BASELINE_SKEW_MS } from '../../core/clock.ts';
import { CheckStatus } from '../../core/enums.ts';
import { type Core, checkSourceTimes, sourceTime, unavailable } from './core.ts';
import type { CheckRecord, Sighting } from './state.ts';

/**
 * The reason code of a version-pinned check whose source reports another
 * revision than the pinned one: the contract is no longer active (draft
 * 13.4).
 */
export const CODE_REQUIREMENTS_CHANGED = 'REQUIREMENTS_CHANGED';

/**
 * The reason code of an approval-class check that is installed but whose
 * native state is for another agent or another principal than the call's
 * (draft 17.3.1: scope mismatch).
 */
export const CODE_APPROVAL_SCOPE_MISMATCH = 'APPROVAL_SCOPE_MISMATCH';

/**
 * The number of source records the guard against re-stamping records beyond
 * the sightings of the state. A guard that is full defers a record it has
 * not seen; it never evicts.
 */
const GUARD_CAPACITY = 4096;

/**
 * A guard against re-stamping that holds the sightings. Of two sightings of
 * one record the earlier is kept, as the guard keeps the lowest time it sees.
 */
export function newGuard(sightings: readonly Sighting[]): Monotonic {
  const g = new Monotonic(sightings.length + GUARD_CAPACITY);
  for (const s of sightings) {
    g.check({
      value: null,
      observedAt: sourceTime(s.observed_at),
      statusCheckedAt: null,
      sourceId: s.source_id,
      sourceRef: s.source_ref,
    });
  }
  return g;
}

/**
 * The outcome of the installed check c. The findings are taken in order, and
 * the native verdict of c is reported only when there is none:
 *
 * 1. the source of c cannot answer: UNKNOWN with DEPENDENCY_UNAVAILABLE;
 * 2. with freshness limits, the record's two times are evaluated against
 *    them by the rules of the freshness profile, with the baseline skew and
 *    the guard against re-stamping, and a result other than PASS is the
 *    outcome. A time ahead of the clock is not passed on. Without limits, a
 *    time the adapter cannot pass on defers the check, as it does a claim;
 * 3. a check pinned to a revision of its source fails with
 *    REQUIREMENTS_CHANGED when the source reports another one, or none.
 */
export function runCheck(core: Core, c: CheckRecord): CheckOutcome {
  const base = { sourceId: c.source_id, sourceRef: c.source_ref, observedAt: null };
  if (unavailable(core, c.source_id)) {
    return {
      ...base,
      sourceRef: '',
      result: Verdict.UNKNOWN,
      reasonCode: Code.DEPENDENCY_UNAVAILABLE,
    };
  }
  const observed = sourceTime(c.observed_at);
  const checked = sourceTime(c.status_checked_at);
  const f = c.freshness;
  if (f !== null) {
    const ev = new Evaluator({ skew: BASELINE_SKEW_MS, guard: core.guard });
    const [result, code] = ev.evaluate(
      {
        max_age_seconds: f.max_age_seconds as number,
        status_max_age_seconds: f.status_max_age_seconds as number,
      },
      {
        value: null,
        observedAt: observed,
        statusCheckedAt: checked,
        sourceId: c.source_id,
        sourceRef: c.source_ref,
      },
      core.clock.now(),
    );
    if (code === ReasonCode.CLOCK_AHEAD) return { ...base, result: Verdict.FAIL, reasonCode: code };
    if (result !== CheckStatus.PASS) {
      return { ...base, result: verdictOf(result), reasonCode: code, observedAt: observed };
    }
  } else {
    try {
      checkSourceTimes(core, observed, checked);
    } catch {
      return {
        ...base,
        sourceRef: '',
        result: Verdict.UNKNOWN,
        reasonCode: Code.DEPENDENCY_UNAVAILABLE,
      };
    }
  }
  if (c.pinned_revision !== '' && c.revision !== c.pinned_revision) {
    return {
      ...base,
      observedAt: observed,
      result: Verdict.FAIL,
      reasonCode: CODE_REQUIREMENTS_CHANGED,
    };
  }
  return { ...base, observedAt: observed, result: c.result as Verdict, reasonCode: c.reason_code };
}

// The verdict of the same name as a check status. Anything but PASS and FAIL
// established nothing, so it is UNKNOWN.
function verdictOf(s: CheckStatus): Verdict {
  if (s === CheckStatus.PASS) return Verdict.PASS;
  if (s === CheckStatus.FAIL) return Verdict.FAIL;
  return Verdict.UNKNOWN;
}
