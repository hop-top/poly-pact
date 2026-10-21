/**
 * The freshness defects of the broken adapter (Go
 * hop.top/pact-go/adapters/internal/broken, freshness.go): limits, pins,
 * sightings or outages the adapter ignores, and times it misjudges.
 *
 * @module
 */
import { Code } from '../../src/adapter/errors.ts';
import { ReasonCode } from '../../src/adapter/freshness.ts';
import { BindingStatus, type CheckOutcome, Verdict } from '../../src/adapter/types.ts';
import type { Enrollment, State } from '../../src/adapters/memory/index.ts';
import { Artifact, maxLifetime } from '../../src/core/clock.ts';
import type { Adapter } from './broken.ts';
import { Defect } from './defects.ts';

/**
 * `st` as the adapter sees it with the defects that change what it knows:
 * limits, pins, sightings or outages it ignores.
 */
export function freshnessState(st: State, defects: readonly Defect[]): State {
  const on = (d: Defect): boolean => defects.includes(d);
  let out = st;
  if (on(Defect.IGNORE_CHECK_LIMITS) || on(Defect.IGNORE_PINNED_REVISION)) {
    out = {
      ...out,
      checks: out.checks.map((c) => ({
        ...c,
        freshness: on(Defect.IGNORE_CHECK_LIMITS) ? null : c.freshness,
        pinned_revision: on(Defect.IGNORE_PINNED_REVISION) ? '' : c.pinned_revision,
      })),
    };
  }
  if (on(Defect.FORGET_SIGHTINGS)) out = { ...out, sightings: [] };
  if (on(Defect.READ_THROUGH_OUTAGE)) out = { ...out, unavailable_sources: [] };
  return out;
}

/**
 * The outcome of the check `checkId` with the defects that misjudge the times
 * of the record it consults.
 */
export function checkFreshness(b: Adapter, checkId: string, out: CheckOutcome): CheckOutcome {
  if (b.has(Defect.DEFER_CLOCK_AHEAD) && out.reasonCode === ReasonCode.CLOCK_AHEAD) {
    return {
      result: Verdict.UNKNOWN,
      reasonCode: Code.DEPENDENCY_UNAVAILABLE,
      sourceId: out.sourceId,
      sourceRef: '',
      observedAt: null,
    };
  }
  const rec = b.state().checks.find((c) => c.id === checkId);
  if (out.result !== Verdict.PASS || rec === undefined || rec.freshness === null) return out;
  const f = rec.freshness;
  const now = Math.floor(b.now() / 1000);
  const ahead = (t: number | null): boolean => t !== null && t > now;
  const atLimit = (t: number | null, limit: number | null): boolean =>
    t !== null && now - t === limit;
  if (b.has(Defect.NO_SKEW_ALLOWANCE) && (ahead(rec.observed_at) || ahead(rec.status_checked_at))) {
    return {
      result: Verdict.FAIL,
      reasonCode: ReasonCode.CLOCK_AHEAD,
      sourceId: out.sourceId,
      sourceRef: out.sourceRef,
      observedAt: null,
    };
  }
  if (
    b.has(Defect.STALE_AT_LIMIT) &&
    (atLimit(rec.observed_at, f.max_age_seconds) ||
      atLimit(rec.status_checked_at, f.status_max_age_seconds))
  ) {
    return { ...out, result: Verdict.FAIL, reasonCode: ReasonCode.STALE_EVIDENCE };
  }
  return out;
}

/**
 * Whether the source holds `e` as revoked or compromised by a status it
 * confirmed less than a contract lifetime ago: the change a status cached at
 * the contract's issuance would not show.
 */
export function revokedWithinContract(b: Adapter, e: Enrollment): boolean {
  if (e.status !== BindingStatus.REVOKED && e.status !== BindingStatus.COMPROMISED) return false;
  if (e.status_checked_at === null) return false;
  const age = b.now() - e.status_checked_at * 1000;
  return age >= 0 && age < maxLifetime(Artifact.CONTRACT);
}
