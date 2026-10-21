// Shared pieces of the ported go/adapter/freshness tests.

import type { AgeLimits, ReasonCode, Result } from '../../src/adapter/freshness.ts';
import { CheckStatus } from '../../src/core/enums.ts';

/**
 * The instant every table measures against, in seconds: the iat of the
 * worked example in Appendix B of the draft.
 */
export const base = 1_792_080_000;

/** The instant `sec` seconds and `ms` milliseconds after the epoch, in ms. */
export function at(sec: number, ms = 0): number {
  return sec * 1000 + ms;
}

/**
 * An evidence or native field rule's age limits. The worked contract of
 * Appendix B.4 uses max_age_seconds 30 and status_max_age_seconds 0.
 */
export function rule(maxAge: number, statusMaxAge: number): AgeLimits {
  return { max_age_seconds: maxAge, status_max_age_seconds: statusMaxAge };
}

/** The expected return of an evaluation. */
export type Outcome = readonly [Result, ReasonCode];

export const pass: Outcome = [CheckStatus.PASS, 'REQUIREMENT_SATISFIED'];
export const stale: Outcome = [CheckStatus.FAIL, 'STALE_EVIDENCE'];
export const ahead: Outcome = [CheckStatus.FAIL, 'CLOCK_AHEAD'];
export const noTime: Outcome = [CheckStatus.UNKNOWN, 'UNSUPPORTED_REQUIREMENT'];
export const badLimit: Outcome = [CheckStatus.UNKNOWN, 'UNSUPPORTED_REQUIREMENT'];
