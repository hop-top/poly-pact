/**
 * What the functions of the memory adapter share: its state, its clock, its
 * installed mappings, its guard against re-stamping and its signing key (Go
 * hop.top/pact-go/adapters/memory, the fields of Adapter and the helpers of
 * memory.go).
 *
 * @module
 */
import type { KeyObject } from 'node:crypto';
import { AdapterError } from '../../adapter/errors.ts';
import type { Monotonic } from '../../adapter/freshness.ts';
import type { Realm as AdapterRealm } from '../../adapter/types.ts';
import { BASELINE_SKEW_MS, type Clock } from '../../core/clock.ts';
import type { Mapping, State } from './state.ts';

/** The internals of one adapter. */
export interface Core {
  readonly st: State;
  readonly clock: Clock;
  readonly mappings: ReadonlyMap<string, Mapping>;
  /**
   * The observation time of every source record a bounded check consulted,
   * starting with the sightings of the state.
   */
  readonly guard: Monotonic;
  /** Whether a workload may serve several agents. */
  readonly shared: boolean;
  /** The ephemeral P-256 key of outcome reports; `null` without reporting. */
  readonly key: KeyObject | null;
  /** Its public half. */
  readonly publicKey: KeyObject | null;
}

/** The realm of the gateway the adapter serves. */
export function realmOf(c: Core): AdapterRealm {
  return { tenantId: c.st.gateway.tenant_id, environmentId: c.st.gateway.environment_id };
}

/**
 * Rejects with a dependency error when the call is already aborted: a call
 * that cannot be completed is not an answer.
 */
export function live(fn: string, signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw AdapterError.dependencyUnavailable(`memory: ${fn}`, { cause: signal.reason });
  }
}

/**
 * The instant of a Unix-seconds member of a source record, in milliseconds.
 * An absent member is no time: the source gives none, and the adapter does
 * not make one up.
 */
export function sourceTime(sec: number | null): number | null {
  return sec === null ? null : sec * 1000;
}

/**
 * Refuses times the adapter cannot pass on. No source observation or
 * status-check time may be later than now plus the skew (draft A.2): such a
 * time did not happen yet, and the source is not trustworthy at this moment,
 * so the answer is that the dependency cannot be relied on, which defers the
 * decision (freshness profile, section 3.2).
 */
export function checkSourceTimes(c: Core, observed: number | null, checked: number | null): void {
  const limit = c.clock.now() + BASELINE_SKEW_MS;
  if (observed !== null && observed > limit) {
    throw AdapterError.dependencyUnavailable(
      'memory: the source reports an observation later than now plus the skew',
    );
  }
  if (checked !== null && checked > limit) {
    throw AdapterError.dependencyUnavailable(
      'memory: the source reports a status check later than now plus the skew',
    );
  }
}

/** Whether the source named id cannot currently answer. */
export function unavailable(c: Core, id: string): boolean {
  return c.st.unavailable_sources.includes(id);
}

/**
 * The error of a read from a source that cannot answer. The adapter keeps no
 * copy to fall back on, so the answer is a deferral (draft 18).
 */
export function outage(fn: string, source: string): AdapterError {
  return AdapterError.dependencyUnavailable(
    `memory: ${fn}: source ${JSON.stringify(source)} cannot answer`,
  );
}
