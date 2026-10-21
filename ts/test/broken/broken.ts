/**
 * A deliberately wrong adapter (Go hop.top/pact-go/adapters/internal/broken,
 * broken.go): the memory adapter with switchable defects, each a violation of
 * draft 17.1 and of the invariants it cites that one common conformance case
 * exists to catch.
 *
 * The conformance suite is only evidence if it can fail. This module is the
 * proof: its test runs the suite against the adapter with each defect on and
 * requires the cases the defect targets to fail, against the adapter with all
 * defects on and requires every case to fail, and against the adapter with
 * none and requires every case to pass. A case that no defect targets fails a
 * test of its own, so a new case cannot land without a mutant that it catches.
 *
 * It lives in the test tree and is never published. Do not use it as an
 * example of anything.
 *
 * @module
 */
import type { Env, Factory, Hooks, Subject } from '../../src/adapter/adaptertest/index.ts';
import type { Adapter as Contract } from '../../src/adapter/index.ts';
import type {
  AgentBinding,
  CheckInput,
  CheckOutcome,
  ClaimContext,
  Decision,
  Descriptor,
  NativeClaim,
  Observation,
  Principal,
  Realm,
  Recorded,
} from '../../src/adapter/types.ts';
import {
  arrive,
  MemoryAdapter,
  parseState,
  type State,
  withSharedWorkloads,
} from '../../src/adapters/memory/index.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import type { Clock } from '../../src/core/clock.ts';
import type { OperationContext } from '../../src/core/types.ts';
import { CATALOGUE } from './catalogue.ts';
import { Defect } from './defects.ts';
import { freshnessState } from './freshness.ts';
import { authenticate, resolveBinding } from './identity.ts';
import { authorize, checkContext, readClaim } from './native.ts';
import { mapOperation } from './operation.ts';
import { LeakySigner, recordOutcome } from './record.ts';

/** The memory adapter with the defects that are switched on. */
export class Adapter implements Contract {
  /** The memory adapter the defects wrap. */
  readonly base: MemoryAdapter;
  /**
   * Whether the adapter's workloads may be shared by several agents, as for
   * `withSharedWorkloads`.
   */
  readonly shared: boolean;
  /** The defects that are on. */
  readonly on: ReadonlySet<Defect>;
  readonly clock: Clock;
  readonly hooks: Hooks;
  /**
   * A memory adapter with execution visibility, whose reports stand in for
   * the success that ASSUME_EXECUTION_SUCCESS invents; `null` without
   * reporting.
   */
  readonly executing: MemoryAdapter | null;
  /** Signs reports with the unredacted text of the observation; `null` without reporting. */
  readonly leaky: LeakySigner | null;

  /**
   * The memory adapter over `st` with `defects` switched on, with workloads
   * that several agents may share when `shared` is true and dedicated ones
   * otherwise (Go `New`). `hooks` receives the execution hook calls of the
   * defects that make them.
   */
  constructor(st: State, clock: Clock, hooks: Hooks, shared: boolean, ...defects: Defect[]) {
    const opts =
      shared || defects.includes(Defect.SELECT_DESPITE_DEDICATED) ? [withSharedWorkloads()] : [];
    this.base = new MemoryAdapter(freshnessState(st, defects), clock, ...opts);
    this.shared = shared;
    this.on = new Set(defects);
    this.clock = clock;
    this.hooks = hooks;
    this.executing = null;
    this.leaky = null;
    if (st.reporting !== null) {
      this.executing = new MemoryAdapter({ ...st, visibility: 'execution' }, clock, ...opts);
      this.leaky = new LeakySigner(st);
    }
  }

  /** Whether the defect `d` is on. */
  has(d: Defect): boolean {
    return this.on.has(d);
  }

  /** The state of the memory adapter. */
  state(): State {
    return this.base.state();
  }

  /** The current time, in milliseconds. */
  now(): number {
    return this.clock.now();
  }

  /** Records that the native hook `name` ran. */
  fire(name: string): void {
    this.hooks.fire(name);
  }

  /** A descriptor that says what this is. */
  describe(): Descriptor {
    return { protocol: 'broken', version: '0', mappingRevision: 'broken-map-0' };
  }

  /** The credential hook of the memory adapter. */
  credential(req: RawRequest, ref: string): RawRequest {
    return this.base.credential(req, ref);
  }

  /**
   * Verifies a report signed by the adapter, by the adapter that stands in
   * for a visible execution, or by the leaky signer; throws the error of the
   * adapter's own verification when none verifies it.
   */
  verifyOutcome(jws: string): void {
    try {
      this.base.verifyOutcome(jws);
    } catch (err) {
      const { executing, leaky } = this;
      if (executing !== null && verifies(() => executing.verifyOutcome(jws))) return;
      if (leaky !== null && verifies(() => leaky.verify(jws))) return;
      throw err;
    }
  }

  authenticateNative(req: RawRequest, signal?: AbortSignal): Promise<Principal> {
    return authenticate(this, req, signal);
  }

  resolveAgentBinding(
    realm: Realm,
    workload: string,
    agent: string,
    signal?: AbortSignal,
  ): Promise<AgentBinding> {
    return resolveBinding(this, realm, workload, agent, signal);
  }

  mapOperation(
    req: RawRequest,
    p: Principal,
    mappingVersion: string,
    signal?: AbortSignal,
  ): Promise<OperationContext> {
    return mapOperation(this, req, p, mappingVersion, signal);
  }

  readNativeClaim(
    nativePath: string,
    cc: ClaimContext,
    signal?: AbortSignal,
  ): Promise<NativeClaim> {
    return readClaim(this, nativePath, cc, signal);
  }

  checkContext(checkId: string, input: CheckInput, signal?: AbortSignal): Promise<CheckOutcome> {
    return checkContext(this, checkId, input, signal);
  }

  authorizeNative(p: Principal, op: OperationContext, signal?: AbortSignal): Promise<Decision> {
    return authorize(this, p, op, signal);
  }

  recordOutcome(o: Observation, signal?: AbortSignal): Promise<Recorded> {
    return recordOutcome(this, o, signal);
  }
}

// Whether verify returns without throwing.
function verifies(verify: () => void): boolean {
  try {
    verify();
    return true;
  } catch {
    return false;
  }
}

function factoryOf(shared: boolean, defects: readonly Defect[]): Factory {
  return async (env: Env): Promise<Subject> => {
    const b = new Adapter(parseState(env.state.text), env.clock, env.hooks, shared, ...defects);
    return {
      adapter: b,
      arrive,
      credential: (req, ref) => b.credential(req, ref),
      verifyOutcome: (jws) => b.verifyOutcome(jws),
    };
  };
}

/**
 * An adaptertest factory for the adapter with `defects` on and dedicated
 * workloads, the default (Go `Factory`).
 */
export function factory(...defects: Defect[]): Factory {
  return factoryOf(false, defects);
}

/**
 * {@link factory} for the adapter whose workloads several agents may share
 * (Go `SharedFactory`). The suite runs it with `sharedWorkloads` set.
 */
export function sharedFactory(...defects: Defect[]): Factory {
  return factoryOf(true, defects);
}

/** Every defect of the catalogue, in catalogue order (Go `Defects`). */
export function defects(): Defect[] {
  return CATALOGUE.map((s) => s.defect);
}
