/**
 * The in-memory reference adapter (Go package hop.top/pact-go/adapters/memory):
 * the seven functions of draft 17.1 over native stores that live in process
 * memory and are built from a document, with no network and no files.
 *
 * It is the baseline of the conformance suite of `adapter/adaptertest`. It
 * passes every common case, and it is written from the draft and the
 * invariants the draft cites, not from the cases.
 *
 * ## Native state
 *
 * An adapter is built from a {@link State}, the neutral common/1 model that
 * the common cases state their native state in: the gateway's trusted
 * configuration, the installed operation mappings, an identity store of
 * bearer tokens, an enrollment source, approved claim paths and their values,
 * installed checks with their verdicts, an authorization policy, and the
 * signer of outcome reports. {@link parseState} reads it strictly from JSON
 * and {@link newMemoryAdapter} builds the adapter over it. The clock passed
 * in is the adapter's only source of the current time.
 *
 * ## What it does
 *
 * - authenticateNative: the bearer token of the Authorization header
 *   decides. Identity headers such as X-User are ignored, and a request that
 *   did not pass through the enforcement point, marked with {@link arrive},
 *   is refused.
 * - resolveAgentBinding: looked up by realm, workload and agent ID together.
 *   A revoked or compromised binding is returned as that status, with the
 *   agent, operator and holder key of the record (identity mapping IM-11);
 *   an agent with no record on the workload is UNKNOWN, with
 *   `enrolledElsewhere` set when it has a record on another workload of the
 *   realm. By default a workload serves one agent, and one with more than one
 *   enrollment in force is a configuration error, UNSUPPORTED_REQUIREMENT
 *   (IM-19); {@link withSharedWorkloads} builds the adapter of a profile
 *   whose workloads several agents may share.
 * - mapOperation: the baseline HTTP mapping of draft 10.2, by the binding
 *   module. A request it refuses is an INVALID_MESSAGE error.
 * - readNativeClaim: only approved paths, per realm and principal, with the
 *   times the source gives and never the time of the read; a fact of a
 *   resource or a task only for the resources of the operation and the task
 *   of the intent.
 * - checkContext: an exact match on the check id, anything else UNKNOWN with
 *   UNSUPPORTED_REQUIREMENT; records scoped to a principal or an agent apply
 *   only to that principal and that agent's binding, and an installed check
 *   no record applies to is FAIL with APPROVAL_SCOPE_MISMATCH. Freshness
 *   limits are evaluated with the freshness module, the baseline skew and a
 *   guard against re-stamping that starts with the sightings of the state; a
 *   pinned revision that changed is REQUIREMENTS_CHANGED.
 * - authorizeNative: the policy decides for the original principal, a deny
 *   wins, and no rule is a deny, with the provenance of the rule that
 *   decided.
 * - recordOutcome: signs outcome reports with ES256 under a P-256 key made
 *   for the instance, declares no visibility for executions it does not
 *   observe, and removes credentials from free text and references.
 *
 * A source the state lists as unavailable is not read. The adapter has no
 * execution path, so it never fires the execution hook.
 *
 * @module
 */
import { generateKeyPairSync } from 'node:crypto';
import type { Env, Factory, Subject } from '../../adapter/adaptertest/harness.ts';
import type { Adapter } from '../../adapter/index.ts';
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
} from '../../adapter/types.ts';
import { Config as BindingConfig, type RawRequest } from '../../core/binding/index.ts';
import type { Clock } from '../../core/clock.ts';
import type { OperationContext } from '../../core/types.ts';
import type { RawJSON } from '../../core/values.ts';
import type { Core } from './core.ts';
import { newGuard } from './freshness.ts';
import { arrive, authenticate, credentialOf, resolveBinding } from './identity.ts';
import { authorize, checkContext, readClaim } from './native.ts';
import { bindingConfig, mapOperation } from './operation.ts';
import { recordOutcome, verifyOutcome } from './outcome.ts';
import { parseState } from './parse.ts';
import { type Mapping, State } from './state.ts';

export { CODE_APPROVAL_SCOPE_MISMATCH, CODE_REQUIREMENTS_CHANGED } from './freshness.ts';
export { arrive, arrived } from './identity.ts';
export { CheckRecord, ClaimRecord, POLICY_SOURCE_ID } from './native.ts';
export { parseState } from './parse.ts';
export {
  type CheckFreshness,
  type Enrollment,
  type Gateway,
  type Identity,
  type Mapping,
  MODEL,
  normalizeOrigin,
  type Obligation,
  type PolicyRule,
  type Realm,
  type Reporting,
  type Route,
  type Sighting,
  State,
} from './state.ts';

/** What an {@link Option} sets. */
export interface Settings {
  sharedWorkloads: boolean;
}

/** Configures a {@link MemoryAdapter}. */
export type Option = (s: Settings) => void;

/**
 * Makes the adapter that of a profile that supports workloads shared by
 * several agents (spec/v1.0/profiles/identity-mapping.md, IM-19):
 * resolveAgentBinding selects among the records of a workload by the agent
 * ID alone, however many of them are in force. Without it, the default of
 * every profile, a workload serves one agent, and a workload with more than
 * one enrollment in force is a configuration error.
 */
export function withSharedWorkloads(): Option {
  return (s) => {
    s.sharedWorkloads = true;
  };
}

// Runs f and turns what it throws into a rejection: the seven functions of
// the contract return promises.
function settle<T>(f: () => T): Promise<T> {
  try {
    return Promise.resolve(f());
  } catch (err) {
    return Promise.reject(err);
  }
}

/**
 * The in-memory reference adapter: it implements the seven functions of
 * draft 17.1 over a {@link State} and keeps nothing outside memory. It never
 * reads the wall clock; the clock it is built with is its only source of the
 * current time. After construction it only reads its state.
 */
export class MemoryAdapter implements Adapter {
  readonly #c: Core;

  /** An adapter over `st`, reading the current time from `clock`; see {@link newMemoryAdapter}. */
  constructor(st: State, clock: Clock, ...opts: Option[]) {
    if (clock === null || clock === undefined || typeof clock.now !== 'function') {
      throw new Error('memory: no clock');
    }
    try {
      State.validate(st);
    } catch (err) {
      throw new Error(`memory: state: ${(err as Error).message}`, { cause: err });
    }
    const settings: Settings = { sharedWorkloads: false };
    for (const o of opts) o(settings);
    const mappings = new Map<string, Mapping>();
    for (const m of st.mappings) {
      // mapOperation applies the baseline HTTP mapping under each installed
      // version; its configuration must be usable before any request.
      try {
        BindingConfig.validate(bindingConfig(st.gateway, m.version));
      } catch (err) {
        throw new Error(`memory: mapping ${JSON.stringify(m.version)}: ${(err as Error).message}`, {
          cause: err,
        });
      }
      mappings.set(m.version, m);
    }
    let key: Core['key'] = null;
    let publicKey: Core['publicKey'] = null;
    if (st.reporting !== null) {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      key = pair.privateKey;
      publicKey = pair.publicKey;
    }
    this.#c = Object.freeze({
      st,
      clock,
      mappings,
      shared: settings.sharedWorkloads,
      guard: newGuard(st.sightings),
      key,
      publicKey,
    });
  }

  /** The adapter's state (Go `Adapter.State`). The caller must not change it. */
  state(): State {
    return this.#c.st;
  }

  /** The descriptor of the memory mechanism. */
  describe(): Descriptor {
    return { protocol: 'memory', version: '1', mappingRevision: 'memory-map-1' };
  }

  /**
   * `req` with the bearer token of the identity named `ref`, unless it
   * already carries an Authorization header; throws for an unknown ref. It is
   * the credential hook of the suite's {@link Subject}.
   */
  credential(req: RawRequest, ref: string): RawRequest {
    return credentialOf(this.#c, req, ref);
  }

  /**
   * Verifies the ES256 signature of a compact JWS this adapter signed;
   * throws an `Error` when it does not verify.
   */
  verifyOutcome(jws: string): void {
    verifyOutcome(this.#c, jws);
  }

  authenticateNative(req: RawRequest, signal?: AbortSignal): Promise<Principal> {
    return settle(() => authenticate(this.#c, req, signal));
  }

  resolveAgentBinding(
    realm: Realm,
    workload: string,
    agent: string,
    signal?: AbortSignal,
  ): Promise<AgentBinding> {
    return settle(() => resolveBinding(this.#c, realm, workload, agent, signal));
  }

  mapOperation(
    req: RawRequest,
    p: Principal,
    mappingVersion: string,
    signal?: AbortSignal,
  ): Promise<OperationContext> {
    return settle(() => mapOperation(this.#c, req, p, mappingVersion, signal));
  }

  readNativeClaim(nativePath: string, c: ClaimContext, signal?: AbortSignal): Promise<NativeClaim> {
    return settle(() => readClaim(this.#c, nativePath, c, signal));
  }

  checkContext(checkId: string, input: CheckInput, signal?: AbortSignal): Promise<CheckOutcome> {
    return settle(() => checkContext(this.#c, checkId, input, signal));
  }

  authorizeNative(p: Principal, op: OperationContext, signal?: AbortSignal): Promise<Decision> {
    return settle(() => authorize(this.#c, p, op, signal));
  }

  recordOutcome(o: Observation, signal?: AbortSignal): Promise<Recorded> {
    return settle(() => recordOutcome(this.#c, o, signal));
  }
}

/** An adapter over `st` reading the current time from `clock` (Go `New`); it validates `st`. */
export function newMemoryAdapter(st: State, clock: Clock, ...opts: Option[]): MemoryAdapter {
  return new MemoryAdapter(st, clock, ...opts);
}

/** Parses a state document with {@link parseState} and builds the adapter (Go `FromJSON`). */
export function fromJSON(
  raw: Uint8Array | string | RawJSON,
  clock: Clock,
  ...opts: Option[]
): MemoryAdapter {
  const text = typeof raw === 'string' || raw instanceof Uint8Array ? raw : raw.text;
  return new MemoryAdapter(parseState(text), clock, ...opts);
}

/** The adapter with the hooks that the suite needs (Go `SubjectOf`). */
export function subjectOf(a: MemoryAdapter): Subject {
  return {
    adapter: a,
    arrive,
    credential: (req, ref) => a.credential(req, ref),
    verifyOutcome: (jws) => a.verifyOutcome(jws),
  };
}

/**
 * The adaptertest factory of the memory adapter built with `opts` (Go
 * `FactoryWith`). The suite runs the adapter built with
 * {@link withSharedWorkloads} with `sharedWorkloads` set in its options.
 * The factory rejects when the state does not build an adapter.
 */
export function factoryWith(...opts: Option[]): Factory {
  return async (env: Env) => subjectOf(fromJSON(env.state, env.clock, ...opts));
}

/**
 * The adaptertest factory of the memory adapter (Go `Factory`): it builds
 * the adapter from the common/1 native state of a case, with the clock of
 * the suite. Its workloads are dedicated, the default.
 */
export const factory: Factory = factoryWith();
