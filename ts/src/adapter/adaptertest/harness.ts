/**
 * What the adapter conformance suite and an adapter under test exchange (Go
 * hop.top/pact-go/adapter/adaptertest, harness.go and the options of suite.go).
 *
 * @module
 */
import type { RawRequest } from '../../core/binding/index.ts';
import type { Clock } from '../../core/clock.ts';
import type { RawJSON } from '../../core/values.ts';
import type { Adapter } from '../index.ts';

/**
 * Builds the adapter under test for one case. The suite calls it once per
 * case, so every case starts from the native state it declares and from
 * nothing else.
 *
 * A factory reads `env.state`, the case's `native_state` member, and builds
 * the adapter's native systems from it: the identity store, the enrollment
 * source, the claim sources, the policy and the installed checks. The common
 * cases in spec/v1.0/fixtures/adapters/_common state it in the neutral `common/1`
 * model that the fixture README defines, and an adapter's own cases state it
 * in whatever shape its factory reads. The suite never looks inside.
 *
 * A factory that cannot build the adapter rejects, or returns a promise that
 * rejects; the case fails with that error. One that throws instead fails the
 * case as broken, as a panic does in Go. The Go factory's `testing.TB`
 * argument, for cleanup only, has no counterpart: the suite imports no test
 * framework.
 */
export type Factory = (env: Env) => Subject | Promise<Subject>;

/** What the suite hands a {@link Factory}. */
export interface Env {
  /** The `native_state` member of the case file, verbatim. */
  readonly state: RawJSON;
  /**
   * The adapter's only source of the current time. The suite holds it at the
   * case's now, so an adapter that reads the wall clock instead is caught by
   * every time assertion.
   */
  readonly clock: Clock;
  /**
   * Records the calls the adapter makes into native execution hooks. An
   * adapter wired to a downstream executor calls `hooks.fire('execute')`
   * where it would run the protected operation; cases then assert, with
   * `expect.must_not_call`, that a denial ran nothing.
   */
  readonly hooks: Hooks;
}

/**
 * The adapter under test with the few hooks that depend on the native
 * mechanism and that the suite cannot supply itself.
 */
export interface Subject {
  /** The adapter under test. */
  readonly adapter: Adapter;
  /**
   * Marks `req` as having reached the adapter through the enforcement point,
   * in the way the adapter's mechanism recognizes, and returns the request to
   * use from then on. A request the suite does not pass through it is a
   * direct request that bypassed the enforcement point; the adapter must not
   * authenticate it. Required.
   */
  readonly arrive: (req: RawRequest) => RawRequest;
  /**
   * Returns `req` with the credential of the native identity that `ref`
   * names in the case's native state, in the form the adapter's mechanism
   * reads: a header, a cookie, a peer certificate. It throws when `ref` is
   * unknown. Required by cases that set `request.native_state_ref`.
   */
  readonly credential?: (req: RawRequest, ref: string) => RawRequest;
  /**
   * When set, verifies the signature of a compact JWS that `recordOutcome`
   * returned, and throws when it does not verify. Optional.
   */
  readonly verifyOutcome?: (jws: string) => void;
}

/** Records the native hooks an adapter fired during a case. */
export class Hooks {
  readonly #fired: string[] = [];

  /** Records that the hook named `name` ran. */
  fire(name: string): void {
    this.#fired.push(name);
  }

  /** The names of the hooks that ran, in order: a new array. */
  fired(): string[] {
    return [...this.#fired];
  }
}

/**
 * A fixture tree rooted at spec/v1.0/fixtures, with `/`-separated paths relative
 * to that root.
 */
export interface FixtureTree {
  /** The bytes of the file at `path`. */
  read(path: string): Uint8Array;
  /** The names of the regular files directly in the directory `dir`. */
  list(dir: string): readonly string[];
}

/** How the suite runs. */
export interface Options {
  /**
   * The fixture tree. When absent, the suite uses the spec/v1.0/fixtures
   * directory of the source repository.
   */
  readonly fixtures?: FixtureTree;
  /**
   * Names the adapter's own cases, the case files directly in
   * adapters/<adapter> of the fixture tree, to run after the common cases.
   * Absent or `''` runs the common cases only.
   */
  readonly adapter?: string;
  /**
   * Says that the adapter's profile supports workloads shared by several
   * agents (spec/v1.0/profiles/identity-mapping.md, IM-19). The suite then runs
   * the cases whose `workloads` member is `shared` instead of those whose
   * member is `dedicated`. False, the default of every profile, runs the
   * dedicated cases. Cases without the member run either way.
   */
  readonly sharedWorkloads?: boolean;
  /**
   * Maps the id of a common case to the adapter's own case that replaces it:
   * a common authenticate_native or authorize_native case, replaced by a case
   * of adapters/<adapter> for the same function with the same outcome class,
   * with a reason. A replaced case is still run and must fail.
   */
  readonly replaced?: Readonly<Record<string, Replacement>>;
}

/**
 * The adapter's own case that stands in for a common case the adapter's
 * mechanism cannot realize. Draft 22.2 lets a conformance claim replace a
 * required test by one that is no weaker than the original intent.
 */
export interface Replacement {
  /** The id of the adapter's own case. */
  readonly by: string;
  /** Why the mechanism cannot realize the common case. */
  readonly reason: string;
}
