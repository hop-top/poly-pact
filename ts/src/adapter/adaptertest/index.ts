/**
 * Adapter conformance suite (Go package hop.top/pact-go/adapter/adaptertest):
 * the case model, frozen with the adapter contract, what the suite and an
 * adapter under test exchange, the case loader, and the two entry points.
 *
 * An adapter author writes a {@link Factory} and one `node:test` test that
 * awaits `runConformance(t, newFactory, { adapter: 'mymechanism' })`.
 *
 * {@link runConformance} executes every case file under adapters/_common of
 * the fixture tree, then the case files in adapters/<adapter>, each as a
 * subtest. {@link evaluateConformance} runs the same cases and returns their
 * results; it imports no test framework, so any runner can use it. The cases
 * are the language-neutral JSON files of spec/v1.0/fixtures/adapters, which
 * spec/v1.0/fixtures/adapters/README.md defines, registered in
 * spec/v1.0/fixtures/manifest.json with the kind adapter-case; the suite builds
 * the adapter for each case with the factory, holds the clock at the case's
 * now, calls the function, and checks the result against what the case
 * requires.
 *
 * An adapter function's answer is the value its promise resolves to and its
 * error the reason it rejects with; one that throws instead of returning a
 * promise fails the case as broken. A rejected promise carries no value, so
 * the Go checks of a value returned together with an error have no
 * counterpart here. A draft 13.4 code is carried by an `AdapterError` in the
 * error's `cause` chain.
 *
 * @module
 */
export type {
  BindingJSON,
  Call,
  Case,
  Expect,
  ExpectBinding,
  ExpectClaim,
  ExpectDecision,
  ExpectOperation,
  ExpectPrincipal,
  LeakScan,
  ObligationJSON,
  ObservationJSON,
  PrincipalJSON,
  RealmJSON,
  Request,
  TLSPeer,
} from './casefile.ts';
export {
  type Env,
  type Factory,
  type FixtureTree,
  Hooks,
  type Options,
  type Replacement,
  type Subject,
} from './harness.ts';
export { defaultFixtures, fixturesAt, loadCases } from './load.ts';
export { evaluateConformance, Result, runConformance } from './suite.ts';
