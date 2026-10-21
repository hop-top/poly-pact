/**
 * The names of the adapter case-file format (Go
 * hop.top/pact-go/adapter/adaptertest, casefile.go): the seven functions, the
 * outcomes each accepts, the workload modes and the arrival values
 * (spec/v1.0/fixtures/adapters/README.md).
 *
 * @module
 */

/** The only case file format this module reads. */
export const CASE_VERSION = 1;

/** The bound of one case file. */
export const MAX_CASE_BYTES = 1 << 20;

/** The seven function names of the draft 17.1 table, as `expect.function` spells them. */
export const FN = Object.freeze({
  authenticate: 'authenticate_native',
  binding: 'resolve_agent_binding',
  mapOperation: 'map_operation',
  claim: 'read_native_claim',
  check: 'check_context',
  authorize: 'authorize_native',
  record: 'record_outcome',
} as const);

/**
 * The outcomes a case can expect; check_context uses the verdict and
 * authorize_native the effect.
 */
export const OUT = Object.freeze({
  authenticated: 'authenticated',
  denied: 'denied',
  error: 'error',
  bound: 'bound',
  notEnrolled: 'unknown',
  unusable: 'unusable',
  mapped: 'mapped',
  claim: 'claim',
  pass: 'PASS',
  fail: 'FAIL',
  unknown: 'UNKNOWN',
  allow: 'ALLOW',
  deny: 'DENY',
  notAllowed: 'not_allowed',
  signed: 'signed',
  noVisibility: 'no_visibility',
  noExecSuccess: 'no_execution_success',
} as const);

/** The outcomes each function accepts. */
export const FUNCTION_OUTCOMES: Readonly<Record<string, readonly string[]>> = {
  [FN.authenticate]: [OUT.authenticated, OUT.denied, OUT.error],
  [FN.binding]: [OUT.bound, OUT.notEnrolled, OUT.unusable, OUT.error],
  [FN.mapOperation]: [OUT.mapped, OUT.error],
  [FN.claim]: [OUT.claim, OUT.error],
  [FN.check]: [OUT.pass, OUT.fail, OUT.unknown],
  [FN.authorize]: [OUT.allow, OUT.deny, OUT.unknown, OUT.notAllowed, OUT.error],
  [FN.record]: [OUT.signed, OUT.noVisibility, OUT.noExecSuccess, OUT.error],
};

/** Values of `Case.workloads`. */
export const WORKLOADS_SHARED = 'shared';
export const WORKLOADS_DEDICATED = 'dedicated';

/** Values of `Request.arrival`. */
export const ARRIVAL_DIRECT = 'direct';

/** The directory of the cases every adapter must pass, relative to the fixture root. */
export const COMMON_DIR = 'adapters/_common';
