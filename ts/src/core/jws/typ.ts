/**
 * The algorithms, signer roles and typ values of the profile (Go
 * go/core/jws/typ.go and alg.go): draft sections 7.2 and 7.3.
 *
 * @module
 */

/** The baseline algorithm, ECDSA P-256 with SHA-256 (RFC 7518 section 3.4). */
export const ALG_ES256 = 'ES256';

/**
 * The fully specified Ed25519 identifier (RFC 9864 section 2.2), accepted
 * only where negotiated. The ambiguous EdDSA identifier is never accepted.
 */
export const ALG_ED25519 = 'Ed25519';

/**
 * The signer role a typ requires, after the "Required signer" column of the
 * draft 7.3 table. Which keys a deployment trusts for a role is
 * configuration: see `KeyResolver`.
 */
export const Role = {
  /** A gateway-authorized requirement publisher. */
  REQUIREMENT_PUBLISHER: 'requirement-publisher',
  /** An evidence issuer authorized for its claim paths and scope. */
  ISSUER: 'issuer',
  /**
   * The enrolled agent holder key: the only role whose key comes from the
   * artifact (an embedded jwk matching holder_jkt) instead of a trusted key
   * set.
   */
  HOLDER: 'holder',
  /** A gateway-authorized validator. */
  VALIDATOR: 'validator',
  /** A reporter authorized for the observation type. */
  REPORTER: 'reporter',
  /** An authorized reputation service. */
  REPUTATION_SERVICE: 'reputation-service',
  /** A native administrator or delegated policy authority. */
  POLICY_AUTHORITY: 'policy-authority',
  /** A learning controller, authorized for the manifest or for the lifecycle transition. */
  LEARNING_CONTROLLER: 'learning-controller',
} as const;
export type Role = (typeof Role)[keyof typeof Role];

export const TYP_REQUIREMENTS = 'pact-requirements+jwt';
export const TYP_EVIDENCE = 'pact-evidence+jwt';
export const TYP_PRESENTATION = 'pact-presentation+jwt';
export const TYP_ADMISSION = 'pact-admission+jwt';
export const TYP_OUTCOME = 'pact-outcome+jwt';
export const TYP_REPUTATION = 'pact-reputation+jwt';
export const TYP_LEARNING_POLICY = 'pact-learning-policy+jwt';
export const TYP_LEARNING_ARTIFACT = 'pact-learning-artifact+jwt';
export const TYP_LEARNING_EVENT = 'pact-learning-event+jwt';

// The draft 7.3 table, in its order.
const TYP_TABLE: readonly (readonly [string, Role])[] = [
  [TYP_REQUIREMENTS, Role.REQUIREMENT_PUBLISHER],
  [TYP_EVIDENCE, Role.ISSUER],
  [TYP_PRESENTATION, Role.HOLDER],
  [TYP_ADMISSION, Role.VALIDATOR],
  [TYP_OUTCOME, Role.REPORTER],
  [TYP_REPUTATION, Role.REPUTATION_SERVICE],
  [TYP_LEARNING_POLICY, Role.POLICY_AUTHORITY],
  [TYP_LEARNING_ARTIFACT, Role.LEARNING_CONTROLLER],
  [TYP_LEARNING_EVENT, Role.LEARNING_CONTROLLER],
];

/**
 * The signer role the draft 7.3 table requires for `typ`, or `undefined`.
 * `typ` is compared exactly: case and an "application/" prefix matter.
 */
export function typRole(typ: string): Role | undefined {
  return TYP_TABLE.find(([t]) => t === typ)?.[1];
}

/** The typ values of the draft 7.3 table, in its order (a new array). */
export function typs(): string[] {
  return TYP_TABLE.map(([t]) => t);
}
