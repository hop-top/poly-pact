/**
 * The codes and the errors of the adapter contract (Go hop.top/pact-go/adapter,
 * errors.go and the denial of auth.go).
 *
 * @module
 */
/** A stable error code of the draft 13.4 table, one per Go sentinel error. */
export const Code = Object.freeze({
  INVALID_MESSAGE: 'INVALID_MESSAGE',
  INVALID_PROOF: 'INVALID_PROOF',
  CONTEXT_MISMATCH: 'CONTEXT_MISMATCH',
  DEPENDENCY_UNAVAILABLE: 'DEPENDENCY_UNAVAILABLE',
  UNSUPPORTED_REQUIREMENT: 'UNSUPPORTED_REQUIREMENT',
  UNSUPPORTED_PURPOSE: 'UNSUPPORTED_PURPOSE',
  MISSING_FIELD: 'MISSING_FIELD',
} as const);

/** A stable error code of the draft 13.4 table. */
export type Code = (typeof Code)[keyof typeof Code];

// The text of each Go sentinel error, after "adapter: ".
const TEXT: Readonly<Record<Code, string>> = {
  INVALID_MESSAGE: 'request or message is malformed or has an unsupported structure',
  INVALID_PROOF: 'native authentication or holder binding failed',
  CONTEXT_MISMATCH: 'principal, realm, intent or operation differs',
  DEPENDENCY_UNAVAILABLE: 'required verification cannot currently be completed',
  UNSUPPORTED_REQUIREMENT: 'required rule, mapping or check is unsupported',
  UNSUPPORTED_PURPOSE: 'purpose has no installed meaning',
  MISSING_FIELD: 'the source holds no value at the native path',
};

/** The options of an {@link AdapterError}: the error it wraps, if any. */
export interface AdapterErrorOptions {
  readonly cause?: unknown;
}

/**
 * An error of the adapter contract with its draft 13.4 {@link Code}; one
 * code per Go sentinel error:
 *
 * - `INVALID_MESSAGE` (`ErrInvalidMessage`): a request or message has a form
 *   the contract does not accept (HTTP 400): invalid JSON, schema or
 *   signature format, or an unsupported structure. `mapOperation` throws it
 *   for an actual request that violates a rule of the baseline HTTP mapping
 *   (draft 10.2, 13.4): among them a fragment or userinfo in the target, an
 *   ambiguous encoding, of which draft 10.2 gives the definition and the
 *   list, and an HTTP content encoding.
 * - `INVALID_PROOF` (`ErrInvalidProof`): native authentication, a signature,
 *   or a holder binding failed. A {@link NativeDenial} has this code.
 * - `CONTEXT_MISMATCH` (`ErrContextMismatch`): the principal, audience,
 *   realm, intent or actual operation differs from what was bound.
 * - `DEPENDENCY_UNAVAILABLE` (`ErrDependencyUnavailable`): a required source
 *   cannot currently answer. The affected check is UNKNOWN and the admission
 *   decision is DEFERRED; it is never a pass and never a failure.
 * - `UNSUPPORTED_REQUIREMENT` (`ErrUnsupportedRequirement`): a required
 *   field rule, extension, mapping or context check has no installed meaning
 *   here. `resolveAgentBinding` throws it for a workload with more than one
 *   enrollment in force when the profile in use does not support workloads
 *   shared by several agents (draft 17.1).
 * - `UNSUPPORTED_PURPOSE` (`ErrUnsupportedPurpose`): a purpose identifier has
 *   no installed meaning.
 * - `MISSING_FIELD` (`ErrMissingField`): the source answers, and it holds no
 *   value at the native path for the principal. An absent value fails the
 *   rule that requires it (draft 9.2); it is not an outage.
 *
 * The message is `adapter: <the Go sentinel text>[: <detail>]`. An error that
 * wraps an adapter error keeps it as its `cause`, and {@link codeOf} finds
 * it there. The seven static constructors name the codes.
 */
export class AdapterError extends Error {
  readonly code: Code;
  /** What the thrower adds to the sentinel text; `''` when nothing. */
  readonly detail: string;

  constructor(code: Code, detail = '', options?: AdapterErrorOptions) {
    super(
      `adapter: ${TEXT[code]}${detail === '' ? '' : `: ${detail}`}`,
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = 'AdapterError';
    this.code = code;
    this.detail = detail;
  }

  /** Go `ErrInvalidMessage`. */
  static invalidMessage(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.INVALID_MESSAGE, detail, options);
  }

  /** Go `ErrInvalidProof`. */
  static invalidProof(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.INVALID_PROOF, detail, options);
  }

  /** Go `ErrContextMismatch`. */
  static contextMismatch(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.CONTEXT_MISMATCH, detail, options);
  }

  /** Go `ErrDependencyUnavailable`. */
  static dependencyUnavailable(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.DEPENDENCY_UNAVAILABLE, detail, options);
  }

  /** Go `ErrUnsupportedRequirement`. */
  static unsupportedRequirement(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.UNSUPPORTED_REQUIREMENT, detail, options);
  }

  /** Go `ErrUnsupportedPurpose`. */
  static unsupportedPurpose(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.UNSUPPORTED_PURPOSE, detail, options);
  }

  /** Go `ErrMissingField`. */
  static missingField(detail = '', options?: AdapterErrorOptions): AdapterError {
    return new AdapterError(Code.MISSING_FIELD, detail, options);
  }
}

/**
 * The code of the first {@link AdapterError} in the `cause` chain of `err`,
 * `err` included, or `''` when there is none (Go `CodeOf`).
 */
export function codeOf(err: unknown): Code | '' {
  const seen = new Set<unknown>();
  for (let e = err; e instanceof Error && !seen.has(e); e = e.cause) {
    if (e instanceof AdapterError) return e.code;
    seen.add(e);
  }
  return '';
}

/**
 * The public reason of a {@link NativeDenial}. The set is closed and each
 * value is something the caller already knows about its own request, so a
 * denial never discloses whether an account, a tenant or an issuer exists
 * (draft 13.4).
 *
 * - `NO_CREDENTIAL`: the request carried no credential.
 * - `CREDENTIAL_REJECTED`: a credential was presented and not accepted,
 *   whether it was malformed, expired, revoked, unknown or unverifiable.
 */
export const DenialReason = Object.freeze({
  NO_CREDENTIAL: 'NO_CREDENTIAL',
  CREDENTIAL_REJECTED: 'CREDENTIAL_REJECTED',
} as const);

/** The public reason of a {@link NativeDenial}. */
export type DenialReason = (typeof DenialReason)[keyof typeof DenialReason];

const denialReasonValues: ReadonlySet<string> = new Set(Object.values(DenialReason));

/** Reports whether `x` is a {@link DenialReason} value (Go `DenialReason.Valid`). */
export function isDenialReason(x: unknown): x is DenialReason {
  return typeof x === 'string' && denialReasonValues.has(x);
}

/**
 * The error `authenticateNative` rejects with when the native system
 * evaluated the request and did not authenticate it. It is an
 * {@link AdapterError} with the code `INVALID_PROOF`, and it carries no
 * cause: an adapter logs internal detail itself. Its message is built from
 * the public reason only.
 */
export class NativeDenial extends AdapterError {
  /**
   * The reason the adapter gave. A value outside {@link DenialReason} is
   * reported as `CREDENTIAL_REJECTED`; see {@link NativeDenial.publicReason}.
   */
  readonly reason: string;

  /** A denial for `reason`; no reason is reported as `CREDENTIAL_REJECTED`. */
  constructor(reason: DenialReason | string = '') {
    super(Code.INVALID_PROOF);
    this.name = 'NativeDenial';
    this.reason = reason;
    this.message = `adapter: native authentication denied: ${this.publicReason()}`;
  }

  /**
   * The reason when it is a {@link DenialReason} value and
   * `CREDENTIAL_REJECTED` otherwise, so that free text an adapter puts in the
   * reason is never shown.
   */
  publicReason(): DenialReason {
    return isDenialReason(this.reason) ? this.reason : DenialReason.CREDENTIAL_REJECTED;
  }
}
