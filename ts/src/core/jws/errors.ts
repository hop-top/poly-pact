/**
 * The reasons of a refusal and the error of the package (Go
 * go/core/jws/errors.go).
 *
 * @module
 */

/**
 * The stable names of why a JWS, a JWK or a key set was rejected, copied
 * from go/core/jws/errors.go in its order. The same names appear as
 * reject_reason in the language-neutral vectors under
 * spec/v1.0/fixtures/vectors/jws.
 */
export const Reason = {
  COMPACT_SIZE: 'compact-size',
  COMPACT_FORM: 'compact-form',
  BASE64_URL: 'base64url',
  HEADER_JSON: 'header-json',
  HEADER_CRIT: 'header-crit',
  HEADER_B64: 'header-b64',
  HEADER_JKU: 'header-jku',
  HEADER_X5U: 'header-x5u',
  HEADER_X5C: 'header-x5c',
  ALG_UNSUPPORTED: 'alg-unsupported',
  TYP_UNSUPPORTED: 'typ-unsupported',
  TYP_MISMATCH: 'typ-mismatch',
  KID_MISSING: 'kid-missing',
  KID_UNKNOWN: 'kid-unknown',
  KID_DUPLICATE: 'kid-duplicate',
  JWK_MISSING: 'jwk-missing',
  JWK_UNEXPECTED: 'jwk-unexpected',
  JWK_PRIVATE: 'jwk-private',
  JWK_INVALID: 'jwk-invalid',
  JWK_CURVE: 'jwk-curve',
  JWK_OFF_CURVE: 'jwk-off-curve',
  JWK_USAGE: 'jwk-usage',
  HOLDER_JKT_MISMATCH: 'holder-jkt-mismatch',
  KEY_UNAVAILABLE: 'key-unavailable',
  PAYLOAD_DETACHED: 'payload-detached',
  PAYLOAD_JSON: 'payload-json',
  SIGNATURE_LENGTH: 'signature-length',
  SIGNATURE_INVALID: 'signature-invalid',
  SIGNING_KEY: 'signing-key',
} as const;
export type Reason = (typeof Reason)[keyof typeof Reason];

function causeText(cause: unknown): string {
  if (cause === undefined) return '';
  return `: ${cause instanceof Error ? cause.message : String(cause)}`;
}

/**
 * A refusal of the JWS profile. `detail` says what was found, such as the
 * member name or the octet count; `cause` is the underlying error (a
 * `StrictJSONError`, a resolver error, a platform import error), when there
 * is one. The message is `jws: <reason>[: <detail>][: <cause message>]`, as
 * in Go.
 */
export class JWSError extends Error {
  readonly reason: Reason;
  readonly detail: string;

  constructor(reason: Reason, detail = '', options?: { cause?: unknown }) {
    super(
      `jws: ${reason}${detail === '' ? '' : `: ${detail}`}${causeText(options?.cause)}`,
      options,
    );
    this.name = 'JWSError';
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * The reason of the first {@link JWSError} in the `cause` chain of `err`,
 * `err` included, or `''` when there is none.
 */
export function reasonOf(err: unknown): Reason | '' {
  const seen = new Set<unknown>();
  for (let e = err; e instanceof Error && !seen.has(e); e = e.cause) {
    if (e instanceof JWSError) return e.reason;
    seen.add(e);
  }
  return '';
}

/** A new {@link JWSError}; `cause` is left out when undefined. */
export function fail(reason: Reason, detail = '', cause?: unknown): JWSError {
  return new JWSError(reason, detail, cause === undefined ? undefined : { cause });
}
