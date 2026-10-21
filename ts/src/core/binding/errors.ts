/**
 * The rules and the error of the baseline HTTP binding (Go
 * hop.top/pact-go/core/binding, binding.go).
 *
 * @module
 */

/**
 * The rule of the baseline HTTP mapping that a request broke, one per row of
 * spec/v1.0/profiles/request-binding.md section 4.1. The package documentation of
 * {@link fromRequest} gives the source of each.
 */
export const Rule = Object.freeze({
  NO_REQUEST: 'no-request',
  METHOD: 'method',
  TARGET_FORM: 'target-form',
  FRAGMENT: 'fragment',
  USERINFO: 'userinfo',
  NON_ASCII_HOST: 'non-ascii-host',
  INVALID_CHARACTER: 'invalid-character',
  MALFORMED_ESCAPE: 'malformed-escape',
  ENCODED_UNRESERVED: 'encoded-unreserved',
  LOWERCASE_HEX: 'lowercase-hex',
  INVALID_UTF8: 'invalid-utf8',
  ENCODED_SLASH: 'encoded-slash',
  DOT_SEGMENT: 'dot-segment',
  TARGET_TOO_LONG: 'target-too-long',
  CONTENT_ENCODING: 'content-encoding',
  TRANSFER_CODING: 'transfer-coding',
  BODY_TOO_LARGE: 'body-too-large',
  HEADER_VALUE: 'header-value',
  HEADER_TOO_LONG: 'header-too-long',
  HEADER_KEY_COLLISION: 'header-key-collision',
  DUPLICATE_HOST: 'duplicate-host',
  MISSING_HOST: 'missing-host',
  INVALID_HOST: 'invalid-host',
} as const);

/** The rule of the baseline HTTP mapping that a request broke. */
export type Rule = (typeof Rule)[keyof typeof Rule];

/**
 * The kinds of a binding failure, one per Go sentinel error:
 * `INVALID_CONFIG` (`ErrInvalidConfig`, a gateway misconfiguration),
 * `INVALID_REQUEST` (`ErrInvalidRequest`, a refused request, INVALID_MESSAGE
 * of draft section 13.4) and `BODY_READ` (`ErrBodyRead`, the body could not
 * be read to its end; {@link RequestError.cause} holds the reason).
 */
export type RequestErrorKind = 'INVALID_CONFIG' | 'INVALID_REQUEST' | 'BODY_READ';

const PREFIX: Readonly<Record<RequestErrorKind, string>> = {
  INVALID_CONFIG: 'binding: invalid configuration',
  INVALID_REQUEST: 'binding: request refused',
  BODY_READ: 'binding: request body could not be read',
};

/**
 * A configuration, request or body read the baseline binding refuses. A
 * refused request (kind `INVALID_REQUEST`) names its {@link Rule}; the other
 * kinds have the rule `''`.
 */
export class RequestError extends Error {
  readonly kind: RequestErrorKind;
  readonly rule: Rule | '';
  /** Where the rule was broken. It quotes little or none of the request. */
  readonly detail: string;

  constructor(
    kind: RequestErrorKind,
    rule: Rule | '',
    detail: string,
    options?: { readonly cause?: unknown },
  ) {
    super(
      `${PREFIX[kind]}${rule === '' ? '' : ` (${rule})`}: ${detail}`,
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = 'RequestError';
    this.kind = kind;
    this.rule = rule;
    this.detail = detail;
  }
}

/** A refused request under rule. */
export function refuse(rule: Rule, detail: string): RequestError {
  return new RequestError('INVALID_REQUEST', rule, detail);
}

/** A configuration error. */
export function configError(detail: string): RequestError {
  return new RequestError('INVALID_CONFIG', '', detail);
}
