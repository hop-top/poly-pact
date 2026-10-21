/**
 * The error of the evaluation-case loader and its helpers.
 *
 * @module
 */

/**
 * A case, signed file or test key the loader cannot read as
 * spec/v1.0/fixtures/README.md defines it. `detail` is the message without the
 * package prefix: the file or case first, then what is wrong, as Go's
 * wrapped errors read. `cause` is the underlying error (a `StrictJSONError`,
 * a `JWSError`, a file system error), when there is one.
 */
export class CaseError extends Error {
  readonly detail: string;

  constructor(detail: string, options?: { readonly cause?: unknown }) {
    super(
      `evalcase: ${detail}`,
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = 'CaseError';
    this.detail = detail;
  }
}

/** The text of err without the package prefix of a {@link CaseError}. */
export function messageOf(err: unknown): string {
  if (err instanceof CaseError) return err.detail;
  if (err instanceof Error) return err.message;
  if (typeof err === 'object' && err !== null && 'message' in err) return String(err.message);
  return String(err);
}

/** err with `prefix: ` before its text; the cause is err's cause, or err itself. */
export function wrap(prefix: string, err: unknown): CaseError {
  return new CaseError(`${prefix}: ${messageOf(err)}`, {
    cause: err instanceof CaseError ? err.cause : err,
  });
}

/** Reports whether err is a file system error for a missing file. */
export function notExist(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT';
}

/** A Go %q of s, near enough: the JSON string. */
export function q(s: string): string {
  return JSON.stringify(s);
}
