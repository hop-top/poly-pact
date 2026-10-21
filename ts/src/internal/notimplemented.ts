/**
 * The error that every stub of a module not ported yet throws. The vectors
 * harness reports an entry whose call ends in it as `fail`, never as a
 * rejection the entry expects.
 *
 * @module
 */

/** A call into a function whose module has not been ported yet. */
export class NotImplementedError extends Error {
  /** The function called, as `module.name`. */
  readonly symbol: string;

  constructor(symbol: string) {
    super(`not implemented: ${symbol}`);
    this.name = 'NotImplementedError';
    this.symbol = symbol;
  }
}

/** Throws a {@link NotImplementedError} for `symbol`. */
export function notImplemented(symbol: string): never {
  throw new NotImplementedError(symbol);
}
