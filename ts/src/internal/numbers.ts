/**
 * The number form of RFC 8785 section 3.2.2.3: the ECMAScript
 * Number::toString of the binary64 value, the shortest digits that round
 * trip, laid out as `JSON.stringify` writes a number: plain from 10^-6 up to
 * below 10^21, otherwise `d[.ddd]e±n` with an explicit sign and no padding;
 * `0` for both zeros.
 *
 * @module
 */

/** The RFC 8785 text of the finite number `f`; a `RangeError` for NaN and the infinities. */
export function numberText(f: number): string {
  if (!Number.isFinite(f)) throw new RangeError(`jcs: ${f} is not a finite number`);
  return JSON.stringify(f);
}
