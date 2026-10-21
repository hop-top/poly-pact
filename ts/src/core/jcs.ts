/**
 * RFC 8785 JSON canonicalization (Go package hop.top/pact-go/core/jcs), for the
 * object digest of draft section 7.4.
 *
 * {@link canonicalize} reads its input with `strictjson.parse` and its
 * default limits, so the checks of draft section 7.1 come first and a
 * refused document throws the same `StrictJSONError`. It then writes the
 * value as RFC 8785 section 3 requires:
 *
 * - no white space between tokens;
 * - strings as `JSON.stringify` writes them (section 3.2.2.2): only the
 *   quotation mark, the reverse solidus and the controls below U+0020 are
 *   escaped, every other character is written as is, with no Unicode
 *   normalization;
 * - numbers in the ECMAScript Number::toString form (section 3.2.2.3);
 * - object members sorted by name, recursively, comparing the names as
 *   arrays of UTF-16 code units (section 3.2.3), which is the default
 *   `Array.prototype.sort` order; array order is kept.
 *
 * Integer literals outside ±(2^53-1) are refused on input, while a float
 * written with an exponent, such as 1e30, is accepted and rounded to
 * binary64. A float of integer value from 2^53 up to 1e21 is therefore
 * written as an integer literal that `canonicalize` does not accept back.
 *
 * @module
 */
import { numberText } from '../internal/numbers.ts';
import { parse } from './strictjson.ts';

const utf8 = new TextEncoder();

/** Returns the RFC 8785 canonical form of the strictly parsed JSON text `input`. */
export function canonicalize(input: Uint8Array | string): Uint8Array {
  const out: string[] = [];
  write(parse(input), out);
  return utf8.encode(out.join(''));
}

// Appends the canonical form of v, a value as parse returns it.
function write(v: unknown, out: string[]): void {
  if (v === null) {
    out.push('null');
  } else if (typeof v === 'boolean') {
    out.push(v ? 'true' : 'false');
  } else if (typeof v === 'number') {
    out.push(numberText(v));
  } else if (typeof v === 'string') {
    out.push(JSON.stringify(v));
  } else if (Array.isArray(v)) {
    out.push('[');
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out.push(',');
      write(v[i], out);
    }
    out.push(']');
  } else if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    out.push('{');
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i] as string;
      if (i > 0) out.push(',');
      out.push(JSON.stringify(k), ':');
      write(Object.getOwnPropertyDescriptor(o, k)?.value, out);
    }
    out.push('}');
  } else {
    throw new TypeError(`jcs: unexpected ${typeof v} in parsed JSON`);
  }
}
