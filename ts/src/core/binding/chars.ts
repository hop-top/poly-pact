/**
 * Character classes of RFC 3986 and RFC 9110 over UTF-16 code units. A
 * code unit of 0x80 or more is never in any of them, so a non-ASCII
 * character fails every check as a non-ASCII octet does in Go.
 *
 * @module
 */

export const isAlpha = (c: number): boolean => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
export const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;

/** RFC 3986 2.3 unreserved. */
export function isUnreserved(c: number): boolean {
  return isAlpha(c) || isDigit(c) || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e;
}

const SUB_DELIMS = "!$&'()*+,;=";
const TCHAR_EXTRA = "!#$%&'*+-.^_`|~";

/** RFC 3986 2.2 sub-delims. */
export function isSubDelim(c: number): boolean {
  return c < 0x80 && SUB_DELIMS.includes(String.fromCharCode(c));
}

/** RFC 3986 3.3 pchar without pct-encoded. */
export function isPchar(c: number): boolean {
  return isUnreserved(c) || isSubDelim(c) || c === 0x3a || c === 0x40;
}

export function isHex(c: number): boolean {
  return isDigit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

export const isLowerHex = (c: number): boolean => c >= 0x61 && c <= 0x66;

export function unhex(c: number): number {
  if (isDigit(c)) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return c - 0x61 + 10;
}

export function isASCII(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) >= 0x80) return false;
  return true;
}

/** Lowercases ASCII letters only, so no Unicode case mapping changes other characters. */
export function lowerASCII(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

/** Whether s is an RFC 9110 5.6.2 token. */
export function isToken(s: string): boolean {
  if (s === '') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!isAlpha(c) && !isDigit(c) && !(c < 0x80 && TCHAR_EXTRA.includes(s[i] ?? ''))) return false;
  }
  return true;
}

/** Whether a and b are equal once ASCII letters are lowercased (Go strings.EqualFold on ASCII). */
export function equalFoldASCII(a: string, b: string): boolean {
  return a.length === b.length && lowerASCII(a) === lowerASCII(b);
}

/** The number of code points of a well-formed string (Go utf8.RuneCountInString). */
export function codePoints(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** s without leading and trailing SP and HTAB (Go strings.Trim(s, " \t")). */
export function trimOWS(s: string): string {
  return s.replace(/^[ \t]+|[ \t]+$/g, '');
}
