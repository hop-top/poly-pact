/**
 * The request-target rules of the baseline binding (Go target.go).
 *
 * @module
 */
import { isASCII, isHex, isLowerHex, isPchar, isUnreserved, lowerASCII, unhex } from './chars.ts';
import { Rule, refuse } from './errors.ts';

const hex2 = (c: number): string => c.toString(16).toUpperCase().padStart(2, '0');

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Returns the exact path and query of a request-target (RFC 9112 3.2): all
 * of it in origin-form, the part after the authority in absolute-form.
 * Other forms, a fragment, userinfo, a non-ASCII host, the ambiguous
 * encodings and dot segments are refused.
 */
export function requestTarget(rt: string): string {
  if (rt.includes('#')) throw refuse(Rule.FRAGMENT, 'the target has a fragment');
  let pathQuery: string;
  if (rt === '') {
    throw refuse(Rule.TARGET_FORM, 'no request-target');
  } else if (rt.startsWith('/')) {
    pathQuery = rt;
  } else {
    pathQuery = absoluteForm(rt);
  }
  const q = pathQuery.indexOf('?');
  const path = q < 0 ? pathQuery : pathQuery.slice(0, q);
  checkComponent(path, true);
  checkDotSegments(path);
  if (q >= 0) checkComponent(pathQuery.slice(q + 1), false);
  return pathQuery;
}

/**
 * Returns the path and query of an http or https absolute-form target. The
 * authority is checked and then dropped: the origin comes from
 * configuration. An empty path is refused rather than normalized to "/".
 * Userinfo is refused under any scheme, as Go refuses the userinfo of the
 * parsed URL before it looks at the form.
 */
function absoluteForm(rt: string): string {
  const sep = rt.indexOf('://');
  if (sep < 0) {
    throw refuse(Rule.TARGET_FORM, 'the target is not origin-form or an http(s) absolute-form');
  }
  const scheme = lowerASCII(rt.slice(0, sep));
  const rest = rt.slice(sep + 3);
  const m = /[/?]/.exec(rest);
  const end = m === null ? rest.length : m.index;
  const authority = rest.slice(0, end);
  const pathQuery = rest.slice(end);
  if (authority.includes('@')) {
    // RFC 9110 4.2.4: a recipient treats userinfo in an http(s) URI as an
    // error.
    throw refuse(Rule.USERINFO, 'the target has userinfo');
  }
  if (scheme !== 'https' && scheme !== 'http') {
    throw refuse(Rule.TARGET_FORM, 'the target is not origin-form or an http(s) absolute-form');
  }
  if (!isASCII(authority) || authority.includes('%')) {
    // RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8.
    throw refuse(Rule.NON_ASCII_HOST, 'the target has a non-ASCII host');
  }
  const colon = authority.indexOf(':');
  if ((colon < 0 ? authority : authority.slice(0, colon)) === '') {
    // RFC 9110 4.2.1, 4.2.2: an http(s) URI with an empty host is invalid.
    throw refuse(Rule.TARGET_FORM, 'the absolute-form target has an empty host');
  }
  if (!pathQuery.startsWith('/')) {
    throw refuse(Rule.TARGET_FORM, 'the absolute-form target has an empty path');
  }
  return pathQuery;
}

/**
 * Checks the path (isPath) or the query of a request target: every octet is
 * allowed there by RFC 3986 3.3 or 3.4, every "%" starts a pct-encoded
 * triplet (2.1), and the encoding is not ambiguous: no escape has a
 * lowercase hex digit (2.1, 6.2.2.1) or encodes an unreserved character
 * (2.3, 6.2.2.2), the path has no %2F, and the decoded octets are valid
 * UTF-8, so no overlong form, surrogate or stray octet (RFC 3629 3).
 */
function checkComponent(s: string, isPath: boolean): void {
  const name = isPath ? 'path' : 'query';
  const decoded = new Uint8Array(s.length);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c !== 0x25) {
      if (!isPchar(c) && c !== 0x2f && (isPath || c !== 0x3f)) {
        throw refuse(
          Rule.INVALID_CHARACTER,
          `the ${name} has the character U+${c.toString(16).toUpperCase().padStart(4, '0')} at offset ${i}, not allowed in a URI`,
        );
      }
      decoded[n++] = c;
      continue;
    }
    const h1 = s.charCodeAt(i + 1);
    const h2 = s.charCodeAt(i + 2);
    if (i + 2 >= s.length || !isHex(h1) || !isHex(h2)) {
      throw refuse(
        Rule.MALFORMED_ESCAPE,
        `the ${name} has a % at offset ${i} not followed by two hex digits`,
      );
    }
    if (isLowerHex(h1) || isLowerHex(h2)) {
      throw refuse(
        Rule.LOWERCASE_HEX,
        `the ${name} has a lowercase hex digit in the escape at offset ${i}`,
      );
    }
    const b = (unhex(h1) << 4) | unhex(h2);
    if (isUnreserved(b)) {
      throw refuse(
        Rule.ENCODED_UNRESERVED,
        `the ${name} encodes the unreserved character %${hex2(b)} at offset ${i}`,
      );
    }
    if (isPath && b === 0x2f) {
      throw refuse(Rule.ENCODED_SLASH, `the path has an encoded slash at offset ${i}`);
    }
    decoded[n++] = b;
    i += 2;
  }
  try {
    utf8.decode(decoded.subarray(0, n));
  } catch {
    throw refuse(Rule.INVALID_UTF8, `the decoded ${name} is not valid UTF-8`);
  }
}

/**
 * Refuses a path with a complete "." or ".." segment (RFC 3986 3.3), which
 * path segment normalization (6.2.2.3) removes with remove_dot_segments
 * (5.2.4), so the path is an ambiguous encoding (draft 10.2). Segments are
 * delimited by "/" only: "a..b", "..." and dots in the query are not dot
 * segments. An encoded dot, as in "%2E%2E", has already been refused as an
 * encoded unreserved character.
 */
function checkDotSegments(path: string): void {
  let offset = 0;
  for (const seg of path.split('/')) {
    if (seg === '.' || seg === '..') {
      throw refuse(
        Rule.DOT_SEGMENT,
        `the path has the dot segment ${JSON.stringify(seg)} at offset ${offset}`,
      );
    }
    offset += seg.length + 1;
  }
}
