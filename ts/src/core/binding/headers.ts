/**
 * The header rules of the baseline binding (Go headers.go) over the field
 * lines of a request in the order received.
 *
 * @module
 */
import { isIPv6 } from 'node:net';
import {
  codePoints,
  equalFoldASCII,
  isDigit,
  isHex,
  isSubDelim,
  isUnreserved,
  lowerASCII,
  trimOWS,
} from './chars.ts';
import { MAX_HEADER_VALUE } from './config.ts';
import { Rule, refuse } from './errors.ts';

type Lines = ReadonlyArray<readonly [name: string, value: string]>;

/**
 * Returns the headers member: the allowlisted headers that are present, plus
 * content-type when a body is present (draft 10.2). A name listed in a
 * Connection field is hop-by-hop for this request (RFC 9110 7.6.1) and is
 * left out.
 */
export function selectHeaders(
  lines: Lines,
  allow: readonly string[],
  hasBody: boolean,
): Record<string, string> {
  const names = hasBody && !allow.includes('content-type') ? [...allow, 'content-type'] : allow;
  const hop = connectionOptions(lines);
  const out: [string, string][] = [];
  for (const name of names) {
    if (hop.has(name)) continue;
    const v = fieldValue(lines, name);
    if (v !== undefined) out.push([name, v]);
  }
  // fromEntries defines own properties, so a name such as __proto__ is a
  // member like any other.
  return Object.fromEntries(out);
}

/**
 * The combined value of the field name: each field line value without
 * leading or trailing SP and HTAB (RFC 9110 5.5, 5.6.3), joined in order
 * with ", " (RFC 9110 5.2, 5.3); undefined without a field line.
 */
function fieldValue(lines: Lines, name: string): string | undefined {
  const values: string[] = [];
  for (const [n, v] of lines) if (equalFoldASCII(n, name)) values.push(trimOWS(v));
  if (values.length === 0) return undefined;
  const v = values.join(', ');
  const q = JSON.stringify(name);
  for (let i = 0; i < v.length; i++) {
    // RFC 9110 5.5: field-content is VCHAR, obs-text, SP and HTAB; CR, LF,
    // NUL and the other controls are invalid.
    const c = v.charCodeAt(i);
    if ((c < 0x20 && c !== 0x09) || c === 0x7f) {
      throw refuse(
        Rule.HEADER_VALUE,
        `the header ${q} has the control octet 0x${c.toString(16).toUpperCase().padStart(2, '0')}`,
      );
    }
  }
  if (!v.isWellFormed()) {
    // Draft 7.1: PACT objects are UTF-8 JSON, so other octets cannot be
    // carried exactly.
    throw refuse(Rule.HEADER_VALUE, `the header ${q} is not valid UTF-8`);
  }
  const n = codePoints(v);
  if (n > MAX_HEADER_VALUE) {
    throw refuse(
      Rule.HEADER_TOO_LONG,
      `the header ${q} has ${n} characters, at most ${MAX_HEADER_VALUE}`,
    );
  }
  return v;
}

/**
 * The Host rules of RFC 9112 3.2 (request-binding.md RB-65, RB-66): more than
 * one Host field line, with names in any ASCII case and whatever the values,
 * is refused; an origin-form request without one has no authority and is
 * refused, while an absolute-form target carries its own (RFC 9112 3.2.2);
 * a value that is not uri-host [ ":" port ] with a non-empty host is
 * refused. A front that reads HTTP/2 gives :authority as the Host line.
 */
export function checkHost(lines: Lines, originForm: boolean): void {
  const values: string[] = [];
  for (const [name, value] of lines) if (equalFoldASCII(name, 'host')) values.push(value);
  if (values.length > 1) {
    throw refuse(Rule.DUPLICATE_HOST, `the request has ${values.length} Host field lines`);
  }
  if (originForm && values.length === 0) {
    throw refuse(Rule.MISSING_HOST, 'an origin-form request without Host');
  }
  for (const v of values) {
    if (!validHost(trimOWS(v))) {
      throw refuse(Rule.INVALID_HOST, 'the Host value is not uri-host [ ":" port ]');
    }
  }
}

/**
 * Whether v is uri-host [ ":" port ] (RFC 9110 7.2) with a host that is not
 * empty (RFC 9110 4.2.1, 4.2.2): an IP literal, IPv6 without a zone
 * identifier or IPvFuture, or a registered name of unreserved, sub-delims and
 * percent-encoded characters, which includes a dotted IPv4 address (RFC 3986
 * 3.2.2); then a port of digits (3.2.3).
 */
function validHost(v: string): boolean {
  let port: string;
  if (v.startsWith('[')) {
    const end = v.indexOf(']');
    if (end < 0) return false;
    const lit = v.slice(1, end);
    const rest = v.slice(end + 1);
    if (!IPV_FUTURE.test(lit) && (lit.includes('%') || !isIPv6(lit))) return false;
    if (rest !== '' && !rest.startsWith(':')) return false;
    port = rest.slice(1);
  } else {
    const colon = v.indexOf(':');
    const host = colon < 0 ? v : v.slice(0, colon);
    port = colon < 0 ? '' : v.slice(colon + 1);
    if (host === '') return false;
    for (let i = 0; i < host.length; i++) {
      const c = host.charCodeAt(i);
      if (isUnreserved(c) || isSubDelim(c)) continue;
      if (c === 0x25 && isHex(host.charCodeAt(i + 1)) && isHex(host.charCodeAt(i + 2))) {
        i += 2;
        continue;
      }
      return false;
    }
  }
  for (let i = 0; i < port.length; i++) if (!isDigit(port.charCodeAt(i))) return false;
  return true;
}

/** IPvFuture (RFC 3986 3.2.2): "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ). */
const IPV_FUTURE = /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+$/;

/** The lowercase connection options of every Connection field line (RFC 9110 7.6.1). */
function connectionOptions(lines: Lines): Set<string> {
  const out = new Set<string>();
  for (const [n, v] of lines) {
    if (!equalFoldASCII(n, 'connection')) continue;
    for (const opt of v.split(',')) {
      const o = trimOWS(opt);
      if (o !== '') out.add(lowerASCII(o));
    }
  }
  return out;
}
