/**
 * The configuration checks of the baseline binding (Go config.go;
 * spec/v1.0/profiles/request-binding.md section 4.2).
 *
 * @module
 */
import { isIPv6 } from 'node:net';
import { codePoints, isASCII, isSubDelim, isToken, isUnreserved, lowerASCII } from './chars.ts';
import { configError } from './errors.ts';
import type { Config } from './index.ts';

/** Schema bounds that keep the output valid against OperationContext and GatewayMetadata. */
export const MAX_IDENTIFIER = 1024;
export const MAX_TARGET_URI = 1024;
export const MAX_HEADERS = 64;
export const MAX_HEADER_VALUE = 8192;

/** A validated configuration: the normalized origin and the lowercase allowlist. */
export interface Prepared {
  readonly origin: string;
  readonly allow: readonly string[];
}

/** Validates cfg; throws a RequestError of kind INVALID_CONFIG. */
export function prepare(cfg: Config): Prepared {
  const origin = normalizeOrigin(cfg.origin);
  const allow = allowlist(cfg.headerAllowlist);
  for (const [name, v] of [
    ['HeaderNormalizationID', cfg.headerNormalizationId],
    ['MappingVersion', cfg.mappingVersion],
  ] as const) {
    const n = typeof v === 'string' && v.isWellFormed() ? codePoints(v) : 0;
    if (n < 1 || n > MAX_IDENTIFIER) {
      throw configError(`${name} must be UTF-8 of 1 to ${MAX_IDENTIFIER} characters`);
    }
  }
  checkMaxBody(cfg.maxBody);
  return { origin, allow };
}

/** Requires a body limit that is a non-negative safe integer. */
export function checkMaxBody(max: number): void {
  if (!Number.isSafeInteger(max)) throw configError('MaxBody is not a safe integer');
  if (max < 0) throw configError('MaxBody is negative');
}

/**
 * Checks an origin and returns it with the scheme and host in lowercase and
 * the default port omitted (RFC 3986 6.2.2.1, 6.2.3; RFC 9110 4.2.3).
 */
function normalizeOrigin(s: string): string {
  const q = JSON.stringify(s);
  const sep = s.indexOf('://');
  if (sep < 0 || lowerASCII(s.slice(0, sep)) !== 'https') {
    throw configError(`Origin ${q} is not an https origin`);
  }
  const authority = s.slice(sep + 3);
  if (/[/?#]/.test(authority)) throw configError(`Origin ${q} has a path, query or fragment`);
  if (authority.includes('@')) throw configError(`Origin ${q} has userinfo`);
  if (!isASCII(authority) || authority.includes('%')) {
    // RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8, so
    // it is a non-ASCII host too.
    throw configError(`Origin ${q} has a non-ASCII host`);
  }
  let host: string;
  let port: string;
  try {
    [host, port] = splitHostPort(authority);
  } catch (err) {
    throw configError(`Origin ${q}: ${(err as Error).message}`);
  }
  let out = `https://${lowerASCII(host)}`;
  if (port !== '' && port !== '443') out += `:${port}`;
  return out;
}

/** Splits an ASCII authority without userinfo into a validated host and port. */
function splitHostPort(a: string): [host: string, port: string] {
  if (a.startsWith('[')) {
    const end = a.indexOf(']');
    if (end < 0) throw new Error('unclosed IP literal');
    const host = a.slice(0, end + 1);
    const rest = a.slice(end + 1);
    // RFC 3986 3.2.2: an IP literal is IPv6 (no zone identifier) or
    // IPvFuture, which no gateway resolves here. A zone needs "%", refused
    // with the non-ASCII host.
    if (!isIPv6(host.slice(1, -1))) {
      throw new Error(`IP literal ${JSON.stringify(host)} is not an IPv6 address without zone`);
    }
    if (rest !== '' && !rest.startsWith(':')) throw new Error('text after the IP literal');
    const port = rest.slice(1);
    checkPort(port);
    return [host, port];
  }
  const colon = a.indexOf(':');
  const host = colon < 0 ? a : a.slice(0, colon);
  const port = colon < 0 ? '' : a.slice(colon + 1);
  // RFC 9110 4.2.2: an https URI with an empty host is invalid.
  if (host === '') throw new Error('empty host');
  for (let i = 0; i < host.length; i++) {
    const c = host.charCodeAt(i);
    if (!isUnreserved(c) && !isSubDelim(c)) {
      throw new Error(`host has the character ${JSON.stringify(host[i])}`);
    }
  }
  checkPort(port);
  return [host, port];
}

/**
 * Accepts an empty port or a decimal port 1..65535 without leading zero or
 * sign, so that the default port is recognized by its spelling.
 */
function checkPort(p: string): void {
  if (p === '') return;
  if (!/^[1-9][0-9]{0,4}$/.test(p) || Number(p) > 65535) {
    throw new Error(`port ${JSON.stringify(p)} is not a number 1..65535 without leading zero`);
  }
}

/**
 * Whether a lowercase header name can never be covered: credentials and
 * presentation headers (draft 10.2, 19), hop-by-hop headers (RFC 9110 7.6.1),
 * message signatures (RFC 9421 4.1, 4.2) and Host, which never selects the
 * origin (request-binding.md RB-3, RB-20).
 */
function excludedHeader(name: string): boolean {
  switch (name) {
    case 'authorization':
    case 'cookie':
    case 'set-cookie':
    case 'connection':
    case 'keep-alive':
    case 'te':
    case 'transfer-encoding':
    case 'upgrade':
    case 'signature':
    case 'signature-input':
    case 'host':
      return true;
  }
  return name.startsWith('pact-') || name.startsWith('proxy-');
}

/** Validates the configured header names and returns them in lowercase. */
function allowlist(names: readonly string[]): string[] {
  const out: string[] = [];
  let withContentType = 0;
  for (const n of names) {
    if (typeof n !== 'string' || !isToken(n)) {
      throw configError(`header name ${JSON.stringify(n)} is not an RFC 9110 token`);
    }
    const l = lowerASCII(n);
    if (excludedHeader(l)) {
      throw configError(`header ${JSON.stringify(l)} cannot be covered by an operation context`);
    }
    if (out.includes(l)) throw configError(`header ${JSON.stringify(l)} is listed twice`);
    out.push(l);
    if (l === 'content-type') withContentType = 1;
  }
  const n = out.length + 1 - withContentType;
  if (n > MAX_HEADERS) {
    throw configError(`${n} header names with content-type, at most ${MAX_HEADERS}`);
  }
  return out;
}
