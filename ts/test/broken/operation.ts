/**
 * map_operation of the broken adapter, with its defects (Go
 * hop.top/pact-go/adapters/internal/broken, operation.go).
 *
 * @module
 */
import { AdapterError, Code, codeOf } from '../../src/adapter/errors.ts';
import type { Principal } from '../../src/adapter/types.ts';
import { equalFoldASCII } from '../../src/core/binding/chars.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import type { OperationContext } from '../../src/core/types.ts';
import type { Digest } from '../../src/core/values.ts';
import type { Adapter } from './broken.ts';
import { Defect } from './defects.ts';
import { header } from './native.ts';

/** The digest of the empty byte string. */
const EMPTY_DIGEST = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';

/** mapOperation of the memory adapter, with the mapping defects. */
export async function mapOperation(
  b: Adapter,
  req: RawRequest,
  principal: Principal,
  mappingVersion: string,
  signal?: AbortSignal,
): Promise<OperationContext> {
  let p = principal;
  if (b.has(Defect.IGNORE_REALM_MAPPING)) {
    const g = b.state().gateway;
    p = { ...p, realm: { tenantId: g.tenant_id, environmentId: g.environment_id } };
  }
  // The memory adapter maps a copy of the request that the defects changed;
  // the copy shares the body of req, so req shows what it did with the body.
  let target = req.rawRequestURI;
  let headers = req.headers;
  if (b.has(Defect.ACCEPT_FRAGMENT)) target = target.split('#', 1)[0] as string;
  if (b.has(Defect.ACCEPT_USERINFO)) target = withoutUserinfo(target);
  if (b.has(Defect.ACCEPT_CONTENT_ENCODING)) {
    headers = headers.filter(([name]) => !equalFoldASCII(name, 'Content-Encoding'));
  }
  if (b.has(Defect.NORMALIZE_AMBIGUOUS_ENCODING)) target = normalizeEncoding(target);
  const copy: RawRequest = { ...req, rawRequestURI: target, headers };

  let op: OperationContext;
  try {
    op = await b.base.mapOperation(copy, p, mappingVersion, signal);
  } catch (err) {
    let e: unknown = err;
    if (b.has(Defect.WRONG_MALFORMED_CODE) && codeOf(e) === Code.INVALID_MESSAGE) {
      // The message says what was wrong; the chain no longer holds the
      // INVALID_MESSAGE code, only another one.
      e = AdapterError.unsupportedRequirement((e as Error).message);
    }
    if (b.has(Defect.LEAK_CREDENTIAL_IN_MAP_ERROR)) {
      e = new Error(
        `${(e as Error).message} (request had Authorization ${JSON.stringify(header(req, 'Authorization'))} and Cookie ${JSON.stringify(header(req, 'Cookie'))})`,
        { cause: e },
      );
    }
    throw e;
  } finally {
    if (b.has(Defect.BODY_NOT_RESTORED)) {
      // The digest is right; the request is left with nothing of its body.
      // A RawRequest is a value whose body a reader can only overwrite, so
      // the body it consumed is left as zeros.
      req.body.fill(0);
    }
  }
  return corrupt(b, op, req);
}

/** The request-target without the userinfo of an absolute-form target. */
export function withoutUserinfo(rt: string): string {
  const i = rt.indexOf('://');
  if (i < 0) return rt;
  const scheme = rt.slice(0, i);
  let rest = rt.slice(i + 3);
  let end = rest.search(/[/?#]/);
  if (end < 0) end = rest.length;
  const at = rest.slice(0, end).lastIndexOf('@');
  if (at >= 0) rest = rest.slice(at + 1);
  return `${scheme}://${rest}`;
}

/**
 * The path and query of a request-target as a lenient gateway reads them: an
 * escape of an unreserved character, of "/" in the path, or an overlong
 * two-octet form of either is decoded, every other escape is written with
 * uppercase hex digits, and the dot segments of the path are removed (RFC
 * 3986 5.2.4).
 */
export function normalizeEncoding(target: string): string {
  let prefix = '';
  let rt = target;
  const i = rt.indexOf('://');
  if (i >= 0) {
    const rest = rt.slice(i + 3);
    let end = rest.search(/[/?#]/);
    if (end < 0) end = rest.length;
    prefix = `${rt.slice(0, i)}://${rest.slice(0, end)}`;
    rt = rest.slice(end);
  }
  const h = rt.indexOf('#');
  const fragment = h < 0 ? undefined : rt.slice(h + 1);
  if (h >= 0) rt = rt.slice(0, h);
  const q = rt.indexOf('?');
  const path = q < 0 ? rt : rt.slice(0, q);
  let out = prefix + removeDotSegments(normalizeComponent(path, true));
  if (q >= 0) out += `?${normalizeComponent(rt.slice(q + 1), false)}`;
  if (fragment !== undefined) out += `#${fragment}`;
  return out;
}

function normalizeComponent(s: string, isPath: boolean): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    let c = escapeAt(s, i);
    if (c === undefined) {
      out += s[i];
      continue;
    }
    i += 2;
    const next = escapeAt(s, i + 1);
    if (next !== undefined && (c === 0xc0 || c === 0xc1) && (next & 0xc0) === 0x80) {
      c = ((c & 0x1f) << 6) | (next & 0x3f);
      i += 3;
    }
    if (isUnreservedByte(c) || (isPath && c === 0x2f)) out += String.fromCharCode(c);
    else out += `%${c.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

/**
 * remove_dot_segments of RFC 3986 5.2.4 for a path that starts with "/".
 * Another path is returned unchanged.
 */
function removeDotSegments(path: string): string {
  if (!path.startsWith('/')) return path;
  const out: string[] = [];
  const segments = path.split('/').slice(1);
  for (const [i, seg] of segments.entries()) {
    const last = i === segments.length - 1;
    if (seg === '.') {
      if (last) out.push('');
    } else if (seg === '..') {
      out.pop();
      if (last) out.push('');
    } else {
      out.push(seg);
    }
  }
  return `/${out.join('/')}`;
}

/** The octet of the escape at s[i], if there is one. */
function escapeAt(s: string, i: number): number | undefined {
  if (i + 2 >= s.length || s[i] !== '%') return undefined;
  const hex = s.slice(i + 1, i + 3);
  return /^[0-9A-Fa-f]{2}$/.test(hex) ? Number.parseInt(hex, 16) : undefined;
}

function isUnreservedByte(c: number): boolean {
  return /^[A-Za-z0-9\-._~]$/.test(String.fromCharCode(c));
}

/** The operation with the defects that change a mapped operation. */
function corrupt(b: Adapter, mapped: OperationContext, req: RawRequest): OperationContext {
  let op: OperationContext = { ...mapped, headers: { ...mapped.headers } };
  const qi = op.target_uri.indexOf('?');
  const query = qi < 0 ? '' : op.target_uri.slice(qi + 1);
  const noScheme = op.target_uri.startsWith('https://')
    ? op.target_uri.slice('https://'.length)
    : op.target_uri;
  const pathOnly = noScheme.split('?', 1)[0] as string;
  const slash = pathOnly.indexOf('/');
  const pathPart = slash < 0 ? '' : pathOnly.slice(slash + 1);

  if (b.has(Defect.FORWARDED_HOST_ORIGIN)) {
    const host = header(req, 'X-Forwarded-Host') || header(req, 'Host');
    op = { ...op, target_uri: `https://${host}/${pathPart}${query === '' ? '' : `?${query}`}` };
  }
  if (b.has(Defect.NORMALIZE_QUERY) && query !== '') {
    const v = new URLSearchParams(query);
    v.sort();
    op = { ...op, target_uri: `${op.target_uri.split('?', 1)[0]}?${v.toString()}` };
  }
  if (b.has(Defect.BODY_NOT_COVERED)) op = { ...op, body_digest: EMPTY_DIGEST as Digest };
  if (b.has(Defect.BLANK_EMPTY_DIGEST) && op.body_digest === EMPTY_DIGEST) {
    op = { ...op, body_digest: '' as Digest };
  }
  if (b.has(Defect.ECHO_ALL_HEADERS)) {
    const all = new Map<string, string[]>();
    for (const [name, value] of req.headers) {
      const k = name.toLowerCase();
      all.set(k, [...(all.get(k) ?? []), value]);
    }
    const headers: Record<string, string> = { ...op.headers };
    for (const [k, vals] of all) headers[k] = vals.join(', ');
    op = { ...op, headers };
  }
  if (b.has(Defect.TRUST_CLIENT_RESOURCES)) {
    const v = header(req, 'X-Resources');
    if (v !== '') op = { ...op, resources: [v] };
  }
  if (b.has(Defect.PRINCIPAL_FROM_HEADER)) {
    const v = header(req, 'X-Principal');
    if (v !== '') op = { ...op, principal_id: v };
  }
  return op;
}
