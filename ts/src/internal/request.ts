/**
 * The one decoder of a request object in the shared fixtures: the `request`
 * of a binding vector (spec/v1.0/fixtures/vectors/README.md) and the `request` of
 * an adapter conformance case (Go adapter/adaptertest `Request`).
 *
 * - A binding vector's request: `method`, `raw_request_uri`, `headers` as an
 *   array of `{"name", "value"}` field lines in the order received, and
 *   `body_b64`.
 * - A case's request: `method`, `url` (the request-target as the gateway
 *   received it), `headers` as an object of name to value, `body_b64`,
 *   `tls_peer` (`subject_cn`, `issuer_cn`, `dns_names`, `uris`),
 *   `native_state_ref` and `arrival`.
 *
 * `body_b64` is canonical standard base64 with padding, `""` for no body.
 *
 * @module
 */
import type { RawRequest, TLSPeer } from '../core/binding/index.ts';

/** The values of a case request's `arrival`; `''` when absent. */
export type Arrival = '' | 'enforcement_point' | 'direct';

/** A decoded request object. */
export interface DecodedRequest {
  readonly request: RawRequest;
  /** The case's `native_state_ref`; `''` when absent. */
  readonly nativeStateRef: string;
  readonly arrival: Arrival;
}

const MEMBERS = [
  'method',
  'raw_request_uri',
  'url',
  'headers',
  'body_b64',
  'tls_peer',
  'native_state_ref',
  'arrival',
];
const PEER_MEMBERS = ['subject_cn', 'issuer_cn', 'dns_names', 'uris'];
const ARRIVALS: readonly string[] = ['', 'enforcement_point', 'direct'];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function only(v: unknown, where: string, allowed: readonly string[]): Record<string, unknown> {
  if (!isObject(v)) throw new Error(`${where} is not a JSON object`);
  const extra = Object.keys(v).filter((k) => !allowed.includes(k));
  if (extra.length > 0) throw new Error(`${where} has unknown members ${JSON.stringify(extra)}`);
  return v;
}

function optString(v: unknown, where: string): string {
  if (v === undefined) return '';
  if (typeof v !== 'string') throw new Error(`${where} is not a string`);
  return v;
}

function optStrings(v: unknown, where: string): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
    throw new Error(`${where} is not an array of strings`);
  }
  return [...v];
}

/** A field name a request can carry: not empty, no SP, HTAB, CR, LF or colon. */
function headerName(n: string, where: string): string {
  if (n === '' || /[ \t\r\n:]/.test(n))
    throw new Error(`${where}: header name ${JSON.stringify(n)} is not valid`);
  return n;
}

function fieldLines(v: unknown, where: string): [string, string][] {
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) {
    return v.map((line, i) => {
      const at = `${where}[${i}]`;
      const f = only(line, at, ['name', 'value']);
      if (typeof f.name !== 'string' || typeof f.value !== 'string') {
        throw new Error(`${at} needs a string name and a string value`);
      }
      return [headerName(f.name, at), f.value];
    });
  }
  if (isObject(v)) {
    return Object.entries(v).map(([name, value]) => {
      if (typeof value !== 'string') throw new Error(`${where}.${name} is not a string`);
      return [headerName(name, where), value];
    });
  }
  throw new Error(`${where} is neither an array of field lines nor an object`);
}

/** Canonical standard base64 with padding (RFC 4648 section 4); "" is no body. */
function body(v: unknown, where: string): Uint8Array {
  const s = optString(v, where);
  const b = Buffer.from(s, 'base64');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || b.toString('base64') !== s) {
    throw new Error(`${where} is not canonical padded base64`);
  }
  return new Uint8Array(b);
}

function tlsPeer(v: unknown, where: string): TLSPeer | undefined {
  if (v === undefined || v === null) return undefined;
  const p = only(v, where, PEER_MEMBERS);
  return {
    subjectCN: optString(p.subject_cn, `${where}.subject_cn`),
    issuerCN: optString(p.issuer_cn, `${where}.issuer_cn`),
    dnsNames: optStrings(p.dns_names, `${where}.dns_names`),
    uris: optStrings(p.uris, `${where}.uris`),
  };
}

/**
 * Decodes a parsed request object of either form. Throws an `Error` naming
 * the member at fault, under `where`.
 */
export function decodeRequest(v: unknown, where = 'request'): DecodedRequest {
  const r = only(v, where, MEMBERS);
  const method = optString(r.method, `${where}.method`);
  if (method === '') throw new Error(`${where}.method is empty or absent`);
  const hasRaw = r.raw_request_uri !== undefined;
  if (hasRaw === (r.url !== undefined)) {
    throw new Error(`${where} needs exactly one of raw_request_uri and url`);
  }
  const targetMember = hasRaw ? 'raw_request_uri' : 'url';
  const target = optString(r[targetMember], `${where}.${targetMember}`);
  if (!hasRaw && target === '') throw new Error(`${where}.url is empty`);
  const arrival = optString(r.arrival, `${where}.arrival`);
  if (!ARRIVALS.includes(arrival)) {
    throw new Error(
      `${where}.arrival ${JSON.stringify(arrival)} is not enforcement_point or direct`,
    );
  }
  const peer = tlsPeer(r.tls_peer, `${where}.tls_peer`);
  const request: RawRequest = {
    method,
    rawRequestURI: target,
    headers: fieldLines(r.headers, `${where}.headers`),
    body: body(r.body_b64, `${where}.body_b64`),
    ...(peer === undefined ? {} : { tlsPeer: peer }),
  };
  return {
    request,
    nativeStateRef: optString(r.native_state_ref, `${where}.native_state_ref`),
    arrival: arrival as Arrival,
  };
}
