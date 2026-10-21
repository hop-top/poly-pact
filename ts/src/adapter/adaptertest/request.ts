/**
 * The request of a case as the adapter receives it (Go
 * hop.top/pact-go/adapter/adaptertest, request.go).
 *
 * @module
 */
import type { RawRequest, TLSPeer } from '../../core/binding/index.ts';
import type { Request } from './casefile.ts';

/**
 * The octets of a `body_b64` member: standard base64 with padding, empty
 * for no body. Throws an `Error` for anything else.
 */
export function decodeBody(b64: string): Uint8Array {
  if (b64 === '') return new Uint8Array(0);
  const b = Buffer.from(b64, 'base64');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b.toString('base64') !== b64) {
    throw new Error('request.body_b64 is not standard padded base64');
  }
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

// An HTTP method is a token (RFC 9110 5.6.2).
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

// A percent sign that does not open an escape of two hex digits, which
// RFC 3986 2.1 does not allow in a URI.
const BAD_ESCAPE = /%(?![0-9A-Fa-f]{2})/;

/**
 * The request of a case before any credential is attached or the
 * enforcement point marks it, and its body octets. The url is the
 * request-target as the gateway received it, octet for octet, so a fragment
 * or userinfo reaches the adapter intact; the headers are the case's field
 * lines, a Host header included. The body is returned as well, for the check
 * that an adapter leaves what it reads. Throws an `Error` for a request no
 * gateway could have received: an empty or non-token method, a url or a
 * peer URI with a malformed escape, a body that is not base64.
 */
export function buildRequest(r: Request): { req: RawRequest; body: Uint8Array } {
  const body = decodeBody(r.body_b64);
  if (!TOKEN.test(r.method)) {
    throw new Error(`request: method ${JSON.stringify(r.method)} is not an HTTP token`);
  }
  if (r.url === '' || BAD_ESCAPE.test(r.url)) {
    throw new Error(`request: url ${JSON.stringify(r.url)} is not a request-target`);
  }
  let peer: TLSPeer | undefined;
  if (r.tlsPeer !== null) {
    for (const u of r.tlsPeer.uris) {
      if (BAD_ESCAPE.test(u)) {
        throw new Error(`request.tls_peer.uris: ${JSON.stringify(u)} is not a URI`);
      }
    }
    peer = Object.freeze({
      subjectCN: r.tlsPeer.subjectCN,
      issuerCN: r.tlsPeer.issuerCN,
      dnsNames: Object.freeze([...r.tlsPeer.dnsNames]),
      uris: Object.freeze([...r.tlsPeer.uris]),
    });
  }
  const req: RawRequest = Object.freeze({
    method: r.method,
    rawRequestURI: r.url,
    headers: Object.freeze(
      Object.entries(r.headers).map(([name, value]) => Object.freeze([name, value] as const)),
    ),
    body: body.slice(),
    ...(peer === undefined ? {} : { tlsPeer: peer }),
  });
  return { req, body };
}
