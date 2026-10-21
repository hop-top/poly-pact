/**
 * The coding and body rules of the baseline binding (Go body.go).
 *
 * @module
 */
import { equalFoldASCII, trimOWS } from './chars.ts';
import { Rule, refuse } from './errors.ts';

type Lines = ReadonlyArray<readonly [name: string, value: string]>;

/**
 * Refuses a request with any Content-Encoding field, since the baseline
 * forbids HTTP content encodings on protected requests (draft 10.2), and one
 * with a transfer coding other than chunked, the only one a server decodes,
 * so the body would not be known to be transfer-decoded.
 */
export function checkCodings(headers: Lines): void {
  for (const [name] of headers) {
    if (equalFoldASCII(name, 'content-encoding')) {
      throw refuse(Rule.CONTENT_ENCODING, 'the request has a Content-Encoding field');
    }
  }
  for (const [name, value] of headers) {
    if (!equalFoldASCII(name, 'transfer-encoding')) continue;
    for (const part of value.split(',')) {
      const c = trimOWS(part);
      if (c !== '' && !equalFoldASCII(c, 'chunked')) {
        throw refuse(
          Rule.TRANSFER_CODING,
          `the request has the transfer coding ${JSON.stringify(c)}`,
        );
      }
    }
  }
}

/**
 * Refuses a body over max bytes: one that a Content-Length field line
 * declares, before the body is looked at, or the body itself.
 */
export function checkBody(headers: Lines, body: Uint8Array, max: number): void {
  for (const [name, value] of headers) {
    if (!equalFoldASCII(name, 'content-length')) continue;
    const v = trimOWS(value);
    if (/^[0-9]+$/.test(v) && BigInt(v) > BigInt(max)) {
      throw refuse(Rule.BODY_TOO_LARGE, `Content-Length ${v} is over ${max}`);
    }
  }
  if (body.length > max) throw refuse(Rule.BODY_TOO_LARGE, `the body is over ${max} bytes`);
}
