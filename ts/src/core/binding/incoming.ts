/**
 * The `node:http` front of the binding, outside the conformance path: a
 * {@link RawRequest} read from an `IncomingMessage`.
 *
 * What `node:http` hides (docs/sdk/probes/ts.md, P1):
 *
 * - field values arrive without their leading and trailing whitespace, which
 *   the baseline normalization removes anyway;
 * - chunked framing and chunk extensions are gone; the body arrives
 *   transfer-decoded and `Transfer-Encoding` stays in the field lines;
 * - trailer fields are in `rawTrailers`, not in the field lines, and are not
 *   bound;
 * - field values are octets read one per character (latin1); they are
 *   decoded as UTF-8 here, and an octet outside a well-formed sequence
 *   becomes a lone surrogate, so a covered header that is not UTF-8 is
 *   refused as `HEADER_VALUE`;
 * - the parser answers 400 itself to a raw non-ASCII octet or a space in the
 *   request-target, a lowercase method, a missing `Host`, obs-fold, a control
 *   character in a field value, and `Content-Length` with `Transfer-Encoding`;
 * - a second `Host` field line is accepted; both lines are in `rawHeaders`,
 *   so the binding refuses the request (`DUPLICATE_HOST`; RFC 9112 3.2).
 *
 * The binding rules do not rely on any of the parser's refusals: the same
 * request given as a {@link RawRequest} is refused by the rules themselves.
 *
 * @module
 */
import type { IncomingMessage } from 'node:http';
import type { OperationContext } from '../types.ts';
import { checkMaxBody, prepare } from './config.ts';
import { RequestError, Rule, refuse } from './errors.ts';
import { type Config, fromRequest, type RawRequest } from './index.ts';

/** The result of {@link fromIncomingMessage}. */
export interface IncomingBinding {
  /** The operation context, `operation_id` and `environment_id` empty. */
  readonly operation: OperationContext;
  /** The request as read; its `body` is the only copy of the body left. */
  readonly request: RawRequest;
}

/**
 * Reads `msg` to its end as a {@link RawRequest}. A body over `maxBody`
 * bytes, declared by `Content-Length` or found while reading, is refused
 * (`BODY_TOO_LARGE`) and `msg` then still yields every byte of it. A body
 * that cannot be read to its end, or a message already read, is a
 * {@link RequestError} of kind `BODY_READ`; a `maxBody` that is not a
 * non-negative safe integer is one of kind `INVALID_CONFIG`.
 */
export async function readIncomingMessage(
  msg: IncomingMessage,
  maxBody: number,
): Promise<RawRequest> {
  checkMaxBody(maxBody);
  const headers: [string, string][] = [];
  for (let i = 0; i + 1 < msg.rawHeaders.length; i += 2) {
    headers.push([octets(msg.rawHeaders[i] ?? ''), octets(msg.rawHeaders[i + 1] ?? '')]);
  }
  const declared = msg.headers['content-length'];
  if (declared !== undefined && /^[0-9]+$/.test(declared) && BigInt(declared) > BigInt(maxBody)) {
    throw refuse(Rule.BODY_TOO_LARGE, `Content-Length ${declared} is over ${maxBody}`);
  }
  const body = await readBody(msg, maxBody);
  return {
    method: msg.method ?? '',
    rawRequestURI: octets(msg.url ?? ''),
    headers,
    body,
  };
}

/**
 * {@link readIncomingMessage} then {@link fromRequest}, after checking `cfg`.
 * The request stream is single use, so the body read is returned with the
 * operation context; a caller that needs it after a refusal calls the two
 * functions itself.
 */
export async function fromIncomingMessage(
  cfg: Config,
  msg: IncomingMessage,
  principalId: string,
  action: string,
  resources: readonly string[],
): Promise<IncomingBinding> {
  prepare(cfg);
  const request = await readIncomingMessage(msg, cfg.maxBody);
  return { operation: fromRequest(cfg, request, principalId, action, resources), request };
}

/**
 * The body of msg, at most max bytes. Over max, the bytes taken are put back
 * and the stream paused, so that msg yields the whole body again.
 */
function readBody(msg: IncomingMessage, max: number): Promise<Uint8Array> {
  if (msg.readableDidRead || msg.readableEnded || msg.destroyed) {
    return Promise.reject(
      new RequestError('BODY_READ', '', 'the request body has already been read'),
    );
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const stop = () => {
      msg.off('data', onData);
      msg.off('end', onEnd);
      msg.off('error', onError);
      msg.off('close', onClose);
    };
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size <= max) return;
      stop();
      msg.pause();
      msg.unshift(Buffer.concat(chunks));
      reject(refuse(Rule.BODY_TOO_LARGE, `the body is over ${max} bytes`));
    };
    const onEnd = () => {
      stop();
      resolve(new Uint8Array(Buffer.concat(chunks)));
    };
    const onError = (err: Error) => {
      stop();
      reject(new RequestError('BODY_READ', '', err.message, { cause: err }));
    };
    const onClose = () => {
      stop();
      reject(new RequestError('BODY_READ', '', 'the connection closed before the body ended'));
    };
    msg.on('data', onData);
    msg.on('end', onEnd);
    msg.on('error', onError);
    msg.on('close', onClose);
  });
}

/**
 * A string of octets, one per character as node:http gives them, decoded as
 * UTF-8; an octet outside a well-formed sequence becomes the lone surrogate
 * U+DC80 to U+DCFF of its value.
 */
function octets(s: string): string {
  const b = Buffer.from(s, 'latin1');
  try {
    return strict.decode(b);
  } catch {
    return escapeDecode(b);
  }
}

const strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** UTF-8 decoding with each octet of an ill-formed sequence escaped to U+DC00 + octet. */
function escapeDecode(b: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i < b.length) {
    const n = sequenceLength(b, i);
    if (n === 0) {
      out += String.fromCharCode(0xdc00 + (b[i] ?? 0));
      i++;
    } else {
      out += strict.decode(b.subarray(i, i + n));
      i += n;
    }
  }
  return out;
}

/** The length of the well-formed UTF-8 sequence at b[i] (RFC 3629 4), or 0. */
function sequenceLength(b: Uint8Array, i: number): number {
  const c = b[i] ?? 0;
  const at = (k: number, lo = 0x80, hi = 0xbf) => {
    const x = b[i + k];
    return x !== undefined && x >= lo && x <= hi;
  };
  if (c < 0x80) return 1;
  if (c >= 0xc2 && c <= 0xdf) return at(1) ? 2 : 0;
  if (c === 0xe0) return at(1, 0xa0) && at(2) ? 3 : 0;
  if (c === 0xed) return at(1, 0x80, 0x9f) && at(2) ? 3 : 0;
  if (c >= 0xe1 && c <= 0xef) return at(1) && at(2) ? 3 : 0;
  if (c === 0xf0) return at(1, 0x90) && at(2) && at(3) ? 4 : 0;
  if (c >= 0xf1 && c <= 0xf3) return at(1) && at(2) && at(3) ? 4 : 0;
  if (c === 0xf4) return at(1, 0x80, 0x8f) && at(2) && at(3) ? 4 : 0;
  return 0;
}
