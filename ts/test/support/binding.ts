// Helpers of the binding tests, after go/core/binding/helpers_test.go. A Go
// request parsed by net/http or built by hand is a RawRequest here; a request
// sent to a real server is sent to a node:http server, whose handler reads
// it with fromIncomingMessage.

import assert from 'node:assert/strict';
import { createServer, type IncomingMessage } from 'node:http';
import { type AddressInfo, connect, type Socket } from 'node:net';
import {
  type Config,
  fromIncomingMessage,
  fromRequest,
  type IncomingBinding,
  type RawRequest,
  RequestError,
  type Rule,
} from '../../src/core/binding/index.ts';
import type { OperationContext } from '../../src/core/types.ts';

/** The public origin of the draft Appendix B gateway. */
export const ORIGIN = 'https://gateway.example';

/** body_digest of draft Appendix B.3: SHA-256 of zero bytes, base64url. */
export const EMPTY_BODY_DIGEST = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';

/** SHA-256("abc"), the FIPS 180-4 example, base64url without padding. */
export const ABC_DIGEST = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

export const PRINCIPAL = 'https://identity.example/principals/alice';
export const ACTION = 'invoice.read';
export const RESOURCE = 'https://invoices.example/invoices/INV-1042';

/** A configuration that can be edited before use. */
export type MutableConfig = { -readonly [K in keyof Config]: Config[K] };

/**
 * A valid configuration: the origin of Appendix B and the
 * protected_header_names and identifiers of Appendix B.13.
 */
export function config(): MutableConfig {
  return {
    origin: ORIGIN,
    headerAllowlist: ['if-match', 'x-dry-run'],
    headerNormalizationId: 'finance-header-normalization-1',
    mappingVersion: 'finance-http-1',
    maxBody: 1 << 20,
  };
}

const latin1 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'latin1'));

/** The UTF-8 bytes of s. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** A request with the given field lines and body. */
export function request(
  method: string,
  target: string,
  headers: ReadonlyArray<readonly [string, string]> = [['Host', 'gateway.example']],
  body: Uint8Array | string = new Uint8Array(),
): RawRequest {
  return {
    method,
    rawRequestURI: target,
    headers,
    body: typeof body === 'string' ? utf8(body) : body,
  };
}

/** A GET request for target with a Host field line. */
export function get(target: string): RawRequest {
  return request('GET', target);
}

/**
 * The text of an HTTP/1.1 request as a RawRequest: the request line, then
 * every field line split at its first colon, the value as after the colon,
 * then the body after the empty line. No transfer decoding.
 */
export function parse(raw: string): RawRequest {
  const end = raw.indexOf('\r\n\r\n');
  assert.ok(end >= 0, `no empty line in ${JSON.stringify(raw)}`);
  const [line = '', ...fields] = raw.slice(0, end).split('\r\n');
  const parts = line.split(' ');
  assert.equal(parts.length, 3, `request line ${JSON.stringify(line)}`);
  const headers = fields.map((f) => {
    const colon = f.indexOf(':');
    assert.ok(colon > 0, `field line ${JSON.stringify(f)}`);
    return [f.slice(0, colon), f.slice(colon + 1)] as const;
  });
  return request(parts[0] ?? '', parts[1] ?? '', headers, raw.slice(end + 4));
}

/** fromRequest with the test principal, action and resource. */
export function from(cfg: Config, req: RawRequest | null | undefined): OperationContext {
  return fromRequest(cfg, req, PRINCIPAL, ACTION, [RESOURCE]);
}

/** Fails unless err is a RequestError of kind INVALID_REQUEST under rule. */
export function wantRule(err: unknown, rule: Rule): void {
  assert.ok(
    err instanceof RequestError,
    `error ${String(err)} is not a RequestError, want ${rule}`,
  );
  assert.equal(err.kind, 'INVALID_REQUEST', `kind of ${err.message}`);
  assert.equal(err.rule, rule, `rule of ${err.message}`);
}

/** Fails unless fn throws a refusal under rule. */
export function wantRefused(fn: () => unknown, rule: Rule): void {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err !== undefined, `no error, want rule ${rule}`);
  wantRule(err, rule);
}

/** Fails unless err is a RequestError of the kind. */
export function wantKind(err: unknown, kind: RequestError['kind']): void {
  assert.ok(
    err instanceof RequestError,
    `error ${String(err)} is not a RequestError, want ${kind}`,
  );
  assert.equal(err.kind, kind, err.message);
}

/** fromRequest, failing on any error. */
export function mustBind(cfg: Config, req: RawRequest): OperationContext {
  return from(cfg, req);
}

/** What a node:http server did with a request sent over a TCP connection. */
export interface Wire<T> {
  /** The status line of the response. */
  readonly status: string;
  /** Whether the request handler ran; false when the parser answered itself. */
  readonly called: boolean;
  readonly value?: T;
  readonly error?: unknown;
}

/**
 * Sends raw (a string is sent as latin1, one octet per character) to a
 * node:http server and runs handler on the request it receives. With
 * `abort`, the client closes the connection once raw is written.
 */
export function overWire<T>(
  raw: string | Uint8Array,
  handler: (msg: IncomingMessage) => Promise<T>,
  opts: { readonly abort?: boolean } = {},
): Promise<Wire<T>> {
  return new Promise((resolve, reject) => {
    let called = false;
    let outcome: { value?: T; error?: unknown } = {};
    let handled: Promise<void> = Promise.resolve();
    const serverClosed: Promise<void>[] = [];
    const srv = createServer((req, res) => {
      called = true;
      handled = Promise.resolve()
        .then(() => handler(req))
        .then(
          (value) => {
            outcome = { value };
          },
          (error: unknown) => {
            outcome = { error };
          },
        )
        .finally(() => {
          res.setHeader('connection', 'close');
          res.end();
        });
    });
    srv.on('connection', (s: Socket) => {
      serverClosed.push(new Promise((r) => s.on('close', () => r())));
    });
    const timer = setTimeout(() => {
      srv.closeAllConnections();
      srv.close();
      reject(new Error('no answer from the server within 5 s'));
    }, 5000);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as AddressInfo;
      let text = '';
      const c = connect(port, '127.0.0.1', () => {
        c.write(typeof raw === 'string' ? latin1(raw) : raw, () => {
          if (opts.abort) c.destroy();
        });
      });
      c.on('data', (d: Buffer) => {
        text += d.toString('latin1');
      });
      c.on('error', reject);
      c.on('close', () => {
        void (async () => {
          await Promise.all(serverClosed);
          await handled;
          clearTimeout(timer);
          srv.close();
          resolve({ status: text.split('\r\n')[0] ?? '', called, ...outcome });
        })();
      });
    });
  });
}

/** Sends raw to a server whose handler runs fromIncomingMessage under cfg. */
export async function bind(cfg: Config, raw: string | Uint8Array): Promise<IncomingBinding> {
  const w = await overWire(raw, (msg) =>
    fromIncomingMessage(cfg, msg, PRINCIPAL, ACTION, [RESOURCE]),
  );
  assert.ok(w.called, `handler not called; server answered ${JSON.stringify(w.status)}`);
  if (w.error !== undefined) throw w.error;
  assert.ok(w.value);
  return w.value;
}

/** bind, expecting a refusal under rule. */
export async function bindRefused(
  cfg: Config,
  raw: string | Uint8Array,
  rule: Rule,
): Promise<void> {
  let err: unknown;
  try {
    await bind(cfg, raw);
  } catch (e) {
    err = e;
  }
  assert.ok(err !== undefined, `no error, want rule ${rule}`);
  wantRule(err, rule);
}
