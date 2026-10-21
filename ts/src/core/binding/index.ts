/**
 * Baseline HTTP request binding (Go package hop.top/pact-go/core/binding):
 * derives the operation context of the baseline HTTP mapping (draft section
 * 10.2, spec/v1.0/profiles/request-binding.md) from a request as received.
 *
 * {@link fromRequest} fills `method`, `target_uri`, `body_digest` and
 * `headers` from a {@link RawRequest} and the gateway's {@link Config}, and
 * copies the principal, action and resources the caller derived from the
 * authenticated request and its mapping rules. The caller sets
 * `operation_id` and `environment_id`, records `Config.mappingVersion` when
 * it issues a requirement contract, and checks that the same version is
 * installed when it validates the actual operation.
 *
 * The rules are those of the Go package, applied to the request as received
 * rather than to a parsed `net/http` request:
 *
 * - `method` is the request method in uppercase. Only ASCII letters are
 *   accepted, as the schema pattern `^[A-Z]+$` requires ({@link Rule}
 *   `METHOD`).
 * - `target_uri` is `Config.origin`, normalized, followed by the exact path
 *   and query of the request-target. Octets, percent-encoding and query order
 *   are kept. `Host`, `Forwarded` and `X-Forwarded-*` are not read.
 *   - The origin is https; its scheme and host are lowercased and port 443
 *     is dropped (RFC 3986 3.2.2, 6.2.2.1, 6.2.3; RFC 9110 4.2.2, 4.2.3).
 *   - The request-target is origin-form or http(s) absolute-form (RFC 9112
 *     3.2). The authority of an absolute-form target is checked and then
 *     dropped. Asterisk-form, authority-form, other schemes, an empty host
 *     and an absolute-form target with an empty path are refused
 *     (`TARGET_FORM`).
 *   - A fragment is refused (`FRAGMENT`; RFC 3986 3.5, RFC 9110 7.1, RFC
 *     9112 3.2.1, 3.2.2), and so is userinfo (`USERINFO`; RFC 9110 4.2.4).
 *   - A host with a non-ASCII character or a percent-encoding is refused
 *     (`NON_ASCII_HOST`; RFC 3986 3.2.2); in the configured origin it is a
 *     configuration error.
 *   - Every octet of the path and query is one RFC 3986 3.3 and 3.4 allow
 *     there (`INVALID_CHARACTER`), and every `%` starts a triplet of RFC 3986
 *     2.1 (`MALFORMED_ESCAPE`).
 *   - Ambiguous encodings are refused, never normalized (draft 10.2): a
 *     percent-encoded unreserved character such as `%41` or `%2E`
 *     (`ENCODED_UNRESERVED`; RFC 3986 2.3, 6.2.2.2); a lowercase hex digit in
 *     an escape (`LOWERCASE_HEX`; RFC 3986 2.1, 6.2.2.1); decoded octets that
 *     are not valid UTF-8, overlong forms and surrogates included
 *     (`INVALID_UTF8`; RFC 3629 3, 10); `%2F` in the path (`ENCODED_SLASH`);
 *     and a complete `.` or `..` path segment (`DOT_SEGMENT`; RFC 3986 3.3,
 *     5.2.4, 6.2.2.3). Segments are delimited by `/` only, so `a..b`, `...`
 *     and dots in the query are kept. `%2F` in the query is data. Other
 *     escapes, such as `%00`, `%25` and `%5C`, and empty segments are kept.
 *   - `target_uri` has at most 1024 characters (`TARGET_TOO_LONG`).
 * - `body_digest` is `bytes_digest` of the body after transfer decoding; an
 *   empty body hashes the empty byte string. Any `Content-Encoding` field is
 *   refused (`CONTENT_ENCODING`), as is a transfer coding other than chunked
 *   (`TRANSFER_CODING`) and a body over `Config.maxBody`, declared by
 *   `Content-Length` or found (`BODY_TOO_LARGE`).
 * - `headers` holds the headers of `Config.headerAllowlist` that are
 *   present, under lowercase names, plus `content-type` when the body is not
 *   empty. A value is each field line without leading and trailing SP and
 *   HTAB, joined in order with `", "` (RFC 9110 5.2, 5.3, 5.5). A name that
 *   a `Connection` field lists is hop-by-hop for the request and left out
 *   (RFC 9110 7.6.1). A value with a control character other than HTAB (RFC
 *   9110 5.5), or that is not well-formed and so cannot be carried exactly in
 *   PACT JSON (draft 7.1), is refused (`HEADER_VALUE`), as is one over 8192
 *   characters (`HEADER_TOO_LONG`).
 * - A request with more than one `Host` field line, with names in any case
 *   and whatever the values, is refused (`DUPLICATE_HOST`; RFC 9112 3.2), as
 *   is an origin-form request without one (`MISSING_HOST`): an absolute-form
 *   target carries its own authority (RFC 9112 3.2.2), and a front that
 *   reads HTTP/2 gives `:authority` as the Host line. A Host value that is
 *   not `uri-host [ ":" port ]` with a non-empty host is refused
 *   (`INVALID_HOST`; RFC 9110 4.2.2, 7.2; RFC 3986 3.2.2, 3.2.3).
 *
 * These names cannot be allowlisted: `authorization`, `cookie` and
 * `set-cookie`; every `pact-` name; `connection`, `keep-alive`, `te`,
 * `transfer-encoding`, `upgrade` and every `proxy-` name; `signature` and
 * `signature-input`; `host`, which never selects the origin. The allowlist
 * and `content-type` together have at most 64 names.
 *
 * A {@link RawRequest} holds its field lines in order, so the Go rule
 * `HEADER_KEY_COLLISION` (one header under two map keys that differ only in
 * case, so that the order of its lines is lost) cannot arise here: lines of
 * one name in any case are joined in the order received. `NO_REQUEST` is a
 * missing request.
 *
 * Every error is a {@link RequestError}: kind `INVALID_CONFIG`,
 * `INVALID_REQUEST` (with the {@link Rule}; INVALID_MESSAGE of draft 13.4) or
 * `BODY_READ`.
 *
 * @module
 */
import { bytesDigest } from '../digest.ts';
import type { OperationContext } from '../types.ts';
import { checkBody, checkCodings } from './body.ts';
import { isAlpha } from './chars.ts';
import { MAX_TARGET_URI, prepare } from './config.ts';
import { Rule, refuse } from './errors.ts';
import { checkHost, selectHeaders } from './headers.ts';
import { requestTarget } from './target.ts';

export { RequestError, type RequestErrorKind, Rule } from './errors.ts';
export {
  fromIncomingMessage,
  type IncomingBinding,
  readIncomingMessage,
} from './incoming.ts';

/**
 * The installed baseline HTTP mapping of a gateway. Its values come from
 * trusted gateway configuration, never from the request.
 */
export interface Config {
  /**
   * The public HTTPS origin, `https://` host [`:` port], with no path, query,
   * fragment or userinfo. The scheme and host are lowercased and port 443 is
   * dropped. The host is ASCII: a registered name of unreserved and
   * sub-delims characters, a dotted IPv4 address, or a bracketed IPv6 address
   * without a zone.
   */
  readonly origin: string;
  /**
   * The application headers that can alter action semantics, published as
   * `GatewayMetadata.protected_header_names`: RFC 9110 tokens, matched
   * without regard to case and written lowercase.
   */
  readonly headerAllowlist: readonly string[];
  /** The header normalization, published as `GatewayMetadata.header_normalization_id`. */
  readonly headerNormalizationId: string;
  /**
   * The installed mapping version, `GatewayMetadata.operation_mapping_version`.
   * The binding only requires it to be set (draft 10.2).
   */
  readonly mappingVersion: string;
  /** The largest body in bytes, a safe integer; zero admits only an empty body. */
  readonly maxBody: number;
}

/** The configuration check (Go `Config.Validate`). */
export const Config = Object.freeze({
  /**
   * Throws a {@link RequestError} of kind `INVALID_CONFIG` unless `cfg` is
   * usable. {@link fromRequest} runs it on every request; a gateway can run
   * it at start-up.
   */
  validate(cfg: Config): void {
    prepare(cfg);
  },
});

/**
 * The attributes of a mutual-TLS client certificate, as the adapter
 * conformance cases give them (`tls_peer`). The binding does not read them.
 */
export interface TLSPeer {
  readonly subjectCN: string;
  readonly issuerCN: string;
  readonly dnsNames: readonly string[];
  readonly uris: readonly string[];
}

/**
 * A request as received on the wire: the request-target octet for octet,
 * every field line in the order received with its name as sent, and the body
 * after transfer decoding (the literal form of the binding vectors'
 * `request` object).
 *
 * Strings hold octets decoded as UTF-8. An octet that is not part of a
 * well-formed UTF-8 sequence is held as the lone surrogate U+DC80 to U+DCFF
 * of its value, as {@link fromIncomingMessage} produces, so such a string is
 * not well-formed.
 */
export interface RawRequest {
  readonly method: string;
  /** The request-target (RFC 9112 3.2), origin-form or absolute-form. */
  readonly rawRequestURI: string;
  /** Every field line, `[name, value]`, value as after the colon. */
  readonly headers: ReadonlyArray<readonly [name: string, value: string]>;
  readonly body: Uint8Array;
  /** The client certificate of a mutual-TLS connection; absent otherwise. */
  readonly tlsPeer?: TLSPeer;
}

/**
 * Derives the operation context of the baseline HTTP mapping (draft 10.2)
 * from `req`.
 *
 * The principal, action and resources are the caller's: it derives them
 * from the authenticated request and its installed mapping rules, never from
 * a list the client supplied; they are copied as given. `operation_id` and
 * `environment_id` are left empty for the caller to set, and the section
 * 20.1 limits are not checked (`validateOperation` does).
 *
 * Throws a {@link RequestError} of kind `INVALID_CONFIG` or
 * `INVALID_REQUEST`.
 */
export function fromRequest(
  cfg: Config,
  req: RawRequest | null | undefined,
  principalId: string,
  action: string,
  resources: readonly string[],
): OperationContext {
  const { origin, allow } = prepare(cfg);
  if (req === null || typeof req !== 'object') throw refuse(Rule.NO_REQUEST, 'no request');
  const method = uppercaseMethod(req.method);
  const target = origin + requestTarget(req.rawRequestURI);
  if (target.length > MAX_TARGET_URI) {
    throw refuse(
      Rule.TARGET_TOO_LONG,
      `target_uri has ${target.length} characters, at most ${MAX_TARGET_URI}`,
    );
  }
  checkHost(req.headers, req.rawRequestURI.startsWith('/'));
  checkCodings(req.headers);
  checkBody(req.headers, req.body, cfg.maxBody);
  const headers = selectHeaders(req.headers, allow, req.body.length > 0);
  return {
    operation_id: '',
    environment_id: '',
    principal_id: principalId,
    action,
    resources: [...resources],
    method,
    target_uri: target,
    body_digest: bytesDigest(req.body),
    headers,
  };
}

/**
 * The method in uppercase. Only ASCII letters are accepted, matching the
 * schema pattern ^[A-Z]+$ for method, so no Unicode case mapping can turn
 * another character into a letter.
 */
function uppercaseMethod(m: string): string {
  if (m === '') throw refuse(Rule.METHOD, 'empty method');
  for (let i = 0; i < m.length; i++) {
    if (!isAlpha(m.charCodeAt(i))) {
      throw refuse(Rule.METHOD, `method has a character other than an ASCII letter at offset ${i}`);
    }
  }
  return m.toUpperCase();
}
