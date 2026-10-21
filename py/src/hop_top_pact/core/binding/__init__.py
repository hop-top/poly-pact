"""Baseline HTTP request binding (draft section 10.2). Mirrors hop.top/pact-go/core/binding.

from_request derives the operation context of the baseline HTTP mapping from
a RawRequest, the request as a gateway received it, and the gateway's
Config. It fills method, target_uri, body_digest and headers, and copies the
principal, action and resources the caller derived from the authenticated
request and its mapping rules. The caller sets operation_id and
environment_id. The caller also records Config.mapping_version when it
issues a requirement contract and checks that the same version is installed
when it validates the actual operation.

decode_request reads the JSON request object of the binding vectors and of
the adapter case files into a RawRequest; it is the conformance path.
from_asgi and from_wsgi build one from an ASGI scope or a WSGI environ.

Rules
-----

method is the request method in uppercase. Only ASCII letters are accepted,
as the schema pattern ^[A-Z]+$ requires (Rule.METHOD).

target_uri is Config.origin, normalized, followed by the exact path and query
of the request-target. Octets, percent-encoding and query order are kept.
Host, Forwarded and X-Forwarded-* headers are not read.

- The origin is https. Its scheme and host are lowercased and port 443 is
  dropped (RFC 3986 3.2.2, 6.2.2.1, 6.2.3; RFC 9110 4.2.2, 4.2.3).
- The request-target is origin-form or http(s) absolute-form (RFC 9112 3.2).
  The authority of an absolute-form target is checked and then dropped.
  Asterisk-form, authority-form, other schemes, an empty host and an
  absolute-form target with an empty path are refused (Rule.TARGET_FORM).
- A fragment is refused (Rule.FRAGMENT): the target URI excludes it (RFC
  3986 3.5; RFC 9110 7.1), and neither origin-form nor absolute-form carries
  one. Userinfo is refused (Rule.USERINFO; RFC 9110 4.2.4).
- A host with a non-ASCII character or a percent-encoding, which in a host
  only represents UTF-8, is refused (Rule.NON_ASCII_HOST; RFC 3986 3.2.2). In
  the configured origin it is a configuration error.
- Every character of the path and query is one RFC 3986 3.3 and 3.4 allow
  there, so non-ASCII, space, controls, "[", "]" and similar are refused
  (Rule.INVALID_CHARACTER), and every "%" starts a triplet of RFC 3986 2.1
  (Rule.MALFORMED_ESCAPE).
- Ambiguous encodings are refused, never normalized (draft 10.2): a
  percent-encoded unreserved character such as %41 or %2E
  (Rule.ENCODED_UNRESERVED; RFC 3986 2.3, 6.2.2.2); a lowercase hex digit in
  an escape (Rule.LOWERCASE_HEX; RFC 3986 2.1, 6.2.2.1); decoded octets that
  are not valid UTF-8, overlong forms and surrogates included
  (Rule.INVALID_UTF8; RFC 3629 3, 10); %2F in the path (Rule.ENCODED_SLASH);
  and a complete "." or ".." path segment (Rule.DOT_SEGMENT; RFC 3986 3.3,
  5.2.4, 6.2.2.3). Segments are delimited by "/" only, so "a..b", "..." and
  dots in the query are kept. %2F in the query is data. Other escapes, such
  as %00, %25 and %5C, and empty segments are kept as sent.
- target_uri has at most 1024 characters (Rule.TARGET_TOO_LONG).

body_digest is bytes_digest of RawRequest.body, the body after transfer
decoding. An empty body hashes the empty byte string. Any Content-Encoding
field is refused (Rule.CONTENT_ENCODING), as is a transfer coding other than
chunked (Rule.TRANSFER_CODING) and a body over Config.max_body
(Rule.BODY_TOO_LARGE).

headers holds the headers of Config.header_allowlist that are present, under
lowercase names, plus content-type when the body is not empty. A value is
each field line without leading and trailing SP and HTAB, joined in order
with ", " (RFC 9110 5.2, 5.3, 5.5). A name the request lists in a Connection
field is hop-by-hop for that request and is left out (RFC 9110 7.6.1). A
value with a control character other than HTAB (RFC 9110 5.5), or that is
not UTF-8 and so cannot be carried exactly in PACT JSON (draft 7.1), is
refused (Rule.HEADER_VALUE), as is one over 8192 characters
(Rule.HEADER_TOO_LONG). Header names match without regard to
ASCII case only.

A request with more than one Host field line, with names in any case and
whatever the values, is refused (Rule.DUPLICATE_HOST; RFC 9112 3.2), as is
an origin-form request without one (Rule.MISSING_HOST): an absolute-form
target carries its own authority (RFC 9112 3.2.2), and an ASGI server gives
HTTP/2 :authority as the host header (ASGI 2.5). A Host value that is not
uri-host [ ":" port ] with a non-empty host is refused (Rule.INVALID_HOST;
RFC 9110 4.2.2, 7.2; RFC 3986 3.2.2, 3.2.3).

These names cannot be allowlisted: authorization, cookie and set-cookie;
every pact- name; connection, keep-alive, te, transfer-encoding, upgrade and
every proxy- name; signature and signature-input; host, which never selects
the origin. The allowlist and content-type together have at most 64 names.

Rule.HEADER_KEY_COLLISION is Go's refusal of a header stored under two map
keys that differ only in case, whose field lines lose their order. A
RawRequest keeps every field line in order, so from_request never raises it.

Errors
------

Every error is a RequestError, a PactError: kind INVALID_REQUEST for a
refused request, whose rule names the rule (INVALID_MESSAGE of draft 13.4);
INVALID_CONFIG for an unusable Config; BODY_READ for a body that could not
be read (from_wsgi only). The package does not import the adapter package,
so a caller maps these to its own codes.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import MappingProxyType

from hop_top_pact.core.binding._config import MAX_TARGET_URI, Config
from hop_top_pact.core.binding._errors import RequestError, RequestErrorKind, Rule, refuse
from hop_top_pact.core.binding._headers import check_codings, check_host, select_headers
from hop_top_pact.core.binding._request import (
    RawRequest,
    RequestObjectError,
    TLSPeer,
    decode_request,
)
from hop_top_pact.core.binding._servers import from_asgi, from_wsgi
from hop_top_pact.core.binding._target import request_target, uppercase_method
from hop_top_pact.core.digest import bytes_digest
from hop_top_pact.core.types import OperationContext

__all__ = [
    "Config",
    "RawRequest",
    "RequestError",
    "RequestErrorKind",
    "RequestObjectError",
    "Rule",
    "TLSPeer",
    "decode_request",
    "from_asgi",
    "from_request",
    "from_wsgi",
]


def from_request(
    cfg: Config,
    req: RawRequest | None,
    principal_id: str,
    action: str,
    resources: Sequence[str],
) -> OperationContext:
    """Derive the operation context of the baseline HTTP mapping (draft 10.2) from req.

    The principal, action and resources are the caller's: it derives them
    from the authenticated request and its installed mapping rules, never
    from a list the client supplied. They are copied as given. operation_id
    and environment_id are left empty for the caller to set; the 20.1 limits
    are not checked here (core.limits.validate_operation does).

    The checks run in Go's order: configuration, method, target, target
    length, Host field lines, codings, body, headers. Raises RequestError.
    """
    origin, allow = cfg.prepare()
    if req is None:
        raise refuse(Rule.NO_REQUEST, "no request")
    method = uppercase_method(req.method)
    target = origin + request_target(req.raw_request_uri)
    if len(target) > MAX_TARGET_URI:
        raise refuse(
            Rule.TARGET_TOO_LONG,
            f"target_uri has {len(target)} characters, at most {MAX_TARGET_URI}",
        )
    lines = tuple(req.headers)
    check_host(lines, req.raw_request_uri.startswith("/"))
    check_codings(lines)
    body = bytes(req.body)
    if len(body) > cfg.max_body:
        raise refuse(Rule.BODY_TOO_LARGE, f"the body is over {cfg.max_body} octets")
    headers = select_headers(lines, allow, len(body) > 0)
    return OperationContext(
        operation_id="",
        environment_id="",
        principal_id=principal_id,
        action=action,
        resources=tuple(resources),
        method=method,
        target_uri=target,
        body_digest=bytes_digest(body),
        headers=MappingProxyType(headers),
    )
