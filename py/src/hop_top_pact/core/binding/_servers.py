"""RawRequest from an ASGI scope or a WSGI environ. Standard library only.

Neither helper is on the conformance path, which builds a RawRequest with
decode_request. docs/sdk/probes/py.md lists what is still to probe against
real servers.
"""

from __future__ import annotations

import io
from collections.abc import Mapping
from typing import IO, Any, Final

from hop_top_pact.core.binding._config import DIGIT, lower_ascii
from hop_top_pact.core.binding._errors import RequestError, RequestErrorKind, Rule, refuse
from hop_top_pact.core.binding._request import RawRequest

_CHUNK: Final = 64 << 10


def _octets(b: bytes) -> str:
    """Header octets as text: UTF-8, with any other octet kept as a lone surrogate."""
    return b.decode("utf-8", "surrogateescape")


def from_asgi(scope: Mapping[str, Any], body: bytes) -> RawRequest:
    """The RawRequest of an ASGI HTTP connection scope and its body.

    body is the concatenation of the body members of the http.request
    messages, which an ASGI server hands over with the chunked coding
    removed. The request-target is raw_path, the path as the server received
    it, then "?" and query_string when the query is not empty: a scope cannot
    tell "/a?" from "/a", so an empty query is not bound. The decoded path is
    never read; a scope without raw_path (it is optional) is refused with
    Rule.TARGET_FORM. Header values are the octets sent, read as UTF-8 with
    "surrogateescape". A scope whose type is not "http" is refused with
    Rule.NO_REQUEST.

    Known limit: query_string is empty both for "/a?" and for "/a" (ASGI
    HTTP specification 2.5, connection scope), so a target with an empty
    query binds without its "?". What servers put in raw_path for an
    absolute-form target or a fragment is still to probe.
    """
    if scope.get("type") != "http":
        raise refuse(Rule.NO_REQUEST, "the ASGI scope is not an http connection")
    raw_path = scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        raise refuse(Rule.TARGET_FORM, "no raw request-target (the scope has no raw_path)")
    target = raw_path.decode("latin-1")
    query = scope.get("query_string", b"")
    if not isinstance(query, bytes):
        raise refuse(Rule.TARGET_FORM, "the scope's query_string is not a byte string")
    if query:
        target += "?" + query.decode("latin-1")
    method = scope.get("method")
    headers = tuple(
        (bytes(n).decode("latin-1"), _octets(bytes(v))) for n, v in scope.get("headers", ())
    )
    return RawRequest(
        method=method if isinstance(method, str) else "",
        raw_request_uri=target,
        headers=headers,
        body=bytes(body),
    )


def _native(s: str) -> str:
    """A PEP 3333 native string (Latin-1 code points) as header text: UTF-8, surrogateescape."""
    try:
        return _octets(s.encode("latin-1"))
    except UnicodeEncodeError:
        return s


class _Rest(io.RawIOBase):
    """The octets already read, then the rest of the original input."""

    def __init__(self, head: bytes, rest: IO[bytes]) -> None:
        self._head = io.BytesIO(head)
        self._rest = rest

    def readable(self) -> bool:
        return True

    def read(self, size: int | None = -1) -> bytes:
        n = -1 if size is None else size
        b = self._head.read(n)
        if n < 0:
            return b + self._rest.read()
        if len(b) < n:
            b += self._rest.read(n - len(b))
        return b


def from_wsgi(environ: dict[str, Any], *, max_body: int | None = None) -> RawRequest:
    """The RawRequest of a WSGI environ.

    PEP 3333 gives only a decoded PATH_INFO, so the request-target is
    RAW_URI (gunicorn) or REQUEST_URI (nginx's uwsgi_params), when the server
    sets one; otherwise the request is refused with Rule.TARGET_FORM ("no raw
    request-target"), and no target is rebuilt from the decoded parts.

    The header lines are CONTENT_TYPE, CONTENT_LENGTH (when not empty) and
    every HTTP_ variable, in environ order, named by lowercasing and putting
    "-" for "_".

    Known limits. The environ holds one value per name: a server that joined
    several field lines into it decides the separator, and gunicorn
    (gunicorn/http/wsgi.py) and the standard library's wsgiref
    (wsgiref.simple_server) join with "," where the baseline normalization
    joins with ", ", so such a header binds another value; other servers are
    still to probe. wsgiref also sets CONTENT_TYPE to "text/plain" when the
    request has no Content-Type, so a body without one is bound with that
    content type. A header name with "_" maps to the same HTTP_ key as the
    one with "-" (PEP 3333 gives no rule; server handling to probe). Two
    Host field lines arrive as one HTTP_HOST (wsgiref joins them with ","),
    so Rule.DUPLICATE_HOST cannot be applied; such a server must refuse the
    request itself (RFC 9112 3.2). A request without Host has no HTTP_HOST
    (SERVER_NAME is not read), so an origin-form one is refused with
    Rule.MISSING_HOST; wsgiref passes any Host value on, and an invalid one is
    refused with Rule.INVALID_HOST. What gunicorn, which sets RAW_URI, does
    with a missing or invalid Host is still to probe.

    The body is CONTENT_LENGTH octets of wsgi.input; without CONTENT_LENGTH
    it is empty, unless a Transfer-Encoding is present, when wsgi.input is
    read to its end (the server has removed the chunked coding, PEP 3333).
    With max_body, a declared length over it is refused with
    Rule.BODY_TOO_LARGE before anything is read, and an undeclared body is
    read one octet past it at most. A read that fails or ends early, or a
    malformed CONTENT_LENGTH, is RequestErrorKind.BODY_READ. Afterwards
    wsgi.input yields the whole body again: an in-memory copy, or after a
    refusal the octets read followed by the rest of the original input.
    """
    target = environ.get("RAW_URI")
    if not isinstance(target, str):
        target = environ.get("REQUEST_URI")
    if not isinstance(target, str):
        raise refuse(Rule.TARGET_FORM, "no raw request-target (no RAW_URI or REQUEST_URI)")
    headers: list[tuple[str, str]] = []
    for key, value in environ.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            if value == "":
                continue
            name = key
        elif key.startswith("HTTP_"):
            name = key[5:]
        else:
            continue
        headers.append((lower_ascii(name.replace("_", "-")), _native(value)))
    method = environ.get("REQUEST_METHOD")
    return RawRequest(
        method=method if isinstance(method, str) else "",
        raw_request_uri=_native(target),
        headers=tuple(headers),
        body=_read_body(environ, max_body),
    )


def _body_read_error(detail: str) -> RequestError:
    return RequestError(None, detail, RequestErrorKind.BODY_READ)


def _read_body(environ: dict[str, Any], max_body: int | None) -> bytes:
    declared = environ.get("CONTENT_LENGTH", "")
    stream: Any = environ.get("wsgi.input")
    if declared:
        if not isinstance(declared, str) or not all(c in DIGIT for c in declared):
            raise _body_read_error(f"CONTENT_LENGTH {declared!r} is not a decimal length")
        n = int(declared)
        if max_body is not None and n > max_body:
            raise refuse(Rule.BODY_TOO_LARGE, f"CONTENT_LENGTH {n} is over {max_body}")
        body = _read(stream, n)
        if len(body) < n:
            raise _body_read_error(f"the body ended after {len(body)} of {n} octets")
    elif "HTTP_TRANSFER_ENCODING" in environ:
        limit = None if max_body is None else max_body + 1
        body = _read(stream, limit)
        if max_body is not None and len(body) > max_body:
            environ["wsgi.input"] = _Rest(body, stream)
            raise refuse(Rule.BODY_TOO_LARGE, f"the body is over {max_body} octets")
    else:
        return b""
    environ["wsgi.input"] = io.BytesIO(body)
    return body


def _read(stream: Any, limit: int | None) -> bytes:
    """Up to limit octets of stream (to its end when limit is None)."""
    out = bytearray()
    try:
        while limit is None or len(out) < limit:
            want = _CHUNK if limit is None else min(_CHUNK, limit - len(out))
            b = stream.read(want)
            if not b:
                break
            out += b
    except Exception as e:
        raise _body_read_error(f"wsgi.input: {e}") from e
    return bytes(out)
