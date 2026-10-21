"""map_operation of the broken adapter, with its defects (Go
adapters/internal/broken, operation.go).

Go's map_operation reads the body from a stream, and BODY_NOT_RESTORED leaves
the stream empty. A RawRequest is frozen and its body is bytes: the defect's
attempt to leave the request it was handed without its body raises
FrozenInstanceError, which the suite reports as a defect of the adapter (an
exception that is not a PactError), in every case whose request has a body,
as Go's suite reports the body it finds consumed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Final
from urllib.parse import quote_plus, urlsplit

from broken.defects import Defect
from broken.errors import BrokenError
from hop_top_pact.adapter import InvalidMessage, Principal, Realm, UnsupportedRequirement
from hop_top_pact.adapters.memory.identity import header
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.binding._config import lower_ascii
from hop_top_pact.core.types import OperationContext
from hop_top_pact.errors import PactError

if TYPE_CHECKING:
    from broken.adapter import BrokenAdapter

__all__ = ["map_operation", "normalize_encoding", "without_userinfo"]

EMPTY_DIGEST: Final = (
    base64.urlsafe_b64encode(hashlib.sha256(b"").digest()).rstrip(b"=").decode("ascii")
)
"""The digest of the empty byte string."""

_HEX2: Final = re.compile(r"[0-9A-Fa-f]{2}", re.ASCII)
_UNRESERVED: Final = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


def map_operation(
    b: BrokenAdapter, req: RawRequest, p: Principal, mapping_version: str
) -> OperationContext:
    """The memory adapter's, with the mapping defects. The memory adapter maps a copy
    of req that the defects changed."""
    if b.has(Defect.IGNORE_REALM_MAPPING):
        g = b.state().gateway
        p = replace(p, realm=Realm(tenant_id=g.tenant_id, environment_id=g.environment_id))
    target = req.raw_request_uri
    headers = tuple(req.headers)
    if b.has(Defect.ACCEPT_FRAGMENT):
        target = target.split("#", 1)[0]
    if b.has(Defect.ACCEPT_USERINFO):
        target = without_userinfo(target)
    if b.has(Defect.ACCEPT_CONTENT_ENCODING):
        headers = tuple(h for h in headers if lower_ascii(h[0]) != "content-encoding")
    if b.has(Defect.NORMALIZE_AMBIGUOUS_ENCODING):
        target = normalize_encoding(target)
    copy = replace(req, raw_request_uri=target, headers=headers)

    failed: PactError | None = None
    try:
        op = b.base.map_operation(copy, p, mapping_version)
    except PactError as e:
        failed = e
    finally:
        if b.has(Defect.BODY_NOT_RESTORED) and req.body:
            # The digest is right; the request is left with nothing of its body.
            req.body = b""  # type: ignore[misc]
    if failed is not None:
        err: PactError = failed
        if b.has(Defect.WRONG_MALFORMED_CODE) and _wraps(err, InvalidMessage):
            # The message says what was wrong; the chain no longer holds the
            # InvalidMessage, only another code.
            err = UnsupportedRequirement(str(err))
        if b.has(Defect.LEAK_CREDENTIAL_IN_MAP_ERROR):
            authz = header(req, "Authorization") or ""
            cookie = header(req, "Cookie") or ""
            raise BrokenError(
                f"{err} (request had Authorization {authz!r} and Cookie {cookie!r})"
            ) from err
        raise err
    return _corrupt(b, op, req)


def _wraps(err: BaseException, cls: type[BaseException]) -> bool:
    """Whether err or an exception it wraps is a cls: Go's errors.Is of a sentinel."""
    seen: set[int] = set()
    e: BaseException | None = err
    while e is not None and id(e) not in seen:
        if isinstance(e, cls):
            return True
        seen.add(id(e))
        e = e.__cause__ if e.__cause__ is not None else e.__context__
    return False


def without_userinfo(rt: str) -> str:
    """The request-target without the userinfo of an absolute-form target."""
    scheme, sep, rest = rt.partition("://")
    if not sep:
        return rt
    end = _authority_end(rest)
    at = rest.rfind("@", 0, end)
    if at >= 0:
        rest = rest[at + 1 :]
    return scheme + "://" + rest


def _authority_end(rest: str) -> int:
    ends = [i for i in (rest.find(c) for c in "/?#") if i >= 0]
    return min(ends) if ends else len(rest)


def normalize_encoding(rt: str) -> str:
    """The path and query of a request-target as a lenient gateway reads them: an
    escape of an unreserved character, of "/" in the path, or an overlong two-octet
    form of either is decoded, every other escape is written with uppercase hex
    digits, and the dot segments of the path are removed (RFC 3986 5.2.4)."""
    prefix = ""
    scheme, sep, rest = rt.partition("://")
    if sep:
        end = _authority_end(rest)
        prefix, rt = scheme + "://" + rest[:end], rest[end:]
    rt, has_fragment, fragment = rt.partition("#")
    path, has_query, query = rt.partition("?")
    out = prefix + _remove_dot_segments(_normalize_component(path, True))
    if has_query:
        out += "?" + _normalize_component(query, False)
    if has_fragment:
        out += "#" + fragment
    return out


def _escape_at(s: str, i: int) -> int | None:
    """The octet of the escape at s[i], if there is one."""
    if i + 2 >= len(s) or s[i] != "%" or not _HEX2.fullmatch(s, i + 1, i + 3):
        return None
    return int(s[i + 1 : i + 3], 16)


def _normalize_component(s: str, is_path: bool) -> str:
    out: list[str] = []
    i = 0
    while i < len(s):
        c = _escape_at(s, i)
        if c is None:
            out.append(s[i])
            i += 1
            continue
        i += 2
        nxt = _escape_at(s, i + 1)
        if nxt is not None and c in (0xC0, 0xC1) and nxt & 0xC0 == 0x80:
            c, i = (c & 0x1F) << 6 | nxt & 0x3F, i + 3
        if c in _UNRESERVED or (is_path and c == ord("/")):
            out.append(chr(c))
        else:
            out.append(f"%{c:02X}")
        i += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    """remove_dot_segments of RFC 3986 5.2.4 for a path that starts with "/".
    Another path is returned unchanged."""
    if not path.startswith("/"):
        return path
    out: list[str] = []
    segments = path.split("/")[1:]
    for n, seg in enumerate(segments):
        last = n == len(segments) - 1
        if seg == ".":
            if last:
                out.append("")
        elif seg == "..":
            if out:
                out.pop()
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def _unescape_query(s: str) -> bytes | None:
    """s with "+" as a space and its escapes decoded, as Go's url.QueryUnescape; None
    for a malformed escape."""
    raw = s.encode("utf-8", "surrogateescape")
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == ord("%"):
            hx = raw[i + 1 : i + 3]
            if len(hx) != 2 or not _HEX2.fullmatch(hx.decode("latin-1")):
                return None
            out.append(int(hx, 16))
            i += 3
            continue
        out.append(ord(" ") if c == ord("+") else c)
        i += 1
    return bytes(out)


def _reencode_query(query: str) -> str | None:
    """query parsed and encoded again as Go's url.ParseQuery and Values.Encode do:
    sorted by key, each value escaped; None when it does not parse."""
    values: dict[bytes, list[bytes]] = {}
    for part in query.split("&"):
        if not part:
            continue
        if ";" in part:
            return None
        k, _, v = part.partition("=")
        key, value = _unescape_query(k), _unescape_query(v)
        if key is None or value is None:
            return None
        values.setdefault(key, []).append(value)
    return "&".join(
        quote_plus(k, safe="") + "=" + quote_plus(v, safe="")
        for k in sorted(values)
        for v in values[k]
    )


def _host(req: RawRequest) -> str:
    """X-Forwarded-Host, else the Host header, else the authority of the
    request-target without userinfo: the host a Go server would report."""
    for name in ("X-Forwarded-Host", "Host"):
        v = header(req, name)
        if v:
            return v
    try:
        netloc = urlsplit(req.raw_request_uri).netloc
    except ValueError:
        return ""
    return netloc.rpartition("@")[2]


def _corrupt(b: BrokenAdapter, op: OperationContext, req: RawRequest) -> OperationContext:
    """The defects that change a mapped operation."""
    target = op.target_uri
    query = target.partition("?")[2] if "?" in target else ""
    path_only = target.removeprefix("https://").partition("?")[0]
    path_part = path_only.partition("/")[2]

    if b.has(Defect.FORWARDED_HOST_ORIGIN):
        target = "https://" + _host(req) + "/" + path_part
        if query:
            target += "?" + query
        op = replace(op, target_uri=target)
    if b.has(Defect.NORMALIZE_QUERY) and query:
        q = _reencode_query(query)
        if q is not None:
            op = replace(op, target_uri=op.target_uri.split("?", 1)[0] + "?" + q)
    if b.has(Defect.BODY_NOT_COVERED):
        op = replace(op, body_digest=EMPTY_DIGEST)
    if b.has(Defect.BLANK_EMPTY_DIGEST) and op.body_digest == EMPTY_DIGEST:
        op = replace(op, body_digest="")
    if b.has(Defect.ECHO_ALL_HEADERS):
        merged: dict[str, list[str]] = {}
        for name, value in req.headers:
            # A Go server keeps the Host header out of its header map.
            if lower_ascii(name) != "host":
                merged.setdefault(lower_ascii(name), []).append(value)
        hs = dict(op.headers)
        hs.update({k: ", ".join(v) for k, v in merged.items()})
        op = replace(op, headers=hs)
    if b.has(Defect.TRUST_CLIENT_RESOURCES):
        v = header(req, "X-Resources")
        if v:
            op = replace(op, resources=(v,))
    if b.has(Defect.PRINCIPAL_FROM_HEADER):
        v = header(req, "X-Principal")
        if v:
            op = replace(op, principal_id=v)
    return op
