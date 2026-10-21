"""Header selection and the baseline header normalization (RFC 9110 5.2, 5.3, 5.5)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Final

from hop_top_pact.core.binding._config import (
    DIGIT,
    HEXDIG,
    MAX_HEADER_VALUE,
    SUB_DELIMS,
    UNRESERVED,
    is_utf8_text,
    lower_ascii,
)
from hop_top_pact.core.binding._errors import Rule, refuse


def select_headers(
    lines: Sequence[tuple[str, str]], allow: Sequence[str], has_body: bool
) -> dict[str, str]:
    """The headers member: the allowlisted headers that are present, plus
    content-type when a body is present (draft 10.2).

    A name listed in a Connection field is hop-by-hop for this request (RFC
    9110 7.6.1) and is left out.
    """
    names = list(allow)
    if has_body and "content-type" not in names:
        names.append("content-type")
    hop = connection_options(lines)
    out: dict[str, str] = {}
    for name in names:
        if name in hop:
            continue
        v = field_value(lines, name)
        if v is not None:
            out[name] = v
    return out


def field_value(lines: Sequence[tuple[str, str]], name: str) -> str | None:
    """The combined value of the field name, or None when there is no field line.

    Each field line value loses its leading and trailing SP and HTAB (RFC 9110
    5.5, 5.6.3); the lines are joined in order with ", " (RFC 9110 5.2, 5.3).
    """
    values = [v.strip(" \t") for n, v in lines if lower_ascii(n) == name]
    if not values:
        return None
    v = ", ".join(values)
    for c in v:
        # RFC 9110 5.5: field-content is VCHAR, obs-text, SP and HTAB; CR, LF,
        # NUL and the other controls are invalid.
        if (c < " " and c != "\t") or c == "\x7f":
            raise refuse(Rule.HEADER_VALUE, f"the header {name!r} has the control U+{ord(c):04X}")
    if not is_utf8_text(v):
        # Draft 7.1: PACT objects are UTF-8 JSON, so other obs-text octets
        # cannot be carried exactly.
        raise refuse(Rule.HEADER_VALUE, f"the header {name!r} is not valid UTF-8")
    if len(v) > MAX_HEADER_VALUE:
        raise refuse(
            Rule.HEADER_TOO_LONG,
            f"the header {name!r} has {len(v)} characters, at most {MAX_HEADER_VALUE}",
        )
    return v


def connection_options(lines: Sequence[tuple[str, str]]) -> frozenset[str]:
    """The lowercase connection options of every Connection field line (RFC 9110 7.6.1)."""
    out: set[str] = set()
    for n, v in lines:
        if lower_ascii(n) != "connection":
            continue
        for opt in v.split(","):
            opt = opt.strip(" \t")
            if opt:
                out.add(lower_ascii(opt))
    return frozenset(out)


def check_host(lines: Sequence[tuple[str, str]], origin_form: bool) -> None:
    """The Host rules of RFC 9112 3.2 (request-binding.md RB-65, RB-66).

    More than one Host field line, with names in any ASCII case and whatever
    the values, is refused. An origin-form request without one has no
    authority and is refused; an absolute-form target carries its own (RFC
    9112 3.2.2), and an ASGI server gives HTTP/2 :authority as the host
    header. A value that is not uri-host [ ":" port ] with a non-empty host
    is refused.
    """
    values = [v for name, v in lines if lower_ascii(name) == "host"]
    if len(values) > 1:
        raise refuse(Rule.DUPLICATE_HOST, f"the request has {len(values)} Host field lines")
    if origin_form and not values:
        raise refuse(Rule.MISSING_HOST, "an origin-form request without Host")
    for v in values:
        if not _valid_host(v.strip(" \t")):
            raise refuse(Rule.INVALID_HOST, 'the Host value is not uri-host [ ":" port ]')


# IPvFuture (RFC 3986 3.2.2): "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ).
_IPV_FUTURE: Final = re.compile(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+")


def _valid_host(v: str) -> bool:
    """Whether v is uri-host [ ":" port ] (RFC 9110 7.2) with a non-empty host.

    The host is an IP literal, IPv6 without a zone identifier or IPvFuture,
    or a registered name of unreserved, sub-delims and percent-encoded
    characters, which includes a dotted IPv4 address (RFC 3986 3.2.2; RFC
    9110 4.2.1, 4.2.2); the port is digits (3.2.3).
    """
    if v.startswith("["):
        end = v.find("]")
        if end < 0:
            return False
        lit, rest = v[1:end], v[end + 1 :]
        if not _IPV_FUTURE.fullmatch(lit):
            if "%" in lit:
                return False
            try:
                ipaddress.IPv6Address(lit)
            except ValueError:
                return False
        if rest and rest[0] != ":":
            return False
        port = rest[1:]
    else:
        host, _, port = v.partition(":")
        if not host:
            return False
        i = 0
        while i < len(host):
            c = host[i]
            if c in UNRESERVED or c in SUB_DELIMS:
                i += 1
            elif c == "%" and len(host) > i + 2 and host[i + 1] in HEXDIG and host[i + 2] in HEXDIG:
                i += 3
            else:
                return False
    return all(c in DIGIT for c in port)


def check_codings(lines: Sequence[tuple[str, str]]) -> None:
    """Refuse any Content-Encoding field and any transfer coding other than chunked.

    The baseline forbids HTTP content encodings on protected requests (draft
    10.2). A RawRequest body is after transfer decoding, and chunked is the
    only coding every recipient removes (RFC 9112 6.1), so a body under
    another coding is not known to be decoded.
    """
    for n, _ in lines:
        if lower_ascii(n) == "content-encoding":
            raise refuse(Rule.CONTENT_ENCODING, "the request has a Content-Encoding field")
    for n, v in lines:
        if lower_ascii(n) != "transfer-encoding":
            continue
        for c in v.split(","):
            c = c.strip(" \t")
            if c and lower_ascii(c) != "chunked":
                raise refuse(Rule.TRANSFER_CODING, f"the request has the transfer coding {c!r}")
