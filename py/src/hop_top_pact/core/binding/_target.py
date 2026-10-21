"""The method and request-target rules (RFC 9112 3.2, RFC 3986)."""

from __future__ import annotations

from typing import Final

from hop_top_pact.core.binding._config import (
    ALPHA,
    HEXDIG,
    SUB_DELIMS,
    UNRESERVED,
    lower_ascii,
    upper_ascii,
)
from hop_top_pact.core.binding._errors import Rule, refuse

# RFC 3986 3.3 pchar without pct-encoded.
_PCHAR: Final = UNRESERVED | SUB_DELIMS | frozenset(":@")
_LOWER_HEX: Final = frozenset("abcdef")


def uppercase_method(m: str) -> str:
    """The method in uppercase.

    Only ASCII letters are accepted, matching the schema pattern ^[A-Z]+$ for
    method, so no Unicode case mapping can turn another character into a
    letter.
    """
    if not isinstance(m, str) or m == "":
        raise refuse(Rule.METHOD, "empty method")
    for i, c in enumerate(m):
        if c not in ALPHA:
            raise refuse(Rule.METHOD, f"method has a character other than an ASCII letter at {i}")
    return upper_ascii(m)


def request_target(rt: str) -> str:
    """The exact path and query of the request-target rt (RFC 9112 3.2).

    All of it in origin-form, the part after the authority in absolute-form.
    Other forms, a fragment, userinfo, a non-ASCII host, the ambiguous
    encodings and dot segments are refused.
    """
    if not isinstance(rt, str) or rt == "":
        raise refuse(Rule.TARGET_FORM, "no request-target")
    if "#" in rt:
        raise refuse(Rule.FRAGMENT, "the target has a fragment")
    path_query = rt if rt[0] == "/" else _absolute_form(rt)
    path, has_query, query = path_query.partition("?")
    _check_component(path, is_path=True)
    _check_dot_segments(path)
    if has_query:
        _check_component(query, is_path=False)
    return path_query


def _absolute_form(rt: str) -> str:
    """The path and query of an http or https absolute-form target.

    The authority is checked and then dropped: the origin comes from
    configuration. An empty path is refused rather than normalized to "/".
    """
    scheme, sep, rest = rt.partition("://")
    end = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    authority, path_query = rest[:end], rest[end:]
    if sep and "@" in authority:
        # RFC 9110 4.2.4: a recipient treats userinfo in an http(s) URI as an
        # error. Checked before the scheme, as Go's URL parse sees userinfo in
        # any scheme://authority target.
        raise refuse(Rule.USERINFO, "the target has userinfo")
    if not sep or lower_ascii(scheme) not in ("https", "http"):
        raise refuse(Rule.TARGET_FORM, "the target is not origin-form or an http(s) absolute-form")
    if not authority.isascii() or "%" in authority:
        # RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8.
        raise refuse(Rule.NON_ASCII_HOST, "the target has a non-ASCII host")
    if authority.partition(":")[0] == "":
        # RFC 9110 4.2.1, 4.2.2: an http(s) URI with an empty host is invalid.
        raise refuse(Rule.TARGET_FORM, "the absolute-form target has an empty host")
    if not path_query.startswith("/"):
        raise refuse(Rule.TARGET_FORM, "the absolute-form target has an empty path")
    return path_query


def _check_component(s: str, *, is_path: bool) -> None:
    """Check the path or the query of a request target.

    Every character is allowed there by RFC 3986 3.3 or 3.4, every "%" starts
    a pct-encoded triplet (2.1), and the encoding is not ambiguous: no escape
    has a lowercase hex digit (2.1, 6.2.2.1); no escape encodes an unreserved
    character (2.3, 6.2.2.2); the path has no %2F, an encoded path separator;
    the decoded octets are valid UTF-8, so no overlong form, surrogate or
    stray octet (RFC 3629 3).
    """
    name = "path" if is_path else "query"
    decoded = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "%":
            if c not in _PCHAR and c != "/" and (is_path or c != "?"):
                raise refuse(
                    Rule.INVALID_CHARACTER,
                    f"the {name} has U+{ord(c):04X} at offset {i}, not allowed in a URI",
                )
            decoded.append(ord(c))
            i += 1
            continue
        if i + 2 >= n or s[i + 1] not in HEXDIG or s[i + 2] not in HEXDIG:
            raise refuse(
                Rule.MALFORMED_ESCAPE,
                f"the {name} has a % at offset {i} not followed by two hex digits",
            )
        if s[i + 1] in _LOWER_HEX or s[i + 2] in _LOWER_HEX:
            raise refuse(
                Rule.LOWERCASE_HEX, f"the {name} has a lowercase hex digit in the escape at {i}"
            )
        b = int(s[i + 1 : i + 3], 16)
        if chr(b) in UNRESERVED:
            raise refuse(
                Rule.ENCODED_UNRESERVED,
                f"the {name} encodes the unreserved character {chr(b)!r} at offset {i}",
            )
        if is_path and b == 0x2F:
            raise refuse(Rule.ENCODED_SLASH, f"the path has an encoded slash at offset {i}")
        decoded.append(b)
        i += 3
    try:
        decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise refuse(Rule.INVALID_UTF8, f"the decoded {name} is not valid UTF-8") from None


def _check_dot_segments(path: str) -> None:
    """Refuse a path with a complete "." or ".." segment (RFC 3986 3.3).

    Path segment normalization (6.2.2.3) removes such segments with
    remove_dot_segments (5.2.4), so the path is an ambiguous encoding (draft
    10.2). Segments are delimited by "/" only: "a..b", "..." and dots in the
    query are not dot segments. An encoded dot, as in "%2E%2E", has already
    been refused as an encoded unreserved character (2.3, 6.2.2.2).
    """
    offset = 0
    for seg in path.split("/"):
        if seg in (".", ".."):
            raise refuse(Rule.DOT_SEGMENT, f"the path has the dot segment {seg!r} at {offset}")
        offset += len(seg) + 1
