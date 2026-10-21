"""The binding configuration and its checks, and the character classes the rules share."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from hop_top_pact.core.binding._errors import config_error

# Schema bounds the package enforces so that its output validates against
# OperationContext and GatewayMetadata in spec/v1.0/schemas/pact.schema.json.
MAX_IDENTIFIER: Final = 1024  # operation_mapping_version, header_normalization_id
MAX_TARGET_URI: Final = 1024  # OperationContext.target_uri maxLength
MAX_HEADERS: Final = 64  # OperationContext.headers maxProperties
MAX_HEADER_VALUE: Final = 8192  # OperationContext.headers value maxLength

ALPHA: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
DIGIT: Final = frozenset("0123456789")
HEXDIG: Final = DIGIT | frozenset("ABCDEFabcdef")
UNRESERVED: Final = ALPHA | DIGIT | frozenset("-._~")  # RFC 3986 2.3
SUB_DELIMS: Final = frozenset("!$&'()*+,;=")  # RFC 3986 2.2
TCHAR: Final = ALPHA | DIGIT | frozenset("!#$%&'*+-.^_`|~")  # RFC 9110 5.6.2

_LOWER: Final = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_UPPER: Final = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def lower_ascii(s: str) -> str:
    """s with its ASCII letters lowercased; no Unicode case mapping changes other characters."""
    return s.translate(_LOWER)


def upper_ascii(s: str) -> str:
    """s with its ASCII letters uppercased."""
    return s.translate(_UPPER)


def is_utf8_text(s: str) -> bool:
    """Whether s encodes as UTF-8: no lone surrogate, such as surrogateescape leaves."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """The installed baseline HTTP mapping of a gateway.

    Its values come from trusted gateway configuration, never from the request.

    origin is the public HTTPS origin, scheme "://" host [":" port], with no
    path, query, fragment or userinfo. The scheme and host are lowercased and
    port 443 is dropped. The host is ASCII: a registered name of unreserved
    and sub-delims characters, a dotted IPv4 address, or a bracketed IPv6
    address without a zone.

    header_allowlist names the application headers that can alter action
    semantics. Names are RFC 9110 tokens, matched without regard to ASCII
    case and written lowercase. Credential, presentation, hop-by-hop and
    signature headers are refused (see the package documentation). The
    gateway publishes the list in GatewayMetadata.protected_header_names.

    header_normalization_id names the header normalization this package
    applies, as published in GatewayMetadata.header_normalization_id.

    mapping_version is the installed mapping version, as published in
    GatewayMetadata.operation_mapping_version. The caller records it when it
    issues a requirement contract and checks that it is unchanged when it
    validates the actual operation (draft 10.2); from_request only requires
    it to be set.

    max_body is the largest request body, in octets, that from_request
    accepts. Zero admits only an empty body.
    """

    origin: str
    header_allowlist: Sequence[str]
    header_normalization_id: str
    mapping_version: str
    max_body: int

    def validate(self) -> None:
        """Raise RequestError (kind INVALID_CONFIG) unless the configuration is usable.

        from_request calls it on every request; a gateway can call it at start-up.
        """
        self.prepare()

    def prepare(self) -> tuple[str, tuple[str, ...]]:
        """Validate the configuration; return the normalized origin and the lowercase allowlist."""
        origin = normalize_origin(self.origin)
        allow = allowlist(self.header_allowlist)
        for name, v in (
            ("header_normalization_id", self.header_normalization_id),
            ("mapping_version", self.mapping_version),
        ):
            if not isinstance(v, str) or not 1 <= len(v) <= MAX_IDENTIFIER or not is_utf8_text(v):
                raise config_error(f"{name} must be UTF-8 of 1 to {MAX_IDENTIFIER} characters")
        if not isinstance(self.max_body, int) or isinstance(self.max_body, bool):
            raise config_error("max_body is not an integer")
        if self.max_body < 0:
            raise config_error("max_body is negative")
        return origin, allow


def normalize_origin(s: str) -> str:
    """s with the scheme and host lowercase and the default port omitted.

    RFC 3986 6.2.2.1 and 6.2.3; RFC 9110 4.2.3.
    """
    if not isinstance(s, str):
        raise config_error("origin is not a string")
    scheme, sep, authority = s.partition("://")
    if not sep or lower_ascii(scheme) != "https":
        raise config_error(f"origin {s!r} is not an https origin")
    if any(c in authority for c in "/?#"):
        raise config_error(f"origin {s!r} has a path, query or fragment")
    if "@" in authority:
        raise config_error(f"origin {s!r} has userinfo")
    if not authority.isascii() or "%" in authority:
        # RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8, so
        # it is a non-ASCII host too.
        raise config_error(f"origin {s!r} has a non-ASCII host")
    host, port = _split_host_port(s, authority)
    out = "https://" + lower_ascii(host)
    if port not in ("", "443"):
        out += ":" + port
    return out


def _split_host_port(origin: str, a: str) -> tuple[str, str]:
    """The validated host and port of an ASCII authority without userinfo; "host:" has port ""."""
    if a.startswith("["):
        end = a.find("]")
        if end < 0:
            raise config_error(f"origin {origin!r}: unclosed IP literal")
        host, rest = a[: end + 1], a[end + 1 :]
        # RFC 3986 3.2.2: an IP literal is IPv6 (no zone identifier) or
        # IPvFuture, which no gateway resolves here. A zone needs "%", which
        # normalize_origin has refused already.
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise config_error(
                f"origin {origin!r}: IP literal {host!r} is not an IPv6 address without zone"
            ) from None
        if rest and not rest.startswith(":"):
            raise config_error(f"origin {origin!r}: text after the IP literal")
        port = rest[1:]
    else:
        host, _, port = a.partition(":")
        if not host:
            # RFC 9110 4.2.2: an https URI with an empty host is invalid.
            raise config_error(f"origin {origin!r}: empty host")
        for c in host:
            if c not in UNRESERVED and c not in SUB_DELIMS:
                raise config_error(f"origin {origin!r}: host has the character {c!r}")
    _check_port(origin, port)
    return host, port


def _check_port(origin: str, p: str) -> None:
    """Accept "" or 1..65535 without leading zero or sign, so 443 is known by its spelling."""
    if p == "":
        return
    if not all(c in DIGIT for c in p) or p[0] == "0" or not 1 <= int(p) <= 65535:
        raise config_error(
            f"origin {origin!r}: port {p!r} is not a number 1..65535 without leading zero"
        )


def excluded_header(name: str) -> bool:
    """Whether a lowercase header name can never be covered.

    Credentials and presentation headers (draft 10.2 and 19), hop-by-hop
    headers (RFC 9110 7.6.1), message signatures (RFC 9421 4.1, 4.2) and
    Host, which never selects the origin (request-binding.md RB-3, RB-20).
    """
    return name in _EXCLUDED or name.startswith(("pact-", "proxy-"))


_EXCLUDED: Final = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "connection",
        "keep-alive",
        "te",
        "transfer-encoding",
        "upgrade",
        "signature",
        "signature-input",
        "host",
    }
)


def allowlist(names: Sequence[str]) -> tuple[str, ...]:
    """The configured header names, validated and lowercase."""
    if isinstance(names, str):
        raise config_error("header_allowlist is a string, not a sequence of names")
    out: list[str] = []
    for n in names:
        if not isinstance(n, str) or not n or not all(c in TCHAR for c in n):
            raise config_error(f"header name {n!r} is not an RFC 9110 token")
        low = lower_ascii(n)
        if excluded_header(low):
            raise config_error(f"header {low!r} cannot be covered by an operation context")
        if low in out:
            raise config_error(f"header {low!r} is listed twice")
        out.append(low)
    count = len(out) + (0 if "content-type" in out else 1)
    if count > MAX_HEADERS:
        raise config_error(f"{count} header names with content-type, at most {MAX_HEADERS}")
    return tuple(out)
