"""The rules of the baseline HTTP mapping and the error of the binding package."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from hop_top_pact.errors import PactError


class Rule(StrEnum):
    """The rule of the baseline HTTP mapping that a request broke.

    The package documentation gives the source of each.
    """

    NO_REQUEST = "no-request"
    METHOD = "method"
    TARGET_FORM = "target-form"
    FRAGMENT = "fragment"
    USERINFO = "userinfo"
    NON_ASCII_HOST = "non-ascii-host"
    INVALID_CHARACTER = "invalid-character"
    MALFORMED_ESCAPE = "malformed-escape"
    ENCODED_UNRESERVED = "encoded-unreserved"
    LOWERCASE_HEX = "lowercase-hex"
    INVALID_UTF8 = "invalid-utf8"
    ENCODED_SLASH = "encoded-slash"
    DOT_SEGMENT = "dot-segment"
    TARGET_TOO_LONG = "target-too-long"
    CONTENT_ENCODING = "content-encoding"
    TRANSFER_CODING = "transfer-coding"
    BODY_TOO_LARGE = "body-too-large"
    HEADER_VALUE = "header-value"
    HEADER_TOO_LONG = "header-too-long"
    HEADER_KEY_COLLISION = "header-key-collision"
    DUPLICATE_HOST = "duplicate-host"
    MISSING_HOST = "missing-host"
    INVALID_HOST = "invalid-host"


class RequestErrorKind(StrEnum):
    """Which failure a RequestError is: the Go sentinels Err* of the binding package."""

    INVALID_CONFIG = "INVALID_CONFIG"
    """The Config is unusable: a gateway misconfiguration, not a fault of the request."""
    INVALID_REQUEST = "INVALID_REQUEST"
    """The request has a form the baseline HTTP mapping refuses (INVALID_MESSAGE, draft 13.4).

    Such an error names the rule it breaks.
    """
    BODY_READ = "BODY_READ"
    """The request body could not be read to its end, for a reason other than its size."""


_MESSAGES: Final = {
    RequestErrorKind.INVALID_CONFIG: "binding: invalid configuration",
    RequestErrorKind.INVALID_REQUEST: "binding: request refused",
    RequestErrorKind.BODY_READ: "binding: request body could not be read",
}


class RequestError(PactError):
    """The binding failed.

    kind tells a refused request (INVALID_REQUEST, which corresponds to
    INVALID_MESSAGE of draft 13.4) from an unusable configuration
    (INVALID_CONFIG) and an unreadable body (BODY_READ). rule names the rule a
    refused request breaks and is None for the other kinds; detail says where
    the rule was broken and quotes little or none of the request.
    """

    def __init__(
        self,
        rule: Rule | None,
        detail: str = "",
        kind: RequestErrorKind = RequestErrorKind.INVALID_REQUEST,
    ) -> None:
        if (kind is RequestErrorKind.INVALID_REQUEST) != (rule is not None):
            raise ValueError("binding: a refused request names a rule; other kinds name none")
        self.kind = kind
        self.rule = rule
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        s = _MESSAGES[self.kind]
        if self.rule is not None:
            s += f" ({self.rule})"
        return f"{s}: {self.detail}" if self.detail else s


def refuse(rule: Rule, detail: str) -> RequestError:
    """A refused request under rule."""
    return RequestError(rule, detail)


def config_error(detail: str) -> RequestError:
    """An unusable configuration."""
    return RequestError(None, detail, RequestErrorKind.INVALID_CONFIG)
