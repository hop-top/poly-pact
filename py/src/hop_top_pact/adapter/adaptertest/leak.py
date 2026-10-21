"""The credential scan of draft 19 (Go adaptertest, leak.go).

Receipts, outcome reports and logs must not contain the headers
authorization, proxy-authorization, cookie, set-cookie, pact-presentation and
pact-admission, any private JWK parameter, or native tokens and passwords.
The patterns are deliberately narrow, so that a legitimate message such as
"basic authentication failed" does not match: an authorization value needs a
long token after the scheme, a header name needs to be a JSON member name,
and a key=value secret needs a name that only credentials have.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from enum import Enum
from typing import Final

from hop_top_pact.adapter.adaptertest.compare import CaseRun, error_text, raw_url_decode

__all__ = ["find_credentials", "json_text"]


def _is_placeholder(m: re.Match[str]) -> bool:
    """Whether the value of an assignment is a mask such as [redacted], REDACTED,
    ***** or xxxxxx rather than a credential."""
    v = m.group(1).strip("[]<>(){}*_-.x").lower()
    return v in ("", "redacted", "removed", "hidden", "masked", "filtered", "omitted", "elided")


_A: Final = re.ASCII
_PATTERNS: Final[Sequence[tuple[str, re.Pattern[str], Callable[[re.Match[str]], bool] | None]]] = (
    (
        "authorization value",
        re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{16,}=*", _A),
        None,
    ),
    (
        "compact JWS or JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", _A),
        None,
    ),
    (
        "credential header as a member name",
        re.compile(
            r'(?i)"(?:authorization|proxy-authorization|cookie|set-cookie|pact-presentation'
            r'|pact-admission)"\s*:',
            _A,
        ),
        None,
    ),
    ("private JWK parameter as a member name", re.compile(r'"(?:d|p|q|dp|dq|qi|k)"\s*:', _A), None),
    (
        "credential assignment",
        re.compile(
            r"(?i)\b(?:access_token|refresh_token|id_token|api_?key|password|passwd|secret"
            r"|session(?:_?id)?|sid)=([^\s&;\"']{6,})",
            _A,
        ),
        _is_placeholder,
    ),
)


def find_credentials(text: str, secrets: Sequence[str]) -> list[str]:
    """A description of every credential in text: each secret that occurs
    literally, and the first match of each pattern."""
    found = [f"secret {s!r}" for s in secrets if s and s in text]
    for name, pattern, placeholder in _PATTERNS:
        for m in pattern.finditer(text):
            if placeholder is not None and placeholder(m):
                continue
            found.append(f"{name} {m.group(0)!r}")
            break
    return found


def _plain(v: object) -> object:
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {f.name: _plain(getattr(v, f.name)) for f in dataclasses.fields(v)}
    if isinstance(v, Enum):
        return _plain(v.value)
    if isinstance(v, Mapping):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_plain(x) for x in v]
    if isinstance(v, datetime):
        return v.isoformat()
    if v is None or isinstance(v, str | int | float | bool):
        return v
    return repr(v)


def json_text(v: object) -> str:
    """The JSON form of a returned value, with its field names as members and no
    escaping of non-ASCII text, so that a secret is found as written."""
    return json.dumps(_plain(v), ensure_ascii=False)


def scan_text(r: CaseRun, what: str, text: str) -> None:
    """Fail the case for each credential in text, when the case asks for the scan."""
    ls = r.case.expect.leak_scan
    if ls is None:
        return
    for f in find_credentials(text, ls.secrets):
        r.fail(f"{what} carries a credential: {f}")


def scan_value(r: CaseRun, what: str, v: object) -> None:
    """Scan the JSON form of a returned value."""
    if r.case.expect.leak_scan is not None:
        scan_text(r, what, json_text(v))


def scan_error(r: CaseRun, what: str, err: BaseException | None) -> None:
    """Scan the text of an error and of everything it wraps."""
    if err is not None and r.case.expect.leak_scan is not None:
        scan_text(r, what + " error", error_text(err))


def scan_jws(r: CaseRun, what: str, jws: str) -> None:
    """Scan a compact JWS: the string as returned, and its header and payload
    decoded, since a credential inside the payload is base64url text in the
    string itself. Only literal secrets are looked for in the encoded form; the
    patterns would match the JWS itself."""
    ls = r.case.expect.leak_scan
    if ls is None:
        return
    for s in ls.secrets:
        if s and s in jws:
            r.fail(f"{what} carries a credential: secret {s!r}")
    for i, seg in enumerate(jws.split(".")[:2]):
        try:
            raw = raw_url_decode(seg)
        except ValueError:
            continue
        scan_text(r, f"{what} segment {i}", raw.decode("utf-8", errors="replace"))
