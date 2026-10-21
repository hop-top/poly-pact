"""record_outcome and verify_outcome of the memory adapter (Go adapters/memory,
outcome.go)."""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hop_top_pact.adapter import (
    ContextMismatch,
    DependencyUnavailable,
    NoVisibility,
    Observation,
    Recorded,
    Signed,
    UnsupportedRequirement,
)
from hop_top_pact.adapters.memory.freshness import EPOCH
from hop_top_pact.adapters.memory.state import MemoryAdapterError
from hop_top_pact.core import VERSION, jws
from hop_top_pact.core.enums import EventKind, ReporterRole

if TYPE_CHECKING:
    from hop_top_pact.adapters.memory.memory import MemoryAdapter

OUTCOME_VALIDITY: Final = timedelta(seconds=300)
"""The validity of a signed outcome report: the baseline maximum of draft 14.3."""

OUTCOME_TYP: Final = "pact-outcome+jwt"

_SECOND: Final = timedelta(seconds=1)


def _unix(t: datetime | None) -> int:
    return 0 if t is None else (t - EPOCH) // _SECOND


def record_outcome(a: MemoryAdapter, o: Observation) -> Recorded:
    """Record the observation as an outcome report signed with ES256.

    What the adapter cannot see it does not claim. An EXECUTION observation with
    no execution visibility returns NoVisibility whatever result the observation
    carries, and never an assumed success (draft 14.1). The adapter signs only
    the events it observes itself: admission and authorization decisions as the
    gateway and, with visibility, executions as the executor. Free text and
    evidence references are cleaned of credential material first (draft 19).
    """
    rep = a.st.reporting
    if a.key is None or rep is None:
        raise UnsupportedRequirement("memory: no reporting key is configured")
    if not o.event_id:
        raise MemoryAdapterError("memory: the observation has no event id")
    g = a.st.gateway
    if o.context.tenant_id != g.tenant_id or o.context.environment_id != g.environment_id:
        raise ContextMismatch("memory: the observation belongs to another realm")
    if o.event_kind in (EventKind.ADMISSION, EventKind.AUTHORIZATION):
        role = ReporterRole.GATEWAY
    elif o.event_kind == EventKind.EXECUTION:
        if a.st.visibility != "execution":
            return NoVisibility(
                reason="the adapter does not observe the execution of operations; execution is"
                " reported by the system that runs them"
            )
        role = ReporterRole.EXECUTOR
    else:
        raise UnsupportedRequirement(f"memory: the adapter does not report {o.event_kind} events")

    now = _unix(a.clock.now())
    report = {
        "pact_version": VERSION,
        "iss": rep.issuer,
        "sub": o.context.agent_id,
        "aud": rep.audience,
        "jti": jti(rep.issuer, o.event_id),
        "iat": now,
        "nbf": now,
        "exp": now + OUTCOME_VALIDITY // _SECOND,
        "tenant_id": o.context.tenant_id,
        "event_id": o.event_id,
        "environment_id": o.context.environment_id,
        "task_id": o.task_id,
        "operation_id": o.operation_id,
        "admission_receipt_id": o.admission_receipt_id,
        "observed_at": _unix(o.observed_at),
        "reporter_role": role,
        "context": wire(o.context),
        "event_kind": o.event_kind,
        "result": o.result,
        "dimension": o.dimension,
        "severity": o.severity,
        "evidence_refs": [redact(a, ref) for ref in o.evidence_refs],
        "attribution": wire(o.attribution),
        "supersedes": list(o.supersedes),
        "details": redact(a, o.details),
    }
    payload = json.dumps(wire(report), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        compact = jws.sign(jws.Header(typ=OUTCOME_TYP, kid=rep.kid), payload, a.key)
    except jws.JWSError as e:
        raise DependencyUnavailable("memory: signing") from e
    return Signed(jws=compact)


def wire(v: object) -> object:
    """v as JSON data: a wire dataclass by its members, leaving out an optional
    member that is None; an enum by its value."""
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        members = getattr(type(v), "_MEMBERS", {})
        out: dict[str, object] = {}
        for f in dataclasses.fields(v):
            x = getattr(v, f.name)
            m = members.get(f.name)
            if x is None and m is not None and not m.required:
                continue
            out[f.name] = wire(x)
        return out
    if isinstance(v, Enum):
        return v.value
    if isinstance(v, Mapping):
        return {str(k): wire(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [wire(x) for x in v]
    return v


def jti(issuer: str, event_id: str) -> str:
    """The jti of an event's report: stable per event, so that a retry of the same
    observation carries the same identifier and the receiver deduplicates it
    (draft 7.5)."""
    s = hashlib.sha256((issuer + "\x00" + event_id).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode("ascii")[:22]


def _raw_url(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s, re.ASCII) or len(s) % 4 == 1:
        raise ValueError("not unpadded base64url")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except binascii.Error as e:
        raise ValueError(str(e)) from None


def verify_outcome(a: MemoryAdapter, compact: str) -> None:
    """Verify the ES256 signature of a compact JWS this adapter signed. Raises
    MemoryAdapterError when it does not verify."""
    if a.key is None:
        raise MemoryAdapterError("memory: no reporting key is configured")
    parts = compact.split(".")
    if len(parts) != 3:
        raise MemoryAdapterError("memory: not a compact JWS")
    try:
        sig = _raw_url(parts[2])
    except ValueError:
        raise MemoryAdapterError("memory: malformed signature") from None
    if len(sig) != 64:
        raise MemoryAdapterError("memory: malformed signature")
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii", errors="replace")
    try:
        a.key.public_key().verify(
            encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError):
        raise MemoryAdapterError("memory: the signature does not verify") from None


# The shapes of credential material that draft 19 keeps out of receipts,
# outcome reports and logs.
_HEADER_LINE: Final = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|pact-presentation"
    r"|pact-admission)\s*:[^\r\n]*",
    re.ASCII,
)
_AUTH_VALUE: Final = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", re.ASCII)
_JWS_LIKE: Final = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", re.ASCII)
_ASSIGNMENT: Final = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|api_?key|password|passwd|secret"
    r"|session(?:_?id)?|sid|token)=[^\s&;\"']+",
    re.ASCII,
)
REDACTED: Final = "[redacted]"


def redact(a: MemoryAdapter, s: str) -> str:
    """s without credential material: every secret the adapter holds, header lines
    that carry credentials, bearer and basic values, compact JWS strings, and
    name=value pairs with a credential name."""
    for i in a.st.identities:
        if i.secret:
            s = s.replace(i.secret, REDACTED)
    s = _HEADER_LINE.sub(lambda m: m.group(1) + ": " + REDACTED, s)
    s = _AUTH_VALUE.sub(lambda m: m.group(1) + " " + REDACTED, s)
    s = _JWS_LIKE.sub(REDACTED, s)
    return _ASSIGNMENT.sub(lambda m: m.group(1) + "=" + REDACTED, s)
