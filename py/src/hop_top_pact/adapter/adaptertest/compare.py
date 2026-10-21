"""The state of one case and the comparisons the checks share (Go adaptertest,
compare.go and the run type of suite.go).

An adapter function reports an error by raising a PactError, the AdapterError
of the draft 13.4 code where it has one. That is the counterpart of a Go
error return. Any other exception is a defect of the adapter, the
counterpart of a Go panic: the case fails, whatever outcome it expects.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Final, TypeVar

from hop_top_pact.adapter._errors import (
    AdapterError,
    Code,
    ContextMismatch,
    DependencyUnavailable,
    InvalidMessage,
    InvalidProof,
    MissingField,
    UnsupportedPurpose,
    UnsupportedRequirement,
    code_of,
)
from hop_top_pact.adapter._types import AgentBinding, Principal, Realm
from hop_top_pact.adapter.adaptertest.casefile import ABSENT, Case
from hop_top_pact.adapter.adaptertest.harness import Hooks, Subject
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.jcs import canonicalize_value
from hop_top_pact.core.types import OperationContext
from hop_top_pact.errors import PactError

T = TypeVar("T")

SKEW: Final = BASELINE_SKEW
"""The clock skew the suite allows between an adapter's timestamps and the
case's now: the baseline of draft 7.5. An adapter configured with a tighter
skew passes; one that needs a larger skew does not."""

EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_SECOND: Final = timedelta(seconds=1)

# The AdapterError subclass of each code: an error that carries a code is that
# class or wraps an instance of it, which is how a caller matches it with
# isinstance (package adapter, Errors).
SENTINELS: Final[Mapping[Code, type[AdapterError]]] = {
    Code.INVALID_MESSAGE: InvalidMessage,
    Code.INVALID_PROOF: InvalidProof,
    Code.CONTEXT_MISMATCH: ContextMismatch,
    Code.DEPENDENCY_UNAVAILABLE: DependencyUnavailable,
    Code.UNSUPPORTED_REQUIREMENT: UnsupportedRequirement,
    Code.UNSUPPORTED_PURPOSE: UnsupportedPurpose,
    Code.MISSING_FIELD: MissingField,
}


def at(sec: int) -> datetime:
    """The instant of sec Unix seconds."""
    return EPOCH + timedelta(seconds=sec)


def unix(t: datetime) -> int:
    """The Unix seconds of t, rounded down."""
    return (t - EPOCH) // _SECOND


_RAW_URL: Final = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)


def raw_url_decode(s: str) -> bytes:
    """Decode unpadded base64url as Go's base64.RawURLEncoding does: the URL-safe
    alphabet only, no padding, spare bits not checked. Raises ValueError."""
    if not _RAW_URL.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError(f"{s[:16]!r} is not unpadded base64url")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except binascii.Error as e:
        raise ValueError(str(e)) from None


def chain(err: BaseException | None) -> Iterator[BaseException]:
    """err and the exceptions it wraps, through __cause__, else __context__: Go's
    error chain."""
    seen: set[int] = set()
    while err is not None and id(err) not in seen:
        seen.add(id(err))
        yield err
        err = err.__cause__ if err.__cause__ is not None else err.__context__


def find(err: BaseException | None, cls: type[T]) -> T | None:
    """The first exception of the chain of err that is a cls: Go's errors.As."""
    for e in chain(err):
        if isinstance(e, cls):
            return e
    return None


def error_text(err: BaseException) -> str:
    """The text of err and of everything it wraps, as Go's Error() of a wrapped
    error reads."""
    parts: list[str] = []
    for e in chain(err):
        s = str(e)
        parts.append(s if s else type(e).__name__)
    return ": ".join(parts)


def json_equal(want: object, got: object) -> bool:
    """Whether want and got are the same JSON data: object member order is ignored,
    array order is significant (draft 8.4). Both are put into RFC 8785 canonical
    form and compared. Raises ValueError when either is not JSON data."""
    try:
        cw = canonicalize_value(want)
    except (TypeError, ValueError, PactError) as e:
        raise ValueError(f"expected value: {e}") from None
    try:
        cg = canonicalize_value(got)
    except (TypeError, ValueError, PactError) as e:
        raise ValueError(f"returned value: {e}") from None
    return cw == cg


def render(v: object) -> str:
    """v in its canonical JSON form for a message, or its repr when it is not JSON
    data."""
    try:
        return canonicalize_value(v).decode("utf-8")
    except (TypeError, ValueError, PactError):
        return repr(v)


def principal_empty(p: Principal) -> bool:
    return p.id == "" and p.workload == "" and p.realm == Realm()


def binding_empty(b: AgentBinding) -> bool:
    return b.agent_id == "" and b.operator_id == "" and b.holder_jkt == ""


def operation_empty(op: OperationContext) -> bool:
    return (
        op.operation_id == ""
        and op.principal_id == ""
        and op.action == ""
        and op.target_uri == ""
        and op.body_digest == ""
        and not op.resources
    )


def format_map(m: Mapping[str, str] | None) -> str:
    """A header map with sorted names, for messages."""
    if m is None:
        return "None"
    return "{" + ", ".join(f"{k!r}: {m[k]!r}" for k in sorted(m)) + "}"


class CaseRun:
    """The state of one case: the case, its now, the hooks, the subject the factory
    returned, and the failures found so far."""

    def __init__(self, case: Case, now: datetime, hooks: Hooks) -> None:
        self.case = case
        self.now = now
        self.hooks = hooks
        self.subject: Subject | None = None
        self.fails: list[str] = []

    def fail(self, msg: str) -> None:
        self.fails.append(msg)

    def call(self, step: str, f: Callable[[], object]) -> tuple[object, PactError | None, bool]:
        """Call f. The result (None when f raised), the PactError it raised, and
        whether it returned or raised a PactError. Any other exception is a failure
        of the step, as a Go panic is. The result is typed object: the checks take
        nothing an adapter returns on trust."""
        try:
            return f(), None, True
        except PactError as e:
            return None, e, True
        except Exception as e:
            self.fail(
                f"{step} raised {type(e).__name__}: {error_text(e)}; an adapter reports an"
                " error as a PactError"
            )
            return None, None, False

    def want_reason(self, step: str, err: BaseException | None) -> None:
        """Check the stable code err carries against the case's reason_code, when the
        case names one, and that err is or wraps the AdapterError class of that
        code."""
        want = self.case.expect.reason_code
        if not want or err is None:
            return
        got = code_of(err)
        if got is None:
            self.fail(f"{step} error carries no draft 13.4 code, want {want}: {error_text(err)}")
            return
        if got != want:
            self.fail(f"{step} error code is {got}, want {want}: {error_text(err)}")
            return
        sentinel = SENTINELS.get(Code(want))
        if sentinel is not None and find(err, sentinel) is None:
            self.fail(
                f"{step} error carries the code {want} but does not wrap the sentinel "
                f"{sentinel.__name__}: raise it, or raise from it, so that isinstance"
                f" matches: {error_text(err)}"
            )

    def want_time(self, what: str, want: object, got: datetime | None) -> None:
        """Check a time against an expected member of the case: ABSENT is not
        checked, None requires no time, a number requires those Unix seconds."""
        if want is ABSENT:
            return
        if want is None:
            if got is not None:
                self.fail(
                    f"{what} is {self._seconds(got)}, want the zero time: the source gives"
                    " none and the adapter must not supply one"
                )
            return
        if isinstance(want, bool) or not isinstance(want, int):
            self.fail(f"{what}: expected value {render(want)} is not an integer")
            return
        if got is None:
            self.fail(f"{what} is the zero time, want {want}")
        elif self._seconds(got) != want:
            self.fail(
                f"{what} is {self._seconds(got)}, want {want} (the time the source gave,"
                " not the time of the read)"
            )

    def _seconds(self, t: datetime) -> int | str:
        try:
            return unix(t)
        except TypeError:
            return repr(t)

    def not_after(self, what: str, t: datetime | None, limit: datetime) -> None:
        """Fail when t is later than limit. None passes: it says the source gives no
        such time."""
        if t is None:
            return
        try:
            late = t > limit
        except TypeError:
            self.fail(f"{what} is {t!r}, not an aware datetime")
            return
        if late:
            self.fail(f"{what} is {unix(t)}, later than the allowed {unix(limit)}")

    def principal(self) -> Principal:
        """The case's principal argument as the adapter type."""
        p = self.case.call.principal
        if p is None:
            return Principal()
        when = self.now if p.authenticated_at is None else at(p.authenticated_at)
        return Principal(
            id=p.id,
            realm=Realm(tenant_id=p.realm.tenant_id, environment_id=p.realm.environment_id),
            workload=p.workload,
            mechanism=p.mechanism or "test",
            authenticated_at=when,
            attributes={} if p.attributes is None else p.attributes,
        )
