"""The case model of the adapter conformance suite (Go adaptertest, casefile.go).

One case file is a stimulus for one of the seven draft 17.1 functions and the
behavior the draft requires of it. Every field keeps the case-file member
name that spec/v1.0/fixtures/adapters/README.md documents, and the types are
decode targets of core.strictjson: a case file strict-decodes into Case, and
an absent member holds the field's default, Go's zero value. Request.tls_peer
is the core.binding.TLSPeer of RawRequest.

A Go json.RawMessage member that tells an absent member from a JSON null is
a field whose default is ABSENT: ABSENT when the member is absent, None for
null, and the parsed JSON value otherwise. Those fields are annotated object,
the strict decoder's free-form target.

load_cases reads the case files of a fixture tree, strict-parses each and
checks the rules of the format; spec/v1.0/fixtures/adapters/README.md defines both.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import Final

from hop_top_pact.adapter._types import BindingStatus
from hop_top_pact.core import strictjson
from hop_top_pact.core.binding import TLSPeer
from hop_top_pact.core.enums import Dimension, EventKind, OutcomeResult, Severity
from hop_top_pact.core.types import (
    Attribution,
    Intent,
    JSONValue,
    OperationContext,
    ReputationContext,
)
from hop_top_pact.errors import PactError

__all__ = [
    "ABSENT",
    "BindingJSON",
    "Call",
    "Case",
    "Expect",
    "ExpectBinding",
    "ExpectClaim",
    "ExpectDecision",
    "ExpectOperation",
    "ExpectPrincipal",
    "LeakScan",
    "LoadError",
    "ObligationJSON",
    "ObservationJSON",
    "PrincipalJSON",
    "RealmJSON",
    "Request",
    "TLSPeer",
    "load_cases",
]


class _Absent(Enum):
    ABSENT = "ABSENT"

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent.ABSENT
"""The value of a free-form member the case file leaves out, told apart from a
JSON null (None)."""


def _no_headers() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True, kw_only=True)
class Request:
    """The HTTP request of an authenticate_native or map_operation case.

    url is the request-target as the gateway received it, in absolute-form;
    headers are read in member order; body_b64 is the body, standard base64 with
    padding, "" for none; tls_peer describes the client certificate of a
    mutual-TLS connection; native_state_ref names the native identity whose
    credential the request presents (the Subject's credential hook attaches
    it); arrival is "enforcement_point" (the default, also "") or "direct".
    core.binding._request.decode_request_object reads the same object into a
    RawRequest.
    """

    method: str = ""
    url: str = ""
    headers: Mapping[str, str] = field(default_factory=_no_headers)
    body_b64: str = ""
    tls_peer: TLSPeer | None = None
    native_state_ref: str = ""
    arrival: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class RealmJSON:
    """A realm in a case file."""

    tenant_id: str = ""
    environment_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class PrincipalJSON:
    """An authenticated principal handed to a function directly. mechanism "" stands
    for the default, "test"; authenticated_at is Unix seconds, None for the
    case's now."""

    id: str = ""
    realm: RealmJSON = RealmJSON()
    workload: str = ""
    mechanism: str = ""
    authenticated_at: int | None = None
    attributes: Mapping[str, JSONValue] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class BindingJSON:
    """An agent binding handed to check_context: the binding of the agent the request
    names, as resolve_agent_binding returned it and the validator verified it
    (draft 11.3 step 2, 17.1). status "" stands for ACTIVE."""

    agent_id: str = ""
    operator_id: str = ""
    holder_jkt: str = ""
    status: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationJSON:
    """An observation in a case file, with the member names of the outcome report
    (draft 14.1). observed_at is Unix seconds."""

    event_id: str = ""
    event_kind: EventKind
    context: ReputationContext
    task_id: str = ""
    operation_id: str = ""
    admission_receipt_id: str | None = None
    observed_at: int = 0
    result: OutcomeResult
    dimension: Dimension
    severity: Severity
    evidence_refs: tuple[str, ...] = ()
    attribution: Attribution
    supersedes: tuple[str, ...] = ()
    details: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Call:
    """The arguments of the function under test other than the HTTP request. Which
    members a case may set depends on expect.function.

    agent_id is the agent ID the request names, the third input of
    resolve_agent_binding (draft 17.1). binding is the agent binding of a
    check_context call; None, the call establishes no agent. evidence_refs is
    None when absent, which an empty array is not.
    """

    realm: RealmJSON | None = None
    workload: str = ""
    agent_id: str = ""
    mapping_version: str = ""
    principal: PrincipalJSON | None = None
    binding: BindingJSON | None = None
    native_path: str = ""
    check_id: str | None = None
    intent: Intent | None = None
    operation: OperationContext | None = None
    evidence_refs: tuple[str, ...] | None = None
    observation: ObservationJSON | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class LeakScan:
    """The credential scan of draft 19: literal credential values that must not
    appear anywhere in the values and errors a function returns."""

    secrets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectPrincipal:
    """The fields of the authenticated principal to check; an empty field is not
    checked. attributes, when present, is a JSON object, each of whose members
    must equal, as JSON data, the principal's attribute of the same name; an
    attribute it does not name is not checked."""

    id: str = ""
    realm: RealmJSON | None = None
    workload: str = ""
    mechanism: str = ""
    attributes: object = ABSENT


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectBinding:
    """The fields of the agent binding to check; an empty field is not checked.

    enrolled_elsewhere, when present, is the required value of
    AgentBinding.enrolled_elsewhere: whether the agent ID is enrolled for
    another workload of the realm (draft 17.1). It may be true only for the
    outcome "unknown", and it is the only member that outcome accepts.
    """

    agent_id: str = ""
    operator_id: str = ""
    holder_jkt: str = ""
    status: str = ""
    enrolled_elsewhere: bool | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectOperation:
    """The fields of the operation context to check; "" or None is not checked."""

    environment_id: str = ""
    principal_id: str = ""
    action: str = ""
    resources: tuple[str, ...] | None = None
    method: str = ""
    target_uri: str = ""
    body_digest: str = ""
    headers: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectClaim:
    """The fields of the native claim to check. ABSENT is not checked; None in a
    time member requires no time."""

    value: object = ABSENT
    observed_at: object = ABSENT
    status_checked_at: object = ABSENT
    source_id: str = ""
    source_ref: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ObligationJSON:
    """An obligation in a case file."""

    id: str = ""
    attributes: Mapping[str, JSONValue] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectDecision:
    """The fields of the native decision to check. ABSENT or "" is not checked; None
    in decided_at requires no decision time, and None in source_ref requires an
    empty source reference: the source keeps no record of the decision.

    obligations, when set, must equal the decision's obligations exactly, in
    order. source_id, source_ref, decided_at (Unix seconds) and policy_revision
    are the provenance the native policy source gave.
    """

    obligations: tuple[ObligationJSON, ...] | None = None
    source_id: str = ""
    source_ref: object = ABSENT
    decided_at: object = ABSENT
    policy_revision: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Expect:
    """What the case requires. function, outcome and the member that belongs to the
    outcome carry the assertions; the rest are optional.

    function is one of the seven draft 17.1 function names and outcome one of
    the outcomes defined for it. reason_code is the stable code the function
    reports: the public denial reason, the draft 13.4 code of an error, or the
    reason code of a check. must_not_call lists native hooks that must not have
    fired by the end of the case.
    """

    function: str = ""
    outcome: str = ""
    reason_code: str = ""
    must_not_call: tuple[str, ...] = ()
    leak_scan: LeakScan | None = None
    principal: ExpectPrincipal | None = None
    binding: ExpectBinding | None = None
    operation: ExpectOperation | None = None
    claim: ExpectClaim | None = None
    decision: ExpectDecision | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Case:
    """One case file.

    draft lists the draft sections the case rests on. workloads limits the case
    to the adapters whose profile supports workloads shared by several agents,
    "shared", or to those whose profile does not, "dedicated"; "" applies to
    every adapter. now is the case's current time in Unix seconds, None for the
    suite's default. native_state is handed to the adapter's Factory verbatim,
    as parsed JSON.
    """

    case_version: int = 0
    id: str = ""
    title: str = ""
    draft: tuple[str, ...] = ()
    workloads: str = ""
    now: int | None = None
    native_state: JSONValue = None
    request: Request | None = None
    call: Call = Call()
    expect: Expect = Expect()


class LoadError(PactError):
    """The case files cannot be read, or one breaks a rule of the format: Go's
    error from Load and Evaluate. The message names the file."""


CASE_VERSION: Final = 1
"""The only case file format this package reads."""

MAX_CASE_BYTES: Final = 1 << 20
"""The bound of one case file."""

# The seven function names of the draft 17.1 table, as a case file spells
# them in expect.function.
FN_AUTHENTICATE: Final = "authenticate_native"
FN_BINDING: Final = "resolve_agent_binding"
FN_MAP_OPERATION: Final = "map_operation"
FN_CLAIM: Final = "read_native_claim"
FN_CHECK: Final = "check_context"
FN_AUTHORIZE: Final = "authorize_native"
FN_RECORD: Final = "record_outcome"

# The outcomes a case can expect; FUNCTION_OUTCOMES lists the ones each
# function accepts and README.md in the fixture directory defines them.
# check_context uses the verdict as the outcome and authorize_native the
# effect.
OUT_AUTHENTICATED: Final = "authenticated"
OUT_DENIED: Final = "denied"
OUT_ERROR: Final = "error"
OUT_BOUND: Final = "bound"
OUT_NOT_ENROLLED: Final = "unknown"
OUT_UNUSABLE: Final = "unusable"
OUT_MAPPED: Final = "mapped"
OUT_CLAIM: Final = "claim"
OUT_PASS: Final = "PASS"  # noqa: S105
OUT_FAIL: Final = "FAIL"
OUT_UNKNOWN: Final = "UNKNOWN"
OUT_ALLOW: Final = "ALLOW"
OUT_DENY: Final = "DENY"
OUT_NOT_ALLOWED: Final = "not_allowed"
OUT_SIGNED: Final = "signed"
OUT_NO_VISIBILITY: Final = "no_visibility"
OUT_NO_EXEC_SUCCESS: Final = "no_execution_success"

FUNCTION_OUTCOMES: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        FN_AUTHENTICATE: (OUT_AUTHENTICATED, OUT_DENIED, OUT_ERROR),
        FN_BINDING: (OUT_BOUND, OUT_NOT_ENROLLED, OUT_UNUSABLE, OUT_ERROR),
        FN_MAP_OPERATION: (OUT_MAPPED, OUT_ERROR),
        FN_CLAIM: (OUT_CLAIM, OUT_ERROR),
        FN_CHECK: (OUT_PASS, OUT_FAIL, OUT_UNKNOWN),
        FN_AUTHORIZE: (OUT_ALLOW, OUT_DENY, OUT_UNKNOWN, OUT_NOT_ALLOWED, OUT_ERROR),
        FN_RECORD: (OUT_SIGNED, OUT_NO_VISIBILITY, OUT_NO_EXEC_SUCCESS, OUT_ERROR),
    }
)

# Values of Case.workloads: whether the adapter's profile supports workloads
# shared by several agents (draft 17.1, identity mapping IM-19).
WORKLOADS_SHARED: Final = "shared"
WORKLOADS_DEDICATED: Final = "dedicated"

# Values of Request.arrival.
ARRIVAL_ENFORCEMENT_POINT: Final = "enforcement_point"
ARRIVAL_DIRECT: Final = "direct"

_ID_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9]*-[0-9]{2,}(\.[a-z0-9]+(-[a-z0-9]+)*)?", re.ASCII)
_ADAPTER_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*", re.ASCII)

COMMON_DIR: Final = "adapters/_common"
"""The directory of the cases every adapter must pass, relative to the fixture
root."""


def accepted(outcome: str) -> bool:
    """Whether an outcome lets the stimulus through, the outcome class ACCEPTED of
    the fixture manifest; every other outcome is REJECTED."""
    return outcome in (
        OUT_AUTHENTICATED,
        OUT_BOUND,
        OUT_MAPPED,
        OUT_CLAIM,
        OUT_SIGNED,
        OUT_ALLOW,
        OUT_PASS,
    )


def applies_to(c: Case, shared: bool) -> bool:
    """Whether c runs against an adapter whose profile supports workloads shared by
    several agents (shared True) or does not."""
    if c.workloads == WORKLOADS_SHARED:
        return shared
    if c.workloads == WORKLOADS_DEDICATED:
        return not shared
    return True


def _child(root: Traversable, rel: str) -> Traversable:
    t = root
    for part in rel.split("/"):
        t = t.joinpath(part)
    return t


def load_cases(fixtures: Traversable, adapter: str = "") -> list[Case]:
    """Read the common cases and, when adapter is not empty, the cases in
    adapters/<adapter>, from the fixture tree rooted at fixtures (spec/v1.0/fixtures),
    such as a pathlib.Path. An adapter's case files sit directly in its
    directory, as the common cases do; a subdirectory is not read. Files are
    read in name order, the common cases first.

    Raises LoadError when a case file does not strict-parse or breaks a rule of
    the format, when a directory holds no case file, and when two cases share an
    id.
    """
    return load_tree(fixtures, adapter)[0]


def load_tree(fixtures: Traversable, adapter: str = "") -> tuple[list[Case], frozenset[str]]:
    """load_cases, and the ids of the cases of adapters/_common."""
    cases = _load_dir(fixtures, COMMON_DIR)
    if not cases:
        raise LoadError(f"adaptertest: no case files in {COMMON_DIR}")
    common = frozenset(c.id for c in cases)
    if adapter:
        if not _ADAPTER_NAME_PATTERN.fullmatch(adapter):
            raise LoadError(
                f"adaptertest: adapter name {adapter!r} is not a lowercase hyphenated name"
            )
        own = _load_dir(fixtures, "adapters/" + adapter)
        if not own:
            raise LoadError(f"adaptertest: no case files in adapters/{adapter}")
        cases += own
    seen: set[str] = set()
    for c in cases:
        if c.id in seen:
            raise LoadError(f"adaptertest: case id {c.id} is used twice")
        seen.add(c.id)
    return cases, common


def _load_dir(fixtures: Traversable, rel: str) -> list[Case]:
    d = _child(fixtures, rel)
    try:
        if not d.is_dir():
            raise LoadError(f"adaptertest: read {rel}: no such directory")
        entries = sorted(d.iterdir(), key=lambda t: t.name)
    except OSError as err:
        raise LoadError(f"adaptertest: read {rel}: {err}") from err
    cases: list[Case] = []
    for entry in entries:
        if entry.is_dir() or not entry.name.endswith(".json"):
            continue
        file = rel + "/" + entry.name
        try:
            data = entry.read_bytes()
        except OSError as err:
            raise LoadError(f"adaptertest: read {file}: {err}") from err
        try:
            c = strictjson.decode(data, Case, strictjson.Limits(max_bytes=MAX_CASE_BYTES))
        except strictjson.StrictJSONError as err:
            raise LoadError(f"adaptertest: {file}: {err}") from err
        problem = validate_case(c)
        if problem:
            raise LoadError(f"adaptertest: {file}: {problem}")
        cases.append(c)
    return cases


def _present_call(k: Call) -> list[str]:
    """The members of the call that are set."""
    present = (
        (k.realm is not None, "realm"),
        (k.workload != "", "workload"),
        (k.agent_id != "", "agent_id"),
        (k.mapping_version != "", "mapping_version"),
        (k.principal is not None, "principal"),
        (k.binding is not None, "binding"),
        (k.native_path != "", "native_path"),
        (k.check_id is not None, "check_id"),
        (k.intent is not None, "intent"),
        (k.operation is not None, "operation"),
        (k.evidence_refs is not None, "evidence_refs"),
        (k.observation is not None, "observation"),
    )
    return [name for ok, name in present if ok]


# Per function, the required and the optional members of the call.
_CALL_MEMBERS: Final[Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]]] = MappingProxyType(
    {
        FN_AUTHENTICATE: ((), ()),
        FN_BINDING: (("realm", "workload", "agent_id"), ()),
        FN_MAP_OPERATION: (("principal", "mapping_version"), ()),
        FN_CLAIM: (("principal", "native_path"), ("intent", "operation")),
        FN_CHECK: (("check_id", "principal", "operation"), ("binding", "intent", "evidence_refs")),
        FN_AUTHORIZE: (("principal", "operation"), ()),
        FN_RECORD: (("observation",), ()),
    }
)

# The Expect member that an outcome must come with, because the outcome says
# nothing without it.
_EXPECT_MEMBER: Final[Mapping[str, str]] = MappingProxyType(
    {OUT_AUTHENTICATED: "principal", OUT_BOUND: "binding", OUT_UNUSABLE: "binding"}
)

# The outcome-specific Expect members a function accepts.
_FUNCTION_EXPECT: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        FN_AUTHENTICATE: ("principal",),
        FN_BINDING: ("binding",),
        FN_MAP_OPERATION: ("operation",),
        FN_CLAIM: ("claim",),
        FN_AUTHORIZE: ("decision",),
    }
)


def _present_expect(e: Expect) -> list[str]:
    """The outcome-specific members of the expectation."""
    present = (
        (e.principal is not None, "principal"),
        (e.binding is not None, "binding"),
        (e.operation is not None, "operation"),
        (e.claim is not None, "claim"),
        (e.decision is not None, "decision"),
    )
    return [name for ok, name in present if ok]


def validate_case(c: Case) -> str:
    """The first rule of the format that c breaks, as a message; "" when none."""
    if c.case_version != CASE_VERSION:
        return f"case_version is {c.case_version}, want {CASE_VERSION}"
    if not _ID_PATTERN.fullmatch(c.id):
        return f"id {c.id!r} does not match {_ID_PATTERN.pattern}"
    if not c.title.strip():
        return f"{c.id}: title is empty"
    if c.workloads not in ("", WORKLOADS_SHARED, WORKLOADS_DEDICATED):
        return (
            f"{c.id}: workloads {c.workloads!r} is not "
            f"{WORKLOADS_SHARED!r} or {WORKLOADS_DEDICATED!r}"
        )
    if c.now is not None and not 0 <= c.now <= strictjson.MAX_SAFE_INTEGER:
        return f"{c.id}: now is outside 0..2^53-1"
    if not isinstance(c.native_state, Mapping):
        return f"{c.id}: native_state is not a JSON object"
    f = c.expect.function
    outcomes = FUNCTION_OUTCOMES.get(f)
    if outcomes is None:
        return f"{c.id}: expect.function {f!r} is not one of the seven functions"
    if c.expect.outcome not in outcomes:
        return (
            f"{c.id}: outcome {c.expect.outcome!r} is not defined for {f}"
            f" (want one of {list(outcomes)})"
        )
    for check in (_validate_request, _validate_call, _validate_expect):
        problem = check(c, f)
        if problem:
            return f"{c.id}: {problem}"
    return ""


def _validate_request(c: Case, f: str) -> str:
    takes_request = f in (FN_AUTHENTICATE, FN_MAP_OPERATION)
    r = c.request
    if takes_request and r is None:
        return f"{f} needs a request"
    if not takes_request and r is not None:
        return f"{f} takes no request"
    if r is None:
        return ""
    if not r.method or not r.url:
        return "request needs a method and a url"
    if r.arrival not in ("", ARRIVAL_ENFORCEMENT_POINT, ARRIVAL_DIRECT):
        return (
            f"request.arrival {r.arrival!r} is not "
            f"{ARRIVAL_ENFORCEMENT_POINT!r} or {ARRIVAL_DIRECT!r}"
        )
    for name in r.headers:
        if not name or any(ch in name for ch in " \t\r\n:"):
            return f"request header name {name!r} is not valid"
    try:
        decode_body(r.body_b64)
    except ValueError as e:
        return str(e)
    return ""


def decode_body(b64: str) -> bytes:
    """Decode a body_b64 member: standard base64 with padding, b"" for no body.
    Raises ValueError otherwise."""
    if not b64:
        return b""
    try:
        return base64.b64decode(b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as e:
        raise ValueError(f"request.body_b64 is not standard padded base64: {e}") from None


def _validate_call(c: Case, f: str) -> str:
    required, optional = _CALL_MEMBERS[f]
    present = _present_call(c.call)
    for name in required:
        if name not in present:
            return f"call.{name} is required for {f}"
    for name in present:
        if name not in required and name not in optional:
            return f"call.{name} is not an argument of {f}"
    if f == FN_CHECK:
        return _validate_check_call(c.call)
    return ""


def _validate_check_call(k: Call) -> str:
    """The principal of a check_context call is the one the operation names (draft
    12.1), and a binding has a defined status."""
    if k.principal is None or k.operation is None:
        return ""
    if k.principal.id != k.operation.principal_id:
        return (
            f"call.principal.id {k.principal.id!r} is not call.operation.principal_id "
            f"{k.operation.principal_id!r}: the principal is the one of the operation"
            " (draft 12.1)"
        )
    b = k.binding
    if b is not None and b.status and not BindingStatus.is_valid(b.status):
        return f"call.binding.status {b.status!r} is not a binding status"
    return ""


def _validate_elsewhere(e: Expect) -> str:
    """Only an UNKNOWN result reports the agent ID enrolled for another workload
    (draft 17.1), so expect.binding.enrolled_elsewhere may be true only for the
    outcome unknown, and that outcome, which names no record, accepts no other
    binding member."""
    b = e.binding
    if b is None:
        return ""
    if e.outcome == OUT_NOT_ENROLLED:
        if b.agent_id or b.operator_id or b.holder_jkt or b.status:
            return f"outcome {e.outcome!r} accepts only enrolled_elsewhere in expect.binding"
        return ""
    if b.enrolled_elsewhere:
        return (
            f"expect.binding.enrolled_elsewhere true applies only to outcome "
            f"{OUT_NOT_ENROLLED!r}, not {e.outcome!r}"
        )
    return ""


def _validate_expect(c: Case, f: str) -> str:
    e = c.expect
    present = _present_expect(e)
    for name in present:
        if name not in _FUNCTION_EXPECT.get(f, ()):
            return f"expect.{name} does not apply to {f}"
    want = _EXPECT_MEMBER.get(e.outcome)
    if want is not None and want not in present:
        return f"outcome {e.outcome!r} needs expect.{want}"
    problem = _validate_elsewhere(e)
    if problem:
        return problem
    p = e.principal
    if p is not None and p.attributes is not ABSENT and not isinstance(p.attributes, Mapping):
        return "expect.principal.attributes is not a JSON object"
    for h in e.must_not_call:
        if not h.strip():
            return "expect.must_not_call has an empty hook name"
    return ""
