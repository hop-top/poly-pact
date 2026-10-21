"""The seven functions of draft section 17.1 and the composite Adapter.

Port of go/adapter/adapter_test.go. The expected names and signatures are
written from the 17.1 table and the adapter-contract freeze note, not
derived from the package under test. It reads spec/v1.0/draft.md: it fails when
the draft is absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips
otherwise (a mirror checkout).
"""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

import pytest

from hop_top_pact import adapter
from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    Descriptor,
    NativeClaim,
    NoVisibility,
    Observation,
    Principal,
    Realm,
    Recorded,
    Workload,
)
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.types import OperationContext

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"

# One row of the draft 17.1 table with the Python name the package gives it:
# the draft name, the Protocol, its method, the parameters after self as
# (name, annotation) and the return annotation.
FUNCTIONS: list[tuple[str, type, str, list[tuple[str, str]], str]] = [
    (
        "authenticate_native",
        adapter.NativeAuthenticator,
        "authenticate_native",
        [("req", "RawRequest")],
        "Principal",
    ),
    (
        "resolve_agent_binding",
        adapter.BindingResolver,
        "resolve_agent_binding",
        [("realm", "Realm"), ("workload", "Workload"), ("agent", "AgentID")],
        "AgentBinding",
    ),
    (
        "map_operation",
        adapter.OperationMapper,
        "map_operation",
        [("req", "RawRequest"), ("p", "Principal"), ("mapping_version", "str")],
        "OperationContext",
    ),
    (
        "read_native_claim",
        adapter.ClaimReader,
        "read_native_claim",
        [("native_path", "str"), ("c", "ClaimContext")],
        "NativeClaim",
    ),
    (
        "check_context",
        adapter.ContextChecker,
        "check_context",
        [("check_id", "str"), ("input", "CheckInput")],
        "CheckOutcome",
    ),
    (
        "authorize_native",
        adapter.NativeAuthorizer,
        "authorize_native",
        [("p", "Principal"), ("op", "OperationContext")],
        "Decision",
    ),
    (
        "record_outcome",
        adapter.OutcomeRecorder,
        "record_outcome",
        [("o", "Observation")],
        "Recorded",
    ),
]


def read_draft() -> str:
    if not DRAFT.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{DRAFT} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return DRAFT.read_text(encoding="utf-8")


def draft_section(heading: str) -> str:
    """The draft text from the line heading to the next heading of level 1 to 3."""
    d = read_draft()
    start = d.find("\n" + heading + "\n")
    assert start >= 0, f"draft has no heading {heading!r}"
    rest = d[start + 1 + len(heading) :]
    end = re.search(r"(?m)^#{1,3} ", rest)
    return rest if end is None else rest[: end.start()]


def draft_rows() -> list[tuple[str, str, str]]:
    """The (function, input, output) rows of the draft 17.1 table."""
    sec = draft_section("### 17.1 Required adapter capabilities")
    row = re.compile(r"(?m)^\| `([a-z_]+)` \| (.+?) \| (.+?) \|$")
    return [(m[1], m[2], m[3]) for m in row.finditer(sec)]


def protocol_methods(proto: type) -> list[str]:
    """The public methods a Protocol declares, its bases' included."""
    names: set[str] = set()
    for cls in proto.__mro__:
        if cls is object or cls.__module__ == "typing":
            continue
        names.update(n for n, v in vars(cls).items() if not n.startswith("_") and callable(v))
    return sorted(names)


def parameters(fn: object) -> tuple[list[tuple[str, str]], str]:
    sig = inspect.signature(fn)  # type: ignore[arg-type]
    params = [(p.name, str(p.annotation)) for p in sig.parameters.values() if p.name != "self"]
    return params, str(sig.return_annotation)


def test_draft_table_has_seven_functions() -> None:
    rows = draft_rows()
    assert len(rows) == len(FUNCTIONS), "draft 17.1 rows against the package's functions"
    for i, r in enumerate(rows):
        assert r[0] == FUNCTIONS[i][0], f"row {i}"


@pytest.mark.parametrize(("draft", "proto", "method", "params", "ret"), FUNCTIONS)
def test_one_interface_per_function(
    draft: str, proto: type, method: str, params: list[tuple[str, str]], ret: str
) -> None:
    assert protocol_methods(proto) == [method], draft
    got_params, got_ret = parameters(getattr(proto, method))
    assert got_params == params, draft
    assert got_ret == ret, draft


def test_composite_exposes_all_seven() -> None:
    want: dict[str, tuple[list[tuple[str, str]], str]] = {"describe": ([], "Descriptor")}
    for _, proto, method, params, ret in FUNCTIONS:
        want[method] = (params, ret)
        assert issubclass(adapter.Adapter, proto), proto.__name__
    assert protocol_methods(adapter.Adapter) == sorted(want)
    for name, (params, ret) in want.items():
        assert parameters(getattr(adapter.Adapter, name)) == (params, ret), name


class Stub:
    """Implements every method; it proves the composite is satisfiable. The
    package itself ships no implementation."""

    def authenticate_native(self, req: RawRequest) -> Principal:
        return Principal()

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        return AgentBinding()

    def map_operation(
        self, req: RawRequest, p: Principal, mapping_version: str
    ) -> OperationContext:
        raise NotImplementedError

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        return NativeClaim()

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        return CheckOutcome()

    def authorize_native(self, p: Principal, op: OperationContext) -> Decision:
        return Decision()

    def record_outcome(self, o: Observation) -> Recorded:
        return NoVisibility(reason="stub")

    def describe(self) -> Descriptor:
        return Descriptor()


def test_stub_satisfies_every_protocol() -> None:
    s = Stub()
    _a: adapter.Adapter = s  # checked by mypy
    assert isinstance(s, adapter.Adapter)
    for _, proto, *_rest in FUNCTIONS:
        assert isinstance(s, proto), proto.__name__


def normalize(s: str) -> str:
    """Collapse whitespace runs, so a wrapped docstring line matches the single-line cell."""
    return " ".join(s.split())


def test_doc_reproduces_draft_table_row_by_row() -> None:
    doc = normalize(adapter.__doc__ or "")
    for i, (fn, inp, out) in enumerate(draft_rows()):
        py_name = FUNCTIONS[i][1].__name__ + "." + FUNCTIONS[i][2]
        for want in (fn, py_name, inp, out):
            assert normalize(want) in doc, f"adapter docstring row {i} ({fn}) lacks {want!r}"


def test_doc_states_the_two_invariants() -> None:
    doc = normalize(adapter.__doc__ or "")
    for want in (
        "authenticated context",
        "configured authoritative lookup",
        "draft 8.5",
        "original source observation",
        "draft 8.3",
    ):
        assert want in doc, want
