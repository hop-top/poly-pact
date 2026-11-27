"""Transport errors. The error codes of the draft 13.4 table, the problem details of
go/validator/problem.go (ProblemOf) and the code lookup of go/validator/transport_test.go."""

from __future__ import annotations

import pytest

from hop_top_pact import contract, holder
from hop_top_pact.adapter import Code, ContextMismatch, InvalidProof
from hop_top_pact.validator import _problem, problem_of

CASES = [
    ("INVALID_MESSAGE", 400, "Invalid message"),
    ("INVALID_PROOF", 401, "Invalid proof"),
    ("REPLAY", 409, "Replay"),
    ("CONTEXT_MISMATCH", 403, "Context mismatch"),
    ("REQUIREMENTS_CHANGED", 409, "Requirements changed"),
    ("UNSUPPORTED_REQUIREMENT", 422, "Unsupported requirement"),
    ("UNSUPPORTED_PURPOSE", 422, "Unsupported purpose"),
    ("MISSING_FIELD", 403, "Missing field"),
    ("DEPENDENCY_UNAVAILABLE", 503, "Dependency unavailable"),
    ("EXPIRED", 410, "Expired"),
    ("SECURITY_HOLD", 403, "Security hold"),
]


@pytest.mark.parametrize(("code", "status", "title"), CASES)
def test_problem_of_each_code(code: str, status: int, title: str) -> None:
    err = _problem.reject(code, "private detail")
    p = problem_of(err, "r1")
    assert p is not None
    assert (p.type, p.title, p.status, p.code, p.request_id) == (
        "about:blank",
        title,
        status,
        code,
        "r1",
    )
    assert "private detail" not in repr(p), "a public error discloses only its code"


def test_problem_of_no_code() -> None:
    assert problem_of(RuntimeError("x"), "r1") is None
    assert problem_of(None, "r1") is None
    # A code outside the draft 13.4 table has no problem.
    assert problem_of(_problem.reject("NOT_EVALUATED", "x"), "r1") is None


def test_reject_defaults_to_invalid_message() -> None:
    assert _problem.reject("", "x").code == "INVALID_MESSAGE"
    assert str(_problem.reject("INVALID_PROOF", "x")) == "validator: INVALID_PROOF: x"


def test_code_of_reads_every_error_family() -> None:
    # What adapter.CodeOf and the sentinels of the Go packages give: the code of an
    # adapter error, a contract error, a holder error, and the first one in a cause chain.
    assert _problem.code_of(InvalidProof("x")) == "INVALID_PROOF"
    assert _problem.code_of(contract.ContractError(contract.CODE_REPLAY)) == "REPLAY"
    assert _problem.code_of(holder.HolderError(Code.MISSING_FIELD)) == "MISSING_FIELD"
    wrapped = RuntimeError("outer")
    wrapped.__cause__ = ContextMismatch("inner")
    assert _problem.code_of(wrapped) == "CONTEXT_MISMATCH"
    assert _problem.code_of(RuntimeError("x")) is None
    assert _problem.code_of(None) is None
