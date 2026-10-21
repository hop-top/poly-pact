"""The adapter errors and their draft 13.4 codes.

Port of go/adapter/errors_test.go. Go's seven sentinel errors are the seven
AdapterError subclasses; errors.Is becomes isinstance and CodeOf code_of,
which follows __cause__, else __context__, through PactError instances. It
reads spec/v1.0/draft.md: it fails when the draft is absent under
PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from hop_top_pact import adapter
from hop_top_pact.adapter import (
    AdapterError,
    Code,
    ContextMismatch,
    DenialReason,
    InvalidProof,
    NativeDenial,
    code_of,
)
from hop_top_pact.errors import PactError

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"

# Each error class with the draft 13.4 code the package contract assigns it.
# The literals are copied from the 13.4 table, not from the code.
SENTINELS: list[tuple[str, type[AdapterError], str]] = [
    ("InvalidMessage", adapter.InvalidMessage, "INVALID_MESSAGE"),
    ("InvalidProof", adapter.InvalidProof, "INVALID_PROOF"),
    ("ContextMismatch", adapter.ContextMismatch, "CONTEXT_MISMATCH"),
    ("DependencyUnavailable", adapter.DependencyUnavailable, "DEPENDENCY_UNAVAILABLE"),
    ("UnsupportedRequirement", adapter.UnsupportedRequirement, "UNSUPPORTED_REQUIREMENT"),
    ("UnsupportedPurpose", adapter.UnsupportedPurpose, "UNSUPPORTED_PURPOSE"),
    ("MissingField", adapter.MissingField, "MISSING_FIELD"),
]


class Wrapped(PactError):
    """A PactError of another family that carries an adapter error as its cause."""


def wrap(err: BaseException, *notes: str) -> BaseException:
    """err raised from inside one Wrapped per note, innermost first: Go's fmt.Errorf %w."""
    for note in notes:
        try:
            try:
                raise err
            except BaseException as inner:
                raise Wrapped(note) from inner
        except Wrapped as outer:
            err = outer
    return err


def read_draft() -> str:
    if not DRAFT.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{DRAFT} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return DRAFT.read_text(encoding="utf-8")


def draft_section(heading: str) -> str:
    d = read_draft()
    start = d.find("\n" + heading + "\n")
    assert start >= 0, f"draft has no heading {heading!r}"
    rest = d[start + 1 + len(heading) :]
    end = re.search(r"(?m)^#{1,3} ", rest)
    return rest if end is None else rest[: end.start()]


@pytest.mark.parametrize(("name", "cls", "code"), SENTINELS)
def test_sentinels_map_to_draft_codes(name: str, cls: type[AdapterError], code: str) -> None:
    err = cls()
    assert isinstance(err, AdapterError)
    assert isinstance(err, PactError)
    assert err.code == code
    assert code_of(err) == code
    wrapped = wrap(err, "lookup", "read claim")
    assert code_of(wrapped) == code
    assert isinstance(wrapped.__cause__, Wrapped)
    assert isinstance(wrapped.__cause__.__cause__, cls), name
    assert str(err) != ""
    assert str(err).startswith("adapter: ")
    detailed = cls("store down")
    assert "store down" in str(detailed)
    assert detailed.code == code


def test_sentinels_are_distinct() -> None:
    for a_name, a, _ in SENTINELS:
        for b_name, b, _ in SENTINELS:
            assert issubclass(a, b) == (a is b), (a_name, b_name)
            assert isinstance(a(), b) == (a is b), (a_name, b_name)


def raised_during(inner: BaseException, outer: BaseException, *, cause: bool) -> BaseException:
    """outer as raised while inner is handled: from inner when cause, else with
    inner as its implicit context."""
    try:
        try:
            raise inner
        except BaseException:
            if cause:
                raise outer from inner
            raise outer  # noqa: B904
    except BaseException as e:
        return e
    raise AssertionError("unreachable")


def test_code_of_follows_context_too() -> None:
    outer = raised_during(adapter.MissingField(), Wrapped("while reading"), cause=True)
    assert code_of(outer) == Code.MISSING_FIELD
    outer = raised_during(adapter.ContextMismatch(), Wrapped("during handling"), cause=False)
    assert outer.__cause__ is None
    assert code_of(outer) == Code.CONTEXT_MISMATCH


def test_code_of_ignores_foreign_errors() -> None:
    assert code_of(None) is None
    assert code_of(Exception("INVALID_PROOF")) is None
    assert code_of(wrap(ValueError("x"), "wrap")) is None
    # The chain is followed through PactError instances only.
    outer = raised_during(adapter.InvalidProof(), RuntimeError("foreign"), cause=True)
    assert code_of(outer) is None


def test_codes_are_in_draft_table() -> None:
    """Every Code member is a code of the 13.4 table."""
    sec = draft_section("### 13.4 Errors")
    table: set[str] = set()
    row = re.compile(r"(?m)^\| (`[A-Z_]+`(?: / `[A-Z_]+`)*) \|")
    tok = re.compile(r"`([A-Z_]+)`")
    for m in row.finditer(sec):
        table.update(t[1] for t in tok.finditer(m[1]))
    assert len(table) >= 15, f"parsed {len(table)} codes from 13.4, want at least 15"
    assert len(Code) == 7
    for c in Code:
        assert c.value in table, c


def test_native_denial_is_an_invalid_proof() -> None:
    d = NativeDenial(DenialReason.CREDENTIAL_REJECTED)
    assert isinstance(d, InvalidProof)
    assert not isinstance(d, ContextMismatch)
    assert d.code == Code.INVALID_PROOF
    assert code_of(wrap(d, "authn")) == Code.INVALID_PROOF
    got = wrap(d, "authn").__cause__
    assert isinstance(got, NativeDenial)
    assert got.reason == DenialReason.CREDENTIAL_REJECTED


def test_native_denial_is_pointer_only() -> None:
    """Go returns *NativeDenial so errors.As has one target type. Python has one
    class: a caller catches NativeDenial, or InvalidProof for any proof failure."""
    assert issubclass(NativeDenial, InvalidProof)
    assert issubclass(NativeDenial, BaseException)
    assert not issubclass(DenialReason, BaseException)
    with pytest.raises(InvalidProof):
        raise NativeDenial(DenialReason.NO_CREDENTIAL)


def test_native_denial_does_not_disclose() -> None:
    """The text of a denial depends only on the public reason set. Free text an
    adapter puts in reason, such as the name of an account, never reaches
    str(), repr(), args or public_reason()."""
    leaks = [
        "user alice@corp.example not found",
        "password mismatch for svc-billing",
        "issuer https://idp.internal.example rejected the token",
        "",
    ]
    base = str(NativeDenial(DenialReason.CREDENTIAL_REJECTED))
    for r in leaks:
        d = NativeDenial(r)
        assert str(d) == base, r
        assert d.public_reason() == DenialReason.CREDENTIAL_REJECTED, r
        if r:
            assert r not in str(d)
            assert r not in repr(d)
            assert all(r not in str(a) for a in d.args)
    for valid in (DenialReason.NO_CREDENTIAL, DenialReason.CREDENTIAL_REJECTED):
        d = NativeDenial(valid)
        assert d.public_reason() == valid
        assert valid.value in str(d)
    assert str(NativeDenial(DenialReason.NO_CREDENTIAL)) != base


def test_nil_native_denial_does_not_panic() -> None:
    """Go's nil *NativeDenial; in Python, a denial built without a reason."""
    d = NativeDenial()
    assert str(d) != ""
    assert d.public_reason() == DenialReason.CREDENTIAL_REJECTED
