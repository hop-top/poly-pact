"""Recorded outcomes and the descriptor conversion.

Port of go/adapter/outcome_test.go. TestDescriptorConvertsToNativeAdapter
reads the B.13 example of spec/v1.0/draft.md: it fails when the draft is absent
under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise.
"""

from __future__ import annotations

import os
import re
import typing
from pathlib import Path

import pytest

from hop_top_pact.adapter import Descriptor, NoVisibility, Recorded, Signed
from hop_top_pact.core import strictjson
from hop_top_pact.core.types import GatewayMetadata

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"


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


@pytest.mark.parametrize(
    ("name", "jws", "ok"),
    [
        ("three segments", "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln", True),
        ("empty", "", False),
        ("two segments", "aaa.bbb", False),
        ("four segments", "aaa.bbb.ccc.ddd", False),
        ("empty header", ".bbb.ccc", False),
        ("empty payload", "aaa..ccc", False),
        ("empty signature", "aaa.bbb.", False),
    ],
)
def test_signed_validate(name: str, jws: str, ok: bool) -> None:
    if ok:
        Signed(jws=jws).validate()
    else:
        with pytest.raises(ValueError, match="compact JWS"):
            Signed(jws=jws).validate()


@pytest.mark.parametrize(
    ("reason", "ok"),
    [
        ("execution happens in a system the adapter cannot observe", True),
        ("", False),
        ("   \t", False),
    ],
)
def test_no_visibility_validate(reason: str, ok: bool) -> None:
    if ok:
        NoVisibility(reason=reason).validate()
    else:
        with pytest.raises(ValueError, match="no reason"):
            NoVisibility(reason=reason).validate()


def kind(r: Recorded) -> str:
    """The exhaustive match a consumer writes over the union."""
    match r:
        case Signed():
            return "signed"
        case NoVisibility():
            return "no-visibility"


def test_recorded_holds_exactly_one() -> None:
    assert kind(Signed(jws="a.b.c")) == "signed"
    assert kind(NoVisibility(reason="r")) == "no-visibility"


def test_recorded_is_sealed() -> None:
    """Recorded is the union of the two final variants: no third one can be added,
    and each has validate."""
    assert typing.get_args(Recorded) == (Signed, NoVisibility)
    for cls in (Signed, NoVisibility):
        assert getattr(cls, "__final__", False) is True, cls.__name__
        assert callable(getattr(cls, "validate", None)), cls.__name__


def test_descriptor_converts_to_native_adapter() -> None:
    """The conversion against the adapters entry of the draft's gateway metadata
    example (B.13)."""
    sec = draft_section("### B.13 Gateway metadata with baseline limits")
    _, sep, rest = sec.partition("```json\n")
    assert sep, "B.13 has no json block"
    body, sep, _ = rest.partition("\n```")
    assert sep, "B.13 json block is not closed"
    md = strictjson.decode(body.encode("utf-8"), GatewayMetadata)
    assert len(md.adapters) == 1
    d = Descriptor(protocol="mcp", version="2025-11-25", mapping_revision="finance-mcp-1")
    assert d.native_adapter() == md.adapters[0]
