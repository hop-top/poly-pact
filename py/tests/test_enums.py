"""The generated string enums. Port of go/core/enums_test.go.

``test_enums_follow_the_go_source`` also compares the enums with the Go
declarations they are generated from; it skips when go/ is absent (a mirror
checkout, or the copy that make py-mutants tests).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import enums

REPO = Path(__file__).resolve().parents[2]
GO_ENUMS = REPO / "go" / "core" / "enums.go"

# Every StrEnum the package exports, each with its is_valid classmethod.
ENUMS: list[Any] = [getattr(enums, name) for name in enums.__all__]


@pytest.mark.parametrize("cls", ENUMS, ids=lambda c: c.__name__)
def test_enum_valid(cls: Any) -> None:
    values = [m.value for m in cls]
    assert values, f"{cls.__name__} has no members"
    for s in values:
        assert cls.is_valid(str(s)), f"{cls.__name__}.is_valid({s!r}) = False"
    for bad in ["", "bogus", " ", "Enforced", "enforced "]:
        if bad in values:
            continue
        assert not cls.is_valid(bad), f"{cls.__name__}.is_valid({bad!r}) = True"


def test_enums_follow_the_go_source() -> None:
    if not GO_ENUMS.exists():
        pytest.skip(f"{GO_ENUMS.relative_to(REPO)} absent")
    text = GO_ENUMS.read_text(encoding="utf-8")
    go: dict[str, list[str]] = {
        name: re.findall(r"(?m)^\s+\w+\s+" + name + r'\s+=\s+"([^"]*)"$', text)
        for name in re.findall(r"(?m)^type (\w+) string$", text)
    }
    assert sorted(go) == sorted(enums.__all__)
    for cls in ENUMS:
        assert [m.value for m in cls] == go[cls.__name__], cls.__name__
